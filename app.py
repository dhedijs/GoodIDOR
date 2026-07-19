from __future__ import annotations

import difflib
import html
import json
import re
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from queue import Queue
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

try:
    import requests
    from bs4 import BeautifulSoup
    from flask import Flask, jsonify, redirect, render_template_string, request, send_from_directory, url_for
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "Dependency belum terpasang. Jalankan: pip install flask requests beautifulsoup4"
    ) from exc


app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

JOBS: Dict[str, "ScanJob"] = {}
JOBS_LOCK = threading.RLock()
HISTORY_FILE = Path(__file__).with_name("scan_history.json")
REPORT_DIR = Path(__file__).with_name("reports")
WORDLIST_DIR = Path(__file__).with_name("wordlists")
PATH_WORDLIST = WORDLIST_DIR / "paths.txt"
PARAM_WORDLIST = WORDLIST_DIR / "parameters.txt"
ID_WORDLIST = WORDLIST_DIR / "ids.txt"

ID_PARAM_RE = re.compile(r"(^id$|_id$|Id$|ID$|user|account|order|invoice|profile|uid)", re.I)
NUMERIC_SEGMENT_RE = re.compile(r"(?<=/)\d+(?=/|$)")
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", re.I)
URL_STRING_RE = re.compile(r"""(?:"|')((?:https?://|/)[^"'<>\\\s]{2,240})(?:"|')""")
DESTRUCTIVE_URL_RE = re.compile(r"(^|/|-|_)(delete|destroy|remove|hapus|logout|signout|deactivate|disable)(/|-|_|$)", re.I)
MAX_BODY = 120_000
DEFAULT_UA = "GoodIDOR/1.0 authorized-security-scanner"


@dataclass
class Finding:
    severity: str
    kind: str
    original_url: str
    test_url: str
    evidence: str
    status_a: int
    status_b: Optional[int]
    similarity: float
    elapsed_ms: int
    confidence: int = 0
    owasp_top10: str = "A01:2021 Broken Access Control"
    owasp_wstg: str = "WSTG-ATHZ Authorization Testing"
    owasp_asvs: str = "ASVS V4 Access Control"
    impact: str = ""
    recommendation: str = ""
    validation_notes: str = ""


@dataclass
class ScanJob:
    id: str
    created_at: float
    target_url: str = ""
    status: str = "queued"
    progress: int = 0
    message: str = "Menunggu scanner..."
    findings: List[Finding] = field(default_factory=list)
    visited: List[str] = field(default_factory=list)
    discovered_urls: List[str] = field(default_factory=list)
    skipped_unsafe: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    report_json: str = ""
    report_html: str = ""
    done: bool = False


def same_origin(base: str, candidate: str) -> bool:
    a = urlparse(base)
    b = urlparse(candidate)
    return a.scheme in {"http", "https"} and b.scheme in {"http", "https"} and a.netloc == b.netloc


def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))


def parse_kv_lines(raw: str) -> Dict[str, str]:
    items: Dict[str, str] = {}
    for line in raw.splitlines():
        if not line.strip() or ":" not in line:
            continue
        key, value = line.split(":", 1)
        items[key.strip()] = value.strip()
    return items


def parse_form_fields(raw: str) -> Dict[str, str]:
    if not raw.strip():
        return {}
    try:
        loaded = json.loads(raw)
        if isinstance(loaded, dict):
            return {str(k): str(v) for k, v in loaded.items()}
    except json.JSONDecodeError:
        pass
    return {k: v for k, v in parse_qsl(raw, keep_blank_values=True)}


def read_wordlist(path: Path, defaults: Iterable[str]) -> List[str]:
    values: List[str] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        lines = list(defaults)
    for line in lines:
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        values.append(value)
    return list(dict.fromkeys(values))


def id_parameter_names() -> Set[str]:
    defaults = ["id", "user_id", "uid", "account_id", "order_id", "invoice_id", "profile_id"]
    return {value.lower() for value in read_wordlist(PARAM_WORDLIST, defaults)}


def test_id_values() -> List[str]:
    defaults = ["0", "1", "2", "3", "10", "100", "1001"]
    return read_wordlist(ID_WORDLIST, defaults)[:50]


def custom_path_patterns() -> List[str]:
    defaults = ["/profile/{id}", "/users/{id}", "/orders/{id}", "/api/users/{id}"]
    return read_wordlist(PATH_WORDLIST, defaults)[:200]


def account_login_fields(config: Dict[str, str], prefix: str) -> Dict[str, str]:
    advanced = parse_form_fields(config.get(f"fields_{prefix}", ""))
    username = config.get(f"username_{prefix}", "").strip()
    password = config.get(f"password_{prefix}", "")
    username_field = config.get(f"username_field_{prefix}", "username").strip() or "username"
    password_field = config.get(f"password_field_{prefix}", "password").strip() or "password"

    fields: Dict[str, str] = {}
    if username:
        fields[username_field] = username
    if password:
        fields[password_field] = password
    fields.update(advanced)
    return fields


def account_has_login_data(config: Dict[str, str], prefix: str) -> bool:
    keys = [
        f"username_{prefix}",
        f"password_{prefix}",
        f"fields_{prefix}",
        f"cookie_{prefix}",
        f"headers_{prefix}",
        f"token_{prefix}",
    ]
    return any(config.get(key, "").strip() for key in keys)


def build_session(cookie_header: str, headers_raw: str) -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": DEFAULT_UA, **parse_kv_lines(headers_raw)})
    if cookie_header.strip():
        session.headers.update({"Cookie": cookie_header.strip()})
    return session


def build_account_session(config: Dict[str, str], prefix: str) -> requests.Session:
    headers = config.get(f"headers_{prefix}", "")
    token = config.get(f"token_{prefix}", "").strip()
    if token:
        headers = f"{headers}\nAuthorization: Bearer {token}".strip()
    return build_session(config.get(f"cookie_{prefix}", ""), headers)


def should_submit_login_form(config: Dict[str, str], prefix: str, login_url: str) -> bool:
    mode = config.get(f"auth_mode_{prefix}", "form")
    return bool(login_url.strip()) and mode == "form"


def login(session: requests.Session, login_url: str, method: str, fields: Dict[str, str]) -> Tuple[bool, str]:
    if not login_url.strip():
        return True, "Tanpa login form, memakai cookie/header manual."
    try:
        req = session.post if method.upper() == "POST" else session.get
        response = req(login_url, data=fields if method.upper() == "POST" else None, params=fields if method.upper() == "GET" else None, timeout=12, allow_redirects=True)
        ok = response.status_code < 500
        return ok, f"Login {method.upper()} status {response.status_code}"
    except requests.RequestException as exc:
        return False, f"Login gagal: {exc}"


def safe_get(session: requests.Session, url: str) -> Tuple[Optional[requests.Response], int, Optional[str]]:
    started = time.time()
    try:
        response = session.get(url, timeout=12, allow_redirects=True)
        elapsed = int((time.time() - started) * 1000)
        return response, elapsed, None
    except requests.RequestException as exc:
        elapsed = int((time.time() - started) * 1000)
        return None, elapsed, str(exc)


def is_safe_discovery_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False
    if DESTRUCTIVE_URL_RE.search(parsed.path):
        return False
    blocked_ext = (".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico", ".css", ".woff", ".woff2", ".ttf", ".pdf", ".zip", ".rar", ".7z")
    return not parsed.path.lower().endswith(blocked_ext)


def extract_links(base_url: str, body: str, include_js_urls: bool = True) -> Iterable[str]:
    soup = BeautifulSoup(body, "html.parser")
    for tag in soup.find_all(["a", "area", "link", "script", "iframe", "form"]):
        raw = tag.get("href") or tag.get("src") or tag.get("action") or tag.get("data-url")
        if not raw or raw.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        resolved = normalize_url(urljoin(base_url, raw))
        if is_safe_discovery_url(resolved):
            yield resolved

    if include_js_urls:
        for match in URL_STRING_RE.finditer(body[:MAX_BODY]):
            raw = match.group(1)
            if raw.startswith(("//", "#", "javascript:", "mailto:", "tel:")):
                continue
            resolved = normalize_url(urljoin(base_url, raw))
            if is_safe_discovery_url(resolved):
                yield resolved


def extract_unsafe_forms(base_url: str, body: str) -> Iterable[str]:
    soup = BeautifulSoup(body, "html.parser")
    for form in soup.find_all("form"):
        method = (form.get("method") or "GET").upper()
        if method in {"GET", "HEAD", "OPTIONS"}:
            continue
        action = normalize_url(urljoin(base_url, form.get("action") or base_url))
        yield f"{method} {action}"


def sitemap_urls(session: requests.Session, target: str) -> Iterable[str]:
    parsed = urlparse(target)
    sitemap = urlunparse((parsed.scheme, parsed.netloc, "/sitemap.xml", "", "", ""))
    response, _, error = safe_get(session, sitemap)
    if error or response is None or response.status_code != 200:
        return []
    urls = re.findall(r"<loc>\s*([^<]+)\s*</loc>", response.text, flags=re.I)
    return [normalize_url(url.strip()) for url in urls if same_origin(target, url.strip()) and is_safe_discovery_url(url.strip())]


def mutate_numeric(value: str) -> List[str]:
    if not value.isdigit():
        return []
    number = int(value)
    candidates = {str(number + 1), str(max(0, number - 1)), *test_id_values()}
    candidates.discard(value)
    return list(candidates)[:8]


def mutate_uuid(value: str) -> List[str]:
    if not UUID_RE.fullmatch(value):
        return []
    return [
        "00000000-0000-4000-8000-000000000001",
        "00000000-0000-4000-8000-000000000002",
    ]


def mutation_urls(url: str) -> List[Tuple[str, str]]:
    parsed = urlparse(url)
    out: List[Tuple[str, str]] = []
    param_names = id_parameter_names()

    params = parse_qsl(parsed.query, keep_blank_values=True)
    for idx, (key, value) in enumerate(params):
        if key.lower() in param_names or ID_PARAM_RE.search(key) or value.isdigit() or UUID_RE.fullmatch(value):
            for mutated in mutate_numeric(value) or mutate_uuid(value) or test_id_values():
                new_params = list(params)
                new_params[idx] = (key, mutated)
                query = urlencode(new_params, doseq=True)
                out.append((urlunparse(parsed._replace(query=query)), f"parameter `{key}` diganti `{value}` -> `{mutated}`"))

    for match in NUMERIC_SEGMENT_RE.finditer(parsed.path):
        original = match.group(0)
        for mutated in mutate_numeric(original):
            new_path = parsed.path[: match.start()] + mutated + parsed.path[match.end() :]
            out.append((urlunparse(parsed._replace(path=new_path)), f"segmen path `{original}` diganti `{mutated}`"))

    for match in UUID_RE.finditer(parsed.path):
        original = match.group(0)
        for mutated in mutate_uuid(original):
            new_path = parsed.path[: match.start()] + mutated + parsed.path[match.end() :]
            out.append((urlunparse(parsed._replace(path=new_path)), f"UUID path `{original}` diganti `{mutated}`"))

    dedup: Dict[str, str] = {}
    for test_url, reason in out:
        dedup.setdefault(test_url, reason)
    return list(dedup.items())[:30]


def wordlist_urls(target: str) -> Iterable[str]:
    parsed = urlparse(target)
    base = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
    for pattern in custom_path_patterns():
        path = pattern if pattern.startswith("/") else f"/{pattern}"
        if "{id}" in path:
            for value in test_id_values():
                yield normalize_url(urljoin(base, path.replace("{id}", value)))
        else:
            yield normalize_url(urljoin(base, path))


def text_similarity(a: str, b: str) -> float:
    a = a[:MAX_BODY]
    b = b[:MAX_BODY]
    return difflib.SequenceMatcher(None, a, b).ratio()


def likely_sensitive(body: str) -> bool:
    sample = body[:MAX_BODY].lower()
    needles = ["email", "phone", "address", "invoice", "token", "api_key", "password", "saldo", "balance", "akun", "profile"]
    return any(item in sample for item in needles)


def response_looks_authenticated(response: requests.Response) -> bool:
    final_url = response.url.lower()
    sample = response.text[:MAX_BODY].lower()
    auth_words = ["login", "signin", "masuk", "password", "forgot password"]
    if response.status_code in {401, 403, 404}:
        return False
    if any(word in final_url for word in ["/login", "/signin", "/auth"]):
        return False
    if response.status_code in {301, 302, 303, 307, 308}:
        return False
    return not (len(sample) < 500 and any(word in sample for word in auth_words))


def meaningful_body(response: requests.Response) -> bool:
    content_type = response.headers.get("content-type", "").lower()
    if response.status_code != 200:
        return False
    if "text/html" not in content_type and "json" not in content_type and "text/plain" not in content_type:
        return False
    return len(response.text.strip()) > 120


def owasp_metadata(severity: str, confidence: int, has_second_account: bool) -> Dict[str, str]:
    if severity == "High":
        impact = "User berpotensi mengakses object atau data milik akun lain melalui perubahan identifier."
        recommendation = "Terapkan server-side object-level authorization pada setiap request. Verifikasi object owner/tenant/role sebelum mengembalikan data."
        validation_notes = "Confidence tinggi hanya diberikan jika respons sukses, konten bermakna, sesi tampak valid, dan pembanding akun lain mendukung."
    elif severity == "Medium":
        impact = "Ada indikasi kontrol akses object belum kuat atau respons mutasi masih membuka data bermakna."
        recommendation = "Tambahkan authorization policy/middleware dan uji negative case untuk object milik user lain."
        validation_notes = "Confidence sedang karena sinyal kuat sebagian, tetapi belum memenuhi seluruh syarat High."
    elif severity == "Info":
        impact = "Kontrol akses tampak menolak akses pada mutasi yang diuji."
        recommendation = "Pertahankan perilaku penolakan akses dan pastikan konsisten di endpoint sejenis."
        validation_notes = "Dicatat sebagai informasi karena status respons menunjukkan akses ditolak."
    else:
        impact = "Sinyal belum cukup kuat untuk menyatakan akses object berhasil, tetapi pola URL layak ditinjau."
        recommendation = "Review manual endpoint ini dan pastikan object-level authorization dilakukan di server."
        validation_notes = "Confidence rendah; temuan tidak dinaikkan severity tanpa bukti akses yang cukup."

    if not has_second_account and severity in {"High", "Medium", "Low"}:
        validation_notes += " Akun B tidak tersedia, sehingga validasi lintas akun lebih terbatas."

    return {
        "impact": impact,
        "recommendation": recommendation,
        "validation_notes": f"{validation_notes} Confidence: {confidence}%.",
    }


def classify(original: requests.Response, mutated: requests.Response, reason: str, second_account: Optional[requests.Response]) -> Tuple[str, str, float, int]:
    similarity = text_similarity(original.text, mutated.text)
    confidence = 20
    if mutated.status_code == 200:
        confidence += 15
    if meaningful_body(mutated):
        confidence += 15
    if response_looks_authenticated(mutated):
        confidence += 15
    if likely_sensitive(mutated.text):
        confidence += 15

    if second_account is not None:
        cross = text_similarity(mutated.text, second_account.text)
        if second_account.status_code == 200 and response_looks_authenticated(second_account):
            confidence += 10
        if mutated.status_code == 200 and cross > 0.86 and meaningful_body(mutated) and response_looks_authenticated(mutated):
            confidence = min(98, confidence + 20)
            return "High", f"Mutasi bisa diakses dan cocok dengan respons akun pembanding. {reason}", cross, confidence

    if original.status_code == mutated.status_code == 200 and similarity > 0.78 and likely_sensitive(mutated.text) and response_looks_authenticated(mutated):
        confidence = min(88, confidence + 10)
        return "Medium", f"Respons mutasi tetap sukses dan memuat indikator data sensitif. {reason}", similarity, confidence
    if mutated.status_code == 200 and original.status_code in {401, 403, 404} and response_looks_authenticated(mutated):
        confidence = min(82, confidence + 8)
        return "Medium", f"URL mutasi sukses saat baseline tidak sukses. {reason}", 0, confidence
    if mutated.status_code in {401, 403, 404}:
        return "Info", f"Kontrol akses tampak menolak mutasi. {reason}", similarity, min(confidence, 55)
    return "Low", f"Sinyal belum cukup kuat, tetapi URL layak ditinjau. {reason}", similarity, min(confidence, 65)


def serialize_job(job: ScanJob) -> Dict[str, object]:
    data = asdict(job)
    data["findings"] = [asdict(finding) for finding in job.findings]
    return data


def save_history() -> None:
    with JOBS_LOCK:
        data = [serialize_job(job) for job in sorted(JOBS.values(), key=lambda item: item.created_at, reverse=True)]
    HISTORY_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=True), encoding="utf-8")


def load_history() -> None:
    if not HISTORY_FILE.exists():
        return
    try:
        raw = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(raw, list):
        return
    with JOBS_LOCK:
        for item in raw:
            if not isinstance(item, dict) or not item.get("id"):
                continue
            findings = []
            for finding in item.get("findings", []):
                if isinstance(finding, dict):
                    finding_data = {
                        "severity": str(finding.get("severity", "Low")),
                        "kind": str(finding.get("kind", "IDOR candidate")),
                        "original_url": str(finding.get("original_url", "")),
                        "test_url": str(finding.get("test_url", "")),
                        "evidence": str(finding.get("evidence", "")),
                        "status_a": int(finding.get("status_a", 0) or 0),
                        "status_b": finding.get("status_b"),
                        "similarity": float(finding.get("similarity", 0) or 0),
                        "elapsed_ms": int(finding.get("elapsed_ms", 0) or 0),
                        "confidence": int(finding.get("confidence", 0) or 0),
                        "owasp_top10": str(finding.get("owasp_top10", "A01:2021 Broken Access Control")),
                        "owasp_wstg": str(finding.get("owasp_wstg", "WSTG-ATHZ Authorization Testing")),
                        "owasp_asvs": str(finding.get("owasp_asvs", "ASVS V4 Access Control")),
                        "impact": str(finding.get("impact", "")),
                        "recommendation": str(finding.get("recommendation", "")),
                        "validation_notes": str(finding.get("validation_notes", "")),
                    }
                    if not finding_data["impact"] or not finding_data["recommendation"] or not finding_data["validation_notes"]:
                        metadata = owasp_metadata(
                            finding_data["severity"],
                            finding_data["confidence"],
                            finding.get("status_b") is not None,
                        )
                        finding_data["impact"] = finding_data["impact"] or metadata["impact"]
                        finding_data["recommendation"] = finding_data["recommendation"] or metadata["recommendation"]
                        finding_data["validation_notes"] = finding_data["validation_notes"] or metadata["validation_notes"]
                    findings.append(Finding(**finding_data))
            job = ScanJob(
                id=str(item.get("id")),
                created_at=float(item.get("created_at", time.time())),
                target_url=str(item.get("target_url", "")),
                status=str(item.get("status", "completed")),
                progress=int(item.get("progress", 100)),
                message=str(item.get("message", "")),
                findings=findings,
                visited=[str(value) for value in item.get("visited", []) if isinstance(value, str)],
                discovered_urls=[str(value) for value in item.get("discovered_urls", []) if isinstance(value, str)],
                skipped_unsafe=[str(value) for value in item.get("skipped_unsafe", []) if isinstance(value, str)],
                errors=[str(value) for value in item.get("errors", []) if isinstance(value, str)],
                report_json=str(item.get("report_json", "")),
                report_html=str(item.get("report_html", "")),
                done=bool(item.get("done", True)),
            )
            JOBS[job.id] = job


def generate_reports(job: ScanJob) -> None:
    REPORT_DIR.mkdir(exist_ok=True)
    report_data = serialize_job(job)
    report_data["generated_at"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    report_data["owasp_methodology"] = {
        "top10": "A01:2021 Broken Access Control",
        "wstg": "WSTG-ATHZ Authorization Testing",
        "asvs": "ASVS V4 Access Control",
        "safety": "Scanner only performs GET requests for crawling/testing and skips destructive URL patterns plus non-GET forms.",
        "accuracy": "Severity is conservative: High requires successful authenticated-looking meaningful response and strong cross-account evidence.",
    }

    json_path = REPORT_DIR / f"{job.id}.json"
    html_path = REPORT_DIR / f"{job.id}.html"
    json_path.write_text(json.dumps(report_data, indent=2, ensure_ascii=True), encoding="utf-8")

    findings_html = "\n".join(
        f"""
        <article class="finding {html.escape(finding.severity)}">
          <h3>{html.escape(finding.severity)} - {html.escape(finding.kind)} ({finding.confidence}% confidence)</h3>
          <p><strong>OWASP:</strong> {html.escape(finding.owasp_top10)} | {html.escape(finding.owasp_wstg)} | {html.escape(finding.owasp_asvs)}</p>
          <p>{html.escape(finding.evidence)}</p>
          <p><strong>Impact:</strong> {html.escape(finding.impact)}</p>
          <p><strong>Recommendation:</strong> {html.escape(finding.recommendation)}</p>
          <p><strong>Validation notes:</strong> {html.escape(finding.validation_notes)}</p>
          <p><strong>Original:</strong> {html.escape(finding.original_url)}</p>
          <p><strong>Test:</strong> {html.escape(finding.test_url)}</p>
          <p>Status A: {finding.status_a} | Status B: {html.escape(str(finding.status_b or "-"))} | Similarity: {round(finding.similarity * 100)}%</p>
        </article>
        """
        for finding in job.findings
    ) or "<p>Tidak ada temuan yang dicatat.</p>"

    skipped_html = "\n".join(f"<li>{html.escape(item)}</li>" for item in job.skipped_unsafe) or "<li>Tidak ada endpoint unsafe terdeteksi.</li>"
    html_doc = f"""<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <title>GoodIDOR Report {html.escape(job.id)}</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 32px; color: #172033; line-height: 1.5; }}
    .meta, .finding {{ border: 1px solid #d9e2ef; border-radius: 8px; padding: 16px; margin-bottom: 14px; }}
    .finding {{ border-left: 6px solid #64748b; }}
    .High {{ border-left-color: #dc3545; }}
    .Medium {{ border-left-color: #fd7e14; }}
    .Low {{ border-left-color: #64748b; }}
    .Info {{ border-left-color: #198754; }}
    code {{ background: #f1f5f9; padding: 2px 5px; border-radius: 4px; }}
  </style>
</head>
<body>
  <h1>GoodIDOR Scan Report</h1>
  <section class="meta">
    <p><strong>Job:</strong> {html.escape(job.id)}</p>
    <p><strong>Target:</strong> {html.escape(job.target_url)}</p>
    <p><strong>Status:</strong> {html.escape(job.status)}</p>
    <p><strong>Discovered URL:</strong> {len(job.discovered_urls)} | <strong>Visited:</strong> {len(job.visited)} | <strong>Findings:</strong> {len(job.findings)}</p>
    <p><strong>Safety:</strong> Scanner hanya menjalankan GET untuk crawling/testing. Endpoint POST/PUT/PATCH/DELETE yang ditemukan dilewati.</p>
    <p><strong>OWASP Mapping:</strong> A01:2021 Broken Access Control, WSTG-ATHZ Authorization Testing, ASVS V4 Access Control.</p>
    <p><strong>Akurasi:</strong> Severity dibuat konservatif. High membutuhkan respons sukses, konten bermakna, sesi terlihat valid, dan bukti pembanding akun.</p>
  </section>
  <h2>Checklist Kontrol Akses</h2>
  <ul>
    <li>Object-level authorization diverifikasi di server pada setiap request.</li>
    <li>User A tidak dapat membaca object milik User B.</li>
    <li>Endpoint unsafe tidak dieksekusi scanner dan dicatat sebagai dilewati.</li>
    <li>Respons unauthorized konsisten memakai 403/404 atau redirect login yang jelas.</li>
    <li>Identifier yang mudah ditebak tidak menjadi satu-satunya kontrol keamanan.</li>
  </ul>
  <h2>Temuan</h2>
  {findings_html}
  <h2>Endpoint Unsafe yang Dilewati</h2>
  <ul>{skipped_html}</ul>
</body>
</html>"""
    html_path.write_text(html_doc, encoding="utf-8")
    job.report_json = str(json_path.name)
    job.report_html = str(html_path.name)


def run_scan(job: ScanJob, config: Dict[str, str]) -> None:
    target = normalize_url(config["target_url"])
    job.target_url = target
    save_history()
    max_pages = max(1, min(int(config.get("max_pages") or 80), 300))
    delay = max(0.0, min(float(config.get("delay") or 0.15), 3.0))
    include_js_urls = config.get("include_js_urls", "on") == "on"
    include_sitemap = config.get("include_sitemap", "on") == "on"
    include_wordlist = config.get("include_wordlist", "on") == "on"
    login_url = config.get("login_url", "").strip()
    method = config.get("login_method", "POST")

    session_a = build_account_session(config, "a")
    session_b = build_account_session(config, "b")

    job.status = "running"
    ok_a, msg_a = login(session_a, login_url, method, account_login_fields(config, "a")) if should_submit_login_form(config, "a", login_url) else (True, "Akun A memakai session/token yang diisi.")
    ok_b, msg_b = login(session_b, login_url, method, account_login_fields(config, "b")) if account_has_login_data(config, "b") and should_submit_login_form(config, "b", login_url) else ((True, "Akun B memakai session/token yang diisi.") if account_has_login_data(config, "b") else (False, "Akun kedua tidak diisi."))
    job.message = f"{msg_a} {msg_b}"
    if not ok_a:
        job.errors.append(msg_a)
        job.status = "failed"
        job.done = True
        save_history()
        return

    queue: Queue[str] = Queue()
    queued: Set[str] = {target}
    queue.put(target)
    if target not in job.discovered_urls:
        job.discovered_urls.append(target)

    if include_sitemap:
        for link in sitemap_urls(session_a, target):
            if link not in queued:
                queued.add(link)
                job.discovered_urls.append(link)
                queue.put(link)
        save_history()

    if include_wordlist:
        for link in wordlist_urls(target):
            if same_origin(target, link) and is_safe_discovery_url(link) and link not in queued:
                queued.add(link)
                job.discovered_urls.append(link)
                queue.put(link)
        save_history()

    while not queue.empty() and len(job.visited) < max_pages:
        url = queue.get()
        if not same_origin(target, url):
            continue

        job.message = f"Memeriksa {url}"
        response, elapsed, error = safe_get(session_a, url)
        if error or response is None:
            job.errors.append(f"{url}: {error}")
            continue

        if url not in job.visited:
            job.visited.append(url)
        job.progress = int((len(job.visited) / max_pages) * 100)

        ctype = response.headers.get("content-type", "")
        if "text/html" in ctype or "javascript" in ctype or "json" in ctype:
            if "text/html" in ctype:
                for unsafe in extract_unsafe_forms(url, response.text):
                    if unsafe not in job.skipped_unsafe:
                        job.skipped_unsafe.append(unsafe)
            for link in extract_links(url, response.text, include_js_urls=include_js_urls):
                if same_origin(target, link) and link not in queued and len(queued) < max_pages * 3:
                    queued.add(link)
                    job.discovered_urls.append(link)
                    queue.put(link)
            save_history()

        for test_url, reason in mutation_urls(url):
            if not same_origin(target, test_url) or not is_safe_discovery_url(test_url):
                skipped = f"GET {test_url} dilewati karena pola URL berisiko/destruktif"
                if skipped not in job.skipped_unsafe:
                    job.skipped_unsafe.append(skipped)
                continue
            mutated, mut_elapsed, mut_error = safe_get(session_a, test_url)
            if mut_error or mutated is None:
                job.errors.append(f"{test_url}: {mut_error}")
                continue

            second = None
            if ok_b:
                second, _, _ = safe_get(session_b, test_url)

            severity, evidence, similarity, confidence = classify(response, mutated, reason, second)
            if severity != "Info" or config.get("include_info") == "on":
                metadata = owasp_metadata(severity, confidence, second is not None)
                job.findings.append(
                    Finding(
                        severity=severity,
                        kind="IDOR candidate",
                        original_url=url,
                        test_url=test_url,
                        evidence=evidence,
                        status_a=mutated.status_code,
                        status_b=second.status_code if second is not None else None,
                        similarity=similarity,
                        elapsed_ms=mut_elapsed or elapsed,
                        confidence=confidence,
                        impact=metadata["impact"],
                        recommendation=metadata["recommendation"],
                        validation_notes=metadata["validation_notes"],
                    )
                )
                save_history()
            time.sleep(delay)

        time.sleep(delay)

    job.progress = 100
    job.status = "completed"
    job.message = f"Selesai. {len(job.visited)} halaman dicek, {len(job.findings)} temuan dicatat."
    job.done = True
    generate_reports(job)
    save_history()


def job_history() -> List[Dict[str, object]]:
    with JOBS_LOCK:
        jobs = sorted(JOBS.values(), key=lambda item: item.created_at, reverse=True)
        return [
            {
                "id": job.id,
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(job.created_at)),
                "status": job.status,
                "progress": job.progress,
                "findings": len(job.findings),
                "visited": len(job.visited),
                "discovered": len(job.discovered_urls),
                "errors": len(job.errors),
                "target_url": job.target_url,
                "message": job.message,
                "report_json": job.report_json,
                "report_html": job.report_html,
            }
            for job in jobs
        ]


load_history()


PAGE = r"""
<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GoodIDOR Scanner</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    :root {
      --app-bg:#f4f7fb;
      --ink:#172033;
      --muted:#667085;
      --line:#d9e2ef;
      --surface:#ffffff;
      --soft:#f8fafc;
      --primary:#2563eb;
      --primary-dark:#1e40af;
      --teal:#0f766e;
    }
    body { background:var(--app-bg); color:var(--ink); font-family:"Segoe UI", Inter, system-ui, -apple-system, sans-serif; font-size:15px; letter-spacing:0; }
    .app-shell { max-width:1240px; }
    .topbar { background:linear-gradient(135deg, #0f172a 0%, #1e3a8a 62%, #0f766e 100%); color:#fff; }
    .brand-mark { width:46px; height:46px; border-radius:8px; display:grid; place-items:center; background:rgba(255,255,255,.14); color:#fff; font-weight:800; letter-spacing:0; border:1px solid rgba(255,255,255,.2); }
    .brand-subtitle { color:rgba(255,255,255,.78); }
    .main-menu { display:flex; flex-wrap:wrap; gap:8px; margin-top:18px; }
    .main-menu a { color:rgba(255,255,255,.82); text-decoration:none; padding:9px 13px; border-radius:8px; border:1px solid rgba(255,255,255,.18); font-weight:650; font-size:.92rem; }
    .main-menu a:hover, .main-menu a.active { background:#fff; color:#1e3a8a; }
    .surface-card { background:var(--surface); border:1px solid rgba(31,42,68,.08); border-radius:8px; box-shadow:0 16px 40px rgba(16,24,40,.08); }
    .section-title { font-size:1.08rem; font-weight:750; letter-spacing:0; }
    .section-copy { color:var(--muted); font-size:.9rem; }
    .step-badge { width:34px; height:34px; border-radius:50%; display:inline-grid; place-items:center; background:#eaf2ff; color:var(--primary); font-weight:800; flex:0 0 auto; }
    .step-strip { display:grid; grid-template-columns:repeat(3,1fr); gap:12px; }
    .step-item { background:#fff; border:1px solid var(--line); border-radius:8px; padding:14px; display:flex; gap:12px; align-items:flex-start; }
    .step-target { border-color:#bfdbfe; background:#eff6ff; }
    .step-target .step-badge { background:#dbeafe; color:#1d4ed8; }
    .step-account { border-color:#99f6e4; background:#f0fdfa; }
    .step-account .step-badge { background:#ccfbf1; color:#0f766e; }
    .step-scan { border-color:#fde68a; background:#fffbeb; }
    .step-scan .step-badge { background:#fef3c7; color:#b45309; }
    .stage-card { border:1px solid rgba(31,42,68,.08); border-radius:8px; background:#fff; box-shadow:0 12px 32px rgba(16,24,40,.07); overflow:hidden; }
    .stage-head { display:flex; align-items:flex-start; gap:12px; padding:18px 20px; border-bottom:1px solid var(--line); }
    .stage-body { padding:20px; }
    .stage-card.stage-target { border-top:5px solid #2563eb; }
    .stage-card.stage-target .stage-head { background:#eff6ff; }
    .stage-card.stage-account { border-top:5px solid #0f766e; }
    .stage-card.stage-account .stage-head { background:#f0fdfa; }
    .stage-card.stage-scan { border-top:5px solid #f59e0b; }
    .stage-card.stage-scan .stage-head { background:#fffbeb; }
    .form-label { margin-bottom:.42rem; color:#344054; }
    .form-control, .form-select { border-color:#cfd8e6; min-height:42px; }
    .form-control:focus, .form-select:focus { border-color:var(--primary); box-shadow:0 0 0 .2rem rgba(37,99,235,.12); }
    .form-control, .form-select, .accordion-button, .btn { border-radius:8px; }
    .nav-pills .nav-link { border-radius:8px; color:#475467; font-weight:650; }
    .nav-pills .nav-link.active { background:var(--primary); }
    .card { border-radius:8px; }
    .form-textarea { min-height:92px; font-family:ui-monospace, SFMono-Regular, Consolas, monospace; font-size:12px; }
    .auth-panel { background:var(--soft); border:1px solid #e5eaf2; border-radius:8px; padding:16px; }
    .btn-primary { background:var(--primary); border-color:var(--primary); }
    .btn-primary:hover { background:var(--primary-dark); border-color:var(--primary-dark); }
    .metric-box { background:#f8fafc; border:1px solid #e8eef7; border-radius:8px; padding:14px; }
    .url-text { overflow-wrap:anywhere; font-family:ui-monospace, SFMono-Regular, Consolas, monospace; font-size:12px; }
    .finding-card { border-left:5px solid #6c757d; box-shadow:none; }
    .finding-card.High { border-left-color:#dc3545; }
    .finding-card.Medium { border-left-color:#fd7e14; }
    .finding-card.Low { border-left-color:#6c757d; }
    .finding-card.Info { border-left-color:#198754; }
    .helper-list { margin:0; padding-left:1.15rem; color:var(--muted); }
    .permission-note { background:#fff7ed; border:1px solid #fed7aa; color:#7c2d12; border-radius:8px; padding:12px 14px; }
    @media (max-width: 991.98px) {
      .step-strip { grid-template-columns:1fr; }
      .surface-card { box-shadow:0 10px 26px rgba(16,24,40,.07); }
    }
    @media (max-width: 575.98px) {
      body { font-size:14px; }
      .brand-mark { width:40px; height:40px; }
      .main-menu { display:grid; grid-template-columns:1fr; }
      .main-menu a { text-align:center; }
      .surface-card .card-body, .stage-body { padding:18px !important; }
      .stage-head { padding:16px 18px; }
      .nav-pills { gap:8px !important; }
      .nav-pills .nav-item { flex:1 1 100%; }
    }
  </style>
</head>
<body>
  <nav class="topbar">
    <div class="container app-shell py-4">
      <div class="d-flex flex-column flex-lg-row align-items-start align-items-lg-center justify-content-between gap-3">
        <div class="d-flex align-items-center gap-3">
          <div class="brand-mark">GI</div>
          <div>
            <h1 class="h3 mb-1 fw-bold">GoodIDOR Scanner</h1>
            <div class="brand-subtitle">Audit IDOR ringan dengan alur input yang sederhana</div>
          </div>
        </div>
        <div>
          <div class="main-menu" aria-label="Menu utama">
            <a class="{{ 'active' if page == 'home' else '' }}" href="{{ url_for('index') }}">Beranda</a>
            <a class="{{ 'active' if page == 'features' else '' }}" href="{{ url_for('features') }}">Fitur</a>
            <a class="{{ 'active' if page == 'owasp' else '' }}" href="{{ url_for('owasp_check') }}">OWASP Check</a>
            <a class="{{ 'active' if page == 'history' else '' }}" href="{{ url_for('history') }}">History Scan</a>
            <a class="{{ 'active' if page == 'about' else '' }}" href="{{ url_for('about') }}">About</a>
          </div>
        </div>
      </div>
    </div>
  </nav>

  <main class="container app-shell py-4 py-lg-5">
    {% if page == 'home' %}
    <div class="permission-note mb-4" role="alert">
      <strong>Catatan izin:</strong> gunakan scanner ini hanya pada website milik sendiri, lab, atau target yang sudah memberi izin uji.
    </div>

    <section class="step-strip mb-4" aria-label="Tahapan scan">
      <div class="step-item step-target">
        <span class="step-badge">1</span>
        <div>
          <div class="fw-bold">Target</div>
          <div class="small text-secondary">Masukkan URL yang memiliki ID.</div>
        </div>
      </div>
      <div class="step-item step-account">
        <span class="step-badge">2</span>
        <div>
          <div class="fw-bold">Akun</div>
          <div class="small text-secondary">Isi login Akun A dan opsional Akun B.</div>
        </div>
      </div>
      <div class="step-item step-scan">
        <span class="step-badge">3</span>
        <div>
          <div class="fw-bold">Scan</div>
          <div class="small text-secondary">Pantau hasil dan prioritas temuan.</div>
        </div>
      </div>
    </section>

    <div class="row g-4">
      <div class="col-lg-6">
        <form action="/scan" method="post" class="d-grid gap-3">
          <section class="stage-card stage-target">
            <div class="stage-head">
              <span class="step-badge">1</span>
              <div>
                <h2 class="section-title mb-0">Masukkan Target</h2>
                <div class="section-copy">Pilih halaman yang punya ID, misalnya profil atau invoice.</div>
              </div>
            </div>

            <div class="stage-body">
            <div class="mb-3">
              <label class="form-label fw-semibold" for="target_url">URL yang ingin dicek</label>
              <input id="target_url" name="target_url" type="url" class="form-control form-control-lg" required placeholder="http://localhost/profile/1">
              <div class="form-text">Contoh bagus: <code>/profile/1</code>, <code>/orders?id=10</code>, atau <code>/invoice/1001</code>.</div>
            </div>
            </div>
          </section>

          <section class="stage-card stage-account">
            <div class="stage-head">
              <span class="step-badge">2</span>
              <div>
                <h2 class="section-title mb-0">Login Akun</h2>
                <div class="section-copy">Minimal isi Akun A. Akun B membuat hasil lebih akurat.</div>
              </div>
            </div>

            <div class="stage-body">
            <div class="row g-3">
              <div class="col-md-8">
                <label class="form-label fw-semibold" for="login_url">URL login</label>
                <input id="login_url" name="login_url" type="url" class="form-control" placeholder="http://localhost/login">
              </div>
              <div class="col-md-4">
                <label class="form-label fw-semibold" for="login_method">Metode</label>
                <select id="login_method" name="login_method" class="form-select">
                  <option>POST</option>
                  <option>GET</option>
                </select>
              </div>
            </div>

            <ul class="nav nav-pills nav-fill gap-2 my-3" id="accountTabs" role="tablist">
              <li class="nav-item" role="presentation">
                <button class="nav-link active" id="account-a-tab" data-bs-toggle="tab" data-bs-target="#account-a" type="button" role="tab">Akun A</button>
              </li>
              <li class="nav-item" role="presentation">
                <button class="nav-link" id="account-b-tab" data-bs-toggle="tab" data-bs-target="#account-b" type="button" role="tab">Akun B</button>
              </li>
            </ul>

            <div class="tab-content">
              <section class="tab-pane fade show active" id="account-a" role="tabpanel" aria-labelledby="account-a-tab">
                <div class="mb-3">
                  <label class="form-label fw-semibold" for="auth_mode_a">Cara login Akun A</label>
                  <select id="auth_mode_a" name="auth_mode_a" class="form-select auth-mode" data-prefix="a">
                    <option value="form" selected>Username dan password</option>
                    <option value="cookie">Cookie session</option>
                    <option value="token">Bearer token / API token</option>
                    <option value="custom">Header custom</option>
                  </select>
                  <div class="form-text">Pakai pilihan pertama kalau kamu punya halaman login biasa.</div>
                </div>
                <div class="auth-panel auth-fields auth-fields-a auth-form-a">
                <div class="row g-3 mb-3">
                  <div class="col-md-6">
                    <label class="form-label fw-semibold" for="username_a">Username Akun A</label>
                    <input id="username_a" name="username_a" class="form-control" autocomplete="username" placeholder="user1">
                  </div>
                  <div class="col-md-6">
                    <label class="form-label fw-semibold" for="password_a">Password Akun A</label>
                    <input id="password_a" name="password_a" class="form-control" type="password" autocomplete="current-password" placeholder="password">
                  </div>
                  <div class="col-md-6">
                    <label class="form-label fw-semibold" for="username_field_a">Nama field username</label>
                    <input id="username_field_a" name="username_field_a" class="form-control" value="username" placeholder="username">
                    <div class="form-text">Kalau form login pakai email, ganti jadi <code>email</code>.</div>
                  </div>
                  <div class="col-md-6">
                    <label class="form-label fw-semibold" for="password_field_a">Nama field password</label>
                    <input id="password_field_a" name="password_field_a" class="form-control" value="password" placeholder="password">
                  </div>
                </div>
                </div>
                <div class="auth-panel auth-fields auth-fields-a auth-cookie-a d-none mb-3">
                  <label class="form-label fw-semibold" for="cookie_a">Cookie Akun A</label>
                  <textarea id="cookie_a" name="cookie_a" class="form-control form-textarea" placeholder="session=abc123"></textarea>
                  <div class="form-text">Default paling umum adalah <code>session=...</code>. Ambil dari DevTools browser bagian Application atau Storage.</div>
                </div>
                <div class="auth-panel auth-fields auth-fields-a auth-token-a d-none mb-3">
                  <label class="form-label fw-semibold" for="token_a">Bearer token Akun A</label>
                  <input id="token_a" name="token_a" class="form-control" placeholder="eyJhbGciOi...">
                  <div class="form-text">Tool otomatis mengubahnya menjadi header <code>Authorization: Bearer token</code>.</div>
                </div>
                <div class="auth-panel auth-fields auth-fields-a auth-custom-a d-none mb-3">
                  <label class="form-label fw-semibold" for="headers_a">Header custom Akun A</label>
                  <textarea id="headers_a" name="headers_a" class="form-control form-textarea" placeholder="Authorization: Bearer token&#10;X-CSRF-Token: token"></textarea>
                  <div class="form-text">Satu baris satu header. Gunakan ini kalau aplikasi butuh header khusus.</div>
                </div>
                <div class="accordion" id="advancedA">
                  <div class="accordion-item">
                    <h3 class="accordion-header">
                      <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#advancedAContent">Opsional: field tambahan Akun A</button>
                    </h3>
                    <div id="advancedAContent" class="accordion-collapse collapse" data-bs-parent="#advancedA">
                      <div class="accordion-body">
                        <label class="form-label fw-semibold" for="fields_a">Data login manual Akun A</label>
                        <textarea id="fields_a" name="fields_a" class="form-control form-textarea mb-3" placeholder="role=user&remember=1"></textarea>
                        <div class="form-text mb-3">Isi ini hanya kalau form login punya field tambahan seperti CSRF, role, atau remember.</div>
                      </div>
                    </div>
                  </div>
                </div>
              </section>

              <section class="tab-pane fade" id="account-b" role="tabpanel" aria-labelledby="account-b-tab">
                <div class="mb-3">
                  <label class="form-label fw-semibold" for="auth_mode_b">Cara login Akun B</label>
                  <select id="auth_mode_b" name="auth_mode_b" class="form-select auth-mode" data-prefix="b">
                    <option value="form" selected>Username dan password</option>
                    <option value="cookie">Cookie session</option>
                    <option value="token">Bearer token / API token</option>
                    <option value="custom">Header custom</option>
                  </select>
                  <div class="form-text">Isi Akun B kalau kamu punya user pembanding.</div>
                </div>
                <div class="auth-panel auth-fields auth-fields-b auth-form-b">
                <div class="row g-3 mb-3">
                  <div class="col-md-6">
                    <label class="form-label fw-semibold" for="username_b">Username Akun B</label>
                    <input id="username_b" name="username_b" class="form-control" autocomplete="username" placeholder="user2">
                  </div>
                  <div class="col-md-6">
                    <label class="form-label fw-semibold" for="password_b">Password Akun B</label>
                    <input id="password_b" name="password_b" class="form-control" type="password" autocomplete="current-password" placeholder="password">
                  </div>
                  <div class="col-md-6">
                    <label class="form-label fw-semibold" for="username_field_b">Nama field username</label>
                    <input id="username_field_b" name="username_field_b" class="form-control" value="username" placeholder="username">
                    <div class="form-text">Samakan dengan Akun A. Contoh: <code>email</code>.</div>
                  </div>
                  <div class="col-md-6">
                    <label class="form-label fw-semibold" for="password_field_b">Nama field password</label>
                    <input id="password_field_b" name="password_field_b" class="form-control" value="password" placeholder="password">
                  </div>
                  <div class="col-12">
                    <div class="form-text">Akun B dipakai sebagai pembanding apakah data user lain ikut terbuka.</div>
                  </div>
                </div>
                </div>
                <div class="auth-panel auth-fields auth-fields-b auth-cookie-b d-none mb-3">
                  <label class="form-label fw-semibold" for="cookie_b">Cookie Akun B</label>
                  <textarea id="cookie_b" name="cookie_b" class="form-control form-textarea" placeholder="session=def456"></textarea>
                  <div class="form-text">Biasanya cukup isi cookie session dari akun kedua.</div>
                </div>
                <div class="auth-panel auth-fields auth-fields-b auth-token-b d-none mb-3">
                  <label class="form-label fw-semibold" for="token_b">Bearer token Akun B</label>
                  <input id="token_b" name="token_b" class="form-control" placeholder="eyJhbGciOi...">
                </div>
                <div class="auth-panel auth-fields auth-fields-b auth-custom-b d-none mb-3">
                  <label class="form-label fw-semibold" for="headers_b">Header custom Akun B</label>
                  <textarea id="headers_b" name="headers_b" class="form-control form-textarea" placeholder="Authorization: Bearer token-lain"></textarea>
                </div>
                <div class="accordion" id="advancedB">
                  <div class="accordion-item">
                    <h3 class="accordion-header">
                      <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#advancedBContent">Opsional: field tambahan Akun B</button>
                    </h3>
                    <div id="advancedBContent" class="accordion-collapse collapse" data-bs-parent="#advancedB">
                      <div class="accordion-body">
                        <label class="form-label fw-semibold" for="fields_b">Data login manual Akun B</label>
                        <textarea id="fields_b" name="fields_b" class="form-control form-textarea mb-3" placeholder="role=user&remember=1"></textarea>
                        <div class="form-text mb-3">Isi ini hanya kalau form login punya field tambahan.</div>
                      </div>
                    </div>
                  </div>
                </div>
              </section>
            </div>
            </div>
          </section>

          <section class="stage-card stage-scan">
            <div class="stage-head">
              <span class="step-badge">3</span>
              <div>
                <h2 class="section-title mb-0">Atur Scan</h2>
                <div class="section-copy">Default aman untuk belajar dan cukup cepat.</div>
              </div>
            </div>

            <div class="stage-body">
            <div class="row g-3">
              <div class="col-6">
                <label class="form-label fw-semibold" for="max_pages">Maks halaman</label>
                <input id="max_pages" name="max_pages" class="form-control" type="number" min="1" max="300" value="80">
              </div>
              <div class="col-6">
                <label class="form-label fw-semibold" for="delay">Delay request</label>
                <input id="delay" name="delay" class="form-control" type="number" min="0" max="3" step="0.05" value="0.15">
              </div>
            </div>
            <div class="form-check form-switch my-3">
              <input class="form-check-input" name="include_info" type="checkbox" role="switch" id="include_info">
              <label class="form-check-label" for="include_info">Tampilkan juga hasil aman/info</label>
            </div>
            <div class="auth-panel mb-3">
              <div class="fw-semibold mb-2">Cakupan crawler</div>
              <div class="form-check">
                <input class="form-check-input" name="include_sitemap" type="checkbox" id="include_sitemap" checked>
                <label class="form-check-label" for="include_sitemap">Cek <code>/sitemap.xml</code> jika tersedia</label>
              </div>
              <div class="form-check">
                <input class="form-check-input" name="include_js_urls" type="checkbox" id="include_js_urls" checked>
                <label class="form-check-label" for="include_js_urls">Cari link di HTML, JavaScript, src, action, dan data-url</label>
              </div>
              <div class="form-check">
                <input class="form-check-input" name="include_wordlist" type="checkbox" id="include_wordlist" checked>
                <label class="form-check-label" for="include_wordlist">Gunakan wordlist custom dari folder <code>wordlists</code></label>
              </div>
              <div class="form-text mt-2">Mode aman aktif: scanner hanya memakai GET untuk crawling/testing. Form POST dan endpoint PUT/PATCH/DELETE dicatat sebagai dilewati.</div>
            </div>
            <button type="submit" class="btn btn-primary btn-lg w-100">Mulai Scan Sekarang</button>
            </div>
          </section>
        </form>
      </div>

      <div class="col-lg-6">
        <section class="card surface-card border-0 mb-4">
          <div class="card-body p-4">
            <div class="d-flex justify-content-between align-items-start gap-3">
              <div>
                <h2 class="section-title mb-1">Hasil Scan</h2>
                <p class="text-secondary mb-0" id="status">{% if job %}{{ job.message }}{% else %}Belum ada scan berjalan. Isi form di kiri lalu klik mulai.{% endif %}</p>
              </div>
              {% if job %}
                <span class="badge text-bg-secondary">Job {{ job.id }}</span>
              {% endif %}
            </div>
            <div class="progress mt-3" role="progressbar" aria-label="Progress scan">
              <div id="progress" class="progress-bar progress-bar-striped progress-bar-animated" style="width:{{ job.progress if job else 0 }}%">{{ job.progress if job else 0 }}%</div>
            </div>
            <div class="row g-3 mt-2">
              <div class="col-sm-3">
                <div class="metric-box">
                  <div class="text-secondary small">Temuan</div>
                  <div class="h4 mb-0" id="findingCount">0</div>
                </div>
              </div>
              <div class="col-sm-3">
                <div class="metric-box">
                  <div class="text-secondary small">Halaman dicek</div>
                  <div class="h4 mb-0" id="visitedCount">0</div>
                </div>
              </div>
              <div class="col-sm-3">
                <div class="metric-box">
                  <div class="text-secondary small">URL ditemukan</div>
                  <div class="h4 mb-0" id="discoveredCount">0</div>
                </div>
              </div>
              <div class="col-sm-3">
                <div class="metric-box">
                  <div class="text-secondary small">Error</div>
                  <div class="h4 mb-0" id="errorCount">0</div>
                </div>
              </div>
            </div>
            <div id="reportLinks" class="mt-3"></div>
            <div id="results" class="mt-3"></div>
          </div>
        </section>

        <section class="card surface-card border-0">
          <div class="card-body p-4">
            <h2 class="section-title mb-3">Panduan Cepat</h2>
            <ol class="helper-list">
              <li>Buka aplikasi lab atau website milik sendiri.</li>
              <li>Login sebagai user pertama, lalu masukkan URL target yang mengandung angka ID.</li>
              <li>Isi Akun A. Tambahkan Akun B kalau tersedia supaya hasil lebih kuat.</li>
              <li>Mulai scan dan cek temuan dengan label High atau Medium lebih dulu.</li>
            </ol>
          </div>
        </section>
      </div>
    </div>
    {% elif page == 'history' %}
    <section class="card surface-card border-0">
      <div class="card-body p-4">
        <div class="d-flex flex-column flex-md-row justify-content-between gap-3 mb-4">
          <div>
            <h2 class="section-title mb-1">History Scan</h2>
            <p class="text-secondary mb-0">Daftar scan tersimpan permanen di file <code>scan_history.json</code>.</p>
          </div>
          <a class="btn btn-primary align-self-md-start" href="{{ url_for('index') }}">Scan Baru</a>
        </div>
        {% if history %}
          <div class="table-responsive">
            <table class="table align-middle">
              <thead>
                <tr>
                  <th>Waktu</th>
                  <th>Job</th>
                  <th>Target</th>
                  <th>Status</th>
                  <th>Progress</th>
                  <th>Halaman</th>
                  <th>Ditemukan</th>
                  <th>Temuan</th>
                  <th>Error</th>
                  <th>Report</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {% for item in history %}
                <tr>
                  <td class="text-nowrap">{{ item.created_at }}</td>
                  <td><code>{{ item.id }}</code></td>
                  <td class="url-text">{{ item.target_url or '-' }}</td>
                  <td><span class="badge text-bg-secondary">{{ item.status }}</span></td>
                  <td>{{ item.progress }}%</td>
                  <td>{{ item.visited }}</td>
                  <td>{{ item.discovered }}</td>
                  <td>{{ item.findings }}</td>
                  <td>{{ item.errors }}</td>
                  <td>
                    {% if item.report_html %}
                      <a class="btn btn-sm btn-outline-success" href="{{ url_for('report_file', job_id=item.id, kind='html') }}">HTML</a>
                    {% else %}
                      <span class="text-secondary small">-</span>
                    {% endif %}
                  </td>
                  <td><a class="btn btn-sm btn-outline-primary" href="{{ url_for('job_view', job_id=item.id) }}">Detail</a></td>
                </tr>
                {% endfor %}
              </tbody>
            </table>
          </div>
        {% else %}
          <div class="alert alert-light border mb-0">Belum ada history scan. Mulai scan dari halaman Beranda.</div>
        {% endif %}
      </div>
    </section>
    {% elif page == 'owasp' %}
    <div class="row g-4">
      <div class="col-lg-7">
        <section class="card surface-card border-0 h-100">
          <div class="card-body p-4">
            <h2 class="section-title mb-3">OWASP Access Control Check</h2>
            <p class="text-secondary">GoodIDOR memetakan temuan IDOR ke kontrol akses OWASP dengan severity konservatif. Fokus utamanya adalah object-level authorization, bukan sekadar apakah user sudah login.</p>
            <div class="row g-3">
              <div class="col-md-4">
                <div class="metric-box h-100">
                  <div class="text-secondary small">OWASP Top 10</div>
                  <div class="fw-bold">A01:2021 Broken Access Control</div>
                </div>
              </div>
              <div class="col-md-4">
                <div class="metric-box h-100">
                  <div class="text-secondary small">OWASP WSTG</div>
                  <div class="fw-bold">WSTG-ATHZ Authorization Testing</div>
                </div>
              </div>
              <div class="col-md-4">
                <div class="metric-box h-100">
                  <div class="text-secondary small">OWASP ASVS</div>
                  <div class="fw-bold">ASVS V4 Access Control</div>
                </div>
              </div>
            </div>
          </div>
        </section>
      </div>
      <div class="col-lg-5">
        <section class="card surface-card border-0 h-100">
          <div class="card-body p-4">
            <h2 class="section-title mb-3">Aturan Akurasi</h2>
            <ul class="helper-list">
              <li><strong>High</strong> hanya jika akses sukses, konten bermakna, sesi tampak valid, dan bukti Akun B kuat.</li>
              <li><strong>Medium</strong> untuk indikasi kuat tanpa semua syarat High.</li>
              <li><strong>Low</strong> untuk sinyal lemah yang tidak cukup sebagai bukti akses.</li>
              <li><strong>Info</strong> untuk kontrol akses yang tampak menolak mutasi.</li>
            </ul>
          </div>
        </section>
      </div>
      <div class="col-12">
        <section class="card surface-card border-0">
          <div class="card-body p-4">
            <h2 class="section-title mb-3">Checklist Remediation</h2>
            <div class="row g-3">
              <div class="col-md-6">
                <ul class="helper-list">
                  <li>Validasi ownership object di server pada setiap endpoint.</li>
                  <li>Jangan percaya ID dari URL, form, cookie, atau client-side state.</li>
                  <li>Gunakan policy/middleware authorization per resource.</li>
                  <li>Pastikan tenant/account boundary selalu dicek.</li>
                </ul>
              </div>
              <div class="col-md-6">
                <ul class="helper-list">
                  <li>Return 403/404 atau redirect login secara konsisten.</li>
                  <li>Tambahkan test negative case: User A mencoba object User B.</li>
                  <li>Log akses object sensitif dan anomali enumerasi ID.</li>
                  <li>Hindari endpoint destruktif via GET.</li>
                </ul>
              </div>
            </div>
          </div>
        </section>
      </div>
    </div>
    {% elif page == 'features' %}
    <div class="row g-4">
      <div class="col-lg-4">
        <section class="stage-card stage-target h-100">
          <div class="stage-head">
            <span class="step-badge">1</span>
            <div>
              <h2 class="section-title mb-0">Target Discovery</h2>
              <div class="section-copy">Crawler ringan satu host.</div>
            </div>
          </div>
          <div class="stage-body">
            <ul class="helper-list">
              <li>Scan tetap di domain target yang sama.</li>
              <li>Mendeteksi menu/link dari HTML, src, action, data-url, JavaScript string, dan sitemap.</li>
              <li>Mencari parameter ID, angka di path URL, dan UUID.</li>
              <li>Memuat pola endpoint custom dari <code>wordlists/paths.txt</code>.</li>
              <li>Mencatat endpoint POST/PUT/PATCH/DELETE sebagai dilewati.</li>
            </ul>
          </div>
        </section>
      </div>
      <div class="col-lg-4">
        <section class="stage-card stage-account h-100">
          <div class="stage-head">
            <span class="step-badge">2</span>
            <div>
              <h2 class="section-title mb-0">Login & Pembanding</h2>
              <div class="section-copy">Akun A dan opsional Akun B.</div>
            </div>
          </div>
          <div class="stage-body">
            <ul class="helper-list">
              <li>Login username/password.</li>
              <li>Cookie session, bearer token, atau header custom.</li>
              <li>Pembanding Akun B untuk meningkatkan confidence.</li>
            </ul>
          </div>
        </section>
      </div>
      <div class="col-lg-4">
        <section class="stage-card stage-scan h-100">
          <div class="stage-head">
            <span class="step-badge">3</span>
            <div>
              <h2 class="section-title mb-0">Validasi Temuan</h2>
              <div class="section-copy">Lebih ketat dan transparan.</div>
            </div>
          </div>
          <div class="stage-body">
            <ul class="helper-list">
              <li>Mutasi ID pada query dan path.</li>
              <li>Nama parameter ID bisa dicustom di <code>wordlists/parameters.txt</code>.</li>
              <li>Nilai ID uji bisa dicustom di <code>wordlists/ids.txt</code>.</li>
              <li>Skor confidence pada tiap temuan.</li>
              <li>History tersimpan di <code>scan_history.json</code>.</li>
              <li>Report otomatis JSON dan HTML per scan.</li>
            </ul>
          </div>
        </section>
      </div>
      <div class="col-12">
        <section class="card surface-card border-0">
          <div class="card-body p-4">
            <h2 class="section-title mb-2">Catatan Akurasi</h2>
            <p class="text-secondary mb-0">Scanner dibuat lebih konservatif: label High membutuhkan respons sukses, konten bermakna, indikasi sesi valid, dan kecocokan kuat dengan akun pembanding. Tetap gunakan review manual sebagai konfirmasi akhir, terutama sebelum membuat laporan resmi.</p>
          </div>
        </section>
      </div>
    </div>
    {% elif page == 'about' %}
    <div class="row g-4">
      <div class="col-lg-7">
        <section class="card surface-card border-0 h-100">
          <div class="card-body p-4">
            <h2 class="section-title mb-3">About GoodIDOR Scanner</h2>
            <p class="text-secondary">GoodIDOR Scanner adalah tool Flask sederhana untuk membantu belajar dan melakukan audit awal terhadap potensi IDOR pada aplikasi yang kamu miliki atau sudah mendapat izin uji.</p>
            <div class="row g-3 mt-2">
              <div class="col-md-6">
                <div class="metric-box">
                  <div class="text-secondary small">Jenis lisensi</div>
                  <div class="fw-bold">MIT License</div>
                </div>
              </div>
              <div class="col-md-6">
                <div class="metric-box">
                  <div class="text-secondary small">Dibuat oleh</div>
                  <div class="fw-bold">Dedi Julyan Sukawanto</div>
                </div>
              </div>
            </div>
          </div>
        </section>
      </div>
      <div class="col-lg-5">
        <section class="card surface-card border-0 h-100">
          <div class="card-body p-4">
            <h2 class="section-title mb-3">Batas Penggunaan</h2>
            <ul class="helper-list">
              <li>Gunakan hanya pada sistem sendiri, lab, atau target yang sudah memberi izin.</li>
              <li>Hasil scanner memakai confidence score, tetapi tetap perlu konfirmasi akhir.</li>
              <li>History scan tersimpan di file <code>scan_history.json</code>.</li>
            </ul>
            <h2 class="section-title mt-4 mb-3">Wordlist Custom</h2>
            <ul class="helper-list">
              <li><code>wordlists/paths.txt</code> untuk pola URL seperti <code>/profile/{id}</code>.</li>
              <li><code>wordlists/parameters.txt</code> untuk nama parameter ID.</li>
              <li><code>wordlists/ids.txt</code> untuk nilai ID yang akan dicoba.</li>
            </ul>
          </div>
        </section>
      </div>
    </div>
    {% endif %}
  </main>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    const jobId = {{ job.id|tojson if job else 'null' }};
    function updateAuthMode(prefix){
      const mode = document.getElementById('auth_mode_' + prefix).value;
      document.querySelectorAll('.auth-fields-' + prefix).forEach(el => el.classList.add('d-none'));
      const active = document.querySelector('.auth-' + mode + '-' + prefix);
      if(active) active.classList.remove('d-none');
    }
    document.querySelectorAll('.auth-mode').forEach(select => {
      select.addEventListener('change', () => updateAuthMode(select.dataset.prefix));
      updateAuthMode(select.dataset.prefix);
    });
    function esc(s){return (s ?? '').toString().replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));}
    function badgeClass(severity){
      return {High:'danger', Medium:'warning', Low:'secondary', Info:'success'}[severity] || 'secondary';
    }
    async function poll(){
      if(!jobId) return;
      const r = await fetch('/api/job/' + jobId);
      const data = await r.json();
      const progress = document.getElementById('progress');
      document.getElementById('status').textContent = data.message;
      progress.style.width = data.progress + '%';
      progress.textContent = data.progress + '%';
      document.getElementById('findingCount').textContent = data.findings.length;
      document.getElementById('visitedCount').textContent = data.visited.length;
      document.getElementById('discoveredCount').textContent = data.discovered_urls.length;
      document.getElementById('errorCount').textContent = data.errors.length;
      document.getElementById('reportLinks').innerHTML = data.report_html ? `
        <div class="alert alert-success border mb-0">
          Report selesai:
          <a class="alert-link" href="/report/${esc(data.id)}/html">HTML</a>
          <span class="mx-1">|</span>
          <a class="alert-link" href="/report/${esc(data.id)}/json">JSON</a>
          <div class="small mt-1">Endpoint unsafe dilewati: ${esc(data.skipped_unsafe.length)}</div>
        </div>` : '';
      document.getElementById('results').innerHTML = data.findings.map(f => `
        <article class="finding-card ${esc(f.severity)} card mb-3">
          <div class="card-body">
            <div class="d-flex flex-wrap align-items-center gap-2 mb-2">
              <span class="badge text-bg-${badgeClass(f.severity)}">${esc(f.severity)}</span>
              <strong>${esc(f.kind)}</strong>
            </div>
            <p class="mb-2">${esc(f.evidence)}</p>
            <div class="small text-secondary">URL asli</div>
            <div class="url-text mb-2">${esc(f.original_url)}</div>
            <div class="small text-secondary">URL hasil mutasi</div>
            <div class="url-text mb-2">${esc(f.test_url)}</div>
            <div class="small text-secondary">Status: ${esc(f.status_a)}${f.status_b ? ' | Akun B: ' + esc(f.status_b) : ''} | Similarity: ${Math.round((f.similarity || 0)*100)}% | Confidence: ${esc(f.confidence || 0)}% | ${esc(f.elapsed_ms)} ms</div>
            <div class="mt-2 small">
              <div><strong>OWASP:</strong> ${esc(f.owasp_top10 || 'A01:2021 Broken Access Control')} | ${esc(f.owasp_wstg || 'WSTG-ATHZ')} | ${esc(f.owasp_asvs || 'ASVS V4')}</div>
              <div><strong>Impact:</strong> ${esc(f.impact || '-')}</div>
              <div><strong>Rekomendasi:</strong> ${esc(f.recommendation || '-')}</div>
              <div><strong>Validasi:</strong> ${esc(f.validation_notes || '-')}</div>
            </div>
          </div>
        </article>`).join('') || '<div class="alert alert-light border mb-0">Belum ada temuan. Saat scan berjalan, hasil akan muncul otomatis di sini.</div>';
      if(!data.done) setTimeout(poll, 900);
    }
    poll();
  </script>
</body>
</html>
"""


@app.get("/")
def index():
    return render_template_string(PAGE, page="home", job=None, history=[])


@app.post("/scan")
def scan():
    target_url = request.form.get("target_url", "").strip()
    parsed = urlparse(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return "Target URL harus berupa http/https yang valid.", 400

    job = ScanJob(id=uuid.uuid4().hex[:10], created_at=time.time())
    with JOBS_LOCK:
        JOBS[job.id] = job

    config = request.form.to_dict()
    thread = threading.Thread(target=run_scan, args=(job, config), daemon=True)
    thread.start()
    return redirect(url_for("job_view", job_id=job.id))


@app.get("/job/<job_id>")
def job_view(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return redirect(url_for("index"))
    return render_template_string(PAGE, page="home", job=job, history=[])


@app.get("/history")
def history():
    return render_template_string(PAGE, page="history", job=None, history=job_history())


@app.get("/features")
def features():
    return render_template_string(PAGE, page="features", job=None, history=[])


@app.get("/owasp")
def owasp_check():
    return render_template_string(PAGE, page="owasp", job=None, history=[])


@app.get("/about")
def about():
    return render_template_string(PAGE, page="about", job=None, history=[])


@app.get("/api/job/<job_id>")
def job_api(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "job tidak ditemukan"}), 404
    return jsonify(
        {
            "id": job.id,
            "status": job.status,
            "progress": job.progress,
            "message": job.message,
            "done": job.done,
            "visited": job.visited[-50:],
            "discovered_urls": job.discovered_urls[-200:],
            "skipped_unsafe": job.skipped_unsafe[-100:],
            "errors": job.errors[-20:],
            "report_json": job.report_json,
            "report_html": job.report_html,
            "findings": [finding.__dict__ for finding in job.findings],
        }
    )


@app.get("/report/<job_id>/<kind>")
def report_file(job_id: str, kind: str):
    job = JOBS.get(job_id)
    if not job:
        return "Report tidak ditemukan.", 404
    if kind == "html" and job.report_html:
        return send_from_directory(REPORT_DIR, job.report_html)
    if kind == "json" and job.report_json:
        return send_from_directory(REPORT_DIR, job.report_json, mimetype="application/json")
    return "Report belum tersedia.", 404


@app.get("/health")
def health():
    return jsonify({"ok": True, "jobs": len(JOBS)})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
