# GoodIDOR Scanner

GoodIDOR Scanner adalah tool berbasis Flask untuk membantu belajar dan melakukan audit awal terhadap potensi IDOR atau Insecure Direct Object Reference pada aplikasi web yang dimiliki sendiri, lab, atau target yang sudah mendapat izin pengujian.

Tool ini dibuat agar mudah dipakai pemula, tetapi tetap memperhatikan kontrol keamanan, akurasi hasil, dan pemetaan standar OWASP.

## Pembuat

GoodIDOR Scanner dibuat oleh **Dedi Julyan Sukawanto**.

## Lisensi

Tool ini menggunakan **MIT License**.

## Tujuan

IDOR terjadi ketika aplikasi mengizinkan user mengakses object milik user lain hanya dengan mengubah identifier seperti ID, UUID, nomor invoice, atau parameter URL.

Contoh pola yang sering diuji:

```text
/profile/1
/profile/2
/orders?id=1001
/api/users/10
```

GoodIDOR membantu menemukan kandidat endpoint seperti itu, melakukan mutasi ID secara aman, lalu memberikan hasil dengan severity, confidence score, mapping OWASP, dan rekomendasi perbaikan.

## Fitur Utama

- Interface web menggunakan Flask dan Bootstrap 5.
- Crawler internal untuk menemukan menu dan link.
- Deteksi link dari HTML, JavaScript string, `href`, `src`, `action`, `data-url`, dan `/sitemap.xml`.
- Scan tetap dibatasi pada host atau domain target yang sama.
- Login menggunakan username/password, cookie session, bearer token, atau header custom.
- Mendukung pembanding Akun A dan Akun B untuk meningkatkan akurasi validasi.
- Mencari ID dari query parameter, path angka, dan UUID.
- Mendukung wordlist custom melalui file `.txt`.
- Mode aman: hanya menjalankan request `GET` untuk crawling/testing.
- Endpoint unsafe seperti `POST`, `PUT`, `PATCH`, `DELETE`, dan URL berisiko seperti `delete`, `destroy`, `remove`, `hapus`, `logout` dilewati.
- History scan tersimpan di `scan_history.json`.
- Report otomatis dalam format JSON dan HTML.
- Mapping OWASP untuk temuan kontrol akses.

## Struktur File Penting

```text
app.py
scan_history.json
reports/
wordlists/
  paths.txt
  parameters.txt
  ids.txt
```

## Wordlist Custom

GoodIDOR tidak hanya bergantung pada contoh seperti `/profile/1`. Scanner juga bisa memuat pola URL dan ID dari file wordlist.

### `wordlists/paths.txt`

Berisi pola endpoint yang akan dicoba scanner.

Gunakan `{id}` sebagai placeholder.

Contoh:

```text
/profile/{id}
/users/{id}
/api/users/{id}
/admin/user/{id}
```

### `wordlists/parameters.txt`

Berisi nama parameter yang dianggap sebagai object identifier.

Contoh:

```text
id
user_id
invoice_id
file_id
document_id
```

### `wordlists/ids.txt`

Berisi nilai ID yang akan dicoba.

Contoh:

```text
1
2
10
100
1001
```

## Cara Menjalankan

Pastikan dependency sudah tersedia:

```powershell
pip install flask requests beautifulsoup4
```

Jalankan aplikasi:

```powershell
python app.py
```

Buka browser:

```text
http://127.0.0.1:5000
```

## Alur Penggunaan

1. Buka menu **Beranda**.
2. Masukkan target URL.
3. Isi login Akun A.
4. Jika tersedia, isi Akun B sebagai pembanding.
5. Atur jumlah halaman, delay, dan cakupan crawler.
6. Klik **Mulai Scan Sekarang**.
7. Lihat hasil scan realtime.
8. Buka report HTML/JSON setelah scan selesai.

## Menu Aplikasi

### Beranda

Halaman utama untuk menjalankan scan IDOR.

### Fitur

Menjelaskan fitur crawler, login, wordlist, validasi, history, dan report.

### OWASP Check

Menjelaskan mapping OWASP dan checklist kontrol akses.

### History Scan

Menampilkan daftar scan yang tersimpan di `scan_history.json`.

### About

Menampilkan informasi lisensi, pembuat, batas penggunaan, dan wordlist custom.

## Mapping OWASP

GoodIDOR memetakan temuan ke standar berikut:

```text
OWASP Top 10: A01:2021 Broken Access Control
OWASP WSTG: WSTG-ATHZ Authorization Testing
OWASP ASVS: ASVS V4 Access Control
```

Fokus utama pengujian adalah object-level authorization, yaitu memastikan user hanya dapat mengakses object yang memang menjadi haknya.

## Confidence Score

Setiap temuan memiliki confidence score.

GoodIDOR sengaja dibuat konservatif:

- **High** hanya diberikan jika akses sukses, respons bermakna, sesi tampak valid, dan pembanding Akun B mendukung.
- **Medium** diberikan untuk indikasi kuat tetapi belum memenuhi semua syarat High.
- **Low** diberikan untuk sinyal yang perlu ditinjau.
- **Info** diberikan jika kontrol akses tampak menolak mutasi.

## Keamanan Scanner

GoodIDOR dirancang agar lebih aman saat digunakan di lab atau sistem sendiri.

Scanner:

- hanya memakai request `GET` untuk crawling dan testing;
- tidak menjalankan `POST`, `PUT`, `PATCH`, atau `DELETE`;
- mencatat form atau endpoint unsafe sebagai dilewati;
- melewati URL yang mengandung pola destruktif seperti `delete`, `destroy`, `remove`, `hapus`, `logout`, dan `signout`;
- membatasi scan pada host target yang sama.

## Report Otomatis

Setelah scan selesai, GoodIDOR membuat report otomatis di folder:

```text
reports/
```

Format report:

- JSON
- HTML

Report berisi:

- target URL;
- daftar URL ditemukan;
- halaman yang dikunjungi;
- endpoint unsafe yang dilewati;
- daftar finding;
- severity;
- confidence;
- mapping OWASP;
- impact;
- rekomendasi perbaikan;
- catatan validasi.

## Rekomendasi Perbaikan IDOR

Untuk memperbaiki IDOR atau Broken Access Control:

- Validasi ownership object di server pada setiap request.
- Jangan percaya ID yang dikirim dari URL, form, cookie, atau client-side state.
- Gunakan authorization policy atau middleware per resource.
- Pastikan boundary tenant, account, role, dan user selalu dicek.
- Return `403`, `404`, atau redirect login secara konsisten untuk akses tidak sah.
- Tambahkan test negative case, misalnya User A mencoba mengakses object milik User B.
- Hindari endpoint destruktif menggunakan method `GET`.
- Log akses object sensitif dan pola enumerasi ID.

## Batasan

GoodIDOR adalah scanner otomatis, sehingga tetap memiliki batasan:

- Tidak menjalankan JavaScript seperti browser penuh.
- Link yang hanya muncul setelah aksi frontend kompleks mungkin tidak selalu ditemukan.
- Endpoint API runtime dari XHR/fetch tidak selalu terlihat jika tidak ada di HTML atau JavaScript string.
- False positive dan false negative masih mungkin terjadi.
- Validasi manual tetap diperlukan sebelum membuat laporan resmi.

## Catatan Etika

Gunakan GoodIDOR hanya pada:

- aplikasi milik sendiri;
- lab keamanan;
- target yang sudah memberi izin tertulis;
- lingkungan pembelajaran yang legal.

Jangan gunakan tool ini untuk menguji sistem tanpa izin.

## Kesimpulan

GoodIDOR Scanner membantu proses belajar dan audit awal IDOR dengan pendekatan yang mudah digunakan, aman, dan terstruktur. Dengan dukungan crawler internal, wordlist custom, pembanding akun, confidence score, report otomatis, dan mapping OWASP, tool ini dapat menjadi fondasi praktis untuk memahami dan menguji kontrol akses object-level pada aplikasi web.
