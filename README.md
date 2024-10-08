# HAProxy Dashboard

HAProxy Dashboard adalah aplikasi web yang dirancang untuk mengelola konfigurasi HAProxy dengan mudah. Aplikasi ini memungkinkan pengguna untuk melakukan operasi CRUD (Create, Read, Update, Delete) pada file konfigurasi HAProxy dan sertifikat SSL, serta memantau status backend dan frontend dengan efisien.

## Fitur

- **Manajemen Konfigurasi HAProxy**: Buat, baca, perbarui, dan hapus konfigurasi HAProxy dengan antarmuka pengguna yang intuitif.
- **Pengelolaan Sertifikat SSL dan DNS**: Kelola sertifikat SSL sekaligus DNS yang sudah di record, termasuk pembuatan dan pembaruan sertifikat.
- **Health Checks**: Konfigurasi health checks untuk backend menggunakan protokol HTTP dan TCP.
- **Frontend dan Backend Dinamis**: Atur nama frontend dan backend secara dinamis berdasarkan input pengguna.
- **Monitoring Statistik**: Lihat statistik dari backend server dan frontend secara real-time.

## Prasyarat

Sebelum memulai, pastikan Anda memiliki hal-hal berikut:

- Python 3.x
- Flask
- HAProxy
- Certbot (serta dengan certificate)

## Instalasi

1. **Install pip (jika belum diinstal):**

   ```bash
   sudo apt install python3-pip

2. **Clone dan masuk ke repositori:**

   ```bash
   git clone https://github.com/lawakobadu/ha1.git
   cd ha1

3. **Prerequisites:**

   Instal Flask dan dependensi aplikasi hanya dengan menjalankan Makefile di cli
   
   ```bash
   make install

5. **Jalankan script:**

   ```bash
   chmod +x install.sh
   ./install.sh

6. **Direktori kerja:**

   Jalur direktori root aplikasi sekarang harus berada di
   
   ```bash
   /etc/haproxy-dashboard

7. **Enjoy:**

   Bukak browser dan tulis url sebagai berikut
   
   ```bash
   https://your-haproxy-server-ip:5000
   ```
   
   Username : admin
   Password : admin123
   Password sudah terenkripsi, silahkan lakukan reset password
