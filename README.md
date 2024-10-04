# HAProxy Manager

HAProxy Manager adalah aplikasi web yang dirancang untuk mengelola konfigurasi HAProxy dengan mudah. Aplikasi ini memungkinkan pengguna untuk melakukan operasi CRUD (Create, Read, Update, Delete) pada file konfigurasi HAProxy dan sertifikat SSL, serta memantau status backend dan frontend dengan efisien.

## Fitur

- **Manajemen Konfigurasi HAProxy**: Buat, baca, perbarui, dan hapus konfigurasi HAProxy dengan antarmuka pengguna yang intuitif.
- **Pengelolaan Sertifikat SSL**: Kelola sertifikat SSL untuk domain yang berbeda, termasuk pembuatan dan pembaruan sertifikat.
- **Health Checks**: Konfigurasi health checks untuk backend menggunakan protokol HTTP dan TCP.
- **Frontend dan Backend Dinamis**: Atur nama frontend dan backend secara dinamis berdasarkan input pengguna.
- **Monitoring Status**: Lihat status dari backend server dan frontend secara real-time.

## Prasyarat

Sebelum memulai, pastikan Anda memiliki hal-hal berikut:

- Python 3.x
- Flask
- HAProxy
- Dependensi yang diperlukan (daftar dependensi di `requirements.txt`)

## Instalasi

1. **Clone repositori ini:**

   ```bash
   git clone https://github.com/username/repo.git
   cd repo
