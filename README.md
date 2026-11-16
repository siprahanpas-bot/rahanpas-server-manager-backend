# Rahanpas Server Manager — Backend

REST API dan layanan bridge untuk **Rahanpas Server Manager**, dibangun menggunakan **Laravel 13** dan dijalankan secara terpisah menggunakan **Docker Compose** (Nginx, PHP-FPM, PHP-CLI, dan Node.js RDP WebSocket Bridge).

Repository: `git@github.com:siprahanpas-bot/rahanpas-server-manager-backend.git`

---

## 1. Arsitektur & Third-Party yang Terpasang

### Layanan Container (Docker Services)
| Service | Image / Base | Fungsi Utama | Custom Port (`.env`) |
| :--- | :--- | :--- | :--- |
| **`nginx`** | Nginx Alpine | Web server & reverse proxy masuk ke PHP-FPM | `BACKEND_PORT` (default: `8080`) |
| **`php-fpm`** | PHP 8.3 FPM | Menjalankan core aplikasi & API Laravel | Internal (`9000`) |
| **`php-cli`** | PHP 8.3 CLI | Container *on-demand* (`--profile tools`) untuk Artisan (`migrate`, `tinker`, dll.) | - |
| **`rdp-ws`** | Node.js | WebSocket Bridge untuk menghubungkan browser dengan Apache Guacamole (`guacd`) | `RDP_BRIDGE_PUBLIC_PORT` (default: `13002`) |

### Library & Third-Party Utama (`composer.json` & Integrasi)
- **Laravel Framework (`^13.17`)** — Core framework API & manajemen queue/scheduler.
- **Laravel Sanctum (`^4.3`)** — Autentikasi berbasis token untuk komunikasi API Frontend–Backend.
- **phpseclib (`^3.0`)** — Eksekusi perintah SSH, SFTP, dan manajemen file remote server langsung dari PHP tanpa ekstensi sistem tambahan.
- **Apache Guacamole (`guacd`)** — Layanan *remote desktop gateway* eksternal (port default `4822`) yang dihubungkan melalui `rdp-ws` untuk sesi RDP/VNC.
- **OnlyOffice Document Server** — Layanan eksternal (port default `13009`) untuk pratinjau dan pengeditan dokumen langsung di File Manager.
- **Host Database (MySQL / MariaDB)** — Database berjalan langsung di host server (di luar container Docker).

---

## 2. Panduan Deployment (Dari Nol Hingga Siap Pakai)

### Langkah 1: Clone Repository
```bash
git clone git@github.com:siprahanpas-bot/rahanpas-server-manager-backend.git /opt/rahanpas-server-manager/backend
cd /opt/rahanpas-server-manager/backend
Langkah 2: Konfigurasi .env (Custom Port & Database Host)
Salin .env.example menjadi .env:

Bash
cp .env.example .env
nano .env
Sesuaikan parameter penting berikut di .env:

Cuplikan kode
APP_NAME="Rahanpas Server Manager"
APP_ENV=production
APP_DEBUG=false
APP_URL=http://IP_SERVER_ANDA:8080

# 1. Custom Port Docker
BACKEND_PORT=8080
RDP_BRIDGE_PUBLIC_PORT=13002
RDP_BRIDGE_PORT=8080
DOCKER_NETWORK=baota_net

# 2. Koneksi ke Database Host Server
# PENTING: Jangan gunakan 127.0.0.1 dari dalam Docker!
# Gunakan IP Gateway Docker (cek via: ip route | grep docker0) atau IP LAN server.
DB_CONNECTION=mysql
DB_HOST=172.17.0.1
DB_PORT=3306
DB_DATABASE=rahanpas_manager
DB_USERNAME=rahanpas_user
DB_PASSWORD=password_kuat_anda

# 3. Keamanan & Integrasi Third-Party
RDP_BRIDGE_SECRET=isi_random_string_minimal_32_karakter
GUACD_HOST=rahanpas-guacd
GUACD_PORT=4822
ONLYOFFICE_PUBLIC_PORT=13009
ONLYOFFICE_API_BASE_URL=http://rahanpas-backend-nginx/api
ONLYOFFICE_INTERNAL_URL=http://rahanpas-onlyoffice

# 4. Penetapan Akun Super Admin
SUPER_ADMIN_EMAIL=admin@domainanda.com
Catatan Database Host: Pastikan MySQL/MariaDB di host server me-listen pada 0.0.0.0 atau 172.17.0.1 (bind-address) dan user database memiliki hak akses dari subnet Docker (GRANT ALL PRIVILEGES ON rahanpas_manager.* TO 'rahanpas_user'@'172.%' IDENTIFIED BY '...';).

Langkah 3: Buat Docker Network & Build Container
Bash
# Buat network eksternal jika belum tersedia
docker network create baota_net 2>/dev/null || true

# Build dan jalankan seluruh container di background
docker compose up -d --build
Langkah 4: Generate Key & Jalankan Migrasi Database
Gunakan container php-cli agar versi PHP dan ekstensi database selalu konsisten dengan environment production:

Bash
# Generate APP_KEY (jika masih kosong di .env)
docker compose --profile tools run --rm php-cli php artisan key:generate --force

# Jalankan migrasi tabel database ke host
docker compose --profile tools run --rm php-cli php artisan migrate --force

# Optimasi cache konfigurasi & route
docker compose --profile tools run --rm php-cli php artisan optimize
Langkah 5: Aktivasi SUPER_ADMIN_EMAIL
Pastikan variabel SUPER_ADMIN_EMAIL di .env sudah diisi alamat email Anda (contoh: SUPER_ADMIN_EMAIL=admin@domainanda.com), lalu jalankan php artisan config:clear via php-cli jika baru diubah:

Bash
docker compose --profile tools run --rm php-cli php artisan config:clear
Buka halaman Register di Frontend dan daftarkan akun baru menggunakan email yang sama persis dengan nilai SUPER_ADMIN_EMAIL tersebut.

Sistem secara otomatis akan mengenali kecocokan config('rahanpas.super_admin_email') dan memberikan hak akses penuh sebagai Super Admin (termasuk bypass pengecekan RBAC).
