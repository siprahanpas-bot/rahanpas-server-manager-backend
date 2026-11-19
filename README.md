# Rahanpas Server Manager — Backend

REST API dan layanan *bridge* untuk **Rahanpas Server Manager**, dibangun menggunakan **Laravel 13** dan dijalankan menggunakan **Docker Compose** (Nginx, PHP-FPM, PHP-CLI, dan Node.js RDP WebSocket Bridge) di atas lingkungan **aaPanel**.

* **Repository:** `git@github.com:siprahanpas-bot/rahanpas-server-manager-backend.git`

* **IP Server Host:** `172.30.1.156` (aaPanel + Reverse Proxy Domain)

* **Docker Network:** `baota_net`

## 1. Arsitektur & Third-Party yang Terpasang

### Layanan Container (Docker Services)

| Service | Image / Base | Fungsi Utama | Custom Port (`.env`) | 
| ----- | ----- | ----- | ----- | 
| **`nginx`** | Nginx Alpine | Web server & proxy masuk ke PHP-FPM | `BACKEND_PORT` (default: `8080`) | 
| **`php-fpm`** | PHP 8.3 FPM | Menjalankan core aplikasi & API Laravel | Internal (`9000`) | 
| **`php-cli`** | PHP 8.3 CLI | Container *on-demand* (`--profile tools`) untuk Artisan (`migrate`, `key:generate`, dll.) | \- | 
| **`rdp-ws`** | Node.js | WebSocket Bridge untuk menghubungkan browser dengan Apache Guacamole (`guacd`) | `RDP_BRIDGE_PUBLIC_PORT` (default: `13002`) | 

### Library & Third-Party Utama (`composer.json` & Integrasi)

* **Laravel Framework (`^13.17`)** — Core framework API, queue worker, dan task scheduler.

* **Laravel Sanctum (`^4.3`)** — Autentikasi berbasis token untuk komunikasi API antara Frontend dan Backend.

* **phpseclib (`^3.0`)** — Eksekusi perintah SSH, SFTP, dan manajemen file remote server langsung dari PHP tanpa ekstensi sistem tambahan.

* **MariaDB (`11.4.2` Docker Container)** — Database relasional yang berjalan di container Docker (terhubung ke network internal `baota_net`).

* **Apache Guacamole (`guacd`)** — Layanan *remote desktop gateway* eksternal (port `4822`) yang dihubungkan melalui container `rdp-ws` untuk sesi RDP/VNC.

* **OnlyOffice Document Server** — Layanan eksternal (port `13009`) untuk pratinjau dan pengeditan dokumen langsung di dalam File Manager.

## 2. Panduan Deployment (Dari Nol Hingga Siap Pakai)

### Langkah 1: Clone Repository

```bash
git clone git@github.com:siprahanpas-bot/rahanpas-server-manager-backend.git /opt/rahanpas-server-manager/backend
cd /opt/rahanpas-server-manager/backend
```

### Langkah 2: Buat & Konfigurasi File `.env` (WAJIB Sebelum Build/Artisan)

> **PENTING:** File `.env` **harus dibuat terlebih dahulu** di direktori host sebelum menjalankan container agar *bind-mount* `./.env:/var/www/html/.env` dapat dibaca dan ditulis oleh `php artisan key:generate`.

1. **Salin template `.env.example` menjadi `.env`:**

   ```bash
   cp .env.example .env
   ```

2. **Generate `RDP_BRIDGE_SECRET` secara otomatis (minimal 32 karakter):**
   Jalankan perintah berikut di terminal untuk membuat random string 64 karakter hex menggunakan `openssl` dan langsung menuliskannya ke file `.env`:

   ```bash
   sed -i "s/^RDP_BRIDGE_SECRET=.*/RDP_BRIDGE_SECRET=$(openssl rand -hex 32)/" .env
   ```

   *(Atau jika ingin melihat string-nya terlebih dahulu lalu copy-paste manual, jalankan `openssl rand -hex 32`)*

3. **Buka file `.env` dan sesuaikan sisa konfigurasi lainnya:**

   ```bash
   nano .env
   ```

   Pastikan parameter berikut di dalam `.env` sudah sesuai:

   ```env
   APP_NAME="Rahanpas Server Manager"
   APP_ENV=production
   APP_DEBUG=false
   # Gunakan domain reverse proxy Anda (misal: https://api-manager.domainanda.com)
   # Atau gunakan http://172.30.1.156:8080 jika masih tahap testing via IP
   APP_URL=https://api-manager.domainanda.com
   
   # 1. Custom Port Docker (Bebas disesuaikan agar tidak bentrok dengan port aaPanel)
   BACKEND_PORT=8080
   RDP_BRIDGE_PUBLIC_PORT=13002
   RDP_BRIDGE_PORT=8080
   DOCKER_NETWORK=baota_net
   
   # 2. Koneksi ke Database Container MariaDB (via Internal Docker Network baota_net)
   # Gunakan nama container MariaDB (cek via: docker ps | grep mariadb) & port internal 3306
   DB_CONNECTION=mysql
   DB_HOST=mariadb_xakf_svmonitor-mariadb_xaKF_svmonitor-1
   DB_PORT=3306
   DB_DATABASE=server_manager
   DB_USERNAME=rahanpas_user
   DB_PASSWORD=password_database_anda
   
   # 3. Konfigurasi Session, CORS & Reverse Proxy
   SESSION_DRIVER=database
   QUEUE_CONNECTION=database
   CACHE_STORE=database
   # Isi dengan domain frontend & backend Anda (pisahkan dengan koma jika lebih dari satu)
   SANCTUM_STATEFUL_DOMAINS=manager.domainanda.com,api-manager.domainanda.com,172.30.1.156
   
   # 4. Keamanan & Integrasi Third-Party
   # Nilai ini sudah terisi otomatis jika Anda menjalankan perintah openssl di atas
   RDP_BRIDGE_SECRET=hasil_generate_openssl_rand_hex_32
   GUACD_HOST=rahanpas-guacd
   GUACD_PORT=4822

   # Konfigurasi OnlyOffice (Pilih salah satu skenario di bawah):
   # Skenario A (Sesama container dalam network baota_net - Direkomendasikan):
   ONLYOFFICE_PUBLIC_PORT=13009
   ONLYOFFICE_API_BASE_URL=http://rahanpas-backend-nginx/api
   ONLYOFFICE_INTERNAL_URL=http://rahanpas-onlyoffice

   # Skenario B (Jika diakses via IP Host 172.30.1.156 atau beda network/server):
   # ONLYOFFICE_PUBLIC_PORT=13009
   # ONLYOFFICE_API_BASE_URL=http://172.30.1.156:8080/api
   # ONLYOFFICE_INTERNAL_URL=http://172.30.1.156:13009
   
   # 5. Penetapan Akun Super Admin
   SUPER_ADMIN_EMAIL=admin@domainanda.com
   ```

> **Catatan Konfigurasi OnlyOffice Menggunakan IP (`172.30.1.156`):**
> * Jika container `rahanpas-onlyoffice` dan `rahanpas-backend-nginx` berada di jaringan Docker yang sama (`baota_net`), gunakan **Skenario A** (`http://rahanpas-backend-nginx/api` dan `http://rahanpas-onlyoffice`).
> * Jika OnlyOffice berjalan di luar jaringan `baota_net` atau Anda ingin komunikasi *callback* dokumen melewati IP host server secara eksplisit, gunakan **Skenario B** dengan menyertakan port masing-masing (`http://172.30.1.156:8080/api` untuk `ONLYOFFICE_API_BASE_URL` dan `http://172.30.1.156:13009` untuk `ONLYOFFICE_INTERNAL_URL`). Pastikan kedua port tersebut (`8080` dan `13009`) terbuka pada firewall aaPanel untuk subnet Docker (`172.18.0.0/16`).

### Langkah 3: Pastikan Konfigurasi `docker-compose.yml` Sesuai

Pastikan service `php-fpm` dan `php-cli` memiliki *volume mount* `./.env:/var/www/html/.env` agar perubahan `.env` di host langsung terbaca oleh Laravel:

```yaml
    volumes:
      - ./.env:/var/www/html/.env
      - backend-storage:/var/www/html/storage
```

### Langkah 4: Hubungkan Network `baota_net` & Jalankan Container

Pastikan network `baota_net` tersedia dan container database MariaDB terhubung ke dalamnya agar komunikasi antar-container berjalan langsung tanpa melewati firewall host:

```bash
# 1. Buat network baota_net jika belum tersedia
docker network create baota_net 2>/dev/null || true

# 2. Hubungkan container MariaDB ke network baota_net (aman dijalankan berulang)
docker network connect baota_net mariadb_xakf_svmonitor-mariadb_xaKF_svmonitor-1 2>/dev/null || true

# 3. Build dan jalankan seluruh container backend
docker compose up -d --build
```

### Langkah 5: Generate `APP_KEY`, Migrasi Database & Optimasi

Jalankan perintah Artisan menggunakan container `php-cli`:

```bash
# 1. Generate APP_KEY (otomatis tertulis ke .env di host)
docker compose --profile tools run --rm php-cli php artisan key:generate --force

# 2. Bersihkan cache konfigurasi lama & jalankan migrasi database
docker compose --profile tools run --rm php-cli php artisan config:clear
docker compose --profile tools run --rm php-cli php artisan migrate --force

# 3. Set permission storage & bootstrap/cache
docker compose --profile tools run --rm php-cli chown -R www-data:www-data /var/www/html/storage /var/www/html/bootstrap/cache

# 4. Optimasi cache konfigurasi, route, dan view
docker compose --profile tools run --rm php-cli php artisan optimize

# 5. Recreate php-fpm agar memuat environment & APP_KEY terbaru
docker compose up -d --no-build --force-recreate php-fpm
```

### Langkah 6: Aktivasi Akun `SUPER_ADMIN_EMAIL`

1. Pastikan variabel `SUPER_ADMIN_EMAIL` di `.env` sudah diisi email utama Anda (misal: `admin@domainanda.com`).

2. Jika Anda baru saja mengubah email tersebut setelah langkah optimasi, jalankan ulang:

   ```bash
   docker compose --profile tools run --rm php-cli php artisan config:clear
   docker compose --profile tools run --rm php-cli php artisan config:cache
   docker compose up -d --no-build --force-recreate php-fpm
   ```

3. Buka halaman **Register** pada aplikasi **Frontend** dan daftarkan akun baru menggunakan **email yang sama persis** dengan `SUPER_ADMIN_EMAIL`.

4. Sistem secara otomatis akan membaca kecocokan `config('rahanpas.super_admin_email')` dan memberikan hak akses penuh sebagai **Super Admin** (termasuk *bypass* pengecekan RBAC).

## 3. Konfigurasi Reverse Proxy Domain di aaPanel

Agar API Backend (`BACKEND_PORT=8080`) dan WebSocket RDP (`RDP_BRIDGE_PUBLIC_PORT=13002`) dapat diakses secara aman melalui domain HTTPS menggunakan aaPanel:

1. **Tambah Website Baru di aaPanel:**

   * Masuk ke menu **Website** > **Add site**.

   * Masukkan domain API Anda (contoh: `api-manager.domainanda.com`), pilih **PHP Version: Pure static**.

   * Aktifkan **SSL (Let's Encrypt)** pada tab **SSL** website tersebut.

2. **Atur Reverse Proxy API Utama:**

   * Klik **Settings** pada domain `api-manager.domainanda.com` > pilih tab **Reverse proxy** > **Add reverse proxy**.

   * **Proxy name:** `backend-api`

   * **Target URL:** `http://127.0.0.1:8080` *(sesuaikan dengan `BACKEND_PORT` di `.env`)*

   * **Sent domain:** `$host`

   * Simpan pengaturan.

3. **Tambahkan Proxy WebSocket untuk RDP Bridge (Opsional jika RDP lewat domain yang sama):**

   * Pada tab **Reverse proxy**, klik **Config file** pada proxy yang baru dibuat, lalu tambahkan blok `location` berikut sebelum tanda tutup `}` terakhir agar koneksi WebSocket RDP (`13002`) berjalan lancar di balik HTTPS:

   ```nginx
   location /rdp-ws/ {
       proxy_pass http://127.0.0.1:13002/;
       proxy_http_version 1.1;
       proxy_set_header Upgrade $http_upgrade;
       proxy_set_header Connection "upgrade";
       proxy_set_header Host $host;
       proxy_set_header X-Real-IP $remote_addr;
       proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
       proxy_set_header X-Forwarded-Proto $scheme;
       proxy_read_timeout 86400;
   }
   ```

## 4. Perintah Operasional & Troubleshooting

* **Cek Status Seluruh Container:**

  ```bash
  docker compose ps
  ```

* **Melihat Log Real-Time:**

  ```bash
  docker compose logs -f php-fpm nginx rdp-ws
  ```

* **Update Aplikasi dari GitHub:**

  ```bash
  cd /opt/rahanpas-server-manager/backend
  git pull origin main
  docker compose up -d --build
  docker compose --profile tools run --rm php-cli php artisan migrate --force
  docker compose --profile tools run --rm php-cli php artisan optimize
  ```

  🖥️ Panduan Setup & Deploy RDP WebSocket Bridge (Guacamole)
Ikuti langkah-langkah berikut agar fitur Remote Desktop (RDP) di browser dapat langsung berjalan mulus saat dideploy ke server baru.

1. Prasyarat Infrastruktur & Docker Network
Pastikan seluruh container backend (php-fpm, nginx, rdp-ws, mariadb) dan container Guacamole berada dalam satu Docker network yang sama (misal: baota_net) agar nama host container dapat saling mengenali via DNS internal Docker.

2. Menjalankan Service rahanpas-guacd
Service Guacamole Proxy Daemon (guacd) wajib aktif di network Docker agar rahanpas-rdp-ws dapat meneruskan koneksi RDP.
Tambahkan service berikut ke dalam docker-compose.yml (atau jalankan terpisah):

YAML
  rahanpas-guacd:
    image: guacamole/guacd:1.6.0
    container_name: rahanpas-guacd
    restart: always
    networks:
      - baota_net
    healthcheck:
      test: ["CMD", "nc", "-z", "localhost", "4822"]
      interval: 10s
      timeout: 5s
      retries: 3
3. Konfigurasi Environment Backend (.env)
Pastikan variabel berikut terdefinisi di file .env bagian backend Laravel dengan panjang secret minimal 32 karakter:

Cuplikan kode
RDP_BRIDGE_SECRET=your_super_secret_key_minimum_32_characters_long
RDP_BRIDGE_PORT=13002
GUACD_HOST=rahanpas-guacd
GUACD_PORT=4822
4. Membuka Port Firewall (UFW)
Jika server menggunakan UFW, pastikan port WebSocket RDP (13002) diizinkan agar dapat diakses oleh klien/browser:

Bash
sudo ufw allow 13002/tcp
sudo ufw reload
5. Catatan Penting untuk Akses Klien (Browser & SSH Tunnel)
Akses Langsung via IP Server: Jika membuka aplikasi melalui IP server (misal http://<IP_Server>:13000), pastikan port 13002 terbuka di firewall server agar browser dapat terhubung ke ws://<IP_Server>:13002.

Akses via SSH Port Forwarding: Jika Anda mengakses aplikasi menggunakan SSH Tunnel dari komputer lokal, pastikan dua port di-forward secara bersamaan (13000 untuk web dan 13002 untuk WebSocket RDP):

Bash
ssh -L 13000:127.0.0.1:13000 -L 13002:127.0.0.1:13002 root@<IP_Server>