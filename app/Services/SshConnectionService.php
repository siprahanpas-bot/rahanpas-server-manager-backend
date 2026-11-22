<?php

namespace App\Services;

use App\Models\ManagedServer;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Net\SSH2;
use RuntimeException;
use Throwable;

class SshConnectionService
{
    private const CONNECTION_TIMEOUT = 10;

    private function createConnection(ManagedServer $server): SSH2
    {
        if (!in_array($server->connection_protocol, ['ssh', 'windows_openssh'], true)) {
            throw new RuntimeException(
                'Protokol ini belum didukung oleh SSH Connection Engine.'
            );
        }

        $host = $server->hostname ?: $server->ip_address;

        if (!$host) {
            throw new RuntimeException('Hostname atau IP address server belum diisi.');
        }

        try {
            return new SSH2(
                $host,
                (int) $server->port,
                self::CONNECTION_TIMEOUT
            );
        } catch (Throwable) {
            throw new RuntimeException(
                'Tidak dapat membuat koneksi SSH ke server. Periksa alamat, port, dan jaringan.'
            );
        }
    }

    /**
     * Mengambil fingerprint host key tanpa mengirim kredensial.
     */
    public function discoverHostKey(ManagedServer $server): array
    {
        $ssh = $this->createConnection($server);

        try {
            $publicHostKey = $ssh->getServerPublicHostKey();

            if ($publicHostKey === false || !is_string($publicHostKey)) {
                throw new RuntimeException(
                    'Server tidak memberikan host key SSH yang valid.'
                );
            }

            $parts = preg_split('/\s+/', trim($publicHostKey), 2);

            if (
                count($parts) !== 2 ||
                !preg_match('/^[A-Za-z0-9@._+-]+$/', $parts[0])
            ) {
                throw new RuntimeException('Format public host key SSH tidak valid.');
            }

            $rawKey = base64_decode($parts[1], true);

            if ($rawKey === false || $rawKey === '') {
                throw new RuntimeException('Public host key SSH tidak dapat dibaca.');
            }

            $fingerprint = 'SHA256:' . rtrim(
                base64_encode(hash('sha256', $rawKey, true)),
                '='
            );

            return [
                'key_type' => $parts[0],
                'fingerprint' => $fingerprint,
            ];
        } catch (RuntimeException $exception) {
            throw $exception;
        } catch (Throwable) {
            throw new RuntimeException(
                'Gagal mengambil fingerprint host key SSH dari server.'
            );
        } finally {
            $ssh->disconnect();
        }
    }

    /**
     * Memverifikasi identitas server sebelum autentikasi.
     */
    public function testConnection(ManagedServer $server): array
    {
        $ssh = $this->createConnection($server);

        try {
            $publicHostKey = $ssh->getServerPublicHostKey();

            if ($publicHostKey === false || !is_string($publicHostKey)) {
                throw new RuntimeException(
                    'Server tidak memberikan host key SSH yang valid.'
                );
            }

            $parts = preg_split('/\s+/', trim($publicHostKey), 2);

            if (count($parts) !== 2) {
                throw new RuntimeException('Format host key SSH tidak valid.');
            }

            $rawKey = base64_decode($parts[1], true);

            if ($rawKey === false || $rawKey === '') {
                throw new RuntimeException('Public host key SSH tidak valid.');
            }

            $fingerprint = 'SHA256:' . rtrim(
                base64_encode(hash('sha256', $rawKey, true)),
                '='
            );

            // Fail closed: fingerprint wajib terdaftar jika verifikasi aktif.
            if ($server->verify_host_key) {
                if (!$server->host_key_fingerprint) {
                    throw new RuntimeException(
                        'Fingerprint host key belum didaftarkan. Lakukan Discover Host Key, verifikasi melalui jalur tepercaya, lalu simpan fingerprint.'
                    );
                }

                if (!hash_equals($server->host_key_fingerprint, $fingerprint)) {
                    throw new RuntimeException(
                        'Fingerprint host key tidak cocok. Koneksi ditolak untuk mencegah kemungkinan serangan man-in-the-middle.'
                    );
                }
            }

            // Autentikasi baru dilakukan setelah pemeriksaan host key.
            if ($server->auth_method === 'password') {
                $authenticated = $ssh->login(
                    $server->username,
                    $server->password
                );
            } elseif ($server->auth_method === 'private_key') {
                if (!$server->private_key) {
                    throw new RuntimeException('Private key belum tersedia.');
                }

                try {
                    $key = PublicKeyLoader::load(
                        $server->private_key,
                        $server->private_key_passphrase ?: false
                    );
                } catch (Throwable) {
                    throw new RuntimeException(
                        'Private key tidak valid atau passphrase tidak sesuai.'
                    );
                }

                $authenticated = $ssh->login($server->username, $key);
            } else {
                throw new RuntimeException('Metode autentikasi tidak didukung.');
            }

            if (!$authenticated) {
                throw new RuntimeException(
                    'Autentikasi SSH gagal. Periksa username dan kredensial server.'
                );
            }

            return [
                'connected' => true,
                'host_key_fingerprint' => $fingerprint,
                'message' => 'Koneksi SSH dan autentikasi berhasil.',
            ];
        } catch (RuntimeException $exception) {
            throw $exception;
        } catch (Throwable) {
            throw new RuntimeException(
                'Terjadi kesalahan saat melakukan koneksi atau autentikasi SSH.'
            );
        } finally {
            $ssh->disconnect();
        }
    }


    /**
     * Mengambil metrik monitoring Linux melalui SSH.
     * Perintah remote bersifat tetap dan tidak menerima input pengguna.
     */
    public function collectMetrics(ManagedServer $server): array
    {
        $ssh = $this->createConnection($server);

        try {
            // Verifikasi host key sebelum mengirim kredensial.
            $publicHostKey = $ssh->getServerPublicHostKey();

            if ($publicHostKey === false || !is_string($publicHostKey)) {
                throw new RuntimeException('Host key SSH tidak valid.');
            }

            $parts = preg_split('/\s+/', trim($publicHostKey), 2);

            if (
                count($parts) !== 2 ||
                !preg_match('/^[A-Za-z0-9@._+-]+$/', $parts[0])
            ) {
                throw new RuntimeException('Format host key SSH tidak valid.');
            }

            $rawKey = base64_decode($parts[1], true);

            if ($rawKey === false || $rawKey === '') {
                throw new RuntimeException('Host key SSH tidak valid.');
            }

            $fingerprint = 'SHA256:' . rtrim(
                base64_encode(hash('sha256', $rawKey, true)),
                '='
            );

            if ($server->verify_host_key) {
                if (!$server->host_key_fingerprint) {
                    throw new RuntimeException('Fingerprint host key belum didaftarkan.');
                }

                if (!hash_equals($server->host_key_fingerprint, $fingerprint)) {
                    throw new RuntimeException('Fingerprint host key tidak cocok. Monitoring ditolak.');
                }
            }

            // Autentikasi SSH.
            if ($server->auth_method === 'password') {
                $authenticated = $ssh->login(
                    $server->username,
                    $server->password
                );
            } elseif ($server->auth_method === 'private_key') {
                if (!$server->private_key) {
                    throw new RuntimeException('Private key belum tersedia.');
                }

                try {
                    $key = PublicKeyLoader::load(
                        $server->private_key,
                        $server->private_key_passphrase ?: false
                    );
                } catch (Throwable) {
                    throw new RuntimeException('Private key tidak valid.');
                }

                $authenticated = $ssh->login($server->username, $key);
            } else {
                throw new RuntimeException('Metode autentikasi tidak didukung.');
            }

            if (!$authenticated) {
                throw new RuntimeException('Autentikasi SSH gagal.');
            }

            $ssh->setTimeout(15);

            // Skrip monitoring tetap. Tidak ada parameter dari pengguna.
            $command = <<<'SHELL'
LC_ALL=C sh -c '
echo "HOSTNAME=$(hostname 2>/dev/null)"
echo "OS_NAME=$(sed -n "s/^PRETTY_NAME=//p" /etc/os-release 2>/dev/null | head -n 1 | tr -d "\"")"
echo "KERNEL=$(uname -r 2>/dev/null)"
echo "UPTIME=$(awk "{print int(\$1)}" /proc/uptime)"
echo "LOAD=$(awk "{print \$1 \",\" \$2 \",\" \$3}" /proc/loadavg)"

awk "
/^MemTotal:/ {total=\$2}
/^MemAvailable:/ {available=\$2}
/^SwapTotal:/ {swap_total=\$2}
/^SwapFree:/ {swap_free=\$2}
END {
  printf \"MEM_TOTAL=%d\\n\", total
  printf \"MEM_AVAILABLE=%d\\n\", available
  printf \"SWAP_TOTAL=%d\\n\", swap_total
  printf \"SWAP_FREE=%d\\n\", swap_free
}" /proc/meminfo

df -Pk / | awk "NR==2 {printf \"DISK_TOTAL=%d\\nDISK_USED=%d\\nDISK_AVAILABLE=%d\\nDISK_PERCENT=%s\\n\", \$2, \$3, \$4, \$5}"

awk "
NR>2 && \$1 !~ /lo:/ {
  gsub(\":\", \"\", \$1)
  rx+=\$2
  tx+=\$10
}
END {
  printf \"NET_RX=%0.f\\nNET_TX=%0.f\\n\", rx, tx
}" /proc/net/dev

awk "NR==1 {print \"CPU_BEFORE=\" \$2+\$3+\$4+\$5+\$6+\$7+\$8, \" \" \$5}" /proc/stat
sleep 1
awk "NR==1 {print \"CPU_AFTER=\" \$2+\$3+\$4+\$5+\$6+\$7+\$8, \" \" \$5}" /proc/stat
'
SHELL;

            $output = $ssh->exec($command);

            if ($output === false || !is_string($output)) {
                throw new RuntimeException('Gagal mengambil data monitoring dari server.');
            }

            $values = [];

            foreach (preg_split('/\r?\n/', trim($output)) as $line) {
                if (preg_match('/^([A-Z_]+)=(.*)$/', trim($line), $match)) {
                    $values[$match[1]] = trim($match[2]);
                }
            }

            $required = [
                'HOSTNAME',
                'KERNEL',
                'UPTIME',
                'LOAD',
                'MEM_TOTAL',
                'MEM_AVAILABLE',
                'SWAP_TOTAL',
                'SWAP_FREE',
                'DISK_TOTAL',
                'DISK_USED',
                'DISK_AVAILABLE',
                'DISK_PERCENT',
                'NET_RX',
                'NET_TX',
                'CPU_BEFORE',
                'CPU_AFTER',
            ];

            foreach ($required as $key) {
                if (!isset($values[$key]) || $values[$key] === '') {
                    throw new RuntimeException('Data monitoring tidak lengkap.');
                }
            }

            $numericKeys = [
                'UPTIME',
                'MEM_TOTAL',
                'MEM_AVAILABLE',
                'SWAP_TOTAL',
                'SWAP_FREE',
                'DISK_TOTAL',
                'DISK_USED',
                'DISK_AVAILABLE',
                'NET_RX',
                'NET_TX',
            ];

            foreach ($numericKeys as $key) {
                if (!is_numeric($values[$key])) {
                    throw new RuntimeException('Data monitoring tidak valid.');
                }
            }

            if (!preg_match('/^\d+(?:\.\d+)?%$/', $values['DISK_PERCENT'])) {
                throw new RuntimeException('Data penggunaan disk tidak valid.');
            }

            $loadParts = explode(',', $values['LOAD']);

            if (count($loadParts) !== 3) {
                throw new RuntimeException('Data load average tidak valid.');
            }

            foreach ($loadParts as $loadPart) {
                if (!is_numeric($loadPart)) {
                    throw new RuntimeException('Data load average tidak valid.');
                }
            }

            foreach (['CPU_BEFORE', 'CPU_AFTER'] as $key) {
                $cpuParts = preg_split('/\s+/', trim($values[$key]));

                if (
                    count($cpuParts) !== 2 ||
                    !is_numeric($cpuParts[0]) ||
                    !is_numeric($cpuParts[1])
                ) {
                    throw new RuntimeException('Data CPU monitoring tidak valid.');
                }
            }

            $memTotal = (int) $values['MEM_TOTAL'];
            $memAvailable = (int) $values['MEM_AVAILABLE'];
            $swapTotal = (int) $values['SWAP_TOTAL'];
            $swapFree = (int) $values['SWAP_FREE'];

            [$cpuBefore, $idleBefore] = array_map(
                'intval',
                preg_split('/\s+/', $values['CPU_BEFORE'])
            );

            [$cpuAfter, $idleAfter] = array_map(
                'intval',
                preg_split('/\s+/', $values['CPU_AFTER'])
            );

            $cpuDelta = $cpuAfter - $cpuBefore;
            $idleDelta = $idleAfter - $idleBefore;

            $cpuUsage = $cpuDelta > 0
                ? round((1 - ($idleDelta / $cpuDelta)) * 100, 2)
                : 0;

            return [
                'hostname' => $values['HOSTNAME'],
                'os_name' => $values['OS_NAME'] ?? 'Unknown',
                'kernel' => $values['KERNEL'],
                'uptime_seconds' => (int) $values['UPTIME'],
                'load_average' => array_map(
                    'floatval',
                    explode(',', $values['LOAD'])
                ),
                'cpu' => [
                    'usage_percent' => max(0, min(100, $cpuUsage)),
                ],
                'memory' => [
                    'total_mb' => round($memTotal / 1024, 2),
                    'used_mb' => round(($memTotal - $memAvailable) / 1024, 2),
                    'available_mb' => round($memAvailable / 1024, 2),
                    'usage_percent' => $memTotal > 0
                        ? round((($memTotal - $memAvailable) / $memTotal) * 100, 2)
                        : 0,
                ],
                'swap' => [
                    'total_mb' => round($swapTotal / 1024, 2),
                    'used_mb' => round(($swapTotal - $swapFree) / 1024, 2),
                    'usage_percent' => $swapTotal > 0
                        ? round((($swapTotal - $swapFree) / $swapTotal) * 100, 2)
                        : 0,
                ],
                'disk' => [
                    'total_gb' => round((int) $values['DISK_TOTAL'] / 1024 / 1024, 2),
                    'used_gb' => round((int) $values['DISK_USED'] / 1024 / 1024, 2),
                    'available_gb' => round((int) $values['DISK_AVAILABLE'] / 1024 / 1024, 2),
                    'usage_percent' => (float) rtrim($values['DISK_PERCENT'], '%'),
                ],
                'network' => [
                    'rx_bytes' => (int) $values['NET_RX'],
                    'tx_bytes' => (int) $values['NET_TX'],
                ],
                'host_key_fingerprint' => $fingerprint,
                'collected_at' => now()->toISOString(),
            ];
        } catch (RuntimeException $exception) {
            throw $exception;
        } catch (Throwable) {
            throw new RuntimeException('Terjadi kesalahan saat mengambil data monitoring SSH.');
        } finally {
            $ssh->disconnect();
        }
    }


    /**
     * Mendeteksi dukungan WireGuard melalui SSH secara read-only.
     * Tidak mengubah interface maupun konfigurasi remote.
     */
    public function detectWireGuardSupport(ManagedServer $server): bool
    {
        $ssh = $this->createConnection($server);

        try {
            $publicHostKey = $ssh->getServerPublicHostKey();

            if ($publicHostKey === false || !is_string($publicHostKey)) {
                throw new RuntimeException('Host key SSH tidak valid.');
            }

            $parts = preg_split('/\s+/', trim($publicHostKey), 2);

            if (
                count($parts) !== 2 ||
                !preg_match('/^[A-Za-z0-9@._+-]+$/', $parts[0])
            ) {
                throw new RuntimeException('Format host key SSH tidak valid.');
            }

            $rawKey = base64_decode($parts[1], true);

            if ($rawKey === false || $rawKey === '') {
                throw new RuntimeException('Host key SSH tidak valid.');
            }

            $fingerprint = 'SHA256:' . rtrim(
                base64_encode(hash('sha256', $rawKey, true)),
                '='
            );

            if ($server->verify_host_key) {
                if (!$server->host_key_fingerprint) {
                    throw new RuntimeException(
                        'Fingerprint host key belum didaftarkan.'
                    );
                }

                if (!hash_equals($server->host_key_fingerprint, $fingerprint)) {
                    throw new RuntimeException(
                        'Fingerprint host key tidak cocok. Koneksi ditolak.'
                    );
                }
            }

            if ($server->auth_method === 'password') {
                $authenticated = $ssh->login(
                    $server->username,
                    $server->password
                );
            } elseif ($server->auth_method === 'private_key') {
                if (!$server->private_key) {
                    throw new RuntimeException('Private key belum tersedia.');
                }

                try {
                    $key = PublicKeyLoader::load(
                        $server->private_key,
                        $server->private_key_passphrase ?: false
                    );
                } catch (Throwable) {
                    throw new RuntimeException(
                        'Private key tidak valid atau passphrase tidak sesuai.'
                    );
                }

                $authenticated = $ssh->login($server->username, $key);
            } else {
                throw new RuntimeException(
                    'Metode autentikasi SSH tidak didukung.'
                );
            }

            if (!$authenticated) {
                throw new RuntimeException('Autentikasi SSH gagal.');
            }

            $ssh->setTimeout(15);

            $command = <<<'SHELL'
LC_ALL=C sh -c '
if ! command -v wg >/dev/null 2>&1; then
    printf "WG_UNSUPPORTED\n"
elif ! command -v ip >/dev/null 2>&1; then
    printf "WG_PROBE_ERROR\n"
else
    interfaces="$(ip -o link show type wireguard 2>/dev/null)" || {
        printf "WG_PROBE_ERROR\n"
        exit 0
    }

    if [ -n "$interfaces" ]; then
        printf "WG_SUPPORTED\n"
    else
        printf "WG_UNSUPPORTED\n"
    fi
fi
'
SHELL;

            $output = $ssh->exec($command);

            if (!is_string($output)) {
                throw new RuntimeException(
                    'Gagal menjalankan deteksi WireGuard melalui SSH.'
                );
            }

            $result = trim($output);

            if ($result === 'WG_SUPPORTED') {
                return true;
            }

            if ($result === 'WG_UNSUPPORTED') {
                return false;
            }

            throw new RuntimeException(
                'Hasil pemeriksaan dukungan WireGuard tidak valid.'
            );
        } catch (RuntimeException $exception) {
            throw $exception;
        } catch (Throwable) {
            throw new RuntimeException(
                'Terjadi kesalahan saat mendeteksi WireGuard melalui SSH.'
            );
        } finally {
            $ssh->disconnect();
        }
    }

    /**
     * Menjalankan operasi WireGuard yang telah di-whitelist.
     * Tidak menyediakan eksekusi shell generik.
     */
    public function executeWireGuardOperation(
        ManagedServer $server,
        string $operation,
        array $parameters = []
    ): array {
        if (!in_array($operation, ['status', 'peers', 'create', 'get-config'], true)) {
            throw new RuntimeException('Operasi WireGuard tidak diizinkan.');
        }

        if (in_array($operation, ['create', 'get-config'], true)) {
            $name = $parameters['name'] ?? null;

            if (
                array_keys($parameters) !== ['name'] ||
                !is_string($name) ||
                !preg_match('/\\A[A-Za-z0-9_-]{1,32}\\z/', $name)
            ) {
                throw new RuntimeException('Nama peer WireGuard tidak valid.');
            }
        } elseif ($parameters !== []) {
            throw new RuntimeException(
                'Parameter operasi WireGuard tidak diizinkan.'
            );
        }

        $ssh = $this->createConnection($server);

        try {
            // Verifikasi host key sebelum autentikasi.
            $publicHostKey = $ssh->getServerPublicHostKey();

            if ($publicHostKey === false || !is_string($publicHostKey)) {
                throw new RuntimeException('Host key SSH tidak valid.');
            }

            $parts = preg_split('/\s+/', trim($publicHostKey), 2);

            if (
                count($parts) !== 2 ||
                !preg_match('/^[A-Za-z0-9@._+-]+$/', $parts[0])
            ) {
                throw new RuntimeException('Format host key SSH tidak valid.');
            }

            $rawKey = base64_decode($parts[1], true);

            if ($rawKey === false || $rawKey === '') {
                throw new RuntimeException('Host key SSH tidak valid.');
            }

            $fingerprint = 'SHA256:' . rtrim(
                base64_encode(hash('sha256', $rawKey, true)),
                '='
            );

            // Fail closed apabila verifikasi host key diaktifkan.
            if ($server->verify_host_key) {
                if (!$server->host_key_fingerprint) {
                    throw new RuntimeException(
                        'Fingerprint host key belum didaftarkan.'
                    );
                }

                if (!hash_equals(
                    $server->host_key_fingerprint,
                    $fingerprint
                )) {
                    throw new RuntimeException(
                        'Fingerprint host key tidak cocok. Koneksi ditolak.'
                    );
                }
            }

            // Autentikasi setelah verifikasi identitas host.
            if ($server->auth_method === 'password') {
                $authenticated = $ssh->login(
                    $server->username,
                    $server->password
                );
            } elseif ($server->auth_method === 'private_key') {
                if (!$server->private_key) {
                    throw new RuntimeException('Private key belum tersedia.');
                }

                try {
                    $key = PublicKeyLoader::load(
                        $server->private_key,
                        $server->private_key_passphrase ?: false
                    );
                } catch (Throwable) {
                    throw new RuntimeException(
                        'Private key tidak valid atau passphrase tidak sesuai.'
                    );
                }

                $authenticated = $ssh->login($server->username, $key);
            } else {
                throw new RuntimeException(
                    'Metode autentikasi SSH tidak didukung.'
                );
            }

            if (!$authenticated) {
                throw new RuntimeException('Autentikasi SSH gagal.');
            }

            $ssh->setTimeout($operation === 'create' ? 60 : 20);

            // Payload hanya berisi field yang diizinkan untuk operasi ini.
            $requestPayload = ['operation' => $operation];

            if (in_array($operation, ['create', 'get-config'], true)) {
                $requestPayload['name'] = $parameters['name'];
            }

            $payload = json_encode(
                $requestPayload,
                JSON_THROW_ON_ERROR
            );

            // Payload di-escape sebagai argumen shell.
            // Command executable dan sudo tidak dapat diubah oleh pengguna.
            $command = 'printf %s ' . escapeshellarg($payload)
                . ' | sudo -n /usr/local/sbin/rahanpas-wireguard';

            $output = $ssh->exec($command);

            if ($output === false || !is_string($output)) {
                throw new RuntimeException(
                    'Tidak dapat menjalankan operasi WireGuard remote.'
                );
            }

            $decoded = json_decode(trim($output), true);

            if (
                !is_array($decoded) ||
                json_last_error() !== JSON_ERROR_NONE ||
                ($decoded['success'] ?? false) !== true ||
                ($decoded['operation'] ?? null) !== $operation
            ) {
                throw new RuntimeException(
                    'Respons WireGuard remote tidak valid.'
                );
            }

            if ($operation === 'create') {
                $peer = $decoded['peer'] ?? null;
                $config = $decoded['config'] ?? null;
                $qrBase64 = $decoded['qr_png_base64'] ?? null;

                if (
                    !is_array($peer) ||
                    ($peer['name'] ?? null) !== $parameters['name'] ||
                    !is_string($peer['public_key'] ?? null) ||
                    !preg_match(
                        '/\\A[A-Za-z0-9+\\/]{43}=\\z/',
                        $peer['public_key']
                    ) ||
                    !is_string($peer['address'] ?? null) ||
                    !str_ends_with($peer['address'], '/32') ||
                    filter_var(
                        substr($peer['address'], 0, -3),
                        FILTER_VALIDATE_IP,
                        FILTER_FLAG_IPV4
                    ) === false ||
                    !is_string($config) ||
                    !str_contains($config, '[Interface]') ||
                    !str_contains($config, '[Peer]') ||
                    !str_contains($config, 'PrivateKey = ') ||
                    !is_string($qrBase64)
                ) {
                    throw new RuntimeException(
                        'Respons pembuatan peer WireGuard tidak valid.'
                    );
                }

                $qrBytes = base64_decode($qrBase64, true);

                if (
                    $qrBytes === false ||
                    !str_starts_with($qrBytes, "\x89PNG\r\n\x1a\n")
                ) {
                    throw new RuntimeException(
                        'Data QR WireGuard tidak valid.'
                    );
                }
            } elseif ($operation === 'get-config') {
                $configBase64 = $decoded['config_base64'] ?? null;
                $qrBase64 = $decoded['qr_png_base64'] ?? null;

                if (
                    ($decoded['name'] ?? null) !== $parameters['name'] ||
                    !is_string($configBase64) ||
                    !is_string($qrBase64)
                ) {
                    throw new RuntimeException(
                        'Respons konfigurasi peer WireGuard tidak valid.'
                    );
                }

                $decoded['peer'] = [
                    'name' => $decoded['name'],
                ];
                unset($decoded['name']);

                $configBytes = base64_decode($configBase64, true);
                $qrBytes = base64_decode($qrBase64, true);

                if (
                    $configBytes === false ||
                    $configBytes === '' ||
                    strlen($configBytes) > 65536 ||
                    !str_contains($configBytes, '[Interface]') ||
                    !str_contains($configBytes, '[Peer]') ||
                    !preg_match('/^PrivateKey\s*=\s*\S+/m', $configBytes) ||
                    $qrBytes === false ||
                    !str_starts_with($qrBytes, "\x89PNG\r\n\x1a\n") ||
                    strlen($qrBytes) > 524288
                ) {
                    throw new RuntimeException(
                        'Isi konfigurasi atau QR peer WireGuard tidak valid.'
                    );
                }

                $decoded['config'] = $configBytes;
                unset($decoded['config_base64']);
            }

            return $decoded;
        } catch (RuntimeException $exception) {
            throw $exception;
        } catch (Throwable) {
            throw new RuntimeException(
                'Terjadi kesalahan saat berkomunikasi dengan WireGuard melalui SSH.'
            );
        } finally {
            $ssh->disconnect();
        }
    }
}
