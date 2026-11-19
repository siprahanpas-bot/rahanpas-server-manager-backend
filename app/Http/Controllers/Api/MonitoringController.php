<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class MonitoringController extends Controller
{
    public function show(Request $request, int $id): JsonResponse
    {
        $server = $request->user()
            ->managedServers()
            ->with('latestMetric')
            ->findOrFail($id);

        $snapshot = $server->latestMetric;

        $metrics = null;

        if ($snapshot) {
            $metrics = [
                'hostname' => $snapshot->hostname,
                'os_name' => $snapshot->os_name,
                'kernel' => $snapshot->kernel,
                'uptime_seconds' => $snapshot->uptime_seconds,
                'cpu' => [
                    'usage_percent' => $snapshot->cpu_usage_percent,
                ],
                'memory' => [
                    'usage_percent' => $snapshot->memory_usage_percent,
                    'used_mb' => $snapshot->memory_used_mb,
                    'total_mb' => $snapshot->memory_total_mb,
                ],
                'swap' => [
                    'usage_percent' => $snapshot->swap_usage_percent,
                    'used_mb' => $snapshot->swap_used_mb,
                    'total_mb' => $snapshot->swap_total_mb,
                ],
                'disk' => [
                    'usage_percent' => $snapshot->disk_usage_percent,
                    'used_gb' => $snapshot->disk_used_gb,
                    'total_gb' => $snapshot->disk_total_gb,
                ],
                'network' => [
                    'rx_bytes' => $snapshot->network_rx_bytes,
                    'tx_bytes' => $snapshot->network_tx_bytes,
                ],
                'load_average' => $snapshot->load_average ?? [],
                'collected_at' => $snapshot->collected_at,
            ];
        }

        return response()->json([
            'message' => $snapshot
                ? 'Snapshot monitoring berhasil diambil.'
                : 'Belum tersedia snapshot monitoring untuk server ini.',
            'metrics' => $metrics,
            'server_status' => [
                'id' => $server->id,
                'status' => $server->status,
                'last_checked_at' => $server->last_checked_at,
                'last_error' => $server->last_error,
            ],
        ]);
    }

    public function history(Request $request, int $id): JsonResponse
    {
        $validated = $request->validate([
            'period' => 'sometimes|in:1h,6h,24h,7d',
        ]);

        $period = $validated['period'] ?? '1h';

        $cutoff = match ($period) {
            '1h' => now()->subHour(),
            '6h' => now()->subHours(6),
            '24h' => now()->subDay(),
            '7d' => now()->subDays(7),
        };

        // Hanya histori milik server yang dimiliki user login.
        $server = $request->user()
            ->managedServers()
            ->findOrFail($id);

        $history = $server->metricHistories()
            ->where('collected_at', '>=', $cutoff)
            ->orderBy('collected_at')
            ->get([
                'id',
                'hostname',
                'cpu_usage_percent',
                'memory_usage_percent',
                'memory_used_mb',
                'memory_total_mb',
                'swap_usage_percent',
                'disk_usage_percent',
                'disk_used_gb',
                'disk_total_gb',
                'network_rx_bytes',
                'network_tx_bytes',
                'load_average',
                'collected_at',
            ]);

        $rawCount = $history->count();
        $maxPoints = 120;

        if ($rawCount > $maxPoints) {
            $sampled = collect();
            $step = ($rawCount - 1) / ($maxPoints - 1);
            for ($i = 0; $i < $maxPoints; $i++) {
                $idx = (int) round($i * $step);
                if (isset($history[$idx])) {
                    $sampled->push($history[$idx]);
                }
            }
            $history = $sampled->unique('id')->values();
        }

        return response()->json([
            'message' => 'Monitoring history berhasil diambil.',
            'server_id' => $server->id,
            'period' => $period,
            'count' => $history->count(),
            'raw_count' => $rawCount,
            'history' => $history,
        ]);
    }

    public function rdpToken(Request $request, int $id): JsonResponse
    {
        $server = $request->user()
            ->managedServers()
            ->findOrFail($id);

        if ($server->os_type !== 'windows') {
            return response()->json([
                'message' => 'Remote Desktop (RDP) hanya tersedia untuk server Windows.',
            ], 422);
        }

        $host = $server->ip_address ?: $server->hostname;
        if (!$host || !$server->username || !$server->password) {
            return response()->json([
                'message' => 'IP/Hostname, username, atau password server belum lengkap.',
            ], 422);
        }

        $width = max(800, min(3840, (int) $request->input('width', 1366)));
        $height = max(600, min(2160, (int) $request->input('height', 768)));

        $payload = [
            'connection' => [
                'type' => 'rdp',
                'settings' => [
                    'hostname' => $host,
                    'port' => 3389,
                    'username' => $server->username,
                    'password' => $server->password,
                    'ignore-cert' => true,
                    'security' => 'any',
                    'resize-method' => 'display-update',
                    'width' => $width,
                    'height' => $height,
                    'dpi' => 96,
                    'disable-glyph-caching' => true,
                    'disable-copy' => false,
                    'disable-paste' => false,
                ],
            ],
        ];

        $secret = (string) config('rahanpas.rdp_bridge.secret', '');

        if (strlen($secret) < 32) {
            throw new \RuntimeException(
                'RDP_BRIDGE_SECRET harus diisi dan minimal 32 karakter.'
            );
        }

        $key = hash('sha256', $secret, true);
        $iv = random_bytes(16);
        $encrypted = openssl_encrypt(json_encode($payload), 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
        $token = base64_encode(json_encode([
            'iv' => base64_encode($iv),
            'value' => base64_encode($encrypted),
        ]));

        return response()->json([
            'token' => $token,
            'ws_port' => (int) config('rahanpas.rdp_bridge.public_port', 13002),
        ]);
    }
}
