<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Services\SshConnectionService;
use App\Services\WinRmConnectionService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use RuntimeException;
use Throwable;

class MonitoringController extends Controller
{
    public function show(
        Request $request,
        int $id,
        SshConnectionService $ssh,
        WinRmConnectionService $winrm
    ): JsonResponse {
        $server = $request->user()
            ->managedServers()
            ->findOrFail($id);

        try {
            $metrics = match ([$server->os_type, $server->connection_protocol]) {
                ['linux', 'ssh'] => $ssh->collectMetrics($server),
                ['windows', 'winrm'] => $winrm->collectMetrics($server),
                default => throw new RuntimeException('Kombinasi OS dan protokol belum didukung untuk monitoring.'),
            };

            $server->forceFill([
                'status' => 'online',
                'last_checked_at' => now(),
                'last_error' => null,
            ])->save();

            $latestSnapshot = $server->metricHistories()->latest('collected_at')->first();
            if (!$latestSnapshot || $latestSnapshot->collected_at->lt(now()->subSeconds(60))) {
                $server->metricHistories()->create([
                    'hostname' => $metrics['hostname'],
                    'os_name' => $metrics['os_name'],
                    'kernel' => $metrics['kernel'],
                    'uptime_seconds' => $metrics['uptime_seconds'],
                    'cpu_usage_percent' => $metrics['cpu']['usage_percent'],
                    'memory_usage_percent' => $metrics['memory']['usage_percent'],
                    'memory_used_mb' => $metrics['memory']['used_mb'],
                    'memory_total_mb' => $metrics['memory']['total_mb'],
                    'swap_usage_percent' => $metrics['swap']['usage_percent'],
                    'swap_used_mb' => $metrics['swap']['used_mb'],
                    'swap_total_mb' => $metrics['swap']['total_mb'],
                    'disk_usage_percent' => $metrics['disk']['usage_percent'],
                    'disk_used_gb' => $metrics['disk']['used_gb'],
                    'disk_total_gb' => $metrics['disk']['total_gb'],
                    'network_rx_bytes' => $metrics['network']['rx_bytes'],
                    'network_tx_bytes' => $metrics['network']['tx_bytes'],
                    'load_average' => $metrics['load_average'],
                    'collected_at' => now(),
                ]);
            }
        } catch (Throwable $exception) {
            $message = $exception instanceof RuntimeException
                ? $exception->getMessage()
                : 'Terjadi kesalahan saat mengambil data monitoring.';

            $server->forceFill([
                'status' => 'error',
                'last_checked_at' => now(),
                'last_error' => $message,
            ])->save();

            return response()->json([
                'message' => $message,
                'server_status' => [
                    'id' => $server->id,
                    'status' => 'error',
                ],
            ], 502);
        }

        return response()->json([
            'message' => 'Monitoring berhasil.',
            'metrics' => $metrics,
            'server_status' => [
                'id' => $server->id,
                'status' => 'online',
                'last_checked_at' => $server->fresh()->last_checked_at,
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
