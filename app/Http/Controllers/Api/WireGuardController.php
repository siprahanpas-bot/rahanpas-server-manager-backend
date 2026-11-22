<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\ManagedServer;
use App\Services\ManagedServerAccessService;
use App\Services\SshConnectionService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Throwable;

class WireGuardController extends Controller
{
    /**
     * Resolve server berdasarkan ownership user dan IP Access Policy.
     */
    private function resolveAccessibleServer(
        Request $request,
        int $id,
        ManagedServerAccessService $accessService
    ): ManagedServer {
        $server = $request->user()
            ->managedServers()
            ->findOrFail($id);

        $accessService->assertIpAllowedForView(
            $request->user(),
            $server
        );

        return $server;
    }

    /**
     * GET /wireguard/servers
     *
     * Daftar server Linux/SSH milik user yang dapat diakses
     * melalui permission WireGuard, tanpa membutuhkan server.view.
     */
    public function indexServers(
        Request $request,
        ManagedServerAccessService $accessService
    ): JsonResponse {
        $servers = $request->user()
            ->managedServers()
            ->where('os_type', 'linux')
            ->where('connection_protocol', 'ssh')
            ->where('is_wireguard_server', true)
            ->latest()
            ->get([
                'id',
                'name',
                'hostname',
                'ip_address',
                'os_type',
                'connection_protocol',
                'status',
                'last_checked_at',
            ]);

        $items = $servers->map(function (ManagedServer $server) use ($request, $accessService) {
            return [
                'id' => $server->id,
                'name' => $server->name,
                'hostname' => $server->hostname,
                'ip_address' => $server->ip_address,
                'os_type' => $server->os_type,
                'connection_protocol' => $server->connection_protocol,
                'status' => $server->status,
                'last_checked_at' => $server->last_checked_at,
                'ip_access' => $accessService->resolveIpAccess(
                    $request->user(),
                    $server->ip_address,
                    $server->hostname
                ),
            ];
        });

        return response()->json([
            'servers' => $items,
            'total' => $items->count(),
        ]);
    }

    /**
     * GET /wireguard/candidates
     *
     * Kandidat berasal dari record server milik user yang belum
     * diklasifikasikan sebagai WireGuard Server.
     */
    public function candidates(
        Request $request,
        ManagedServerAccessService $accessService
    ): JsonResponse {
        $servers = $request->user()
            ->managedServers()
            ->where('os_type', 'linux')
            ->where('connection_protocol', 'ssh')
            ->where('is_wireguard_server', false)
            ->latest()
            ->get([
                'id',
                'name',
                'hostname',
                'ip_address',
                'os_type',
                'connection_protocol',
                'status',
            ]);

        $items = $servers->map(function (ManagedServer $server) use ($request, $accessService) {
            return [
                'id' => $server->id,
                'name' => $server->name,
                'hostname' => $server->hostname,
                'ip_address' => $server->ip_address,
                'status' => $server->status,
                'ip_access' => $accessService->resolveIpAccess(
                    $request->user(),
                    $server->ip_address,
                    $server->hostname
                ),
            ];
        });

        return response()->json([
            'candidates' => $items,
            'total' => $items->count(),
        ]);
    }

    /**
     * POST /wireguard/servers/{id}/register
     *
     * Mendaftarkan record server yang sudah ada setelah deteksi SSH
     * read-only memastikan terdapat interface WireGuard aktif.
     */
    public function registerServer(
        Request $request,
        int $id,
        SshConnectionService $sshService,
        ManagedServerAccessService $accessService
    ): JsonResponse {
        $server = $request->user()
            ->managedServers()
            ->findOrFail($id);

        $accessService->assertIpAllowedForView(
            $request->user(),
            $server
        );

        if (
            $server->os_type !== 'linux' ||
            $server->connection_protocol !== 'ssh'
        ) {
            return response()->json([
                'message' => 'Hanya server Linux dengan koneksi SSH yang dapat didaftarkan.',
            ], 422);
        }

        if ($server->is_wireguard_server) {
            return response()->json([
                'message' => 'Server ini sudah terdaftar sebagai WireGuard Server.',
                'server_id' => $server->id,
            ], 409);
        }

        try {
            $supported = $sshService->detectWireGuardSupport($server);

            if (!$supported) {
                return response()->json([
                    'message' => 'Interface WireGuard aktif tidak ditemukan. Server tidak didaftarkan.',
                ], 422);
            }

            $server->forceFill([
                'is_wireguard_server' => true,
            ])->save();

            return response()->json([
                'message' => 'Server berhasil didaftarkan sebagai WireGuard Server.',
                'server' => [
                    'id' => $server->id,
                    'name' => $server->name,
                    'hostname' => $server->hostname,
                    'ip_address' => $server->ip_address,
                ],
            ], 201);
        } catch (Throwable $exception) {
            Log::warning('WireGuard server registration detection failed.', [
                'server_id' => $server->id,
                'exception' => get_class($exception),
            ]);

            return response()->json([
                'message' => 'Pemeriksaan SSH atau deteksi WireGuard gagal. Server belum didaftarkan.',
            ], 502);
        }
    }

    /**
     * GET /servers/{id}/wireguard/status
     */
    public function status(
        Request $request,
        int $id,
        SshConnectionService $sshService,
        ManagedServerAccessService $accessService
    ): JsonResponse {
        $server = $this->resolveAccessibleServer(
            $request,
            $id,
            $accessService
        );

        try {
            // Deteksi dilakukan untuk setiap server, tanpa ketergantungan ID.
            $supported = $sshService->detectWireGuardSupport($server);

            if (!$supported) {
                return response()->json([
                    'success' => true,
                    'server_id' => $server->id,
                    'server_name' => $server->name,
                    'supported' => false,
                    'wireguard' => null,
                ]);
            }

            $result = $sshService->executeWireGuardOperation(
                $server,
                'status'
            );

            return response()->json([
                'success' => true,
                'server_id' => $server->id,
                'server_name' => $server->name,
                'supported' => true,
                'wireguard' => $result,
            ]);
        } catch (Throwable $exception) {
            Log::warning('WireGuard status request failed.', [
                'server_id' => $server->id,
                'exception' => get_class($exception),
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Gagal mengambil status WireGuard dari server.',
            ], 502);
        }
    }

    /**
     * GET /servers/{id}/wireguard/peers
     */
    public function peers(
        Request $request,
        int $id,
        SshConnectionService $sshService,
        ManagedServerAccessService $accessService
    ): JsonResponse {
        $server = $this->resolveAccessibleServer(
            $request,
            $id,
            $accessService
        );

        try {
            $result = $sshService->executeWireGuardOperation(
                $server,
                'peers'
            );

            return response()->json([
                'success' => true,
                'server_id' => $server->id,
                'server_name' => $server->name,
                'wireguard' => $result,
            ]);
        } catch (Throwable $exception) {
            Log::warning('WireGuard peers request failed.', [
                'server_id' => $server->id,
                'exception' => get_class($exception),
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Gagal mengambil daftar peer WireGuard dari server.',
            ], 502);
        }

    }

    /**
     * GET /servers/{id}/wireguard/peers/{name}/config
     */
    public function getPeerConfig(
        Request $request,
        int $id,
        string $name,
        SshConnectionService $sshService,
        ManagedServerAccessService $accessService
    ): JsonResponse {
        $headers = [
            'Cache-Control' => 'no-store, no-cache, must-revalidate, private',
            'Pragma' => 'no-cache',
            'Expires' => '0',
            'X-Content-Type-Options' => 'nosniff',
        ];

        if (!preg_match('/\A[A-Za-z0-9_-]{1,32}\z/', $name)) {
            return response()->json([
                'success' => false,
                'message' => 'Nama peer WireGuard tidak valid.',
            ], 422)->withHeaders($headers);
        }

        $server = $this->resolveAccessibleServer(
            $request,
            $id,
            $accessService
        );

        try {
            $result = $sshService->executeWireGuardOperation(
                $server,
                'get-config',
                ['name' => $name]
            );

            return response()->json([
                'success' => true,
                'server_id' => $server->id,
                'server_name' => $server->name,
                'wireguard' => [
                    'peer' => $result['peer'],
                    'config' => $result['config'],
                    'qr_png_base64' => $result['qr_png_base64'],
                ],
            ])->withHeaders($headers);
        } catch (Throwable $exception) {
            Log::warning('WireGuard peer config retrieval failed.', [
                'server_id' => $server->id,
                'exception' => get_class($exception),
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Gagal mengambil konfigurasi peer WireGuard.',
            ], 502)->withHeaders($headers);
        }
    }

    /**
     * POST /servers/{id}/wireguard/peers
     *
     * Respons membawa private key melalui konfigurasi client.
     * Jangan menyimpan atau mencatat isi respons ke log/cache.
     */
    public function createPeer(
        Request $request,
        int $id,
        SshConnectionService $sshService,
        ManagedServerAccessService $accessService
    ): JsonResponse {
        $data = $request->validate([
            'name' => [
                'required',
                'string',
                'regex:/\A[A-Za-z0-9_-]{1,32}\z/',
            ],
        ]);

        $server = $request->user()
            ->managedServers()
            ->findOrFail($id);

        $accessService->assertIpAllowedForMutation(
            $request->user(),
            $server->ip_address,
            $server->hostname
        );

        try {
            $result = $sshService->executeWireGuardOperation(
                $server,
                'create',
                ['name' => $data['name']]
            );

            return response()->json([
                'success' => true,
                'server_id' => $server->id,
                'server_name' => $server->name,
                'wireguard' => [
                    'peer' => $result['peer'],
                    'config' => $result['config'],
                    'qr_png_base64' => $result['qr_png_base64'],
                ],
            ], 201)
                ->header(
                    'Cache-Control',
                    'no-store, no-cache, must-revalidate, private'
                )
                ->header('Pragma', 'no-cache')
                ->header('Expires', '0')
                ->header('X-Content-Type-Options', 'nosniff');
        } catch (Throwable $exception) {
            // Jangan log exception message, output SSH, private key,
            // konfigurasi client, ataupun QR.
            Log::warning('WireGuard peer creation failed.', [
                'server_id' => $server->id,
                'exception' => get_class($exception),
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Gagal membuat peer WireGuard pada server tujuan.',
            ], 502)
                ->header(
                    'Cache-Control',
                    'no-store, no-cache, must-revalidate, private'
                )
                ->header('Pragma', 'no-cache')
                ->header('Expires', '0');
        }
    }

}
