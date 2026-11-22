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
