<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\ManagedServer;
use App\Models\User;
use App\Models\UserAllowedIp;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;
use App\Services\SshConnectionService;
use Throwable;

class ServerController extends Controller
{
    private function rules(bool $updating = false): array
    {
        $required = $updating ? 'sometimes' : 'required';

        return [
            'name' => [$required, 'string', 'max:100'],
            'hostname' => ['nullable', 'string', 'max:255'],
            'ip_address' => ['nullable', 'ip'],
            'os_type' => [$required, Rule::in(['linux', 'windows'])],
            'connection_protocol' => [
                $required,
                Rule::in(['ssh', 'winrm', 'windows_openssh']),
            ],
            'port' => ['sometimes', 'integer', 'min:1', 'max:65535'],
            'username' => [$required, 'string', 'max:100'],
            'auth_method' => [
                $required,
                Rule::in(['password', 'private_key']),
            ],
            'password' => [
                $updating ? 'sometimes' : 'required_if:auth_method,password',
                'nullable',
                'string',
            ],
            'private_key' => [
                $updating ? 'sometimes' : 'required_if:auth_method,private_key',
                'nullable',
                'string',
            ],
            'private_key_passphrase' => ['nullable', 'string'],
            'verify_host_key' => ['sometimes', 'boolean'],
            'host_key_fingerprint' => ['nullable', 'string', 'max:255'],
            'notes' => ['nullable', 'string'],
        ];
    }

    private function validateProtocol(array $data, ?ManagedServer $server = null): void
    {
        $os = $data['os_type'] ?? $server?->os_type;
        $protocol = $data['connection_protocol'] ?? $server?->connection_protocol;

        $valid = match ($os) {
            'linux' => $protocol === 'ssh',
            'windows' => in_array($protocol, ['winrm', 'windows_openssh'], true),
            default => false,
        };

        if (!$valid) {
            abort(response()->json([
                'message' => 'Protokol koneksi tidak sesuai dengan sistem operasi.',
                'errors' => [
                    'connection_protocol' => [
                        'Linux menggunakan SSH. Windows menggunakan WinRM atau Windows OpenSSH.',
                    ],
                ],
            ], 422));
        }
    }

    public function index(Request $request): JsonResponse
    {
        $user = $request->user();
        $servers = $user->managedServers()
            ->with('latestMetric')
            ->latest()
            ->paginate(20);

        $servers->getCollection()->transform(function (ManagedServer $server) use ($user) {
            $arr = $server->toArray();
            $arr['ip_access'] = $this->resolveIpAccess($user, $server->ip_address, $server->hostname);
            $arr['latest_metric'] = $server->latestMetric ? $server->latestMetric->toArray() : null;
            return $arr;
        });

        return response()->json($servers);
    }

    public function store(Request $request): JsonResponse
    {
        $data = $request->validate($this->rules());

        $this->validateProtocol($data);
        $this->assertIpAllowedForMutation($request->user(), $data['ip_address'] ?? null, $data['hostname'] ?? null);
        $this->assertIpNotDuplicate($data['ip_address'] ?? null, $data['hostname'] ?? null);

        if ($data['auth_method'] === 'password' && empty($data['password'])) {
            return response()->json([
                'message' => 'Password wajib diisi.',
            ], 422);
        }

        if ($data['auth_method'] === 'private_key' && empty($data['private_key'])) {
            return response()->json([
                'message' => 'Private key wajib diisi.',
            ], 422);
        }

        $data['port'] ??= match ($data['connection_protocol']) {
            'winrm' => 5985,
            default => 22,
        };

        $server = $request->user()->managedServers()->create($data);

        return response()->json([
            'message' => 'Server berhasil ditambahkan.',
            'server' => $server,
        ], 201);
    }

    public function show(Request $request, int $id): JsonResponse
    {
        $server = $request->user()
            ->managedServers()
            ->findOrFail($id);

        $access = $this->resolveIpAccess($request->user(), $server->ip_address, $server->hostname);
        if (!$access['allowed']) {
            return response()->json([
                'message' => $access['message'] ?: 'Akses detail server ditolak.',
                'ip_access' => $access,
            ], 403);
        }

        $arr = $server->toArray();
        $arr['ip_access'] = $access;

        return response()->json(['server' => $arr]);
    }

    public function update(Request $request, int $id): JsonResponse
    {
        $server = $request->user()
            ->managedServers()
            ->findOrFail($id);

        $data = $request->validate($this->rules(true));

        $this->validateProtocol($data, $server);
        $this->assertIpAllowedForMutation(
            $request->user(),
            array_key_exists('ip_address', $data) ? $data['ip_address'] : $server->ip_address,
            array_key_exists('hostname', $data) ? $data['hostname'] : $server->hostname
        );
        $this->assertIpNotDuplicate(
            array_key_exists('ip_address', $data) ? $data['ip_address'] : $server->ip_address,
            array_key_exists('hostname', $data) ? $data['hostname'] : $server->hostname,
            $server->id
        );

        $effectiveAuth = $data['auth_method'] ?? $server->auth_method;

        if (
            $effectiveAuth === 'password' &&
            ($data['auth_method'] ?? null) !== null &&
            empty($data['password']) &&
            $server->auth_method !== 'password'
        ) {
            return response()->json([
                'message' => 'Password baru wajib diisi saat mengganti metode autentikasi.',
            ], 422);
        }

        if (
            $effectiveAuth === 'private_key' &&
            ($data['auth_method'] ?? null) !== null &&
            empty($data['private_key']) &&
            $server->auth_method !== 'private_key'
        ) {
            return response()->json([
                'message' => 'Private key baru wajib diisi saat mengganti metode autentikasi.',
            ], 422);
        }

        // Hapus credential yang tidak sesuai dengan metode autentikasi aktif.
        // Credential metode aktif tetap dipertahankan jika tidak dikirim.
        if ($effectiveAuth === 'password') {
            $data['private_key'] = null;
            $data['private_key_passphrase'] = null;
        } else {
            $data['password'] = null;
        }

        $server->update($data);

        return response()->json([
            'message' => 'Server berhasil diperbarui.',
            'server' => $server->fresh(),
        ]);
    }

    public function destroy(Request $request, int $id): JsonResponse
    {
        $server = $request->user()
            ->managedServers()
            ->findOrFail($id);

        $server->delete();

        return response()->json([
            'message' => 'Server berhasil dihapus.',
        ]);
    }

    public function discoverHostKey(
        Request $request,
        int $id,
        SshConnectionService $sshService
    ): JsonResponse {
        $server = $request->user()
            ->managedServers()
            ->findOrFail($id);

        try {
            $result = $sshService->discoverHostKey($server);

            return response()->json([
                'message' => 'Fingerprint host key berhasil ditemukan.',
                'host_key' => $result,
                'warning' => 'Bandingkan fingerprint ini dengan fingerprint server melalui jalur tepercaya sebelum menyimpannya.',
            ]);
        } catch (Throwable $exception) {
            return response()->json([
                'message' => $exception->getMessage(),
            ], 502);
        }
    }

    public function testConnection(
        Request $request,
        int $id,
        SshConnectionService $sshService
    ): JsonResponse {
        $server = $request->user()
            ->managedServers()
            ->findOrFail($id);

        try {
            $result = $sshService->testConnection($server);

            $server->forceFill([
                'status' => 'online',
                'last_checked_at' => now(),
                'last_error' => null,
            ])->save();

            return response()->json([
                'message' => $result['message'],
                'connected' => true,
                'host_key_fingerprint' => $result['host_key_fingerprint'],
                'server' => $server->fresh(),
            ]);
        } catch (Throwable $exception) {
            $safeMessage = $exception->getMessage();

            $server->forceFill([
                'status' => 'error',
                'last_checked_at' => now(),
                'last_error' => $safeMessage,
            ])->save();

            return response()->json([
                'message' => $safeMessage,
                'connected' => false,
                'server' => $server->fresh(),
            ], 502);
        }
    }

    private function resolveIpAccess(User $user, ?string $ipAddress, ?string $hostname): array
    {
        if ($user->isSuperAdministrator()) {
            return [
                'allowed' => true,
                'status' => 'permanent',
                'label' => 'Aktif Permanen',
                'message' => null,
                'expires_at' => null,
            ];
        }

        $targetIp = $ipAddress ?: (filter_var((string) $hostname, FILTER_VALIDATE_IP) ? $hostname : null);
        if (!$targetIp) {
            return [
                'allowed' => false,
                'status' => 'unregistered',
                'label' => 'IP belum terdaftar',
                'message' => 'IP server wajib didaftarkan oleh administrator sebelum digunakan.',
                'expires_at' => null,
            ];
        }

        $rule = UserAllowedIp::query()
            ->where('user_id', $user->id)
            ->where('ip_address', $targetIp)
            ->first();

        if (!$rule) {
            return [
                'allowed' => false,
                'status' => 'unregistered',
                'label' => 'IP belum terdaftar',
                'message' => "IP {$targetIp} belum didaftarkan untuk akun Anda.",
                'expires_at' => null,
            ];
        }

        return $rule->evaluateAccess();
    }

    private function assertIpAllowedForMutation(User $user, ?string $ipAddress, ?string $hostname): void
    {
        $access = $this->resolveIpAccess($user, $ipAddress, $hostname);
        if (!$access['allowed']) {
            abort(response()->json([
                'message' => $access['message'] ?: 'IP server tidak diizinkan.',
                'errors' => [
                    'ip_address' => [$access['message'] ?: 'IP server tidak diizinkan.'],
                ],
            ], 422));
        }
    }

    private function assertIpNotDuplicate(?string $ipAddress, ?string $hostname, ?int $ignoreServerId = null): void
    {
        $targetIp = trim((string) ($ipAddress ?: (filter_var((string) $hostname, FILTER_VALIDATE_IP) ? $hostname : '')));
        if ($targetIp === '') {
            return;
        }

        $query = ManagedServer::query()->where(function ($q) use ($targetIp) {
            $q->where('ip_address', $targetIp)
                ->orWhere('hostname', $targetIp);
        });

        if ($ignoreServerId !== null) {
            $query->where('id', '!=', $ignoreServerId);
        }

        if ($query->exists()) {
            $msg = "Server dengan IP {$targetIp} sudah terdaftar dan tidak dapat diduplikasi.";
            abort(response()->json([
                'message' => $msg,
                'errors' => [
                    'ip_address' => [$msg],
                ],
            ], 422));
        }
    }
}
