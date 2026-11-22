<?php

namespace App\Services;

use App\Models\ManagedServer;
use App\Models\User;
use App\Models\UserAllowedIp;

class ManagedServerAccessService
{
    /**
     * Memeriksa izin akses user terhadap IP server.
     */
    public function resolveIpAccess(
        User $user,
        ?string $ipAddress,
        ?string $hostname
    ): array {
        if ($user->isSuperAdministrator()) {
            return [
                'allowed' => true,
                'status' => 'permanent',
                'label' => 'Aktif Permanen',
                'message' => null,
                'expires_at' => null,
            ];
        }

        $targetIp = $ipAddress ?: (
            filter_var((string) $hostname, FILTER_VALIDATE_IP)
                ? $hostname
                : null
        );

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

    /**
     * Menolak operasi jika IP server tidak diizinkan.
     */
    public function assertIpAllowedForMutation(
        User $user,
        ?string $ipAddress,
        ?string $hostname
    ): void {
        $access = $this->resolveIpAccess($user, $ipAddress, $hostname);

        if (!$access['allowed']) {
            abort(response()->json([
                'message' => $access['message'] ?: 'IP server tidak diizinkan.',
                'errors' => [
                    'ip_address' => [
                        $access['message'] ?: 'IP server tidak diizinkan.',
                    ],
                ],
            ], 422));
        }
    }

    /**
     * Memeriksa akses sebelum menampilkan detail server.
     */
    public function assertIpAllowedForView(
        User $user,
        ManagedServer $server
    ): array {
        $access = $this->resolveIpAccess(
            $user,
            $server->ip_address,
            $server->hostname
        );

        if (!$access['allowed']) {
            abort(response()->json([
                'message' => $access['message'] ?: 'Akses detail server ditolak.',
                'ip_access' => $access,
            ], 403));
        }

        return $access;
    }
}
