<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        $now = now();

        $permissions = [
            [
                'name' => 'WireGuard View',
                'slug' => 'wireguard.view',
                'description' => 'Melihat status dan daftar peer WireGuard.',
            ],
            [
                'name' => 'WireGuard Manage',
                'slug' => 'wireguard.manage',
                'description' => 'Mengelola client, konfigurasi, QR, dan backup WireGuard.',
            ],
        ];

        foreach ($permissions as $permission) {
            DB::table('permissions')->insertOrIgnore([
                ...$permission,
                'created_at' => $now,
                'updated_at' => $now,
            ]);
        }

        // Permission baru hanya diberikan kepada role Super Administrator.
        $adminRoleId = DB::table('roles')
            ->where('slug', 'super-administrator')
            ->value('id');

        if (!$adminRoleId) {
            throw new RuntimeException(
                'Role super-administrator tidak ditemukan.'
            );
        }

        $permissionIds = DB::table('permissions')
            ->whereIn('slug', ['wireguard.view', 'wireguard.manage'])
            ->pluck('id');

        foreach ($permissionIds as $permissionId) {
            DB::table('permission_role')->insertOrIgnore([
                'permission_id' => $permissionId,
                'role_id' => $adminRoleId,
            ]);
        }
    }

    public function down(): void
    {
        $permissionIds = DB::table('permissions')
            ->whereIn('slug', ['wireguard.view', 'wireguard.manage'])
            ->pluck('id');

        DB::table('permission_role')
            ->whereIn('permission_id', $permissionIds)
            ->delete();

        DB::table('permissions')
            ->whereIn('slug', ['wireguard.view', 'wireguard.manage'])
            ->delete();
    }
};
