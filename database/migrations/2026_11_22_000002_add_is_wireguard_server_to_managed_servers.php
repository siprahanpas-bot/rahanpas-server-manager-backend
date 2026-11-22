<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('managed_servers', function (Blueprint $table) {
            $table->boolean('is_wireguard_server')
                ->default(false)
                ->after('connection_protocol');

            $table->index(
                ['user_id', 'is_wireguard_server'],
                'managed_servers_user_wireguard_idx'
            );
        });
    }

    public function down(): void
    {
        Schema::table('managed_servers', function (Blueprint $table) {
            $table->dropIndex('managed_servers_user_wireguard_idx');
            $table->dropColumn('is_wireguard_server');
        });
    }
};
