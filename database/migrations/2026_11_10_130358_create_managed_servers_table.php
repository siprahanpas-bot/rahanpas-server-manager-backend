<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('managed_servers', function (Blueprint $table) {
            $table->id();

            // Pemilik server
            $table->foreignId('user_id')
                ->constrained()
                ->cascadeOnDelete();

            // Identitas server
            $table->string('name', 100);
            $table->string('hostname', 255)->nullable();
            $table->string('ip_address', 45)->nullable();

            // Sistem operasi dan protokol koneksi
            $table->enum('os_type', ['linux', 'windows']);
            $table->enum('connection_protocol', [
                'ssh',
                'winrm',
                'windows_openssh',
            ]);

            $table->unsignedSmallInteger('port')->default(22);
            $table->string('username', 100);

            // Metode autentikasi
            $table->enum('auth_method', [
                'password',
                'private_key',
            ])->default('password');

            // Kolom kredensial: wajib dienkripsi melalui Laravel Model Cast
            $table->text('password')->nullable();
            $table->longText('private_key')->nullable();
            $table->text('private_key_passphrase')->nullable();

            // Verifikasi identitas host SSH
            $table->boolean('verify_host_key')->default(true);
            $table->string('host_key_fingerprint', 255)->nullable();

            // Status koneksi
            $table->enum('status', [
                'unknown',
                'online',
                'offline',
                'error',
            ])->default('unknown');

            $table->timestamp('last_checked_at')->nullable();
            $table->text('last_error')->nullable();
            $table->text('notes')->nullable();

            $table->timestamps();

            // Indeks untuk pencarian dan filtering
            $table->index(['user_id', 'status']);
            $table->index(['user_id', 'os_type']);
            $table->unique(['user_id', 'name']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('managed_servers');
    }
};
