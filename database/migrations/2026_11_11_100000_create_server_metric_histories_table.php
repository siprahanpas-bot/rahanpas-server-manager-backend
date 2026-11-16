<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('server_metric_histories', function (Blueprint $table) {
            $table->id();

            $table->foreignId('managed_server_id')
                ->constrained('managed_servers')
                ->cascadeOnDelete();

            // Informasi sistem
            $table->string('hostname', 255)->nullable();
            $table->string('os_name', 255)->nullable();
            $table->string('kernel', 255)->nullable();
            $table->unsignedBigInteger('uptime_seconds')->default(0);

            // CPU
            $table->decimal('cpu_usage_percent', 7, 2)->default(0);

            // Memory
            $table->decimal('memory_usage_percent', 7, 2)->default(0);
            $table->decimal('memory_used_mb', 12, 2)->default(0);
            $table->decimal('memory_total_mb', 12, 2)->default(0);

            // Swap
            $table->decimal('swap_usage_percent', 7, 2)->default(0);
            $table->decimal('swap_used_mb', 12, 2)->default(0);
            $table->decimal('swap_total_mb', 12, 2)->default(0);

            // Root disk
            $table->decimal('disk_usage_percent', 7, 2)->default(0);
            $table->decimal('disk_used_gb', 12, 2)->default(0);
            $table->decimal('disk_total_gb', 12, 2)->default(0);

            // Network cumulative counters
            $table->unsignedBigInteger('network_rx_bytes')->default(0);
            $table->unsignedBigInteger('network_tx_bytes')->default(0);

            // Load average 1, 5, 15 menit
            $table->json('load_average')->nullable();

            $table->timestamp('collected_at');

            $table->timestamps();

            $table->index(
                ['managed_server_id', 'collected_at'],
                'server_metric_histories_server_collected_index'
            );
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('server_metric_histories');
    }
};
