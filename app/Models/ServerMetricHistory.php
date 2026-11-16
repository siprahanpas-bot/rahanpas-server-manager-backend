<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class ServerMetricHistory extends Model
{
    protected $fillable = [
        'managed_server_id',
        'hostname',
        'os_name',
        'kernel',
        'uptime_seconds',
        'cpu_usage_percent',
        'memory_usage_percent',
        'memory_used_mb',
        'memory_total_mb',
        'swap_usage_percent',
        'swap_used_mb',
        'swap_total_mb',
        'disk_usage_percent',
        'disk_used_gb',
        'disk_total_gb',
        'network_rx_bytes',
        'network_tx_bytes',
        'load_average',
        'collected_at',
    ];

    protected function casts(): array
    {
        return [
            'uptime_seconds' => 'integer',
            'cpu_usage_percent' => 'float',
            'memory_usage_percent' => 'float',
            'memory_used_mb' => 'float',
            'memory_total_mb' => 'float',
            'swap_usage_percent' => 'float',
            'swap_used_mb' => 'float',
            'swap_total_mb' => 'float',
            'disk_usage_percent' => 'float',
            'disk_used_gb' => 'float',
            'disk_total_gb' => 'float',
            'network_rx_bytes' => 'integer',
            'network_tx_bytes' => 'integer',
            'load_average' => 'array',
            'collected_at' => 'datetime',
        ];
    }

    public function managedServer(): BelongsTo
    {
        return $this->belongsTo(ManagedServer::class);
    }
}
