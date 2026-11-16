<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;

class ManagedServer extends Model
{
    protected $attributes = [
        'status' => 'unknown',
    ];

    protected $fillable = [
        'name',
        'hostname',
        'ip_address',
        'os_type',
        'connection_protocol',
        'port',
        'username',
        'auth_method',
        'password',
        'private_key',
        'private_key_passphrase',
        'verify_host_key',
        'host_key_fingerprint',
        'notes',
    ];

    protected $hidden = [
        'password',
        'private_key',
        'private_key_passphrase',
    ];

    protected function casts(): array
    {
        return [
            'password' => 'encrypted',
            'private_key' => 'encrypted',
            'private_key_passphrase' => 'encrypted',
            'verify_host_key' => 'boolean',
            'last_checked_at' => 'datetime',
        ];
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function metricHistories(): HasMany
    {
        return $this->hasMany(ServerMetricHistory::class);
    }

    public function latestMetric(): HasOne
    {
        return $this->hasOne(ServerMetricHistory::class)->latestOfMany('collected_at');
    }
}
