<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class UserAllowedIp extends Model
{
    protected $fillable = [
        'user_id',
        'ip_address',
        'access_type',
        'expires_at',
        'notes',
    ];

    protected function casts(): array
    {
        return [
            'expires_at' => 'datetime',
        ];
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function evaluateAccess(): array
    {
        if ($this->access_type === 'inactive') {
            return [
                'allowed' => false,
                'status' => 'inactive',
                'label' => 'Tidak aktif',
                'message' => 'Akses IP server ini sedang dinonaktifkan.',
                'expires_at' => null,
            ];
        }

        if ($this->access_type === 'timed') {
            if ($this->expires_at && now()->greaterThan($this->expires_at)) {
                return [
                    'allowed' => false,
                    'status' => 'expired',
                    'label' => 'Server sudah habis masa aktifnya',
                    'message' => 'Server sudah habis masa aktifnya.',
                    'expires_at' => $this->expires_at->toISOString(),
                ];
            }

            return [
                'allowed' => true,
                'status' => 'timed',
                'label' => $this->expires_at ? 'Aktif s/d ' . $this->expires_at->timezone('Asia/Jakarta')->format('d M Y H:i') : 'Masa Aktif',
                'message' => null,
                'expires_at' => $this->expires_at?->toISOString(),
            ];
        }

        return [
            'allowed' => true,
            'status' => 'permanent',
            'label' => 'Aktif Permanen',
            'message' => null,
            'expires_at' => null,
        ];
    }
}
