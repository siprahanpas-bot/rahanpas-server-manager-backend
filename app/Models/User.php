<?php

namespace App\Models;

use Database\Factories\UserFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Laravel\Sanctum\HasApiTokens;
use Illuminate\Notifications\Notifiable;

#[Fillable(['name', 'email', 'phone', 'password', 'account_status'])]
#[Hidden(['password', 'remember_token'])]
class User extends Authenticatable
{
    /** @use HasFactory<UserFactory> */
    use HasApiTokens, HasFactory, Notifiable;

    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
        ];
    }

    public function managedServers(): HasMany
    {
        return $this->hasMany(ManagedServer::class);
    }

    public function groups(): BelongsToMany
    {
        return $this->belongsToMany(Group::class);
    }

    public function hasPermission(string $permission): bool
    {
        // Akun lama yang belum dimasukkan ke group tetap berfungsi.
        if ($this->groups()->get()->isEmpty()) {
            return true;
        }

        return $this->groups()
            ->whereHas('roles', function ($query) use ($permission) {
                $query->where('slug', 'super-administrator')
                    ->orWhereHas('permissions', function ($permissionQuery) use ($permission) {
                        $permissionQuery->where('slug', $permission);
                    });
            })
            ->get()
            ->isNotEmpty();
    }

    public function isSuperAdministrator(): bool
    {
        $superAdminEmail = (string) config('rahanpas.super_admin_email', '');

        if (
            $superAdminEmail !== ''
            && strtolower((string) $this->email) === $superAdminEmail
        ) {
            return true;
        }

        if ($this->groups()->count() === 0) {
            return true;
        }

        return $this->groups()->where('slug', 'super-administrator')->exists();
    }

    public function permissionSlugs(): array
    {
        if ($this->isSuperAdministrator()) {
            return Permission::query()->orderBy('slug')->pluck('slug')->all();
        }

        return $this->groups()
            ->with('roles.permissions:id,slug')
            ->get()
            ->flatMap(fn ($group) => $group->roles)
            ->flatMap(fn ($role) => $role->permissions)
            ->pluck('slug')
            ->unique()
            ->values()
            ->all();
    }
}
