<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        RateLimiter::for('storage-mount', function (Request $request) {
            $user = $request->user();
            $identity = $user
                ? 'user:' . $user->getAuthIdentifier()
                : 'ip:' . $request->ip();

            $serverId = (string) $request->route('id');

            return Limit::perMinute(30)
                ->by("storage-mount:{$identity}:server:{$serverId}");
        });

        RateLimiter::for('storage-unmount', function (Request $request) {
            $user = $request->user();
            $identity = $user
                ? 'user:' . $user->getAuthIdentifier()
                : 'ip:' . $request->ip();

            $serverId = (string) $request->route('id');

            return Limit::perMinute(30)
                ->by("storage-unmount:{$identity}:server:{$serverId}");
        });

        RateLimiter::for('storage-devices', function (Request $request) {
            $user = $request->user();
            $identity = $user
                ? 'user:' . $user->getAuthIdentifier()
                : 'ip:' . $request->ip();

            $serverId = (string) $request->route('id');

            return Limit::perMinute(60)
                ->by("storage-devices:{$identity}:server:{$serverId}");
        });
    }
}
