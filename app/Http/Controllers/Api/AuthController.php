<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;

class AuthController extends Controller
{
    public function register(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'phone' => ['required', 'regex:/^\+62[0-9]{8,13}$/', 'unique:users,phone'],
            'email' => ['required', 'email', 'max:255', 'unique:users,email'],
        ], [
            'phone.regex' => 'Nomor telepon harus menggunakan format +62 diikuti nomor telepon.',
        ]);

        $user = DB::transaction(function () use ($validated) {
            $user = User::create([
                'name' => $validated['name'],
                'phone' => $validated['phone'],
                'email' => Str::lower($validated['email']),
                'password' => Str::random(64),
                'account_status' => 'pending_verification',
            ]);

            $pendingGroup = DB::table('groups')
                ->where('slug', 'pending-verification')
                ->value('id');

            if ($pendingGroup) {
                $user->groups()->syncWithoutDetaching([$pendingGroup]);
            }

            return $user;
        });

        $token = Str::random(64);

        DB::table('account_activation_tokens')->insert([
            'user_id' => $user->id,
            'purpose' => 'email_verification',
            'token_hash' => hash('sha256', $token),
            'expires_at' => now()->addHours(24),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $url = rtrim((string) config('app.frontend_url', config('app.url')), '/') . '/verify-email?email=' .
            urlencode($user->email) . '&token=' . urlencode($token);

        Mail::raw(
            "Halo {$user->name},\n\nKlik tautan berikut untuk memverifikasi email Anda:\n\n{$url}\n\nTautan berlaku selama 24 jam.\n\nRAHANPAS SERVER MANAGER",
            function ($message) use ($user) {
                $message->to($user->email)
                    ->subject('Verifikasi Email - RAHANPAS SERVER MANAGER');
            }
        );

        return response()->json([
            'message' => 'Registrasi berhasil. Silakan periksa email untuk verifikasi.',
        ], 201);
    }

    public function resendVerification(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'email' => ['required', 'email', 'max:255'],
        ]);

        $email = Str::lower($validated['email']);

        $user = User::where('email', $email)->first();

        // Respons dibuat generik agar endpoint tidak membocorkan
        // keberadaan atau status suatu akun.
        if (
            !$user ||
            $user->email_verified_at ||
            $user->account_status !== 'pending_verification'
        ) {
            return response()->json([
                'message' => 'Jika akun dapat diverifikasi, tautan verifikasi akan dikirim ke email tersebut.',
            ]);
        }

        $token = Str::random(64);
        $tokenHash = hash('sha256', $token);

        DB::table('account_activation_tokens')->insert([
            'user_id' => $user->id,
            'purpose' => 'email_verification',
            'token_hash' => $tokenHash,
            'expires_at' => now()->addHours(24),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $url = rtrim((string) config('app.frontend_url', config('app.url')), '/') . '/verify-email?email=' .
            urlencode($user->email) . '&token=' . urlencode($token);

        try {
            Mail::raw(
                "Halo {$user->name},\n\nKlik tautan berikut untuk memverifikasi email Anda:\n\n{$url}\n\nTautan berlaku selama 24 jam.\n\nRAHANPAS SERVER MANAGER",
                function ($message) use ($user) {
                    $message->to($user->email)
                        ->subject('Verifikasi Email - RAHANPAS SERVER MANAGER');
                }
            );
        } catch (\Throwable $exception) {
            // Pertahankan token lama jika pengiriman email gagal.
            DB::table('account_activation_tokens')
                ->where('token_hash', $tokenHash)
                ->delete();

            report($exception);

            return response()->json([
                'message' => 'Email verifikasi belum berhasil dikirim. Silakan coba kembali nanti.',
            ], 503);
        }

        // Setelah email berhasil dikirim, nonaktifkan token verifikasi lama.
        DB::table('account_activation_tokens')
            ->where('user_id', $user->id)
            ->where('purpose', 'email_verification')
            ->whereNull('used_at')
            ->where('token_hash', '!=', $tokenHash)
            ->update([
                'used_at' => now(),
                'updated_at' => now(),
            ]);

        return response()->json([
            'message' => 'Jika akun dapat diverifikasi, tautan verifikasi akan dikirim ke email tersebut.',
        ]);
    }

    public function verifyEmail(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'email' => ['required', 'email'],
            'token' => ['required', 'string'],
        ]);

        $user = User::where('email', Str::lower($validated['email']))->first();

        if (!$user || $user->email_verified_at) {
            return response()->json(['message' => 'Tautan verifikasi tidak valid atau sudah digunakan.'], 422);
        }

        $setupToken = Str::random(64);

        $verified = DB::transaction(function () use ($user, $validated, $setupToken) {
            $activation = DB::table('account_activation_tokens')
                ->where('user_id', $user->id)
                ->where('purpose', 'email_verification')
                ->where('token_hash', hash('sha256', $validated['token']))
                ->whereNull('used_at')
                ->where('expires_at', '>', now())
                ->lockForUpdate()
                ->first();

            if (!$activation) {
                return false;
            }

            DB::table('account_activation_tokens')
                ->where('id', $activation->id)
                ->update(['used_at' => now(), 'updated_at' => now()]);

            $user->forceFill(['email_verified_at' => now()])->save();

            DB::table('account_activation_tokens')->insert([
                'user_id' => $user->id,
                'purpose' => 'password_setup',
                'token_hash' => hash('sha256', $setupToken),
                'expires_at' => now()->addHours(2),
                'created_at' => now(),
                'updated_at' => now(),
            ]);

            return true;
        });

        if (!$verified) {
            return response()->json(['message' => 'Token verifikasi tidak valid atau sudah kedaluwarsa.'], 422);
        }

        return response()->json([
            'message' => 'Email berhasil diverifikasi. Silakan buat password.',
            'password_setup_token' => $setupToken,
        ]);
    }

    public function setPassword(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'email' => ['required', 'email'],
            'token' => ['required', 'string'],
            'password' => ['required', 'string', 'min:12', 'confirmed'],
        ]);

        $user = User::where('email', Str::lower($validated['email']))->first();

        if (!$user || !$user->email_verified_at) {
            return response()->json(['message' => 'Email belum diverifikasi.'], 422);
        }

        $completed = DB::transaction(function () use ($user, $validated) {
            $activation = DB::table('account_activation_tokens')
                ->where('user_id', $user->id)
                ->where('purpose', 'password_setup')
                ->where('token_hash', hash('sha256', $validated['token']))
                ->whereNull('used_at')
                ->where('expires_at', '>', now())
                ->lockForUpdate()
                ->first();

            if (!$activation) {
                return false;
            }

            DB::table('account_activation_tokens')
                ->where('id', $activation->id)
                ->update(['used_at' => now(), 'updated_at' => now()]);

            $user->password = $validated['password'];
            $user->account_status = 'active';
            $user->save();

            $superAdminEmail = (string) config('rahanpas.super_admin_email', '');
            $isSuperAdmin = $superAdminEmail !== ''
                && strtolower((string) $user->email) === $superAdminEmail;

            $targetGroup = DB::table('groups')
                ->where('slug', $isSuperAdmin ? 'super-administrator' : 'registered-user')
                ->value('id');

            if ($targetGroup) {
                $user->groups()->sync([$targetGroup]);
            }

            return true;
        });

        if (!$completed) {
            return response()->json(['message' => 'Token pengaturan password tidak valid atau kedaluwarsa.'], 422);
        }

        return response()->json([
            'message' => 'Password berhasil dibuat. Silakan login.',
        ]);
    }


public function forgotPassword(Request $request): JsonResponse
{
    $validated = $request->validate([
        'email' => ['required', 'email', 'max:255'],
    ]);

    $email = Str::lower($validated['email']);
    $user = User::where('email', $email)->first();

    $genericMessage = 'Jika email terdaftar dan aktif, tautan reset password telah dikirim.';

    if (!$user) {
        return response()->json(['message' => $genericMessage]);
    }

    $token = Str::random(64);
    $tokenHash = hash('sha256', $token);
    $now = now();

    DB::table('account_activation_tokens')->insert([
        'user_id' => $user->id,
        'purpose' => 'password_reset',
        'token_hash' => $tokenHash,
        'expires_at' => $now->copy()->addHours(2),
        'created_at' => $now,
        'updated_at' => $now,
    ]);

    $url = rtrim((string) config('app.frontend_url', config('app.url')), '/')
        . '/reset-password?email=' . urlencode($user->email)
        . '&token=' . urlencode($token);

    try {
        Mail::raw(
            "Halo {$user->name},\n\nKami menerima permintaan untuk mengatur ulang password akun Anda.\nKlik tautan berikut untuk membuat password baru:\n\n{$url}\n\nTautan berlaku selama 2 jam. Jika Anda tidak meminta reset password, abaikan email ini.\n\nRAHANPAS SERVER MANAGER",
            function ($message) use ($user) {
                $message->to($user->email)
                    ->subject('Reset Password - RAHANPAS SERVER MANAGER');
            }
        );
    } catch (\Throwable $exception) {
        DB::table('account_activation_tokens')
            ->where('token_hash', $tokenHash)
            ->delete();

        report($exception);

        return response()->json([
            'message' => 'Email reset password belum berhasil dikirim. Silakan coba kembali nanti.',
        ], 503);
    }

    DB::table('account_activation_tokens')
        ->where('user_id', $user->id)
        ->where('purpose', 'password_reset')
        ->whereNull('used_at')
        ->where('token_hash', '!=' , $tokenHash)
        ->update([
            'used_at' => $now,
            'updated_at' => $now,
        ]);

    return response()->json(['message' => $genericMessage]);
}

public function resetPassword(Request $request): JsonResponse
{
    $validated = $request->validate([
        'email' => ['required', 'email'],
        'token' => ['required', 'string'],
        'password' => ['required', 'string', 'min:12', 'confirmed'],
    ]);

    $user = User::where('email', Str::lower($validated['email']))->first();

    if (!$user) {
        return response()->json(['message' => 'Tautan reset password tidak valid atau sudah kedaluwarsa.'], 422);
    }

    $reset = DB::transaction(function () use ($user, $validated) {
        $now = now();
        $activation = DB::table('account_activation_tokens')
            ->where('user_id', $user->id)
            ->where('purpose', 'password_reset')
            ->where('token_hash', hash('sha256', $validated['token']))
            ->whereNull('used_at')
            ->where('expires_at', '>', $now)
            ->lockForUpdate()
            ->first();

        if (!$activation) {
            return false;
        }

        DB::table('account_activation_tokens')
            ->where('id', $activation->id)
            ->update(['used_at' => $now, 'updated_at' => $now]);

        $user->password = $validated['password'];
        $user->save();

        DB::table('account_activation_tokens')
            ->where('user_id', $user->id)
            ->where('purpose', 'password_reset')
            ->whereNull('used_at')
            ->update(['used_at' => $now, 'updated_at' => $now]);

        return true;
    });

    if (!$reset) {
        return response()->json(['message' => 'Token reset password tidak valid atau sudah kedaluwarsa.'], 422);
    }

    return response()->json([
        'message' => 'Password berhasil diperbarui. Silakan login dengan password baru Anda.',
    ]);
}
    public function login(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'email' => ['required', 'email', 'max:255'],
            'password' => ['required', 'string', 'max:255'],
            'device_name' => ['required', 'string', 'max:100'],
        ]);

        $user = User::where('email', Str::lower($validated['email']))->first();

        if (!$user || !Hash::check($validated['password'], $user->password)) {
            return response()->json(['message' => 'Email atau password tidak valid.'], 401);
        }

        if ($user->account_status !== 'active') {
            return response()->json([
                'message' => 'Akun belum aktif. Selesaikan verifikasi email dan pengaturan password.',
            ], 403);
        }

        $token = $user->createToken($validated['device_name']);

        return response()->json([
            'message' => 'Login berhasil.',
            'token_type' => 'Bearer',
            'token' => $token->plainTextToken,
            'user' => $user,
        ]);
    }

    public function me(Request $request): JsonResponse
    {
        $user = $request->user()->load('groups:id,name,slug');

        return response()->json([
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'phone' => $user->phone,
                'account_status' => $user->account_status,
                'is_super_admin' => $user->isSuperAdministrator(),
                'groups' => $user->groups->map(fn ($g) => [
                    'id' => $g->id,
                    'name' => $g->name,
                    'slug' => $g->slug,
                ])->values(),
                'permissions' => $user->permissionSlugs(),
            ],
        ]);
    }

    public function logout(Request $request): JsonResponse
    {
        $request->user()->currentAccessToken()->delete();

        return response()->json(['message' => 'Logout berhasil.']);
    }

    public function googleConfig(): JsonResponse
    {
        return response()->json([
            'client_id' => (string) env('GOOGLE_CLIENT_ID', ''),
            'configured' => env('GOOGLE_CLIENT_ID', '') !== '' && env('GOOGLE_CLIENT_SECRET', '') !== '',
        ]);
    }

    public function googleExchange(Request $request): JsonResponse
    {
        $data = $request->validate([
            'code' => ['required', 'string'],
            'redirect_uri' => ['required', 'url'],
        ]);

        $clientId = (string) env('GOOGLE_CLIENT_ID', '');
        $clientSecret = (string) env('GOOGLE_CLIENT_SECRET', '');

        if ($clientId === '' || $clientSecret === '') {
            return response()->json([
                'message' => 'Google OAuth belum dikonfigurasi (GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET kosong).',
            ], 422);
        }

        $tokenRes = Http::asForm()->timeout(15)->post('https://oauth2.googleapis.com/token', [
            'code' => $data['code'],
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
            'redirect_uri' => $data['redirect_uri'],
            'grant_type' => 'authorization_code',
        ]);

        if (!$tokenRes->successful() || !$tokenRes->json('access_token')) {
            return response()->json([
                'message' => 'Gagal memverifikasi kode otorisasi Google.',
            ], 401);
        }

        $profileRes = Http::withToken($tokenRes->json('access_token'))
            ->timeout(15)
            ->get('https://www.googleapis.com/oauth2/v3/userinfo');

        if (!$profileRes->successful() || !$profileRes->json('email')) {
            return response()->json([
                'message' => 'Gagal mengambil profil akun Google.',
            ], 401);
        }

        $email = strtolower((string) $profileRes->json('email'));
        $name = (string) ($profileRes->json('name') ?: explode('@', $email)[0]);

        $user = \App\Models\User::where('email', $email)->first();

        if (!$user) {
            $user = \App\Models\User::create([
                'name' => $name,
                'email' => $email,
                'password' => bcrypt(Str::random(32)),
                'email_verified_at' => now(),
                'is_active' => true,
            ]);
        } elseif (!$user->email_verified_at) {
            $user->forceFill(['email_verified_at' => now()])->save();
        }

        if (isset($user->is_active) && !$user->is_active) {
            return response()->json([
                'message' => 'Akun Anda sedang dinonaktifkan.',
            ], 403);
        }

        $token = $user->createToken('google-oauth')->plainTextToken;

        return response()->json([
            'token' => $token,
            'user' => $user,
        ]);
    }
}
