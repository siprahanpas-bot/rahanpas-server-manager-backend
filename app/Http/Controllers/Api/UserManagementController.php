<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Group;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\Rule;

class UserManagementController extends Controller
{
    public function index(Request $request): JsonResponse
    {
        $search = trim((string) $request->query('search', ''));
        $status = trim((string) $request->query('status', ''));

        $query = User::query()
            ->with('groups:id,name,slug')
            ->orderBy('id');

        if ($search !== '') {
            $query->where(function ($q) use ($search) {
                $q->where('name', 'like', "%{$search}%")
                    ->orWhere('email', 'like', "%{$search}%")
                    ->orWhere('phone', 'like', "%{$search}%");
            });
        }

        if ($status !== '') {
            $query->where('account_status', $status);
        }

        $users = $query->get()->map(fn (User $u) => $this->formatUser($u));

        return response()->json([
            'users' => $users,
            'groups' => Group::query()->orderBy('name')->get(['id', 'name', 'slug', 'description']),
        ]);
    }

    public function show(int $id): JsonResponse
    {
        $user = User::with('groups:id,name,slug')->findOrFail($id);

        return response()->json([
            'user' => $this->formatUser($user),
        ]);
    }

    public function store(Request $request): JsonResponse
    {
        $data = $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'email', 'max:255', 'unique:users,email'],
            'phone' => ['nullable', 'string', 'max:20', 'unique:users,phone'],
            'password' => ['required', 'string', 'min:8'],
            'account_status' => ['sometimes', Rule::in(['active', 'inactive', 'pending_verification'])],
            'group_ids' => ['sometimes', 'array'],
            'group_ids.*' => ['integer', 'exists:groups,id'],
        ]);

        $groupIds = $this->sanitizeGroupIds($data['group_ids'] ?? [], $data['email']);

        $user = User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'phone' => $data['phone'] ?? null,
            'password' => Hash::make($data['password']),
            'account_status' => $data['account_status'] ?? 'active',
        ]);

        if (!empty($groupIds)) {
            $user->groups()->sync($groupIds);
        }

        return response()->json([
            'message' => 'User berhasil dibuat.',
            'user' => $this->formatUser($user->load('groups:id,name,slug')),
        ], 201);
    }

    public function update(Request $request, int $id): JsonResponse
    {
        $user = User::with('groups:id,name,slug')->findOrFail($id);

        $data = $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'email', 'max:255', Rule::unique('users', 'email')->ignore($user->id)],
            'phone' => ['nullable', 'string', 'max:20', Rule::unique('users', 'phone')->ignore($user->id)],
            'password' => ['nullable', 'string', 'min:8'],
            'account_status' => ['required', Rule::in(['active', 'inactive', 'pending_verification'])],
            'group_ids' => ['sometimes', 'array'],
            'group_ids.*' => ['integer', 'exists:groups,id'],
        ]);

        if ($this->isSuperAdminEmail($user->email)) {
            if (!$this->isSuperAdminEmail($data['email'])) {
                return response()->json([
                    'message' => 'Email akun Super Administrator utama tidak boleh diubah.',
                ], 422);
            }
            if ($data['account_status'] !== 'active') {
                return response()->json([
                    'message' => 'Akun Super Administrator utama harus tetap aktif.',
                ], 422);
            }
        }

        $payload = [
            'name' => $data['name'],
            'email' => $data['email'],
            'phone' => $data['phone'] ?? null,
            'account_status' => $data['account_status'],
        ];

        if (!empty($data['password'])) {
            $payload['password'] = Hash::make($data['password']);
        }

        $user->update($payload);

        if (array_key_exists('group_ids', $data)) {
            $groupIds = $this->sanitizeGroupIds($data['group_ids'] ?? [], $user->email);
            $user->groups()->sync($groupIds);
        }

        return response()->json([
            'message' => 'Data user berhasil diperbarui.',
            'user' => $this->formatUser($user->fresh('groups:id,name,slug')),
        ]);
    }

    public function toggleStatus(Request $request, int $id): JsonResponse
    {
        $user = User::findOrFail($id);

        if ($this->isSuperAdminEmail($user->email)) {
            return response()->json([
                'message' => 'Akun Super Administrator utama tidak boleh dinonaktifkan.',
            ], 422);
        }

        if ($request->user()->id === $user->id) {
            return response()->json([
                'message' => 'Anda tidak dapat menonaktifkan akun Anda sendiri.',
            ], 422);
        }

        $newStatus = $user->account_status === 'active' ? 'inactive' : 'active';
        $user->update(['account_status' => $newStatus]);

        return response()->json([
            'message' => $newStatus === 'active' ? 'Akun user diaktifkan.' : 'Akun user dinonaktifkan.',
            'user' => $this->formatUser($user->fresh('groups:id,name,slug')),
        ]);
    }

    public function destroy(Request $request, int $id): JsonResponse
    {
        $user = User::findOrFail($id);

        if ($this->isSuperAdminEmail($user->email)) {
            return response()->json([
                'message' => 'Akun Super Administrator utama tidak boleh dihapus.',
            ], 422);
        }

        if ($request->user()->id === $user->id) {
            return response()->json([
                'message' => 'Anda tidak dapat menghapus akun Anda sendiri.',
            ], 422);
        }

        $user->delete();

        return response()->json([
            'message' => 'User berhasil dihapus.',
        ]);
    }

    private function isSuperAdminEmail(?string $email): bool
    {
        $configuredEmail = (string) config('rahanpas.super_admin_email', '');

        return $configuredEmail !== ''
            && strtolower(trim((string) $email)) === $configuredEmail;
    }

    private function sanitizeGroupIds(array $groupIds, string $email): array
    {
        $superAdminGroupId = Group::query()->where('slug', 'super-administrator')->value('id');
        if (!$superAdminGroupId) {
            return $groupIds;
        }

        $clean = array_values(array_unique(array_map('intval', $groupIds)));

        if ($this->isSuperAdminEmail($email)) {
            if (!in_array((int) $superAdminGroupId, $clean, true)) {
                $clean[] = (int) $superAdminGroupId;
            }
            return $clean;
        }

        return array_values(array_filter($clean, fn (int $gid) => $gid !== (int) $superAdminGroupId));
    }

    private function formatUser(User $user): array
    {
        return [
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
            'created_at' => $user->created_at?->toISOString(),
        ];
    }
}
