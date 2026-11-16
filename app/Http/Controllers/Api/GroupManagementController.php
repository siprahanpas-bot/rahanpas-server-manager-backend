<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Group;
use App\Models\Role;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;

class GroupManagementController extends Controller
{
    public function index(): JsonResponse
    {
        $groups = Group::query()
            ->with(['roles:id,name,slug', 'users:id,name,email'])
            ->withCount(['roles', 'users'])
            ->orderBy('id')
            ->get();

        return response()->json([
            'groups' => $groups,
            'roles' => Role::query()->orderBy('name')->get(['id', 'name', 'slug', 'description']),
            'users' => User::query()->orderBy('name')->get(['id', 'name', 'email', 'account_status']),
        ]);
    }

    public function store(Request $request): JsonResponse
    {
        $data = $request->validate([
            'name' => ['required', 'string', 'max:255', 'unique:groups,name'],
            'slug' => ['nullable', 'string', 'max:255', 'unique:groups,slug'],
            'description' => ['nullable', 'string'],
            'role_ids' => ['sometimes', 'array'],
            'role_ids.*' => ['integer', 'exists:roles,id'],
            'user_ids' => ['sometimes', 'array'],
            'user_ids.*' => ['integer', 'exists:users,id'],
        ]);

        $slug = !empty($data['slug']) ? Str::slug($data['slug']) : Str::slug($data['name']);

        $group = Group::create([
            'name' => $data['name'],
            'slug' => $slug,
            'description' => $data['description'] ?? null,
        ]);

        if (isset($data['role_ids'])) {
            $group->roles()->sync($data['role_ids']);
        }
        if (isset($data['user_ids'])) {
            $group->users()->sync($data['user_ids']);
        }

        return response()->json([
            'message' => 'Group berhasil dibuat.',
            'group' => $group->load(['roles:id,name,slug', 'users:id,name,email'])->loadCount(['roles', 'users']),
        ], 201);
    }

    public function update(Request $request, int $id): JsonResponse
    {
        $group = Group::findOrFail($id);

        $data = $request->validate([
            'name' => ['required', 'string', 'max:255', Rule::unique('groups', 'name')->ignore($group->id)],
            'slug' => ['nullable', 'string', 'max:255', Rule::unique('groups', 'slug')->ignore($group->id)],
            'description' => ['nullable', 'string'],
            'role_ids' => ['sometimes', 'array'],
            'role_ids.*' => ['integer', 'exists:roles,id'],
            'user_ids' => ['sometimes', 'array'],
            'user_ids.*' => ['integer', 'exists:users,id'],
        ]);

        if ($group->slug === 'super-administrator') {
            return response()->json([
                'message' => 'Group Super Administrator dilindungi dan tidak dapat dimodifikasi.',
            ], 422);
        }

        $group->update([
            'name' => $data['name'],
            'slug' => !empty($data['slug']) ? Str::slug($data['slug']) : $group->slug,
            'description' => $data['description'] ?? null,
        ]);

        if (array_key_exists('role_ids', $data)) {
            $group->roles()->sync($data['role_ids'] ?? []);
        }
        if (array_key_exists('user_ids', $data)) {
            $group->users()->sync($data['user_ids'] ?? []);
        }

        return response()->json([
            'message' => 'Group berhasil diperbarui.',
            'group' => $group->fresh(['roles:id,name,slug', 'users:id,name,email'])->loadCount(['roles', 'users']),
        ]);
    }

    public function destroy(int $id): JsonResponse
    {
        $group = Group::findOrFail($id);

        if (in_array($group->slug, ['super-administrator', 'registered-user', 'pending-verification'], true)) {
            return response()->json([
                'message' => 'Group bawaan sistem tidak dapat dihapus.',
            ], 422);
        }

        $group->delete();

        return response()->json([
            'message' => 'Group berhasil dihapus.',
        ]);
    }
}
