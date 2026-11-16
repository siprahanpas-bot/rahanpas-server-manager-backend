<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Permission;
use App\Models\Role;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;

class RoleManagementController extends Controller
{
    public function index(): JsonResponse
    {
        $roles = Role::query()
            ->with('permissions:id,name,slug')
            ->withCount(['permissions', 'groups'])
            ->orderBy('id')
            ->get();

        return response()->json([
            'roles' => $roles,
            'permissions' => Permission::query()->orderBy('slug')->get(['id', 'name', 'slug', 'description']),
        ]);
    }

    public function store(Request $request): JsonResponse
    {
        $data = $request->validate([
            'name' => ['required', 'string', 'max:255', 'unique:roles,name'],
            'slug' => ['nullable', 'string', 'max:255', 'unique:roles,slug'],
            'description' => ['nullable', 'string'],
            'permission_ids' => ['sometimes', 'array'],
            'permission_ids.*' => ['integer', 'exists:permissions,id'],
        ]);

        $role = Role::create([
            'name' => $data['name'],
            'slug' => !empty($data['slug']) ? Str::slug($data['slug']) : Str::slug($data['name']),
            'description' => $data['description'] ?? null,
        ]);

        if (isset($data['permission_ids'])) {
            $role->permissions()->sync($data['permission_ids']);
        }

        return response()->json([
            'message' => 'Role berhasil dibuat.',
            'role' => $role->load('permissions:id,name,slug')->loadCount(['permissions', 'groups']),
        ], 201);
    }

    public function update(Request $request, int $id): JsonResponse
    {
        $role = Role::findOrFail($id);

        if ($role->slug === 'super-administrator') {
            return response()->json([
                'message' => 'Role Super Administrator dilindungi dan tidak dapat dimodifikasi.',
            ], 422);
        }

        $data = $request->validate([
            'name' => ['required', 'string', 'max:255', Rule::unique('roles', 'name')->ignore($role->id)],
            'slug' => ['nullable', 'string', 'max:255', Rule::unique('roles', 'slug')->ignore($role->id)],
            'description' => ['nullable', 'string'],
            'permission_ids' => ['sometimes', 'array'],
            'permission_ids.*' => ['integer', 'exists:permissions,id'],
        ]);

        $role->update([
            'name' => $data['name'],
            'slug' => !empty($data['slug']) ? Str::slug($data['slug']) : $role->slug,
            'description' => $data['description'] ?? null,
        ]);

        if (array_key_exists('permission_ids', $data)) {
            $role->permissions()->sync($data['permission_ids'] ?? []);
        }

        return response()->json([
            'message' => 'Role berhasil diperbarui.',
            'role' => $role->fresh('permissions:id,name,slug')->loadCount(['permissions', 'groups']),
        ]);
    }

    public function destroy(int $id): JsonResponse
    {
        $role = Role::findOrFail($id);

        if ($role->slug === 'super-administrator') {
            return response()->json([
                'message' => 'Role Super Administrator tidak dapat dihapus.',
            ], 422);
        }

        $role->delete();

        return response()->json([
            'message' => 'Role berhasil dihapus.',
        ]);
    }
}
