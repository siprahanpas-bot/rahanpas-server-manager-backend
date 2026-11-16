<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Permission;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;

class PermissionManagementController extends Controller
{
    public function index(): JsonResponse
    {
        $permissions = Permission::query()
            ->withCount('roles')
            ->orderBy('slug')
            ->get();

        return response()->json([
            'permissions' => $permissions,
        ]);
    }

    public function store(Request $request): JsonResponse
    {
        $data = $request->validate([
            'name' => ['required', 'string', 'max:255', 'unique:permissions,name'],
            'slug' => ['required', 'string', 'max:255', 'unique:permissions,slug', 'regex:/^[a-z0-9._-]+$/'],
            'description' => ['nullable', 'string'],
        ]);

        $permission = Permission::create($data);

        return response()->json([
            'message' => 'Permission berhasil dibuat.',
            'permission' => $permission->loadCount('roles'),
        ], 201);
    }

    public function update(Request $request, int $id): JsonResponse
    {
        $permission = Permission::findOrFail($id);

        $data = $request->validate([
            'name' => ['required', 'string', 'max:255', Rule::unique('permissions', 'name')->ignore($permission->id)],
            'slug' => ['required', 'string', 'max:255', Rule::unique('permissions', 'slug')->ignore($permission->id), 'regex:/^[a-z0-9._-]+$/'],
            'description' => ['nullable', 'string'],
        ]);

        $permission->update($data);

        return response()->json([
            'message' => 'Permission berhasil diperbarui.',
            'permission' => $permission->fresh()->loadCount('roles'),
        ]);
    }

    public function destroy(int $id): JsonResponse
    {
        $permission = Permission::findOrFail($id);
        $permission->delete();

        return response()->json([
            'message' => 'Permission berhasil dihapus.',
        ]);
    }
}
