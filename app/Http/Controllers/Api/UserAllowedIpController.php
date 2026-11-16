<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Models\UserAllowedIp;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;

class UserAllowedIpController extends Controller
{
    public function index(Request $request): JsonResponse
    {
        $userId = $request->query('user_id');
        $search = trim((string) $request->query('search', ''));

        $query = UserAllowedIp::query()
            ->with('user:id,name,email')
            ->orderByDesc('id');

        if ($userId) {
            $query->where('user_id', (int) $userId);
        }

        if ($search !== '') {
            $query->where(function ($q) use ($search) {
                $q->where('ip_address', 'like', "%{$search}%")
                    ->orWhereHas('user', function ($uq) use ($search) {
                        $uq->where('name', 'like', "%{$search}%")
                            ->orWhere('email', 'like', "%{$search}%");
                    });
            });
        }

        $items = $query->get()->map(function (UserAllowedIp $row) {
            $eval = $row->evaluateAccess();
            return [
                'id' => $row->id,
                'user_id' => $row->user_id,
                'user' => $row->user,
                'ip_address' => $row->ip_address,
                'access_type' => $row->access_type,
                'expires_at' => $row->expires_at?->toISOString(),
                'notes' => $row->notes,
                'effective_status' => $eval['status'],
                'effective_label' => $eval['label'],
                'allowed' => $eval['allowed'],
            ];
        });

        return response()->json([
            'items' => $items,
            'users' => User::query()->orderBy('name')->get(['id', 'name', 'email']),
        ]);
    }

    public function store(Request $request): JsonResponse
    {
        $data = $request->validate([
            'user_id' => ['required', 'integer', 'exists:users,id'],
            'ip_address' => [
                'required',
                'ip',
                Rule::unique('user_allowed_ips', 'ip_address')->where('user_id', $request->input('user_id')),
            ],
            'access_type' => ['required', Rule::in(['permanent', 'timed', 'inactive'])],
            'expires_at' => ['required_if:access_type,timed', 'nullable', 'date'],
            'notes' => ['nullable', 'string', 'max:500'],
        ]);

        $row = UserAllowedIp::create([
            'user_id' => $data['user_id'],
            'ip_address' => $data['ip_address'],
            'access_type' => $data['access_type'],
            'expires_at' => $data['access_type'] === 'timed' ? $data['expires_at'] : null,
            'notes' => $data['notes'] ?? null,
        ]);

        return response()->json([
            'message' => 'Aturan IP server berhasil ditambahkan.',
            'item' => $row->load('user:id,name,email'),
        ], 201);
    }

    public function update(Request $request, int $id): JsonResponse
    {
        $row = UserAllowedIp::findOrFail($id);

        $data = $request->validate([
            'user_id' => ['required', 'integer', 'exists:users,id'],
            'ip_address' => [
                'required',
                'ip',
                Rule::unique('user_allowed_ips', 'ip_address')
                    ->where('user_id', $request->input('user_id'))
                    ->ignore($row->id),
            ],
            'access_type' => ['required', Rule::in(['permanent', 'timed', 'inactive'])],
            'expires_at' => ['required_if:access_type,timed', 'nullable', 'date'],
            'notes' => ['nullable', 'string', 'max:500'],
        ]);

        $row->update([
            'user_id' => $data['user_id'],
            'ip_address' => $data['ip_address'],
            'access_type' => $data['access_type'],
            'expires_at' => $data['access_type'] === 'timed' ? $data['expires_at'] : null,
            'notes' => $data['notes'] ?? null,
        ]);

        return response()->json([
            'message' => 'Aturan IP server berhasil diperbarui.',
            'item' => $row->fresh('user:id,name,email'),
        ]);
    }

    public function destroy(int $id): JsonResponse
    {
        $row = UserAllowedIp::findOrFail($id);
        $row->delete();

        return response()->json([
            'message' => 'Aturan IP server berhasil dihapus.',
        ]);
    }
}
