<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\ManagedServer;
use App\Services\RemoteFileManagerService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use RuntimeException;
use Throwable;

class OnlyOfficeController extends Controller
{
    private const DOC_TYPES = [
        'docx' => 'word', 'doc' => 'word', 'odt' => 'word', 'rtf' => 'word', 'txt' => 'word',
        'xlsx' => 'cell', 'xls' => 'cell', 'ods' => 'cell', 'csv' => 'cell',
        'pptx' => 'slide', 'ppt' => 'slide', 'odp' => 'slide',
        'pdf' => 'pdf',
    ];

    public function config(Request $request, int $id): JsonResponse
    {
        $data = $request->validate([
            'path' => ['required', 'string', 'max:4096'],
        ]);

        $server = $request->user()->managedServers()->findOrFail($id);
        $path = $data['path'];
        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));

        if (!isset(self::DOC_TYPES[$ext])) {
            return response()->json([
                'message' => 'Format file belum didukung untuk editor ONLYOFFICE.',
            ], 422);
        }

        $canEdit = ($ext !== 'pdf');
        if ($server->os_type === 'windows' && preg_match('/^C:/i', $path)) {
            $canEdit = false;
        }

        $token = $this->signToken([
            'server_id' => $server->id,
            'path' => $path,
            'can_edit' => $canEdit,
            'exp' => now()->addHours(2)->timestamp,
        ]);

        $docKey = substr(hash('sha256', "{$server->id}|{$path}|" . time()), 0, 32);

        $apiBaseUrl = rtrim(
            (string) config('rahanpas.onlyoffice.api_base_url', ''),
            '/'
        );

        if ($apiBaseUrl === '') {
            throw new RuntimeException('ONLYOFFICE_API_BASE_URL belum dikonfigurasi.');
        }

        return response()->json([
            'onlyoffice_port' => (int) config('rahanpas.onlyoffice.public_port', 13009),
            'config' => [
                'documentType' => self::DOC_TYPES[$ext],
                'document' => [
                    'fileType' => $ext,
                    'key' => $docKey,
                    'title' => basename(str_replace('\\', '/', $path)),
                    'url' => "{$apiBaseUrl}/onlyoffice/file/{$token}",
                    'permissions' => [
                        'edit' => $canEdit,
                        'download' => true,
                        'print' => true,
                    ],
                ],
                'editorConfig' => [
                    'mode' => $canEdit ? 'edit' : 'view',
                    'lang' => 'id',
                    'callbackUrl' => "{$apiBaseUrl}/onlyoffice/callback/{$token}",
                    'user' => [
                        'id' => (string) $request->user()->id,
                        'name' => $request->user()->name,
                    ],
                    'customization' => [
                        'autosave' => true,
                        'forcesave' => true,
                    ],
                ],
            ],
        ]);
    }

    public function file(string $token, RemoteFileManagerService $fileManager)
    {
        $payload = $this->verifyToken($token);
        $server = ManagedServer::findOrFail($payload['server_id']);

        $download = $fileManager->prepareDownload($server, $payload['path']);
        $localPath = $download['local_path'];
        $filename = preg_replace('/[\x00-\x1F\x7F]/', '_', $download['filename']) ?: 'document';

        return response()->download($localPath, $filename)->deleteFileAfterSend(true);
    }

    public function callback(Request $request, string $token, RemoteFileManagerService $fileManager): JsonResponse
    {
        try {
            $payload = $this->verifyToken($token);
            $status = (int) $request->input('status', 0);

            if (in_array($status, [2, 6], true)) {
                if (empty($payload['can_edit'])) {
                    return response()->json(['error' => 0]);
                }

                $downloadUrl = (string) $request->input('url', '');
                if ($downloadUrl === '') {
                    return response()->json(['error' => 1]);
                }

                // Arahkan URL download internal ke container rahanpas-onlyoffice di baota_net
                $onlyOfficeInternalUrl = rtrim(
                    (string) config('rahanpas.onlyoffice.internal_url', ''),
                    '/'
                );

                if ($onlyOfficeInternalUrl === '') {
                    throw new RuntimeException('ONLYOFFICE_INTERNAL_URL belum dikonfigurasi.');
                }

                $internalUrl = preg_replace(
                    '#^https?://[^/]+#',
                    $onlyOfficeInternalUrl,
                    $downloadUrl
                );
                $response = Http::timeout(60)->get($internalUrl);

                if (!$response->successful()) {
                    return response()->json(['error' => 1]);
                }

                $tmpPath = tempnam(sys_get_temp_dir(), 'oo_save_');
                file_put_contents($tmpPath, $response->body());

                try {
                    $server = ManagedServer::findOrFail($payload['server_id']);
                    $fileManager->overwriteFile($server, $payload['path'], $tmpPath);
                } finally {
                    @unlink($tmpPath);
                }
            }

            return response()->json(['error' => 0]);
        } catch (Throwable) {
            return response()->json(['error' => 1]);
        }
    }

    private function signToken(array $payload): string
    {
        $data = rtrim(strtr(base64_encode(json_encode($payload)), '+/', '-_'), '=');
        $sig = hash_hmac('sha256', $data, (string) config('app.key'));
        return "{$data}.{$sig}";
    }

    private function verifyToken(string $token): array
    {
        $parts = explode('.', $token, 2);
        if (count($parts) !== 2) {
            throw new RuntimeException('Token tidak valid.');
        }

        [$data, $sig] = $parts;
        $expected = hash_hmac('sha256', $data, (string) config('app.key'));
        if (!hash_equals($expected, $sig)) {
            throw new RuntimeException('Signature token tidak valid.');
        }

        $padded = strtr($data, '-_', '+/') . str_repeat('=', (4 - strlen($data) % 4) % 4);
        $payload = json_decode(base64_decode($padded, true) ?: '', true);

        if (!is_array($payload) || empty($payload['exp']) || time() > (int) $payload['exp']) {
            throw new RuntimeException('Token kadaluarsa.');
        }

        return $payload;
    }
}
