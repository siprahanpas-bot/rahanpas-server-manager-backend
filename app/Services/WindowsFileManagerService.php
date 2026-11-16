<?php

namespace App\Services;

use App\Models\ManagedServer;
use RuntimeException;

class WindowsFileManagerService
{
    public function __construct(
        private readonly WinRmConnectionService $winrm
    ) {
    }

    public function getStorageDevices(ManagedServer $server): array
    {
        $ps = <<<'POWERSHELL'
$ErrorActionPreference='SilentlyContinue'
$p=@{};Get-PSDrive -PSProvider FileSystem|%{$p[$_.Name.ToUpper()+':']=$_}
$v=@{};Get-Volume|?{$_.DriveLetter}|%{$v[([string]$_.DriveLetter).ToUpper()+':']=$_}
$w=@{};Get-CimInstance Win32_LogicalDisk|%{$w[$_.DeviceID.ToUpper()]=$_}
$fmt={param([double]$b)if($b -ge 1TB){'{0:N2} TB'-f($b/1TB)}elseif($b -ge 1GB){'{0:N2} GB'-f($b/1GB)}else{'{0:N2} MB'-f($b/1MB)}}
$sysDrive=($env:SystemDrive).TrimEnd('\').ToUpper();if(-not $sysDrive){$sysDrive='C:'}
$devs=@();$mts=@();$exp=@()
foreach($dk in (Get-Disk|Sort-Object Number)){
$isUsb=($dk.BusType -eq 'USB');$ch=@();$hasSys=$false
foreach($pt in (Get-Partition -DiskNumber $dk.Number|Sort-Object PartitionNumber)){
if($pt.Type -in 'Reserved','System','Recovery'){continue}
$dl=if($pt.DriveLetter){([string]$pt.DriveLetter).ToUpper()+':'}else{$null}
if($dl -and $dl -eq $sysDrive){$hasSys=$true}
$vol=if($dl){$v[$dl]}else{$null};$psd=if($dl){$p[$dl]}else{$null};$wmi=if($dl){$w[$dl]}else{$null}
$fs=if($vol -and $vol.FileSystem){[string]$vol.FileSystem}elseif($wmi -and $wmi.FileSystem){[string]$wmi.FileSystem}else{'RAW'}
$t=if($vol -and $vol.Size -gt 0){[double]$vol.Size}else{[double]$pt.Size}
$u=0.0;$ready=($dl -and $fs -ne 'RAW' -and $vol -and $vol.Size -gt 0)
if($ready){$u=if($psd -and $null -ne $psd.Used){[double]$psd.Used}else{$t-[double]$vol.SizeRemaining};if($u -lt 0){$u=0}}
$pct=if($ready -and $t -gt 0){[math]::Round($u/$t*100,1)}else{$null}
$mp=if($ready){"$dl\"}else{$null}
if($mp){$exp+=$mp;$mts+=[ordered]@{source=$dl;target=$mp;fstype=$fs;options='rw'}}
$ch+=[ordered]@{name=if($dl){$dl}else{"Part $($pt.PartitionNumber)"};kname="disk$($dk.Number)p$($pt.PartitionNumber)";path=if($mp){$mp}else{"PhysicalDrive$($dk.Number)#$($pt.PartitionNumber)"};type='part';size=(&$fmt $t);fstype=$fs;label=if($vol){[string]$vol.FileSystemLabel}else{''};uuid=if($wmi){[string]$wmi.VolumeSerialNumber}else{''};mountpoint=$mp;tran=if($isUsb){'usb'}else{'sata'};rm=$isUsb;ro=$false;model=if($vol){[string]$vol.FileSystemLabel}else{''};used_bytes=if($ready){[int64]$u}else{0};total_bytes=[int64]$t;usage_percent=$pct;usage_summary=if($ready){"$(&$fmt $u) / $(&$fmt $t)"}else{"RAW / Unformatted ($(&$fmt $t))"}}
}
$devs+=[ordered]@{name=if($dk.FriendlyName){[string]$dk.FriendlyName}else{"Disk $($dk.Number)"};kname="disk$($dk.Number)";path="PhysicalDrive$($dk.Number)";type='disk';size=(&$fmt ([double]$dk.Size));fstype=$null;label=$null;uuid=$null;mountpoint=$null;tran=if($isUsb){'usb'}else{'raid'};rm=$isUsb;ro=($dk.IsReadOnly -or $hasSys);is_system=$hasSys;model=[string]$dk.FriendlyName;children=$ch}
}
if($env:USERPROFILE -and ($exp -notcontains $env:USERPROFILE)){$exp+=$env:USERPROFILE}
[ordered]@{devices=$devs;mounts=$mts;explorable_mountpoints=$exp}|ConvertTo-Json -Depth 6 -Compress
POWERSHELL;

        $raw = $this->winrm->executePowerShell($server, $ps);
        $decoded = json_decode(trim($raw), true);

        if (!is_array($decoded) || !isset($decoded['devices'])) {
            throw new RuntimeException('Gagal membaca daftar storage Windows.');
        }

        return [
            'devices' => $decoded['devices'] ?? [],
            'mounts' => $decoded['mounts'] ?? [],
            'explorable_mountpoints' => $decoded['explorable_mountpoints'] ?? [],
            'detected_at' => now()->toISOString(),
        ];
    }

    public function inspectStorageDeviceFormat(ManagedServer $server, string $devicePath): array
    {
        if (!preg_match('/^PhysicalDrive(\d+)$/', $devicePath, $match)) {
            throw new RuntimeException('Format path disk Windows tidak valid.');
        }

        $diskNum = (int) $match[1];
        $ps = <<<POWERSHELL
\$ErrorActionPreference='Stop'
\$dk=Get-Disk -Number {$diskNum}
\$sysDrive=(\$env:SystemDrive).TrimEnd('\\').ToUpper();if(-not \$sysDrive){\$sysDrive='C:'}
\$hasSys=\$false
foreach(\$pt in (Get-Partition -DiskNumber {$diskNum} -ErrorAction SilentlyContinue)){
if(\$pt.DriveLetter -and (([string]\$pt.DriveLetter).ToUpper()+':') -eq \$sysDrive){\$hasSys=\$true}
}
[ordered]@{number=\$dk.Number;model=[string]\$dk.FriendlyName;serial=[string]\$dk.SerialNumber;size_bytes=[int64]\$dk.Size;bus=[string]\$dk.BusType;is_boot=[bool]\$dk.IsBoot;is_system=([bool]\$dk.IsSystem -or \$hasSys);is_readonly=[bool]\$dk.IsReadOnly}|ConvertTo-Json -Compress
POWERSHELL;

        $raw = $this->winrm->executePowerShell($server, $ps);
        $info = json_decode(trim($raw), true);

        if (!is_array($info) || !isset($info['size_bytes'])) {
            throw new RuntimeException("Disk {$devicePath} tidak ditemukan di server Windows.");
        }

        $reasons = [];
        if (!empty($info['is_boot']) || !empty($info['is_system'])) {
            $reasons[] = 'Disk berisi sistem operasi Windows aktif dan tidak boleh diformat.';
        }
        if (!empty($info['is_readonly'])) {
            $reasons[] = 'Disk dalam status Read-Only.';
        }

        $eligible = count($reasons) === 0;
        $fingerprint = hash('sha256', "{$server->id}|{$devicePath}|{$info['size_bytes']}|{$info['serial']}");

        return [
            'eligible' => $eligible,
            'reasons' => $reasons,
            'fingerprint' => $fingerprint,
            'supported_filesystems' => ['exfat', 'ntfs', 'fat32'],
            'device' => [
                'path' => $devicePath,
                'model' => $info['model'] ?? 'Unknown',
                'serial' => $info['serial'] ?: '-',
                'size_bytes' => (int) $info['size_bytes'],
            ],
        ];
    }

    public function formatStorageDevice(
        ManagedServer $server,
        string $devicePath,
        string $fingerprint,
        string $filesystem,
        ?string $label = null
    ): array {
        $preflight = $this->inspectStorageDeviceFormat($server, $devicePath);

        if (!$preflight['eligible']) {
            throw new RuntimeException(implode(' ', $preflight['reasons'] ?: ['Disk tidak memenuhi syarat untuk diformat.']));
        }

        if (!hash_equals($preflight['fingerprint'], $fingerprint)) {
            throw new RuntimeException('Fingerprint disk berubah. Muat ulang dialog format dan coba lagi.');
        }

        $fsMap = ['exfat' => 'exFAT', 'ntfs' => 'NTFS', 'fat32' => 'FAT32'];
        $fsKey = strtolower($filesystem);
        if (!isset($fsMap[$fsKey])) {
            throw new RuntimeException('Filesystem tidak didukung untuk Windows (gunakan exfat, ntfs, atau fat32).');
        }

        preg_match('/^PhysicalDrive(\d+)$/', $devicePath, $match);
        $diskNum = (int) $match[1];
        $fsWin = $fsMap[$fsKey];
        $cleanLabel = preg_replace('/[^A-Za-z0-9._-]/', '', (string) ($label ?? ''));
        $labelArg = $cleanLabel !== '' ? "-NewFileSystemLabel '{$cleanLabel}'" : '';

        $ps = <<<POWERSHELL
\$ErrorActionPreference='Stop'
Clear-Disk -Number {$diskNum} -RemoveData -RemoveOEM -Confirm:\$false
\$dk=Get-Disk -Number {$diskNum}
if(\$dk.PartitionStyle -eq 'RAW'){Initialize-Disk -Number {$diskNum} -PartitionStyle MBR|Out-Null}
\$part=New-Partition -DiskNumber {$diskNum} -UseMaximumSize -AssignDriveLetter
\$vol=Format-Volume -Partition \$part -FileSystem {$fsWin} {$labelArg} -Confirm:\$false
[ordered]@{drive="\$(\$part.DriveLetter):\\";filesystem=[string]\$vol.FileSystem;label=[string]\$vol.FileSystemLabel}|ConvertTo-Json -Compress
POWERSHELL;

        $raw = $this->winrm->executePowerShell($server, $ps, 120);
        $res = json_decode(trim($raw), true);

        return [
            'device_path' => $devicePath,
            'filesystem' => $res['filesystem'] ?? $fsWin,
            'mountpoint' => $res['drive'] ?? null,
        ];
    }

    public function listDirectory(ManagedServer $server, ?string $requestedPath = null): array
    {
        $pathB64 = base64_encode($requestedPath ?? '');

        $ps = <<<POWERSHELL
\$ErrorActionPreference = 'Stop'
\$reqPath = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{$pathB64}'))
\$homeRoot = \$env:USERPROFILE
if (-not \$homeRoot -or -not (Test-Path -LiteralPath \$homeRoot)) {
    \$homeRoot = 'C:\\'
}

if ([string]::IsNullOrWhiteSpace(\$reqPath)) {
    \$target = \$homeRoot
} else {
    \$target = \$reqPath.Trim()
    if (\$target -match '^[A-Za-z]:$') {
        \$target = "\$target\\"
    }
}

if (-not (Test-Path -LiteralPath \$target)) {
    throw "Path tidak ditemukan: \$target"
}

\$item = Get-Item -LiteralPath \$target -Force
if (-not \$item.PSIsContainer) {
    throw "Path yang diminta bukan direktori."
}

\$resolvedPath = \$item.FullName
\$driveRoot = [System.IO.Path]::GetPathRoot(\$resolvedPath)
\$navRoot = if (\$resolvedPath.StartsWith(\$homeRoot, [System.StringComparison]::OrdinalIgnoreCase)) { \$homeRoot } else { \$driveRoot }

\$sysDrive = (\$env:SystemDrive).TrimEnd('\\')
if (-not \$sysDrive) { \$sysDrive = 'C:' }
\$currentDrive = \$driveRoot.TrimEnd('\\')
\$isReadOnly = (\$currentDrive.Equals(\$sysDrive, [System.StringComparison]::OrdinalIgnoreCase))

\$parent = \$null
if (\$resolvedPath.TrimEnd('\\') -ne \$navRoot.TrimEnd('\\')) {
    \$p = Split-Path -Path \$resolvedPath -Parent
    if (\$p) { \$parent = \$p }
}

\$entries = @()
foreach (\$child in (Get-ChildItem -LiteralPath \$resolvedPath -Force)) {
    \$isSym = [bool](\$child.Attributes -band [System.IO.FileAttributes]::ReparsePoint)
    \$type = if (\$isSym) { 'symlink' } elseif (\$child.PSIsContainer) { 'directory' } else { 'file' }
    \$mtime = [int64]([DateTimeOffset]\$child.LastWriteTimeUtc).ToUnixTimeSeconds()
    \$entries += [ordered]@{
        name = \$child.Name
        path = \$child.FullName
        type = \$type
        size = if (\$child.PSIsContainer) { \$null } else { [int64]\$child.Length }
        modified_at = \$mtime
        permissions = if (\$child.IsReadOnly) { 'r--' } else { 'rw-' }
        is_symlink = \$isSym
    }
}

[ordered]@{
    root_path = \$navRoot
    home_root_path = \$homeRoot
    current_path = \$resolvedPath
    parent_path = \$parent
    read_only = \$isReadOnly
    access_mode = if (\$isReadOnly) { 'read_only' } else { 'read_write' }
    items = \$entries
    total_items = \$entries.Count
} | ConvertTo-Json -Depth 5 -Compress
POWERSHELL;

        $raw = $this->winrm->executePowerShell($server, $ps);
        $decoded = json_decode(trim($raw), true);

        if (!is_array($decoded) || !isset($decoded['current_path'])) {
            throw new RuntimeException('Gagal membaca isi direktori Windows.');
        }

        $items = $decoded['items'] ?? [];
        usort($items, static function (array $a, array $b): int {
            $priority = ['directory' => 0, 'file' => 1, 'symlink' => 2];
            $cmp = ($priority[$a['type']] ?? 9) <=> ($priority[$b['type']] ?? 9);
            return $cmp !== 0 ? $cmp : strnatcasecmp($a['name'], $b['name']);
        });
        $decoded['items'] = $items;

        return $decoded;
    }

    public function createDirectory(ManagedServer $server, string $path, string $name): array
    {
        $cleanName = trim(str_replace(['/', '\\'], '', $name));
        if ($cleanName === '' || $cleanName === '.' || $cleanName === '..') {
            throw new RuntimeException('Nama folder tidak valid.');
        }

        $pathB64 = base64_encode($path);
        $nameB64 = base64_encode($cleanName);

        $ps = <<<POWERSHELL
\$ErrorActionPreference = 'Stop'
\$parent = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{$pathB64}'))
\$sysDrive = (\$env:SystemDrive).TrimEnd('\\'); if (-not \$sysDrive) { \$sysDrive = 'C:' }
if (([System.IO.Path]::GetPathRoot(\$parent).TrimEnd('\\')).Equals(\$sysDrive, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Drive sistem OS (\$sysDrive) bersifat read-only."
}
\$name = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{$nameB64}'))
\$target = Join-Path -Path \$parent -ChildPath \$name
if (Test-Path -LiteralPath \$target) {
    throw "Folder sudah ada: \$name"
}
\$created = New-Item -ItemType Directory -Path \$target -Force
[ordered]@{ name = \$created.Name; path = \$created.FullName } | ConvertTo-Json -Compress
POWERSHELL;

        $raw = $this->winrm->executePowerShell($server, $ps);
        return json_decode(trim($raw), true) ?: ['name' => $cleanName, 'path' => rtrim($path, '\\') . '\\' . $cleanName];
    }

    public function renameEntry(ManagedServer $server, string $path, string $name): array
    {
        $cleanName = trim(str_replace(['/', '\\'], '', $name));
        if ($cleanName === '' || $cleanName === '.' || $cleanName === '..') {
            throw new RuntimeException('Nama baru tidak valid.');
        }

        $pathB64 = base64_encode($path);
        $nameB64 = base64_encode($cleanName);

        $ps = <<<POWERSHELL
\$ErrorActionPreference = 'Stop'
\$src = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{$pathB64}'))
\$sysDrive = (\$env:SystemDrive).TrimEnd('\\'); if (-not \$sysDrive) { \$sysDrive = 'C:' }
if (([System.IO.Path]::GetPathRoot(\$src).TrimEnd('\\')).Equals(\$sysDrive, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Drive sistem OS (\$sysDrive) bersifat read-only."
}
\$name = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{$nameB64}'))
\$renamed = Rename-Item -LiteralPath \$src -NewName \$name -PassThru
[ordered]@{ name = \$renamed.Name; path = \$renamed.FullName } | ConvertTo-Json -Compress
POWERSHELL;

        $raw = $this->winrm->executePowerShell($server, $ps);
        return json_decode(trim($raw), true) ?: ['name' => $cleanName, 'path' => $path];
    }

    public function deleteEntry(ManagedServer $server, string $path): array
    {
        $pathB64 = base64_encode($path);

        $ps = <<<POWERSHELL
\$ErrorActionPreference = 'Stop'
\$target = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{$pathB64}'))
\$sysDrive = (\$env:SystemDrive).TrimEnd('\\'); if (-not \$sysDrive) { \$sysDrive = 'C:' }
if (([System.IO.Path]::GetPathRoot(\$target).TrimEnd('\\')).Equals(\$sysDrive, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Drive sistem OS (\$sysDrive) bersifat read-only."
}
if (-not (Test-Path -LiteralPath \$target)) {
    throw "Item tidak ditemukan."
}
Remove-Item -LiteralPath \$target -Recurse -Force
[ordered]@{ deleted = \$target } | ConvertTo-Json -Compress
POWERSHELL;

        $this->winrm->executePowerShell($server, $ps);
        return ['deleted' => $path];
    }

    public function uploadFile(ManagedServer $server, string $localPath, string $originalName, ?string $targetDir = null): array
    {
        if (!is_file($localPath)) {
            throw new RuntimeException('File upload lokal tidak ditemukan.');
        }

        $dirB64 = base64_encode($targetDir ?: '');
        $nameB64 = base64_encode(basename($originalName));

        $ps = <<<POWERSHELL
\$ErrorActionPreference = 'Stop'
\$dir = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{$dirB64}'))
if ([string]::IsNullOrWhiteSpace(\$dir)) { \$dir = \$env:USERPROFILE }
\$sysDrive = (\$env:SystemDrive).TrimEnd('\\'); if (-not \$sysDrive) { \$sysDrive = 'C:' }
if (([System.IO.Path]::GetPathRoot(\$dir).TrimEnd('\\')).Equals(\$sysDrive, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Drive sistem OS (\$sysDrive) bersifat read-only."
}
\$name = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{$nameB64}'))
\$dest = Join-Path -Path \$dir -ChildPath \$name
if (Test-Path -LiteralPath \$dest) {
    throw "File sudah ada: \$name"
}
\$stdin = [Console]::OpenStandardInput()
\$fs = [System.IO.File]::Create(\$dest)
try {
    \$stdin.CopyTo(\$fs)
} finally {
    \$fs.Close()
    \$stdin.Close()
}
\$len = (Get-Item -LiteralPath \$dest).Length
[ordered]@{ name = \$name; path = \$dest; size = \$len } | ConvertTo-Json -Compress
POWERSHELL;

        $raw = $this->winrm->executePowerShellWithStdin($server, $ps, $localPath, 120);
        return json_decode(trim($raw), true) ?: ['name' => basename($originalName), 'path' => $targetDir];
    }

    public function prepareDownload(ManagedServer $server, string $path): array
    {
        $pathB64 = base64_encode($path);

        $ps = <<<POWERSHELL
\$ErrorActionPreference = 'Stop'
\$target = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{$pathB64}'))
\$item = Get-Item -LiteralPath \$target -Force
if (\$item.PSIsContainer) { throw "Tidak dapat mengunduh direktori." }
[ordered]@{
    filename = \$item.Name
    content_b64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes(\$item.FullName))
} | ConvertTo-Json -Compress
POWERSHELL;

        $raw = $this->winrm->executePowerShell($server, $ps, 60);
        $decoded = json_decode(trim($raw), true);

        if (!is_array($decoded) || !isset($decoded['content_b64'])) {
            throw new RuntimeException('Gagal mengunduh file dari Windows.');
        }

        $tmpPath = tempnam(sys_get_temp_dir(), 'winrm_dl_');
        file_put_contents($tmpPath, base64_decode($decoded['content_b64'], true) ?: '');

        return [
            'local_path' => $tmpPath,
            'filename' => (string) ($decoded['filename'] ?? 'download'),
        ];
    }

    public function overwriteFile(ManagedServer $server, string $remotePath, string $localPath): void
    {
        if (!is_file($localPath)) {
            throw new RuntimeException('File sementara tidak ditemukan.');
        }

        $pathB64 = base64_encode($remotePath);
        $ps = <<<POWERSHELL
\$ErrorActionPreference = 'Stop'
\$dest = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{$pathB64}'))
\$sysDrive = (\$env:SystemDrive).TrimEnd('\\'); if (-not \$sysDrive) { \$sysDrive = 'C:' }
if (([System.IO.Path]::GetPathRoot(\$dest).TrimEnd('\\')).Equals(\$sysDrive, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Drive sistem OS (\$sysDrive) bersifat read-only."
}
\$stdin = [Console]::OpenStandardInput()
\$fs = [System.IO.File]::Create(\$dest)
try {
    \$stdin.CopyTo(\$fs)
} finally {
    \$fs.Close()
    \$stdin.Close()
}
Write-Output "OK"
POWERSHELL;

        $this->winrm->executePowerShellWithStdin($server, $ps, $localPath, 120);
    }
}
