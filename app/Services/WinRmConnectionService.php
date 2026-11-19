<?php

namespace App\Services;

use App\Models\ManagedServer;
use RuntimeException;
use SimpleXMLElement;
use Throwable;

class WinRmConnectionService
{
    public function executePowerShell(ManagedServer $server, string $psScript, int $timeoutSeconds = 20): string
    {
        if ($server->auth_method !== 'password' || !$server->password) {
            throw new RuntimeException('Koneksi WinRM saat ini membutuhkan autentikasi password.');
        }

        $scheme = (int) $server->port === 5986 ? 'https' : 'http';
        $port = $server->port ?: 5985;
        $endpoint = "{$scheme}://{$server->ip_address}:{$port}/wsman";
        $encodedScript = base64_encode(mb_convert_encoding($psScript, 'UTF-16LE', 'UTF-8'));

        $shellId = null;

        try {
            $shellId = $this->openShell($endpoint, $server, $timeoutSeconds);
            $commandId = $this->runCommand($endpoint, $server, $shellId, $encodedScript, $timeoutSeconds);

            return $this->receiveOutput($endpoint, $server, $shellId, $commandId, $timeoutSeconds);
        } finally {
            if ($shellId !== null) {
                try {
                    $this->closeShell($endpoint, $server, $shellId);
                } catch (Throwable) {
                    // Abaikan error saat menutup shell.
                }
            }
        }
    }

    /**
     * Menjalankan skrip PowerShell melalui stdin agar tidak terkena
     * batas panjang command line Windows pada -EncodedCommand.
     *
     * Skrip monitoring saat ini menggunakan karakter ASCII.
     */
    public function executePowerShellViaStdin(ManagedServer $server, string $psScript, int $timeoutSeconds = 120): string
    {
        if ($server->auth_method !== 'password' || !$server->password) {
            throw new RuntimeException('Koneksi WinRM saat ini membutuhkan autentikasi password.');
        }

        $scheme = (int) $server->port === 5986 ? 'https' : 'http';
        $port = $server->port ?: 5985;
        $endpoint = "{$scheme}://{$server->ip_address}:{$port}/wsman";

        $shellId = null;

        try {
            $shellId = $this->openShell($endpoint, $server, $timeoutSeconds);
            $commandId = $this->runCommandViaStdin(
                $endpoint,
                $server,
                $shellId,
                $timeoutSeconds
            );

            // Kirim skrip sebagai UTF-8. Skrip monitoring menggunakan ASCII,
            // sehingga tidak bergantung pada code page karakter Windows.
            $this->sendInput(
                $endpoint,
                $server,
                $shellId,
                $commandId,
                base64_encode($psScript),
                true,
                $timeoutSeconds
            );

            return $this->receiveOutput(
                $endpoint,
                $server,
                $shellId,
                $commandId,
                $timeoutSeconds
            );
        } finally {
            if ($shellId !== null) {
                try {
                    $this->closeShell($endpoint, $server, $shellId);
                } catch (Throwable) {
                    // Abaikan error saat menutup shell.
                }
            }
        }
    }

    public function executePowerShellWithStdin(ManagedServer $server, string $psScript, string $localFilePath, int $timeoutSeconds = 120): string
    {
        if ($server->auth_method !== 'password' || !$server->password) {
            throw new RuntimeException('Koneksi WinRM saat ini membutuhkan autentikasi password.');
        }

        $fp = @fopen($localFilePath, 'rb');
        if ($fp === false) {
            throw new RuntimeException('Gagal membuka file lokal untuk upload.');
        }

        $scheme = (int) $server->port === 5986 ? 'https' : 'http';
        $port = $server->port ?: 5985;
        $endpoint = "{$scheme}://{$server->ip_address}:{$port}/wsman";
        $encodedScript = base64_encode(mb_convert_encoding($psScript, 'UTF-16LE', 'UTF-8'));

        $shellId = null;

        try {
            $shellId = $this->openShell($endpoint, $server, $timeoutSeconds);
            $commandId = $this->runCommand($endpoint, $server, $shellId, $encodedScript, $timeoutSeconds);

            $chunkSize = 200000;
            $sentAny = false;
            while (!feof($fp)) {
                $chunk = fread($fp, $chunkSize);
                if ($chunk === false) {
                    throw new RuntimeException('Gagal membaca potongan file lokal.');
                }
                if ($chunk === '' && $sentAny) {
                    break;
                }
                $sentAny = true;
                $isEnd = feof($fp);
                $this->sendInput($endpoint, $server, $shellId, $commandId, base64_encode($chunk), $isEnd, $timeoutSeconds);
            }

            return $this->receiveOutput($endpoint, $server, $shellId, $commandId, $timeoutSeconds);
        } finally {
            fclose($fp);
            if ($shellId !== null) {
                try {
                    $this->closeShell($endpoint, $server, $shellId);
                } catch (Throwable) {
                }
            }
        }
    }

    public function collectMetrics(ManagedServer $server): array
    {
        try {
            $rawOutput = $this->executePowerShellViaStdin(
                $server,
                $this->buildMetricsScript(),
                120
            );
            $data = json_decode(trim($rawOutput), true);

            if (!is_array($data) || !isset($data['hostname'])) {
                throw new RuntimeException('Data monitoring Windows tidak valid atau tidak lengkap.');
            }

            $memTotalKb = (float) ($data['mem_total_kb'] ?? 0);
            $memFreeKb = (float) ($data['mem_free_kb'] ?? 0);
            $memUsedKb = max(0, $memTotalKb - $memFreeKb);

            $swapTotalMb = (float) ($data['swap_total_mb'] ?? 0);
            $swapUsedMb = (float) ($data['swap_used_mb'] ?? 0);

            $diskTotalBytes = (float) ($data['disk_total_bytes'] ?? 0);
            $diskFreeBytes = (float) ($data['disk_free_bytes'] ?? 0);
            $diskUsedBytes = max(0, $diskTotalBytes - $diskFreeBytes);

            return [
                'hostname' => (string) $data['hostname'],
                'os_name' => (string) ($data['os_name'] ?? 'Windows'),
                'kernel' => (string) ($data['kernel'] ?? 'Unknown'),
                'uptime_seconds' => (int) ($data['uptime_seconds'] ?? 0),
                'load_average' => [0.0, 0.0, 0.0],
                'cpu' => [
                    'usage_percent' => max(0, min(100, round((float) ($data['cpu_usage_percent'] ?? 0), 2))),
                ],
                'memory' => [
                    'total_mb' => round($memTotalKb / 1024, 2),
                    'used_mb' => round($memUsedKb / 1024, 2),
                    'available_mb' => round($memFreeKb / 1024, 2),
                    'usage_percent' => $memTotalKb > 0
                        ? round(($memUsedKb / $memTotalKb) * 100, 2)
                        : 0,
                ],
                'swap' => [
                    'total_mb' => round($swapTotalMb, 2),
                    'used_mb' => round($swapUsedMb, 2),
                    'usage_percent' => $swapTotalMb > 0
                        ? round(($swapUsedMb / $swapTotalMb) * 100, 2)
                        : 0,
                ],
                'disk' => [
                    'total_gb' => round($diskTotalBytes / 1024 / 1024 / 1024, 2),
                    'used_gb' => round($diskUsedBytes / 1024 / 1024 / 1024, 2),
                    'available_gb' => round($diskFreeBytes / 1024 / 1024 / 1024, 2),
                    'usage_percent' => $diskTotalBytes > 0
                        ? round(($diskUsedBytes / $diskTotalBytes) * 100, 2)
                        : 0,
                ],
                'network' => [
                    'rx_bytes' => (int) ($data['net_rx_bytes'] ?? 0),
                    'tx_bytes' => (int) ($data['net_tx_bytes'] ?? 0),
                ],
                'host_key_fingerprint' => null,
                'collected_at' => now()->toISOString(),
            ];
        } catch (RuntimeException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new RuntimeException('Terjadi kesalahan saat mengambil data monitoring WinRM: ' . $exception->getMessage());
        }
    }

    private function buildMetricsScript(): string
    {
        return <<<'POWERSHELL'
$ErrorActionPreference = 'SilentlyContinue'
$os = Get-CimInstance Win32_OperatingSystem
$uptime = [int64][math]::Max(0, [math]::Floor(((Get-Date) - $os.LastBootUpTime).TotalSeconds))

$cpu = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples[0].CookedValue
if ($null -eq $cpu) {
    $cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
}

$swapTotal = 0
$swapUsed = 0
foreach ($item in (Get-CimInstance Win32_PageFileUsage)) {
    $swapTotal += [double]$item.AllocatedBaseSize
    $swapUsed += [double]$item.CurrentUsage
}

$drive = $env:SystemDrive
if (-not $drive) { $drive = 'C:' }
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$drive'"

$rx = [int64]0
$tx = [int64]0

try {
    if (-not ('WinIfHelper' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct MIB_IF_ROW2
{
    public ulong InterfaceLuid;
    public uint InterfaceIndex;
    public Guid InterfaceGuid;

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)]
    public string Alias;

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)]
    public string Description;

    public uint PhysicalAddressLength;

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public byte[] PhysicalAddress;

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public byte[] PermanentPhysicalAddress;

    public uint Mtu;
    public uint Type;
    public int TunnelType;
    public int MediaType;
    public int PhysicalMediumType;
    public int AccessType;
    public int DirectionType;
    public byte InterfaceAndOperStatusFlags;
    public int OperStatus;
    public int AdminStatus;
    public int MediaConnectState;
    public Guid NetworkGuid;
    public int ConnectionType;
    public ulong TransmitLinkSpeed;
    public ulong ReceiveLinkSpeed;
    public ulong InOctets;
    public ulong InUcastPkts;
    public ulong InNUcastPkts;
    public ulong InDiscards;
    public ulong InErrors;
    public ulong InUnknownProtos;
    public ulong InUcastOctets;
    public ulong InMulticastOctets;
    public ulong InBroadcastOctets;
    public ulong OutOctets;
    public ulong OutUcastPkts;
    public ulong OutNUcastPkts;
    public ulong OutDiscards;
    public ulong OutErrors;
    public ulong OutUcastOctets;
    public ulong OutMulticastOctets;
    public ulong OutBroadcastOctets;
    public ulong OutQLen;
}

public static class WinIfHelper
{
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    public static extern uint GetIfEntry2(ref MIB_IF_ROW2 row);
}
'@ -ErrorAction Stop
    }

    $adapters = @(
        Get-NetAdapter -ErrorAction Stop |
        Where-Object { $_.Status -eq 'Up' }
    )

    foreach ($adapter in $adapters) {
        try {
            $row = New-Object MIB_IF_ROW2
            $row.InterfaceIndex = [uint32]$adapter.ifIndex
            $row.PhysicalAddress = New-Object byte[] 32
            $row.PermanentPhysicalAddress = New-Object byte[] 32

            $apiResult = [WinIfHelper]::GetIfEntry2([ref]$row)

            if ($apiResult -eq 0) {
                $rx += [int64]$row.InUcastOctets
                $rx += [int64]$row.InMulticastOctets
                $rx += [int64]$row.InBroadcastOctets

                $tx += [int64]$row.OutUcastOctets
                $tx += [int64]$row.OutMulticastOctets
                $tx += [int64]$row.OutBroadcastOctets
            }
        } catch {
            continue
        }
    }
} catch {
    # Network counters remain zero if the Windows API is unavailable.
}

$result = [ordered]@{
    hostname = $env:COMPUTERNAME
    os_name = [string]$os.Caption
    kernel = [string]$os.Version
    uptime_seconds = $uptime
    cpu_usage_percent = [math]::Round([double]$cpu, 2)
    mem_total_kb = [double]$os.TotalVisibleMemorySize
    mem_free_kb = [double]$os.FreePhysicalMemory
    swap_total_mb = $swapTotal
    swap_used_mb = $swapUsed
    disk_total_bytes = [double]$disk.Size
    disk_free_bytes = [double]$disk.FreeSpace
    net_rx_bytes = $rx
    net_tx_bytes = $tx
}

$result | ConvertTo-Json -Compress
POWERSHELL;
    }

    private function openShell(string $endpoint, ManagedServer $server, int $timeout): string
    {
        $uuid = $this->uuid();
        $xml = <<<XML
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
            xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <s:Header>
    <wsa:To>{$endpoint}</wsa:To>
    <wsa:ReplyTo>
      <wsa:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
    </wsa:ReplyTo>
    <wsman:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</wsman:ResourceURI>
    <wsa:Action s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</wsa:Action>
    <wsman:MaxEnvelopeSize s:mustUnderstand="true">512000</wsman:MaxEnvelopeSize>
    <wsa:MessageID>uuid:{$uuid}</wsa:MessageID>
    <wsman:OperationTimeout>PT{$timeout}S</wsman:OperationTimeout>
  </s:Header>
  <s:Body>
    <rsp:Shell>
      <rsp:InputStreams>stdin</rsp:InputStreams>
      <rsp:OutputStreams>stdout stderr</rsp:OutputStreams>
    </rsp:Shell>
  </s:Body>
</s:Envelope>
XML;

        $response = $this->sendSoap($endpoint, $server, $xml, $timeout);
        $nodes = $response->xpath('//*[local-name()="ShellId" or (local-name()="Selector" and @Name="ShellId")]');

        if (empty($nodes)) {
            throw new RuntimeException('Gagal membuka sesi WinRM Shell.');
        }

        return (string) $nodes[0];
    }

    private function runCommand(string $endpoint, ManagedServer $server, string $shellId, string $encodedScript, int $timeout): string
    {
        $uuid = $this->uuid();
        $xml = <<<XML
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
            xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <s:Header>
    <wsa:To>{$endpoint}</wsa:To>
    <wsa:ReplyTo>
      <wsa:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
    </wsa:ReplyTo>
    <wsman:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</wsman:ResourceURI>
    <wsa:Action s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</wsa:Action>
    <wsman:MaxEnvelopeSize s:mustUnderstand="true">512000</wsman:MaxEnvelopeSize>
    <wsa:MessageID>uuid:{$uuid}</wsa:MessageID>
    <wsman:SelectorSet>
      <wsman:Selector Name="ShellId">{$shellId}</wsman:Selector>
    </wsman:SelectorSet>
    <wsman:OperationTimeout>PT{$timeout}S</wsman:OperationTimeout>
  </s:Header>
  <s:Body>
    <rsp:CommandLine>
      <rsp:Command>powershell</rsp:Command>
      <rsp:Arguments>-NoProfile -NonInteractive -EncodedCommand {$encodedScript}</rsp:Arguments>
    </rsp:CommandLine>
  </s:Body>
</s:Envelope>
XML;

        $response = $this->sendSoap($endpoint, $server, $xml, $timeout);
        $nodes = $response->xpath('//*[local-name()="CommandId"]');

        if (empty($nodes)) {
            throw new RuntimeException('Gagal menjalankan perintah di WinRM.');
        }

        return (string) $nodes[0];
    }

    /**
     * Memulai PowerShell dengan membaca perintah dari standard input.
     */
    private function runCommandViaStdin(
        string $endpoint,
        ManagedServer $server,
        string $shellId,
        int $timeout
    ): string {
        $uuid = $this->uuid();

        $xml = <<<XML
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
            xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <s:Header>
    <wsa:To>{$endpoint}</wsa:To>
    <wsa:ReplyTo>
      <wsa:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
    </wsa:ReplyTo>
    <wsman:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</wsman:ResourceURI>
    <wsa:Action s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</wsa:Action>
    <wsman:MaxEnvelopeSize s:mustUnderstand="true">512000</wsman:MaxEnvelopeSize>
    <wsa:MessageID>uuid:{$uuid}</wsa:MessageID>
    <wsman:SelectorSet>
      <wsman:Selector Name="ShellId">{$shellId}</wsman:Selector>
    </wsman:SelectorSet>
    <wsman:OperationTimeout>PT{$timeout}S</wsman:OperationTimeout>
  </s:Header>
  <s:Body>
    <rsp:CommandLine>
      <rsp:Command>powershell</rsp:Command>
      <rsp:Arguments>-NoProfile -NonInteractive -Command -</rsp:Arguments>
    </rsp:CommandLine>
  </s:Body>
</s:Envelope>
XML;

        $response = $this->sendSoap($endpoint, $server, $xml, $timeout);
        $nodes = $response->xpath('//*[local-name()="CommandId"]');

        if (empty($nodes)) {
            throw new RuntimeException('Gagal menjalankan PowerShell melalui stdin WinRM.');
        }

        return (string) $nodes[0];
    }

    private function sendInput(string $endpoint, ManagedServer $server, string $shellId, string $commandId, string $chunkB64, bool $isEnd, int $timeout): void
    {
        $uuid = $this->uuid();
        $endAttr = $isEnd ? ' End="true"' : '';
        $xml = <<<XML
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
            xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <s:Header>
    <wsa:To>{$endpoint}</wsa:To>
    <wsa:ReplyTo>
      <wsa:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
    </wsa:ReplyTo>
    <wsman:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</wsman:ResourceURI>
    <wsa:Action s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send</wsa:Action>
    <wsman:MaxEnvelopeSize s:mustUnderstand="true">512000</wsman:MaxEnvelopeSize>
    <wsa:MessageID>uuid:{$uuid}</wsa:MessageID>
    <wsman:SelectorSet>
      <wsman:Selector Name="ShellId">{$shellId}</wsman:Selector>
    </wsman:SelectorSet>
    <wsman:OperationTimeout>PT{$timeout}S</wsman:OperationTimeout>
  </s:Header>
  <s:Body>
    <rsp:Send>
      <rsp:Stream Name="stdin" CommandId="{$commandId}"{$endAttr}>{$chunkB64}</rsp:Stream>
    </rsp:Send>
  </s:Body>
</s:Envelope>
XML;

        $this->sendSoap($endpoint, $server, $xml, $timeout);
    }

    private function receiveOutput(string $endpoint, ManagedServer $server, string $shellId, string $commandId, int $timeout): string
    {
        $stdout = '';
        $stderr = '';

        for ($attempt = 0; $attempt < 30; $attempt++) {
            $uuid = $this->uuid();
            $xml = <<<XML
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
            xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <s:Header>
    <wsa:To>{$endpoint}</wsa:To>
    <wsa:ReplyTo>
      <wsa:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
    </wsa:ReplyTo>
    <wsman:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</wsman:ResourceURI>
    <wsa:Action s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive</wsa:Action>
    <wsman:MaxEnvelopeSize s:mustUnderstand="true">512000</wsman:MaxEnvelopeSize>
    <wsa:MessageID>uuid:{$uuid}</wsa:MessageID>
    <wsman:SelectorSet>
      <wsman:Selector Name="ShellId">{$shellId}</wsman:Selector>
    </wsman:SelectorSet>
    <wsman:OperationTimeout>PT{$timeout}S</wsman:OperationTimeout>
  </s:Header>
  <s:Body>
    <rsp:Receive>
      <rsp:DesiredStream CommandId="{$commandId}">stdout stderr</rsp:DesiredStream>
    </rsp:Receive>
  </s:Body>
</s:Envelope>
XML;

            $response = $this->sendSoap($endpoint, $server, $xml, $timeout);

            foreach ($response->xpath('//*[local-name()="Stream"]') as $stream) {
                $name = (string) ($stream['Name'] ?? '');
                $chunk = base64_decode((string) $stream, true) ?: '';

                if ($name === 'stdout') {
                    $stdout .= $chunk;
                } elseif ($name === 'stderr') {
                    $stderr .= $chunk;
                }
            }

            $stateNodes = $response->xpath('//*[local-name()="CommandState"]');
            $state = !empty($stateNodes) ? (string) ($stateNodes[0]['State'] ?? '') : '';

            if (str_ends_with($state, '/Done')) {
                break;
            }
        }

        if ($stdout === '' && $stderr !== '') {
            throw new RuntimeException('PowerShell WinRM error: ' . trim($stderr));
        }

        return $stdout;
    }

    private function closeShell(string $endpoint, ManagedServer $server, string $shellId): void
    {
        $uuid = $this->uuid();
        $xml = <<<XML
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
  <s:Header>
    <wsa:To>{$endpoint}</wsa:To>
    <wsa:ReplyTo>
      <wsa:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
    </wsa:ReplyTo>
    <wsman:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</wsman:ResourceURI>
    <wsa:Action s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete</wsa:Action>
    <wsman:MaxEnvelopeSize s:mustUnderstand="true">512000</wsman:MaxEnvelopeSize>
    <wsa:MessageID>uuid:{$uuid}</wsa:MessageID>
    <wsman:SelectorSet>
      <wsman:Selector Name="ShellId">{$shellId}</wsman:Selector>
    </wsman:SelectorSet>
  </s:Header>
  <s:Body/>
</s:Envelope>
XML;

        $this->sendSoap($endpoint, $server, $xml, 10);
    }

    private function sendSoap(string $endpoint, ManagedServer $server, string $xml, int $timeout = 20): SimpleXMLElement
    {
        $ch = curl_init($endpoint);

        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $xml,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $timeout + 5,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_HTTPAUTH => CURLAUTH_BASIC,
            CURLOPT_USERPWD => "{$server->username}:{$server->password}",
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/soap+xml;charset=UTF-8',
            ],
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
        ]);

        $body = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($body === false) {
            throw new RuntimeException("Koneksi WinRM gagal: {$error}");
        }

        if ($status === 401) {
            throw new RuntimeException('Autentikasi WinRM gagal (401). Pastikan username/password benar dan Basic Auth aktif.');
        }

        if ($status < 200 || $status >= 300) {
            throw new RuntimeException("WinRM mengembalikan HTTP {$status}.");
        }

        $parsed = @simplexml_load_string($body);

        if ($parsed === false) {
            throw new RuntimeException('Respons XML WinRM tidak valid.');
        }

        return $parsed;
    }

    private function uuid(): string
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
    }
}
