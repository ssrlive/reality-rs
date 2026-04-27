param(
    [string]$ServerListen = '127.0.0.1:9445',
    [string]$ClientListen = '127.0.0.1:1081',
    [string]$UdpEchoListen = '127.0.0.1:19090',
    [switch]$KeepRunning,
    [switch]$BuildWithCargo
)

# UDP ASSOCIATE end-to-end smoke test for anytls-real.
#
# Topology:
#   PowerShell UDP client
#     -> SOCKS5 UDP relay (anytls-real-client on $ClientListen)
#     -> REALITY tunnel
#     -> anytls-real-server (on $ServerListen)
#     -> UDP echo server (on $UdpEchoListen)
#     -> back the same way
#
# Run from the repo root:
#   pwsh -File admin/reality-smoke-udp.ps1
#   pwsh -File admin/reality-smoke-udp.ps1 -BuildWithCargo

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot

# ---------------------------------------------------------------------------
# Infrastructure helpers (shared pattern with reality-smoke.ps1)
# ---------------------------------------------------------------------------

function Split-Endpoint {
    param([string]$Endpoint)
    $parts = $Endpoint.Split(':')
    if ($parts.Count -lt 2) { throw "Invalid endpoint: $Endpoint" }
    [pscustomobject]@{
        HostName = ($parts[0..($parts.Count - 2)] -join ':')
        Port     = [int]$parts[-1]
    }
}

function Test-TcpEndpointAvailable {
    param([string]$Endpoint)
    $r = Split-Endpoint $Endpoint
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse($r.HostName), $r.Port)
    try { $listener.Start(); return $true } catch { return $false } finally { $listener.Stop() }
}

function Get-FreeLoopbackEndpoint {
    param([string]$BindHost)
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse($BindHost), 0)
    try { $listener.Start(); return "${BindHost}:$($listener.LocalEndpoint.Port)" } finally { $listener.Stop() }
}

function Resolve-Endpoint {
    param([string]$PreferredEndpoint, [string]$Label)
    if (Test-TcpEndpointAvailable $PreferredEndpoint) { return $PreferredEndpoint }
    $r = Split-Endpoint $PreferredEndpoint
    $fallback = Get-FreeLoopbackEndpoint $r.HostName
    Write-Warning "$Label endpoint $PreferredEndpoint is already in use. Falling back to $fallback"
    return $fallback
}

function Wait-TcpEndpoint {
    param([string]$Endpoint, [int]$TimeoutSeconds = 30)
    $r = Split-Endpoint $Endpoint
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $tcp = [System.Net.Sockets.TcpClient]::new()
        try {
            $iar = $tcp.BeginConnect($r.HostName, $r.Port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(500)) { $tcp.EndConnect($iar); return }
        }
        catch {} finally { $tcp.Dispose() }
        Start-Sleep -Milliseconds 250
    }
    throw "Timed out waiting for $Endpoint"
}

function New-LogPaths {
    param([string]$LogName)
    $log = Join-Path $repoRoot "target\tmp\$LogName.log"
    $err = Join-Path $repoRoot "target\tmp\$LogName.err.log"
    New-Item -ItemType Directory -Path (Split-Path -Parent $log) -Force | Out-Null
    if (Test-Path $log) { Remove-Item $log -Force }
    if (Test-Path $err) { Remove-Item $err -Force }
    [pscustomobject]@{ LogPath = $log; ErrorPath = $err }
}

function Start-BinaryProcess {
    param([string]$FilePath, [string[]]$Arguments, [string]$LogName)
    $paths = New-LogPaths $LogName
    $proc = Start-Process `
        -FilePath $FilePath `
        -ArgumentList $Arguments `
        -WorkingDirectory $repoRoot `
        -RedirectStandardOutput $paths.LogPath `
        -RedirectStandardError  $paths.ErrorPath `
        -PassThru
    [pscustomobject]@{ Process = $proc; LogPath = $paths.LogPath; ErrorPath = $paths.ErrorPath }
}

function Show-Logs {
    param([object[]]$Entries)
    foreach ($e in ($Entries | Where-Object { $null -ne $_ })) {
        if (Test-Path $e.LogPath) { Write-Host "===== $($e.LogPath) ====="; Get-Content $e.LogPath }
        if (Test-Path $e.ErrorPath) { Write-Host "===== $($e.ErrorPath) ====="; Get-Content $e.ErrorPath }
    }
}

function Assert-ProcessRunning {
    param($Entry, [string]$Label)
    if ($Entry.Process.HasExited) {
        Show-Logs -Entries @($Entry)
        throw "$Label exited early with code $($Entry.Process.ExitCode)"
    }
}

# ---------------------------------------------------------------------------
# SOCKS5 / UDP helpers
# ---------------------------------------------------------------------------

function Read-Exact {
    param([System.IO.Stream]$Stream, [int]$Count)
    $buf = New-Object byte[] $Count
    $off = 0
    while ($off -lt $Count) {
        $n = $Stream.Read($buf, $off, $Count - $off)
        if ($n -le 0) { throw "Unexpected EOF reading $Count bytes" }
        $off += $n
    }
    return $buf
}

function Read-Socks5AddressWithAtyp {
    param([byte]$Atyp, [System.IO.Stream]$Stream)
    switch ($Atyp) {
        1 {
            $addr = Read-Exact $Stream 4
            $pport = Read-Exact $Stream 2
            $ip = [System.Net.IPAddress]::new($addr)
            $port = ([int]$pport[0] * 256) + [int]$pport[1]
            return [pscustomobject]@{
                Endpoint = [System.Net.IPEndPoint]::new($ip, $port)
                RawTail  = [byte[]]($addr + $pport)
            }
        }
        4 {
            $addr = Read-Exact $Stream 16
            $pport = Read-Exact $Stream 2
            $ip = [System.Net.IPAddress]::new($addr)
            $port = ([int]$pport[0] * 256) + [int]$pport[1]
            return [pscustomobject]@{
                Endpoint = [System.Net.IPEndPoint]::new($ip, $port)
                RawTail  = [byte[]]($addr + $pport)
            }
        }
        3 {
            $len = (Read-Exact $Stream 1)[0]
            $hb = Read-Exact $Stream $len
            $pport = Read-Exact $Stream 2
            $dnsName = [System.Text.Encoding]::ASCII.GetString($hb)
            $port = ([int]$pport[0] * 256) + [int]$pport[1]
            $ip = ([System.Net.Dns]::GetHostAddresses($dnsName) | Select-Object -First 1)
            return [pscustomobject]@{
                Endpoint = [System.Net.IPEndPoint]::new($ip, $port)
                RawTail  = [byte[]](@($len) + $hb + $pport)
            }
        }
        default { throw "Unsupported SOCKS5 ATYP $Atyp" }
    }
}

function New-Socks5UdpPacket {
    param([byte[]]$Payload, [string]$TargetHost, [int]$TargetPort)
    $ip = [System.Net.IPAddress]::Parse($TargetHost)
    $pkt = [System.Collections.Generic.List[byte]]::new()
    $pkt.AddRange([byte[]](0, 0, 0))  # RSV, FRAG
    if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        $pkt.Add(1)
    }
    else {
        $pkt.Add(4)
    }
    $pkt.AddRange([byte[]]$ip.GetAddressBytes())
    $pkt.Add([byte](($TargetPort -shr 8) -band 0xff))
    $pkt.Add([byte]($TargetPort -band 0xff))
    $pkt.AddRange([byte[]]$Payload)
    return $pkt.ToArray()
}

function Parse-Socks5UdpPacket {
    param([byte[]]$Packet)
    if ($Packet.Length -lt 4) { throw "UDP relay packet too short" }
    $off = 3
    $atyp = $Packet[$off++]
    switch ($atyp) {
        1 { $addr = [System.Net.IPAddress]::new($Packet[$off..($off + 3)]); $off += 4 }
        4 { $addr = [System.Net.IPAddress]::new($Packet[$off..($off + 15)]); $off += 16 }
        3 {
            $nl = $Packet[$off++]
            $addr = [System.Text.Encoding]::ASCII.GetString($Packet[$off..($off + $nl - 1)])
            $off += $nl
        }
        default { throw "Unsupported UDP ATYP $atyp" }
    }
    $port = ([int]$Packet[$off] * 256) + [int]$Packet[$off + 1]; $off += 2
    $payload = if ($off -lt $Packet.Length) { $Packet[$off..($Packet.Length - 1)] } else { [byte[]]::new(0) }
    return [pscustomobject]@{ Address = $addr; Port = $port; Payload = [byte[]]$payload }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

$exeSuffix = if ($IsWindows) { '.exe' } else { '' }
$serverBinary = Join-Path $repoRoot "target\debug\anytls-real-server$exeSuffix"
$clientBinary = Join-Path $repoRoot "target\debug\anytls-real-client$exeSuffix"
$smokePassword = 'reality-smoke-password'

$ServerListen = Resolve-Endpoint $ServerListen  'Server'
$ClientListen = Resolve-Endpoint $ClientListen  'Client'
$server_config_path = Join-Path $repoRoot 'target\tmp\reality-server.smoke.toml'
$client_config_path = Join-Path $repoRoot 'target\tmp\reality-client.smoke.toml'
$null = New-Item -ItemType Directory -Path (Join-Path $repoRoot 'target\tmp') -Force

$echoEndpoint = Split-Endpoint $UdpEchoListen
$echoHost = $echoEndpoint.HostName
$echoPort = $echoEndpoint.Port

@"
[reality]
shortId = "aabbcc"
privateKey = "SMGC8zRkH_w4ZggVwiEJOdkeY1jWMZLCet5Qf2i-SmM"
version = "010203"
serverNames = ["test"]

[anytls]
password = "$smokePassword"

[server]
listen = "$ServerListen"
cert = "./bogo/keys/cert.pem"
key = "./bogo/keys/key.pem"
"@ | Set-Content -Path $server_config_path -Encoding UTF8

@"
[reality]
shortId = "aabbcc"
publicKey = "h72QTtr2UAYmGeblfKYIUsN3q4kOJQZPxq556g6eIhg"
serverName = "test"
version = "010203"

[anytls]
password = "$smokePassword"
idleCheckSecs = 30
idleTimeoutSecs = 30
minIdleSessions = 5

[client]
listen = "$ClientListen"
serverAddr = "$ServerListen"
caFile = "./bogo/keys/cert.pem"
insecure = true
"@ | Set-Content -Path $client_config_path -Encoding UTF8

# UDP echo helper script (written to target/tmp at runtime)
$udpEchoScript = Join-Path $repoRoot 'target\tmp\udp-echo-helper.ps1'
New-Item -ItemType Directory -Path (Join-Path $repoRoot 'target\tmp') -Force | Out-Null

$echoEntry = $null
$serverEntry = $null
$clientEntry = $null
$controlTcp = $null
$udpClient = $null

try {
    if ($BuildWithCargo) {
        Write-Host 'Building anytls-real binaries with Cargo'
        $paths = New-LogPaths 'reality-build'
        $build = Start-Process cargo `
            -ArgumentList @('build', '-p', 'anytls-real') `
            -WorkingDirectory $repoRoot `
            -RedirectStandardOutput $paths.LogPath `
            -RedirectStandardError  $paths.ErrorPath `
            -PassThru
        $build.WaitForExit()
        if ($build.ExitCode -ne 0) {
            Show-Logs -Entries @([pscustomobject]@{ LogPath = $paths.LogPath; ErrorPath = $paths.ErrorPath })
            throw "Cargo build failed with exit code $($build.ExitCode)"
        }
    }

    if (-not (Test-Path $serverBinary -PathType Leaf)) {
        throw "Server binary not found at '$serverBinary'. Build first with '-BuildWithCargo' or 'cargo build -p anytls-real'."
    }
    if (-not (Test-Path $clientBinary -PathType Leaf)) {
        throw "Client binary not found at '$clientBinary'. Build first with '-BuildWithCargo' or 'cargo build -p anytls-real'."
    }

    # Start UDP echo server
    Write-Host "Starting UDP echo server on ${echoHost}:${echoPort}"
    @"
param([string]`$BindHost, [int]`$Port)
`$udp = [System.Net.Sockets.UdpClient]::new([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse(`$BindHost), `$Port))
try {
    while (`$true) {
        `$remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
        `$data = `$udp.Receive([ref]`$remote)
        [void]`$udp.Send(`$data, `$data.Length, `$remote)
    }
} finally { `$udp.Dispose() }
"@ | Set-Content -Path $udpEchoScript -Encoding UTF8

    $shellPath = (Get-Process -Id $PID).Path
    $echoPaths = New-LogPaths 'udp-echo'
    $echoProc = Start-Process $shellPath `
        -ArgumentList @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', $udpEchoScript, '-BindHost', $echoHost, '-Port', $echoPort) `
        -WorkingDirectory $repoRoot `
        -RedirectStandardOutput $echoPaths.LogPath `
        -RedirectStandardError  $echoPaths.ErrorPath `
        -PassThru
    $echoEntry = [pscustomobject]@{ Process = $echoProc; LogPath = $echoPaths.LogPath; ErrorPath = $echoPaths.ErrorPath }
    Start-Sleep -Milliseconds 250

    # Start anytls-real-server
    Write-Host "Starting anytls-real-server on $ServerListen"
    $serverEntry = Start-BinaryProcess $serverBinary @('--config', $server_config_path) 'reality-server'
    Start-Sleep -Milliseconds 500
    Assert-ProcessRunning $serverEntry 'anytls-real-server'
    Wait-TcpEndpoint $ServerListen

    # Start anytls-real-client
    Write-Host "Starting anytls-real-client on $ClientListen"
    $clientEntry = Start-BinaryProcess $clientBinary @('--config', $client_config_path) 'reality-client'
    Start-Sleep -Milliseconds 500
    Assert-ProcessRunning $clientEntry 'anytls-real-client'
    Wait-TcpEndpoint $ClientListen

    # SOCKS5 handshake: open control TCP connection for UDP ASSOCIATE
    Write-Host 'Opening SOCKS5 control connection for UDP ASSOCIATE'
    $clientEp = Split-Endpoint $ClientListen
    $controlTcp = [System.Net.Sockets.TcpClient]::new($clientEp.HostName, $clientEp.Port)
    $stream = $controlTcp.GetStream()

    # Auth negotiation: VER=5, NMETHODS=1, METHOD=0 (no auth)
    $stream.Write([byte[]](0x05, 0x01, 0x00), 0, 3)
    $authResp = Read-Exact $stream 2
    if ($authResp[0] -ne 0x05 -or $authResp[1] -ne 0x00) {
        throw "SOCKS5 auth negotiation failed: $([System.BitConverter]::ToString($authResp))"
    }

    # UDP ASSOCIATE request: VER=5, CMD=3, RSV=0, ATYP=1, ADDR=0.0.0.0, PORT=0
    $udpReq = [byte[]](0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    $stream.Write($udpReq, 0, $udpReq.Length)

    $replyHead = Read-Exact $stream 4
    if ($replyHead[0] -ne 0x05 -or $replyHead[1] -ne 0x00) {
        throw "UDP ASSOCIATE failed (REP=$($replyHead[1])): $([System.BitConverter]::ToString($replyHead))"
    }

    $replyAddr = Read-Socks5AddressWithAtyp -Atyp $replyHead[3] -Stream $stream
    $relayEp = $replyAddr.Endpoint
    Write-Host "SOCKS5 UDP relay endpoint: $relayEp"

    # Send a UDP packet through the relay to the echo server
    $udpClient = [System.Net.Sockets.UdpClient]::new()
    $udpClient.Client.ReceiveTimeout = 5000

    $payload = [System.Text.Encoding]::UTF8.GetBytes('reality-uot-ok')
    $pkt = New-Socks5UdpPacket -Payload $payload -TargetHost $echoHost -TargetPort $echoPort
    [void]$udpClient.Send($pkt, $pkt.Length, $relayEp)
    Write-Host "Sent UDP packet through SOCKS5 relay -> echo server"

    $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
    $response = $udpClient.Receive([ref]$remote)
    $decoded = Parse-Socks5UdpPacket -Packet $response
    $text = [System.Text.Encoding]::UTF8.GetString($decoded.Payload)

    Write-Host "Received UDP echo: '$text' from $($decoded.Address):$($decoded.Port)"

    if ($text -ne 'reality-uot-ok') {
        throw "Unexpected UDP payload: '$text'"
    }
    if ($decoded.Port -ne $echoPort) {
        throw "Unexpected UDP source port $($decoded.Port), expected $echoPort"
    }

    Write-Host 'UDP ASSOCIATE end-to-end smoke test passed'

    if ($KeepRunning) {
        Write-Host 'Tunnel is up. Press Ctrl+C to stop background processes.'
        while ($true) { Start-Sleep -Seconds 1 }
    }
}
catch {
    Show-Logs -Entries @($serverEntry, $clientEntry, $echoEntry)
    throw
}
finally {
    if ($null -ne $udpClient) { $udpClient.Dispose() }
    if ($null -ne $controlTcp) { $controlTcp.Dispose() }

    Write-Host 'Cleaning up background processes'
    foreach ($entry in @($clientEntry, $serverEntry, $echoEntry)) {
        if ($null -ne $entry -and -not $entry.Process.HasExited) {
            Stop-Process -Id $entry.Process.Id -Force -ErrorAction SilentlyContinue
        }
    }
    if (Test-Path $udpEchoScript) { Remove-Item $udpEchoScript -Force -ErrorAction SilentlyContinue }
    foreach ($path in @($server_config_path, $client_config_path)) {
        if (Test-Path $path) { Remove-Item $path -Force -ErrorAction SilentlyContinue }
    }
    Write-Host 'Done.'
}
