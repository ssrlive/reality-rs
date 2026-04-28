param(
    [string]$ServerListen = '127.0.0.1:9445',
    [string]$ClientListen = '127.0.0.1:1081',
    [string]$TargetListen = '127.0.0.1:18080',
    [switch]$KeepRunning,
    [switch]$BuildWithCargo
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot

function Split-Endpoint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Endpoint
    )

    $parts = $Endpoint.Split(':')
    if ($parts.Count -lt 2) {
        throw "Invalid endpoint: $Endpoint"
    }

    [pscustomobject]@{
        HostName = ($parts[0..($parts.Count - 2)] -join ':')
        Port     = [int]$parts[-1]
    }
}

function Test-TcpEndpointAvailable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Endpoint
    )

    $resolved = Split-Endpoint -Endpoint $Endpoint
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse($resolved.HostName), $resolved.Port)
    try {
        $listener.Start()
        return $true
    }
    catch {
        return $false
    }
    finally {
        $listener.Stop()
    }
}

function Get-FreeLoopbackEndpoint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BindHost
    )

    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse($BindHost), 0)
    try {
        $listener.Start()
        $port = $listener.LocalEndpoint.Port
        return "${BindHost}:$port"
    }
    finally {
        $listener.Stop()
    }
}

function Resolve-Endpoint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PreferredEndpoint,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    if (Test-TcpEndpointAvailable -Endpoint $PreferredEndpoint) {
        return $PreferredEndpoint
    }

    $resolved = Split-Endpoint -Endpoint $PreferredEndpoint
    $fallback = Get-FreeLoopbackEndpoint -BindHost $resolved.HostName
    Write-Warning "$Label endpoint $PreferredEndpoint is already in use. Falling back to $fallback"
    return $fallback
}

function Wait-TcpEndpoint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Endpoint,

        [int]$TimeoutSeconds = 30
    )

    $resolved = Split-Endpoint -Endpoint $Endpoint
    $hostName = $resolved.HostName
    $port = $resolved.Port
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    while ((Get-Date) -lt $deadline) {
        $client = [System.Net.Sockets.TcpClient]::new()
        try {
            $async = $client.BeginConnect($hostName, $port, $null, $null)
            if ($async.AsyncWaitHandle.WaitOne(500)) {
                $client.EndConnect($async)
                return
            }
        }
        catch {
        }
        finally {
            $client.Dispose()
        }

        Start-Sleep -Milliseconds 250
    }

    throw "Timed out waiting for $Endpoint"
}

function Start-CargoProcess {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$LogName
    )

    $logPath = Join-Path $repoRoot ("target/tmp/$LogName.log")
    $errorPath = Join-Path $repoRoot ("target/tmp/$LogName.err.log")

    New-Item -ItemType Directory -Path (Split-Path -Parent $logPath) -Force | Out-Null
    if (Test-Path $logPath) { Remove-Item $logPath -Force }
    if (Test-Path $errorPath) { Remove-Item $errorPath -Force }

    $process = Start-Process `
        -FilePath 'cargo' `
        -ArgumentList $Arguments `
        -WorkingDirectory $repoRoot `
        -RedirectStandardOutput $logPath `
        -RedirectStandardError $errorPath `
        -PassThru

    [pscustomobject]@{
        Process   = $process
        LogPath   = $logPath
        ErrorPath = $errorPath
    }
}

function Start-BinaryProcess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$LogName
    )

    $logPath = Join-Path $repoRoot ("target/tmp/$LogName.log")
    $errorPath = Join-Path $repoRoot ("target/tmp/$LogName.err.log")

    New-Item -ItemType Directory -Path (Split-Path -Parent $logPath) -Force | Out-Null
    if (Test-Path $logPath) { Remove-Item $logPath -Force }
    if (Test-Path $errorPath) { Remove-Item $errorPath -Force }

    $process = Start-Process `
        -FilePath $FilePath `
        -ArgumentList $Arguments `
        -WorkingDirectory $repoRoot `
        -RedirectStandardOutput $logPath `
        -RedirectStandardError $errorPath `
        -PassThru

    [pscustomobject]@{
        Process   = $process
        LogPath   = $logPath
        ErrorPath = $errorPath
    }
}

function Start-HttpTargetProcess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ListenUri,

        [Parameter(Mandatory = $true)]
        [string]$LogName
    )

    $scriptPath = Join-Path $repoRoot ("target/tmp/$LogName.ps1")
    $logPath = Join-Path $repoRoot ("target/tmp/$LogName.log")
    $errorPath = Join-Path $repoRoot ("target/tmp/$LogName.err.log")
    $shellPath = (Get-Process -Id $PID).Path

    New-Item -ItemType Directory -Path (Split-Path -Parent $scriptPath) -Force | Out-Null
    if (Test-Path $scriptPath) { Remove-Item $scriptPath -Force }
    if (Test-Path $logPath) { Remove-Item $logPath -Force }
    if (Test-Path $errorPath) { Remove-Item $errorPath -Force }

    @'
param(
    [string]$ListenUri
)

$ErrorActionPreference = 'Stop'
$listener = [System.Net.HttpListener]::new()

try {
    $listener.Prefixes.Add($ListenUri)
    $listener.Start()
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $body = [System.Text.Encoding]::UTF8.GetBytes('reality tunnel ok')
        $context.Response.StatusCode = 200
        $context.Response.ContentType = 'text/plain'
        $context.Response.ContentLength64 = $body.Length
        $context.Response.OutputStream.Write($body, 0, $body.Length)
        $context.Response.OutputStream.Close()
    }
}
finally {
    if ($listener.IsListening) {
        $listener.Stop()
    }
    $listener.Close()
}
'@ | Set-Content -Path $scriptPath -Encoding UTF8

    $process = Start-Process `
        -FilePath $shellPath `
        -ArgumentList @('-NoProfile', '-File', $scriptPath, $ListenUri) `
        -WorkingDirectory $repoRoot `
        -RedirectStandardOutput $logPath `
        -RedirectStandardError $errorPath `
        -PassThru

    [pscustomobject]@{
        Process    = $process
        LogPath    = $logPath
        ErrorPath  = $errorPath
        ScriptPath = $scriptPath
    }
}

function Show-Logs {
    param(
        [Parameter()]
        [object[]]$Entries
    )

    if ($null -eq $Entries -or $Entries.Count -eq 0) {
        return
    }

    foreach ($entry in $Entries) {
        if (Test-Path $entry.LogPath) {
            Write-Host "===== $($entry.LogPath) ====="
            Get-Content $entry.LogPath
        }
        if (Test-Path $entry.ErrorPath) {
            Write-Host "===== $($entry.ErrorPath) ====="
            Get-Content $entry.ErrorPath
        }
    }
}

function Assert-ProcessRunning {
    param(
        [Parameter(Mandatory = $true)]
        $Entry,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    if ($Entry.Process.HasExited) {
        Show-Logs -Entries @($Entry)
        throw "$Label exited early with code $($Entry.Process.ExitCode)"
    }
}

function Assert-FileExists {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    if (-not (Test-Path $FilePath -PathType Leaf)) {
        throw "$Label binary not found at '$FilePath'. Build it first with './admin/reality-smoke.ps1 -BuildWithCargo' or 'cargo build -p anytls-real'."
    }
}

$httpTarget = $null
$server = $null
$client = $null
$server_config_path = Join-Path $repoRoot 'target/tmp/reality-server.smoke.toml'
$client_config_path = Join-Path $repoRoot 'target/tmp/reality-client.smoke.toml'

$exeSuffix = if ($IsWindows) { '.exe' } else { '' }
$serverBinary = Join-Path $repoRoot ("target/debug/anytls-real-server$exeSuffix")
$clientBinary = Join-Path $repoRoot ("target/debug/anytls-real-client$exeSuffix")

$ServerListen = Resolve-Endpoint -PreferredEndpoint $ServerListen -Label 'Server'
$ClientListen = Resolve-Endpoint -PreferredEndpoint $ClientListen -Label 'Client'
$TargetListen = Resolve-Endpoint -PreferredEndpoint $TargetListen -Label 'Target'
$targetUri = "http://$TargetListen/"

$smokePassword = 'reality-smoke-password'
$null = New-Item -ItemType Directory -Path (Join-Path $repoRoot 'target/tmp') -Force

@"
[reality]
shortId = "aabbcc"
privateKey = "SMGC8zRkH_w4ZggVwiEJOdkeY1jWMZLCet5Qf2i-SmM"
version = "010203"
serverNames = ["baidu.com", "www.baidu.com"]

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
serverName = "baidu.com"
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

try {
    if ($BuildWithCargo) {
        Write-Host 'Building formal server and client binaries with Cargo'
        $build = Start-CargoProcess -Arguments @('build', '-p', 'anytls-real') -LogName 'reality-build'
        $build.Process.WaitForExit()
        if ($build.Process.ExitCode -ne 0) {
            Show-Logs -Entries @($build)
            throw "Cargo build exited with code $($build.Process.ExitCode)"
        }
    }

    Assert-FileExists -FilePath $serverBinary -Label 'Formal server'
    Assert-FileExists -FilePath $clientBinary -Label 'Formal client'

    Write-Host "Starting local HTTP target on $targetUri"
    $httpTarget = Start-HttpTargetProcess -ListenUri $targetUri -LogName 'reality-target'
    Start-Sleep -Milliseconds 250
    Assert-ProcessRunning -Entry $httpTarget -Label 'HTTP target'
    Wait-TcpEndpoint -Endpoint $TargetListen

    Write-Host "Starting formal server on $ServerListen"
    $server = Start-BinaryProcess -FilePath $serverBinary -Arguments @('--config', $server_config_path) -LogName 'reality-server'
    Start-Sleep -Milliseconds 500
    Assert-ProcessRunning -Entry $server -Label 'Formal server'
    Wait-TcpEndpoint -Endpoint $ServerListen

    Write-Host "Starting formal client on $ClientListen"
    $client = Start-BinaryProcess -FilePath $clientBinary -Arguments @('--config', $client_config_path) -LogName 'reality-client'
    Start-Sleep -Milliseconds 500
    Assert-ProcessRunning -Entry $client -Label 'Formal client'
    Wait-TcpEndpoint -Endpoint $ClientListen

    Write-Host 'Running SOCKS5 smoke request'
    $response = & curl.exe --silent --show-error --socks5-hostname $ClientListen $targetUri
    if ($LASTEXITCODE -ne 0) {
        throw "curl exited with code $LASTEXITCODE"
    }

    Write-Host "Smoke response: $response"

    $serverEndpoint = Split-Endpoint -Endpoint $ServerListen
    $resolveArg = "baidu.com:$($serverEndpoint.Port):$($serverEndpoint.HostName)"
    Write-Host "Running direct SNI fallback probe to baidu.com on $ServerListen"
    $fallbackResponse = & curl.exe --silent --show-error -k --resolve $resolveArg "https://baidu.com:$($serverEndpoint.Port)/"
    if ($LASTEXITCODE -ne 0) {
        throw "Fallback curl probe exited with code $LASTEXITCODE"
    }
    Write-Host "Fallback probe response: $fallbackResponse"

    if ($response -ne 'reality tunnel ok') {
        throw "Unexpected response body: $response"
    }

    if ($KeepRunning) {
        Write-Host 'Tunnel is up. Press Ctrl+C to stop background processes.'
        while ($true) {
            Start-Sleep -Seconds 1
        }
    }
}
catch {
    $logEntries = @($httpTarget, $server, $client) | Where-Object { $null -ne $_ }
    Show-Logs -Entries $logEntries
    throw
}
finally {
    if (-not $KeepRunning) {
        Write-Host 'Cleaning up background processes'

        foreach ($entry in @($client, $server, $httpTarget)) {
            if ($null -ne $entry -and -not $entry.Process.HasExited) {
                Stop-Process -Id $entry.Process.Id -Force
            }
        }

        if ($null -ne $httpTarget -and (Test-Path $httpTarget.ScriptPath)) {
            Remove-Item $httpTarget.ScriptPath -Force -ErrorAction SilentlyContinue
        }

        foreach ($path in @($server_config_path, $client_config_path)) {
            if (Test-Path $path) {
                Remove-Item $path -Force -ErrorAction SilentlyContinue
            }
        }

        Write-Host 'Done.'
    }
}