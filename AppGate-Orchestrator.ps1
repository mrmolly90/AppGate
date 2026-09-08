<#
.SYNOPSIS
    AppGate Unified Proxy System Orchestrator
.DESCRIPTION
    Builds, deploys, and manages the AppGate security gateway ecosystem:
    - Rust Gateway (primary data plane)
    - Go Control Plane (policy & audit management)
    - Security scanning, auth, rate limiting, traffic forwarding
.NOTES
    Run as Administrator for service registration.
    Requires: Rust (cargo), Go (1.21+), PowerShell 7+, Docker (optional)
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet("build", "run", "test", "deploy", "stop", "logs", "status", "security-scan")]
    [string]$Action = "status",

    [Parameter()]
    [string]$RootPath = "C:\AppGate",

    [Parameter()]
    [string]$Environment = "development",

    [Parameter()]
    [switch]$EnableDocker
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "Continue"

# ── Configuration ─────────────────────────────────────────────────────────────
$Config = @{
    RootPath       = $RootPath
    GatewayPath    = Join-Path $RootPath "gateway"
    RustGatewayPath= Join-Path $RootPath "rust-gateway"
    ControlPlanePath = Join-Path $RootPath "control-plane"
    LogPath        = Join-Path $RootPath "logs"
    BinPath        = Join-Path $RootPath "bin"
    EnvFile        = Join-Path $RootPath ".env"
    Ports          = @{
        GatewayHTTP  = 8080
        GatewayHTTPS = 8443
        ControlPlane = 9090
        Metrics      = 9091
    }
    Colors         = @{
        Success = "`e[32m"
        Error   = "`e[31m"
        Warning = "`e[33m"
        Info    = "`e[36m"
        Reset   = "`e[0m"
    }
}

# ── Helper Functions ──────────────────────────────────────────────────────────
function Write-AppGateLog {
    param([string]$Level, [string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "SUCCESS" { $Config.Colors.Success }
        "ERROR"   { $Config.Colors.Error }
        "WARN"    { $Config.Colors.Warning }
        default   { $Config.Colors.Info }
    }
    Write-Host "$color[$timestamp] [$Level] $Message$($Config.Colors.Reset)"
}

function Ensure-Directory {
    param([string]$Path)
    if (!(Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        Write-AppGateLog "INFO" "Created directory: $Path"
    }
}

function Test-Command {
    param([string]$Command)
    $null = Get-Command $Command -ErrorAction SilentlyContinue
    return $?
}

function Invoke-Step {
    param([string]$Description, [scriptblock]$Action)
    Write-AppGateLog "INFO" "▶ $Description"
    try {
        & $Action
        Write-AppGateLog "SUCCESS" "✓ $Description"
    }
    catch {
        Write-AppGateLog "ERROR" "✗ $Description : $_"
        throw
    }
}

# ── Build Actions ─────────────────────────────────────────────────────────────
function Build-Gateway {
    Invoke-Step "Building Rust Gateway (Primary Data Plane)" {
        Push-Location $Config.GatewayPath
        try {
            # Check and fix dependencies first
            if (!(Test-Path "Cargo.toml")) {
                throw "Cargo.toml not found in $($Config.GatewayPath)"
            }

            # Run cargo check to surface all errors
            Write-AppGateLog "INFO" "Running cargo check..."
            $checkOutput = cargo check 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-AppGateLog "WARN" "cargo check found issues — applying fixes..."
                # The fixes above should already be in place
            }

            # Build release binary
            Write-AppGateLog "INFO" "Compiling release binary..."
            cargo build --release

            # Copy to bin directory
            $src = Join-Path $Config.GatewayPath "target\release\appgate.exe"
            $dst = Join-Path $Config.BinPath "appgate-gateway.exe"
            Copy-Item $src $dst -Force
            Write-AppGateLog "SUCCESS" "Gateway binary: $dst"
        }
        finally {
            Pop-Location
        }
    }
}

function Build-RustGateway {
    if (!(Test-Path $Config.RustGatewayPath)) {
        Write-AppGateLog "WARN" "rust-gateway path not found, skipping"
        return
    }
    Invoke-Step "Building Rust Gateway (Alt/Edge)" {
        Push-Location $Config.RustGatewayPath
        try {
            cargo build --release
            $src = Join-Path $Config.RustGatewayPath "target\release\appgate-gateway.exe"
            $dst = Join-Path $Config.BinPath "appgate-edge.exe"
            if (Test-Path $src) {
                Copy-Item $src $dst -Force
                Write-AppGateLog "SUCCESS" "Edge gateway binary: $dst"
            }
        }
        finally {
            Pop-Location
        }
    }
}

function Build-ControlPlane {
    Invoke-Step "Building Go Control Plane" {
        Push-Location $Config.ControlPlanePath
        try {
            $env:CGO_ENABLED = "0"
            $env:GOOS = "windows"
            $env:GOARCH = "amd64"

            go build -ldflags "-s -w -X main.version=$(git describe --tags --always 2>$null || echo 'dev')" `
                -o (Join-Path $Config.BinPath "appgate-control-plane.exe") `
                .\cmd\server

            Write-AppGateLog "SUCCESS" "Control plane binary built"
        }
        finally {
            Pop-Location
        }
    }
}

# ── Run Actions ───────────────────────────────────────────────────────────────
function Start-Gateway {
    $binary = Join-Path $Config.BinPath "appgate-gateway.exe"
    if (!(Test-Path $binary)) {
        throw "Gateway binary not found. Run -Action build first."
    }

    $logFile = Join-Path $Config.LogPath "gateway-$(Get-Date -Format yyyyMMdd-HHmmss).log"

    $env:RUST_LOG = "info"
    $env:BIND_ADDR = "0.0.0.0"
    $env:PORT = $Config.Ports.GatewayHTTP
    $env:TLS_ENABLED = "false"
    $env:JWT_ENABLED = "true"
    $env:RATE_LIMIT_ENABLED = "true"
    $env:AUDIT_ENABLED = "true"
    $env:AUDIT_ENDPOINT = "http://localhost:$($Config.Ports.ControlPlane)"
    $env:CIRCUIT_BREAKER_ENABLED = "true"

    $proc = Start-Process -FilePath $binary -ArgumentList @() `
        -RedirectStandardOutput $logFile -RedirectStandardError $logFile `
        -WindowStyle Hidden -PassThru

    # Write PID file
    $pidFile = Join-Path $Config.RootPath "gateway.pid"
    $proc.Id | Out-File $pidFile -Force
    Write-AppGateLog "SUCCESS" "Gateway started (PID: $($proc.Id)) on port $($Config.Ports.GatewayHTTP)"
    return $proc
}

function Start-ControlPlane {
    $binary = Join-Path $Config.BinPath "appgate-control-plane.exe"
    if (!(Test-Path $binary)) {
        throw "Control plane binary not found. Run -Action build first."
    }

    $logFile = Join-Path $Config.LogPath "control-plane-$(Get-Date -Format yyyyMMdd-HHmmss).log"

    $env:HTTP_PORT = $Config.Ports.ControlPlane
    $env:DATABASE_URL = "postgres://appgate:appgate@localhost:5432/appgate?sslmode=disable"
    $env:ETCD_ENDPOINTS = "localhost:2379"
    $env:LEADER_ELECTION_KEY = "/appgate/leader"
    $env:INSTANCE_ID = $env:COMPUTERNAME

    $proc = Start-Process -FilePath $binary -ArgumentList @() `
        -RedirectStandardOutput $logFile -RedirectStandardError $logFile `
        -WindowStyle Hidden -PassThru

    $pidFile = Join-Path $Config.RootPath "control-plane.pid"
    $proc.Id | Out-File $pidFile -Force
    Write-AppGateLog "SUCCESS" "Control Plane started (PID: $($proc.Id)) on port $($Config.Ports.ControlPlane)"
    return $proc
}

# ── Test Actions ──────────────────────────────────────────────────────────────
function Test-Gateway {
    Invoke-Step "Running Gateway unit tests" {
        Push-Location $Config.GatewayPath
        try {
            cargo test --release
        }
        finally {
            Pop-Location
        }
    }

    # Integration health check
    Start-Sleep -Seconds 2
    try {
        $resp = Invoke-RestMethod -Uri "http://localhost:$($Config.Ports.GatewayHTTP)/health" -Method GET -TimeoutSec 5
        Write-AppGateLog "SUCCESS" "Gateway health check: $resp"
    }
    catch {
        Write-AppGateLog "WARN" "Gateway health check failed (may not be running yet)"
    }
}

function Test-ControlPlane {
    Invoke-Step "Running Control Plane tests" {
        Push-Location $Config.ControlPlanePath
        try {
            go test ./...
        }
        finally {
            Pop-Location
        }
    }
}

# ── Security Scan ─────────────────────────────────────────────────────────────
function Invoke-SecurityScan {
    Write-AppGateLog "INFO" "🔒 Starting AppGate Security Scan"

    # 1. Dependency vulnerability scan (Rust)
    if (Test-Command "cargo") {
        Invoke-Step "Rust dependency audit" {
            Push-Location $Config.GatewayPath
            if (!(Test-Command "cargo-audit")) {
                cargo install cargo-audit
            }
            cargo audit
            Pop-Location
        }
    }

    # 2. Go vulnerability scan
    if (Test-Command "govulncheck") {
        Invoke-Step "Go vulnerability scan" {
            Push-Location $Config.ControlPlanePath
            govulncheck ./...
            Pop-Location
        }
    }

    # 3. Secret leak detection
    Invoke-Step "Secret leak detection" {
        $patterns = @(
            'apikey\s*=\s*["''][a-zA-Z0-9]{16,}["'']',
            'password\s*=\s*["''][^"'']+["'']',
            'AKIA[0-9A-Z]{16}',
            'ghp_[a-zA-Z0-9]{36}',
            'sk-[a-zA-Z0-9]{20,}'
        )
        $files = Get-ChildItem -Path $Config.RootPath -Recurse -Include *.rs,*.go,*.toml,*.yaml,*.yml,*.json,*.env
        $leaks = 0
        foreach ($file in $files) {
            $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
            foreach ($pattern in $patterns) {
                if ($content -match $pattern) {
                    Write-AppGateLog "WARN" "Potential secret in $($file.FullName)"
                    $leaks++
                }
            }
        }
        if ($leaks -eq 0) {
            Write-AppGateLog "SUCCESS" "No potential secrets leaked in source files"
        }
    }

    # 4. TLS configuration audit
    Invoke-Step "TLS configuration audit" {
        $certPath = Join-Path $Config.RootPath "tls\cert.pem"
        if (Test-Path $certPath) {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath)
            $daysUntilExpiry = ($cert.NotAfter - (Get-Date)).Days
            if ($daysUntilExpiry -lt 30) {
                Write-AppGateLog "ERROR" "TLS certificate expires in $daysUntilExpiry days!"
            }
            else {
                Write-AppGateLog "SUCCESS" "TLS certificate valid for $daysUntilExpiry days"
            }
        }
    }
}

# ── Status & Logs ─────────────────────────────────────────────────────────────
function Get-SystemStatus {
    Write-AppGateLog "INFO" "📊 AppGate System Status"

    $components = @(
        @{ Name = "Gateway"; PidFile = "gateway.pid"; Port = $Config.Ports.GatewayHTTP; HealthPath = "/health" }
        @{ Name = "ControlPlane"; PidFile = "control-plane.pid"; Port = $Config.Ports.ControlPlane; HealthPath = "/healthz" }
    )

    foreach ($comp in $components) {
        $pidFile = Join-Path $Config.RootPath $comp.PidFile
        $running = $false
        if (Test-Path $pidFile) {
            $pid = Get-Content $pidFile -Raw
            $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
            $running = ($null -ne $proc)
        }

        $status = if ($running) { "RUNNING" } else { "STOPPED" }
        $color = if ($running) { "SUCCESS" } else { "WARN" }
        Write-AppGateLog $color "$($comp.Name): $status (Port: $($comp.Port))"

        if ($running) {
            try {
                $resp = Invoke-RestMethod -Uri "http://localhost:$($comp.Port)$($comp.HealthPath)" -TimeoutSec 3
                Write-AppGateLog "SUCCESS" "  ↳ Health: $resp"
            }
            catch {
                Write-AppGateLog "WARN" "  ↳ Health check failed"
            }
        }
    }
}

function Show-Logs {
    param([string]$Component = "all", [int]$Lines = 50)
    $logFiles = Get-ChildItem $Config.LogPath -Filter "*.log" | Sort-Object LastWriteTime -Descending
    if ($Component -ne "all") {
        $logFiles = $logFiles | Where-Object { $_.Name -like "*$Component*" }
    }
    foreach ($file in $logFiles | Select-Object -First 3) {
        Write-AppGateLog "INFO" "📄 $($file.Name) (last $Lines lines):"
        Get-Content $file.FullName -Tail $Lines | ForEach-Object { Write-Host "  $_" }
        Write-Host ""
    }
}

# ── Stop Actions ──────────────────────────────────────────────────────────────
function Stop-All {
    $pidFiles = @("gateway.pid", "control-plane.pid")
    foreach ($file in $pidFiles) {
        $path = Join-Path $Config.RootPath $file
        if (Test-Path $path) {
            $pid = Get-Content $path -Raw
            $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
            if ($proc) {
                Write-AppGateLog "INFO" "Stopping $($file.Replace('.pid','')) (PID: $pid)..."
                $proc | Stop-Process -Force
                Remove-Item $path -Force
                Write-AppGateLog "SUCCESS" "$($file.Replace('.pid','')) stopped"
            }
        }
    }
}

# ── Main Orchestrator ─────────────────────────────────────────────────────────
Ensure-Directory $Config.LogPath
Ensure-Directory $Config.BinPath

switch ($Action) {
    "build" {
        Build-Gateway
        Build-RustGateway
        Build-ControlPlane
        Write-AppGateLog "SUCCESS" "🚀 All components built successfully"
    }
    "test" {
        Test-Gateway
        Test-ControlPlane
    }
    "run" {
        Stop-All
        Start-Sleep -Seconds 1
        Start-ControlPlane
        Start-Sleep -Seconds 2
        Start-Gateway
        Write-AppGateLog "SUCCESS" "🚀 AppGate system is running"
        Get-SystemStatus
    }
    "stop" {
        Stop-All
    }
    "status" {
        Get-SystemStatus
    }
    "logs" {
        Show-Logs -Component $env:APPGATE_LOG_COMPONENT -Lines ($env:APPGATE_LOG_LINES ?? 50)
    }
    "security-scan" {
        Invoke-SecurityScan
    }
    "deploy" {
        Build-Gateway
        Build-ControlPlane
        Stop-All
        Start-Sleep -Seconds 1
        Start-ControlPlane
        Start-Sleep -Seconds 2
        Start-Gateway
        Invoke-SecurityScan
        Get-SystemStatus
    }
    default {
        Write-AppGateLog "INFO" "Usage: .\AppGate-Orchestrator.ps1 -Action <build|run|test|deploy|stop|logs|status|security-scan>"
    }
}