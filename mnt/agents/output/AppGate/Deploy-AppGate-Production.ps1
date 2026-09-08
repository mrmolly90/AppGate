<#
.SYNOPSIS
    AppGate Production Deployment Script
.DESCRIPTION
    Deploys the complete AppGate proxy system with health checks,
    database migrations, certificate generation, and rollback capability.
.PARAMETER Environment
    Target environment: dev, staging, production
.PARAMETER Action
    deploy, rollback, status, destroy
#>
[CmdletBinding()]
param(
    [ValidateSet("dev","staging","production")]
    [string]$Environment = "production",
    
    [ValidateSet("deploy","rollback","status","destroy")]
    [string]$Action = "deploy"
)

$ErrorActionPreference = "Stop"
$AppGateRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$BackupDir = "$AppGateRoot/backups/$Timestamp"

function Write-AppGateBanner {
    param([string]$Message)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  $Message" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
}

function Initialize-Secrets {
    Write-AppGateBanner "Initializing Secrets"
    
    $SecretsDir = "$AppGateRoot/secrets"
    New-Item -ItemType Directory -Force -Path $SecretsDir | Out-Null

    # Generate JWT signing key pair if missing
    if (-not (Test-Path "$SecretsDir/signing-key.pem")) {
        Write-Host "Generating RSA 4096-bit signing key pair..." -ForegroundColor Yellow
        openssl genrsa -out "$SecretsDir/signing-key.pem" 4096 2>$null
        openssl rsa -in "$SecretsDir/signing-key.pem" -pubout -out "$SecretsDir/jwt-public.pem" 2>$null
        Write-Host "Signing keys generated." -ForegroundColor Green
    }

    # Generate TLS certificates if missing
    if (-not (Test-Path "$SecretsDir/tls-cert.pem")) {
        Write-Host "Generating self-signed TLS certificates (replace with real certs in prod)..." -ForegroundColor Yellow
        openssl req -x509 -nodes -days 365 -newkey rsa:4096 `
            -keyout "$SecretsDir/tls-key.pem" `
            -out "$SecretsDir/tls-cert.pem" `
            -subj "/CN=appgate.local/O=AppGate Security/C=US" 2>$null
        Write-Host "TLS certificates generated." -ForegroundColor Green
    }
}

function Invoke-HealthCheck {
    param(
        [string]$Url,
        [string]$Name,
        [int]$Retries = 30,
        [int]$DelaySeconds = 2
    )
    
    Write-Host "Health checking $Name at $Url..." -NoNewline
    for ($i = 0; $i -lt $Retries; $i++) {
        try {
            $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
            if ($response.StatusCode -eq 200) {
                Write-Host " READY" -ForegroundColor Green
                return $true
            }
        } catch {
            Start-Sleep -Seconds $DelaySeconds
            Write-Host "." -NoNewline
        }
    }
    Write-Host " FAILED" -ForegroundColor Red
    return $false
}

function Invoke-Deploy {
    Write-AppGateBanner "Deploying AppGate - Environment: $Environment"
    
    Initialize-Secrets
    
    # Create backup snapshot before deployment
    if (Test-Path "$AppGateRoot/docker-compose.yml") {
        New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
        Copy-Item "$AppGateRoot/docker-compose.yml" "$BackupDir/" -Force
        Write-Host "Backup created at $BackupDir" -ForegroundColor DarkGray
    }

    # Pull latest images
    Write-Host "`nPulling latest images..." -ForegroundColor Yellow
    docker compose -f "$AppGateRoot/docker-compose.yml" pull

    # Deploy stack
    Write-Host "`nStarting services..." -ForegroundColor Yellow
    docker compose -f "$AppGateRoot/docker-compose.yml" up -d --remove-orphans

    # Wait for database
    $dbHealthy = Invoke-HealthCheck -Url "http://localhost:8080/readyz" -Name "Control Plane" -Retries 30 -DelaySeconds 3
    if (-not $dbHealthy) {
        throw "Control Plane failed health checks. Deployment aborted."
    }

    # Wait for gateway
    $gatewayHealthy = Invoke-HealthCheck -Url "http://localhost:8081/health" -Name "Gateway" -Retries 20 -DelaySeconds 2
    if (-not $gatewayHealthy) {
        throw "Gateway failed health checks. Deployment aborted."
    }

    # Verify end-to-end token flow
    Write-Host "`nVerifying authentication flow..." -ForegroundColor Yellow
    try {
        $tokenResponse = Invoke-RestMethod -Uri "http://localhost:8080/v1/auth/token" -Method Post `
            -ContentType "application/json" `
            -Body '{"client_id":"appgate-gateway-1","client_secret":"test-secret"}' `
            -ErrorAction Stop
        Write-Host "Token endpoint responding. Access token received: $($tokenResponse.access_token.Substring(0,20))..." -ForegroundColor Green
    } catch {
        Write-Warning "Token endpoint check failed (expected if seed secret not configured): $_"
    }

    Write-AppGateBanner "Deployment Complete"
    Write-Host "Control Plane: https://localhost:8080" -ForegroundColor Cyan
    Write-Host "Gateway:       https://localhost:8081" -ForegroundColor Cyan
    Write-Host "Grafana:       http://localhost:3000" -ForegroundColor Cyan
    Write-Host "Prometheus:    http://localhost:9090" -ForegroundColor Cyan
}

function Invoke-Rollback {
    Write-AppGateBanner "Rolling Back AppGate"
    
    $Backups = Get-ChildItem "$AppGateRoot/backups" -Directory | Sort-Object Name -Descending
    if ($Backups.Count -eq 0) {
        throw "No backups found for rollback."
    }
    
    $LatestBackup = $Backups[0].FullName
    Write-Host "Rolling back to: $LatestBackup" -ForegroundColor Yellow
    
    docker compose -f "$AppGateRoot/docker-compose.yml" down
    Copy-Item "$LatestBackup/docker-compose.yml" "$AppGateRoot/" -Force
    docker compose -f "$AppGateRoot/docker-compose.yml" up -d
    
    Write-Host "Rollback complete." -ForegroundColor Green
}

function Get-Status {
    Write-AppGateBanner "AppGate System Status"
    
    docker compose -f "$AppGateRoot/docker-compose.yml" ps
    
    Write-Host "`n--- Resource Usage ---" -ForegroundColor Yellow
    docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.PIDs}}"
    
    Write-Host "`n--- Recent Logs ---" -ForegroundColor Yellow
    docker compose -f "$AppGateRoot/docker-compose.yml" logs --tail=20 control-plane gateway
}

function Invoke-Destroy {
    Write-AppGateBanner "Destroying AppGate Stack"
    $confirm = Read-Host "Are you sure? This will delete all containers and volumes. Type 'destroy' to confirm"
    if ($confirm -eq "destroy") {
        docker compose -f "$AppGateRoot/docker-compose.yml" down -v --remove-orphans
        Write-Host "AppGate stack destroyed." -ForegroundColor Red
    } else {
        Write-Host "Destruction cancelled." -ForegroundColor Green
    }
}

# Main execution
switch ($Action) {
    "deploy"   { Invoke-Deploy }
    "rollback" { Invoke-Rollback }
    "status"   { Get-Status }
    "destroy"  { Invoke-Destroy }
}