# =============================================================================
# AppGate — End-to-End Integration Test (PowerShell)
# =============================================================================
# Tests the AppGate reverse proxy control plane with real HTTP traffic.
# Run after starting the server: .\server.exe
# =============================================================================

$PASSES = 0
$FAILURES = 0
$BASE = "http://localhost:8080"

function Pass($msg) { $script:PASSES++; Write-Host "[PASS] $msg" -ForegroundColor Green }
function Fail($msg) { $script:FAILURES++; Write-Host "[FAIL] $msg" -ForegroundColor Red }
function Info($msg) { Write-Host "[INFO] $msg" -ForegroundColor Yellow }

function Test-Get($path, $expectedSubstring) {
    try {
        $req = [System.Net.WebRequest]::Create("$BASE$path")
        $req.Timeout = 5000
        $resp = $req.GetResponse()
        $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
        $body = $reader.ReadToEnd()
        $reader.Close()
        if ($body -match $expectedSubstring) {
            Pass "$path returns 200 with '$expectedSubstring'"
        } else {
            Fail "$path expected '$expectedSubstring' but got: $($body.Substring(0, [Math]::Min(80, $body.Length)))"
        }
    } catch {
        Fail "$path failed: $_"
    }
}

function Test-Post($path, $jsonBody, $expectedSubstring) {
    try {
        $url = "$BASE$path"
        $req = [System.Net.WebRequest]::Create($url)
        $req.Method = "POST"
        $req.ContentType = "application/json"
        $req.Timeout = 5000
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($jsonBody)
        $req.ContentLength = $bytes.Length
        $stream = $req.GetRequestStream()
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Close()
        $resp = $req.GetResponse()
        $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
        $body = $reader.ReadToEnd()
        $reader.Close()
        if ($body -match $expectedSubstring) {
            Pass "POST $path returns $($resp.StatusCode) with '$expectedSubstring'"
        } else {
            Fail "POST $path expected '$expectedSubstring' but got: $($body.Substring(0, [Math]::Min(80, $body.Length)))"
        }
    } catch {
        Fail "POST $path failed: $_"
    }
}

# ═══════════════════════════════════════════════════════════════════════════
Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "  AppGate Reverse Proxy — Traffic Test Suite" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Target: $BASE`n"

# ── 1. Health & Readiness ────────────────────────────────────────────────
Info "--- Health Endpoints ---"
Test-Get "/healthz" "ok"
Test-Get "/readyz" "ready"

# ── 2. JWKS ──────────────────────────────────────────────────────────────
Info "--- JWKS ---"
Test-Get "/.well-known/jwks.json" "keys"

# ── 3. Auth ──────────────────────────────────────────────────────────────
Info "--- Auth ---"
Test-Post "/v1/auth/token" '{}' "token"
Test-Post "/v1/auth/refresh" '{}' "refreshed"
Test-Post "/v1/auth/revoke" '{}' ""
Test-Get "/v1/auth/introspect" "active"

# ── 4. Policies CRUD ────────────────────────────────────────────────────
Info "--- Policies CRUD ---"
Test-Get "/v1/policies" "policies"
Test-Post "/v1/policies" '{"name":"test","spec":{"subjects":{"roles":["admin"]},"providers":["openai"],"models":["gpt-4"],"limits":{"requests_per_minute":10},"logging":{"metadata_only":true}}}' "created"
Test-Post "/v1/policies/test-1/validate" '{}' "valid"

# ── 5. Gateways ──────────────────────────────────────────────────────────
Info "--- Gateways ---"
Test-Get "/v1/gateways" "gateways"

# ── 6. Audit ─────────────────────────────────────────────────────────────
Info "--- Audit ---"
Test-Get "/v1/audit/events" "events"
Test-Post "/v1/audit/batch" '[{"event_type":"test","event_time":"2026-01-01T00:00:00Z","severity":1,"actor":{"id":"tester","type_":"user","roles":[],"tenant_id":null},"action":{"name":"test","type_":"api"},"resource":{"type_":"test","name":"test","provider":"test","model":"test"},"result":{"status":"allowed","reason":"policy_match","policy_id":"pol-1"},"correlation_id":"corr-1","metadata":{}}]' "ingested"

# ── 7. Export ────────────────────────────────────────────────────────────
Info "--- Export ---"
Test-Post "/v1/audit/events/export" '{}' "exported_at"

# ═══════════════════════════════════════════════════════════════════════════
Write-Host "`n═══════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Results: $PASSES passed, $FAILURES failed" -ForegroundColor $(if ($FAILURES -eq 0) { "Green" } else { "Red" })
Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan

if ($FAILURES -gt 0) { exit 1 } else { exit 0 }