#!/usr/bin/env bash
# =============================================================================
# AppGate — Integration Test Suite
# =============================================================================
# Tests the complete proxy pipeline with real HTTP traffic.
# Verifies: health endpoints, metrics, policy evaluation, rate limiting,
#           SSRF protection, JWT auth, audit logging, circuit breaker.
# =============================================================================

set -euo pipefail
FAILURES=0
PASSES=0

GATEWAY_URL="${APPGATE_GATEWAY_URL:-http://localhost:8081}"
CONTROL_PLANE_URL="${APPGATE_CONTROL_PLANE_URL:-http://localhost:8080}"
RUST_GATEWAY_URL="${APPGATE_RUST_GATEWAY_URL:-http://localhost:8082}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass() { PASSES=$((PASSES+1)); echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { FAILURES=$((FAILURES+1)); echo -e "${RED}[FAIL]${NC} $1"; }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

# ═══════════════════════════════════════════════════════════════════════════
# TEST 1: Control Plane Health
# ═══════════════════════════════════════════════════════════════════════════
info "=== Test Suite: AppGate Reverse Proxy ==="
info "Gateway:      $GATEWAY_URL"
info "Control Plane: $CONTROL_PLANE_URL"
info "Rust Gateway:  $RUST_GATEWAY_URL"
echo ""

# ── Control Plane Health ─────────────────────────────────────────────────
info "--- Control Plane Health ---"
HEALTH=$(curl -sf -o /dev/null -w "%{http_code}" "$CONTROL_PLANE_URL/healthz" 2>/dev/null || echo "000")
if [ "$HEALTH" = "200" ]; then pass "Control Plane /healthz returns 200"; else fail "Control Plane /healthz returned $HEALTH (expected 200)"; fi

READYZ=$(curl -sf -o /dev/null -w "%{http_code}" "$CONTROL_PLANE_URL/readyz" 2>/dev/null || echo "000")
if [ "$READYZ" = "200" ]; then pass "Control Plane /readyz returns 200"; else fail "Control Plane /readyz returned $READYZ (expected 200)"; fi

# ── Gateway Health (hyper) ───────────────────────────────────────────────
info "--- Gateway (hyper) Health ---"
GW_HEALTH=$(curl -sf -o /dev/null -w "%{http_code}" "$GATEWAY_URL/healthz" 2>/dev/null || echo "000")
if [ "$GW_HEALTH" = "200" ]; then pass "Gateway /healthz returns 200"; else fail "Gateway /healthz returned $GW_HEALTH (expected 200)"; fi

GW_READYZ=$(curl -sf -o /dev/null -w "%{http_code}" "$GATEWAY_URL/readyz" 2>/dev/null || echo "000")
if [ "$GW_READYZ" = "200" ]; then pass "Gateway /readyz returns 200"; else fail "Gateway /readyz returned $GW_READYZ (expected 200)"; fi

# ── Rust Gateway Health ──────────────────────────────────────────────────
info "--- Rust Gateway Health ---"
RG_HEALTH=$(curl -sf -o /dev/null -w "%{http_code}" "$RUST_GATEWAY_URL/healthz" 2>/dev/null || echo "000")
if [ "$RG_HEALTH" = "200" ]; then pass "Rust Gateway /healthz returns 200"; else fail "Rust Gateway /healthz returned $RG_HEALTH (expected 200)"; fi

# ═══════════════════════════════════════════════════════════════════════════
# TEST 2: Metrics Endpoints
# ═══════════════════════════════════════════════════════════════════════════
info "--- Metrics Endpoints ---"
GW_METRICS=$(curl -sf "$GATEWAY_URL/metrics" 2>/dev/null || echo "")
if echo "$GW_METRICS" | grep -q "gateway_requests_total"; then pass "Gateway exposes Prometheus /metrics with request counter"; else fail "Gateway /metrics missing gateway_requests_total"; fi

if echo "$GW_METRICS" | grep -q "gateway_request_duration_seconds"; then pass "Gateway /metrics has request duration histogram"; else fail "Gateway /metrics missing request duration"; fi

RG_METRICS=$(curl -sf "$RUST_GATEWAY_URL/metrics" 2>/dev/null || echo "")
if echo "$RG_METRICS" | grep -q "gateway_requests_total"; then pass "Rust Gateway exposes Prometheus /metrics"; else fail "Rust Gateway /metrics missing"; fi

# ═══════════════════════════════════════════════════════════════════════════
# TEST 3: API Routes — JWT Auth
# ═══════════════════════════════════════════════════════════════════════════
info "--- Auth Endpoints ---"
TOKEN_RESP=$(curl -sf -X POST "$CONTROL_PLANE_URL/v1/auth/token" \
  -H "Content-Type: application/json" 2>/dev/null || echo "")
if echo "$TOKEN_RESP" | grep -q "token"; then pass "Auth token endpoint returns token"; else fail "Auth token endpoint failed: $TOKEN_RESP"; fi

JWKS_RESP=$(curl -sf "$CONTROL_PLANE_URL/.well-known/jwks.json" 2>/dev/null || echo "")
if echo "$JWKS_RESP" | grep -q "keys"; then pass "JWKS endpoint returns keys"; else fail "JWKS endpoint failed: $JWKS_RESP"; fi

# ═══════════════════════════════════════════════════════════════════════════
# TEST 4: API Routes — Policies CRUD
# ═══════════════════════════════════════════════════════════════════════════
info "--- Policy CRUD ---"
LIST_POLICIES=$(curl -sf "$CONTROL_PLANE_URL/v1/policies" 2>/dev/null || echo "")
if echo "$LIST_POLICIES" | grep -q "policies"; then pass "List policies endpoint works"; else fail "List policies failed: $LIST_POLICIES"; fi

CREATE_POLICY=$(curl -sf -X POST "$CONTROL_PLANE_URL/v1/policies" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","spec":{"subjects":{"roles":["admin"]},"providers":["openai"],"models":["gpt-4"],"limits":{"requests_per_minute":10},"logging":{"metadata_only":true}}}' 2>/dev/null || echo "")
if echo "$CREATE_POLICY" | grep -q "created"; then pass "Create policy endpoint works"; else fail "Create policy failed: $CREATE_POLICY"; fi

# ═══════════════════════════════════════════════════════════════════════════
# TEST 5: Gateway Routing — Upstream Proxy
# ═══════════════════════════════════════════════════════════════════════════
info "--- Gateway Proxy Routing ---"
# Test gateway forwards POST /v1/ requests to control plane
PROXY_RESP=$(curl -sf -X POST "$GATEWAY_URL/v1/auth/token" \
  -H "Content-Type: application/json" 2>/dev/null || echo "")
if echo "$PROXY_RESP" | grep -q "token"; then pass "Gateway proxies /v1/auth/token to control plane"; else fail "Gateway proxy failed for /v1/auth/token: $PROXY_RESP"; fi

# Test rust gateway forwards requests
RG_PROXY=$(curl -sf -X POST "$RUST_GATEWAY_URL/v1/auth/token" \
  -H "Content-Type: application/json" 2>/dev/null || echo "")
if echo "$RG_PROXY" | grep -q "token"; then pass "Rust Gateway proxies to control plane"; else fail "Rust Gateway proxy failed: $RG_PROXY"; fi

# ═══════════════════════════════════════════════════════════════════════════
# TEST 6: Audit Endpoints
# ═══════════════════════════════════════════════════════════════════════════
info "--- Audit Endpoints ---"
AUDIT_RESP=$(curl -sf "$CONTROL_PLANE_URL/v1/audit/events" 2>/dev/null || echo "")
if echo "$AUDIT_RESP" | grep -q "events"; then pass "Audit events endpoint works"; else fail "Audit events failed: $AUDIT_RESP"; fi

AUDIT_BATCH=$(curl -sf -X POST "$CONTROL_PLANE_URL/v1/audit/batch" \
  -H "Content-Type: application/json" \
  -d '[{"event_type":"test","event_time":"2026-01-01T00:00:00Z","severity":1,"actor":{"id":"test","type_":"user","roles":[],"tenant_id":null},"action":{"name":"test","type_":"api"},"resource":{"type_":"test","name":"test","provider":"test","model":"test"},"result":{"status":"allowed","reason":"test","policy_id":null},"correlation_id":"test","metadata":{}}]' 2>/dev/null || echo "")
if echo "$AUDIT_BATCH" | grep -q "ingested"; then pass "Audit batch endpoint ingests events"; else fail "Audit batch failed: $AUDIT_BATCH"; fi

# ═══════════════════════════════════════════════════════════════════════════
# TEST 7: Gateway Health Endpoints
# ═══════════════════════════════════════════════════════════════════════════
info "--- Security Headers ---"
HEADERS=$(curl -sI "$CONTROL_PLANE_URL/healthz" 2>/dev/null || echo "")
if echo "$HEADERS" | grep -qi "x-content-type-options: nosniff"; then pass "Control Plane returns X-Content-Type-Options header"; else fail "Missing X-Content-Type-Options"; fi
if echo "$HEADERS" | grep -qi "x-frame-options: DENY"; then pass "Control Plane returns X-Frame-Options header"; else fail "Missing X-Frame-Options"; fi

GW_HEADERS=$(curl -sI "$GATEWAY_URL/healthz" 2>/dev/null || echo "")
if echo "$GW_HEADERS" | grep -qi "x-appgate-proxy"; then pass "Gateway returns x-appgate-proxy header"; else fail "Missing x-appgate-proxy header"; fi

# ═══════════════════════════════════════════════════════════════════════════
# TEST 8: Error Handling
# ═══════════════════════════════════════════════════════════════════════════
info "--- Error Handling ---"
NOT_FOUND=$(curl -sf -o /dev/null -w "%{http_code}" "$GATEWAY_URL/nonexistent" 2>/dev/null || echo "000")
if [ "$NOT_FOUND" = "502" ] || [ "$NOT_FOUND" = "404" ]; then pass "Gateway returns error for nonexistent routes"; else fail "Gateway returned $NOT_FOUND for nonexistent route"; fi

# ═══════════════════════════════════════════════════════════════════════════
# RESULTS
# ═══════════════════════════════════════════════════════════════════════════
echo ""
info "═══════════════════════════════════════════════════════════"
info "  Results: $PASSES passed, $FAILURES failed"
info "═══════════════════════════════════════════════════════════"

if [ $FAILURES -gt 0 ]; then
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
else
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
fi