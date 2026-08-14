# AppGate Platform Recovery Plan

## Current CI Failures (5 jobs)
| Job | Time | Annotations | Root Cause |
|-----|------|-------------|------------|
| Terraform | 2s | — | `terraform init` without backend fails; no path filter triggers on every commit |
| Rust | 2s | — | `Cargo.lock` missing → `--locked` fails; no `cargo generate-lockfile` |
| Go | 1m19s | — | `go test -race` has no tests → slow timeout; no `go mod download` cache |
| Docker | 1m38s | 2 | `scratch` images can't be scanned by Trivy; no `.dockerignore` for gateway |
| Security | 1m20s | 5 | Gitleaks on full history; Trivy finds OS vulns in scratch; Semgrep config errors |

## Recovery Steps

### 1. CI Fixes — Path-Filtered Jobs + Aggressive Caching
- Add `dorny/paths-filter` to only run jobs when their code changes
- Add `actions/cache` for Go module cache, Rust `~/.cargo` and `target/`
- Fix Terraform: use `terraform init -backend=false` with proper provider plugins
- Fix Rust: generate `Cargo.lock` via `cargo generate-lockfile` before `--locked` build
- Fix Go: add `go mod download` caching layer
- Fix Docker: use distroless base images instead of `scratch` for Trivy compatibility

### 2. Supply Chain Hardening
- Generate SPDX SBOM via `syft` after each Docker build
- Sign images with `cosign` using OIDC (keyless signing)
- Upload Trivy SARIF to GitHub Security tab for both images
- Add `scorecard` action for supply-chain health

### 3. Rust Gateway Scaling
- Switch to `rust:1.78-alpine` with `musl-target` for static linking
- Add `--target x86_64-unknown-linux-musl` for fully static binaries
- Multi-arch: build for `linux/amd64` and `linux/arm64` via Docker Buildx
- Wire OpenTelemetry tracing: add `opentelemetry` + `opentelemetry-otlp` back with proper init
- Add `tracing-opentelemetry` for span export

### 4. Go Control Plane Hardening
- Embed version via `-ldflags="-X main.Version=$(git describe) -s -w"`
- Add structured logging with `zerolog` level from env
- Add `go test -race -shuffle=on -count=1` for race-free tests
- Add `golangci-lint` with strict config

### 5. Terraform Multi-Env IaC
- Workspace-based: `terraform workspace select|new <env>`
- S3 backend with DynamoDB locking (already configured)
- Add `conftest` policy-as-code for OPA-style validation
- Add `terraform plan` with JSON output for PR comments

### 6. Helm + Flagger + Falco
- Complete Helm chart with templates for both services
- Add Flagger `Canary` CRD for progressive delivery
- Add Falco `falco-rules.yaml` for runtime security
- Add `PodDisruptionBudget`, `HorizontalPodAutoscaler`, `topologySpreadConstraints`

### 7. SLOs + Dashboards
- Prometheus recording rules for p99 latency, error rate
- Grafana dashboard JSON for AppGate overview
- SLO alerts: `appgate:p99_latency:5m > 50ms`, `appgate:error_rate:5m > 0.001`