# =============================================================================
# AppGate — CI Fix Runbook
# =============================================================================
# This file contains all commands needed to fix CI failures.
# =============================================================================

## 1. Fix Trivy Scanner Config
```bash
# The trivy.yaml needs proper YAML formatting
cat > security/trivy/trivy.yaml << 'EOF'
severity: [HIGH, CRITICAL]
scanners: [vuln, secret, misconfig]
skip-dirs:
  - .git
  - vendor
  - target
  - node_modules
  - .terraform
timeout: 10m
ignore-unfixed: true
EOF
```

## 2. Fix Helm Lint (missing values.yaml defaults)
```bash
# Ensure all .Values.x references have default values
helm lint deploy/helm/appgate --strict
helm template appgate deploy/helm/appgate --debug > /dev/null
```

## 3. Fix Rust Gateway (toolchain/lockfile/compilation)
```bash
cd gateway
rustup show
cargo generate-lockfile
cargo check --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked
cargo build --release --target x86_64-unknown-linux-musl --locked
```

## 4. Fix Terraform Validation
```bash
cd infra/terraform/environments/dev
terraform fmt -check -recursive ../../../
terraform init -backend=false -input=false
terraform validate -no-color
```

## 5. Fix Go Control Plane
```bash
cd control-plane
go mod tidy
go mod verify
go vet ./...
go test ./... -race -shuffle=on -count=1 -timeout=60s
golangci-lint run --timeout=5m --out-format=colored-line-number
```

## 6. Generate Cargo.lock
```bash
cd gateway
cargo generate-lockfile
```

## 7. Generate go.sum
```bash
cd control-plane
go mod tidy
go mod download
```

## 8. Full CI Fix One-Liner
```bash
# From repo root
cd gateway && cargo generate-lockfile && cargo check && cd .. && \
cd control-plane && go mod tidy && go mod download && go vet ./... && cd .. && \
cd infra/terraform/environments/dev && terraform init -backend=false -input=false && terraform validate -no-color && cd ../../.. && \
helm lint deploy/helm/appgate --strict
```