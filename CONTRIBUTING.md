# =============================================================================
# AppGate — Contributing Guide
# =============================================================================

## Development Environment Setup

### Prerequisites
- Rust 1.80.0 (rustup)
- Go 1.23
- Docker with Buildx
- Terraform 1.7+
- Helm 3.14+
- kubectl

### Quick Start
```bash
# Clone the repo
git clone https://github.com/mrmolly90/AppGate.git
cd AppGate

# Install Rust toolchain
rustup toolchain install 1.80.0
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl

# Run all checks
make ci
```

### Docker Compose (local development)
```bash
docker compose up -d
# Gateway: http://localhost:8443
# Control Plane: http://localhost:8080
# etcd: http://localhost:2379
```

## Testing Requirements

- All Rust code: `cargo test --locked`
- All Go code: `go test ./... -race -count=1`
- Integration tests: `make go-test-integration`
- Benchmarks: `cargo bench`

## Commit Conventions

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add JWT validation
fix: correct SSRF IP range check
chore: update dependencies
docs: add architecture diagram
ci: fix Docker build caching
security: add certificate pinning
perf: optimize hot path allocation
```

## PR Checklist

- [ ] `make ci` passes locally
- [ ] Tests added for new functionality
- [ ] Documentation updated
- [ ] No secrets in code
- [ ] All containers use nonroot user
- [ ] All Terraform resources have tags
- [ ] Helm chart passes `helm lint --strict`