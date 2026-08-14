.PHONY: all build test lint clean fmt vet security tf docker help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

# ── Control Plane (Go) ────────────────────────────────────────────
go-build: ## Build Go control plane binary
	cd control-plane && CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=$(shell git describe --tags --always --dirty) -X main.Commit=$(shell git rev-parse --short HEAD) -X main.BuildTime=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)" -o bin/appgate ./cmd/appgate

go-test: ## Run Go unit tests
	cd control-plane && go test ./... -race -shuffle=on -count=1 -timeout=60s -tags=unit

go-test-integration: ## Run Go integration tests
	cd control-plane && go test ./... -race -count=1 -timeout=300s -tags=integration

go-lint: ## Run Go linters
	cd control-plane && golangci-lint run --timeout=5m --out-format=colored-line-number

go-vet: ## Run Go vet
	cd control-plane && go vet ./...

go-mod: ## Tidy and verify Go modules
	cd control-plane && go mod tidy && go mod verify

go-all: go-mod go-vet go-lint go-test go-build ## Run all Go checks

# ── Gateway (Rust) ────────────────────────────────────────────────
rust-check: ## Run Rust fmt, clippy, and test
	cd gateway && cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test

rust-build: ## Build Rust gateway binary (musl, release)
	cd gateway && cargo build --release --target x86_64-unknown-linux-musl --locked

rust-test: ## Run Rust tests
	cd gateway && cargo test --locked

rust-fmt: ## Format Rust code
	cd gateway && cargo fmt

rust-clippy: ## Run Rust clippy
	cd gateway && cargo clippy --all-targets --all-features -- -D warnings

rust-audit: ## Audit Rust dependencies for vulnerabilities
	cd gateway && cargo audit

rust-all: rust-fmt rust-clippy rust-test rust-audit rust-build ## Run all Rust checks

# ── Docker ────────────────────────────────────────────────────────
docker-control-plane: ## Build control-plane Docker image
	docker buildx build --platform=linux/amd64,linux/arm64 \
		--cache-from type=gha,scope=control-plane \
		--cache-to type=gha,mode=max,scope=control-plane \
		-t ghcr.io/mrmolly90/appgate-control-plane:latest \
		-f control-plane/Dockerfile control-plane

docker-gateway: ## Build gateway Docker image
	docker buildx build --platform=linux/amd64,linux/arm64 \
		--cache-from type=gha,scope=gateway \
		--cache-to type=gha,mode=max,scope=gateway \
		-t ghcr.io/mrmolly90/appgate-gateway:latest \
		-f gateway/Dockerfile gateway

docker-all: docker-control-plane docker-gateway ## Build all Docker images

# ── Terraform ─────────────────────────────────────────────────────
tf-init: ## Initialize Terraform for all environments
	cd infra/terraform/environments/dev && terraform init -backend=false -input=false
	cd infra/terraform/environments/staging && terraform init -backend=false -input=false
	cd infra/terraform/environments/production && terraform init -backend=false -input=false

tf-validate: ## Validate Terraform for all environments
	cd infra/terraform/environments/dev && terraform validate -no-color
	cd infra/terraform/environments/staging && terraform validate -no-color
	cd infra/terraform/environments/production && terraform validate -no-color

tf-fmt: ## Format Terraform code
	terraform fmt -recursive infra/terraform/

tf-plan: ## Plan Terraform for dev
	cd infra/terraform/environments/dev && terraform plan -no-color

tf-all: tf-fmt tf-init tf-validate ## Run all Terraform checks

# ── Helm ──────────────────────────────────────────────────────────
helm-lint: ## Lint Helm chart
	helm lint deploy/helm/appgate --strict

helm-template: ## Render Helm templates
	helm template appgate deploy/helm/appgate --debug > /dev/null

helm-all: helm-lint helm-template ## Run all Helm checks

# ── Security ──────────────────────────────────────────────────────
trivy-fs: ## Scan filesystem with Trivy
	trivy fs --config security/trivy/trivy.yaml --ignorefile security/trivy/trivyignore .

gitleaks: ## Scan for secrets with Gitleaks
	gitleaks detect --source . --verbose

semgrep: ## Run Semgrep
	semgrep --config=auto --error .

security-all: trivy-fs gitleaks semgrep ## Run all security scans

# ── All ───────────────────────────────────────────────────────────
build: go-build rust-build ## Build all binaries
test: go-test rust-test ## Run all tests
lint: go-lint rust-clippy ## Run all linters
fmt: go-vet rust-fmt ## Format all code
security: security-all ## Run all security scans
ci: go-all rust-all helm-all tf-all ## Run full CI (no Docker — use CI runner)
all: build test lint security ## Build, test, lint, scan