.PHONY: all build test lint clean fmt vet security tf

all: build test lint

# Control Plane
build-control-plane:
	cd control-plane && go build -o bin/appgate ./cmd/appgate

test-control-plane:
	cd control-plane && go test ./... -race -count=1

vet-control-plane:
	cd control-plane && go vet ./...

lint-control-plane:
	cd control-plane && golangci-lint run

# Gateway
build-gateway:
	cd gateway && cargo build --release

test-gateway:
	cd gateway && cargo test

clippy-gateway:
	cd gateway && cargo clippy --all-targets --all-features -- -D warnings

audit-gateway:
	cd gateway && cargo audit

# Infrastructure
tf-init:
	cd infra/terraform/environments/dev && terraform init && terraform validate

tf-plan:
	cd infra/terraform/environments/dev && terraform plan

tf-apply:
	cd infra/terraform/environments/dev && terraform apply

tf-security:
	cd infra/terraform && tflint && checkov -d . && tfsec .

# Security
security-scan:
	trivy fs --severity HIGH,CRITICAL .
	gitleaks detect --source .
	semgrep --config=auto --error .

# Observability
otel-collector:
	docker run --rm -v $(PWD)/observability/otel/otel-config.yaml:/etc/otel/config.yaml \
		-p 4317:4317 -p 4318:4318 otel/opentelemetry-collector-contrib:latest

# All
build: build-control-plane build-gateway
test: test-control-plane test-gateway
lint: lint-control-plane clippy-gateway
fmt:
	cd control-plane && go fmt ./...
	cd gateway && cargo fmt --check
vet: vet-control-plane
security: security-scan audit-gateway tf-security