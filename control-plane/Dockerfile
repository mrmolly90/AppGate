# syntax=docker/dockerfile:1
# =============================================================================
# AppGate Control Plane — Multi-arch Docker Build
# =============================================================================
# Architecture:
#   - Multi-stage: golang:1.23-alpine builder → distroless/static:nonroot
#   - Cross-compilation: NO QEMU emulation, uses --platform=$BUILDPLATFORM
#   - CGO_ENABLED=0 for fully static binary
#   - USER 65532:65532 (nonroot)
# =============================================================================

FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS builder
WORKDIR /src
RUN apk add --no-cache git ca-certificates

# Cache modules
COPY go.mod go.sum ./
RUN go mod download

# Build
COPY . .
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build \
    -ldflags="-s -w -X main.Version=$(git describe --tags --always --dirty 2>/dev/null || echo '0.2.0') -X main.Commit=$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown') -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o /control-plane ./cmd/server

# ── Runtime stage: distroless nonroot ─────────────────────────────
FROM gcr.io/distroless/static:nonroot
WORKDIR /app
COPY --from=builder /control-plane /app/control-plane
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
USER 65532:65532
EXPOSE 8080 9090
ENTRYPOINT ["/app/control-plane"]
