# syntax=docker/dockerfile:1
# =============================================================================
# AppGate Gateway — Multi-arch Docker Build
# =============================================================================
# Architecture:
#   - Multi-stage: builder → distroless nonroot
#   - Cross-compilation: NO QEMU emulation, uses --platform=$BUILDPLATFORM
#   - rustls (no OpenSSL), musl target for fully static binary
#   - USER 65532:65532 (nonroot)
# =============================================================================

FROM --platform=$BUILDPLATFORM rust:1.97-alpine AS builder
WORKDIR /src

# Install musl cross-compilation tools (no openssl-dev needed — using rustls)
RUN apk add --no-cache musl-dev

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY .cargo ./.cargo

# Create dummy main.rs for dependency caching
RUN mkdir -p src && echo "fn main() {}" > src/main.rs

# Build dependencies only (cached layer)
RUN cargo build --release --target x86_64-unknown-linux-musl 2>/dev/null || true

# Copy actual source
COPY src ./src

# Cross-compile for target architecture
ARG TARGETARCH
RUN case "$TARGETARCH" in \
    amd64) export TARGET=x86_64-unknown-linux-musl ;; \
    arm64) export TARGET=aarch64-unknown-linux-musl ;; \
    *) export TARGET=x86_64-unknown-linux-musl ;; \
    esac && \
    cargo build --release --target "$TARGET" --locked && \
    cp "target/$TARGET/release/appgate-gateway" /gateway

# ── Runtime stage: distroless nonroot ─────────────────────────────
FROM gcr.io/distroless/static:nonroot
WORKDIR /app
COPY --from=builder /gateway /app/gateway
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/app/gateway"]
ENTRYPOINT ["/app/gateway"]
