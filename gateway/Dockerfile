# syntax=docker/dockerfile:1
# =============================================================================
# AppGate Gateway — Multi-arch Docker Build (Production)
# =============================================================================

FROM --platform=$BUILDPLATFORM rust:1.80-alpine AS builder
WORKDIR /src

RUN apk add --no-cache musl-dev

COPY Cargo.toml Cargo.lock ./
COPY .cargo ./.cargo

RUN mkdir -p src && echo "fn main() {}" > src/main.rs
RUN cargo build --release --target x86_64-unknown-linux-musl 2>/dev/null || true

COPY src ./src

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

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/app/gateway", "--health-check"] || exit 1

ENTRYPOINT ["/app/gateway"]