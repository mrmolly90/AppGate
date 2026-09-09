# syntax=docker/dockerfile:1
# =============================================================================
# AppGate Rust Gateway — Production Build (appgate-gateway v0.2.0)
# =============================================================================

# ── Builder stage ────────────────────────────────────────────────────────────
FROM rust:1.80-alpine AS builder
RUN apk add --no-cache musl-dev gcc cmake make protoc protobuf-dev
WORKDIR /app
COPY rust-gateway/Cargo.toml rust-gateway/Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release --locked 2>/dev/null || true
COPY rust-gateway/ ./
RUN touch src/main.rs
RUN cargo build --release --locked

# ── Runtime stage ────────────────────────────────────────────────────────────
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tini curl && \
    addgroup -g 1000 appgate && \
    adduser -u 1000 -G appgate -s /sbin/nologin -D appgate
COPY --from=builder /app/target/release/appgate-gateway /usr/local/bin/appgate-gateway
USER appgate
EXPOSE 8080 9090
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/usr/local/bin/appgate-gateway"]