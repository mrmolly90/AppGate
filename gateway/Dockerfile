# syntax=docker/dockerfile:1
# =============================================================================
# AppGate Gateway — Multi-stage Production Build
# =============================================================================

# ── Chef stage: dependency caching ───────────────────────────────────────────
FROM rust:alpine AS chef
RUN apk add --no-cache musl-dev gcc cmake make perl protoc protobuf-dev && \
    ln -sf /usr/bin/gcc /usr/bin/x86_64-linux-musl-gcc
ENV PATH="/usr/local/cargo/bin:${PATH}"
RUN cargo install cargo-chef
WORKDIR /app

# ── Planner stage: generate recipe.json ──────────────────────────────────────
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── Builder stage: compile release binary ────────────────────────────────────
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build --release --locked

# ── Runtime stage: minimal attack surface ────────────────────────────────────
FROM alpine:3.20 AS runtime
RUN apk add --no-cache ca-certificates tini curl && \
    addgroup -g 1000 appgate && \
    adduser -u 1000 -G appgate -s /sbin/nologin -D appgate

COPY --from=builder /app/target/release/appgate-gateway /usr/local/bin/appgate-gateway

USER appgate
EXPOSE 8080 9090

# tini handles PID 1 responsibilities and signal forwarding
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/usr/local/bin/appgate-gateway"]