# syntax=docker/dockerfile:1
# AppGate Gateway — Production Build with Dependency Caching via cargo-chef

# ------------------------------------------------------------------
# STAGE 1: Chef base image
# ------------------------------------------------------------------
FROM rust:alpine AS chef
RUN apk add --no-cache musl-dev gcc cmake make perl && \
    ln -sf /usr/bin/gcc /usr/bin/x86_64-linux-musl-gcc
RUN cargo install cargo-chef
WORKDIR /app

# ------------------------------------------------------------------
# STAGE 2: Planner — generate dependency recipe from Cargo.toml/lock
# ------------------------------------------------------------------
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ------------------------------------------------------------------
# STAGE 3: Builder — compile dependencies ONCE, cache the layer
# ------------------------------------------------------------------
FROM chef AS builder
WORKDIR /app
# Copy ONLY the recipe. This layer is cached unless Cargo.toml/lock changes.
COPY --from=planner /app/recipe.json recipe.json
# Build deps. Registry cache mount survives between builds.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo chef cook --release --recipe-path recipe.json
# NOW copy full source. Only YOUR code recompiles here.
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build --release

# ------------------------------------------------------------------
# STAGE 4: Runtime — hardened, minimal, non-root
# ------------------------------------------------------------------
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tini && \
    addgroup -g 1000 appgate && \
    adduser -u 1000 -G appgate -s /sbin/nologin -D appgate && \
    mkdir -p /etc/appgate/tls /etc/appgate/jwt && \
    chown -R appgate:appgate /etc/appgate
COPY --from=builder /app/target/release/appgate-gateway /usr/local/bin/appgate-gateway
USER appgate
EXPOSE 8443
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/usr/local/bin/appgate-gateway"]
