# syntax=docker/dockerfile:1
# Multi-stage cross-compilation for linux/amd64 + linux/arm64

FROM --platform=$BUILDPLATFORM rust:1.80-alpine AS builder
WORKDIR /src
RUN apk add --no-cache musl-dev openssl-dev pkgconfig

# Cache dependencies
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release --target x86_64-unknown-linux-musl 2>/dev/null || true
RUN cargo build --release --target aarch64-unknown-linux-musl 2>/dev/null || true

# Build actual source
COPY src ./src
ARG TARGETARCH
RUN case "$TARGETARCH" in \
    amd64) export TARGET=x86_64-unknown-linux-musl ;; \
    arm64) export TARGET=aarch64-unknown-linux-musl ;; \
    *) export TARGET=x86_64-unknown-linux-musl ;; \
    esac && \
    cargo build --release --target $(echo $TARGET) && \
    cp target/$(echo $TARGET)/release/gateway /gateway

# Final stage: distroless nonroot
FROM gcr.io/distroless/static:nonroot
WORKDIR /app
COPY --from=builder /gateway /app/gateway
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app/gateway"]
