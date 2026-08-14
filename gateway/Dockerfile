# AppGate Rust Gateway — Multi-stage, musl static, cross-compiled, distroless, multi-arch
# Uses cross-compilation (NOT QEMU emulation) for speed
# syntax=docker/dockerfile:1

# Stage 1: Cross-compile musl static binary
FROM --platform=$BUILDPLATFORM rust:1.80-alpine AS builder

RUN apk add --no-cache musl-dev git clang lld

ARG TARGETPLATFORM
ARG BUILDPLATFORM

# Map TARGETPLATFORM to Rust target triple
RUN echo "$TARGETPLATFORM" | sed 's|linux/amd64|x86_64-unknown-linux-musl|; s|linux/arm64|aarch64-unknown-linux-musl|' > /target.txt
RUN cat /target.txt

# Install cross-compilation linker based on target
RUN case "$TARGETPLATFORM" in \
    linux/amd64) apk add --no-cache musl-dev ;; \
    linux/arm64) apk add --no-cache aarch64-none-elf-binutils ;; \
    esac

WORKDIR /app

# Cache dependencies first (layer caching)
COPY Cargo.toml Cargo.lock* ./
RUN mkdir -p src && echo "fn main() {}" > src/main.rs && \
    cargo build --release --target "$(cat /target.txt)" 2>/dev/null || true
RUN rm -rf src

# Full build
COPY . .
RUN cargo build --release --target "$(cat /target.txt)" && \
    cp "target/$(cat /target.txt)/release/appgate-gateway" /appgate-gateway

# Stage 2: Minimal distroless image
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /appgate-gateway /appgate-gateway

USER 65534:65534
EXPOSE 8443

LABEL org.opencontainers.image.source=https://github.com/mrmolly90/AppGate
LABEL org.opencontainers.image.description="AppGate Rust Gateway — Zero Trust SDP Gateway"

ENTRYPOINT ["/appgate-gateway"]