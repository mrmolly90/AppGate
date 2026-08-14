# AppGate Rust Gateway — Multi-stage, musl static, distroless, multi-arch
# syntax=docker/dockerfile:1

# Stage 1: Build musl static binary
FROM --platform=$BUILDPLATFORM rust:1.78-alpine AS builder

RUN apk add --no-cache musl-dev git

ARG TARGETPLATFORM
RUN echo "$TARGETPLATFORM" | sed 's|linux/amd64|x86_64-unknown-linux-musl|; s|linux/arm64|aarch64-unknown-linux-musl|' > /target.txt && \
    cat /target.txt

WORKDIR /app
COPY Cargo.toml ./
RUN if [ -f Cargo.lock ]; then cp Cargo.lock Cargo.lock.bak; fi && \
    cargo generate-lockfile 2>/dev/null || true && \
    mkdir src && echo "fn main() {}" > src/main.rs && \
    cargo build --release --target $(cat /target.txt) 2>/dev/null || true
RUN rm -rf src
COPY Cargo.lock* ./

COPY . .
RUN cargo build --release --target $(cat /target.txt) 2>&1 && \
    cp target/$(cat /target.txt)/release/appgate-gateway /appgate-gateway

# Stage 2: Distroless non-root
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /appgate-gateway /appgate-gateway

USER 65534:65534
EXPOSE 8443

LABEL org.opencontainers.image.source=https://github.com/mrmolly90/AppGate
LABEL org.opencontainers.image.description="AppGate Rust Gateway"

ENTRYPOINT ["/appgate-gateway"]