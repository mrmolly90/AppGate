# AppGate Rust Gateway
FROM rust:1.78-alpine AS builder

RUN apk add --no-cache musl-dev
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/target/release/appgate-gateway /appgate-gateway

USER 65534:65534
EXPOSE 8443

ENTRYPOINT ["/appgate-gateway"]