# =============================================================================
# AppGate Gateway — Production Build
# =============================================================================

# ── Builder stage ────────────────────────────────────────────────────────────
FROM rust:1.80-alpine AS builder
RUN apk add --no-cache musl-dev gcc cmake make protoc protobuf-dev
WORKDIR /app
COPY . .
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