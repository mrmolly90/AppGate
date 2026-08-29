# =============================================================================
# AppGate Control Plane — Simplified Docker Build
# =============================================================================

FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS builder
WORKDIR /src
RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG TARGETARCH
ENV CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64}
RUN go build -ldflags="-s -w -X main.Version=0.3.1 -X main.Commit=release -X main.BuildTime=2026-08-29" -o /control-plane ./cmd/server

FROM gcr.io/distroless/static:nonroot
WORKDIR /app
COPY --from=builder /control-plane /app/control-plane
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
USER 65532:65532
EXPOSE 8080 9090
ENTRYPOINT ["/app/control-plane"]
