FROM golang:1.25-bookworm AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.Version=$(git describe --tags --always --dirty 2>/dev/null || echo dev) -X main.Commit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown) -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)" -a -installsuffix cgo -o bin/appgate ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=builder /app/bin/appgate /control-plane
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
EXPOSE 8080 9090 9091
USER nonroot:nonroot
ENTRYPOINT ["/control-plane"]