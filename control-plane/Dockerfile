# AppGate Go Control Plane — Multi-stage, distroless, SBOM-ready
# syntax=docker/dockerfile:1

FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates
WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true
COPY . .

ARG VERSION=0.0.0
ARG COMMIT=unknown
ARG BUILDTIME

RUN CGO_ENABLED=0 go build \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildTime=${BUILDTIME}" \
    -o /appgate ./cmd/appgate

# Distroless non-root base for Trivy compatibility
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /appgate /appgate

USER 65534:65534
EXPOSE 8443

ARG VERSION=0.0.0
ARG COMMIT=unknown
ARG BUILDTIME

LABEL org.opencontainers.image.source=https://github.com/mrmolly90/AppGate
LABEL org.opencontainers.image.description="AppGate Go Control Plane"
LABEL org.opencontainers.image.version=${VERSION}
LABEL org.opencontainers.image.revision=${COMMIT}

ENTRYPOINT ["/appgate"]