# AppGate Go Control Plane — Multi-stage, cross-compiled, distroless, SBOM-ready
# syntax=docker/dockerfile:1

# Stage 1: Cross-compile Go binary
FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS builder

RUN apk add --no-cache git ca-certificates

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=0.0.0
ARG COMMIT=unknown
ARG BUILDTIME

WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true
COPY . .

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildTime=${BUILDTIME}" \
    -o /appgate ./cmd/appgate

# Stage 2: Distroless non-root
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /appgate /appgate

USER 65534:65534
EXPOSE 8443

LABEL org.opencontainers.image.source=https://github.com/mrmolly90/AppGate
LABEL org.opencontainers.image.description="AppGate Go Control Plane — Zero Trust SDP"

ENTRYPOINT ["/appgate"]
ARG BUILDTIME

LABEL org.opencontainers.image.source=https://github.com/mrmolly90/AppGate
LABEL org.opencontainers.image.description="AppGate Go Control Plane"
LABEL org.opencontainers.image.version=${VERSION}
LABEL org.opencontainers.image.revision=${COMMIT}

ENTRYPOINT ["/appgate"]