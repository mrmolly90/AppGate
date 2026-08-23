# =============================================================================
# AppGate — Architecture Document
# =============================================================================

## System Overview

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Clients    │────▶│    Gateway   │────▶│ Control Plane│
│  (HTTPS/mTLS)│     │  (Rust/tokio)│     │   (Go/etcd)  │
└──────────────┘     └──────┬───────┘     └──────┬────────┘
                           │                     │
                           ▼                     ▼
                    ┌──────────────┐     ┌──────────────┐
                    │   Upstream   │     │     etcd     │
                    │ LLM Providers│     │  (Config DB) │
                    └──────────────┘     └──────────────┘
```

## Data Flow

1. **Client → Gateway**: TLS 1.3 connection with mTLS client certificate
2. **Gateway → JWT Validation**: Extracts and validates JWT from Authorization header
3. **Gateway → Rate Limiter**: GCRA token bucket per identity
4. **Gateway → Policy Engine**: Evaluates access policies from control plane
5. **Gateway → SSRF Defense**: Validates upstream URL against allowlist
6. **Gateway → Upstream**: Forwards request to LLM provider
7. **Gateway → Control Plane**: Sends audit event asynchronously

## Technology Choices

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Gateway | Rust (tokio + hyper) | Zero-cost abstractions, memory safety, 1M+ connections |
| Control Plane | Go (gorilla/mux + etcd) | Fast compilation, excellent concurrency, K8s ecosystem |
| TLS | rustls (ring) | Memory-safe, no OpenSSL, TLS 1.3 only |
| Config Store | etcd | Distributed, consistent, watch patterns |
| Metrics | Prometheus | Industry standard, HPA integration |
| Tracing | OpenTelemetry | Vendor-neutral, Tempo backend |
| Logs | Loki | Cost-effective log aggregation |
| IaC | Terraform | Multi-cloud, state management |
| K8s | Helm + Kustomize | Declarative, environment-specific |

## Scaling Strategy

- **Horizontal Pod Autoscaling**: CPU (70%) + custom metric (gateway_connections_active)
- **Cluster Autoscaling**: Karpenter for EKS node scaling
- **Multi-Region**: Active-active for production, RPO 5min / RTO 15min
- **Connection Pooling**: deadpool for upstream connections

## Disaster Recovery

- **RPO**: 5 minutes (etcd snapshots every 5min)
- **RTO**: 15 minutes (automated failover)
- **Backup**: etcd backup to S3 every hour
- **Restore**: Automated restore procedure in runbook