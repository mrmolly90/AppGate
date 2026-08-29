# Architecture Overview

## System Context

AppGate is deployed as a Kubernetes-native security gateway. The control plane manages policies and authentication; the data plane (Rust gateway) enforces them at request time.

## Components

### Go Control Plane
- **Purpose**: Authentication, authorization, policy management, audit, gateway registration
- **Language**: Go 1.22+
- **Deployment**: Kubernetes Deployment with 2+ replicas
- **Storage**: PostgreSQL for persistent state
- **API**: gRPC + HTTP/JSON for external admin access

### Rust Gateway
- **Purpose**: High-performance request-level security enforcement
- **Language**: Rust 2024 edition
- **Deployment**: Kubernetes DaemonSet or Deployment with horizontal scaling
- **State**: Stateless; configuration pulled from control plane

### Cilium
- **Purpose**: Kubernetes networking and network security enforcement
- **Mode**: Default-deny with explicit allow policies
- **Features**: NetworkPolicies, Hubble observability

## Data Flow

1. Client sends request with JWT to Rust Gateway
2. Gateway validates JWT signature, issuer, audience, expiration
3. Gateway extracts identity and requests policy decision from control plane (cached)
4. Policy is evaluated: is this identity allowed to access this model/provider?
5. Rate limits are checked
6. Request is routed to the approved LLM provider
7. Response is returned to client
8. Audit event is recorded

## Trust Boundaries

```
[Untrusted Client] → [Rust Gateway] → [Trusted Upstream LLM]
                         ↑
              [Go Control Plane]
              (Trusted Internal)
```

The gateway is the trust boundary. Client-provided security context is never trusted directly.