# AppGate — Enterprise LLM Security Gateway

**AppGate** is a zero-trust security gateway that sits between applications and LLM providers, enforcing authentication, authorization, policy, audit, and rate limiting before any request reaches an upstream LLM.

## Architecture

```
Internet / Client
     │
     ▼
┌─────────────────────────────┐
│     Rust Gateway            │
│  (Data Plane)               │
│  - JWT validation           │
│  - Policy enforcement       │
│  - LLM routing              │
│  - Rate limiting            │
│  - Audit metadata           │
│  - SSRF defense             │
└─────────────┬───────────────┘
              │ Secure control API
              ▼
┌─────────────────────────────┐
│     Go Control Plane        │
│  (Control Plane)            │
│  - Authentication           │
│  - Authorization            │
│  - Policy management        │
│  - Gateway registration     │
│  - Audit events             │
│  - JWT signing              │
└─────────────┬───────────────┘
              │
              ▼
    Kubernetes / EKS
    ┌───────┴───────┐
    │  Cilium       │
    │  Network      │
    │  Security     │
    └───────────────┘
```

## Security Principles

- **Zero Trust**: No implicit trust. Every request is authenticated, authorized, and audited.
- **Least Privilege**: Every component has minimum required permissions.
- **Defense in Depth**: Multiple layers of security controls.
- **Fail Closed**: Security failures deny access by default.
- **Separation of Concerns**: Control plane and data plane are separate.

## Repository Structure

```
appgate/
├── docs/              # Architecture, threat model, security, operations
├── infra/             # Terraform, Cilium configuration
├── control-plane/     # Go control plane service
├── gateway/           # Rust gateway proxy
├── policies/          # Policy schemas and examples
├── deploy/            # Helm, Kustomize, manifests
├── security/          # Security scanning configurations
├── observability/     # Prometheus, Grafana, OpenTelemetry
└── scripts/           # Build and operational scripts
```

## Non-Negotiable Rules

1. No secrets in Git, container images, or logs.
2. No `privileged` containers, `hostNetwork`, `hostPID`, `hostIPC`.
3. No `cluster-admin` RBAC without documented security review.
4. No `0.0.0.0/0` egress without explicit justification.
5. No client-provided security context trusted blindly.
6. No arbitrary user-controlled upstream URLs (SSRF defense).
7. No unbounded upstream requests.
8. No full prompts/responses in default logs.
9. No default service account usage.
10. No database superuser from application code.