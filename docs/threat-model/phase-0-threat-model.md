# Phase 0 Threat Model

## Assets
1. JWT signing keys
2. Database credentials
3. Policy configurations
4. Audit logs
5. LLM API keys
6. Kubernetes API server access

## Trust Boundaries
1. **Internet ↔ Gateway**: Untrusted → Trusted
2. **Gateway ↔ Control Plane**: Trusted internal (mutual TLS)
3. **Control Plane ↔ Database**: Trusted internal
4. **Admin ↔ Control Plane**: Authenticated, authorized

## Threats

### T1: Unauthorized Access to LLM
- **Risk**: Attacker sends requests without valid JWT
- **Mitigation**: JWT validation with signature, issuer, audience, expiration checks
- **Severity**: Critical

### T2: JWT Forgery
- **Risk**: Attacker forges a JWT to impersonate another identity
- **Mitigation**: Asymmetric signing (RS256/ES256), algorithm allowlist, no algorithm confusion
- **Severity**: Critical

### T3: SSRF via Gateway
- **Risk**: Attacker provides arbitrary upstream URL
- **Mitigation**: Explicit provider allowlist, reject private IPs, DNS rebinding protection
- **Severity**: Critical

### T4: Secrets Exposure
- **Risk**: Secrets leaked in logs, Git, or container images
- **Mitigation**: Secrets externalized, git-secrets scanning, no sensitive data in logs
- **Severity**: High

### T5: Privilege Escalation via Kubernetes
- **Risk**: Compromised pod escalates to cluster-admin
- **Mitigation**: Minimal RBAC, no privileged containers, Pod Security Standards
- **Severity**: High

### T6: Audit Tampering
- **Risk**: Attacker modifies or deletes audit logs
- **Mitigation**: Append-only audit storage, cryptographic verification, separate audit cluster
- **Severity**: High

### T7: Denial of Service
- **Risk**: Attacker overwhelms gateway with requests
- **Mitigation**: Rate limiting, connection pooling, timeouts, circuit breakers
- **Severity**: Medium

### T8: Control Plane Compromise
- **Risk**: Attacker gains access to control plane API
- **Mitigation**: Separate admin API, mTLS, short-lived tokens, audit logging
- **Severity**: Critical