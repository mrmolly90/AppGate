# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 2.x     | ✅ Active development |
| 1.x     | ✅ Security patches only |

## Reporting a Vulnerability

**DO NOT** file public GitHub issues for security vulnerabilities.

Contact the security team immediately:
- **Email**: security@appgate.io
- **PGP Key**: Available at https://appgate.io/security-pgp
- **Response SLA**: Acknowledgment within 24 hours, fix within 7 days for critical issues

### What to Include
- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact
- Any suggested fix (if available)

## Security Requirements

All contributions must comply with:
1. **Zero Trust Architecture**: No implicit trust. Every request must be authenticated, authorized, and encrypted.
2. **Least Privilege Principle**: All components run as nonroot (UID 65532:65532). No inline IAM policies.
3. **Defense in Depth**: Network policies (default-deny), WAF, rate limiting, SSRF protection, mTLS.
4. **Fail Closed**: Policy engine denies by default. SSRF protection blocks by default.
5. **Secure Defaults**: TLS 1.3 only, rustls (no OpenSSL), distroless containers.
6. **Explicit Authorization**: All access requires JWT validation + policy evaluation.
7. **Short-lived Credentials**: JWT TTL < 1 hour. Certificate renewal every 15 days.
8. **Strong Service Identity**: mTLS between all services. SPIFFE-compatible identity.
9. **Immutable Infrastructure**: No runtime patches. Rebuild and redeploy.
10. **No Secrets in Git**: All secrets via external secret management (AWS Secrets Manager, K8s Secrets).

## Supply Chain Security

- All GitHub Actions pinned to SHA commits (SLSA Level 3)
- Cosign keyless signing for all container images
- SBOM generation with Syft (SPDX format)
- Dependency review blocks CVEs with severity HIGH+
- Trivy scans for vulnerabilities, secrets, and misconfigurations
- OpenSSF Scorecard published weekly

## Compliance

AppGate is designed for FedRAMP High, SOC 2 Type II, and ISO 27001 compliance:
- FIPS 140-2/3 validated cryptography (via rustls/ring)
- Audit logging for all security events
- RBAC with separation of duties
- Data encryption at rest (KMS) and in transit (TLS 1.3)
- Incident response plan documented in runbooks