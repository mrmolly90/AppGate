# Phase 0 Architecture

## Infrastructure Security Baseline

### VPC Design
- Public subnets for NAT gateways and load balancers
- Private subnets for all workloads
- No direct internet access for worker nodes
- VPC endpoints for ECR, S3, CloudWatch, STS
- Security groups with least-privilege rules

### EKS Cluster
- Private worker nodes only
- Control plane endpoint: private + public (restricted)
- Audit logging enabled
- Secrets encryption with KMS
- IRSA for pod identity
- Pod Security Standards enforced

### Cilium Network Policies
- Default-deny for all namespaces
- DNS allowed (kube-dns)
- Control plane → database allowed
- Gateway → control plane allowed
- Gateway → approved LLM endpoints only
- Metrics → Prometheus allowed
- Everything else denied

### Secrets Management
- AWS Secrets Manager or KMS for secrets
- External Secrets Operator for Kubernetes
- No secrets in Git, Helm values, or container images
- Rotation procedures documented

### Observability
- Prometheus for metrics collection
- OpenTelemetry for distributed tracing
- Grafana for dashboards
- Centralized logging with CloudWatch
- Metrics: requests, duration, auth failures, rate limits, errors