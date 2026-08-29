# Phase 0 Runbook

## Prerequisites
- AWS CLI configured with appropriate permissions
- Terraform 1.7+
- kubectl
- Helm 3.0+
- Cilium CLI

## Deployment

### 1. Terraform
```bash
cd infra/terraform/environments/dev
terraform init
terraform plan
terraform apply
```

### 2. Configure kubectl
```bash
aws eks update-kubeconfig --name appgate-dev --region us-east-1
```

### 3. Install Cilium
```bash
cilium install --set ipam.mode=kubernetes
cilium status --wait
```

### 4. Apply Network Policies
```bash
kubectl apply -f infra/cilium/default-deny.yaml
kubectl apply -f infra/cilium/allow-dns.yaml
kubectl apply -f infra/cilium/allow-metrics.yaml
```

### 5. Install External Secrets Operator
```bash
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets
```

### 6. Install Prometheus + Grafana
```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install prometheus prometheus-community/kube-prometheus-stack
```

## Rollback
```bash
terraform destroy  # Destroys entire environment
```

## Disaster Recovery
1. Restore Terraform state from S3 backend
2. Re-run `terraform apply`
3. Restore database from RDS snapshot
4. Verify Cilium status
5. Verify network policies
6. Verify metrics and logs