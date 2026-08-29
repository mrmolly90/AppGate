# =============================================================================
# AppGate — Operations Guide
# =============================================================================

## On-Call Runbook Index

1. [Gateway Latency Spike](runbooks/RUNBOOK-gateway-latency-spike.md)
2. [Control Plane Failover](runbooks/RUNBOOK-control-plane-failover.md)
3. [Certificate Rotation](runbooks/RUNBOOK-certificate-rotation.md)

## Deployment Procedures

### Canary Deployment
```bash
# Deploy to 10% of instances first
kubectl set image deployment/appgate-gateway \
  appgate-gateway=ghcr.io/mrmolly90/appgate-gateway:v2.0.0 \
  --record
# Monitor for 5 minutes
kubectl rollout status deployment/appgate-gateway
```

### Blue/Green Deployment
```bash
# Deploy green stack
helm upgrade --install appgate-green deploy/helm/appgate \
  --values deploy/helm/appgate/values-production.yaml \
  --set gateway.replicas=10 \
  --set gateway.service.type=ClusterIP

# Switch traffic
kubectl patch service appgate-gateway -p \
  '{"spec":{"selector":{"version":"green"}}}'

# Verify and destroy blue
kubectl delete deployment appgate-gateway --selector=version=blue
```

### Full Rollout
```bash
helm upgrade --install appgate deploy/helm/appgate \
  --values deploy/helm/appgate/values-production.yaml \
  --set gateway.image.tag=v2.0.0 \
  --set controlPlane.image.tag=v2.0.0
```

## Rollback Procedures

```bash
# Rollback Helm release
helm rollback appgate 1

# Rollback Kubernetes deployment
kubectl rollout undo deployment/appgate-gateway

# Rollback Terraform
cd infra/terraform/environments/production
terraform plan -destroy
```

## Certificate Rotation

See [RUNBOOK-certificate-rotation.md](runbooks/RUNBOOK-certificate-rotation.md).