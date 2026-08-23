# RUNBOOK: Control Plane Failover
# Severity: P0 (Critical)
# SLO: RTO < 15 minutes

## Symptoms
- Alert: ControlPlaneLeaderElectionFailed
- /readyz returns 503
- Policy evaluation failures

## Immediate Actions

1. **Check leader status**
   ```bash
   kubectl exec -it pod/appgate-control-plane-0 -- /app/control-plane /healthz
   kubectl logs -l app.kubernetes.io/component=control-plane --tail=100
   ```

2. **Check etcd health**
   ```bash
   kubectl exec -it pod/etcd-0 -- etcdctl endpoint health
   kubectl exec -it pod/etcd-0 -- etcdctl member list
   ```

3. **Force re-election**
   ```bash
   # Delete the leader election lease
   kubectl delete lease appgate-control-plane-leader
   ```

4. **Restart control plane**
   ```bash
   kubectl rollout restart statefulset/appgate-control-plane
   ```

## Recovery Verification

```bash
kubectl wait --for=condition=ready pod -l app.kubernetes.io/component=control-plane --timeout=60s
curl -k https://control-plane:8443/readyz
```

## Post-Mortem

- Check etcd disk I/O and memory
- Review leader election logs
- Verify network connectivity between replicas