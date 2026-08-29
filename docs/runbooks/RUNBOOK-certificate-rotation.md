# RUNBOOK: Certificate Rotation
# Severity: P1 (High)
# SLO: Complete within 1 hour

## Symptoms
- Alert: GatewayCertificateExpiry fires
- Certificate expires in < 7 days

## Automated Rotation (cert-manager)

If cert-manager is enabled, certificates are rotated automatically:
```bash
# Check certificate status
kubectl get certificate -n appgate-system
kubectl describe certificate appgate-gateway-tls -n appgate-system
```

## Manual Rotation

1. **Generate new certificate**
   ```bash
   openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
     -days 365 -nodes -subj "/CN=gateway.appgate.local"
   ```

2. **Update Kubernetes secret**
   ```bash
   kubectl create secret tls appgate-gateway-tls \
     --cert=cert.pem --key=key.pem \
     --dry-run=client -o yaml | kubectl apply -f -
   ```

3. **Roll pods to pick up new certificate**
   ```bash
   kubectl rollout restart deployment/appgate-gateway
   ```

4. **Verify**
   ```bash
   openssl s_client -connect gateway:443 -servername gateway.appgate.local
   ```

## Emergency Rotation

If certificate has already expired:
```bash
kubectl delete secret appgate-gateway-tls
kubectl create secret tls appgate-gateway-tls --cert=cert.pem --key=key.pem
kubectl rollout restart deployment/appgate-gateway
```