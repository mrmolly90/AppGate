# RUNBOOK: Gateway Latency Spike
# Severity: P0 (Critical)
# SLO: p99 < 50ms

## Symptoms
- Alert: GatewayHighLatency fires
- Users report slow responses
- p99 latency > 50ms for 5+ minutes

## Immediate Actions

1. **Check current latency**
   ```bash
   kubectl exec -it deployment/appgate-gateway -- /app/gateway --metrics
   # Or query Prometheus:
   # histogram_quantile(0.99, rate(gateway_request_duration_seconds_bucket[5m]))
   ```

2. **Check upstream latency**
   ```bash
   # Query upstream duration histogram
   # histogram_quantile(0.99, rate(gateway_upstream_duration_seconds_bucket[5m]))
   ```

3. **Scale up**
   ```bash
   kubectl scale deployment/appgate-gateway --replicas=50
   ```

4. **Check resource exhaustion**
   ```bash
   kubectl top pods -l app.kubernetes.io/component=gateway
   ```

## Root Cause Analysis

- If upstream latency is normal → gateway CPU/memory bottleneck
- If upstream latency is high → LLM provider issue
- If connection count is high → rate limiting tuning needed

## Resolution

1. Increase HPA limits if needed
2. Tune tokio runtime parameters
3. Consider connection pooling improvements
4. Escalate to LLM provider if upstream issue