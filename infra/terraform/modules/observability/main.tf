# =============================================================================
# AppGate — Observability Module (Prometheus, Grafana, Tempo, Loki)
# =============================================================================
# Deploys kube-prometheus-stack for production-grade monitoring.
# =============================================================================

terraform {
  required_version = ">= 1.7.0"
  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.28"
    }
  }
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
}

variable "tags" {
  description = "Common tags"
  type        = map(string)
  default     = {}
}

# ── kube-prometheus-stack ─────────────────────────────────────────
resource "helm_release" "kube_prometheus_stack" {
  name             = "kube-prometheus-stack"
  repository       = "https://prometheus-community.github.io/helm-charts"
  chart            = "kube-prometheus-stack"
  version          = "~> 58.0"
  namespace        = "appgate-observability"
  create_namespace = true
  timeout          = 600

  values = [
    <<-EOT
    prometheus:
      prometheusSpec:
        retention: 30d
        retentionSize: 50GB
        scrapeInterval: 15s
        evaluationInterval: 15s
        resources:
          requests:
            cpu: 500m
            memory: 2Gi
          limits:
            cpu: 2
            memory: 8Gi
        serviceMonitorSelectorNilUsesHelmValues: false
        podMonitorSelectorNilUsesHelmValues: false
    alerting:
      alertmanager:
        enabled: true
        config:
          global:
            resolve_timeout: 5m
          route:
            group_by: ['alertname', 'cluster']
            group_wait: 30s
            group_interval: 5m
            repeat_interval: 12h
            receiver: 'null'
          receivers:
            - name: 'null'
    grafana:
      adminPassword: ${var.environment == "production" ? "" : "admin"}
      persistence:
        enabled: true
        size: 10Gi
      dashboardProviders:
        dashboardproviders.yaml:
          apiVersion: 1
          providers:
            - name: appgate
              orgId: 1
              folder: AppGate
              type: file
              disableDeletion: false
              editable: true
              options:
                path: /var/lib/grafana/dashboards/appgate
      dashboards:
        appgate:
          appgate-overview:
            json: |
              {
                "title": "AppGate Overview",
                "panels": []
              }
    EOT
  ]

  depends_on = []
}

# ── Tempo (Traces) ────────────────────────────────────────────────
resource "helm_release" "tempo" {
  name             = "tempo"
  repository       = "https://grafana.github.io/helm-charts"
  chart            = "tempo"
  version          = "~> 1.7"
  namespace        = "appgate-observability"
  create_namespace = true
  timeout          = 300

  values = [
    <<-EOT
    tempo:
      retention: 72h
      resources:
        requests:
          cpu: 200m
          memory: 512Mi
    EOT
  ]
}

# ── Loki (Logs) ───────────────────────────────────────────────────
resource "helm_release" "loki" {
  name             = "loki"
  repository       = "https://grafana.github.io/helm-charts"
  chart            = "loki"
  version          = "~> 5.41"
  namespace        = "appgate-observability"
  create_namespace = true
  timeout          = 300

  values = [
    <<-EOT
    loki:
      auth_enabled: false
      commonConfig:
        replication_factor: 1
      storage:
        type: filesystem
      schemaConfig:
        configs:
          - from: 2024-01-01
            store: tsdb
            object_store: filesystem
            schema: v13
            index:
              prefix: index_
              period: 24h
    EOT
  ]
}

output "prometheus_endpoint" {
  value = "http://kube-prometheus-stack-prometheus.appgate-observability:9090"
}

output "grafana_endpoint" {
  value = "http://kube-prometheus-stack-grafana.appgate-observability:80"
}

output "tempo_endpoint" {
  value = "http://tempo.appgate-observability:4317"
}

output "loki_endpoint" {
  value = "http://loki.appgate-observability:3100"
}