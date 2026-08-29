# =============================================================================
# AppGate — Security Module (WAF, Security Groups, GuardDuty)
# =============================================================================
# All resources tagged with environment for cost tracking.
# =============================================================================

terraform {
  required_version = ">= 1.7.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "environment" {
  description = "Environment name (dev/staging/production)"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID for security groups"
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
}

variable "private_subnet_cidrs" {
  description = "Private subnet CIDR blocks"
  type        = list(string)
}

variable "tags" {
  description = "Common tags"
  type        = map(string)
  default     = {}
}

# ── WAF WebACL ────────────────────────────────────────────────────
resource "aws_wafv2_web_acl" "main" {
  count       = var.environment == "production" ? 1 : 0
  name        = "appgate-${var.environment}-waf"
  description = "WAF for AppGate ${var.environment}"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  # Rate-based rule: 5000 requests per 5 minutes
  rule {
    name     = "rate-limit"
    priority = 1
    action   = "block"
    statement {
      rate_based_statement {
        limit              = 5000
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name               = "RateLimitRule"
      sampled_requests_enabled   = true
    }
  }

  # AWS managed rules
  rule {
    name     = "aws-common-rules"
    priority = 2
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name               = "AWSCommonRules"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-sqli-rules"
    priority = 3
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name               = "AWSSQLiRules"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name               = "AppGateWAF"
    sampled_requests_enabled   = true
  }

  tags = merge(var.tags, {
    Name        = "appgate-${var.environment}-waf"
    Environment = var.environment
  })
}

# ── Security Groups ───────────────────────────────────────────────
resource "aws_security_group" "gateway_alb" {
  name        = "appgate-${var.environment}-gateway-alb"
  description = "Security group for AppGate gateway ALB"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, {
    Name        = "appgate-${var.environment}-gateway-alb"
    Environment = var.environment
  })
}

resource "aws_security_group" "gateway_ecs" {
  name        = "appgate-${var.environment}-gateway-ecs"
  description = "Security group for AppGate gateway ECS tasks"
  vpc_id      = var.vpc_id

  ingress {
    description     = "Traffic from ALB"
    from_port       = 8443
    to_port         = 8443
    protocol        = "tcp"
    security_groups = [aws_security_group.gateway_alb.id]
  }

  ingress {
    description = "Metrics scraping"
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, {
    Name        = "appgate-${var.environment}-gateway-ecs"
    Environment = var.environment
  })
}

# ── GuardDuty ─────────────────────────────────────────────────────
resource "aws_guardduty_detector" "main" {
  count  = var.environment == "production" ? 1 : 0
  enable = true

  tags = merge(var.tags, {
    Environment = var.environment
  })
}

# ── Outputs ───────────────────────────────────────────────────────
output "waf_acl_id" {
  value = var.environment == "production" ? aws_wafv2_web_acl.main[0].id : null
}

output "gateway_alb_security_group_id" {
  value = aws_security_group.gateway_alb.id
}

output "gateway_ecs_security_group_id" {
  value = aws_security_group.gateway_ecs.id
}