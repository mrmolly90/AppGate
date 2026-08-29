# KMS Module
# Creates KMS keys for EKS encryption and application secrets

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "description" {
  description = "Description for the KMS key"
  type        = string
  default     = "AppGate encryption key"
}

resource "aws_kms_key" "this" {
  description             = "${var.description} - ${var.environment}"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  is_enabled              = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
    ]
  })

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_kms_alias" "this" {
  name          = "alias/appgate-${var.environment}"
  target_key_id = aws_kms_key.this.key_id
}

data "aws_caller_identity" "current" {}

output "key_arn" {
  value = aws_kms_key.this.arn
}

output "key_id" {
  value = aws_kms_key.this.key_id
}

output "alias" {
  value = aws_kms_alias.this.name
}