# IRSA for AppGate Control Plane
resource "aws_iam_role" "appgate_control_plane" {
  name = "appgate-${var.environment}-control-plane"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRoleWithWebIdentity"
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.eks.arn
      }
      Condition = {
        StringEquals = {
          "${replace(aws_eks_cluster.this.identity[0].oidc[0].issuer, "https://", "")}:sub" = "system:serviceaccount:appgate-system:appgate-control-plane"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "control_plane_secrets" {
  name = "appgate-control-plane-secrets"
  role = aws_iam_role.appgate_control_plane.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "kms:Decrypt",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:ResourceTag/ManagedBy" = "appgate"
          }
        }
      },
    ]
  })
}