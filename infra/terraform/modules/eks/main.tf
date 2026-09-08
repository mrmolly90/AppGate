# EKS Module v2.0.0 — Production-Grade with IRSA, Addons, IMDSv2
# Scales to millions of RPS via Karpenter integration

variable "environment" { type = string }
variable "cluster_name" { type = string }
variable "kubernetes_version" { type = string default = "1.30" }
variable "vpc_id" { type = string }
variable "vpc_cidr" { type = string }
variable "private_subnet_ids" { type = list(string) }
variable "node_instance_types" { type = list(string) default = ["m6i.2xlarge", "m7i.2xlarge", "c7i.2xlarge"] }
variable "node_desired_size" { type = number default = 5 }
variable "node_min_size" { type = number default = 5 }
variable "node_max_size" { type = number default = 100 }
variable "kms_key_arn" { type = string }

# IAM role for EKS cluster
resource "aws_iam_role" "cluster" {
  name = "appgate-${var.environment}-eks-cluster"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
    }]
  })
  tags = { Environment = var.environment, ManagedBy = "terraform" }
}

resource "aws_iam_role_policy_attachment" "cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.cluster.name
}

resource "aws_iam_role_policy_attachment" "vpc_resource_controller" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.cluster.name
}

# OIDC Provider for IRSA
resource "aws_iam_openid_connect_provider" "eks" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["9e99a48a9960b14926bb7f3b6f0d5a9b7e5b7c5a"] # Amazon root CA
  url             = aws_eks_cluster.this.identity[0].oidc[0].issuer
}

# EKS Cluster
resource "aws_eks_cluster" "this" {
  name     = var.cluster_name
  version  = var.kubernetes_version
  role_arn = aws_iam_role.cluster.arn

  vpc_config {
    subnet_ids              = var.private_subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = false
    security_group_ids      = [aws_security_group.cluster.id]
  }

  encryption_config {
    provider { key_arn = var.kms_key_arn }
    resources = ["secrets"]
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  depends_on = [
    aws_iam_role_policy_attachment.cluster_policy,
    aws_iam_role_policy_attachment.vpc_resource_controller,
  ]

  tags = { Environment = var.environment, ManagedBy = "terraform" }
}

# EKS Addons — critical for networking stability at scale
resource "aws_eks_addon" "vpc_cni" {
  cluster_name  = aws_eks_cluster.this.name
  addon_name    = "vpc-cni"
  addon_version = "v1.18.0-eksbuild.1"
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "PRESERVE"
}

resource "aws_eks_addon" "kube_proxy" {
  cluster_name  = aws_eks_cluster.this.name
  addon_name    = "kube-proxy"
  addon_version = "v1.30.0-eksbuild.3"
}

resource "aws_eks_addon" "coredns" {
  cluster_name  = aws_eks_cluster.this.name
  addon_name    = "coredns"
  addon_version = "v1.11.1-eksbuild.8"
  depends_on    = [aws_eks_node_group.this]
}

# IRSA role for Karpenter (node autoscaling)
resource "aws_iam_role" "karpenter" {
  name = "appgate-${var.environment}-karpenter"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.eks.arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${replace(aws_eks_cluster.this.identity[0].oidc[0].issuer, "https://", "")}:sub" = "system:serviceaccount:karpenter:karpenter"
        }
      }
    }]
  })
}

# Node IAM role with minimal permissions
resource "aws_iam_role" "node" {
  name = "appgate-${var.environment}-eks-node"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = { Environment = var.environment, ManagedBy = "terraform" }
}

resource "aws_iam_role_policy_attachment" "node_worker" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.node.name
}

resource "aws_iam_role_policy_attachment" "node_cni" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.node.name
}

resource "aws_iam_role_policy_attachment" "node_ecr" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.node.name
}

resource "aws_iam_role_policy_attachment" "node_ssm" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  role       = aws_iam_role.node.name
}

# Security groups
resource "aws_security_group" "cluster" {
  name        = "appgate-${var.environment}-eks-cluster"
  description = "Security group for EKS cluster"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "appgate-${var.environment}-eks-cluster-sg", Environment = var.environment }
}

resource "aws_security_group" "node" {
  name        = "appgate-${var.environment}-eks-node"
  description = "Security group for EKS worker nodes"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
    description = "Internal cluster traffic"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound (controlled by Cilium)"
  }

  tags = { Name = "appgate-${var.environment}-eks-node-sg", Environment = var.environment }
}

# EKS Managed Node Group — baseline for Karpenter
resource "aws_eks_node_group" "this" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "appgate-${var.environment}-baseline"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = var.private_subnet_ids

  instance_types = var.node_instance_types

  scaling_config {
    desired_size = var.node_desired_size
    min_size     = var.node_min_size
    max_size     = var.node_max_size
  }

  update_config {
    max_unavailable_percentage = 25
  }

  capacity_type = "ON_DEMAND"
  disk_size     = 100

  # IMDSv2 enforcement — prevents SSRF credential exfiltration
  launch_template {
    id      = aws_launch_template.node.id
    version = aws_launch_template.node.latest_version
  }

  depends_on = [
    aws_iam_role_policy_attachment.node_worker,
    aws_iam_role_policy_attachment.node_cni,
    aws_iam_role_policy_attachment.node_ecr,
  ]

  tags = { Environment = var.environment, ManagedBy = "terraform" }
}

# Launch template with IMDSv2 required
resource "aws_launch_template" "node" {
  name          = "appgate-${var.environment}-node"
  image_id      = data.aws_ami.eks_optimized.id
  instance_type = var.node_instance_types[0]

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"  # IMDSv2 enforced
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  tag_specifications {
    resource_type = "instance"
    tags = { Name = "appgate-${var.environment}-node", Environment = var.environment }
  }
}

data "aws_ami" "eks_optimized" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amazon-eks-node-${var.kubernetes_version}-v*"]
  }
}

# Outputs
output "cluster_name" { value = aws_eks_cluster.this.name }
output "cluster_endpoint" { value = aws_eks_cluster.this.endpoint }
output "cluster_certificate_authority" { value = aws_eks_cluster.this.certificate_authority[0].data }
output "cluster_security_group_id" { value = aws_security_group.cluster.id }
output "node_security_group_id" { value = aws_security_group.node.id }
output "node_role_arn" { value = aws_iam_role.node.arn }
output "oidc_provider_arn" { value = aws_iam_openid_connect_provider.eks.arn }
output "oidc_issuer_url" { value = aws_eks_cluster.this.identity[0].oidc[0].issuer }