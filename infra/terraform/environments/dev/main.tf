# AppGate Development Environment
# Uses remote state with locking

terraform {
  backend "s3" {
    bucket         = "appgate-terraform-state"
    key            = "dev/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "appgate-terraform-locks"
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# VPC
module "vpc" {
  source = "../../modules/vpc"

  environment          = "dev"
  vpc_cidr             = "10.0.0.0/16"
  availability_zones   = ["us-east-1a", "us-east-1b", "us-east-1c"]
  private_subnet_cidrs = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnet_cidrs  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_vpc_endpoints = true
}

# KMS
module "kms" {
  source      = "../../modules/kms"
  environment = "dev"
  description = "AppGate Development Encryption Key"
}

# EKS
module "eks" {
  source = "../../modules/eks"

  environment         = "dev"
  cluster_name        = "appgate-dev"
  kubernetes_version  = "1.30"
  vpc_id              = module.vpc.vpc_id
  vpc_cidr            = "10.0.0.0/16"
  private_subnet_ids  = module.vpc.private_subnet_ids
  node_instance_types = ["m6i.large"]
  node_desired_size   = 3
  node_min_size       = 3
  node_max_size       = 5
  kms_key_arn         = module.kms.key_arn
}

output "cluster_name" {
  value = module.eks.cluster_name
}

output "cluster_endpoint" {
  value = module.eks.cluster_endpoint
}

output "vpc_id" {
  value = module.vpc.vpc_id
}