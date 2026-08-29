# Production environment
# Full HA: 3 AZs, multi-NAT, larger node pools, strict security

terraform {
  backend "s3" {
    bucket         = "appgate-terraform-state"
    key            = "production/terraform.tfstate"
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

module "vpc" {
  source = "../../modules/vpc"

  environment          = "production"
  vpc_cidr            = "10.2.0.0/16"
  availability_zones  = ["us-east-1a", "us-east-1b", "us-east-1c"]
  private_subnet_cidrs = ["10.2.1.0/24", "10.2.2.0/24", "10.2.3.0/24"]
  public_subnet_cidrs  = ["10.2.101.0/24", "10.2.102.0/24", "10.2.103.0/24"]
  enable_nat_gateway  = true
  single_nat_gateway  = false
  enable_vpc_endpoints = true
}

module "kms" {
  source      = "../../modules/kms"
  environment = "production"
}

module "eks" {
  source = "../../modules/eks"

  environment        = "production"
  cluster_name       = "appgate-production"
  kubernetes_version = "1.30"
  vpc_id            = module.vpc.vpc_id
  vpc_cidr          = "10.2.0.0/16"
  private_subnet_ids = module.vpc.private_subnet_ids
  node_instance_types = ["m6i.large", "m6a.large"]
  node_desired_size  = 5
  node_min_size      = 5
  node_max_size      = 20
  kms_key_arn       = module.kms.key_arn
}