# Staging environment
# Same structure as dev but with single_nat_gateway = false for HA

terraform {
  backend "s3" {
    bucket         = "appgate-terraform-state"
    key            = "staging/terraform.tfstate"
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

  environment          = "staging"
  vpc_cidr            = "10.1.0.0/16"
  availability_zones  = ["us-east-1a", "us-east-1b", "us-east-1c"]
  private_subnet_cidrs = ["10.1.1.0/24", "10.1.2.0/24", "10.1.3.0/24"]
  public_subnet_cidrs  = ["10.1.101.0/24", "10.1.102.0/24", "10.1.103.0/24"]
  enable_nat_gateway  = true
  single_nat_gateway  = false
  enable_vpc_endpoints = true
}

module "kms" {
  source      = "../../modules/kms"
  environment = "staging"
}

module "eks" {
  source = "../../modules/eks"

  environment        = "staging"
  cluster_name       = "appgate-staging"
  kubernetes_version = "1.30"
  vpc_id            = module.vpc.vpc_id
  vpc_cidr          = "10.1.0.0/16"
  private_subnet_ids = module.vpc.private_subnet_ids
  node_instance_types = ["m6i.large"]
  node_desired_size  = 3
  node_min_size      = 3
  node_max_size      = 8
  kms_key_arn       = module.kms.key_arn
}