# AppGate Production Terraform Variables
environment          = "production"
cluster_name         = "appgate-production"
vpc_cidr             = "10.2.0.0/16"
node_desired_size    = 5
node_min_size        = 5
node_max_size        = 100  # Aligned with main.tf for Karpenter headroom
node_instance_types  = ["m6i.2xlarge", "m7i.2xlarge", "c7i.2xlarge"]
enable_nat_gateway   = true
single_nat_gateway   = false
enable_vpc_endpoints = true