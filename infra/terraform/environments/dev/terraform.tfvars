# AppGate Dev Terraform Variables
environment     = "dev"
cluster_name    = "appgate-dev"
vpc_cidr        = "10.0.0.0/16"
node_desired_size = 3
node_min_size     = 3
node_max_size     = 5
node_instance_types = ["m6i.large"]
enable_nat_gateway  = true
single_nat_gateway  = true
enable_vpc_endpoints = true