# AppGate Production Terraform Variables
environment          = "production"
cluster_name         = "appgate-production"
vpc_cidr             = "10.2.0.0/16"
node_desired_size    = 5
node_min_size        = 3
node_max_size        = 10
node_instance_types  = ["m6i.large", "m6a.large", "m7i.large"]
enable_nat_gateway   = true
single_nat_gateway   = false
enable_vpc_endpoints = true