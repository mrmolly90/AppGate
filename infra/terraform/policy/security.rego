# Conftest policy: Require S3 backend with DynamoDB locking
package main

deny[msg] {
    input.terraform.backend.s3 == null
    msg = "All environments must use S3 backend with DynamoDB locking"
}

deny[msg] {
    input.terraform.backend.s3.dynamodb_table == null
    msg = "S3 backend must specify dynamodb_table for state locking"
}

deny[msg] {
    input.terraform.backend.s3.encrypt != true
    msg = "S3 backend must have encrypt = true"
}

# Require private EKS endpoints
deny[msg] {
    some i
    resource := input.resource.aws_eks_cluster[i]
    resource.vpc_config.endpoint_public_access == true
    msg = sprintf("EKS cluster %s must have endpoint_public_access = false", [resource.name])
}

# Require encryption on EKS
deny[msg] {
    some i
    resource := input.resource.aws_eks_cluster[i]
    resource.encryption_config == null
    msg = sprintf("EKS cluster %s must have encryption_config enabled", [resource.name])
}

# Require cluster logging
deny[msg] {
    some i
    resource := input.resource.aws_eks_cluster[i]
    resource.enabled_cluster_log_types == null
    msg = sprintf("EKS cluster %s must have enabled_cluster_log_types", [resource.name])
}

# Require version >= 1.27
deny[msg] {
    some i
    resource := input.resource.aws_eks_cluster[i]
    semver_compare(resource.version, ">= 1.27.0") == false
    msg = sprintf("EKS cluster %s must use Kubernetes >= 1.27", [resource.name])
}

# No 0.0.0.0/0 egress on security groups
deny[msg] {
    some i, j
    resource := input.resource.aws_security_group[i]
    rule := resource.egress[j]
    rule.cidr_blocks[_] == "0.0.0.0/0"
    msg = sprintf("Security group %s has 0.0.0.0/0 egress — use specific CIDRs", [resource.name])
}