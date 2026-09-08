# AppGate VPC Module
# =============================================================================
# Creates VPC, subnets, NAT gateways, and VPC endpoints for EKS.

variable "environment" {
  description = "Environment name (dev, staging, production)"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
}

variable "enable_nat_gateway" {
  description = "Enable NAT Gateway for private subnets"
  type        = bool
  default     = true
}

variable "single_nat_gateway" {
  description = "Use a single NAT Gateway for all AZs"
  type        = bool
  default     = false
}

variable "enable_vpc_endpoints" {
  description = "Enable VPC endpoints for S3, ECR, etc."
  type        = bool
  default     = true
}

# ── VPC ──────────────────────────────────────────────────────────────────────
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "appgate-${var.environment}"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# ── Internet Gateway ─────────────────────────────────────────────────────────
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name        = "appgate-${var.environment}-igw"
    Environment = var.environment
  }
}

# ── Public Subnets ───────────────────────────────────────────────────────────
resource "aws_subnet" "public" {
  count = length(var.public_subnet_cidrs)

  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name        = "appgate-${var.environment}-public-${count.index + 1}"
    Environment = var.environment
    Type        = "public"
    "kubernetes.io/role/elb" = "1"
  }
}

# ── Private Subnets ──────────────────────────────────────────────────────────
resource "aws_subnet" "private" {
  count = length(var.private_subnet_cidrs)

  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = {
    Name        = "appgate-${var.environment}-private-${count.index + 1}"
    Environment = var.environment
    Type        = "private"
    "kubernetes.io/role/internal-elb" = "1"
  }
}

# ── NAT Gateway ──────────────────────────────────────────────────────────────
resource "aws_eip" "nat" {
  count = var.enable_nat_gateway ? (var.single_nat_gateway ? 1 : length(var.public_subnet_cidrs)) : 0
  domain = "vpc"

  tags = {
    Name        = "appgate-${var.environment}-nat-${count.index + 1}"
    Environment = var.environment
  }
}

resource "aws_nat_gateway" "main" {
  count = var.enable_nat_gateway ? (var.single_nat_gateway ? 1 : length(var.public_subnet_cidrs)) : 0

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[var.single_nat_gateway ? 0 : count.index].id

  tags = {
    Name        = "appgate-${var.environment}-nat-${count.index + 1}"
    Environment = var.environment
  }

  depends_on = [aws_internet_gateway.main]
}

# ── Route Tables ─────────────────────────────────────────────────────────────
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name        = "appgate-${var.environment}-public"
    Environment = var.environment
  }
}

resource "aws_route_table_association" "public" {
  count = length(var.public_subnet_cidrs)

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  count = var.enable_nat_gateway ? (var.single_nat_gateway ? 1 : length(var.private_subnet_cidrs)) : 0
  vpc_id = aws_vpc.main.id

  dynamic "route" {
    for_each = var.enable_nat_gateway ? [1] : []
    content {
      cidr_block     = "0.0.0.0/0"
      nat_gateway_id = aws_nat_gateway.main[var.single_nat_gateway ? 0 : count.index].id
    }
  }

  tags = {
    Name        = "appgate-${var.environment}-private-${count.index + 1}"
    Environment = var.environment
  }
}

resource "aws_route_table_association" "private" {
  count = length(var.private_subnet_cidrs)

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = var.enable_nat_gateway ? aws_route_table.private[var.single_nat_gateway ? 0 : count.index].id : aws_route_table.private[0].id
}

# ── VPC Endpoints ────────────────────────────────────────────────────────────
resource "aws_vpc_endpoint" "s3" {
  count = var.enable_vpc_endpoints ? 1 : 0

  vpc_id       = aws_vpc.main.id
  service_name = "com.amazonaws.${data.aws_region.current.name}.s3"

  tags = {
    Name        = "appgate-${var.environment}-s3-endpoint"
    Environment = var.environment
  }
}

resource "aws_vpc_endpoint" "ecr_api" {
  count = var.enable_vpc_endpoints ? 1 : 0

  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.ecr.api"
  vpc_endpoint_type = "Interface"
  subnet_ids        = aws_subnet.private[*].id

  security_group_ids = [aws_security_group.vpc_endpoints.id]

  tags = {
    Name        = "appgate-${var.environment}-ecr-api"
    Environment = var.environment
  }
}

resource "aws_vpc_endpoint" "ecr_dkr" {
  count = var.enable_vpc_endpoints ? 1 : 0

  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.ecr.dkr"
  vpc_endpoint_type = "Interface"
  subnet_ids        = aws_subnet.private[*].id

  security_group_ids = [aws_security_group.vpc_endpoints.id]

  tags = {
    Name        = "appgate-${var.environment}-ecr-dkr"
    Environment = var.environment
  }
}

resource "aws_vpc_endpoint" "sts" {
  count = var.enable_vpc_endpoints ? 1 : 0

  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.sts"
  vpc_endpoint_type = "Interface"
  subnet_ids        = aws_subnet.private[*].id

  security_group_ids = [aws_security_group.vpc_endpoints.id]

  tags = {
    Name        = "appgate-${var.environment}-sts"
    Environment = var.environment
  }
}

resource "aws_vpc_endpoint" "cloudwatch" {
  count = var.enable_vpc_endpoints ? 1 : 0

  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.logs"
  vpc_endpoint_type = "Interface"
  subnet_ids        = aws_subnet.private[*].id

  security_group_ids = [aws_security_group.vpc_endpoints.id]

  tags = {
    Name        = "appgate-${var.environment}-logs"
    Environment = var.environment
  }
}

# ── Security Group for VPC Endpoints ─────────────────────────────────────────
resource "aws_security_group" "vpc_endpoints" {
  count = var.enable_vpc_endpoints ? 1 : 0

  name_prefix = "appgate-${var.environment}-vpc-endpoints-"
  description = "Security group for VPC endpoints"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "HTTPS from VPC"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
    description = "VPC-internal only"
  }

  tags = {
    Name        = "appgate-${var.environment}-vpc-endpoints"
    Environment = var.environment
  }
}

# ── Data Sources ─────────────────────────────────────────────────────────────
data "aws_region" "current" {}

# ── Outputs ──────────────────────────────────────────────────────────────────
output "vpc_id" {
  value = aws_vpc.main.id
}

output "vpc_cidr" {
  value = aws_vpc.main.cidr_block
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "public_subnet_ids" {
  value = aws_subnet.public[*].id
}

output "private_subnet_cidrs" {
  value = aws_subnet.private[*].cidr_block
}

output "public_subnet_cidrs" {
  value = aws_subnet.public[*].cidr_block
}

output "nat_gateway_ids" {
  value = var.enable_nat_gateway ? aws_nat_gateway.main[*].id : []
}

output "vpc_endpoints" {
  value = var.enable_vpc_endpoints ? {
    s3         = try(aws_vpc_endpoint.s3[0].id, "")
    ecr_api    = try(aws_vpc_endpoint.ecr_api[0].id, "")
    ecr_dkr    = try(aws_vpc_endpoint.ecr_dkr[0].id, "")
    sts        = try(aws_vpc_endpoint.sts[0].id, "")
    cloudwatch = try(aws_vpc_endpoint.cloudwatch[0].id, "")
  } : {}