# --- VPC ---

resource "aws_vpc" "ecliptix" {
  cidr_block = "10.1.0.0/16"
  tags       = { Name = "ecliptix-vpc" }
}

# --- Public Subnets ---

locals {
  public_azs  = ["eu-central-1a", "eu-central-1b", "eu-central-1c"]
  public_cidrs = ["10.1.4.0/22", "10.1.8.0/22", "10.1.12.0/22"]
}

resource "aws_subnet" "ecliptix_public" {
  count                   = length(local.public_azs)
  vpc_id                  = aws_vpc.ecliptix.id
  cidr_block              = local.public_cidrs[count.index]
  availability_zone       = local.public_azs[count.index]
  map_public_ip_on_launch = true
  tags = { Name = "ecliptix-public-${local.public_azs[count.index]}" }
}

# --- Private Subnets ---

locals {
  private_azs  = ["eu-central-1a", "eu-central-1b", "eu-central-1c"]
  private_cidrs = ["10.1.16.0/22", "10.1.20.0/22", "10.1.24.0/22"]
}

resource "aws_subnet" "ecliptix_private" {
  count             = length(local.private_azs)
  vpc_id            = aws_vpc.ecliptix.id
  cidr_block        = local.private_cidrs[count.index]
  availability_zone = local.private_azs[count.index]
  tags = { Name = "ecliptix-private-${local.private_azs[count.index]}" }
}

# --- Internet Gateway ---

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.ecliptix.id
  tags   = { Name = "ecliptix-igw" }
}

# --- Route Tables ---

resource "aws_route_table" "ecliptix_public_rt" {
  vpc_id = aws_vpc.ecliptix.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = { Name = "ecliptix-public-rt" }
}

resource "aws_route_table" "ecliptix_private_rt" {
  vpc_id = aws_vpc.ecliptix.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }
  tags = { Name = "ecliptix-private-rt" }
}

# --- Route Table Associations ---

resource "aws_route_table_association" "public_assoc" {
  count          = length(aws_subnet.ecliptix_public)
  subnet_id      = aws_subnet.ecliptix_public[count.index].id
  route_table_id = aws_route_table.ecliptix_public_rt.id
}

resource "aws_route_table_association" "private_assoc" {
  count          = length(aws_subnet.ecliptix_private)
  subnet_id      = aws_subnet.ecliptix_private[count.index].id
  route_table_id = aws_route_table.ecliptix_private_rt.id
}

# --- VPC Endpoints ---

resource "aws_vpc_endpoint" "ecr_api" {
  vpc_id            = aws_vpc.ecliptix.id
  service_name      = "com.amazonaws.eu-central-1.ecr.api"
  vpc_endpoint_type = "Interface"
  subnet_ids        = aws_subnet.ecliptix_private[*].id
  security_group_ids = [aws_security_group.vpc_endpoints.id]
}

resource "aws_vpc_endpoint" "ecr_dkr" {
  vpc_id            = aws_vpc.ecliptix.id
  service_name      = "com.amazonaws.eu-central-1.ecr.dkr"
  vpc_endpoint_type = "Interface"
  subnet_ids        = aws_subnet.ecliptix_private[*].id
  security_group_ids = [aws_security_group.vpc_endpoints.id]
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id             = aws_vpc.ecliptix.id
  service_name       = "com.amazonaws.eu-central-1.s3"
  vpc_endpoint_type  = "Gateway"
  route_table_ids    = [aws_route_table.ecliptix_public_rt.id]
}
