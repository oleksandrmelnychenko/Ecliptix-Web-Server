# --- VPC ---

resource "aws_vpc" "ecliptix" {
  cidr_block = "10.1.0.0/16"
  tags       = { Name = "ecliptix-vpc" }
}

# --- Public Subnets ---

resource "aws_subnet" "ecliptix_public_1a" {
  vpc_id                  = aws_vpc.ecliptix.id
  cidr_block              = "10.1.4.0/22"
  availability_zone       = "eu-central-1a"
  map_public_ip_on_launch = true
  tags                    = { Name = "ecliptix-public-subnet-1a" }
}

resource "aws_subnet" "ecliptix_public_1b" {
  vpc_id                  = aws_vpc.ecliptix.id
  cidr_block              = "10.1.8.0/22"
  availability_zone       = "eu-central-1b"
  map_public_ip_on_launch = true
  tags = { Name = "ecliptix-public-subnet-1b" }
}

# --- Private Subnet ---

resource "aws_subnet" "ecliptix_private" {
  vpc_id     = aws_vpc.ecliptix.id
  cidr_block = "10.1.12.0/22"
  tags       = { Name = "ecliptix-private-subnet" }
}

# --- Internet Gateway ---

resource "aws_internet_gateway" "ecliptix_igw" {
  vpc_id = aws_vpc.ecliptix.id
  tags   = { Name = "ecliptix-igw" }
}

# --- Route Table for Public Subnet ---

resource "aws_route_table" "ecliptix_public_rt" {
  vpc_id = aws_vpc.ecliptix.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.ecliptix_igw.id
  }
  tags = { Name = "ecliptix-public-rt" }
}

resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.ecliptix.id
  
  route {
    cidr_block        = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  } 
}

# --- Route Table associations ---

resource "aws_route_table_association" "ecliptix_public_assoc_1a" {
  subnet_id      = aws_subnet.ecliptix_public_1a.id
  route_table_id = aws_route_table.ecliptix_public_rt.id
}

resource "aws_route_table_association" "ecliptix_public_assoc_1b" {
  subnet_id      = aws_subnet.ecliptix_public_1b.id
  route_table_id = aws_route_table.ecliptix_public_rt.id
}

resource "aws_route_table_association" "ecliptix_private_assoc" {
  subnet_id      = aws_subnet.ecliptix_private.id
  route_table_id = aws_route_table.private_rt.id
}

# --- VPC endpoints ---

# --- ECR API endpint  ---

resource "aws_vpc_endpoint" "ecr_api" {
  vpc_id             = aws_vpc.ecliptix.id
  service_name       = "com.amazonaws.eu-central-1.ecr.api"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = [aws_subnet.ecliptix_private.id]
  security_group_ids = [aws_security_group.vpc_endpoints.id]
}

# --- ECR Docker endpoint ---

resource "aws_vpc_endpoint" "ecr_dkr" {
  vpc_id             = aws_vpc.ecliptix.id
  service_name       = "com.amazonaws.eu-central-1.ecr.dkr"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = [aws_subnet.ecliptix_private.id]
  security_group_ids = [aws_security_group.vpc_endpoints.id] 
}

# --- S3 enpoint for ECR layers ---

resource "aws_vpc_endpoint" "s3" {
  vpc_id           = aws_vpc.ecliptix.id
  service_name     = "com.amazonaws.eu-central-1.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids  = [aws_route_table.ecliptix_public_rt.id]
}
