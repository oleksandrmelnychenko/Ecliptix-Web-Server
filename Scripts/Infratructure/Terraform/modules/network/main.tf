# --- VPC --- 

resource "aws_vpc" "this" {
  cidr_block = var.vpc_cidr
  tags       = merge(var.tags, { Name = "${var.tags["project"]}-vpc" })
}

# --- Public Subnets ---

resource "aws_subnet" "public" {
  count                   = length(var.availability_zones)
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.public_cidrs[count.index]
  availability_zone      = var.availability_zones[count.index]
  map_public_ip_on_launch = true

  tags = merge(var.tags, {
    Name = "${var.tags["project"]}-public-${var.availability_zones[count.index]}"
  })
}

# --- Private Subnets ---

resource "aws_subnet" "private" {
  count              = length(var.availability_zones)
  vpc_id             = aws_vpc.this.id
  cidr_block         = var.private_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = merge(var.tags, {
    Name = "${var.tags["project"]}-private-${var.availability_zones[count.index]}"
  })
}

# --- Internal Gateway --- 

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "${var.tags["project"]}-igw" })
}

# --- NAT Gateway ---
resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = { Name = "ecliptix-nat-eip" }
}

resource "aws_nat_gateway" "this" {
  allocation_id = aws_eip.nat.allocation_id
  subnet_id     = aws_subnet.public[0].id

  tags = { Name = "ecliptix-nat-gateway" }

  depends_on = [aws_internet_gateway.this]
}

# --- Route Tables ---

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags =  merge(var.tags, { Name = "${var.tags["project"]}-public-rt" })
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.this.id
  }
  tags = merge(var.tags, { Name = "${var.tags["project"]}-private-rt" })
}

# --- Route Table Associations ---

resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}