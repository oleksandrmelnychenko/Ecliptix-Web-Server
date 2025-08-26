terraform {
  required_version = ">= 1.13.0"

  backend "s3" {
    bucket         = "ecliptix-terraform-state"
    key            = "ecliptix-control/terraform.tfstate"
    region         = "eu-central-1"
    dynamodb_table = "ecliptix-terraform-locks"
    encrypt        = true
  }
}

provider "aws" {
  region = "eu-central-1"
}

# --- Генеруємо SSH ключ ED25519 ---

resource "tls_private_key" "ecliptix_key" {
  algorithm = "ED25519"
}

resource "aws_key_pair" "ecliptix_key" {
  key_name   = "ecliptix-control-key"
  public_key = tls_private_key.ecliptix_key.public_key_openssh
}

# --- VPC для ecliptix ---

resource "aws_vpc" "ecliptix" {
  cidr_block = "10.1.0.0/16"
  tags       = { Name = "ecliptix-vpc" }
}

# --- Public Subnet ---

resource "aws_subnet" "ecliptix_public" {
  vpc_id                  = aws_vpc.ecliptix.id
  cidr_block              = "10.1.4.0/22"
  map_public_ip_on_launch = true
  tags                    = { Name = "ecliptix-public-subnet" }
}

# --- Інтернет Gateway ---

resource "aws_internet_gateway" "ecliptix_igw" {
  vpc_id = aws_vpc.ecliptix.id
  tags   = { Name = "ecliptix-igw" }
}

# --- Route Table для Public Subnet ---

resource "aws_route_table" "ecliptix_public_rt" {
  vpc_id = aws_vpc.ecliptix.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.ecliptix_igw.id
  }
  tags = { Name = "ecliptix-public-rt" }
}

resource "aws_route_table_association" "ecliptix_public_assoc" {
  subnet_id      = aws_subnet.ecliptix_public.id
  route_table_id = aws_route_table.ecliptix_public_rt.id
}

# --- Security Group для SSH ---

resource "aws_security_group" "ecliptix_control_sg" {
  name        = "ecliptix-control-sg"
  description = "Allow SSH inbound"
  vpc_id      = aws_vpc.ecliptix.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "ecliptix-control-sg" }
}

# --- Два EC2 інстанси для ecliptix-control ---

resource "aws_instance" "ecliptix_control" {
  count           = 1
  ami             = "ami-02003f9f0fde924ea" # Ubuntu 24.04 LTS 
  instance_type   = "t3.medium"
  subnet_id       = aws_subnet.ecliptix_public.id
  key_name        = aws_key_pair.ecliptix_key.key_name
  vpc_security_group_ids = [aws_security_group.ecliptix_control_sg.id]
  tags = { Name = "ecliptix-control-${count.index + 1}" }
}

# --- Вивід Public IPs та Private Key ---

output "ecliptix_control_public_ips" {
  value = aws_instance.ecliptix_control[*].public_ip
}

output "ecliptix_private_key_ed25519" {
  value     = tls_private_key.ecliptix_key.private_key_openssh
  sensitive = true
}
