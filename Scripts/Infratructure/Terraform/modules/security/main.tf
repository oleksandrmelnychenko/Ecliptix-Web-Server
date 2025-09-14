# --- ALB SG (public) ---

resource "aws_security_group" "alb_sg" {
  name        = "ecliptix-alb-sg"
  description = "Allow inbound to ALB"
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    for_each = var.alb_ports
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"] 
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "ecliptix-alb-sg" }
}

# --- ECS tasks SG (private, allow only ALB) ---

resource "aws_security_group" "ecs_sg" {
  name   = "ecliptix-ecs-sg"
  vpc_id = var.vpc_id

  ingress {
    from_port       = 5051
    to_port         = 5051
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "ecliptix-ecs-sg"}
}

# --- SSH SG for Control Instances ---

resource "aws_security_group" "control_sg" {
  name        = "ecliptix-control-sg"
  description = "Allow SSH inbound"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_ssh_cidrs
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Access to MSSQL only from Control instance
  egress {
    from_port   = 1433
    to_port     = 1433
    protocol    = "tcp"
    cidr_blocks = [var.allowed_vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "ecliptix-control-sg" }
}

# --- SG for VPC Endpoints ---

resource "aws_security_group" "vpc_endpoints" {
  name        = "vpc-enpoints-sg"
  vpc_id      = var.vpc_id
  description = "Allow HTTPS for VPC Endpoints"

  ingress {
    from_port  = 443
    to_port    = 443
    protocol   = "tcp"
    cidr_blocks = [var.allowed_vpc_cidr]
  }

  egress {
    from_port  = 0
    to_port    = 0
    protocol   = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- SG for MSSQL subnet group ---

resource "aws_security_group" "mssql_sg" {
  name        = "ecliptix-mssql-sg"
  description = "Allow MSSQL traffic from ECS tasks and Control"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 1433
    to_port         = 1433
    protocol        = "tcp"
    security_groups = [
      aws_security_group.ecs_sg.id,
      aws_security_group.control_sg.id
    ]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "ecliptix-mssql-sg" }
}

