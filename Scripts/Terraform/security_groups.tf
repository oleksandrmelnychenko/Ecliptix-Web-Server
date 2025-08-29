# --- ALB SG (public)  ---

resource "aws_security_group" "alb_sg" {
  name        = "ecliptix-alb-sg"
  description = "Allow HTTPS inbound"
  vpc_id      = aws_vpc.ecliptix.id

  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] 
  }

  ingress {
    from_port   = 5051
    to_port     = 5051
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "ecliptix-alb-sg" }
}

# --- ECS tasks SG (private, allow traffic only from ALB)  ---

resource "aws_security_group" "ecs_sg" {
  name   = "ecliptix-ecs-sg"
  vpc_id = aws_vpc.ecliptix.id  

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }
  ingress {
    from_port       = 5051
    to_port         = 5051
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  egress {
    from_port  = 0
    to_port    = 0
    protocol   = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "ecliptix-ecs-sg" }
} 

# --- SSH SG for Control Instances ---

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
    from_port   = 1433
    to_port     = 1433
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.ecliptix.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "ecliptix-control-sg" }
}

# --- SG for VPC Enpoints ---

resource "aws_security_group" "vpc_endpoints" {
  name        = "vpc-enpoints-sg"
  vpc_id      = aws_vpc.ecliptix.id
  description = "Allow HTTPS for VPC Endpoints"

  ingress {
    from_port  = 443
    to_port    = 443
    protocol   = "tcp"
    cidr_blocks = ["10.1.0.0/16"]
  }

  egress {
    from_port  = 0
    to_port    = 0
    protocol   = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- SG for mssql subnet group ---

resource "aws_security_group" "mssql_sg" {
  name        = "ecliptix-memberships-mssql-sg"
  description = "Allow MSSQL traffic from ECS tasks"
  vpc_id      = aws_vpc.ecliptix.id

  ingress {
    from_port       = 1433
    to_port         = 1433
    protocol        = "tcp"
    security_groups = [
      aws_security_group.ecs_sg.id,
      aws_security_group.ecliptix_control_sg.id
    ]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }  

  tags = { Name = "ecliptix-memberships-mssql-sg" }
}
