# --- ALB SG (public)  ---

resource "aws_security_group" "alb_sg" {
  name        = "ecliptix-alb-sg"
  description = "Allow HTTPS inbound"
  vpc_id      = aws_vpc.ecliptix.id

  ingress {
    from_port  = 443
    to_port    = 443
    protocol   = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port  = 0
    to_port    = 0
    protocol   = "-1"
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
    protocol   = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "ecliptix-ecs-sg" }
} 

# --- SSH Security Group for Control Instances ---

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

