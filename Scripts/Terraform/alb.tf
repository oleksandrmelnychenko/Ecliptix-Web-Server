# --- Internal ALB ---

resource "aws_lb" "ecliptix" {
  name               = "ecliptix-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets = [
    for az, subnets in {
      for s in concat(
        aws_subnet.ecliptix_public[*]
      ) : s.availability_zone => s...
    } : subnets[0].id
  ]
}

# --- Target group for HTTP/1 (8080) ---

resource "aws_lb_target_group" "memberships_http" {
  name       = "ecliptix-memberships-http-tg"
  port       = 8080
  protocol   = "HTTP"
  target_type = "ip"
  vpc_id     = aws_vpc.ecliptix.id

  health_check {
    enabled             = true
    path                = "/"
    interval            = 10
    timeout             = 5
    healthy_threshold   = 3
    unhealthy_threshold = 2
    matcher             = "200"
    protocol            = "HTTP"
    port                = "traffic-port"
  }
}

# --- Target group for GRPC (5051) ---

resource "aws_lb_target_group" "memberships_grpc" {
  name             = "ecliptix-memberships-grpc-tg"
  port             = 5051
  protocol         = "HTTP"
  protocol_version = "HTTP2"
  target_type      = "ip"
  vpc_id           = aws_vpc.ecliptix.id

  health_check {
    enabled             = true
    path                = "/"
    interval            = 10
    timeout             = 5
    healthy_threshold   = 3
    unhealthy_threshold = 2
    matcher             = "200-499"
    protocol            = "HTTP"
    port                = "traffic-port"
  }
}

# --- HTTPS Listener for memberships 8080 ---

resource "aws_lb_listener" "memberships_https" {
  load_balancer_arn = aws_lb.ecliptix.arn
  port              = "8080"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-Res-2021-06"
  certificate_arn   = var.alb_acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.memberships_http.arn
  }
}

# --- HTTPS  Listener for memberships 5051 ---

resource "aws_lb_listener" "memberships_grpc" {
  load_balancer_arn = aws_lb.ecliptix.arn
  port              = 5051
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-Res-2021-06"
  certificate_arn   = var.alb_acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.memberships_grpc.arn 
  }
}
