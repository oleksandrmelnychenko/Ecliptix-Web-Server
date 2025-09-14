resource "aws_lb" "this" {
  name               = "${var.project}-${var.env}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [var.alb_sg_id]
  subnets            = var.public_subnet_ids

  tags = merge(var.tags, { Name = "${var.project}-${var.env}-alb" })
}

# --- Target group for HTTP/1 (8080) ---

resource "aws_lb_target_group" "http" {
  name        = "${var.project}-${var.env}-http-tg"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.vpc_id

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

  tags = merge(var.tags, { Name = "${var.project}-${var.env}-http-tg" })
}

# --- Target group for GRPC (5051) ---

resource "aws_lb_target_group" "grpc" {
  name             = "${var.project}-${var.env}-grpc-tg"
  port             = 5051
  protocol         = "HTTP"
  protocol_version = "HTTP2"
  target_type      = "ip"
  vpc_id           = var.vpc_id

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

  tags = merge(var.tags, { Name = "${var.project}-${var.env}-grpc-tg" })
}

# --- HTTPS Listener for memberships 8080 ---

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = "8080"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-Res-2021-06"
  certificate_arn   = var.alb_acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.http.arn
  }
}

# --- HTTPS Listener for memberships 5051 ---

resource "aws_lb_listener" "grpc" {
  load_balancer_arn = aws_lb.this.arn
  port              = 5051
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-Res-2021-06"
  certificate_arn   = var.alb_acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.grpc.arn
  }
}
