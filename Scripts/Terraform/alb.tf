resource "aws_lb" "ecliptix" {
  name               = "ecliptix-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.ecliptix_control_sg.id]
  subnets            = [aws_subnet.ecliptix_public.id]
}

resource "aws_lb_target_group" "memberships" {
  name     = "ecliptix-memberships-tg"
  port     = 5051
  protocol = "HTTP"
  vpc_id   = aws_vpc.ecliptix.id
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.ecliptix.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "<your-acm-certificate-arn>"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.memberships.arn
  }
}
