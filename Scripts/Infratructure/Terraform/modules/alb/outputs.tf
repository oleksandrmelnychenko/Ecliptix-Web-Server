output "alb_dns_name" {
  value = aws_lb.this.dns_name
}

output "alb_arn" {
  value = aws_lb.this.arn
}

output "http_tg_arn" {
  value = aws_lb_target_group.http.arn
}

output "grpc_tg_arn" {
  value = aws_lb_target_group.grpc.arn
}
