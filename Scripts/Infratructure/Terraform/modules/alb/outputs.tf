output "alb_dns_name" {
  value = aws_lb.this.dns_name
}

output "alb_arn" {
  value = aws_lb.this.arn
}

output "memberships_http_tg_arn" {
  description = "Target group ARN for HTTP (8080)"
  value       = aws_lb_target_group.memberships_http.arn
}

output "memberships_grpc_tg_arn" {
  description = "Target group ARN for gRPC (5051)"
  value       = aws_lb_target_group.memberships_grpc.arn
}

output "memberships_https_listener" {
  description = "HTTPS listener for memberships 8080"
  value       = aws_lb_listener.memberships_http.arn
}

output "memberships_grpc_listener" {
  description = "HTTPS listener for memberships gRPC 5051"
  value       = aws_lb_listener.memberships_grpc.arn
}
