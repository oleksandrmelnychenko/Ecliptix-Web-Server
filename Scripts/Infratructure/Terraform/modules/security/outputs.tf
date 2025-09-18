output "alb_sg_id" {
  value = aws_security_group.alb_sg.id
}

output "ecs_sg_id" {
  value = aws_security_group.ecs_sg.id
}

output "control_sg_id" {
  value = aws_security_group.control_sg.id
}

output "endpoint_sg_id" {
  value       = aws_security_group.vpc_endpoints.id
  description = "Security group ID for VPC endpoints"
}

output "mssql_sg_id" {
  value = aws_security_group.mssql_sg.id
}
