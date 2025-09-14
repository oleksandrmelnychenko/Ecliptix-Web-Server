output "service_id" {
  value = aws_ecs_service.this.id
}

output "service_name" {
  value = aws_ecs_service.this.name
}
