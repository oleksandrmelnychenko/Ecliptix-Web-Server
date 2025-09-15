output "ecs_task_execution_role_arn" {
  description = "ARN of ECS task execution role"
  value       = aws_iam_role.ecs_task_execution.arn
}

output "ecs_task_role_arn" {
  description = "ARN of ECS task role"
  value       = aws_iam_role.ecs_task_role.arn
}

output "ecs_cloudwatch_policy_arn" {
  description = "ARN of ECS CloudWatch policy"
  value       = aws_iam_policy.ecs_cloudwatch_logs.arn
}
