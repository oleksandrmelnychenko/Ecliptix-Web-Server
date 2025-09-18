# --- ECR ---

output "memberships_repository_url" {
  value = module.ecr.memberships_repository_url
}

# --- IAM --- 

output "ecs_task_execution_role_arn" {
  description = "ARN of ECS task execution role"
  value       = module.iam.ecs_task_execution_role_arn
}

output "ecs_task_role_arn" {
  description = "ARN of ECS task role"
  value       = module.iam.ecs_task_role_arn
}

output "ecs_cloudwatch_policy_arn" {
  description = "ARN of ECS CloudWatch policy"
  value       = module.iam.ecs_cloudwatch_policy_arn
}
