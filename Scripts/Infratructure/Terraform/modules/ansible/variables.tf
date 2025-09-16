variable "aws_region" {
  type        = string
  description = "AWS region"
}

variable "control_instance_public_ip" {
  type        = string
  description = "Public IP of control EC2 instance"
}

variable "ecr_repo" {
  type        = string
  description = "ECR repo URL"
}

variable "ecs_cluster" {
  type        = string
  description = "ECS cluster name"
}

variable "ecs_memberships_service" {
  type        = string
  description = "ECS memberships service name"
}
