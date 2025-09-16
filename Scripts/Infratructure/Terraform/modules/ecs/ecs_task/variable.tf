variable "family" {
  type        = string
  description = "ECS Task Definition family name"
}

variable "cpu" {
  type        = number
  description = "CPU units for the task"
}

variable "memory" {
  type        = number
  description = "Memory for the task"
}

variable "execution_role_arn" {
  type        = string
  description = "ARN of the ECS execution role"
}

variable "task_role_arn" {
  type        = string
  description = "ARN of the ECS task role"
}

variable "container_name" {
  type        = string
}

variable "image_url" {
  type        = string
  description = "ECS repository URL"
}

variable "port_mappings" {
  type = list(object({
    containerPort = number
    protocol      = string
  }))

  description = "List of port mappings for the container"
}

variable "environment" {
  type = list(object({
    name  = string
    value = string
  }))

  description = "Environment variables for the container"
}
