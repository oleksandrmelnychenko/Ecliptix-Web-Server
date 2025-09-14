variable "project" { type = string }
variable "env"     { type = string }

variable "cluster_id" { type = string }
variable "task_definition_arn" { type = string }

variable "private_subnet_ids" { type = list(string) }
variable "ecs_sg_id"          { type = string }

variable "load_balancers" {
  type = list(object({
    target_group_arn = string
    container_name   = string
    container_port   = number
  }))
}

variable "desired_count" {
  type    = number
  default = 1
}

variable "tags" {
  type    = map(string)
  default = {}
}
