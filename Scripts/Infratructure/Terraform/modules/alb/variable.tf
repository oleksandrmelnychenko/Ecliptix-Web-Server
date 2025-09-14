variable "vpc_id" {
  type        = string
  description = "VPC ID"
}

variable "public_subnet_ids" {
  type        = list(string)
  description = "Public subnet IDs for ALB"
}

variable "alb_sg_id" {
  type        = string
  description = "Security group ID for ALB"
}

variable "alb_acm_certificate_arn" {
  type        = string
  description = "ACM certificate ARN for ALB HTTPS listener"
}

variable "project" {
  type = string
}

variable "env" {
  type = string
}

variable "tags" {
  type = map(string)
  default = {}
}
