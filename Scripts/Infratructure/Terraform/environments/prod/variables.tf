variable "aws_region" {
  type    = string
  default = "eu-central-1"
}

variable "alb_acm_certificate_arn" {
  description = "balancer.ecliptix.online"
  type        = string
  default     = "arn:aws:acm:eu-central-1:605009360854:certificate/2f0ec6f2-11c3-4e23-8b0f-b8c5e0e90a7e"
}

variable "env" {
  type    = string
  default = "prod"
}