variable "aws_region" {
  type    = string
  default = "eu-central-1"
}

variable "alb_acm_certificate_arn" {
  description = "dev.balancer.ecliptix.online"
  type        = string
  default     = "arn:aws:acm:eu-central-1:605009360854:certificate/cd3b43ac-675b-462a-9fbc-c1b26015db3b"
}