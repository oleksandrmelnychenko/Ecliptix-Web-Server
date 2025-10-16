variable "aws_region" {
  type    = string
  default = "eu-central-1"
}

variable "alb_acm_certificate_arn" {
  description = "dev.balancer.ecliptix.online"
  type        = string
  default     = "arn:aws:acm:eu-central-1:020498483284:certificate/28e1d468-5a7f-4c78-801e-34338e2f18ee"
}

variable "env" {
  type    = string
  default = "dev"
}
