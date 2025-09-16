variable "algorithm" {
  type = string
  default = "ED25519"
}

variable "ecliptix_key_name" {
  type        = string
  description = "Key pair name for ecliptix-control"
}

variable "tags" {
  type    = map(string)
  default = {}
}
