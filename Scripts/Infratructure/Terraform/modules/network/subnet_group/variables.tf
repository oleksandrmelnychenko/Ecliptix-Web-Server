variable "private_subnet_ids" {
  type       = list(string)
  description = "List of subnet IDs for the DB subnet group"
}

variable "memberships_subnet_group_name" {
  type        = string
  description = "The name of the subnet group for the memberships database"
}

variable "tags" {
  type = map(string)
}