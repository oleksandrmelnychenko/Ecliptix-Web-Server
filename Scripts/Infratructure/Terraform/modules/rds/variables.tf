variable "mssql_secret_name" {
  type        = string
  description = "Name of the secret in Secrets Manager for MSSQL credentials"
}

variable "mssql_identifier" {
  type        = string
  description = "Identifier for the RDS MSSQL instance"
  default     = "memberships-mssql"
}

variable "mssql_engine_version" {
  type        = string
  description = "Engine version for SQL Server"
  default     = "15.00.4435.7.v1"
}

variable "mssql_allocated_storage" {
  type        = number
  description = "Allocated storage in GB"
  default     = 20
}

variable "mssql_instance_class" {
  type        = string
  description = "Instance class for MSSQL"
  default     = "db.t3.micro"
}

variable "mssql_subnet_group_name" {
  type        = string
  description = "Subnet group name for MSSQL RDS instance"
}

variable "mssql_sg_id" {
  type        = string
  description = "Security Group ID for MSSQL"
}

variable "ecliptix_control_id" {
  type        = string
  description = "ID of ecliptix-control instance"
}

variable "ecliptix_control_public_ip" {
  type        = string
  description = "Public IP of ecliptix-control instance"
}

variable "ecliptix_private_key" {
  type        = string
  description = "Private key for SSH connection to ecliptix-control"
  sensitive   = true
}
