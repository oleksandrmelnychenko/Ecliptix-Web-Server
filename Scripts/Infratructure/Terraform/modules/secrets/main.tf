data "aws_secretsmanager_secret" "memberships_mssql" {
  name = var.memberships_secret_name
}

data "aws_secretsmanager_secret_version" "memberships_mssql" {
  secret_id = data.aws_secretsmanager_secret.memberships_mssql.id
}
locals {
  db_credentials = jsondecode(data.aws_secretsmanager_secret_version.memberships_mssql.secret_string)
}
