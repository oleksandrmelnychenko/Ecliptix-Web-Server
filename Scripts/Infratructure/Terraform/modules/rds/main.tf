# --- Take existing secret from AWS Secrets Manager ---

data "aws_secretsmanager_secret" "ecliptix_mssql" {
  name = var.mssql_secret_name
}

# --- Take actual secret version ---

data "aws_secretsmanager_secret_version" "ecliptix_mssql" {
  secret_id = data.aws_secretsmanager_secret.ecliptix_mssql.id
}

# --- Decode credentials ---

locals {
  db_credentials = jsondecode(data.aws_secretsmanager_secret_version.ecliptix_mssql.secret_string)
}

# --- Create RDS MSSQL Instance ---

resource "aws_db_instance" "ecliptix_mssql" {
  identifier             = var.mssql_identifier
  engine                 = "sqlserver-ex"
  engine_version         = var.mssql_engine_version
  allocated_storage      = var.mssql_allocated_storage
  instance_class         = var.mssql_instance_class
  
  username               = local.db_credentials["username"]
  password               = local.db_credentials["password"]

  db_subnet_group_name   = var.mssql_subnet_group_name
  vpc_security_group_ids = [var.mssql_sg_id]

  multi_az               = false
  publicly_accessible    = false
  skip_final_snapshot    = true
}
