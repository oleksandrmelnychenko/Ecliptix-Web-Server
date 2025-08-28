# --- Take exist secret --- 

data "aws_secretsmanager_secret" "memberships_mssql" {
  name = "prod/ecliptix/memberships/mssql"
}

# --- Take actual secret version ---

data "aws_secretsmanager_secret_version" "memberships_mssql" {
  secret_id = data.aws_secretsmanager_secret.memberships_mssql.id
}

# --- Create RDS MSSQL with secret ---

resource "aws_db_instance" "memberships_mssql" {
  identifier        = "memberships-mssql"
  engine            = "sqlserver-ex"
  engine_version    = "15.00.4435.7.v1"  
  allocated_storage = 20
  instance_class    = "db.t3.micro" 

  username = jsondecode(data.aws_secretsmanager_secret_version.memberships_mssql.secret_string)["username"]
  password = jsondecode(data.aws_secretsmanager_secret_version.memberships_mssql.secret_string)["password"]

  db_subnet_group_name   = aws_db_subnet_group.memberships_mssql.name
  vpc_security_group_ids = [aws_security_group.mssql_sg.id]

  multi_az            = false
  publicly_accessible = false
  skip_final_snapshot = true
}
