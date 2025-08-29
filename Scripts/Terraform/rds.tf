# --- Take exist secret --- 

data "aws_secretsmanager_secret" "memberships_mssql" {
  name = "prod/ecliptix/memberships/mssql"
}

# --- Take actual secret version ---

data "aws_secretsmanager_secret_version" "memberships_mssql" {
  secret_id = data.aws_secretsmanager_secret.memberships_mssql.id
}

locals {
  db_credentials = jsondecode(data.aws_secretsmanager_secret_version.memberships_mssql.secret_string)
}

# --- Create RDS MSSQL with secret ---

resource "aws_db_instance" "memberships_mssql" {
  identifier        = "memberships-mssql"
  engine            = "sqlserver-ex"
  engine_version    = "15.00.4435.7.v1"  
  allocated_storage = 20
  instance_class    = "db.t3.micro" 

  username = local.db_credentials["username"]
  password = local.db_credentials["password"]

  db_subnet_group_name   = aws_db_subnet_group.memberships_mssql.name
  vpc_security_group_ids = [aws_security_group.mssql_sg.id]

  multi_az            = false
  publicly_accessible = false
  skip_final_snapshot = true
}

# --- Create memberships db manually ---

resource "null_resource" "memberships_create_db" {
  depends_on = [aws_instance.ecliptix_control, aws_db_instance.memberships_mssql]

  connection {
    type        = "ssh"
    host        = aws_instance.ecliptix_control.public_ip
    user        = "ubuntu"
    private_key = tls_private_key.ecliptix_key.private_key_openssh
  }

  provisioner "remote-exec" {
    inline = [
      "export PATH=$PATH:/opt/mssql-tools/bin",
      "sqlcmd -S ${aws_db_instance.memberships_mssql.address} -U ${local.db_credentials.username} -P ${local.db_credentials.password} -C -Q 'CREATE DATABASE memberships'"
    ]
  }
}
