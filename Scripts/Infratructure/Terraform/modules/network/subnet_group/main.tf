resource "aws_db_subnet_group" "mssql" {
  name       = "mssql-subnet-group"
  subnet_ids = var.private_subnet_ids
  tags       = { Name = "mssql-subnet-group" }
}
