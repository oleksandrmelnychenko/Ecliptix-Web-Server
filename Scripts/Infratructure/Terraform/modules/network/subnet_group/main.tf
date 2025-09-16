resource "aws_db_subnet_group" "mssql" {
  name       = "mssql-subnet-group"
  subnet_ids = var.private_subnet_ids
  tags       = merge(var.tags, { Name = "${var.tags["project"]}-${var.tags["env"]}-mssql-subnet-group" })
}
