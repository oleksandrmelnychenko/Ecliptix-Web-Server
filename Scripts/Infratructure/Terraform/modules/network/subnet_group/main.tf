resource "aws_db_subnet_group" "mssql" {
  name       = var.memberships_subnet_group_name
  subnet_ids = var.private_subnet_ids
  tags       = merge(var.tags, { Name = "${var.tags["project"]}-${var.tags["env"]}-mssql-subnet-group" })
}
