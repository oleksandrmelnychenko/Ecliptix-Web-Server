resource "aws_db_subnet_group" "memberships_mssql" {
  name       = "mssql-subnet-group"
  subnet_ids = aws_subnet.ecliptix_private[*].id
  tags       = { Name = "memberships-mssql-subnet-group" }
}
