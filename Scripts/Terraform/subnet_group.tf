resource "aws_db_subnet_group" "mssql" {
  name       = "mssql-subnet-group"
  subnet_ids = aws_subnet.ecliptix_private[*].id
  tags       = { Name = "mssql-subnet-group" }
}
