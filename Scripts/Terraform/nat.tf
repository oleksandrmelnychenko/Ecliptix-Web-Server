resource "aws_eip" "nat" { }

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.ecliptix_public[0].id
  tags          = { Name = "ecliptix-nat-gateway" }
}
