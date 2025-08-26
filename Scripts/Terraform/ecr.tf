resource "aws_ecr_repository" "memberships" {
  name                 = "ecliptix/memberships"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}
