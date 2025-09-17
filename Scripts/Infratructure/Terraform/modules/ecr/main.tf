resource "aws_ecr_repository" "memberships" {
  name                 = var.memberships_repo_name
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}
