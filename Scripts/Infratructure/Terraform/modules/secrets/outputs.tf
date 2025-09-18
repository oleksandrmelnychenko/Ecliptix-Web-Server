output "memberships_username" {
  value     = local.db_credentials["username"]
  sensitive = true
}

output "memberships_password" {
  value     = local.db_credentials["password"]
  sensitive = true
}
