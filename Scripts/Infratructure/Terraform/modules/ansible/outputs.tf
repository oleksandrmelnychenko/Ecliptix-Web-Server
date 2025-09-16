output "inventory_file" {
  value = local_file.ansible_inventory.filename
}


output "vars_file" {
  value = local_file.ansible_vars.filename
}
