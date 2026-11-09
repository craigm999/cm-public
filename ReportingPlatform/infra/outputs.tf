output "function_app_name" {
  value = azurerm_function_app_flex_consumption.reports.name
}

output "function_app_hostname" {
  description = "Portal address (resolves privately via privatelink.azurewebsites.net)."
  value       = azurerm_function_app_flex_consumption.reports.default_hostname
}

output "managed_identity_name" {
  value = azurerm_user_assigned_identity.reports.name
}

output "managed_identity_client_id" {
  value = azurerm_user_assigned_identity.reports.client_id
}

output "managed_identity_principal_id" {
  description = "Grant Graph permissions and Azure Reader to this (setup script, -Stage Permissions)."
  value       = azurerm_user_assigned_identity.reports.principal_id
}

output "reports_storage_account_name" {
  value = azurerm_storage_account.reports.name
}

output "resource_group_name" {
  value = data.azurerm_resource_group.this.name
}
