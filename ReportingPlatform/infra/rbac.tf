# Managed identity -> the storage and monitoring it needs, nothing more.
# Graph application permissions and Azure Reader at the management group are granted
# separately by setup/Set-ReportingPrerequisites.ps1 (needs privileged roles the pipeline
# shouldn't hold).

resource "azurerm_role_assignment" "host_blob" {
  scope                = azurerm_storage_account.host.id
  role_definition_name = "Storage Blob Data Owner"
  principal_id         = azurerm_user_assigned_identity.reports.principal_id
  principal_type       = "ServicePrincipal"
}

resource "azurerm_role_assignment" "host_queue" {
  scope                = azurerm_storage_account.host.id
  role_definition_name = "Storage Queue Data Contributor"
  principal_id         = azurerm_user_assigned_identity.reports.principal_id
  principal_type       = "ServicePrincipal"
}

resource "azurerm_role_assignment" "host_table" {
  scope                = azurerm_storage_account.host.id
  role_definition_name = "Storage Table Data Contributor"
  principal_id         = azurerm_user_assigned_identity.reports.principal_id
  principal_type       = "ServicePrincipal"
}

# Report data: read/write on the reports container only.
resource "azurerm_role_assignment" "reports_container" {
  scope                = azurerm_storage_container.reports.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.reports.principal_id
  principal_type       = "ServicePrincipal"
}

resource "azurerm_role_assignment" "app_insights" {
  scope                = azurerm_application_insights.this.id
  role_definition_name = "Monitoring Metrics Publisher"
  principal_id         = azurerm_user_assigned_identity.reports.principal_id
  principal_type       = "ServicePrincipal"
}
