resource "azurerm_log_analytics_workspace" "this" {
  count               = var.log_analytics_workspace_id == null ? 1 : 0
  name                = local.names.log_analytics_workspace
  resource_group_name = data.azurerm_resource_group.this.name
  location            = local.location
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
  tags                = local.tags
}

# Entra-only ingestion (no instrumentation-key auth). The Function App sends telemetry
# with its managed identity (Monitoring Metrics Publisher, see rbac.tf).
resource "azurerm_application_insights" "this" {
  name                         = local.names.application_insights
  resource_group_name          = data.azurerm_resource_group.this.name
  location                     = local.location
  application_type             = "other"
  workspace_id                 = coalesce(var.log_analytics_workspace_id, try(azurerm_log_analytics_workspace.this[0].id, null))
  local_authentication_enabled = false
  tags                         = local.tags
}
