data "azurerm_client_config" "current" {}

data "azurerm_resource_group" "this" {
  name = var.resource_group_name
}

locals {
  location  = coalesce(var.location, data.azurerm_resource_group.this.location)
  base      = "${var.name_prefix}-${var.environment}"
  compact   = "${var.name_prefix}${var.environment}"
  tenant_id = coalesce(var.report_tenant_id, data.azurerm_client_config.current.tenant_id)
  tags      = merge({ workload = "identity-azure-reporting" }, var.tags)

  names = {
    function_app            = coalesce(var.names.function_app, "func-${local.base}-reports")
    service_plan            = coalesce(var.names.service_plan, "asp-${local.base}-reports")
    managed_identity        = coalesce(var.names.managed_identity, "id-${local.base}-reports")
    host_storage_account    = coalesce(var.names.host_storage_account, substr("st${local.compact}rptfn", 0, 24))
    reports_storage_account = coalesce(var.names.reports_storage_account, substr("st${local.compact}rptdata", 0, 24))
    application_insights    = coalesce(var.names.application_insights, "appi-${local.base}-reports")
    log_analytics_workspace = coalesce(var.names.log_analytics_workspace, "log-${local.base}-reports")
  }

  reports_container = "reports"
  package_container = "app-package"
}

# The identity everything runs as: report jobs (Graph + ARM), storage access, App Insights.
resource "azurerm_user_assigned_identity" "reports" {
  name                = local.names.managed_identity
  resource_group_name = data.azurerm_resource_group.this.name
  location            = local.location
  tags                = local.tags
}
