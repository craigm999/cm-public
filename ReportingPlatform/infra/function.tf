resource "azurerm_service_plan" "reports" {
  name                = local.names.service_plan
  resource_group_name = data.azurerm_resource_group.this.name
  location            = local.location
  os_type             = "Linux"
  sku_name            = "FC1"
  tags                = local.tags
}

resource "azurerm_function_app_flex_consumption" "reports" {
  name                = local.names.function_app
  resource_group_name = data.azurerm_resource_group.this.name
  location            = local.location
  service_plan_id     = azurerm_service_plan.reports.id
  tags                = local.tags

  runtime_name           = "powershell"
  runtime_version        = "7.4"
  instance_memory_in_mb  = var.instance_memory_in_mb
  maximum_instance_count = var.maximum_instance_count

  # Deployment package storage, accessed with the managed identity (no keys).
  storage_container_type            = "blobContainer"
  storage_container_endpoint        = "${azurerm_storage_account.host.primary_blob_endpoint}${azurerm_storage_container.package.name}"
  storage_authentication_type       = "UserAssignedIdentity"
  storage_user_assigned_identity_id = azurerm_user_assigned_identity.reports.id

  # Private only: inbound through the private endpoint, outbound through the VNet.
  public_network_access_enabled                  = false
  virtual_network_subnet_id                      = local.integration_subnet_id
  https_only                                     = true
  webdeploy_publish_basic_authentication_enabled = false

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.reports.id]
  }

  site_config {
    application_insights_connection_string = azurerm_application_insights.this.connection_string
    minimum_tls_version                    = "1.2"
    scm_minimum_tls_version                = "1.2"
    http2_enabled                          = true
  }

  app_settings = {
    # Host storage with the managed identity
    "AzureWebJobsStorage__accountName" = azurerm_storage_account.host.name
    "AzureWebJobsStorage__credential"  = "managedidentity"
    "AzureWebJobsStorage__clientId"    = azurerm_user_assigned_identity.reports.client_id

    # Application Insights with Entra auth
    "APPLICATIONINSIGHTS_AUTHENTICATION_STRING" = "ClientId=${azurerm_user_assigned_identity.reports.client_id};Authorization=AAD"

    # Read by the ReportPlatform module
    "AZURE_CLIENT_ID"       = azurerm_user_assigned_identity.reports.client_id
    "REPORT_TENANT_ID"      = local.tenant_id
    "REPORTS_BLOB_ENDPOINT" = azurerm_storage_account.reports.primary_blob_endpoint
    "REPORTS_CONTAINER"     = azurerm_storage_container.reports.name

    # Timer schedules (function.json: "schedule": "%SCHEDULE_...%")
    "SCHEDULE_LEAST_PRIVILEGE"    = var.report_schedules.least_privilege
    "SCHEDULE_AZURE_CHANGES"      = var.report_schedules.azure_changes
    "SCHEDULE_APP_SIGNINS"        = var.report_schedules.app_signins
    "SCHEDULE_CONDITIONAL_ACCESS" = var.report_schedules.conditional_access
    "SCHEDULE_AUTH_METHODS"       = var.report_schedules.auth_methods
  }

  # App Service authentication (Easy Auth) with Entra ID. No client secret: sign-in uses the
  # ID token flow, so the app registration must allow ID tokens (the setup script does this).
  # Who can sign in is controlled by 'assignment required' on the enterprise app.
  auth_settings_v2 {
    auth_enabled           = true
    require_authentication = true
    require_https          = true
    unauthenticated_action = "RedirectToLoginPage"
    default_provider       = "azureactivedirectory"

    active_directory_v2 {
      client_id            = var.easy_auth_client_id
      tenant_auth_endpoint = "https://login.microsoftonline.com/${data.azurerm_client_config.current.tenant_id}/v2.0"
      allowed_audiences    = [var.easy_auth_client_id, "api://${var.easy_auth_client_id}"]
      allowed_groups       = length(var.easy_auth_allowed_group_ids) > 0 ? var.easy_auth_allowed_group_ids : null
    }

    login {
      token_store_enabled = false
    }
  }

  depends_on = [
    # The app needs its storage roles before it starts.
    azurerm_role_assignment.host_blob,
    azurerm_role_assignment.host_queue,
    azurerm_role_assignment.host_table,
  ]

  lifecycle {
    # The pipeline deploys code separately.
    ignore_changes = [zip_deploy_file, app_settings["WEBSITE_RUN_FROM_PACKAGE"]]
  }
}
