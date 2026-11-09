# Plan-level tests against a mocked azurerm provider (no Azure access needed):
#   terraform init -backend=false && terraform test

mock_provider "azurerm" {
  mock_data "azurerm_client_config" {
    defaults = { tenant_id = "11111111-1111-1111-1111-111111111111" }
  }
  mock_data "azurerm_resource_group" {
    defaults = { location = "uksouth", name = "rg-test" }
  }
  mock_data "azurerm_virtual_network" {
    defaults = { name = "vnet-test", resource_group_name = "rg-net" }
  }
  mock_data "azurerm_subnet" {
    defaults = { id = "/subscriptions/0000/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-test/subnets/existing" }
  }
}

variables {
  resource_group_name          = "rg-test"
  name_prefix                  = "idrpt"
  environment                  = "tst"
  virtual_network_name         = "vnet-test"
  private_endpoint_subnet_name = "snet-pe"
  easy_auth_client_id          = "22222222-2222-2222-2222-222222222222"
}

run "creates_integration_subnet_when_given_a_range" {
  command = plan
  variables {
    integration_subnet_address_prefix = "10.0.4.0/27"
  }
  assert {
    condition     = length(azurerm_subnet.integration) == 1 && azurerm_subnet.integration[0].delegation[0].service_delegation[0].name == "Microsoft.App/environments"
    error_message = "Expected a new integration subnet delegated to Microsoft.App/environments."
  }
  assert {
    condition     = length(azurerm_private_endpoint.this) == 5
    error_message = "Expected 5 private endpoints (host blob/queue/table, reports blob, function)."
  }
}

run "uses_existing_integration_subnet" {
  command = plan
  variables {
    integration_subnet_name = "snet-flex"
  }
  assert {
    condition     = length(azurerm_subnet.integration) == 0
    error_message = "No subnet should be created when an existing one is named."
  }
}

run "requires_an_integration_subnet" {
  command         = plan
  expect_failures = [azurerm_subnet.integration]
}

run "everything_is_private_and_keyless" {
  command = plan
  variables {
    integration_subnet_address_prefix = "10.0.4.0/27"
  }
  assert {
    condition     = azurerm_function_app_flex_consumption.reports.public_network_access_enabled == false
    error_message = "Function App must not be publicly reachable."
  }
  assert {
    condition = alltrue([for sa in [azurerm_storage_account.host, azurerm_storage_account.reports] :
    sa.public_network_access_enabled == false && sa.shared_access_key_enabled == false && sa.network_rules[0].default_action == "Deny"])
    error_message = "Storage accounts must be private and Entra-auth only."
  }
  assert {
    condition     = azurerm_function_app_flex_consumption.reports.storage_authentication_type == "UserAssignedIdentity"
    error_message = "Deployment storage must use the managed identity."
  }
  assert {
    condition     = azurerm_application_insights.this.local_authentication_enabled == false
    error_message = "App Insights must use Entra ingestion only."
  }
}

run "sign_in_is_required" {
  command = plan
  variables {
    integration_subnet_address_prefix = "10.0.4.0/27"
  }
  assert {
    condition = (azurerm_function_app_flex_consumption.reports.auth_settings_v2[0].require_authentication == true &&
      azurerm_function_app_flex_consumption.reports.auth_settings_v2[0].unauthenticated_action == "RedirectToLoginPage" &&
    azurerm_function_app_flex_consumption.reports.auth_settings_v2[0].active_directory_v2[0].client_id == var.easy_auth_client_id)
    error_message = "Entra sign-in must be required."
  }
}

run "dns_zone_groups_only_when_zones_given" {
  command = plan
  variables {
    integration_subnet_address_prefix = "10.0.4.0/27"
    private_dns_zone_ids = {
      blob = "/subscriptions/0000/resourceGroups/rg-dns/providers/Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net"
    }
  }
  assert {
    condition     = length(azurerm_private_endpoint.this["reports-blob"].private_dns_zone_group) == 1 && length(azurerm_private_endpoint.this["function"].private_dns_zone_group) == 0
    error_message = "Zone groups should only be created for zones that are supplied."
  }
}

run "schedules_reach_app_settings" {
  command = plan
  variables {
    integration_subnet_address_prefix = "10.0.4.0/27"
    report_schedules                  = { least_privilege = "0 15 1 * * *" }
  }
  assert {
    condition = (azurerm_function_app_flex_consumption.reports.app_settings["SCHEDULE_LEAST_PRIVILEGE"] == "0 15 1 * * *" &&
      azurerm_function_app_flex_consumption.reports.app_settings["SCHEDULE_AZURE_CHANGES"] == "0 30 2 * * *" &&
    azurerm_function_app_flex_consumption.reports.app_settings["SCHEDULE_AUTH_METHODS"] == "0 0 3 * * *")
    error_message = "Schedule overrides and defaults should both reach the app settings."
  }
}

run "storage_names_are_valid" {
  command = plan
  variables {
    integration_subnet_address_prefix = "10.0.4.0/27"
  }
  assert {
    condition = alltrue([for n in [azurerm_storage_account.host.name, azurerm_storage_account.reports.name] :
    can(regex("^[a-z0-9]{3,24}$", n))])
    error_message = "Generated storage account names must be 3-24 lowercase letters/digits."
  }
}
