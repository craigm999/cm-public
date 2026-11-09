data "azurerm_virtual_network" "this" {
  name                = var.virtual_network_name
  resource_group_name = coalesce(var.virtual_network_resource_group_name, var.resource_group_name)
}

data "azurerm_subnet" "private_endpoints" {
  name                 = var.private_endpoint_subnet_name
  virtual_network_name = data.azurerm_virtual_network.this.name
  resource_group_name  = data.azurerm_virtual_network.this.resource_group_name
}

# Outbound VNet integration subnet: use an existing delegated subnet, or create one.
data "azurerm_subnet" "integration" {
  count                = var.integration_subnet_name != null ? 1 : 0
  name                 = var.integration_subnet_name
  virtual_network_name = data.azurerm_virtual_network.this.name
  resource_group_name  = data.azurerm_virtual_network.this.resource_group_name
}

resource "azurerm_subnet" "integration" {
  count                = var.integration_subnet_name == null ? 1 : 0
  name                 = "snet-${local.base}-reports-func"
  virtual_network_name = data.azurerm_virtual_network.this.name
  resource_group_name  = data.azurerm_virtual_network.this.resource_group_name
  address_prefixes     = [var.integration_subnet_address_prefix]

  delegation {
    name = "flex-consumption"
    service_delegation {
      name    = "Microsoft.App/environments"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }

  lifecycle {
    precondition {
      condition     = var.integration_subnet_address_prefix != null
      error_message = "Set integration_subnet_name (existing delegated subnet) or integration_subnet_address_prefix (create one)."
    }
  }
}

locals {
  integration_subnet_id = var.integration_subnet_name != null ? data.azurerm_subnet.integration[0].id : azurerm_subnet.integration[0].id

  # Private endpoints: one per target sub-resource.
  private_endpoints = {
    host-blob    = { resource_id = azurerm_storage_account.host.id, subresource = "blob", zone = var.private_dns_zone_ids.blob }
    host-queue   = { resource_id = azurerm_storage_account.host.id, subresource = "queue", zone = var.private_dns_zone_ids.queue }
    host-table   = { resource_id = azurerm_storage_account.host.id, subresource = "table", zone = var.private_dns_zone_ids.table }
    reports-blob = { resource_id = azurerm_storage_account.reports.id, subresource = "blob", zone = var.private_dns_zone_ids.blob }
    function     = { resource_id = azurerm_function_app_flex_consumption.reports.id, subresource = "sites", zone = var.private_dns_zone_ids.sites }
  }
}

resource "azurerm_private_endpoint" "this" {
  for_each            = local.private_endpoints
  name                = "pe-${local.base}-reports-${each.key}"
  resource_group_name = data.azurerm_resource_group.this.name
  location            = local.location
  subnet_id           = data.azurerm_subnet.private_endpoints.id
  tags                = local.tags

  private_service_connection {
    name                           = "psc-${each.key}"
    private_connection_resource_id = each.value.resource_id
    subresource_names              = [each.value.subresource]
    is_manual_connection           = false
  }

  dynamic "private_dns_zone_group" {
    for_each = each.value.zone != null ? [each.value.zone] : []
    content {
      name                 = "default"
      private_dns_zone_ids = [private_dns_zone_group.value]
    }
  }

  # Platforms that create DNS records through Azure Policy add the zone group themselves.
  lifecycle {
    ignore_changes = [private_dns_zone_group]
  }
}
