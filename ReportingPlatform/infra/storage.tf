# Two accounts: one for the Function App itself (deployment package, host state), one for
# report data. Both: Entra auth only, no public network access, private endpoints only.

locals {
  storage_common = {
    account_tier                      = "Standard"
    account_kind                      = "StorageV2"
    https_traffic_only_enabled        = true
    min_tls_version                   = "TLS1_2"
    shared_access_key_enabled         = false
    default_to_oauth_authentication   = true
    public_network_access_enabled     = false
    allow_nested_items_to_be_public   = false
    cross_tenant_replication_enabled  = false
    infrastructure_encryption_enabled = true
    local_user_enabled                = false
    sftp_enabled                      = false
    allowed_copy_scope                = "PrivateLink"
  }
}

resource "azurerm_storage_account" "host" {
  name                              = local.names.host_storage_account
  resource_group_name               = data.azurerm_resource_group.this.name
  location                          = local.location
  account_replication_type          = var.storage_replication_type
  account_tier                      = local.storage_common.account_tier
  account_kind                      = local.storage_common.account_kind
  https_traffic_only_enabled        = local.storage_common.https_traffic_only_enabled
  min_tls_version                   = local.storage_common.min_tls_version
  shared_access_key_enabled         = local.storage_common.shared_access_key_enabled
  default_to_oauth_authentication   = local.storage_common.default_to_oauth_authentication
  public_network_access_enabled     = local.storage_common.public_network_access_enabled
  allow_nested_items_to_be_public   = local.storage_common.allow_nested_items_to_be_public
  cross_tenant_replication_enabled  = local.storage_common.cross_tenant_replication_enabled
  infrastructure_encryption_enabled = local.storage_common.infrastructure_encryption_enabled
  local_user_enabled                = local.storage_common.local_user_enabled
  sftp_enabled                      = local.storage_common.sftp_enabled
  allowed_copy_scope                = local.storage_common.allowed_copy_scope
  tags                              = local.tags

  network_rules {
    default_action = "Deny"
    bypass         = ["None"]
  }
}

resource "azurerm_storage_container" "package" {
  name                  = local.package_container
  storage_account_id    = azurerm_storage_account.host.id
  container_access_type = "private"
}

resource "azurerm_storage_account" "reports" {
  name                              = local.names.reports_storage_account
  resource_group_name               = data.azurerm_resource_group.this.name
  location                          = local.location
  account_replication_type          = var.storage_replication_type
  account_tier                      = local.storage_common.account_tier
  account_kind                      = local.storage_common.account_kind
  https_traffic_only_enabled        = local.storage_common.https_traffic_only_enabled
  min_tls_version                   = local.storage_common.min_tls_version
  shared_access_key_enabled         = local.storage_common.shared_access_key_enabled
  default_to_oauth_authentication   = local.storage_common.default_to_oauth_authentication
  public_network_access_enabled     = local.storage_common.public_network_access_enabled
  allow_nested_items_to_be_public   = local.storage_common.allow_nested_items_to_be_public
  cross_tenant_replication_enabled  = local.storage_common.cross_tenant_replication_enabled
  infrastructure_encryption_enabled = local.storage_common.infrastructure_encryption_enabled
  local_user_enabled                = local.storage_common.local_user_enabled
  sftp_enabled                      = local.storage_common.sftp_enabled
  allowed_copy_scope                = local.storage_common.allowed_copy_scope
  tags                              = local.tags

  blob_properties {
    versioning_enabled = true
    delete_retention_policy {
      days = 14
    }
    container_delete_retention_policy {
      days = 14
    }
  }

  network_rules {
    default_action = "Deny"
    bypass         = ["None"]
  }
}

resource "azurerm_storage_container" "reports" {
  name                  = local.reports_container
  storage_account_id    = azurerm_storage_account.reports.id
  container_access_type = "private"
}

# Dated copies: cool after N days, delete after the retention period. Old versions of
# latest/ and status/ blobs are cleaned up after 30 days.
resource "azurerm_storage_management_policy" "reports" {
  storage_account_id = azurerm_storage_account.reports.id

  rule {
    name    = "report-history"
    enabled = true
    filters {
      blob_types   = ["blockBlob"]
      prefix_match = ["${local.reports_container}/history/"]
    }
    actions {
      base_blob {
        tier_to_cool_after_days_since_modification_greater_than = var.history_cool_after_days
        delete_after_days_since_modification_greater_than       = var.history_retention_days
      }
      version {
        delete_after_days_since_creation = 30
      }
    }
  }

  rule {
    name    = "old-versions"
    enabled = true
    filters {
      blob_types   = ["blockBlob"]
      prefix_match = ["${local.reports_container}/latest/", "${local.reports_container}/status/"]
    }
    actions {
      version {
        delete_after_days_since_creation = 30
      }
    }
  }
}
