terraform {
  required_version = ">= 1.9.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.40"
    }
  }

  # Partial configuration: the pipeline supplies resource_group_name, storage_account_name,
  # container_name and key with -backend-config (see backend.hcl.example).
  backend "azurerm" {
    use_azuread_auth = true
  }
}

provider "azurerm" {
  # Resource providers are registered once by a subscription owner (see README), so the
  # pipeline identity doesn't need subscription-wide registration rights.
  resource_provider_registrations = "none"
  storage_use_azuread             = true

  features {
    storage {
      # Storage accounts have public network access disabled; don't let the provider try
      # data-plane calls while creating them. Containers are created through ARM.
      data_plane_available = false
    }
  }
}
