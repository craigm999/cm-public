# --- Placement ----------------------------------------------------------------------

variable "resource_group_name" {
  description = "Existing resource group to deploy into."
  type        = string
}

variable "location" {
  description = "Azure region. Defaults to the resource group's region. Must support Flex Consumption."
  type        = string
  default     = null
}

variable "name_prefix" {
  description = "Short prefix used in resource names, e.g. 'idrpt'. Lowercase letters and digits."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9]{2,10}$", var.name_prefix))
    error_message = "name_prefix must be 2-10 lowercase letters or digits."
  }
}

variable "environment" {
  description = "Environment name used in resource names, e.g. 'prd'."
  type        = string
  default     = "prd"
  validation {
    condition     = can(regex("^[a-z0-9]{2,5}$", var.environment))
    error_message = "environment must be 2-5 lowercase letters or digits."
  }
}

variable "names" {
  description = "Optional overrides for resource names (storage account names must be globally unique)."
  type = object({
    function_app            = optional(string)
    service_plan            = optional(string)
    managed_identity        = optional(string)
    host_storage_account    = optional(string)
    reports_storage_account = optional(string)
    application_insights    = optional(string)
    log_analytics_workspace = optional(string)
  })
  default = {}
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default     = {}
}

# --- Network -------------------------------------------------------------------------

variable "virtual_network_name" {
  description = "Existing virtual network."
  type        = string
}

variable "virtual_network_resource_group_name" {
  description = "Resource group of the virtual network (defaults to resource_group_name)."
  type        = string
  default     = null
}

variable "private_endpoint_subnet_name" {
  description = "Existing (shared) subnet for the private endpoints."
  type        = string
}

variable "integration_subnet_name" {
  description = <<-EOT
    Existing subnet for the Function App's outbound VNet integration. It must be delegated to
    Microsoft.App/environments and not used for private endpoints, service endpoints or any
    other delegation (it can be shared with other Flex Consumption apps). /27 or larger.
    Set this OR integration_subnet_address_prefix.
  EOT
  type        = string
  default     = null
}

variable "integration_subnet_address_prefix" {
  description = "Address range for a new integration subnet to create in the VNet (e.g. 10.10.5.0/27). Set this OR integration_subnet_name."
  type        = string
  default     = null
}

variable "private_dns_zone_ids" {
  description = <<-EOT
    Resource IDs of the privatelink DNS zones to register the private endpoints in. Leave a zone
    null if your platform creates the records another way (e.g. Azure Policy in a hub).
  EOT
  type = object({
    blob  = optional(string) # privatelink.blob.core.windows.net
    queue = optional(string) # privatelink.queue.core.windows.net
    table = optional(string) # privatelink.table.core.windows.net
    sites = optional(string) # privatelink.azurewebsites.net
  })
  default = {}
}

# --- Sign-in -------------------------------------------------------------------------

variable "easy_auth_client_id" {
  description = "Application (client) ID of the Entra app registration used for sign-in (created by setup/Set-ReportingPrerequisites.ps1)."
  type        = string
}

variable "easy_auth_allowed_group_ids" {
  description = <<-EOT
    Optional extra check: object IDs of groups whose members may sign in. Requires the app
    registration to emit group claims. The primary control is 'assignment required' on the
    enterprise app with the reader group assigned (done by the setup script).
  EOT
  type        = list(string)
  default     = []
}

# --- Reports -------------------------------------------------------------------------

variable "report_tenant_id" {
  description = "Tenant to report on. Defaults to the tenant Terraform runs in."
  type        = string
  default     = null
}

variable "report_schedules" {
  description = "NCRONTAB schedules (UTC; Flex Consumption doesn't support time zones): {second} {minute} {hour} {day} {month} {day-of-week}."
  type = object({
    least_privilege    = optional(string, "0 0 2 * * *")  # daily 02:00
    azure_changes      = optional(string, "0 30 2 * * *") # daily 02:30
    app_signins        = optional(string, "0 0 4 * * 1")  # Mondays 04:00
    conditional_access = optional(string, "0 30 4 * * 1") # Mondays 04:30
    auth_methods       = optional(string, "0 0 3 * * *")  # daily 03:00
  })
  default = {}
}

variable "history_cool_after_days" {
  description = "Move dated report copies to the cool tier after this many days."
  type        = number
  default     = 30
}

variable "history_retention_days" {
  description = "Delete dated report copies after this many days."
  type        = number
  default     = 400
}

# --- Function App --------------------------------------------------------------------

variable "instance_memory_in_mb" {
  description = "Flex Consumption instance size: 512, 2048 or 4096."
  type        = number
  default     = 2048
}

variable "maximum_instance_count" {
  description = "Maximum on-demand instances."
  type        = number
  default     = 10
}

variable "storage_replication_type" {
  description = "Replication for both storage accounts."
  type        = string
  default     = "ZRS"
}

# --- Monitoring ----------------------------------------------------------------------

variable "log_analytics_workspace_id" {
  description = "Existing Log Analytics workspace for Application Insights. If null, one is created."
  type        = string
  default     = null
}

variable "log_retention_days" {
  description = "Retention for a created Log Analytics workspace."
  type        = number
  default     = 30
}
