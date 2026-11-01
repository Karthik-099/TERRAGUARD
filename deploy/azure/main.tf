# TerraGuard on Azure: Container Apps in an internal environment (VNet only,
# no public endpoint), with the AI key kept as a Container Apps secret.
terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 4.0" }
  }
}

provider "azurerm" {
  features {}
}

variable "name" {
  type        = string
  description = "Name prefix for all resources."
  default     = "terraguard"
}

variable "resource_group_name" {
  type        = string
  description = "Existing resource group."
}

variable "location" {
  type        = string
  description = "Azure region."
}

variable "infrastructure_subnet_id" {
  type        = string
  description = "Dedicated VNet subnet (/23 or larger) for the Container Apps environment."
}

variable "image" {
  type        = string
  description = "Container image. Mirror it into Azure Container Registry for fully private pulls."
  default     = "ghcr.io/karthik-099/terraguard:latest"
}

variable "ai_api_key" {
  type        = string
  description = "Optional AI key (Azure OpenAI or another provider). Empty = no AI."
  default     = ""
  sensitive   = true
}

resource "azurerm_log_analytics_workspace" "this" {
  name                = "${var.name}-logs"
  resource_group_name = var.resource_group_name
  location            = var.location
  retention_in_days   = 90
}

resource "azurerm_container_app_environment" "this" {
  name                           = "${var.name}-env"
  resource_group_name            = var.resource_group_name
  location                       = var.location
  log_analytics_workspace_id     = azurerm_log_analytics_workspace.this.id
  infrastructure_subnet_id       = var.infrastructure_subnet_id
  internal_load_balancer_enabled = true
}

resource "azurerm_container_app" "this" {
  name                         = var.name
  resource_group_name          = var.resource_group_name
  container_app_environment_id = azurerm_container_app_environment.this.id
  revision_mode                = "Single"

  dynamic "secret" {
    for_each = var.ai_api_key == "" ? [] : [var.ai_api_key]
    content {
      name  = "ai-key"
      value = secret.value
    }
  }

  ingress {
    external_enabled = false
    target_port      = 8080
    transport        = "http"
    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  template {
    min_replicas = 1
    max_replicas = 3
    container {
      name    = "terraguard"
      image   = var.image
      cpu     = 0.5
      memory  = "1Gi"
      command = ["terraguard", "serve", "--addr", "0.0.0.0:8080"]
      env {
        name  = "TERRAGUARD_TRUST_PROXY"
        value = "true"
      }
      liveness_probe {
        transport = "HTTP"
        port      = 8080
        path      = "/healthz"
      }
    }
  }
}

output "internal_fqdn" {
  value       = azurerm_container_app.this.ingress[0].fqdn
  description = "Private FQDN, resolvable inside the VNet."
}
