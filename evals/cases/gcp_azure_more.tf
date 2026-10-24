# expect: TG-GCP-SQL-001, TG-GCP-IAM-001, TG-GCP-GKE-001, TG-AZ-KV-001, TG-AZ-SQL-001, TG-AZ-AKS-001
resource "google_sql_database_instance" "db" {
  database_version = "POSTGRES_16"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled = true
      authorized_networks {
        name  = "anyone"
        value = "0.0.0.0/0"
      }
    }
  }
}
resource "google_project_iam_member" "dev" {
  project = "p"
  role    = "roles/owner"
  member  = "user:dev@example.com"
}
resource "google_container_cluster" "gke" {
  name     = "gke"
  location = "us-central1"
}
resource "azurerm_key_vault" "kv" {
  name                = "kv"
  resource_group_name = "rg"
  location            = "westeurope"
  tenant_id           = "t"
  sku_name            = "standard"
}
resource "azurerm_mssql_firewall_rule" "all" {
  name             = "all"
  server_id        = "s"
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"
}
resource "azurerm_kubernetes_cluster" "aks" {
  name = "aks"
}
