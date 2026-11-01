# forbid: TG-AZ-ST-003, TG-AZ-ST-004, TG-AZ-ST-005, TG-AZ-KV-002, TG-AZ-SQL-002, TG-AZ-DB-002, TG-AZ-COSMOS-001, TG-AZ-REDIS-001, TG-AZ-ACR-002, TG-AZ-AKS-002, TG-AZ-IAM-001, TG-AZ-MSG-001, TG-GCP-GKE-002, TG-GCP-GKE-003, TG-GCP-GKE-004, TG-GCP-SQL-002, TG-GCP-SQL-003, TG-GCP-GCS-002, TG-GCP-VM-003, TG-GCP-VM-004, TG-GCP-IAM-002, TG-GCP-IAM-003, TG-GCP-IAM-004, TG-GCP-IAM-005, TG-GCP-LB-001, TG-GCP-REDIS-001, TG-K8S-004, TG-K8S-005, TG-K8S-006, TG-K8S-007, TG-K8S-008
resource "azurerm_storage_account" "st" {
  name                      = "st"
  shared_access_key_enabled = false
  network_rules {
    default_action = "Deny"
  }
}
resource "azurerm_storage_container" "c" {
  name                  = "c"
  container_access_type = "private"
}
resource "azurerm_key_vault" "kv" {
  name                     = "kv"
  purge_protection_enabled = true
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
}
resource "azurerm_mssql_server" "sql" {
  name                          = "sql"
  minimum_tls_version           = "1.2"
  public_network_access_enabled = false
  azuread_administrator {
    login_username = "admins"
    object_id      = "0000"
  }
}
resource "azurerm_postgresql_flexible_server" "pg" {
  name                          = "pg"
  delegated_subnet_id           = "subnet-id"
  public_network_access_enabled = false
}
resource "azurerm_cosmosdb_account" "cosmos" {
  name                              = "cosmos"
  public_network_access_enabled     = false
  local_authentication_enabled      = false
}
resource "azurerm_redis_cache" "r" {
  name                 = "r"
  non_ssl_port_enabled = false
}
resource "azurerm_container_registry" "acr" {
  name                   = "acr"
  admin_enabled          = false
  anonymous_pull_enabled = false
}
resource "azurerm_kubernetes_cluster" "aks" {
  name                   = "aks"
  local_account_disabled = true
  network_profile {
    network_plugin = "azure"
    network_policy = "azure"
  }
}
resource "azurerm_role_definition" "reader" {
  name  = "reader"
  scope = "/subscriptions/0000"
  permissions {
    actions = ["Microsoft.Storage/storageAccounts/read"]
  }
}
resource "azurerm_servicebus_namespace" "sb" {
  name               = "sb"
  local_auth_enabled = false
}
resource "google_container_cluster" "gke" {
  name = "gke"
  workload_identity_config {
    workload_pool = "p.svc.id.goog"
  }
  private_cluster_config {
    enable_private_nodes = true
  }
  node_config {
    workload_metadata_config {
      mode = "GKE_METADATA"
    }
  }
}
resource "google_sql_database_instance" "sql" {
  name             = "sql"
  database_version = "MYSQL_8_0"
  settings {
    tier = "db-f1-micro"
    backup_configuration {
      enabled = true
    }
    database_flags {
      name  = "local_infile"
      value = "off"
    }
  }
}
resource "google_storage_bucket" "b" {
  name                        = "b"
  location                    = "EU"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
}
resource "google_compute_instance" "vm" {
  name         = "vm"
  machine_type = "e2-small"
  metadata = {
    enable-oslogin         = "TRUE"
    block-project-ssh-keys = "true"
  }
  network_interface {
    network = "default"
  }
}
resource "google_project_iam_member" "viewer" {
  project = "p"
  role    = "roles/viewer"
  member  = "group:devs@example.com"
}
resource "google_secret_manager_secret_iam_member" "app" {
  secret_id = "s"
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:app@p.iam.gserviceaccount.com"
}
resource "google_iam_workload_identity_pool_provider" "gh" {
  workload_identity_pool_id          = "pool"
  workload_identity_pool_provider_id = "gh"
  attribute_condition                = "assertion.repository == 'acme/infra'"
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}
resource "google_compute_ssl_policy" "modern" {
  name            = "modern"
  profile         = "MODERN"
  min_tls_version = "TLS_1_2"
}
resource "google_redis_instance" "cache" {
  name                    = "cache"
  memory_size_gb          = 1
  auth_enabled            = true
  transit_encryption_mode = "SERVER_AUTHENTICATION"
}
resource "kubernetes_deployment_v1" "app" {
  metadata {
    name = "app"
  }
  spec {
    template {
      metadata {
        name = "app"
      }
      spec {
        security_context {
          run_as_non_root = true
        }
        container {
          name  = "app"
          image = "app:1.0"
          security_context {
            capabilities {
              drop = ["ALL"]
            }
          }
        }
      }
    }
  }
}
resource "kubernetes_role_binding_v1" "ok" {
  metadata {
    name = "ok"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = "deployer"
  }
  subject {
    kind = "Group"
    name = "deployers"
  }
}
resource "kubernetes_role_v1" "deployer" {
  metadata {
    name = "deployer"
  }
  rule {
    api_groups = ["apps"]
    resources  = ["deployments"]
    verbs      = ["get", "list", "patch"]
  }
}
