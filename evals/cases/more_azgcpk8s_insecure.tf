# expect: TG-AZ-ST-003, TG-AZ-ST-004, TG-AZ-ST-005, TG-AZ-KV-002, TG-AZ-SQL-002, TG-AZ-DB-002, TG-AZ-COSMOS-001, TG-AZ-REDIS-001, TG-AZ-ACR-002, TG-AZ-AKS-002, TG-AZ-IAM-001, TG-AZ-MSG-001, TG-GCP-GKE-002, TG-GCP-GKE-003, TG-GCP-GKE-004, TG-GCP-SQL-002, TG-GCP-SQL-003, TG-GCP-GCS-002, TG-GCP-VM-003, TG-GCP-VM-004, TG-GCP-IAM-002, TG-GCP-IAM-003, TG-GCP-IAM-004, TG-GCP-IAM-005, TG-GCP-LB-001, TG-GCP-REDIS-001, TG-K8S-004, TG-K8S-005, TG-K8S-006, TG-K8S-007, TG-K8S-008
resource "azurerm_storage_account" "st" {
  name          = "st"
  network_rules {
    default_action = "Allow"
  }
}
resource "azurerm_storage_container" "c" {
  name                  = "c"
  container_access_type = "blob"
}
resource "azurerm_key_vault" "kv" {
  name                     = "kv"
  purge_protection_enabled = true
}
resource "azurerm_mssql_server" "sql" {
  name                          = "sql"
  minimum_tls_version           = "1.2"
  public_network_access_enabled = true
}
resource "azurerm_postgresql_flexible_server" "pg" {
  name                          = "pg"
  public_network_access_enabled = true
}
resource "azurerm_cosmosdb_account" "cosmos" {
  name                         = "cosmos"
  local_authentication_enabled = true
}
resource "azurerm_redis_cache" "r" {
  name                 = "r"
  non_ssl_port_enabled = true
}
resource "azurerm_container_registry" "acr" {
  name                   = "acr"
  admin_enabled          = false
  anonymous_pull_enabled = true
}
resource "azurerm_kubernetes_cluster" "aks" {
  name                    = "aks"
  private_cluster_enabled = true
  role_based_access_control_enabled = true
}
resource "azurerm_role_definition" "god" {
  name  = "god"
  scope = "/subscriptions/0000"
  permissions {
    actions = ["*"]
  }
}
resource "azurerm_servicebus_namespace" "sb" {
  name = "sb"
}
resource "google_container_cluster" "gke" {
  name                  = "gke"
  enable_shielded_nodes = false
  logging_service       = "none"
  master_auth {
    client_certificate_config {
      issue_client_certificate = true
    }
  }
  node_config {
    workload_metadata_config {
      mode = "GCE_METADATA"
    }
  }
}
resource "google_sql_database_instance" "sql" {
  name             = "sql"
  database_version = "MYSQL_8_0"
  settings {
    tier = "db-f1-micro"
    database_flags {
      name  = "local_infile"
      value = "on"
    }
  }
}
resource "google_storage_bucket" "b" {
  name     = "b"
  location = "EU"
  uniform_bucket_level_access = true
}
resource "google_compute_instance" "vm" {
  name         = "vm"
  machine_type = "e2-small"
  metadata = {
    enable-oslogin = "FALSE"
  }
  network_interface {
    network = "default"
    access_config {}
  }
}
resource "google_project_iam_member" "impersonate" {
  project = "p"
  role    = "roles/iam.serviceAccountTokenCreator"
  member  = "group:devs@example.com"
}
resource "google_project_iam_member" "sa_admin" {
  project = "p"
  role    = "roles/storage.admin"
  member  = "serviceAccount:app@p.iam.gserviceaccount.com"
}
resource "google_secret_manager_secret_iam_member" "pub" {
  secret_id = "s"
  role      = "roles/secretmanager.secretAccessor"
  member    = "allUsers"
}
resource "google_iam_workload_identity_pool_provider" "gh" {
  workload_identity_pool_id          = "pool"
  workload_identity_pool_provider_id = "gh"
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}
resource "google_compute_ssl_policy" "old" {
  name = "old"
}
resource "google_redis_instance" "cache" {
  name           = "cache"
  memory_size_gb = 1
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
        container {
          name  = "app"
          image = "app:1.0"
          security_context {
            capabilities {
              add = ["SYS_ADMIN"]
            }
          }
        }
        volume {
          name = "sock"
          host_path {
            path = "/var/run/docker.sock"
          }
        }
      }
    }
  }
}
resource "kubernetes_cluster_role_binding_v1" "anon" {
  metadata {
    name = "anon"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "view"
  }
  subject {
    kind = "User"
    name = "system:anonymous"
  }
}
resource "kubernetes_cluster_role_v1" "all" {
  metadata {
    name = "all"
  }
  rule {
    api_groups = ["*"]
    resources  = ["*"]
    verbs      = ["*"]
  }
}
