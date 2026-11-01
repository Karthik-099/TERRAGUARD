# forbid: TG-AWS-CACHE-002, TG-AWS-ECS-004, TG-AWS-ECS-005, TG-AWS-EKS-003, TG-AWS-TRANSFER-002, TG-AWS-EVB-001, TG-AWS-ELB-001, TG-AZ-APIM-001, TG-AZ-NSG-002, TG-GCP-IAM-006, TG-GCP-ORG-001, TG-GCP-GKE-005, TG-ALI-RDS-001, TG-K8S-009, TG-K8S-010, TG-K8S-012, TG-K8S-015, TG-K8S-016, TG-K8S-017
resource "aws_elasticache_replication_group" "r" {
  replication_group_id = "r"
  description          = "r"
  engine               = "redis"
  user_group_ids       = ["app-users"]
}
resource "aws_ecs_task_definition" "t" {
  family = "t"
  container_definitions = jsonencode([{ name = "app", image = "app:1.0", readonlyRootFilesystem = true }])
  volume {
    name = "data"
    efs_volume_configuration {
      file_system_id     = "fs-1"
      transit_encryption = "ENABLED"
    }
  }
}
resource "aws_eks_node_group" "ng" {
  cluster_name  = "c"
  node_role_arn = "arn:aws:iam::1:role/n"
  subnet_ids    = ["subnet-1"]
  remote_access {
    ec2_ssh_key               = "ops"
    source_security_group_ids = ["sg-bastion"]
  }
}
resource "aws_transfer_server" "sftp" {
  protocols = ["SFTP"]
}
resource "aws_cloudwatch_event_permission" "org" {
  principal    = "*"
  statement_id = "org"
  condition {
    key   = "aws:PrincipalOrgID"
    type  = "StringEquals"
    value = "o-abc123"
  }
}
resource "aws_elb" "tls" {
  name = "tls"
  listener {
    instance_port      = 8080
    instance_protocol  = "http"
    lb_port            = 443
    lb_protocol        = "https"
    ssl_certificate_id = "arn:aws:acm:eu-west-1:1:certificate/c"
  }
}
resource "azurerm_api_management" "apim" {
  name = "apim"
  security {
    frontend_tls10_enabled = false
  }
}
resource "azurerm_network_watcher_flow_log" "fl" {
  name = "fl"
  retention_policy {
    enabled = true
    days    = 365
  }
}
resource "google_project_iam_audit_config" "audit" {
  project = "p"
  service = "allServices"
  audit_log_config {
    log_type = "DATA_READ"
  }
}
resource "google_org_policy_policy" "keys" {
  name   = "projects/p/policies/iam.disableServiceAccountKeyCreation"
  parent = "projects/p"
  spec {
    rules {
      enforce = "TRUE"
    }
  }
}
resource "google_container_node_pool" "np" {
  name    = "np"
  cluster = "c"
  management {
    auto_upgrade = true
  }
}
resource "alicloud_db_instance" "db" {
  engine         = "MySQL"
  engine_version = "8.0"
  instance_type  = "rds.mysql.s1.small"
  security_ips   = ["10.0.0.0/16"]
}
resource "kubernetes_deployment_v1" "web" {
  metadata {
    name      = "web"
    namespace = "apps"
  }
  spec {
    template {
      metadata {
        name = "web"
      }
      spec {
        automount_service_account_token = false
        container {
          name  = "web"
          image = "web:1.0"
          port {
            container_port = 8080
          }
          resources {
            limits = { memory = "256Mi", cpu = "500m" }
          }
          readiness_probe {
            http_get {
              path = "/healthz"
              port = 8080
            }
          }
          security_context {
            read_only_root_filesystem = true
          }
          volume_mount {
            name       = "db"
            mount_path = "/secrets"
          }
        }
      }
    }
  }
}
