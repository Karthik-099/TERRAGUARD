# expect: TG-AWS-CACHE-002, TG-AWS-ECS-004, TG-AWS-ECS-005, TG-AWS-EKS-003, TG-AWS-TRANSFER-002, TG-AWS-EVB-001, TG-AWS-ELB-001, TG-AZ-APIM-001, TG-AZ-NSG-002, TG-GCP-IAM-006, TG-GCP-ORG-001, TG-GCP-GKE-005, TG-ALI-RDS-001, TG-K8S-009, TG-K8S-010, TG-K8S-012, TG-K8S-015, TG-K8S-016, TG-K8S-017
resource "aws_elasticache_replication_group" "r" {
  replication_group_id = "r"
  description          = "r"
  engine               = "redis"
}
resource "aws_ecs_task_definition" "t" {
  family = "t"
  container_definitions = jsonencode([{ name = "app", image = "app:1.0" }])
  volume {
    name = "data"
    efs_volume_configuration {
      file_system_id = "fs-1"
    }
  }
}
resource "aws_eks_node_group" "ng" {
  cluster_name  = "c"
  node_role_arn = "arn:aws:iam::1:role/n"
  subnet_ids    = ["subnet-1"]
  remote_access {
    ec2_ssh_key = "ops"
  }
}
resource "aws_transfer_server" "ftp" {
  protocols = ["FTP", "SFTP"]
}
resource "aws_cloudwatch_event_permission" "any" {
  principal    = "*"
  statement_id = "any"
}
resource "aws_elb" "legacy" {
  name = "legacy"
  listener {
    instance_port     = 80
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"
  }
}
resource "azurerm_api_management" "apim" {
  name = "apim"
  security {
    frontend_tls10_enabled = true
  }
}
resource "azurerm_network_watcher_flow_log" "fl" {
  name = "fl"
  retention_policy {
    enabled = true
    days    = 7
  }
}
resource "google_project_iam_audit_config" "audit" {
  project = "p"
  service = "allServices"
  audit_log_config {
    log_type         = "DATA_READ"
    exempted_members = ["user:ci@example.com"]
  }
}
resource "google_org_policy_policy" "keys" {
  name   = "projects/p/policies/iam.disableServiceAccountKeyCreation"
  parent = "projects/p"
  spec {
    rules {
      enforce = "FALSE"
    }
  }
}
resource "google_container_node_pool" "np" {
  name    = "np"
  cluster = "c"
  management {
    auto_upgrade = false
  }
}
resource "alicloud_db_instance" "db" {
  engine         = "MySQL"
  engine_version = "8.0"
  instance_type  = "rds.mysql.s1.small"
  security_ips   = ["0.0.0.0/0"]
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
        container {
          name  = "web"
          image = "web:1.0"
          port {
            container_port = 80
          }
          env {
            name = "DB_PASSWORD"
            value_from {
              secret_key_ref {
                name = "db"
                key  = "password"
              }
            }
          }
        }
      }
    }
  }
}
