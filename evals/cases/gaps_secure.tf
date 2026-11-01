# forbid: TG-AWS-EFS-001, TG-AWS-REDSHIFT-001, TG-AWS-APIGW-001, TG-AWS-LB-002, TG-AWS-ECS-001, TG-AWS-CW-001, TG-AWS-SUBNET-001, TG-AWS-EKS-002, TG-AWS-IAM-004, TG-AZ-VM-001, TG-AZ-APP-001, TG-AZ-DB-001, TG-AZ-ACR-001, TG-GCP-BQ-001, TG-GCP-KMS-001, TG-GCP-NET-001, TG-GCP-VM-002, TG-GH-001, TG-GH-002, TG-DO-K8S-001
variable "deploy_token" {
  description = "Deploy token"
  type        = string
  sensitive   = true
}

resource "aws_efs_file_system" "f" {
  encrypted = true
}

resource "aws_redshift_cluster" "w" {
  cluster_identifier  = "w"
  node_type           = "ra3.xlplus"
  publicly_accessible = false
  encrypted           = true
}

resource "aws_api_gateway_method" "get" {
  rest_api_id   = "a"
  resource_id   = "r"
  http_method   = "GET"
  authorization = "AWS_IAM"
}

resource "aws_api_gateway_method" "cors" {
  rest_api_id   = "a"
  resource_id   = "r"
  http_method   = "OPTIONS"
  authorization = "NONE"
}

resource "aws_lb" "web" {
  name                       = "web"
  drop_invalid_header_fields = true
}

resource "aws_lb" "net" {
  name               = "net"
  load_balancer_type = "network"
}

resource "aws_ecs_task_definition" "t" {
  family = "t"
  container_definitions = jsonencode([{
    name        = "app"
    image       = "app:1.0"
    environment = [{ name = "LOG_LEVEL", value = "info" }]
    secrets     = [{ name = "DB_PASSWORD", valueFrom = "arn:aws:ssm:eu-west-1:1:parameter/db" }]
  }])
}

resource "aws_cloudwatch_log_group" "l" {
  name              = "app"
  retention_in_days = 365
}

resource "aws_subnet" "priv" {
  vpc_id     = "vpc-1"
  cidr_block = "10.0.2.0/24"
}

resource "aws_eks_cluster" "k" {
  name                      = "k"
  role_arn                  = "arn:aws:iam::1:role/eks"
  enabled_cluster_log_types = ["api", "audit"]
  encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = "arn:aws:kms:eu-west-1:1:key/k"
    }
  }
  vpc_config {
    subnet_ids              = ["subnet-1"]
    endpoint_public_access  = false
    endpoint_private_access = true
  }
}

resource "azurerm_linux_virtual_machine" "vm" {
  name                            = "vm"
  disable_password_authentication = true
}

resource "azurerm_linux_web_app" "app" {
  name       = "app"
  https_only = true
  site_config {
    minimum_tls_version = "1.2"
    ftps_state          = "Disabled"
  }
}

resource "azurerm_postgresql_server" "pg" {
  name                             = "pg"
  ssl_enforcement_enabled          = true
  ssl_minimal_tls_version_enforced = "TLS1_2"
}

resource "azurerm_container_registry" "acr" {
  name          = "acr"
  admin_enabled = false
}

resource "google_bigquery_dataset" "d" {
  dataset_id = "d"
  access {
    role           = "READER"
    group_by_email = "analysts@example.com"
  }
}

resource "google_kms_crypto_key" "k" {
  name            = "k"
  key_ring        = "r"
  rotation_period = "7776000s"
}

resource "google_compute_subnetwork" "s" {
  name          = "s"
  network       = "n"
  ip_cidr_range = "10.1.0.0/24"
  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
  }
}

resource "google_compute_instance" "vm" {
  name         = "vm"
  machine_type = "e2-small"
  metadata = {
    enable-oslogin = "TRUE"
  }
}

resource "github_branch_protection" "main" {
  repository_id       = "r"
  pattern             = "main"
  enforce_admins      = true
  allows_force_pushes = false
  required_pull_request_reviews {
    required_approving_review_count = 1
  }
}

resource "github_actions_secret" "token" {
  repository      = "r"
  secret_name     = "DEPLOY_TOKEN"
  plaintext_value = var.deploy_token
}

resource "digitalocean_kubernetes_cluster" "k" {
  name         = "k"
  region       = "ams3"
  version      = "1.31.1-do.0"
  auto_upgrade = true
}
