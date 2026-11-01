# expect: TG-AWS-EFS-001, TG-AWS-REDSHIFT-001, TG-AWS-APIGW-001, TG-AWS-LB-002, TG-AWS-ECS-001, TG-AWS-CW-001, TG-AWS-SUBNET-001, TG-AWS-EKS-002, TG-AWS-IAM-004, TG-AZ-VM-001, TG-AZ-APP-001, TG-AZ-DB-001, TG-AZ-ACR-001, TG-GCP-BQ-001, TG-GCP-KMS-001, TG-GCP-NET-001, TG-GCP-VM-002, TG-GH-001, TG-GH-002, TG-DO-K8S-001
resource "aws_efs_file_system" "f" {}

resource "aws_redshift_cluster" "w" {
  cluster_identifier  = "w"
  node_type           = "ra3.xlplus"
  publicly_accessible = true
  encrypted           = false
}

resource "aws_api_gateway_method" "get" {
  rest_api_id   = "a"
  resource_id   = "r"
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_lb" "web" {
  name = "web"
}

resource "aws_ecs_task_definition" "t" {
  family = "t"
  container_definitions = jsonencode([{
    name       = "app"
    image      = "app:1.0"
    privileged = true
    environment = [{ name = "DB_PASSWORD", value = "hunter2hunter2" }]
  }])
}

resource "aws_cloudwatch_log_group" "l" {
  name = "app"
}

resource "aws_subnet" "pub" {
  vpc_id                  = "vpc-1"
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
}

resource "aws_eks_cluster" "k" {
  name     = "k"
  role_arn = "arn:aws:iam::1:role/eks"
  vpc_config {
    subnet_ids              = ["subnet-1"]
    endpoint_public_access  = false
    endpoint_private_access = true
  }
}

resource "aws_iam_access_key" "ci" {
  user = "ci"
}

resource "azurerm_linux_virtual_machine" "vm" {
  name                            = "vm"
  disable_password_authentication = false
}

resource "azurerm_linux_web_app" "app" {
  name = "app"
  site_config {
    minimum_tls_version = "1.0"
    ftps_state          = "AllAllowed"
  }
}

resource "azurerm_postgresql_server" "pg" {
  name                             = "pg"
  ssl_enforcement_enabled          = false
  ssl_minimal_tls_version_enforced = "TLS1_0"
}

resource "azurerm_container_registry" "acr" {
  name          = "acr"
  admin_enabled = true
}

resource "google_bigquery_dataset" "d" {
  dataset_id = "d"
  access {
    role          = "READER"
    special_group = "allAuthenticatedUsers"
  }
}

resource "google_kms_crypto_key" "k" {
  name     = "k"
  key_ring = "r"
}

resource "google_compute_subnetwork" "s" {
  name          = "s"
  network       = "n"
  ip_cidr_range = "10.1.0.0/24"
}

resource "google_compute_instance" "vm" {
  name         = "vm"
  machine_type = "e2-small"
  metadata = {
    serial-port-enable = "true"
  }
}

resource "github_branch_protection" "main" {
  repository_id       = "r"
  pattern             = "main"
  allows_force_pushes = true
}

resource "github_actions_secret" "token" {
  repository      = "r"
  secret_name     = "DEPLOY_TOKEN"
  plaintext_value = "ghp_notarealtokenvalue"
}

resource "digitalocean_kubernetes_cluster" "k" {
  name    = "k"
  region  = "ams3"
  version = "1.31.1-do.0"
}
