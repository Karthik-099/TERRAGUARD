# forbid: TG-RHCS-001, TG-RHCS-002, TG-RHCS-003, TG-RHCS-004, TG-RHCS-005, TG-RHCS-006
variable "admin_password" {
  type      = string
  sensitive = true
}

resource "rhcs_cluster_rosa_classic" "prod" {
  name               = "payments-prod"
  cloud_region       = "us-east-1"
  aws_account_id     = "123456789012"
  multi_az           = true
  availability_zones = ["us-east-1a", "us-east-1b", "us-east-1c"]
  private            = true
  aws_private_link   = true
  etcd_encryption    = true
  fips               = true

  admin_credentials = {
    username = "cluster-admin"
    password = var.admin_password
  }
}

resource "rhcs_cluster_rosa_hcp" "dev" {
  name               = "payments-dev"
  cloud_region       = "us-east-1"
  aws_account_id     = "123456789012"
  availability_zones = ["us-east-1a"]
  aws_subnet_ids     = ["subnet-0123456789abcdef0"]
  private            = true
  fips               = true
  sts = {
    role_arn         = "arn:aws:iam::123456789012:role/installer"
    support_role_arn = "arn:aws:iam::123456789012:role/support"
    operator_role_prefix = "dev"
    oidc_config_id   = "abc"
    instance_iam_roles = { worker_role_arn = "arn:aws:iam::123456789012:role/worker" }
  }
}
