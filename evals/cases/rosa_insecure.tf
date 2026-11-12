# expect: TG-RHCS-001, TG-RHCS-002, TG-RHCS-003, TG-RHCS-004, TG-RHCS-005, TG-RHCS-006
resource "rhcs_cluster_rosa_classic" "prod" {
  name                        = "payments-prod"
  cloud_region                = "us-east-1"
  aws_account_id              = "123456789012"
  availability_zones          = ["us-east-1a"]
  disable_workload_monitoring = true

  admin_credentials = {
    username = "cluster-admin"
    password = "Sup3rS3cret-Passw0rd!"
  }
}

resource "rhcs_identity_provider" "local" {
  cluster = rhcs_cluster_rosa_classic.prod.id
  name    = "local"
  htpasswd = {
    users = [{ username = "ops", password = "An0ther-Passw0rd!" }]
  }
}
