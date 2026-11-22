# forbid: TG-DBX-CL-001, TG-DBX-CL-002, TG-DBX-CL-003, TG-DBX-CL-004, TG-DBX-CL-005, TG-DBX-SQL-001, TG-DBX-UC-001, TG-DBX-UC-002, TG-DBX-IAM-001, TG-DBX-IAM-002, TG-DBX-TOK-001, TG-DBX-WS-001, TG-DBX-NET-001, TG-DBX-SEC-001, TG-DBX-SEC-002, TG-DBX-ACC-001, TG-DBX-ACC-002, TG-DBX-JOB-001, TG-VAL-025
variable "db_password" {
  type      = string
  sensitive = true
}

resource "databricks_cluster" "shared" {
  cluster_name                 = "shared"
  spark_version                = "15.4.x-scala2.12"
  node_type_id                 = "i3.xlarge"
  data_security_mode           = "USER_ISOLATION"
  enable_local_disk_encryption = true
  runtime_engine               = "PHOTON"
  spark_conf = {
    "spark.hadoop.javax.jdo.option.ConnectionPassword" = "{{secrets/hive/password}}"
  }
  init_scripts {
    volumes {
      destination = "/Volumes/main/ops/scripts/setup.sh"
    }
  }
}

resource "databricks_cluster_policy" "standard" {
  name = "standard"
  definition = jsonencode({
    "autotermination_minutes" : { "type" : "range", "maxValue" : 120, "defaultValue" : 60 },
    "data_security_mode" : { "type" : "fixed", "value" : "USER_ISOLATION" }
  })
}

resource "databricks_sql_endpoint" "bi" {
  name           = "bi"
  cluster_size   = "Small"
  auto_stop_mins = 10
}

resource "databricks_grants" "sandbox" {
  catalog = "sandbox"
  grant {
    principal  = "account users"
    privileges = ["USE_CATALOG", "USE_SCHEMA", "SELECT"]
  }
  grant {
    principal  = "data-engineers"
    privileges = ["ALL_PRIVILEGES"]
  }
}

resource "databricks_metastore" "this" {
  name                                              = "primary"
  delta_sharing_scope                               = "INTERNAL_AND_EXTERNAL"
  delta_sharing_recipient_token_lifetime_in_seconds = 86400
}

resource "databricks_permissions" "cluster" {
  cluster_id = databricks_cluster.shared.id
  access_control {
    group_name       = "users"
    permission_level = "CAN_ATTACH_TO"
  }
}

resource "databricks_token" "ci" {
  comment          = "CI"
  lifetime_seconds = 2592000
}

resource "databricks_workspace_conf" "this" {
  custom_config = {
    "enableIpAccessLists"  = true
    "maxTokenLifetimeDays" = "90"
  }
}

resource "databricks_ip_access_list" "office" {
  label        = "office"
  list_type    = "ALLOW"
  ip_addresses = ["203.0.113.0/24"]
}

resource "databricks_secret" "db" {
  key          = "db-password"
  scope        = "app"
  string_value = var.db_password
}

resource "databricks_secret_scope" "app" {
  name = "app"
}

resource "databricks_mws_workspaces" "this" {
  account_id                               = "00000000-0000-0000-0000-000000000000"
  workspace_name                           = "prod"
  aws_region                               = "us-east-1"
  managed_services_customer_managed_key_id = "cmk-1"
  storage_customer_managed_key_id          = "cmk-2"
  private_access_settings_id               = "pas-1"
}

resource "databricks_job" "etl" {
  name = "etl"
  run_as {
    service_principal_name = "8d23ae77-912e-4a19-81e4-b9c3f5cc9349"
  }
}
