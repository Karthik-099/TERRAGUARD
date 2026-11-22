# expect: TG-DBX-CL-001, TG-DBX-CL-002, TG-DBX-CL-003, TG-DBX-CL-004, TG-DBX-CL-005, TG-DBX-SQL-001, TG-DBX-UC-001, TG-DBX-UC-002, TG-DBX-IAM-001, TG-DBX-IAM-002, TG-DBX-TOK-001, TG-DBX-WS-001, TG-DBX-NET-001, TG-DBX-SEC-001, TG-DBX-SEC-002, TG-DBX-ACC-001, TG-DBX-ACC-002, TG-DBX-JOB-001, TG-VAL-025
resource "databricks_cluster" "shared" {
  cluster_name                 = "shared"
  spark_version                = "15.4.x-scala2.12"
  node_type_id                 = "i3.xlarge"
  autotermination_minutes      = 0
  data_security_mode           = "NONE"
  enable_local_disk_encryption = false
  runtime_engine               = "PHOTONN"
  spark_conf = {
    "spark.hadoop.javax.jdo.option.ConnectionPassword" = "hive-Metastore-9f3kQ2"
  }
  init_scripts {
    dbfs {
      destination = "dbfs:/init/setup.sh"
    }
  }
}

resource "databricks_sql_endpoint" "bi" {
  name           = "bi"
  cluster_size   = "Small"
  auto_stop_mins = 0
}

resource "databricks_grants" "sandbox" {
  catalog = "sandbox"
  grant {
    principal  = "account users"
    privileges = ["ALL_PRIVILEGES"]
  }
}

resource "databricks_metastore" "this" {
  name                                              = "primary"
  delta_sharing_scope                               = "INTERNAL_AND_EXTERNAL"
  delta_sharing_recipient_token_lifetime_in_seconds = 0
}

resource "databricks_permissions" "cluster" {
  cluster_id = databricks_cluster.shared.id
  access_control {
    group_name       = "users"
    permission_level = "CAN_MANAGE"
  }
}

resource "databricks_access_control_rule_set" "sp" {
  name = "accounts/00000000-0000-0000-0000-000000000000/servicePrincipals/1234/ruleSets/default"
  grant_rules {
    principals = ["groups/users"]
    role       = "roles/servicePrincipal.user"
  }
}

resource "databricks_token" "ci" {
  comment = "CI"
}

resource "databricks_workspace_conf" "this" {
  custom_config = {
    "enableIpAccessLists"               = false
    "enableDeprecatedGlobalInitScripts" = true
  }
}

resource "databricks_ip_access_list" "all" {
  label        = "everyone"
  list_type    = "ALLOW"
  ip_addresses = ["0.0.0.0/0"]
}

resource "databricks_secret" "db" {
  key          = "db-password"
  scope        = "app"
  string_value = "Xk2v9QmZr7Lp4Wn8"
}

resource "databricks_secret_scope" "app" {
  name                     = "app"
  initial_manage_principal = "users"
}

resource "databricks_mws_workspaces" "this" {
  account_id     = "00000000-0000-0000-0000-000000000000"
  workspace_name = "prod"
  aws_region     = "us-east-1"
}

resource "databricks_job" "etl" {
  name = "etl"
  run_as {
    user_name = "alice@example.com"
  }
  task {
    task_key = "main"
    new_cluster {
      spark_version = "15.4.x-scala2.12"
      num_workers   = 2
    }
  }
}
