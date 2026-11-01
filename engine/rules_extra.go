package engine

import (
	"encoding/json"
	"strings"
)

// extraRules flag explicit bad values or clearly missing controls only.
var extraRules = []Rule{
	{ID: "TG-AWS-EFS-001", Title: "EFS file system is not encrypted", Severity: Medium, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_efs_file_system"}, Remediation: "Set encrypted = true (optionally with kms_key_id). Encryption cannot be added later without recreating the file system.",
		Check: func(r *Resource) []Hit {
			if notTrue(r.get("encrypted")) {
				return []Hit{{Path: "encrypted", Msg: "Files are stored unencrypted at rest.", Fix: fix(true, "Encrypt the file system", "encrypted")}}
			}
			return nil
		}},
	{ID: "TG-AWS-REDSHIFT-001", Title: "Redshift cluster is public or unencrypted", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"aws_redshift_cluster"}, Remediation: "Set publicly_accessible = false and encrypted = true.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			if is(r.get("publicly_accessible"), true) {
				hits = append(hits, Hit{Path: "publicly_accessible", Msg: "The data warehouse gets a public endpoint.", Fix: fix(false, "Make the cluster private", "publicly_accessible")})
			}
			if is(r.get("encrypted"), false) {
				hits = append(hits, Hit{Path: "encrypted", Sev: Medium, Msg: "Warehouse data is stored unencrypted.", Fix: fix(true, "Encrypt the cluster", "encrypted")})
			}
			return hits
		}},
	{ID: "TG-AWS-APIGW-001", Title: "API Gateway method has no authorization", Severity: Medium, Category: CatSecurity, CWE: "CWE-306",
		Types: []string{"aws_api_gateway_method"}, Remediation: "Use authorization = \"AWS_IAM\", \"COGNITO_USER_POOLS\" or \"CUSTOM\", or require an API key for intentionally public methods.",
		Check: func(r *Resource) []Hit {
			auth, _ := asString(r.get("authorization"))
			method, _ := asString(r.get("http_method"))
			if strings.EqualFold(auth, "NONE") && !strings.EqualFold(method, "OPTIONS") && notTrue(r.get("api_key_required")) {
				return []Hit{{Path: "authorization", Msg: "Anyone on the internet can call this " + method + " method."}}
			}
			return nil
		}},
	{ID: "TG-AWS-LB-002", Title: "Load balancer forwards invalid HTTP headers", Severity: Low, Category: CatSecurity, CWE: "CWE-444",
		Types: []string{"aws_lb", "aws_alb"}, Remediation: "Set drop_invalid_header_fields = true to block HTTP desync and header smuggling.",
		Check: func(r *Resource) []Hit {
			if t, _ := asString(r.get("load_balancer_type")); (t == "" || t == "application") && notTrue(r.get("drop_invalid_header_fields")) {
				return []Hit{{Path: "drop_invalid_header_fields", Msg: "Malformed headers reach the application, enabling request smuggling.", Fix: fix(true, "Drop invalid header fields", "drop_invalid_header_fields")}}
			}
			return nil
		}},
	{ID: "TG-AWS-ECS-001", Title: "ECS task is privileged or has plaintext secrets", Severity: High, Category: CatSecurity, CWE: "CWE-250",
		Types: []string{"aws_ecs_task_definition"}, Remediation: "Remove privileged = true, and pass secrets with the secrets block (Secrets Manager or SSM) instead of environment.",
		Check: func(r *Resource) []Hit {
			defs := r.get("container_definitions")
			if s, ok := asString(defs); ok {
				_ = json.Unmarshal([]byte(s), &defs)
			}
			var hits []Hit
			walkMaps(defs, "", func(_ string, m map[string]any) {
				if is(m["privileged"], true) {
					hits = append(hits, Hit{Path: "container_definitions", Msg: "A privileged container has root access to the host."})
				}
				if name, ok := asString(m["name"]); ok && m["value"] != nil && secretVarRE.MatchString(name) {
					if v, _ := asString(m["value"]); v != "" && !isUnknown(m["value"]) {
						hits = append(hits, Hit{Path: "container_definitions", Msg: "Environment variable " + name + " holds a secret in plaintext; it is visible in the console and API."})
					}
				}
			})
			return hits
		}},
	{ID: "TG-AWS-CW-001", Title: "Log group keeps logs forever", Severity: Low, Category: CatReliability, CWE: "CWE-779",
		Types: []string{"aws_cloudwatch_log_group"}, Remediation: "Set retention_in_days to match your policy (for example 365) so cost and retention stay deliberate.",
		Check: func(r *Resource) []Hit {
			if r.get("retention_in_days") == nil {
				return []Hit{{Path: "retention_in_days", Msg: "No retention is set: logs are kept and billed indefinitely."}}
			}
			return nil
		}},
	{ID: "TG-AWS-SUBNET-001", Title: "Subnet gives instances public IPs automatically", Severity: Low, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"aws_subnet"}, Remediation: "Set map_public_ip_on_launch = false; load balancers and NAT gateways do not need it.",
		Check: func(r *Resource) []Hit {
			if is(r.get("map_public_ip_on_launch"), true) {
				return []Hit{{Path: "map_public_ip_on_launch", Msg: "Every instance launched here is reachable from the internet by default.", Fix: fix(false, "Stop assigning public IPs", "map_public_ip_on_launch")}}
			}
			return nil
		}},
	{ID: "TG-AWS-EKS-002", Title: "EKS secrets are not encrypted with KMS", Severity: Medium, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_eks_cluster"}, Remediation: "Add encryption_config { resources = [\"secrets\"] provider { key_arn = ... } } and enable control-plane logs (api, audit).",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			if r.get("encryption_config") == nil {
				hits = append(hits, Hit{Path: "encryption_config", Msg: "Kubernetes secrets are stored without envelope encryption."})
			}
			if r.get("enabled_cluster_log_types") == nil {
				hits = append(hits, Hit{Path: "enabled_cluster_log_types", Sev: Low, Msg: "Control-plane audit logs are off, so API activity cannot be investigated."})
			}
			return hits
		}},
	{ID: "TG-AWS-IAM-004", Title: "Permissions attached to IAM users or long-lived keys", Severity: Low, Category: CatSecurity, CWE: "CWE-269",
		Types: []string{"aws_iam_user_policy", "aws_iam_user_policy_attachment", "aws_iam_access_key"}, Remediation: "Grant permissions through groups or roles, and prefer SSO or OIDC over long-lived access keys.",
		Check: func(r *Resource) []Hit {
			if r.Type == "aws_iam_access_key" {
				return []Hit{{Path: "user", Sev: Medium, Msg: "A long-lived access key is created; its secret also ends up in state."}}
			}
			return []Hit{{Path: "user", Msg: "Policies attached directly to users are hard to audit and revoke."}}
		}},
	{ID: "TG-AZ-VM-001", Title: "Linux VM allows password login", Severity: Medium, Category: CatSecurity, CWE: "CWE-287",
		Types: []string{"azurerm_linux_virtual_machine", "azurerm_linux_virtual_machine_scale_set"}, Remediation: "Set disable_password_authentication = true and use admin_ssh_key.",
		Check: func(r *Resource) []Hit {
			if is(r.get("disable_password_authentication"), false) {
				return []Hit{{Path: "disable_password_authentication", Msg: "SSH passwords can be brute-forced; keys cannot.", Fix: fix(true, "Disable password login", "disable_password_authentication")}}
			}
			return nil
		}},
	{ID: "TG-AZ-APP-001", Title: "App Service allows HTTP, old TLS or plain FTP", Severity: Medium, Category: CatSecurity, CWE: "CWE-319",
		Types:       []string{"azurerm_linux_web_app", "azurerm_windows_web_app", "azurerm_linux_function_app", "azurerm_windows_function_app", "azurerm_app_service", "azurerm_function_app"},
		Remediation: "Set https_only = true, site_config.minimum_tls_version = \"1.2\" and site_config.ftps_state = \"Disabled\" (or \"FtpsOnly\").",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			if notTrue(r.get("https_only")) {
				hits = append(hits, Hit{Path: "https_only", Msg: "The app also answers over plain HTTP.", Fix: fix(true, "Require HTTPS", "https_only")})
			}
			if v, _ := asString(r.get("site_config.minimum_tls_version")); v == "1.0" || v == "1.1" {
				hits = append(hits, Hit{Path: "site_config", Msg: "TLS " + v + " is deprecated and weak."})
			}
			if v, _ := asString(r.get("site_config.ftps_state")); v == "AllAllowed" {
				hits = append(hits, Hit{Path: "site_config", Msg: "Plain FTP sends deployment credentials unencrypted."})
			}
			return hits
		}},
	{ID: "TG-AZ-DB-001", Title: "Azure database accepts unencrypted or old-TLS connections", Severity: High, Category: CatSecurity, CWE: "CWE-319",
		Types:       []string{"azurerm_postgresql_server", "azurerm_mysql_server", "azurerm_mariadb_server", "azurerm_mssql_server"},
		Remediation: "Set ssl_enforcement_enabled = true and the minimum TLS version to 1.2.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			if is(r.get("ssl_enforcement_enabled"), false) {
				hits = append(hits, Hit{Path: "ssl_enforcement_enabled", Msg: "Clients can connect without TLS.", Fix: fix(true, "Enforce TLS", "ssl_enforcement_enabled")})
			}
			for _, k := range []string{"ssl_minimal_tls_version_enforced", "minimum_tls_version"} {
				if v, _ := asString(r.get(k)); v == "TLS1_0" || v == "TLS1_1" || v == "1.0" || v == "1.1" {
					hits = append(hits, Hit{Path: k, Sev: Medium, Msg: "TLS " + v + " is deprecated and weak."})
				}
			}
			return hits
		}},
	{ID: "TG-AZ-ACR-001", Title: "Container registry admin account is enabled", Severity: Medium, Category: CatSecurity, CWE: "CWE-798",
		Types: []string{"azurerm_container_registry"}, Remediation: "Set admin_enabled = false and pull with managed identities or service principals.",
		Check: func(r *Resource) []Hit {
			if is(r.get("admin_enabled"), true) {
				return []Hit{{Path: "admin_enabled", Msg: "One shared admin password can push and pull every image.", Fix: fix(false, "Disable the admin account", "admin_enabled")}}
			}
			return nil
		}},
	{ID: "TG-GCP-BQ-001", Title: "BigQuery dataset is public", Severity: Critical, Category: CatSecurity, CWE: "CWE-284",
		Types:       []string{"google_bigquery_dataset", "google_bigquery_dataset_iam_member", "google_bigquery_dataset_iam_binding", "google_bigquery_dataset_access"},
		Remediation: "Remove allUsers and allAuthenticatedUsers; grant access to specific groups or service accounts.",
		Check: func(r *Resource) []Hit {
			public := false
			walkMaps(r.Attrs, "", func(_ string, m map[string]any) {
				for _, k := range []string{"special_group", "iam_member", "member"} {
					if v, _ := asString(m[k]); v == "allUsers" || v == "allAuthenticatedUsers" {
						public = true
					}
				}
				if contains(asStrings(m["members"]), "allUsers", "allAuthenticatedUsers") {
					public = true
				}
			})
			if public {
				return []Hit{{Path: "access", Msg: "Anyone with a Google account (or anyone at all) can read this dataset."}}
			}
			return nil
		}},
	{ID: "TG-GCP-KMS-001", Title: "Cloud KMS key is never rotated", Severity: Medium, Category: CatSecurity, CWE: "CWE-324",
		Types: []string{"google_kms_crypto_key"}, Remediation: "Set rotation_period, for example \"7776000s\" (90 days).",
		Check: func(r *Resource) []Hit {
			if purpose, _ := asString(r.get("purpose")); (purpose == "" || purpose == "ENCRYPT_DECRYPT") && r.get("rotation_period") == nil {
				return []Hit{{Path: "rotation_period", Msg: "The same key material encrypts data indefinitely.", Fix: fix("7776000s", "Rotate every 90 days", "rotation_period")}}
			}
			return nil
		}},
	{ID: "TG-GCP-NET-001", Title: "Subnet has no flow logs", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"google_compute_subnetwork"}, Remediation: "Add a log_config block so network traffic can be investigated.",
		Check: func(r *Resource) []Hit {
			if purpose, _ := asString(r.get("purpose")); (purpose == "" || purpose == "PRIVATE") && r.get("log_config") == nil {
				return []Hit{{Path: "log_config", Msg: "Traffic in this subnet is not recorded."}}
			}
			return nil
		}},
	{ID: "TG-GCP-VM-002", Title: "VM serial port access is enabled", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"google_compute_instance", "google_compute_instance_template"}, Remediation: "Remove serial-port-enable from metadata, or set it to \"false\".",
		Check: func(r *Resource) []Hit {
			if v := r.get("metadata.serial-port-enable"); is(v, true) || v == "true" || v == "TRUE" {
				return []Hit{{Path: "metadata", Msg: "The interactive serial console bypasses network firewalls."}}
			}
			return nil
		}},
	{ID: "TG-GH-001", Title: "Branch protection allows unreviewed or forced pushes", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"github_branch_protection", "github_branch_protection_v3"}, Remediation: "Add required_pull_request_reviews (at least one approval), set enforce_admins = true and allows_force_pushes = false.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			if r.get("required_pull_request_reviews") == nil {
				hits = append(hits, Hit{Path: "required_pull_request_reviews", Msg: "Changes can merge without any review."})
			}
			if is(r.get("allows_force_pushes"), true) {
				hits = append(hits, Hit{Path: "allows_force_pushes", Sev: High, Msg: "Force pushes can rewrite protected history.", Fix: fix(false, "Block force pushes", "allows_force_pushes")})
			}
			if is(r.get("enforce_admins"), false) {
				hits = append(hits, Hit{Path: "enforce_admins", Sev: Low, Msg: "Administrators can bypass the protection.", Fix: fix(true, "Apply rules to admins", "enforce_admins")})
			}
			return hits
		}},
	{ID: "TG-GH-002", Title: "GitHub Actions secret value is in the code", Severity: High, Category: CatSecurity, CWE: "CWE-798",
		Types:       []string{"github_actions_secret", "github_actions_organization_secret", "github_actions_environment_secret", "github_dependabot_secret"},
		Remediation: "Pass the value from a sensitive variable or a secrets manager data source; never as a literal. Rotate the exposed value.",
		Check: func(r *Resource) []Hit {
			if v, ok := asString(r.get("plaintext_value")); ok && v != "" {
				return []Hit{{Path: "plaintext_value", Msg: "The secret is written in plain text in the repository."}}
			}
			return nil
		}},
	{ID: "TG-DO-K8S-001", Title: "DigitalOcean Kubernetes cluster does not auto-upgrade", Severity: Low, Category: CatReliability, CWE: "CWE-1104",
		Types: []string{"digitalocean_kubernetes_cluster"}, Remediation: "Set auto_upgrade = true with a maintenance_policy window so security patches land.",
		Check: func(r *Resource) []Hit {
			if notTrue(r.get("auto_upgrade")) {
				return []Hit{{Path: "auto_upgrade", Msg: "Patch releases are not applied automatically.", Fix: fix(true, "Enable auto-upgrade", "auto_upgrade")}}
			}
			return nil
		}},
}
