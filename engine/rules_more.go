package engine

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// Checks that fire on an absent setting are LOW unless the default is unsafe.
var moreRules = []Rule{
	// AWS
	{ID: "TG-AWS-RDS-004", Title: "Database exports no logs or skips IAM authentication", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"aws_db_instance", "aws_rds_cluster"}, Remediation: "Set enabled_cloudwatch_logs_exports for the engine's logs and iam_database_authentication_enabled = true.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			if len(asStrings(r.get("enabled_cloudwatch_logs_exports"))) == 0 && !isUnknown(r.get("enabled_cloudwatch_logs_exports")) {
				hits = append(hits, Hit{Path: "enabled_cloudwatch_logs_exports", Msg: "Database logs are not exported, so access and errors cannot be audited."})
			}
			if engine, _ := asString(r.get("engine")); iamAuthEngineRE.MatchString(engine) && notTrue(r.get("iam_database_authentication_enabled")) {
				hits = append(hits, Hit{Path: "iam_database_authentication_enabled", Msg: "Only static passwords can log in; IAM authentication is off.", Fix: fix(true, "Enable IAM database authentication", "iam_database_authentication_enabled")})
			}
			return hits
		}},
	{ID: "TG-AWS-RDS-005", Title: "Database snapshot is shared publicly", Severity: Critical, Category: CatSecurity, CWE: "CWE-200",
		Types: []string{"aws_db_snapshot", "aws_db_cluster_snapshot"}, Remediation: "Remove \"all\" from shared_accounts; share with specific account IDs only.",
		Check: func(r *Resource) []Hit {
			if contains(asStrings(r.get("shared_accounts")), "all") {
				return []Hit{{Path: "shared_accounts", Msg: "Any AWS account can copy and restore this database snapshot."}}
			}
			return nil
		}},
	{ID: "TG-AWS-DOCDB-001", Title: "DocumentDB is unencrypted or allows plaintext connections", Severity: High, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_docdb_cluster", "aws_docdb_cluster_parameter_group"}, Remediation: "Set storage_encrypted = true (forces a new cluster) and keep the tls parameter enabled.",
		Check: func(r *Resource) []Hit {
			if r.Type == "aws_docdb_cluster_parameter_group" {
				for _, p := range r.blocks("parameter") {
					if n, _ := asString(p["name"]); n == "tls" {
						if v, _ := asString(p["value"]); v == "disabled" {
							return []Hit{{Path: "parameter", Msg: "TLS is disabled, so clients connect in plaintext."}}
						}
					}
				}
				return nil
			}
			if notTrue(r.get("storage_encrypted")) {
				return []Hit{{Path: "storage_encrypted", Msg: "Documents are stored unencrypted at rest.", Fix: fix(true, "Encrypt storage (replaces the cluster)", "storage_encrypted")}}
			}
			return nil
		}},
	{ID: "TG-AWS-NEPTUNE-001", Title: "Neptune cluster is not encrypted", Severity: High, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_neptune_cluster"}, Remediation: "Set storage_encrypted = true (forces a new cluster).",
		Check: func(r *Resource) []Hit {
			if notTrue(r.get("storage_encrypted")) {
				return []Hit{{Path: "storage_encrypted", Msg: "Graph data is stored unencrypted at rest.", Fix: fix(true, "Encrypt storage (replaces the cluster)", "storage_encrypted")}}
			}
			return nil
		}},
	{ID: "TG-AWS-MQ-001", Title: "Amazon MQ broker is publicly accessible", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"aws_mq_broker"}, Remediation: "Set publicly_accessible = false and reach the broker through the VPC.",
		Check: func(r *Resource) []Hit {
			if is(r.get("publicly_accessible"), true) {
				return []Hit{{Path: "publicly_accessible", Msg: "The message broker has a public endpoint.", Fix: fix(false, "Make the broker private", "publicly_accessible")}}
			}
			return nil
		}},
	{ID: "TG-AWS-DMS-001", Title: "DMS replication instance is publicly accessible", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"aws_dms_replication_instance"}, Remediation: "Set publicly_accessible = false.",
		Check: func(r *Resource) []Hit {
			if is(r.get("publicly_accessible"), true) {
				return []Hit{{Path: "publicly_accessible", Msg: "The migration instance, which holds database credentials, has a public IP.", Fix: fix(false, "Make the instance private", "publicly_accessible")}}
			}
			return nil
		}},
	{ID: "TG-AWS-SAGEMAKER-001", Title: "SageMaker notebook has direct internet access", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"aws_sagemaker_notebook_instance"}, Remediation: "Place it in a subnet, set direct_internet_access = \"Disabled\" and root_access = \"Disabled\".",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			if v, _ := asString(r.get("direct_internet_access")); (v == "" && !isUnknown(r.get("direct_internet_access"))) || v == "Enabled" {
				hits = append(hits, Hit{Path: "direct_internet_access", Msg: "The notebook can reach and be reached from the internet outside your VPC controls."})
			}
			if v, _ := asString(r.get("root_access")); v == "Enabled" {
				hits = append(hits, Hit{Path: "root_access", Sev: Low, Msg: "Notebook users get root on the instance."})
			}
			return hits
		}},
	{ID: "TG-AWS-KINESIS-001", Title: "Kinesis stream is not encrypted", Severity: Medium, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_kinesis_stream"}, Remediation: "Set encryption_type = \"KMS\" and kms_key_id = \"alias/aws/kinesis\" (or your key).",
		Check: func(r *Resource) []Hit {
			if v, _ := asString(r.get("encryption_type")); (v == "" && !isUnknown(r.get("encryption_type"))) || v == "NONE" {
				return []Hit{{Path: "encryption_type", Msg: "Records are stored unencrypted at rest."}}
			}
			return nil
		}},
	{ID: "TG-AWS-MSK-001", Title: "MSK allows plaintext, unauthenticated or public brokers", Severity: High, Category: CatSecurity, CWE: "CWE-319",
		Types: []string{"aws_msk_cluster"}, Remediation: "Use client_broker = \"TLS\", keep in_cluster encryption, disable unauthenticated access and public brokers.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			if v, _ := asString(r.get("encryption_info.encryption_in_transit.client_broker")); v == "PLAINTEXT" || v == "TLS_PLAINTEXT" {
				hits = append(hits, Hit{Path: "encryption_info", Msg: "Clients can talk to brokers in plaintext (" + v + ")."})
			}
			if is(r.get("encryption_info.encryption_in_transit.in_cluster"), false) {
				hits = append(hits, Hit{Path: "encryption_info", Msg: "Traffic between brokers is unencrypted."})
			}
			if is(r.get("client_authentication.unauthenticated"), true) {
				hits = append(hits, Hit{Path: "client_authentication", Msg: "Unauthenticated clients can produce and consume."})
			}
			if v, _ := asString(r.get("broker_node_group_info.connectivity_info.public_access.type")); v == "SERVICE_PROVIDED_EIPS" {
				hits = append(hits, Hit{Path: "broker_node_group_info", Msg: "Brokers have public IP addresses."})
			}
			return hits
		}},
	{ID: "TG-AWS-OS-001", Title: "OpenSearch domain without fine-grained access control", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"aws_opensearch_domain", "aws_elasticsearch_domain"}, Remediation: "Enable advanced_security_options, keep anonymous_auth_enabled = false, and use tls_security_policy = \"Policy-Min-TLS-1-2-2019-07\".",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			if notTrue(r.get("advanced_security_options.enabled")) {
				sev := Medium
				if r.get("vpc_options") == nil {
					sev = High
				}
				hits = append(hits, Hit{Path: "advanced_security_options", Sev: sev, Msg: "No fine-grained access control: anyone allowed by the access policy can read every index."})
			}
			if is(r.get("advanced_security_options.anonymous_auth_enabled"), true) {
				hits = append(hits, Hit{Path: "advanced_security_options", Msg: "Anonymous users can query the domain."})
			}
			if v, _ := asString(r.get("domain_endpoint_options.tls_security_policy")); v == "Policy-Min-TLS-1-0-2019-07" {
				hits = append(hits, Hit{Path: "domain_endpoint_options", Sev: Medium, Msg: "TLS 1.0 and 1.1 are accepted."})
			}
			return hits
		}},
	{ID: "TG-AWS-IAM-006", Title: "IAM policy allows privilege escalation on all resources", Severity: High, Category: CatSecurity, CWE: "CWE-269",
		Types: []string{"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy", "aws_iam_policy_document"}, Remediation: "Scope iam:PassRole and policy-management actions to specific role and policy ARNs.",
		Check: func(r *Resource) []Hit {
			sts, path := statements(r.get("policy")), "policy"
			if r.Type == "aws_iam_policy_document" {
				sts, path = policyDocStatements(r), "statement"
			}
			for _, st := range sts {
				if st.Effect != "Allow" || !contains(st.Resources, "*") {
					continue
				}
				for _, a := range st.Actions {
					if escalationRE.MatchString(a) {
						return []Hit{{Path: path, Msg: a + ` on Resource "*" lets the holder grant themselves more permissions.`}}
					}
				}
			}
			return nil
		}},
	{ID: "TG-AWS-IAM-007", Title: "GitHub Actions role can be assumed from any repository", Severity: Critical, Category: CatSecurity, CWE: "CWE-863",
		Types: []string{"aws_iam_role", "aws_iam_policy_document"}, Remediation: "Add a condition on token.actions.githubusercontent.com:sub limited to your repository and branch, e.g. repo:org/repo:ref:refs/heads/main.",
		Check: func(r *Resource) []Hit {
			if githubOIDCOpen(r) {
				return []Hit{{Path: map[bool]string{true: "statement", false: "assume_role_policy"}[r.Type == "aws_iam_policy_document"], Msg: "Any GitHub repository, including an attacker's, can assume this role."}}
			}
			return nil
		}},
	{ID: "TG-AWS-IAM-008", Title: "IAM account password policy is weak", Severity: Medium, Category: CatSecurity, CWE: "CWE-521",
		Types: []string{"aws_iam_account_password_policy"}, Remediation: "Require at least 14 characters, symbols, numbers, upper and lower case, and prevent reuse of the last 24 passwords.",
		Check: func(r *Resource) []Hit {
			var weak []string
			if n, ok := asFloat(r.get("minimum_password_length")); !ok || n < 14 {
				weak = append(weak, "length under 14")
			}
			for _, k := range []string{"require_symbols", "require_numbers", "require_uppercase_characters", "require_lowercase_characters"} {
				if notTrue(r.get(k)) {
					weak = append(weak, k+" off")
				}
			}
			if n, ok := asFloat(r.get("password_reuse_prevention")); !ok || n < 24 {
				weak = append(weak, "reuse prevention under 24")
			}
			if len(weak) > 0 {
				return []Hit{{Path: "minimum_password_length", Msg: "Weak password policy: " + strings.Join(weak, ", ") + "."}}
			}
			return nil
		}},
	{ID: "TG-AWS-LAMBDA-003", Title: "Lambda permission is open to any account or source", Severity: Medium, Category: CatSecurity, CWE: "CWE-441",
		Types: []string{"aws_lambda_permission"}, Remediation: "Set source_arn (and source_account for S3) so only your resource can invoke the function.",
		Check: func(r *Resource) []Hit {
			p, _ := asString(r.get("principal"))
			switch {
			case p == "*" && r.get("source_arn") == nil:
				return []Hit{{Path: "principal", Sev: Critical, Msg: "Anyone can invoke this function."}}
			case strings.HasSuffix(p, ".amazonaws.com") && r.get("source_arn") == nil:
				return []Hit{{Path: "principal", Msg: p + " from any account can invoke this function (confused deputy)."}}
			case p == "s3.amazonaws.com" && r.get("source_account") == nil:
				return []Hit{{Path: "principal", Sev: Low, Msg: "S3 bucket ARNs carry no account ID; add source_account."}}
			}
			return nil
		}},
	{ID: "TG-AWS-CT-002", Title: "CloudTrail is stopped or not encrypted with KMS", Severity: Medium, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"aws_cloudtrail"}, Remediation: "Keep enable_logging = true and set kms_key_id.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			if is(r.get("enable_logging"), false) {
				hits = append(hits, Hit{Path: "enable_logging", Sev: High, Msg: "The trail exists but records nothing.", Fix: fix(true, "Turn logging on", "enable_logging")})
			}
			if r.get("kms_key_id") == nil {
				hits = append(hits, Hit{Path: "kms_key_id", Sev: Low, Msg: "Audit logs use S3-managed keys, so anyone who can read the bucket reads the trail."})
			}
			return hits
		}},
	{ID: "TG-AWS-GD-001", Title: "GuardDuty detector is suspended", Severity: Medium, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"aws_guardduty_detector"}, Remediation: "Set enable = true.",
		Check: func(r *Resource) []Hit {
			if is(r.get("enable"), false) {
				return []Hit{{Path: "enable", Msg: "Threat detection is turned off.", Fix: fix(true, "Enable GuardDuty", "enable")}}
			}
			return nil
		}},
	{ID: "TG-AWS-EC2-002", Title: "AMI is shared publicly", Severity: Critical, Category: CatSecurity, CWE: "CWE-200",
		Types: []string{"aws_ami_launch_permission"}, Remediation: "Share the image with specific account IDs, never group = \"all\".",
		Check: func(r *Resource) []Hit {
			if g, _ := asString(r.get("group")); g == "all" {
				return []Hit{{Path: "group", Msg: "Anyone can launch this image and read whatever was baked into it."}}
			}
			return nil
		}},
	{ID: "TG-AWS-EC2-003", Title: "Instance gets a public IP address", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"aws_instance", "aws_launch_template"}, Remediation: "Set associate_public_ip_address = false and reach instances through a load balancer, bastion or SSM.",
		Check: func(r *Resource) []Hit {
			path := "associate_public_ip_address"
			if r.Type == "aws_launch_template" {
				path = "network_interfaces.associate_public_ip_address"
			}
			if v := r.get(path); is(v, true) {
				return []Hit{{Path: strings.Split(path, ".")[0], Msg: "The instance is directly addressable from the internet."}}
			}
			return nil
		}},
	{ID: "TG-AWS-SG-002", Title: "Default security group has rules", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"aws_default_security_group"}, Remediation: "Remove every ingress and egress block; attach purpose-built security groups instead.",
		Check: func(r *Resource) []Hit {
			if len(r.blocks("ingress")) > 0 || len(r.blocks("egress")) > 0 {
				return []Hit{{Path: "ingress", Msg: "Resources that fall back to the default group silently get this access (CIS: the default group must allow nothing)."}}
			}
			return nil
		}},
	{ID: "TG-AWS-NACL-001", Title: "Network ACL allows admin ports or all traffic from the internet", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"aws_network_acl_rule", "aws_network_acl"}, Remediation: "Restrict cidr_block, or deny 22 and 3389 from 0.0.0.0/0 and ::/0.",
		Check: func(r *Resource) []Hit {
			rules, action, path := []map[string]any{r.Attrs}, "rule_action", ""
			if r.Type == "aws_network_acl" {
				rules, action, path = r.blocks("ingress"), "action", "ingress"
			} else if is(r.Attrs["egress"], true) {
				return nil
			}
			for _, m := range rules {
				if a, _ := asString(m[action]); a != "allow" || !anyWorld(m["cidr_block"], m["ipv6_cidr_block"]) {
					continue
				}
				proto, _ := asString(m["protocol"])
				lo, _ := asFloat(m["from_port"])
				hi, _ := asFloat(m["to_port"])
				if proto == "-1" || proto == "all" || (lo <= 22 && hi >= 22) || (lo <= 3389 && hi >= 3389) {
					return []Hit{{Path: path, Msg: "The subnet admits SSH, RDP or all traffic from the whole internet."}}
				}
			}
			return nil
		}},
	{ID: "TG-AWS-APIGW-002", Title: "API Gateway stage has no access logging", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"aws_api_gateway_stage", "aws_apigatewayv2_stage"}, Remediation: "Add access_log_settings with a destination_arn and format.",
		Check: func(r *Resource) []Hit {
			if r.get("access_log_settings") == nil {
				return []Hit{{Path: "access_log_settings", Msg: "API calls are not logged, so abuse cannot be traced."}}
			}
			return nil
		}},
	{ID: "TG-AWS-LB-003", Title: "Load balancer access logs are disabled", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"aws_lb", "aws_alb"}, Remediation: "Add access_logs { bucket = ..., enabled = true }.",
		Check: func(r *Resource) []Hit {
			if t, _ := asString(r.get("load_balancer_type")); t != "gateway" && notTrue(r.get("access_logs.enabled")) {
				return []Hit{{Path: "access_logs", Msg: "Requests are not logged (enabled defaults to false even when a bucket is set)."}}
			}
			return nil
		}},
	{ID: "TG-AWS-CODEBUILD-001", Title: "CodeBuild output or logs are unencrypted", Severity: Medium, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_codebuild_project"}, Remediation: "Remove encryption_disabled = true from artifacts and S3 logs; justify privileged_mode with a waiver.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			for _, p := range []string{"artifacts.encryption_disabled", "secondary_artifacts.encryption_disabled", "logs_config.s3_logs.encryption_disabled"} {
				if is(r.get(p), true) {
					hits = append(hits, Hit{Path: strings.Split(p, ".")[0], Msg: "Build output is stored unencrypted (" + p + ")."})
				}
			}
			if is(r.get("environment.privileged_mode"), true) {
				hits = append(hits, Hit{Path: "environment", Sev: Low, Msg: "Builds run privileged; a malicious dependency gets root on the build host."})
			}
			return hits
		}},
	{ID: "TG-AWS-SSM-001", Title: "Secret stored as a plaintext SSM parameter", Severity: High, Category: CatSecurity, CWE: "CWE-312",
		Types: []string{"aws_ssm_parameter"}, Remediation: "Use type = \"SecureString\" (replaces the parameter) and never insecure_value for secrets.",
		Check: func(r *Resource) []Hit {
			name, _ := asString(r.get("name"))
			if t, _ := asString(r.get("type")); t != "SecureString" && !isUnknown(r.get("type")) && secretNameRE.MatchString(name) {
				return []Hit{{Path: "type", Msg: name + " looks like a secret but is stored unencrypted and shown in the console."}}
			}
			return nil
		}},
	{ID: "TG-AWS-CDN-002", Title: "CloudFront reaches its origin over HTTP or old TLS", Severity: Medium, Category: CatSecurity, CWE: "CWE-319",
		Types: []string{"aws_cloudfront_distribution"}, Remediation: "Use origin_protocol_policy = \"https-only\" and origin_ssl_protocols = [\"TLSv1.2\"].",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			for _, o := range r.blocks("origin") {
				c := get(o, "custom_origin_config")
				if p, _ := asString(get(c, "origin_protocol_policy")); p == "http-only" || p == "match-viewer" {
					hits = append(hits, Hit{Path: "origin", Msg: "Traffic from the CDN to the origin can travel unencrypted (" + p + ")."})
				}
				if contains(asStrings(get(c, "origin_ssl_protocols")), "SSLv3", "TLSv1", "TLSv1.1") {
					hits = append(hits, Hit{Path: "origin", Msg: "The origin connection allows SSLv3 or TLS 1.0/1.1."})
				}
			}
			return hits
		}},

	// Azure (azurerm v4 and v5 field names)
	{ID: "TG-AZ-ST-003", Title: "Storage account allows Shared Key authorization", Severity: Low, Category: CatSecurity, CWE: "CWE-287",
		Types: []string{"azurerm_storage_account"}, Remediation: "Set shared_access_key_enabled = false once clients use Entra ID.",
		Check: func(r *Resource) []Hit {
			if notFalse(r.get("shared_access_key_enabled")) {
				return []Hit{{Path: "shared_access_key_enabled", Msg: "Account keys and SAS tokens grant full access and are hard to rotate."}}
			}
			return nil
		}},
	{ID: "TG-AZ-ST-004", Title: "Blob container allows anonymous read", Severity: High, Category: CatSecurity, CWE: "CWE-732",
		Types: []string{"azurerm_storage_container"}, Remediation: "Set container_access_type = \"private\".",
		Check: func(r *Resource) []Hit {
			if v, _ := asString(r.get("container_access_type")); v == "blob" || v == "container" {
				return []Hit{{Path: "container_access_type", Msg: "Anyone on the internet can read blobs in this container.", Fix: fix("private", "Make the container private", "container_access_type")}}
			}
			return nil
		}},
	{ID: "TG-AZ-ST-005", Title: "Storage account network default is Allow", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"azurerm_storage_account", "azurerm_storage_account_network_rules"}, Remediation: "Set default_action = \"Deny\" and list allowed subnets or IP ranges.",
		Check: func(r *Resource) []Hit {
			path := "network_rules.default_action"
			if r.Type == "azurerm_storage_account_network_rules" {
				path = "default_action"
			}
			if v, _ := asString(r.get(path)); v == "Allow" {
				return []Hit{{Path: strings.Split(path, ".")[0], Msg: "Any network can reach the storage endpoints."}}
			}
			return nil
		}},
	{ID: "TG-AZ-KV-002", Title: "Key Vault is reachable from any network", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"azurerm_key_vault"}, Remediation: "Add network_acls { default_action = \"Deny\", bypass = \"AzureServices\" } or disable public network access.",
		Check: func(r *Resource) []Hit {
			if is(r.get("public_network_access_enabled"), false) {
				return nil
			}
			if v, _ := asString(r.get("network_acls.default_action")); v == "Allow" || (r.get("network_acls") == nil && !isUnknown(r.get("public_network_access_enabled"))) {
				return []Hit{{Path: "network_acls", Msg: "Secrets and keys are reachable from any network (only authentication protects them)."}}
			}
			return nil
		}},
	{ID: "TG-AZ-SQL-002", Title: "Azure SQL server is public or lacks Entra ID admin", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"azurerm_mssql_server"}, Remediation: "Set public_network_access_enabled = false (use private endpoints) and configure azuread_administrator.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			if is(r.get("public_network_access_enabled"), true) {
				hits = append(hits, Hit{Path: "public_network_access_enabled", Msg: "The server has a public endpoint.", Fix: fix(false, "Disable public network access", "public_network_access_enabled")})
			}
			if r.get("azuread_administrator") == nil {
				hits = append(hits, Hit{Path: "azuread_administrator", Sev: Low, Msg: "Only SQL logins exist; there is no central identity or MFA."})
			}
			return hits
		}},
	{ID: "TG-AZ-DB-002", Title: "Flexible database server allows public access", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"azurerm_postgresql_flexible_server", "azurerm_mysql_flexible_server"}, Remediation: "Deploy into a delegated subnet or disable public network access.",
		Check: func(r *Resource) []Hit {
			if r.get("delegated_subnet_id") != nil {
				return nil
			}
			pg := is(r.get("public_network_access_enabled"), true)
			my, _ := asString(r.get("public_network_access"))
			if pg || my == "Enabled" {
				return []Hit{{Path: "public_network_access_enabled", Msg: "The database server has a public endpoint."}}
			}
			return nil
		}},
	{ID: "TG-AZ-COSMOS-001", Title: "Cosmos DB is open to the internet or uses key auth", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"azurerm_cosmosdb_account"}, Remediation: "Restrict with ip_range_filter or virtual network rules, and set local_authentication_enabled = false.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			open := notFalse(r.get("public_network_access_enabled")) && notTrue(r.get("is_virtual_network_filter_enabled")) && len(asStrings(r.get("ip_range_filter"))) == 0 && !isUnknown(r.get("ip_range_filter"))
			if open {
				hits = append(hits, Hit{Path: "public_network_access_enabled", Msg: "The database accepts connections from any network."})
			}
			if is(r.get("local_authentication_enabled"), true) {
				hits = append(hits, Hit{Path: "local_authentication_enabled", Sev: Medium, Msg: "Primary keys grant full access; prefer Entra ID.", Fix: fix(false, "Disable key authentication", "local_authentication_enabled")})
			}
			return hits
		}},
	{ID: "TG-AZ-REDIS-001", Title: "Azure Cache for Redis has the non-TLS port open", Severity: High, Category: CatSecurity, CWE: "CWE-319",
		Types: []string{"azurerm_redis_cache"}, Remediation: "Set non_ssl_port_enabled = false.",
		Check: func(r *Resource) []Hit {
			if is(r.get("non_ssl_port_enabled"), true) || is(r.get("enable_non_ssl_port"), true) {
				return []Hit{{Path: "non_ssl_port_enabled", Msg: "Port 6379 accepts plaintext connections, including the access key."}}
			}
			return nil
		}},
	{ID: "TG-AZ-ACR-002", Title: "Container registry allows anonymous pull", Severity: High, Category: CatSecurity, CWE: "CWE-306",
		Types: []string{"azurerm_container_registry"}, Remediation: "Set anonymous_pull_enabled = false.",
		Check: func(r *Resource) []Hit {
			if is(r.get("anonymous_pull_enabled"), true) {
				return []Hit{{Path: "anonymous_pull_enabled", Msg: "Anyone can download every image, including baked-in configuration.", Fix: fix(false, "Disable anonymous pull", "anonymous_pull_enabled")}}
			}
			return nil
		}},
	{ID: "TG-AZ-AKS-002", Title: "AKS cluster lacks core hardening", Severity: Low, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"azurerm_kubernetes_cluster"}, Remediation: "Set local_account_disabled = true (with Entra ID RBAC) and a network_profile.network_policy.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			if notTrue(r.get("local_account_disabled")) {
				hits = append(hits, Hit{Path: "local_account_disabled", Msg: "A static admin kubeconfig exists that bypasses Entra ID."})
			}
			if r.get("network_profile.network_policy") == nil && !isUnknown(r.get("network_profile")) {
				hits = append(hits, Hit{Path: "network_profile", Msg: "No network policy engine: every pod can reach every other pod."})
			}
			return hits
		}},
	{ID: "TG-AZ-IAM-001", Title: "Custom role grants all actions", Severity: High, Category: CatSecurity, CWE: "CWE-269",
		Types: []string{"azurerm_role_definition"}, Remediation: "List the specific actions the role needs.",
		Check: func(r *Resource) []Hit {
			for _, p := range r.blocks("permissions") {
				if contains(asStrings(p["actions"]), "*") {
					return []Hit{{Path: "permissions", Msg: `actions = ["*"] makes this an owner-equivalent custom role.`}}
				}
			}
			return nil
		}},
	{ID: "TG-AZ-MSG-001", Title: "Event Hub or Service Bus allows SAS keys", Severity: Low, Category: CatSecurity, CWE: "CWE-287",
		Types: []string{"azurerm_eventhub_namespace", "azurerm_servicebus_namespace"}, Remediation: "Set local_authentication_enabled (Event Hub) or local_auth_enabled (Service Bus) to false and use Entra ID.",
		Check: func(r *Resource) []Hit {
			key := "local_authentication_enabled"
			if r.Type == "azurerm_servicebus_namespace" {
				key = "local_auth_enabled"
			}
			if notFalse(r.get(key)) {
				return []Hit{{Path: key, Msg: "Shared access keys grant broad, long-lived access."}}
			}
			return nil
		}},

	// Google Cloud
	{ID: "TG-GCP-GKE-002", Title: "GKE workloads can reach node credentials", Severity: Medium, Category: CatSecurity, CWE: "CWE-522",
		Types: []string{"google_container_cluster", "google_container_node_pool"}, Remediation: "Enable workload_identity_config and use workload_metadata_config { mode = \"GKE_METADATA\" }.",
		Check: func(r *Resource) []Hit {
			if m, _ := asString(r.get("node_config.workload_metadata_config.mode")); m == "GCE_METADATA" {
				return []Hit{{Path: "node_config", Msg: "Pods can read the node's service account token from the metadata server."}}
			}
			if r.Type == "google_container_cluster" && notTrue(r.get("enable_autopilot")) && r.get("workload_identity_config") == nil {
				return []Hit{{Path: "workload_identity_config", Sev: Low, Msg: "Workload Identity is off, so pods share the node's identity."}}
			}
			return nil
		}},
	{ID: "TG-GCP-GKE-003", Title: "GKE issues client certificates or has logging off", Severity: High, Category: CatSecurity, CWE: "CWE-287",
		Types: []string{"google_container_cluster"}, Remediation: "Set issue_client_certificate = false and keep logging_service and monitoring_service enabled.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			if is(r.get("master_auth.client_certificate_config.issue_client_certificate"), true) {
				hits = append(hits, Hit{Path: "master_auth", Msg: "A long-lived client certificate gives cluster access that cannot be revoked."})
			}
			for _, k := range []string{"logging_service", "monitoring_service"} {
				if v, _ := asString(r.get(k)); v == "none" {
					hits = append(hits, Hit{Path: k, Sev: Medium, Msg: k + " is off, so cluster activity is not recorded."})
				}
			}
			return hits
		}},
	{ID: "TG-GCP-GKE-004", Title: "GKE nodes are public or not shielded", Severity: Low, Category: CatSecurity, CWE: "CWE-693",
		Types: []string{"google_container_cluster"}, Remediation: "Use private_cluster_config { enable_private_nodes = true } and keep enable_shielded_nodes = true.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			if is(r.get("enable_shielded_nodes"), false) {
				hits = append(hits, Hit{Path: "enable_shielded_nodes", Sev: Medium, Msg: "Nodes boot without verified firmware.", Fix: fix(true, "Shield the nodes", "enable_shielded_nodes")})
			}
			if notTrue(r.get("private_cluster_config.enable_private_nodes")) && notTrue(r.get("enable_autopilot")) {
				hits = append(hits, Hit{Path: "private_cluster_config", Msg: "Nodes have public IP addresses."})
			}
			return hits
		}},
	{ID: "TG-GCP-SQL-002", Title: "Cloud SQL automated backups are disabled", Severity: Medium, Category: CatReliability, CWE: "CWE-693",
		Types: []string{"google_sql_database_instance"}, Remediation: "Add settings { backup_configuration { enabled = true } }.",
		Check: func(r *Resource) []Hit {
			if r.get("master_instance_name") != nil {
				return nil // read replicas do not take backups
			}
			if notTrue(r.get("settings.backup_configuration.enabled")) {
				return []Hit{{Path: "settings", Msg: "No automated backups: data loss is unrecoverable."}}
			}
			return nil
		}},
	{ID: "TG-GCP-SQL-003", Title: "Cloud SQL database flag weakens security", Severity: Medium, Category: CatSecurity, CWE: "CWE-732",
		Types: []string{"google_sql_database_instance"}, Remediation: "Turn off local_infile (MySQL) and cross db ownership chaining, contained database authentication, external scripts and remote access (SQL Server).",
		Check: func(r *Resource) []Hit {
			bad := map[string]bool{"local_infile": true, "cross db ownership chaining": true, "contained database authentication": true, "external scripts enabled": true, "remote access": true}
			var hits []Hit
			for _, f := range blocksAt(r.get("settings"), "database_flags") {
				name, _ := asString(f["name"])
				if v, _ := asString(f["value"]); bad[name] && strings.EqualFold(v, "on") {
					hits = append(hits, Hit{Path: "settings", Msg: "Database flag " + name + " is on."})
				}
			}
			return hits
		}},
	{ID: "TG-GCP-GCS-002", Title: "Bucket does not enforce public access prevention", Severity: Low, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"google_storage_bucket"}, Remediation: "Set public_access_prevention = \"enforced\".",
		Check: func(r *Resource) []Hit {
			if v, _ := asString(r.get("public_access_prevention")); v != "enforced" && !isUnknown(r.get("public_access_prevention")) {
				return []Hit{{Path: "public_access_prevention", Msg: "A later IAM change can still make objects public.", Fix: fix("enforced", "Enforce public access prevention", "public_access_prevention")}}
			}
			return nil
		}},
	{ID: "TG-GCP-VM-003", Title: "VM disables OS Login or accepts project SSH keys", Severity: Medium, Category: CatSecurity, CWE: "CWE-287",
		Types: []string{"google_compute_instance", "google_compute_instance_template", "google_compute_project_metadata", "google_compute_project_metadata_item"}, Remediation: "Use OS Login (enable-oslogin = \"TRUE\") and set block-project-ssh-keys = \"true\" on instances.",
		Check: func(r *Resource) []Hit {
			if r.Type == "google_compute_project_metadata_item" {
				k, _ := asString(r.get("key"))
				v, _ := asString(r.get("value"))
				if k == "enable-oslogin" && !strings.EqualFold(v, "true") {
					return []Hit{{Path: "value", Msg: "OS Login is off project-wide, so SSH keys are managed by hand."}}
				}
				return nil
			}
			if v, ok := asString(r.get("metadata.enable-oslogin")); ok && strings.EqualFold(v, "false") {
				return []Hit{{Path: "metadata", Msg: "OS Login is off, so SSH access is not tied to IAM."}}
			}
			if strings.HasPrefix(r.Type, "google_compute_instance") {
				if v, _ := asString(r.get("metadata.block-project-ssh-keys")); !strings.EqualFold(v, "true") && !isUnknown(r.get("metadata")) {
					return []Hit{{Path: "metadata", Sev: Low, Msg: "Project-wide SSH keys can log in to this VM."}}
				}
			}
			return nil
		}},
	{ID: "TG-GCP-VM-004", Title: "VM has an external IP or forwards packets", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"google_compute_instance", "google_compute_instance_template"}, Remediation: "Remove access_config (use Cloud NAT and IAP) and set can_ip_forward = false.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			for _, ni := range r.blocks("network_interface") {
				if _, ok := ni["access_config"]; ok {
					hits = append(hits, Hit{Path: "network_interface", Msg: "The VM has a public IP address (even an empty access_config assigns one)."})
					break
				}
			}
			if is(r.get("can_ip_forward"), true) {
				hits = append(hits, Hit{Path: "can_ip_forward", Sev: Low, Msg: "The VM can route traffic for other addresses.", Fix: fix(false, "Disable IP forwarding", "can_ip_forward")})
			}
			return hits
		}},
	{ID: "TG-GCP-IAM-002", Title: "Project-wide service account impersonation", Severity: High, Category: CatSecurity, CWE: "CWE-269",
		Types:       []string{"google_project_iam_member", "google_project_iam_binding", "google_folder_iam_member", "google_folder_iam_binding", "google_organization_iam_member", "google_organization_iam_binding"},
		Remediation: "Grant roles/iam.serviceAccountUser or TokenCreator on the specific service account, not the project.",
		Check: func(r *Resource) []Hit {
			if role, _ := asString(r.get("role")); role == "roles/iam.serviceAccountUser" || role == "roles/iam.serviceAccountTokenCreator" {
				return []Hit{{Path: "role", Msg: "The member can act as every service account in scope, including privileged ones."}}
			}
			return nil
		}},
	{ID: "TG-GCP-IAM-003", Title: "Service account has an admin or primitive role", Severity: High, Category: CatSecurity, CWE: "CWE-269",
		Types: []string{"google_project_iam_member", "google_project_iam_binding"}, Remediation: "Give service accounts narrow predefined roles; never grant roles to default service accounts.",
		Check: func(r *Resource) []Hit {
			members := append(asStrings(r.get("member")), asStrings(r.get("members"))...)
			role, _ := asString(r.get("role"))
			for _, m := range members {
				switch {
				case strings.HasSuffix(m, "-compute@developer.gserviceaccount.com") || strings.HasSuffix(m, "@appspot.gserviceaccount.com"):
					return []Hit{{Path: "member", Sev: Medium, Msg: "A default service account, used by every VM or App Engine app, gets " + role + "."}}
				case strings.HasPrefix(m, "serviceAccount:") && (role == "roles/owner" || role == "roles/editor" || strings.HasSuffix(strings.ToLower(role), "admin")):
					return []Hit{{Path: "role", Msg: "A service account key or workload gets " + role + "."}}
				}
			}
			return nil
		}},
	{ID: "TG-GCP-IAM-004", Title: "Resource IAM grants public access", Severity: Critical, Category: CatSecurity, CWE: "CWE-732",
		Types: []string{"google_kms_crypto_key_iam_member", "google_kms_crypto_key_iam_binding", "google_kms_key_ring_iam_member", "google_kms_key_ring_iam_binding",
			"google_secret_manager_secret_iam_member", "google_secret_manager_secret_iam_binding", "google_pubsub_topic_iam_member", "google_pubsub_topic_iam_binding",
			"google_artifact_registry_repository_iam_member", "google_artifact_registry_repository_iam_binding", "google_cloud_run_service_iam_member", "google_cloud_run_service_iam_binding",
			"google_cloud_run_v2_service_iam_member", "google_cloud_run_v2_service_iam_binding", "google_cloudfunctions_function_iam_member", "google_cloudfunctions_function_iam_binding",
			"google_cloudfunctions2_function_iam_member", "google_cloudfunctions2_function_iam_binding"},
		Remediation: "Grant to specific users, groups or service accounts. For a public API, put it behind a load balancer with authentication or Cloud Armor.",
		Check: func(r *Resource) []Hit {
			if !contains(append(asStrings(r.get("member")), asStrings(r.get("members"))...), "allUsers", "allAuthenticatedUsers") {
				return nil
			}
			sev := Critical
			switch {
			case strings.Contains(r.Type, "pubsub") || strings.Contains(r.Type, "artifact_registry"):
				sev = High
			case strings.Contains(r.Type, "cloud_run") || strings.Contains(r.Type, "cloudfunctions"):
				sev = Medium // often an intended public endpoint
			}
			return []Hit{{Path: "member", Sev: sev, Msg: "Everyone on the internet is granted access to this resource."}}
		}},
	{ID: "TG-GCP-IAM-005", Title: "Workload identity provider trusts any token from a shared issuer", Severity: High, Category: CatSecurity, CWE: "CWE-863",
		Types: []string{"google_iam_workload_identity_pool_provider"}, Remediation: "Set attribute_condition, e.g. assertion.repository == \"org/repo\".",
		Check: func(r *Resource) []Hit {
			issuer, _ := asString(r.get("oidc.issuer_uri"))
			shared := strings.Contains(issuer, "token.actions.githubusercontent.com") || strings.Contains(issuer, "gitlab.com") || strings.Contains(issuer, "app.terraform.io")
			if cond, _ := asString(r.get("attribute_condition")); shared && strings.TrimSpace(cond) == "" && !isUnknown(r.get("attribute_condition")) {
				return []Hit{{Path: "attribute_condition", Msg: "Every repository or workspace on " + issuer + " can exchange tokens for your Google credentials."}}
			}
			return nil
		}},
	{ID: "TG-GCP-LB-001", Title: "SSL policy allows old TLS", Severity: Medium, Category: CatSecurity, CWE: "CWE-326",
		Types: []string{"google_compute_ssl_policy"}, Remediation: "Set min_tls_version = \"TLS_1_2\" and profile = \"MODERN\" or \"RESTRICTED\".",
		Check: func(r *Resource) []Hit {
			if v, _ := asString(r.get("min_tls_version")); (v == "" && !isUnknown(r.get("min_tls_version"))) || v == "TLS_1_0" || v == "TLS_1_1" {
				return []Hit{{Path: "min_tls_version", Msg: "Load balancers using this policy accept TLS 1.0 (the default).", Fix: fix("TLS_1_2", "Require TLS 1.2", "min_tls_version")}}
			}
			return nil
		}},
	{ID: "TG-GCP-REDIS-001", Title: "Memorystore Redis has no AUTH or TLS", Severity: High, Category: CatSecurity, CWE: "CWE-306",
		Types: []string{"google_redis_instance"}, Remediation: "Set auth_enabled = true and transit_encryption_mode = \"SERVER_AUTHENTICATION\" (forces a new instance).",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			if notTrue(r.get("auth_enabled")) {
				hits = append(hits, Hit{Path: "auth_enabled", Msg: "Anything on the network can read and write the cache.", Fix: fix(true, "Require AUTH", "auth_enabled")})
			}
			if v, _ := asString(r.get("transit_encryption_mode")); (v == "" && !isUnknown(r.get("transit_encryption_mode"))) || v == "DISABLED" {
				hits = append(hits, Hit{Path: "transit_encryption_mode", Sev: Medium, Msg: "Cache traffic is unencrypted."})
			}
			return hits
		}},

	// Kubernetes
	{ID: "TG-K8S-004", Title: "Workload mounts a host path", Severity: Medium, Category: CatSecurity, CWE: "CWE-668",
		Remediation: "Use persistent volumes or projected volumes instead of host_path.",
		Check: func(r *Resource) []Hit {
			if !strings.HasPrefix(r.Type, "kubernetes_") {
				return nil
			}
			var hits []Hit
			walkMaps(r.Attrs, "", func(p string, m map[string]any) {
				if hp, ok := get(m, "host_path.path").(string); ok {
					sev := Medium
					if criticalHostPaths[strings.TrimRight(hp, "/")] || hp == "/" {
						sev = Critical
					}
					hits = append(hits, Hit{Path: p, Sev: sev, Msg: "Mounts " + hp + " from the node; a compromised container can tamper with the host."})
				}
			})
			return hits
		}},
	{ID: "TG-K8S-005", Title: "Container may run as root", Severity: Low, Category: CatSecurity, CWE: "CWE-250",
		Remediation: "Set security_context { run_as_non_root = true } on the pod or each container, and read_only_root_filesystem = true.",
		Check: func(r *Resource) []Hit {
			if !strings.HasPrefix(r.Type, "kubernetes_") {
				return nil
			}
			var hits []Hit
			forEachPodSpec(r.Attrs, func(p string, spec map[string]any) {
				podNonRoot := is(get(spec, "security_context.run_as_non_root"), true)
				for i, c := range blocksAt(spec, "container") {
					if !podNonRoot && notTrue(get(c, "security_context.run_as_non_root")) {
						if u, _ := asString(get(c, "security_context.run_as_user")); u == "" || u == "0" {
							name, _ := asString(c["name"])
							hits = append(hits, Hit{Path: join(p, "container."+strconv.Itoa(i)), Msg: "Container " + name + " can run as root."})
						}
					}
				}
			})
			return hits
		}},
	{ID: "TG-K8S-006", Title: "Container adds dangerous Linux capabilities", Severity: High, Category: CatSecurity, CWE: "CWE-250",
		Remediation: "Drop ALL capabilities and add back only what is needed; never SYS_ADMIN, NET_ADMIN or SYS_PTRACE.",
		Check: func(r *Resource) []Hit {
			if !strings.HasPrefix(r.Type, "kubernetes_") {
				return nil
			}
			var hits []Hit
			walkMaps(r.Attrs, "", func(p string, m map[string]any) {
				for _, c := range asStrings(get(m, "capabilities.add")) {
					if dangerousCaps[strings.TrimPrefix(strings.ToUpper(c), "CAP_")] {
						hits = append(hits, Hit{Path: p, Msg: "Adds " + c + ", which allows escaping to the node."})
					}
				}
			})
			return hits
		}},
	{ID: "TG-K8S-007", Title: "RBAC binding grants cluster-admin or binds anonymous users", Severity: Critical, Category: CatSecurity, CWE: "CWE-269",
		Types: []string{"kubernetes_cluster_role_binding", "kubernetes_cluster_role_binding_v1", "kubernetes_role_binding", "kubernetes_role_binding_v1"}, Remediation: "Bind least-privilege roles to named users, groups or service accounts.",
		Check: func(r *Resource) []Hit {
			role, _ := asString(r.get("role_ref.name"))
			for _, s := range r.blocks("subject") {
				name, _ := asString(s["name"])
				switch {
				case name == "system:anonymous" || name == "system:unauthenticated":
					return []Hit{{Path: "subject", Msg: "Unauthenticated requests get role " + role + "."}}
				case role == "cluster-admin" && name == "system:authenticated":
					return []Hit{{Path: "subject", Msg: "Every authenticated identity becomes cluster-admin."}}
				}
			}
			if role == "cluster-admin" {
				return []Hit{{Path: "role_ref", Sev: High, Msg: "Grants full control of the cluster."}}
			}
			return nil
		}},
	{ID: "TG-K8S-008", Title: "RBAC role uses wildcards or grants secret access", Severity: High, Category: CatSecurity, CWE: "CWE-269",
		Types: []string{"kubernetes_cluster_role", "kubernetes_cluster_role_v1", "kubernetes_role", "kubernetes_role_v1"}, Remediation: "List explicit verbs and resources; avoid secrets get/list and pods/exec create unless required.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			for _, rule := range r.blocks("rule") {
				verbs, res := asStrings(rule["verbs"]), asStrings(rule["resources"])
				switch {
				case contains(verbs, "*") && contains(res, "*"):
					hits = append(hits, Hit{Path: "rule", Msg: "Any verb on any resource: equivalent to cluster-admin in scope."})
				case contains(verbs, "*") || contains(res, "*"):
					hits = append(hits, Hit{Path: "rule", Sev: Medium, Msg: "Wildcard verbs or resources grant more than intended as APIs grow."})
				case contains(res, "secrets") && contains(verbs, "get", "list", "watch"):
					hits = append(hits, Hit{Path: "rule", Sev: Medium, Msg: "Can read secrets, including service account tokens."})
				case contains(res, "pods/exec") && contains(verbs, "create"):
					hits = append(hits, Hit{Path: "rule", Sev: Medium, Msg: "Can exec into pods and act as their service accounts."})
				}
			}
			return hits
		}},
}

var (
	escalationRE    = regexp.MustCompile(`(?i)^iam:(PassRole|CreatePolicyVersion|SetDefaultPolicyVersion|Attach(User|Role|Group)Policy|Put(User|Role|Group)Policy|CreateAccessKey|CreateLoginProfile|UpdateLoginProfile|UpdateAssumeRolePolicy|AddUserToGroup|Pass\*|Put\*|Attach\*)$`)
	iamAuthEngineRE = regexp.MustCompile(`^(aurora-)?(mysql|postgres(ql)?)$`)
	secretNameRE    = regexp.MustCompile(`(?i)(pass(word)?|secret|token|api[_-]?key|private[_-]?key|credential)`)

	criticalHostPaths = map[string]bool{"/var/run/docker.sock": true, "/run/containerd/containerd.sock": true, "/var/run/crio/crio.sock": true, "/etc": true, "/proc": true, "/root": true, "/var/lib/kubelet": true}
	dangerousCaps     = map[string]bool{"ALL": true, "SYS_ADMIN": true, "NET_ADMIN": true, "SYS_PTRACE": true, "SYS_MODULE": true, "DAC_READ_SEARCH": true, "BPF": true, "NET_RAW": true}
)

// notFalse reports a value that is true or absent (when the provider default is true).
func notFalse(v any) bool { return !isUnknown(v) && !is(v, false) }

// blocksAt returns nested blocks named name inside v (a block or list of blocks).
func blocksAt(v any, name string) []map[string]any {
	var out []map[string]any
	switch t := get(v, name).(type) {
	case []any:
		for _, e := range t {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
	case map[string]any:
		out = append(out, t)
	}
	if l, ok := v.([]any); ok && len(l) > 1 { // several parent blocks: collect from each
		out = nil
		for _, e := range l {
			out = append(out, blocksAt(e, name)...)
		}
	}
	return out
}

// forEachPodSpec calls fn for every pod spec (a map with containers) in a workload.
func forEachPodSpec(attrs map[string]any, fn func(path string, spec map[string]any)) {
	walkMaps(attrs, "", func(p string, m map[string]any) {
		if _, ok := m["container"]; ok {
			fn(p, m)
		}
	})
}

const githubSub = "token.actions.githubusercontent.com:sub"

// githubOIDCOpen: a GitHub OIDC trust with no repo restriction on the sub claim.
func githubOIDCOpen(r *Resource) bool {
	type trust struct {
		federated []string
		actions   []string
		subs      []string
		hasSub    bool
	}
	var ts []trust
	if r.Type == "aws_iam_policy_document" {
		for _, s := range r.blocks("statement") {
			t := trust{actions: asStrings(s["actions"])}
			for _, p := range blocksAt(s, "principals") {
				t.federated = append(t.federated, asStrings(p["identifiers"])...)
			}
			for _, c := range blocksAt(s, "condition") {
				if v, _ := asString(c["variable"]); v == githubSub {
					t.hasSub, t.subs = true, append(t.subs, asStrings(c["values"])...)
				}
			}
			ts = append(ts, t)
		}
	} else {
		doc := r.get("assume_role_policy")
		if s, ok := doc.(string); ok {
			_ = json.Unmarshal([]byte(s), &doc)
		}
		raw, _ := get(doc, "Statement").([]any)
		if m, ok := get(doc, "Statement").(map[string]any); ok {
			raw = []any{m}
		}
		for _, e := range raw {
			t := trust{actions: asStrings(get(e, "Action")), federated: asStrings(get(e, "Principal.Federated"))}
			if conds, ok := get(e, "Condition").(map[string]any); ok {
				for _, op := range conds {
					// The key contains dots, so index the map directly rather than with get.
					if m, ok := op.(map[string]any); ok && m[githubSub] != nil {
						t.hasSub, t.subs = true, append(t.subs, asStrings(m[githubSub])...)
					}
				}
			}
			ts = append(ts, t)
		}
	}
	for _, t := range ts {
		github := false
		for _, f := range t.federated {
			github = github || strings.Contains(f, "token.actions.githubusercontent.com")
		}
		if !github || !contains(t.actions, "sts:AssumeRoleWithWebIdentity") {
			continue
		}
		if !t.hasSub {
			return true
		}
		for _, s := range t.subs {
			if s == "*" || s == "repo:*" || s == "repo:*/*" || strings.HasPrefix(s, "repo:*") {
				return true
			}
		}
	}
	return false
}
