package engine

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// A check is one setting on one kind of resource. Most rules are just that, so
// they live in a table instead of each getting a function.
type check struct {
	ID, Title string
	Sev       Severity
	CWE       string
	Types     []string
	Kind      string // eq, missing, missing_or_eq, lt, lt_or_missing, gt, want, set, present
	Path      string
	Cat       string  // defaults to security
	Why       string  // impact, appended to the generated message
	Want      []any   // want: the allowed values
	MissingOK bool    // want, set: an absent value passes
	Bad       []any   // eq kinds
	Num       float64 // lt and gt kinds
	Good      any     // a safe value; also used as the fix when Fixable
	Fixable   bool    // every parent in Path is a block, so hclwrite can set it
	Msg       string
}

func (c check) rule() Rule {
	shown := strings.ReplaceAll(c.Path, ".0", "")
	remedy := fmt.Sprintf("Set %s = %s.", shown, literal(c.Good))
	switch {
	case c.Kind == "missing" || c.Kind == "set":
		remedy = fmt.Sprintf("Configure %s.", shown)
	case c.Kind == "present":
		remedy = fmt.Sprintf("Remove %s.", shown)
	case c.Kind == "want" && len(c.Want) > 1:
		remedy = fmt.Sprintf("Set %s to one of %s.", shown, literals(c.Want))
	}
	cat := c.Cat
	if cat == "" {
		cat = CatSecurity
	}
	return Rule{ID: c.ID, Title: c.Title, Severity: c.Sev, Category: cat, CWE: c.CWE, Types: c.Types, Remediation: remedy,
		Check: func(r *Resource) []Hit {
			v := r.get(c.Path)
			if isUnknown(v) || containsUnknown(v) || unknownAlong(r.Attrs, c.Path) || !c.violated(v) {
				return nil
			}
			msg := c.Msg
			if msg == "" {
				if empty(v) {
					msg = shown + " is not set."
				} else {
					msg = fmt.Sprintf("%s is %s.", shown, literal(v))
				}
				if c.Why != "" {
					msg += " " + c.Why
				}
			}
			h := Hit{Path: strings.Split(c.Path, ".")[0], Msg: msg}
			if c.Fixable {
				h.Fix = fix(c.Good, fmt.Sprintf("Set %s = %s", shown, literal(c.Good)), strings.Split(shown, ".")...)
			}
			return []Hit{h}
		}}
}

func (c check) violated(v any) bool {
	n, isNum := asFloat(v)
	switch c.Kind {
	case "want":
		if empty(v) {
			return !c.MissingOK
		}
		return !oneOf(v, c.Want)
	case "set":
		return empty(v) && !c.MissingOK
	case "present":
		return !empty(v)
	case "missing":
		return v == nil
	case "missing_or_eq":
		return v == nil || oneOf(v, c.Bad)
	case "eq":
		return v != nil && oneOf(v, c.Bad)
	case "lt":
		return isNum && n < c.Num
	case "lt_or_missing":
		return v == nil || (isNum && n < c.Num)
	case "gt":
		return isNum && n > c.Num
	}
	return false
}

// empty is true for an absent value, an empty string and an empty list.
func empty(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case []any:
		return len(t) == 0
	}
	return false
}

func containsUnknown(v any) bool {
	if l, ok := v.([]any); ok {
		for _, e := range l {
			if isUnknown(e) {
				return true
			}
		}
	}
	return false
}

func literals(vs []any) string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = literal(v)
	}
	return strings.Join(out, ", ")
}

func oneOf(v any, set []any) bool {
	if l, ok := v.([]any); ok && len(l) > 1 { // a list matches when any element does
		for _, e := range l {
			if oneOf(e, set) {
				return true
			}
		}
		return false
	}
	for _, b := range set {
		if strings.EqualFold(scalar(v), scalar(b)) {
			return true
		}
	}
	return false
}

func scalar(v any) string {
	switch t := v.(type) {
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case []any: // a single-element list compares as its element
		if len(t) == 1 {
			return scalar(t[0])
		}
	}
	return fmt.Sprint(v)
}

func literal(v any) string {
	if s, ok := v.(string); ok {
		return strconv.Quote(s)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

var k8sWorkloads = []string{"kubernetes_pod", "kubernetes_pod_v1", "kubernetes_deployment", "kubernetes_deployment_v1", "kubernetes_daemon_set_v1", "kubernetes_daemonset",
	"kubernetes_stateful_set", "kubernetes_stateful_set_v1", "kubernetes_job", "kubernetes_job_v1", "kubernetes_cron_job", "kubernetes_cron_job_v1",
	"kubernetes_replication_controller", "kubernetes_replication_controller_v1"}

var appServices = []string{"azurerm_linux_web_app", "azurerm_windows_web_app", "azurerm_linux_function_app", "azurerm_windows_function_app"}

var tableChecks = []check{
	// AWS
	{ID: "TG-AWS-EMR-001", Sev: Medium, CWE: "CWE-311", Title: "EMR cluster has no security configuration", Types: []string{"aws_emr_cluster"}, Kind: "missing", Path: "security_configuration", Msg: "Without a security configuration, EMR does not encrypt data at rest, local disks or traffic between nodes."},
	{ID: "TG-AWS-EMR-002", Sev: High, CWE: "CWE-284", Title: "EMR block public access is disabled", Types: []string{"aws_emr_block_public_access_configuration"}, Kind: "eq", Path: "block_public_security_group_rules", Bad: []any{false}, Good: true, Fixable: true, Msg: "EMR clusters can be launched with security groups open to the internet."},
	{ID: "TG-AWS-GLUE-001", Sev: Medium, CWE: "CWE-311", Title: "Glue Data Catalog is not encrypted", Types: []string{"aws_glue_data_catalog_encryption_settings"}, Kind: "eq", Path: "data_catalog_encryption_settings.encryption_at_rest.catalog_encryption_mode", Bad: []any{"DISABLED"}, Good: "SSE-KMS", Fixable: true, Msg: "Table metadata in the Data Catalog is stored without encryption."},
	{ID: "TG-AWS-GLUE-002", Sev: Medium, CWE: "CWE-312", Title: "Glue connection passwords are returned in plaintext", Types: []string{"aws_glue_data_catalog_encryption_settings"}, Kind: "eq", Path: "data_catalog_encryption_settings.connection_password_encryption.return_connection_password_encrypted", Bad: []any{false}, Good: true, Fixable: true, Msg: "Anyone allowed to call GetConnection can read stored database passwords."},
	{ID: "TG-AWS-GLUE-003", Sev: Medium, CWE: "CWE-311", Title: "Glue security configuration leaves S3 data unencrypted", Types: []string{"aws_glue_security_configuration"}, Kind: "eq", Path: "encryption_configuration.s3_encryption.s3_encryption_mode", Bad: []any{"DISABLED"}, Good: "SSE-KMS", Fixable: true, Msg: "Glue jobs using this configuration write S3 output without encryption."},
	{ID: "TG-AWS-ATHENA-001", Sev: Medium, CWE: "CWE-311", Title: "Athena workgroup query results are not encrypted", Types: []string{"aws_athena_workgroup"}, Kind: "missing", Path: "configuration.result_configuration.encryption_configuration", Msg: "Query results written to S3 are not encrypted by the workgroup."},
	{ID: "TG-AWS-ATHENA-002", Sev: Low, CWE: "CWE-693", Title: "Athena workgroup lets clients override its settings", Types: []string{"aws_athena_workgroup"}, Kind: "eq", Path: "configuration.enforce_workgroup_configuration", Bad: []any{false}, Good: true, Fixable: true, Msg: "Clients can turn off result encryption and change where results go."},
	{ID: "TG-AWS-BACKUP-001", Sev: Low, CWE: "CWE-311", Title: "Backup vault uses the AWS-managed key", Types: []string{"aws_backup_vault"}, Kind: "missing", Path: "kms_key_arn", Msg: "Recovery points use aws/backup, so you can't control or audit who uses the key."},
	{ID: "TG-AWS-ACM-001", Sev: Low, CWE: "CWE-693", Title: "Certificate Transparency logging is disabled", Types: []string{"aws_acm_certificate"}, Kind: "eq", Path: "options.certificate_transparency_logging_preference", Bad: []any{"DISABLED"}, Good: "ENABLED", Fixable: true, Msg: "Mis-issued certificates are harder to spot, and browsers may reject this one."},
	{ID: "TG-AWS-CONFIG-001", Sev: Medium, CWE: "CWE-778", Title: "AWS Config recorder is stopped", Types: []string{"aws_config_configuration_recorder_status"}, Kind: "eq", Path: "is_enabled", Bad: []any{false}, Good: true, Fixable: true, Msg: "Configuration changes are not recorded, so audits and Config rules have nothing."},
	{ID: "TG-AWS-ECR-002", Sev: Low, CWE: "CWE-311", Title: "ECR repository is not encrypted with KMS", Types: []string{"aws_ecr_repository"}, Kind: "missing_or_eq", Path: "encryption_configuration.encryption_type", Bad: []any{"AES256"}, Good: "KMS", Msg: "Images use an AWS-owned key that you can't restrict or audit."},
	{ID: "TG-AWS-ECS-002", Sev: Medium, CWE: "CWE-250", Title: "ECS task uses host networking", Types: []string{"aws_ecs_task_definition"}, Kind: "eq", Path: "network_mode", Bad: []any{"host"}, Good: "awsvpc", Msg: "Containers share the host network and can bind to or sniff any host port."},
	{ID: "TG-AWS-ECS-003", Sev: High, CWE: "CWE-250", Title: "ECS task shares the host process namespace", Types: []string{"aws_ecs_task_definition"}, Kind: "eq", Path: "pid_mode", Bad: []any{"host"}, Good: "task", Fixable: true, Msg: "Containers can see and signal every process on the host."},
	{ID: "TG-AWS-SFN-001", Sev: Low, CWE: "CWE-778", Title: "Step Functions execution logging is off", Types: []string{"aws_sfn_state_machine"}, Kind: "missing_or_eq", Path: "logging_configuration.level", Bad: []any{"OFF"}, Good: "ERROR", Msg: "Failed or abused executions leave no history in CloudWatch."},
	{ID: "TG-AWS-APPSYNC-001", Sev: Low, CWE: "CWE-200", Title: "AppSync introspection is enabled", Types: []string{"aws_appsync_graphql_api"}, Kind: "missing_or_eq", Path: "introspection_config", Bad: []any{"ENABLED"}, Good: "DISABLED", Fixable: true, Msg: "Anyone with access can download the whole API schema."},
	{ID: "TG-AWS-COGNITO-001", Sev: Low, CWE: "CWE-308", Title: "Cognito user pool does not use MFA", Types: []string{"aws_cognito_user_pool"}, Kind: "missing_or_eq", Path: "mfa_configuration", Bad: []any{"OFF"}, Good: "ON", Msg: "A stolen password alone is enough to log in."},
	{ID: "TG-AWS-COGNITO-002", Sev: Medium, CWE: "CWE-306", Title: "Cognito identity pool allows unauthenticated identities", Types: []string{"aws_cognito_identity_pool"}, Kind: "eq", Path: "allow_unauthenticated_identities", Bad: []any{true}, Good: false, Fixable: true, Msg: "Anonymous callers get AWS credentials for the unauthenticated role."},
	{ID: "TG-AWS-TRANSFER-001", Sev: Medium, CWE: "CWE-327", Title: "Transfer Family server uses an outdated security policy", Types: []string{"aws_transfer_server"}, Kind: "missing_or_eq", Path: "security_policy_name",
		Bad: []any{"TransferSecurityPolicy-2018-11", "TransferSecurityPolicy-2020-06", "TransferSecurityPolicy-FIPS-2020-06", "TransferSecurityPolicy-Restricted-2018-11", "TransferSecurityPolicy-Restricted-2020-06"}, Good: "TransferSecurityPolicy-2024-01", Fixable: true, Msg: "The server accepts weak SSH and TLS ciphers."},
	{ID: "TG-AWS-DAX-001", Sev: Medium, CWE: "CWE-311", Title: "DAX cluster is not encrypted at rest", Types: []string{"aws_dax_cluster"}, Kind: "missing_or_eq", Path: "server_side_encryption.enabled", Bad: []any{false}, Good: true, Msg: "Cached DynamoDB data sits unencrypted on cluster nodes."},
	{ID: "TG-AWS-DAX-002", Sev: Medium, CWE: "CWE-319", Title: "DAX endpoint does not use TLS", Types: []string{"aws_dax_cluster"}, Kind: "missing_or_eq", Path: "cluster_endpoint_encryption_type", Bad: []any{"NONE"}, Good: "TLS", Msg: "Clients talk to DAX in plaintext."},
	{ID: "TG-AWS-MEMDB-001", Sev: High, CWE: "CWE-319", Title: "MemoryDB cluster has TLS disabled", Types: []string{"aws_memorydb_cluster"}, Kind: "eq", Path: "tls_enabled", Bad: []any{false}, Good: true, Msg: "Data and credentials travel to the cluster unencrypted."},
	{ID: "TG-AWS-MEMDB-002", Sev: High, CWE: "CWE-306", Title: "MemoryDB cluster uses the open-access ACL", Types: []string{"aws_memorydb_cluster"}, Kind: "eq", Path: "acl_name", Bad: []any{"open-access"}, Good: "app-acl", Msg: "Any client that reaches the cluster can run any command."},
	{ID: "TG-AWS-SM-001", Sev: Low, CWE: "CWE-693", Title: "Secret can be deleted with no recovery window", Types: []string{"aws_secretsmanager_secret"}, Kind: "eq", Path: "recovery_window_in_days", Bad: []any{0}, Good: 30, Fixable: true, Msg: "Deleting the secret removes it at once with no way back."},
	{ID: "TG-AWS-KMS-002", Sev: Medium, CWE: "CWE-284", Title: "KMS key skips the policy lockout safety check", Types: []string{"aws_kms_key"}, Kind: "eq", Path: "bypass_policy_lockout_safety_check", Bad: []any{true}, Good: false, Fixable: true, Msg: "A bad key policy can lock everyone out and strand the data it encrypts."},
	{ID: "TG-AWS-S3-004", Sev: Low, CWE: "CWE-284", Title: "S3 bucket ownership still allows ACLs", Types: []string{"aws_s3_bucket_ownership_controls"}, Kind: "eq", Path: "rule.object_ownership", Bad: []any{"ObjectWriter"}, Good: "BucketOwnerEnforced", Fixable: true, Msg: "Object ACLs stay active, so uploads can be made public outside the bucket policy."},
	{ID: "TG-AWS-LB-004", Sev: Low, CWE: "CWE-444", Title: "Load balancer desync mitigation is in monitor mode", Types: []string{"aws_lb", "aws_alb"}, Kind: "eq", Path: "desync_mitigation_mode", Bad: []any{"monitor"}, Good: "defensive", Fixable: true, Msg: "Ambiguous requests that enable request smuggling are forwarded."},
	{ID: "TG-AWS-RDS-006", Sev: Low, CWE: "CWE-1104", Title: "Database auto minor version upgrade is off", Types: []string{"aws_db_instance", "aws_rds_cluster_instance"}, Kind: "eq", Path: "auto_minor_version_upgrade", Bad: []any{false}, Good: true, Fixable: true, Msg: "Security patches in minor engine releases are not applied."},
	{ID: "TG-AWS-RDS-007", Sev: Medium, CWE: "CWE-298", Title: "Database uses the expired rds-ca-2019 certificate", Types: []string{"aws_db_instance", "aws_rds_cluster_instance"}, Kind: "eq", Path: "ca_cert_identifier", Bad: []any{"rds-ca-2019"}, Good: "rds-ca-rsa2048-g1", Fixable: true, Msg: "Clients that verify the certificate fail, or fall back to not verifying."},
	{ID: "TG-AWS-EC2-004", Sev: Medium, CWE: "CWE-311", Title: "EBS encryption by default is turned off", Types: []string{"aws_ebs_encryption_by_default"}, Kind: "eq", Path: "enabled", Bad: []any{false}, Good: true, Fixable: true, Msg: "New volumes in this region are created unencrypted."},
	{ID: "TG-AWS-EC2-005", Sev: Low, CWE: "CWE-918", Title: "Metadata hop limit lets containers reach IMDS", Types: []string{"aws_instance", "aws_launch_template"}, Kind: "gt", Path: "metadata_options.http_put_response_hop_limit", Num: 1, Good: 1, Fixable: true, Msg: "Containers on the host can fetch the instance role's credentials."},
	{ID: "TG-AWS-MWAA-001", Sev: Medium, CWE: "CWE-284", Title: "Airflow web server is public", Types: []string{"aws_mwaa_environment"}, Kind: "eq", Path: "webserver_access_mode", Bad: []any{"PUBLIC_ONLY"}, Good: "PRIVATE_ONLY", Fixable: true, Msg: "The Airflow login page is reachable from the internet."},
	{ID: "TG-AWS-APIGW-003", Sev: Medium, CWE: "CWE-327", Title: "API Gateway domain allows TLS 1.0", Types: []string{"aws_api_gateway_domain_name"}, Kind: "eq", Path: "security_policy", Bad: []any{"TLS_1_0"}, Good: "TLS_1_2", Fixable: true, Msg: "Clients can connect with a deprecated TLS version."},
	{ID: "TG-AWS-SSM-002", Sev: High, CWE: "CWE-200", Title: "SSM document is shared publicly", Types: []string{"aws_ssm_document"}, Kind: "eq", Path: "permissions.account_ids", Bad: []any{"All"}, Good: "123456789012", Msg: "Every AWS account can read and run this document."},
	{ID: "TG-AWS-FIREHOSE-001", Sev: Low, CWE: "CWE-311", Title: "Firehose delivery stream is not encrypted", Types: []string{"aws_kinesis_firehose_delivery_stream"}, Kind: "missing_or_eq", Path: "server_side_encryption.enabled", Bad: []any{false}, Good: true, Msg: "Buffered records are stored unencrypted."},
	{ID: "TG-AWS-WS-001", Sev: Medium, CWE: "CWE-311", Title: "WorkSpaces root volume is not encrypted", Types: []string{"aws_workspaces_workspace"}, Kind: "missing_or_eq", Path: "root_volume_encryption_enabled", Bad: []any{false}, Good: true, Msg: "The desktop's system disk is stored unencrypted."},

	// Azure
	{ID: "TG-AZ-WAF-001", Sev: Medium, CWE: "CWE-693", Title: "WAF policy is in detection mode", Types: []string{"azurerm_web_application_firewall_policy"}, Kind: "eq", Path: "policy_settings.mode", Bad: []any{"Detection"}, Good: "Prevention", Fixable: true, Msg: "Attacks are logged but not blocked."},
	{ID: "TG-AZ-WAF-002", Sev: High, CWE: "CWE-693", Title: "WAF policy is disabled", Types: []string{"azurerm_web_application_firewall_policy"}, Kind: "eq", Path: "policy_settings.enabled", Bad: []any{false}, Good: true, Fixable: true, Msg: "The firewall inspects nothing."},
	{ID: "TG-AZ-AGW-001", Sev: Medium, CWE: "CWE-327", Title: "Application Gateway allows TLS 1.0 or 1.1", Types: []string{"azurerm_application_gateway"}, Kind: "eq", Path: "ssl_policy.min_protocol_version", Bad: []any{"TLSv1_0", "TLSv1_1"}, Good: "TLSv1_2", Fixable: true, Msg: "Clients can negotiate deprecated TLS versions."},
	{ID: "TG-AZ-AGW-002", Sev: Medium, CWE: "CWE-693", Title: "Application Gateway WAF is in detection mode", Types: []string{"azurerm_application_gateway"}, Kind: "eq", Path: "waf_configuration.firewall_mode", Bad: []any{"Detection"}, Good: "Prevention", Fixable: true, Msg: "The gateway's WAF only logs attacks."},
	{ID: "TG-AZ-FD-001", Sev: Medium, CWE: "CWE-693", Title: "Front Door WAF policy is in detection mode", Types: []string{"azurerm_cdn_frontdoor_firewall_policy"}, Kind: "eq", Path: "mode", Bad: []any{"Detection"}, Good: "Prevention", Fixable: true, Msg: "Front Door logs attacks instead of blocking them."},
	{ID: "TG-AZ-FW-001", Sev: Medium, CWE: "CWE-693", Title: "Azure Firewall threat intelligence is off", Types: []string{"azurerm_firewall"}, Kind: "eq", Path: "threat_intel_mode", Bad: []any{"Off"}, Good: "Deny", Fixable: true, Msg: "Traffic to known-malicious addresses is neither alerted nor blocked."},
	{ID: "TG-AZ-FW-002", Sev: Medium, CWE: "CWE-693", Title: "Firewall policy threat intelligence is off", Types: []string{"azurerm_firewall_policy"}, Kind: "eq", Path: "threat_intelligence_mode", Bad: []any{"Off"}, Good: "Deny", Fixable: true, Msg: "Traffic to known-malicious addresses is neither alerted nor blocked."},
	{ID: "TG-AZ-DISK-001", Sev: Low, CWE: "CWE-284", Title: "Managed disk allows public network access", Types: []string{"azurerm_managed_disk"}, Kind: "missing_or_eq", Path: "public_network_access_enabled", Bad: []any{true}, Good: false, Fixable: true, Msg: "Disk export and import links work from any network."},
	{ID: "TG-AZ-LAW-001", Sev: Low, CWE: "CWE-779", Title: "Log Analytics keeps logs for under 90 days", Types: []string{"azurerm_log_analytics_workspace"}, Kind: "lt_or_missing", Path: "retention_in_days", Num: 90, Good: 90, Fixable: true, Msg: "Logs are deleted before most investigations need them (default 30 days)."},
	{ID: "TG-AZ-SYN-001", Sev: Medium, CWE: "CWE-284", Title: "Synapse workspace has no managed virtual network", Types: []string{"azurerm_synapse_workspace"}, Kind: "missing_or_eq", Path: "managed_virtual_network_enabled", Bad: []any{false}, Good: true, Msg: "Spark and pipeline compute isn't isolated and can send data anywhere."},
	{ID: "TG-AZ-ADF-001", Sev: Low, CWE: "CWE-284", Title: "Data Factory is reachable from the public network", Types: []string{"azurerm_data_factory"}, Kind: "missing_or_eq", Path: "public_network_enabled", Bad: []any{true}, Good: false, Fixable: true, Msg: "The factory's endpoints face the internet instead of private endpoints."},
	{ID: "TG-AZ-DBX-001", Sev: Medium, CWE: "CWE-284", Title: "Databricks clusters get public IPs", Types: []string{"azurerm_databricks_workspace"}, Kind: "eq", Path: "custom_parameters.no_public_ip", Bad: []any{false}, Good: true, Msg: "Cluster nodes get public IP addresses."},
	{ID: "TG-AZ-APP-002", Sev: Medium, CWE: "CWE-489", Title: "App Service remote debugging is enabled", Types: appServices, Kind: "eq", Path: "site_config.remote_debugging_enabled", Bad: []any{true}, Good: false, Fixable: true, Msg: "A debugger port is open that can inspect or control the running app."},
	{ID: "TG-AZ-APP-003", Sev: Medium, CWE: "CWE-327", Title: "App Service deployment site allows old TLS", Types: appServices, Kind: "eq", Path: "site_config.scm_minimum_tls_version", Bad: []any{"1.0", "1.1"}, Good: "1.2", Fixable: true, Msg: "The Kudu deployment endpoint accepts deprecated TLS."},
	{ID: "TG-AZ-APP-004", Sev: Low, CWE: "CWE-287", Title: "App Service allows FTP basic-auth publishing", Types: appServices, Kind: "missing_or_eq", Path: "ftp_publish_basic_authentication_enabled", Bad: []any{true}, Good: false, Fixable: true, Msg: "A static publishing password can deploy code, bypassing Entra ID."},
	{ID: "TG-AZ-VM-002", Sev: Low, CWE: "CWE-311", Title: "VM does not use encryption at host", Types: []string{"azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine", "azurerm_linux_virtual_machine_scale_set", "azurerm_windows_virtual_machine_scale_set"}, Kind: "missing_or_eq", Path: "encryption_at_host_enabled", Bad: []any{false}, Good: true, Msg: "Temp disks and caches on the host are not encrypted."},
	{ID: "TG-AZ-BASTION-001", Sev: Medium, CWE: "CWE-284", Title: "Bastion shareable links are enabled", Types: []string{"azurerm_bastion_host"}, Kind: "eq", Path: "shareable_link_enabled", Bad: []any{true}, Good: false, Fixable: true, Msg: "Anyone with a link can open an RDP or SSH session without a portal login."},
	{ID: "TG-AZ-ST-006", Sev: Medium, CWE: "CWE-284", Title: "Storage account allows cross-tenant replication", Types: []string{"azurerm_storage_account"}, Kind: "eq", Path: "cross_tenant_replication_enabled", Bad: []any{true}, Good: false, Fixable: true, Msg: "Blob data can be copied to a storage account in another tenant."},
	{ID: "TG-AZ-SQL-003", Sev: High, CWE: "CWE-311", Title: "SQL database Transparent Data Encryption is off", Types: []string{"azurerm_mssql_database"}, Kind: "eq", Path: "transparent_data_encryption_enabled", Bad: []any{false}, Good: true, Fixable: true, Msg: "Database files and backups are stored unencrypted."},

	// Google Cloud
	{ID: "TG-GCP-DATAPROC-001", Sev: Medium, CWE: "CWE-284", Title: "Dataproc cluster nodes have public IPs", Types: []string{"google_dataproc_cluster"}, Kind: "eq", Path: "cluster_config.gce_cluster_config.internal_ip_only", Bad: []any{false}, Good: true, Msg: "Cluster VMs get external IP addresses."},
	{ID: "TG-GCP-DATAPROC-002", Sev: Low, CWE: "CWE-311", Title: "Dataproc disks are not encrypted with CMEK", Types: []string{"google_dataproc_cluster"}, Kind: "missing", Path: "cluster_config.encryption_config.kms_key_name", Msg: "Cluster disks use Google-managed keys you can't revoke."},
	{ID: "TG-GCP-DATAFLOW-001", Sev: Medium, CWE: "CWE-284", Title: "Dataflow workers have public IPs", Types: []string{"google_dataflow_job", "google_dataflow_flex_template_job"}, Kind: "missing_or_eq", Path: "ip_configuration", Bad: []any{"WORKER_IP_PUBLIC"}, Good: "WORKER_IP_PRIVATE", Msg: "Pipeline workers are directly reachable from the internet."},
	{ID: "TG-GCP-PUBSUB-001", Sev: Low, CWE: "CWE-311", Title: "Pub/Sub topic is not encrypted with CMEK", Types: []string{"google_pubsub_topic"}, Kind: "missing", Path: "kms_key_name", Msg: "Messages use Google-managed keys you can't revoke."},
	{ID: "TG-GCP-SPANNER-001", Sev: Low, CWE: "CWE-311", Title: "Spanner database is not encrypted with CMEK", Types: []string{"google_spanner_database"}, Kind: "missing", Path: "encryption_config.kms_key_name", Msg: "Data uses Google-managed keys you can't revoke."},
	{ID: "TG-GCP-SPANNER-002", Sev: Low, CWE: "CWE-693", Title: "Spanner drop protection is off", Types: []string{"google_spanner_database"}, Kind: "missing_or_eq", Path: "enable_drop_protection", Bad: []any{false}, Good: true, Fixable: true, Msg: "The database can be dropped from the API or console, not only through Terraform."},
	{ID: "TG-GCP-BIGTABLE-001", Sev: Low, CWE: "CWE-693", Title: "Bigtable deletion protection is off", Types: []string{"google_bigtable_instance"}, Kind: "eq", Path: "deletion_protection", Bad: []any{false}, Good: true, Fixable: true, Msg: "A destroy or replace deletes every table."},
	{ID: "TG-GCP-CF-001", Sev: Low, CWE: "CWE-284", Title: "Cloud Function accepts traffic from anywhere", Types: []string{"google_cloudfunctions_function"}, Kind: "missing_or_eq", Path: "ingress_settings", Bad: []any{"ALLOW_ALL"}, Good: "ALLOW_INTERNAL_AND_GCLB", Msg: "The function URL bypasses the load balancer and Cloud Armor."},
	{ID: "TG-GCP-CF-002", Sev: Low, CWE: "CWE-284", Title: "Cloud Function (2nd gen) accepts traffic from anywhere", Types: []string{"google_cloudfunctions2_function"}, Kind: "missing_or_eq", Path: "service_config.ingress_settings", Bad: []any{"ALLOW_ALL"}, Good: "ALLOW_INTERNAL_AND_GCLB", Msg: "The function URL bypasses the load balancer and Cloud Armor."},
	{ID: "TG-GCP-CF-003", Sev: Medium, CWE: "CWE-319", Title: "Cloud Function HTTP trigger allows plain HTTP", Types: []string{"google_cloudfunctions_function"}, Kind: "eq", Path: "https_trigger_security_level", Bad: []any{"SECURE_OPTIONAL"}, Good: "SECURE_ALWAYS", Fixable: true, Msg: "Requests can travel without TLS."},
	{ID: "TG-GCP-RUN-001", Sev: Low, CWE: "CWE-284", Title: "Cloud Run service accepts traffic from anywhere", Types: []string{"google_cloud_run_v2_service"}, Kind: "missing_or_eq", Path: "ingress", Bad: []any{"INGRESS_TRAFFIC_ALL"}, Good: "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER", Msg: "The run.app URL bypasses the load balancer and Cloud Armor."},
	{ID: "TG-GCP-RUN-002", Sev: High, CWE: "CWE-306", Title: "Cloud Run invoker IAM check is disabled", Types: []string{"google_cloud_run_v2_service"}, Kind: "eq", Path: "invoker_iam_disabled", Bad: []any{true}, Good: false, Fixable: true, Msg: "Anyone who reaches the URL can call the service without authenticating."},
	{ID: "TG-GCP-AR-001", Sev: Low, CWE: "CWE-311", Title: "Artifact Registry is not encrypted with CMEK", Types: []string{"google_artifact_registry_repository"}, Kind: "missing", Path: "kms_key_name", Msg: "Images and packages use Google-managed keys you can't revoke."},
	{ID: "TG-GCP-LOG-001", Sev: Medium, CWE: "CWE-778", Title: "Log sink is disabled", Types: []string{"google_logging_project_sink", "google_logging_folder_sink", "google_logging_organization_sink"}, Kind: "eq", Path: "disabled", Bad: []any{true}, Good: false, Fixable: true, Msg: "Logs meant for long-term or SIEM storage are not exported."},
	{ID: "TG-GCP-BQ-002", Sev: Low, CWE: "CWE-311", Title: "BigQuery dataset is not encrypted with CMEK", Types: []string{"google_bigquery_dataset"}, Kind: "missing", Path: "default_encryption_configuration", Msg: "Tables use Google-managed keys you can't revoke."},
	{ID: "TG-GCP-DNS-001", Sev: Medium, CWE: "CWE-327", Title: "DNSSEC uses RSASHA1", Types: []string{"google_dns_managed_zone"}, Kind: "eq", Path: "dnssec_config.default_key_specs.algorithm", Bad: []any{"rsasha1"}, Good: "rsasha256", Fixable: true, Msg: "SHA-1 signatures are weak enough to forge records."},
	{ID: "TG-GCP-LB-002", Sev: Low, CWE: "CWE-327", Title: "HTTPS or SSL proxy has no SSL policy", Types: []string{"google_compute_target_https_proxy", "google_compute_target_ssl_proxy"}, Kind: "missing", Path: "ssl_policy", Msg: "Google's default policy still accepts TLS 1.0."},
	{ID: "TG-GCP-NET-002", Sev: Low, CWE: "CWE-284", Title: "VPC network creates subnets automatically", Types: []string{"google_compute_network"}, Kind: "missing_or_eq", Path: "auto_create_subnetworks", Bad: []any{true}, Good: false, Msg: "A subnet is created in every region, including ones you don't use."},
	{ID: "TG-GCP-IAP-001", Sev: High, CWE: "CWE-284", Title: "IAP access is granted to everyone", Types: []string{"google_iap_web_iam_member", "google_iap_web_backend_service_iam_member", "google_iap_tunnel_instance_iam_member"}, Kind: "eq", Path: "member", Bad: []any{"allUsers", "allAuthenticatedUsers"}, Good: "group:admins@example.com", Msg: "Identity-Aware Proxy lets any signed-in user through."},

	// Kubernetes and other providers
	{ID: "TG-K8S-013", Sev: Low, CWE: "CWE-284", Title: "Service is exposed as NodePort", Types: []string{"kubernetes_service", "kubernetes_service_v1"}, Kind: "eq", Path: "spec.type", Bad: []any{"NodePort"}, Good: "ClusterIP", Msg: "A high port opens on every node, bypassing ingress controls."},
	{ID: "TG-K8S-014", Sev: Low, CWE: "CWE-284", Title: "Workload runs in the default namespace", Types: append([]string{"kubernetes_service", "kubernetes_service_v1"}, k8sWorkloads...), Kind: "missing_or_eq", Path: "metadata.namespace", Bad: []any{"default"}, Good: "apps", Msg: "The shared default namespace is hard to isolate with RBAC and network policies."},
	{ID: "TG-K8S-018", Sev: Low, CWE: "CWE-319", Title: "Ingress has no TLS", Types: []string{"kubernetes_ingress_v1", "kubernetes_ingress"}, Kind: "missing", Path: "spec.tls", Msg: "Traffic to the ingress hosts is plain HTTP."},
	{ID: "TG-DO-LB-001", Sev: Low, CWE: "CWE-319", Title: "Load balancer does not redirect HTTP to HTTPS", Types: []string{"digitalocean_loadbalancer"}, Kind: "missing_or_eq", Path: "redirect_http_to_https", Bad: []any{false}, Good: true, Fixable: true, Msg: "Visitors who type http:// stay on an unencrypted connection."},
	{ID: "TG-LIN-OBJ-001", Sev: High, CWE: "CWE-284", Title: "Linode Object Storage bucket is public", Types: []string{"linode_object_storage_bucket"}, Kind: "eq", Path: "acl", Bad: []any{"public-read", "public-read-write", "authenticated-read"}, Good: "private", Fixable: true, Msg: "Bucket contents can be read, or written, by anyone."},
	{ID: "TG-HZ-SRV-002", Sev: Medium, CWE: "CWE-287", Title: "Hetzner server is created without SSH keys", Types: []string{"hcloud_server"}, Kind: "missing", Path: "ssh_keys", Msg: "A root password is generated and emailed, and password login stays on."},
	{ID: "TG-OCI-VM-001", Sev: Medium, CWE: "CWE-918", Title: "OCI instance allows legacy IMDS v1", Types: []string{"oci_core_instance"}, Kind: "missing_or_eq", Path: "instance_options.are_legacy_imds_endpoints_disabled", Bad: []any{false}, Good: true, Fixable: true, Msg: "An SSRF bug can read instance credentials from the v1 metadata endpoint."},
	{ID: "TG-OCI-OKE-001", Sev: Medium, CWE: "CWE-284", Title: "OKE API endpoint has a public IP", Types: []string{"oci_containerengine_cluster"}, Kind: "eq", Path: "endpoint_config.is_public_ip_enabled", Bad: []any{true}, Good: false, Fixable: true, Msg: "The Kubernetes API is reachable from the internet."},
	{ID: "TG-ALI-KMS-001", Sev: Low, CWE: "CWE-324", Title: "Alibaba KMS key is never rotated", Types: []string{"alicloud_kms_key"}, Kind: "missing_or_eq", Path: "automatic_rotation", Bad: []any{"Disabled"}, Good: "Enabled", Msg: "The same key material is used indefinitely."},
}

// customChecks need more than one setting or a walk through nested blocks.
var customChecks = []Rule{
	{ID: "TG-AWS-CACHE-002", Title: "ElastiCache Redis has no AUTH token or user group", Severity: Medium, Category: CatSecurity, CWE: "CWE-306",
		Types: []string{"aws_elasticache_replication_group"}, Remediation: "Set auth_token (with transit encryption) or user_group_ids.",
		Check: func(r *Resource) []Hit {
			engine, _ := asString(r.get("engine"))
			if (engine == "" || engine == "redis" || engine == "valkey") && r.get("auth_token") == nil && len(asStrings(r.get("user_group_ids"))) == 0 && !isUnknown(r.get("user_group_ids")) {
				return []Hit{{Path: "auth_token", Msg: "Anyone who reaches the cache port can read and write without a password."}}
			}
			return nil
		}},
	{ID: "TG-AWS-ECS-004", Title: "ECS EFS volume is mounted without in-transit encryption", Severity: Medium, Category: CatSecurity, CWE: "CWE-319",
		Types: []string{"aws_ecs_task_definition"}, Remediation: "Set transit_encryption = \"ENABLED\" in efs_volume_configuration.",
		Check: func(r *Resource) []Hit {
			for _, v := range r.blocks("volume") {
				for _, e := range blocksAt(v, "efs_volume_configuration") {
					if t, _ := asString(e["transit_encryption"]); t != "ENABLED" && !isUnknown(e["transit_encryption"]) {
						return []Hit{{Path: "volume", Msg: "File traffic between the task and EFS is unencrypted."}}
					}
				}
			}
			return nil
		}},
	{ID: "TG-AWS-ECS-005", Title: "ECS container root filesystem is writable", Severity: Low, Category: CatSecurity, CWE: "CWE-732",
		Types: []string{"aws_ecs_task_definition"}, Remediation: "Set readonlyRootFilesystem = true and mount writable volumes where needed.",
		Check: func(r *Resource) []Hit {
			defs := r.get("container_definitions")
			if s, ok := asString(defs); ok {
				_ = json.Unmarshal([]byte(s), &defs)
			}
			list, _ := defs.([]any)
			for _, c := range list {
				if m, ok := c.(map[string]any); ok && notTrue(m["readonlyRootFilesystem"]) {
					name, _ := asString(m["name"])
					return []Hit{{Path: "container_definitions", Msg: "Container " + name + " can change its own binaries and plant files."}}
				}
			}
			return nil
		}},
	{ID: "TG-AWS-EKS-003", Title: "EKS node group SSH is open to the internet", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"aws_eks_node_group"}, Remediation: "Set remote_access.source_security_group_ids, or drop SSH and use SSM.",
		Check: func(r *Resource) []Hit {
			if r.get("remote_access.ec2_ssh_key") != nil && len(asStrings(r.get("remote_access.source_security_group_ids"))) == 0 && !isUnknown(r.get("remote_access.source_security_group_ids")) {
				return []Hit{{Path: "remote_access", Msg: "With no source security groups, AWS opens SSH on the nodes to 0.0.0.0/0."}}
			}
			return nil
		}},
	{ID: "TG-AWS-TRANSFER-002", Title: "Transfer Family server allows plain FTP", Severity: High, Category: CatSecurity, CWE: "CWE-319",
		Types: []string{"aws_transfer_server"}, Remediation: "Use SFTP or FTPS only.",
		Check: func(r *Resource) []Hit {
			if contains(asStrings(r.get("protocols")), "FTP") {
				return []Hit{{Path: "protocols", Msg: "Usernames, passwords and files are sent in clear text."}}
			}
			return nil
		}},
	{ID: "TG-AWS-EVB-001", Title: "EventBridge bus accepts events from any account", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"aws_cloudwatch_event_permission"}, Remediation: "Name specific account IDs, or add a condition on aws:PrincipalOrgID.",
		Check: func(r *Resource) []Hit {
			if p, _ := asString(r.get("principal")); p == "*" && r.get("condition") == nil {
				return []Hit{{Path: "principal", Msg: "Any AWS account can put events on the bus and trigger your rules."}}
			}
			return nil
		}},
	{ID: "TG-AWS-ELB-001", Title: "Classic load balancer listens over plain HTTP", Severity: Medium, Category: CatSecurity, CWE: "CWE-319",
		Types: []string{"aws_elb"}, Remediation: "Use HTTPS listeners, or move to an ALB with an HTTPS listener and redirect.",
		Check: func(r *Resource) []Hit {
			for _, l := range r.blocks("listener") {
				if p, _ := asString(l["lb_protocol"]); strings.EqualFold(p, "http") {
					return []Hit{{Path: "listener", Msg: "Client traffic to the load balancer is unencrypted."}}
				}
			}
			return nil
		}},
	{ID: "TG-AZ-APIM-001", Title: "API Management allows SSL 3.0 or TLS 1.0/1.1", Severity: Medium, Category: CatSecurity, CWE: "CWE-327",
		Types: []string{"azurerm_api_management"}, Remediation: "Set the frontend and backend ssl30/tls10/tls11 options in the security block to false.",
		Check: func(r *Resource) []Hit {
			for _, side := range []string{"frontend", "backend"} {
				for _, v := range []string{"ssl30", "tls10", "tls11"} {
					if is(r.get("security."+side+"_"+v+"_enabled"), true) {
						return []Hit{{Path: "security", Msg: "The gateway accepts or uses broken TLS versions (" + side + " " + v + ")."}}
					}
				}
			}
			return nil
		}},
	{ID: "TG-AZ-NSG-002", Title: "Flow log retention is under 90 days", Severity: Low, Category: CatSecurity, CWE: "CWE-779",
		Types: []string{"azurerm_network_watcher_flow_log"}, Remediation: "Set retention_policy { enabled = true, days = 90 } or more.",
		Check: func(r *Resource) []Hit {
			if is(r.get("retention_policy.enabled"), false) {
				return nil
			}
			if d, ok := asFloat(r.get("retention_policy.days")); ok && d > 0 && d < 90 {
				return []Hit{{Path: "retention_policy", Msg: "Network flow records are deleted before an incident is likely to be investigated."}}
			}
			return nil
		}},
	{ID: "TG-GCP-IAM-006", Title: "Audit logging exempts some principals", Severity: Medium, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"google_project_iam_audit_config", "google_folder_iam_audit_config", "google_organization_iam_audit_config"}, Remediation: "Remove exempted_members.",
		Check: func(r *Resource) []Hit {
			for _, c := range r.blocks("audit_log_config") {
				if len(asStrings(c["exempted_members"])) > 0 {
					return []Hit{{Path: "audit_log_config", Msg: "Actions by the exempted members leave no audit trail."}}
				}
			}
			return nil
		}},
	{ID: "TG-GCP-ORG-001", Title: "Organization policy switches off a security constraint", Severity: Medium, Category: CatSecurity, CWE: "CWE-693",
		Types: []string{"google_org_policy_policy", "google_project_organization_policy", "google_folder_organization_policy", "google_organization_policy"}, Remediation: "Enforce the constraint, or document the exception with a waiver.",
		Check: func(r *Resource) []Hit {
			var constraint string
			off := false
			if r.Type == "google_org_policy_policy" {
				name, _ := asString(r.get("name"))
				constraint = name[strings.LastIndex(name, "/")+1:]
				for _, rule := range blocksAt(r.get("spec"), "rules") {
					if v, _ := asString(rule["enforce"]); strings.EqualFold(v, "FALSE") {
						off = true
					}
				}
			} else {
				c, _ := asString(r.get("constraint"))
				constraint = strings.TrimPrefix(c, "constraints/")
				off = is(r.get("boolean_policy.enforced"), false)
			}
			if off && guardrailConstraints[constraint] {
				return []Hit{{Path: "name", Msg: constraint + " is switched off for this scope."}}
			}
			return nil
		}},
	{ID: "TG-GCP-GKE-005", Title: "GKE node auto-upgrade is disabled", Severity: Medium, Category: CatSecurity, CWE: "CWE-1104",
		Types: []string{"google_container_node_pool", "google_container_cluster"}, Remediation: "Set management { auto_upgrade = true }.",
		Check: func(r *Resource) []Hit {
			pools := []map[string]any{r.Attrs}
			if r.Type == "google_container_cluster" {
				pools = r.blocks("node_pool")
			}
			for _, p := range pools {
				if is(get(p, "management.auto_upgrade"), false) {
					return []Hit{{Path: "management", Msg: "Nodes miss Kubernetes and OS security patches."}}
				}
			}
			return nil
		}},
	{ID: "TG-ALI-RDS-001", Title: "Alibaba RDS whitelist allows any IP", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"alicloud_db_instance"}, Remediation: "Replace 0.0.0.0/0 with the addresses that need access.",
		Check: func(r *Resource) []Hit {
			ips := asStrings(r.get("security_ips"))
			for _, a := range r.blocks("db_instance_ip_array") {
				ips = append(ips, asStrings(a["security_ips"])...)
			}
			if contains(ips, "0.0.0.0/0", "0.0.0.0") {
				return []Hit{{Path: "security_ips", Msg: "The database accepts connections from the whole internet."}}
			}
			return nil
		}},
	k8sContainerRule("TG-K8S-009", "Container has no memory limit", "CWE-770", "Set resources { limits = { memory = \"512Mi\" } }.", func(c map[string]any) string {
		if lim, ok := get(c, "resources.limits").(map[string]any); !ok || lim["memory"] == nil {
			return "can use all of the node's memory and starve other pods"
		}
		return ""
	}),
	k8sContainerRule("TG-K8S-010", "Container has no liveness or readiness probe", "CWE-754", "Add a readiness_probe and a liveness_probe.", func(c map[string]any) string {
		if c["liveness_probe"] == nil && c["readiness_probe"] == nil {
			return "keeps receiving traffic when hung, and is never restarted"
		}
		return ""
	}),
	k8sContainerRule("TG-K8S-015", "Container listens on a privileged port", "CWE-250", "Listen on a port above 1023 and map it in the Service.", func(c map[string]any) string {
		for _, p := range blocksAt(c, "port") {
			if n, ok := asFloat(p["container_port"]); ok && n < 1024 {
				return "binds below 1024, which needs root or NET_BIND_SERVICE"
			}
		}
		return ""
	}),
	k8sContainerRule("TG-K8S-016", "Secret is passed as an environment variable", "CWE-526", "Mount the secret as a file instead.", func(c map[string]any) string {
		for _, e := range blocksAt(c, "env") {
			if get(e, "value_from.secret_key_ref") != nil {
				return "gets a secret through env, which leaks into crash dumps and child processes"
			}
		}
		for _, e := range blocksAt(c, "env_from") {
			if e["secret_ref"] != nil {
				return "gets secrets through env_from, which leak into crash dumps and child processes"
			}
		}
		return ""
	}),
	k8sContainerRule("TG-K8S-017", "Container root filesystem is writable", "CWE-732", "Set security_context { read_only_root_filesystem = true }.", func(c map[string]any) string {
		if notTrue(get(c, "security_context.read_only_root_filesystem")) {
			return "can change its own binaries and plant files"
		}
		return ""
	}),
	{ID: "TG-K8S-012", Title: "Pod mounts the service account token automatically", Severity: Low, Category: CatSecurity, CWE: "CWE-284",
		Remediation: "Set automount_service_account_token = false unless the pod calls the Kubernetes API.",
		Check: func(r *Resource) []Hit {
			if !isWorkload(r.Type) {
				return nil
			}
			var hits []Hit
			forEachPodSpec(r.Attrs, func(p string, spec map[string]any) {
				if notFalse(spec["automount_service_account_token"]) {
					hits = append(hits, Hit{Path: p, Msg: "Code in the pod gets an API token it can use against the cluster."})
				}
			})
			return hits
		}},
}

var guardrailConstraints = map[string]bool{"iam.disableServiceAccountKeyCreation": true, "iam.disableServiceAccountKeyUpload": true, "iam.automaticIamGrantsForDefaultServiceAccounts": true,
	"compute.requireOsLogin": true, "compute.skipDefaultNetworkCreation": true, "compute.disableSerialPortAccess": true, "compute.requireShieldedVm": true,
	"storage.uniformBucketLevelAccess": true, "storage.publicAccessPrevention": true, "sql.restrictPublicIp": true}

func isWorkload(t string) bool { return contains(k8sWorkloads, t) }

// k8sContainerRule runs problem on each container of a workload; a non-empty
// result is the reason for a finding.
func k8sContainerRule(id, title, cwe, remedy string, problem func(c map[string]any) string) Rule {
	return Rule{ID: id, Title: title, Severity: Low, Category: CatSecurity, CWE: cwe, Remediation: remedy,
		Check: func(r *Resource) []Hit {
			if !isWorkload(r.Type) {
				return nil
			}
			var hits []Hit
			forEachPodSpec(r.Attrs, func(p string, spec map[string]any) {
				for _, kind := range []string{"container", "init_container"} {
					for i, c := range blocksAt(spec, kind) {
						if why := problem(c); why != "" {
							name, _ := asString(c["name"])
							hits = append(hits, Hit{Path: join(p, kind+"."+strconv.Itoa(i)), Msg: "Container " + name + " " + why + "."})
						}
					}
				}
			})
			return hits
		}}
}

func tableRules() []Rule {
	out := make([]Rule, 0, len(tableChecks)+len(customChecks))
	for _, c := range tableChecks {
		out = append(out, c.rule())
	}
	for _, list := range [][]check{parityChecks, cfnParityChecks, armParityChecks} {
		for _, c := range list {
			out = append(out, c.rule())
		}
	}
	return append(out, customChecks...)
}

// unknownAlong is true when an object on the way to path is unresolved, so the
// setting may well be there once the expression is known.
func unknownAlong(v any, path string) bool {
	for _, seg := range strings.Split(path, ".") {
		if isUnknown(v) {
			return true
		}
		switch t := v.(type) {
		case []any:
			if len(t) == 0 {
				return false
			}
			if i, err := strconv.Atoi(seg); err == nil && i < len(t) {
				v = t[i]
			} else {
				v = t[0]
			}
			if m, ok := v.(map[string]any); ok && seg != "0" {
				v = m[seg]
			}
		case map[string]any:
			if seg == "0" && t["0"] == nil {
				continue
			}
			v = t[seg]
		default:
			return false
		}
	}
	return isUnknown(v)
}
