package engine

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Rules for AWS resources.
var portedAWS = []Rule{
	// API Gateway
	{ID: "TG-AWS-APIGW-201", Title: "API Gateway cache is not encrypted", Severity: Medium, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_api_gateway_method_settings"}, Remediation: "Set settings.cache_data_encrypted = true wherever caching_enabled = true.",
		Check: func(r *Resource) []Hit {
			if is(r.get("settings.caching_enabled"), true) && notTrue(r.get("settings.cache_data_encrypted")) {
				return []Hit{{Path: "settings", Msg: "Cached API responses are stored unencrypted.", Fix: fix(true, "Encrypt the method cache", "settings", "cache_data_encrypted")}}
			}
			return nil
		}},

	// EKS
	{ID: "TG-AWS-EKS-202", Title: "EKS cluster runs an unsupported Kubernetes version", Severity: Medium, Category: CatSecurity, CWE: "CWE-1104",
		Types: []string{"aws_eks_cluster"}, Remediation: "Upgrade version to 1.29 or later.",
		Check: func(r *Resource) []Hit {
			v, _ := asString(r.get("version"))
			if maj, min, ok := awspMajorMinor(v); ok && (maj < 1 || maj == 1 && min < 29) {
				return []Hit{{Path: "version", Msg: "Kubernetes " + v + " is out of standard support and gets no security patches."}}
			}
			return nil
		}},
	{ID: "TG-AWS-EKS-203", Title: "EKS public endpoint has an empty CIDR allowlist", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"aws_eks_cluster"}, Remediation: "List the CIDRs that may reach the API in vpc_config.public_access_cidrs, or set endpoint_public_access = false.",
		Check: func(r *Resource) []Hit {
			l, ok := r.get("vpc_config.public_access_cidrs").([]any)
			if ok && len(l) == 0 && notFalse(r.get("vpc_config.endpoint_public_access")) {
				return []Hit{{Path: "vpc_config", Msg: "An empty public_access_cidrs falls back to 0.0.0.0/0, so the API is open to the internet."}}
			}
			return nil
		}},

	// Neptune
	{ID: "TG-AWS-NEPTUNE-201", Title: "Neptune audit logs are not exported", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"aws_neptune_cluster"}, Remediation: `Set enable_cloudwatch_logs_exports = ["audit"].`,
		Check: func(r *Resource) []Hit {
			v := r.get("enable_cloudwatch_logs_exports")
			if !isUnknown(v) && !contains(asStrings(v), "audit") {
				return []Hit{{Path: "enable_cloudwatch_logs_exports", Msg: "Queries against the graph are not audited."}}
			}
			return nil
		}},
	{ID: "TG-AWS-NEPTUNE-202", Title: "Neptune cluster skips IAM authentication", Severity: Medium, Category: CatSecurity, CWE: "CWE-287",
		Types: []string{"aws_neptune_cluster"}, Remediation: "Set iam_database_authentication_enabled = true.",
		Check: func(r *Resource) []Hit {
			if notTrue(r.get("iam_database_authentication_enabled")) {
				return []Hit{{Path: "iam_database_authentication_enabled", Msg: "Anyone who reaches the endpoint can query without IAM credentials.", Fix: fix(true, "Enable IAM authentication", "iam_database_authentication_enabled")}}
			}
			return nil
		}},
	{ID: "TG-AWS-NEPTUNE-203", Title: "Neptune keeps backups for less than 7 days", Severity: Low, Category: CatReliability, CWE: "CWE-693",
		Types: []string{"aws_neptune_cluster"}, Remediation: "Set backup_retention_period = 7 or more.",
		Check: func(r *Resource) []Hit { return awspRetention(r, 7) }},
	{ID: "TG-AWS-NEPTUNE-204", Title: "Neptune snapshots do not inherit tags", Severity: Low, Category: CatBestPrac, CWE: "CWE-710",
		Types: []string{"aws_neptune_cluster"}, Remediation: "Set copy_tags_to_snapshot = true.",
		Check: func(r *Resource) []Hit {
			if notTrue(r.get("copy_tags_to_snapshot")) {
				return []Hit{{Path: "copy_tags_to_snapshot", Msg: "Snapshots lose owner and classification tags.", Fix: fix(true, "Copy tags to snapshots", "copy_tags_to_snapshot")}}
			}
			return nil
		}},

	// DocumentDB
	{ID: "TG-AWS-DOCDB-201", Title: "DocumentDB audit logging is off", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"aws_docdb_cluster_parameter_group"}, Remediation: `Add parameter { name = "audit_logs" value = "all" }.`,
		Check: func(r *Resource) []Hit {
			for _, p := range r.blocks("parameter") {
				if n, _ := asString(p["name"]); n == "audit_logs" {
					v, ok := asString(p["value"])
					if !ok || strings.Contains(v, "enabled") || strings.Contains(v, "ddl") || strings.Contains(v, "all") {
						return nil
					}
				}
			}
			return []Hit{{Path: "parameter", Msg: "Database activity is not written to the audit log."}}
		}},
	{ID: "TG-AWS-DOCDB-202", Title: "DocumentDB keeps backups for less than 7 days", Severity: Low, Category: CatReliability, CWE: "CWE-693",
		Types: []string{"aws_docdb_cluster"}, Remediation: "Set backup_retention_period = 7 or more.",
		Check: func(r *Resource) []Hit { return awspRetention(r, 7) }},
	{ID: "TG-AWS-DOCDB-203", Title: "DocumentDB logs are not exported", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"aws_docdb_cluster"}, Remediation: `Set enabled_cloudwatch_logs_exports = ["audit", "profiler"].`,
		Check: func(r *Resource) []Hit {
			v := r.get("enabled_cloudwatch_logs_exports")
			if !isUnknown(v) && !contains(asStrings(v), "audit", "profiler") {
				return []Hit{{Path: "enabled_cloudwatch_logs_exports", Msg: "Neither audit nor profiler logs reach CloudWatch."}}
			}
			return nil
		}},

	// Redshift
	{ID: "TG-AWS-REDSHIFT-201", Title: "Redshift parameter group does not require SSL", Severity: Medium, Category: CatSecurity, CWE: "CWE-319",
		Types: []string{"aws_redshift_parameter_group"}, Remediation: `Add parameter { name = "require_ssl" value = "true" }.`,
		Check: func(r *Resource) []Hit {
			for _, p := range r.blocks("parameter") {
				if n, _ := asString(p["name"]); n == "require_ssl" && (is(p["value"], true) || isUnknown(p["value"])) {
					return nil
				}
			}
			return []Hit{{Path: "parameter", Msg: "Clients can connect to the warehouse without TLS."}}
		}},
	{ID: "TG-AWS-REDSHIFT-202", Title: "Public Redshift cluster uses a common admin username", Severity: Medium, Category: CatSecurity, CWE: "CWE-1392",
		Types: []string{"aws_redshift_cluster"}, Remediation: "Pick a non-default master_username and set publicly_accessible = false.",
		Check: func(r *Resource) []Hit {
			// Absent publicly_accessible defaults to false in provider v5, so only an explicit true counts.
			if u, _ := asString(r.get("master_username")); (u == "awsuser" || u == "admin" || u == "administrator") && is(r.get("publicly_accessible"), true) {
				return []Hit{{Path: "master_username", Msg: "A guessable admin name on a public endpoint invites password spraying."}}
			}
			return nil
		}},
	{ID: "TG-AWS-REDSHIFT-203", Title: "Redshift audit logging is disabled", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"aws_redshift_cluster"}, Remediation: "Enable logging, preferably with an aws_redshift_logging resource.",
		Check: func(r *Resource) []Hit {
			// Only an explicit false: logging may live in a separate aws_redshift_logging resource.
			if is(r.get("logging.enable"), false) {
				return []Hit{{Path: "logging", Msg: "Connections and queries are not audited.", Fix: fix(true, "Enable audit logging", "logging", "enable")}}
			}
			return nil
		}},

	// SSM
	{ID: "TG-AWS-SSM-201", Title: "Session Manager sessions are not encrypted with KMS", Severity: Medium, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_ssm_document"}, Remediation: "Set inputs.kmsKeyId in the Session document content.",
		Check: func(r *Resource) []Hit {
			if in, ok := awspSessionInputs(r); ok && !awspTruthy(in["kmsKeyId"]) {
				return []Hit{{Path: "content", Msg: "Session data is only protected by TLS, not by your KMS key."}}
			}
			return nil
		}},
	{ID: "TG-AWS-SSM-202", Title: "Session Manager logs are off or unencrypted", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"aws_ssm_document"}, Remediation: "Set s3BucketName with s3EncryptionEnabled, or cloudWatchLogGroupName with cloudWatchEncryptionEnabled.",
		Check: func(r *Resource) []Hit {
			in, ok := awspSessionInputs(r)
			if !ok || awspTruthy(in["s3BucketName"]) && awspTruthy(in["s3EncryptionEnabled"]) || awspTruthy(in["cloudWatchLogGroupName"]) && awspTruthy(in["cloudWatchEncryptionEnabled"]) {
				return nil
			}
			return []Hit{{Path: "content", Msg: "Shell sessions are not recorded to an encrypted destination."}}
		}},
	{ID: "TG-AWS-SSM-203", Title: "SecureString parameter uses the AWS-managed key", Severity: Low, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_ssm_parameter"}, Remediation: "Set key_id to a customer-managed KMS key.",
		Check: func(r *Resource) []Hit {
			if t, _ := asString(r.get("type")); t == "SecureString" && r.get("key_id") == nil {
				return []Hit{{Path: "key_id", Msg: "Anyone allowed to use aws/ssm in the account can decrypt the value."}}
			}
			return nil
		}},

	// EMR
	{ID: "TG-AWS-EMR-201", Title: "EMR security configuration does not use SSE-KMS", Severity: Low, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_emr_security_configuration"}, Remediation: `Use "EncryptionMode": "SSE-KMS" with your key in S3EncryptionConfiguration.`,
		Check: func(r *Resource) []Hit {
			if s, ok := awspText(r.get("configuration")); ok && !strings.Contains(s, "SSE-KMS") {
				return []Hit{{Path: "configuration", Msg: "EMRFS data in S3 is not encrypted with a KMS key you control."}}
			}
			return nil
		}},
	{ID: "TG-AWS-EMR-202", Title: "EMR security configuration leaves local disks unencrypted", Severity: Medium, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_emr_security_configuration"}, Remediation: "Enable EnableAtRestEncryption with a LocalDiskEncryptionConfiguration.",
		Check: func(r *Resource) []Hit {
			enc, ok := awspEMREncryption(r)
			if ok && !(is(enc["EnableAtRestEncryption"], true) && get(enc, "AtRestEncryptionConfiguration.LocalDiskEncryptionConfiguration") != nil) {
				return []Hit{{Path: "configuration", Msg: "Shuffle and spill data on instance disks is unencrypted."}}
			}
			return nil
		}},
	{ID: "TG-AWS-EMR-203", Title: "EMR security configuration leaves EBS volumes unencrypted", Severity: Medium, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_emr_security_configuration"}, Remediation: "Set LocalDiskEncryptionConfiguration.EnableEbsEncryption = true.",
		Check: func(r *Resource) []Hit {
			enc, ok := awspEMREncryption(r)
			// At-rest off or no local disk config is TG-AWS-EMR-202.
			ld := get(enc, "AtRestEncryptionConfiguration.LocalDiskEncryptionConfiguration")
			if ok && is(enc["EnableAtRestEncryption"], true) && ld != nil && !awspTruthy(get(ld, "EnableEbsEncryption")) {
				return []Hit{{Path: "configuration", Msg: "EBS root and storage volumes of the cluster are unencrypted."}}
			}
			return nil
		}},
	{ID: "TG-AWS-EMR-204", Title: "EMR security configuration skips in-transit encryption", Severity: Medium, Category: CatSecurity, CWE: "CWE-319",
		Types: []string{"aws_emr_security_configuration"}, Remediation: "Set EnableInTransitEncryption = true with a TLS certificate provider.",
		Check: func(r *Resource) []Hit {
			enc, ok := awspEMREncryption(r)
			if ok && !awspTruthy(enc["EnableInTransitEncryption"]) {
				return []Hit{{Path: "configuration", Msg: "Traffic between cluster nodes is unencrypted."}}
			}
			return nil
		}},

	// DynamoDB
	{ID: "TG-AWS-DDB-201", Title: "DynamoDB table is not encrypted with a customer-managed key", Severity: Low, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_dynamodb_table"}, Remediation: "Add server_side_encryption { enabled = true, kms_key_arn = <your key> }.",
		Check: func(r *Resource) []Hit {
			if !is(r.get("server_side_encryption.enabled"), true) || r.get("server_side_encryption.kms_key_arn") == nil {
				if isUnknown(r.get("server_side_encryption.enabled")) {
					return nil
				}
				return []Hit{{Path: "server_side_encryption", Msg: "Data uses an AWS-owned key you cannot audit or revoke."}}
			}
			return nil
		}},

	// Config
	{ID: "TG-AWS-CONFIG-201", Title: "Config aggregator does not cover all regions", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"aws_config_configuration_aggregator"}, Remediation: "Set all_regions = true in the aggregation source.",
		Check: func(r *Resource) []Hit {
			a, o := r.get("account_aggregation_source.all_regions"), r.get("organization_aggregation_source.all_regions")
			if is(a, true) || is(o, true) || isUnknown(a) || isUnknown(o) {
				return nil
			}
			return []Hit{{Path: "account_aggregation_source", Msg: "Resources in regions left out are never evaluated."}}
		}},

	// Classic ELB
	{ID: "TG-AWS-ELB-201", Title: "Classic load balancer listener has no certificate", Severity: Medium, Category: CatSecurity, CWE: "CWE-319",
		Types: []string{"aws_elb"}, Remediation: "Use HTTPS or SSL listeners with an ACM ssl_certificate_id.",
		Check: func(r *Resource) []Hit {
			for i, l := range r.blocks("listener") {
				if l["ssl_certificate_id"] == nil {
					return []Hit{{Path: fmt.Sprintf("listener.%d", i), Msg: "Clients connect without TLS on this listener."}}
				}
			}
			return nil
		}},
	{ID: "TG-AWS-ELB-202", Title: "Load balancer policy allows legacy SSL/TLS", Severity: Medium, Category: CatSecurity, CWE: "CWE-327",
		Types: []string{"aws_load_balancer_policy"}, Remediation: `Use Reference-Security-Policy = "ELBSecurityPolicy-TLS-1-2-2017-01" and drop SSLv3/TLSv1/TLSv1.1.`,
		Check: func(r *Resource) []Hit {
			old := []string{"ELBSecurityPolicy-2016-08", "ELBSecurityPolicy-TLS-1-1-2017-01", "ELBSecurityPolicy-2015-05", "ELBSecurityPolicy-2015-03",
				"ELBSecurityPolicy-2015-02", "ELBSecurityPolicy-TLS-1-0-2015-04", "ELBSecurityPolicy-2014-10", "ELBSecurityPolicy-Default", "ELBSecurityPolicy-2014-01"}
			for _, a := range r.blocks("policy_attribute") {
				n, _ := asString(a["name"])
				v, _ := asString(a["value"])
				if (n == "Protocol-SSLv3" || n == "Protocol-TLSv1" || n == "Protocol-TLSv1.1") && is(a["value"], true) ||
					n == "Reference-Security-Policy" && contains(old, v) {
					return []Hit{{Path: "policy_attribute", Msg: n + " lets clients negotiate broken protocols."}}
				}
			}
			return nil
		}},
	{ID: "TG-AWS-ELB-203", Title: "Classic load balancer talks to instances without TLS", Severity: Low, Category: CatSecurity, CWE: "CWE-319",
		Types: []string{"aws_elb"}, Remediation: `Use instance_protocol = "HTTPS" or "SSL" with a certificate.`,
		Check: func(r *Resource) []Hit {
			for i, l := range r.blocks("listener") {
				p, _ := asString(l["instance_protocol"])
				switch strings.ToLower(p) {
				case "http", "tcp":
					return []Hit{{Path: fmt.Sprintf("listener.%d", i), Msg: "Traffic from the load balancer to instances is unencrypted."}}
				}
			}
			return nil
		}},
	{ID: "TG-AWS-ELB-204", Title: "Classic load balancer desync mitigation is in monitor mode", Severity: Low, Category: CatSecurity, CWE: "CWE-444",
		Types: []string{"aws_elb"}, Remediation: `Set desync_mitigation_mode = "defensive" or "strictest".`,
		Check: func(r *Resource) []Hit {
			if m, _ := asString(r.get("desync_mitigation_mode")); m == "monitor" {
				return []Hit{{Path: "desync_mitigation_mode", Msg: "Ambiguous requests that enable HTTP request smuggling are passed through.", Fix: fix("defensive", "Use defensive mode", "desync_mitigation_mode")}}
			}
			return nil
		}},

	// Load balancers
	{ID: "TG-AWS-LB-201", Title: "Network load balancer has cross-zone balancing off", Severity: Low, Category: CatReliability, CWE: "CWE-400",
		Types: []string{"aws_lb", "aws_alb"}, Remediation: "Set enable_cross_zone_load_balancing = true.",
		Check: func(r *Resource) []Hit {
			if t, _ := asString(r.get("load_balancer_type")); (t == "network" || t == "gateway") && notTrue(r.get("enable_cross_zone_load_balancing")) {
				return []Hit{{Path: "enable_cross_zone_load_balancing", Msg: "Losing the targets in one zone drops the traffic routed to that zone.", Fix: fix(true, "Balance across zones", "enable_cross_zone_load_balancing")}}
			}
			return nil
		}},
	{ID: "TG-AWS-LB-202", Title: "HTTP target group health checks are disabled", Severity: Low, Category: CatReliability, CWE: "CWE-754",
		Types: []string{"aws_lb_target_group", "aws_alb_target_group"}, Remediation: "Keep health_check enabled with a path that reflects application health.",
		Check: func(r *Resource) []Hit {
			// Without a health_check block (or path) the provider checks "/" anyway; only disabling it is a gap.
			if p, _ := asString(r.get("protocol")); (p == "HTTP" || p == "HTTPS") && is(r.get("health_check.enabled"), false) {
				return []Hit{{Path: "health_check", Msg: "Traffic keeps going to targets that are down.", Fix: fix(true, "Enable health checks", "health_check", "enabled")}}
			}
			return nil
		}},

	// RDS
	{ID: "TG-AWS-RDS-201", Title: "Database backup retention is off or invalid", Severity: Low, Category: CatReliability, CWE: "CWE-693",
		Types: []string{"aws_db_instance", "aws_rds_cluster"}, Remediation: "Set backup_retention_period between 1 and 35 (7 or more recommended).",
		Check: func(r *Resource) []Hit {
			if n, ok := asFloat(r.get("backup_retention_period")); ok && (n < 0 || n > 35) { // 0 is TG-AWS-RDS-003
				return []Hit{{Path: "backup_retention_period", Msg: fmt.Sprintf("backup_retention_period = %g: automated backups are off or the value is rejected by RDS.", n)}}
			}
			return nil
		}},
	{ID: "TG-AWS-RDS-202", Title: "DB security group is an EC2-Classic resource", Severity: Low, Category: CatReliability, CWE: "CWE-477",
		Types: []string{"aws_db_security_group"}, Remediation: "Use VPC security groups via vpc_security_group_ids.",
		Check: func(r *Resource) []Hit {
			return []Hit{{Msg: "EC2-Classic is retired; DB security groups cannot be created and the resource is gone from provider v5."}}
		}},
	{ID: "TG-AWS-RDS-203", Title: "Global database cluster is not encrypted", Severity: Medium, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_rds_global_cluster"}, Remediation: "Set storage_encrypted = true (forces a new cluster).",
		Check: func(r *Resource) []Hit {
			if r.get("source_db_cluster_identifier") == nil && notTrue(r.get("storage_encrypted")) {
				return []Hit{{Path: "storage_encrypted", Msg: "Every regional copy of the data is stored unencrypted.", Fix: fix(true, "Encrypt storage (replaces the cluster)", "storage_encrypted")}}
			}
			return nil
		}},
	{ID: "TG-AWS-RDS-204", Title: "PostgreSQL version is vulnerable through log_fdw", Severity: Medium, Category: CatSecurity, CWE: "CWE-1104",
		Types: []string{"aws_db_instance", "aws_rds_cluster"}, Remediation: "Upgrade engine_version past the fixes in AWS-2022-004.",
		Check: func(r *Resource) []Hit {
			eng, _ := asString(r.get("engine"))
			ver, _ := asString(r.get("engine_version"))
			p := strings.Split(ver, ".")
			n := make([]int, len(p))
			for i, s := range p {
				x, err := strconv.Atoi(s)
				if err != nil {
					return nil
				}
				n[i] = x
			}
			bad := false
			switch {
			case eng == "postgres" && len(n) >= 2 && len(n) <= 3:
				fixed := map[int]int{13: 2, 12: 6, 11: 11, 10: 16}
				switch m, ok := fixed[n[0]]; {
				case n[0] >= 14:
				case ok:
					bad = n[1] <= m
				case n[0] == 9 && n[1] == 6:
					if len(n) < 3 {
						return nil
					}
					bad = n[2] <= 21
				default:
					bad = true
				}
			case eng == "aurora-postgresql" && len(n) == 2:
				fixed := map[int]int{11: 8, 10: 13}
				if m, ok := fixed[n[0]]; ok {
					bad = n[1] <= m
				} else {
					bad = n[0] < 12
				}
			}
			if bad {
				return []Hit{{Path: "engine_version", Msg: eng + " " + ver + " lets database users read local files through the log_fdw extension."}}
			}
			return nil
		}},
	{ID: "TG-AWS-RDS-205", Title: "Aurora MySQL cluster does not export audit logs", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"aws_rds_cluster"}, Remediation: `Add "audit" to enabled_cloudwatch_logs_exports.`,
		Check: func(r *Resource) []Hit {
			v := r.get("enabled_cloudwatch_logs_exports")
			if e, _ := asString(r.get("engine")); awspAuroraMySQL(e, true) && !isUnknown(v) && !contains(asStrings(v), "audit") {
				return []Hit{{Path: "enabled_cloudwatch_logs_exports", Msg: "Logins and queries are not sent to CloudWatch."}}
			}
			return nil
		}},
	{ID: "TG-AWS-RDS-206", Title: "Aurora MySQL backtracking is off", Severity: Low, Category: CatReliability, CWE: "CWE-693",
		Types: []string{"aws_rds_cluster"}, Remediation: "Set backtrack_window (seconds, up to 259200).",
		Check: func(r *Resource) []Hit {
			v := r.get("backtrack_window")
			if n, ok := asFloat(v); awspAuroraEngine(r) && (v == nil || ok && n == 0) {
				return []Hit{{Path: "backtrack_window", Msg: "A bad write can only be undone by restoring a snapshot."}}
			}
			return nil
		}},
	{ID: "TG-AWS-RDS-207", Title: "RDS Performance Insights is off", Severity: Low, Category: CatBestPrac, CWE: "CWE-778",
		Types: []string{"aws_db_instance", "aws_rds_cluster_instance"}, Remediation: "Set performance_insights_enabled = true.",
		Check: func(r *Resource) []Hit {
			eng, _ := asString(r.get("engine"))
			class, _ := asString(r.get("instance_class"))
			small := map[string]bool{"db.t2.micro": true, "db.t2.small": true, "db.t3.micro": true, "db.t3.small": true, "db.t4g.micro": true, "db.t4g.small": true}
			if (eng == "mariadb" || eng == "mysql") && small[class] || strings.HasPrefix(eng, "db2") {
				return nil // not supported on these
			}
			if notTrue(r.get("performance_insights_enabled")) {
				return []Hit{{Path: "performance_insights_enabled", Msg: "Load and slow queries cannot be diagnosed after the fact.", Fix: fix(true, "Enable Performance Insights", "performance_insights_enabled")}}
			}
			return nil
		}},
	{ID: "TG-AWS-RDS-208", Title: "Performance Insights uses the AWS-managed key", Severity: Low, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_db_instance", "aws_rds_cluster_instance"}, Remediation: "Set performance_insights_kms_key_id to a customer-managed key.",
		Check: func(r *Resource) []Hit {
			if is(r.get("performance_insights_enabled"), true) && r.get("performance_insights_kms_key_id") == nil {
				return []Hit{{Path: "performance_insights_kms_key_id", Msg: "Captured SQL text is encrypted with a key you cannot restrict."}}
			}
			return nil
		}},

	// ElastiCache
	{ID: "TG-AWS-CACHE-201", Title: "ElastiCache security group is an EC2-Classic resource", Severity: Low, Category: CatReliability, CWE: "CWE-477",
		Types: []string{"aws_elasticache_security_group"}, Remediation: "Use VPC security groups via security_group_ids.",
		Check: func(r *Resource) []Hit {
			return []Hit{{Msg: "EC2-Classic is retired; cache security groups cannot be created and the resource is gone from provider v5."}}
		}},
	{ID: "TG-AWS-CACHE-202", Title: "Redis cache cluster has no automatic backups", Severity: Low, Category: CatReliability, CWE: "CWE-693",
		Types: []string{"aws_elasticache_cluster"}, Remediation: "Set snapshot_retention_limit to 1 or more.",
		Check: func(r *Resource) []Hit {
			v := r.get("snapshot_retention_limit")
			// Members of a replication group take backups from the group and cannot set this.
			if eng, _ := asString(r.get("engine")); eng == "memcached" || isUnknown(v) || r.get("replication_group_id") != nil {
				return nil
			}
			if n, _ := asFloat(v); n == 0 {
				return []Hit{{Path: "snapshot_retention_limit", Msg: "Cached data cannot be restored after a node failure or bad flush."}}
			}
			return nil
		}},
	{ID: "TG-AWS-CACHE-203", Title: "Redis cache cluster has minor version upgrades off", Severity: Low, Category: CatSecurity, CWE: "CWE-1104",
		Types: []string{"aws_elasticache_cluster"}, Remediation: "Set auto_minor_version_upgrade = true.",
		Check: func(r *Resource) []Hit {
			if eng, _ := asString(r.get("engine")); eng != "memcached" && is(r.get("auto_minor_version_upgrade"), false) {
				return []Hit{{Path: "auto_minor_version_upgrade", Msg: "Security patches for the engine are never applied automatically.", Fix: fix(true, "Enable minor upgrades", "auto_minor_version_upgrade")}}
			}
			return nil
		}},

	// S3
	{ID: "TG-AWS-S3-201", Title: "S3 object lock configuration is not enabled", Severity: Low, Category: CatReliability, CWE: "CWE-693",
		Types: []string{"aws_s3_bucket"}, Remediation: `Set object_lock_configuration.object_lock_enabled = "Enabled" (or object_lock_enabled = true).`,
		Check: func(r *Resource) []Hit {
			if r.get("object_lock_configuration") == nil {
				return nil
			}
			if v := r.get("object_lock_configuration.object_lock_enabled"); !isUnknown(v) && !contains(asStrings(v), "Enabled") {
				return []Hit{{Path: "object_lock_configuration", Msg: "Objects can be deleted or overwritten despite the lock block."}}
			}
			return nil
		}},
	{ID: "TG-AWS-S3-202", Title: "S3 lifecycle never aborts incomplete uploads", Severity: Info, Category: CatBestPrac, CWE: "CWE-400",
		Types: []string{"aws_s3_bucket_lifecycle_configuration"}, Remediation: "Add an enabled bucket-wide rule with abort_incomplete_multipart_upload { days_after_initiation = 7 }.",
		Check: func(r *Resource) []Hit {
			if isUnknown(r.get("rule")) {
				return nil // dynamic rules
			}
			for _, rule := range r.blocks("rule") {
				if st, _ := asString(rule["status"]); st != "Enabled" || len(blocksAt(rule, "abort_incomplete_multipart_upload")) == 0 {
					continue
				}
				scoped := false
				for _, f := range blocksAt(rule, "filter") {
					if a := blocksAt(f, "and"); len(a) > 0 {
						f = a[0]
					}
					for _, k := range []string{"prefix", "object_size_greater_than", "object_size_less_than", "tag"} {
						if awspTruthy(f[k]) {
							scoped = true
						}
					}
				}
				if !scoped {
					return nil
				}
			}
			return []Hit{{Path: "rule", Msg: "Parts of failed multipart uploads are stored and billed forever."}}
		}},
	{ID: "TG-AWS-S3-203", Title: "S3 ACL lets everyone read or manage permissions", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"aws_s3_bucket_acl"}, Remediation: "Remove FULL_CONTROL and READ_ACP grants to the AllUsers group.",
		Check: func(r *Resource) []Hit {
			for _, p := range r.blocks("access_control_policy") {
				for _, g := range blocksAt(p, "grant") {
					perm, _ := asString(g["permission"])
					if perm != "FULL_CONTROL" && perm != "READ_ACP" {
						continue
					}
					for _, ge := range blocksAt(g, "grantee") {
						if u, _ := asString(ge["uri"]); strings.Contains(u, "acs.amazonaws.com/groups/global/AllUsers") {
							return []Hit{{Path: "access_control_policy", Msg: "Anyone on the internet gets " + perm + " on the bucket."}}
						}
					}
				}
			}
			return nil
		}},
	{ID: "TG-AWS-S3-204", Title: "S3 access point turns off all public access blocks", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"aws_s3_access_point"}, Remediation: "Keep block_public_acls, block_public_policy and restrict_public_buckets true.",
		Check: func(r *Resource) []Hit {
			c := "public_access_block_configuration."
			if is(r.get(c+"block_public_acls"), false) && is(r.get(c+"block_public_policy"), false) && is(r.get(c+"restrict_public_buckets"), false) {
				return []Hit{{Path: "public_access_block_configuration", Msg: "A policy or ACL on the access point can make data public."}}
			}
			return nil
		}},
	{ID: "TG-AWS-S3-205", Title: "S3 bucket policy denies policy changes to everyone", Severity: Medium, Category: CatReliability, CWE: "CWE-284",
		Types: []string{"aws_s3_bucket", "aws_s3_bucket_policy"}, Remediation: "Add a Condition (for example aws:PrincipalArn) so admins can still change the policy.",
		Check: func(r *Resource) []Hit {
			for _, st := range awspStmts(r.get("policy")) {
				if st["Effect"] != "Deny" || st["Condition"] != nil || st["NotAction"] != nil || !awspAnyone(st) {
					continue
				}
				if contains(asStrings(st["Action"]), "s3:PutBucketPolicy", "s3:*BucketPolicy", "s3:Put*", "s3:*", "*") {
					return []Hit{{Path: "policy", Msg: "Nobody but the root user can fix or remove this bucket policy."}}
				}
			}
			return nil
		}},
	{ID: "TG-AWS-S3-206", Title: "S3 bucket policy allows any principal", Severity: Critical, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"aws_s3_bucket", "aws_s3_bucket_policy"}, Remediation: "Name specific principals, or add a Condition on aws:PrincipalOrgID, aws:SourceVpce or aws:PrincipalArn.",
		Check: func(r *Resource) []Hit {
			for _, st := range awspStmts(r.get("policy")) {
				if awspPublic(st) {
					return []Hit{{Path: "policy", Msg: "Any AWS account, or anonymous users, can perform the allowed S3 actions."}}
				}
			}
			return nil
		}},

	// CodeBuild
	{ID: "TG-AWS-CODEBUILD-201", Title: "CodeBuild artifacts use the AWS-managed key", Severity: Low, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_codebuild_project"}, Remediation: "Set encryption_key to a customer-managed KMS key.",
		Check: func(r *Resource) []Hit {
			a := r.get("artifacts")
			if t, _ := asString(r.get("artifacts.type")); a == nil || t == "NO_ARTIFACTS" {
				return nil
			}
			if r.get("encryption_key") == nil {
				return []Hit{{Path: "encryption_key", Msg: "Build outputs are encrypted with aws/s3, which you cannot restrict."}}
			}
			return nil
		}},
	{ID: "TG-AWS-CODEBUILD-202", Title: "CodeBuild project writes no build logs", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"aws_codebuild_project"}, Remediation: "Keep cloudwatch_logs enabled or enable s3_logs.",
		Check: func(r *Resource) []Hit {
			// CloudWatch logging is on by default, so only an explicit DISABLED with no S3 logs is a gap.
			cw, _ := asString(r.get("logs_config.cloudwatch_logs.status"))
			s3, _ := asString(r.get("logs_config.s3_logs.status"))
			if cw == "DISABLED" && s3 != "ENABLED" {
				return []Hit{{Path: "logs_config", Msg: "Builds leave no record of what ran."}}
			}
			return nil
		}},

	// VPC
	{ID: "TG-AWS-VPC-201", Title: "Default VPC is managed and kept in use", Severity: Low, Category: CatBestPrac, CWE: "CWE-1188",
		Types: []string{"aws_default_vpc"}, Remediation: "Run workloads in purpose-built VPCs and leave the default VPC unused or deleted.",
		Check: func(r *Resource) []Hit {
			return []Hit{{Msg: "The default VPC has public subnets and permissive defaults that new resources inherit."}}
		}},

	// Secrets Manager
	{ID: "TG-AWS-SM-201", Title: "Secret uses the AWS-managed key", Severity: Low, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_secretsmanager_secret"}, Remediation: "Set kms_key_id to a customer-managed KMS key.",
		Check: func(r *Resource) []Hit {
			v := r.get("kms_key_id")
			if s, _ := asString(v); !isUnknown(v) && (s == "" || strings.Contains(s, "aws/")) {
				return []Hit{{Path: "kms_key_id", Msg: "Anyone allowed to use aws/secretsmanager can decrypt it; it cannot be shared cross-account."}}
			}
			return nil
		}},
	{ID: "TG-AWS-SM-202", Title: "Secret is rotated less often than every 90 days", Severity: Low, Category: CatSecurity, CWE: "CWE-324",
		Types: []string{"aws_secretsmanager_secret_rotation"}, Remediation: "Set rotation_rules.automatically_after_days to 90 or less.",
		Check: func(r *Resource) []Hit {
			d, e := r.get("rotation_rules.automatically_after_days"), r.get("rotation_rules.schedule_expression")
			if isUnknown(d) || isUnknown(e) {
				return nil
			}
			if n, ok := asFloat(d); ok && n <= 90 {
				return nil
			}
			s, _ := asString(e)
			if strings.HasPrefix(s, "cron(") {
				return nil
			}
			if m := awspRateRE.FindStringSubmatch(s); m != nil {
				n, _ := strconv.Atoi(m[1])
				if map[byte]int{'d': 1, 'h': 24, 'm': 1440}[m[2][0]]*90 >= n {
					return nil
				}
			}
			return []Hit{{Path: "rotation_rules", Msg: "A leaked secret stays valid for more than 90 days."}}
		}},

	// Auto Scaling
	{ID: "TG-AWS-ASG-201", Title: "Auto Scaling group sets no tags", Severity: Low, Category: CatBestPrac, CWE: "CWE-710",
		Types: []string{"aws_autoscaling_group"}, Remediation: "Add tag blocks with propagate_at_launch = true.",
		Check: func(r *Resource) []Hit {
			if r.get("tag") == nil && r.get("tags") == nil {
				return []Hit{{Msg: "Instances launch without owner or cost tags."}}
			}
			return nil
		}},
	{ID: "TG-AWS-ASG-202", Title: "Auto Scaling group uses a launch configuration", Severity: Low, Category: CatBestPrac, CWE: "CWE-477",
		Types: []string{"aws_autoscaling_group"}, Remediation: "Use launch_template (or mixed_instances_policy.launch_template).",
		Check: func(r *Resource) []Hit {
			if r.get("launch_template") == nil && r.get("mixed_instances_policy.launch_template") == nil {
				return []Hit{{Path: "launch_configuration", Msg: "Launch configurations are deprecated and miss IMDSv2 defaults and newer instance types."}}
			}
			return nil
		}},

	// Resource policies
	{ID: "TG-AWS-IAM-201", Title: "Resource policy lets anyone in", Severity: Critical, Category: CatSecurity, CWE: "CWE-284",
		Types:       []string{"aws_glacier_vault", "aws_sqs_queue"}, // TG-AWS-IAM-002 covers the standalone policy resources
		Remediation: "Name specific principals, or add a Condition on aws:PrincipalOrgID, aws:SourceArn or aws:SourceAccount.",
		Check: func(r *Resource) []Hit {
			path := "policy"
			if r.Type == "aws_glacier_vault" {
				path = "access_policy"
			}
			for _, st := range awspStmts(r.get(path)) {
				if awspPublic(st) {
					return []Hit{{Path: path, Msg: "Any AWS account, or anonymous users, can use the allowed actions."}}
				}
			}
			return nil
		}},
	{ID: "TG-AWS-MSG-201", Title: "SQS queue policy allows every action", Severity: Medium, Category: CatSecurity, CWE: "CWE-269",
		Types: []string{"aws_sqs_queue_policy"}, Remediation: "List the SQS actions each principal needs.",
		Check: func(r *Resource) []Hit {
			for _, st := range awspStmts(r.get("policy")) {
				if st["Effect"] != "Deny" && contains(asStrings(st["Action"]), "*") {
					return []Hit{{Path: "policy", Msg: "Principals can also purge, delete and re-permission the queue."}}
				}
			}
			return nil
		}},
	{ID: "TG-AWS-MSG-202", Title: "SNS topic policy grants other accounts without conditions", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"aws_sns_topic_policy"}, Remediation: "Add a Condition (aws:SourceArn, aws:SourceAccount) to cross-account grants.",
		Check: func(r *Resource) []Hit {
			for _, st := range awspStmts(r.get("policy")) {
				if st["Effect"] != "Allow" || st["Condition"] != nil {
					continue
				}
				for _, p := range awspPrincipals(st, "AWS") {
					if strings.HasPrefix(p, "arn:aws:iam::") {
						return []Hit{{Path: "policy", Msg: "Principal " + p + " can use the topic with no further restriction."}}
					}
				}
			}
			return nil
		}},

	// IAM
	{ID: "TG-AWS-IAM-202", Title: "AdministratorAccess granted through a role or permission set", Severity: High, Category: CatSecurity, CWE: "CWE-269",
		Types: []string{"aws_iam_role", "aws_ssoadmin_managed_policy_attachment"}, Remediation: "Use a scoped policy; keep admin for break-glass roles with MFA.",
		Check: func(r *Resource) []Hit {
			path := "managed_policy_arns"
			if r.Type != "aws_iam_role" {
				path = "managed_policy_arn"
			}
			if contains(asStrings(r.get(path)), "arn:aws:iam::aws:policy/AdministratorAccess") {
				return []Hit{{Path: path, Msg: "The AWS-managed AdministratorAccess policy grants full account control."}}
			}
			return nil
		}},
	{ID: "TG-AWS-IAM-203", Title: "IAM user defined instead of federated access", Severity: Low, Category: CatBestPrac, CWE: "CWE-308",
		Types: []string{"aws_iam_user"}, Remediation: "Give people access through IAM Identity Center (SSO) and workloads through roles.",
		Check: func(r *Resource) []Hit {
			return []Hit{{Msg: "IAM users carry long-lived passwords or keys that are hard to rotate and audit."}}
		}},
	{ID: "TG-AWS-IAM-204", Title: "IAM policy exposes credentials", Severity: High, Category: CatSecurity, CWE: "CWE-522",
		Types:       []string{"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy", "aws_ssoadmin_permission_set_inline_policy"},
		Remediation: "Scope credential-issuing actions to specific resource ARNs.",
		Check: func(r *Resource) []Hit {
			var skip []string
			if r.Type == "aws_ssoadmin_permission_set_inline_policy" {
				skip = []string{"*", "*:*", "iam:*", "sts:*", "kms:*", "organizations:*"} // reported by TG-AWS-IAM-209
			}
			return awspActionHits(r, awspCredActions, "can mint or read credentials for other identities", skip...)
		}},
	{ID: "TG-AWS-IAM-205", Title: "IAM policy allows data exfiltration on all resources", Severity: Medium, Category: CatSecurity, CWE: "CWE-200",
		Types:       []string{"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy", "aws_ssoadmin_permission_set_inline_policy"},
		Remediation: "Scope object, parameter and secret reads to specific resource ARNs.",
		Check: func(r *Resource) []Hit {
			return awspActionHits(r, awspExfilActions, "reads every object, parameter or secret in the account")
		}},
	{ID: "TG-AWS-IAM-206", Title: "GitHub OIDC trust accepts unsafe subject claims", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"aws_iam_role"}, Remediation: `Restrict token.actions.githubusercontent.com:sub to "repo:<org>/<repo>:..." values.`,
		Check: func(r *Resource) []Hit {
			for _, st := range awspStmts(r.get("assume_role_policy")) {
				if !awspGitHubPrincipal(st) {
					continue
				}
				if bad, why := awspGitHubUnsafe(st["Condition"]); bad {
					return []Hit{{Path: "assume_role_policy", Msg: "Workflows outside your repositories can assume this role: " + why + "."}}
				}
			}
			return nil
		}},
	{ID: "TG-AWS-IAM-207", Title: "Shared policy attachment includes IAM users", Severity: Low, Category: CatSecurity, CWE: "CWE-269",
		Types: []string{"aws_iam_policy_attachment"}, Remediation: "Attach the policy to groups or roles instead of users.",
		Check: func(r *Resource) []Hit {
			if v := r.get("users"); v != nil && !isUnknown(v) && len(asStrings(v))+awspLen(v) > 0 {
				return []Hit{{Path: "users", Msg: "Policies attached directly to users are hard to audit and revoke."}}
			}
			return nil
		}},
	{ID: "TG-AWS-IAM-208", Title: "Role trusts an entire AWS account", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"aws_iam_role"}, Remediation: "Trust specific role ARNs, or require sts:ExternalId or MFA in a Condition.",
		Check: func(r *Resource) []Hit {
			for _, st := range awspStmts(r.get("assume_role_policy")) {
				// A Condition (ExternalId, MFA, PrincipalArn) narrows the trust, so it is not flagged.
				if st["Effect"] == "Deny" || st["Condition"] != nil {
					continue
				}
				for _, p := range awspPrincipals(st, "AWS") {
					if awspAccountRE.MatchString(p) {
						return []Hit{{Path: "assume_role_policy", Msg: "Any identity in account " + p + " with sts:AssumeRole permission can assume this role."}}
					}
				}
			}
			return nil
		}},
	{ID: "TG-AWS-IAM-209", Title: "Permission set inline policy grants wildcard permissions", Severity: High, Category: CatSecurity, CWE: "CWE-269",
		Types: []string{"aws_ssoadmin_permission_set_inline_policy"}, Remediation: "List the exact actions and resource ARNs the permission set needs.",
		Check: func(r *Resource) []Hit {
			return wildcardHits(statements(awspDoc(r.get("inline_policy"))), "inline_policy")
		}},

	// Lambda
	{ID: "TG-AWS-LAMBDA-201", Title: "Lambda environment uses the AWS-managed key", Severity: Low, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_lambda_function"}, Remediation: "Set kms_key_arn to a customer-managed key.",
		Check: func(r *Resource) []Hit {
			if r.get("environment") == nil {
				return nil
			}
			// A key with no environment variables has nothing to encrypt, so that is not a gap.
			if v := r.get("kms_key_arn"); !isUnknown(v) {
				if s, _ := asString(v); s == "" {
					return []Hit{{Path: "kms_key_arn", Msg: "Environment variables are decryptable by anyone allowed to use aws/lambda."}}
				}
			}
			return nil
		}},
	{ID: "TG-AWS-LAMBDA-202", Title: "Lambda environment holds a hard-coded secret", Severity: High, Category: CatSecurity, CWE: "CWE-798",
		Types: []string{"aws_lambda_function"}, Remediation: "Read secrets from Secrets Manager or SSM at runtime.",
		Check: func(r *Resource) []Hit {
			vars, _ := r.get("environment.variables").(map[string]any)
			for k, v := range vars {
				s, ok := asString(v)
				if ok && (awspAWSKeyRE.MatchString(s) || secretNameRE.MatchString(k) && len(s) >= 8 && !strings.HasPrefix(s, "arn:")) {
					return []Hit{{Path: "environment", Msg: "Variable " + k + " is visible to anyone who can read the function configuration."}}
				}
			}
			return nil
		}},
	{ID: "TG-AWS-LAMBDA-203", Title: "Lambda X-Ray tracing is not active", Severity: Low, Category: CatBestPrac, CWE: "CWE-778",
		Types: []string{"aws_lambda_function"}, Remediation: `Add tracing_config { mode = "Active" }.`,
		Check: func(r *Resource) []Hit {
			// Absent tracing_config means PassThrough; neither one traces, so both are flagged.
			v := r.get("tracing_config.mode")
			if s, _ := asString(v); s != "Active" && !isUnknown(v) {
				return []Hit{{Path: "tracing_config", Msg: "Requests through this function cannot be traced.", Fix: fix("Active", "Enable X-Ray tracing", "tracing_config", "mode")}}
			}
			return nil
		}},

	// EC2
	{ID: "TG-AWS-EC2-201", Title: "AMI volume is not encrypted", Severity: Medium, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_ami"}, Remediation: "Set encrypted = true on every ebs_block_device that is not built from a snapshot.",
		Check: func(r *Resource) []Hit {
			for i, d := range r.blocks("ebs_block_device") {
				if d["snapshot_id"] == nil && notTrue(d["encrypted"]) {
					return []Hit{{Path: fmt.Sprintf("ebs_block_device.%d", i), Msg: "Instances launched from this image get unencrypted disks."}}
				}
			}
			return nil
		}},
	{ID: "TG-AWS-EC2-202", Title: "User data contains AWS credentials", Severity: High, Category: CatSecurity, CWE: "CWE-798",
		Types: []string{"aws_instance", "aws_launch_template", "aws_launch_configuration"}, Remediation: "Use an instance profile instead of keys in user data.",
		Check: func(r *Resource) []Hit {
			if s, ok := asString(r.get("user_data")); ok && (awspAWSKeyRE.MatchString(s) || awspAWSSecretRE.MatchString(s)) {
				return []Hit{{Path: "user_data", Msg: "Anyone who can describe the instance, or reach IMDS, can read these keys."}}
			}
			return nil
		}},
	{ID: "TG-AWS-EC2-203", Title: "Launch configuration allows IMDSv1", Severity: Medium, Category: CatSecurity, CWE: "CWE-918",
		Types: []string{"aws_launch_configuration"}, Remediation: `Add metadata_options { http_tokens = "required" }.`,
		Check: func(r *Resource) []Hit {
			if ep, _ := asString(r.get("metadata_options.http_endpoint")); ep == "disabled" {
				return nil
			}
			v := r.get("metadata_options.http_tokens")
			if s, _ := asString(v); s != "required" && !isUnknown(v) {
				return []Hit{{Path: "metadata_options", Msg: "An SSRF bug can steal the instance role credentials.", Fix: fix("required", "Require IMDSv2", "metadata_options", "http_tokens")}}
			}
			return nil
		}},
	{ID: "TG-AWS-EC2-204", Title: "Instance disks rely on account default encryption", Severity: Low, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_instance", "aws_launch_configuration"}, Remediation: "Add root_block_device { encrypted = true } and encrypt every ebs_block_device.",
		Check: func(r *Resource) []Hit {
			root := r.get("root_block_device")
			if isUnknown(root) {
				return nil
			}
			if root == nil || get(root, "encrypted") == nil && get(root, "snapshot_id") == nil {
				return []Hit{{Path: "root_block_device", Msg: "The root disk is unencrypted unless EBS encryption by default is on for the account."}}
			}
			if r.Type == "aws_launch_configuration" {
				for _, b := range []string{"root_block_device", "ebs_block_device"} {
					for i, d := range r.blocks(b) {
						if is(d["encrypted"], false) && d["snapshot_id"] == nil {
							return []Hit{{Path: fmt.Sprintf("%s.%d.encrypted", b, i), Msg: b + " explicitly disables encryption."}}
						}
					}
				}
			}
			return nil
		}},
	{ID: "TG-AWS-TGW-201", Title: "Transit gateway auto-accepts shared attachments", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"aws_ec2_transit_gateway"}, Remediation: `Set auto_accept_shared_attachments = "disable".`,
		Check: func(r *Resource) []Hit {
			if v, _ := asString(r.get("auto_accept_shared_attachments")); v == "enable" {
				return []Hit{{Path: "auto_accept_shared_attachments", Msg: "Any account the gateway is shared with can join its network without review.", Fix: fix("disable", "Require attachment approval", "auto_accept_shared_attachments")}}
			}
			return nil
		}},

	// ECS
	{ID: "TG-AWS-ECS-201", Title: "ECS Exec sessions are not logged with encryption", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"aws_ecs_cluster"}, Remediation: "Set execute_command_configuration.kms_key_id and log_configuration with encryption enabled.",
		Check: func(r *Resource) []Hit {
			ec := r.get("configuration.execute_command_configuration")
			if ec == nil {
				return nil
			}
			if l, _ := asString(get(ec, "logging")); l == "NONE" {
				return nil
			}
			lc := get(ec, "log_configuration")
			if get(ec, "kms_key_id") != nil && (is(get(lc, "cloud_watch_encryption_enabled"), true) || is(get(lc, "s3_bucket_encryption_enabled"), true)) {
				return nil
			}
			return []Hit{{Path: "configuration", Msg: "Interactive shells into containers are not encrypted with your key or not recorded encrypted."}}
		}},
	{ID: "TG-AWS-ECS-202", Title: "ECS task and execution roles are the same", Severity: Low, Category: CatSecurity, CWE: "CWE-250",
		Types: []string{"aws_ecs_task_definition"}, Remediation: "Use a separate task_role_arn with only what the application needs.",
		Check: func(r *Resource) []Hit {
			e, t := r.get("execution_role_arn"), r.get("task_role_arn")
			if e != nil && t != nil && fmt.Sprint(e) == fmt.Sprint(t) {
				return []Hit{{Path: "task_role_arn", Msg: "Application code gets the image-pull and secret-read rights of the execution role."}}
			}
			return nil
		}},
	{ID: "TG-AWS-ECS-203", Title: "Fargate service pins an old platform version", Severity: Low, Category: CatSecurity, CWE: "CWE-1104",
		Types: []string{"aws_ecs_service"}, Remediation: `Set platform_version = "LATEST" or remove it.`,
		Check: func(r *Resource) []Hit {
			if lt, _ := asString(r.get("launch_type")); lt == "FARGATE" {
				if v, ok := asString(r.get("platform_version")); ok && v != "LATEST" {
					return []Hit{{Path: "platform_version", Msg: "Tasks miss kernel and runtime patches from newer platform versions.", Fix: fix("LATEST", "Track the latest platform", "platform_version")}}
				}
			}
			return nil
		}},
	{ID: "TG-AWS-ECS-204", Title: "ECS Container Insights is off", Severity: Low, Category: CatBestPrac, CWE: "CWE-778",
		Types: []string{"aws_ecs_cluster"}, Remediation: `Add setting { name = "containerInsights" value = "enabled" }.`,
		Check: func(r *Resource) []Hit {
			for _, s := range r.blocks("setting") {
				if n, _ := asString(s["name"]); n == "containerInsights" {
					if v, _ := asString(s["value"]); v == "enabled" || v == "enhanced" || isUnknown(s["value"]) {
						return nil
					}
				}
			}
			return []Hit{{Path: "setting", Msg: "Task-level CPU, memory and restart metrics are not collected."}}
		}},
	{ID: "TG-AWS-BATCH-201", Title: "Batch job runs a privileged container", Severity: High, Category: CatSecurity, CWE: "CWE-250",
		Types: []string{"aws_batch_job_definition"}, Remediation: "Remove privileged = true from container_properties.",
		Check: func(r *Resource) []Hit {
			if awspTruthy(get(awspDoc(r.get("container_properties")), "privileged")) {
				return []Hit{{Path: "container_properties", Msg: "The job's container has root access to the host."}}
			}
			return nil
		}},

	// MQ
	{ID: "TG-AWS-MQ-201", Title: "ActiveMQ broker audit logging is off", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"aws_mq_broker"}, Remediation: "Set logs { audit = true }.",
		Check: func(r *Resource) []Hit {
			if t, _ := asString(r.get("engine_type")); !strings.EqualFold(t, "RabbitMQ") && notTrue(r.get("logs.audit")) {
				return []Hit{{Path: "logs", Msg: "Management actions on the broker are not audited.", Fix: fix(true, "Enable audit logs", "logs", "audit")}}
			}
			return nil
		}},
	{ID: "TG-AWS-MQ-202", Title: "MQ broker runs an outdated engine version", Severity: Low, Category: CatSecurity, CWE: "CWE-1104",
		Types: []string{"aws_mq_broker", "aws_mq_configuration"}, Remediation: "Use ActiveMQ 5.17+ or RabbitMQ 3.11+.",
		Check: func(r *Resource) []Hit {
			t, _ := asString(r.get("engine_type"))
			t = map[string]string{"activemq": "ActiveMQ", "rabbitmq": "RabbitMQ"}[strings.ToLower(t)]
			v, _ := asString(r.get("engine_version"))
			maj, min, ok := awspMajorMinor(v)
			if !ok {
				return nil
			}
			if t == "ActiveMQ" && (maj < 5 || maj == 5 && min < 17) || t == "RabbitMQ" && (maj < 3 || maj == 3 && min < 11) {
				return []Hit{{Path: "engine_version", Msg: t + " " + v + " is past end of support."}}
			}
			return nil
		}},

	// Image Builder
	{ID: "TG-AWS-IMAGEBUILDER-201", Title: "Image recipe disk is not encrypted with a customer key", Severity: Low, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_imagebuilder_image_recipe"}, Remediation: "Set ebs.encrypted = true and ebs.kms_key_id in every block_device_mapping.",
		Check: func(r *Resource) []Hit {
			for _, m := range r.blocks("block_device_mapping") {
				for _, e := range blocksAt(m, "ebs") {
					if notTrue(e["encrypted"]) {
						return []Hit{{Path: "block_device_mapping", Sev: Medium, Msg: "Images are built with unencrypted volumes."}}
					}
					if e["kms_key_id"] == nil {
						return []Hit{{Path: "block_device_mapping", Msg: "Image volumes use the AWS-managed EBS key."}}
					}
				}
			}
			return nil
		}},

	// WAF
	{ID: "TG-AWS-WAF-201", Title: "WAF web ACL has no rules", Severity: Medium, Category: CatSecurity, CWE: "CWE-693",
		Types: []string{"aws_waf_web_acl", "aws_wafregional_web_acl", "aws_wafv2_web_acl"}, Remediation: "Add rules, for example the AWS managed common rule set.",
		Check: func(r *Resource) []Hit {
			if !awspNonEmpty(r.get("rule")) && !awspNonEmpty(r.get("rules")) {
				return []Hit{{Msg: "Every request falls through to the default action; nothing is filtered."}}
			}
			return nil
		}},
	{ID: "TG-AWS-WAF-202", Title: "WAF web ACL does not block Log4Shell", Severity: Medium, Category: CatSecurity, CWE: "CWE-917",
		Types: []string{"aws_wafv2_web_acl"}, Remediation: "Add AWSManagedRulesKnownBadInputsRuleSet with override_action { none {} } and keep Log4JRCE active.",
		Check: func(r *Resource) []Hit {
			if isUnknown(r.get("rule")) {
				return nil // dynamic rules
			}
			for _, rule := range r.blocks("rule") {
				g := get(rule, "statement.managed_rule_group_statement")
				if n, _ := asString(get(g, "name")); n != "AWSManagedRulesKnownBadInputsRuleSet" {
					continue
				}
				for _, k := range []string{"excluded_rule", "rule_action_override"} {
					for _, x := range blocksAt(g, k) {
						if n, _ := asString(x["name"]); n == "Log4JRCE" {
							return []Hit{{Path: "rule", Msg: "The Log4JRCE rule is excluded, so CVE-2021-44228 payloads pass."}}
						}
					}
				}
				if get(rule, "override_action.none") == nil {
					return []Hit{{Path: "rule", Msg: "The known-bad-inputs group only counts matches; Log4Shell payloads pass."}}
				}
				return nil
			}
			return []Hit{{Path: "rule", Msg: "No AWSManagedRulesKnownBadInputsRuleSet rule; Log4Shell (CVE-2021-44228) payloads pass."}}
		}},
	{ID: "TG-AWS-WAF-203", Title: "WAF rule has no action", Severity: Low, Category: CatSecurity, CWE: "CWE-693",
		Types:       []string{"aws_waf_web_acl", "aws_wafregional_web_acl", "aws_wafv2_web_acl", "aws_wafv2_rule_group", "aws_wafregional_rule_group", "aws_waf_rule_group"},
		Remediation: "Give every rule an action or override_action.",
		Check: func(r *Resource) []Hit {
			for _, k := range []string{"rule", "rules", "activated_rule"} {
				for i, rule := range r.blocks(k) {
					if !awspNonEmpty(rule["action"]) && !awspNonEmpty(rule["override_action"]) && get(rule, "statement.managed_rule_group_statement") == nil {
						return []Hit{{Path: fmt.Sprintf("%s.%d", k, i), Msg: "A rule without an action never blocks or counts anything."}}
					}
				}
			}
			return nil
		}},

	// CloudFront
	{ID: "TG-AWS-CDN-201", Title: "CloudFront viewers can use TLS below 1.2", Severity: Medium, Category: CatSecurity, CWE: "CWE-327",
		Types: []string{"aws_cloudfront_distribution"}, Remediation: `Use your own certificate with minimum_protocol_version = "TLSv1.2_2021".`,
		Check: func(r *Resource) []Hit {
			if is(r.get("viewer_certificate.cloudfront_default_certificate"), true) {
				return []Hit{{Path: "viewer_certificate", Msg: "The default *.cloudfront.net certificate accepts TLS 1.0 and 1.1."}}
			}
			v := r.get("viewer_certificate.minimum_protocol_version")
			if s, _ := asString(v); !isUnknown(v) && !awspTLS12RE.MatchString(s) && !contains([]string{"SSLv3", "TLSv1", "TLSv1_2016", "TLSv1.1_2016"}, s) { // TG-AWS-CDN-001 reports those
				return []Hit{{Path: "viewer_certificate", Msg: "Viewers can negotiate protocols older than TLS 1.2."}}
			}
			return nil
		}},
	{ID: "TG-AWS-CDN-202", Title: "CloudFront response policy has weak HSTS", Severity: Low, Category: CatSecurity, CWE: "CWE-319",
		Types: []string{"aws_cloudfront_response_headers_policy"}, Remediation: "Set strict_transport_security with max age >= 31536000, include_subdomains, preload and override = true.",
		Check: func(r *Resource) []Hit {
			h := r.get("security_headers_config.strict_transport_security")
			age, _ := asFloat(get(h, "access_control_max_age_sec"))
			if h == nil || age < 31536000 || !is(get(h, "include_subdomains"), true) || !is(get(h, "preload"), true) || !is(get(h, "override"), true) {
				return []Hit{{Path: "security_headers_config", Msg: "Browsers may still connect over plain HTTP and be downgraded."}}
			}
			return nil
		}},
	{ID: "TG-AWS-CDN-203", Title: "CloudFront distribution has no origin failover", Severity: Low, Category: CatReliability, CWE: "CWE-1188",
		Types: []string{"aws_cloudfront_distribution"}, Remediation: "Add an origin_group with failover_criteria and two members.",
		Check: func(r *Resource) []Hit {
			gs := r.blocks("origin_group")
			for _, g := range gs {
				if g["failover_criteria"] == nil || awspLen(g["member"]) < 2 {
					gs = nil
					break
				}
			}
			if len(gs) == 0 {
				return []Hit{{Path: "origin_group", Msg: "If the origin goes down, every request fails."}}
			}
			return nil
		}},

	// Firehose
	{ID: "TG-AWS-FIREHOSE-201", Title: "Firehose stream is not encrypted with a customer key", Severity: Low, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_kinesis_firehose_delivery_stream"}, Remediation: `Set server_side_encryption { enabled = true, key_type = "CUSTOMER_MANAGED_CMK", key_arn = <key> }.`,
		Check: func(r *Resource) []Hit {
			if r.get("kinesis_source_configuration") != nil {
				return nil // SSE is set on the source stream instead
			}
			kt, _ := asString(r.get("server_side_encryption.key_type"))
			if !is(r.get("server_side_encryption.enabled"), true) || kt != "CUSTOMER_MANAGED_CMK" || !awspTruthy(r.get("server_side_encryption.key_arn")) {
				return []Hit{{Path: "server_side_encryption", Msg: "Buffered records are not encrypted with a key you control."}}
			}
			return nil
		}},

	// DLM
	{ID: "TG-AWS-DLM-201", Title: "DLM cross-region copies are not encrypted", Severity: Medium, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_dlm_lifecycle_policy"}, Remediation: "Set encrypted = true on cross_region_copy_rule and encryption = true on event cross_region_copy.",
		Check: func(r *Resource) []Hit { return awspDLM(r, false) }},
	{ID: "TG-AWS-DLM-202", Title: "DLM cross-region copies use the AWS-managed key", Severity: Low, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_dlm_lifecycle_policy"}, Remediation: "Set cmk_arn on every encrypted cross-region copy.",
		Check: func(r *Resource) []Hit { return awspDLM(r, true) }},

	// CodeCommit, Keyspaces, DMS, CodeGuru
	{ID: "TG-AWS-CODECOMMIT-201", Title: "CodeCommit approval template needs fewer than 2 approvals", Severity: Low, Category: CatBestPrac, CWE: "CWE-284",
		Types: []string{"aws_codecommit_approval_rule_template"}, Remediation: `Set "NumberOfApprovalsNeeded": 2 or more in content.`,
		Check: func(r *Resource) []Hit {
			doc := awspDoc(r.get("content"))
			if doc == nil {
				return nil
			}
			if n, ok := asFloat(get(doc, "Statements.0.NumberOfApprovalsNeeded")); !ok || n < 2 {
				return []Hit{{Path: "content", Msg: "A single reviewer can approve changes to protected branches."}}
			}
			return nil
		}},
	{ID: "TG-AWS-KEYSPACES-201", Title: "Keyspaces table uses the AWS-owned key", Severity: Low, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_keyspaces_table"}, Remediation: `Set encryption_specification { type = "CUSTOMER_MANAGED_KMS_KEY", kms_key_identifier = <key> }.`,
		Check: func(r *Resource) []Hit {
			if t, _ := asString(r.get("encryption_specification.type")); t != "CUSTOMER_MANAGED_KMS_KEY" || r.get("encryption_specification.kms_key_identifier") == nil {
				return []Hit{{Path: "encryption_specification", Msg: "Table data uses a key you cannot audit or revoke."}}
			}
			return nil
		}},
	{ID: "TG-AWS-DMS-201", Title: "DMS endpoint uses the AWS-managed key", Severity: Low, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_dms_endpoint"}, Remediation: "Set kms_key_arn (or s3_settings.server_side_encryption_kms_key_id for S3 targets).",
		Check: func(r *Resource) []Hit {
			k := "kms_key_arn"
			if e, _ := asString(r.get("engine_name")); e == "s3" {
				k = "s3_settings.server_side_encryption_kms_key_id"
			}
			if v := r.get(k); !isUnknown(v) && !awspTruthy(v) {
				return []Hit{{Path: strings.Split(k, ".")[0], Msg: "Endpoint credentials and data use the default aws/dms key."}}
			}
			return nil
		}},
	{ID: "TG-AWS-CODEGURU-201", Title: "CodeGuru Reviewer association uses the AWS-owned key", Severity: Low, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_codegurureviewer_repository_association"}, Remediation: `Set kms_key_details { encryption_option = "CUSTOMER_MANAGED_CMK" }.`,
		Check: func(r *Resource) []Hit {
			if o, _ := asString(r.get("kms_key_details.encryption_option")); o != "CUSTOMER_MANAGED_CMK" && !isUnknown(r.get("kms_key_details.encryption_option")) {
				return []Hit{{Path: "kms_key_details", Msg: "Source code analysed by CodeGuru is encrypted with a key you do not control."}}
			}
			return nil
		}},

	// Elastic Beanstalk
	{ID: "TG-AWS-EB-201", Title: "Elastic Beanstalk enhanced health reporting is off", Severity: Low, Category: CatReliability, CWE: "CWE-778",
		Types: []string{"aws_elastic_beanstalk_environment"}, Remediation: `Add setting { namespace = "aws:elasticbeanstalk:healthreporting:system" name = "HealthStreamingEnabled" value = "true" }.`,
		Check: func(r *Resource) []Hit {
			return awspEBSetting(r, "aws:elasticbeanstalk:healthreporting:system", "HealthStreamingEnabled", "Instance and application health is not streamed, so failures surface late.")
		}},
	{ID: "TG-AWS-EB-202", Title: "Elastic Beanstalk managed platform updates are off", Severity: Low, Category: CatSecurity, CWE: "CWE-1104",
		Types: []string{"aws_elastic_beanstalk_environment"}, Remediation: `Add setting { namespace = "aws:elasticbeanstalk:managedactions" name = "ManagedActionsEnabled" value = "true" }.`,
		Check: func(r *Resource) []Hit {
			return awspEBSetting(r, "aws:elasticbeanstalk:managedactions", "ManagedActionsEnabled", "Platform patches are never applied automatically.")
		}},

	// OpenSearch / Elasticsearch
	{ID: "TG-AWS-OS-201", Title: "OpenSearch audit logs are not published", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"aws_elasticsearch_domain", "aws_opensearch_domain"}, Remediation: `Add log_publishing_options { log_type = "AUDIT_LOGS" cloudwatch_log_group_arn = <arn> }.`,
		Check: func(r *Resource) []Hit {
			for _, o := range r.blocks("log_publishing_options") {
				// enabled defaults to true in the provider.
				if t, _ := asString(o["log_type"]); t == "AUDIT_LOGS" && notFalse(o["enabled"]) {
					return nil
				}
			}
			return []Hit{{Path: "log_publishing_options", Msg: "Who read or changed which index is not recorded."}}
		}},
	{ID: "TG-AWS-OS-202", Title: "OpenSearch domain is not highly available", Severity: Low, Category: CatReliability, CWE: "CWE-1188",
		Types: []string{"aws_elasticsearch_domain", "aws_opensearch_domain"}, Remediation: "Use three dedicated master nodes and zone_awareness_enabled = true.",
		Check: func(r *Resource) []Hit {
			n, _ := asFloat(r.get("cluster_config.dedicated_master_count"))
			if n < 3 || !is(r.get("cluster_config.zone_awareness_enabled"), true) {
				return []Hit{{Path: "cluster_config", Msg: "Losing one node or zone can make the cluster unavailable."}}
			}
			return nil
		}},
	{ID: "TG-AWS-OS-204", Title: "OpenSearch publishes no logs", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"aws_elasticsearch_domain", "aws_opensearch_domain"}, Remediation: "Add log_publishing_options with a CloudWatch log group.",
		Check: func(r *Resource) []Hit {
			os := r.blocks("log_publishing_options")
			if len(os) == 0 && !isUnknown(r.get("log_publishing_options")) || len(os) > 0 && is(os[0]["enabled"], false) {
				return []Hit{{Path: "log_publishing_options", Msg: "Slow queries and errors are not recorded."}}
			}
			return nil
		}},

	// MSK, EFS, CloudWatch
	{ID: "TG-AWS-MSK-201", Title: "MSK broker logs are not delivered", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"aws_msk_cluster"}, Remediation: "Enable cloudwatch_logs, firehose or s3 under logging_info.broker_logs.",
		Check: func(r *Resource) []Hit {
			for _, d := range []string{"cloudwatch_logs", "firehose", "s3"} {
				if v := r.get("logging_info.broker_logs." + d + ".enabled"); is(v, true) || isUnknown(v) {
					return nil
				}
			}
			return []Hit{{Path: "logging_info", Msg: "Broker errors and authentication failures are not recorded."}}
		}},
	{ID: "TG-AWS-EFS-201", Title: "EFS access point exposes the file system root", Severity: Low, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"aws_efs_access_point"}, Remediation: "Set root_directory.path to an application directory.",
		Check: func(r *Resource) []Hit {
			v := r.get("root_directory.path")
			if s, _ := asString(v); !isUnknown(v) && (s == "" || s == "/") {
				return []Hit{{Path: "root_directory", Msg: "Clients of this access point can reach every directory in the file system."}}
			}
			return nil
		}},
	{ID: "TG-AWS-CW-201", Title: "Log group keeps logs for less than a year", Severity: Low, Category: CatReliability, CWE: "CWE-779",
		Types: []string{"aws_cloudwatch_log_group"}, Remediation: "Set retention_in_days = 365 or more.",
		Check: func(r *Resource) []Hit {
			// Absent retention means never expire, which is not short retention.
			if n, ok := asFloat(r.get("retention_in_days")); ok && n > 0 && n < 365 {
				return []Hit{{Path: "retention_in_days", Msg: fmt.Sprintf("Logs are deleted after %g days, before most incident investigations finish.", n), Fix: fix(365, "Keep logs for a year", "retention_in_days")}}
			}
			return nil
		}},

	// Security groups
	{ID: "TG-AWS-SG-201", Title: "Security group or rule has no description", Severity: Low, Category: CatBestPrac, CWE: "CWE-710",
		Types: []string{"aws_security_group", "aws_security_group_rule", "aws_db_security_group", "aws_elasticache_security_group",
			"aws_redshift_security_group", "aws_vpc_security_group_egress_rule", "aws_vpc_security_group_ingress_rule"},
		Remediation: "Describe why each group and rule exists.",
		Check: func(r *Resource) []Hit {
			if s, _ := asString(r.get("description")); s == "" && !isUnknown(r.get("description")) {
				return []Hit{{Path: "description", Msg: "Without a description nobody can tell whether the access is still needed."}}
			}
			for _, k := range []string{"ingress", "egress"} {
				for i, b := range r.blocks(k) {
					if s, _ := asString(b["description"]); s == "" && !isUnknown(b["description"]) {
						return []Hit{{Path: fmt.Sprintf("%s.%d", k, i), Msg: "An inline " + k + " rule has no description."}}
					}
				}
			}
			return nil
		}},
}

// portedAWSIDs maps foreign check IDs to these rules, or to an existing rule
// that already covers the control, so existing skip comments keep working.
var portedAWSIDs = map[string]string{
	// Existing rules that are the same control.
	"CKV_AWS_97": "TG-AWS-ECS-004", "CKV_AWS_336": "TG-AWS-ECS-005", "CKV_AWS_100": "TG-AWS-EKS-003",
	"CKV_AWS_357": "TG-AWS-TRANSFER-002", "CKV_AWS_303": "TG-AWS-SSM-002", "CKV_AWS_206": "TG-AWS-APIGW-003",
	"CKV_AWS_7": "TG-AWS-KMS-001", "CKV_AWS_59": "TG-AWS-APIGW-001", "CKV_AWS_131": "TG-AWS-LB-002",
	"CKV_AWS_28": "TG-AWS-DDB-001", "CKV_AWS_66": "TG-AWS-CW-001", "CKV_AWS_94": "TG-AWS-GLUE-001",
	"CKV_AWS_99": "TG-AWS-GLUE-003", "CKV_AWS_92": "TG-AWS-LB-003", "CKV_AWS_2": "TG-AWS-LB-001",
	"CKV_AWS_63": "TG-AWS-IAM-001", "CKV_AWS_10": "TG-AWS-IAM-008", "CKV_AWS_13": "TG-AWS-IAM-008",
	"CKV_AWS_34": "TG-AWS-CDN-001", "CKV_AWS_96": "TG-AWS-RDS-002", "CKV_AWS_60": "TG-AWS-IAM-002",
	"CKV_AWS_240": "TG-AWS-FIREHOSE-001",
	// SQS: new queues get SSE-SQS by default, so an absent setting is encrypted.
	"CKV_AWS_27": "TG-AWS-MSG-001",
	// ECS has no "privilege" field or container-level pidMode; the rules check the real fields.
	"CKV_AWS_334": "TG-AWS-ECS-001", "CKV_AWS_335": "TG-AWS-ECS-003",
	// Runtimes such as nodejs18.x are retired.
	"CKV_AWS_363": "TG-AWS-LAMBDA-002",
	// TRANSFER-001 flags the policies known to be outdated.
	"CKV_AWS_380": "TG-AWS-TRANSFER-001",

	// New rules.
	"CKV_AWS_308": "TG-AWS-APIGW-201", "CKV_AWS_37": "TG-AWS-EKS-002", "CKV_AWS_339": "TG-AWS-EKS-202",
	"CKV_AWS_101": "TG-AWS-NEPTUNE-201", "CKV_AWS_359": "TG-AWS-NEPTUNE-202", "CKV_AWS_361": "TG-AWS-NEPTUNE-203",
	"CKV_AWS_362": "TG-AWS-NEPTUNE-204", "CKV_AWS_104": "TG-AWS-DOCDB-201", "CKV_AWS_360": "TG-AWS-DOCDB-202",
	"CKV_AWS_85": "TG-AWS-DOCDB-203", "CKV_AWS_105": "TG-AWS-REDSHIFT-201", "CKV_AWS_391": "TG-AWS-REDSHIFT-202",
	"CKV_AWS_71": "TG-AWS-REDSHIFT-203", "CKV_AWS_112": "TG-AWS-SSM-201", "CKV_AWS_113": "TG-AWS-SSM-202",
	"CKV_AWS_337": "TG-AWS-SSM-203", "CKV_AWS_171": "TG-AWS-EMR-201", "CKV_AWS_349": "TG-AWS-EMR-202",
	"CKV_AWS_350": "TG-AWS-EMR-203", "CKV_AWS_351": "TG-AWS-EMR-204", "CKV_AWS_119": "TG-AWS-DDB-201",
	"CKV_AWS_121": "TG-AWS-CONFIG-201", "CKV_AWS_127": "TG-AWS-ELB-201", "CKV_AWS_213": "TG-AWS-ELB-202",
	"CKV_AWS_376": "TG-AWS-ELB-203", "CKV_AWS_152": "TG-AWS-LB-201", "CKV_AWS_261": "TG-AWS-LB-202",
	"CKV_AWS_133": "TG-AWS-RDS-201", "CKV_AWS_198": "TG-AWS-RDS-202", "CKV_AWS_140": "TG-AWS-RDS-203",
	"CKV_AWS_250": "TG-AWS-RDS-204", "CKV_AWS_325": "TG-AWS-RDS-205", "CKV_AWS_326": "TG-AWS-RDS-206",
	"CKV_AWS_353": "TG-AWS-RDS-207", "CKV_AWS_354": "TG-AWS-RDS-208", "CKV_AWS_388": "TG-AWS-RDS-204",
	"CKV_AWS_196": "TG-AWS-CACHE-201", "CKV_AWS_134": "TG-AWS-CACHE-202", "CKV_AWS_322": "TG-AWS-CACHE-203",
	"CKV_AWS_31": "TG-AWS-CACHE-001", "CKV_AWS_143": "TG-AWS-S3-201", "CKV_AWS_300": "TG-AWS-S3-202",
	"CKV_AWS_375": "TG-AWS-S3-203", "CKV_AWS_392": "TG-AWS-S3-204", "CKV_AWS_93": "TG-AWS-S3-205",
	"CKV_AWS_70": "TG-AWS-S3-206", "CKV_AWS_147": "TG-AWS-CODEBUILD-201", "CKV_AWS_314": "TG-AWS-CODEBUILD-202",
	"CKV_AWS_148": "TG-AWS-VPC-201", "CKV_AWS_149": "TG-AWS-SM-201", "CKV_AWS_304": "TG-AWS-SM-202",
	"CKV_AWS_153": "TG-AWS-ASG-201", "CKV_AWS_315": "TG-AWS-ASG-202",
	"CKV_AWS_167": "TG-AWS-IAM-201", "CKV_AWS_168": "TG-AWS-IAM-201", "CKV_AWS_169": "TG-AWS-IAM-201",
	"CKV_AWS_32": "TG-AWS-IAM-201", "CKV_AWS_387": "TG-AWS-IAM-201", "CKV_AWS_72": "TG-AWS-MSG-201",
	"CKV_AWS_385": "TG-AWS-MSG-202", "CKV_AWS_33": "TG-AWS-IAM-002", "CKV_AWS_273": "TG-AWS-IAM-203",
	"CKV_AWS_287": "TG-AWS-IAM-204", "CKV_AWS_288": "TG-AWS-IAM-205", "CKV_AWS_393": "TG-AWS-IAM-206",
	"CKV_AWS_61": "TG-AWS-IAM-208", "CKV_AWS_173": "TG-AWS-LAMBDA-201", "CKV_AWS_45": "TG-AWS-LAMBDA-202",
	"CKV_AWS_50": "TG-AWS-LAMBDA-203", "CKV_AWS_204": "TG-AWS-EC2-201", "CKV_AWS_46": "TG-AWS-EC2-202",
	"CKV_AWS_331": "TG-AWS-TGW-201", "CKV_AWS_224": "TG-AWS-ECS-201", "CKV_AWS_249": "TG-AWS-ECS-202",
	"CKV_AWS_332": "TG-AWS-ECS-203", "CKV_AWS_65": "TG-AWS-ECS-204", "CKV_AWS_210": "TG-AWS-BATCH-201",
	"CKV_AWS_197": "TG-AWS-MQ-201", "CKV_AWS_208": "TG-AWS-MQ-202", "CKV_AWS_200": "TG-AWS-IMAGEBUILDER-201",
	"CKV_AWS_175": "TG-AWS-WAF-201", "CKV_AWS_192": "TG-AWS-WAF-202", "CKV_AWS_342": "TG-AWS-WAF-203",
	"CKV_AWS_174": "TG-AWS-CDN-201", "CKV_AWS_259": "TG-AWS-CDN-202", "CKV_AWS_310": "TG-AWS-CDN-203",
	"CKV_AWS_241": "TG-AWS-FIREHOSE-201", "CKV_AWS_253": "TG-AWS-DLM-201", "CKV_AWS_255": "TG-AWS-DLM-201",
	"CKV_AWS_254": "TG-AWS-DLM-202", "CKV_AWS_256": "TG-AWS-DLM-202", "CKV_AWS_257": "TG-AWS-CODECOMMIT-201",
	"CKV_AWS_265": "TG-AWS-KEYSPACES-201", "CKV_AWS_296": "TG-AWS-DMS-201", "CKV_AWS_381": "TG-AWS-CODEGURU-201",
	"CKV_AWS_312": "TG-AWS-EB-201", "CKV_AWS_340": "TG-AWS-EB-202", "CKV_AWS_317": "TG-AWS-OS-201",
	"CKV_AWS_318": "TG-AWS-OS-202", "CKV_AWS_6": "TG-AWS-CACHE-001", "CKV_AWS_84": "TG-AWS-OS-204",
	"CKV_AWS_80": "TG-AWS-MSK-201", "CKV_AWS_329": "TG-AWS-EFS-201", "CKV_AWS_338": "TG-AWS-CW-201",
	"CKV_AWS_23": "TG-AWS-SG-201",
}

// portedAWSAlso adds a second rule where an existing rule covers only part of
// the control and the new rule fills the gap without duplicating it.
var portedAWSAlso = map[string][]string{
	"CKV_AWS_328": {"TG-AWS-LB-004", "TG-AWS-ELB-204"},
	"CKV_AWS_274": {"TG-AWS-IAM-003", "TG-AWS-IAM-202"},
	"CKV_AWS_40":  {"TG-AWS-IAM-004", "TG-AWS-IAM-207"},
	"CKV_AWS_62":  {"TG-AWS-IAM-001", "TG-AWS-IAM-209"},
	"CKV_AWS_38":  {"TG-AWS-EKS-001", "TG-AWS-EKS-203"},
	"CKV_AWS_79":  {"TG-AWS-EC2-001", "TG-AWS-EC2-203"},
	"CKV_AWS_8":   {"TG-AWS-EBS-001", "TG-AWS-EC2-204"},
}

func init() {
	for ckv, id := range portedAWSIDs {
		foreignRules[ckv] = append(foreignRules[ckv], id)
	}
	for ckv, ids := range portedAWSAlso {
		foreignRules[ckv] = append(foreignRules[ckv], ids...)
	}
}

var (
	awspRefRE       = regexp.MustCompile(`\$\{[^}]*\}`)
	awspTrailingRE  = regexp.MustCompile(`,(\s*[\]}])`) // trailing commas in hand-written heredoc JSON
	awspRateRE      = regexp.MustCompile(`^rate\((\d+)\s+(days?|hours?|minutes?)\)`)
	awspTLS12RE     = regexp.MustCompile(`^TLSv1\.[23]_\d{4}$`)
	awspAccountRE   = regexp.MustCompile(`^(\d{12}|arn:aws:iam::\d{12}:root)`)
	awspAWSKeyRE    = regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`)
	awspAWSSecretRE = regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*["']?[A-Za-z0-9/+]{40}`)
	awspGHRepoRE    = regexp.MustCompile(`^(\$\{)?[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)*(\})?/[^/]+`)
	awspGHSubRE     = regexp.MustCompile(`^token\.actions\.githubusercontent\.com(?:/[a-zA-Z0-9_-]+)?:sub$`)
	awspWildAcctRE  = regexp.MustCompile(`^arn:aws[a-z-]*:[a-z0-9-]*::\*`)

	awspCredActions = []string{"chime:CreateApiKey", "codepipeline:PollForJobs", "cognito-identity:GetOpenIdToken",
		"cognito-identity:GetOpenIdTokenForDeveloperIdentity", "cognito-identity:GetCredentialsForIdentity", "connect:GetFederationToken",
		"connect:GetFederationTokens", "ec2:GetPasswordData", "gamelift:RequestUploadCredentials", "iam:CreateAccessKey",
		"iam:CreateLoginProfile", "iam:CreateServiceSpecificCredential", "iam:ResetServiceSpecificCredential", "iam:UpdateAccessKey",
		"lightsail:GetInstanceAccessDetails", "lightsail:GetRelationalDatabaseMasterUserPassword", "rds-db:Connect",
		"redshift:GetClusterCredentials", "sso:GetRoleCredentials", "mediapackage:RotateChannelCredentials",
		"mediapackage:RotateIngestEndpointCredentials", "sts:AssumeRole", "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity",
		"sts:GetFederationToken", "sts:GetSessionToken"}
	awspExfilActions = []string{"s3:GetObject", "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath", "secretsmanager:GetSecretValue"}

	// Condition keys that tie a public principal to your organisation, network or source resource.
	awspScopingKeys = map[string]bool{"aws:sourcearn": true, "aws:sourceaccount": true, "aws:sourceowner": true, "aws:principalorgid": true,
		"aws:principalorgpaths": true, "aws:principalaccount": true, "aws:principalarn": true, "aws:sourcevpc": true, "aws:sourcevpce": true,
		"aws:sourceip": true, "aws:vpceaccount": true, "aws:userid": true, "aws:ec2instancesourcevpc": true, "ec2:sourceinstancearn": true,
		"lambda:sourcefunctionarn": true, "ssm:sourceinstancearn": true, "aws:resourceorgid": true}
)

// awspDoc decodes a policy or JSON document from a string, a jsonencode()
// value, or a heredoc whose interpolations become opaque placeholder strings.
func awspDoc(v any) any {
	s := ""
	switch t := v.(type) {
	case string:
		s = t
	case Unknown:
		s = strings.TrimSpace(t.Expr)
		if strings.HasPrefix(s, "<<") {
			lines := strings.Split(s, "\n")
			if len(lines) < 3 {
				return nil
			}
			s = strings.Join(lines[1:len(lines)-1], "\n")
		}
		s = awspRefRE.ReplaceAllString(s, awspRefMark)
	default:
		return v
	}
	var doc any
	if json.Unmarshal([]byte(s), &doc) != nil && json.Unmarshal([]byte(awspTrailingRE.ReplaceAllString(s, "$1")), &doc) != nil {
		return nil
	}
	return doc
}

// awspText is a document's raw text; false when it is only a reference.
func awspText(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case Unknown:
		return t.Expr, strings.Contains(t.Expr, "{")
	case map[string]any, []any:
		b, err := json.Marshal(t)
		return string(b), err == nil
	}
	return "", false
}

func awspStmts(v any) []map[string]any {
	doc, _ := awspDoc(v).(map[string]any)
	var out []map[string]any
	switch s := doc["Statement"].(type) {
	case map[string]any:
		out = append(out, s)
	case []any:
		for _, e := range s {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
	}
	return out
}

// awspPrincipals lists principal values of one kind ("AWS", "Federated"); a bare "*" counts for every kind.
func awspPrincipals(st map[string]any, kind string) []string {
	switch p := st["Principal"].(type) {
	case string, []any:
		return asStrings(p)
	case map[string]any:
		return asStrings(p[kind])
	}
	return nil
}

func awspAnyone(st map[string]any) bool {
	for _, p := range awspPrincipals(st, "AWS") {
		if p == "*" || awspWildAcctRE.MatchString(p) {
			return true
		}
	}
	return false
}

// awspPublic: an Allow statement any account can use, with no condition that scopes it.
func awspPublic(st map[string]any) bool {
	if e, _ := st["Effect"].(string); e != "Allow" || !awspAnyone(st) {
		return false
	}
	cond, _ := st["Condition"].(map[string]any)
	for op, kv := range cond {
		m, _ := kv.(map[string]any)
		for k, val := range m {
			if !awspScopingKeys[strings.ToLower(k)] {
				continue
			}
			if strings.HasPrefix(op, "Arn") && !strings.HasPrefix(op, "ArnNot") {
				open := false
				for _, s := range asStrings(val) {
					open = open || awspWildAcctRE.MatchString(s)
				}
				if open {
					continue
				}
			}
			return false
		}
	}
	return true
}

func awspActionHits(r *Resource, list []string, what string, skip ...string) []Hit {
	path := "policy"
	if r.Type == "aws_ssoadmin_permission_set_inline_policy" {
		path = "inline_policy"
	}
	for _, st := range awspStmts(r.get(path)) {
		// Only grants on every resource; scoped grants are deliberate.
		if e, _ := st["Effect"].(string); e != "Allow" || !contains(asStrings(st["Resource"]), "*") {
			continue
		}
		for _, a := range asStrings(st["Action"]) {
			if contains(skip, a) {
				continue
			}
			for _, want := range list {
				if ok, _ := awspMatch(a, want); ok {
					return []Hit{{Path: path, Msg: fmt.Sprintf("%s on all resources %s.", a, what)}}
				}
			}
		}
	}
	return nil
}

// awspMatch matches an IAM action pattern (with * and ?) case-insensitively.
func awspMatch(pattern, action string) (bool, error) {
	re, err := regexp.Compile("(?i)^" + strings.NewReplacer(`\*`, ".*", `\?`, ".").Replace(regexp.QuoteMeta(pattern)) + "$")
	if err != nil {
		return false, err
	}
	return re.MatchString(action), nil
}

func awspGitHubPrincipal(st map[string]any) bool {
	p, ok := st["Principal"].(map[string]any)
	if !ok {
		return false
	}
	for _, f := range asStrings(p["Federated"]) {
		if strings.Contains(f, "oidc-provider/token.actions.githubusercontent.com") {
			return true
		}
	}
	return false
}

// awspGitHubUnsafe is true when any allowed sub claim value is too broad: one is enough to let another workflow in.
func awspGitHubUnsafe(cond any) (bool, string) {
	c, _ := cond.(map[string]any)
	for _, kv := range c {
		m, _ := kv.(map[string]any)
		for k, vals := range m {
			if !awspGHSubRE.MatchString(k) {
				continue
			}
			for _, v := range asStrings(vals) {
				if strings.Contains(v, awspRefMark) {
					continue // decided by a variable at apply time
				}
				parts := strings.Split(v, ":")
				switch {
				case v == "*" || len(parts) == 1:
					return true, "sub is " + v
				case parts[1] == "*":
					return true, "sub " + v + " has a wildcard where the repository belongs"
				}
				for _, claim := range []string{"workflow", "environment", "ref", "context", "head_ref", "base_ref"} {
					if strings.HasPrefix(parts[0], claim) {
						return true, "sub " + v + " starts with the forgeable " + claim + " claim"
					}
				}
				if parts[0] == "repo" && !awspGHRepoRE.MatchString(parts[1]) {
					return true, "sub " + v + " does not name an owner/repository"
				}
			}
			return false, "" // every allowed sub names one repository
		}
	}
	return true, "no sub claim condition"
}

// awspSessionInputs returns the inputs of a Session Manager preferences document.
func awspSessionInputs(r *Resource) (map[string]any, bool) {
	if t, _ := asString(r.get("document_type")); t != "Session" {
		return nil, false
	}
	content := r.get("content")
	if f, _ := asString(r.get("document_format")); f == "YAML" {
		s, ok := asString(content)
		if !ok || yaml.Unmarshal([]byte(s), &content) != nil {
			return nil, false
		}
	} else {
		content = awspDoc(content)
	}
	in, ok := get(content, "inputs").(map[string]any)
	return in, ok && len(in) > 0
}

func awspEMREncryption(r *Resource) (map[string]any, bool) {
	doc, ok := awspDoc(r.get("configuration")).(map[string]any)
	if !ok {
		return nil, false
	}
	enc, _ := doc["EncryptionConfiguration"].(map[string]any)
	return enc, true
}

func awspDLM(r *Resource, cmk bool) []Hit {
	for _, a := range blocksAt(r.get("policy_details"), "action") {
		for _, c := range blocksAt(a, "cross_region_copy") {
			e := get(c, "encryption_configuration")
			if !is(get(e, "encryption"), true) || cmk && get(e, "cmk_arn") == nil {
				return []Hit{{Path: "policy_details", Msg: "Snapshots copied to another region by an event policy are not protected by your key."}}
			}
		}
	}
	for _, s := range blocksAt(r.get("policy_details"), "schedule") {
		for _, c := range blocksAt(s, "cross_region_copy_rule") {
			if !is(c["encrypted"], true) || cmk && c["cmk_arn"] == nil {
				return []Hit{{Path: "policy_details", Msg: "Snapshots copied to another region are not protected by your key."}}
			}
		}
	}
	return nil
}

func awspEBSetting(r *Resource, ns, name, msg string) []Hit {
	for _, s := range r.blocks("setting") {
		n, _ := asString(s["namespace"])
		k, _ := asString(s["name"])
		if n == ns && k == name && (is(s["value"], true) || s["value"] == "True" || isUnknown(s["value"])) {
			return nil
		}
	}
	return []Hit{{Path: "setting", Msg: msg}}
}

func awspRetention(r *Resource, min float64) []Hit {
	v := r.get("backup_retention_period")
	n, ok := asFloat(v)
	if v == nil {
		n, ok = 1, true // provider default
	}
	if ok && n < min {
		return []Hit{{Path: "backup_retention_period", Msg: fmt.Sprintf("Only %g day(s) of backups are kept; a problem found later cannot be rolled back.", n), Fix: fix(7, "Keep 7 days of backups", "backup_retention_period")}}
	}
	return nil
}

// awspAuroraMySQL: an absent engine on aws_rds_cluster defaults to aurora (MySQL).
func awspAuroraMySQL(engine string, mysql bool) bool {
	return engine == "" || engine == "aurora" || engine == "aurora-mysql" || mysql && engine == "mysql"
}

func awspAuroraEngine(r *Resource) bool {
	eng, _ := asString(r.get("engine"))
	return awspAuroraMySQL(eng, false) && !isUnknown(r.get("engine"))
}

func awspMajorMinor(v string) (int, int, bool) {
	p := strings.Split(v, ".")
	if len(p) < 2 {
		return 0, 0, false
	}
	a, err1 := strconv.Atoi(p[0])
	b, err2 := strconv.Atoi(p[1])
	return a, b, err1 == nil && err2 == nil
}

// awspTruthy follows JSON truthiness: true, non-zero numbers and non-empty strings other than "false".
func awspTruthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t != "" && !strings.EqualFold(t, "false")
	case float64:
		return t != 0
	case nil:
		return false
	case Unknown:
		return true
	}
	return true
}

func awspLen(v any) int {
	switch t := v.(type) {
	case []any:
		return len(t)
	case map[string]any:
		return 1
	}
	return 0
}

func awspNonEmpty(v any) bool {
	switch t := v.(type) {
	case []any:
		for _, x := range t {
			if m, ok := x.(map[string]any); !ok || len(m) > 0 {
				return true
			}
		}
		return false
	case map[string]any:
		return len(t) > 0
	}
	return v != nil
}

// awspRefMark stands in for a ${...} reference in a policy string, so checks can tell it from a literal.
const awspRefMark = "__tg_ref__"
