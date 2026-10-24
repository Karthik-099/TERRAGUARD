package engine

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
)

// Rule is a resource-level check. Rules see normalized Resources, so the same
// rule fires on raw .tf source and on `terraform show -json` plan output.
type Rule struct {
	ID          string                  `json:"id"`
	Title       string                  `json:"title"`
	Severity    Severity                `json:"severity"`
	Category    string                  `json:"category"`
	CWE         string                  `json:"cwe,omitempty"`
	Remediation string                  `json:"remediation"`
	Types       []string                `json:"resource_types,omitempty"`
	Blocking    bool                    `json:"blocking,omitempty"`
	Themes      []string                `json:"compliance_themes,omitempty"`
	Check       func(r *Resource) []Hit `json:"-"`
}

type Hit struct {
	Path string // line lookup key
	Msg  string
	Sev  Severity // overrides rule severity when set
	Fix  *Fix     // Path/Value/Description; File/Block are filled in by the engine
}

func fix(value any, desc string, path ...string) *Fix {
	return &Fix{Path: path, Value: value, Description: desc}
}

func is(v any, want bool) bool { b, ok := asBool(v); return ok && b == want }

// notTrue is true when an attribute is explicitly false or absent (not unknown).
func notTrue(v any) bool { return !isUnknown(v) && !is(v, true) }

var sensitivePorts = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 445: "SMB", 1433: "MSSQL", 1521: "Oracle", 2379: "etcd",
	3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5601: "Kibana", 5900: "VNC", 6379: "Redis",
	6443: "Kubernetes API", 9092: "Kafka", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}

func worldCIDR(s string) bool { return s == "0.0.0.0/0" || s == "::/0" }

func anyWorld(vs ...any) bool {
	for _, v := range vs {
		for _, s := range asStrings(v) {
			if worldCIDR(s) || s == "*" || s == "Internet" {
				return true
			}
		}
	}
	return false
}

// exposure grades an internet-open port range; ok=false means nothing sensitive.
func exposure(protocol, from, to any) (Severity, string, bool) {
	p, _ := asString(protocol)
	f, fok := asFloat(from)
	t, tok := asFloat(to)
	if p == "-1" || p == "all" || (fok && tok && f <= 0 && t >= 65535) {
		return Critical, "all ports", true
	}
	if !fok || !tok {
		return "", "", false
	}
	var hit []int
	for port := range sensitivePorts {
		if float64(port) >= f && float64(port) <= t {
			hit = append(hit, port)
		}
	}
	if len(hit) == 0 {
		return "", "", false
	}
	sort.Ints(hit)
	var names []string
	for _, port := range hit {
		names = append(names, fmt.Sprintf("%d/%s", port, sensitivePorts[port]))
	}
	return High, strings.Join(names, ", "), true
}

// ── IAM policy helpers ──────────────────────────────────────────────────────

type stmt struct {
	Effect     string
	Actions    []string
	Resources  []string
	Principals []string
	HasCond    bool
}

// statements normalizes a JSON policy string, a decoded jsonencode() object, or
// an aws_iam_policy_document data source into flat statements.
func statements(v any) []stmt {
	if s, ok := v.(string); ok {
		var doc any
		if json.Unmarshal([]byte(s), &doc) != nil {
			return nil
		}
		v = doc
	}
	doc, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	raw := doc["Statement"]
	list, ok := raw.([]any)
	if !ok {
		list = []any{raw}
	}
	var out []stmt
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		st := stmt{Effect: "Allow", Actions: asStrings(m["Action"]), Resources: asStrings(m["Resource"]), HasCond: m["Condition"] != nil}
		if eff, ok := m["Effect"].(string); ok {
			st.Effect = eff
		}
		switch p := m["Principal"].(type) {
		case string:
			st.Principals = []string{p}
		case map[string]any:
			for _, pv := range p {
				st.Principals = append(st.Principals, asStrings(pv)...)
			}
		}
		out = append(out, st)
	}
	return out
}

func policyDocStatements(r *Resource) []stmt {
	var out []stmt
	for _, s := range r.blocks("statement") {
		st := stmt{Effect: "Allow", Actions: asStrings(s["actions"]), Resources: asStrings(s["resources"]), HasCond: s["condition"] != nil}
		if eff, ok := s["effect"].(string); ok {
			st.Effect = eff
		}
		if ps, ok := s["principals"].([]any); ok {
			for _, p := range ps {
				if pm, ok := p.(map[string]any); ok {
					st.Principals = append(st.Principals, asStrings(pm["identifiers"])...)
				}
			}
		}
		out = append(out, st)
	}
	return out
}

func contains(list []string, vals ...string) bool {
	for _, s := range list {
		for _, v := range vals {
			if s == v {
				return true
			}
		}
	}
	return false
}

// wildcardHits reports Allow statements granting "*" or service-wide actions.
func wildcardHits(sts []stmt, path string) []Hit {
	var hits []Hit
	for _, st := range sts {
		if st.Effect != "Allow" {
			continue
		}
		allRes := contains(st.Resources, "*")
		switch {
		case contains(st.Actions, "*", "*:*") && allRes:
			hits = append(hits, Hit{Path: path, Sev: Critical, Msg: `Policy allows Action "*" on Resource "*" — this is full administrator access.`})
		case contains(st.Actions, "*", "*:*"):
			hits = append(hits, Hit{Path: path, Sev: High, Msg: `Policy allows every action ("*") on the listed resources.`})
		case contains(st.Actions, "iam:*", "sts:*", "kms:*", "organizations:*") && allRes:
			hits = append(hits, Hit{Path: path, Sev: High, Msg: fmt.Sprintf("Policy grants %v on all resources, which allows privilege escalation.", st.Actions)})
		}
	}
	return hits
}

func IsAdminPolicy(r *Resource) bool {
	var sts []stmt
	if r.Type == "aws_iam_policy_document" {
		sts = policyDocStatements(r)
	} else {
		sts = statements(r.get("policy"))
	}
	for _, h := range wildcardHits(sts, "") {
		if h.Sev == Critical {
			return true
		}
	}
	return false
}

var bucketNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

// coreRules covers AWS, GCP, Azure, Cloudflare and Terraform semantics; see rules_clouds.go for the rest.
var coreRules = []Rule{
	// ── AWS S3 ──
	{ID: "TG-AWS-S3-001", Title: "S3 bucket ACL grants public access", Severity: High, Category: CatSecurity, CWE: "CWE-732",
		Types: []string{"aws_s3_bucket", "aws_s3_bucket_acl"}, Remediation: `Set acl = "private" and serve public content through CloudFront with Origin Access Control.`,
		Check: func(r *Resource) []Hit {
			acl, _ := asString(r.get("acl"))
			switch acl {
			case "public-read-write":
				return []Hit{{Path: "acl", Sev: Critical, Msg: "Anyone on the internet can read AND write objects in this bucket.", Fix: fix("private", `Set acl = "private"`, "acl")}}
			case "public-read", "authenticated-read":
				return []Hit{{Path: "acl", Msg: fmt.Sprintf("Bucket ACL %q exposes every object to the internet.", acl), Fix: fix("private", `Set acl = "private"`, "acl")}}
			}
			return nil
		}},
	{ID: "TG-AWS-S3-002", Title: "S3 Block Public Access is disabled", Severity: High, Category: CatSecurity, CWE: "CWE-732",
		Types: []string{"aws_s3_bucket_public_access_block", "aws_s3_account_public_access_block"}, Remediation: "Enable all four Block Public Access settings.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			for _, k := range []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"} {
				if notTrue(r.get(k)) {
					hits = append(hits, Hit{Path: k, Msg: k + " is not enabled, so public ACLs/policies can take effect.", Fix: fix(true, "Set "+k+" = true", k)})
				}
			}
			return hits
		}},
	{ID: "TG-VAL-005", Title: "Invalid S3 bucket name (apply will fail)", Severity: High, Category: CatValidate, Blocking: true,
		Types: []string{"aws_s3_bucket"}, Remediation: "Bucket names must be 3–63 chars of lowercase letters, digits, dots and hyphens, starting and ending with a letter or digit.",
		Check: func(r *Resource) []Hit {
			name, ok := asString(r.get("bucket"))
			if !ok || name == "" {
				return nil
			}
			if !bucketNameRE.MatchString(name) || strings.Contains(name, "..") || net.ParseIP(name) != nil {
				return []Hit{{Path: "bucket", Msg: fmt.Sprintf("%q is not a valid S3 bucket name; AWS rejects it during apply (plan succeeds, apply fails).", name)}}
			}
			return nil
		}},
	{ID: "TG-TF-010", Title: "Deprecated inline S3 bucket arguments", Severity: Low, Category: CatBestPrac,
		Types: []string{"aws_s3_bucket"}, Remediation: "Since AWS provider v4 use the standalone aws_s3_bucket_* resources (aws_s3_bucket_acl, aws_s3_bucket_versioning, ...).",
		Check: func(r *Resource) []Hit {
			if r.FromPlan {
				return nil
			}
			var hits []Hit
			for _, k := range []string{"acl", "versioning", "server_side_encryption_configuration", "logging", "lifecycle_rule", "website", "cors_rule", "policy"} {
				if _, ok := r.Attrs[k]; ok {
					res := "aws_s3_bucket_" + strings.TrimSuffix(k, "_rule")
					if k == "server_side_encryption_configuration" {
						res = "aws_s3_bucket_server_side_encryption_configuration"
					} else if k == "lifecycle_rule" {
						res = "aws_s3_bucket_lifecycle_configuration"
					} else if k == "website" {
						res = "aws_s3_bucket_website_configuration"
					} else if k == "cors_rule" {
						res = "aws_s3_bucket_cors_configuration"
					}
					hits = append(hits, Hit{Path: k, Msg: fmt.Sprintf("Inline %q is deprecated; move it to %s to avoid perpetual diffs.", k, res)})
				}
			}
			return hits
		}},

	// ── Network ──
	{ID: "TG-AWS-SG-001", Title: "Security group open to the internet", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types:       []string{"aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule"},
		Remediation: "Restrict ingress to known CIDRs, a bastion/VPN security group, or use SSM Session Manager instead of public SSH/RDP.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			add := func(path string, proto, from, to any) {
				if sev, what, ok := exposure(proto, from, to); ok {
					hits = append(hits, Hit{Path: path, Sev: sev, Msg: "Ingress from 0.0.0.0/0 exposes " + what + " to the whole internet."})
				}
			}
			switch r.Type {
			case "aws_security_group":
				for i, in := range r.blocks("ingress") {
					if anyWorld(in["cidr_blocks"], in["ipv6_cidr_blocks"]) {
						add(fmt.Sprintf("ingress.%d", i), in["protocol"], in["from_port"], in["to_port"])
					}
				}
			case "aws_security_group_rule":
				if t, _ := asString(r.get("type")); t == "ingress" && anyWorld(r.get("cidr_blocks"), r.get("ipv6_cidr_blocks")) {
					add("cidr_blocks", r.get("protocol"), r.get("from_port"), r.get("to_port"))
				}
			case "aws_vpc_security_group_ingress_rule":
				if anyWorld(r.get("cidr_ipv4"), r.get("cidr_ipv6")) {
					add("cidr_ipv4", r.get("ip_protocol"), r.get("from_port"), r.get("to_port"))
				}
			}
			return hits
		}},
	{ID: "TG-VAL-006", Title: "Port range is inverted (apply will fail)", Severity: High, Category: CatValidate, Blocking: true,
		Types: []string{"aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule"}, Remediation: "from_port must be <= to_port.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			check := func(path string, m map[string]any) {
				f, ok1 := asFloat(m["from_port"])
				t, ok2 := asFloat(m["to_port"])
				if ok1 && ok2 && f > t {
					hits = append(hits, Hit{Path: path, Msg: fmt.Sprintf("from_port %v is greater than to_port %v.", f, t)})
				}
			}
			check("from_port", r.Attrs)
			for _, b := range []string{"ingress", "egress"} {
				for i, m := range r.blocks(b) {
					check(fmt.Sprintf("%s.%d", b, i), m)
				}
			}
			return hits
		}},
	{ID: "TG-VAL-004", Title: "Invalid CIDR block (apply will fail)", Severity: High, Category: CatValidate, Blocking: true,
		Remediation: "Use a valid network address, e.g. 10.0.0.0/16 (host bits must be zero).",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			var walk func(prefix string, v any)
			walk = func(prefix string, v any) {
				switch t := v.(type) {
				case map[string]any:
					for k, e := range t {
						p := k
						if prefix != "" {
							p = prefix + "." + k
						}
						if strings.Contains(k, "cidr") || k == "source_ranges" || k == "address_prefixes" || k == "address_prefix" {
							for _, s := range asStrings(e) {
								if s == "" || strings.Contains(s, "${") {
									continue
								}
								ip, n, err := net.ParseCIDR(s)
								if err != nil {
									hits = append(hits, Hit{Path: p, Msg: fmt.Sprintf("%q is not a valid CIDR.", s)})
								} else if !ip.Equal(n.IP) {
									hits = append(hits, Hit{Path: p, Msg: fmt.Sprintf("%q has host bits set; the canonical form is %s.", s, n.String())})
								}
							}
						}
						walk(p, e)
					}
				case []any:
					for i, e := range t {
						if _, ok := e.(map[string]any); ok {
							walk(fmt.Sprintf("%s.%d", prefix, i), e)
						}
					}
				}
			}
			walk("", r.Attrs)
			return hits
		}},
	{ID: "TG-AWS-LB-001", Title: "Load balancer listener without modern TLS", Severity: Medium, Category: CatSecurity, CWE: "CWE-319",
		Types: []string{"aws_lb_listener", "aws_alb_listener"}, Remediation: `Use protocol = "HTTPS" with ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06", and redirect HTTP to HTTPS.`,
		Check: func(r *Resource) []Hit {
			proto, _ := asString(r.get("protocol"))
			if proto == "HTTP" {
				if t, _ := asString(r.get("default_action.type")); t != "redirect" {
					return []Hit{{Path: "protocol", Msg: "Listener serves plain HTTP without redirecting to HTTPS."}}
				}
			}
			if p, ok := asString(r.get("ssl_policy")); ok && (p == "ELBSecurityPolicy-2016-08" || strings.Contains(p, "TLS-1-0") || strings.Contains(p, "TLS-1-1") || p == "ELBSecurityPolicy-2015-05") {
				return []Hit{{Path: "ssl_policy", Msg: fmt.Sprintf("ssl_policy %q still allows TLS 1.0/1.1.", p), Fix: fix("ELBSecurityPolicy-TLS13-1-2-2021-06", "Use a TLS 1.2+/1.3 policy", "ssl_policy")}}
			}
			return nil
		}},

	// ── Databases & storage ──
	{ID: "TG-AWS-RDS-001", Title: "Database is publicly accessible", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"aws_db_instance", "aws_rds_cluster_instance"}, Remediation: "Set publicly_accessible = false and place the database in private subnets.",
		Check: func(r *Resource) []Hit {
			if is(r.get("publicly_accessible"), true) {
				return []Hit{{Path: "publicly_accessible", Msg: "The database gets a public IP and DNS name.", Fix: fix(false, "Set publicly_accessible = false", "publicly_accessible")}}
			}
			return nil
		}},
	{ID: "TG-AWS-RDS-002", Title: "Database storage is not encrypted", Severity: High, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_db_instance", "aws_rds_cluster"}, Remediation: "Set storage_encrypted = true (optionally with kms_key_id). Note: this forces replacement of an existing database.",
		Check: func(r *Resource) []Hit {
			if notTrue(r.get("storage_encrypted")) {
				return []Hit{{Path: "storage_encrypted", Msg: "Data, snapshots and replicas are stored unencrypted at rest.", Fix: fix(true, "Set storage_encrypted = true (forces replacement on existing DBs)", "storage_encrypted")}}
			}
			return nil
		}},
	{ID: "TG-AWS-RDS-003", Title: "Database has no deletion protection or backups", Severity: Low, Category: CatReliability,
		Types: []string{"aws_db_instance", "aws_rds_cluster"}, Remediation: "Enable deletion_protection and keep backup_retention_period >= 7.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			if notTrue(r.get("deletion_protection")) {
				hits = append(hits, Hit{Path: "deletion_protection", Msg: "A single `terraform destroy` or replace can delete this database.", Fix: fix(true, "Set deletion_protection = true", "deletion_protection")})
			}
			if n, ok := asFloat(r.get("backup_retention_period")); ok && n == 0 {
				hits = append(hits, Hit{Path: "backup_retention_period", Sev: Medium, Msg: "Automated backups are disabled (backup_retention_period = 0).", Fix: fix(7, "Keep 7 days of backups", "backup_retention_period")})
			}
			return hits
		}},
	{ID: "TG-AWS-EBS-001", Title: "EBS volume is not encrypted", Severity: Medium, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_ebs_volume", "aws_instance", "aws_launch_template"}, Remediation: "Set encrypted = true, or enable EBS encryption by default for the account.",
		Check: func(r *Resource) []Hit {
			if r.Type == "aws_ebs_volume" {
				if notTrue(r.get("encrypted")) {
					return []Hit{{Path: "encrypted", Msg: "Volume data and snapshots are unencrypted.", Fix: fix(true, "Set encrypted = true", "encrypted")}}
				}
				return nil
			}
			var hits []Hit
			for _, b := range []string{"root_block_device", "ebs_block_device"} {
				for i, d := range r.blocks(b) {
					if is(d["encrypted"], false) {
						h := Hit{Path: fmt.Sprintf("%s.%d.encrypted", b, i), Msg: b + " explicitly disables encryption."}
						if b == "root_block_device" {
							h.Fix = fix(true, "Set root_block_device.encrypted = true", b, "encrypted")
						}
						hits = append(hits, h)
					}
				}
			}
			return hits
		}},
	{ID: "TG-AWS-DDB-001", Title: "DynamoDB table without point-in-time recovery", Severity: Low, Category: CatReliability,
		Types: []string{"aws_dynamodb_table"}, Remediation: "Add point_in_time_recovery { enabled = true }.",
		Check: func(r *Resource) []Hit {
			if notTrue(r.get("point_in_time_recovery.enabled")) {
				return []Hit{{Path: "point_in_time_recovery", Msg: "Accidental writes or deletes cannot be rolled back.", Fix: fix(true, "Enable point-in-time recovery", "point_in_time_recovery", "enabled")}}
			}
			return nil
		}},

	// ── Compute ──
	{ID: "TG-AWS-EC2-001", Title: "Instance metadata service allows IMDSv1", Severity: Medium, Category: CatSecurity, CWE: "CWE-918",
		Types: []string{"aws_instance", "aws_launch_template"}, Remediation: `Add metadata_options { http_tokens = "required" } to block SSRF credential theft.`,
		Check: func(r *Resource) []Hit {
			v := r.get("metadata_options.http_tokens")
			if s, _ := asString(v); s != "required" && !isUnknown(v) {
				return []Hit{{Path: "metadata_options", Msg: "IMDSv1 lets any SSRF bug steal the instance role credentials (Capital One 2019).", Fix: fix("required", `Set metadata_options.http_tokens = "required"`, "metadata_options", "http_tokens")}}
			}
			return nil
		}},
	{ID: "TG-AWS-LAMBDA-001", Title: "Lambda function URL has no authentication", Severity: High, Category: CatSecurity, CWE: "CWE-306",
		Types: []string{"aws_lambda_function_url"}, Remediation: `Use authorization_type = "AWS_IAM" or put the function behind API Gateway with an authorizer.`,
		Check: func(r *Resource) []Hit {
			if s, _ := asString(r.get("authorization_type")); s == "NONE" {
				return []Hit{{Path: "authorization_type", Msg: "Anyone with the URL can invoke this function."}}
			}
			return nil
		}},
	{ID: "TG-AWS-EKS-001", Title: "EKS API endpoint is public to the internet", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"aws_eks_cluster"}, Remediation: "Set vpc_config.endpoint_public_access = false or restrict public_access_cidrs.",
		Check: func(r *Resource) []Hit {
			pub := r.get("vpc_config.endpoint_public_access")
			cidrs := r.get("vpc_config.public_access_cidrs")
			if (pub == nil || is(pub, true)) && !isUnknown(cidrs) && (cidrs == nil || anyWorld(cidrs)) {
				return []Hit{{Path: "vpc_config", Msg: "The Kubernetes API server is reachable from any IP (public access defaults to true)."}}
			}
			return nil
		}},

	// ── IAM ──
	{ID: "TG-AWS-IAM-001", Title: "IAM policy grants wildcard permissions", Severity: High, Category: CatSecurity, CWE: "CWE-269",
		Types:       []string{"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy", "aws_iam_policy_document"},
		Remediation: "Apply least privilege: list the exact actions and resource ARNs. Use IAM Access Analyzer policy generation from CloudTrail.",
		Check: func(r *Resource) []Hit {
			if r.Type == "aws_iam_policy_document" {
				return wildcardHits(policyDocStatements(r), "statement")
			}
			return wildcardHits(statements(r.get("policy")), "policy")
		}},
	{ID: "TG-AWS-IAM-002", Title: "Policy allows any principal", Severity: Critical, Category: CatSecurity, CWE: "CWE-284",
		Types:       []string{"aws_iam_role", "aws_s3_bucket_policy", "aws_sqs_queue_policy", "aws_sns_topic_policy", "aws_kms_key", "aws_iam_policy_document"},
		Remediation: "Name specific account/role ARNs as principals, or add a Condition (aws:PrincipalOrgID, aws:SourceArn).",
		Check: func(r *Resource) []Hit {
			var sts []stmt
			path := "policy"
			switch r.Type {
			case "aws_iam_role":
				path = "assume_role_policy"
				sts = statements(r.get(path))
			case "aws_iam_policy_document":
				path = "statement"
				sts = policyDocStatements(r)
			default:
				sts = statements(r.get("policy"))
			}
			for _, st := range sts {
				if st.Effect == "Allow" && contains(st.Principals, "*") && !st.HasCond {
					return []Hit{{Path: path, Msg: `Principal "*" without a Condition lets any AWS account (or anonymous users) use this.`}}
				}
			}
			return nil
		}},
	{ID: "TG-AWS-IAM-003", Title: "AdministratorAccess attached directly", Severity: High, Category: CatSecurity, CWE: "CWE-269",
		Types:       []string{"aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment", "aws_iam_group_policy_attachment", "aws_iam_policy_attachment"},
		Remediation: "Attach a scoped customer-managed policy instead; reserve admin for break-glass roles with MFA.",
		Check: func(r *Resource) []Hit {
			if s, _ := asString(r.get("policy_arn")); strings.HasSuffix(s, "/AdministratorAccess") {
				return []Hit{{Path: "policy_arn", Msg: "The AWS-managed AdministratorAccess policy grants full account control."}}
			}
			return nil
		}},
	{ID: "TG-AWS-KMS-001", Title: "KMS key rotation disabled", Severity: Medium, Category: CatSecurity, CWE: "CWE-320",
		Types: []string{"aws_kms_key"}, Remediation: "Set enable_key_rotation = true.",
		Check: func(r *Resource) []Hit {
			if spec, _ := asString(r.get("customer_master_key_spec")); spec != "" && spec != "SYMMETRIC_DEFAULT" {
				return nil // rotation only applies to symmetric keys
			}
			if notTrue(r.get("enable_key_rotation")) {
				return []Hit{{Path: "enable_key_rotation", Msg: "Key material is never rotated.", Fix: fix(true, "Set enable_key_rotation = true", "enable_key_rotation")}}
			}
			return nil
		}},
	{ID: "TG-AWS-CT-001", Title: "CloudTrail is not hardened", Severity: Medium, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"aws_cloudtrail"}, Remediation: "Enable log file validation and multi-region trails so attackers cannot hide activity.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			if notTrue(r.get("enable_log_file_validation")) {
				hits = append(hits, Hit{Path: "enable_log_file_validation", Msg: "Log files can be tampered with undetected.", Fix: fix(true, "Set enable_log_file_validation = true", "enable_log_file_validation")})
			}
			if notTrue(r.get("is_multi_region_trail")) {
				hits = append(hits, Hit{Path: "is_multi_region_trail", Sev: Low, Msg: "Activity in other regions is not recorded.", Fix: fix(true, "Set is_multi_region_trail = true", "is_multi_region_trail")})
			}
			return hits
		}},

	// ── Google Cloud ──
	{ID: "TG-GCP-GCS-001", Title: "GCS bucket is public or lacks uniform access", Severity: Medium, Category: CatSecurity, CWE: "CWE-732",
		Types: []string{"google_storage_bucket", "google_storage_bucket_iam_member", "google_storage_bucket_iam_binding"}, Remediation: "Enable uniform_bucket_level_access and never grant allUsers/allAuthenticatedUsers.",
		Check: func(r *Resource) []Hit {
			if r.Type == "google_storage_bucket" {
				if notTrue(r.get("uniform_bucket_level_access")) {
					return []Hit{{Path: "uniform_bucket_level_access", Msg: "Per-object ACLs can silently make objects public.", Fix: fix(true, "Set uniform_bucket_level_access = true", "uniform_bucket_level_access")}}
				}
				return nil
			}
			members := append(asStrings(r.get("member")), asStrings(r.get("members"))...)
			if contains(members, "allUsers", "allAuthenticatedUsers") {
				return []Hit{{Path: "member", Sev: High, Msg: "Bucket is granted to allUsers/allAuthenticatedUsers (public)."}}
			}
			return nil
		}},
	{ID: "TG-GCP-FW-001", Title: "GCP firewall open to the internet", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"google_compute_firewall"}, Remediation: "Restrict source_ranges; use IAP TCP forwarding (35.235.240.0/20) for SSH/RDP.",
		Check: func(r *Resource) []Hit {
			if d, _ := asString(r.get("direction")); d == "EGRESS" || !anyWorld(r.get("source_ranges")) {
				return nil
			}
			var hits []Hit
			for i, a := range r.blocks("allow") {
				proto, _ := asString(a["protocol"])
				ports := asStrings(a["ports"])
				if proto == "all" || len(ports) == 0 {
					hits = append(hits, Hit{Path: fmt.Sprintf("allow.%d", i), Sev: Critical, Msg: "All ports are open to 0.0.0.0/0."})
					continue
				}
				for _, p := range ports {
					lo, hi, _ := strings.Cut(p, "-")
					if hi == "" {
						hi = lo
					}
					if sev, what, ok := exposure(proto, lo, hi); ok {
						hits = append(hits, Hit{Path: fmt.Sprintf("allow.%d", i), Sev: sev, Msg: "Firewall exposes " + what + " to 0.0.0.0/0."})
					}
				}
			}
			return hits
		}},

	// ── Azure ──
	{ID: "TG-AZ-ST-001", Title: "Azure storage account is weakly configured", Severity: Medium, Category: CatSecurity, CWE: "CWE-319",
		Types: []string{"azurerm_storage_account"}, Remediation: `Set min_tls_version = "TLS1_2", https_traffic_only_enabled = true, allow_nested_items_to_be_public = false.`,
		Check: func(r *Resource) []Hit {
			var hits []Hit
			if v, ok := asString(r.get("min_tls_version")); ok && v != "TLS1_2" && v != "TLS1_3" {
				hits = append(hits, Hit{Path: "min_tls_version", Msg: "TLS " + v + " is allowed.", Fix: fix("TLS1_2", "Require TLS 1.2", "min_tls_version")})
			}
			if is(r.get("https_traffic_only_enabled"), false) || is(r.get("enable_https_traffic_only"), false) {
				hits = append(hits, Hit{Path: "https_traffic_only_enabled", Msg: "Plain HTTP access is allowed."})
			}
			if is(r.get("allow_nested_items_to_be_public"), true) {
				hits = append(hits, Hit{Path: "allow_nested_items_to_be_public", Sev: High, Msg: "Containers can be made public.", Fix: fix(false, "Disallow public containers", "allow_nested_items_to_be_public")})
			}
			return hits
		}},
	{ID: "TG-AZ-NSG-001", Title: "Azure NSG rule open to the internet", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"azurerm_network_security_rule"}, Remediation: "Restrict source_address_prefix; use Azure Bastion for SSH/RDP.",
		Check: func(r *Resource) []Hit {
			dir, _ := asString(r.get("direction"))
			acc, _ := asString(r.get("access"))
			if dir != "Inbound" || acc != "Allow" || !anyWorld(r.get("source_address_prefix"), r.get("source_address_prefixes")) {
				return nil
			}
			for _, p := range append(asStrings(r.get("destination_port_range")), asStrings(r.get("destination_port_ranges"))...) {
				if p == "*" {
					return []Hit{{Path: "destination_port_range", Sev: Critical, Msg: "All ports are open to the internet."}}
				}
				lo, hi, _ := strings.Cut(p, "-")
				if hi == "" {
					hi = lo
				}
				if sev, what, ok := exposure("tcp", lo, hi); ok {
					return []Hit{{Path: "destination_port_range", Sev: sev, Msg: "Rule exposes " + what + " to the internet."}}
				}
			}
			return nil
		}},

	// ── Cloudflare ──
	{ID: "TG-CF-001", Title: "Cloudflare zone has weak TLS/security settings", Severity: High, Category: CatSecurity, CWE: "CWE-319",
		Types: []string{"cloudflare_zone_settings_override", "cloudflare_zone_setting"}, Remediation: `Use ssl = "strict" (Full strict), min_tls_version = "1.2" and always_use_https = "on".`,
		Check: func(r *Resource) []Hit {
			settings := map[string]any{}
			prefix := "settings.0."
			if r.Type == "cloudflare_zone_setting" { // provider v5: one resource per setting
				id, _ := asString(r.get("setting_id"))
				settings[id] = r.get("value")
				prefix = ""
			} else if s, ok := get(r.Attrs, "settings").([]any); ok && len(s) > 0 {
				settings, _ = s[0].(map[string]any)
			}
			var hits []Hit
			path := func(k string) string {
				if prefix == "" {
					return "value"
				}
				return prefix + k
			}
			if v, _ := asString(settings["ssl"]); v == "off" || v == "flexible" {
				hits = append(hits, Hit{Path: path("ssl"), Msg: fmt.Sprintf("ssl = %q: traffic from Cloudflare to your origin is unencrypted or unauthenticated.", v)})
			}
			if v, _ := asString(settings["min_tls_version"]); v == "1.0" || v == "1.1" {
				hits = append(hits, Hit{Path: path("min_tls_version"), Sev: Medium, Msg: "Clients may connect with TLS " + v + "."})
			}
			if v, _ := asString(settings["always_use_https"]); v == "off" {
				hits = append(hits, Hit{Path: path("always_use_https"), Sev: Low, Msg: "HTTP requests are not redirected to HTTPS."})
			}
			if v, _ := asString(settings["security_level"]); v == "essentially_off" || v == "off" {
				hits = append(hits, Hit{Path: path("security_level"), Sev: Medium, Msg: "security_level = " + v + " disables Cloudflare's threat-score challenges."})
			}
			return hits
		}},
	{ID: "TG-CF-002", Title: "DNS record bypasses the Cloudflare proxy", Severity: Info, Category: CatSecurity, CWE: "CWE-200",
		Types: []string{"cloudflare_record", "cloudflare_dns_record"}, Remediation: "Set proxied = true so the origin IP stays hidden behind Cloudflare's DDoS/WAF protection.",
		Check: func(r *Resource) []Hit {
			t, _ := asString(r.get("type"))
			if (t == "A" || t == "AAAA" || t == "CNAME") && notTrue(r.get("proxied")) {
				return []Hit{{Path: "proxied", Msg: "The record is DNS-only, exposing the origin IP to direct attacks.", Fix: fix(true, "Set proxied = true", "proxied")}}
			}
			return nil
		}},

	// ── Terraform semantics ──
	{ID: "TG-VAL-007", Title: "count and for_each used together (validate will fail)", Severity: High, Category: CatValidate, Blocking: true,
		Remediation: "Use either count or for_each on a resource, never both.",
		Check: func(r *Resource) []Hit {
			if r.FromPlan {
				return nil
			}
			_, c := r.Attrs["count"]
			_, f := r.Attrs["for_each"]
			if c && f {
				return []Hit{{Path: "for_each", Msg: `"count" and "for_each" are mutually exclusive.`}}
			}
			return nil
		}},
}

func (r *Rule) applies(t string) bool {
	if len(r.Types) == 0 {
		return true
	}
	for _, x := range r.Types {
		if x == t {
			return true
		}
	}
	return false
}
