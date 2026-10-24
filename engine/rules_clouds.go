package engine

import (
	"fmt"
	"strconv"
	"strings"
)

// Rules is the full resource-rule catalog.
var Rules = concatRules(coreRules, moreAWSRules, gcpAzureRules, otherCloudRules, kubernetesRules, dnsCDNRules, costRules)

func concatRules(sets ...[]Rule) []Rule {
	var out []Rule
	for _, s := range sets {
		out = append(out, s...)
	}
	return out
}

// portRange parses provider port syntaxes: 22, "22", "80-85", "8000:9000", "22/22", "any", "all", "".
func portRange(v any) (lo, hi float64, ok bool) {
	if f, isNum := v.(float64); isNum {
		return f, f, true
	}
	s, isStr := v.(string)
	if !isStr {
		return 0, 0, false
	}
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || s == "any" || s == "all" || s == "*" || s == "-1/-1" {
		return 0, 65535, true
	}
	for _, sep := range []string{"-", ":", "/"} {
		if a, b, found := strings.Cut(s, sep); found {
			fa, e1 := strconv.ParseFloat(a, 64)
			fb, e2 := strconv.ParseFloat(b, 64)
			return fa, fb, e1 == nil && e2 == nil
		}
	}
	f, err := strconv.ParseFloat(s, 64)
	return f, f, err == nil
}

// openPorts reports an internet-open port range; protocol "all"/"-1" means every port.
func openPorts(path, where string, protocol any, lo, hi float64) []Hit {
	if p, _ := asString(protocol); p == "icmp" || p == "1" {
		return nil
	} else if p == "all" || p == "-1" {
		lo, hi = 0, 65535
	}
	if sev, what, ok := exposure("tcp", lo, hi); ok {
		return []Hit{{Path: path, Sev: sev, Msg: where + " exposes " + what + " to the whole internet."}}
	}
	return nil
}

// walkMaps visits every nested object with its Lines-compatible path ("spec.0.container.0").
func walkMaps(v any, path string, fn func(path string, m map[string]any)) {
	switch t := v.(type) {
	case map[string]any:
		fn(path, t)
		for k, e := range t {
			p := k
			if path != "" {
				p = path + "." + k
			}
			walkMaps(e, p, fn)
		}
	case []any:
		for i, e := range t {
			walkMaps(e, fmt.Sprintf("%s.%d", path, i), fn)
		}
	}
}

func join(path, k string) string {
	if path == "" {
		return k
	}
	return path + "." + k
}

var (
	blockedRuntimes = map[string]bool{"python2.7": true, "python3.6": true, "python3.7": true, "nodejs": true, "nodejs4.3": true, "nodejs6.10": true,
		"nodejs8.10": true, "nodejs10.x": true, "nodejs12.x": true, "nodejs14.x": true, "nodejs16.x": true, "dotnetcore1.0": true, "dotnetcore2.0": true,
		"dotnetcore2.1": true, "dotnetcore3.1": true, "ruby2.5": true, "ruby2.7": true, "go1.x": true, "java8": true}
	deprecatedRuntimes = map[string]bool{"python3.8": true, "python3.9": true, "nodejs18.x": true, "dotnet6": true, "dotnet7": true, "ruby3.2": true, "provided": true}
	previousGen        = []string{"t1.", "t2.", "m1.", "m2.", "m3.", "m4.", "c1.", "c3.", "c4.", "r3.", "r4.", "i2.", "i3.", "x1.", "db.t2.", "db.m4.", "db.r4.", "db.m3.", "db.r3."}
)

var moreAWSRules = []Rule{
	{ID: "TG-AWS-LAMBDA-002", Title: "Lambda runtime is deprecated", Severity: High, Category: CatValidate, CWE: "CWE-1104",
		Types: []string{"aws_lambda_function"}, Remediation: "Move to a supported runtime (python3.12+, nodejs20.x+, java21, dotnet8, provided.al2023).",
		Check: func(r *Resource) []Hit {
			rt, _ := asString(r.get("runtime"))
			switch {
			case blockedRuntimes[rt]:
				return []Hit{{Path: "runtime", Msg: fmt.Sprintf("Runtime %q is past end of support; AWS blocks creating and updating functions that use it, so apply fails.", rt)}}
			case deprecatedRuntimes[rt]:
				return []Hit{{Path: "runtime", Sev: Medium, Msg: fmt.Sprintf("Runtime %q is deprecated: no security patches, and creates/updates will soon be blocked.", rt)}}
			}
			return nil
		}},
	{ID: "TG-AWS-CDN-001", Title: "CloudFront allows HTTP or legacy TLS", Severity: Medium, Category: CatSecurity, CWE: "CWE-319",
		Types: []string{"aws_cloudfront_distribution"}, Remediation: `Use viewer_protocol_policy = "redirect-to-https" and minimum_protocol_version = "TLSv1.2_2021".`,
		Check: func(r *Resource) []Hit {
			var hits []Hit
			if p, _ := asString(r.get("default_cache_behavior.viewer_protocol_policy")); p == "allow-all" {
				hits = append(hits, Hit{Path: "default_cache_behavior.0.viewer_protocol_policy", Msg: "Viewers can use plain HTTP.",
					Fix: fix("redirect-to-https", "Redirect HTTP to HTTPS", "default_cache_behavior", "viewer_protocol_policy")})
			}
			if v, _ := asString(r.get("viewer_certificate.minimum_protocol_version")); v == "SSLv3" || v == "TLSv1" || v == "TLSv1_2016" || v == "TLSv1.1_2016" {
				hits = append(hits, Hit{Path: "viewer_certificate.0.minimum_protocol_version", Msg: v + " allows obsolete TLS versions.",
					Fix: fix("TLSv1.2_2021", "Require TLS 1.2+", "viewer_certificate", "minimum_protocol_version")})
			}
			return hits
		}},
	{ID: "TG-AWS-MSG-001", Title: "SQS/SNS messages are not encrypted", Severity: Medium, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_sqs_queue", "aws_sns_topic"}, Remediation: "SQS: keep sqs_managed_sse_enabled = true or set kms_master_key_id. SNS: set kms_master_key_id.",
		Check: func(r *Resource) []Hit {
			if r.get("kms_master_key_id") != nil {
				return nil
			}
			if r.Type == "aws_sqs_queue" && is(r.get("sqs_managed_sse_enabled"), false) {
				return []Hit{{Path: "sqs_managed_sse_enabled", Msg: "Server-side encryption is explicitly disabled.", Fix: fix(true, "Enable SQS-managed SSE", "sqs_managed_sse_enabled")}}
			}
			if r.Type == "aws_sns_topic" {
				return []Hit{{Path: "kms_master_key_id", Sev: Low, Msg: "Topic messages are stored without KMS encryption."}}
			}
			return nil
		}},
	{ID: "TG-AWS-ECR-001", Title: "ECR repository allows tag overwrite or skips scanning", Severity: Low, Category: CatSecurity, CWE: "CWE-829",
		Types: []string{"aws_ecr_repository"}, Remediation: `Set image_tag_mutability = "IMMUTABLE" and image_scanning_configuration { scan_on_push = true }.`,
		Check: func(r *Resource) []Hit {
			var hits []Hit
			if m, _ := asString(r.get("image_tag_mutability")); m != "IMMUTABLE" && !isUnknown(r.get("image_tag_mutability")) {
				hits = append(hits, Hit{Path: "image_tag_mutability", Msg: "Tags like :v1.2 can be silently replaced with a different image.", Fix: fix("IMMUTABLE", "Make tags immutable", "image_tag_mutability")})
			}
			if notTrue(r.get("image_scanning_configuration.scan_on_push")) {
				hits = append(hits, Hit{Path: "image_scanning_configuration", Msg: "Images are not scanned for CVEs on push.", Fix: fix(true, "Scan on push", "image_scanning_configuration", "scan_on_push")})
			}
			return hits
		}},
	{ID: "TG-AWS-CACHE-001", Title: "ElastiCache/OpenSearch without encryption", Severity: Medium, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"aws_elasticache_replication_group", "aws_opensearch_domain", "aws_elasticsearch_domain"}, Remediation: "Enable encryption at rest and in transit, and enforce HTTPS.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			if r.Type == "aws_elasticache_replication_group" {
				if notTrue(r.get("transit_encryption_enabled")) {
					hits = append(hits, Hit{Path: "transit_encryption_enabled", Msg: "Redis traffic (including AUTH tokens) is sent in clear text.", Fix: fix(true, "Enable in-transit encryption (forces replacement)", "transit_encryption_enabled")})
				}
				if notTrue(r.get("at_rest_encryption_enabled")) {
					hits = append(hits, Hit{Path: "at_rest_encryption_enabled", Msg: "Snapshots and swap are unencrypted."})
				}
				return hits
			}
			for _, k := range []string{"encrypt_at_rest.enabled", "node_to_node_encryption.enabled", "domain_endpoint_options.enforce_https"} {
				if notTrue(r.get(k)) {
					blk, attr, _ := strings.Cut(k, ".")
					hits = append(hits, Hit{Path: blk, Msg: k + " is not enabled.", Fix: fix(true, "Set "+k+" = true", blk, attr)})
				}
			}
			return hits
		}},
}

var gcpAzureRules = []Rule{
	{ID: "TG-GCP-SQL-001", Title: "Cloud SQL is reachable from the internet", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"google_sql_database_instance"}, Remediation: "Remove 0.0.0.0/0 from authorized_networks; use private IP or the Cloud SQL Auth Proxy, and set ssl_mode = \"ENCRYPTED_ONLY\".",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			if nets, ok := r.get("settings.ip_configuration.authorized_networks").([]any); ok {
				for _, n := range nets {
					if m, ok := n.(map[string]any); ok && anyWorld(m["value"]) {
						hits = append(hits, Hit{Path: "settings", Sev: Critical, Msg: "authorized_networks contains 0.0.0.0/0: the database accepts connections from anywhere."})
					}
				}
			}
			if m, _ := asString(r.get("settings.ip_configuration.ssl_mode")); m == "ALLOW_UNENCRYPTED_AND_ENCRYPTED" {
				hits = append(hits, Hit{Path: "settings", Sev: Medium, Msg: "Unencrypted client connections are allowed."})
			}
			if is(r.get("deletion_protection"), false) {
				hits = append(hits, Hit{Path: "deletion_protection", Sev: Low, Msg: "deletion_protection = false lets a destroy/replace delete the database.", Fix: fix(true, "Enable deletion protection", "deletion_protection")})
			}
			return hits
		}},
	{ID: "TG-GCP-IAM-001", Title: "GCP project grants primitive or public roles", Severity: High, Category: CatSecurity, CWE: "CWE-269",
		Types: []string{"google_project_iam_member", "google_project_iam_binding"}, Remediation: "Grant predefined, narrowly scoped roles instead of roles/owner or roles/editor; never grant to allUsers.",
		Check: func(r *Resource) []Hit {
			members := append(asStrings(r.get("member")), asStrings(r.get("members"))...)
			if contains(members, "allUsers", "allAuthenticatedUsers") {
				return []Hit{{Path: "member", Sev: Critical, Msg: "A project role is granted to everyone on the internet."}}
			}
			if role, _ := asString(r.get("role")); role == "roles/owner" || role == "roles/editor" {
				return []Hit{{Path: "role", Msg: role + " is a primitive role with thousands of permissions."}}
			}
			return nil
		}},
	{ID: "TG-GCP-GKE-001", Title: "GKE control plane is weakly protected", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"google_container_cluster"}, Remediation: "Disable legacy ABAC and restrict master_authorized_networks_config (or use a private cluster).",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			if is(r.get("enable_legacy_abac"), true) {
				hits = append(hits, Hit{Path: "enable_legacy_abac", Sev: High, Msg: "Legacy ABAC grants broad permissions outside RBAC.", Fix: fix(false, "Disable legacy ABAC", "enable_legacy_abac")})
			}
			if r.get("master_authorized_networks_config") == nil && r.get("private_cluster_config") == nil {
				hits = append(hits, Hit{Path: "master_authorized_networks_config", Msg: "The Kubernetes API endpoint accepts connections from any IP."})
			}
			return hits
		}},
	{ID: "TG-GCP-VM-001", Title: "VM uses the default service account with full scopes", Severity: Medium, Category: CatSecurity, CWE: "CWE-269",
		Types: []string{"google_compute_instance", "google_compute_instance_template"}, Remediation: "Attach a dedicated service account with only the roles the workload needs.",
		Check: func(r *Resource) []Hit {
			scopes := asStrings(r.get("service_account.scopes"))
			email, _ := asString(r.get("service_account.email"))
			if contains(scopes, "cloud-platform", "https://www.googleapis.com/auth/cloud-platform") && (email == "" || strings.HasSuffix(email, "-compute@developer.gserviceaccount.com")) {
				return []Hit{{Path: "service_account", Msg: "Any process on the VM gets Editor-level access to the project."}}
			}
			return nil
		}},
	{ID: "TG-AZ-KV-001", Title: "Key Vault can be permanently purged", Severity: Medium, Category: CatReliability, CWE: "CWE-693",
		Types: []string{"azurerm_key_vault"}, Remediation: "Set purge_protection_enabled = true.",
		Check: func(r *Resource) []Hit {
			if notTrue(r.get("purge_protection_enabled")) {
				return []Hit{{Path: "purge_protection_enabled", Msg: "Deleted keys and secrets can be purged immediately (ransomware / accident).", Fix: fix(true, "Enable purge protection", "purge_protection_enabled")}}
			}
			return nil
		}},
	{ID: "TG-AZ-SQL-001", Title: "Azure database firewall open to the internet", Severity: Critical, Category: CatSecurity, CWE: "CWE-284",
		Types:       []string{"azurerm_mssql_firewall_rule", "azurerm_sql_firewall_rule", "azurerm_postgresql_flexible_server_firewall_rule", "azurerm_mysql_flexible_server_firewall_rule"},
		Remediation: "Allow only specific client ranges, or use Private Endpoints.",
		Check: func(r *Resource) []Hit {
			s, _ := asString(r.get("start_ip_address"))
			e, _ := asString(r.get("end_ip_address"))
			switch {
			case s == "0.0.0.0" && e == "255.255.255.255":
				return []Hit{{Path: "start_ip_address", Msg: "Every IPv4 address can reach the database."}}
			case s == "0.0.0.0" && e == "0.0.0.0":
				return []Hit{{Path: "start_ip_address", Sev: Medium, Msg: `"Allow Azure services" admits traffic from every Azure tenant, not just yours.`}}
			}
			return nil
		}},
	{ID: "TG-AZ-AKS-001", Title: "AKS API server is public or RBAC is off", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"azurerm_kubernetes_cluster"}, Remediation: "Use private_cluster_enabled or api_server_access_profile.authorized_ip_ranges, and keep RBAC enabled.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			if is(r.get("role_based_access_control_enabled"), false) {
				hits = append(hits, Hit{Path: "role_based_access_control_enabled", Sev: High, Msg: "Kubernetes RBAC is disabled.", Fix: fix(true, "Enable RBAC", "role_based_access_control_enabled")})
			}
			if !is(r.get("private_cluster_enabled"), true) && r.get("api_server_access_profile.authorized_ip_ranges") == nil && r.get("api_server_authorized_ip_ranges") == nil {
				hits = append(hits, Hit{Path: "private_cluster_enabled", Msg: "The API server is reachable from any IP."})
			}
			return hits
		}},
}

var otherCloudRules = []Rule{
	// ── DigitalOcean ──
	{ID: "TG-DO-FW-001", Title: "DigitalOcean firewall open to the internet", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"digitalocean_firewall"}, Remediation: "Limit source_addresses to your office/VPN or use a bastion droplet tag.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			for i, in := range r.blocks("inbound_rule") {
				if lo, hi, ok := portRange(in["port_range"]); ok && anyWorld(in["source_addresses"]) {
					hits = append(hits, openPorts(fmt.Sprintf("inbound_rule.%d", i), "Inbound rule", in["protocol"], lo, hi)...)
				}
			}
			return hits
		}},
	{ID: "TG-DO-SPACES-001", Title: "DigitalOcean Spaces bucket is public", Severity: High, Category: CatSecurity, CWE: "CWE-732",
		Types: []string{"digitalocean_spaces_bucket"}, Remediation: `Set acl = "private" and share objects with presigned URLs or a CDN.`,
		Check: func(r *Resource) []Hit {
			if acl, _ := asString(r.get("acl")); acl == "public-read" {
				return []Hit{{Path: "acl", Msg: "Every object in the Space can be listed and downloaded by anyone.", Fix: fix("private", `Set acl = "private"`, "acl")}}
			}
			return nil
		}},
	{ID: "TG-DO-DROPLET-001", Title: "Droplet created without SSH keys", Severity: Low, Category: CatSecurity, CWE: "CWE-521",
		Types: []string{"digitalocean_droplet"}, Remediation: "Set ssh_keys so DigitalOcean doesn't email a root password; disable password auth in user_data.",
		Check: func(r *Resource) []Hit {
			if r.get("ssh_keys") == nil {
				return []Hit{{Path: "ssh_keys", Msg: "Without ssh_keys, a root password is generated and emailed, and password SSH stays enabled."}}
			}
			return nil
		}},

	// ── Akamai / Linode ──
	{ID: "TG-LIN-FW-001", Title: "Linode firewall open to the internet", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"linode_firewall"}, Remediation: `Set inbound_policy = "DROP" and allow only specific ipv4/ipv6 ranges.`,
		Check: func(r *Resource) []Hit {
			var hits []Hit
			if p, _ := asString(r.get("inbound_policy")); p == "ACCEPT" {
				hits = append(hits, Hit{Path: "inbound_policy", Sev: Critical, Msg: `inbound_policy = "ACCEPT" allows all traffic not explicitly dropped.`, Fix: fix("DROP", "Default-deny inbound", "inbound_policy")})
			}
			for i, in := range r.blocks("inbound") {
				if a, _ := asString(in["action"]); a != "ACCEPT" || !anyWorld(in["ipv4"], in["ipv6"]) {
					continue
				}
				if lo, hi, ok := portRange(in["ports"]); ok {
					hits = append(hits, openPorts(fmt.Sprintf("inbound.%d", i), "Inbound rule", in["protocol"], lo, hi)...)
				}
			}
			return hits
		}},

	// ── Hetzner Cloud ──
	{ID: "TG-HZ-FW-001", Title: "Hetzner firewall open to the internet", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"hcloud_firewall"}, Remediation: "Restrict source_ips; reach SSH through a VPN or Hetzner private network.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			for i, rule := range r.blocks("rule") {
				if d, _ := asString(rule["direction"]); d != "in" || !anyWorld(rule["source_ips"]) {
					continue
				}
				if lo, hi, ok := portRange(rule["port"]); ok {
					hits = append(hits, openPorts(fmt.Sprintf("rule.%d", i), "Firewall rule", rule["protocol"], lo, hi)...)
				}
			}
			return hits
		}},

	// ── OVHcloud & any OpenStack cloud ──
	{ID: "TG-OS-SG-001", Title: "OpenStack/OVH security group rule open to the internet", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"openstack_networking_secgroup_rule_v2"}, Remediation: "Set remote_ip_prefix to a trusted range or use remote_group_id.",
		Check: func(r *Resource) []Hit {
			if d, _ := asString(r.get("direction")); d != "ingress" {
				return nil
			}
			prefix := r.get("remote_ip_prefix")
			if !(anyWorld(prefix) || (prefix == nil && r.get("remote_group_id") == nil)) {
				return nil
			}
			lo, okLo := asFloat(r.get("port_range_min"))
			hi, okHi := asFloat(r.get("port_range_max"))
			if !okLo || !okHi {
				lo, hi = 0, 65535 // no port range = all ports
			}
			proto := r.get("protocol")
			if proto == nil {
				proto = "all"
			}
			return openPorts("remote_ip_prefix", "Rule", proto, lo, hi)
		}},
	{ID: "TG-OVH-DB-001", Title: "OVHcloud managed database allows any IP", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"ovh_cloud_project_database", "ovh_cloud_project_database_ip_restriction"}, Remediation: "Restrict ip_restrictions to your application's egress IPs or private network.",
		Check: func(r *Resource) []Hit {
			if anyWorld(r.get("ip")) {
				return []Hit{{Path: "ip", Msg: "The database accepts connections from 0.0.0.0/0."}}
			}
			for i, b := range r.blocks("ip_restrictions") {
				if anyWorld(b["ip"]) {
					return []Hit{{Path: fmt.Sprintf("ip_restrictions.%d", i), Msg: "The database accepts connections from 0.0.0.0/0."}}
				}
			}
			return nil
		}},

	// ── Oracle Cloud ──
	{ID: "TG-OCI-NET-001", Title: "OCI security list open to the internet", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"oci_core_security_list", "oci_core_network_security_group_security_rule"}, Remediation: "Restrict source CIDRs; use OCI Bastion for SSH.",
		Check: func(r *Resource) []Hit {
			check := func(path string, m map[string]any) []Hit {
				if !anyWorld(m["source"]) {
					return nil
				}
				opts, _ := get(m, "tcp_options").([]any)
				if len(opts) == 0 {
					return openPorts(path, "Ingress rule", "all", 0, 65535)
				}
				o, _ := opts[0].(map[string]any)
				if dr, ok := get(o, "destination_port_range").([]any); ok && len(dr) > 0 { // NSG rule shape
					o, _ = dr[0].(map[string]any)
				}
				lo, ok1 := asFloat(o["min"])
				hi, ok2 := asFloat(o["max"])
				if !ok1 || !ok2 {
					return nil
				}
				return openPorts(path, "Ingress rule", "tcp", lo, hi)
			}
			if r.Type == "oci_core_network_security_group_security_rule" {
				if d, _ := asString(r.get("direction")); d == "INGRESS" {
					return check("source", r.Attrs)
				}
				return nil
			}
			var hits []Hit
			for i, in := range r.blocks("ingress_security_rules") {
				hits = append(hits, check(fmt.Sprintf("ingress_security_rules.%d", i), in)...)
			}
			return hits
		}},
	{ID: "TG-OCI-OS-001", Title: "OCI Object Storage bucket is public", Severity: High, Category: CatSecurity, CWE: "CWE-732",
		Types: []string{"oci_objectstorage_bucket"}, Remediation: `Set access_type = "NoPublicAccess" and use pre-authenticated requests.`,
		Check: func(r *Resource) []Hit {
			if a, _ := asString(r.get("access_type")); a == "ObjectRead" || a == "ObjectReadWithoutList" {
				return []Hit{{Path: "access_type", Msg: "Objects can be read anonymously.", Fix: fix("NoPublicAccess", "Disable public access", "access_type")}}
			}
			return nil
		}},

	// ── Alibaba Cloud ──
	{ID: "TG-ALI-001", Title: "Alibaba Cloud resource exposed to the internet", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"alicloud_security_group_rule", "alicloud_oss_bucket", "alicloud_oss_bucket_acl"}, Remediation: "Restrict cidr_ip and keep OSS buckets private.",
		Check: func(r *Resource) []Hit {
			if r.Type != "alicloud_security_group_rule" {
				if acl, _ := asString(r.get("acl")); acl == "public-read" || acl == "public-read-write" {
					return []Hit{{Path: "acl", Msg: "OSS bucket ACL is " + acl + ".", Fix: fix("private", `Set acl = "private"`, "acl")}}
				}
				return nil
			}
			t, _ := asString(r.get("type"))
			pol, _ := asString(r.get("policy"))
			if t != "ingress" || pol == "drop" || !anyWorld(r.get("cidr_ip"), r.get("ipv6_cidr_ip")) {
				return nil
			}
			if lo, hi, ok := portRange(r.get("port_range")); ok {
				return openPorts("cidr_ip", "Security group rule", r.get("ip_protocol"), lo, hi)
			}
			return nil
		}},

	// ── Vultr ──
	{ID: "TG-VULTR-001", Title: "Vultr firewall rule open to the internet", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"vultr_firewall_rule"}, Remediation: "Use a specific subnet/subnet_size instead of 0.0.0.0/0.",
		Check: func(r *Resource) []Hit {
			sub, _ := asString(r.get("subnet"))
			size, _ := asFloat(r.get("subnet_size"))
			if (sub != "0.0.0.0" && sub != "::") || size != 0 {
				return nil
			}
			if lo, hi, ok := portRange(r.get("port")); ok {
				return openPorts("subnet", "Firewall rule", r.get("protocol"), lo, hi)
			}
			return nil
		}},

	// ── Cloudflare Workers ──
	{ID: "TG-CF-003", Title: "Worker secret stored as plain-text binding", Severity: High, Category: CatSecurity, CWE: "CWE-798",
		Types: []string{"cloudflare_workers_script", "cloudflare_worker_script"}, Remediation: "Use secret_text_binding (or `wrangler secret put`) for credentials.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			for i, b := range r.blocks("plain_text_binding") {
				if n, _ := asString(b["name"]); secretVarRE.MatchString(n) {
					hits = append(hits, Hit{Path: fmt.Sprintf("plain_text_binding.%d", i), Msg: fmt.Sprintf("Binding %q looks like a secret but is stored in plain text and shown in the dashboard.", n)})
				}
			}
			return hits
		}},
}

var kubernetesRules = []Rule{
	{ID: "TG-K8S-001", Title: "Privileged or host-namespace workload", Severity: High, Category: CatSecurity, CWE: "CWE-250",
		Remediation: "Remove privileged/allow_privilege_escalation and host_network/host_pid/host_ipc; run as non-root.",
		Check: func(r *Resource) []Hit {
			if !strings.HasPrefix(r.Type, "kubernetes_") {
				return nil
			}
			var hits []Hit
			walkMaps(r.Attrs, "", func(p string, m map[string]any) {
				for _, k := range []string{"privileged", "allow_privilege_escalation", "host_network", "host_pid", "host_ipc"} {
					if is(m[k], true) {
						hits = append(hits, Hit{Path: join(p, k), Msg: k + " = true lets a compromised container escape to the node."})
					}
				}
			})
			return hits
		}},
	{ID: "TG-K8S-002", Title: "Container image uses a mutable tag", Severity: Low, Category: CatSecurity, CWE: "CWE-829",
		Remediation: "Pin images to a version tag or, better, an @sha256 digest.",
		Check: func(r *Resource) []Hit {
			if !strings.HasPrefix(r.Type, "kubernetes_") {
				return nil
			}
			var hits []Hit
			walkMaps(r.Attrs, "", func(p string, m map[string]any) {
				img, ok := asString(m["image"])
				if !ok || img == "" || strings.Contains(img, "@sha256:") {
					return
				}
				last := img[strings.LastIndex(img, "/")+1:]
				if !strings.Contains(last, ":") || strings.HasSuffix(last, ":latest") {
					hits = append(hits, Hit{Path: join(p, "image"), Msg: fmt.Sprintf("Image %q can change under you between deploys.", img)})
				}
			})
			return hits
		}},
	{ID: "TG-K8S-003", Title: "LoadBalancer service open to the internet", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"kubernetes_service", "kubernetes_service_v1"}, Remediation: "Set spec.load_balancer_source_ranges or use an internal load balancer annotation.",
		Check: func(r *Resource) []Hit {
			if t, _ := asString(r.get("spec.type")); t == "LoadBalancer" && r.get("spec.load_balancer_source_ranges") == nil {
				return []Hit{{Path: "spec", Msg: "A public cloud load balancer is created with no source IP restriction."}}
			}
			return nil
		}},
	{ID: "TG-HELM-001", Title: "Helm chart version is not pinned", Severity: Medium, Category: CatSecurity, CWE: "CWE-829",
		Types: []string{"helm_release"}, Remediation: "Set version = \"x.y.z\" so applies are reproducible.",
		Check: func(r *Resource) []Hit {
			if r.get("version") == nil {
				return []Hit{{Path: "chart", Msg: "Every apply may install whatever chart version is newest."}}
			}
			return nil
		}},
}

var costRules = []Rule{
	{ID: "TG-COST-001", Title: "gp2 volume: gp3 is cheaper and faster", Severity: Low, Category: CatCost,
		Types: []string{"aws_ebs_volume", "aws_instance", "aws_db_instance", "aws_launch_template"}, Remediation: "Use gp3: ~20% lower $/GB with 3,000 IOPS baseline regardless of size. Changing type is an in-place modification.",
		Check: func(r *Resource) []Hit {
			switch r.Type {
			case "aws_ebs_volume":
				if t, _ := asString(r.get("type")); t == "gp2" {
					return []Hit{{Path: "type", Msg: "Volume type gp2.", Fix: fix("gp3", "Switch to gp3", "type")}}
				}
			case "aws_db_instance":
				if t, _ := asString(r.get("storage_type")); t == "gp2" {
					return []Hit{{Path: "storage_type", Msg: "Storage type gp2.", Fix: fix("gp3", "Switch to gp3", "storage_type")}}
				}
			case "aws_instance":
				if t, _ := asString(r.get("root_block_device.volume_type")); t == "gp2" {
					return []Hit{{Path: "root_block_device.0.volume_type", Msg: "Root volume type gp2.", Fix: fix("gp3", "Switch root volume to gp3", "root_block_device", "volume_type")}}
				}
			}
			return nil
		}},
	{ID: "TG-COST-002", Title: "Previous-generation instance type", Severity: Info, Category: CatCost,
		Types: []string{"aws_instance", "aws_launch_template", "aws_db_instance", "aws_rds_cluster_instance"}, Remediation: "Move to current generation (t3/t4g, m7g/m7i, r7g, db.t4g, db.m7g) for ~10–40% better price-performance.",
		Check: func(r *Resource) []Hit {
			for _, k := range []string{"instance_type", "instance_class"} {
				t, _ := asString(r.get(k))
				for _, p := range previousGen {
					if strings.HasPrefix(t, p) {
						return []Hit{{Path: k, Msg: t + " is a previous-generation type."}}
					}
				}
			}
			return nil
		}},
	{ID: "TG-COST-003", Title: "Logs are retained forever", Severity: Low, Category: CatCost,
		Types: []string{"aws_cloudwatch_log_group"}, Remediation: "Set retention_in_days (e.g. 30–400) to match your compliance requirement.",
		Check: func(r *Resource) []Hit {
			if n, ok := asFloat(r.get("retention_in_days")); r.get("retention_in_days") == nil || (ok && n == 0) {
				return []Hit{{Path: "retention_in_days", Msg: "Without retention, CloudWatch storage cost grows forever.", Fix: fix(90, "Retain logs for 90 days", "retention_in_days")}}
			}
			return nil
		}},
}

// Hosts that are free to re-register once the target resource is deleted,
// which turns a stale CNAME into a subdomain takeover.
var takeoverSuffixes = []string{".s3-website", ".s3.amazonaws.com", ".cloudfront.net", ".elasticbeanstalk.com", ".azurewebsites.net",
	".cloudapp.net", ".trafficmanager.net", ".blob.core.windows.net", ".herokuapp.com", ".github.io", ".netlify.app", ".pages.dev", ".vercel.app", ".fly.dev"}

var dnsCDNRules = []Rule{
	{ID: "TG-DNS-001", Title: "CNAME to a takeover-prone hostname", Severity: Low, Category: CatSecurity, CWE: "CWE-350",
		Types:       []string{"aws_route53_record", "cloudflare_record", "cloudflare_dns_record", "google_dns_record_set", "azurerm_dns_cname_record", "digitalocean_record"},
		Remediation: "Reference the target resource (e.g. aws_cloudfront_distribution.x.domain_name) instead of a literal, and delete the record in the same change that deletes the target.",
		Check: func(r *Resource) []Hit {
			if t, _ := asString(r.get("type")); t != "" && t != "CNAME" {
				return nil
			}
			var targets []string
			for _, k := range []string{"records", "rrdatas", "content", "value", "record"} {
				targets = append(targets, asStrings(r.get(k))...)
			}
			for _, t := range targets {
				host := strings.TrimSuffix(strings.ToLower(t), ".")
				for _, suf := range takeoverSuffixes {
					if strings.Contains(host, suf) {
						return []Hit{{Path: "type", Msg: fmt.Sprintf("Hardcoded CNAME to %q: if that %s resource is deleted, anyone can claim the name and serve content on your domain.", t, strings.TrimPrefix(suf, "."))}}
					}
				}
			}
			return nil
		}},
	{ID: "TG-DNS-002", Title: "DNSSEC is not enabled", Severity: Low, Category: CatSecurity, CWE: "CWE-350",
		Types: []string{"google_dns_managed_zone"}, Remediation: `Add dnssec_config { state = "on" } for public zones.`,
		Check: func(r *Resource) []Hit {
			if v, _ := asString(r.get("visibility")); v == "private" {
				return nil
			}
			if s, _ := asString(r.get("dnssec_config.state")); s != "on" && !isUnknown(r.get("dnssec_config.state")) {
				return []Hit{{Path: "dnssec_config", Msg: "Responses for this public zone can be spoofed (cache poisoning).", Fix: fix("on", "Enable DNSSEC", "dnssec_config", "state")}}
			}
			return nil
		}},
	{ID: "TG-CDN-001", Title: "Azure CDN / Front Door allows HTTP", Severity: Medium, Category: CatSecurity, CWE: "CWE-319",
		Types: []string{"azurerm_cdn_endpoint", "azurerm_cdn_frontdoor_route"}, Remediation: "Set is_http_allowed = false (CDN) or https_redirect_enabled = true (Front Door).",
		Check: func(r *Resource) []Hit {
			if r.Type == "azurerm_cdn_endpoint" && !is(r.get("is_http_allowed"), false) && !isUnknown(r.get("is_http_allowed")) {
				return []Hit{{Path: "is_http_allowed", Msg: "Plain HTTP is allowed (the default).", Fix: fix(false, "Disallow HTTP", "is_http_allowed")}}
			}
			if r.Type == "azurerm_cdn_frontdoor_route" && is(r.get("https_redirect_enabled"), false) {
				return []Hit{{Path: "https_redirect_enabled", Msg: "HTTP requests are not redirected to HTTPS.", Fix: fix(true, "Redirect to HTTPS", "https_redirect_enabled")}}
			}
			return nil
		}},
}
