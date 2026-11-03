package engine

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// Rules for other providers resources.
var portedOther = []Rule{
	// Alibaba Cloud
	{ID: "TG-ALI-RAM-201", Title: "RAM password policy allows passwords under 14 characters", Severity: Medium, Category: CatSecurity, CWE: "CWE-521",
		Types: []string{"alicloud_ram_account_password_policy"}, Remediation: "Set minimum_password_length = 14 or more.",
		Check: func(r *Resource) []Hit {
			if n, ok := othpNum(r.get("minimum_password_length"), 8); ok && n < 14 {
				return []Hit{{Path: "minimum_password_length", Msg: "Users can choose short, guessable passwords.", Fix: fix(14, "Require 14 characters", "minimum_password_length")}}
			}
			return nil
		}},
	{ID: "TG-ALI-RAM-202", Title: "RAM password policy allows password reuse", Severity: Medium, Category: CatSecurity, CWE: "CWE-521",
		Types: []string{"alicloud_ram_account_password_policy"}, Remediation: "Set password_reuse_prevention = 24.",
		Check: func(r *Resource) []Hit {
			if n, ok := othpNum(r.get("password_reuse_prevention"), 0); ok && n < 24 {
				return []Hit{{Path: "password_reuse_prevention", Msg: "Users can cycle back to recently used, possibly leaked, passwords.", Fix: fix(24, "Block reuse of the last 24 passwords", "password_reuse_prevention")}}
			}
			return nil
		}},
	{ID: "TG-ALI-RAM-203", Title: "RAM passwords do not expire within 90 days", Severity: Low, Category: CatSecurity, CWE: "CWE-262",
		Types: []string{"alicloud_ram_account_password_policy"}, Remediation: "Set max_password_age between 1 and 90.",
		Check: func(r *Resource) []Hit {
			if n, ok := othpNum(r.get("max_password_age"), 0); ok && (n <= 0 || n > 90) {
				return []Hit{{Path: "max_password_age", Msg: "A leaked password keeps working indefinitely or for more than 90 days.", Fix: fix(90, "Expire passwords after 90 days", "max_password_age")}}
			}
			return nil
		}},
	{ID: "TG-ALI-RAM-204", Title: "RAM allows more than 5 failed logins", Severity: Medium, Category: CatSecurity, CWE: "CWE-307",
		Types: []string{"alicloud_ram_account_password_policy"}, Remediation: "Set max_login_attempts = 5 or fewer.",
		Check: func(r *Resource) []Hit {
			if n, ok := othpNum(r.get("max_login_attempts"), 5); ok && n > 5 {
				return []Hit{{Path: "max_login_attempts", Msg: "Attackers get more password guesses before the account locks.", Fix: fix(5, "Lock out after 5 failed logins", "max_login_attempts")}}
			}
			return nil
		}},
	{ID: "TG-ALI-APIGW-201", Title: "API Gateway API accepts plain HTTP", Severity: Medium, Category: CatSecurity, CWE: "CWE-319",
		Types: []string{"alicloud_api_gateway_api"}, Remediation: `Set request_config protocol = "HTTPS".`,
		Check: func(r *Resource) []Hit {
			var hits []Hit
			for i, c := range r.blocks("request_config") {
				if p, ok := asString(c["protocol"]); ok && p != "HTTPS" {
					hits = append(hits, Hit{Path: fmt.Sprintf("request_config.%d.protocol", i), Msg: "Requests and their credentials can travel unencrypted (protocol " + p + ")."})
				}
			}
			return hits
		}},
	{ID: "TG-ALI-DB-201", Title: "RDS instance without Transparent Data Encryption", Severity: Medium, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"alicloud_db_instance"}, Remediation: `Set tde_status = "Enabled".`,
		Check: func(r *Resource) []Hit {
			engine, _ := asString(r.get("engine"))
			version, _ := asString(r.get("engine_version"))
			tdeVersions := map[string]bool{"5.6": true, "5.7": true, "8": true, "8.0": true, // MySQL
				"08r2_ent_ha": true, "2012_ent_ha": true, "2016_ent_ha": true, "2017_ent": true, "2019_std_ha": true, "2019_ent": true} // SQL Server
			if (engine != "MySQL" && engine != "SQLServer") || !tdeVersions[version] || isUnknown(r.get("tde_status")) {
				return nil
			}
			if s, _ := asString(r.get("tde_status")); s != "Enabled" {
				return []Hit{{Path: "tde_status", Msg: "Data files and backups are stored without database-level encryption.", Fix: fix("Enabled", "Enable TDE", "tde_status")}}
			}
			return nil
		}},
	{ID: "TG-ALI-DB-202", Title: "RDS SQL audit log kept under 180 days", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"alicloud_db_instance"}, Remediation: `Set sql_collector_status = "Enabled" and sql_collector_config_value = 180 or more.`,
		Check: func(r *Resource) []Hit {
			status := r.get("sql_collector_status")
			if isUnknown(status) {
				return nil
			}
			if s, _ := asString(status); s != "Enabled" {
				return []Hit{{Path: "sql_collector_status", Msg: "SQL statements are not recorded, so queries cannot be audited.", Fix: fix("Enabled", "Enable the SQL collector", "sql_collector_status")}}
			}
			if n, ok := othpNum(r.get("sql_collector_config_value"), 30); ok && n < 180 {
				return []Hit{{Path: "sql_collector_config_value", Msg: "SQL audit records are deleted in under 180 days.", Fix: fix(180, "Keep SQL audit logs 180 days", "sql_collector_config_value")}}
			}
			return nil
		}},
	{ID: "TG-ALI-DB-203", Title: "Database allows connections from any IP address", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"alicloud_db_instance", "alicloud_mongodb_instance"}, Remediation: "Replace 0.0.0.0/0 in the IP whitelist with your application subnets.",
		Check: func(r *Resource) []Hit {
			key := "security_ips"
			if r.Type == "alicloud_mongodb_instance" {
				key = "security_ip_list"
			}
			for _, ip := range asStrings(r.get(key)) {
				if ip == "0.0.0.0" || ip == "0.0.0.0/0" {
					return []Hit{{Path: key, Msg: "The whitelist admits every IPv4 address, so the database login is reachable from the internet."}}
				}
			}
			return nil
		}},
	{ID: "TG-ALI-ACK-201", Title: "Kubernetes cluster has no network-policy capable CNI", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"alicloud_cs_kubernetes"}, Remediation: `Add the "terway-eniip" addon with pod_vswitch_ids distinct from the node vswitches, or "flannel" with pod_cidr.`,
		Check: func(r *Resource) []Hit {
			if isUnknown(r.get("addons")) {
				return nil
			}
			names := map[string]bool{}
			for _, a := range r.blocks("addons") {
				n, _ := asString(a["name"])
				names[n] = true
			}
			pods := r.get("pod_vswitch_ids")
			switch {
			case names["terway-eniip"] && (len(asStrings(pods)) > 0 || isUnknown(pods)):
				nodes := append(asStrings(r.get("worker_vswitch_ids")), asStrings(r.get("master_vswitch_ids"))...)
				for _, p := range asStrings(pods) {
					if contains(nodes, p) {
						return []Hit{{Path: "pod_vswitch_ids", Msg: "Pod vswitch " + p + " is also a node vswitch, which Terway does not support."}}
					}
				}
				return nil
			case names["flannel"] && r.get("pod_cidr") != nil:
				return nil
			}
			return []Hit{{Path: "addons", Msg: "Without Terway or Flannel, Kubernetes NetworkPolicy objects are not enforced and every pod can reach every other pod."}}
		}},
	{ID: "TG-ALI-ECS-201", Title: "Launch template data disk is not encrypted", Severity: Medium, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"alicloud_ecs_launch_template"}, Remediation: "Set encrypted = true on every data_disks block.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			for i, d := range r.blocks("data_disks") {
				if notTrue(d["encrypted"]) {
					hits = append(hits, Hit{Path: fmt.Sprintf("data_disks.%d", i), Msg: "Instances launched from this template write data unencrypted at rest."})
				}
			}
			return hits
		}},
	{ID: "TG-ALI-DISK-201", Title: "Disk is not encrypted", Severity: Medium, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"alicloud_disk"}, Remediation: "Set encrypted = true (forces a new disk).",
		Check: func(r *Resource) []Hit {
			if r.get("snapshot_id") != nil { // encryption is inherited from the snapshot
				return nil
			}
			if notTrue(r.get("encrypted")) {
				return []Hit{{Path: "encrypted", Msg: "Disk data and its snapshots are stored unencrypted.", Fix: fix(true, "Encrypt the disk (replaces it)", "encrypted")}}
			}
			return nil
		}},
	{ID: "TG-ALI-DISK-202", Title: "Disk is not encrypted with a customer-managed key", Severity: Low, Category: CatSecurity, CWE: "CWE-320",
		Types: []string{"alicloud_disk"}, Remediation: "Set encrypted = true and kms_key_id to your KMS key.",
		Check: func(r *Resource) []Hit {
			if r.get("snapshot_id") == nil && (r.get("kms_key_id") == nil || is(r.get("encrypted"), false)) {
				return []Hit{{Path: "kms_key_id", Msg: "Without your own KMS key you cannot rotate, audit or revoke access to the disk data."}}
			}
			return nil
		}},

	// DigitalOcean
	{ID: "TG-DO-SPACES-201", Title: "Spaces bucket versioning is off", Severity: Low, Category: CatReliability, CWE: "CWE-693",
		Types: []string{"digitalocean_spaces_bucket"}, Remediation: "Add versioning { enabled = true }.",
		Check: func(r *Resource) []Hit {
			if notTrue(r.get("versioning.0.enabled")) {
				return []Hit{{Path: "versioning", Msg: "Overwritten or deleted objects cannot be recovered.", Fix: fix(true, "Enable versioning", "versioning", "enabled")}}
			}
			return nil
		}},
	{ID: "TG-DO-FW-201", Title: "Firewall inbound rule accepts the whole internet", Severity: Low, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"digitalocean_firewall"}, Remediation: "Limit source_addresses to known ranges, droplets, tags or load balancers.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			for i, in := range r.blocks("inbound_rule") {
				if !anyWorld(in["source_addresses"]) {
					continue
				}
				if lo, hi, ok := portRange(in["port_range"]); ok && openPorts("", "", in["protocol"], lo, hi) != nil {
					continue // sensitive ports are reported by TG-DO-FW-001
				}
				hits = append(hits, Hit{Path: fmt.Sprintf("inbound_rule.%d", i), Msg: "Any address on the internet can open connections to this port."})
			}
			return hits
		}},

	// GitHub and GitLab
	{ID: "TG-GH-REPO-201", Title: "GitHub repository is public", Severity: Medium, Category: CatSecurity, CWE: "CWE-200",
		Types: []string{"github_repository"}, Remediation: `Set visibility = "private" (or "internal") unless the code is meant to be open source.`,
		Check: func(r *Resource) []Hit {
			if isUnknown(r.get("visibility")) || isUnknown(r.get("private")) || is(r.get("private"), true) {
				return nil
			}
			if v, _ := asString(r.get("visibility")); v == "private" || v == "internal" {
				return nil
			}
			return []Hit{{Path: "visibility", Msg: "Anyone can read the code, history and any secrets ever committed."}}
		}},
	{ID: "TG-GH-REPO-202", Title: "GitHub repository vulnerability alerts are off", Severity: Low, Category: CatSecurity, CWE: "CWE-1104",
		Types: []string{"github_repository"}, Remediation: "Set vulnerability_alerts = true.",
		Check: func(r *Resource) []Hit {
			if is(r.get("archived"), true) || isUnknown(r.get("vulnerability_alerts")) {
				return nil
			}
			v, _ := asString(r.get("visibility"))
			private := is(r.get("private"), true) || v == "private" || v == "internal"
			// GitHub turns alerts on by default for public repositories only.
			if is(r.get("vulnerability_alerts"), false) || (private && r.get("vulnerability_alerts") == nil) {
				return []Hit{{Path: "vulnerability_alerts", Msg: "Dependabot does not warn about dependencies with known vulnerabilities.", Fix: fix(true, "Enable vulnerability alerts", "vulnerability_alerts")}}
			}
			return nil
		}},
	{ID: "TG-GH-BRANCH-201", Title: "Branch protection requires fewer than two approvals", Severity: Low, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"github_branch_protection", "github_branch_protection_v3"}, Remediation: "Set required_approving_review_count = 2 in required_pull_request_reviews.",
		Check: func(r *Resource) []Hit {
			// A missing required_pull_request_reviews block is reported by TG-GH-001.
			if r.get("required_pull_request_reviews") == nil {
				return nil
			}
			if n, ok := othpNum(r.get("required_pull_request_reviews.0.required_approving_review_count"), 1); ok && n < 2 {
				return []Hit{{Path: "required_pull_request_reviews", Msg: "A single reviewer can approve and merge a change alone.", Fix: fix(2, "Require two approvals", "required_pull_request_reviews", "required_approving_review_count")}}
			}
			return nil
		}},
	{ID: "TG-GL-PROJECT-201", Title: "GitLab project requires fewer than two merge approvals", Severity: Low, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"gitlab_project"}, Remediation: "Set approvals_before_merge = 2 (or add a gitlab_project_approval_rule).",
		Check: func(r *Resource) []Hit {
			if n, ok := othpNum(r.get("approvals_before_merge"), 0); ok && n < 2 {
				return []Hit{{Path: "approvals_before_merge", Msg: "Merge requests can be merged with fewer than two reviews.", Fix: fix(2, "Require two approvals", "approvals_before_merge")}}
			}
			return nil
		}},

	// Naver Cloud
	{ID: "TG-NCP-LB-201", Title: "HTTP target group has no health check path", Severity: Low, Category: CatReliability, CWE: "CWE-693",
		Types: []string{"ncloud_lb_target_group"}, Remediation: "Add health_check { url_path = \"/health\" } for HTTP and HTTPS target groups.",
		Check: func(r *Resource) []Hit {
			if p, _ := asString(r.get("protocol")); p != "HTTP" && p != "HTTPS" {
				return nil
			}
			if r.get("health_check.0.url_path") == nil {
				return []Hit{{Path: "health_check", Msg: "Traffic keeps going to targets whose application has stopped answering."}}
			}
			return nil
		}},
	{ID: "TG-NCP-LB-202", Title: "Load balancer listener is unencrypted or allows old TLS", Severity: Medium, Category: CatSecurity, CWE: "CWE-319",
		Types: []string{"ncloud_lb_listener"}, Remediation: `Use protocol = "HTTPS" or "TLS" with tls_min_version_type = "TLSV12".`,
		Check: func(r *Resource) []Hit {
			p, ok := asString(r.get("protocol"))
			if !ok {
				return nil
			}
			if p != "HTTPS" && p != "TLS" {
				return []Hit{{Path: "protocol", Msg: "Clients connect without encryption (protocol " + p + ")."}}
			}
			if v := r.get("tls_min_version_type"); !isUnknown(v) && v != "TLSV12" {
				return []Hit{{Path: "tls_min_version_type", Msg: "TLS 1.0 and 1.1 are accepted.", Fix: fix("TLSV12", "Require TLS 1.2", "tls_min_version_type")}}
			}
			return nil
		}},
	{ID: "TG-NCP-LB-203", Title: "Load balancer target group uses plain HTTP", Severity: Low, Category: CatSecurity, CWE: "CWE-319",
		Types: []string{"ncloud_lb_target_group"}, Remediation: `Set protocol = "HTTPS" so traffic stays encrypted to the targets.`,
		Check: func(r *Resource) []Hit {
			if p, _ := asString(r.get("protocol")); p == "HTTP" {
				return []Hit{{Path: "protocol", Msg: "Traffic between the load balancer and the servers is unencrypted."}}
			}
			return nil
		}},
	{ID: "TG-NCP-NACL-201", Title: "Network ACL inbound rule allows every port", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"ncloud_network_acl_rule"}, Remediation: "Set port_range on each TCP/UDP inbound rule to the ports the service needs.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			for i, in := range r.blocks("inbound") {
				if p, _ := asString(in["protocol"]); p == "ICMP" || isUnknown(in["port_range"]) {
					continue
				}
				if lo, hi, ok := portRange(in["port_range"]); in["port_range"] == nil || ok && lo <= 1 && hi >= 65535 {
					hits = append(hits, Hit{Path: fmt.Sprintf("inbound.%d", i), Msg: "The subnet accepts traffic on all ports instead of only the ones it serves."})
				}
			}
			return hits
		}},
	{ID: "TG-NCP-ACG-201", Title: "Access control group or rule has no description", Severity: Low, Category: CatBestPrac, CWE: "CWE-1078",
		Types: []string{"ncloud_access_control_group", "ncloud_access_control_group_rule"}, Remediation: "Add a description to the group and to every inbound and outbound rule.",
		Check: func(r *Resource) []Hit {
			if r.Type == "ncloud_access_control_group" {
				if othpBlank(r.get("description")) {
					return []Hit{{Path: "description", Msg: "Reviewers cannot tell what this group is for."}}
				}
				return nil
			}
			var hits []Hit
			for _, dir := range []string{"inbound", "outbound"} {
				for i, b := range r.blocks(dir) {
					if othpBlank(b["description"]) {
						hits = append(hits, Hit{Path: fmt.Sprintf("%s.%d", dir, i), Msg: "Reviewers cannot tell why this rule exists or when it can go."})
					}
				}
			}
			return hits
		}},
	{ID: "TG-NCP-ACG-202", Title: "Access control group allows outbound traffic anywhere", Severity: Low, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"ncloud_access_control_group_rule"}, Remediation: "Limit outbound ip_block to the networks the servers need to reach.",
		Check: func(r *Resource) []Hit {
			for i, out := range r.blocks("outbound") {
				if ip, _ := asString(out["ip_block"]); worldCIDR(ip) {
					return []Hit{{Path: fmt.Sprintf("outbound.%d.ip_block", i), Msg: "A compromised server can send data to any address on the internet."}}
				}
			}
			return nil
		}},
	{ID: "TG-NCP-IP-201", Title: "Public IP is attached to a server", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"ncloud_public_ip"}, Remediation: "Remove server_instance_no and reach the server through a load balancer, NAT gateway or bastion.",
		Check: func(r *Resource) []Hit {
			if v := r.get("server_instance_no"); v != nil && v != "" { // a reference still attaches the IP
				return []Hit{{Path: "server_instance_no", Msg: "The server is directly reachable from the internet."}}
			}
			return nil
		}},

	// Oracle Cloud
	{ID: "TG-OCI-NET-201", Title: "Ingress security rule is stateful", Severity: Low, Category: CatBestPrac, CWE: "CWE-693",
		Types: []string{"oci_core_security_list", "oci_core_network_security_group_security_rule"}, Remediation: "Set stateless = true on ingress rules and add the matching egress rules.",
		Check: func(r *Resource) []Hit {
			// Only an explicit stateless = false fires: stateful is OCI's default
			// and not a weakness on its own.
			// A rule list containing references parses as unknown and is skipped.
			if r.Type == "oci_core_network_security_group_security_rule" {
				if d, _ := asString(r.get("direction")); d == "INGRESS" && is(r.get("stateless"), false) {
					return []Hit{{Path: "stateless", Msg: "Stateful rules track every connection, which limits throughput under load or attack.", Fix: fix(true, "Make the rule stateless", "stateless")}}
				}
				return nil
			}
			var hits []Hit
			for i, in := range r.blocks("ingress_security_rules") {
				if is(in["stateless"], false) {
					hits = append(hits, Hit{Path: fmt.Sprintf("ingress_security_rules.%d.stateless", i), Msg: "Stateful rules track every connection, which limits throughput under load or attack."})
				}
			}
			return hits
		}},
	{ID: "TG-OCI-IAM-201", Title: "OCI password policy allows passwords under 14 characters", Severity: Medium, Category: CatSecurity, CWE: "CWE-521",
		Types: []string{"oci_identity_authentication_policy"}, Remediation: "Set password_policy { minimum_password_length = 14 }.",
		Check: func(r *Resource) []Hit {
			if n, ok := othpNum(r.get("password_policy.0.minimum_password_length"), 12); ok && n < 14 {
				return []Hit{{Path: "password_policy", Msg: "Local users can choose short, guessable passwords.", Fix: fix(14, "Require 14 characters", "password_policy", "minimum_password_length")}}
			}
			return nil
		}},
	{ID: "TG-OCI-CATALOG-201", Title: "Data Catalog has no private endpoint", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"oci_datacatalog_catalog"}, Remediation: "Attach an oci_datacatalog_catalog_private_endpoint through attached_catalog_private_endpoints.",
		Check: func(r *Resource) []Hit {
			if v := r.get("attached_catalog_private_endpoints"); !isUnknown(v) && othpLen(v) == 0 {
				return []Hit{{Path: "attached_catalog_private_endpoints", Msg: "The catalog is only reachable over its public endpoint."}}
			}
			return nil
		}},

	// Okta
	{ID: "TG-OKTA-SIGNON-201", Title: "Okta sign-on policy rule allows single-factor login", Severity: High, Category: CatSecurity, CWE: "CWE-308",
		Types: []string{"okta_app_signon_policy_rule"}, Remediation: `Set factor_mode = "2FA".`,
		Check: func(r *Resource) []Hit {
			if m, _ := asString(r.get("factor_mode")); m == "1FA" {
				return []Hit{{Path: "factor_mode", Msg: "A stolen password alone is enough to sign in to the application.", Fix: fix("2FA", "Require two factors", "factor_mode")}}
			}
			return nil
		}},

	// OpenStack
	{ID: "TG-OS-COMPUTE-201", Title: "Compute instance sets an admin password", Severity: High, Category: CatSecurity, CWE: "CWE-798",
		Types: []string{"openstack_compute_instance_v2"}, Remediation: "Remove admin_pass and log in with a key_pair.",
		Check: func(r *Resource) []Hit {
			if v := r.get("admin_pass"); v != nil && v != "" { // a variable still enables password login
				return []Hit{{Path: "admin_pass", Msg: "The server accepts a password login, and the password is stored in Terraform state."}}
			}
			return nil
		}},
	{ID: "TG-OS-FW-201", Title: "Firewall allow rule has no destination restriction", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"openstack_fw_rule_v1"}, Remediation: "Set destination_ip_address to the hosts the rule is meant for.",
		Check: func(r *Resource) []Hit {
			if a, _ := asString(r.get("action")); a != "allow" {
				return nil
			}
			if d := r.get("destination_ip_address"); d == nil || d == "0.0.0.0" || d == "0.0.0.0/0" {
				return []Hit{{Path: "destination_ip_address", Msg: "The rule allows traffic to every address behind the firewall."}}
			}
			return nil
		}},

	// Palo Alto Networks PAN-OS
	{ID: "TG-PANOS-POLICY-201", Title: "Security rule disables server response inspection", Severity: Medium, Category: CatSecurity, CWE: "CWE-693",
		Types: othpPanTypes, Remediation: "Set disable_server_response_inspection = false on every rule.",
		Check: func(r *Resource) []Hit {
			return othpPanRules(r, "disable_server_response_inspection", "Threats in server responses are not inspected.", func(v any) bool { return is(v, true) })
		}},
	{ID: "TG-PANOS-POLICY-202", Title: "Security rule allows any application", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: othpPanTypes, Remediation: "List the specific applications the rule should allow.",
		Check: func(r *Resource) []Hit {
			return othpPanRules(r, "applications", "Every application, including tunnelling and file-sharing tools, is allowed.", othpAny)
		}},
	{ID: "TG-PANOS-POLICY-203", Title: "Security rule allows any service", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: othpPanTypes, Remediation: `Use "application-default" or list the specific services.`,
		Check: func(r *Resource) []Hit {
			return othpPanRules(r, "services", "Allowed applications can run on any port.", othpAny)
		}},
	{ID: "TG-PANOS-POLICY-204", Title: "Security rule allows any source to any destination", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: othpPanTypes, Remediation: "Restrict source_addresses or destination_addresses to specific address objects.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			for i, rule := range r.blocks("rule") {
				if othpAny(rule["source_addresses"]) && othpAny(rule["destination_addresses"]) {
					hits = append(hits, Hit{Path: fmt.Sprintf("rule.%d", i), Msg: "Traffic from any address to any address matches this rule."})
				}
			}
			return hits
		}},
	{ID: "TG-PANOS-POLICY-205", Title: "Security rule has no description", Severity: Low, Category: CatBestPrac, CWE: "CWE-1078",
		Types: othpPanTypes, Remediation: "Add a description explaining why each rule exists.",
		Check: func(r *Resource) []Hit {
			return othpPanRules(r, "description", "Reviewers cannot tell why this rule exists or when it can go.", othpBlank)
		}},
	{ID: "TG-PANOS-POLICY-206", Title: "Security rule has no log forwarding profile", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: othpPanTypes, Remediation: "Set log_setting to a log forwarding profile on every rule.",
		Check: func(r *Resource) []Hit {
			return othpPanRules(r, "log_setting", "Traffic logs for this rule stay on the firewall and never reach your SIEM.", othpBlank)
		}},
	{ID: "TG-PANOS-POLICY-207", Title: "Security rule does not log session end", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: othpPanTypes, Remediation: "Remove log_end = false (it defaults to true).",
		Check: func(r *Resource) []Hit {
			return othpPanRules(r, "log_end", "Completed sessions matching this rule are not logged.", func(v any) bool { return is(v, false) })
		}},
	{ID: "TG-PANOS-IPSEC-201", Title: "IPsec crypto profile allows weak encryption", Severity: Medium, Category: CatSecurity, CWE: "CWE-327",
		Types: []string{"panos_ipsec_crypto_profile", "panos_panorama_ipsec_crypto_profile"}, Remediation: `Use only "aes-128-gcm" or "aes-256-gcm" in encryptions.`,
		Check: func(r *Resource) []Hit {
			for _, e := range asStrings(r.get("encryptions")) {
				switch e {
				case "des", "3des", "aes-128-cbc", "aes-192-cbc", "aes-256-cbc", "null":
					return []Hit{{Path: "encryptions", Msg: "The tunnel can negotiate " + e + ", which is broken or weaker than AES-GCM."}}
				}
			}
			return nil
		}},
	{ID: "TG-PANOS-IPSEC-202", Title: "IPsec crypto profile allows weak authentication", Severity: Medium, Category: CatSecurity, CWE: "CWE-327",
		Types: []string{"panos_ipsec_crypto_profile", "panos_panorama_ipsec_crypto_profile"}, Remediation: `Use "sha256" or stronger in authentications.`,
		Check: func(r *Resource) []Hit {
			for _, a := range asStrings(r.get("authentications")) {
				if a == "none" || a == "md5" || a == "sha1" {
					return []Hit{{Path: "authentications", Msg: "The tunnel can negotiate " + a + " integrity, which can be forged."}}
				}
			}
			return nil
		}},
	{ID: "TG-PANOS-ZONE-201", Title: "Security zone has no zone protection profile", Severity: Medium, Category: CatSecurity, CWE: "CWE-400",
		Types: []string{"panos_zone", "panos_panorama_zone"}, Remediation: "Set zone_profile to a zone protection profile.",
		Check: func(r *Resource) []Hit {
			if othpBlank(r.get("zone_profile")) {
				return []Hit{{Path: "zone_profile", Msg: "The zone has no flood, reconnaissance or packet-based attack protection."}}
			}
			return nil
		}},
	{ID: "TG-PANOS-ZONE-202", Title: "User-ID zone has no include ACL", Severity: Low, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"panos_zone", "panos_panorama_zone"}, Remediation: "Set include_acls to the internal networks User-ID should map.",
		Check: func(r *Resource) []Hit {
			if !is(r.get("enable_user_id"), true) || isUnknown(r.get("include_acls")) {
				return nil
			}
			acls := asStrings(r.get("include_acls"))
			bad := len(acls) == 0
			for _, a := range acls {
				bad = bad || strings.TrimSpace(a) == ""
			}
			if bad {
				return []Hit{{Path: "include_acls", Msg: "User-ID probes and maps any address, including untrusted ones."}}
			}
			return nil
		}},

	// Tencent Cloud
	{ID: "TG-TC-CLB-201", Title: "CLB instance does not ship access logs", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"tencentcloud_clb_instance"}, Remediation: "Set log_set_id and log_topic_id to a CLS log set and topic.",
		Check: func(r *Resource) []Hit {
			if r.get("log_set_id") == nil || r.get("log_topic_id") == nil {
				return []Hit{{Path: "log_set_id", Msg: "Requests through the load balancer are not logged."}}
			}
			return nil
		}},
	{ID: "TG-TC-CVM-201", Title: "CVM user data contains Tencent Cloud credentials", Severity: High, Category: CatSecurity, CWE: "CWE-798",
		Types: []string{"tencentcloud_instance"}, Remediation: "Remove TENCENTCLOUD_SECRET_ID/KEY from user data and attach a CAM role to the instance.",
		Check: func(r *Resource) []Hit {
			for _, k := range []string{"user_data_raw", "user_data"} {
				if t := othpText(r.get(k)); strings.Contains(t, "TENCENTCLOUD_SECRET_ID") || strings.Contains(t, "TENCENTCLOUD_SECRET_KEY") {
					return []Hit{{Path: k, Msg: "API keys in user data can be read by anyone with access to the instance metadata or the code."}}
				}
			}
			return nil
		}},
	{ID: "TG-TC-CVM-202", Title: "CVM instance uses the default security group", Severity: Low, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"tencentcloud_instance"}, Remediation: "Create a dedicated security group with only the ports the instance needs.",
		Check: func(r *Resource) []Hit {
			for _, k := range []string{"orderly_security_groups", "security_groups"} {
				if strings.Contains(othpText(r.get(k)), ".default.") {
					return []Hit{{Path: k, Msg: "The shared default group is broad and changes to it affect every instance using it."}}
				}
			}
			return nil
		}},
	{ID: "TG-TC-CVM-203", Title: "CVM instance runs in the default VPC", Severity: Low, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"tencentcloud_instance"}, Remediation: "Place the instance in a dedicated VPC and subnet.",
		Check: func(r *Resource) []Hit {
			for _, k := range []string{"vpc_id", "subnet_id"} {
				if strings.Contains(othpText(r.get(k)), ".default.") {
					return []Hit{{Path: k, Msg: "The default network is shared with unrelated workloads and has no planned segmentation."}}
				}
			}
			return nil
		}},
	{ID: "TG-TC-TKE-201", Title: "TKE cluster nodes get public IP addresses", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"tencentcloud_kubernetes_cluster"}, Remediation: "Set public_ip_assigned = false in master_config and worker_config; use a NAT gateway for egress.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			for _, cfg := range []string{"master_config", "worker_config"} {
				for i, c := range r.blocks(cfg) {
					pub := c["public_ip_assigned"]
					bw, _ := asFloat(c["internet_max_bandwidth_out"])
					if is(pub, true) || (pub == nil && bw > 0) {
						hits = append(hits, Hit{Path: fmt.Sprintf("%s.%d", cfg, i), Msg: "Cluster nodes are directly reachable from the internet."})
					}
				}
			}
			return hits
		}},
	{ID: "TG-TC-SG-201", Title: "Security group accepts all traffic from the internet", Severity: Critical, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"tencentcloud_security_group_rule_set"}, Remediation: "Limit cidr_block to trusted ranges and set protocol and port to what the service needs.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			for i, in := range r.blocks("ingress") {
				if a, ok := asString(in["action"]); ok && a != "ACCEPT" {
					continue
				}
				v4, _ := asString(in["cidr_block"])
				v6, _ := asString(in["ipv6_cidr_block"])
				if !worldCIDR(v4) && !worldCIDR(v6) && v6 != "0::0/0" {
					continue
				}
				proto, _ := asString(in["protocol"])
				port, _ := asString(in["port"])
				if strings.EqualFold(proto, "ALL") || strings.EqualFold(port, "ALL") {
					hits = append(hits, Hit{Path: fmt.Sprintf("ingress.%d", i), Msg: "Every port and protocol is open to the whole internet."})
				}
			}
			return hits
		}},

	// Yandex Cloud
	{ID: "TG-YC-MDB-201", Title: "Managed database cluster has a public IP", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"yandex_mdb_postgresql_cluster", "yandex_mdb_sqlserver_cluster", "yandex_mdb_mysql_cluster", "yandex_mdb_mongodb_cluster",
			"yandex_mdb_kafka_cluster", "yandex_mdb_greenplum_cluster", "yandex_mdb_elasticsearch_cluster", "yandex_mdb_clickhouse_cluster"},
		Remediation: "Set assign_public_ip = false and connect from inside the VPC.",
		Check: func(r *Resource) []Hit {
			switch r.Type {
			case "yandex_mdb_greenplum_cluster":
				if is(r.get("assign_public_ip"), true) {
					return []Hit{{Path: "assign_public_ip", Msg: "The database cluster is reachable from the internet.", Fix: fix(false, "Remove the public IP", "assign_public_ip")}}
				}
			case "yandex_mdb_kafka_cluster":
				if is(r.get("config.0.assign_public_ip"), true) {
					return []Hit{{Path: "config", Msg: "Kafka brokers are reachable from the internet.", Fix: fix(false, "Remove the public IP", "config", "assign_public_ip")}}
				}
			default:
				for i, h := range r.blocks("host") {
					if is(h["assign_public_ip"], true) {
						return []Hit{{Path: fmt.Sprintf("host.%d.assign_public_ip", i), Msg: "A database host is reachable from the internet."}}
					}
				}
			}
			return nil
		}},
	{ID: "TG-YC-STORAGE-201", Title: "Object storage bucket is public", Severity: High, Category: CatSecurity, CWE: "CWE-732",
		Types: []string{"yandex_storage_bucket"}, Remediation: `Set acl = "private" and remove grants to AllUsers.`,
		Check: func(r *Resource) []Hit {
			switch acl, _ := asString(r.get("acl")); acl {
			case "public-read-write":
				return []Hit{{Path: "acl", Sev: Critical, Msg: "Anyone can read, overwrite and delete objects.", Fix: fix("private", `Set acl = "private"`, "acl")}}
			case "public-read":
				return []Hit{{Path: "acl", Msg: "Anyone can list and download every object.", Fix: fix("private", `Set acl = "private"`, "acl")}}
			}
			for i, g := range r.blocks("grant") {
				if u, _ := asString(g["uri"]); u == "http://acs.amazonaws.com/groups/global/AllUsers" {
					return []Hit{{Path: fmt.Sprintf("grant.%d", i), Msg: "A grant gives everyone on the internet access to the bucket."}}
				}
			}
			return nil
		}},
	{ID: "TG-YC-SG-201", Title: "Security group allows all ports from the internet", Severity: Critical, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"yandex_vpc_security_group", "yandex_vpc_security_group_rule"}, Remediation: "Set port (or from_port/to_port) to the service ports and narrow v4_cidr_blocks.",
		Check: func(r *Resource) []Hit {
			if r.Type == "yandex_vpc_security_group_rule" {
				if d, _ := asString(r.get("direction")); d == "ingress" && othpYCAllowAll(r.Attrs) {
					return []Hit{{Path: "v4_cidr_blocks", Msg: "Every port is open to the whole internet."}}
				}
				return nil
			}
			var hits []Hit
			for i, in := range r.blocks("ingress") {
				if othpYCAllowAll(in) {
					hits = append(hits, Hit{Path: fmt.Sprintf("ingress.%d", i), Msg: "Every port is open to the whole internet."})
				}
			}
			return hits
		}},
	{ID: "TG-YC-IAM-201", Title: "IAM role granted to a personal Yandex account", Severity: Low, Category: CatSecurity, CWE: "CWE-269",
		Types: []string{"yandex_resourcemanager_folder_iam_binding", "yandex_resourcemanager_folder_iam_member", "yandex_resourcemanager_cloud_iam_binding",
			"yandex_resourcemanager_cloud_iam_member", "yandex_organizationmanager_organization_iam_binding", "yandex_organizationmanager_organization_iam_member"},
		Remediation: "Grant roles to service accounts or federated users instead of userAccount members.",
		Check: func(r *Resource) []Hit {
			key := "member"
			if strings.HasSuffix(r.Type, "_binding") {
				key = "members"
			}
			for _, m := range asStrings(r.get(key)) {
				if strings.HasPrefix(m, "userAccount:") {
					return []Hit{{Path: key, Msg: m + " is a personal Passport account that your organization cannot offboard or force MFA on."}}
				}
			}
			return nil
		}},
}

var othpPanTypes = []string{"panos_security_policy", "panos_security_rule_group"}

// othpPanRules reports each PAN-OS security rule block whose attr is bad.
func othpPanRules(r *Resource, attr, msg string, bad func(any) bool) []Hit {
	var hits []Hit
	for i, rule := range r.blocks("rule") {
		if !isUnknown(rule[attr]) && bad(rule[attr]) {
			hits = append(hits, Hit{Path: fmt.Sprintf("rule.%d", i), Msg: msg})
		}
	}
	return hits
}

// othpAny is true when a PAN-OS address/application/service list contains "any".
func othpAny(v any) bool { return contains(asStrings(v), "any") }

// othpBlank is true when a value is absent or only whitespace (unknown is not blank).
func othpBlank(v any) bool {
	if v == nil {
		return true
	}
	s, ok := v.(string)
	return ok && strings.TrimSpace(s) == ""
}

// othpNum reads a number, using def when absent; ok is false for unknown or non-numeric values.
func othpNum(v any, def float64) (float64, bool) {
	if v == nil {
		return def, true
	}
	return asFloat(v)
}

// othpLen counts list elements (a single value counts as one).
func othpLen(v any) int {
	switch t := v.(type) {
	case nil:
		return 0
	case []any:
		return len(t)
	case string:
		if t == "" {
			return 0
		}
	}
	return 1
}

// othpText flattens a value into searchable text: literals, base64-decoded
// literals and the source of unknown expressions (references, function calls).
func othpText(v any) string {
	switch t := v.(type) {
	case string:
		if b, err := base64.StdEncoding.DecodeString(t); err == nil {
			return t + "\n" + string(b)
		}
		return t
	case Unknown:
		return t.Expr
	case []any:
		var parts []string
		for _, e := range t {
			parts = append(parts, othpText(e))
		}
		return strings.Join(parts, "\n")
	}
	return ""
}

// othpYCAllowAll is true for a Yandex ingress rule open to 0.0.0.0/0 on every port.
func othpYCAllowAll(m map[string]any) bool {
	if p, _ := asString(m["protocol"]); strings.Contains(strings.ToUpper(p), "ICMP") {
		return false // ICMP has no ports
	}
	if !contains(asStrings(m["v4_cidr_blocks"]), "0.0.0.0/0") {
		return false
	}
	if p, ok := m["port"]; ok && p != nil {
		n, known := asFloat(p)
		return known && n == -1
	}
	from, to := m["from_port"], m["to_port"]
	if from == nil && to == nil {
		return true
	}
	lo, lok := asFloat(from)
	hi, hok := asFloat(to)
	return lok && hok && lo <= 0 && hi >= 65535
}

// portedOtherIDs maps foreign check IDs to these rules, so existing skip comments keep working.
var portedOtherIDs = map[string]string{
	"CKV_ALI_13": "TG-ALI-RAM-201", "CKV_ALI_18": "TG-ALI-RAM-202", "CKV_ALI_16": "TG-ALI-RAM-203", "CKV_ALI_23": "TG-ALI-RAM-204",
	"CKV_ALI_21": "TG-ALI-APIGW-201",
	"CKV_ALI_22": "TG-ALI-DB-201",
	"CKV_ALI_25": "TG-ALI-DB-202",
	"CKV_ALI_9":  "TG-ALI-DB-203", "CKV_ALI_43": "TG-ALI-DB-203",
	"CKV_ALI_26": "TG-ALI-ACK-201",
	"CKV_ALI_32": "TG-ALI-ECS-201",
	"CKV_ALI_7":  "TG-ALI-DISK-201",
	"CKV_ALI_8":  "TG-ALI-DISK-202",

	"CKV_DIO_1": "TG-DO-SPACES-201",
	"CKV_DIO_4": "TG-DO-FW-201",

	"CKV_GIT_1": "TG-GH-REPO-201",
	"CKV_GIT_3": "TG-GH-REPO-202",
	"CKV_GIT_4": "TG-GH-002", // existing rule already covers plaintext secrets
	"CKV_GIT_5": "TG-GH-BRANCH-201",
	"CKV_GLB_1": "TG-GL-PROJECT-201",

	"CKV_NCP_1":  "TG-NCP-LB-201",
	"CKV_NCP_13": "TG-NCP-LB-202",
	"CKV_NCP_15": "TG-NCP-LB-203",
	"CKV_NCP_12": "TG-NCP-NACL-201",
	"CKV_NCP_2":  "TG-NCP-ACG-201",
	"CKV_NCP_3":  "TG-NCP-ACG-202",
	"CKV_NCP_23": "TG-NCP-IP-201",

	"CKV_OCI_17": "TG-OCI-NET-201", "CKV_OCI_21": "TG-OCI-NET-201",
	"CKV_OCI_18": "TG-OCI-IAM-201",
	"CKV_OCI_23": "TG-OCI-CATALOG-201",

	"CKV_OKTA_1": "TG-OKTA-SIGNON-201",

	"CKV_OPENSTACK_4": "TG-OS-COMPUTE-201",
	"CKV_OPENSTACK_5": "TG-OS-FW-201",

	"CKV_PAN_4":  "TG-PANOS-POLICY-201",
	"CKV_PAN_5":  "TG-PANOS-POLICY-202",
	"CKV_PAN_6":  "TG-PANOS-POLICY-203",
	"CKV_PAN_7":  "TG-PANOS-POLICY-204",
	"CKV_PAN_8":  "TG-PANOS-POLICY-205",
	"CKV_PAN_9":  "TG-PANOS-POLICY-206",
	"CKV_PAN_10": "TG-PANOS-POLICY-207",
	"CKV_PAN_11": "TG-PANOS-IPSEC-201",
	"CKV_PAN_12": "TG-PANOS-IPSEC-202",
	"CKV_PAN_14": "TG-PANOS-ZONE-201",
	"CKV_PAN_15": "TG-PANOS-ZONE-202",

	"CKV_TC_11": "TG-TC-CLB-201",
	"CKV_TC_13": "TG-TC-CVM-201",
	"CKV_TC_4":  "TG-TC-CVM-202",
	"CKV_TC_5":  "TG-TC-CVM-203",
	"CKV_TC_7":  "TG-TC-TKE-201",
	"CKV_TC_8":  "TG-TC-SG-201",

	"CKV_YC_12": "TG-YC-MDB-201",
	"CKV_YC_17": "TG-YC-STORAGE-201",
	"CKV_YC_19": "TG-YC-SG-201", "CKV_YC_20": "TG-YC-SG-201",
	"CKV_YC_24": "TG-YC-IAM-201",
}

func init() {
	for ckv, id := range portedOtherIDs {
		foreignRules[ckv] = append(foreignRules[ckv], id)
	}
}
