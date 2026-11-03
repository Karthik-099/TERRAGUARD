package engine

import (
	"fmt"
	"strconv"
	"strings"
)

// Rules for Google Cloud and Kubernetes resources.
var portedGCP = []Rule{
	// Google Cloud: IAM
	{ID: "TG-GCP-IAM-201", Title: "Resource is shared with allUsers or allAuthenticatedUsers", Severity: Critical, Category: CatSecurity, CWE: "CWE-732",
		Types:       []string{"google_bigquery_table_iam_member", "google_bigquery_table_iam_binding", "google_dataproc_cluster_iam_member", "google_dataproc_cluster_iam_binding", "google_storage_bucket_iam_member", "google_storage_bucket_iam_binding"},
		Remediation: "Grant the role to named users, groups or service accounts; front public APIs with a load balancer that authenticates.",
		Check: func(r *Resource) []Hit {
			// allAuthenticatedUsers is any Google account, which is just as public as allUsers.
			if !contains(gcppMembers(r), "allUsers", "allAuthenticatedUsers") {
				return nil
			}
			sev := Critical
			switch {
			case strings.Contains(r.Type, "pubsub") || strings.Contains(r.Type, "artifact_registry"):
				sev = High
			case strings.Contains(r.Type, "cloud_run") || strings.Contains(r.Type, "cloudfunctions"):
				sev = Medium // often an intended public endpoint
			}
			return []Hit{{Path: gcppMemberPath(r), Sev: sev, Msg: "Anyone on the internet gets this role on the resource."}}
		}},
	{ID: "TG-GCP-IAM-202", Title: "Basic role granted at project, folder or organization level", Severity: High, Category: CatSecurity, CWE: "CWE-269",
		Types:       []string{"google_organization_iam_member", "google_organization_iam_binding", "google_folder_iam_member", "google_folder_iam_binding"}, // project level is TG-GCP-IAM-001
		Remediation: "Replace roles/owner, roles/editor and roles/viewer with predefined roles scoped to the job.",
		Check: func(r *Resource) []Hit {
			role, _ := asString(r.get("role"))
			switch role {
			case "roles/owner", "roles/editor":
				return []Hit{{Path: "role", Msg: role + " grants broad write access to every resource below this level."}}
			case "roles/viewer":
				return []Hit{{Path: "role", Sev: Medium, Msg: "roles/viewer can read nearly every resource below this level."}}
			}
			return nil
		}},
	{ID: "TG-GCP-IAM-203", Title: "Role that can act as service accounts granted to a folder or organization", Severity: High, Category: CatSecurity, CWE: "CWE-269",
		Types:       []string{"google_organization_iam_member", "google_organization_iam_binding", "google_folder_iam_member", "google_folder_iam_binding"},
		Remediation: "Grant impersonation and service agent roles on the specific service account or project that needs them.",
		Check: func(r *Resource) []Hit {
			if role, _ := asString(r.get("role")); gcppImpersonationRoles[role] {
				return []Hit{{Path: "role", Msg: role + " lets the member act as every service account under this node, including privileged ones."}}
			}
			return nil
		}},
	{ID: "TG-GCP-IAM-204", Title: "Default service account granted a folder or organization role", Severity: Medium, Category: CatSecurity, CWE: "CWE-269",
		Types:       []string{"google_organization_iam_member", "google_organization_iam_binding", "google_folder_iam_member", "google_folder_iam_binding"},
		Remediation: "Grant the role to a dedicated service account instead of the Compute Engine or App Engine default account.",
		Check: func(r *Resource) []Hit {
			for _, m := range gcppMembers(r) {
				if strings.HasSuffix(m, "-compute@developer.gserviceaccount.com") || strings.HasSuffix(m, "@appspot.gserviceaccount.com") {
					return []Hit{{Path: gcppMemberPath(r), Msg: "Every VM or App Engine app using " + strings.TrimPrefix(m, "serviceAccount:") + " inherits this role across many projects."}}
				}
			}
			return nil
		}},

	// Google Cloud: firewall
	gcppFirewallRule("TG-GCP-FW-205", 20, "FTP data", Medium),
	gcppFirewallRule("TG-GCP-FW-206", 80, "HTTP", Low),

	// Google Cloud: Cloud SQL

	// Google Cloud: GKE
	{ID: "TG-GCP-GKE-201", Title: "GKE cluster does not enforce network policies", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"google_container_cluster"}, Remediation: `Set datapath_provider = "ADVANCED_DATAPATH" (Dataplane V2) or network_policy { enabled = true }.`,
		Check: func(r *Resource) []Hit {
			// Dataplane V2 and Autopilot always enforce NetworkPolicy, whatever network_policy says.
			if dp, _ := asString(r.get("datapath_provider")); dp == "ADVANCED_DATAPATH" || is(r.get("enable_autopilot"), true) {
				return nil
			}
			if v := r.get("network_policy.enabled"); is(v, true) || isUnknown(v) || isUnknown(r.get("network_policy")) || isUnknown(r.get("datapath_provider")) {
				return nil
			}
			return []Hit{{Path: "network_policy", Msg: "Every pod can reach every other pod; NetworkPolicy objects are ignored."}}
		}},
	{ID: "TG-GCP-GKE-202", Title: "GKE node pool is defined inside the cluster", Severity: Low, Category: CatReliability, CWE: "CWE-710",
		Types: []string{"google_container_cluster"}, Remediation: "Set remove_default_node_pool = true and manage pools with google_container_node_pool.",
		Check: func(r *Resource) []Hit {
			if r.get("node_pool") != nil && notTrue(r.get("remove_default_node_pool")) {
				return []Hit{{Path: "node_pool", Msg: "Inline node pools cannot be removed or replaced without recreating the whole cluster."}}
			}
			return nil
		}},
	{ID: "TG-GCP-GKE-203", Title: "GKE control plane is open to the internet", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"google_container_cluster"}, Remediation: "List only your office, VPN or CI ranges in master_authorized_networks_config, or make the endpoint private.",
		Check: func(r *Resource) []Hit {
			for i, c := range blocksAt(r.get("master_authorized_networks_config"), "cidr_blocks") {
				if v, _ := asString(c["cidr_block"]); worldCIDR(v) {
					return []Hit{{Path: fmt.Sprintf("master_authorized_networks_config.0.cidr_blocks.%d", i), Msg: "The Kubernetes API accepts connections from any IP address."}}
				}
			}
			return nil
		}},
	{ID: "TG-GCP-GKE-204", Title: "GKE cluster has no resource labels", Severity: Info, Category: CatBestPrac, CWE: "CWE-710",
		Types: []string{"google_container_cluster"}, Remediation: "Add resource_labels such as team, env and cost-center.",
		Check: func(r *Resource) []Hit {
			v := r.get("resource_labels")
			if m, ok := v.(map[string]any); v == nil || ok && len(m) == 0 {
				return []Hit{{Path: "resource_labels", Msg: "Cluster costs and ownership cannot be attributed in billing reports."}}
			}
			return nil
		}},
	{ID: "TG-GCP-GKE-205", Title: "GKE Binary Authorization is not enforced", Severity: Medium, Category: CatSecurity, CWE: "CWE-494",
		Types: []string{"google_container_cluster"}, Remediation: `Add binary_authorization { evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE" }.`,
		Check: func(r *Resource) []Hit {
			mode := r.get("binary_authorization.evaluation_mode")
			if s, _ := asString(mode); s == "PROJECT_SINGLETON_POLICY_ENFORCE" || isUnknown(mode) || isUnknown(r.get("binary_authorization")) {
				return nil
			}
			for _, k := range []string{"binary_authorization.enabled", "enable_binary_authorization"} {
				if v := r.get(k); is(v, true) || isUnknown(v) {
					return nil
				}
			}
			return []Hit{{Path: "binary_authorization", Msg: "Any image, signed or not, can be deployed to the cluster."}}
		}},
	{ID: "TG-GCP-GKE-206", Title: "GKE nodes boot without Secure Boot", Severity: Low, Category: CatSecurity, CWE: "CWE-693",
		Types: []string{"google_container_cluster", "google_container_node_pool"}, Remediation: "Set node_config { shielded_instance_config { enable_secure_boot = true } }.",
		Check: func(r *Resource) []Hit {
			nc := r.get("node_config")
			if nc == nil || isUnknown(nc) || isUnknown(r.get("node_config.shielded_instance_config")) {
				return nil // no node_config: the cluster's nodes are defined elsewhere
			}
			if v := r.get("node_config.shielded_instance_config.enable_secure_boot"); !is(v, true) && !isUnknown(v) {
				return []Hit{{Path: "node_config", Msg: "Nodes can boot tampered kernels or drivers (rootkits) undetected."}}
			}
			return nil
		}},

	// Google Cloud: functions, DNS, networking
	{ID: "TG-GCP-NET-201", Title: "Subnet has Private Google Access off", Severity: Low, Category: CatSecurity, CWE: "CWE-668",
		Types: []string{"google_compute_subnetwork"}, Remediation: "Set private_ip_google_access = true.",
		Check: func(r *Resource) []Hit {
			if gcppProxySubnet(r) {
				return nil
			}
			if notTrue(r.get("private_ip_google_access")) {
				return []Hit{{Path: "private_ip_google_access", Msg: "VMs without external IPs cannot reach Google APIs, which pushes teams to add public IPs.", Fix: fix(true, "Enable Private Google Access", "private_ip_google_access")}}
			}
			return nil
		}},
	{ID: "TG-GCP-NET-202", Title: "Dual-stack subnet has IPv6 Private Google Access off", Severity: Low, Category: CatSecurity, CWE: "CWE-668",
		Types: []string{"google_compute_subnetwork"}, Remediation: `Set private_ipv6_google_access = "ENABLE_OUTBOUND_VM_ACCESS_TO_GOOGLE".`,
		Check: func(r *Resource) []Hit {
			if st, _ := asString(r.get("stack_type")); st != "IPV4_IPV6" || gcppProxySubnet(r) || isUnknown(r.get("private_ipv6_google_access")) {
				return nil
			}
			if v, _ := asString(r.get("private_ipv6_google_access")); v != "ENABLE_OUTBOUND_VM_ACCESS_TO_GOOGLE" && v != "ENABLE_BIDIRECTIONAL_ACCESS_TO_GOOGLE" {
				return []Hit{{Path: "private_ipv6_google_access", Msg: "IPv6-only workloads cannot reach Google APIs privately.", Fix: fix("ENABLE_OUTBOUND_VM_ACCESS_TO_GOOGLE", "Enable IPv6 Private Google Access", "private_ipv6_google_access")}}
			}
			return nil
		}},
	{ID: "TG-GCP-ARMOR-201", Title: "Cloud Armor policy does not block Log4Shell", Severity: Medium, Category: CatSecurity, CWE: "CWE-917",
		Types: []string{"google_compute_security_policy"}, Remediation: `Add a rule with action = "deny(403)" matching evaluatePreconfiguredWaf('cve-canary'), not in preview.`,
		Check: func(r *Resource) []Hit {
			rules := r.blocks("rule")
			if len(rules) == 0 {
				return nil // rules may live in google_compute_security_policy_rule resources
			}
			for _, rule := range rules {
				expr := get(rule, "match.expr.expression")
				if isUnknown(expr) || isUnknown(rule["match"]) {
					return nil
				}
				if s, _ := asString(expr); s == "evaluatePreconfiguredWaf('cve-canary')" || s == "evaluatePreconfiguredExpr('cve-canary')" {
					if a, _ := asString(rule["action"]); a == "allow" || is(rule["preview"], true) {
						return []Hit{{Path: "rule", Msg: "The CVE-2021-44228 rule is in preview or allows matches, so Log4j lookups reach the backends."}}
					}
					return nil
				}
			}
			return []Hit{{Path: "rule", Msg: "No rule blocks CVE-2021-44228 (Log4Shell) JNDI lookups."}}
		}},

	// Google Cloud: Compute Engine
	{ID: "TG-GCP-VM-201", Title: "VM runs as the Compute Engine default service account", Severity: Medium, Category: CatSecurity, CWE: "CWE-269",
		Types: []string{"google_compute_instance", "google_compute_instance_template", "google_compute_instance_from_template"}, Remediation: "Create a dedicated service account with only the roles the workload needs and set service_account { email = ... }.",
		Check: func(r *Resource) []Hit {
			if n, _ := asString(r.get("name")); strings.HasPrefix(n, "gke-") {
				return nil // GKE-managed nodes
			}
			sa := r.get("service_account")
			if sa == nil || isUnknown(sa) || isUnknown(r.get("service_account.email")) {
				return nil
			}
			if e, ok := asString(r.get("service_account.email")); !ok || gcppDefaultComputeSA(e) {
				return []Hit{{Path: "service_account", Msg: "The default account is shared by every VM in the project and often holds Editor."}}
			}
			return nil
		}},
	{ID: "TG-GCP-VM-202", Title: "VM boot disk is not encrypted with a customer key", Severity: Low, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"google_compute_instance"}, Remediation: "Set boot_disk { kms_key_self_link = google_kms_crypto_key.x.id } (or disk_encryption_key_raw).",
		Check: func(r *Resource) []Hit {
			if isUnknown(r.get("boot_disk")) {
				return nil
			}
			if r.get("boot_disk.kms_key_self_link") == nil && r.get("boot_disk.disk_encryption_key_raw") == nil {
				return []Hit{{Path: "boot_disk", Msg: "The disk uses Google-managed keys you cannot revoke or audit."}}
			}
			return nil
		}},
	{ID: "TG-GCP-VM-203", Title: "VM turns off Shielded VM protections", Severity: Medium, Category: CatSecurity, CWE: "CWE-693",
		Types: []string{"google_compute_instance", "google_compute_instance_template", "google_compute_instance_from_template"}, Remediation: "Set shielded_instance_config { enable_vtpm = true, enable_integrity_monitoring = true }.",
		Check: func(r *Resource) []Hit {
			// GCE enables vTPM and integrity monitoring by default on shielded images.
			var hits []Hit
			for _, k := range []string{"enable_vtpm", "enable_integrity_monitoring"} {
				if is(r.get("shielded_instance_config."+k), false) {
					hits = append(hits, Hit{Path: "shielded_instance_config", Msg: k + " = false: boot-level tampering goes undetected.", Fix: fix(true, "Turn on "+k, "shielded_instance_config", k)})
				}
			}
			return hits
		}},
	{ID: "TG-GCP-KMS-201", Title: "Cloud KMS key is not rotated every 90 days", Severity: Medium, Category: CatSecurity, CWE: "CWE-324",
		Types: []string{"google_kms_crypto_key"}, Remediation: `Set rotation_period = "7776000s" (90 days) or shorter.`,
		Check: func(r *Resource) []Hit {
			if p, _ := asString(r.get("purpose")); strings.HasPrefix(p, "ASYMMETRIC") || isUnknown(r.get("rotation_period")) {
				return nil // asymmetric keys cannot rotate automatically
			}
			v := r.get("rotation_period")
			if v == nil {
				return nil // TG-GCP-KMS-001 reports a key with no rotation at all
			}
			s, _ := asString(v)
			if secs, err := strconv.ParseFloat(strings.TrimSuffix(s, "s"), 64); err != nil || secs < 86400 || secs > 90*86400 {
				return []Hit{{Path: "rotation_period", Msg: fmt.Sprintf("rotation_period %q is outside 1 to 90 days.", s)}}
			}
			return nil
		}},

	// Google Cloud: storage, data
	{ID: "TG-GCP-GCS-201", Title: "Bucket has no access logging", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"google_storage_bucket"}, Remediation: "Add logging { log_bucket = google_storage_bucket.logs.name }.",
		Check: func(r *Resource) []Hit {
			if v := r.get("logging.log_bucket"); v == nil && !isUnknown(r.get("logging")) || v == "" {
				return []Hit{{Path: "logging", Msg: "Object reads and writes are not recorded for investigation."}}
			}
			return nil
		}},
	{ID: "TG-GCP-GCS-202", Title: "Bucket writes access logs to itself", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"google_storage_bucket"}, Remediation: "Send access logs to a separate bucket.",
		Check: func(r *Resource) []Hit {
			lb, ok1 := asString(r.get("logging.log_bucket"))
			name, ok2 := asString(r.get("name"))
			if ok1 && ok2 && lb == name {
				return []Hit{{Path: "logging", Msg: "Every log write is itself logged, and anyone who can delete objects can erase the trail."}}
			}
			return nil
		}},
	{ID: "TG-GCP-VERTEX-201", Title: "Vertex AI notebook has a public IP", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"google_notebooks_instance"}, Remediation: "Set no_public_ip = true and reach it through IAP or a private network.",
		Check: func(r *Resource) []Hit {
			if notTrue(r.get("no_public_ip")) {
				return []Hit{{Path: "no_public_ip", Msg: "The notebook VM, with its data and credentials, is directly reachable from the internet.", Fix: fix(true, "Remove the public IP", "no_public_ip")}}
			}
			return nil
		}},

	// Kubernetes: workloads
	gcppContainerRule("TG-K8S-POD-201", "Container has no CPU request", Low, CatReliability, "CWE-770", "Set resources { requests = { cpu = \"250m\" } }.",
		func(c map[string]any) string {
			return gcppIf(gcppAbsent(c, "resources.requests.cpu"), "The scheduler cannot place the pod sensibly and it can be starved under load.")
		}),
	gcppContainerRule("TG-K8S-POD-202", "Container has no CPU limit", Low, CatReliability, "CWE-770", "Set resources { limits = { cpu = \"1\" } }.",
		func(c map[string]any) string {
			return gcppIf(gcppAbsent(c, "resources.limits.cpu"), "One busy container can take all CPU on the node.")
		}),
	gcppContainerRule("TG-K8S-POD-204", "Container has no memory request", Low, CatReliability, "CWE-770", "Set resources { requests = { memory = \"256Mi\" } }.",
		func(c map[string]any) string {
			return gcppIf(gcppAbsent(c, "resources.requests.memory"), "The pod can land on a node without room for it and be evicted first.")
		}),
	gcppContainerRule("TG-K8S-POD-205", "Image pull policy is not Always", Low, CatSecurity, "CWE-829", "Set image_pull_policy = \"Always\" or pin the image by digest.",
		func(c map[string]any) string {
			p, img := c["image_pull_policy"], c["image"]
			if isUnknown(p) || isUnknown(img) {
				return ""
			}
			if p == nil {
				s, _ := asString(img)
				// Kubernetes defaults to Always for :latest or untagged images; digests are immutable.
				if s == "" || strings.Contains(s, "@") || strings.Contains(s, "latest") || !strings.Contains(s[strings.LastIndex(s, "/")+1:], ":") {
					return ""
				}
				return "A cached image is reused without checking the registry or the pull secret."
			}
			return gcppIf(p != "Always", "A cached image is reused without checking the registry or the pull secret.")
		}),
	gcppContainerRule("TG-K8S-POD-206", "git-sync container lets the git binary be overridden", High, CatSecurity, "CWE-78", "Remove the GITSYNC_GIT environment variable.",
		func(c map[string]any) string {
			for _, e := range blocksAt(c, "env") {
				if n, _ := asString(e["name"]); n == "GITSYNC_GIT" {
					return "GITSYNC_GIT runs an arbitrary binary in place of git, a known route to code execution."
				}
			}
			return ""
		}),
	gcppContainerRule("TG-K8S-POD-213", "Container adds Linux capabilities", Medium, CatSecurity, "CWE-250", "Remove capabilities.add; grant a single capability only when it is required.",
		func(c map[string]any) string {
			add := asStrings(get(c, "security_context.capabilities.add"))
			return gcppIf(len(add) > 0, "Adds "+strings.Join(add, ", ")+", widening what a compromised process can do on the node.")
		}),
	gcppContainerRule("TG-K8S-POD-214", "Container binds a host port", Low, CatSecurity, "CWE-668", "Remove host_port and expose the pod through a Service.",
		func(c map[string]any) string {
			for _, p := range blocksAt(c, "port") {
				if _, ok := p["host_port"]; ok {
					return "The port opens on the node itself, bypassing Service and network policy controls and limiting scheduling."
				}
			}
			return ""
		}),
	gcppContainerRule("TG-K8S-POD-217", "Container has no security context", Low, CatSecurity, "CWE-693", "Add security_context { run_as_non_root = true, allow_privilege_escalation = false, read_only_root_filesystem = true }.",
		func(c map[string]any) string {
			return gcppIf(c["security_context"] == nil, "The container runs with the runtime's permissive defaults.")
		}),
	{ID: "TG-K8S-POD-218", Title: "Tiller (Helm v2) is deployed", Severity: High, Category: CatSecurity, CWE: "CWE-306",
		Types: k8sWorkloads, Remediation: "Remove Tiller and move to Helm 3, which has no in-cluster component.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			walkMaps(r.Attrs, "", func(p string, m map[string]any) {
				if gcppTillerLabels(get(m, "labels")) {
					hits = append(hits, Hit{Path: p, Msg: "Tiller exposes an unauthenticated gRPC API that usually runs with cluster-admin."})
				}
				if img, _ := asString(m["image"]); tillerImage(img) {
					hits = append(hits, Hit{Path: join(p, "image"), Msg: "Tiller exposes an unauthenticated gRPC API that usually runs with cluster-admin."})
				}
			})
			return hits[:min(len(hits), 1)]
		}},
	gcppContainerRule("TG-K8S-POD-220", "Container does not drop all capabilities", Low, CatSecurity, "CWE-250", "Set security_context { capabilities { drop = [\"ALL\"] } } and add back only what is needed.",
		func(c map[string]any) string {
			// Only containers that declare a security_context are judged.
			if c["security_context"] == nil || isUnknown(c["security_context"]) || isUnknown(get(c, "security_context.capabilities")) {
				return ""
			}
			d := get(c, "security_context.capabilities.drop")
			return gcppIf(!isUnknown(d) && !contains(gcppUpper(asStrings(d)), "ALL"), "The container keeps the runtime's default capabilities, such as NET_RAW and CHOWN.")
		}),
	gcppContainerRule("TG-K8S-POD-221", "Image is not pinned by digest", Info, CatSecurity, "CWE-829", "Reference the image as name@sha256:<digest>.",
		func(c map[string]any) string {
			img, ok := asString(c["image"])
			return gcppIf(ok && !strings.Contains(img, "@"), "A tag can be moved to a different image between deploys.")
		}),
	gcppContainerRule("TG-K8S-POD-222", "Container has no liveness probe", Low, CatReliability, "CWE-754", "Add a liveness_probe (http_get, tcp_socket or exec).",
		func(c map[string]any) string {
			// No probes at all is TG-K8S-010.
			return gcppIf(c["liveness_probe"] == nil && c["readiness_probe"] != nil, "A hung process keeps running and is never restarted.")
		}),
	gcppContainerRule("TG-K8S-POD-223", "Container has no readiness probe", Low, CatReliability, "CWE-754", "Add a readiness_probe so traffic waits until the app can serve.",
		func(c map[string]any) string {
			// No probes at all is TG-K8S-010.
			return gcppIf(c["readiness_probe"] == nil && c["liveness_probe"] != nil, "Traffic is sent before the app is ready and during failures.")
		}),

	// Kubernetes: PodSecurityPolicy
	{ID: "TG-K8S-PSP-201", Title: "PodSecurityPolicy admits privileged containers", Severity: High, Category: CatSecurity, CWE: "CWE-250",
		Types: []string{"kubernetes_pod_security_policy"}, Remediation: "Set spec { privileged = false }.",
		Check: func(r *Resource) []Hit {
			if is(r.get("spec.privileged"), true) {
				return []Hit{{Path: "spec", Msg: "Pods under this policy can get full access to the node.", Fix: fix(false, "Disallow privileged pods", "spec", "privileged")}}
			}
			return nil
		}},
	{ID: "TG-K8S-PSP-202", Title: "PodSecurityPolicy admits root containers", Severity: Medium, Category: CatSecurity, CWE: "CWE-250",
		Types: []string{"kubernetes_pod_security_policy"}, Remediation: `Set run_as_user { rule = "MustRunAsNonRoot" } (or MustRunAs with ranges starting above 0).`,
		Check: func(r *Resource) []Hit {
			ru := r.get("spec.run_as_user.rule")
			if isUnknown(ru) || isUnknown(r.get("spec")) {
				return nil
			}
			switch s, _ := asString(ru); s {
			case "MustRunAsNonRoot":
				return nil
			case "MustRunAs":
				ranges := blocksAt(r.get("spec.run_as_user"), "range")
				safe := len(ranges) > 0
				for _, rg := range ranges {
					if isUnknown(rg["min"]) {
						return nil
					}
					if m, ok := asFloat(rg["min"]); !ok || m == 0 {
						safe = false
					}
				}
				if safe {
					return nil
				}
			}
			return []Hit{{Path: "spec", Msg: "Pods under this policy can run as UID 0."}}
		}},
	{ID: "TG-K8S-PSP-203", Title: "PodSecurityPolicy does not drop NET_RAW", Severity: Low, Category: CatSecurity, CWE: "CWE-250",
		Types: []string{"kubernetes_pod_security_policy"}, Remediation: `Set required_drop_capabilities = ["ALL"].`,
		Check: func(r *Resource) []Hit {
			d := r.get("spec.required_drop_capabilities")
			if isUnknown(d) || isUnknown(r.get("spec")) || contains(gcppUpper(asStrings(d)), "ALL", "NET_RAW") {
				return nil
			}
			return []Hit{{Path: "spec", Msg: "Pods keep NET_RAW and can spoof packets on the pod network."}}
		}},
	{ID: "TG-K8S-PSP-204", Title: "PodSecurityPolicy sets no default seccomp profile", Severity: Low, Category: CatSecurity, CWE: "CWE-693",
		Types: []string{"kubernetes_pod_security_policy"}, Remediation: `Annotate seccomp.security.alpha.kubernetes.io/defaultProfileName = "runtime/default".`,
		Check: func(r *Resource) []Hit {
			a := r.get("metadata.annotations")
			if isUnknown(a) || isUnknown(get(a, "seccomp.security.alpha.kubernetes.io/defaultProfileName")) {
				return nil
			}
			if m, ok := a.(map[string]any); ok {
				for k, v := range m {
					if strings.Join(strings.Fields(k), "") == "seccomp.security.alpha.kubernetes.io/defaultProfileName" {
						if s, _ := asString(v); strings.Contains(s, "runtime/default") || strings.Contains(s, "docker/default") {
							return nil
						}
					}
				}
			}
			return []Hit{{Path: "metadata", Msg: "Pods run with every syscall allowed unless they ask for a profile."}}
		}},
	{ID: "TG-K8S-PSP-205", Title: "PodSecurityPolicy requires no capabilities to be dropped", Severity: Low, Category: CatSecurity, CWE: "CWE-250",
		Types: []string{"kubernetes_pod_security_policy"}, Remediation: `Set required_drop_capabilities = ["ALL"].`,
		Check: func(r *Resource) []Hit {
			d := r.get("spec.required_drop_capabilities")
			if isUnknown(d) || isUnknown(r.get("spec")) || len(asStrings(d)) > 0 {
				return nil
			}
			return []Hit{{Path: "spec", Msg: "Pods keep every default Linux capability."}}
		}},

	// Kubernetes: namespaces, service accounts, RBAC, services
	{ID: "TG-K8S-NS-201", Title: "Object is created in the default namespace", Severity: Low, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"kubernetes_secret", "kubernetes_secret_v1", "kubernetes_config_map", "kubernetes_config_map_v1", "kubernetes_service_account",
			"kubernetes_service_account_v1", "kubernetes_role_binding", "kubernetes_role_binding_v1", "kubernetes_ingress", "kubernetes_ingress_v1",
			"kubernetes_replication_controller", "kubernetes_replication_controller_v1"},
		Remediation: "Set metadata { namespace = \"<app namespace>\" }; TG-K8S-014 covers workloads and services.",
		Check: func(r *Resource) []Hit {
			ns := r.get("metadata.namespace")
			if s, _ := asString(ns); (ns == nil && gcppKnown(r.Attrs, "metadata.namespace")) || s == "default" {
				return []Hit{{Path: "metadata", Msg: "Objects in the shared default namespace are hard to isolate with RBAC and network policies."}}
			}
			return nil
		}},
	{ID: "TG-K8S-SA-201", Title: "Default service account mounts its token", Severity: Low, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"kubernetes_service_account", "kubernetes_service_account_v1"}, Remediation: "Set automount_service_account_token = false on the default service account.",
		Check: func(r *Resource) []Hit {
			if n, _ := asString(r.get("metadata.name")); n == "default" && !is(r.get("automount_service_account_token"), false) && !isUnknown(r.get("automount_service_account_token")) {
				return []Hit{{Path: "automount_service_account_token", Msg: "Every pod that names no account gets an API token it probably does not need.", Fix: fix(false, "Stop mounting the token", "automount_service_account_token")}}
			}
			return nil
		}},
	{ID: "TG-K8S-RBAC-201", Title: "Role is bound to the default service account", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"kubernetes_role_binding", "kubernetes_role_binding_v1", "kubernetes_cluster_role_binding", "kubernetes_cluster_role_binding_v1"}, Remediation: "Bind the role to a dedicated service account used only by the workload that needs it.",
		Check: func(r *Resource) []Hit {
			for i, s := range r.blocks("subject") {
				k, _ := asString(s["kind"])
				n, _ := asString(s["name"])
				if k == "ServiceAccount" && n == "default" {
					return []Hit{{Path: fmt.Sprintf("subject.%d", i), Msg: "Every pod in the namespace that names no account inherits these permissions."}}
				}
			}
			return nil
		}},
	{ID: "TG-K8S-SVC-201", Title: "Tiller (Helm v2) service is exposed", Severity: Medium, Category: CatSecurity, CWE: "CWE-306",
		Types: []string{"kubernetes_service", "kubernetes_service_v1"}, Remediation: "Delete the Tiller service and move to Helm 3.",
		Check: func(r *Resource) []Hit {
			if gcppTillerLabels(r.get("metadata.labels")) {
				return []Hit{{Path: "metadata", Msg: "The service exposes Tiller's unauthenticated gRPC API."}}
			}
			if m, ok := r.get("spec.selector").(map[string]any); ok {
				for _, v := range m {
					if s, _ := asString(v); strings.EqualFold(s, "tiller") {
						return []Hit{{Path: "spec", Msg: "The service exposes Tiller's unauthenticated gRPC API."}}
					}
				}
			}
			return nil
		}},
}

// portedGCPIDs maps foreign check IDs to these rules, so existing skip comments keep working.
var portedGCPIDs = map[string]string{
	"CKV_GCP_100": "TG-GCP-IAM-201", "CKV_GCP_101": "TG-GCP-IAM-201", "CKV_GCP_102": "TG-GCP-IAM-201", "CKV_GCP_107": "TG-GCP-IAM-201",
	"CKV_GCP_98": "TG-GCP-IAM-201", "CKV_GCP_99": "TG-GCP-IAM-201", "CKV_GCP_28": "TG-GCP-IAM-201",
	"CKV_GCP_115": "TG-GCP-IAM-202", "CKV_GCP_116": "TG-GCP-IAM-202", "CKV_GCP_117": "TG-GCP-IAM-202",
	"CKV_GCP_44": "TG-GCP-IAM-203", "CKV_GCP_45": "TG-GCP-IAM-203", "CKV_GCP_47": "TG-GCP-IAM-204", "CKV_GCP_48": "TG-GCP-IAM-204",
	"CKV_GCP_2": "TG-GCP-FW-001", "CKV_GCP_3": "TG-GCP-FW-001", "CKV_GCP_88": "TG-GCP-FW-001", "CKV_GCP_75": "TG-GCP-FW-001",
	"CKV_GCP_77": "TG-GCP-FW-205", "CKV_GCP_106": "TG-GCP-FW-206",
	"CKV_GCP_11": "TG-GCP-SQL-001", "CKV_GCP_6": "TG-GCP-SQL-001",
	"CKV_GCP_12": "TG-GCP-GKE-201", "CKV_GCP_123": "TG-GCP-GKE-202", "CKV_GCP_18": "TG-GCP-GKE-203", "CKV_GCP_21": "TG-GCP-GKE-204",
	"CKV_GCP_66": "TG-GCP-GKE-205", "CKV_GCP_68": "TG-GCP-GKE-206",
	"CKV_GCP_124": "TG-GCP-CF-001", "CKV_GCP_74": "TG-GCP-NET-201", "CKV_GCP_76": "TG-GCP-NET-202", "CKV_GCP_73": "TG-GCP-ARMOR-201",
	"CKV_GCP_30": "TG-GCP-VM-201", "CKV_GCP_38": "TG-GCP-VM-202", "CKV_GCP_39": "TG-GCP-VM-203", "CKV_GCP_43": "TG-GCP-KMS-201",
	"CKV_GCP_62": "TG-GCP-GCS-201", "CKV_GCP_63": "TG-GCP-GCS-202", "CKV_GCP_89": "TG-GCP-VERTEX-201",
	// Existing rules that already cover the control.
	"CKV_GCP_15": "TG-GCP-BQ-001", "CKV_GCP_16": "TG-DNS-002", "CKV_GCP_17": "TG-GCP-DNS-001", "CKV_GCP_26": "TG-GCP-NET-001",
	"CKV_GCP_31": "TG-GCP-VM-001", "CKV_GCP_35": "TG-GCP-VM-002", "CKV_GCP_94": "TG-GCP-DATAFLOW-001",
	"CKV_K8S_14": "TG-K8S-002", "CKV_K8S_21": "TG-K8S-014",

	"CKV_K8S_10": "TG-K8S-POD-201", "CKV_K8S_11": "TG-K8S-POD-202", "CKV_K8S_12": "TG-K8S-009", "CKV_K8S_13": "TG-K8S-POD-204",
	"CKV_K8S_15": "TG-K8S-POD-205", "CKV_K8S_159": "TG-K8S-POD-206", "CKV_K8S_16": "TG-K8S-001", "CKV_K8S_17": "TG-K8S-001",
	"CKV_K8S_18": "TG-K8S-001", "CKV_K8S_19": "TG-K8S-001", "CKV_K8S_20": "TG-K8S-001", "CKV_K8S_22": "TG-K8S-017",
	"CKV_K8S_25": "TG-K8S-POD-213", "CKV_K8S_26": "TG-K8S-POD-214", "CKV_K8S_28": "TG-K8S-POD-217", "CKV_K8S_29": "TG-K8S-POD-217",
	"CKV_K8S_30": "TG-K8S-POD-217", "CKV_K8S_34": "TG-K8S-POD-218", "CKV_K8S_35": "TG-K8S-016", "CKV_K8S_37": "TG-K8S-POD-220",
	"CKV_K8S_43": "TG-K8S-POD-221", "CKV_K8S_8": "TG-K8S-POD-222", "CKV_K8S_9": "TG-K8S-POD-223",
	"CKV_K8S_2": "TG-K8S-PSP-201", "CKV_K8S_6": "TG-K8S-PSP-202", "CKV_K8S_7": "TG-K8S-PSP-203", "CKV_K8S_32": "TG-K8S-PSP-204",
	"CKV_K8S_36": "TG-K8S-PSP-205", "CKV_K8S_41": "TG-K8S-SA-201", "CKV_K8S_42": "TG-K8S-RBAC-201", "CKV_K8S_44": "TG-K8S-SVC-201",
}

func init() {
	for ckv, id := range portedGCPIDs {
		foreignRules[ckv] = append(foreignRules[ckv], id)
	}
	foreignRules["CKV_K8S_21"] = append(foreignRules["CKV_K8S_21"], "TG-K8S-NS-201") // TG-K8S-014 covers the workload types
}

// Roles that let the holder act as service accounts or service agents; owner and editor are TG-GCP-IAM-202.
var gcppImpersonationRoles = map[string]bool{}

func init() {
	for _, r := range strings.Fields(`roles/iam.securityAdmin roles/iam.serviceAccountAdmin roles/iam.serviceAccountKeyAdmin
		roles/iam.serviceAccountOpenIdTokenCreator roles/iam.workloadIdentityUser
		roles/dataflow.developer roles/dataflow.admin roles/deploymentmanager.editor roles/cloudbuild.builds.editor roles/cloudbuild.builds.builder
		roles/composer.worker roles/run.sourceDeveloper roles/assuredoss.admin roles/securitycenter.admin roles/backupdr.computeEngineOperator
		roles/dataproc.hubAgent roles/krmapihosting.anthosApiEndpointServiceAgent`) {
		gcppImpersonationRoles[r] = true
	}
}

func gcppMembers(r *Resource) []string {
	return append(asStrings(r.get("member")), asStrings(r.get("members"))...)
}

func gcppMemberPath(r *Resource) string {
	if r.get("members") != nil {
		return "members"
	}
	return "member"
}

func gcppIf(cond bool, msg string) string {
	if cond {
		return msg
	}
	return ""
}

func gcppUpper(l []string) []string {
	for i := range l {
		l[i] = strings.ToUpper(l[i])
	}
	return l
}

// gcppAbsent reports a path that is missing, but not one hidden behind an unknown value.
func gcppAbsent(v any, path string) bool { return gcppKnown(v, path) && get(v, path) == nil }

// gcppKnown reports that neither the value at path nor any parent is unknown.
func gcppKnown(v any, path string) bool {
	segs := strings.Split(path, ".")
	for i := range segs {
		if isUnknown(get(v, strings.Join(segs[:i+1], "."))) {
			return false
		}
	}
	return true
}

func gcppDefaultComputeSA(email string) bool {
	user, ok := strings.CutSuffix(email, "-compute@developer.gserviceaccount.com")
	_, err := strconv.Atoi(user)
	return ok && err == nil
}

// gcppProxySubnet: proxy-only subnets carry no VM traffic, so flow and access settings do not apply.
func gcppProxySubnet(r *Resource) bool {
	p, _ := asString(r.get("purpose"))
	return p == "INTERNAL_HTTPS_LOAD_BALANCER" || p == "REGIONAL_MANAGED_PROXY" || p == "GLOBAL_MANAGED_PROXY"
}

func gcppTillerLabels(v any) bool {
	app, _ := asString(get(v, "app"))
	name, _ := asString(get(v, "name"))
	return app == "helm" || name == "tiller"
}

// gcppFirewallRule flags an ingress rule that opens port to 0.0.0.0/0 or ::/0.
func gcppFirewallRule(id string, port int, svc string, sev Severity) Rule {
	return Rule{ID: id, Title: fmt.Sprintf("Firewall opens port %d (%s) to the internet", port, svc), Severity: sev, Category: CatSecurity, CWE: "CWE-284",
		Types:       []string{"google_compute_firewall"},
		Remediation: fmt.Sprintf("Limit source_ranges for port %d to known networks; for admin access use IAP TCP forwarding (35.235.240.0/20).", port),
		Check: func(r *Resource) []Hit {
			if d, _ := asString(r.get("direction")); d == "EGRESS" || is(r.get("disabled"), true) || !anyWorld(r.get("source_ranges")) {
				return nil
			}
			for i, a := range r.blocks("allow") {
				proto, _ := asString(a["protocol"])
				ports := a["ports"]
				// No ports or protocol all is reported by TG-GCP-FW-001 as all ports open.
				if isUnknown(ports) || proto == "all" || len(asStrings(ports)) == 0 {
					continue
				}
				if gcppPortIn(asStrings(ports), port) {
					return []Hit{{Path: fmt.Sprintf("allow.%d", i), Msg: fmt.Sprintf("Anyone on the internet can reach %s on port %d of the targeted VMs.", svc, port)}}
				}
			}
			return nil
		}}
}

func gcppPortIn(ports []string, port int) bool {
	for _, p := range ports {
		lo, hi, rng := strings.Cut(p, "-")
		if !rng {
			hi = lo
		}
		l, err1 := strconv.Atoi(strings.TrimSpace(lo))
		h, err2 := strconv.Atoi(strings.TrimSpace(hi))
		if err1 == nil && err2 == nil && l <= port && port <= h {
			return true
		}
	}
	return false
}

// gcppContainerRule runs check on every container of a workload; a non-empty result is a finding.
func gcppContainerRule(id, title string, sev Severity, cat, cwe, rem string, check func(c map[string]any) string) Rule {
	return Rule{ID: id, Title: title, Severity: sev, Category: cat, CWE: cwe, Types: k8sWorkloads, Remediation: rem,
		Check: func(r *Resource) []Hit {
			var hits []Hit
			forEachPodSpec(r.Attrs, func(p string, spec map[string]any) {
				for _, kind := range []string{"container", "init_container"} {
					for i, c := range blocksAt(spec, kind) {
						if msg := check(c); msg != "" {
							name, _ := asString(c["name"])
							hits = append(hits, Hit{Path: join(p, kind+"."+strconv.Itoa(i)), Msg: strings.TrimSpace("Container " + name + ": " + msg)})
						}
					}
				}
			})
			return hits
		}}
}

// gcppStripIdx turns "spec.0.template.0.spec.0" into "spec.template.spec" for a Fix path.
func gcppStripIdx(p string) string {
	var out []string
	for _, s := range strings.Split(p, ".") {
		if _, err := strconv.Atoi(s); err != nil {
			out = append(out, s)
		}
	}
	return strings.Join(out, ".")
}

// tillerImage is true for the Helm 2 Tiller image (gcr.io/kubernetes-helm/tiller:v2.16), not names that merely contain it.
func tillerImage(img string) bool {
	n := img[strings.LastIndex(img, "/")+1:]
	n, _, _ = strings.Cut(n, "@")
	n, _, _ = strings.Cut(n, ":")
	return n == "tiller"
}
