package engine

import (
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Rules for Azure resources.
var portedAzure = []Rule{
	// Virtual machines and disks
	{ID: "TG-AZ-VM-201", Title: "Linux VM allows SSH password login", Severity: High, Category: CatSecurity, CWE: "CWE-287",
		Types: []string{"azurerm_virtual_machine"}, // azurerm_linux_virtual_machine is TG-AZ-VM-001 Remediation: "Set disable_password_authentication = true and log in with an SSH key (admin_ssh_key or ssh_keys).",
		Check: func(r *Resource) []Hit {
			path := "disable_password_authentication"
			if r.Type == "azurerm_virtual_machine" {
				path = "os_profile_linux_config.disable_password_authentication"
			}
			if is(r.get(path), false) {
				return []Hit{{Path: path, Msg: "Anyone who guesses or reuses the admin password can log in over SSH."}}
			}
			return nil
		}},
	{ID: "TG-AZ-VM-202", Title: "VM custom_data contains a credential", Severity: High, Category: CatSecurity, CWE: "CWE-798",
		Types: []string{"azurerm_virtual_machine", "azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine", "azurerm_linux_virtual_machine_scale_set", "azurerm_windows_virtual_machine_scale_set"}, Remediation: "Fetch secrets at boot from Key Vault with the VM's managed identity instead of embedding them in custom_data.",
		Check: func(r *Resource) []Hit {
			path := "custom_data"
			if r.Type == "azurerm_virtual_machine" {
				path = "os_profile.custom_data"
			}
			// An all-zero GUID is not a credential; only real key formats and secret assignments match.
			if s, _ := asString(r.get(path)); azpHasCredential(s) {
				return []Hit{{Path: path, Msg: "custom_data is readable by anyone with read access to the VM and is kept in state."}}
			}
			return nil
		}},
	{ID: "TG-AZ-VM-203", Title: "VM uses unmanaged VHD disks", Severity: Low, Category: CatBestPrac, CWE: "CWE-1188",
		Types: []string{"azurerm_virtual_machine", "azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine"}, Remediation: "Use managed disks (managed_disk_type) instead of vhd_uri page blobs.",
		Check: func(r *Resource) []Hit {
			for _, b := range []string{"storage_os_disk", "storage_data_disk"} {
				for _, d := range r.blocks(b) {
					if d["vhd_uri"] != nil {
						return []Hit{{Path: b, Msg: "The disk lives in a storage account blob, outside managed-disk encryption, RBAC and availability guarantees."}}
					}
				}
			}
			return nil
		}},
	{ID: "TG-AZ-VM-204", Title: "Scale set does not patch its OS image automatically", Severity: Low, Category: CatSecurity, CWE: "CWE-1104",
		Types: []string{"azurerm_virtual_machine_scale_set"}, Remediation: "Set automatic_os_upgrade = true and, on Windows, os_profile_windows_config { enable_automatic_upgrades = true }.",
		Check: func(r *Resource) []Hit {
			if notTrue(r.get("automatic_os_upgrade")) {
				return []Hit{{Path: "automatic_os_upgrade", Msg: "Instances keep running the original image until someone rolls them by hand."}}
			}
			if w := r.blocks("os_profile_windows_config"); len(w) > 0 && notTrue(w[0]["enable_automatic_upgrades"]) {
				return []Hit{{Path: "os_profile_windows_config", Msg: "Windows Update is off on the scale set instances."}}
			}
			return nil
		}},
	{ID: "TG-AZ-DISK-201", Title: "Managed disk encryption is turned off", Severity: Medium, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"azurerm_managed_disk"}, Remediation: "Remove encryption_settings { enabled = false } or set disk_encryption_set_id for customer-managed keys.",
		Check: func(r *Resource) []Hit {
			if r.get("disk_encryption_set_id") == nil && is(r.get("encryption_settings.enabled"), false) {
				return []Hit{{Path: "encryption_settings", Msg: "Azure Disk Encryption is explicitly disabled for this disk.", Fix: fix(true, "Enable disk encryption", "encryption_settings", "enabled")}}
			}
			return nil
		}},

	// App Service and Functions
	{ID: "TG-AZ-APP-201", Title: "App Service built-in authentication is off", Severity: Low, Category: CatSecurity, CWE: "CWE-306",
		Types: azpWebApps, Remediation: "Enable auth_settings_v2 { auth_enabled = true } (or auth_settings { enabled = true }) with an identity provider, unless the app authenticates users itself.",
		Check: func(r *Resource) []Hit {
			v1, v2 := r.get("auth_settings.enabled"), r.get("auth_settings_v2.auth_enabled")
			if isUnknown(v1) || isUnknown(v2) || is(v1, true) || is(v2, true) {
				return nil
			}
			return []Hit{{Path: "auth_settings", Msg: "Requests reach the app without the platform checking who is calling."}}
		}},
	{ID: "TG-AZ-APP-203", Title: "App Service does not require client certificates", Severity: Low, Category: CatSecurity, CWE: "CWE-295",
		Types: azpWebApps, Remediation: "Set client_certificate_enabled = true (client_cert_enabled on azurerm_app_service) when callers can present certificates.",
		Check: func(r *Resource) []Hit {
			key := "client_certificate_enabled"
			if r.Type == "azurerm_app_service" {
				key = "client_cert_enabled"
			}
			if notTrue(r.get(key)) {
				return []Hit{{Path: key, Msg: "Any client can open a TLS session; callers are not authenticated by certificate.", Fix: fix(true, "Require client certificates", key)}}
			}
			return nil
		}},
	{ID: "TG-AZ-APP-204", Title: "App Service has no health check", Severity: Low, Category: CatReliability, CWE: "CWE-754",
		Types: azpWebApps, Remediation: `Set site_config { health_check_path = "/healthz" } so unhealthy instances are taken out of rotation.`,
		Check: func(r *Resource) []Hit {
			if r.get("site_config.health_check_path") == nil {
				return []Hit{{Path: "site_config", Msg: "Traffic keeps going to an instance that has stopped responding."}}
			}
			return nil
		}},
	{ID: "TG-AZ-APP-205", Title: "App Service detailed error logging is off", Severity: Low, Category: CatBestPrac, CWE: "CWE-778",
		Types: azpWebApps, Remediation: "Add logs { detailed_error_messages = true } (detailed_error_messages_enabled on azurerm_app_service).",
		Check: func(r *Resource) []Hit {
			key := "detailed_error_messages"
			if r.Type == "azurerm_app_service" {
				key = "detailed_error_messages_enabled"
			}
			if notTrue(r.get("logs." + key)) {
				return []Hit{{Path: "logs", Msg: "Server errors are not logged in detail, which slows down incident analysis.", Fix: fix(true, "Log detailed errors", "logs", key)}}
			}
			return nil
		}},
	{ID: "TG-AZ-APP-206", Title: "App Service failed request tracing is off", Severity: Low, Category: CatBestPrac, CWE: "CWE-778",
		Types: azpWebApps, Remediation: "Add logs { failed_request_tracing = true } (failed_request_tracing_enabled on azurerm_app_service).",
		Check: func(r *Resource) []Hit {
			key := "failed_request_tracing"
			if r.Type == "azurerm_app_service" {
				key = "failed_request_tracing_enabled"
			}
			if notTrue(r.get("logs." + key)) {
				return []Hit{{Path: "logs", Msg: "Failed requests leave no trace to investigate.", Fix: fix(true, "Trace failed requests", "logs", key)}}
			}
			return nil
		}},
	{ID: "TG-AZ-APP-207", Title: "App Service runs an end-of-life .NET version", Severity: Medium, Category: CatSecurity, CWE: "CWE-1104",
		Types: []string{"azurerm_app_service", "azurerm_windows_web_app"}, Remediation: `Move to a supported .NET release, e.g. application_stack { dotnet_version = "v8.0" }.`,
		Check: func(r *Resource) []Hit {
			for _, p := range []string{"site_config.dotnet_framework_version", "site_config.application_stack.dotnet_version"} {
				// v4.0 is .NET Framework 4.x, which Microsoft still supports, so it is not flagged.
				if v, _ := asString(r.get(p)); contains([]string{"v2.0", "v3.0", "v5.0", "v6.0", "v7.0"}, v) {
					return []Hit{{Path: "site_config", Msg: ".NET " + v + " no longer gets security fixes."}}
				}
			}
			return nil
		}},
	{ID: "TG-AZ-APP-208", Title: "App Service plan runs a single instance", Severity: Info, Category: CatReliability, CWE: "CWE-1188",
		Types: []string{"azurerm_service_plan"}, Remediation: "Set worker_count = 2 or more (and zone_balancing_enabled where supported) so one instance can fail.",
		Check: func(r *Resource) []Hit {
			v := r.get("worker_count")
			if n, ok := asFloat(v); (ok && n < 2) || v == nil {
				return []Hit{{Path: "worker_count", Msg: "One instance means any host failure or platform update takes the apps down."}}
			}
			return nil
		}},
	{ID: "TG-AZ-FUNCTION-201", Title: "Function app accepts plain HTTP", Severity: Medium, Category: CatSecurity, CWE: "CWE-319",
		Types: azpFunctionApps, Remediation: "Set https_only = true and keep auth_settings_v2 require_https = true.",
		Check: func(r *Resource) []Hit {
			// TG-AZ-APP-001 covers https_only on the non-slot function apps.
			if strings.HasSuffix(r.Type, "_slot") && notTrue(r.get("https_only")) {
				return []Hit{{Path: "https_only", Msg: "Function calls and their keys can travel unencrypted.", Fix: fix(true, "Redirect HTTP to HTTPS", "https_only")}}
			}
			if is(r.get("auth_settings_v2.require_https"), false) {
				return []Hit{{Path: "auth_settings_v2", Msg: "Authentication flows are allowed over plain HTTP.", Fix: fix(true, "Require HTTPS for auth", "auth_settings_v2", "require_https")}}
			}
			return nil
		}},

	// API Management
	{ID: "TG-AZ-APIM-201", Title: "Consumption API Management does not request client certificates", Severity: Low, Category: CatSecurity, CWE: "CWE-295",
		Types: []string{"azurerm_api_management"}, Remediation: "Set client_certificate_enabled = true so policies can validate caller certificates.",
		Check: func(r *Resource) []Hit {
			if sku, _ := asString(r.get("sku_name")); strings.HasPrefix(sku, "Consumption") && notTrue(r.get("client_certificate_enabled")) {
				return []Hit{{Path: "client_certificate_enabled", Msg: "The gateway never asks for a client certificate, so certificate-based authentication cannot work.", Fix: fix(true, "Request client certificates", "client_certificate_enabled")}}
			}
			return nil
		}},
	{ID: "TG-AZ-APIM-202", Title: "API Management enables SSL 3.0 or TLS 1.0/1.1", Severity: Medium, Category: CatSecurity, CWE: "CWE-327",
		Types: []string{"azurerm_api_management"}, Remediation: "Set the security block's enable_*_ssl30, enable_*_tls10 and enable_*_tls11 options to false.",
		Check: func(r *Resource) []Hit {
			// The *_enabled names of azurerm 3+ are covered by TG-AZ-APIM-001; these are the 2.x names.
			for _, k := range []string{"enable_back_end_ssl30", "enable_backend_ssl30", "enable_backend_tls10", "enable_backend_tls11", "enable_frontend_ssl30", "enable_frontend_tls10", "enable_frontend_tls11"} {
				if is(r.get("security."+k), true) {
					return []Hit{{Path: "security", Msg: "The gateway accepts or uses a broken protocol (" + k + ").", Fix: fix(false, "Disable "+k, "security", k)}}
				}
			}
			return nil
		}},
	{ID: "TG-AZ-APIM-203", Title: "API Management backend uses plain HTTP", Severity: Medium, Category: CatSecurity, CWE: "CWE-319",
		Types: []string{"azurerm_api_management_backend"}, Remediation: "Point url at an https:// endpoint.",
		Check: func(r *Resource) []Hit {
			if u, ok := asString(r.get("url")); ok && !strings.HasPrefix(strings.ToLower(u), "https://") && !strings.Contains(u, "${") {
				return []Hit{{Path: "url", Msg: "Requests, including forwarded credentials, travel unencrypted to the backend."}}
			}
			return nil
		}},

	// AKS
	{ID: "TG-AZ-AKS-201", Title: "AKS cluster does not run the Azure Policy add-on", Severity: Low, Category: CatSecurity, CWE: "CWE-693",
		Types: []string{"azurerm_kubernetes_cluster"}, Remediation: "Set azure_policy_enabled = true.",
		Check: func(r *Resource) []Hit {
			a, b := r.get("azure_policy_enabled"), r.get("addon_profile.azure_policy.enabled")
			if isUnknown(a) || isUnknown(b) || is(a, true) || is(b, true) {
				return nil
			}
			return []Hit{{Path: "azure_policy_enabled", Msg: "Pod security and other guardrail policies are not enforced in the cluster.", Fix: fix(true, "Enable Azure Policy for AKS", "azure_policy_enabled")}}
		}},
	{ID: "TG-AZ-AKS-202", Title: "AKS nodes get public IP addresses", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"azurerm_kubernetes_cluster", "azurerm_kubernetes_cluster_node_pool"}, Remediation: "Set node_public_ip_enabled = false (enable_node_public_ip on older providers).",
		Check: func(r *Resource) []Hit {
			prefix := ""
			if r.Type == "azurerm_kubernetes_cluster" {
				prefix = "default_node_pool."
			}
			for _, k := range []string{"node_public_ip_enabled", "enable_node_public_ip"} {
				if is(r.get(prefix+k), true) {
					return []Hit{{Path: strings.Split(prefix+k, ".")[0], Msg: "Every node is directly reachable from the internet.", Fix: fix(false, "Remove node public IPs", strings.Split(prefix+k, ".")...)}}
				}
			}
			return nil
		}},
	{ID: "TG-AZ-AKS-203", Title: "AKS node pool allows too few pods per node", Severity: Low, Category: CatReliability, CWE: "CWE-1188",
		Types: []string{"azurerm_kubernetes_cluster", "azurerm_kubernetes_cluster_node_pool"}, Remediation: "Set max_pods = 50 or more; it cannot be changed without recreating the pool.",
		Check: func(r *Resource) []Hit {
			path := "max_pods"
			if r.Type == "azurerm_kubernetes_cluster" {
				path = "default_node_pool.max_pods"
			}
			if n, ok := asFloat(r.get(path)); ok && n < 50 {
				return []Hit{{Path: strings.Split(path, ".")[0], Msg: "System pods alone can fill a node, leaving little room for workloads and forcing extra nodes."}}
			}
			if r.get(path) == nil && r.Type == "azurerm_kubernetes_cluster" && azpStr(r.get("network_profile.network_plugin")) == "azure" && r.get("network_profile.network_plugin_mode") == nil {
				// Only classic Azure CNI defaults to 30 pods; kubenet and overlay default far higher.
				return []Hit{{Path: "default_node_pool", Msg: "Classic Azure CNI defaults to 30 pods per node."}}
			}
			return nil
		}},
	{ID: "TG-AZ-AKS-204", Title: "AKS cluster has no automatic upgrade channel", Severity: Low, Category: CatSecurity, CWE: "CWE-1104",
		Types: []string{"azurerm_kubernetes_cluster"}, Remediation: `Set automatic_upgrade_channel = "patch" (automatic_channel_upgrade on azurerm 3).`,
		Check: func(r *Resource) []Hit {
			a, b := r.get("automatic_upgrade_channel"), r.get("automatic_channel_upgrade")
			if isUnknown(a) || isUnknown(b) {
				return nil
			}
			if sa, sb := azpStr(a), azpStr(b); (sa == "" || sa == "none") && (sb == "" || sb == "none") {
				return []Hit{{Path: "automatic_upgrade_channel", Msg: "Kubernetes patch releases with security fixes are only applied when someone upgrades by hand."}}
			}
			return nil
		}},
	{ID: "TG-AZ-AKS-205", Title: "AKS nodes do not use encryption at host", Severity: Medium, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"azurerm_kubernetes_cluster", "azurerm_kubernetes_cluster_node_pool"}, Remediation: "Set host_encryption_enabled = true (enable_host_encryption on older providers); the subscription needs the EncryptionAtHost feature.",
		Check: func(r *Resource) []Hit {
			prefix, path := "", "host_encryption_enabled"
			if r.Type == "azurerm_kubernetes_cluster" {
				prefix, path = "default_node_pool.", "default_node_pool"
			}
			a, b := r.get(prefix+"host_encryption_enabled"), r.get(prefix+"enable_host_encryption")
			if isUnknown(a) || isUnknown(b) || is(a, true) || is(b, true) {
				return nil
			}
			return []Hit{{Path: path, Msg: "Temp disks and disk caches on the node hosts are not encrypted."}}
		}},
	{ID: "TG-AZ-AKS-206", Title: "AKS cluster does not send logs to Azure Monitor", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"azurerm_kubernetes_cluster"}, Remediation: "Add oms_agent { log_analytics_workspace_id = ... }.",
		Check: func(r *Resource) []Hit {
			if r.get("oms_agent.log_analytics_workspace_id") != nil {
				return nil
			}
			if v := r.get("addon_profile.oms_agent.enabled"); isUnknown(v) || is(v, true) {
				return nil
			}
			return []Hit{{Path: "oms_agent", Msg: "Container and node logs are not collected, so incidents cannot be investigated."}}
		}},
	{ID: "TG-AZ-AKS-209", Title: "AKS Kubernetes Dashboard is enabled", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"azurerm_kubernetes_cluster"}, Remediation: "Remove addon_profile { kube_dashboard } or set enabled = false.",
		Check: func(r *Resource) []Hit {
			if is(r.get("addon_profile.kube_dashboard.enabled"), true) {
				return []Hit{{Path: "addon_profile", Msg: "The dashboard runs with broad cluster rights and has been a common entry point for attackers.", Fix: fix(false, "Disable the dashboard", "addon_profile", "kube_dashboard", "enabled")}}
			}
			return nil
		}},

	// Container Registry
	{ID: "TG-AZ-ACR-201", Title: "Premium container registry does not enforce content trust", Severity: Low, Category: CatSecurity, CWE: "CWE-345",
		Types: []string{"azurerm_container_registry"}, Remediation: "Set trust_policy_enabled = true (trust_policy { enabled = true } on older providers) and sign images.",
		Check: func(r *Resource) []Hit {
			// Content trust exists only on Premium; asking for it elsewhere fails the apply.
			// Content trust exists only on Premium, so Standard registries are not flagged.
			if sku, _ := asString(r.get("sku")); sku != "Premium" {
				return nil
			}
			a, b := r.get("trust_policy_enabled"), r.get("trust_policy.enabled")
			if isUnknown(a) || isUnknown(b) || is(a, true) || is(b, true) {
				return nil
			}
			return []Hit{{Path: "trust_policy_enabled", Msg: "Unsigned or tampered images can be pulled and run."}}
		}},
	{ID: "TG-AZ-ACR-202", Title: "Container registry is not geo-replicated", Severity: Info, Category: CatReliability, CWE: "CWE-1188",
		Types: []string{"azurerm_container_registry"}, Remediation: `Use sku = "Premium" with a georeplications block per deployment region.`,
		Check: func(r *Resource) []Hit {
			if sku, ok := asString(r.get("sku")); (ok && sku != "Premium") || (sku == "Premium" && r.get("georeplications") == nil) {
				return []Hit{{Path: "georeplications", Msg: "A regional outage stops image pulls everywhere; Premium replicas cost extra."}}
			}
			return nil
		}},
	{ID: "TG-AZ-ACR-203", Title: "Container registry never cleans up untagged manifests", Severity: Low, Category: CatBestPrac, CWE: "CWE-404",
		Types: []string{"azurerm_container_registry"}, Remediation: "Set retention_policy_in_days = 7 (retention_policy { enabled = true } on older providers); requires Premium.",
		Check: func(r *Resource) []Hit {
			if r.get("retention_policy_in_days") != nil {
				return nil
			}
			if v := r.get("retention_policy.enabled"); isUnknown(v) || is(v, true) {
				return nil
			}
			return []Hit{{Path: "retention_policy_in_days", Msg: "Untagged images pile up, growing storage cost and the pool of stale, vulnerable images."}}
		}},
	{ID: "TG-AZ-ACR-204", Title: "Container registry is not zone redundant", Severity: Info, Category: CatReliability, CWE: "CWE-1188",
		Types: []string{"azurerm_container_registry"}, Remediation: "Set zone_redundancy_enabled = true on the registry and each georeplications block (Premium, forces a new registry).",
		Check: func(r *Resource) []Hit {
			if notTrue(r.get("zone_redundancy_enabled")) {
				return []Hit{{Path: "zone_redundancy_enabled", Msg: "A zone outage can make the registry unavailable."}}
			}
			for _, g := range r.blocks("georeplications") {
				if notTrue(g["zone_redundancy_enabled"]) {
					return []Hit{{Path: "georeplications", Msg: "A replica is not zone redundant."}}
				}
			}
			return nil
		}},

	// Key Vault
	{ID: "TG-AZ-KV-201", Title: "Key Vault key is not backed by an HSM", Severity: Low, Category: CatSecurity, CWE: "CWE-320",
		Types: []string{"azurerm_key_vault_key"}, Remediation: `Use key_type = "RSA-HSM" or "EC-HSM" (needs a Premium vault or Managed HSM).`,
		Check: func(r *Resource) []Hit {
			if t, ok := asString(r.get("key_type")); ok && t != "RSA-HSM" && t != "EC-HSM" {
				return []Hit{{Path: "key_type", Msg: "The key material is protected in software rather than in a hardware security module."}}
			}
			return nil
		}},

	// Networking
	{ID: "TG-AZ-NSG-201", Title: "NSG allows UDP from the internet", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"azurerm_network_security_group", "azurerm_network_security_rule"}, Remediation: "Restrict source_address_prefix to known ranges or deny inbound UDP from the internet.",
		Check: func(r *Resource) []Hit {
			rules, path := []map[string]any{r.Attrs}, ""
			if r.Type == "azurerm_network_security_group" {
				rules, path = r.blocks("security_rule"), "security_rule"
			}
			for _, sr := range rules {
				if azpStr(sr["protocol"]) != "udp" || azpStr(sr["direction"]) != "inbound" || azpStr(sr["access"]) != "allow" {
					continue
				}
				for _, src := range append(asStrings(sr["source_address_prefix"]), asStrings(sr["source_address_prefixes"])...) {
					if azpInternet(src) {
						return []Hit{{Path: map[bool]string{true: "source_address_prefix", false: path}[path == ""], Msg: "UDP services (DNS, NTP, SNMP and others) can be reached and abused for amplification from anywhere."}}
					}
				}
			}
			return nil
		}},
	{ID: "TG-AZ-VNET-201", Title: "Virtual network has a single DNS server", Severity: Low, Category: CatReliability, CWE: "CWE-1188",
		Types: []string{"azurerm_virtual_network", "azurerm_virtual_network_dns_servers"}, Remediation: "List at least two dns_servers, or remove dns_servers to use Azure DNS.",
		Check: func(r *Resource) []Hit {
			if v := r.get("dns_servers"); len(asStrings(v)) == 1 && !containsUnknown(v) {
				return []Hit{{Path: "dns_servers", Msg: "If that one server fails, name resolution fails for everything in the network."}}
			}
			return nil
		}},
	{ID: "TG-AZ-VNET-202", Title: "Virtual network uses a public DNS resolver", Severity: Low, Category: CatSecurity, CWE: "CWE-350",
		Types: []string{"azurerm_virtual_network"}, Remediation: "Use resolvers on private addresses (or remove dns_servers to use Azure DNS) so private DNS zones and private endpoints resolve.",
		Check: func(r *Resource) []Hit {
			// Hub-and-spoke designs put DNS in a peered VNet, so only public resolvers are flagged.
			for _, s := range asStrings(r.get("dns_servers")) {
				if ip := net.ParseIP(s); ip != nil && !ip.IsPrivate() && !ip.IsLoopback() && s != "168.63.129.16" {
					return []Hit{{Path: "dns_servers", Msg: s + " is a public resolver: internal names and private endpoints will not resolve and queries leave the network."}}
				}
			}
			return nil
		}},

	// Databases
	{ID: "TG-AZ-SQL-201", Title: "Single-server database firewall allows every IPv4 address", Severity: Critical, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"azurerm_mariadb_firewall_rule", "azurerm_postgresql_firewall_rule", "azurerm_mysql_firewall_rule"}, Remediation: "Allow only specific client ranges, or use private endpoints.", // TG-AZ-SQL-001 covers the other firewall types
		Check: func(r *Resource) []Hit {
			s, _ := asString(r.get("start_ip_address"))
			e, _ := asString(r.get("end_ip_address"))
			if (s == "0.0.0.0" || s == "0.0.0.0/0") && e == "255.255.255.255" {
				return []Hit{{Path: "start_ip_address", Msg: "Every IPv4 address can reach the database login."}}
			}
			return nil
		}},
	{ID: "TG-AZ-SQL-202", Title: "SQL threat detection skips some alert types", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"azurerm_mssql_server_security_alert_policy"}, Remediation: "Remove disabled_alerts so every threat type raises an alert.",
		Check: func(r *Resource) []Hit {
			for _, a := range asStrings(r.get("disabled_alerts")) {
				if a != "" {
					return []Hit{{Path: "disabled_alerts", Msg: "Alerts for " + a + " are turned off, so those attacks go unnoticed."}}
				}
			}
			return nil
		}},
	{ID: "TG-AZ-PG-201", Title: "PostgreSQL audit or throttling parameter is off", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"azurerm_postgresql_configuration"}, Remediation: `Set value = "on" for log_checkpoints, log_connections, log_retention and connection_throttling.`,
		Check: func(r *Resource) []Hit {
			n, _ := asString(r.get("name"))
			if contains([]string{"log_checkpoints", "log_connections", "log_retention", "connection_throttling"}, n) && azpStr(r.get("value")) == "off" {
				return []Hit{{Path: "value", Msg: n + " is off, so the server records less of what happens or does not slow down password guessing.", Fix: fix("on", "Turn "+n+" on", "value")}}
			}
			return nil
		}},
	{ID: "TG-AZ-PG-202", Title: "PostgreSQL flexible server backups are not geo-redundant", Severity: Low, Category: CatReliability, CWE: "CWE-1188",
		Types: []string{"azurerm_postgresql_flexible_server"}, Remediation: "Set geo_redundant_backup_enabled = true (forces a new server).",
		Check: func(r *Resource) []Hit {
			if m, _ := asString(r.get("create_mode")); m == "Replica" { // replicas cannot have their own geo backups
				return nil
			}
			if notTrue(r.get("geo_redundant_backup_enabled")) {
				return []Hit{{Path: "geo_redundant_backup_enabled", Msg: "Backups stay in one region, so a regional outage can make them unrecoverable."}}
			}
			return nil
		}},

	// Storage
	{ID: "TG-AZ-ST-201", Title: "Storage account allows local users", Severity: Low, Category: CatSecurity, CWE: "CWE-287",
		Types: []string{"azurerm_storage_account"}, Remediation: "Set local_user_enabled = false unless SFTP local users are required.",
		Check: func(r *Resource) []Hit {
			v := r.get("local_user_enabled")
			if is(v, true) || (v == nil && is(r.get("is_hns_enabled"), true)) {
				return []Hit{{Path: "local_user_enabled", Msg: "SFTP local users authenticate with passwords or keys outside Entra ID.", Fix: fix(false, "Disable local users", "local_user_enabled")}}
			}
			return nil
		}},
	{ID: "TG-AZ-ST-202", Title: "Storage queue requests are not logged", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"azurerm_storage_account"}, Remediation: "Add queue_properties { logging { read = true, write = true, delete = true, version = \"1.0\" } }.",
		Check: func(r *Resource) []Hit {
			if k := r.get("account_kind"); isUnknown(k) || (k != nil && k != "Storage" && k != "StorageV2") {
				return nil
			}
			for _, k := range []string{"read", "write", "delete"} {
				if notTrue(r.get("queue_properties.logging." + k)) {
					return []Hit{{Path: "queue_properties", Msg: "Queue reads, writes and deletes leave no audit trail."}}
				}
			}
			return nil
		}},
	{ID: "TG-AZ-ST-203", Title: "Storage firewall blocks trusted Azure services", Severity: Low, Category: CatReliability, CWE: "CWE-1188",
		Types: []string{"azurerm_storage_account", "azurerm_storage_account_network_rules"}, Remediation: `Include "AzureServices" in bypass.`,
		Check: func(r *Resource) []Hit {
			rules, path := []map[string]any{r.Attrs}, "bypass"
			if r.Type == "azurerm_storage_account" {
				rules, path = r.blocks("network_rules"), "network_rules"
			}
			for _, n := range rules {
				b := n["bypass"]
				if azpStr(n["default_action"]) == "deny" && b != nil && !isUnknown(b) && !containsUnknown(b) && !contains(asStrings(b), "AzureServices") {
					return []Hit{{Path: path, Msg: "Backup, monitoring and other trusted Microsoft services cannot reach the account."}}
				}
			}
			return nil
		}},
	{ID: "TG-AZ-ST-204", Title: "Invalid storage account name (apply will fail)", Severity: High, Category: CatValidate, Blocking: true,
		Types: []string{"azurerm_storage_account"}, Remediation: "Use 3 to 24 characters, lowercase letters and digits only.",
		Check: func(r *Resource) []Hit {
			if n, ok := asString(r.get("name")); ok && !strings.Contains(n, "${") && !azpStorageNameRE.MatchString(n) {
				return []Hit{{Path: "name", Msg: strconv.Quote(n) + " is not a valid storage account name; Azure rejects it during apply."}}
			}
			return nil
		}},
	{ID: "TG-AZ-ST-206", Title: "Storage Sync Service accepts traffic from any network", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"azurerm_storage_sync"}, Remediation: `Set incoming_traffic_policy = "AllowVirtualNetworksOnly" and use private endpoints.`,
		Check: func(r *Resource) []Hit {
			if v := r.get("incoming_traffic_policy"); v == nil || azpStr(v) == "allowalltraffic" {
				return []Hit{{Path: "incoming_traffic_policy", Msg: "The sync service endpoint is reachable from the internet (the default).", Fix: fix("AllowVirtualNetworksOnly", "Allow only virtual networks", "incoming_traffic_policy")}}
			}
			return nil
		}},

	// Monitoring and Defender
	{ID: "TG-AZ-MON-201", Title: "Activity log profile keeps logs for under a year", Severity: Low, Category: CatSecurity, CWE: "CWE-779",
		Types: []string{"azurerm_monitor_log_profile"}, Remediation: "Set retention_policy { enabled = true, days = 365 }, or days = 0 to keep logs forever.",
		Check: func(r *Resource) []Hit {
			if r.get("retention_policy") == nil {
				return []Hit{{Path: "retention_policy", Msg: "No retention is set for the activity log."}}
			}
			// Retention disabled or days = 0 keeps the logs forever.
			if !is(r.get("retention_policy.enabled"), true) {
				return nil
			}
			if d, ok := asFloat(r.get("retention_policy.days")); ok && d > 0 && d < 365 {
				return []Hit{{Path: "retention_policy", Msg: "Control-plane activity is deleted after " + strconv.Itoa(int(d)) + " days, before many investigations need it."}}
			}
			return nil
		}},
	{ID: "TG-AZ-MON-202", Title: "Activity log profile skips some categories", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"azurerm_monitor_log_profile"}, Remediation: `Set categories = ["Action", "Delete", "Write"].`,
		Check: func(r *Resource) []Hit {
			v := r.get("categories")
			if isUnknown(v) || containsUnknown(v) {
				return nil
			}
			for _, c := range []string{"Action", "Delete", "Write"} {
				if !contains(asStrings(v), c) {
					return []Hit{{Path: "categories", Msg: c + " operations on the subscription are not captured."}}
				}
			}
			return nil
		}},
	{ID: "TG-AZ-DEF-201", Title: "Microsoft Defender plan is on the Free tier", Severity: Medium, Category: CatSecurity, CWE: "CWE-693",
		Types: []string{"azurerm_security_center_subscription_pricing"}, Remediation: `Set tier = "Standard" for this resource_type.`,
		Check: func(r *Resource) []Hit {
			rt := azpStr(r.get("resource_type"))
			if !contains([]string{"virtualmachines", "appservices", "sqlservers", "sqlservervirtualmachines", "storageaccounts", "kubernetesservice", "containerregistry", "keyvaults", "arm"}, rt) {
				return nil
			}
			if t := r.get("tier"); !isUnknown(t) && azpStr(t) != "standard" {
				return []Hit{{Path: "tier", Msg: "Threat detection for " + rt + " is off, so attacks on those resources raise no alerts.", Fix: fix("Standard", "Turn on the Defender plan", "tier")}}
			}
			return nil
		}},

	// Gateways, WAF and CDN
	{ID: "TG-AZ-AGW-201", Title: "Application Gateway SSL policy allows weak protocols or ciphers", Severity: Medium, Category: CatSecurity, CWE: "CWE-327",
		Types: []string{"azurerm_application_gateway"}, Remediation: `Use ssl_policy { policy_type = "Predefined", policy_name = "AppGwSslPolicy20220101S" } or a Custom policy with min_protocol_version = "TLSv1_2" and only GCM ECDHE ciphers.`,
		Check: func(r *Resource) []Hit {
			ps := r.blocks("ssl_policy")
			if len(ps) == 0 {
				return nil // current API versions default to a TLS 1.2 policy
			}
			p := ps[0]
			if isUnknown(p["policy_type"]) || isUnknown(p["policy_name"]) || isUnknown(p["min_protocol_version"]) || containsUnknown(p["cipher_suites"]) {
				return nil
			}
			if t, _ := asString(p["policy_type"]); strings.HasPrefix(t, "Custom") {
				if v, _ := asString(p["min_protocol_version"]); v != "TLSv1_2" && v != "TLSv1_3" {
					return []Hit{{Path: "ssl_policy", Msg: "The custom policy accepts TLS older than 1.2."}}
				}
				for _, c := range asStrings(p["cipher_suites"]) {
					if azpWeakCipher(c) {
						return []Hit{{Path: "ssl_policy", Msg: c + " is a CBC or non-forward-secret cipher."}}
					}
				}
				return nil
			}
			if n, _ := asString(p["policy_name"]); n != "AppGwSslPolicy20220101S" {
				return []Hit{{Path: "ssl_policy", Msg: "The predefined policy " + strconv.Quote(n) + " allows older protocols or CBC ciphers."}}
			}
			return nil
		}},
	{ID: "TG-AZ-WAF-201", Title: "Application Gateway WAF does not block Log4Shell", Severity: High, Category: CatSecurity, CWE: "CWE-917",
		Types: []string{"azurerm_web_application_firewall_policy"}, Remediation: "Use managed_rule_set OWASP 3.1+ or Microsoft_DefaultRuleSet and do not disable rule 944240 in REQUEST-944-APPLICATION-ATTACK-JAVA.",
		Check: func(r *Resource) []Hit {
			for _, set := range blocksAt(r.get("managed_rules"), "managed_rule_set") {
				t, _ := asString(set["type"])
				v, _ := asString(set["version"])
				if !((t == "" || t == "OWASP") && (v == "3.1" || v == "3.2")) && t != "Microsoft_DefaultRuleSet" {
					continue
				}
				for _, o := range blocksAt(set, "rule_group_override") {
					if g, _ := asString(o["rule_group_name"]); g != "REQUEST-944-APPLICATION-ATTACK-JAVA" && g != "JAVA" {
						continue
					}
					if contains(asStrings(o["disabled_rules"]), "944240") {
						return []Hit{{Path: "managed_rules", Msg: "Rule 944240 (Log4j JNDI lookup) is disabled."}}
					}
					for _, rl := range blocksAt(o, "rule") {
						if id, _ := asString(rl["id"]); id == "944240" && is(rl["enabled"], false) {
							return []Hit{{Path: "managed_rules", Msg: "Rule 944240 (Log4j JNDI lookup) is disabled."}}
						}
					}
				}
				return nil
			}
			return []Hit{{Path: "managed_rules", Msg: "No managed rule set that detects Log4j JNDI lookups (CVE-2021-44228) is applied."}}
		}},
	{ID: "TG-AZ-FD-201", Title: "Front Door WAF policy is disabled", Severity: High, Category: CatSecurity, CWE: "CWE-693",
		Types: []string{"azurerm_frontdoor_firewall_policy"}, Remediation: "Set enabled = true.",
		Check: func(r *Resource) []Hit {
			if is(r.get("enabled"), false) {
				return []Hit{{Path: "enabled", Msg: "The firewall inspects nothing.", Fix: fix(true, "Enable the WAF policy", "enabled")}}
			}
			if is(r.get("policy_settings.enabled"), false) {
				return []Hit{{Path: "policy_settings", Msg: "The firewall inspects nothing."}}
			}
			return nil
		}},
	{ID: "TG-AZ-FD-202", Title: "Front Door WAF does not block Log4Shell", Severity: High, Category: CatSecurity, CWE: "CWE-917",
		Types: []string{"azurerm_frontdoor_firewall_policy"}, Remediation: "Add managed_rule { type = \"DefaultRuleSet\" } (or Microsoft_DefaultRuleSet) and keep rule 944240 enabled with action Block.",
		Check: func(r *Resource) []Hit {
			for _, m := range r.blocks("managed_rule") {
				if t, _ := asString(m["type"]); t != "DefaultRuleSet" && t != "Microsoft_DefaultRuleSet" {
					continue
				}
				for _, o := range blocksAt(m, "override") {
					if g, _ := asString(o["rule_group_name"]); g != "JAVA" {
						continue
					}
					for _, rl := range blocksAt(o, "rule") {
						if id, _ := asString(rl["rule_id"]); id != "944240" {
							continue
						}
						if a, _ := asString(rl["action"]); notTrue(rl["enabled"]) || (a != "Block" && a != "Redirect" && !isUnknown(rl["action"])) {
							return []Hit{{Path: "managed_rule", Msg: "Rule 944240 (Log4j JNDI lookup) is overridden so it no longer blocks."}}
						}
					}
				}
				return nil
			}
			return []Hit{{Path: "managed_rule", Msg: "No default rule set that detects Log4j JNDI lookups (CVE-2021-44228) is applied."}}
		}},
	{ID: "TG-AZ-CDN-202", Title: "CDN endpoint has HTTPS disabled", Severity: Medium, Category: CatSecurity, CWE: "CWE-319",
		Types: []string{"azurerm_cdn_endpoint"}, Remediation: "Set is_https_allowed = true.",
		Check: func(r *Resource) []Hit {
			if is(r.get("is_https_allowed"), false) {
				return []Hit{{Path: "is_https_allowed", Msg: "Clients cannot reach the endpoint over an encrypted connection.", Fix: fix(true, "Enable HTTPS", "is_https_allowed")}}
			}
			return nil
		}},
	{ID: "TG-AZ-CDN-203", Title: "CDN custom domain allows TLS 1.0", Severity: Medium, Category: CatSecurity, CWE: "CWE-326",
		Types: []string{"azurerm_cdn_endpoint_custom_domain"}, Remediation: `Set tls_version = "TLS12" in cdn_managed_https or user_managed_https.`,
		Check: func(r *Resource) []Hit {
			for _, b := range []string{"cdn_managed_https", "user_managed_https"} {
				if v, _ := asString(r.get(b + ".tls_version")); v == "None" || v == "TLS10" {
					return []Hit{{Path: b, Msg: "The custom domain accepts TLS 1.0 (or any version).", Fix: fix("TLS12", "Require TLS 1.2", b, "tls_version")}}
				}
			}
			return nil
		}},

	// Identity
	{ID: "TG-AZ-IAM-201", Title: "Resource has no managed identity", Severity: Low, Category: CatBestPrac, CWE: "CWE-798",
		Types: []string{"azurerm_kusto_cluster", "azurerm_search_service"}, Remediation: `Add identity { type = "SystemAssigned" } and grant it the roles it needs instead of using keys or connection strings.`,
		Check: func(r *Resource) []Hit {
			if r.get("identity") == nil {
				return []Hit{{Path: "identity", Msg: "Without a managed identity the resource must use stored keys or secrets to reach other Azure services."}}
			}
			return nil
		}},
	{ID: "TG-AZ-IAM-202", Title: "GitHub federated credential trusts too many workflows", Severity: Critical, Category: CatSecurity, CWE: "CWE-863",
		Types: []string{"azuread_application_federated_identity_credential"}, Remediation: "Set subject to one repository and a branch or environment, e.g. repo:org/repo:environment:prod.",
		Check: func(r *Resource) []Hit {
			if iss, ok := asString(r.get("issuer")); ok && !strings.Contains(iss, "token.actions.githubusercontent.com") {
				return nil
			}
			v := r.get("subject")
			if isUnknown(v) {
				return nil
			}
			s, _ := asString(v)
			if !azpGitHubSubjectOK(s) {
				return []Hit{{Path: "subject", Msg: "Workflows outside the intended repository can obtain tokens for this application."}}
			}
			return nil
		}},

	// Data and AI services
	{ID: "TG-AZ-ADF-201", Title: "Data Factory is not connected to source control", Severity: Low, Category: CatBestPrac, CWE: "CWE-1188",
		Types: []string{"azurerm_data_factory"}, Remediation: "Add github_configuration or vsts_configuration with a repository_name.",
		Check: func(r *Resource) []Hit {
			if r.get("github_configuration.repository_name") == nil && r.get("vsts_configuration.repository_name") == nil {
				return []Hit{{Path: "github_configuration", Msg: "Pipeline changes are made live in the portal with no history or review."}}
			}
			return nil
		}},
	{ID: "TG-AZ-ML-201", Title: "Machine Learning compute cluster allows local authentication", Severity: Medium, Category: CatSecurity, CWE: "CWE-287",
		Types: []string{"azurerm_machine_learning_compute_cluster"}, Remediation: "Set local_auth_enabled = false (forces a new cluster).",
		Check: func(r *Resource) []Hit {
			if notFalse(r.get("local_auth_enabled")) {
				return []Hit{{Path: "local_auth_enabled", Msg: "Nodes accept SSH or local accounts outside Entra ID (on by default).", Fix: fix(false, "Disable local authentication", "local_auth_enabled")}}
			}
			return nil
		}},
	{ID: "TG-AZ-ML-202", Title: "Machine Learning workspace is reachable from public networks", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"azurerm_machine_learning_workspace"}, Remediation: "Set public_network_access_enabled = false and use private endpoints.",
		Check: func(r *Resource) []Hit {
			if notFalse(r.get("public_network_access_enabled")) {
				return []Hit{{Path: "public_network_access_enabled", Msg: "Models, datasets and notebooks are reachable from the internet (the default).", Fix: fix(false, "Disable public network access", "public_network_access_enabled")}}
			}
			return nil
		}},
	{ID: "TG-AZ-SEARCH-201", Title: "Search service has too few replicas for the query SLA", Severity: Info, Category: CatReliability, CWE: "CWE-1188",
		Types: []string{"azurerm_search_service"}, Remediation: "Set replica_count = 2 or more (each replica is billed).",
		Check: func(r *Resource) []Hit {
			if v := r.get("replica_count"); v == nil || azpLess(v, 2) {
				return []Hit{{Path: "replica_count", Msg: "Fewer than 2 replicas carries no availability SLA for queries."}}
			}
			return nil
		}},
	{ID: "TG-AZ-SEARCH-202", Title: "Search service has too few replicas for the indexing SLA", Severity: Info, Category: CatReliability, CWE: "CWE-1188",
		Types: []string{"azurerm_search_service"}, Remediation: "Set replica_count = 3 or more (each replica is billed).",
		Check: func(r *Resource) []Hit {
			if v := r.get("replica_count"); v == nil || azpLess(v, 3) {
				return []Hit{{Path: "replica_count", Msg: "Fewer than 3 replicas carries no availability SLA for index updates."}}
			}
			return nil
		}},
	{ID: "TG-AZ-SYN-201", Title: "Synapse workspace uses a SQL administrator password", Severity: Low, Category: CatSecurity, CWE: "CWE-522",
		Types: []string{"azurerm_synapse_workspace"}, Remediation: "Remove sql_administrator_login_password and use Entra ID only authentication (azuread_authentication_only = true).",
		Check: func(r *Resource) []Hit {
			if r.get("sql_administrator_login_password") != nil {
				return []Hit{{Path: "sql_administrator_login_password", Msg: "The SQL admin password is stored in state and can be guessed or leaked."}}
			}
			return nil
		}},
	{ID: "TG-AZ-SYN-202", Title: "Synapse SQL pool is not encrypted", Severity: Medium, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"azurerm_synapse_sql_pool"}, Remediation: "Set data_encrypted = true (transparent data encryption).",
		Check: func(r *Resource) []Hit {
			if notTrue(r.get("data_encrypted")) {
				return []Hit{{Path: "data_encrypted", Msg: "Warehouse data is stored without transparent data encryption.", Fix: fix(true, "Enable transparent data encryption", "data_encrypted")}}
			}
			return nil
		}},
	{ID: "TG-AZ-COG-201", Title: "Azure OpenAI account can send data to any destination", Severity: Medium, Category: CatSecurity, CWE: "CWE-200",
		Types: []string{"azurerm_cognitive_account"}, Remediation: "Set outbound_network_access_restricted = true and list the allowed fqdns.",
		Check: func(r *Resource) []Hit {
			if azpStr(r.get("kind")) != "openai" {
				return nil
			}
			f := r.get("fqdns")
			if notTrue(r.get("outbound_network_access_restricted")) || (len(asStrings(f)) == 0 && !isUnknown(f) && !containsUnknown(f)) {
				return []Hit{{Path: "outbound_network_access_restricted", Msg: "Prompts and data can be sent to arbitrary outside endpoints."}}
			}
			return nil
		}},
	{ID: "TG-AZ-BATCH-201", Title: "Batch account endpoint allows any public network", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"azurerm_batch_account"}, Remediation: `Set network_profile { account_access { default_action = "Deny" } } with ip_rule entries, or public_network_access_enabled = false.`,
		Check: func(r *Resource) []Hit {
			if v := r.get("public_network_access_enabled"); is(v, false) || isUnknown(v) {
				return nil
			}
			if azpStr(r.get("network_profile.account_access.default_action")) == "allow" {
				return []Hit{{Path: "network_profile", Msg: "The account management endpoint accepts requests from any IP."}}
			}
			return nil
		}},
	{ID: "TG-AZ-ACI-201", Title: "Container group passes environment variables in plain text", Severity: Low, Category: CatSecurity, CWE: "CWE-312",
		Types: []string{"azurerm_container_group"}, Remediation: "Move sensitive values to secure_environment_variables.",
		Check: func(r *Resource) []Hit {
			for _, b := range []string{"container", "init_container"} {
				for _, c := range r.blocks(b) {
					env, ok := c["environment_variables"].(map[string]any)
					if !ok && c["environment_variables"] == nil {
						continue
					}
					for k := range env {
						if secretAttrRE.MatchString(strings.ToLower(k)) {
							return []Hit{{Path: b, Sev: High, Msg: k + " looks like a secret but is a plain environment variable, visible to anyone who can read the container group."}}
						}
					}
					return []Hit{{Path: b, Msg: "environment_variables are shown in the portal and API; only non-sensitive values belong there."}}
				}
			}
			return nil
		}},
	{ID: "TG-AZ-SF-201", Title: "Service Fabric cluster traffic is not encrypted and signed", Severity: Medium, Category: CatSecurity, CWE: "CWE-319",
		Types: []string{"azurerm_service_fabric_cluster"}, Remediation: `Add fabric_settings { name = "Security", parameters = { ClusterProtectionLevel = "EncryptAndSign" } }.`,
		Check: func(r *Resource) []Hit {
			for _, s := range r.blocks("fabric_settings") {
				if n, _ := asString(s["name"]); n != "Security" {
					continue
				}
				p, _ := s["parameters"].(map[string]any)
				if isUnknown(s["parameters"]) || azpStr(p["ClusterProtectionLevel"]) == "encryptandsign" ||
					(azpStr(p["name"]) == "clusterprotectionlevel" && azpStr(p["value"]) == "encryptandsign") {
					return nil
				}
			}
			return []Hit{{Path: "fabric_settings", Msg: "Node-to-node traffic is not both encrypted and signed."}}
		}},
}

// portedAzureIDs maps foreign check IDs to these rules, so existing skip comments keep working.
var portedAzureIDs = map[string]string{
	"CKV_AZURE_1": "TG-AZ-VM-201", "CKV_AZURE_45": "TG-AZ-VM-202", "CKV_AZURE_92": "TG-AZ-VM-203", "CKV_AZURE_95": "TG-AZ-VM-204",
	"CKV_AZURE_2": "TG-AZ-DISK-201", "CKV_AZURE_251": "TG-AZ-DISK-001",
	"CKV_AZURE_13": "TG-AZ-APP-201", "CKV_AZURE_15": "TG-AZ-APP-001", "CKV_AZURE_145": "TG-AZ-APP-001", "CKV_AZURE_17": "TG-AZ-APP-203",
	"CKV_AZURE_213": "TG-AZ-APP-204", "CKV_AZURE_65": "TG-AZ-APP-205", "CKV_AZURE_66": "TG-AZ-APP-206", "CKV_AZURE_80": "TG-AZ-APP-207",
	"CKV_AZURE_212": "TG-AZ-APP-208", "CKV_AZURE_70": "TG-AZ-FUNCTION-201",
	"CKV_AZURE_152": "TG-AZ-APIM-201", "CKV_AZURE_173": "TG-AZ-APIM-202", "CKV_AZURE_215": "TG-AZ-APIM-203",
	"CKV_AZURE_116": "TG-AZ-AKS-201", "CKV_AZURE_143": "TG-AZ-AKS-202", "CKV_AZURE_168": "TG-AZ-AKS-203", "CKV_AZURE_171": "TG-AZ-AKS-204",
	"CKV_AZURE_227": "TG-AZ-AKS-205", "CKV_AZURE_4": "TG-AZ-AKS-206", "CKV_AZURE_5": "TG-AZ-AKS-001", "CKV_AZURE_6": "TG-AZ-AKS-001", "CKV_AZURE_8": "TG-AZ-AKS-209",
	"CKV_AZURE_164": "TG-AZ-ACR-201", "CKV_AZURE_165": "TG-AZ-ACR-202", "CKV_AZURE_167": "TG-AZ-ACR-203", "CKV_AZURE_233": "TG-AZ-ACR-204",
	"CKV_AZURE_112": "TG-AZ-KV-201", "CKV_AZURE_189": "TG-AZ-KV-002", "CKV_AZURE_42": "TG-AZ-KV-001",
	"CKV_AZURE_77": "TG-AZ-NSG-201", "CKV_AZURE_12": "TG-AZ-NSG-002", "CKV_AZURE_182": "TG-AZ-VNET-201", "CKV_AZURE_183": "TG-AZ-VNET-202",
	"CKV_AZURE_11": "TG-AZ-SQL-201", "CKV_AZURE_25": "TG-AZ-SQL-202",
	"CKV_AZURE_30": "TG-AZ-PG-201", "CKV_AZURE_31": "TG-AZ-PG-201", "CKV_AZURE_32": "TG-AZ-PG-201", "CKV_AZURE_146": "TG-AZ-PG-201", "CKV_AZURE_136": "TG-AZ-PG-202",
	"CKV_AZURE_244": "TG-AZ-ST-201", "CKV_AZURE_33": "TG-AZ-ST-202", "CKV_AZURE_36": "TG-AZ-ST-203", "CKV_AZURE_43": "TG-AZ-ST-204", "CKV_AZURE_44": "TG-AZ-ST-001", "CKV_AZURE_250": "TG-AZ-ST-206",
	"CKV_AZURE_37": "TG-AZ-MON-201", "CKV_AZURE_38": "TG-AZ-MON-202",
	"CKV_AZURE_55": "TG-AZ-DEF-201", "CKV_AZURE_61": "TG-AZ-DEF-201", "CKV_AZURE_69": "TG-AZ-DEF-201", "CKV_AZURE_79": "TG-AZ-DEF-201", "CKV_AZURE_84": "TG-AZ-DEF-201",
	"CKV_AZURE_85": "TG-AZ-DEF-201", "CKV_AZURE_86": "TG-AZ-DEF-201", "CKV_AZURE_87": "TG-AZ-DEF-201", "CKV_AZURE_234": "TG-AZ-DEF-201",
	"CKV_AZURE_218": "TG-AZ-AGW-201", "CKV_AZURE_122": "TG-AZ-WAF-002", "CKV_AZURE_135": "TG-AZ-WAF-201", "CKV_AZURE_123": "TG-AZ-FD-201", "CKV_AZURE_133": "TG-AZ-FD-202",
	"CKV_AZURE_197": "TG-CDN-001", "CKV_AZURE_198": "TG-AZ-CDN-202", "CKV_AZURE_200": "TG-AZ-CDN-203",
	"CKV_AZURE_16": "TG-AZ-APP-105", "CKV_AZURE_181": "TG-AZ-IAM-201", "CKV_AZURE_207": "TG-AZ-IAM-201", "CKV_AZURE_249": "TG-AZ-IAM-202",
	"CKV_AZURE_103": "TG-AZ-ADF-201", "CKV_AZURE_142": "TG-AZ-ML-201", "CKV_AZURE_144": "TG-AZ-ML-202", "CKV_AZURE_209": "TG-AZ-SEARCH-201", "CKV_AZURE_208": "TG-AZ-SEARCH-202",
	"CKV_AZURE_239": "TG-AZ-SYN-201", "CKV_AZURE_241": "TG-AZ-SYN-202", "CKV_AZURE_247": "TG-AZ-COG-201", "CKV_AZURE_248": "TG-AZ-BATCH-201",
	"CKV_AZURE_235": "TG-AZ-ACI-201", "CKV_AZURE_125": "TG-AZ-SF-201",
}

func init() {
	for ckv, id := range portedAzureIDs {
		foreignRules[ckv] = append(foreignRules[ckv], id)
	}
}

var (
	azpWebApps      = []string{"azurerm_app_service", "azurerm_linux_web_app", "azurerm_windows_web_app"}
	azpFunctionApps = []string{"azurerm_function_app", "azurerm_linux_function_app", "azurerm_windows_function_app", "azurerm_function_app_slot", "azurerm_linux_function_app_slot", "azurerm_windows_function_app_slot"}

	azpStorageNameRE = regexp.MustCompile(`^[a-z0-9]{3,24}$`)
	azpCredAssignRE  = regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)\s*[:=]\s*["']?[^\s"'$]{6,}`)
	azpGitHubRepoRE  = regexp.MustCompile(`^(\$\{)?[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*\}?/[^/]+$`)
)

// azpStr returns a lower-cased string (or number) value, "" otherwise.
func azpStr(v any) string {
	switch t := v.(type) {
	case string:
		return strings.ToLower(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	}
	return ""
}

// azpLess reports a known number below n.
func azpLess(v any, n float64) bool { f, ok := asFloat(v); return ok && f < n }

func azpInternet(s string) bool {
	switch strings.ToLower(s) {
	case "*", "0.0.0.0", "internet", "any":
		return true
	}
	return strings.HasSuffix(s, "/0")
}

func azpHasCredential(s string) bool {
	if s == "" {
		return false
	}
	for _, p := range credPatterns {
		if p.re.MatchString(s) {
			return true
		}
	}
	return azpCredAssignRE.MatchString(s)
}

// azpWeakCipher: CBC-mode, static-RSA, DHE and 3DES suites.
func azpWeakCipher(c string) bool {
	c = strings.TrimSpace(c)
	return strings.Contains(c, "_CBC_") || strings.HasPrefix(c, "TLS_RSA_") || strings.HasPrefix(c, "TLS_DHE_")
}

// azpGitHubSubjectOK: the subject names one repository, not a wildcard or a
// claim (workflow, environment, ref...) that any repository can satisfy.
func azpGitHubSubjectOK(s string) bool {
	parts := strings.Split(s, ":")
	if len(parts) < 2 || parts[0] == "*" || parts[1] == "*" {
		return false
	}
	if contains([]string{"workflow", "environment", "ref", "context", "head_ref", "base_ref"}, parts[0]) {
		return false
	}
	return parts[0] != "repo" || azpGitHubRepoRE.MatchString(parts[1])
}
