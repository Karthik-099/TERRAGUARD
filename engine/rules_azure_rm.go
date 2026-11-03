package engine

import (
	"encoding/base64"
	"net"
	"strconv"
	"strings"
)

// Rules for Azure Resource Manager templates that need more than one
// setting compared to a value. Paths follow the template ("properties.").

const (
	armWeb      = "Microsoft.Web/sites"
	armWebCfg   = "Microsoft.Web/sites/config"
	armAKS      = "Microsoft.ContainerService/managedClusters"
	armAKSPool  = "Microsoft.ContainerService/managedClusters/agentPools"
	armVM       = "Microsoft.Compute/virtualMachines"
	armVMSS     = "Microsoft.Compute/virtualMachineScaleSets"
	armStorage  = "Microsoft.Storage/storageAccounts"
	armSQL      = "Microsoft.Sql/servers"
	armSQLDB    = "Microsoft.Sql/servers/databases"
	armCosmos   = "Microsoft.DocumentDB/databaseAccounts"
	armACR      = "Microsoft.ContainerRegistry/registries"
	armNSG      = "Microsoft.Network/networkSecurityGroups"
	armNSGRule  = "Microsoft.Network/networkSecurityGroups/securityRules"
	armPricing  = "Microsoft.Security/pricings"
	armContacts = "Microsoft.Security/securityContacts"
	armLogProf  = "Microsoft.Insights/logprofiles"
	armSynapse  = "Microsoft.Synapse/workspaces"
	armDBX      = "Microsoft.Databricks/workspaces"
	armSearch   = "Microsoft.Search/searchServices"
)

// armSimple are single-setting checks in the rule-table form.
var armSimple = []check{
	{ID: "TG-ARM-ACR-203", Sev: Low, CWE: "CWE-693", Cat: CatReliability, Title: "Container registry zone redundancy is turned off", Types: []string{armACR, armACR + "/replications"}, Kind: "eq", Path: "properties.zoneRedundancy", Bad: []any{"Disabled"}, Good: "Enabled", Why: "A zone outage takes the registry, and every image pull, down with it."},
	{ID: "TG-ARM-AKS-207", Sev: Low, CWE: "CWE-1104", Cat: CatSecurity, Title: "AKS cluster has no automatic upgrade channel", Types: []string{armAKS}, Kind: "missing_or_eq", Path: "properties.autoUpgradeProfile.upgradeChannel", Bad: []any{"none"}, Good: "patch", Why: "Kubernetes patches are applied only when someone upgrades by hand."},
	{ID: "TG-ARM-APP-203", Sev: Info, CWE: "CWE-693", Cat: CatReliability, Title: "App Service runs a single instance", Types: []string{armWeb, armWeb + "/slots"}, Kind: "lt_or_missing", Path: "properties.siteConfig.numberOfWorkers", Num: 2, Good: 2, Why: "One instance failing or restarting takes the app offline."},
	{ID: "TG-ARM-APP-204", Sev: Low, CWE: "CWE-693", Cat: CatReliability, Title: "App Service has no health check path", Types: []string{armWeb, armWeb + "/slots"}, Kind: "set", Path: "properties.siteConfig.healthCheckPath", Why: "Unhealthy instances keep receiving traffic because the platform cannot detect them."},
	{ID: "TG-ARM-APP-205", Sev: Medium, CWE: "CWE-319", Cat: CatSecurity, Title: "App Service authentication accepts plain HTTP", Types: []string{armWebCfg}, Kind: "eq", Path: "properties.httpSettings.requireHttps", Bad: []any{false}, Good: true, Why: "Sign-in tokens and cookies can travel unencrypted."},
	{ID: "TG-ARM-KUSTO-201", Sev: Low, CWE: "CWE-311", Cat: CatSecurity, Title: "Data Explorer cluster has no double encryption", Types: []string{"Microsoft.Kusto/clusters"}, Kind: "want", Path: "properties.enableDoubleEncryption", Want: []any{true}, Good: true, Why: "Data at rest is protected by a single encryption layer."},
	{ID: "TG-ARM-VM-205", Sev: Medium, CWE: "CWE-311", Cat: CatSecurity, Title: "Scale set has no encryption at host", Types: []string{armVMSS}, Kind: "want", Path: "properties.virtualMachineProfile.securityProfile.encryptionAtHost", Want: []any{true}, Good: true, Why: "Temp disks and disk caches on the host are not encrypted."},
	{ID: "TG-ARM-ST-206", Sev: Medium, CWE: "CWE-326", Cat: CatSecurity, Title: "Storage account allows TLS older than 1.2", Types: []string{armStorage}, Kind: "eq", Path: "properties.minimumTlsVersion", Bad: []any{"TLS1_0", "TLS1_1"}, Good: "TLS1_2", Why: "Old TLS versions have known weaknesses that let an attacker downgrade or decrypt traffic."},
	{ID: "TG-ARM-KV-201", Sev: Low, CWE: "CWE-324", Cat: CatSecurity, Title: "Key Vault secret has no expiration date", Types: []string{"Microsoft.KeyVault/vaults/secrets"}, Kind: "set", Path: "properties.attributes.exp", Why: "The secret stays valid forever, so a leaked value is never retired."},
	{ID: "TG-ARM-KV-202", Sev: Low, CWE: "CWE-320", Cat: CatSecurity, Title: "Key Vault key is not backed by an HSM", Types: []string{"Microsoft.KeyVault/vaults/keys"}, Kind: "want", Path: "properties.kty", Want: []any{"RSA-HSM", "EC-HSM"}, Good: "RSA-HSM", Why: "Software keys can be exported from memory instead of staying inside hardware."},
	{ID: "TG-ARM-DBX-202", Sev: Medium, CWE: "CWE-284", Cat: CatSecurity, Title: "Databricks workspace is reachable from the public internet", Types: []string{armDBX}, Kind: "want", Path: "properties.publicNetworkAccess", Want: []any{"Disabled"}, Good: "Disabled", Why: "The workspace and its clusters talk to the control plane over public endpoints."},
	{ID: "TG-ARM-COSMOS-202", Sev: Medium, CWE: "CWE-284", Cat: CatSecurity, Title: "Cosmos DB account keys can change account settings", Types: []string{armCosmos}, Kind: "want", Path: "properties.disableKeyBasedMetadataWriteAccess", Want: []any{true}, Good: true, Why: "Anyone holding a data key can also create or delete databases and containers."},
	{ID: "TG-ARM-ADF-201", Sev: Low, CWE: "CWE-1357", Cat: CatBestPrac, Title: "Data Factory is not connected to a Git repository", Types: []string{"Microsoft.DataFactory/factories"}, Kind: "set", Path: "properties.repoConfiguration", Why: "Pipeline changes have no history or review."},
	{ID: "TG-ARM-PUBSUB-201", Sev: Low, CWE: "CWE-693", Cat: CatReliability, Title: "Web PubSub uses the Free SKU", Types: []string{"Microsoft.SignalRService/webPubSub"}, Kind: "eq", Path: "sku.name", Bad: []any{"Free_F1"}, Good: "Standard_S1", Why: "The Free tier has no SLA."},
	{ID: "TG-ARM-SEARCH-201", Sev: Info, CWE: "CWE-693", Cat: CatReliability, Title: "Search service has fewer than three replicas", Types: []string{armSearch}, Kind: "lt_or_missing", Path: "properties.replicaCount", Num: 3, Good: 3, Why: "Index updates are not covered by the SLA below three replicas."},
	{ID: "TG-ARM-SEARCH-202", Sev: Info, CWE: "CWE-693", Cat: CatReliability, Title: "Search service has fewer than two replicas", Types: []string{armSearch}, Kind: "lt_or_missing", Path: "properties.replicaCount", Num: 2, Good: 2, Why: "Queries are not covered by the SLA below two replicas."},
	{ID: "TG-ARM-SYN-202", Sev: Low, CWE: "CWE-311", Cat: CatSecurity, Title: "Synapse workspace does not use a customer-managed key", Types: []string{armSynapse}, Kind: "set", Path: "properties.encryption.cmk", Why: "Workspace data is encrypted only with keys you cannot rotate or revoke."},
	{ID: "TG-ARM-SYN-204", Sev: Medium, CWE: "CWE-284", Cat: CatSecurity, Title: "Synapse workspace has no managed virtual network", Types: []string{armSynapse}, Kind: "want", Path: "properties.managedVirtualNetwork", Want: []any{"default"}, Good: "default", Why: "Workspace compute shares a network with no isolation or data exfiltration protection."},
	{ID: "TG-ARM-SEC-201", Sev: Info, CWE: "CWE-693", Cat: CatSecurity, Title: "Security contact has no phone number", Types: []string{armContacts}, Kind: "set", Path: "properties.phone", Why: "Microsoft cannot reach anyone by phone about an active incident."},
}

var armRules = []Rule{
	{ID: "TG-ARM-ACR-201", Title: "Container registry allows anonymous pulls", Severity: High, Category: CatSecurity, CWE: "CWE-306",
		Types: []string{armACR}, Remediation: "Set properties.anonymousPullEnabled = false.",
		Check: func(r *Resource) []Hit {
			if is(armAt(r, "properties.anonymousPullEnabled"), true) && !strings.EqualFold(armStr(armAt(r, "sku.name")), "basic") {
				return []Hit{{Path: "properties.anonymousPullEnabled", Msg: "Anyone on the internet can pull every image in the registry."}}
			}
			return nil
		}},
	{ID: "TG-ARM-ACR-202", Title: "Container registry uses the Basic SKU", Severity: Low, Category: CatBestPrac, CWE: "CWE-693",
		Types: []string{armACR}, Remediation: "Use the Standard or Premium SKU.",
		Check: func(r *Resource) []Hit {
			if strings.EqualFold(armStr(armAt(r, "sku.name")), "basic") {
				return []Hit{{Path: "sku", Msg: "Basic registries lack network rules, private endpoints and image quarantine for scanning."}}
			}
			return nil
		}},
	{ID: "TG-ARM-AKS-201", Title: "AKS API server is open to any address", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{armAKS}, Remediation: "Set properties.apiServerAccessProfile.authorizedIPRanges, or make the cluster private.",
		Check: func(r *Resource) []Hit {
			prof := armAt(r, "properties.apiServerAccessProfile")
			old := armAt(r, "properties.apiServerAuthorizedIPRanges")
			ranges := armAt(r, "properties.apiServerAccessProfile.authorizedIPRanges")
			private := armAt(r, "properties.apiServerAccessProfile.enablePrivateCluster")
			if isUnknown(prof) || isUnknown(old) || isUnknown(ranges) || isUnknown(private) || is(private, true) || !empty(ranges) || !empty(old) {
				return nil
			}
			return []Hit{{Path: "properties", Msg: "The Kubernetes API endpoint accepts connections from the whole internet."}}
		}},
	{ID: "TG-ARM-AKS-202", Title: "AKS Kubernetes dashboard is enabled", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{armAKS}, Remediation: "Remove the kubeDashboard add-on or set its enabled = false.",
		Check: func(r *Resource) []Hit {
			if is(armAt(r, "properties.addonProfiles.kubeDashboard.enabled"), true) || armStr(r.get("apiVersion")) == "2017-08-31" {
				return []Hit{{Path: "properties.addonProfiles", Msg: "The dashboard runs with broad cluster rights and has been used to take over clusters."}}
			}
			return nil
		}},
	{ID: "TG-ARM-AKS-203", Title: "AKS cluster sends no logs to Azure Monitor", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{armAKS}, Remediation: "Enable the omsagent add-on (addonProfiles.omsagent.enabled = true) with a Log Analytics workspace.",
		Check: func(r *Resource) []Hit {
			a, b := armAt(r, "properties.addonProfiles.omsagent.enabled"), armAt(r, "properties.addonProfiles.omsAgent.enabled")
			m := armAt(r, "properties.azureMonitorProfile.metrics.enabled")
			if isUnknown(a) || isUnknown(b) || isUnknown(m) || is(a, true) || is(b, true) || is(m, true) {
				return nil
			}
			return []Hit{{Path: "properties", Msg: "Container and node logs are not collected, so incidents cannot be investigated."}}
		}},
	{ID: "TG-ARM-AKS-204", Title: "AKS cluster has no network policy", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{armAKS}, Remediation: "Set properties.networkProfile.networkPolicy to azure, calico or cilium.",
		Check: func(r *Resource) []Hit {
			if v := armAt(r, "properties.networkProfile.networkPolicy"); !isUnknown(v) && empty(v) {
				return []Hit{{Path: "properties.networkProfile", Msg: "Every pod can reach every other pod, so one compromised pod reaches the rest."}}
			}
			return nil
		}},
	{ID: "TG-ARM-AKS-205", Title: "AKS cluster has Kubernetes RBAC turned off", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{armAKS}, Remediation: "Set properties.enableRBAC = true (this recreates the cluster).",
		Check: func(r *Resource) []Hit {
			if is(armAt(r, "properties.enableRBAC"), false) || armStr(r.get("apiVersion")) == "2017-08-31" {
				return []Hit{{Path: "properties.enableRBAC", Msg: "Every authenticated user has full control of the cluster."}}
			}
			return nil
		}},
	{ID: "TG-ARM-AKS-206", Title: "AKS node pool allows fewer than 50 pods per node", Severity: Low, Category: CatBestPrac, CWE: "CWE-400",
		Types: []string{armAKS, armAKSPool}, Remediation: "Set maxPods to 50 or more.",
		Check: func(r *Resource) []Hit {
			for _, p := range armPools(r) {
				if f, ok := asFloat(get(p.v, "maxPods")); ok && f < 50 {
					return []Hit{{Path: p.path, Msg: "Nodes fill up quickly and system pods can fail to schedule."}}
				}
			}
			return nil
		}},
	{ID: "TG-ARM-AKS-208", Title: "AKS node pool has no encryption at host", Severity: Medium, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{armAKS, armAKSPool}, Remediation: "Set enableEncryptionAtHost = true on every node pool.",
		Check: func(r *Resource) []Hit {
			for _, p := range armPools(r) {
				if v := get(p.v, "enableEncryptionAtHost"); !isUnknown(v) && !is(v, true) {
					return []Hit{{Path: p.path, Msg: "Temp disks, disk caches and data moving to storage are not encrypted on the host."}}
				}
			}
			return nil
		}},
	{ID: "TG-ARM-APIM-201", Title: "API Management allows SSL 3.0, TLS 1.0 or TLS 1.1", Severity: Medium, Category: CatSecurity, CWE: "CWE-326",
		Types: []string{"Microsoft.ApiManagement/service"}, Remediation: "Set the Ssl30, Tls10 and Tls11 entries under properties.customProperties to \"false\".",
		Check: func(r *Resource) []Hit {
			cp, _ := armAt(r, "properties.customProperties").(map[string]any)
			for _, k := range []string{"Backend.Protocols.Ssl30", "Backend.Protocols.Tls10", "Backend.Protocols.Tls11", "Protocols.Ssl30", "Protocols.Tls10", "Protocols.Tls11"} {
				if v := cp["Microsoft.WindowsAzure.ApiManagement.Gateway.Security."+k]; strings.EqualFold(armStr(v), "true") {
					return []Hit{{Path: "properties.customProperties", Msg: "The gateway accepts " + k + ", which has known weaknesses."}}
				}
			}
			return nil
		}},
	{ID: "TG-ARM-AGW-201", Title: "Application Gateway WAF does not block Log4Shell", Severity: High, Category: CatSecurity, CWE: "CWE-917",
		Types: []string{"Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies"}, Remediation: "Use OWASP 3.1+ or Microsoft_DefaultRuleSet and keep rule 944240 enabled.",
		Check: func(r *Resource) []Hit {
			return armLog4j(r, "REQUEST-944-APPLICATION-ATTACK-JAVA", func(typ, ver string) bool {
				return (typ == "owasp" || typ == "") && (ver == "3.1" || ver == "3.2") || typ == "microsoft_defaultruleset"
			})
		}},
	{ID: "TG-ARM-FD-201", Title: "Front Door WAF does not block Log4Shell", Severity: High, Category: CatSecurity, CWE: "CWE-917",
		Types: []string{"Microsoft.Network/FrontDoorWebApplicationFirewallPolicies"}, Remediation: "Use DefaultRuleSet or Microsoft_DefaultRuleSet and keep rule 944240 enabled with action Block.",
		Check: func(r *Resource) []Hit {
			return armLog4j(r, "JAVA", func(typ, _ string) bool { return typ == "defaultruleset" || typ == "microsoft_defaultruleset" })
		}},
	{ID: "TG-ARM-FD-202", Title: "Front Door WAF policy is disabled", Severity: Medium, Category: CatSecurity, CWE: "CWE-693",
		Types: []string{"Microsoft.Network/FrontDoorWebApplicationFirewallPolicies"}, Remediation: "Set properties.policySettings.enabledState = \"Enabled\".",
		Check: func(r *Resource) []Hit {
			if strings.EqualFold(armStr(armAt(r, "properties.policySettings.enabledState")), "disabled") {
				return []Hit{{Path: "properties.policySettings", Msg: "Requests reach the backend without any WAF inspection."}}
			}
			return nil
		}},
	{ID: "TG-ARM-AGW-202", Title: "Application Gateway allows TLS older than 1.2 or weak ciphers", Severity: Medium, Category: CatSecurity, CWE: "CWE-326",
		Types: []string{"Microsoft.Network/applicationGateways"}, Remediation: "Set properties.sslPolicy to policyName AppGwSslPolicy20220101S, or a custom policy with minProtocolVersion TLSv1_2 and GCM ciphers.",
		Check: func(r *Resource) []Hit {
			sp := armAt(r, "properties.sslPolicy")
			if isUnknown(sp) {
				return nil
			}
			m, _ := sp.(map[string]any)
			if m == nil {
				// the default policy is TLS 1.2 only from API version 2023-02-01
				if v := armStr(r.get("apiVersion")); v != "" && v < "2023-02-01" {
					return []Hit{{Path: "properties", Msg: "No SSL policy is set, so this API version uses a default that allows TLS 1.0."}}
				}
				return nil
			}
			typ := strings.ToLower(armStr(m["policyType"]))
			if strings.HasPrefix(typ, "custom") {
				if !oneOf(m["minProtocolVersion"], []any{"TLSv1_2", "TLSv1_3"}) {
					return []Hit{{Path: "properties.sslPolicy", Msg: "The custom SSL policy allows TLS older than 1.2."}}
				}
				for _, c := range asStrings(m["cipherSuites"]) {
					if azpWeakCipher(c) {
						return []Hit{{Path: "properties.sslPolicy", Msg: "The custom SSL policy allows the weak cipher " + c + "."}}
					}
				}
				return nil
			}
			if name, ok := m["policyName"].(string); ok {
				if !oneOf(name, []any{"AppGwSslPolicy20170401S", "AppGwSslPolicy20220101", "AppGwSslPolicy20220101S"}) {
					return []Hit{{Path: "properties.sslPolicy", Msg: "The predefined SSL policy " + name + " allows TLS older than 1.2."}}
				}
				return nil
			}
			off := asStrings(m["disabledSslProtocols"])
			if isUnknown(m["policyName"]) || contains(off, "TLSv1_0") && contains(off, "TLSv1_1") {
				return nil
			}
			return []Hit{{Path: "properties.sslPolicy", Msg: "The SSL policy still allows TLS 1.0 or 1.1."}}
		}},
	{ID: "TG-ARM-APP-201", Title: "App Service built-in authentication is off", Severity: Low, Category: CatSecurity, CWE: "CWE-306",
		Types: []string{armWebCfg}, Remediation: "Enable authentication in the authsettingsV2 config (properties.platform.enabled = true) with an identity provider.",
		Check: func(r *Resource) []Hit {
			name := strings.ToLower(r.Name[strings.LastIndex(r.Name, "/")+1:])
			path := ""
			switch {
			case strings.Contains(name, "authsettingsv2"):
				path = "properties.platform.enabled"
			case strings.Contains(name, "authsettings"):
				path = "properties.enabled"
			default:
				return nil
			}
			if notTrue(armAt(r, path)) {
				return []Hit{{Path: "properties", Msg: "Requests reach the app without the platform checking who is calling."}}
			}
			return nil
		}},
	{ID: "TG-ARM-APP-202", Title: "App Service does not require client certificates", Severity: Low, Category: CatSecurity, CWE: "CWE-295",
		Types: []string{armWeb}, Remediation: "Set properties.clientCertEnabled = true when callers can present certificates.",
		Check: func(r *Resource) []Hit {
			if notTrue(armAt(r, "properties.clientCertEnabled")) {
				return []Hit{{Path: "properties", Msg: "Any client can connect without proving its identity with a certificate."}}
			}
			return nil
		}},
	{ID: "TG-ARM-BATCH-201", Title: "Batch account accepts public traffic from any address", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"Microsoft.Batch/batchAccounts"}, Remediation: "Set networkProfile.accountAccess.defaultAction = \"Deny\" with IP rules, or disable public network access.",
		Check: func(r *Resource) []Hit {
			if strings.EqualFold(armStr(armAt(r, "properties.publicNetworkAccess")), "disabled") {
				return nil
			}
			if strings.EqualFold(armStr(armAt(r, "properties.networkProfile.accountAccess.defaultAction")), "allow") {
				return []Hit{{Path: "properties.networkProfile", Msg: "The account endpoint is open to the whole internet."}}
			}
			return nil
		}},
	{ID: "TG-ARM-DEF-201", Title: "Defender for Cloud plan is on the Free tier", Severity: Medium, Category: CatSecurity, CWE: "CWE-693",
		Types: []string{armPricing}, Remediation: "Set properties.pricingTier = \"Standard\".",
		Check: func(r *Resource) []Hit {
			if t := armAt(r, "properties.pricingTier"); !isUnknown(t) && !strings.EqualFold(armStr(t), "standard") {
				return []Hit{{Path: "properties", Msg: "Threat detection for " + r.Name + " is off, so attacks on those resources raise no alerts."}}
			}
			return nil
		}},
	{ID: "TG-ARM-VM-201", Title: "Linux VM allows SSH password login", Severity: High, Category: CatSecurity, CWE: "CWE-287",
		Types: []string{armVM, armVMSS}, Remediation: "Set linuxConfiguration.disablePasswordAuthentication = true and add an SSH public key.",
		Check: func(r *Resource) []Hit {
			os := armOSProfile(r)
			linux, isMap := armAt(r, os+".linuxConfiguration").(map[string]any)
			if !isMap || armAt(r, os+".windowsConfiguration") != nil {
				return nil
			}
			if v := linux["disablePasswordAuthentication"]; notTrue(v) {
				return []Hit{{Path: os, Msg: "Anyone who guesses or reuses the admin password can log in over SSH."}}
			}
			return nil
		}},
	{ID: "TG-ARM-VM-202", Title: "VM custom data contains a credential", Severity: High, Category: CatSecurity, CWE: "CWE-798",
		Types: []string{armVM, armVMSS}, Remediation: "Fetch secrets at boot from Key Vault with the VM's managed identity instead of embedding them in customData.",
		Check: func(r *Resource) []Hit {
			s, _ := armAt(r, armOSProfile(r)+".customData").(string)
			if b, err := base64.StdEncoding.DecodeString(s); err == nil {
				s += "\n" + string(b)
			}
			if azpHasCredential(s) {
				return []Hit{{Path: armOSProfile(r), Msg: "customData is readable by anyone with read access to the VM and its deployment history."}}
			}
			return nil
		}},
	{ID: "TG-ARM-VM-203", Title: "VM uses unmanaged VHD disks", Severity: Low, Category: CatBestPrac, CWE: "CWE-1188",
		Types: []string{armVM}, Remediation: "Use managed disks (managedDisk) instead of vhd URIs.",
		Check: func(r *Resource) []Hit {
			disks := []any{armAt(r, "properties.storageProfile.osDisk")}
			if l, ok := armAt(r, "properties.storageProfile.dataDisks").([]any); ok {
				disks = append(disks, l...)
			}
			for _, d := range disks {
				if m, ok := d.(map[string]any); ok && m["vhd"] != nil {
					return []Hit{{Path: "properties.storageProfile", Msg: "The disk lives in a storage account blob, outside managed-disk encryption, RBAC and availability guarantees."}}
				}
			}
			return nil
		}},
	{ID: "TG-ARM-VM-204", Title: "Scale set does not patch its OS image automatically", Severity: Low, Category: CatSecurity, CWE: "CWE-1104",
		Types: []string{armVMSS}, Remediation: "Set upgradePolicy.automaticOSUpgradePolicy.enableAutomaticOSUpgrade = true.",
		Check: func(r *Resource) []Hit {
			v := armAt(r, "properties.upgradePolicy.automaticOSUpgradePolicy.enableAutomaticOSUpgrade")
			if isUnknown(v) || is(v, true) {
				return nil
			}
			exts, _ := armAt(r, "properties.virtualMachineProfile.extensionProfile.extensions").([]any)
			for _, e := range exts {
				if x := get(e, "properties.enableAutomaticUpgrade"); isUnknown(x) || is(x, true) {
					return nil
				}
			}
			return []Hit{{Path: "properties", Msg: "Instances keep running the original image until someone rolls them by hand."}}
		}},
	{ID: "TG-ARM-VM-206", Title: "Windows VM has automatic updates turned off", Severity: Low, Category: CatSecurity, CWE: "CWE-1104",
		Types: []string{armVM, armVMSS}, Remediation: "Set windowsConfiguration.enableAutomaticUpdates = true.",
		Check: func(r *Resource) []Hit {
			if is(armAt(r, armOSProfile(r)+".windowsConfiguration.enableAutomaticUpdates"), false) {
				return []Hit{{Path: armOSProfile(r), Msg: "Windows Update is off, so security patches are not installed."}}
			}
			return nil
		}},
	{ID: "TG-ARM-DISK-201", Title: "Managed disk encryption is turned off", Severity: Medium, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"Microsoft.Compute/disks"}, Remediation: "Remove encryptionSettingsCollection.enabled = false or set properties.encryption with a disk encryption set.",
		Check: func(r *Resource) []Hit {
			if armAt(r, "properties.encryption") != nil {
				return nil
			}
			if is(armAt(r, "properties.encryptionSettingsCollection.enabled"), false) || is(armAt(r, "properties.encryptionSettings.enabled"), false) {
				return []Hit{{Path: "properties", Msg: "Azure Disk Encryption is explicitly disabled for this disk."}}
			}
			return nil
		}},
	{ID: "TG-ARM-ST-201", Title: "Storage account accepts plain HTTP", Severity: Medium, Category: CatSecurity, CWE: "CWE-319",
		Types: []string{armStorage}, Remediation: "Set properties.supportsHttpsTrafficOnly = true.",
		Check: func(r *Resource) []Hit {
			v := armAt(r, "properties.supportsHttpsTrafficOnly")
			// HTTPS-only became the default with API version 2019-04-01
			if is(v, false) || v == nil && armStr(r.get("apiVersion")) != "" && armStr(r.get("apiVersion")) < "2019-04-01" {
				return []Hit{{Path: "properties", Msg: "Data and SAS tokens can be sent unencrypted."}}
			}
			return nil
		}},
	{ID: "TG-ARM-ST-202", Title: "Blob container allows anonymous public read", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{armStorage + "/blobServices/containers"}, Remediation: "Set properties.publicAccess = \"None\".",
		Check: func(r *Resource) []Hit {
			if oneOf(armAt(r, "properties.publicAccess"), []any{"Container", "Blob"}) {
				return []Hit{{Path: "properties.publicAccess", Msg: "Anyone on the internet can read blobs in this container without credentials."}}
			}
			return nil
		}},
	{ID: "TG-ARM-ST-203", Title: "Storage account network rules allow all traffic by default", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{armStorage}, Remediation: "Set properties.networkAcls.defaultAction = \"Deny\" and allow only the networks that need access.",
		Check: func(r *Resource) []Hit {
			if strings.EqualFold(armStr(armAt(r, "properties.publicNetworkAccess")), "disabled") {
				return nil
			}
			if v := armAt(r, "properties.networkAcls.defaultAction"); !isUnknown(v) && !strings.EqualFold(armStr(v), "deny") {
				return []Hit{{Path: "properties", Msg: "Any network can reach the account endpoints; only keys and SAS tokens stand in the way."}}
			}
			return nil
		}},
	{ID: "TG-ARM-ST-204", Title: "Storage firewall blocks trusted Azure services", Severity: Low, Category: CatReliability, CWE: "CWE-693",
		Types: []string{armStorage}, Remediation: "Add AzureServices to properties.networkAcls.bypass.",
		Check: func(r *Resource) []Hit {
			b, ok := armAt(r, "properties.networkAcls.bypass").(string)
			if ok && strings.EqualFold(armStr(armAt(r, "properties.networkAcls.defaultAction")), "deny") && !strings.Contains(strings.ToLower(b), "azureservices") {
				return []Hit{{Path: "properties.networkAcls", Msg: "Backup, monitoring and other Azure services cannot reach the account."}}
			}
			return nil
		}},
	{ID: "TG-ARM-ST-205", Title: "Invalid storage account name (deployment will fail)", Severity: High, Category: CatValidate, Blocking: true, CWE: "CWE-20",
		Types: []string{armStorage}, Remediation: "Use 3 to 24 characters, lowercase letters and digits only.",
		Check: func(r *Resource) []Hit {
			if n := r.Name; n != "" && !strings.HasPrefix(n, "[") && !azpStorageNameRE.MatchString(n) {
				return []Hit{{Path: "name", Msg: "Storage account name " + strconv.Quote(n) + " is not 3 to 24 lowercase letters and digits."}}
			}
			return nil
		}},
	{ID: "TG-ARM-ST-207", Title: "Queue service does not log reads, writes and deletes", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{armStorage + "/queueServices/providers/diagnosticSettings"}, Remediation: "Enable the StorageRead, StorageWrite and StorageDelete log categories.",
		Check: func(r *Resource) []Hit {
			logs, ok := armAt(r, "properties.logs").([]any)
			if isUnknown(armAt(r, "properties.logs")) {
				return nil
			}
			on := map[string]bool{}
			for _, l := range logs {
				if c, _ := get(l, "category").(string); is(get(l, "enabled"), true) || isUnknown(get(l, "enabled")) {
					on[strings.ToLower(c)] = true
				}
			}
			if !ok || !on["storageread"] || !on["storagewrite"] || !on["storagedelete"] {
				return []Hit{{Path: "properties", Msg: "Some queue operations are not logged, so misuse cannot be traced."}}
			}
			return nil
		}},
	armNSGPortRule("TG-ARM-NSG-201", "RDP", 3389, High),
	armNSGPortRule("TG-ARM-NSG-202", "SSH", 22, High),
	armNSGPortRule("TG-ARM-NSG-203", "HTTP", 80, Medium),
	{ID: "TG-ARM-SQL-201", Title: "SQL server firewall allows every IP address", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{armSQL}, Remediation: "Replace the 0.0.0.0-255.255.255.255 firewall rule with the specific ranges that need access.",
		Check: func(r *Resource) []Hit {
			for _, c := range armChildren(r, "firewallRules") {
				if oneOf(get(c.v, "properties.startIpAddress"), []any{"0.0.0.0", "0.0.0.0/0"}) && armStr(get(c.v, "properties.endIpAddress")) == "255.255.255.255" {
					return []Hit{{Path: c.path, Msg: "The database server accepts connections from the whole internet."}}
				}
			}
			return nil
		}},
	{ID: "TG-ARM-SQL-202", Title: "SQL server auditing is off", Severity: Medium, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{armSQL}, Remediation: "Add an auditingSettings child with properties.state = \"Enabled\".",
		Check: func(r *Resource) []Hit {
			kids := armChildren(r, "auditingSettings", "extendedAuditingSettings")
			if len(kids) == 0 && strings.HasPrefix(r.Name, "[") {
				return nil // children with unresolved names cannot be matched
			}
			for _, c := range kids {
				if s := get(c.v, "properties.state"); isUnknown(s) || strings.EqualFold(armStr(s), "enabled") {
					return nil
				}
			}
			return []Hit{{Path: "properties", Msg: "Queries, logins and permission changes are not recorded."}}
		}},
	{ID: "TG-ARM-SQL-203", Title: "SQL auditing keeps logs for less than 90 days", Severity: Low, Category: CatSecurity, CWE: "CWE-779",
		Types: []string{armSQL}, Remediation: "Set retentionDays to 90 or more (0 keeps logs forever).",
		Check: func(r *Resource) []Hit {
			for _, c := range armChildren(r, "auditingSettings", "extendedAuditingSettings") {
				if d, ok := asFloat(get(c.v, "properties.retentionDays")); ok && d > 0 && d < 90 && strings.EqualFold(armStr(get(c.v, "properties.state")), "enabled") {
					return []Hit{{Path: c.path, Msg: "Audit records are deleted before most investigations start."}}
				}
			}
			return nil
		}},
	{ID: "TG-ARM-SQL-204", Title: "SQL threat detection has alert types turned off", Severity: Medium, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{armSQL, armSQLDB}, Remediation: "Remove properties.disabledAlerts from the security alert policy.",
		Check: func(r *Resource) []Hit {
			for _, c := range armChildren(r, "securityAlertPolicies") {
				if d := get(c.v, "properties.disabledAlerts"); !isUnknown(d) && !containsUnknown(d) && len(armNonEmpty(d)) > 0 {
					return []Hit{{Path: c.path, Msg: "Attacks of the disabled types raise no alert."}}
				}
			}
			return nil
		}},
	{ID: "TG-ARM-SQL-205", Title: "SQL threat detection alerts go to nobody", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{armSQL, armSQLDB}, Remediation: "Set emailAddresses or emailAccountAdmins = true on the security alert policy.",
		Check: func(r *Resource) []Hit {
			for _, c := range armChildren(r, "securityAlertPolicies") {
				if !strings.EqualFold(armStr(get(c.v, "properties.state")), "enabled") {
					continue
				}
				mails, admins := get(c.v, "properties.emailAddresses"), get(c.v, "properties.emailAccountAdmins")
				if !isUnknown(mails) && !containsUnknown(mails) && len(armNonEmpty(mails)) == 0 && notTrue(admins) {
					return []Hit{{Path: c.path, Msg: "Alerts are raised but no one is emailed about them."}}
				}
			}
			return nil
		}},
	{ID: "TG-ARM-PG-201", Title: "PostgreSQL logging or connection throttling is turned off", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{"Microsoft.DBforPostgreSQL/servers/configurations", "Microsoft.DBforPostgreSQL/flexibleServers/configurations"}, Remediation: "Set the parameter's properties.value = \"on\".",
		Check: func(r *Resource) []Hit {
			name := strings.ToLower(r.Name[strings.LastIndex(r.Name, "/")+1:])
			if !contains([]string{"log_checkpoints", "log_connections", "connection_throttling", "connection_throttle.enable"}, name) {
				return nil
			}
			if v := armStr(armAt(r, "properties.value")); strings.EqualFold(v, "off") {
				return []Hit{{Path: "properties", Msg: name + " is off, which hides connection activity or lets failed logins go unthrottled."}}
			}
			return nil
		}},
	{ID: "TG-ARM-MON-201", Title: "Activity log profile keeps logs for less than a year", Severity: Low, Category: CatSecurity, CWE: "CWE-779",
		Types: []string{armLogProf}, Remediation: "Set retentionPolicy.days to 365 or more, or 0 to keep logs forever.",
		Check: func(r *Resource) []Hit {
			d, ok := asFloat(armAt(r, "properties.retentionPolicy.days"))
			if ok && d > 0 && d < 365 && is(armAt(r, "properties.retentionPolicy.enabled"), true) {
				return []Hit{{Path: "properties.retentionPolicy", Msg: "Activity history is deleted before a yearly review or late investigation."}}
			}
			return nil
		}},
	{ID: "TG-ARM-MON-202", Title: "Activity log profile does not capture every category", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{armLogProf}, Remediation: "Set properties.categories to Write, Delete and Action.",
		Check: func(r *Resource) []Hit {
			c := armAt(r, "properties.categories")
			if isUnknown(c) || containsUnknown(c) {
				return nil
			}
			got := asStrings(c)
			for _, want := range []string{"Write", "Delete", "Action"} {
				if !contains(got, want) {
					return []Hit{{Path: "properties", Msg: want + " operations are not logged."}}
				}
			}
			return nil
		}},
	{ID: "TG-ARM-NW-201", Title: "NSG flow logs are kept for less than 90 days", Severity: Low, Category: CatSecurity, CWE: "CWE-779",
		Types: []string{"Microsoft.Network/networkWatchers/flowLogs"}, Remediation: "Set retentionPolicy.days to 90 or more, or 0 to keep logs forever.",
		Check: func(r *Resource) []Hit {
			d, ok := asFloat(armAt(r, "properties.retentionPolicy.days"))
			if ok && d > 0 && d < 90 && is(armAt(r, "properties.retentionPolicy.enabled"), true) {
				return []Hit{{Path: "properties.retentionPolicy", Msg: "Network traffic records are deleted before most investigations start."}}
			}
			return nil
		}},
	{ID: "TG-ARM-IAM-201", Title: "Custom role grants every action on a subscription", Severity: High, Category: CatSecurity, CWE: "CWE-269",
		Types: []string{"Microsoft.Authorization/roleDefinitions"}, Remediation: "List only the actions the role needs, or use a built-in role.",
		Check: func(r *Resource) []Hit {
			scopes, _ := armAt(r, "properties.assignableScopes").([]any)
			wide := false
			for _, s := range scopes {
				t := strings.ToLower(armText(s))
				wide = wide || t == "/" || strings.HasPrefix(t, "/subscriptions/") && strings.Count(t, "/") == 2 || strings.Contains(t, "subscription().id")
			}
			perms, _ := armAt(r, "properties.permissions").([]any)
			for _, p := range perms {
				if wide && contains(asStrings(get(p, "actions")), "*") {
					return []Hit{{Path: "properties.permissions", Msg: "The role is an owner in all but name: whoever holds it controls the subscription."}}
				}
			}
			return nil
		}},
	{ID: "TG-ARM-KV-203", Title: "Key Vault is reachable from any network", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"Microsoft.KeyVault/vaults"}, Remediation: "Set properties.publicNetworkAccess = \"Disabled\" or networkAcls.defaultAction = \"Deny\".",
		Check: func(r *Resource) []Hit {
			pna, act := armAt(r, "properties.publicNetworkAccess"), armAt(r, "properties.networkAcls.defaultAction")
			if isUnknown(pna) || isUnknown(act) || strings.EqualFold(armStr(pna), "disabled") || strings.EqualFold(armStr(act), "deny") {
				return nil
			}
			return []Hit{{Path: "properties", Msg: "Anyone on the internet can reach the vault endpoint and try stolen credentials."}}
		}},
	{ID: "TG-ARM-DBX-201", Title: "Databricks root storage does not use a customer-managed key", Severity: Low, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{armDBX}, Remediation: "Set parameters.prepareEncryption.value = true and parameters.encryption with a Key Vault key.",
		Check: func(r *Resource) []Hit {
			if s := armStr(armAt(r, "sku.name")); s != "" && !strings.EqualFold(s, "premium") {
				return nil // customer-managed keys need the Premium tier
			}
			prep, enc := armAt(r, "properties.parameters.prepareEncryption.value"), armAt(r, "properties.parameters.encryption.value")
			if isUnknown(prep) || isUnknown(enc) || is(prep, true) && enc != nil {
				return nil
			}
			return []Hit{{Path: "properties", Msg: "Workspace root storage is encrypted only with keys you cannot rotate or revoke."}}
		}},
	{ID: "TG-ARM-MYSQL-201", Title: "MySQL server allows public network access", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"Microsoft.DBforMySQL/servers", "Microsoft.DBforMySQL/flexibleServers"}, Remediation: "Set publicNetworkAccess = \"Disabled\" and connect through private endpoints or VNet integration.",
		Check: func(r *Resource) []Hit {
			path := "properties.publicNetworkAccess"
			if strings.HasSuffix(r.Type, "flexibleServers") {
				path = "properties.network.publicNetworkAccess"
			}
			v := armAt(r, path)
			subnet := armAt(r, "properties.network.delegatedSubnetResourceId")
			if strings.EqualFold(armStr(v), "enabled") || v == nil && subnet == nil {
				return []Hit{{Path: "properties", Msg: "The database can be reached from the internet if firewall rules allow it."}}
			}
			return nil
		}},
	{ID: "TG-ARM-MYSQL-202", Title: "MySQL flexible server does not use a customer-managed key", Severity: Low, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"Microsoft.DBforMySQL/flexibleServers"}, Remediation: "Configure properties.dataEncryption with a Key Vault key.",
		Check: func(r *Resource) []Hit {
			a, b := armAt(r, "properties.dataEncryption"), armAt(r, "properties.dataencryption")
			if a == nil && b == nil {
				return []Hit{{Path: "properties", Msg: "Data is encrypted only with keys you cannot rotate or revoke."}}
			}
			return nil
		}},
	{ID: "TG-ARM-COSMOS-201", Title: "Cosmos DB account accepts connections from any address", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{armCosmos}, Remediation: "Add ipRules or virtual network rules (with isVirtualNetworkFilterEnabled = true), or disable public network access.",
		Check: func(r *Resource) []Hit {
			pna, ips, vnet, rules := armAt(r, "properties.publicNetworkAccess"), armAt(r, "properties.ipRules"), armAt(r, "properties.isVirtualNetworkFilterEnabled"), armAt(r, "properties.virtualNetworkRules")
			if isUnknown(pna) || isUnknown(ips) || isUnknown(vnet) || isUnknown(rules) || strings.EqualFold(armStr(pna), "disabled") || !empty(ips) || is(vnet, true) && !empty(rules) {
				return nil
			}
			return []Hit{{Path: "properties", Msg: "No IP or network filter is set, so the account answers the whole internet."}}
		}},
	{ID: "TG-ARM-COSMOS-203", Title: "Cosmos DB account allows key-based authentication", Severity: Medium, Category: CatSecurity, CWE: "CWE-287",
		Types: []string{armCosmos}, Remediation: "Set properties.disableLocalAuth = true and use Microsoft Entra ID with RBAC.",
		Check: func(r *Resource) []Hit {
			if k := armStr(armAt(r, "kind")); k != "" && !strings.EqualFold(k, "GlobalDocumentDB") {
				return nil
			}
			if notTrue(armAt(r, "properties.disableLocalAuth")) {
				return []Hit{{Path: "properties", Msg: "Anyone with a leaked account key gets full data access, outside Entra ID controls."}}
			}
			return nil
		}},
	{ID: "TG-ARM-SF-201", Title: "Service Fabric cluster does not encrypt and sign node traffic", Severity: Medium, Category: CatSecurity, CWE: "CWE-319",
		Types: []string{"Microsoft.ServiceFabric/clusters"}, Remediation: "Secure the cluster with a certificate and set the Security ClusterProtectionLevel to EncryptAndSign.",
		Check: func(r *Resource) []Hit {
			settings, _ := armAt(r, "properties.fabricSettings").([]any)
			for _, s := range settings {
				if !strings.EqualFold(armStr(get(s, "name")), "Security") {
					continue
				}
				params, _ := get(s, "parameters").([]any)
				for _, p := range params {
					if strings.EqualFold(armStr(get(p, "name")), "ClusterProtectionLevel") {
						if v := get(p, "value"); !isUnknown(v) && !strings.EqualFold(armStr(v), "EncryptAndSign") {
							return []Hit{{Path: "properties.fabricSettings", Msg: "Traffic between cluster nodes can be read or altered on the network."}}
						}
						return nil
					}
				}
			}
			// the default is EncryptAndSign only on a certificate-secured cluster
			if armAt(r, "properties.certificate") == nil && armAt(r, "properties.certificateCommonNames") == nil {
				return []Hit{{Path: "properties", Msg: "The cluster has no certificate, so node traffic is neither encrypted nor signed."}}
			}
			return nil
		}},
	{ID: "TG-ARM-VNET-201", Title: "Virtual network or NIC has a single DNS server", Severity: Low, Category: CatReliability, CWE: "CWE-693",
		Types: []string{"Microsoft.Network/virtualNetworks", "Microsoft.Network/networkInterfaces"}, Remediation: "List at least two DNS servers.",
		Check: func(r *Resource) []Hit {
			for _, p := range []string{"properties.dhcpOptions.dnsServers", "properties.dnsSettings.dnsServers"} {
				if l, ok := armAt(r, p).([]any); ok && len(l) == 1 {
					return []Hit{{Path: p, Msg: "Name resolution fails for every workload when that one server is down."}}
				}
			}
			return nil
		}},
	{ID: "TG-ARM-VNET-202", Title: "Virtual network uses DNS servers outside its address space", Severity: Info, Category: CatBestPrac, CWE: "CWE-693",
		Types: []string{"Microsoft.Network/virtualNetworks"}, Remediation: "Point dnsServers at resolvers inside the network, or use Azure Private DNS zones.",
		Check: func(r *Resource) []Hit {
			dns, _ := armAt(r, "properties.dhcpOptions.dnsServers").([]any)
			prefixes, _ := armAt(r, "properties.addressSpace.addressPrefixes").([]any)
			if len(dns) == 0 {
				return nil
			}
			for _, d := range dns {
				ip := net.ParseIP(armStr(d))
				if ip == nil {
					return nil
				}
				for _, p := range prefixes {
					_, n, err := net.ParseCIDR(armStr(p))
					if err != nil || n.Contains(ip) {
						return nil
					}
				}
			}
			return []Hit{{Path: "properties.dhcpOptions", Msg: "Name resolution depends on servers outside this network and its controls."}}
		}},
	{ID: "TG-ARM-SYN-201", Title: "Synapse SQL administrator password is written in the template", Severity: High, Category: CatSecurity, CWE: "CWE-798",
		Types: []string{armSynapse}, Remediation: "Pass the password as a secureString parameter without a default, or reference Key Vault.",
		Check: func(r *Resource) []Hit {
			if s, ok := armAt(r, "properties.sqlAdministratorLoginPassword").(string); ok && s != "" {
				return []Hit{{Path: "properties.sqlAdministratorLoginPassword", Msg: "Anyone who can read the template or its deployment history has the password."}}
			}
			return nil
		}},
	{ID: "TG-ARM-SYN-203", Title: "Synapse workspace has IP firewall rules", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{armSynapse}, Remediation: "Remove the firewall rules and reach the workspace through private endpoints.",
		Check: func(r *Resource) []Hit {
			for _, d := range asStrings(armAt(r, "dependsOn")) {
				if strings.Contains(strings.ToLower(d), "microsoft.synapse/workspaces/firewallrules") {
					return []Hit{{Path: "dependsOn", Msg: "The workspace endpoints accept connections from public IP ranges."}}
				}
			}
			if kids := armChildren(r, "firewallRules"); len(kids) > 0 {
				return []Hit{{Path: kids[0].path, Msg: "The workspace endpoints accept connections from public IP ranges."}}
			}
			return nil
		}},
	{ID: "TG-ARM-ML-201", Title: "Machine Learning workspace has no private endpoint", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"Microsoft.MachineLearningServices/workspaces"}, Remediation: "Disable public network access and add a private endpoint, or a PrivateEndpoint outbound rule in the managed network.",
		Check: func(r *Resource) []Hit {
			pna, rules := armAt(r, "properties.publicNetworkAccess"), armAt(r, "properties.managedNetwork.outboundRules")
			if isUnknown(pna) || isUnknown(rules) || strings.EqualFold(armStr(pna), "disabled") {
				return nil
			}
			if m, ok := rules.(map[string]any); ok {
				for _, x := range m {
					if t := get(x, "type"); isUnknown(t) || strings.EqualFold(armStr(t), "PrivateEndpoint") {
						return nil
					}
				}
			}
			return []Hit{{Path: "properties", Msg: "The workspace and its data are reached over public endpoints."}}
		}},
	{ID: "TG-ARM-SEC-202", Title: "Security alert emails are turned off", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{armContacts}, Remediation: "Set properties.alertNotifications to \"On\" (or state = \"On\").",
		Check: func(r *Resource) []Hit {
			v := armAt(r, "properties.alertNotifications")
			if m, ok := v.(map[string]any); ok {
				v = m["state"]
			}
			if !isUnknown(v) && !strings.EqualFold(armStr(v), "on") {
				return []Hit{{Path: "properties", Msg: "High-severity Defender alerts are not emailed to the security contact."}}
			}
			return nil
		}},
	{ID: "TG-ARM-SEC-203", Title: "Security alerts are not sent to subscription owners", Severity: Low, Category: CatSecurity, CWE: "CWE-778",
		Types: []string{armContacts}, Remediation: "Set properties.alertsToAdmins = \"On\" (or notificationsByRole.state = \"On\").",
		Check: func(r *Resource) []Hit {
			a, b := armAt(r, "properties.alertsToAdmins"), armAt(r, "properties.notificationsByRole.state")
			if isUnknown(a) || isUnknown(b) || strings.EqualFold(armStr(a), "on") || strings.EqualFold(armStr(b), "on") {
				return nil
			}
			return []Hit{{Path: "properties", Msg: "Owners and admins are not told about high-severity alerts."}}
		}},
	{ID: "TG-ARM-PARAM-201", Title: "Secure parameter has a hard-coded default", Severity: High, Category: CatSecurity, CWE: "CWE-798",
		Types: []string{"parameter"}, Remediation: "Remove defaultValue and pass the value at deployment time or from Key Vault.",
		Check: func(r *Resource) []Hit {
			switch d := r.Attrs["defaultValue"].(type) {
			case string:
				if d == "" || strings.HasPrefix(d, "[") && !strings.HasPrefix(d, "[[") {
					return nil // an expression such as newGuid() is not a hard-coded secret
				}
			case map[string]any:
				if len(d) == 0 {
					return nil
				}
			case nil:
				return nil
			}
			return []Hit{{Path: "defaultValue", Msg: "The secret is stored in the template, readable by anyone with the source."}}
		}},
}

func armNSGPortRule(id, name string, port float64, sev Severity) Rule {
	return Rule{ID: id, Title: "NSG allows " + name + " from the internet", Severity: sev, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{armNSG, armNSGRule}, Remediation: "Restrict sourceAddressPrefix to known ranges, or reach the port through Bastion or a VPN.",
		Check: func(r *Resource) []Hit {
			var rules []armNode
			if r.Type == armNSGRule {
				rules = []armNode{{"properties", r.Attrs["properties"]}}
			} else if l, ok := armAt(r, "properties.securityRules").([]any); ok {
				for i, x := range l {
					rules = append(rules, armNode{"properties.securityRules." + strconv.Itoa(i), get(x, "properties")})
				}
			}
			for _, rl := range rules {
				p, _ := rl.v.(map[string]any)
				if !strings.EqualFold(armStr(p["access"]), "allow") || !strings.EqualFold(armStr(p["direction"]), "inbound") || !oneOf(p["protocol"], []any{"tcp", "*"}) {
					continue
				}
				ports := append(armList(p["destinationPortRanges"]), p["destinationPortRange"])
				srcs := append(armList(p["sourceAddressPrefixes"]), p["sourceAddressPrefix"])
				for _, pr := range ports {
					if lo, hi, ok := portRange(pr); ok && lo <= port && port <= hi || armStr(pr) == "*" {
						for _, s := range srcs {
							if s, ok := s.(string); ok && azpInternet(s) {
								return []Hit{{Path: rl.path, Msg: name + " (port " + strconv.Itoa(int(port)) + ") is open to the whole internet."}}
							}
						}
					}
				}
			}
			return nil
		}}
}

// armLog4j reports a WAF policy with no managed rule set that blocks
// rule 944240 (Log4Shell), or one whose override turns that rule off.
func armLog4j(r *Resource, group string, ok func(typ, ver string) bool) []Hit {
	sets := armAt(r, "properties.managedRules.managedRuleSets")
	if isUnknown(sets) || containsUnknown(sets) {
		return nil
	}
	for _, s := range armList(sets) {
		typ, ver := strings.ToLower(armStr(get(s, "ruleSetType"))), armStr(get(s, "ruleSetVersion"))
		if !ok(typ, ver) {
			continue
		}
		off := false
		for _, g := range armList(get(s, "ruleGroupOverrides")) {
			if !strings.EqualFold(armStr(get(g, "ruleGroupName")), group) {
				continue
			}
			for _, x := range armList(get(g, "rules")) {
				if armStr(get(x, "ruleId")) != "944240" {
					continue
				}
				state := get(x, "state")
				if state == nil {
					state = get(x, "enabledState")
				}
				// an override entry without a state disables the rule
				off = off || state == nil || strings.EqualFold(armStr(state), "disabled") || oneOf(get(x, "action"), []any{"Log", "Allow"})
			}
		}
		if !off {
			return nil
		}
	}
	return []Hit{{Path: "properties", Msg: "Requests carrying JNDI lookups (CVE-2021-44228) are not blocked."}}
}

type armNode struct {
	path string
	v    any
}

// armAt is r.get, except a path through an Unknown value is Unknown.
func armAt(r *Resource, path string) any {
	var v any = r.Attrs
	for _, seg := range strings.Split(path, ".") {
		if isUnknown(v) {
			return v
		}
		v = get(v, seg)
	}
	return v
}

// armOSProfile is the osProfile path of a VM or scale set.
func armOSProfile(r *Resource) string {
	if r.Type == armVMSS {
		return "properties.virtualMachineProfile.osProfile"
	}
	return "properties.osProfile"
}

// armPools lists a cluster's agent pool profiles, or the pool's own properties.
func armPools(r *Resource) []armNode {
	if r.Type == armAKSPool {
		return []armNode{{"properties", armAt(r, "properties")}}
	}
	var out []armNode
	for i, p := range armList(armAt(r, "properties.agentPoolProfiles")) {
		out = append(out, armNode{"properties.agentPoolProfiles." + strconv.Itoa(i), p})
	}
	return out
}

// armChildren lists child resources of the given kinds (last type segment).
func armChildren(r *Resource, kinds ...string) []armNode {
	var out []armNode
	for i, c := range armList(r.Attrs["resources"]) {
		t := armStr(get(c, "type"))
		t = t[strings.LastIndex(t, "/")+1:]
		for _, k := range kinds {
			if strings.EqualFold(t, k) {
				out = append(out, armNode{"resources." + strconv.Itoa(i), c})
			}
		}
	}
	return out
}

func armList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return nil
}

func armNonEmpty(v any) []string {
	var out []string
	for _, s := range asStrings(v) {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

// armStr is a string or number value as text, "" otherwise.
func armStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	}
	return ""
}

// armForeign maps reference check IDs to the rules above and to generated
// rules that already cover the same control.
var armForeign = map[string][]string{
	"CKV_AZURE_138": {"TG-ARM-ACR-201"}, "CKV_AZURE_163": {"TG-ARM-ACR-202"}, "CKV_AZURE_233": {"TG-ARM-ACR-203"},
	"CKV_AZURE_6": {"TG-ARM-AKS-201"}, "CKV_AZURE_8": {"TG-ARM-AKS-202"}, "CKV_AZURE_4": {"TG-ARM-AKS-203"}, "CKV_AZURE_7": {"TG-ARM-AKS-204"},
	"CKV_AZURE_5": {"TG-ARM-AKS-205"}, "CKV_AZURE_168": {"TG-ARM-AKS-206"}, "CKV_AZURE_171": {"TG-ARM-AKS-207"}, "CKV_AZURE_227": {"TG-ARM-AKS-208"},
	"CKV_AZURE_173": {"TG-ARM-APIM-201"}, "CKV_AZURE_135": {"TG-ARM-AGW-201"}, "CKV_AZURE_218": {"TG-ARM-AGW-202"},
	"CKV_AZURE_133": {"TG-ARM-FD-201"}, "CKV_AZURE_123": {"TG-ARM-FD-202"},
	"CKV_AZURE_13": {"TG-ARM-APP-201"}, "CKV_AZURE_56": {"TG-ARM-APP-201"}, "CKV_AZURE_17": {"TG-ARM-APP-202"}, "CKV_AZURE_212": {"TG-ARM-APP-203"},
	"CKV_AZURE_213": {"TG-ARM-APP-204"}, "CKV_AZURE_70": {"TG-ARM-WEB-115", "TG-ARM-APP-205"},
	"CKV_AZURE_14": {"TG-ARM-WEB-115"}, "CKV_AZURE_15": {"TG-ARM-WEB-114"}, "CKV_AZURE_16": {"TG-ARM-WEB-107"}, "CKV_AZURE_18": {"TG-ARM-WEB-106"},
	"CKV_AZURE_248": {"TG-ARM-BATCH-201"}, "CKV_AZURE_75": {"TG-ARM-KUSTO-201"},
	"CKV_AZURE_19": {"TG-ARM-DEF-201"}, "CKV_AZURE_79": {"TG-ARM-DEF-201"}, "CKV_AZURE_84": {"TG-ARM-DEF-201"}, "CKV_AZURE_85": {"TG-ARM-DEF-201"}, "CKV_AZURE_87": {"TG-ARM-DEF-201"},
	"CKV_AZURE_1": {"TG-ARM-VM-201"}, "CKV_AZURE_49": {"TG-ARM-VM-201"}, "CKV_AZURE_149": {"TG-ARM-VM-201"}, "CKV_AZURE_178": {"TG-ARM-VM-201"},
	"CKV_AZURE_45": {"TG-ARM-VM-202"}, "CKV_AZURE_92": {"TG-ARM-VM-203"}, "CKV_AZURE_95": {"TG-ARM-VM-204"}, "CKV_AZURE_97": {"TG-ARM-COMPUTE-103", "TG-ARM-VM-205"},
	"CKV_AZURE_177": {"TG-ARM-VM-206"}, "CKV_AZURE_2": {"TG-ARM-DISK-201"},
	"CKV_AZURE_3": {"TG-ARM-ST-201"}, "CKV_AZURE_34": {"TG-ARM-ST-202"}, "CKV_AZURE_35": {"TG-ARM-ST-203"}, "CKV_AZURE_36": {"TG-ARM-ST-204"},
	"CKV_AZURE_43": {"TG-ARM-ST-205"}, "CKV_AZURE_44": {"TG-ARM-ST-206"}, "CKV_AZURE_33": {"TG-ARM-ST-207"},
	"CKV_AZURE_9": {"TG-ARM-NSG-201"}, "CKV_AZURE_10": {"TG-ARM-NSG-202"}, "CKV_AZURE_160": {"TG-ARM-NSG-203"},
	"CKV_AZURE_11": {"TG-ARM-SQL-201"}, "CKV_AZURE_23": {"TG-ARM-SQL-202"}, "CKV_AZURE_24": {"TG-ARM-SQL-203"}, "CKV_AZURE_25": {"TG-ARM-SQL-204"},
	"CKV_AZURE_26": {"TG-ARM-SQL-205"}, "CKV_AZURE_27": {"TG-ARM-SQL-205"},
	"CKV_AZURE_30": {"TG-ARM-PG-201"}, "CKV_AZURE_31": {"TG-ARM-PG-201"}, "CKV_AZURE_32": {"TG-ARM-PG-201"},
	"CKV_AZURE_37": {"TG-ARM-MON-201"}, "CKV_AZURE_38": {"TG-ARM-MON-202"}, "CKV_AZURE_12": {"TG-ARM-NW-201"}, "CKV_AZURE_39": {"TG-ARM-IAM-201"},
	"CKV_AZURE_41": {"TG-ARM-KV-201"}, "CKV_AZURE_112": {"TG-ARM-KV-202"}, "CKV_AZURE_189": {"TG-ARM-KV-203"}, "CKV_AZURE_42": {"TG-ARM-KEYVAULT-103"},
	"CKV2_AZURE_48": {"TG-ARM-DBX-201"}, "CKV_AZURE_158": {"TG-ARM-DBX-202"}, "CKV_AZURE_53": {"TG-ARM-MYSQL-201"}, "CKV_AZURE_96": {"TG-ARM-MYSQL-202"},
	"CKV_AZURE_99": {"TG-ARM-COSMOS-201"}, "CKV_AZURE_132": {"TG-ARM-COSMOS-202"}, "CKV_AZURE_140": {"TG-ARM-COSMOS-203"},
	"CKV_AZURE_103": {"TG-ARM-ADF-201"}, "CKV_AZURE_125": {"TG-ARM-SF-201"}, "CKV_AZURE_175": {"TG-ARM-PUBSUB-201"},
	"CKV_AZURE_182": {"TG-ARM-VNET-201"}, "CKV_AZURE_183": {"TG-ARM-VNET-202"}, "CKV_AZURE_208": {"TG-ARM-SEARCH-201"}, "CKV_AZURE_209": {"TG-ARM-SEARCH-202"},
	"CKV_AZURE_239": {"TG-ARM-SYN-201"}, "CKV_AZURE_240": {"TG-ARM-SYN-202"}, "CKV2_AZURE_19": {"TG-ARM-SYN-203"}, "CKV_AZURE_58": {"TG-ARM-SYN-204"}, "CKV_AZURE_243": {"TG-ARM-ML-201"},
	"CKV_AZURE_20": {"TG-ARM-SEC-201"}, "CKV_AZURE_21": {"TG-ARM-SEC-202"}, "CKV_AZURE_22": {"TG-ARM-SEC-203"}, "CKV_AZURE_131": {"TG-ARM-PARAM-201"},
}

func init() { registerForeign(armForeign) }

// armRuleSet is the ARM rules plus the single-setting checks.
func armRuleSet() []Rule {
	out := append([]Rule{}, armRules...)
	for _, c := range armSimple {
		out = append(out, c.rule())
	}
	return out
}
