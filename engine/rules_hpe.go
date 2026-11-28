package engine

import (
	"fmt"
	"strings"
)

// HPE rules for both Terraform providers: HPE/hpe (v2.3, hpe_morpheus_* and
// hpe_opsramp_*) and the legacy GreenLake provider HPE/hpegl (hpegl_vmaas_*,
// hpegl_metal_*, hpegl_caas_*). Every default relied on is from the provider
// source (terraform-provider-hpe) or, for hpegl, whose resource code lives in
// other modules, from its generated docs:
//   - morpheus { insecure } defaults to false (morpheus/provider.go).
//   - identity sources are SDKv2 resources whose create sends d.Get(...), so an
//     unset use_ssl sends useSSL "off" and an unset validate_assertion_signature
//     sends doNotValidateSignature true
//     (morpheus/sdkv2/resources/identitysource/resource_identity_source_*.go).
//   - ssl_cert = 0 or unset means no certificate on a virtual server
//     (morpheus/framework/resources/loadbalancervirtualserver/schema_gen.go).

// hpeWriteOnly lists the deprecated arguments that store a secret in state next
// to their write-only replacement (the only resources in v2.3 that have both,
// from the schema_gen.go of each). The provider detects changes to *_wo itself
// (write_only_revision); *_wo_version is deprecated, to be removed in 2.6.
var hpeWriteOnly = map[string][]string{
	"hpe_morpheus_network_domain":         {"domain_password"},
	"hpe_morpheus_task_shell_script":      {"remote_target_password"},
	"hpe_morpheus_task_powershell_script": {"remote_target_password"},
}

// hpeCredentialFields are the secret arguments of the credential resources.
var hpeCredentialFields = map[string][]string{
	"hpe_morpheus_cypher_secret": {"value"},
	"hpe_morpheus_credential":    {"password", "api_key", "client_secret", "secret_key"},
	"hpe_opsramp_credential_set": {"password", "account_key", "community", "enable_password", "encrypt_password",
		"esx_password", "management_certificate_passphrase", "sp_password"},
}

// hpeMigration maps hpegl VMaaS types to their direct HPE replacements, from the
// "hpegl to HPE" guide (docs/guides/hpegl_to_hpe_migration.md of
// terraform-provider-hpe v2.3.0): its resource table and its data source table.
// hpegl_vmaas_morpheus_details has no replacement and is not listed.
var hpeMigration = map[string]map[string]string{
	"managed": {
		"hpegl_vmaas_instance":                     "hpe_morpheus_instance",
		"hpegl_vmaas_instance_clone":               "hpe_morpheus_instance_clone",
		"hpegl_vmaas_network":                      "hpe_morpheus_network",
		"hpegl_vmaas_dhcp_server":                  "hpe_morpheus_network_dhcp_server",
		"hpegl_vmaas_router":                       "hpe_morpheus_network_router",
		"hpegl_vmaas_router_bgp_neighbor":          "hpe_morpheus_network_router_bgp_neighbor",
		"hpegl_vmaas_router_nat_rule":              "hpe_morpheus_network_router_nat",
		"hpegl_vmaas_router_route":                 "hpe_morpheus_network_router_route",
		"hpegl_vmaas_router_firewall_rule_group":   "hpe_morpheus_network_router_firewall_rule_group",
		"hpegl_vmaas_load_balancer":                "hpe_morpheus_load_balancer",
		"hpegl_vmaas_load_balancer_monitor":        "hpe_morpheus_load_balancer_monitor",
		"hpegl_vmaas_load_balancer_pool":           "hpe_morpheus_load_balancer_pool",
		"hpegl_vmaas_load_balancer_profile":        "hpe_morpheus_load_balancer_profile",
		"hpegl_vmaas_load_balancer_virtual_server": "hpe_morpheus_load_balancer_virtual_server",
	},
	"data": {
		"hpegl_vmaas_cloud":                                 "hpe_morpheus_cloud",
		"hpegl_vmaas_group":                                 "hpe_morpheus_group",
		"hpegl_vmaas_plan":                                  "hpe_morpheus_service_plan",
		"hpegl_vmaas_layout":                                "hpe_morpheus_instance_type_layout",
		"hpegl_vmaas_network":                               "hpe_morpheus_network",
		"hpegl_vmaas_datastore":                             "hpe_morpheus_datastore",
		"hpegl_vmaas_template":                              "hpe_morpheus_image",
		"hpegl_vmaas_environment":                           "hpe_morpheus_environment",
		"hpegl_vmaas_network_type":                          "hpe_morpheus_network_type",
		"hpegl_vmaas_network_pool":                          "hpe_morpheus_network_pool",
		"hpegl_vmaas_network_domain":                        "hpe_morpheus_network_domain",
		"hpegl_vmaas_router":                                "hpe_morpheus_network_router",
		"hpegl_vmaas_edge_cluster":                          "hpe_morpheus_network_edge_cluster",
		"hpegl_vmaas_transport_zone":                        "hpe_morpheus_network_transport_zone",
		"hpegl_vmaas_load_balancer":                         "hpe_morpheus_load_balancer",
		"hpegl_vmaas_load_balancer_monitor":                 "hpe_morpheus_load_balancer_monitor",
		"hpegl_vmaas_load_balancer_pool":                    "hpe_morpheus_load_balancer_pool",
		"hpegl_vmaas_load_balancer_profile":                 "hpe_morpheus_load_balancer_profile",
		"hpegl_vmaas_load_balancer_virtual_server":          "hpe_morpheus_load_balancer_virtual_server",
		"hpegl_vmaas_dhcp_server":                           "hpe_morpheus_network_dhcp_server",
		"hpegl_vmaas_resource_pool":                         "hpe_morpheus_resource_pool",
		"hpegl_vmaas_power_schedule":                        "hpe_morpheus_power_schedule",
		"hpegl_vmaas_cloud_folder":                          "hpe_morpheus_cloud_folder",
		"hpegl_vmaas_network_proxy":                         "hpe_morpheus_network_proxy",
		"hpegl_vmaas_network_interface":                     "hpe_morpheus_network_interface_type",
		"hpegl_vmaas_instance_storage_controller":           "hpe_morpheus_instance_storage_controller",
		"hpegl_vmaas_lb_pool_member_group":                  "hpe_morpheus_network_server_group",
		"hpegl_vmaas_instance_disk_type":                    "hpe_morpheus_instance_disk_type",
		"hpegl_vmaas_load_balancer_virtual_server_ssl_cert": "hpe_morpheus_certificate",
	},
}

func hpeMigrationTypes() []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range []string{"managed", "data"} {
		for _, t := range sortedKeys(hpeMigration[m]) {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	return out
}

// hpeLiteral returns a secret written in the code: a non-empty literal string
// that is not a placeholder and does not come from a variable.
func hpeLiteral(r *Resource, path string) (string, bool) {
	s, ok := r.get(path).(string)
	s = strings.TrimSpace(s)
	key := path[strings.LastIndex(path, ".")+1:]
	norm := func(x string) string { return strings.ToLower(strings.ReplaceAll(x, "-", "_")) }
	// Docs write the argument's own name as the value: access_token = "access_token".
	return s, ok && s != "" && !placeholder(s) && r.via(path) == "" && norm(s) != norm(key)
}

func str(v any) string { s, _ := asString(v); return s }

// hpeCredentialSet reports whether a resource sets any credential argument.
func hpeCredentialSet(attrs map[string]any) bool {
	for k, v := range attrs {
		if v != nil && (strings.Contains(k, "password") || strings.Contains(k, "token") || strings.Contains(k, "secret") ||
			k == "credential_id" || k == "private_key" || k == "access_key") {
			return true
		}
	}
	return false
}

var hpeURLAttr = map[string]string{
	"hpe_morpheus_integration_ansible":         "url",
	"hpe_morpheus_integration_ansible_tower":   "url",
	"hpe_morpheus_integration_chef":            "url",
	"hpe_morpheus_integration_docker_registry": "url",
	"hpe_morpheus_integration_git":             "url",
	"hpe_morpheus_integration_servicenow":      "url",
	"hpe_morpheus_integration_vro":             "url",
	"hpe_morpheus_network_pool_server":         "service_url",
	"hpe_morpheus_network_server":              "service_url",
	"hpe_morpheus_storage_server":              "service_url",
}

// hpeLegacyTLS are NSX-T protocol names older than TLS 1.2.
var hpeLegacyTLS = map[string]bool{"SSL_V2": true, "SSL_V3": true, "TLS_V1": true, "TLS_V1_1": true}

func sslProfileHits(path string, p map[string]any) []Hit {
	var hits []Hit
	if s, _ := asString(p["ssl_suite"]); strings.EqualFold(s, "HIGH_COMPATIBILITY") {
		hits = append(hits, Hit{Path: path + ".ssl_suite", Msg: `ssl_suite = "HIGH_COMPATIBILITY" lets clients negotiate TLS 1.0 and 1.1 and legacy ciphers such as 3DES.`})
	}
	for _, proto := range asStrings(p["supported_ssl_protocols"]) {
		if hpeLegacyTLS[strings.ToUpper(proto)] {
			hits = append(hits, Hit{Path: path + ".supported_ssl_protocols", Msg: "supported_ssl_protocols allows " + proto + ", which is deprecated (RFC 8996) and open to downgrade attacks."})
		}
	}
	return hits
}

// acceptsIngress is true for an inbound rule that allows traffic; direction is
// required because the providers do not document its default.
func acceptsIngress(direction, policy any) bool {
	d, _ := asString(direction)
	p, ok := asString(policy)
	p = strings.ToLower(p)
	return strings.EqualFold(d, "ingress") && (!ok || p == "accept" || p == "allow")
}

func ruleExposure(where string, protocol, ports any) []Hit {
	lo, hi, ok := portRange(ports)
	if p, _ := asString(protocol); ports == nil && (strings.EqualFold(p, "any") || strings.EqualFold(p, "all")) {
		lo, hi, ok = 0, 65535, true
	}
	if !ok {
		return nil
	}
	if p, _ := asString(protocol); strings.EqualFold(p, "icmp") {
		return nil
	}
	if sev, what, ok := exposure("tcp", lo, hi); ok {
		return []Hit{{Path: "port_range", Sev: sev, Msg: where + " opens " + what + " to every source address."}}
	}
	return nil
}

// eachHPEString calls fn for every literal string at parts, through nested
// blocks (lists of objects), nested attributes (objects) and lists of strings.
func eachHPEString(v any, parts []string, path string, fn func(path, v string)) {
	switch t := v.(type) {
	case map[string]any:
		if len(parts) > 0 {
			if c, ok := t[parts[0]]; ok {
				eachHPEString(c, parts[1:], join(path, parts[0]), fn)
			}
		}
	case []any:
		for i, e := range t {
			eachHPEString(e, parts, fmt.Sprintf("%s.%d", path, i), fn)
		}
	case string:
		if len(parts) == 0 && t != "" {
			fn(path, t)
		}
	}
}

// linePath shortens path to the deepest part the parser recorded a line for.
func linePath(r *Resource, path string) string {
	for p := path; p != ""; {
		if _, ok := r.Lines[p]; ok {
			return p
		}
		i := strings.LastIndex(p, ".")
		if i < 0 {
			break
		}
		p = p[:i]
	}
	return path
}

var hpeRules = []Rule{
	{ID: "TG-HPE-STATE-001", Title: "HPE resource stores a secret in Terraform state", Severity: Medium, Category: CatSecurity, CWE: "CWE-312",
		Types:       sortedKeys(hpeWriteOnly),
		Remediation: "Rename the argument to its write-only form (<field>_wo, for example domain_password_wo) and pass it from a sensitive or ephemeral variable. Write-only arguments need Terraform or OpenTofu 1.11 or later, so raise required_version if it allows older. The provider detects changes to the write-only value itself; do not add the deprecated <field>_wo_version.",
		Check: managed(func(r *Resource) []Hit {
			var hits []Hit
			for _, f := range hpeWriteOnly[r.Type] {
				v := r.get(f)
				if v == nil {
					continue
				}
				h := Hit{Path: f, Msg: fmt.Sprintf("%s is stored in Terraform state in plain text, readable by anyone with the state file; use %s_wo, which is never stored.", f, f),
					Fix: &Fix{Path: []string{f}, New: f + "_wo", Description: "Rename " + f + " to " + f + "_wo"}}
				if r.get(f+"_wo") != nil {
					h.Fix = nil // the provider rejects both together; leave the choice to the author
				}
				if _, lit := hpeLiteral(r, f); lit {
					h.Sev = High
					h.Msg = fmt.Sprintf("%s is written in the code and stored in Terraform state in plain text; use %s_wo from a sensitive variable, which is never stored.", f, f)
				}
				hits = append(hits, h)
			}
			return hits
		})},
	{ID: "TG-HPE-SEC-001", Title: "HPE credential resource holds a literal secret", Severity: High, Category: CatSecurity, CWE: "CWE-798",
		Types:       sortedKeys(hpeCredentialFields),
		Remediation: "Pass the secret from a sensitive variable fed by a secrets manager or CI secret, rotate the value, and remove it from git history. Anyone with the repository or the state can read it.",
		Check: managed(func(r *Resource) []Hit {
			var hits []Hit
			for _, f := range hpeCredentialFields[r.Type] {
				if v, ok := hpeLiteral(r, f); ok {
					hits = append(hits, Hit{Path: f, Msg: fmt.Sprintf("%s is set to a literal value (%s) in the code; it is also stored in Terraform state.", f, redact(v))})
				}
			}
			return hits
		})},
	{ID: "TG-HPE-TLS-001", Title: "HPE integration skips TLS certificate checks", Severity: Medium, Category: CatSecurity, CWE: "CWE-295",
		Types:       []string{"hpe_morpheus_network_pool_server", "hpe_morpheus_option_list_rest", "hpe_morpheus_setting_appliance"},
		Remediation: "Install a certificate the appliance trusts (a CA-signed certificate, or the private CA added to Morpheus' trust store) and remove the setting. It is not changed automatically because a self-signed endpoint would stop working.",
		Check: managed(func(r *Resource) []Hit {
			switch {
			case is(r.get("ignore_ssl"), true):
				return []Hit{{Path: "ignore_ssl", Msg: "ignore_ssl = true makes Morpheus accept any certificate from the IPAM server, so a man-in-the-middle gets its credentials."}}
			case is(r.get("ignore_ssl_errors"), true):
				return []Hit{{Path: "ignore_ssl_errors", Msg: "ignore_ssl_errors = true accepts any certificate from the REST endpoint, so a man-in-the-middle can read or change the option list data and any credentials sent."}}
			case is(r.get("agent_ssl_verify"), false):
				return []Hit{{Path: "agent_ssl_verify", Msg: "agent_ssl_verify = false makes every Morpheus agent accept any certificate for the appliance, so a man-in-the-middle can send commands to managed hosts."}}
			}
			return nil
		})},
	{ID: "TG-HPE-TLS-002", Title: "HPE endpoint receives credentials over plain HTTP", Severity: Medium, Category: CatSecurity, CWE: "CWE-319",
		Types:       sortedKeys(hpeURLAttr),
		Remediation: "Use an https:// URL so the credentials and data are encrypted in transit.",
		Check: managed(func(r *Resource) []Hit {
			a := hpeURLAttr[r.Type]
			if plainHTTP(str(r.get(a))) && hpeCredentialSet(r.Attrs) {
				return []Hit{{Path: a, Msg: a + " uses http://, so the credentials set on this resource and every response travel unencrypted."}}
			}
			return nil
		})},
	{ID: "TG-HPE-IAM-001", Title: "Active Directory identity source connects without SSL", Severity: Medium, Category: CatSecurity, CWE: "CWE-319",
		Types:       []string{"hpe_morpheus_identity_source_active_directory"},
		Remediation: "Set use_ssl = true (LDAPS) so the binding password and user logins are encrypted. Leaving it unset sends useSSL off.",
		Check: managed(func(r *Resource) []Hit {
			if v := r.get("use_ssl"); v == nil || is(v, false) {
				h := Hit{Path: "use_ssl", Msg: "use_ssl is false, so Morpheus sends the binding password and every user's login to the domain controller unencrypted."}
				if v == nil {
					h.Path, h.Msg = "", "use_ssl is not set, and the provider then sends useSSL off: the binding password and every user's login go to the domain controller unencrypted."
				}
				return []Hit{h}
			}
			return nil
		})},
	{ID: "TG-HPE-IAM-002", Title: "SAML identity source does not validate assertion signatures", Severity: High, Category: CatSecurity, CWE: "CWE-347",
		Types:       []string{"hpe_morpheus_identity_source_saml"},
		Remediation: "Set validate_assertion_signature = true. Leaving it unset sends doNotValidateSignature true.",
		Check: managed(func(r *Resource) []Hit {
			v := r.get("validate_assertion_signature")
			switch {
			case v == nil:
				return []Hit{{Msg: "validate_assertion_signature is not set, and the provider then turns signature checks off: anyone can forge a SAML response and log in as any user."}}
			case is(v, false):
				return []Hit{{Path: "validate_assertion_signature", Msg: "validate_assertion_signature = false: anyone can forge a SAML response and log in as any user."}}
			}
			return nil
		})},
	{ID: "TG-HPE-NET-001", Title: "HPE firewall rule opens admin ports to any source", Severity: High, Category: CatSecurity, CWE: "CWE-284",
		Types:       []string{"hpe_morpheus_security_group_rule", "hpe_morpheus_network_router_firewall_rule"},
		Remediation: "Allow the port only from the addresses that need it (a VPN, bastion or office range), or use a group or tier source.",
		Check: managed(func(r *Resource) []Hit {
			if !acceptsIngress(r.get("direction"), r.get("policy")) {
				return nil
			}
			if r.Type == "hpe_morpheus_security_group_rule" {
				st, _ := asString(r.get("source_type"))
				if (st == "" || strings.EqualFold(st, "cidr")) && anyWorld(r.get("source")) {
					return ruleExposure("The security group rule", r.get("protocol"), r.get("port_range"))
				}
				return nil
			}
			if st, _ := asString(r.get("source_type")); strings.EqualFold(st, "all") {
				return ruleExposure("The router firewall rule", r.get("protocol"), r.get("port_range"))
			}
			return nil
		})},
	{ID: "TG-HPE-LB-001", Title: "Load balancer virtual server serves HTTP without TLS", Severity: Low, Category: CatSecurity, CWE: "CWE-319",
		Types:       []string{"hpe_morpheus_load_balancer_virtual_server", "hpegl_vmaas_load_balancer_virtual_server"},
		Remediation: "Attach a certificate (ssl_cert on hpe, ssl_client_cert on hpegl) with an SSL client profile, or keep plain HTTP only on port 80 to redirect to HTTPS.",
		Check: managed(func(r *Resource) []Hit {
			proto, cert := "vip_protocol", "ssl_cert"
			if r.Type == "hpegl_vmaas_load_balancer_virtual_server" {
				proto, cert = "type", "ssl_client_cert"
			}
			if p, _ := asString(r.get(proto)); !strings.EqualFold(p, "http") {
				return nil
			}
			port, ok := asFloat(r.get("vip_port"))
			if !ok || port == 80 {
				return nil // port 80 is usually the redirect listener
			}
			if c := r.get(cert); c != nil {
				if n, isNum := asFloat(c); !isNum || n != 0 {
					return nil
				}
			}
			return []Hit{{Path: proto, Msg: fmt.Sprintf("The virtual server answers HTTP on port %g with no certificate, so sessions, cookies and credentials cross the network in clear text.", port)}}
		})},
	{ID: "TG-HPE-LB-002", Title: "Load balancer SSL profile allows TLS 1.0 or 1.1", Severity: Medium, Category: CatSecurity, CWE: "CWE-327",
		Types:       []string{"hpe_morpheus_load_balancer_profile", "hpegl_vmaas_load_balancer_profile"},
		Remediation: `Use ssl_suite = "BALANCED" or "HIGH_SECURITY", or with CUSTOM list only TLS_V1_2 (and TLS_V1_3 where supported).`,
		Check: managed(func(r *Resource) []Hit {
			var hits []Hit
			for _, k := range []string{"config_client_ssl", "config_server_ssl", "client_profile", "server_profile"} {
				for i, p := range r.blocks(k) {
					path := k
					if _, isList := r.Attrs[k].([]any); isList {
						path = fmt.Sprintf("%s.%d", k, i)
					}
					hits = append(hits, sslProfileHits(path, p)...)
				}
			}
			for i := range hits {
				hits[i].Path = linePath(r, hits[i].Path)
			}
			return hits
		})},
	{ID: "TG-HPE-METAL-001", Title: "Metal host user data sets a plaintext password", Severity: High, Category: CatSecurity, CWE: "CWE-256",
		Types:       []string{"hpegl_metal_host"},
		Remediation: "Use SSH keys (the ssh argument) or a hashed password (cloud-init passwd with a SHA-512 hash), and template secrets in from a sensitive variable.",
		Check: managed(func(r *Resource) []Hit {
			return guestPasswordHits(map[string]any{"user_data": r.Attrs["user_data"]}, "", false)
		})},
	{ID: "TG-HPE-MIG-001", Title: "hpegl VMaaS type has a replacement in the HPE provider", Severity: Info, Category: CatBestPrac,
		Types:       hpeMigrationTypes(),
		Remediation: `Migrate to the HPE/hpe provider with HPE's tfmigrator tool ("tfmigrator migrate"), which rewrites hpegl_vmaas_* to hpe_morpheus_* and transforms the provider block; then check that terraform plan shows no changes. See the "hpegl to HPE" and "tfmigrator" guides in the HPE provider docs.`,
		Check: func(r *Resource) []Hit {
			if r.Format != "" {
				return nil
			}
			mode := "managed"
			if r.Mode == "data" {
				mode = "data"
			}
			if to := hpeMigration[mode][r.Type]; to != "" {
				return []Hit{{Msg: fmt.Sprintf("%s is replaced by %s in the HPE provider (HPE/hpe), which also manages Morpheus directly; HPE's tfmigrator tool ports it, as described in the provider's hpegl to HPE migration guide.", r.Type, to)}}
			}
			return nil
		}},
	{ID: "TG-VAL-026", Title: "Value the HPE provider rejects", Severity: High, Category: CatValidate, CWE: "CWE-20", Blocking: true,
		Types: valueTypes(hpeValueChecks), Remediation: "Use one of the values the HPE provider accepts; terraform validate and plan fail otherwise.",
		Check: func(r *Resource) []Hit {
			if r.Mode == "data" || r.Format != "" {
				return nil
			}
			var hits []Hit
			for _, c := range hpeValueChecks[r.Type] {
				eachHPEString(r.Attrs, strings.Split(c.attr, "."), "", func(path, v string) {
					cc := awsValueCheck{attr: c.attr, enum: c.enum}
					if msg := cc.problem(v); msg != "" {
						hits = append(hits, Hit{Path: linePath(r, path), Msg: fmt.Sprintf("%s = %q: %s; the hpe provider rejects it at plan time.", c.attr, v, msg)})
					}
				})
			}
			return hits
		}},
}

// hpeProviderRules report provider block settings. They are listed with the
// resource rules for their metadata; their Types match no resource, and
// hpeProviderChecks, a module check, produces the findings.
var hpeProviderRules = []Rule{
	{ID: "TG-HPE-PRV-001", Title: "HPE provider skips TLS certificate checks", Severity: High, Category: CatSecurity, CWE: "CWE-295",
		Types: hpeProviderTypes, Check: noHits,
		Remediation: "Remove insecure = true (hpe, morpheus block) or allow_insecure = true (hpegl, vmaas block), and give the appliance a certificate the runner trusts (CA-signed, or its CA in the system trust store)."},
	{ID: "TG-HPE-PRV-002", Title: "HPE provider credential written in the configuration", Severity: High, Category: CatSecurity, CWE: "CWE-798",
		Types: hpeProviderTypes, Check: noHits,
		Remediation: "Remove the value from the provider block. OpsRamp reads OPSRAMP_CLIENT_ID and OPSRAMP_CLIENT_SECRET; hpegl reads HPEGL_USER_ID, HPEGL_USER_SECRET and HPEGL_MORPHEUS_TOKEN; the morpheus block has no environment variables, so pass password, access_token, client_secret or iam_token from a sensitive variable (TF_VAR_...). Rotate the leaked value."},
}

var hpeProviderTypes = []string{"provider.hpe", "provider.hpegl"}

func noHits(*Resource) []Hit { return nil }

type hpeProviderSetting struct {
	provider, path string // path inside the provider block: block.attr or attr
}

var (
	hpeTLSOff = []hpeProviderSetting{{"hpe", "morpheus.insecure"}, {"hpegl", "vmaas.allow_insecure"}}
	hpeCreds  = []hpeProviderSetting{
		{"hpe", "morpheus.password"}, {"hpe", "morpheus.access_token"},
		{"hpe", "morpheus.pce_identity.client_secret"}, {"hpe", "morpheus.pce_identity.iam_token"},
		{"hpe", "morpheus.pce_disconnected_identity.client_secret"}, {"hpe", "morpheus.pce_disconnected_identity.iam_token"},
		{"hpe", "opsramp.client_secret"},
		{"hpegl", "user_secret"}, {"hpegl", "iam_token"}, {"hpegl", "vmaas.morpheus_token"},
	}
	hpeURLs = []hpeProviderSetting{{"hpe", "morpheus.url"}, {"hpegl", "vmaas.morpheus_url"}, {"hpegl", "iam_service_url"}}
)

// hpeProviderChecks reports hpe and hpegl provider blocks that turn certificate
// checks off, hold literal credentials, or reach the appliance over http.
func hpeProviderChecks(m *Module) []Finding {
	var out []Finding
	count := map[string]int{}
	for _, b := range m.Blocks {
		if b.Kind == "provider" && len(b.Labels) == 1 {
			count[b.File+" "+b.Labels[0]]++
		}
	}
	for _, b := range m.Blocks {
		if b.Kind != "provider" || len(b.Labels) != 1 || (b.Labels[0] != "hpe" && b.Labels[0] != "hpegl") {
			continue
		}
		r := &Resource{Attrs: b.Attrs, Lines: b.Lines, Via: b.via, Line: b.Line}
		addr := "provider." + b.Labels[0]
		each := func(list []hpeProviderSetting, fn func(path string, v any)) {
			for _, s := range list {
				if s.provider != b.Labels[0] {
					continue
				}
				parts := strings.Split(s.path, ".")
				eachHPEValue(b.Attrs, parts, "", fn)
			}
		}
		each(hpeTLSOff, func(path string, v any) {
			if !is(v, true) {
				return
			}
			attr := path[strings.LastIndex(path, ".")+1:]
			f := newFinding("TG-HPE-PRV-001", "", fmt.Sprintf("provider %q sets %s = true, so it sends credentials to any server that answers, including a man-in-the-middle.", b.Labels[0], attr), addr, b.File, r.line(path))
			if src := r.via(path); src != "" {
				f.Message += " The value comes from " + src + "; change it where that is set."
			} else if count[b.File+" "+b.Labels[0]] == 1 && strings.Count(path, ".") == 2 && strings.Contains(path, ".0.") {
				block := path[:strings.Index(path, ".")]
				f.Fix = &Fix{File: b.File, Block: addr, Path: []string{block, attr}, Value: false, Description: "Set " + attr + " = false"}
			}
			out = append(out, f)
		})
		each(hpeCreds, func(path string, _ any) {
			if v, ok := hpeLiteral(r, path); ok {
				attr := path[strings.LastIndex(path, ".")+1:]
				out = append(out, newFinding("TG-HPE-PRV-002", "", fmt.Sprintf("provider %q sets %s to a literal value (%s); anyone with the repository can use it.", b.Labels[0], attr, redact(v)), addr, b.File, r.line(path)))
			}
		})
		each(hpeURLs, func(path string, v any) {
			if plainHTTP(str(v)) {
				attr := path[strings.LastIndex(path, ".")+1:]
				out = append(out, newFinding("TG-HPE-TLS-002", "", fmt.Sprintf("provider %q sets %s to an http:// URL, so its credentials and tokens travel unencrypted.", b.Labels[0], attr), addr, b.File, r.line(path)))
			}
		})
	}
	return out
}

// eachHPEValue calls fn for every value at parts, with its Lines path.
func eachHPEValue(v any, parts []string, path string, fn func(path string, v any)) {
	switch t := v.(type) {
	case map[string]any:
		if len(parts) == 0 {
			return
		}
		if c, ok := t[parts[0]]; ok {
			if len(parts) == 1 {
				fn(join(path, parts[0]), c)
				return
			}
			eachHPEValue(c, parts[1:], join(path, parts[0]), fn)
		}
	case []any:
		for i, e := range t {
			eachHPEValue(e, parts, fmt.Sprintf("%s.%d", path, i), fn)
		}
	}
}

func init() {
	for _, id := range []string{"TG-HPE-PRV-001", "TG-HPE-TLS-001"} {
		ruleThemes[id] = []string{"encryption-in-transit"}
	}
	ruleThemes["TG-HPE-IAM-002"] = []string{"access"}
	ruleThemes["TG-HPE-METAL-001"] = []string{"secrets"}
}
