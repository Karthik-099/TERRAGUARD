package engine

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Nutanix rules for both Terraform provider generations: v1 names (nutanix_virtual_machine,
// nutanix_network_security_rule, nutanix_image) and v2 names (nutanix_virtual_machine_v2,
// nutanix_network_security_policy_v2, nutanix_images_v2), plus Cluster API (CAPX) manifests.

var (
	// Windows answer files mark a password stored in clear with <PlainText>true</PlainText>.
	sysprepPlainRE = regexp.MustCompile(`(?i)<PlainText>\s*true\s*</PlainText>`)
	// cloud-init password keys; lock_passwd and hashed_passwd are excluded by the boundary.
	cloudInitPassRE = regexp.MustCompile(`(?m)(?:^|[{,\s-])(plain_text_passwd|passwd|password)\s*:\s*["']?([^\s"',}#]+)`)
	chpasswdEchoRE  = regexp.MustCompile(`echo\s+["']?[\w.-]+:[^\s$"'|]+["']?\s*\|\s*(?:sudo\s+)?chpasswd`)
)

// plaintextPassword names the kind of clear-text password found in guest
// customization data (cloud-init or sysprep), or returns "".
func plaintextPassword(text string) string {
	if sysprepPlainRE.MatchString(text) {
		return "the Windows answer file stores a password with PlainText true"
	}
	for _, m := range cloudInitPassRE.FindAllStringSubmatch(text, -1) {
		v := strings.ToLower(m[2])
		if strings.HasPrefix(v, "$") || strings.HasPrefix(v, "{{") || strings.HasPrefix(v, "<") || strings.HasPrefix(v, "!") ||
			v == "true" || v == "false" || v == "null" || v == "~" {
			continue // hashes, template placeholders, locked accounts, booleans
		}
		return "the cloud-init data sets " + m[1] + " in clear text"
	}
	if chpasswdEchoRE.MatchString(text) {
		return "the user data pipes a clear-text password into chpasswd"
	}
	return ""
}

// guestPasswordHits looks at every value under a guest customization key
// (cloud-init user data, sysprep answer files), decoding base64 literals.
func guestPasswordHits(attrs map[string]any, path string, inGuest bool) []Hit {
	var hits []Hit
	for _, k := range sortedKeys(attrs) {
		p := join(path, k)
		g := inGuest || strings.Contains(k, "cloud_init") || strings.Contains(k, "sysprep") || strings.Contains(k, "unattend") || k == "user_data"
		switch v := attrs[k].(type) {
		case map[string]any:
			hits = append(hits, guestPasswordHits(v, p, g)...)
		case []any:
			for i, e := range v {
				if m, ok := e.(map[string]any); ok {
					hits = append(hits, guestPasswordHits(m, fmt.Sprintf("%s.%d", p, i), g)...)
				} else if g {
					hits = append(hits, guestPasswordHit(e, p)...)
				}
			}
		default:
			if g {
				hits = append(hits, guestPasswordHit(v, p)...)
			}
		}
	}
	return hits
}

func guestPasswordHit(v any, path string) []Hit {
	if what := plaintextPassword(othpText(v)); what != "" {
		return []Hit{{Path: path, Msg: "In " + path + ", " + what + "; anyone who can read the VM configuration, the code or the state can log in."}}
	}
	return nil
}

// managed wraps a check so it skips data sources, which read settings rather than set them.
func managed(check func(r *Resource) []Hit) func(r *Resource) []Hit {
	return func(r *Resource) []Hit {
		if r.Mode == "data" {
			return nil
		}
		return check(r)
	}
}

// checkRules turns table checks into rules that skip data sources.
func checkRules(cs []check) []Rule {
	out := make([]Rule, 0, len(cs))
	for _, c := range cs {
		r := c.rule()
		r.Check = managed(r.Check)
		out = append(out, r)
	}
	return out
}

// worldPeer is true for a Flow peer that matches every address.
func worldPeer(spec, ip, prefix any) bool {
	if s, _ := asString(spec); s == "ALL" {
		return true
	}
	ipS, _ := asString(ip)
	n, ok := asFloat(prefix)
	return ipS == "0.0.0.0" && ok && n == 0
}

var nutanixChecks = []check{
	{ID: "TG-NTX-ST-001", Sev: Medium, Cat: CatReliability, Title: "Storage container keeps a single copy of data",
		Types: []string{"nutanix_storage_containers_v2"}, Kind: "eq", Path: "replication_factor", Bad: []any{1}, Good: 2,
		Msg: "replication_factor = 1 keeps one copy of every block, so a single disk or node failure loses data."},
}

var nutanixRules = append(checkRules(nutanixChecks), []Rule{
	{ID: "TG-NTX-VM-001", Title: "Guest customization sets a plaintext password", Severity: High, Category: CatSecurity, CWE: "CWE-256",
		Types:       []string{"nutanix_virtual_machine", "nutanix_virtual_machine_v2", "nutanix_vm_guest_customization_profile_v2", "nutanix_template_v2", "nutanix_vm_gc_update_v2", "nutanix_vm_clone_v2"},
		Remediation: "Use SSH keys or a hashed password (cloud-init passwd with a SHA-512 hash), and pass Windows passwords from a sensitive variable with PlainText false.",
		Check: managed(func(r *Resource) []Hit {
			return guestPasswordHits(r.Attrs, "", false)
		})},
	{ID: "TG-NTX-VM-002", Title: "UEFI VM boots without Secure Boot", Severity: Low, Category: CatSecurity, CWE: "CWE-693",
		Types:       []string{"nutanix_virtual_machine", "nutanix_virtual_machine_v2"},
		Remediation: `Use boot_type = "SECURE_BOOT" (v1) or boot_config { uefi_boot { is_secure_boot_enabled = true } } with machine_type = "Q35" (v2).`,
		Check: managed(func(r *Resource) []Hit {
			if s, _ := asString(r.get("boot_type")); s == "UEFI" {
				return []Hit{{Path: "boot_type", Msg: `boot_type = "UEFI" loads unsigned boot loaders and kernels, so a bootkit survives reinstalls of the OS.`}}
			}
			for i, bc := range r.blocks("boot_config") {
				for j, u := range asMaps(bc["uefi_boot"]) {
					if v := u["is_secure_boot_enabled"]; notTrue(v) {
						return []Hit{{Path: fmt.Sprintf("boot_config.%d.uefi_boot.%d", i, j), Msg: "The VM boots with UEFI but Secure Boot is off, so unsigned boot loaders and kernels run."}}
					}
				}
			}
			return nil
		})},
	{ID: "TG-NTX-FLOW-001", Title: "Flow security policy allows inbound traffic from any source", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types:       []string{"nutanix_network_security_rule", "nutanix_network_security_policy_v2"},
		Remediation: "Allow inbound traffic only from specific categories, address groups or subnets, and only on the ports the application needs.",
		Check: managed(func(r *Resource) []Hit {
			var hits []Hit
			for _, list := range []string{"app_rule_inbound_allow_list", "ad_rule_inbound_allow_list"} {
				for i, in := range r.blocks(list) {
					if !worldPeer(in["peer_specification_type"], in["ip_subnet"], in["ip_subnet_prefix_length"]) {
						continue
					}
					h := Hit{Path: fmt.Sprintf("%s.%d", list, i), Msg: "An inbound allow entry matches every source address."}
					if p, _ := asString(in["protocol"]); p == "ALL" {
						h.Sev, h.Msg = High, "An inbound allow entry matches every source address on every protocol and port."
					}
					hits = append(hits, h)
				}
			}
			for i, rule := range r.blocks("rules") {
				for _, spec := range asMaps(rule["spec"]) {
					for _, app := range asMaps(spec["application_rule_spec"]) {
						var src map[string]any
						if s := asMaps(app["src_subnet"]); len(s) > 0 {
							src = s[0]
						}
						if !worldPeer(app["src_allow_spec"], src["value"], src["prefix_length"]) {
							continue
						}
						h := Hit{Path: fmt.Sprintf("rules.%d", i), Msg: "An application rule allows traffic from every source into the secured group."}
						if is(app["is_all_protocol_allowed"], true) {
							h.Sev, h.Msg = High, "An application rule allows every protocol and port from every source into the secured group."
						}
						hits = append(hits, h)
					}
				}
			}
			return hits
		})},
	{ID: "TG-NTX-IMG-001", Title: "Image is downloaded without an integrity check", Severity: Medium, Category: CatSecurity, CWE: "CWE-494",
		Types:       []string{"nutanix_image", "nutanix_images_v2"},
		Remediation: "Download over https with certificate checks on, and set checksum so a tampered image is rejected.",
		Check: managed(func(r *Resource) []Hit {
			if r.get("checksum") != nil {
				return nil
			}
			if u, _ := asString(r.get("source_uri")); strings.HasPrefix(strings.ToLower(u), "http://") {
				return []Hit{{Path: "source_uri", Msg: "The image comes over plain http with no checksum, so anyone on the path can swap in a backdoored disk."}}
			}
			for i, src := range r.blocks("source") {
				for j, us := range asMaps(src["url_source"]) {
					p := fmt.Sprintf("source.%d.url_source.%d", i, j)
					if u, _ := asString(us["url"]); strings.HasPrefix(strings.ToLower(u), "http://") {
						return []Hit{{Path: p + ".url", Msg: "The image comes over plain http with no checksum, so anyone on the path can swap in a backdoored disk."}}
					}
					if is(us["should_allow_insecure_url"], true) {
						return []Hit{{Path: p + ".should_allow_insecure_url", Msg: "Certificate errors are ignored and there is no checksum, so a man-in-the-middle can serve a tampered image."}}
					}
				}
			}
			return nil
		})},
	{ID: "TG-NTX-NKE-001", Title: "NKE cluster has a single control plane", Severity: Medium, Category: CatReliability,
		Types:       []string{"nutanix_karbon_cluster"},
		Remediation: "Add active_passive_config or external_lb_config for two or more masters, and run etcd_node_pool with 3 instances.",
		Check: managed(func(r *Resource) []Hit {
			var hits []Hit
			if r.get("active_passive_config") == nil && r.get("external_lb_config") == nil {
				hits = append(hits, Hit{Path: "master_node_pool", Msg: "With no active_passive_config or external_lb_config the cluster runs one master; when it fails, the Kubernetes API is down."})
			}
			if n, ok := asFloat(r.get("etcd_node_pool.num_instances")); ok && n < 3 {
				hits = append(hits, Hit{Path: "etcd_node_pool", Msg: fmt.Sprintf("etcd runs on %g node(s), so losing one loses quorum and the cluster state.", n)})
			}
			return hits
		})},
	{ID: "TG-NTX-IAM-001", Title: "Directory service binds over plain LDAP", Severity: Medium, Category: CatSecurity, CWE: "CWE-319",
		Types:       []string{"nutanix_directory_services_v2"},
		Remediation: "Use an ldaps:// URL (port 636) so the service account password and user logins are encrypted.",
		Check: managed(func(r *Resource) []Hit {
			for _, k := range []string{"url", "secondary_urls"} {
				for _, u := range asStrings(r.get(k)) {
					if strings.HasPrefix(strings.ToLower(u), "ldap://") {
						return []Hit{{Path: k, Msg: "Prism sends the service account password and every user's login to " + u + " unencrypted."}}
					}
				}
			}
			return nil
		})},
	{ID: "TG-NTX-SNMP-001", Title: "SNMPv3 user uses MD5 or DES", Severity: Medium, Category: CatSecurity, CWE: "CWE-327",
		Types:       []string{"nutanix_snmp_user_v2"},
		Remediation: `Set auth_type = "SHA256" (or stronger) and priv_type = "AES256".`,
		Check: managed(func(r *Resource) []Hit {
			var hits []Hit
			if s, _ := asString(r.get("auth_type")); s == "MD5" {
				hits = append(hits, Hit{Path: "auth_type", Msg: "MD5 authentication can be forged; an attacker on the network can change SNMP data in transit."})
			}
			if s, _ := asString(r.get("priv_type")); s == "DES" {
				hits = append(hits, Hit{Path: "priv_type", Msg: "DES encryption is broken; captured SNMP traffic can be decrypted."})
			}
			return hits
		})},
	{ID: "TG-NTX-SNMP-002", Title: "SNMP trap uses a v2c community string", Severity: Low, Category: CatSecurity, CWE: "CWE-319",
		Types:       []string{"nutanix_snmp_trap_v2"},
		Remediation: `Use version = "V3" with a username and SHA/AES authentication and encryption.`,
		Check: managed(func(r *Resource) []Hit {
			if v, _ := asString(r.get("version")); v != "V2" {
				return nil
			}
			if c, _ := asString(r.get("community_string")); c == "public" || c == "private" {
				return []Hit{{Path: "community_string", Sev: Medium, Msg: "SNMPv2c sends the well-known community string " + c + " in clear text with every trap."}}
			}
			return []Hit{{Path: "version", Msg: "SNMPv2c sends the community string and every trap in clear text."}}
		})},

	// Cluster API provider (CAPX), as used by Nutanix Kubernetes Platform.
	{ID: "TG-NTX-CAPX-001", Title: "CAPX skips Prism Central certificate checks", Severity: Medium, Category: CatSecurity, CWE: "CWE-295",
		Types:       []string{"kubernetes_nutanix_cluster"},
		Remediation: "Set spec.prismCentral.insecure: false, and give a private CA through additionalTrustBundle.",
		Check: func(r *Resource) []Hit {
			if is(r.get("spec.prism_central.insecure"), true) {
				return []Hit{{Path: "spec.prism_central.insecure", Msg: "The controller sends Prism Central credentials to whoever answers at the address, so a man-in-the-middle can take them.",
					Fix: fix(false, "Set spec.prismCentral.insecure: false", "spec", "prism_central", "insecure")}}
			}
			return nil
		}},
	{ID: "TG-NTX-CAPX-002", Title: "Prism Central credentials are written in a manifest", Severity: High, Category: CatSecurity, CWE: "CWE-798",
		Types:       []string{"kubernetes_secret_v1"},
		Remediation: "Create the credentials Secret from a secret store (External Secrets, Sealed Secrets, SOPS) or clusterctl variables; never commit the password.",
		Check: func(r *Resource) []Hit {
			for _, k := range []string{"string_data", "data"} {
				s, _ := asString(r.get(k + ".credentials"))
				if k == "data" {
					b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
					if err != nil {
						continue
					}
					s = string(b)
				}
				if capxLiteralPassword(s) {
					return []Hit{{Path: k, Msg: "The Secret holds a Prism Central password in the manifest; anyone with the repository can log in to Prism."}}
				}
			}
			return nil
		}},
	{ID: "TG-NTX-CAPX-003", Title: "Nutanix cluster runs fewer than three control plane nodes", Severity: Medium, Category: CatReliability,
		Types:       []string{"kubernetes_kubeadm_control_plane"},
		Remediation: "Set spec.replicas: 3 (or another odd number of at least 3).",
		Check: func(r *Resource) []Hit {
			kind, _ := asString(r.get("spec.machine_template.infrastructure_ref.kind"))
			if kind == "" {
				kind, _ = asString(r.get("spec.machine_template.spec.infrastructure_ref.kind"))
			}
			if kind != "NutanixMachineTemplate" {
				return nil
			}
			v := r.get("spec.replicas")
			n, ok := asFloat(v)
			switch {
			case v == nil: // KubeadmControlPlane defaults to one replica
				return []Hit{{Path: "spec", Msg: "spec.replicas is not set, so the control plane runs one node; when it fails, the Kubernetes API is down."}}
			case ok && n < 3:
				return []Hit{{Path: "spec.replicas", Msg: fmt.Sprintf("%g control plane node(s) cannot keep etcd quorum through a node failure.", n)}}
			}
			return nil
		}},
	{ID: "TG-NTX-CAPX-004", Title: "NutanixCluster has no failure domains", Severity: Low, Category: CatReliability,
		Types:       []string{"kubernetes_nutanix_cluster"},
		Remediation: "List controlPlaneFailureDomains (NutanixFailureDomain objects on different Prism Element clusters) so control plane machines are spread.",
		Check: func(r *Resource) []Hit {
			// Without prismCentral this is a kustomize patch, not the whole object.
			if r.get("spec.prism_central") == nil || r.get("spec.failure_domains") != nil || r.get("spec.control_plane_failure_domains") != nil {
				return nil
			}
			return []Hit{{Path: "spec", Msg: "Every control plane machine lands on one Prism Element cluster, so that cluster's outage takes the whole Kubernetes cluster down."}}
		}},
	{ID: "TG-VAL-023", Title: "Value the Nutanix provider rejects", Severity: High, Category: CatValidate, CWE: "CWE-20", Blocking: true,
		Types: valueTypes(nutanixValueChecks), Remediation: "Use one of the values the Nutanix provider accepts; terraform validate and plan fail otherwise.",
		Check: func(r *Resource) []Hit {
			return checkCloudValues(r, nutanixValueChecks, "the nutanix provider rejects it at plan time")
		}},
}...)

// capxLiteralPassword reads a CAPX credentials document and reports a basic_auth
// password that is a real value rather than a clusterctl ${VARIABLE}.
func capxLiteralPassword(doc string) bool {
	var creds []struct {
		Type string `json:"type"`
		Data struct {
			PrismCentral struct {
				Password string `json:"password"`
			} `json:"prismCentral"`
		} `json:"data"`
	}
	if json.Unmarshal([]byte(doc), &creds) != nil {
		return false
	}
	for _, c := range creds {
		if p := c.Data.PrismCentral.Password; c.Type == "basic_auth" && p != "" && !strings.Contains(p, "${") {
			return true
		}
	}
	return false
}

// asMaps returns the objects of a nested block value.
func asMaps(v any) []map[string]any {
	return (&Resource{Attrs: map[string]any{"v": v}}).blocks("v")
}

// nutanixValueChecks are enum validations (validation.StringInSlice, case-sensitive)
// from the terraform-provider-nutanix schema.
var nutanixValueChecks = map[string][]awsValueCheck{
	"nutanix_virtual_machine":    {{attr: "boot_type", enum: []string{"UEFI", "LEGACY", "SECURE_BOOT"}}},
	"nutanix_virtual_machine_v2": {{attr: "machine_type", enum: []string{"PSERIES", "Q35", "PC"}}, {attr: "power_state", enum: []string{"ON", "OFF", "PAUSED", "UNDETERMINED"}}},
	"nutanix_images_v2":          {{attr: "type", enum: []string{"DISK_IMAGE", "ISO_IMAGE"}}},
	"nutanix_subnet_v2":          {{attr: "subnet_type", enum: []string{"OVERLAY", "VLAN"}}},
	"nutanix_vpc_v2":             {{attr: "vpc_type", enum: []string{"REGULAR", "TRANSIT"}}},
	"nutanix_virtual_switch_v2":  {{attr: "bond_mode", enum: []string{"ACTIVE_BACKUP", "BALANCE_SLB", "BALANCE_TCP", "NONE"}}},
	"nutanix_users_v2":           {{attr: "user_type", enum: []string{"LOCAL", "SAML", "LDAP", "EXTERNAL", "SERVICE_ACCOUNT"}}},
	"nutanix_pbr":                {{attr: "action", enum: []string{"DENY", "PERMIT", "REROUTE"}}, {attr: "protocol_type", enum: []string{"TCP", "UDP", "ICMP", "PROTOCOL_NUMBER", "ALL"}}},
	"nutanix_storage_containers_v2": {
		{attr: "erasure_code", enum: []string{"NONE", "OFF", "ON"}},
		{attr: "cache_deduplication", enum: []string{"NONE", "OFF", "ON"}},
		{attr: "on_disk_dedup", enum: []string{"NONE", "OFF", "POST_PROCESS"}},
	},
	"nutanix_network_security_policy_v2": {
		{attr: "type", enum: []string{"QUARANTINE", "ISOLATION", "APPLICATION", "SHAREDSERVICE", "CRITICAL", "COREINFRASTRUCTURE", "ZONE", "WORKLOAD"}},
		{attr: "state", enum: []string{"SAVE", "MONITOR", "ENFORCE"}},
		{attr: "scope", enum: []string{"ALL_VLAN", "GLOBAL", "ALL_VPC", "VPC_LIST", "VPC_AS_CATEGORY"}},
		{attr: "rules.type", enum: []string{"QUARANTINE", "TWO_ENV_ISOLATION", "APPLICATION", "INTRA_GROUP", "MULTI_ENV_ISOLATION", "SHARED_SERVICE", "FLEX"}},
	},
	"nutanix_ndb_maintenance_window": {
		{attr: "recurrence", enum: []string{"MONTHLY", "WEEKLY"}},
		{attr: "day_of_week", enum: []string{"MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY", "SATURDAY", "SUNDAY"}},
	},
}

// providerTLSOff maps a provider to the argument that turns certificate checks off,
// and the rule that reports it.
var providerTLSOff = []struct{ provider, attr, rule string }{
	{"nutanix", "insecure", "TG-NTX-PRV-001"},
	{"vsphere", "allow_unverified_ssl", "TG-VS-PRV-001"},
}

// providerTLSChecks reports provider blocks that accept any server certificate.
func providerTLSChecks(m *Module) []Finding {
	var out []Finding
	count := map[string]int{}
	for _, b := range m.Blocks {
		if b.Kind == "provider" && len(b.Labels) == 1 {
			count[b.File+" "+b.Labels[0]]++
		}
	}
	for _, b := range m.Blocks {
		if b.Kind != "provider" || len(b.Labels) != 1 {
			continue
		}
		for _, p := range providerTLSOff {
			if b.Labels[0] != p.provider || !is(b.Attrs[p.attr], true) {
				continue
			}
			f := newFinding(p.rule, "", fmt.Sprintf("provider %q sets %s = true, so it sends credentials to any server that answers, including a man-in-the-middle.", p.provider, p.attr), "provider."+p.provider, b.File, b.Lines[p.attr])
			if src := b.via[p.attr]; src != "" {
				f.Message += " The value comes from " + src + "; change it where that is set."
			} else if count[b.File+" "+p.provider] == 1 { // the fixer edits the first block of that name in the file
				f.Fix = &Fix{File: b.File, Block: "provider." + p.provider, Path: []string{p.attr}, Value: false, Description: "Set " + p.attr + " = false"}
			}
			out = append(out, f)
		}
	}
	return out
}
