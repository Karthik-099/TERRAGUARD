package engine

// VMware vSphere provider rules. The provider-level allow_unverified_ssl check
// lives with the Nutanix one in providerTLSChecks.

var vsphereChecks = []check{
	{ID: "TG-VS-HOST-001", Sev: Low, CWE: "CWE-284", Title: "ESXi host is not in lockdown mode",
		Types: []string{"vsphere_host"}, Kind: "missing_or_eq", Path: "lockdown", Bad: []any{"disabled"}, Good: "normal",
		Msg: "Lockdown is disabled (the provider default), so anyone with a host account can change the host directly and bypass vCenter roles and logging."},
	{ID: "TG-VS-CL-001", Sev: Medium, Cat: CatReliability, Title: "Compute cluster has vSphere HA off",
		Types: []string{"vsphere_compute_cluster"}, Kind: "missing_or_eq", Path: "ha_enabled", Bad: []any{false}, Good: true, Fixable: true,
		Msg: "vSphere HA is off (the provider default), so VMs on a failed host stay down until someone restarts them."},
	{ID: "TG-VS-DS-001", Sev: Low, Cat: CatReliability, Title: "Datastore cluster has Storage DRS off",
		Types: []string{"vsphere_datastore_cluster"}, Kind: "missing_or_eq", Path: "sdrs_enabled", Bad: []any{false}, Good: true, Fixable: true,
		Msg: "Storage DRS is off (the provider default), so nothing balances space or I/O and one datastore can fill up and stop its VMs."},
}

var vsphereNetT = []string{"vsphere_distributed_port_group", "vsphere_distributed_virtual_switch", "vsphere_host_port_group", "vsphere_host_virtual_switch"}

var vsphereRules = append(checkRules(vsphereChecks), []Rule{
	{ID: "TG-VS-NET-001", Title: "Port group or switch weakens Layer 2 security", Severity: Medium, Category: CatSecurity, CWE: "CWE-923",
		Types: vsphereNetT, Remediation: "Set allow_promiscuous, allow_forged_transmits and allow_mac_changes to false; enable them only on a dedicated port group for the appliance that needs them.",
		Check: managed(func(r *Resource) []Hit {
			var hits []Hit
			for _, s := range []struct{ attr, why string }{
				{"allow_promiscuous", "every VM on the port group can capture the traffic of the others"},
				{"allow_forged_transmits", "a VM can send frames with another machine's MAC address and impersonate it"},
				{"allow_mac_changes", "a VM can change its MAC address to receive traffic meant for another machine"},
			} {
				if is(r.get(s.attr), true) {
					hits = append(hits, Hit{Path: s.attr, Msg: s.attr + " = true: " + s.why + ".", Fix: fix(false, "Set "+s.attr+" = false", s.attr)})
				}
			}
			return hits
		})},
	{ID: "TG-VS-VM-001", Title: "EFI virtual machine boots without Secure Boot", Severity: Low, Category: CatSecurity, CWE: "CWE-693",
		Types: []string{"vsphere_virtual_machine"}, Remediation: "Set efi_secure_boot_enabled = true for guests that support it (Windows Server 2016+, current Linux distributions).",
		Check: managed(func(r *Resource) []Hit {
			if f, _ := asString(r.get("firmware")); f == "efi" && notTrue(r.get("efi_secure_boot_enabled")) {
				return []Hit{{Path: "firmware", Msg: `firmware = "efi" without efi_secure_boot_enabled (default false), so unsigned boot loaders and kernels run.`}}
			}
			return nil
		})},
	{ID: "TG-VS-VM-002", Title: "Guest customization sets a plaintext password", Severity: High, Category: CatSecurity, CWE: "CWE-256",
		Types:       []string{"vsphere_virtual_machine", "vsphere_guest_os_customization"},
		Remediation: "Pass the administrator password from a sensitive variable through windows_options, or set PlainText false in the answer file; never commit it.",
		Check: managed(func(r *Resource) []Hit {
			return guestPasswordHits(r.Attrs, "", false)
		})},
	{ID: "TG-VAL-024", Title: "Value the vSphere provider rejects", Severity: High, Category: CatValidate, CWE: "CWE-20", Blocking: true,
		Types: valueTypes(vsphereValueChecks), Remediation: "Use one of the values the vSphere provider accepts; terraform validate and plan fail otherwise.",
		Check: func(r *Resource) []Hit {
			return checkCloudValues(r, vsphereValueChecks, "the vsphere provider rejects it at plan time")
		}},
}...)

// vsphereValueChecks are enum validations from the terraform-provider-vsphere schema.
var vsphereValueChecks = map[string][]awsValueCheck{
	"vsphere_virtual_machine": {{attr: "firmware", enum: []string{"bios", "efi"}}, {attr: "scsi_type", enum: []string{"pvscsi", "lsilogic", "lsilogic-sas"}}},
	"vsphere_host":            {{attr: "lockdown", enum: []string{"disabled", "normal", "strict"}}},
	"vsphere_compute_cluster": {
		{attr: "drs_automation_level", enum: []string{"manual", "partiallyAutomated", "fullyAutomated"}},
		{attr: "ha_admission_control_policy", enum: []string{"resourcePercentage", "slotPolicy", "failoverHosts", "disabled"}},
	},
	"vsphere_folder":       {{attr: "type", enum: []string{"vm", "network", "host", "datastore", "datacenter"}}},
	"vsphere_tag_category": {{attr: "cardinality", enum: []string{"SINGLE", "MULTIPLE"}}},
}
