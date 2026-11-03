package engine

import (
	"fmt"
	"strings"
)

// Deployment Manager rules read Google API shapes (camelCase, as written).
// A value decided at deploy time ($(ref...)) never fires a rule.

func gdmTypes(apiTypes ...string) []string {
	out := make([]string, len(apiTypes))
	for i, t := range apiTypes {
		out[i] = gdmType(t)
	}
	return out
}

var (
	gdmBucketT   = gdmTypes("storage.v1.bucket")
	gdmSQLT      = gdmTypes("sqladmin.v1beta4.instance")
	gdmVMT       = gdmTypes("compute.v1.instance", "compute.beta.instance", "compute.alpha.instance", "compute.v1.instanceTemplate", "compute.beta.instanceTemplate")
	gdmFirewallT = gdmTypes("compute.v1.firewall", "compute.beta.firewall", "compute.alpha.firewall")
	gdmDiskT     = gdmTypes("compute.v1.disk", "compute.beta.disk")
	gdmGKET      = gdmTypes("container.v1.cluster", "container.v1beta1.cluster")
	gdmBQT       = gdmTypes("bigquery.v2.dataset")
	gdmDNST      = gdmTypes("dns.v1.managedZone", "dns.v1beta2.managedZone")
)

// gdmAt reads a dotted path; unknown is true when the value or any parent is decided at deploy time.
func gdmAt(r *Resource, path string) (v any, unknown bool) {
	segs := strings.Split(path, ".")
	for i := range segs {
		v = get(r.Attrs, strings.Join(segs[:i+1], "."))
		if isUnknown(v) {
			return v, true
		}
		if v == nil {
			return nil, false
		}
	}
	return v, false
}

// gdmRoot is where an object's settings sit: instance templates nest them
// under properties, and container clusters under cluster.
func gdmRoot(r *Resource) string {
	if strings.HasSuffix(r.Type, "_instanceTemplate") {
		return "properties."
	}
	if strings.HasPrefix(r.Type, "gdm_container_") && r.Attrs["cluster"] != nil {
		return "cluster."
	}
	return ""
}

// gdmOff is true when a boolean is explicitly false or absent (absent means off).
func gdmOff(r *Resource, path string) bool {
	v, unk := gdmAt(r, path)
	return !unk && !is(v, true)
}

func gdmOn(r *Resource, path string) bool { v, _ := gdmAt(r, path); return is(v, true) }

func gdmList(r *Resource, path string) []map[string]any {
	v, _ := gdmAt(r, path)
	var out []map[string]any
	for _, e := range asList(v) {
		if m, ok := e.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// gdmMeta returns the value of a metadata item (metadata.items[].key) and whether it is set.
func gdmMeta(r *Resource, key string) (v any, path string, set bool) {
	p := gdmRoot(r) + "metadata.items"
	for i, it := range gdmList(r, p) {
		if k, _ := it["key"].(string); k == key {
			return it["value"], fmt.Sprintf("%s.%d.value", p, i), true
		}
	}
	return nil, p, false
}

// gdmTruthy reads the values metadata accepts for true (TRUE, 1, y, yes).
func gdmTruthy(v any) (b, known bool) {
	switch t := v.(type) {
	case bool:
		return t, true
	case float64:
		return t != 0, true
	case string:
		switch strings.ToLower(t) {
		case "true", "1", "y", "yes":
			return true, true
		case "false", "0", "n", "no":
			return false, true
		}
	}
	return false, false
}

var gdmPublicMembers = map[string]bool{"allUsers": true, "allAuthenticatedUsers": true}

var gdmRules = []Rule{
	{ID: "TG-GDM-STORAGE-001", Title: "Storage bucket grants access to all users", Severity: High, Category: CatSecurity, CWE: "CWE-732", Types: gdmBucketT,
		Remediation: "Remove allUsers and allAuthenticatedUsers from acl and defaultObjectAcl, and drop public predefined ACLs.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			for _, f := range []string{"acl", "defaultObjectAcl"} {
				for i, e := range gdmList(r, f) {
					ent, _ := e["entity"].(string)
					if !gdmPublicMembers[ent] {
						continue
					}
					sev := High
					if role, _ := e["role"].(string); role == "WRITER" || role == "OWNER" {
						sev = Critical
					}
					hits = append(hits, Hit{Path: fmt.Sprintf("%s.%d.entity", f, i), Sev: sev, Msg: fmt.Sprintf("%s gives %s access to the bucket's objects.", f, ent)})
				}
			}
			for _, f := range []string{"predefinedAcl", "predefinedDefaultObjectAcl"} {
				v, _ := gdmAt(r, f)
				switch s, _ := v.(string); s {
				case "publicReadWrite":
					hits = append(hits, Hit{Path: f, Sev: Critical, Msg: "Anyone on the internet can read and write the bucket."})
				case "publicRead", "authenticatedRead":
					hits = append(hits, Hit{Path: f, Msg: f + " " + s + " makes objects readable outside the project."})
				}
			}
			return hits
		}},
	{ID: "TG-GDM-STORAGE-002", Title: "Storage bucket does not use uniform bucket-level access", Severity: Medium, Category: CatSecurity, CWE: "CWE-732", Types: gdmBucketT,
		Remediation: "Set iamConfiguration.uniformBucketLevelAccess.enabled to true so only IAM decides access.",
		Check: func(r *Resource) []Hit {
			if gdmOff(r, "iamConfiguration.uniformBucketLevelAccess.enabled") && gdmOff(r, "iamConfiguration.bucketPolicyOnly.enabled") {
				return []Hit{{Path: "iamConfiguration", Msg: "Object ACLs can grant access that bucket IAM policy does not show."}}
			}
			return nil
		}},
	{ID: "TG-GDM-STORAGE-003", Title: "Storage bucket versioning is off", Severity: Low, Category: CatSecurity, CWE: "CWE-693", Types: gdmBucketT,
		Remediation: "Set versioning.enabled to true (with a lifecycle rule for old versions).",
		Check: func(r *Resource) []Hit {
			if gdmOff(r, "versioning.enabled") {
				return []Hit{{Path: "versioning", Msg: "An overwrite or delete destroys the only copy of an object."}}
			}
			return nil
		}},
	{ID: "TG-GDM-STORAGE-004", Title: "Storage bucket access logging is off", Severity: Low, Category: CatSecurity, CWE: "CWE-778", Types: gdmBucketT,
		Remediation: "Set logging.logBucket to a bucket that collects access logs (or rely on Data Access audit logs).",
		Check: func(r *Resource) []Hit {
			if v, unk := gdmAt(r, "logging.logBucket"); !unk && v == nil {
				return []Hit{{Path: "logging", Msg: "Reads and writes to the bucket leave no access log."}}
			}
			return nil
		}},

	{ID: "TG-GDM-SQL-001", Title: "Cloud SQL instance accepts connections from any address", Severity: High, Category: CatSecurity, CWE: "CWE-284", Types: gdmSQLT,
		Remediation: "Replace 0.0.0.0/0 in authorizedNetworks with specific ranges, or use private IP and the Cloud SQL Auth Proxy.",
		Check: func(r *Resource) []Hit {
			if v, _ := gdmAt(r, "settings.ipConfiguration.ipv4Enabled"); is(v, false) {
				return nil
			}
			var hits []Hit
			for i, n := range gdmList(r, "settings.ipConfiguration.authorizedNetworks") {
				if s, _ := n["value"].(string); worldCIDR(s) || s == "0.0.0.0" {
					hits = append(hits, Hit{Path: fmt.Sprintf("settings.ipConfiguration.authorizedNetworks.%d.value", i), Msg: "The database's public IP is open to the whole internet."})
				}
			}
			return hits
		}},
	{ID: "TG-GDM-SQL-002", Title: "Cloud SQL instance does not require SSL", Severity: Medium, Category: CatSecurity, CWE: "CWE-319", Types: gdmSQLT,
		Remediation: "Set settings.ipConfiguration.sslMode to ENCRYPTED_ONLY (or requireSsl to true).",
		Check: func(r *Resource) []Hit {
			mode, unk := gdmAt(r, "settings.ipConfiguration.sslMode")
			if unk || mode == "ENCRYPTED_ONLY" || mode == "TRUSTED_CLIENT_CERTIFICATE_REQUIRED" {
				return nil
			}
			if mode == nil && gdmOff(r, "settings.ipConfiguration.requireSsl") || mode == "ALLOW_UNENCRYPTED_AND_ENCRYPTED" {
				return []Hit{{Path: "settings.ipConfiguration", Msg: "Clients can connect without encryption, so credentials and data cross the network in clear text."}}
			}
			return nil
		}},
	{ID: "TG-GDM-SQL-003", Title: "Cloud SQL instance has automated backups off", Severity: Medium, Category: CatReliability, CWE: "CWE-693", Types: gdmSQLT,
		Remediation: "Set settings.backupConfiguration.enabled to true.",
		Check: func(r *Resource) []Hit {
			if gdmOff(r, "settings.backupConfiguration.enabled") {
				return []Hit{{Path: "settings.backupConfiguration", Msg: "Without backups, a bad change or deletion cannot be restored."}}
			}
			return nil
		}},
	{ID: "TG-GDM-SQL-004", Title: "MySQL instance has local_infile on", Severity: Medium, Category: CatSecurity, CWE: "CWE-73", Types: gdmSQLT,
		Remediation: "Set the local_infile database flag to off.",
		Check: func(r *Resource) []Hit {
			for i, f := range gdmList(r, "settings.databaseFlags") {
				if n, _ := f["name"].(string); n == "local_infile" {
					if v, _ := f["value"].(string); strings.EqualFold(v, "on") {
						return []Hit{{Path: fmt.Sprintf("settings.databaseFlags.%d.value", i), Msg: "LOAD DATA LOCAL lets a client or injected query read files from the client host."}}
					}
				}
			}
			return nil
		}},

	{ID: "TG-GDM-COMPUTE-001", Title: "VM has a public IP address", Severity: Medium, Category: CatSecurity, CWE: "CWE-284", Types: gdmVMT,
		Remediation: "Remove accessConfigs from networkInterfaces; reach the VM through IAP or a load balancer and use Cloud NAT for egress.",
		Check: func(r *Resource) []Hit {
			p := gdmRoot(r) + "networkInterfaces"
			for i, ni := range gdmList(r, p) {
				if len(asList(ni["accessConfigs"])) > 0 {
					return []Hit{{Path: fmt.Sprintf("%s.%d.accessConfigs", p, i), Msg: "An access config gives the VM an external IP reachable from the internet."}}
				}
			}
			return nil
		}},
	{ID: "TG-GDM-COMPUTE-002", Title: "VM has IP forwarding on", Severity: Medium, Category: CatSecurity, CWE: "CWE-284", Types: gdmVMT,
		Remediation: "Set canIpForward to false unless the VM is a router or NAT appliance.",
		Check: func(r *Resource) []Hit {
			if p := gdmRoot(r) + "canIpForward"; gdmOn(r, p) {
				return []Hit{{Path: p, Msg: "The VM can send and receive packets for other addresses, bypassing network controls."}}
			}
			return nil
		}},
	{ID: "TG-GDM-COMPUTE-003", Title: "VM has the serial console enabled", Severity: Medium, Category: CatSecurity, CWE: "CWE-306", Types: gdmVMT,
		Remediation: "Remove the serial-port-enable metadata item or set it to false.",
		Check: func(r *Resource) []Hit {
			if v, p, set := gdmMeta(r, "serial-port-enable"); set {
				if b, ok := gdmTruthy(v); ok && b {
					return []Hit{{Path: p, Msg: "The interactive serial console accepts connections from any address that has the key."}}
				}
			}
			return nil
		}},
	{ID: "TG-GDM-COMPUTE-004", Title: "VM uses the default service account with full API access", Severity: High, Category: CatSecurity, CWE: "CWE-250", Types: gdmVMT,
		Remediation: "Use a dedicated service account with only the roles it needs, or narrow the scopes.",
		Check: func(r *Resource) []Hit {
			p := gdmRoot(r) + "serviceAccounts"
			for i, sa := range gdmList(r, p) {
				email, _ := sa["email"].(string)
				if email != "default" && !strings.HasSuffix(email, "-compute@developer.gserviceaccount.com") {
					continue
				}
				for _, s := range asStrings(sa["scopes"]) {
					if s == "https://www.googleapis.com/auth/cloud-platform" {
						return []Hit{{Path: fmt.Sprintf("%s.%d.scopes", p, i), Msg: "Anything on the VM gets the project-wide Editor role of the default service account."}}
					}
				}
			}
			return nil
		}},
	{ID: "TG-GDM-COMPUTE-005", Title: "VM accepts project-wide SSH keys", Severity: Low, Category: CatSecurity, CWE: "CWE-284", Types: gdmVMT,
		Remediation: "Add the metadata item block-project-ssh-keys with value true, or use OS Login.",
		Check: func(r *Resource) []Hit {
			if _, unk := gdmAt(r, gdmRoot(r)+"metadata.items"); unk {
				return nil
			}
			login, _, _ := gdmMeta(r, "enable-oslogin")
			block, p, _ := gdmMeta(r, "block-project-ssh-keys")
			if b, _ := gdmTruthy(login); b || isUnknown(login) {
				return nil // OS Login ignores metadata keys
			}
			if b, _ := gdmTruthy(block); b || isUnknown(block) {
				return nil
			}
			return []Hit{{Path: p, Msg: "A key added to project metadata opens SSH to this VM too."}}
		}},
	{ID: "TG-GDM-COMPUTE-006", Title: "VM turns OS Login off", Severity: Medium, Category: CatSecurity, CWE: "CWE-287", Types: gdmVMT,
		Remediation: "Remove enable-oslogin = false from the metadata so IAM controls SSH access.",
		Check: func(r *Resource) []Hit {
			if v, p, set := gdmMeta(r, "enable-oslogin"); set {
				if b, ok := gdmTruthy(v); ok && !b {
					return []Hit{{Path: p, Msg: "SSH access falls back to metadata keys, which IAM cannot audit or revoke."}}
				}
			}
			return nil
		}},
	{ID: "TG-GDM-COMPUTE-101", Title: "Firewall opens ports to the internet", Severity: High, Category: CatSecurity, CWE: "CWE-284", Types: gdmFirewallT,
		Remediation: "Limit sourceRanges to known networks, or use IAP TCP forwarding (35.235.240.0/20) for administration.",
		Check: func(r *Resource) []Hit {
			if d, _ := gdmAt(r, "direction"); d != nil && d != "INGRESS" || gdmOn(r, "disabled") {
				return nil
			}
			if v, _ := gdmAt(r, "sourceRanges"); !anyWorld(v) {
				return nil
			}
			var hits []Hit
			for i, a := range gdmList(r, "allowed") {
				proto, _ := a["IPProtocol"].(string)
				proto = strings.ToLower(proto)
				if isUnknown(a["ports"]) || proto != "all" && proto != "tcp" && proto != "udp" && proto != "sctp" {
					continue
				}
				p := fmt.Sprintf("allowed.%d", i)
				ports := asList(a["ports"])
				if len(ports) == 0 {
					hits = append(hits, openPorts(p, "The firewall", "all", 0, 65535)...)
					continue
				}
				for j, pv := range ports {
					if lo, hi, ok := portRange(pv); ok {
						hits = append(hits, openPorts(fmt.Sprintf("%s.ports.%d", p, j), "The firewall", proto, lo, hi)...)
					}
				}
			}
			return hits
		}},
	{ID: "TG-GDM-COMPUTE-201", Title: "Disk does not use a customer-managed key", Severity: Low, Category: CatSecurity, CWE: "CWE-311", Types: gdmDiskT,
		Remediation: "Set diskEncryptionKey.kmsKeyName to a Cloud KMS key you control.",
		Check: func(r *Resource) []Hit {
			if v, unk := gdmAt(r, "diskEncryptionKey"); !unk && v == nil {
				return []Hit{{Path: "diskEncryptionKey", Msg: "The disk is encrypted with a Google-managed key you cannot rotate, disable or audit."}}
			}
			return nil
		}},

	{ID: "TG-GDM-GKE-001", Title: "GKE cluster nodes have public IP addresses", Severity: Medium, Category: CatSecurity, CWE: "CWE-284", Types: gdmGKET,
		Remediation: "Set privateClusterConfig.enablePrivateNodes to true (with a masterIpv4CidrBlock).",
		Check: func(r *Resource) []Hit {
			if p := gdmRoot(r) + "privateClusterConfig.enablePrivateNodes"; gdmOff(r, p) {
				return []Hit{{Path: gdmRoot(r) + "privateClusterConfig", Msg: "Every node gets an external IP reachable from the internet."}}
			}
			return nil
		}},
	{ID: "TG-GDM-GKE-002", Title: "GKE cluster has legacy ABAC enabled", Severity: High, Category: CatSecurity, CWE: "CWE-285", Types: gdmGKET,
		Remediation: "Set legacyAbac.enabled to false and grant access with Kubernetes RBAC.",
		Check: func(r *Resource) []Hit {
			if p := gdmRoot(r) + "legacyAbac.enabled"; gdmOn(r, p) {
				return []Hit{{Path: p, Msg: "ABAC grants broad static permissions that RBAC policies cannot narrow."}}
			}
			return nil
		}},
	{ID: "TG-GDM-GKE-003", Title: "GKE control plane has no authorized networks", Severity: Medium, Category: CatSecurity, CWE: "CWE-284", Types: gdmGKET,
		Remediation: "Set masterAuthorizedNetworksConfig.enabled to true with the CIDR blocks that may reach the API server.",
		Check: func(r *Resource) []Hit {
			if p := gdmRoot(r) + "masterAuthorizedNetworksConfig.enabled"; gdmOff(r, p) {
				return []Hit{{Path: gdmRoot(r) + "masterAuthorizedNetworksConfig", Msg: "The Kubernetes API server is reachable from any address."}}
			}
			return nil
		}},
	{ID: "TG-GDM-GKE-004", Title: "GKE cluster issues client certificates or basic auth", Severity: Medium, Category: CatSecurity, CWE: "CWE-287", Types: gdmGKET,
		Remediation: "Remove masterAuth.username and password and set clientCertificateConfig.issueClientCertificate to false.",
		Check: func(r *Resource) []Hit {
			root := gdmRoot(r) + "masterAuth."
			if gdmOn(r, root+"clientCertificateConfig.issueClientCertificate") {
				return []Hit{{Path: root + "clientCertificateConfig.issueClientCertificate", Msg: "A long-lived client certificate grants cluster access that IAM cannot revoke."}}
			}
			if u, _ := gdmAt(r, root+"username"); u != nil && u != "" && !isUnknown(u) {
				return []Hit{{Path: root + "username", Msg: "Basic authentication with a static password is enabled on the API server."}}
			}
			return nil
		}},
	{ID: "TG-GDM-GKE-005", Title: "GKE cluster does not enforce network policy", Severity: Low, Category: CatSecurity, CWE: "CWE-284", Types: gdmGKET,
		Remediation: "Set networkPolicy.enabled to true, or use Dataplane V2 (networkConfig.datapathProvider ADVANCED_DATAPATH).",
		Check: func(r *Resource) []Hit {
			root := gdmRoot(r)
			if dp, unk := gdmAt(r, root+"networkConfig.datapathProvider"); unk || dp == "ADVANCED_DATAPATH" {
				return nil
			}
			if gdmOff(r, root+"networkPolicy.enabled") {
				return []Hit{{Path: root + "networkPolicy", Msg: "Every pod can reach every other pod; a compromised pod can move laterally."}}
			}
			return nil
		}},

	{ID: "TG-GDM-BIGQUERY-001", Title: "BigQuery dataset is public", Severity: High, Category: CatSecurity, CWE: "CWE-732", Types: gdmBQT,
		Remediation: "Remove allUsers and allAuthenticatedUsers entries from access.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			for i, a := range gdmList(r, "access") {
				for _, k := range []string{"specialGroup", "iamMember"} {
					if s, _ := a[k].(string); gdmPublicMembers[s] {
						hits = append(hits, Hit{Path: fmt.Sprintf("access.%d.%s", i, k), Msg: s + " can read the dataset's tables."})
					}
				}
			}
			return hits
		}},

	{ID: "TG-GDM-DNS-001", Title: "Public DNS zone has DNSSEC off", Severity: Medium, Category: CatSecurity, CWE: "CWE-345", Types: gdmDNST,
		Remediation: "Set dnssecConfig.state to on.",
		Check: func(r *Resource) []Hit {
			if v, _ := gdmAt(r, "visibility"); v == "private" || isUnknown(v) {
				return nil
			}
			st, unk := gdmAt(r, "dnssecConfig.state")
			if !unk && st != "on" && st != "transfer" {
				return []Hit{{Path: "dnssecConfig", Msg: "Resolvers cannot verify answers, so responses for the zone can be spoofed."}}
			}
			return nil
		}},
	{ID: "TG-GDM-DNS-002", Title: "DNSSEC uses RSASHA1", Severity: Medium, Category: CatSecurity, CWE: "CWE-327", Types: gdmDNST,
		Remediation: "Use rsasha256, rsasha512 or ecdsap256sha256 in dnssecConfig.defaultKeySpecs.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			for i, k := range gdmList(r, "dnssecConfig.defaultKeySpecs") {
				if a, _ := k["algorithm"].(string); strings.EqualFold(a, "rsasha1") {
					hits = append(hits, Hit{Path: fmt.Sprintf("dnssecConfig.defaultKeySpecs.%d.algorithm", i), Msg: "SHA-1 signatures can be forged."})
				}
			}
			return hits
		}},
}
