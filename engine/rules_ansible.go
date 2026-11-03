package engine

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Rules for Ansible tasks (resource shapes in format_ansible.go).

func init() {
	for ref, ids := range ansibleForeign {
		foreignRules[ref] = append(foreignRules[ref], ids...)
	}
}

func ansT(mods ...string) []string {
	var out []string
	for _, m := range mods {
		out = append(out, "ansible_"+m)
	}
	return out
}

// ansGet is the value at path, or Unknown when it or anything above it is templated.
func ansGet(r *Resource, path string) any {
	if u, ok := r.Attrs["_args"].(Unknown); ok {
		return u
	}
	segs := strings.Split(path, ".")
	for i := 1; i < len(segs); i++ {
		if v := get(r.Attrs, strings.Join(segs[:i], ".")); isUnknown(v) {
			return v
		}
	}
	return get(r.Attrs, path)
}

// ansBool reads Ansible's spellings of a boolean.
func ansBool(v any) (b, known bool) {
	switch t := v.(type) {
	case bool:
		return t, true
	case float64:
		return t != 0, t == 0 || t == 1
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "yes", "true", "on", "y", "1":
			return true, true
		case "no", "false", "off", "n", "0":
			return false, true
		}
	}
	return false, false
}

func ansOn(r *Resource, path string) bool  { b, ok := ansBool(ansGet(r, path)); return ok && b }
func ansOff(r *Resource, path string) bool { b, ok := ansBool(ansGet(r, path)); return ok && !b }

// ansNotOn is true when the setting is absent or false (not templated).
func ansNotOn(r *Resource, path string) bool {
	v := ansGet(r, path)
	b, ok := ansBool(v)
	return v == nil || ok && !b
}

func ansAbsent(r *Resource, path string) bool { return ansGet(r, path) == nil }

func ansStr(r *Resource, path string) string {
	s, _ := ansGet(r, path).(string)
	return strings.ToLower(strings.TrimSpace(s))
}

// ansLive skips tasks that remove or only read the object.
func ansLive(r *Resource) bool {
	switch ansStr(r, "state") {
	case "absent", "list", "info", "deleted":
		return false
	}
	return true
}

func ansRule(id string, sev Severity, cwe, title, rem string, mods []string, check func(r *Resource) []Hit) Rule {
	return Rule{ID: id, Title: title, Severity: sev, Category: CatSecurity, CWE: cwe, Remediation: rem, Types: ansT(mods...),
		Check: func(r *Resource) []Hit {
			if r.Format != FormatAnsible || !ansLive(r) {
				return nil
			}
			return check(r)
		}}
}

func one(path, msg string) []Hit { return []Hit{{Path: path, Msg: msg}} }

func whenOn(path, msg string) func(*Resource) []Hit {
	return func(r *Resource) []Hit {
		if ansOn(r, path) {
			return one(path, msg)
		}
		return nil
	}
}

func whenOff(path, msg string) func(*Resource) []Hit {
	return func(r *Resource) []Hit {
		if ansOff(r, path) {
			return one(path, msg)
		}
		return nil
	}
}

func unlessOn(path, msg string) func(*Resource) []Hit {
	return func(r *Resource) []Hit {
		if ansNotOn(r, path) {
			return one(path, msg)
		}
		return nil
	}
}

func unlessSet(path, msg string) func(*Resource) []Hit {
	return func(r *Resource) []Hit {
		if ansAbsent(r, path) {
			return one(path, msg)
		}
		return nil
	}
}

// publicStatements reports Allow statements open to every principal without a condition.
func publicStatements(r *Resource, path, what string) []Hit {
	for _, st := range statements(ansGet(r, path)) {
		if st.Effect == "Allow" && contains(st.Principals, "*") && !st.HasCond {
			return one(path, fmt.Sprintf("The %s policy allows %v to anyone on the internet.", what, st.Actions))
		}
	}
	return nil
}

// plainHTTP is an http:// URL to a host other than this machine.
func plainHTTP(s string) bool {
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(s)), "http://") {
		return false
	}
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return true
	}
	h := strings.ToLower(u.Hostname())
	return h != "localhost" && !strings.HasPrefix(h, "127.") && h != "::1"
}

// portRange reads "22", "1000-2000", "*" or a number.
func ansPortRange(v any) (float64, float64, bool) {
	if f, ok := v.(float64); ok {
		return f, f, true
	}
	s, ok := v.(string)
	if !ok {
		return 0, 0, false
	}
	s = strings.TrimSpace(s)
	if s == "*" || strings.EqualFold(s, "any") {
		return 0, 65535, true
	}
	a, b, rng := strings.Cut(s, "-")
	f, err1 := strconv.ParseFloat(strings.TrimSpace(a), 64)
	t, err2 := f, error(nil)
	if rng {
		t, err2 = strconv.ParseFloat(strings.TrimSpace(b), 64)
	}
	return f, t, err1 == nil && err2 == nil
}

// ansOpenPorts grades internet-open port ranges: sensitive or all ports first, then wide ranges.
func ansOpenPorts(path, proto string, ranges [][2]float64, wide bool) []Hit {
	for _, pr := range ranges {
		if sev, what, ok := exposure(proto, pr[0], pr[1]); ok {
			if wide {
				return nil
			}
			return []Hit{{Path: path, Sev: sev, Msg: "Anyone on the internet can reach " + what + "."}}
		}
	}
	if !wide {
		return nil
	}
	for _, pr := range ranges {
		if pr[1] > pr[0] {
			return one(path, fmt.Sprintf("Ports %.0f-%.0f are open to the internet, more than one service needs.", pr[0], pr[1]))
		}
	}
	return nil
}

func ec2GroupHits(r *Resource, wide bool) []Hit {
	var out []Hit
	for i, e := range asList(ansGet(r, "rules")) {
		m, _ := e.(map[string]any)
		if m == nil || !anyWorld(m["cidr_ip"], m["cidr_ipv6"]) {
			continue
		}
		proto := fmt.Sprint(m["proto"])
		if f, ok := m["proto"].(float64); ok {
			proto = strconv.Itoa(int(f))
		}
		var ranges [][2]float64
		if ps := m["ports"]; ps != nil {
			for _, p := range append(asList(ps), ps) {
				if f, t, ok := ansPortRange(p); ok {
					ranges = append(ranges, [2]float64{f, t})
				}
			}
		} else if f, t, ok := ansPortRange(m["from_port"]); ok {
			if t2, _, ok := ansPortRange(m["to_port"]); ok {
				t = t2
			}
			if f < 0 {
				f, t = 0, 65535
			}
			ranges = append(ranges, [2]float64{f, t})
		} else if proto == "-1" || proto == "all" {
			ranges = append(ranges, [2]float64{0, 65535})
		}
		out = append(out, ansOpenPorts("rules."+strconv.Itoa(i), proto, ranges, wide)...)
	}
	return out
}

func nsgHits(r *Resource) []Hit {
	var out []Hit
	for i, e := range asList(ansGet(r, "rules")) {
		m, _ := e.(map[string]any)
		if m == nil || m["access"] != nil && !strings.EqualFold(fmt.Sprint(m["access"]), "allow") ||
			m["direction"] != nil && !strings.EqualFold(fmt.Sprint(m["direction"]), "inbound") {
			continue
		}
		src := m["source_address_prefix"]
		if src == nil {
			src = "*" // the module's default
		}
		if !anyWorld(src) {
			continue
		}
		var ranges [][2]float64
		dst := m["destination_port_range"]
		if dst == nil {
			dst = "*"
		}
		for _, p := range append(asList(dst), dst) {
			if f, t, ok := ansPortRange(p); ok {
				ranges = append(ranges, [2]float64{f, t})
			}
		}
		out = append(out, ansOpenPorts("rules."+strconv.Itoa(i), "tcp", ranges, false)...)
	}
	return out
}

func gcpFirewallHits(r *Resource) []Hit {
	if d := ansStr(r, "direction"); d != "" && d != "ingress" || !anyWorld(ansGet(r, "source_ranges")) {
		return nil
	}
	var out []Hit
	for i, e := range asList(ansGet(r, "allowed")) {
		m, _ := e.(map[string]any)
		if m == nil {
			continue
		}
		proto := strings.ToLower(fmt.Sprint(m["ip_protocol"]))
		var ranges [][2]float64
		if m["ports"] == nil && (proto == "all" || proto == "tcp" || proto == "udp") {
			ranges = append(ranges, [2]float64{0, 65535})
		}
		for _, p := range asList(m["ports"]) {
			if f, t, ok := ansPortRange(p); ok {
				ranges = append(ranges, [2]float64{f, t})
			}
		}
		out = append(out, ansOpenPorts("allowed."+strconv.Itoa(i), proto, ranges, false)...)
	}
	return out
}

var (
	ansShellMods = []string{"shell", "command", "raw", "script", "win_shell", "win_command"}
	ansPkgMods   = []string{"apk", "apt", "bundler", "dnf", "dnf5", "easy_install", "gem", "homebrew", "jenkins_plugin", "npm",
		"openbsd_pkg", "opkg", "pacman", "pip", "pkg5", "pkgng", "pkgutil", "portage", "slackpkg", "snap", "sorcery", "swdepot",
		"win_chocolatey", "yarn", "yum", "zypper", "package"}
	ansFileMods = []string{"file", "copy", "template", "assemble", "get_url", "unarchive", "archive", "lineinfile", "blockinfile",
		"ini_file", "htpasswd"}
	psDownloadRE = regexp.MustCompile(`(?i)\b(?:iex|invoke-expression)\b[^\n]*\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring)\b|\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring)\b[^\n]*\|\s*(?:iex|invoke-expression)\b`)
	awsKeyRE     = regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)
	ansModeRE    = regexp.MustCompile(`(?:^|,)[ugoa]*[oa][ugoa]*[+=][rwxXst]*w`)
	ansBecomePw  = map[string]bool{"ansible_become_pass": true, "ansible_become_password": true, "ansible_sudo_pass": true,
		"ansible_sudo_password": true, "ansible_ssh_pass": true, "ansible_password": true, "ansible_ssh_password": true}
)

// ansCmd is the command text of a shell-like task.
func ansCmd(r *Resource) string {
	if s, ok := r.Attrs["cmd"].(string); ok {
		return s
	}
	return strings.Join(asStrings(r.Attrs["argv"]), " ")
}

// ansArgKeys lists module arguments (not task keywords), sorted.
func ansArgKeys(r *Resource) []string {
	var out []string
	for k := range r.Attrs {
		if !ansTaskKeys[k] && k != "_args" && k != "cmd" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// ansSecretKey is an argument that carries a credential.
func ansSecretKey(k string) bool {
	return secretAttrRE.MatchString(k) && !secretMetaRE.MatchString(k) && k != "update_password" || ansBecomePw[strings.ToLower(k)]
}

// literalSecrets finds secrets written as plain values under prefix, a few levels deep.
func ansLiteralSecrets(v any, prefix string, depth int, out *[]Hit) {
	m, ok := v.(map[string]any)
	if !ok || depth > 3 {
		return
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p := join(prefix, k)
		if ansBecomePw[strings.ToLower(k)] {
			continue // TG-ANS-BECOME-001
		}
		s, _ := m[k].(string)
		if literalSecret(k, m[k]) || awsKeyRE.MatchString(s) {
			*out = append(*out, Hit{Path: p, Msg: "The value of " + k + " is written into the playbook, so everyone with the repository can read it."})
			continue
		}
		ansLiteralSecrets(m[k], p, depth+1, out)
	}
}

// ansOctalMode reads mode as octal digits (YAML may have turned 0777 into 777).
func ansWorldWritable(v any) bool {
	var s string
	switch t := v.(type) {
	case float64:
		s = strconv.Itoa(int(t))
	case string:
		s = strings.TrimSpace(t)
	default:
		return false
	}
	if n, err := strconv.ParseUint(strings.TrimPrefix(s, "0o"), 8, 32); err == nil {
		return n&0o002 != 0
	}
	return ansModeRE.MatchString(s)
}

var ansibleRules = []Rule{
	// General
	ansRule("TG-ANS-SHELL-001", High, "CWE-494", "Task pipes a download straight into a shell",
		"Download the script with get_url and a checksum, review it, then run it; or install a signed package.", ansShellMods,
		func(r *Resource) []Hit {
			if c := ansCmd(r); pipeShellRE.MatchString(c) || psDownloadRE.MatchString(c) {
				return one("cmd", "Whatever the server returns runs as code on the host, so a compromised or spoofed server owns the machine.")
			}
			return nil
		}),
	ansRule("TG-ANS-SHELL-002", Medium, "CWE-295", "Shell command turns off TLS certificate checks",
		"Drop --insecure, --no-check-certificate and similar flags; install the CA certificate the server needs instead.", ansShellMods,
		func(r *Resource) []Hit {
			if tlsOffText(ansCmd(r)) {
				return one("cmd", "The command accepts any certificate, so anyone on the network path can swap what it downloads.")
			}
			return nil
		}),
	ansRule("TG-ANS-TLS-001", Medium, "CWE-295", "Task turns off certificate validation",
		"Remove validate_certs: false (and sslverify: false); point the task at a CA bundle if the server uses a private CA.", nil,
		func(r *Resource) []Hit {
			for _, k := range []string{"validate_certs", "sslverify"} {
				if ansOff(r, k) {
					return one(k, "The task trusts any certificate, so a man-in-the-middle can tamper with what it downloads or sends.")
				}
			}
			return nil
		}),
	ansRule("TG-ANS-HTTP-001", Medium, "CWE-319", "Task downloads or calls a URL over plain HTTP",
		"Use an https:// URL; for downloads also set checksum so a tampered file is rejected.",
		[]string{"get_url", "uri", "apt_key", "rpm_key", "unarchive", "win_get_url", "win_uri"},
		func(r *Resource) []Hit {
			for _, k := range []string{"url", "key", "src"} {
				if s, _ := ansGet(r, k).(string); plainHTTP(s) {
					return one(k, "Traffic to "+s+" is unencrypted and can be read or changed on the way.")
				}
			}
			return nil
		}),
	ansRule("TG-ANS-PKG-001", High, "CWE-494", "Package install skips signature checks",
		"Remove allow_unauthenticated, force, disable_gpg_check and gpgcheck: false; import the repository's signing key instead.",
		[]string{"apt", "yum", "dnf", "dnf5", "zypper", "yum_repository", "package"},
		func(r *Resource) []Hit {
			for _, k := range []string{"allow_unauthenticated", "force", "disable_gpg_check"} {
				if ansOn(r, k) {
					return one(k, k+" installs packages whose signature is missing or wrong, so a tampered package is accepted.")
				}
			}
			if ansOff(r, "gpgcheck") {
				return one("gpgcheck", "The repository's packages are installed without checking their signatures.")
			}
			return nil
		}),
	ansRule("TG-ANS-PKG-002", Low, "CWE-1357", "Package is installed at the latest version",
		"Pin the version (name: nginx=1.24.0, or version:) and update it on purpose.", ansPkgMods,
		func(r *Resource) []Hit {
			if ansStr(r, "state") == "latest" && ansAbsent(r, "version") && !ansOn(r, "update_only") {
				return one("state", "Each run can upgrade to a new release, so two hosts built a day apart differ and a bad release ships unreviewed.")
			}
			return nil
		}),
	ansRule("TG-ANS-SECRET-001", Medium, "CWE-532", "Task handles a secret without no_log",
		"Add no_log: true to the task (or its block) so the value is not printed in output and logs.", nil,
		func(r *Resource) []Hit {
			if r.Type == "ansible_play" || r.Type == "ansible_block" || ansOn(r, "no_log") || isUnknown(ansGet(r, "no_log")) {
				return nil
			}
			for _, k := range ansArgKeys(r) {
				if v := r.Attrs[k]; ansSecretKey(k) && v != nil && v != "" {
					return one(k, "Ansible prints module arguments on failure and in verbose runs, so "+k+" ends up in CI logs.")
				}
			}
			return nil
		}),
	ansRule("TG-ANS-SECRET-002", High, "CWE-798", "Secret is written in plain text",
		"Move the value to Ansible Vault (!vault) or a lookup from a secret store, and rotate it.", nil,
		func(r *Resource) []Hit {
			var out []Hit
			ansLiteralSecrets(r.Attrs, "", 0, &out)
			return out
		}),
	ansRule("TG-ANS-BECOME-001", High, "CWE-256", "Become or login password is written in plain text",
		"Store ansible_become_password in Ansible Vault or pass it with --ask-become-pass; prefer key-based sudo rules.", nil,
		func(r *Resource) []Hit {
			for _, k := range []string{"vars"} {
				m, _ := ansGet(r, k).(map[string]any)
				keys := make([]string, 0, len(m))
				for name := range m {
					keys = append(keys, name)
				}
				sort.Strings(keys)
				for _, name := range keys {
					if s, ok := m[name].(string); ok && ansBecomePw[strings.ToLower(name)] && strings.TrimSpace(s) != "" {
						return one(k+"."+name, "The privilege-escalation password is in the playbook, so anyone who reads it can become root on these hosts.")
					}
				}
			}
			return nil
		}),
	ansRule("TG-ANS-BECOME-002", Low, "CWE-269", "become_user is set but become is off",
		"Set become: true next to become_user, or remove become_user.", nil,
		func(r *Resource) []Hit {
			if _, own := r.Lines["become_user"]; own && !ansAbsent(r, "become_user") && ansNotOn(r, "become") {
				return one("become_user", "Without become the task runs as the connecting user, not the account named in become_user.")
			}
			return nil
		}),
	ansRule("TG-ANS-FILE-001", Medium, "CWE-732", "File is made world-writable",
		"Use a mode without write for others, such as 0644 for files or 0755 for directories.", ansFileMods,
		func(r *Resource) []Hit {
			if ansWorldWritable(ansGet(r, "mode")) {
				return one("mode", "Any local user can change this file, so a low-privilege account can alter what the service runs or reads.")
			}
			return nil
		}),
	{ID: "TG-ANS-FILE-002", Title: "File is created without an explicit mode", Severity: Info, Category: CatBestPrac, CWE: "CWE-276",
		Remediation: "Set mode: on the task (for example 0644) so permissions do not depend on the umask.",
		Types:       ansT("copy", "template", "get_url", "assemble", "archive", "file", "lineinfile", "blockinfile", "ini_file", "htpasswd"),
		Check: func(r *Resource) []Hit {
			if r.Format != FormatAnsible || !ansAbsent(r, "mode") || ansOn(r, "recurse") {
				return nil
			}
			st := ansStr(r, "state")
			switch r.Type {
			case "ansible_file":
				if st != "touch" && st != "directory" {
					return nil
				}
			case "ansible_lineinfile", "ansible_blockinfile":
				if !ansOn(r, "create") {
					return nil
				}
			case "ansible_ini_file", "ansible_htpasswd":
				if ansOff(r, "create") || st == "absent" {
					return nil
				}
			default:
				if st == "absent" || st == "link" || isUnknown(ansGet(r, "dest")) && isUnknown(ansGet(r, "path")) {
					return nil
				}
			}
			return one("", "The file gets whatever permissions the remote umask gives, which may be readable by every user.")
		}},
	{ID: "TG-ANS-BLOCK-001", Title: "Block has no rescue section", Severity: Info, Category: CatReliability,
		Remediation: "Add a rescue: section that cleans up or reports, so a failed task does not leave hosts half-changed.",
		Types:       ansT("block"),
		Check: func(r *Resource) []Hit {
			if r.Format == FormatAnsible && r.Attrs["rescue"] == nil {
				return one("", "When a task in the block fails the play stops with no cleanup or rollback.")
			}
			return nil
		}},

	// AWS
	ansRule("TG-ANS-S3-001", Critical, "CWE-284", "S3 bucket policy allows anyone",
		"Name specific principals in the bucket policy, or add a condition (aws:SourceVpce, aws:PrincipalOrgID).", []string{"s3_bucket"},
		func(r *Resource) []Hit { return publicStatements(r, "policy", "bucket") }),
	ansRule("TG-ANS-S3-002", High, "CWE-284", "S3 object or bucket ACL is public",
		"Use permission: private and share objects with presigned URLs or CloudFront instead.", []string{"aws_s3", "s3_object"},
		func(r *Resource) []Hit {
			for _, p := range asStrings(ansGet(r, "permission")) {
				if strings.HasPrefix(p, "public-read") || p == "authenticated-read" {
					return one("permission", "ACL "+p+" lets anyone (or any AWS account) read the object.")
				}
			}
			return nil
		}),
	ansRule("TG-ANS-S3-003", Medium, "CWE-311", "S3 bucket encryption is turned off",
		"Set encryption: AES256 or aws:kms (with encryption_key_id).", []string{"s3_bucket"},
		func(r *Resource) []Hit {
			if ansStr(r, "encryption") == "none" {
				return one("encryption", "The bucket's default encryption is removed, so objects uploaded without a header are stored unencrypted.")
			}
			return nil
		}),
	ansRule("TG-ANS-S3-004", Medium, "CWE-693", "S3 bucket versioning is not enabled",
		"Set versioning: true so overwritten or deleted objects can be restored.", []string{"s3_bucket"},
		unlessOn("versioning", "Without versioning an overwrite or delete (or ransomware) destroys the only copy.")),
	ansRule("TG-ANS-S3-005", Medium, "CWE-942", "S3 CORS rule allows any origin",
		"List the exact origins that need cross-origin access in allowed_origins.", []string{"aws_s3_cors", "s3_cors"},
		func(r *Resource) []Hit {
			for i, e := range asList(ansGet(r, "rules")) {
				if m, ok := e.(map[string]any); ok && contains(asStrings(m["allowed_origins"]), "*") {
					return one("rules."+strconv.Itoa(i), "Any website can make browsers send requests to this bucket.")
				}
			}
			return nil
		}),
	ansRule("TG-ANS-SG-001", High, "CWE-284", "Security group opens a sensitive port to the internet",
		"Restrict cidr_ip to known ranges, or reach the service through a bastion, VPN or load balancer.", []string{"ec2_group", "ec2_security_group"},
		func(r *Resource) []Hit { return ec2GroupHits(r, false) }),
	ansRule("TG-ANS-SG-002", Medium, "CWE-284", "Security group opens a wide port range to the internet",
		"Open only the ports the service listens on.", []string{"ec2_group", "ec2_security_group"},
		func(r *Resource) []Hit { return ec2GroupHits(r, true) }),
	ansRule("TG-ANS-EC2-001", High, "CWE-311", "EBS volume is not encrypted",
		"Set encrypted: true (and kms_key_id for a customer key), or turn on EBS encryption by default for the account.",
		[]string{"ec2_vol", "ec2_lc", "autoscaling_launch_config"},
		func(r *Resource) []Hit {
			if r.Type == "ansible_ec2_vol" {
				return unlessOn("encrypted", "Data on the volume and its snapshots is stored unencrypted.")(r)
			}
			for i, e := range asList(ansGet(r, "volumes")) {
				if m, ok := e.(map[string]any); ok && m["ephemeral"] == nil && m["encrypted"] != true && !isUnknown(m["encrypted"]) {
					if b, ok := ansBool(m["encrypted"]); !ok || !b {
						return one("volumes."+strconv.Itoa(i), "Instances launched from this configuration get unencrypted volumes.")
					}
				}
			}
			return nil
		}),
	ansRule("TG-ANS-EC2-002", Medium, "CWE-284", "Instance gets a public IP address",
		"Launch into a private subnet without a public IP and reach it through a load balancer, bastion or SSM.",
		[]string{"ec2", "ec2_instance", "ec2_launch_template"},
		func(r *Resource) []Hit {
			for _, p := range []string{"assign_public_ip", "network.assign_public_ip", "network_interfaces.associate_public_ip_address"} {
				if ansOn(r, p) {
					return one(p, "The instance is reachable from the internet whenever its security group allows it.")
				}
			}
			return nil
		}),
	ansRule("TG-ANS-EC2-003", Low, "CWE-918", "Instance metadata allows IMDSv1",
		"Set metadata_options.http_tokens: required.", []string{"ec2_instance", "ec2_launch_template"},
		func(r *Resource) []Hit {
			if ansStr(r, "metadata_options.http_endpoint") == "disabled" || isUnknown(ansGet(r, "metadata_options.http_tokens")) {
				return nil
			}
			if ansStr(r, "metadata_options.http_tokens") != "required" {
				return one("metadata_options", "Without session tokens an SSRF bug in the app can read the instance's IAM credentials.")
			}
			return nil
		}),
	ansRule("TG-ANS-EC2-004", Medium, "CWE-311", "AMI has unencrypted volumes",
		"Set encrypted: true on every device_mapping entry.", []string{"ec2_ami"},
		func(r *Resource) []Hit {
			for i, e := range asList(ansGet(r, "device_mapping")) {
				if m, ok := e.(map[string]any); ok && !isUnknown(m["encrypted"]) {
					if b, _ := ansBool(m["encrypted"]); !b {
						return one("device_mapping."+strconv.Itoa(i), "Instances built from the image start with unencrypted disks.")
					}
				}
			}
			return nil
		}),
	ansRule("TG-ANS-EC2-005", High, "CWE-200", "AMI is shared publicly",
		"Remove group_names: all from launch_permissions and share with specific account IDs.", []string{"ec2_ami"},
		func(r *Resource) []Hit {
			if contains(asStrings(ansGet(r, "launch_permissions.group_names")), "all") {
				return one("launch_permissions", "Every AWS account can launch the image and read anything baked into it.")
			}
			return nil
		}),
	ansRule("TG-ANS-RDS-001", High, "CWE-284", "Database is publicly accessible",
		"Set publicly_accessible: false and connect from inside the VPC.", []string{"rds_instance", "rds"},
		whenOn("publicly_accessible", "The database gets a public endpoint, one security group change away from the internet.")),
	ansRule("TG-ANS-RDS-002", High, "CWE-311", "Database storage is not encrypted",
		"Set storage_encrypted: true (and kms_key_id for a customer key); existing instances need a snapshot restore.", []string{"rds_instance"},
		func(r *Resource) []Hit {
			if ansNotOn(r, "storage_encrypted") && ansAbsent(r, "kms_key_id") {
				return one("storage_encrypted", "Data, backups and snapshots are stored unencrypted.")
			}
			return nil
		}),
	ansRule("TG-ANS-RDS-003", Medium, "CWE-693", "Database backups are turned off",
		"Set backup_retention_period to 7 or more days.", []string{"rds_instance"},
		func(r *Resource) []Hit {
			if f, ok := asFloat(ansGet(r, "backup_retention_period")); ok && f == 0 {
				return one("backup_retention_period", "A retention period of 0 disables automated backups and point-in-time restore.")
			}
			return nil
		}),
	ansRule("TG-ANS-RDS-004", Low, "CWE-287", "Database IAM authentication is off",
		"Set enable_iam_database_authentication: true so users log in with short-lived IAM tokens.", []string{"rds_instance"},
		unlessOn("enable_iam_database_authentication", "Only static database passwords can be used, which are hard to rotate and audit.")),
	ansRule("TG-ANS-RDS-005", Low, "CWE-1104", "Database minor version upgrades are off",
		"Set auto_minor_version_upgrade: true.", []string{"rds_instance"},
		whenOff("auto_minor_version_upgrade", "Security patches in minor engine releases are not applied.")),
	ansRule("TG-ANS-REDSHIFT-001", High, "CWE-284", "Redshift cluster is publicly accessible",
		"Set publicly_accessible: false.", []string{"redshift"},
		whenOn("publicly_accessible", "The warehouse gets a public endpoint.")),
	ansRule("TG-ANS-REDSHIFT-002", High, "CWE-311", "Redshift cluster is not encrypted",
		"Set encrypted: true when the cluster is created.", []string{"redshift"},
		func(r *Resource) []Hit {
			if c := ansStr(r, "command"); c != "" && c != "create" {
				return nil
			}
			return unlessOn("encrypted", "Warehouse data and snapshots are stored unencrypted.")(r)
		}),
	ansRule("TG-ANS-EFS-001", High, "CWE-311", "EFS file system is not encrypted",
		"Set encrypt: true (and kms_key_id for a customer key).", []string{"efs"},
		unlessOn("encrypt", "Files are stored unencrypted at rest.")),
	ansRule("TG-ANS-KMS-001", Low, "CWE-320", "KMS key rotation is off",
		"Set enable_key_rotation: true.", []string{"aws_kms", "kms_key"},
		func(r *Resource) []Hit {
			if ansOff(r, "enabled") || ansStr(r, "key_spec") != "" && ansStr(r, "key_spec") != "symmetric_default" {
				return nil
			}
			return unlessOn("enable_key_rotation", "The same key material encrypts data for as long as the key exists.")(r)
		}),
	ansRule("TG-ANS-KMS-002", High, "CWE-732", "KMS key policy allows anyone",
		"Name the accounts and roles that may use the key in its policy.", []string{"aws_kms", "kms_key"},
		func(r *Resource) []Hit { return publicStatements(r, "policy", "key") }),
	ansRule("TG-ANS-IAM-001", High, "CWE-269", "IAM policy grants full or service-wide access",
		"List the actions and resources the role needs instead of wildcards.", []string{"iam_managed_policy", "iam_policy"},
		func(r *Resource) []Hit {
			for _, p := range []string{"policy", "policy_json"} {
				if h := wildcardHits(statements(ansGet(r, p)), p); len(h) > 0 {
					return h[:1]
				}
			}
			return nil
		}),
	ansRule("TG-ANS-IAM-002", High, "CWE-284", "IAM role can be assumed by anyone",
		"Name the trusted account or service in the trust policy, and require sts:ExternalId or MFA for other accounts.", []string{"iam_role"},
		func(r *Resource) []Hit { return publicStatements(r, "assume_role_policy_document", "trust") }),
	ansRule("TG-ANS-IAM-003", Medium, "CWE-521", "Account password policy is weak",
		"Require at least 14 characters, prevent reuse of the last 24 passwords and expire passwords within 90 days.", []string{"iam_password_policy"},
		func(r *Resource) []Hit {
			first := func(keys ...string) (string, any) {
				for _, k := range keys {
					if v := ansGet(r, k); v != nil {
						return k, v
					}
				}
				return keys[0], nil
			}
			if k, v := first("min_pw_length", "minimum_password_length"); !isUnknown(v) {
				if f, ok := asFloat(v); !ok && v == nil || ok && f < 14 {
					return one(k, "Passwords shorter than 14 characters are allowed.")
				}
			}
			if k, v := first("pw_reuse_prevent", "password_reuse_prevent", "prevent_reuse"); !isUnknown(v) {
				if f, ok := asFloat(v); v == nil || ok && f == 0 {
					return one(k, "Users can reuse old passwords.")
				}
			}
			if k, v := first("pw_max_age", "password_max_age"); !isUnknown(v) {
				if f, ok := asFloat(v); v == nil || ok && (f == 0 || f > 90) {
					return one(k, "Passwords never expire or live longer than 90 days.")
				}
			}
			return nil
		}),
	ansRule("TG-ANS-IAM-004", Low, "CWE-798", "IAM user gets a long-lived access key",
		"Use roles (instance profiles, OIDC, SSO) instead of access keys.", []string{"iam", "iam_access_key"},
		func(r *Resource) []Hit {
			if ansStr(r, "access_key_state") == "active" || r.Type == "ansible_iam_access_key" && !ansNotOn(r, "active") {
				return one("access_key_state", "Static keys leak through laptops, CI logs and repositories and stay valid until rotated.")
			}
			return nil
		}),
	ansRule("TG-ANS-CT-001", Medium, "CWE-778", "CloudTrail is off or covers one region",
		"Set enable_logging: true and is_multi_region_trail: true.", []string{"cloudtrail"},
		func(r *Resource) []Hit {
			if ansOff(r, "enable_logging") {
				return one("enable_logging", "API activity is not recorded.")
			}
			return unlessOn("is_multi_region_trail", "Activity in other regions, where attackers like to work, is not recorded.")(r)
		}),
	ansRule("TG-ANS-CT-002", Low, "CWE-354", "CloudTrail log file validation is off",
		"Set enable_log_file_validation: true.", []string{"cloudtrail"},
		func(r *Resource) []Hit {
			if ansNotOn(r, "enable_log_file_validation") && ansNotOn(r, "log_file_validation_enabled") {
				return one("enable_log_file_validation", "Altered or deleted log files cannot be detected.")
			}
			return nil
		}),
	ansRule("TG-ANS-CT-003", Low, "CWE-311", "CloudTrail logs are not encrypted with a KMS key",
		"Set kms_key_id to a customer managed key.", []string{"cloudtrail"},
		unlessSet("kms_key_id", "Anyone who can read the log bucket can read the trail.")),
	ansRule("TG-ANS-CF-001", Medium, "CWE-319", "CloudFront serves content over HTTP",
		"Set viewer_protocol_policy to redirect-to-https or https-only.", []string{"cloudfront_distribution"},
		func(r *Resource) []Hit {
			if ansStr(r, "default_cache_behavior.viewer_protocol_policy") == "allow-all" {
				return one("default_cache_behavior.viewer_protocol_policy", "Viewers can use unencrypted HTTP.")
			}
			for i, e := range asList(ansGet(r, "cache_behaviors")) {
				if m, ok := e.(map[string]any); ok && strings.EqualFold(fmt.Sprint(m["viewer_protocol_policy"]), "allow-all") {
					return one("cache_behaviors."+strconv.Itoa(i), "Viewers can use unencrypted HTTP for this path.")
				}
			}
			return nil
		}),
	ansRule("TG-ANS-CF-002", Medium, "CWE-326", "CloudFront allows TLS older than 1.2",
		"Use your own certificate with minimum_protocol_version: TLSv1.2_2021.", []string{"cloudfront_distribution"},
		func(r *Resource) []Hit {
			if ansOn(r, "viewer_certificate.cloudfront_default_certificate") {
				return one("viewer_certificate", "The default certificate accepts TLS 1.0 and 1.1.")
			}
			if v := ansStr(r, "viewer_certificate.minimum_protocol_version"); v != "" && !strings.HasPrefix(v, "tlsv1.2") && !strings.HasPrefix(v, "tlsv1.3") {
				return one("viewer_certificate.minimum_protocol_version", "Protocol "+v+" allows broken TLS versions.")
			}
			return nil
		}),
	ansRule("TG-ANS-CF-003", Low, "CWE-778", "CloudFront access logging is off",
		"Set logging.enabled: true with a log bucket.", []string{"cloudfront_distribution"},
		unlessOn("logging.enabled", "Requests to the distribution are not recorded.")),
	ansRule("TG-ANS-ELB-001", Medium, "CWE-319", "Load balancer listens on plain HTTP",
		"Use an HTTPS listener, and make any HTTP listener only redirect to HTTPS.", []string{"elb_application_lb"},
		func(r *Resource) []Hit {
			for i, e := range asList(ansGet(r, "listeners")) {
				m, _ := e.(map[string]any)
				if m == nil || !strings.EqualFold(fmt.Sprint(m["Protocol"]), "HTTP") {
					continue
				}
				redirect := false
				for _, a := range asList(m["DefaultActions"]) {
					if am, ok := a.(map[string]any); ok && strings.EqualFold(fmt.Sprint(am["Type"]), "redirect") {
						redirect = true
					}
				}
				if !redirect {
					return one("listeners."+strconv.Itoa(i), "Traffic between clients and the load balancer is unencrypted.")
				}
			}
			return nil
		}),
	ansRule("TG-ANS-ELB-002", Medium, "CWE-326", "Load balancer uses an outdated TLS policy",
		"Use ELBSecurityPolicy-TLS13-1-2-2021-06 or another TLS 1.2+ policy.", []string{"elb_application_lb", "elb_network_lb"},
		func(r *Resource) []Hit {
			for i, e := range asList(ansGet(r, "listeners")) {
				m, _ := e.(map[string]any)
				p, _ := m["SslPolicy"].(string)
				if p == "ELBSecurityPolicy-2015-05" || p == "ELBSecurityPolicy-2016-08" || strings.Contains(p, "TLS-1-0") || strings.Contains(p, "TLS-1-1") {
					return one("listeners."+strconv.Itoa(i), "Policy "+p+" still accepts TLS 1.0 or 1.1.")
				}
			}
			return nil
		}),
	ansRule("TG-ANS-SQS-001", High, "CWE-284", "SQS queue policy allows anyone",
		"Name specific principals in the queue policy, or add an aws:SourceArn condition.", []string{"sqs_queue"},
		func(r *Resource) []Hit { return publicStatements(r, "policy", "queue") }),
	ansRule("TG-ANS-SQS-002", Low, "CWE-311", "SQS queue is not encrypted",
		"Set kms_master_key_id, or sqs_managed_sse_enabled: true.", []string{"sqs_queue"},
		func(r *Resource) []Hit {
			if ansAbsent(r, "kms_master_key_id") && ansOff(r, "sqs_managed_sse_enabled") {
				return one("sqs_managed_sse_enabled", "Messages are stored unencrypted.")
			}
			return nil
		}),
	ansRule("TG-ANS-SNS-001", High, "CWE-284", "SNS topic policy allows anyone",
		"Name specific principals in the topic policy.", []string{"sns_topic"},
		func(r *Resource) []Hit { return publicStatements(r, "policy", "topic") }),
	ansRule("TG-ANS-ECR-001", High, "CWE-284", "ECR repository policy allows anyone",
		"Name specific accounts in the repository policy.", []string{"ecs_ecr"},
		func(r *Resource) []Hit { return publicStatements(r, "policy", "repository") }),
	ansRule("TG-ANS-ECR-002", Low, "CWE-494", "ECR image tags can be overwritten",
		"Set image_tag_mutability: immutable.", []string{"ecs_ecr"},
		func(r *Resource) []Hit {
			if v := ansGet(r, "image_tag_mutability"); !isUnknown(v) && ansStr(r, "image_tag_mutability") != "immutable" {
				return one("image_tag_mutability", "A pushed tag can be replaced, so a deploy of a tag may pull different code.")
			}
			return nil
		}),
	ansRule("TG-ANS-LAMBDA-001", High, "CWE-284", "Lambda permission allows any principal",
		"Set principal to the service or account that calls the function, with source_arn.", []string{"lambda_policy"},
		func(r *Resource) []Hit {
			if ansStr(r, "principal") == "*" {
				return one("principal", "Anyone can invoke the function.")
			}
			return nil
		}),
	ansRule("TG-ANS-ES-001", Medium, "CWE-319", "OpenSearch domain does not require HTTPS",
		"Set domain_endpoint_options.enforce_https: true.", []string{"opensearch"},
		unlessOn("domain_endpoint_options.enforce_https", "Clients can talk to the domain over unencrypted HTTP.")),
	ansRule("TG-ANS-KINESIS-001", Medium, "CWE-311", "Kinesis stream is not encrypted",
		"Set encryption_state: enabled with encryption_type: KMS.", []string{"kinesis_stream"},
		func(r *Resource) []Hit {
			if v := ansGet(r, "encryption_state"); !isUnknown(v) && ansStr(r, "encryption_state") != "enabled" {
				return one("encryption_state", "Records are stored unencrypted.")
			}
			return nil
		}),
	ansRule("TG-ANS-BATCH-001", High, "CWE-250", "Batch job runs a privileged container",
		"Remove privileged: true from the job definition.", []string{"aws_batch_job_definition", "batch_job_definition"},
		whenOn("privileged", "The container has root access to the host.")),
	ansRule("TG-ANS-ECS-001", Medium, "CWE-284", "ECS service gives tasks public IPs",
		"Set network_configuration.assign_public_ip: false and use private subnets.", []string{"ecs_service"},
		whenOn("network_configuration.assign_public_ip", "Tasks are reachable from the internet whenever the security group allows it.")),
	ansRule("TG-ANS-LOGS-001", Low, "CWE-778", "Log group keeps logs forever or has no retention",
		"Set retention (in days) to what your audit policy requires.", []string{"cloudwatchlogs_log_group"},
		unlessSet("retention", "Logs are never expired, so costs grow and sensitive data is kept longer than needed.")),

	// Azure
	ansRule("TG-ANS-AZ-ST-001", High, "CWE-284", "Storage account accepts traffic from any network",
		"Set network_acls.default_action: Deny and list allowed networks, or public_network_access: Disabled.", []string{"azure_rm_storageaccount"},
		func(r *Resource) []Hit {
			if ansStr(r, "public_network_access") == "disabled" {
				return nil
			}
			if ansStr(r, "network_acls.default_action") == "allow" {
				return one("network_acls.default_action", "Any network can reach the storage endpoints.")
			}
			for i, e := range asList(ansGet(r, "network_acls.ip_rules")) {
				if m, ok := e.(map[string]any); ok && anyWorld(m["value"]) {
					return one("network_acls.ip_rules."+strconv.Itoa(i), "An IP rule admits the whole internet.")
				}
			}
			return nil
		}),
	ansRule("TG-ANS-AZ-ST-002", Medium, "CWE-319", "Storage account allows plain HTTP",
		"Set https_only: true.", []string{"azure_rm_storageaccount"},
		whenOff("https_only", "Data can be sent to the account unencrypted.")),
	ansRule("TG-ANS-AZ-ST-003", Medium, "CWE-326", "Storage account allows TLS older than 1.2",
		"Set minimum_tls_version: TLS1_2.", []string{"azure_rm_storageaccount"},
		func(r *Resource) []Hit {
			if v := ansStr(r, "minimum_tls_version"); v == "tls1_0" || v == "tls1_1" {
				return one("minimum_tls_version", "Clients may use broken TLS versions.")
			}
			return nil
		}),
	ansRule("TG-ANS-AZ-ST-004", High, "CWE-284", "Blob container or account allows anonymous reads",
		"Set public_access to none (omit it) and allow_blob_public_access: false.", []string{"azure_rm_storageblob", "azure_rm_storageaccount"},
		func(r *Resource) []Hit {
			if v := ansStr(r, "public_access"); v == "container" || v == "blob" {
				return one("public_access", "Anyone with the URL can read the blobs without credentials.")
			}
			return whenOn("allow_blob_public_access", "Containers in the account can be made readable by anyone.")(r)
		}),
	ansRule("TG-ANS-AZ-SQL-001", Critical, "CWE-284", "Database firewall rule allows every IP address",
		"Narrow start_ip_address and end_ip_address to the addresses that connect, or use private endpoints.",
		[]string{"azure_rm_sqlfirewallrule", "azure_rm_mysqlfirewallrule", "azure_rm_postgresqlfirewallrule", "azure_rm_mariadbfirewallrule", "azure_rm_rediscachefirewallrule"},
		func(r *Resource) []Hit {
			s, e := ansStr(r, "start_ip_address"), ansStr(r, "end_ip_address")
			if s == "" {
				s, e = ansStr(r, "start_ip"), ansStr(r, "end_ip")
			}
			if s == "0.0.0.0" && e == "255.255.255.255" {
				return one("start_ip_address", "The whole internet can try to log in to the server.")
			}
			return nil
		}),
	ansRule("TG-ANS-AZ-SQL-002", Low, "CWE-1391", "SQL server admin login is easy to guess",
		"Use an admin login name that is not admin, administrator, sa, root or similar.", []string{"azure_rm_sqlserver"},
		func(r *Resource) []Hit {
			switch ansStr(r, "admin_username") {
			case "admin", "administrator", "sa", "root", "dbadmin", "sqladmin", "azure_superuser", "guest", "public", "user", "test":
				return one("admin_username", "Attackers try these names first in brute-force attacks.")
			}
			return nil
		}),
	ansRule("TG-ANS-AZ-DB-001", Medium, "CWE-319", "Database server does not require TLS",
		"Set enforce_ssl: true.", []string{"azure_rm_mysqlserver", "azure_rm_postgresqlserver", "azure_rm_mariadbserver"},
		unlessOn("enforce_ssl", "Clients can connect without encryption (the module default).")),
	ansRule("TG-ANS-AZ-DB-002", Low, "CWE-778", "PostgreSQL connection or checkpoint logging is off",
		"Set the parameter's value to on.", []string{"azure_rm_postgresqlconfiguration"},
		func(r *Resource) []Hit {
			switch ansStr(r, "name") {
			case "log_checkpoints", "log_connections", "log_disconnections", "log_duration", "connection_throttling":
				if ansOff(r, "value") {
					return one("value", "Parameter "+ansStr(r, "name")+" is off, so sign-ins and load problems are not visible.")
				}
			}
			return nil
		}),
	ansRule("TG-ANS-AZ-REDIS-001", Medium, "CWE-319", "Redis cache allows the non-TLS port",
		"Set enable_non_ssl_port: false.", []string{"azure_rm_rediscache"},
		whenOn("enable_non_ssl_port", "Clients can connect on 6379 without encryption.")),
	ansRule("TG-ANS-AZ-NSG-001", High, "CWE-284", "Network security group opens a sensitive port to the internet",
		"Set source_address_prefix to known ranges, or reach the service through Bastion or a VPN.", []string{"azure_rm_securitygroup"},
		nsgHits),
	ansRule("TG-ANS-AZ-AKS-001", Medium, "CWE-285", "AKS cluster has Kubernetes RBAC off",
		"Set enable_rbac: true.", []string{"azure_rm_aks"},
		unlessOn("enable_rbac", "Without RBAC every authenticated identity has full control of the cluster (the module default is off).")),
	ansRule("TG-ANS-AZ-AKS-002", Low, "CWE-284", "AKS cluster has no network policy",
		"Set network_profile.network_policy to azure or calico.", []string{"azure_rm_aks"},
		unlessSet("network_profile.network_policy", "Every pod can talk to every other pod.")),
	ansRule("TG-ANS-AZ-ACR-001", Medium, "CWE-798", "Container registry admin user is on",
		"Set admin_user_enabled: false and use Azure AD identities to pull and push.", []string{"azure_rm_containerregistry"},
		whenOn("admin_user_enabled", "A shared admin password grants full push and pull access.")),
	ansRule("TG-ANS-AZ-KV-001", Medium, "CWE-693", "Key vault soft delete is off",
		"Set enable_soft_delete: true and enable_purge_protection: true.", []string{"azure_rm_keyvault"},
		whenOff("enable_soft_delete", "Deleted keys and secrets cannot be recovered.")),
	ansRule("TG-ANS-AZ-WEB-001", Medium, "CWE-319", "Web app accepts plain HTTP",
		"Set https_only: true.", []string{"azure_rm_webapp"},
		unlessOn("https_only", "Users can reach the app over unencrypted HTTP (the module default).")),
	ansRule("TG-ANS-AZ-COSMOS-001", Medium, "CWE-284", "Cosmos DB account is open to all networks",
		"Set ip_rules or virtual_network_rules with is_virtual_network_filter_enabled, or public_network_access: Disabled.", []string{"azure_rm_cosmosdbaccount"},
		func(r *Resource) []Hit {
			if ansStr(r, "public_network_access") == "disabled" || !ansAbsent(r, "ip_rules") || !ansAbsent(r, "ip_range_filter") || !ansNotOn(r, "is_virtual_network_filter_enabled") {
				return nil
			}
			return one("", "Any network can reach the account endpoint.")
		}),
	ansRule("TG-ANS-AZ-VM-001", Medium, "CWE-309", "Linux VM allows SSH password sign-in",
		"Set ssh_password_enabled: false and provide ssh_public_keys.", []string{"azure_rm_virtualmachine"},
		func(r *Resource) []Hit {
			if os := ansStr(r, "os_type"); os != "" && os != "linux" || ansOff(r, "ssh_password_enabled") || isUnknown(ansGet(r, "ssh_password_enabled")) {
				return nil
			}
			return one("ssh_password_enabled", "Passwords can be brute-forced; key-only SSH removes that risk.")
		}),
	ansRule("TG-ANS-AZ-AG-001", Medium, "CWE-693", "Application gateway WAF is off",
		"Set web_application_firewall_configuration.enabled: true in Prevention mode.", []string{"azure_rm_appgateway"},
		whenOff("web_application_firewall_configuration.enabled", "Common web attacks reach the backend unfiltered.")),
	ansRule("TG-ANS-AZ-ROLE-001", Medium, "CWE-269", "Custom role can manage role definitions or do anything",
		"List only the actions the role needs; leave out * and Microsoft.Authorization/*.", []string{"azure_rm_roledefinition"},
		func(r *Resource) []Hit {
			for i, e := range asList(ansGet(r, "permissions")) {
				m, _ := e.(map[string]any)
				for _, a := range asStrings(m["actions"]) {
					if a == "*" || strings.EqualFold(a, "Microsoft.Authorization/*") || strings.EqualFold(a, "Microsoft.Authorization/roleDefinitions/write") {
						return one("permissions."+strconv.Itoa(i), "Action "+a+" lets holders grant themselves more access.")
					}
				}
			}
			return nil
		}),
	ansRule("TG-ANS-AZ-MON-001", Low, "CWE-778", "Activity log profile keeps logs less than a year",
		"Set retention_policy.enabled: true with days of 365 or more.", []string{"azure_rm_monitorlogprofile"},
		func(r *Resource) []Hit {
			if ansOff(r, "retention_policy.enabled") {
				return one("retention_policy.enabled", "Activity logs are not retained.")
			}
			if d, ok := asFloat(ansGet(r, "retention_policy.days")); ok && d > 0 && d < 365 {
				return one("retention_policy.days", "Activity logs are deleted before a typical one-year audit window.")
			}
			return nil
		}),

	// GCP
	ansRule("TG-ANS-GCP-GCS-001", Critical, "CWE-284", "Cloud Storage bucket is public",
		"Remove allUsers and allAuthenticatedUsers from acl and default_object_acl.", []string{"gcp_storage_bucket"},
		func(r *Resource) []Hit {
			for _, p := range []string{"acl", "default_object_acl"} {
				for _, e := range append(asList(ansGet(r, p)), ansGet(r, p)) {
					m, _ := e.(map[string]any)
					if s := strings.ToLower(fmt.Sprint(m["entity"])); s == "allusers" || s == "allauthenticatedusers" {
						return one(p, "Anyone (or any Google account) can read the bucket's objects.")
					}
				}
			}
			return nil
		}),
	ansRule("TG-ANS-GCP-GCS-002", Low, "CWE-693", "Cloud Storage bucket versioning is off",
		"Set versioning.enabled: true.", []string{"gcp_storage_bucket"},
		unlessOn("versioning.enabled", "An overwrite or delete destroys the only copy.")),
	ansRule("TG-ANS-GCP-GCS-003", Low, "CWE-778", "Cloud Storage bucket access logging is off",
		"Set logging.log_bucket.", []string{"gcp_storage_bucket"},
		unlessSet("logging", "Reads and writes to the bucket are not recorded.")),
	ansRule("TG-ANS-GCP-BQ-001", High, "CWE-284", "BigQuery dataset is public",
		"Remove allUsers and allAuthenticatedUsers from access.", []string{"gcp_bigquery_dataset"},
		func(r *Resource) []Hit {
			for i, e := range asList(ansGet(r, "access")) {
				m, _ := e.(map[string]any)
				if s := strings.ToLower(fmt.Sprint(m["special_group"])); s == "allauthenticatedusers" || strings.EqualFold(fmt.Sprint(m["iam_member"]), "allUsers") {
					return one("access."+strconv.Itoa(i), "Anyone (or any Google account) can query the dataset.")
				}
			}
			return nil
		}),
	ansRule("TG-ANS-GCP-SQL-001", Critical, "CWE-284", "Cloud SQL instance accepts connections from anywhere",
		"Remove 0.0.0.0/0 from authorized_networks and use private IP or the Cloud SQL Auth Proxy.", []string{"gcp_sql_instance"},
		func(r *Resource) []Hit {
			for i, e := range asList(ansGet(r, "settings.ip_configuration.authorized_networks")) {
				if m, ok := e.(map[string]any); ok && anyWorld(m["value"]) {
					return one("settings.ip_configuration.authorized_networks."+strconv.Itoa(i), "The database is reachable from the whole internet.")
				}
			}
			return nil
		}),
	ansRule("TG-ANS-GCP-SQL-002", High, "CWE-319", "Cloud SQL instance does not require TLS",
		"Set settings.ip_configuration.require_ssl: true.", []string{"gcp_sql_instance"},
		unlessOn("settings.ip_configuration.require_ssl", "Clients can connect without encryption.")),
	ansRule("TG-ANS-GCP-SQL-003", Medium, "CWE-693", "Cloud SQL backups are off",
		"Set settings.backup_configuration.enabled: true.", []string{"gcp_sql_instance"},
		unlessOn("settings.backup_configuration.enabled", "Without automated backups data loss cannot be undone.")),
	ansRule("TG-ANS-GCP-SQL-004", High, "CWE-284", "Cloud SQL database flag weakens isolation",
		"Set local_infile, cross db ownership chaining and contained database authentication to off.", []string{"gcp_sql_instance"},
		func(r *Resource) []Hit {
			for i, e := range asList(ansGet(r, "settings.database_flags")) {
				m, _ := e.(map[string]any)
				switch fmt.Sprint(m["name"]) {
				case "local_infile", "cross db ownership chaining", "contained database authentication":
					if b, ok := ansBool(m["value"]); ok && b {
						return one("settings.database_flags."+strconv.Itoa(i), "Flag "+fmt.Sprint(m["name"])+" is on, which lets users read server files or cross database boundaries.")
					}
				}
			}
			return nil
		}),
	ansRule("TG-ANS-GCP-GKE-001", High, "CWE-285", "GKE cluster uses legacy ABAC",
		"Set legacy_abac.enabled: false and use RBAC.", []string{"gcp_container_cluster"},
		whenOn("legacy_abac.enabled", "Legacy ABAC grants broad, hard-to-audit permissions.")),
	ansRule("TG-ANS-GCP-GKE-002", Medium, "CWE-287", "GKE cluster uses basic auth or client certificates",
		"Remove master_auth.username/password and client certificate issuing; use Google identities.", []string{"gcp_container_cluster"},
		func(r *Resource) []Hit {
			if u := ansGet(r, "master_auth.username"); u != nil && !isUnknown(u) && u != "" {
				return one("master_auth.username", "A static username and password grant cluster admin.")
			}
			return whenOn("master_auth.client_certificate_config.issue_client_certificate", "A long-lived client certificate grants cluster admin and cannot be revoked.")(r)
		}),
	ansRule("TG-ANS-GCP-GKE-003", Medium, "CWE-284", "GKE nodes or control plane are public",
		"Set private_cluster_config.enable_private_nodes: true and turn on master_authorized_networks_config.", []string{"gcp_container_cluster"},
		func(r *Resource) []Hit {
			if ansNotOn(r, "private_cluster_config.enable_private_nodes") {
				return one("private_cluster_config", "Nodes get public IP addresses.")
			}
			return unlessOn("master_authorized_networks_config.enabled", "The Kubernetes API is reachable from any address.")(r)
		}),
	ansRule("TG-ANS-GCP-GKE-004", Medium, "CWE-284", "GKE network policy is off",
		"Set network_policy.enabled: true (or addons_config.network_policy_config.disabled: false).", []string{"gcp_container_cluster"},
		func(r *Resource) []Hit {
			if ansOff(r, "network_policy.enabled") || ansOn(r, "addons_config.network_policy_config.disabled") {
				return one("network_policy", "Every pod can talk to every other pod.")
			}
			return nil
		}),
	ansRule("TG-ANS-GCP-GKE-005", Medium, "CWE-778", "GKE logging or monitoring is off",
		"Set logging_service: logging.googleapis.com/kubernetes and monitoring_service: monitoring.googleapis.com/kubernetes.", []string{"gcp_container_cluster"},
		func(r *Resource) []Hit {
			for _, k := range []string{"logging_service", "monitoring_service"} {
				if ansStr(r, k) == "none" {
					return one(k, k+" is none, so cluster activity is not recorded.")
				}
			}
			return nil
		}),
	ansRule("TG-ANS-GCP-GKE-006", Medium, "CWE-1104", "GKE node pool auto-repair or auto-upgrade is off",
		"Set management.auto_repair and management.auto_upgrade to true.", []string{"gcp_container_node_pool"},
		func(r *Resource) []Hit {
			for _, k := range []string{"management.auto_repair", "management.auto_upgrade"} {
				if ansOff(r, k) {
					return one(k, "Broken or unpatched nodes stay in the pool.")
				}
			}
			return nil
		}),
	ansRule("TG-ANS-GCP-VM-001", Medium, "CWE-284", "Compute instance has a public IP",
		"Remove access_configs from network_interfaces and use Cloud NAT and IAP.", []string{"gcp_compute_instance"},
		func(r *Resource) []Hit {
			for i, e := range asList(ansGet(r, "network_interfaces")) {
				if m, ok := e.(map[string]any); ok && len(asList(m["access_configs"])) > 0 {
					return one("network_interfaces."+strconv.Itoa(i), "The VM is reachable from the internet whenever firewall rules allow it.")
				}
			}
			return nil
		}),
	ansRule("TG-ANS-GCP-VM-002", Medium, "CWE-287", "Compute instance metadata weakens SSH access",
		"Set metadata block-project-ssh-keys: true and enable-oslogin: true, and leave serial-port-enable off.", []string{"gcp_compute_instance"},
		func(r *Resource) []Hit {
			md, _ := ansGet(r, "metadata").(map[string]any)
			if b, ok := ansBool(md["serial-port-enable"]); ok && b {
				return one("metadata.serial-port-enable", "The interactive serial console is reachable for anyone with the right IAM role, bypassing network controls.")
			}
			if b, ok := ansBool(md["enable-oslogin"]); ok && !b {
				return one("metadata.enable-oslogin", "SSH access is not tied to IAM identities.")
			}
			if v := md["block-project-ssh-keys"]; !isUnknown(ansGet(r, "metadata")) && !isUnknown(v) {
				if b, _ := ansBool(v); !b {
					return one("metadata", "Project-wide SSH keys can log in to this VM.")
				}
			}
			return nil
		}),
	ansRule("TG-ANS-GCP-VM-003", Medium, "CWE-284", "Compute instance can forward IP traffic",
		"Set can_ip_forward: false unless the VM is a router or NAT.", []string{"gcp_compute_instance"},
		whenOn("can_ip_forward", "The VM can send and receive packets for other addresses, which helps an attacker pivot.")),
	ansRule("TG-ANS-GCP-VM-004", Medium, "CWE-250", "Compute instance has full access to Google Cloud APIs",
		"Use a dedicated service account with only the roles it needs, and avoid the cloud-platform scope.", []string{"gcp_compute_instance"},
		func(r *Resource) []Hit {
			for i, e := range asList(ansGet(r, "service_accounts")) {
				m, _ := e.(map[string]any)
				for _, s := range asStrings(m["scopes"]) {
					if strings.HasSuffix(s, "/cloud-platform") || s == "cloud-platform" {
						return one("service_accounts."+strconv.Itoa(i), "Code on the VM can call every Google Cloud API the service account can.")
					}
				}
			}
			return nil
		}),
	ansRule("TG-ANS-GCP-VM-005", Low, "CWE-693", "Compute instance is not a shielded VM",
		"Set shielded_instance_config.enable_secure_boot, enable_vtpm and enable_integrity_monitoring to true.", []string{"gcp_compute_instance"},
		func(r *Resource) []Hit {
			for _, k := range []string{"enable_secure_boot", "enable_vtpm", "enable_integrity_monitoring"} {
				if ansOff(r, "shielded_instance_config."+k) {
					return one("shielded_instance_config."+k, "Boot-level malware and rootkits are not detected.")
				}
			}
			return nil
		}),
	ansRule("TG-ANS-GCP-FW-001", High, "CWE-284", "Firewall rule opens a sensitive port to the internet",
		"Narrow source_ranges, or reach the service through IAP or a VPN.", []string{"gcp_compute_firewall"},
		gcpFirewallHits),
	ansRule("TG-ANS-GCP-DNS-001", Medium, "CWE-350", "Cloud DNS zone has DNSSEC off or uses RSASHA1",
		"Set dnssec_config.state: on with RSASHA256 or ECDSA keys.", []string{"gcp_dns_managed_zone"},
		func(r *Resource) []Hit {
			if ansStr(r, "visibility") == "private" {
				return nil
			}
			if s := ansStr(r, "dnssec_config.state"); s == "off" || s == "" && !isUnknown(ansGet(r, "dnssec_config.state")) {
				return one("dnssec_config", "Answers for the zone can be spoofed.")
			}
			for i, e := range asList(ansGet(r, "dnssec_config.default_key_specs")) {
				if m, ok := e.(map[string]any); ok && strings.EqualFold(fmt.Sprint(m["algorithm"]), "rsasha1") {
					return one("dnssec_config.default_key_specs."+strconv.Itoa(i), "RSASHA1 signatures can be forged.")
				}
			}
			return nil
		}),
	ansRule("TG-ANS-GCP-KMS-001", Medium, "CWE-320", "KMS key rotates rarely or never",
		"Set rotation_period to 7776000s (90 days) or less.", []string{"gcp_kms_crypto_key"},
		func(r *Resource) []Hit {
			v := ansGet(r, "rotation_period")
			if isUnknown(v) {
				return nil
			}
			s, _ := v.(string)
			if d, err := strconv.ParseFloat(strings.TrimSuffix(s, "s"), 64); v == nil || err == nil && d > 7776000 {
				return one("rotation_period", "The same key material protects data for longer than 90 days.")
			}
			return nil
		}),
}

// ansibleForeign maps reference IDs (Checkov and KICS) to these rules.
var ansibleForeign = map[string][]string{
	"CKV_ANSIBLE_1": {"TG-ANS-TLS-001"}, "CKV_ANSIBLE_2": {"TG-ANS-TLS-001"}, "CKV_ANSIBLE_3": {"TG-ANS-TLS-001"},
	"CKV_ANSIBLE_4": {"TG-ANS-TLS-001"}, "CKV_ANSIBLE_5": {"TG-ANS-PKG-001"}, "CKV_ANSIBLE_6": {"TG-ANS-PKG-001"},
	"CKV2_ANSIBLE_1": {"TG-ANS-HTTP-001"}, "CKV2_ANSIBLE_2": {"TG-ANS-HTTP-001"}, "CKV2_ANSIBLE_3": {"TG-ANS-BLOCK-001"},
	"CKV2_ANSIBLE_4": {"TG-ANS-PKG-001"}, "CKV2_ANSIBLE_5": {"TG-ANS-TLS-001"}, "CKV2_ANSIBLE_6": {"TG-ANS-TLS-001"},
	"2e8d4922-8362-4606-8c14-aa10466a1ce3": {"TG-ANS-HTTP-001"},
	"59029ddf-e651-412b-ae7b-ff6d403184bc": {"TG-ANS-SECRET-001"},
	"0e75052f-cc02-41b8-ac39-a78017527e95": {"TG-ANS-BECOME-002"},
	"88841d5c-d22d-4b7e-a6a0-89ca50e44b9f": {"TG-ANS-FILE-002"},
	"c05e2c20-0a2c-4686-b1f8-5f0a5612d4e8": {"TG-ANS-PKG-002"},
	"c2f15af3-66a0-4176-a56e-e4711e502e5c": {"TG-ANS-SECRET-002"},
	"f34508b9-f574-4330-b42d-88c44cced645": {"TG-ANS-SECRET-002"},
	"b47b98ab-e481-4a82-8bb1-1ab39fd36e33": {"TG-ANS-TLS-001"},
	"3ab1f27d-52cc-4943-af1d-43c1939e739a": {"TG-ANS-S3-001"},
	"6fa44721-ef21-41c6-8665-330d59461163": {"TG-ANS-S3-001"},
	"53bce6a8-5492-4b1b-81cf-664385f0c4bf": {"TG-ANS-S3-001"},
	"d395a950-12ce-4314-a742-ac5a785ab44e": {"TG-ANS-S3-001"},
	"a0f1bfe0-741e-473f-b3b2-13e66f856fab": {"TG-ANS-S3-001"},
	"6a6d7e56-c913-4549-b5c5-5221e624d2ec": {"TG-ANS-S3-001"},
	"c3e073c1-f65e-4d18-bd67-4a8f20ad1ab9": {"TG-ANS-S3-002"},
	"a1ef9d2e-4163-40cb-bd92-04f0d602a15d": {"TG-ANS-S3-002"},
	"75480b31-f349-4b9a-861f-bce19588e674": {"TG-ANS-S3-002"},
	"594f54e7-f744-45ab-93e4-c6dbaf6cd571": {"TG-ANS-S3-003"},
	"9232306a-f839-40aa-b3ef-b352001da9a5": {"TG-ANS-S3-004"},
	"3505094c-f77c-4ba0-95da-f83db712f86c": {"TG-ANS-S3-005"},
	"ea6bc7a6-d696-4dcf-a788-17fa03c17c81": {"TG-ANS-SG-001"},
	"57ced4b9-6ba4-487b-8843-b65562b90c77": {"TG-ANS-SG-001"},
	"eda7301d-1f3e-47cf-8d4e-976debc64341": {"TG-ANS-SG-001"},
	"83c5fa4c-e098-48fc-84ee-0a537287ddd2": {"TG-ANS-SG-001"},
	"71ea648a-d31a-4b5a-a589-5674243f1c33": {"TG-ANS-SG-002"},
	"722b0f24-5a64-4cca-aa96-cfc26b7e3a5b": {"TG-ANS-SG-002"},
	"4b6012e7-7176-46e4-8108-e441785eae57": {"TG-ANS-EC2-001"},
	"66477506-6abb-49ed-803d-3fa174cd5f6a": {"TG-ANS-EC2-001"},
	"a8b0c58b-cd25-4b53-9ad0-55bca0be0bc1": {"TG-ANS-EC2-002"},
	"b9ef8c0e-1392-4df4-aa84-2e0f95681c75": {"TG-ANS-EC2-003"},
	"97707503-a22c-4cd7-b7c0-f088fa7cf830": {"TG-ANS-EC2-004"},
	"a19b2942-142e-4e2b-93b7-6cf6a6c8d90f": {"TG-ANS-EC2-005"},
	"c09e3ca5-f08a-4717-9c87-3919c5e6d209": {"TG-ANS-RDS-001"},
	"7dfb316c-a6c2-454d-b8a2-97f147b0c0ff": {"TG-ANS-RDS-002"},
	"e69890e6-fce5-461d-98ad-cb98318dfc96": {"TG-ANS-RDS-003"},
	"0ed012a4-9199-43d2-b9e4-9bd049a48aa4": {"TG-ANS-RDS-004"},
	"857f8808-e96a-4ba8-a9b7-f2d4ec6cad94": {"TG-ANS-RDS-005"},
	"5c6b727b-1382-4629-8ba9-abd1365e5610": {"TG-ANS-REDSHIFT-001"},
	"6a647814-def5-4b85-88f5-897c19f509cd": {"TG-ANS-REDSHIFT-002"},
	"727c4fd4-d604-4df6-a179-7713d3c85e20": {"TG-ANS-EFS-001"},
	"af96d737-0818-4162-8c41-40d969bd65d1": {"TG-ANS-KMS-001"},
	"5b9d237a-57d5-4177-be0e-71434b0fef47": {"TG-ANS-KMS-002"},
	"e401d614-8026-4f4b-9af9-75d1197461ba": {"TG-ANS-IAM-001"},
	"b5ed026d-a772-4f07-97f9-664ba0b116f8": {"TG-ANS-IAM-001"},
	"12a7a7ce-39d6-49dd-923d-aeb4564eb66c": {"TG-ANS-IAM-001"},
	"babdedcf-d859-43da-9a7b-6d72e661a8fd": {"TG-ANS-IAM-002"},
	"af167837-9636-4086-b815-c239186b9dda": {"TG-ANS-IAM-002"},
	"8bc2168c-1723-4eeb-a6f3-a1ba614b9a6d": {"TG-ANS-IAM-003"},
	"6f5f5444-1422-495f-81ef-24cefd61ed2c": {"TG-ANS-IAM-003"},
	"3f2cf811-88fa-4eda-be45-7a191a18aba9": {"TG-ANS-IAM-003"},
	"7f79f858-fbe8-4186-8a2c-dfd0d958a40f": {"TG-ANS-IAM-004"},
	"e71d0bc7-d9e8-4e6e-ae90-0a4206db6f40": {"TG-ANS-IAM-004"},
	"d4a73c49-cbaa-4c6f-80ee-d6ef5a3a26f5": {"TG-ANS-CT-001"},
	"6ad087d7-a509-4b20-b853-9ef6f5ebaa98": {"TG-ANS-CT-001"},
	"4d8681a2-3d30-4c89-8070-08acd142748e": {"TG-ANS-CT-002"},
	"f5587077-3f57-4370-9b4e-4eb5b1bac85b": {"TG-ANS-CT-003"},
	"a6d27cf7-61dc-4bde-ae08-3b353b609f76": {"TG-ANS-CF-001"},
	"d0c13053-d2c8-44a6-95da-d592996e9e67": {"TG-ANS-CF-002"},
	"fb8f8929-afeb-4c46-99f0-a6cf410f7df4": {"TG-ANS-CF-002"},
	"218413a0-c716-4b94-9e08-0bb70d854709": {"TG-ANS-CF-002"},
	"d31cb911-bf5b-4eb6-9fc3-16780c77c7bd": {"TG-ANS-CF-003"},
	"f81d63d2-c5d7-43a4-a5b5-66717a41c895": {"TG-ANS-ELB-001"},
	"730a5951-2760-407a-b032-dd629b55c23a": {"TG-ANS-ELB-002"},
	"2034fb37-bc23-4ca0-8d95-2b9f15829ab5": {"TG-ANS-ELB-002"},
	"d994585f-defb-4b51-b6d2-c70f020ceb10": {"TG-ANS-SQS-001"},
	"86b0efa7-4901-4edd-a37a-c034bec6645a": {"TG-ANS-SQS-001"},
	"ed9b3beb-92cf-44d9-a9d2-171eeba569d4": {"TG-ANS-SQS-001"},
	"e1e7b278-2a8b-49bd-a26e-66a7f70b17eb": {"TG-ANS-SQS-002"},
	"905f4741-f965-45c1-98db-f7a00a0e5c73": {"TG-ANS-SNS-001"},
	"fb5a5df7-6d74-4243-ab82-ff779a958bfd": {"TG-ANS-ECR-001"},
	"60bfbb8a-c72f-467f-a6dd-a46b7d612789": {"TG-ANS-ECR-002"},
	"1d972c56-8ec2-48c1-a578-887adb09c57a": {"TG-ANS-LAMBDA-001"},
	"d6c2d06f-43c1-488a-9ba1-8d75b40fc62d": {"TG-ANS-ES-001"},
	"f2ea6481-1d31-4d40-946a-520dc6321dd7": {"TG-ANS-KINESIS-001"},
	"defe5b18-978d-4722-9325-4d1975d3699f": {"TG-ANS-BATCH-001"},
	"560f256b-0b45-4496-bcb5-733681e7d38d": {"TG-ANS-ECS-001"},
	"e24e18d9-4c2b-4649-b3d0-18c088145e24": {"TG-ANS-LOGS-001"},
	"ca4df748-613a-4fbf-9c76-f02cbd580307": {"TG-ANS-AZ-ST-001"},
	"35e2f133-a395-40de-a79d-b260d973d1bd": {"TG-ANS-AZ-ST-001"},
	"2c99a474-2a3c-4c17-8294-53ffa5ed0522": {"TG-ANS-AZ-ST-002"},
	"c62746cf-92d5-4649-9acf-7d48d086f2ee": {"TG-ANS-AZ-ST-003"},
	"4d3817db-dd35-4de4-a80d-3867157e7f7f": {"TG-ANS-AZ-ST-004"},
	"f4e9ff70-0f3b-4c50-a713-26cbe7ec4039": {"TG-ANS-AZ-SQL-001"},
	"3f23c96c-f9f5-488d-9b17-605b8da5842f": {"TG-ANS-AZ-SQL-001"},
	"0d0c12b9-edce-4510-9065-13f6a758750c": {"TG-ANS-AZ-SQL-001"},
	"0632d0db-9190-450a-8bb3-c283bffea445": {"TG-ANS-AZ-SQL-001"},
	"663062e9-473d-4e87-99bc-6f3684b3df40": {"TG-ANS-AZ-SQL-002"},
	"2a901825-0f3b-4655-a0fe-e0470e50f8e6": {"TG-ANS-AZ-DB-001"},
	"961ce567-a16d-4d7d-9027-f0ec2628a555": {"TG-ANS-AZ-DB-001"},
	"7ab33ac0-e4a3-418f-a673-50da4e34df21": {"TG-ANS-AZ-DB-002"},
	"7b47138f-ec0e-47dc-8516-e7728fe3cc17": {"TG-ANS-AZ-DB-002"},
	"054d07b5-941b-4c28-8eef-18989dc62323": {"TG-ANS-AZ-DB-002"},
	"729ebb15-8060-40f7-9017-cb72676a5487": {"TG-ANS-AZ-DB-002"},
	"a9becca7-892a-4af7-b9e1-44bf20a4cd9a": {"TG-ANS-AZ-DB-002"},
	"869e7fb4-30f0-4bdb-b360-ad548f337f2f": {"TG-ANS-AZ-REDIS-001"},
	"0ac9abbc-6d7a-41cf-af23-2e57ddb3dbfc": {"TG-ANS-AZ-NSG-001"},
	"149fa56c-4404-4f90-9e25-d34b676d5b39": {"TG-ANS-AZ-AKS-001"},
	"8c3bedf1-c570-4c3b-b414-d068cd39a00c": {"TG-ANS-AZ-AKS-002"},
	"29f35127-98e6-43af-8ec1-201b79f99604": {"TG-ANS-AZ-ACR-001"},
	"881696a8-68c5-4073-85bc-7c38a3deb854": {"TG-ANS-AZ-KV-001"},
	"eb8c2560-8bee-4248-9d0d-e80c8641dd91": {"TG-ANS-AZ-WEB-001"},
	"e8c80448-31d8-4755-85fc-6dbab69c2717": {"TG-ANS-AZ-COSMOS-001"},
	"e2d834b7-8b25-4935-af53-4a60668dcbe0": {"TG-ANS-AZ-VM-001"},
	"2fc5ab5a-c5eb-4ae4-b687-0f16fe77c255": {"TG-ANS-AZ-AG-001"},
	"5c80db8e-03f5-43a2-b4af-1f3f87018157": {"TG-ANS-AZ-ROLE-001"},
	"0461b4fd-21ef-4687-929e-484ee4796785": {"TG-ANS-AZ-MON-001"},
	"37fafbea-dedb-4e0d-852e-d16ee0589326": {"TG-ANS-AZ-MON-001"},
	"086031e1-9d4a-4249-acb3-5bfe4c363db2": {"TG-ANS-GCP-GCS-001"},
	"7814ddda-e758-4a56-8be3-289a81ded929": {"TG-ANS-GCP-GCS-002"},
	"507df964-ad97-4035-ab14-94a82eabdfdd": {"TG-ANS-GCP-GCS-003"},
	"2263b286-2fe9-4747-a0ae-8b4768a2bbd2": {"TG-ANS-GCP-BQ-001"},
	"7d7054c0-3a52-4e9b-b9ff-cbfe16a2378b": {"TG-ANS-GCP-SQL-001"},
	"d0f7da39-a2d5-4c78-bb85-4b7f338b3cbb": {"TG-ANS-GCP-SQL-002"},
	"0c82eae2-aca0-401f-93e4-fb37a0f9e5e8": {"TG-ANS-GCP-SQL-003"},
	"a7b520bb-2509-4fb0-be05-bc38f54c7a4c": {"TG-ANS-GCP-SQL-004"},
	"9e0c33ed-97f3-4ed6-8be9-bcbf3f65439f": {"TG-ANS-GCP-SQL-004"},
	"6d34aff3-fdd2-460c-8190-756a3b4969e8": {"TG-ANS-GCP-SQL-004"},
	"300a9964-b086-41f7-9378-b6de3ba1c32b": {"TG-ANS-GCP-GKE-001"},
	"344bf8ab-9308-462b-a6b2-697432e40ba1": {"TG-ANS-GCP-GKE-002"},
	"9df7f78f-ebe3-432e-ac3b-b67189c15518": {"TG-ANS-GCP-GKE-002"},
	"20180133-a0d0-4745-bfe0-94049fbb12a9": {"TG-ANS-GCP-GKE-002"},
	"3b30e3d6-c99b-4318-b38f-b99db74578b5": {"TG-ANS-GCP-GKE-003"},
	"d43366c5-80b0-45de-bbe8-2338f4ab0a83": {"TG-ANS-GCP-GKE-003"},
	"98e04ca0-34f5-4c74-8fec-d2e611ce2790": {"TG-ANS-GCP-GKE-004"},
	"19c9e2a0-fc33-4264-bba1-e3682661e8f7": {"TG-ANS-GCP-GKE-005"},
	"20dcd953-a8b8-4892-9026-9afa6d05a525": {"TG-ANS-GCP-GKE-005"},
	"d58c6f24-3763-4269-9f5b-86b2569a003b": {"TG-ANS-GCP-GKE-006"},
	"d6e10477-2e19-4bcd-b8a8-19c65b89ccdf": {"TG-ANS-GCP-GKE-006"},
	"829f1c60-2bab-44c6-8a21-5cd9d39a2c82": {"TG-ANS-GCP-VM-001"},
	"c6fc6f29-dc04-46b6-99ba-683c01aff350": {"TG-ANS-GCP-VM-002"},
	"099b4411-d11e-4537-a0fc-146b19762a79": {"TG-ANS-GCP-VM-002"},
	"66dae697-507b-4aef-be18-eec5bd707f33": {"TG-ANS-GCP-VM-002"},
	"11bd3554-cd56-4257-8e25-7aaf30cf8f5f": {"TG-ANS-GCP-VM-003"},
	"bc20bbc6-0697-4568-9a73-85af1dd97bdd": {"TG-ANS-GCP-VM-004"},
	"18d3a83d-4414-49dc-90ea-f0387b2856cc": {"TG-ANS-GCP-VM-005"},
	"b2fbf1df-76dd-4d78-a6c0-e538f4a9b016": {"TG-ANS-GCP-FW-001"},
	"75418eb9-39ec-465f-913c-6f2b6a80dc77": {"TG-ANS-GCP-FW-001"},
	"3602d273-3290-47b2-80fa-720162b1a8af": {"TG-ANS-GCP-FW-001"},
	"80b15fb1-6207-40f4-a803-6915ae619a03": {"TG-ANS-GCP-DNS-001"},
	"6cf4c3a7-ceb0-4475-8892-3745b84be24a": {"TG-ANS-GCP-DNS-001"},
	"f9b7086b-deb8-4034-9330-d7fd38f1b8de": {"TG-ANS-GCP-KMS-001"},
}
