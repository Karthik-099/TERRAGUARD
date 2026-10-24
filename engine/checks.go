package engine

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ModuleRules documents checks that need the whole module (cross-file or
// cross-resource) rather than a single resource. Their logic lives below.
var ModuleRules = []Rule{
	{ID: "TG-VAL-001", Title: "HCL syntax error", Severity: High, Category: CatValidate, Blocking: true, Remediation: "Fix the syntax error; terraform cannot parse this file."},
	{ID: "TG-VAL-002", Title: "Duplicate declaration (validate will fail)", Severity: High, Category: CatValidate, Blocking: true, Remediation: "Each resource, data source, variable, output, module and local must have a unique name."},
	{ID: "TG-VAL-003", Title: "Reference to undeclared object (validate will fail)", Severity: High, Category: CatValidate, Blocking: true, Remediation: "Declare the referenced object, fix the typo, or include the file that declares it in the scan."},
	{ID: "TG-VAL-008", Title: "Required variable has no value", Severity: Medium, Category: CatValidate, Remediation: "Add it to a .tfvars file, give it a default, or export TF_VAR_<name>; CI runs with -input=false fail otherwise."},
	{ID: "TG-VAL-009", Title: "tfvars sets an undeclared variable", Severity: Low, Category: CatValidate, Remediation: "Remove the value or declare the variable; terraform warns and the value is silently ignored."},
	{ID: "TG-VAL-010", Title: "Unused variable", Severity: Info, Category: CatBestPrac, Remediation: "Delete it to keep the module interface honest."},
	{ID: "TG-SEC-001", Title: "Hardcoded secret in configuration", Severity: High, Category: CatSecurity, CWE: "CWE-798", Remediation: "Read it from a sensitive variable, AWS Secrets Manager / SSM data source, or use manage_master_user_password for RDS. Rotate the leaked value — it is in git history."},
	{ID: "TG-SEC-002", Title: "Credential pattern found in file", Severity: Critical, Category: CatSecurity, CWE: "CWE-798", Remediation: "Revoke the credential immediately, remove it from git history, and use OIDC / a secrets manager instead."},
	{ID: "TG-SEC-003", Title: "Secret variable not marked sensitive", Severity: Medium, Category: CatSecurity, CWE: "CWE-532", Remediation: "Set sensitive = true so the value is redacted from plan output and CI logs."},
	{ID: "TG-TF-001", Title: "Provider version is not pinned", Severity: Low, Category: CatBestPrac, Remediation: `Declare it in terraform { required_providers { aws = { source = "hashicorp/aws", version = "~> 5.0" } } } and commit .terraform.lock.hcl.`},
	{ID: "TG-TF-002", Title: "Module source is not pinned", Severity: Medium, Category: CatSecurity, CWE: "CWE-829", Remediation: `Pin registry modules with version = "x.y.z" and git sources with ?ref=<tag or commit SHA>.`},
	{ID: "TG-TF-003", Title: "Terraform version is not constrained", Severity: Info, Category: CatBestPrac, Remediation: `Add terraform { required_version = ">= 1.6, < 2.0" } so everyone (and CI) runs a compatible binary.`},
	{ID: "TG-STATE-001", Title: "Remote state is unencrypted or unlocked", Severity: Medium, Category: CatReliability, CWE: "CWE-362", Remediation: `For the s3 backend set encrypt = true and use_lockfile = true (Terraform 1.10+) or dynamodb_table; concurrent applies without a lock corrupt state.`},
	{ID: "TG-STATE-002", Title: "Terraform state file is in the repository", Severity: Critical, Category: CatSecurity, CWE: "CWE-312", Remediation: "State contains every secret in plaintext. Delete it from git history, rotate secrets, move to a remote backend, and add *.tfstate* to .gitignore."},
	{ID: "TG-STATE-003", Title: "No remote backend configured", Severity: Info, Category: CatReliability, Remediation: "Configure a remote backend (s3, gcs, azurerm, remote/cloud) so state isn't tied to one laptop."},
	{ID: "TG-AWS-VPC-001", Title: "VPC has no flow logs", Severity: Low, Category: CatSecurity, CWE: "CWE-778", Remediation: "Add an aws_flow_log for the VPC so incidents can be investigated."},
	{ID: "TG-DO-DB-001", Title: "DigitalOcean database has no trusted sources", Severity: Medium, Category: CatSecurity, CWE: "CWE-284", Remediation: "Add a digitalocean_database_firewall restricting access to your droplets, tags or app."},
	{ID: "TG-HZ-SRV-001", Title: "Hetzner server has no firewall", Severity: Medium, Category: CatSecurity, CWE: "CWE-284", Remediation: "Attach an hcloud_firewall via firewall_ids or hcloud_firewall_attachment; servers are fully exposed by default."},
	{ID: "TG-DNS-003", Title: "Public DNS zone without DNSSEC", Severity: Low, Category: CatSecurity, CWE: "CWE-350", Remediation: "Add aws_route53_hosted_zone_dnssec (Route 53) or cloudflare_zone_dnssec (Cloudflare) for public zones."},
	{ID: "TG-AWS-S3-003", Title: "S3 bucket has no versioning", Severity: Low, Category: CatReliability, Remediation: "Add an aws_s3_bucket_versioning resource with status = \"Enabled\" to recover from deletes/overwrites."},
	{ID: "TG-PATH-001", Title: "Attack path: database reachable from the internet", Severity: Critical, Category: CatAttackPath, CWE: "CWE-284", Remediation: "Set publicly_accessible = false and restrict the security group to the application tier."},
	{ID: "TG-PATH-002", Title: "Attack path: public endpoint runs with admin privileges", Severity: Critical, Category: CatAttackPath, CWE: "CWE-269", Remediation: "Scope the execution role to least privilege; one bug in the public code path currently means full account takeover."},
	{ID: "TG-PATH-003", Title: "Attack path: internet-exposed instance with admin role", Severity: Critical, Category: CatAttackPath, CWE: "CWE-269", Remediation: "Close the security group, enforce IMDSv2, and scope the instance role."},
	{ID: "TG-PLAN-001", Title: "Plan destroys a resource", Severity: High, Category: CatPlan, Remediation: "Confirm the destroy is intended; protect stateful resources with lifecycle { prevent_destroy = true }."},
	{ID: "TG-PLAN-002", Title: "Plan replaces a resource", Severity: Medium, Category: CatPlan, Remediation: "Check the attribute forcing replacement; for stateful resources use create_before_destroy, a moved block, or revert the change."},
	{ID: "TG-POL-001", Title: "Waiver has expired", Severity: Medium, Category: CatPolicy, Remediation: "Fix the finding or renew the waiver with a new expiry and approver."},
}

var (
	secretAttrRE = regexp.MustCompile(`(?i)(^|_)(password|passwd|secret|secret_string|token|api_key|apikey|access_key|secret_key|private_key|client_secret)$`)
	secretVarRE  = regexp.MustCompile(`(?i)(password|passwd|secret|token|api_key|apikey|private_key|access_key)`)
	credPatterns = []struct {
		re   *regexp.Regexp
		name string
	}{
		{regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`), "AWS access key ID"},
		{regexp.MustCompile(`-----BEGIN ([A-Z]+ )?PRIVATE KEY-----`), "private key"},
		{regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36}\b`), "GitHub token"},
		{regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}`), "Slack token"},
		{regexp.MustCompile(`\bgsk_[A-Za-z0-9]{40,}`), "Groq API key"},
		{regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), "Google API key"},
		{regexp.MustCompile(`\bsk-or-v1-[a-f0-9]{40,}`), "OpenRouter API key"},
	}
	moduleRegistryRE = regexp.MustCompile(`^[A-Za-z0-9-]+/[A-Za-z0-9_-]+/[A-Za-z0-9]+(//.*)?$`)
)

var ruleIndex = func() map[string]*Rule {
	m := map[string]*Rule{}
	for i := range Rules {
		m[Rules[i].ID] = &Rules[i]
	}
	for i := range ModuleRules {
		m[ModuleRules[i].ID] = &ModuleRules[i]
	}
	return m
}()

// newFinding fills rule metadata; sev overrides the rule default when non-empty.
func newFinding(id string, sev Severity, msg, resource, file string, line int) Finding {
	r := ruleIndex[id]
	if sev == "" {
		sev = r.Severity
	}
	return Finding{RuleID: id, Severity: sev, Category: r.Category, Title: r.Title, Message: msg,
		Resource: resource, File: file, Line: line, Remediation: r.Remediation, CWE: r.CWE, Blocking: r.Blocking}
}

func moduleChecks(m *Module) []Finding {
	var out []Finding
	out = append(out, m.Syntax...)
	out = append(out, declarationChecks(m)...)
	out = append(out, secretChecks(m)...)
	out = append(out, pinningChecks(m)...)
	out = append(out, graphChecks(m)...)
	out = append(out, stateChecks(m)...)
	return out
}

func stateChecks(m *Module) []Finding {
	var out []Finding
	for _, f := range m.State {
		out = append(out, newFinding("TG-STATE-002", "", f+" is part of the scanned files. Anyone with repo access can read every secret it holds.", "", f, 0))
	}
	hasBackend := false
	for _, b := range m.Blocks {
		if b.Kind != "terraform" {
			continue
		}
		for _, nb := range b.body.Blocks {
			if nb.Type != "backend" && nb.Type != "cloud" {
				continue
			}
			hasBackend = true
			if nb.Type != "backend" || len(nb.Labels) == 0 || nb.Labels[0] != "s3" {
				continue
			}
			attrs := walkBody(nb.Body, m.Files[b.File], "", map[string]int{}, new([]Ref), nil)
			line := nb.DefRange().Start.Line
			if !is(attrs["encrypt"], true) {
				out = append(out, newFinding("TG-STATE-001", "", "S3 backend without encrypt = true stores state (and its secrets) unencrypted.", "backend.s3", b.File, line))
			}
			if attrs["dynamodb_table"] == nil && !is(attrs["use_lockfile"], true) {
				out = append(out, newFinding("TG-STATE-001", "", "S3 backend has no state locking; two concurrent applies can corrupt state.", "backend.s3", b.File, line))
			}
		}
	}
	versioned := false
	for _, b := range m.Blocks {
		if b.Kind == "terraform" && b.Attrs["required_version"] != nil {
			versioned = true
		}
	}
	for _, b := range m.Blocks {
		if b.Kind == "terraform" && !versioned {
			out = append(out, newFinding("TG-TF-003", "", "No required_version: a newer or older Terraform binary may plan differently or fail.", "terraform", b.File, b.Line))
			break
		}
	}
	if !hasBackend && len(m.Resources) > 0 {
		r := m.Resources[0]
		out = append(out, newFinding("TG-STATE-003", "", "State will be written to a local terraform.tfstate file.", "", r.File, 0))
	}
	return out
}

func declarationChecks(m *Module) []Finding {
	var out []Finding
	declared := map[string]bool{}
	firstSeen := map[string]string{}
	for _, b := range m.Blocks {
		switch b.Kind {
		case "resource", "data", "variable", "module", "output":
			if b.Kind != "output" && b.Kind != "variable" && b.Kind != "module" && len(b.Labels) != 2 {
				continue
			}
			if len(b.Labels) == 0 {
				continue
			}
			addr := b.Address()
			if prev, dup := firstSeen[addr]; dup {
				out = append(out, newFinding("TG-VAL-002", "", fmt.Sprintf("%s is declared more than once (first in %s).", addr, prev), addr, b.File, b.Line))
			}
			firstSeen[addr] = fmt.Sprintf("%s:%d", b.File, b.Line)
			declared[addr] = true
		}
	}
	for n := range m.Locals {
		declared["local."+n] = true
	}

	used := map[string]bool{}
	reported := map[string]bool{}
	for _, b := range m.Blocks {
		for _, ref := range b.Refs {
			used[ref.Addr] = true
			root, _, _ := strings.Cut(ref.Addr, ".")
			checkable := root == "var" || root == "local" || root == "module" || root == "data" || strings.Contains(root, "_")
			if !checkable || declared[ref.Addr] || reported[ref.Addr+b.File] {
				continue
			}
			reported[ref.Addr+b.File] = true
			out = append(out, newFinding("TG-VAL-003", "", fmt.Sprintf("Reference to %s, which is not declared in the scanned files.", ref.Addr), b.Address(), b.File, ref.Line))
		}
	}

	tfvarsSet := map[string]bool{}
	for file, vars := range m.Tfvars {
		for name, line := range vars {
			tfvarsSet[name] = true
			if !declared["var."+name] {
				out = append(out, newFinding("TG-VAL-009", "", fmt.Sprintf("%s sets %q but no variable with that name is declared.", file, name), "var."+name, file, line))
			}
		}
	}
	for _, b := range m.Blocks {
		if b.Kind != "variable" || len(b.Labels) != 1 {
			continue
		}
		name := b.Labels[0]
		_, hasDefault := b.Attrs["default"]
		if len(m.Tfvars) > 0 && !hasDefault && !tfvarsSet[name] {
			out = append(out, newFinding("TG-VAL-008", "", fmt.Sprintf("Variable %q has no default and is not set in any .tfvars file.", name), b.Address(), b.File, b.Line))
		}
		if !used["var."+name] {
			out = append(out, newFinding("TG-VAL-010", "", fmt.Sprintf("Variable %q is declared but never referenced.", name), b.Address(), b.File, b.Line))
		}
		if secretVarRE.MatchString(name) {
			if !is(b.Attrs["sensitive"], true) {
				f := newFinding("TG-SEC-003", "", fmt.Sprintf("Variable %q looks like a secret but will be printed in plan output.", name), b.Address(), b.File, b.Line)
				f.Fix = &Fix{File: b.File, Block: b.fixAddr(), Path: []string{"sensitive"}, Value: true, Description: "Set sensitive = true"}
				out = append(out, f)
			}
			if s, ok := asString(b.Attrs["default"]); ok && s != "" {
				out = append(out, newFinding("TG-SEC-001", "", fmt.Sprintf("Variable %q has a hardcoded default secret.", name), b.Address(), b.File, b.Lines["default"]))
			}
		}
	}
	return out
}

func secretChecks(m *Module) []Finding {
	var out []Finding
	for _, b := range m.Blocks {
		if b.Kind != "resource" && b.Kind != "provider" && b.Kind != "module" && b.Kind != "data" {
			continue
		}
		var walk func(prefix string, v map[string]any)
		walk = func(prefix string, v map[string]any) {
			for k, e := range v {
				p := prefix + k
				switch t := e.(type) {
				case string:
					if t != "" && secretAttrRE.MatchString(k) && !strings.HasPrefix(t, "arn:") {
						out = append(out, newFinding("TG-SEC-001", "", fmt.Sprintf("%q is set to a literal value in %s.", k, b.Address()), b.Address(), b.File, b.Lines[p]))
					}
				case []any:
					for i, c := range t {
						if cm, ok := c.(map[string]any); ok {
							walk(fmt.Sprintf("%s.%d.", p, i), cm)
						}
					}
				case map[string]any: // e.g. kubernetes_secret data = { password = "..." }
					walk(p+".", t)
				}
			}
		}
		walk("", b.Attrs)
	}
	names := make([]string, 0, len(m.Files))
	for n := range m.Files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		for i, line := range strings.Split(string(m.Files[name]), "\n") {
			for _, p := range credPatterns {
				if p.re.MatchString(line) {
					out = append(out, newFinding("TG-SEC-002", "", fmt.Sprintf("Looks like a %s is committed in %s.", p.name, name), "", name, i+1))
				}
			}
		}
	}
	return out
}

func pinningChecks(m *Module) []Finding {
	var out []Finding
	pinned := map[string]bool{}
	tfLine, tfFile := 0, ""
	for _, b := range m.Blocks {
		if b.Kind != "terraform" {
			continue
		}
		tfLine, tfFile = b.Line, b.File
		for _, rp := range b.blocksAttr("required_providers") {
			for name, v := range rp {
				if pm, ok := v.(map[string]any); ok && pm["version"] != nil {
					pinned[name] = true
				}
			}
		}
	}
	firstUse := map[string]*Block{}
	var order []string
	for _, b := range m.Blocks {
		var p string
		switch {
		case (b.Kind == "resource" || b.Kind == "data") && len(b.Labels) == 2:
			p, _, _ = strings.Cut(b.Labels[0], "_")
		case b.Kind == "provider" && len(b.Labels) == 1:
			p = b.Labels[0]
		}
		if p == "" || p == "terraform" || firstUse[p] != nil {
			continue
		}
		firstUse[p] = b
		order = append(order, p)
	}
	for _, p := range order {
		if pinned[p] {
			continue
		}
		file, line := firstUse[p].File, firstUse[p].Line
		if tfFile != "" {
			file, line = tfFile, tfLine
		}
		out = append(out, newFinding("TG-TF-001", "", fmt.Sprintf("Provider %q has no version constraint; the next major release can break plans without any code change.", p), "provider."+p, file, line))
	}

	for _, b := range m.Blocks {
		if b.Kind != "module" || len(b.Labels) != 1 {
			continue
		}
		src, ok := asString(b.Attrs["source"])
		if !ok || strings.HasPrefix(src, "./") || strings.HasPrefix(src, "../") {
			continue
		}
		isGit := strings.HasPrefix(src, "git::") || strings.HasPrefix(src, "github.com/") || strings.HasPrefix(src, "bitbucket.org/") || strings.Contains(src, ".git")
		switch {
		case isGit && !strings.Contains(src, "ref="):
			out = append(out, newFinding("TG-TF-002", "", fmt.Sprintf("Module %q tracks the default branch of %s; any upstream push changes your infrastructure.", b.Labels[0], src), b.Address(), b.File, b.Lines["source"]))
		case moduleRegistryRE.MatchString(src) && b.Attrs["version"] == nil:
			out = append(out, newFinding("TG-TF-002", "", fmt.Sprintf("Registry module %q has no version constraint.", src), b.Address(), b.File, b.Lines["source"]))
		}
	}
	return out
}

func (b *Block) blocksAttr(name string) []map[string]any {
	r := Resource{Attrs: b.Attrs}
	return r.blocks(name)
}

func refsTo(r *Resource, set map[string]bool) []string {
	var hit []string
	for _, ref := range r.Refs {
		if set[ref] {
			hit = append(hit, ref)
		}
	}
	return hit
}

// graphChecks find risks that only exist in combination: each resource may
// look acceptable alone, but the reference graph forms an attack path.
func graphChecks(m *Module) []Finding {
	var out []Finding
	byType := map[string][]*Resource{}
	for _, r := range m.Resources {
		byType[r.Type] = append(byType[r.Type], r)
	}
	admin := map[string]bool{} // admin policies and docs, then admin roles
	for _, t := range []string{"aws_iam_policy_document", "aws_iam_policy"} {
		for _, r := range byType[t] {
			if IsAdminPolicy(r) || len(refsTo(r, admin)) > 0 {
				admin[r.Address] = true
			}
		}
	}
	adminRoles := map[string]bool{}
	for _, t := range []string{"aws_iam_role_policy", "aws_iam_role_policy_attachment", "aws_iam_policy_attachment"} {
		for _, r := range byType[t] {
			arn, _ := asString(r.get("policy_arn"))
			if IsAdminPolicy(r) || len(refsTo(r, admin)) > 0 || strings.HasSuffix(arn, "/AdministratorAccess") {
				for _, ref := range r.Refs {
					if strings.HasPrefix(ref, "aws_iam_role.") {
						adminRoles[ref] = true
					}
				}
			}
		}
	}
	for _, r := range byType["aws_iam_role"] {
		for _, ip := range r.blocks("inline_policy") {
			for _, h := range wildcardHits(statements(ip["policy"]), "") {
				if h.Sev == Critical {
					adminRoles[r.Address] = true
				}
			}
		}
	}

	openSG := map[string]bool{}
	for _, r := range byType["aws_security_group"] {
		for _, in := range r.blocks("ingress") {
			if anyWorld(in["cidr_blocks"], in["ipv6_cidr_blocks"]) {
				openSG[r.Address] = true
			}
		}
	}
	for _, t := range []string{"aws_security_group_rule", "aws_vpc_security_group_ingress_rule"} {
		for _, r := range byType[t] {
			typ, _ := asString(r.get("type"))
			if (t == "aws_vpc_security_group_ingress_rule" || typ == "ingress") && anyWorld(r.get("cidr_blocks"), r.get("cidr_ipv4"), r.get("cidr_ipv6")) {
				for _, ref := range r.Refs {
					if strings.HasPrefix(ref, "aws_security_group.") {
						openSG[ref] = true
					}
				}
			}
		}
	}

	for _, t := range []string{"aws_db_instance", "aws_rds_cluster"} {
		for _, r := range byType[t] {
			if sgs := refsTo(r, openSG); len(sgs) > 0 && is(r.get("publicly_accessible"), true) {
				f := newFinding("TG-PATH-001", "", fmt.Sprintf("%s is publicly accessible and its security group %s accepts traffic from 0.0.0.0/0. Anyone can attempt to log in to the database.", r.Address, strings.Join(sgs, ", ")), r.Address, r.File, r.Line)
				f.Related = append([]string{r.Address}, sgs...)
				out = append(out, f)
			}
		}
	}

	publicLambda := map[string]string{}
	for _, r := range byType["aws_lambda_function_url"] {
		if s, _ := asString(r.get("authorization_type")); s == "NONE" {
			for _, ref := range r.Refs {
				publicLambda[ref] = r.Address
			}
		}
	}
	for _, t := range []string{"aws_lambda_permission", "aws_api_gateway_integration", "aws_apigatewayv2_integration"} {
		for _, r := range byType[t] {
			if p, _ := asString(r.get("principal")); t == "aws_lambda_permission" && p != "apigateway.amazonaws.com" && p != "*" {
				continue
			}
			for _, ref := range r.Refs {
				publicLambda[ref] = r.Address
			}
		}
	}
	for _, r := range byType["aws_lambda_function"] {
		entry, public := publicLambda[r.Address]
		roles := refsTo(r, adminRoles)
		if public && len(roles) > 0 {
			f := newFinding("TG-PATH-002", "", fmt.Sprintf("%s is invoked publicly via %s and runs as %s, which has administrator permissions.", r.Address, entry, roles[0]), r.Address, r.File, r.Line)
			f.Related = []string{entry, r.Address, roles[0]}
			out = append(out, f)
		}
	}

	profiles := map[string]string{}
	for _, r := range byType["aws_iam_instance_profile"] {
		if roles := refsTo(r, adminRoles); len(roles) > 0 {
			profiles[r.Address] = roles[0]
		}
	}
	for _, r := range byType["aws_instance"] {
		sgs := refsTo(r, openSG)
		for _, ref := range r.Refs {
			if role, ok := profiles[ref]; ok && len(sgs) > 0 {
				f := newFinding("TG-PATH-003", "", fmt.Sprintf("%s is reachable through %s and carries %s (admin). An RCE or SSRF on the box becomes full AWS account takeover.", r.Address, sgs[0], role), r.Address, r.File, r.Line)
				f.Related = []string{sgs[0], r.Address, ref, role}
				out = append(out, f)
			}
		}
	}

	referenced := func(srcTypes []string) map[string]bool {
		set := map[string]bool{}
		for _, t := range srcTypes {
			for _, r := range byType[t] {
				for _, ref := range r.Refs {
					set[ref] = true
				}
			}
		}
		return set
	}
	flowLogged := referenced([]string{"aws_flow_log"})
	for _, r := range byType["aws_vpc"] {
		if !flowLogged[r.Address] {
			out = append(out, newFinding("TG-AWS-VPC-001", "", r.Address+" has no aws_flow_log; network activity is not recorded.", r.Address, r.File, r.Line))
		}
	}
	doFirewalled := referenced([]string{"digitalocean_database_firewall"})
	for _, r := range byType["digitalocean_database_cluster"] {
		if !doFirewalled[r.Address] {
			out = append(out, newFinding("TG-DO-DB-001", "", r.Address+" accepts connections from any IP that has the credentials.", r.Address, r.File, r.Line))
		}
	}
	dnssec := referenced([]string{"aws_route53_hosted_zone_dnssec", "cloudflare_zone_dnssec"})
	for _, t := range []string{"aws_route53_zone", "cloudflare_zone"} {
		for _, r := range byType[t] {
			if !dnssec[r.Address] && r.Attrs["vpc"] == nil { // private Route 53 zones have vpc blocks
				out = append(out, newFinding("TG-DNS-003", "", r.Address+" is served without DNSSEC; resolvers can't detect spoofed answers.", r.Address, r.File, r.Line))
			}
		}
	}
	hzAttached := referenced([]string{"hcloud_firewall_attachment"})
	for _, r := range byType["hcloud_server"] {
		if r.Attrs["firewall_ids"] == nil && !hzAttached[r.Address] {
			out = append(out, newFinding("TG-HZ-SRV-001", "", r.Address+" has no firewall; every listening port is public.", r.Address, r.File, r.Line))
		}
	}

	versioned := map[string]bool{}
	for _, r := range byType["aws_s3_bucket_versioning"] {
		for _, ref := range r.Refs {
			versioned[ref] = true
		}
	}
	for _, r := range byType["aws_s3_bucket"] {
		if !versioned[r.Address] && !is(r.get("versioning.enabled"), true) {
			out = append(out, newFinding("TG-AWS-S3-003", "", fmt.Sprintf("%s has no versioning; deleted or overwritten objects are unrecoverable.", r.Address), r.Address, r.File, r.Line))
		}
	}
	return out
}
