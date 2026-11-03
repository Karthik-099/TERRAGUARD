package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func load(t *testing.T, dir string) Input {
	t.Helper()
	in := Input{Files: map[string]string{}}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		switch {
		case e.Name() == ".terraguard.yml":
			in.Config = string(b)
		case strings.HasSuffix(e.Name(), ".tf") || strings.HasSuffix(e.Name(), ".tfvars"):
			in.Files[e.Name()] = string(b)
		}
	}
	return in
}

func ids(r *Report) map[string]int {
	m := map[string]int{}
	for _, f := range r.Findings {
		if !f.Waived {
			m[f.RuleID]++
		}
	}
	return m
}

func TestInsecureExample(t *testing.T) {
	r := Scan(load(t, "../examples/insecure"))
	got := ids(r)
	for _, id := range []string{
		"TG-VAL-003", "TG-VAL-004", "TG-VAL-005", "TG-VAL-008", "TG-VAL-009", "TG-VAL-010",
		"TG-AWS-S3-001", "TG-AWS-S3-002", "TG-AWS-SG-001", "TG-AWS-RDS-001", "TG-AWS-RDS-002", "TG-AWS-RDS-003",
		"TG-AWS-IAM-001", "TG-AWS-LAMBDA-001", "TG-AWS-EC2-001", "TG-AWS-EBS-001", "TG-AWS-KMS-001", "TG-AWS-CT-001",
		"TG-CF-001", "TG-SEC-001", "TG-SEC-003", "TG-TF-001", "TG-TF-002", "TG-TF-010",
		"TG-PATH-001", "TG-PATH-002", "TG-POL-001", "ORG-TAG-001",
	} {
		if got[id] == 0 {
			t.Errorf("expected %s", id)
		}
	}
	if r.Passed || r.Verdict.WillApply || r.Verdict.Blocking != 3 {
		t.Errorf("verdict = %+v passed=%v", r.Verdict, r.Passed)
	}
	if r.Waived != 1 {
		t.Errorf("waived = %d, want 1 (S3-003 waiver)", r.Waived)
	}
	// EC2-001 is overridden to HIGH by .terraguard.yml
	for _, f := range r.Findings {
		if f.RuleID == "TG-AWS-EC2-001" && f.Severity != High {
			t.Errorf("severity override not applied: %s", f.Severity)
		}
	}
}

var ruleNumRE = regexp.MustCompile(`-(\d{3})$`)

func TestSecureExampleIsClean(t *testing.T) {
	r := Scan(load(t, "../examples/secure"))
	for _, f := range r.Findings {
		// Rules numbered 101 and up cover Checkov's catalogue and include
		// hardening advice, so they may raise LOW on a secure setup.
		limit := Info
		if m := ruleNumRE.FindStringSubmatch(f.RuleID); m != nil && m[1] >= "101" {
			limit = Low
		}
		if f.Severity.Rank() > limit.Rank() {
			t.Errorf("unexpected finding %s %s:%d %s", f.RuleID, f.File, f.Line, f.Message)
		}
	}
	if !r.Passed || r.Grade != "A" {
		t.Errorf("passed=%v grade=%s", r.Passed, r.Grade)
	}
}

func TestFixAllRemovesFixableFindings(t *testing.T) {
	in := load(t, "../examples/insecure")
	changed, errs := FixAll(in)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	for k, v := range changed {
		in.Files[k] = v
	}
	if r := Scan(in); r.Fixable != 0 {
		t.Errorf("fixable after fix = %d", r.Fixable)
	}
	if !strings.Contains(in.Files["main.tf"], "# Intentionally vulnerable") {
		t.Error("fix dropped comments")
	}
}

func TestPlanAnalysis(t *testing.T) {
	plan, _ := os.ReadFile("../examples/plan.json")
	r := Scan(Input{Plan: string(plan)})
	if r.Plan == nil || r.Plan.Replace != 1 || r.Plan.Delete != 1 || r.Plan.Create != 2 || r.Plan.Update != 1 {
		t.Fatalf("plan summary = %+v errors=%v", r.Plan, r.Errors)
	}
	got := ids(r)
	for _, id := range []string{"TG-PLAN-001", "TG-PLAN-002", "TG-AWS-SG-001", "TG-AWS-IAM-001", "TG-AWS-RDS-001", "TG-AWS-EC2-001"} {
		if got[id] == 0 {
			t.Errorf("expected %s from plan", id)
		}
	}
	if r := Scan(Input{Plan: `{"x":1}`}); len(r.Errors) == 0 {
		t.Error("non-plan JSON should report an error")
	}
}

func TestInlineIgnoreAndSyntaxError(t *testing.T) {
	r := Scan(Input{Files: map[string]string{"a.tf": `
# terraguard:ignore TG-AWS-RDS-001
resource "aws_db_instance" "x" {
  publicly_accessible = true # terraguard:ignore TG-AWS-RDS-002
}
`, "b.tf": `resource "aws_s3_bucket" "b" {`}})
	got := ids(r)
	if got["TG-AWS-RDS-001"] != 0 {
		t.Error("block-level ignore not honoured")
	}
	if got["TG-VAL-001"] != 1 || r.Verdict.WillApply {
		t.Errorf("syntax error not blocking: %v", got)
	}
}

func TestReferencesInsideDynamicAndFor(t *testing.T) {
	r := Scan(Input{Files: map[string]string{"main.tf": `
variable "ports" { default = [80, 443] }
locals { names = [for p in var.ports : "p-${p}"] }
resource "aws_security_group" "s" {
  name = local.names[0]
  dynamic "ingress" {
    for_each = var.ports
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
}
`}})
	if n := ids(r)["TG-VAL-003"]; n != 0 {
		t.Errorf("false undeclared-reference findings: %v", r.Findings)
	}
}

func TestCustomRuleOperators(t *testing.T) {
	cfg := `
custom_rules:
  - {id: C1, attribute: instance_type, resource_types: [aws_instance], not_in: [x1.32xlarge]}
  - {id: C2, attribute: tags.env, resource_types: ["aws_*"], in: [dev, prod]}
  - {id: C3, attribute: ami, resource_types: [aws_instance], matches: "^ami-"}
`
	r := Scan(Input{Config: cfg, Files: map[string]string{"m.tf": `
resource "aws_instance" "a" {
  instance_type = "x1.32xlarge"
  ami           = "img-1"
  tags          = { env = "staging" }
}
resource "aws_instance" "b" {
  instance_type = var.t
  ami           = "ami-1"
  tags          = { env = "prod" }
}
`}})
	got := ids(r)
	if got["C1"] != 1 || got["C2"] != 1 || got["C3"] != 1 {
		t.Errorf("custom rules = %v", got)
	}
}

func TestJUnit(t *testing.T) {
	b, err := JUnit(Scan(load(t, "../examples/insecure")))
	if err != nil || !strings.Contains(string(b), `<testsuite name="terraguard"`) || !strings.Contains(string(b), `type="CRITICAL"`) {
		t.Fatalf("%v\n%s", err, b)
	}
	clean, _ := JUnit(Scan(Input{Files: map[string]string{"a.tf": ""}}))
	if !strings.Contains(string(clean), `failures="0"`) {
		t.Fatalf("clean run must have no failures: %s", clean)
	}
}

// BenchmarkScan measures a full scan of the 12-resource demo project.
func BenchmarkScan(b *testing.B) {
	in := Input{Files: map[string]string{}}
	for _, n := range []string{"main.tf", "variables.tf", "terraform.tfvars"} {
		src, _ := os.ReadFile("../examples/insecure/" + n)
		in.Files[n] = string(src)
	}
	for i := 0; i < b.N; i++ {
		Scan(in)
	}
}

func TestCodeQuality(t *testing.T) {
	b, err := CodeQuality(Scan(load(t, "../examples/insecure")))
	if err != nil || !strings.Contains(string(b), `"severity": "blocker"`) || !strings.Contains(string(b), `"fingerprint"`) {
		t.Fatalf("%v %s", err, b[:200])
	}
}

func TestSARIF(t *testing.T) {
	b, err := SARIF(Scan(load(t, "../examples/insecure")))
	if err != nil || !strings.Contains(string(b), `"version": "2.1.0"`) {
		t.Fatal(err)
	}
}

func TestFailOnOverride(t *testing.T) {
	in := load(t, "../examples/insecure")
	in.FailOn = "NONE"
	r := Scan(in)
	if len(r.Errors) > 0 || r.Waived != 1 {
		t.Fatalf("policy must still load: errors=%v waived=%d", r.Errors, r.Waived)
	}
	if r.Passed { // blocking validation errors fail regardless of threshold
		t.Error("blocking findings must fail even with fail_on NONE")
	}
}

func TestVerifyAcceptsOnlyRealImprovements(t *testing.T) {
	base := map[string]string{"main.tf": `resource "aws_db_instance" "x" {
  publicly_accessible = true
  storage_encrypted   = true
  deletion_protection = true
}`}
	before := Scan(Input{Files: base})
	cases := []struct {
		name, src string
		ok        bool
	}{
		{"fixes the finding", strings.Replace(base["main.tf"], "= true\n  storage", "= false\n  storage", 1), true},
		{"no change", base["main.tf"], false},
		{"breaks syntax", base["main.tf"] + "\nresource \"aws_s3_bucket\" {", false},
		{"trades one issue for another", strings.Replace(base["main.tf"], "publicly_accessible = true\n  storage_encrypted   = true", "publicly_accessible = false\n  storage_encrypted   = false", 1), false},
	}
	for _, c := range cases {
		ok, why := Verify(before, Scan(Input{Files: map[string]string{"main.tf": c.src}}))
		if ok != c.ok {
			t.Errorf("%s: got %v (%s)", c.name, ok, why)
		}
	}
}

func TestReviewJudgesOnlyTheChange(t *testing.T) {
	base := Scan(Input{Files: map[string]string{"main.tf": `resource "aws_db_instance" "db" {
  publicly_accessible = true
  storage_encrypted   = true
  deletion_protection = true
}
resource "aws_kms_key" "k" {
}`}})
	head := Scan(Input{Files: map[string]string{"main.tf": `resource "aws_db_instance" "db" {
  publicly_accessible = false
  storage_encrypted   = true
  deletion_protection = true
}
resource "aws_kms_key" "k" {
}
resource "aws_security_group" "ssh" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}`}})
	r := NewReview(base, head, []string{"main.tf"})
	ids := func(fs []Finding) string {
		var s []string
		for _, f := range fs {
			s = append(s, f.RuleID)
		}
		return strings.Join(s, ",")
	}
	if !strings.Contains(ids(r.New), "TG-AWS-SG-001") || strings.Contains(ids(r.New), "TG-AWS-KMS-001") {
		t.Errorf("new = %s; pre-existing KMS finding must not count as new", ids(r.New))
	}
	if !strings.Contains(ids(r.Resolved), "TG-AWS-RDS-001") {
		t.Errorf("resolved = %s", ids(r.Resolved))
	}
	if r.Tier != "full" || r.Passed || r.Existing == 0 {
		t.Errorf("tier=%s passed=%v existing=%d", r.Tier, r.Passed, r.Existing)
	}
	md := r.Markdown()
	for _, s := range []string{"changes requested", "### Security", "**Important** `TG-AWS-SG-001`", "### Resolved in this change"} {
		if !strings.Contains(md, s) {
			t.Errorf("markdown missing %q:\n%s", s, md)
		}
	}
	if NewReview(base, base, nil).Tier != "trivial" {
		t.Error("no Terraform changes must be the trivial tier")
	}
}

func TestAgentsMD(t *testing.T) {
	in := load(t, "../examples/insecure")
	out := AgentsMD(in.Files, in.Config)
	for _, s := range []string{"# AGENTS.md", "State backend: none (local state)", "`aws_db_instance.main`", "`ORG-TAG-001`", "gate at HIGH", "approved by platform-team"} {
		if !strings.Contains(out, s) {
			t.Errorf("AGENTS.md missing %q:\n%s", s, out)
		}
	}
	if AgentsMD(in.Files, in.Config) != out {
		t.Error("output must be deterministic")
	}
}

func TestPolicyWhereAssertAndGlobs(t *testing.T) {
	cfg := `
disable: ["TG-TF-*", "TG-STATE-*"]
severity_overrides: {"TG-AWS-RDS-*": CRITICAL}
custom_rules:
  - id: ORG-PROD-001
    title: Production databases need multi-AZ and 14+ days of backups
    severity: HIGH
    resource_types: [aws_db_instance]
    where: [{attribute: tags.env, equals: prod}]
    assert:
      - {attribute: multi_az, equals: true}
      - {attribute: backup_retention_period, min: 14}
  - id: ORG-NAME-001
    resource_types: ["aws_*"]
    attribute: tags.Name
    not_matches: "^test-"
  - id: ORG-SG-001
    resource_types: [aws_security_group]
    attribute: tags
    contains: owner
`
	files := map[string]string{"m.tf": `
resource "aws_db_instance" "prod" {
  multi_az                = true
  backup_retention_period = 7
  publicly_accessible     = true
  tags = { env = "prod", Name = "test-db" }
}
resource "aws_db_instance" "dev" {
  backup_retention_period = 1
  tags = { env = "dev" }
}
resource "aws_security_group" "sg" {
  tags = { team = "x" }
}`}
	r := Scan(Input{Config: cfg, Files: files})
	if len(r.Errors) > 0 {
		t.Fatal(r.Errors)
	}
	got := map[string][]string{}
	for _, f := range r.Findings {
		got[f.RuleID] = append(got[f.RuleID], f.Resource)
		if strings.HasPrefix(f.RuleID, "TG-TF-") || strings.HasPrefix(f.RuleID, "TG-STATE-") {
			t.Errorf("glob disable failed: %s", f.RuleID)
		}
		if f.RuleID == "TG-AWS-RDS-001" && f.Severity != Critical {
			t.Errorf("glob override failed: %s", f.Severity)
		}
	}
	if strings.Join(got["ORG-PROD-001"], ",") != "aws_db_instance.prod" {
		t.Errorf("where/assert: %v (dev must be filtered out, prod fails min backups)", got["ORG-PROD-001"])
	}
	if strings.Join(got["ORG-NAME-001"], ",") != "aws_db_instance.prod" || strings.Join(got["ORG-SG-001"], ",") != "aws_security_group.sg" {
		t.Errorf("not_matches/contains: %v", got)
	}
	if _, err := ParseConfig("custom_rules: [{id: X}]"); err == nil {
		t.Error("a rule without conditions must be rejected")
	}
	if _, err := ParseConfig("fail_on: SEVERE"); err == nil {
		t.Error("an invalid fail_on must be rejected")
	}
}

func TestResolveExtends(t *testing.T) {
	packs := map[string]string{
		"org.yml":  "fail_on: MEDIUM\ndisable: [TG-CF-002]\ncustom_rules: [{id: ORG-1, attribute: tags.owner, exists: true, severity: LOW}]\n",
		"team.yml": "extends: [org.yml]\ncustom_rules: [{id: ORG-1, attribute: tags.owner, exists: true, severity: HIGH}]\n",
		"loop.yml": "extends: [loop.yml]\n",
	}
	load := func(ref string) (string, error) { return packs[ref], nil }
	merged, err := ResolveExtends("extends: [team.yml]\nwaivers: [{rule: X}]\n", load)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseConfig(merged)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FailOn != Medium || len(cfg.Disable) != 1 || len(cfg.CustomRules) != 1 || cfg.CustomRules[0].Severity != High || len(cfg.Waivers) != 1 {
		t.Fatalf("merged = %+v", cfg)
	}
	if _, err := ResolveExtends("extends: [loop.yml]", load); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("cycle must be detected, got %v", err)
	}
}

func TestBaselineBudgetAndOwner(t *testing.T) {
	files := map[string]string{"m.tf": `resource "aws_db_instance" "a" {
  publicly_accessible = true
  storage_encrypted   = true
  deletion_protection = true
  tags = { owner = "x" }
}`}
	first := Scan(Input{Files: files, FailOn: "HIGH"})
	if first.Passed || len(first.GateFailures) == 0 {
		t.Fatalf("expected a gate failure with reasons, got %+v", first.GateFailures)
	}
	var keys []string
	for _, f := range first.Findings {
		keys = append(keys, FindingKey(f))
	}
	if r := Scan(Input{Files: files, FailOn: "HIGH", Baseline: keys}); !r.Passed || r.Waived == 0 {
		t.Fatalf("baselined findings must not fail the gate: %+v", r.GateFailures)
	}
	broken := map[string]string{"m.tf": `resource "aws_s3_bucket" "b" {
  bucket = "Bad_Name"
}`}
	var bk []string
	for _, f := range Scan(Input{Files: broken}).Findings {
		bk = append(bk, FindingKey(f))
	}
	if r := Scan(Input{Files: broken, Baseline: bk}); r.Verdict.WillApply || !r.Passed {
		t.Fatalf("a baselined blocking finding still breaks apply (verdict) but not the gate: will_apply=%v passed=%v", r.Verdict.WillApply, r.Passed)
	}
	cfg := "fail_on: NONE\nmax_findings: {HIGH: 0}\ncustom_rules: [{id: ORG-1, attribute: tags.cost_center, exists: true, owner: finops, docs_url: https://wiki/cc}]\n"
	r := Scan(Input{Files: files, Config: cfg})
	if r.Passed || !strings.Contains(strings.Join(r.GateFailures, ";"), "budget") {
		t.Fatalf("budget must fail the gate: %v", r.GateFailures)
	}
	for _, f := range r.Findings {
		if f.RuleID == "ORG-1" && (f.Owner != "finops" || f.Docs != "https://wiki/cc") {
			t.Fatalf("owner/docs not propagated: %+v", f)
		}
	}
}

func TestLocalModulesAreScopedAndCallsChecked(t *testing.T) {
	r := Scan(Input{Files: map[string]string{
		"main.tf": `variable "name" {
  description = "n"
}
module "vpc" {
  source = "./modules/vpc"
  name   = var.name
  cidr   = "10.0.0.0/16"
}
module "ok" {
  source = "./modules/vpc"
  name   = "x"
  region = "eu-west-1"
}`,
		"modules/vpc/main.tf": `variable "name" {
  description = "n"
}
variable "region" {
  description = "r"
}
variable "tags" {
  description = "t"
  default     = {}
}
output "name" {
  description = "n"
  value       = "${var.name}-${var.region}-${length(var.tags)}"
}`,
	}})
	got := ids(r)
	if got["TG-VAL-002"] != 0 {
		t.Errorf("same variable name in two modules reported as duplicate: %v", got)
	}
	if got["TG-VAL-011"] != 1 || got["TG-VAL-012"] != 1 {
		t.Errorf("want one unknown input (cidr) and one missing input (region), got %v", got)
	}
	for _, f := range r.Findings {
		if (f.RuleID == "TG-VAL-011" || f.RuleID == "TG-VAL-012") && f.Resource != "module.vpc" {
			t.Errorf("%s reported on %s, want module.vpc", f.RuleID, f.Resource)
		}
	}
}

func TestVariablesAndLocalsAreResolved(t *testing.T) {
	scan := func(files map[string]string) map[string]Finding {
		out := map[string]Finding{}
		for _, f := range Scan(Input{Files: files}).Findings {
			out[f.RuleID] = f
		}
		return out
	}
	main := `variable "acl" {
  default = "private"
}
resource "aws_s3_bucket" "b" {
  bucket = "my-bucket-1"
  acl    = var.acl
}`
	if _, ok := scan(map[string]string{"main.tf": main})["TG-AWS-S3-001"]; ok {
		t.Error("a private default must not be flagged")
	}
	got := scan(map[string]string{"main.tf": main, "terraform.tfvars": `acl = "public-read"`})
	f, ok := got["TG-AWS-S3-001"]
	if !ok {
		t.Fatal("terraform.tfvars overrides the default and must be checked")
	}
	if f.Fix != nil || !strings.Contains(f.Message, "var.acl") {
		t.Errorf("a value from a variable gets no auto-fix and names its source: %+v", f)
	}
	// Two environment files that disagree: the value is not known statically.
	if _, ok := scan(map[string]string{"main.tf": main, "dev.tfvars": `acl = "public-read"`, "prod.tfvars": `acl = "private"`})["TG-AWS-S3-001"]; ok {
		t.Error("conflicting tfvars files must not be guessed")
	}
	// A module folder's variables are its own.
	if _, ok := scan(map[string]string{"main.tf": `variable "acl" {
  default = "private"
}`, "modules/b/main.tf": main, "modules/b/terraform.tfvars": `acl = "public-read"`})["TG-AWS-S3-001"]; !ok {
		t.Error("tfvars next to a module apply to that module")
	}
}

func TestStrictExceptionControls(t *testing.T) {
	src := "# terraguard:ignore TG-AWS-S3-001\nresource \"aws_s3_bucket\" \"b\" {\n  bucket = \"strict-bucket\"\n  acl    = \"public-read\"\n}\n"
	active := func(cfg string) (bool, map[string]int) {
		r := Scan(Input{Files: map[string]string{"main.tf": src}, Config: cfg})
		on := false
		for _, f := range r.Findings {
			if f.RuleID == "TG-AWS-S3-001" && !f.Waived {
				on = true
			}
		}
		return on, ids(r)
	}
	if on, _ := active(""); on {
		t.Fatal("inline ignores work by default")
	}
	if on, _ := active("inline_ignores: false\n"); !on {
		t.Error("inline_ignores: false must make ignore comments have no effect")
	}
	waiver := "max_waiver_days: 90\nwaivers:\n  - rule: TG-AWS-S3-001\n    reason: public site\n"
	if on, got := active("inline_ignores: false\n" + waiver + "    expires: 2099-01-01\n"); !on || got["TG-POL-002"] == 0 {
		t.Errorf("a waiver beyond max_waiver_days must not apply and must be reported: %v", got)
	}
	if on, got := active("inline_ignores: false\n" + waiver); !on || got["TG-POL-002"] == 0 {
		t.Errorf("a waiver without expiry must not apply under max_waiver_days: %v", got)
	}
	soon := time.Now().AddDate(0, 0, 30).Format("2006-01-02")
	if on, _ := active("inline_ignores: false\n" + waiver + "    expires: " + soon + "\n"); on {
		t.Error("a waiver within the limit applies")
	}
}

func TestPolicyWeakening(t *testing.T) {
	base := "fail_on: HIGH\nmax_waiver_days: 90\nmax_findings: {MEDIUM: 5}\ncustom_rules:\n  - {id: ORG-1, resource_types: [aws_*], attribute: tags.owner, exists: true}\n"
	if got := PolicyWeakening(base, base+"disable: []\n"); len(got) != 0 {
		t.Errorf("no change reported as weakening: %v", got)
	}
	if got := PolicyWeakening(base, "fail_on: MEDIUM\nmax_waiver_days: 30\nmax_findings: {MEDIUM: 2}\ncustom_rules:\n  - {id: ORG-1, resource_types: [aws_*], attribute: tags.owner, exists: true}\n"); len(got) != 0 {
		t.Errorf("a stricter policy reported as weaker: %v", got)
	}
	got := strings.Join(PolicyWeakening(base, "fail_on: CRITICAL\nwaivers:\n  - {rule: TG-AWS-*}\n"), "; ")
	for _, want := range []string{"fail_on loosened from HIGH to CRITICAL", "adds a waiver for TG-AWS-*", "removes custom rule ORG-1", "MEDIUM budget", "max_waiver_days"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
}

func TestOpenTofuAndTerragrunt(t *testing.T) {
	r := Scan(Input{Files: map[string]string{
		// OpenTofu prefers main.tofu over main.tf in the same folder.
		"main.tf":   `resource "aws_s3_bucket" "b" { bucket = "tf-version" }`,
		"main.tofu": "variable \"acl\" {}\nresource \"aws_s3_bucket\" \"b\" {\n  bucket = \"tofu-version\"\n  acl    = var.acl\n}\n",
		"terragrunt.hcl": `inputs = { acl = "public-read" }
remote_state {
  backend = "s3"
  config = {
    bucket = "state"
    key    = "app.tfstate"
  }
}
terraform {
  source = "."
}`,
	}})
	got := ids(r)
	if got["TG-AWS-S3-001"] != 1 {
		t.Errorf("Terragrunt inputs must feed variables of the .tofu code: %v", got)
	}
	if got["TG-STATE-001"] != 2 {
		t.Errorf("Terragrunt remote_state without encryption and locking: %v", got)
	}
	if got["TG-STATE-003"] != 0 || got["TG-TF-003"] != 0 {
		t.Errorf("Terragrunt's own blocks are not Terraform code: %v", got)
	}
	for _, f := range r.Findings {
		if f.File == "main.tf" {
			t.Errorf("main.tf is shadowed by main.tofu: %+v", f)
		}
	}
}

func TestRulesVersionPinning(t *testing.T) {
	// TG-AWS-EFS-001 arrived in 2.1; TG-AWS-S3-001 was in 2.0.
	files := map[string]string{"main.tf": "resource \"aws_efs_file_system\" \"f\" {}\nresource \"aws_s3_bucket\" \"b\" {\n  bucket = \"pin-bucket\"\n  acl    = \"public-read\"\n}\n"}
	state := func(cfg string) map[string]bool {
		out := map[string]bool{}
		for _, f := range Scan(Input{Files: files, Config: cfg}).Findings {
			out[f.RuleID] = !f.Waived
		}
		return out
	}
	if s := state(""); !s["TG-AWS-EFS-001"] || !s["TG-AWS-S3-001"] {
		t.Errorf("unpinned: every rule gates: %v", s)
	}
	s := state("rules_version: \"2.0\"\n")
	if !s["TG-AWS-S3-001"] {
		t.Error("a 2.0 rule must still gate under rules_version 2.0")
	}
	if active, seen := s["TG-AWS-EFS-001"]; !seen || active {
		t.Errorf("a 2.1 rule must be reported but not gate under 2.0: seen=%v active=%v", seen, active)
	}
	if _, err := ParseConfig("rules_version: \"9.9\"\n"); err == nil {
		t.Error("a rules_version newer than the build must be rejected")
	}
	if got := strings.Join(PolicyWeakening("", "rules_version: \"2.0\"\n"), ";"); !strings.Contains(got, "pins rules_version") {
		t.Errorf("pinning to an older set loosens the gate: %q", got)
	}
}

func TestGraphExports(t *testing.T) {
	r := load(t, "../examples/insecure")
	rep := Scan(r)
	m := GraphMermaid(rep)
	if !strings.HasPrefix(m, "flowchart LR") || !strings.Contains(m, "-->") || !strings.Contains(m, "class ") {
		t.Errorf("mermaid output looks wrong:\n%.400s", m)
	}
	d := GraphDOT(rep)
	if !strings.HasPrefix(d, "digraph terraform {") || !strings.Contains(d, "->") || !strings.HasSuffix(d, "}\n") {
		t.Errorf("dot output looks wrong:\n%.400s", d)
	}
}

func TestPlanImportsMovesOutputsAndDrift(t *testing.T) {
	plan := `{"format_version":"1.2",
 "resource_changes":[
  {"address":"aws_s3_bucket.imported","mode":"managed","type":"aws_s3_bucket","name":"imported","change":{"actions":["no-op"],"importing":{"id":"legacy-bucket"},"after":{"bucket":"legacy-bucket"}}},
  {"address":"aws_iam_role.app","previous_address":"aws_iam_role.old","mode":"managed","type":"aws_iam_role","name":"app","change":{"actions":["no-op"],"after":{}}}],
 "resource_drift":[
  {"address":"aws_security_group.web","mode":"managed","type":"aws_security_group","change":{"actions":["update"],"before":{"description":"web","ingress":[{"from_port":443}]},"after":{"description":"web","ingress":[{"from_port":22}]}}},
  {"address":"aws_db_instance.main","mode":"managed","type":"aws_db_instance","change":{"actions":["delete"],"before":{"identifier":"main"},"after":null}}],
 "output_changes":{"url":{"actions":["update"]},"same":{"actions":["no-op"]}}}`
	r := Scan(Input{Plan: plan})
	p := r.Plan
	if p == nil || p.Import != 1 || p.Moved != 1 || len(p.Outputs) != 1 || len(p.Drift) != 2 {
		t.Fatalf("plan summary = %+v errors=%v", p, r.Errors)
	}
	if got := strings.Join(p.Drift[0].Reasons, ","); got != "ingress" {
		t.Errorf("drift should name the changed attribute, got %q", got)
	}
	msgs := ""
	for _, f := range r.Findings {
		if f.RuleID == "TG-PLAN-003" {
			msgs += f.Message + "\n"
		}
	}
	if !strings.Contains(msgs, "aws_security_group.web was changed outside Terraform (ingress)") || !strings.Contains(msgs, "aws_db_instance.main was deleted outside Terraform") {
		t.Errorf("drift findings:\n%s", msgs)
	}
	if md := Markdown(r); !strings.Contains(md, "1 to import, 1 moved") || !strings.Contains(md, "2 resource(s) drifted") {
		t.Errorf("markdown summary misses imports, moves or drift:\n%.600s", md)
	}
}

func TestCIAnnotationFormats(t *testing.T) {
	r := &Report{Findings: []Finding{{RuleID: "TG-X-1", Title: "a, b: c", Severity: High, File: "dir,1/main.tf", Line: 3, Message: "line one\nline two 100%", Remediation: "fix"}}}
	gh := GitHubAnnotations(r)
	if gh != "::error file=dir%2C1/main.tf,line=3,title=TG-X-1 a%2C b%3A c::line one%0Aline two 100%25 Fix: fix\n" {
		t.Errorf("github annotation escaping: %q", gh)
	}
	if az := AzureDevOps(r); !strings.HasPrefix(az, "##vso[task.logissue type=error;sourcepath=dir,1/main.tf;linenumber=3;code=TG-X-1]") || strings.Count(az, "\n") != 1 {
		t.Errorf("azure logging command: %q", az)
	}
	if cs, err := Checkstyle(r); err != nil || !strings.Contains(string(cs), `source="terraguard.TG-X-1"`) {
		t.Errorf("checkstyle: %v %s", err, cs)
	}
}

func TestUnwaivableAndFileIgnores(t *testing.T) {
	src := "# terraguard:ignore-file TG-AWS-S3-003\n# terraguard:ignore TG-AWS-S3-001\nresource \"aws_s3_bucket\" \"b\" {\n  bucket = \"lock-bucket\"\n  acl    = \"public-read\"\n}\n"
	active := func(cfg string) map[string]bool {
		out := map[string]bool{}
		for _, f := range Scan(Input{Files: map[string]string{"main.tf": src}, Config: cfg}).Findings {
			out[f.RuleID] = out[f.RuleID] || !f.Waived
		}
		return out
	}
	a := active("")
	if a["TG-AWS-S3-001"] || a["TG-AWS-S3-003"] {
		t.Errorf("inline and file-level ignores apply by default: %v", a)
	}
	a = active("unwaivable: [\"TG-AWS-S3-00*\"]\nwaivers:\n  - {rule: TG-AWS-S3-001, reason: x, expires: 2099-01-01}\n")
	if !a["TG-AWS-S3-001"] || !a["TG-AWS-S3-003"] {
		t.Errorf("unwaivable rules ignore comments and waivers: %v", a)
	}
	late := "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"late-bucket\"\n}\n# terraguard:ignore-file TG-AWS-S3-003\n"
	for _, f := range Scan(Input{Files: map[string]string{"main.tf": late}}).Findings {
		if f.RuleID == "TG-AWS-S3-003" && f.Waived {
			t.Error("ignore-file below code must not apply")
		}
	}
	if got := strings.Join(PolicyWeakening("unwaivable: [TG-SEC-*]\n", ""), ";"); !strings.Contains(got, "TG-SEC-* be waived again") {
		t.Errorf("dropping an unwaivable rule loosens the policy: %q", got)
	}
}

func TestForeignAndExpiringIgnores(t *testing.T) {
	waived := func(src string) map[string]bool {
		out := map[string]bool{}
		for _, f := range Scan(Input{Files: map[string]string{"main.tf": src}}).Findings {
			out[f.RuleID] = f.Waived
		}
		return out
	}
	snap := "resource \"aws_db_snapshot\" \"s\" {\n  %s\n  db_instance_identifier = \"db\"\n  db_snapshot_identifier = \"s\"\n  shared_accounts        = [\"all\"]\n}\n"
	if w := waived(fmt.Sprintf(snap, "#checkov:skip=CKV_AWS_302:shared on purpose for the DR account")); !w["TG-AWS-RDS-005"] {
		t.Error("checkov:skip with a mapped ID must waive the equivalent rule")
	}
	if w := waived(fmt.Sprintf(snap, "#checkov:skip=CKV_AWS_999")); w["TG-AWS-RDS-005"] {
		t.Error("an unrelated checkov ID must not waive anything")
	}
	if w := waived(fmt.Sprintf(snap, "# terraguard:ignore TG-AWS-RDS-005 exp:2020-01-01")); w["TG-AWS-RDS-005"] {
		t.Error("an expired inline ignore must not apply")
	}
	if w := waived(fmt.Sprintf(snap, "# terraguard:ignore TG-AWS-RDS-005 exp:2099-01-01")); !w["TG-AWS-RDS-005"] {
		t.Error("an inline ignore before its expiry applies")
	}
}

func TestTrivyIgnoreMapping(t *testing.T) {
	src := "#trivy:ignore:AVD-AWS-0013:exp:2099-01-01\nresource \"aws_cloudfront_distribution\" \"cdn\" {\n  enabled = true\n  origin {\n    domain_name = \"o.example.com\"\n    origin_id   = \"o\"\n    custom_origin_config {\n      origin_protocol_policy = \"http-only\"\n    }\n  }\n}\n"
	for _, f := range Scan(Input{Files: map[string]string{"main.tf": src}}).Findings {
		if f.RuleID == "TG-AWS-CDN-002" && !f.Waived {
			t.Error("trivy:ignore with a mapped AVD ID must waive the equivalent rule")
		}
	}
}

func TestSARIFFingerprintIgnoresLines(t *testing.T) {
	fp := func(prefix string) string {
		r := Scan(Input{Files: map[string]string{"main.tf": prefix + "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"fp-bucket\"\n  acl    = \"public-read\"\n}\n"}})
		b, _ := SARIF(r)
		var doc struct {
			Runs []struct {
				Results []struct {
					RuleID string            `json:"ruleId"`
					FP     map[string]string `json:"partialFingerprints"`
				} `json:"results"`
			} `json:"runs"`
		}
		json.Unmarshal(b, &doc)
		for _, res := range doc.Runs[0].Results {
			if res.RuleID == "TG-AWS-S3-001" {
				return res.FP["terraguardFindingKey/v1"]
			}
		}
		return ""
	}
	a, b := fp(""), fp("\n\n# moved down\n")
	if a == "" || a != b {
		t.Errorf("fingerprint must survive line moves: %q vs %q", a, b)
	}
}

func TestExtendsKeepsAllSettingsAndDataLists(t *testing.T) {
	base := "unwaivable: [TG-SEC-*]\nmax_waiver_days: 90\ndata:\n  regions: [eu-west-1, eu-central-1]\n"
	child := "extends: [base.yml]\ninline_ignores: false\nrules_version: \"2.0\"\ncustom_rules:\n  - id: ORG-REGION-001\n    title: Only approved regions\n    resource_types: [aws_s3_bucket]\n    attribute: region\n    in_data: regions\n"
	merged, err := ResolveExtends(child, func(string) (string, error) { return base, nil })
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseConfig(merged)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InlineIgnores == nil || *cfg.InlineIgnores || cfg.MaxWaiverDays != 90 || cfg.RulesVersion != "2.0" || len(cfg.Unwaivable) != 1 {
		t.Errorf("settings lost through extends: %+v", cfg)
	}
	r := Scan(Input{Config: merged, Files: map[string]string{"main.tf": "resource \"aws_s3_bucket\" \"ok\" {\n  bucket = \"a-bucket\"\n  region = \"eu-west-1\"\n}\nresource \"aws_s3_bucket\" \"bad\" {\n  bucket = \"b-bucket\"\n  region = \"us-east-1\"\n}\n"}})
	var flagged []string
	for _, f := range r.Findings {
		if f.RuleID == "ORG-REGION-001" {
			flagged = append(flagged, f.Resource)
		}
	}
	if len(flagged) != 1 || flagged[0] != "aws_s3_bucket.bad" {
		t.Errorf("in_data must use the inherited list: %v (errors %v)", flagged, r.Errors)
	}
	if _, err := ParseConfig("custom_rules:\n  - {id: ORG-X-001, resource_types: [aws_*], attribute: region, in_data: nope}\n"); err == nil {
		t.Error("an unknown data list must be an error")
	}
}

// Regressions from the code review of 2.1.
func TestReviewRegressions(t *testing.T) {
	// Terragrunt inputs that are not a map must not panic.
	Scan(Input{Files: map[string]string{"terragrunt.hcl": "inputs = [\"a\"]\n", "main.tf": "variable \"x\" {}\n"}})

	// Variables set by --var-file or Terragrunt inputs have a value.
	vars := map[string]string{"main.tf": "variable \"a\" {}\nvariable \"b\" {}\nvariable \"c\" {}\n", "terraform.tfvars": "c = 1\n", "terragrunt.hcl": "inputs = { b = 2 }\n"}
	got := ids(Scan(Input{Files: vars, VarFiles: []VarFile{{Dir: ".", Source: "a = 1\n"}}}))
	if got["TG-VAL-008"] != 0 {
		t.Errorf("var-file and Terragrunt inputs set the variables: %v", got)
	}

	// Two identical findings in one file get distinct SARIF fingerprints.
	two := "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"x-bucket\"\n  acl    = \"public-read\"\n}\nresource \"aws_s3_bucket\" \"b\" {\n  bucket = \"x-bucket\"\n  acl    = \"public-read\"\n}\n"
	b, _ := SARIF(Scan(Input{Files: map[string]string{"main.tf": two}}))
	seen := map[string]bool{}
	for _, m := range regexp.MustCompile(`"terraguardFindingKey/v1": ?"([^"]+)"`).FindAllStringSubmatch(string(b), -1) {
		if seen[m[1]] {
			t.Errorf("duplicate fingerprint %s", m[1])
		}
		seen[m[1]] = true
	}
	if len(seen) < 2 {
		t.Errorf("expected a fingerprint per finding, got %d", len(seen))
	}

	// A reason after a colon still waives.
	bucket := "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"r-bucket\"\n  acl    = \"public-read\" # terraguard:ignore TG-AWS-S3-001: public website\n}\n"
	for _, f := range Scan(Input{Files: map[string]string{"main.tf": bucket}}).Findings {
		if f.RuleID == "TG-AWS-S3-001" && !f.Waived {
			t.Error("ignore with a reason after a colon must apply")
		}
	}

	// Unwaivable rules survive disable and --skip-check.
	public := map[string]string{"main.tf": "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"u-bucket\"\n  acl    = \"public-read\"\n}\n"}
	if got := ids(Scan(Input{Files: public, Config: "unwaivable: [TG-AWS-S3-001]\ndisable: [TG-AWS-S3-001]\n", Skip: []string{"TG-AWS-S3-001"}})); got["TG-AWS-S3-001"] != 1 {
		t.Errorf("unwaivable must not be disabled or skipped: %v", got)
	}

	// A data source used only in a lifecycle block is used.
	lc := "data \"aws_ami\" \"a\" {}\nresource \"aws_instance\" \"i\" {\n  ami = \"ami-1\"\n  lifecycle {\n    precondition {\n      condition     = data.aws_ami.a.id != \"\"\n      error_message = \"x\"\n    }\n  }\n}\n"
	if got := ids(Scan(Input{Files: map[string]string{"main.tf": lc}})); got["TG-TF-008"] != 0 {
		t.Errorf("lifecycle references count as use: %v", got)
	}

	// Drift the plan leaves alone is informational.
	plan := `{"format_version":"1.2","resource_changes":[{"address":"aws_security_group.web","mode":"managed","type":"aws_security_group","change":{"actions":["no-op"],"after":{}}}],
 "resource_drift":[{"address":"aws_security_group.web","mode":"managed","type":"aws_security_group","change":{"actions":["update"],"before":{"description":"a"},"after":{"description":"b"}}}]}`
	for _, f := range Scan(Input{Plan: plan}).Findings {
		if f.RuleID == "TG-PLAN-003" && f.Severity != Info {
			t.Errorf("no-op drift should be Info, got %s", f.Severity)
		}
	}
}

func TestBundledSchemasAndVersionGating(t *testing.T) {
	code := "resource \"aws_s3_bucket\" \"b\" {\n  bukcet = \"gate-bucket\"\n}\n"
	schemaHits := func(in Input) int {
		return ids(Scan(in))["TG-SCHEMA-001"]
	}
	if n := schemaHits(Input{Files: map[string]string{"main.tf": code}}); n != 1 {
		t.Errorf("bundled schema should catch the misspelt argument, got %d", n)
	}
	pinned := "terraform {\n  required_providers {\n    aws = { source = \"hashicorp/aws\", version = \"~> 4.0\" }\n  }\n}\n"
	if n := schemaHits(Input{Files: map[string]string{"main.tf": code, "versions.tf": pinned}}); n != 0 {
		t.Errorf("an older pinned major must not be checked against the bundled schema, got %d", n)
	}
	lock := "provider \"registry.terraform.io/hashicorp/aws\" {\n  version = \"5.31.0\"\n  hashes = []\n}\n"
	if n := schemaHits(Input{Files: map[string]string{"main.tf": code, ".terraform.lock.hcl": lock}}); n != 0 {
		t.Errorf("a lock file on another major must turn the bundled schema off, got %d", n)
	}
	if n := schemaHits(Input{Files: map[string]string{"main.tf": code}, NoBuiltinSchema: true}); n != 0 {
		t.Errorf("NoBuiltinSchema must turn it off, got %d", n)
	}
	for _, c := range []struct {
		constraint, v string
		ok            bool
	}{{"~> 6.0", "6.71.0", true}, {"~> 6.2.0", "6.71.0", false}, {">= 5.0, < 7.0", "6.71.0", true}, {"< 6.0", "6.71.0", false}, {"~> 5", "6.1.0", false}, {"6.71.0", "6.71.0", true}} {
		if got := versionAllowed(c.constraint, c.v); got != c.ok {
			t.Errorf("versionAllowed(%q, %q) = %v", c.constraint, c.v, got)
		}
	}
}

func TestTerraformJSONSyntax(t *testing.T) {
	src := `{
  "variable": {"acl": {"type": "string", "default": "public-read"}},
  "resource": {
    "aws_s3_bucket": {
      "logs": {
        "bucket": "Bad_Bucket",
        "acl": "${var.acl}",
        "lifecycle": {"prevent_destroy": true}
      }
    }
  }
}`
	r := Scan(Input{Files: map[string]string{"cdktf.tf.json": src}})
	lines := map[string]int{}
	for _, f := range r.Findings {
		lines[f.RuleID] = f.Line
		if f.Fix != nil {
			t.Errorf("%s: JSON files must not get an auto-fix", f.RuleID)
		}
	}
	if lines["TG-VAL-005"] != 6 {
		t.Errorf("invalid bucket name should point at JSON line 6, got %d (%v)", lines["TG-VAL-005"], r.Errors)
	}
	if _, ok := lines["TG-AWS-S3-001"]; !ok {
		t.Errorf("the public ACL from the variable default should be found: %v", lines)
	}
	if r := Scan(Input{Files: map[string]string{"bad.tf.json": "{"}}); ids(r)["TG-VAL-001"] != 1 {
		t.Error("broken JSON is a syntax error")
	}
}

func TestSecretVariableHeuristic(t *testing.T) {
	src := "variable \"secret_rotation_interval\" {\n  type    = string\n  default = \"2m\"\n}\nvariable \"db_password\" {\n  type    = string\n  default = \"hunter2hunter2\"\n}\noutput \"o\" { value = [var.secret_rotation_interval, var.db_password] }\n"
	hits := map[string]int{}
	for _, f := range Scan(Input{Files: map[string]string{"main.tf": src}}).Findings {
		if f.RuleID == "TG-SEC-001" || f.RuleID == "TG-SEC-003" {
			hits[f.Resource]++
		}
	}
	if hits["var.secret_rotation_interval"] != 0 || hits["var.db_password"] != 2 {
		t.Errorf("a setting about a secret is not a secret: %v", hits)
	}
}

func TestTerraformJSONDepthLimit(t *testing.T) {
	deep := strings.Repeat(`{"a":`, 100000) + "1" + strings.Repeat("}", 100000)
	if r := Scan(Input{Files: map[string]string{"x.tf.json": deep}}); ids(r)["TG-VAL-001"] != 1 {
		t.Error("a deeply nested .tf.json must be rejected, not recursed into")
	}
}

func TestLiteralSecretsOutsideTerraform(t *testing.T) {
	r := &Resource{Type: "AWS::RDS::DBInstance", Address: "AWS::RDS::DBInstance.db", Format: FormatCloudFormation, Attrs: map[string]any{"Properties": map[string]any{
		"MasterUserPassword": "hunter2hunter2", "MasterUsername": "admin",
		"DBPassword":   "{{resolve:secretsmanager:db:SecretString:password}}",
		"ClientSecret": "${env.CLIENT_SECRET}", "TokenTTL": "3600",
	}}}
	fs := literalSecrets(r)
	if len(fs) != 1 || !strings.Contains(fs[0].Message, "MasterUserPassword") {
		t.Errorf("only the literal password is a secret: %+v", fs)
	}
}

func TestCoverageReport(t *testing.T) {
	src := "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"cov-bucket\"\n  acl    = \"public-read\"\n}\nresource \"null_resource\" \"n\" {}\n"
	r := Scan(Input{Files: map[string]string{"main.tf": src}, Coverage: true})
	c := r.Coverage
	if c == nil || c.Resources != 2 || c.Covered != 1 || len(c.Uncovered) != 1 || c.Uncovered[0] != "null_resource" {
		t.Fatalf("coverage = %+v", c)
	}
	if c.Failed == 0 || c.Passed == 0 || c.Passed+c.Failed != c.Checks || len(c.Items) != 2 {
		t.Errorf("passed/failed must split the checks: %+v", c)
	}
	off := Scan(Input{Files: map[string]string{"main.tf": src}, Config: "disable: [\"TG-AWS-S3-*\"]\n"}).Coverage
	if off.Checks >= c.Checks || off.Items != nil {
		t.Errorf("disabled rules are not checks, and items need Coverage: %+v", off)
	}
}

func TestPolicyPacks(t *testing.T) {
	src := map[string]string{"main.tf": "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"pack-bucket\"\n}\n"}
	min := Scan(Input{Files: src, Config: "extends: [terraguard:minimal]\n"})
	strict := Scan(Input{Files: src, Config: "extends: [terraguard:strict]\nmax_waiver_days: 60\n"})
	if min.FailOn != Critical || strict.FailOn != Medium {
		t.Errorf("packs set the gate: minimal %s, strict %s", min.FailOn, strict.FailOn)
	}
	if _, err := ResolveExtends("extends: [terraguard:nope]\n", nil); err == nil {
		t.Error("an unknown pack is an error")
	}
	merged, _ := ResolveExtends("extends: [terraguard:strict]\nmax_waiver_days: 60\n", nil)
	if !strings.Contains(merged, "max_waiver_days: 60") || !strings.Contains(merged, "TG-SEC-*") {
		t.Errorf("own settings override the pack, the rest is kept:\n%s", merged)
	}
}

func TestModuleInputsFlowIntoLocalModules(t *testing.T) {
	files := map[string]string{
		"main.tf":                 "module \"data\" {\n  source = \"./modules/bucket\"\n  acl    = \"public-read\"\n}\nmodule \"logs\" {\n  source = \"./modules/private\"\n  acl    = \"private\"\n}\n",
		"modules/bucket/main.tf":  "variable \"acl\" {\n  type    = string\n  default = \"private\"\n}\nresource \"aws_s3_bucket\" \"b\" {\n  bucket = \"mod-bucket\"\n  acl    = var.acl\n}\n",
		"modules/private/main.tf": "variable \"acl\" {\n  type = string\n}\nresource \"aws_s3_bucket\" \"p\" {\n  bucket = \"mod-private\"\n  acl    = var.acl\n}\n",
		// called twice with different values: unknown, so silent
		"two.tf":                "module \"a\" {\n  source = \"./modules/twice\"\n  acl    = \"public-read\"\n}\nmodule \"b\" {\n  source = \"./modules/twice\"\n  acl    = \"private\"\n}\n",
		"modules/twice/main.tf": "variable \"acl\" {\n  type = string\n}\nresource \"aws_s3_bucket\" \"t\" {\n  bucket = \"mod-twice\"\n  acl    = var.acl\n}\n",
	}
	got := map[string]bool{}
	for _, f := range Scan(Input{Files: files}).Findings {
		if f.RuleID == "TG-AWS-S3-001" {
			got[f.Resource] = true
		}
	}
	if !got["aws_s3_bucket.b"] {
		t.Error("the caller's public-read must reach the module's bucket")
	}
	if got["aws_s3_bucket.p"] || got["aws_s3_bucket.t"] {
		t.Errorf("private input, and disagreeing callers, must stay silent: %v", got)
	}
}
