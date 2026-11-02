package engine

import (
	"os"
	"path/filepath"
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

func TestSecureExampleIsClean(t *testing.T) {
	r := Scan(load(t, "../examples/secure"))
	for _, f := range r.Findings {
		if f.Severity != Info {
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
