package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
