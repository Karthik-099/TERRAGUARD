package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Karthik-099/TERRAGUARD/engine"
)

func TestScanSelectionFlags(t *testing.T) {
	t.Chdir(t.TempDir())
	os.WriteFile("main.tf", []byte("variable \"acl\" {\n  type    = string\n  default = \"private\"\n}\nresource \"aws_s3_bucket\" \"b\" {\n  bucket = \"flags-bucket\"\n  acl    = var.acl\n}\n"), 0o644)
	os.WriteFile("prod.tfvars", []byte(`acl = "private"`), 0o644)
	os.WriteFile("public.tfvars", []byte(`acl = "public-read"`), 0o644)
	os.MkdirAll("test/fixtures", 0o755)
	os.WriteFile("test/fixtures/bad.tf", []byte("resource \"aws_security_group\" \"x\" {\n  ingress {\n    from_port = 22\n    to_port = 22\n    protocol = \"tcp\"\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n}\n"), 0o644)
	rules := func(args ...string) map[string]bool {
		t.Helper()
		out := filepath.Join(t.TempDir(), "r.json")
		if _, err := runScan(append(args, "--json", out, "--format", "json", ".")); err != nil {
			t.Fatal(err)
		}
		var rep engine.Report
		b, _ := os.ReadFile(out)
		json.Unmarshal(b, &rep)
		got := map[string]bool{}
		for _, f := range rep.Findings {
			if !f.Waived {
				got[f.RuleID+"@"+f.File] = true
			}
		}
		return got
	}
	devnull, _ := os.Open(os.DevNull)
	stdout := os.Stdout
	os.Stdout = devnull
	t.Cleanup(func() { os.Stdout = stdout })

	if r := rules(); r["TG-AWS-S3-001@main.tf"] {
		t.Error("prod.tfvars and public.tfvars disagree, so the default applies")
	}
	if r := rules("--var-file", "public.tfvars"); !r["TG-AWS-S3-001@main.tf"] {
		t.Error("--var-file must decide the value, like terraform -var-file")
	}
	if r := rules("--var-file", "public.tfvars", "--skip-check", "TG-AWS-S3-00*"); r["TG-AWS-S3-001@main.tf"] {
		t.Error("--skip-check must drop matching rules")
	}
	r := rules("--check", "TG-AWS-SG-*")
	for k := range r {
		if !strings.HasPrefix(k, "TG-AWS-SG-") {
			t.Errorf("--check keeps only matching rules: %v", r)
		}
	}
	if !r["TG-AWS-SG-001@test/fixtures/bad.tf"] {
		t.Errorf("--check must keep the matching rule: %v", r)
	}
	if r := rules("--skip-path", "test/**"); r["TG-AWS-SG-001@test/fixtures/bad.tf"] {
		t.Error("--skip-path must drop files under the path")
	}
}
