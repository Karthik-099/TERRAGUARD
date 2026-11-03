package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegoPolicies(t *testing.T) {
	files := map[string]string{"main.tf": "resource \"aws_s3_bucket\" \"logs\" {\n  bucket = \"logs-x\"\n}\nresource \"aws_s3_bucket\" \"ok\" {\n  bucket = \"ok-x\"\n  tags   = { owner = \"team\" }\n}\n"}
	fs, err := regoFindings([]string{"testdata/rego"}, files, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].RuleID != "OPA.main.deny" || !strings.Contains(fs[0].Message, "logs") {
		t.Errorf("HCL input: %+v", fs)
	}
	plan := `{"resource_changes":[{"address":"aws_db_instance.db","change":{"actions":["delete"]}}]}`
	fs, err = regoFindings([]string{"testdata/rego"}, nil, plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].RuleID != "OPA.main.warn" || fs[0].Severity != "LOW" {
		t.Errorf("plan input: %+v", fs)
	}
	if _, err := regoFindings([]string{"testdata/missing"}, files, ""); err == nil {
		t.Error("a missing policy folder is an error")
	}
}

func TestRegoHasNoNetwork(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "p.rego"), []byte("package main\n\nimport rego.v1\n\ndeny contains msg if {\n\tr := http.send({\"method\": \"get\", \"url\": \"http://127.0.0.1:1\"})\n\tmsg := sprintf(\"%v\", [r.status_code])\n}\n"), 0o644)
	if _, err := regoFindings([]string{dir}, map[string]string{"main.tf": ""}, ""); err == nil {
		t.Error("http.send must not be available to policies")
	}
}
