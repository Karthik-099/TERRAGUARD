package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Karthik-099/TERRAGUARD/engine"
)

func TestReportHTMLEscapesAndIsSelfContained(t *testing.T) {
	evil := `<script>alert(1)</script>`
	doc := &engine.ComplianceDoc{Framework: "SOC 2", Disclaimer: engine.ComplianceDisclaimer, Controls: []engine.ComplianceControl{{
		ID: "CC6.1", Status: "fail", Themes: []string{"Encryption at rest"},
		Failures: []engine.ComplianceFailure{{RuleID: "TG-X", Resource: `aws_s3_bucket.` + evil, File: "a.tf", Line: 3, Message: evil}},
		Waivers:  []engine.ComplianceWaiver{{RuleID: "TG-X", Reason: evil, ApprovedBy: `"><img src=x>`, Expires: "2020-01-01", Expired: true}},
	}}}
	b, err := renderReport(doc, "html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(b)
	for _, bad := range []string{"<script>", "<img", "http://", "https://", "<link", "@import"} {
		if strings.Contains(html, bad) {
			t.Errorf("report HTML contains %q", bad)
		}
	}
	for _, want := range []string{"&lt;script&gt;", "not a certification", "Fail", "expired", "@media print"} {
		if !strings.Contains(html, want) {
			t.Errorf("report HTML lacks %q", want)
		}
	}
}

func TestReportCommandJSON(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.tf"), []byte(ebsVolume), 0o644)
	out := filepath.Join(t.TempDir(), "r.json")
	if code, err := runReport([]string{dir, "--framework", "iso27001", "--format", "json", "--out", out}); err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	b, _ := os.ReadFile(out)
	var doc engine.ComplianceDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Schema != engine.ComplianceSchema || len(doc.FilesSHA256) != 64 || doc.Summary.Fail == 0 {
		t.Fatalf("unexpected report: %s", b)
	}
	if code, _ := runReport([]string{dir, "--framework", "nist"}); code != 2 {
		t.Fatal("unknown framework must be a usage error")
	}
}
