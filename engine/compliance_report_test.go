package engine

import (
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"
	"time"
)

var updateGolden = flag.Bool("update", false, "rewrite golden files")

// complianceFixture is a hand-built report, so the golden file does not move
// when rules are added: no built-in rule targets example_thing.
func complianceFixture() (*Report, *Config) {
	rep := &Report{
		Stats:    Stats{Files: 2},
		Coverage: &Coverage{Items: []ResourceCoverage{{Address: "example_thing.a", Type: "example_thing", File: "main.tf", Line: 1}}},
		Findings: []Finding{
			{RuleID: "TG-AWS-EBS-001", Severity: High, Title: "EBS volume not encrypted", Message: "Volume is not encrypted.", Resource: "aws_ebs_volume.data", File: "main.tf", Line: 4},
			{RuleID: "TG-AWS-S3-002", Severity: Medium, Title: "S3 access", Message: "Bucket policy is broad.", Resource: "aws_s3_bucket.logs", File: "s3.tf", Line: 9,
				Waived: true, WaiverReason: "log bucket (approved by sec-team)"},
		},
	}
	cfg := &Config{Waivers: []Waiver{
		{Rule: "TG-AWS-S3-*", Resource: "aws_s3_bucket.logs", Reason: "log bucket", ApprovedBy: "sec-team", Expires: "2027-01-31"},
		{Rule: "TG-AWS-EBS-001", Reason: "migration", ApprovedBy: "ops-lead", Expires: "2026-10-01"},
	}}
	return rep, cfg
}

func TestComplianceReportGolden(t *testing.T) {
	rep, cfg := complianceFixture()
	doc, err := ComplianceReport(rep, cfg, "soc2", time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	doc.FilesSHA256 = FilesDigest(map[string]string{"main.tf": "a", "s3.tf": "b"})
	doc.Version, doc.RulesVersion = "X", "X" // release bumps must not touch the golden file
	for i := range doc.Controls {
		doc.Controls[i].RulesMapped = 0 // grows with the rule catalog
	}
	got, _ := json.MarshalIndent(doc, "", "  ")
	const golden = "testdata/compliance_soc2.golden.json"
	if *updateGolden {
		os.WriteFile(golden, append(got, '\n'), 0o644)
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(want)) != string(got) {
		t.Fatalf("compliance JSON changed (go test ./engine -run ComplianceReportGolden -update):\n%s", got)
	}
}

func TestComplianceReportStatusAndExpiredWaiver(t *testing.T) {
	rep, cfg := complianceFixture()
	doc, err := ComplianceReport(rep, cfg, "SOC2", time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]ComplianceControl{}
	for _, c := range doc.Controls {
		by[c.ID] = c
	}
	// CC6.1 holds encryption at rest: the EBS finding fails it, and its waiver is expired.
	c := by["CC6.1"]
	if c.Status != "fail" || len(c.Failures) != 1 || len(c.Waivers) != 1 || !c.Waivers[0].Expired || c.Waivers[0].ApprovedBy != "ops-lead" {
		t.Fatalf("CC6.1 = %+v", c)
	}
	if c := by["CC6.3"]; c.Status != "pass" || len(c.Waivers) != 1 || c.Waivers[0].Expired || c.Waivers[0].Expires != "2027-01-31" {
		t.Fatalf("CC6.3 (waived access finding) = %+v", c)
	}
	if c := by["A1.2"]; c.Status != "not_assessed" {
		t.Fatalf("A1.2 (no backup rule applied) = %+v", c)
	}
	// The waiver is still live on its expiry day.
	doc, _ = ComplianceReport(rep, cfg, "soc2", time.Date(2026, 10, 1, 23, 0, 0, 0, time.UTC))
	for _, c := range doc.Controls {
		if c.ID == "CC6.1" && len(c.Waivers) > 0 && c.Waivers[0].Expired {
			t.Fatal("waiver flagged expired on its expiry day")
		}
	}
	if _, err := ComplianceReport(rep, cfg, "nist", time.Now()); err == nil {
		t.Fatal("unknown framework accepted")
	}
	if FilesDigest(map[string]string{"ab": "c"}) == FilesDigest(map[string]string{"a": "bc"}) {
		t.Fatal("digest is ambiguous")
	}
}

func TestSARIFFixes(t *testing.T) {
	src := "resource \"aws_ebs_volume\" \"v\" {\n  availability_zone = \"us-east-1a\"\n}\n"
	files := map[string]string{"main.tf": src}
	b, err := SARIFWithFixes(Scan(Input{Files: files}), files)
	if err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
				Fixes  []struct {
					ArtifactChanges []struct {
						Replacements []struct {
							DeletedRegion   map[string]int    `json:"deletedRegion"`
							InsertedContent map[string]string `json:"insertedContent"`
						} `json:"replacements"`
					} `json:"artifactChanges"`
				} `json:"fixes"`
			} `json:"results"`
		} `json:"runs"`
	}
	json.Unmarshal(b, &log)
	for _, r := range log.Runs[0].Results {
		if r.RuleID != "TG-AWS-EBS-001" {
			continue
		}
		rp := r.Fixes[0].ArtifactChanges[0].Replacements[0]
		// Insert before line 3, zero-length region.
		if rp.DeletedRegion["startLine"] != 3 || rp.DeletedRegion["endLine"] != 3 || rp.DeletedRegion["endColumn"] != 1 || !strings.Contains(rp.InsertedContent["text"], "encrypted") {
			t.Fatalf("fix = %+v", rp)
		}
		return
	}
	t.Fatalf("no EBS fix in SARIF:\n%s", b)
}
