package engine

import "testing"

// Fuzz targets: any input must produce a report, never a panic. CI runs each
// briefly; run longer locally with go test ./engine -fuzz FuzzScan -fuzztime 5m.

func FuzzScan(f *testing.F) {
	f.Add(`resource "aws_s3_bucket" "b" { acl = "public-read" }`, "")
	f.Add(`module "m" { source = "./x" }`, `{"resource_changes":[]}`)
	f.Add(`variable "v" { default = "${foo}" }`, "{")
	f.Fuzz(func(t *testing.T, src, plan string) {
		r := Scan(Input{Files: map[string]string{"main.tf": src, "x/main.tf": src}, Plan: plan})
		if r == nil {
			t.Fatal("nil report")
		}
		_ = Markdown(r)
		_, _ = SARIF(r)
	})
}

func FuzzConfig(f *testing.F) {
	f.Add("fail_on: HIGH\ncustom_rules:\n  - id: X\n    attribute: tags.owner\n    exists: true\n")
	f.Add("waivers:\n  - rule: TG-*\n    expires: 2020-01-01\n")
	f.Fuzz(func(t *testing.T, cfg string) {
		Scan(Input{Files: map[string]string{"main.tf": `resource "aws_s3_bucket" "b" {}`}, Config: cfg})
	})
}
