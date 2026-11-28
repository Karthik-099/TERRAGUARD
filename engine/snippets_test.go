package engine

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func TestIsSnippet(t *testing.T) {
	yes := []string{
		"examples/provider/provider.tf",
		"examples/resources/hpe_morpheus_key_pair/resource.tf",
		"examples/data-sources/morpheus_cluster/example-id.tf",
		"examples/functions/parse_id/function.tf",
		"examples/ephemeral-resources/hpe_token/ephemeral-resource.tf",
		"examples/actions/hpe_power/action.tf",
		"terraform-provider-hpe/examples/resources/x/example-name.tf",
		`examples\resources\x\a.tf`,
	}
	no := []string{
		"examples/e2e/main.tf",
		"examples/e2e/resources/x/main.tf",
		"examples/complete/main.tf",
		"examples/complete/data-sources/x.tf",
		"examples/resources/x.tf",                  // no type folder
		"examples/resources/x/nested/a.tf",         // deeper than the layout
		"examples/provider/nested/provider.tf",     // provider has no type folder
		"examples/resources/x/terraform.tfvars",    // not a .tf file
		"examples/resources/x/import.sh",           // not a .tf file
		"modules/resources/x/main.tf",              // no examples segment
		"examples-old/resources/x/main.tf",         // not the examples segment
		"examples/vmaas/data-sources/hpegl_x/a.tf", // not the tfplugindocs layout
		"examples/resources/x/example.tf.json",     // tfplugindocs reads .tf only
		"examples/resources",                       // a folder
		"resources/x/main.tf",                      // no examples segment
		"main.tf",
	}
	for _, f := range yes {
		if !IsSnippet(f) {
			t.Errorf("IsSnippet(%q) = false, want true", f)
		}
	}
	for _, f := range no {
		if IsSnippet(f) {
			t.Errorf("IsSnippet(%q) = true, want false", f)
		}
	}
}

func reportIDs(rep *Report) map[string]int {
	got := map[string]int{}
	for _, f := range rep.Findings {
		got[f.RuleID]++
	}
	return got
}

// Two alternative snippets in one folder: each is its own scope.
func TestSnippetScope(t *testing.T) {
	alt := `data "hpe_morpheus_cluster" "example" {
  name = var.cluster_name
}
`
	files := func(dir string) map[string]string {
		return map[string]string{dir + "/example-id.tf": alt, dir + "/example-name.tf": alt}
	}
	snip := reportIDs(Scan(Input{Files: files("examples/data-sources/morpheus_cluster")}))
	for _, id := range []string{"TG-VAL-002", "TG-VAL-003", "TG-TF-008", "TG-STATE-003"} {
		if snip[id] > 0 {
			t.Errorf("snippet folder: unexpected %s", id)
		}
	}
	for name, in := range map[string]Input{
		"module path":  {Files: files("modules/cluster")},
		"snippets off": {Files: files("examples/data-sources/morpheus_cluster"), Snippets: "off"},
		"policy off":   {Files: files("examples/data-sources/morpheus_cluster"), Config: "snippets: off\n"},
		"e2e example":  {Files: files("examples/e2e")},
	} {
		got := reportIDs(Scan(in))
		if got["TG-VAL-002"] == 0 || got["TG-VAL-003"] == 0 {
			t.Errorf("%s: want TG-VAL-002 and TG-VAL-003, got %v", name, got)
		}
	}
	if got := reportIDs(Scan(Input{Files: files("modules/cluster"), Snippets: "on"})); got["TG-VAL-002"] > 0 {
		t.Errorf("snippets on: unexpected TG-VAL-002")
	}

	// A duplicate inside one snippet file is still an error, and value and
	// security checks still run on snippets.
	one := `resource "aws_vpc" "a" {
  cidr_block = "10.0.0.1/16"
}
resource "aws_vpc" "a" {
  cidr_block = "10.0.0.0/16"
}
provider "aws" {
  secret_key = "literal-value-here"
}
`
	got := reportIDs(Scan(Input{Files: map[string]string{"examples/resources/aws_vpc/resource.tf": one}}))
	for _, id := range []string{"TG-VAL-002", "TG-VAL-004", "TG-SEC-001"} {
		if got[id] == 0 {
			t.Errorf("single snippet: want %s, got %v", id, got)
		}
	}

	if _, err := ParseConfig("snippets: maybe\n"); err == nil {
		t.Error("snippets: maybe should be rejected")
	}
}

// A snippet that elides arguments with "# ..." gets no missing-argument finding.
func TestSnippetElidedArguments(t *testing.T) {
	scan := func(file, body string) map[string]int {
		return reportIDs(Scan(Input{Files: map[string]string{file: "resource \"aws_s3_bucket_policy\" \"x\" {\n" + body + "}\n"}}))
	}
	const own = "examples/resources/aws_s3_bucket_policy/resource.tf"
	if got := scan(own, "  # ... bucket and policy ...\n"); got["TG-SCHEMA-002"] > 0 {
		t.Errorf("elided snippet: unexpected TG-SCHEMA-002")
	}
	if got := scan(own, "  tags = {}\n"); got["TG-SCHEMA-002"] == 0 {
		t.Errorf("documented type without elision: want TG-SCHEMA-002, got %v", got)
	}
	if got := scan("examples/data-sources/tls_certificate/data-source.tf", "  tags = {}\n"); got["TG-SCHEMA-002"] > 0 {
		t.Errorf("context resource in a snippet: unexpected TG-SCHEMA-002")
	}
	if got := scan("modules/policy/main.tf", "  tags = {}\n"); got["TG-SCHEMA-002"] == 0 {
		t.Errorf("module: want TG-SCHEMA-002, got %v", got)
	}
}

func TestSec002NeedsRealKeyBody(t *testing.T) {
	header := "-----BEGIN RSA " + "PRIVATE KEY-----"
	footer := "-----END RSA " + "PRIVATE KEY-----"
	raw := make([]byte, 144)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	b := base64.StdEncoding.EncodeToString(raw) // 192 characters
	realKey := header + "\n" + b[:64] + "\n" + b[64:128] + "\n" + b[128:] + "\n" + footer
	sec002 := func(key string) int {
		src := "resource \"hpe_morpheus_key_pair\" \"k\" {\n  private_key = <<EOT\n" + key + "\nEOT\n}\n"
		n := 0
		for _, f := range secretChecks(Parse(map[string]string{"examples/resources/morpheus_key_pair/resource.tf": src})) {
			if f.RuleID == "TG-SEC-002" {
				n++
			}
		}
		return n
	}
	for name, key := range map[string]string{
		"truncated": header + "\nMIIEpAIBAAKCAQEA...\n-----END...",
		"words":     header + "\nYOUR_PRIVATE_KEY_HERE\n" + footer,
		"inline":    strings.ReplaceAll(header+`\n...\n`+footer, "\n", ""),
	} {
		if n := sec002(key); n != 0 {
			t.Errorf("%s placeholder: got %d TG-SEC-002, want 0", name, n)
		}
	}
	if n := sec002(realKey); n != 1 {
		t.Errorf("real key: got %d TG-SEC-002, want 1", n)
	}
	if n := sec002(header + `\n` + b[:64] + `\n` + footer); n != 1 {
		t.Errorf("real key on one line: got %d TG-SEC-002, want 1", n)
	}
}
