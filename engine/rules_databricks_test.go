package engine

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

func dbxScan(files map[string]string, id string) []Finding {
	var out []Finding
	for _, f := range Scan(Input{Files: files}).Findings {
		if f.RuleID == id {
			out = append(out, f)
		}
	}
	return out
}

func TestRuleSince(t *testing.T) {
	for id, want := range map[string]string{
		"TG-DBX-CL-001": "3.1", "TG-VAL-025": "3.1", "TG-SECRET-016": "3.1",
		"TG-NTX-VM-001": "3.0", "TG-AWS-S3-001": "2.0", "TG-AWS-EFS-001": "2.1",
	} {
		if got := RuleSince(id); got != want {
			t.Errorf("RuleSince(%s) = %s, want %s", id, got, want)
		}
	}
	for _, r := range databricksRules {
		if ruleIndex[r.ID] == nil || RuleSince(r.ID) != "3.1" {
			t.Errorf("%s: missing from the index or rulesV31", r.ID)
		}
		if r.Category == CatSecurity && len(ThemesFor(r.ID)) == 0 {
			t.Errorf("%s: no compliance themes", r.ID)
		}
	}
}

func TestDatabricksPolicyDefinition(t *testing.T) {
	src := `resource "databricks_cluster_policy" "p" {
  name = "p"
  definition = jsonencode({
    "autotermination_minutes" : { "type" : "fixed", "value" : 0 },
    "data_security_mode" : { "type" : "fixed", "value" : "NONE" },
    "init_scripts.0.dbfs.destination" : { "type" : "fixed", "value" : "dbfs:/x.sh" },
    "spark_conf.fs.s3a.secret.key" : { "type" : "fixed", "value" : "wZr7Lp4Wn8Xk2v9QmZr7Lp4Wn8Xk2v9QmZr7Lp4W" }
  })
}`
	for _, id := range []string{"TG-DBX-CL-001", "TG-DBX-CL-002", "TG-DBX-CL-004", "TG-DBX-CL-005"} {
		if fs := dbxScan(map[string]string{"main.tf": src}, id); len(fs) != 1 || fs[0].Fix != nil {
			t.Errorf("%s: want one finding without a fix on the policy, got %+v", id, fs)
		}
	}
	allow := strings.ReplaceAll(src, `"fixed", "value" : "NONE"`, `"allowlist", "values" : ["NONE"]`)
	if fs := dbxScan(map[string]string{"main.tf": allow}, "TG-DBX-CL-002"); len(fs) != 0 {
		t.Errorf("an allowlist does not force NONE: %+v", fs)
	}
}

func TestDatabricksSkipsUnknownAndData(t *testing.T) {
	src := `variable "mode" {}
data "databricks_cluster" "c" { autotermination_minutes = 0 }
resource "databricks_cluster" "c" {
  spark_version      = "x"
  data_security_mode = var.mode
  spark_conf         = { "fs.s3a.secret.key" = var.key }
}
resource "databricks_token" "t" { lifetime_seconds = var.ttl }`
	for _, id := range []string{"TG-DBX-CL-001", "TG-DBX-CL-002", "TG-DBX-CL-004", "TG-DBX-TOK-001"} {
		if fs := dbxScan(map[string]string{"main.tf": src}, id); len(fs) != 0 {
			t.Errorf("%s fired on unknown values or a data source: %+v", id, fs)
		}
	}
	if fs := dbxScan(map[string]string{"main.tf": `resource "databricks_cluster" "c" { autotermination_minutes = 0 }`}, "TG-DBX-CL-001"); len(fs) != 1 || fs[0].Fix == nil {
		t.Errorf("want a fixable TG-DBX-CL-001, got %+v", fs)
	}
}

func TestDatabricksTokenSecret(t *testing.T) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	tok := "dapi" + hex.EncodeToString(b) // built at run time: no token in the source
	for name, src := range map[string]string{
		"main.tf":       "provider \"databricks\" {\n  token = \"" + tok + "\"\n}\n",
		"databricks.sh": "export DATABRICKS_TOKEN=" + tok + "-2\n",
	} {
		fs := dbxScan(map[string]string{name: src}, "TG-SECRET-016")
		if len(fs) != 1 || strings.Contains(fs[0].Message, tok[4:]) {
			t.Errorf("%s: want one redacted TG-SECRET-016, got %+v", name, fs)
		}
	}
	short := "dapi" + hex.EncodeToString(b)[:20]
	if fs := dbxScan(map[string]string{"main.tf": "# " + short + "\n"}, "TG-SECRET-016"); len(fs) != 0 {
		t.Errorf("a short dapi string is not a token: %+v", fs)
	}
}
