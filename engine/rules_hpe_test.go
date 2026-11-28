package engine

import (
	"strings"
	"testing"
)

func hpeScan(src string, id string) []Finding {
	return dbxScan(map[string]string{"main.tf": src}, id)
}

func TestHPERuleSince(t *testing.T) {
	for _, r := range append(append([]Rule{}, hpeRules...), hpeProviderRules...) {
		if ruleIndex[r.ID] == nil || RuleSince(r.ID) != "3.2" {
			t.Errorf("%s: missing from the index or rulesV32", r.ID)
		}
		if r.Category == CatSecurity && len(ThemesFor(r.ID)) == 0 {
			t.Errorf("%s: no compliance themes", r.ID)
		}
	}
	if RuleSince("TG-VAL-026") != "3.2" || RuleSince("TG-VAL-025") != "3.1" {
		t.Error("TG-VAL-026 is 3.2, TG-VAL-025 stays 3.1")
	}
}

func TestHPEProviderChecks(t *testing.T) {
	src := `provider "hpe" {
  morpheus {
    url          = "http://morpheus.corp.internal"
    access_token = "Zr7Lp4Wn8Xk2v9QmTq3c"
    insecure     = true
  }
  opsramp {
    client_id     = "abc"
    client_secret = var.opsramp_secret
  }
}

provider "hpegl" {
  user_secret = "Q9vT2mWx7LpZr4Kn8Bc"
  vmaas {
    allow_insecure = true
  }
}
`
	got := map[string]int{}
	var fixes int
	for _, f := range hpeProviderChecks(Parse(map[string]string{"main.tf": src})) {
		got[f.RuleID]++
		if f.Fix != nil {
			fixes++
			if f.Fix.Value != false || len(f.Fix.Path) != 2 {
				t.Errorf("bad fix %+v", f.Fix)
			}
		}
	}
	want := map[string]int{"TG-HPE-PRV-001": 2, "TG-HPE-PRV-002": 2, "TG-HPE-TLS-002": 1}
	for id, n := range want {
		if got[id] != n {
			t.Errorf("%s: got %d findings, want %d (%v)", id, got[id], n, got)
		}
	}
	if fixes != 2 {
		t.Errorf("want a fix for each insecure flag, got %d", fixes)
	}
	safe := `provider "hpe" {
  morpheus {
    url      = "https://morpheus.corp.internal"
    username = "svc"
    password = "password"
  }
}
`
	if fs := hpeProviderChecks(Parse(map[string]string{"main.tf": safe})); len(fs) != 0 {
		t.Errorf("https, no insecure and a placeholder password: %+v", fs)
	}
}

func TestHPEStateRenameFix(t *testing.T) {
	src := `resource "hpe_morpheus_task_shell_script" "t" {
  name                   = "t"
  # kept comment
  remote_target_password = var.pw
}
`
	fs := hpeScan(src, "TG-HPE-STATE-001")
	if len(fs) != 1 || fs[0].Fix == nil || fs[0].Severity != Medium {
		t.Fatalf("want one MEDIUM finding with a fix, got %+v", fs)
	}
	out, errs := ApplyFixes(map[string]string{"main.tf": src}, []*Fix{fs[0].Fix})
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	fixed := out["main.tf"]
	if !strings.Contains(fixed, "remote_target_password_wo = var.pw") || !strings.Contains(fixed, "# kept comment") || strings.Contains(fixed, "_wo_version") {
		t.Errorf("rename must keep the value and comments and add no deprecated version: %s", fixed)
	}
	if fs := hpeScan(fixed, "TG-HPE-STATE-001"); len(fs) != 0 {
		t.Errorf("fixed file still fires: %+v", fs)
	}
	both := strings.Replace(src, "# kept comment", "remote_target_password_wo = var.pw", 1)
	if fs := hpeScan(both, "TG-HPE-STATE-001"); len(fs) != 1 || fs[0].Fix != nil {
		t.Errorf("with both set, report without a fix: %+v", fs)
	}
	lit := strings.Replace(src, "var.pw", `"Zr7Lp4Wn8Xk2v9QmTq3c"`, 1)
	res := Scan(Input{Files: map[string]string{"main.tf": lit}})
	n := 0
	for _, f := range res.Findings {
		switch f.RuleID {
		case "TG-HPE-STATE-001":
			n++
			if f.Severity != High {
				t.Errorf("a literal is HIGH: %+v", f)
			}
		case "TG-SEC-001", "TG-SECRET-014":
			t.Errorf("superseded by TG-HPE-STATE-001: %+v", f)
		}
	}
	if n != 1 {
		t.Errorf("want one TG-HPE-STATE-001, got %d", n)
	}
}

func TestHPELiteralSecrets(t *testing.T) {
	src := `resource "hpe_morpheus_credential" "c" {
  name     = "c"
  type     = "username-password"
  username = "svc"
  password = "Zr7Lp4Wn8Xk2v9QmTq3c"
}

resource "hpe_opsramp_credential_set" "snmp" {
  name            = "snmp"
  credential_type = "SNMP"
  community       = "Qx8Lm2Vt9Wr4"
}

resource "hpe_morpheus_cypher_secret" "doc" {
  key   = "apipassword"
  value = "password123"
}
`
	res := Scan(Input{Files: map[string]string{"main.tf": src}})
	got := map[string]int{}
	for _, f := range res.Findings {
		got[f.RuleID]++
	}
	if got["TG-HPE-SEC-001"] != 2 || got["TG-SEC-001"] != 0 || got["TG-SECRET-014"] != 0 {
		t.Errorf("want TG-HPE-SEC-001 on the password and community only, nothing generic: %v", got)
	}
}

func TestHPEKeyPairUsesSecretScan(t *testing.T) {
	body := strings.Repeat("Zr7Lp4Wn8Xk2v9QmTq3cBd6Hy1Fs5Jg0", 3)
	real := "resource \"hpe_morpheus_key_pair\" \"k\" {\n  name        = \"k\"\n  private_key = <<-EOT\n    -----BEGIN RSA " + "PRIVATE KEY-----\n    " + body + "\n    -----END RSA " + "PRIVATE KEY-----\n  EOT\n}\n"
	if fs := hpeScan(real, "TG-SECRET-011"); len(fs) != 1 {
		t.Errorf("a real key body is TG-SECRET-011: %+v", fs)
	}
	fake := strings.Replace(real, body, "MIIE...", 1)
	if fs := hpeScan(fake, "TG-SECRET-011"); len(fs) != 0 {
		t.Errorf("a truncated placeholder is not a key: %+v", fs)
	}
}

func TestHPEIdentitySourceDefaults(t *testing.T) {
	ad := `resource "hpe_morpheus_identity_source_active_directory" "ad" {
  name = "ad"
}
resource "hpe_morpheus_identity_source_saml" "s" {
  name = "s"
}
`
	if fs := hpeScan(ad, "TG-HPE-IAM-001"); len(fs) != 1 {
		t.Errorf("unset use_ssl sends useSSL off: %+v", fs)
	}
	if fs := hpeScan(ad, "TG-HPE-IAM-002"); len(fs) != 1 {
		t.Errorf("unset validate_assertion_signature turns checks off: %+v", fs)
	}
	unknown := `resource "hpe_morpheus_identity_source_active_directory" "ad" {
  name    = "ad"
  use_ssl = var.ssl
}
`
	if fs := hpeScan(unknown, "TG-HPE-IAM-001"); len(fs) != 0 {
		t.Errorf("an unknown value is not reported: %+v", fs)
	}
}

func TestHPERouterFirewall(t *testing.T) {
	src := `resource "hpe_morpheus_network_router_firewall_rule" "r" {
  router_id   = 1
  parent_id   = "group-1"
  name        = "rdp"
  direction   = "INGRESS"
  policy      = "accept"
  source_type = "all"
  protocol    = "tcp"
  port_range  = "3389"
}
`
	if fs := hpeScan(src, "TG-HPE-NET-001"); len(fs) != 1 || fs[0].Severity != High {
		t.Errorf("RDP from any source: %+v", fs)
	}
	deny := strings.Replace(src, `"accept"`, `"reject"`, 1)
	if fs := hpeScan(deny, "TG-HPE-NET-001"); len(fs) != 0 {
		t.Errorf("a reject rule is not exposure: %+v", fs)
	}
}

func TestHPEMigration(t *testing.T) {
	src := `data "hpegl_vmaas_morpheus_details" "d" {}
resource "hpegl_metal_host" "h" {
  name = "h"
}
data "hpegl_vmaas_plan" "p" {
  name = "G1-CI-Medium"
}
`
	fs := hpeScan(src, "TG-HPE-MIG-001")
	if len(fs) != 1 || !strings.Contains(fs[0].Message, "hpe_morpheus_service_plan") || fs[0].Severity.Rank() >= High.Rank() || !strings.Contains(fs[0].Message, "tfmigrator") {
		t.Errorf("only the plan data source maps (to hpe_morpheus_service_plan), below the default gate: %+v", fs)
	}
	if n := len(hpeMigration["managed"]) + len(hpeMigration["data"]); n != 43 {
		t.Errorf("the guide lists 14 resources and 29 data sources, table has %d", n)
	}
}

func TestHPEValues(t *testing.T) {
	src := `resource "hpe_morpheus_load_balancer_profile" "p" {
  load_balancer_id = 1
  name             = "p"
  service_type     = "LBClientSslProfile"
  config_client_ssl = {
    ssl_suite = "STRONG"
  }
}
resource "hpe_morpheus_load_balancer_virtual_server" "v" {
  load_balancer_id = 1
  vip_protocol     = var.proto
}
`
	fs := hpeScan(src, "TG-VAL-026")
	if len(fs) != 1 || !fs[0].Blocking || fs[0].Line != 5 {
		t.Errorf("want one blocking finding on the config_client_ssl line: %+v", fs)
	}
}
