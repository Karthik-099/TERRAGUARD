package engine

import (
	"strings"
	"testing"
)

func TestPlaintextPassword(t *testing.T) {
	cases := map[string]bool{
		"#cloud-config\npassword: hunter2-pass\n":                                       true,
		"#cloud-config\nchpasswd:\n  users:\n    - {name: root, password: s3cret-pw}\n": true,
		"#cloud-config\nusers:\n  - name: ops\n    plain_text_passwd: abc123xyz\n":      true,
		"#!/bin/bash\necho 'root:Passw0rd' | chpasswd\n":                                true,
		"<AdministratorPassword><Value>x</Value><PlainText>true</PlainText>":            true,
		"#cloud-config\nusers:\n  - name: ops\n    passwd: $6$rounds=4096$abc$hash\n":   false,
		"#cloud-config\nusers:\n  - lock_passwd: false\n    hashed_passwd: $6$x\n":      false,
		"#cloud-config\npassword: ${admin_password}\nssh_pwauth: false\n":               false,
		"#cloud-config\npassword: {{ vm_password }}\n":                                  false,
		"<AdministratorPassword><Value>eA==</Value><PlainText>false</PlainText>":        false,
		`base64encode(templatefile("init.tpl", { password = var.pw }))`:                 false,
	}
	for text, want := range cases {
		if got := plaintextPassword(text) != ""; got != want {
			t.Errorf("plaintextPassword(%q) = %v, want %v", text, got, want)
		}
	}
}

func TestCapxLiteralPassword(t *testing.T) {
	cases := map[string]bool{
		`[{"type":"basic_auth","data":{"prismCentral":{"username":"admin","password":"pw-123456"}}}]`:             true,
		`[{"type":"basic_auth","data":{"prismCentral":{"username":"${USER}","password":"${NUTANIX_PASSWORD}"}}}]`: false,
		`[{"type":"basic_auth","data":{"prismCentral":{"username":"admin","password":""}}}]`:                      false,
		`not json`: false,
	}
	for doc, want := range cases {
		if got := capxLiteralPassword(doc); got != want {
			t.Errorf("capxLiteralPassword(%q) = %v, want %v", doc, got, want)
		}
	}
}

func TestProviderTLSChecks(t *testing.T) {
	scan := func(src string) []Finding {
		var out []Finding
		for _, f := range Scan(Input{Files: map[string]string{"main.tf": src}}).Findings {
			if f.RuleID == "TG-NTX-PRV-001" || f.RuleID == "TG-VS-PRV-001" {
				out = append(out, f)
			}
		}
		return out
	}
	fs := scan(`provider "nutanix" { insecure = true }
provider "vsphere" { allow_unverified_ssl = true }`)
	if len(fs) != 2 || fs[0].Fix == nil || fs[1].Fix == nil {
		t.Fatalf("want two findings with fixes, got %+v", fs)
	}
	fs = scan(`variable "insecure" { default = true }
provider "nutanix" { insecure = var.insecure }`)
	if len(fs) != 1 || fs[0].Fix != nil || !strings.Contains(fs[0].Message, "var.insecure") {
		t.Errorf("a value from a variable is reported without a fix: %+v", fs)
	}
	fs = scan(`provider "nutanix" { insecure = true }
provider "nutanix" {
  alias    = "dr"
  insecure = true
}`)
	if len(fs) != 2 || fs[0].Fix != nil || fs[1].Fix != nil {
		t.Errorf("two blocks of the same provider get no fix: %+v", fs)
	}
	if fs := scan(`provider "nutanix" { insecure = false }`); len(fs) != 0 {
		t.Errorf("insecure = false fired: %+v", fs)
	}
}

func TestNutanixRulesSkipDataSources(t *testing.T) {
	src := `data "vsphere_host" "h" { name = "esx" }
data "nutanix_virtual_machine" "vm" { boot_type = "UEFI" }`
	for _, f := range Scan(Input{Files: map[string]string{"main.tf": src}}).Findings {
		if strings.HasPrefix(f.RuleID, "TG-VS-") || strings.HasPrefix(f.RuleID, "TG-NTX-") {
			t.Errorf("%s fired on a data source", f.RuleID)
		}
	}
}
