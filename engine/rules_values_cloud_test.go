package engine

import (
	"strings"
	"testing"
)

func TestCloudValues(t *testing.T) {
	cases := []struct{ name, src, want string }{
		{"azure bad enum", `resource "azurerm_key_vault" "a" { sku_name = "premum" }`, `did you mean "premium"`},
		{"azure name too long", `resource "azurerm_key_vault" "a" { name = "` + strings.Repeat("k", 25) + `" }`, "does not match the pattern"},
		{"google bad enum", `resource "google_compute_firewall" "a" { direction = "INGRES" }`, `did you mean "INGRESS"`},
		{"google nested enum", `resource "google_compute_subnetwork" "a" {
  log_config { aggregation_interval = "INTERVAL_5_SEC" }
  log_config { aggregation_interval = "INTERVAL_2_SEC" }
}`, "log_config.aggregation_interval"},
		{"google name too long", `resource "google_compute_address" "a" { name = "` + strings.Repeat("a", 64) + `" }`, "does not match the pattern"},
		{"valid", `resource "azurerm_key_vault" "a" {
  name     = "kv-prod-01"
  sku_name = "standard"
}
resource "google_compute_firewall" "b" { direction = "EGRESS" }
resource "google_compute_address" "c" { name = "my-address" }`, ""},
		{"unknown", `variable "s" {}` + "\n" + `resource "azurerm_key_vault" "a" { sku_name = var.s }` + "\n" + `resource "google_compute_firewall" "b" { direction = var.s }`, ""},
		{"via variable skips pattern", `variable "p" { default = "" }` + "\n" + `resource "azurerm_key_vault" "a" { name = "${var.p}-` + strings.Repeat("k", 30) + `" }`, ""},
		{"dynamic block", `resource "google_compute_subnetwork" "a" {
  dynamic "log_config" {
    for_each = [1]
    content { aggregation_interval = "bad" }
  }
}`, ""},
	}
	for _, c := range cases {
		var got []string
		for _, r := range Parse(map[string]string{"main.tf": c.src}).Resources {
			for _, rule := range cloudValueRules {
				if rule.applies(r.Type) {
					for _, h := range rule.Check(r) {
						got = append(got, h.Path+": "+h.Msg)
					}
				}
			}
		}
		if c.want == "" {
			if len(got) != 0 {
				t.Errorf("%s: unexpected %v", c.name, got)
			}
			continue
		}
		if len(got) != 1 || !strings.Contains(got[0], c.want) {
			t.Errorf("%s: got %v, want one hit containing %q", c.name, got, c.want)
		}
	}
	for _, r := range cloudValueRules {
		if !r.Blocking || r.Severity != High || r.Category != CatValidate || len(r.Types) == 0 {
			t.Errorf("%s must be blocking, high, validate, with types", r.ID)
		}
	}
}
