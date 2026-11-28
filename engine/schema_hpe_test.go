package engine

import (
	"strings"
	"testing"
)

func TestBundledHPESchemas(t *testing.T) {
	code := `resource "hpe_morpheus_group" "bad" {
  name     = "g"
  locaton  = "dc1"
}

resource "hpe_morpheus_group" "good" {
  name     = "g"
  location = "dc1"
}

resource "hpegl_caas_cluster" "bad" {
  name         = "c"
  blueprint_id = "b"
  site_id      = "s"
  space_id     = "x"
  spcae        = "x"
}
`
	r := Scan(Input{Files: map[string]string{"main.tf": code}})
	got := map[string][]string{}
	for _, f := range r.Findings {
		if strings.HasPrefix(f.RuleID, "TG-SCHEMA") {
			got[f.Resource] = append(got[f.Resource], f.RuleID+" "+f.Message)
		}
	}
	if len(got["hpe_morpheus_group.good"]) > 0 {
		t.Errorf("false positive: %v", got["hpe_morpheus_group.good"])
	}
	if want := `TG-SCHEMA-001 hpe_morpheus_group does not support argument "locaton". Did you mean "location"?`; len(got["hpe_morpheus_group.bad"]) != 1 || got["hpe_morpheus_group.bad"][0] != want {
		t.Errorf("hpe typo: got %v", got["hpe_morpheus_group.bad"])
	}
	if len(got["hpegl_caas_cluster.bad"]) != 1 {
		t.Errorf("hpegl typo: got %v", got["hpegl_caas_cluster.bad"])
	}
	// The registry source is case-insensitive; an older major turns the bundled schema off.
	pinned := "terraform {\n  required_providers {\n    hpe = { source = \"HPE/hpe\", version = \"~> 1.0\" }\n  }\n}\n"
	if n := ids(Scan(Input{Files: map[string]string{"main.tf": code, "versions.tf": pinned}}))["TG-SCHEMA-001"]; n != 1 {
		t.Errorf("hpe pinned to 1.x should only leave the hpegl finding, got %d", n)
	}
}
