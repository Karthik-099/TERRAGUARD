package engine

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// withRedhatRules registers the Red Hat rules for one test unless the
// catalog already holds them, so it keeps working once they are in Rules.
func withRedhatRules(t *testing.T) {
	t.Helper()
	for _, r := range Rules {
		if r.ID == redhatRules[0].ID {
			return
		}
	}
	saved := Rules
	Rules = concatRules(Rules, redhatRules)
	for i := range redhatRules {
		ruleIndex[redhatRules[i].ID] = &redhatRules[i]
	}
	t.Cleanup(func() {
		Rules = saved
		for _, r := range redhatRules {
			delete(ruleIndex, r.ID)
		}
	})
}

var evalHeaderRE = regexp.MustCompile(`(?m)^#\s*(expect|forbid):\s*(.+)$`)

// TestRedhatEvalCases runs the Red Hat eval cases through Scan, limited to
// the IDs each case names.
func TestRedhatEvalCases(t *testing.T) {
	withRedhatRules(t)
	for _, name := range []string{"openshift_insecure.yaml", "openshift_clean.yaml", "rosa_insecure.tf", "rosa_clean.tf", "redhat_aro_insecure.tf", "redhat_aro_clean.tf"} {
		b, err := os.ReadFile(filepath.Join("..", "evals", "cases", name))
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]bool{} // id -> must fire
		var only []string
		for _, m := range evalHeaderRE.FindAllStringSubmatch(string(b), -1) {
			for _, id := range strings.Split(m[2], ",") {
				id = strings.TrimSpace(id)
				want[id] = m[1] == "expect"
				only = append(only, id)
			}
		}
		rep := Scan(Input{Files: map[string]string{name: string(b)}, Only: only})
		got := map[string]bool{}
		for _, f := range rep.Findings {
			got[f.RuleID] = true
		}
		for id, expect := range want {
			if got[id] != expect {
				t.Errorf("%s: %s fired=%v, want %v (errors %v)", name, id, got[id], expect, rep.Errors)
			}
		}
	}
}

func TestRedhatRuleMessages(t *testing.T) {
	src := `apiVersion: security.openshift.io/v1
kind: SecurityContextConstraints
metadata: {name: x}
allowHostNetwork: true
allowHostIPC: true
---
apiVersion: authorization.openshift.io/v1
kind: ClusterRoleBinding
metadata: {name: legacy}
roleRef: {name: edit}
groupNames: ["system:unauthenticated"]
---
apiVersion: image.openshift.io/v1
kind: ImageStream
metadata:
  name: is
  annotations: {openshift.io/image.insecureRepository: "true"}
`
	withRedhatRules(t)
	rep := Scan(Input{Files: map[string]string{"ocp.yaml": src}, Only: []string{"TG-OCP-*"}})
	count := map[string]int{}
	for _, f := range rep.Findings {
		count[f.RuleID]++
		if f.Line == 0 {
			t.Errorf("%s has no line", f.RuleID)
		}
	}
	if count["TG-OCP-SCC-002"] != 2 || count["TG-OCP-RBAC-001"] != 1 || count["TG-OCP-IS-001"] != 1 {
		t.Errorf("counts: %v", count)
	}
}

// TestRedhatUnknownValues: values decided by variables must not fire.
func TestRedhatUnknownValues(t *testing.T) {
	src := `variable "private" {}
variable "fips" {}
variable "azs" {}
resource "rhcs_cluster_rosa_hcp" "prod" {
  name               = "prod"
  private            = var.private
  fips               = var.fips
  availability_zones = var.azs
}
`
	withRedhatRules(t)
	for _, f := range Scan(Input{Files: map[string]string{"main.tf": src}, Only: []string{"TG-RHCS-*"}}).Findings {
		t.Errorf("unexpected %s: %s", f.RuleID, f.Message)
	}
}

func TestRosaProd(t *testing.T) {
	for name, want := range map[string]bool{"payments-prod": true, "prod": true, "production-eu": true, "nonprod": false, "non-prod-1": false, "preprod": false, "product-catalog": false, "dev": false} {
		if got := rosaProd(&Resource{Attrs: map[string]any{"name": name}}); got != want {
			t.Errorf("%s: %v, want %v", name, got, want)
		}
	}
}

// TestRedhatCorpus scans a folder of real manifests and modules with only the
// Red Hat rules and logs every finding, to review for false positives:
// REDHAT_CORPUS=<dir> go test ./engine -run RedhatCorpus -v
func TestRedhatCorpus(t *testing.T) {
	dir := os.Getenv("REDHAT_CORPUS")
	if dir == "" {
		t.Skip("set REDHAT_CORPUS to a folder of manifests or modules")
	}
	withRedhatRules(t)
	files := map[string]string{}
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && IsScannable(p) {
			if b, err := os.ReadFile(p); err == nil && len(b) < 1<<20 {
				files[p] = string(b)
			}
		}
		return nil
	})
	var only []string
	for _, r := range redhatRules {
		only = append(only, r.ID)
	}
	rep := Scan(Input{Files: files, Only: only})
	for _, f := range rep.Findings {
		t.Logf("%s %s:%d %s", f.RuleID, f.File, f.Line, f.Message)
	}
	t.Logf("%d files, %d findings", len(files), len(rep.Findings))
}
