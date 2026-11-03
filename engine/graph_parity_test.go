package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestCheckovGraphParity runs each built-in graph policy against the fixture
// Checkov ships for it (tests/terraform/graph/checks/resources/<Name>).
func TestCheckovGraphParity(t *testing.T) {
	src := os.Getenv("CKV_SRC")
	if src == "" {
		t.Skip("set CKV_SRC to a checkov checkout")
	}
	idRE := regexp.MustCompile(`(?m)^\s*id:\s*"?(CKV2?_[A-Z0-9]+_\d+)"?`)
	var report, twins []string
	agree, tested := 0, 0
	files, _ := filepath.Glob(filepath.Join(src, "checkov/terraform/checks/graph_checks/*/*.yaml"))
	sort.Strings(files)
	for _, f := range files {
		b, _ := os.ReadFile(f)
		m := idRE.FindSubmatch(b)
		if m == nil {
			continue
		}
		id := graphIDs[string(m[1])]
		dir := filepath.Join(src, "tests/terraform/graph/checks/resources", strings.TrimSuffix(filepath.Base(f), ".yaml"))
		exp, err := os.ReadFile(filepath.Join(dir, "expected.yaml"))
		if id == "" || err != nil {
			continue
		}
		var want struct{ Pass, Fail []string }
		yaml.Unmarshal(exp, &want)
		tfs := map[string]string{}
		filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(p, ".tf") {
				c, _ := os.ReadFile(p)
				rel, _ := filepath.Rel(dir, p)
				tfs[rel] = pyBoolRE.ReplaceAllStringFunc(string(c), strings.ToLower)
			}
			return nil
		})
		failed := map[string]bool{}
		for _, fd := range Scan(Input{Files: tfs, Only: []string{id}}).Findings {
			failed[strings.TrimPrefix(stripKeys(fd.Resource), "data.")] = true
		}
		if out := os.Getenv("CKV_TWINS"); out != "" && len(want.Pass) > 0 && len(want.Fail) > 0 {
			twins = append(twins, exactTwins(string(m[1]), []string{id}, tfs, want.Pass, want.Fail)...)
		}
		tested++
		var missed, extra []string
		for _, r := range want.Fail {
			if !failed[stripKeys(r)] {
				missed = append(missed, r)
			}
		}
		for _, r := range want.Pass {
			if failed[stripKeys(r)] && !listed(want.Fail, r) {
				extra = append(extra, r)
			}
		}
		if len(missed)+len(extra) == 0 {
			agree++
			continue
		}
		report = append(report, fmt.Sprintf("%s %s %s missed=%v extra=%v", m[1], id, filepath.Base(f), missed, extra))
	}
	t.Logf("%d of %d graph policies agree with Checkov's fixtures", agree, tested)
	if out := os.Getenv("CKV_TWINS"); out != "" {
		sort.Strings(twins)
		os.WriteFile(out, []byte(strings.Join(twins, "\n")+"\n"), 0o644)
	}
	if out := os.Getenv("CKV_REPORT"); out != "" {
		os.WriteFile(out, []byte(strings.Join(report, "\n")+"\n"), 0o644)
	}
}
