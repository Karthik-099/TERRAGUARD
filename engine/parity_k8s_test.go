package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestCheckovK8sParity runs the rules mapped to each Checkov Kubernetes check
// against that check's manifest fixtures. Tests that list resources must
// match exactly; tests that only count must fail the same number. Point
// CKV_SRC at a checkov clone; CKV_REPORT writes the mismatches to a file.
func TestCheckovK8sParity(t *testing.T) {
	src := os.Getenv("CKV_SRC")
	if src == "" {
		t.Skip("set CKV_SRC to a checkov checkout")
	}
	idRE := regexp.MustCompile(`\bid\s*=\s*["'](CKV_K8S_\d+)["']`)
	class := map[string]string{} // CKV id -> check module name
	checks, _ := filepath.Glob(filepath.Join(src, "checkov/kubernetes/checks/resource/k8s/*.py"))
	for _, f := range checks {
		b, _ := os.ReadFile(f)
		if m := idRE.FindSubmatch(b); m != nil {
			class[string(m[1])] = strings.TrimSuffix(filepath.Base(f), ".py")
		}
	}
	importRE := regexp.MustCompile(`from checkov\.kubernetes\.checks\.resource\.k8s\.(\w+) import check`)
	dirRE := regexp.MustCompile(`["']/?(example_\w+)/?["']`)
	setRE := regexp.MustCompile(`(?s)(passing|failing)_resources\s*=\s*\{([^}]*)\}`)
	strRE := regexp.MustCompile(`"([^"]+)"|'([^']+)'`)
	countRE := regexp.MustCompile(`summary\[["']failed["']\]\s*,\s*(\d+)`)
	type fixture struct {
		dir        string
		pass, fail []string
		failCount  int
	}
	fixtures := map[string]fixture{}
	tests, _ := filepath.Glob(filepath.Join(src, "tests/kubernetes/checks/test_*.py"))
	for _, f := range tests {
		b, _ := os.ReadFile(f)
		im, dm := importRE.FindSubmatch(b), dirRE.FindSubmatch(b)
		if im == nil || dm == nil {
			continue
		}
		fx := fixture{dir: filepath.Join(filepath.Dir(f), string(dm[1])), failCount: -1}
		for _, s := range setRE.FindAllSubmatch(b, -1) {
			for _, r := range strRE.FindAllSubmatch(s[2], -1) {
				name := string(r[1]) + string(r[2])
				if string(s[1]) == "passing" {
					fx.pass = append(fx.pass, name)
				} else {
					fx.fail = append(fx.fail, name)
				}
			}
		}
		if c := countRE.FindSubmatch(b); c != nil {
			fx.failCount, _ = strconv.Atoi(string(c[1]))
		}
		fixtures[string(im[1])] = fx
	}

	var ids, report, unmapped []string
	for ckv := range class {
		ids = append(ids, ckv)
	}
	sort.Strings(ids)
	agree, tested := 0, 0
	for _, ckv := range ids {
		fx, ok := fixtures[class[ckv]]
		if !ok || len(fx.pass)+len(fx.fail) == 0 && fx.failCount < 0 {
			continue
		}
		rules := foreignRules[ckv]
		if len(rules) == 0 {
			unmapped = append(unmapped, ckv)
			continue
		}
		files := map[string]string{}
		filepath.WalkDir(fx.dir, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && (strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".json")) {
				b, _ := os.ReadFile(p)
				rel, _ := filepath.Rel(fx.dir, p)
				files[rel] = string(b)
			}
			return nil
		})
		res := Parse(files).Resources
		failed, perFile := map[string]bool{}, map[string]bool{} // fixtures reuse names, even within a file
		for _, f := range Scan(Input{Files: files, Only: rules}).Findings {
			if f.Resource != "" {
				failed[f.Resource] = true
				perFile[k8sOwner(res, f)] = true
			}
		}
		tested++
		var problem string
		if len(fx.pass)+len(fx.fail) > 0 {
			var missed, extra []string
			for _, r := range fx.fail {
				if !failed[r] {
					missed = append(missed, r)
				}
			}
			for _, r := range fx.pass {
				if failed[r] && !listed(fx.fail, r) {
					extra = append(extra, r)
				}
			}
			if len(missed)+len(extra) > 0 {
				problem = fmt.Sprintf("missed=%v extra=%v", missed, extra)
			}
		} else if len(perFile) != fx.failCount {
			var got []string
			for r := range perFile {
				got = append(got, r)
			}
			sort.Strings(got)
			problem = fmt.Sprintf("failed %d, want %d: %v", len(perFile), fx.failCount, got)
		}
		if problem == "" {
			agree++
			continue
		}
		report = append(report, fmt.Sprintf("%s %s %v %s", ckv, class[ckv], rules, problem))
	}
	t.Logf("%d of %d mapped Checkov Kubernetes checks agree with Checkov's fixtures; unmapped: %v", agree, tested, unmapped)
	if out := os.Getenv("CKV_REPORT"); out != "" {
		os.WriteFile(out, []byte(strings.Join(report, "\n")+"\n"), 0o644)
	}
	if os.Getenv("CKV_STRICT") != "" && len(report) > 0 {
		t.Errorf("%d checks disagree:\n%s", len(report), strings.Join(report, "\n"))
	}
}

// k8sOwner names the object a finding belongs to: same file and address, nearest start above the line.
func k8sOwner(rs []*Resource, f Finding) string {
	best := 0
	for _, r := range rs {
		if r.File == f.File && r.Address == f.Resource && r.Line <= f.Line && r.Line > best {
			best = r.Line
		}
	}
	return fmt.Sprintf("%s:%d %s", f.File, best, f.Resource)
}
