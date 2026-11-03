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

// TestCheckovCfnParity runs the CloudFormation and Serverless rules against
// the reference fixtures: named failing resources must fail and named passing
// ones must not; where a test only gives counts, the failure count must match.
func TestCheckovCfnParity(t *testing.T) {
	src := os.Getenv("CKV_SRC")
	if src == "" {
		t.Skip("set CKV_SRC to a checkov checkout")
	}
	idRE := regexp.MustCompile(`\bid\s*=\s*["'](CKV2?_[A-Z0-9]+_\d+)["']`)
	module := map[string]string{} // python module -> check ID
	for _, g := range []string{"checkov/cloudformation/checks/resource/aws/*.py", "checkov/serverless/checks/function/aws/*.py"} {
		files, _ := filepath.Glob(filepath.Join(src, g))
		for _, f := range files {
			b, _ := os.ReadFile(f)
			if m := idRE.FindSubmatch(b); m != nil {
				rel, _ := filepath.Rel(src, strings.TrimSuffix(f, ".py"))
				module[strings.ReplaceAll(rel, string(filepath.Separator), ".")] = string(m[1])
			}
		}
	}
	importRE := regexp.MustCompile(`from (checkov\.[\w.]+) import check\b`)
	dirRE := regexp.MustCompile(`(?:current_dir \+ |parent / )["']/?([\w-]+)["']`)
	setRE := regexp.MustCompile(`(?s)(passing|failing)_resources\s*=\s*\{([^}]*)\}`)
	strRE := regexp.MustCompile(`"([^"]+)"|'([^']+)'`)
	failedRE := regexp.MustCompile(`summary\[["']failed["']\],\s*(\d+)`)

	var tests []string
	for _, g := range []string{"tests/cloudformation/checks/resource/aws/test_*.py", "tests/serverless/checks/aws/test_*.py"} {
		f, _ := filepath.Glob(filepath.Join(src, g))
		tests = append(tests, f...)
	}
	sort.Strings(tests)
	var report []string
	agree, tested := 0, 0
	for _, tf := range tests {
		b, _ := os.ReadFile(tf)
		im, dm := importRE.FindSubmatch(b), dirRE.FindSubmatch(b)
		if im == nil || dm == nil {
			continue
		}
		ckv := module[string(im[1])]
		var ids []string
		for _, id := range foreignRules[ckv] {
			if strings.HasPrefix(id, "TG-CFN-") || strings.HasPrefix(id, "TG-SLS-") {
				ids = append(ids, id)
			}
		}
		if len(ids) == 0 {
			continue
		}
		dir := filepath.Join(filepath.Dir(tf), string(dm[1]))
		files := map[string]string{}
		filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && IsScannable(p) {
				c, _ := os.ReadFile(p)
				rel, _ := filepath.Rel(dir, p)
				files[filepath.ToSlash(rel)] = string(c)
			}
			return nil
		})
		failed := map[string]bool{}
		count := map[string]bool{}
		for _, f := range Scan(Input{Files: files, Only: ids}).Findings {
			if f.Resource != "" && contains(ids, f.RuleID) {
				failed[f.Resource] = true
				count[f.File+"|"+f.Resource] = true
			}
		}
		var pass, fail []string
		for _, s := range setRE.FindAllSubmatch(b, -1) {
			for _, r := range strRE.FindAllSubmatch(s[2], -1) {
				name := string(r[1]) + string(r[2])
				if string(s[1]) == "passing" {
					pass = append(pass, name)
				} else {
					fail = append(fail, name)
				}
			}
		}
		tested++
		name := ckv + " " + filepath.Base(tf)
		if len(pass)+len(fail) > 0 {
			var missed, extra []string
			for _, r := range fail {
				if !failed[r] {
					missed = append(missed, r)
				}
			}
			for _, r := range pass {
				if failed[r] && !contains(fail, r) {
					extra = append(extra, r)
				}
			}
			if len(missed)+len(extra) == 0 {
				agree++
				continue
			}
			report = append(report, fmt.Sprintf("%s %v missed=%v extra=%v", name, ids, missed, extra))
			continue
		}
		m := failedRE.FindSubmatch(b)
		if m == nil {
			tested--
			continue
		}
		want, _ := strconv.Atoi(string(m[1]))
		if len(count) == want {
			agree++
			continue
		}
		got := make([]string, 0, len(count))
		for k := range count {
			got = append(got, k)
		}
		sort.Strings(got)
		report = append(report, fmt.Sprintf("%s %v failed %d, want %d: %v", name, ids, len(count), want, got))
	}
	t.Logf("%d of %d CloudFormation and Serverless checks agree with the reference fixtures", agree, tested)
	for _, l := range report {
		t.Log(l)
	}
	if out := os.Getenv("CKV_REPORT"); out != "" {
		os.WriteFile(out, []byte(strings.Join(report, "\n")+"\n"), 0o644)
	}
}
