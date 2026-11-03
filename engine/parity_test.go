package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestCheckovParity runs every rule that maps to a Checkov ID against that
// check's own fixtures: the resources Checkov expects to fail must fail here
// and the ones it expects to pass must not. Point CKV_SRC at a checkov clone;
// CKV_REPORT writes the mismatches to a file.
func TestCheckovParity(t *testing.T) {
	src := os.Getenv("CKV_SRC")
	if src == "" {
		t.Skip("set CKV_SRC to a checkov checkout")
	}
	idRE := regexp.MustCompile(`\bid\s*=\s*["'](CKV2?_[A-Z0-9]+_\d+)["']`)
	module := map[string]string{} // CKV id -> provider/Class
	checks, _ := filepath.Glob(filepath.Join(src, "checkov/terraform/checks/resource/*/*.py"))
	for _, f := range checks {
		b, _ := os.ReadFile(f)
		if m := idRE.FindSubmatch(b); m != nil {
			module[string(m[1])] = filepath.Base(filepath.Dir(f)) + "/" + strings.TrimSuffix(filepath.Base(f), ".py")
		}
	}
	importRE := regexp.MustCompile(`from checkov\.terraform\.checks\.resource\.(\w+)\.(\w+) import check`)
	dirRE := regexp.MustCompile(`["']/?(example_\w+)/?["']`)
	setRE := regexp.MustCompile(`(?s)(passing|failing)_resources\s*=\s*\{([^}]*)\}`)
	strRE := regexp.MustCompile(`"([^"]+)"|'([^']+)'`)
	type fixture struct {
		dir        string
		pass, fail []string
	}
	fixtures := map[string]fixture{}
	tests, _ := filepath.Glob(filepath.Join(src, "tests/terraform/checks/resource/*/test_*.py"))
	for _, f := range tests {
		b, _ := os.ReadFile(f)
		im, dm := importRE.FindSubmatch(b), dirRE.FindSubmatch(b)
		if im == nil || dm == nil {
			continue
		}
		fx := fixture{dir: filepath.Join(filepath.Dir(f), string(dm[1]))}
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
		fixtures[string(im[1])+"/"+string(im[2])] = fx
	}

	var report, dups, twins []string
	agree, tested := 0, 0
	ids := make([]string, 0, len(foreignRules))
	for ckv := range foreignRules {
		ids = append(ids, ckv)
	}
	sort.Strings(ids)
	only := map[string]bool{} // CKV_ONLY: a file listing the Checkov IDs to test
	if f := os.Getenv("CKV_ONLY"); f != "" {
		b, _ := os.ReadFile(f)
		for _, id := range regexp.MustCompile(`CKV2?_[A-Z0-9]+_\d+`).FindAllString(string(b), -1) {
			only[id] = true
		}
	}
	for _, ckv := range ids {
		if len(only) > 0 && !only[ckv] {
			continue
		}
		fx, ok := fixtures[module[ckv]]
		if !ok || len(fx.fail)+len(fx.pass) == 0 {
			continue
		}
		files := map[string]string{}
		filepath.WalkDir(fx.dir, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(p, ".tf") {
				b, _ := os.ReadFile(p)
				rel, _ := filepath.Rel(fx.dir, p)
				// Checkov's fixtures sometimes write Python booleans, which Terraform rejects.
				files[rel] = pyBoolRE.ReplaceAllStringFunc(string(b), strings.ToLower)
			}
			return nil
		})
		rules := foreignRules[ckv]
		if out := os.Getenv("CKV_TWINS"); out != "" && len(fx.pass) > 0 && len(fx.fail) > 0 {
			twins = append(twins, exactTwins(ckv, rules, files, fx.pass, fx.fail)...)
		}
		if id, ok := parityIDs[ckv]; ok {
			if dup := duplicateOf(files, id); dup != "" {
				dups = append(dups, ckv+" "+dup)
			}
		}
		failed := map[string]bool{}
		for _, f := range Scan(Input{Files: files, Only: rules}).Findings {
			if f.Resource != "" {
				failed[stripKeys(f.Resource)] = true
			}
		}
		tested++
		var missed, extra []string
		for _, r := range fx.fail {
			if !failed[stripKeys(r)] {
				missed = append(missed, r)
			}
		}
		for _, r := range fx.pass {
			if failed[stripKeys(r)] && !listed(fx.fail, r) {
				extra = append(extra, r)
			}
		}
		if len(missed)+len(extra) == 0 {
			agree++
			continue
		}
		report = append(report, fmt.Sprintf("%s %v missed=%v extra=%v", ckv, rules, missed, extra))
	}
	t.Logf("%d of %d mapped Checkov checks agree with Checkov's fixtures", agree, tested)
	if out := os.Getenv("CKV_REPORT"); out != "" {
		os.WriteFile(out, []byte(strings.Join(report, "\n")+"\n"), 0o644)
	}
	if out := os.Getenv("CKV_TWINS"); out != "" {
		sort.Strings(twins)
		os.WriteFile(out, []byte(strings.Join(twins, "\n")+"\n"), 0o644)
	}
	if out := os.Getenv("CKV_DUPS"); out != "" {
		sort.Strings(dups)
		os.WriteFile(out, []byte(strings.Join(dups, "\n")+"\n"), 0o644)
	}
	if os.Getenv("CKV_STRICT") != "" && len(report) > 0 {
		t.Errorf("%d checks disagree:\n%s", len(report), strings.Join(report, "\n"))
	}
}

var pyBoolRE = regexp.MustCompile(`\b(True|False)\b`)

func listed(l []string, s string) bool {
	for _, x := range l {
		if stripKeys(x) == stripKeys(s) {
			return true
		}
	}
	return false
}

// duplicateOf names a hand-written rule that flags exactly the same
// resources and lines as the generated rule id on these files.
func duplicateOf(files map[string]string, id string) string {
	hits := map[string][]string{}
	for _, f := range Scan(Input{Files: files}).Findings {
		hits[f.RuleID] = append(hits[f.RuleID], fmt.Sprintf("%s:%d", f.Resource, f.Line))
	}
	want := strings.Join(hits[id], ",")
	if want == "" {
		return ""
	}
	for rid, h := range hits {
		if rid != id && !isParity(rid) && strings.Join(h, ",") == want {
			return rid
		}
	}
	return ""
}

func isParity(id string) bool {
	for _, p := range parityIDs {
		if p == id {
			return true
		}
	}
	return false
}

// exactTwins lists other rules that reproduce a Checkov fixture exactly:
// they fail every expected failure and pass every expected pass, which
// distinct controls almost never do. Those are double reports.
func exactTwins(ckv string, mapped []string, files map[string]string, pass, fail []string) []string {
	hits := map[string]map[string]bool{}
	for _, f := range Scan(Input{Files: files, NoBuiltinSchema: true}).Findings {
		if hits[f.RuleID] == nil {
			hits[f.RuleID] = map[string]bool{}
		}
		hits[f.RuleID][stripKeys(f.Resource)] = true
	}
	var out []string
	for rid, h := range hits {
		if listed(mapped, rid) {
			continue
		}
		ok := true
		for _, r := range fail {
			ok = ok && h[stripKeys(r)]
		}
		for _, r := range pass {
			ok = ok && !h[stripKeys(r)]
		}
		if ok {
			out = append(out, fmt.Sprintf("%s mapped=%v twin=%s", ckv, mapped, rid))
		}
	}
	return out
}
