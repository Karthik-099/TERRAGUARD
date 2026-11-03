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

// TestARMParity runs each ARM rule mapped to a reference check against that
// check's fixtures. Set CKV_SRC to the checkout; CKV_REPORT writes mismatches.
func TestARMParity(t *testing.T) {
	src := os.Getenv("CKV_SRC")
	if src == "" {
		t.Skip("set CKV_SRC to a checkov checkout")
	}
	idRE := regexp.MustCompile(`\bid\s*=\s*["'](CKV2?_[A-Z0-9]+_\d+)["']`)
	importRE := regexp.MustCompile(`from checkov\.arm\.checks\.(resource|parameter)\.(\w+) import check`)
	dirRE := regexp.MustCompile(`current_dir\s*(?:\+\s*|,\s*)["']/?([\w-]+)/?["']`)
	setRE := regexp.MustCompile(`(?s)(passing|failing)_resources\s*=\s*\{([^}]*)\}`)
	strRE := regexp.MustCompile(`"([^"]+)"|'([^']+)'`)
	countRE := regexp.MustCompile(`summary\[['"](passed|failed|skipped)['"]\],\s*(\d+)`)

	tests, _ := filepath.Glob(filepath.Join(src, "tests/arm/checks/*/test_*.py"))
	sort.Strings(tests)
	var report []string
	agree, tested := 0, 0
	for _, f := range tests {
		b, _ := os.ReadFile(f)
		im, dm := importRE.FindSubmatch(b), dirRE.FindSubmatch(b)
		if im == nil || dm == nil {
			continue
		}
		cb, err := os.ReadFile(filepath.Join(src, "checkov/arm/checks", string(im[1]), string(im[2])+".py"))
		idm := idRE.FindSubmatch(cb)
		if err != nil || idm == nil {
			continue
		}
		ckv := string(idm[1])
		var rules []string
		for _, id := range foreignRules[ckv] {
			if strings.HasPrefix(id, "TG-ARM-") {
				rules = append(rules, id)
			}
		}
		if len(rules) == 0 {
			continue
		}
		dir := filepath.Join(filepath.Dir(f), string(dm[1]))
		files := map[string]string{}
		filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(p, ".json") {
				b, _ := os.ReadFile(p)
				rel, _ := filepath.Rel(dir, p)
				files[rel] = string(b)
			}
			return nil
		})
		if len(files) == 0 {
			continue
		}
		failed := map[string]bool{}
		for _, fd := range Scan(Input{Files: files, Only: rules}).Findings {
			if fd.Resource != "" {
				failed[fd.File+":"+armKey(fd.Resource)] = true
			}
		}
		var pass, fail []string
		for _, s := range setRE.FindAllSubmatch(b, -1) {
			for _, r := range strRE.FindAllSubmatch(s[2], -1) {
				if string(s[1]) == "passing" {
					pass = append(pass, armKey(string(r[1])+string(r[2])))
				} else {
					fail = append(fail, armKey(string(r[1])+string(r[2])))
				}
			}
		}
		hit := func(k string) bool {
			for fk := range failed {
				if strings.HasSuffix(fk, ":"+k) {
					return true
				}
			}
			return false
		}
		var problem string
		if len(pass)+len(fail) > 0 {
			var missed, extra []string
			for _, k := range fail {
				if !hit(k) {
					missed = append(missed, k)
				}
			}
			for _, k := range pass {
				if hit(k) && !contains(fail, k) {
					extra = append(extra, k)
				}
			}
			if len(missed)+len(extra) > 0 {
				problem = fmt.Sprintf("missed=%v extra=%v", missed, extra)
			}
		} else {
			want := map[string]int{}
			for _, m := range countRE.FindAllSubmatch(b, -1) {
				want[string(m[1])], _ = strconv.Atoi(string(m[2]))
			}
			applicable := 0
			for _, r := range Parse(files).Resources {
				for _, id := range rules {
					if rl := ruleIndex[id]; rl != nil && rl.applies(r.Type) {
						applicable++
						break
					}
				}
			}
			gotFail := len(failed)
			if gotFail != want["failed"]+want["skipped"] || applicable-gotFail < want["passed"] {
				problem = fmt.Sprintf("failed=%d want %d, passed=%d want %d", gotFail, want["failed"]+want["skipped"], applicable-gotFail, want["passed"])
			}
		}
		tested++
		if problem == "" {
			agree++
			continue
		}
		report = append(report, fmt.Sprintf("%s %v %s", ckv, rules, problem))
	}
	t.Logf("%d of %d mapped ARM checks agree with the reference fixtures", agree, tested)
	if out := os.Getenv("CKV_REPORT"); out != "" {
		os.WriteFile(out, []byte(strings.Join(report, "\n")+"\n"), 0o644)
	}
}

// armKey reduces "Type.name" to the last type and name segments, since nested
// children are named by their full path here and by their short name there.
func armKey(addr string) string {
	cut := strings.Index(addr, ".")
	if slash := strings.Index(addr, "/"); slash >= 0 {
		cut = slash + strings.Index(addr[slash:], ".")
	}
	if cut < 0 {
		return strings.ToLower(addr)
	}
	typ, name := addr[:cut], addr[cut+1:]
	return strings.ToLower(typ[strings.LastIndex(typ, "/")+1:] + "." + name[strings.LastIndex(name, "/")+1:])
}
