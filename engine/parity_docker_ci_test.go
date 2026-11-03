package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestCheckovParityDockerCI runs the Dockerfile, Azure Pipelines and GitHub
// Actions rules mapped to Checkov IDs against Checkov's own fixtures.
func TestCheckovParityDockerCI(t *testing.T) {
	src := os.Getenv("CKV_SRC")
	if src == "" {
		t.Skip("set CKV_SRC to a checkov checkout")
	}
	idRE := regexp.MustCompile(`\bid\s*[=:]\s*["'](CKV2?_[A-Z0-9]+_\d+)["']`)
	idOf := func(f string) string {
		b, _ := os.ReadFile(f)
		if m := idRE.FindSubmatch(b); m != nil {
			return string(m[1])
		}
		return ""
	}
	setRE := regexp.MustCompile(`(?s)(passing|failing)_resources\s*=\s*\{([^}]*)\}`)
	strRE := regexp.MustCompile(`"([^"]+)"|'([^']+)'`)
	sets := func(f string) (pass, fail []string) {
		b, _ := os.ReadFile(f)
		for _, s := range setRE.FindAllSubmatch(b, -1) {
			for _, r := range strRE.FindAllSubmatch(s[2], -1) {
				if string(s[1]) == "passing" {
					pass = append(pass, string(r[1])+string(r[2]))
				} else {
					fail = append(fail, string(r[1])+string(r[2]))
				}
			}
		}
		return
	}
	failedIn := func(files map[string]string, rules []string) map[string]bool {
		out := map[string]bool{}
		for _, f := range Scan(Input{Files: files, Only: rules, NoBuiltinSchema: true}).Findings {
			out[f.File] = true
			out[f.Resource] = true
		}
		return out
	}
	var report []string
	agree, tested := 0, 0
	compare := func(ckv string, wantFail, wantPass map[string]bool, got map[string]bool) {
		tested++
		var missed, extra []string
		for k := range wantFail {
			if !got[k] {
				missed = append(missed, k)
			}
		}
		for k := range wantPass {
			if got[k] && !wantFail[k] {
				extra = append(extra, k)
			}
		}
		if len(missed)+len(extra) == 0 {
			agree++
			return
		}
		report = append(report, fmt.Sprintf("%s %v missed=%v extra=%v", ckv, foreignRules[ckv], missed, extra))
	}

	// Dockerfile: resources are /<dir>/Dockerfile.<INSTRUCTION>; compare per file.
	tests, _ := filepath.Glob(filepath.Join(src, "tests/dockerfile/checks/test_*.py"))
	for _, f := range tests {
		name := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), "test_"), ".py")
		ckv := idOf(filepath.Join(src, "checkov/dockerfile/checks", name+".py"))
		if ckv == "" || foreignRules[ckv] == nil {
			continue
		}
		pass, fail := sets(f)
		files := map[string]string{}
		wantFail, wantPass := map[string]bool{}, map[string]bool{}
		for _, r := range append(pass, fail...) {
			file := strings.TrimPrefix(r[:strings.LastIndex(r, ".")], "/")
			b, err := os.ReadFile(filepath.Join(filepath.Dir(f), "example_"+name, file))
			if err != nil {
				continue
			}
			files[file] = string(b)
			if listed(fail, r) {
				wantFail[file] = true
			} else {
				wantPass[file] = true
			}
		}
		compare(ckv, wantFail, wantPass, failedIn(files, foreignRules[ckv]))
	}

	// Azure Pipelines: resources are jobs[i](name) or stages[i](name).jobs[j](name)[.steps[k]].
	jobRE := regexp.MustCompile(`^(?:stages\[(\d+)\]\([^)]*\)\.)?jobs\[(\d+)\]`)
	tests, _ = filepath.Glob(filepath.Join(src, "tests/azure_pipelines/checks/jobs/test_*.py"))
	for _, f := range tests {
		name := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), "test_"), ".py")
		ckv := idOf(filepath.Join(src, "checkov/azure_pipelines/checks/job", name+".py"))
		if ckv == "" || foreignRules[ckv] == nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(filepath.Dir(f), "example_"+name, "azure-pipelines.yml"))
		if err != nil {
			continue
		}
		docs, _ := decodeYAMLDocs(string(b))
		if len(docs) == 0 {
			continue
		}
		jobAt := func(r string) string {
			m := jobRE.FindStringSubmatch(r)
			if m == nil {
				return r
			}
			p := "jobs." + m[2]
			if m[1] != "" {
				p = "stages." + m[1] + "." + p
			}
			id, _ := get(docs[0].value, p+".job").(string)
			return "azure_pipeline_job." + id
		}
		pass, fail := sets(f)
		wantFail, wantPass := map[string]bool{}, map[string]bool{}
		for _, r := range fail {
			wantFail[jobAt(r)] = true
		}
		for _, r := range pass {
			wantPass[jobAt(r)] = true
		}
		compare(ckv, wantFail, wantPass, failedIn(map[string]string{"azure-pipelines.yml": string(b)}, foreignRules[ckv]))
	}

	// GitHub Actions graph checks: expected.yaml lists <file>.<entity> per outcome; compare per file.
	dirs, _ := filepath.Glob(filepath.Join(src, "tests/github_actions/checks/graph_checks/resources/*/expected.yaml"))
	for _, e := range dirs {
		dir := filepath.Dir(e)
		ckv := idOf(filepath.Join(src, "checkov/github_actions/checks/graph_checks", filepath.Base(dir)+".yaml"))
		if ckv == "" || foreignRules[ckv] == nil {
			continue
		}
		docs, _ := decodeYAMLDocs(readFile(e))
		if len(docs) == 0 {
			continue
		}
		files := map[string]string{}
		wf, _ := filepath.Glob(filepath.Join(dir, ".github/workflows/*"))
		for _, p := range wf {
			files[".github/workflows/"+filepath.Base(p)] = readFile(p)
		}
		want := map[string]map[string]bool{"pass": {}, "fail": {}}
		for k := range want {
			for _, r := range asStrings(get(docs[0].value, k)) {
				for file := range files {
					if strings.HasPrefix(r, filepath.Base(file)+".") {
						want[k][file] = true
					}
				}
			}
		}
		compare(ckv, want["fail"], want["pass"], failedIn(files, foreignRules[ckv]))
	}

	t.Logf("%d of %d mapped Dockerfile and CI checks agree with Checkov's fixtures", agree, tested)
	if len(report) > 0 {
		t.Logf("disagreements:\n%s", strings.Join(report, "\n"))
	}
	if os.Getenv("CKV_STRICT") != "" && len(report) > 0 {
		t.Errorf("%d checks disagree", len(report))
	}
}

func readFile(p string) string {
	b, _ := os.ReadFile(p)
	return string(b)
}
