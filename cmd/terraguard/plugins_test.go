package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Karthik-099/TERRAGUARD/engine"
)

// fakePlugin reads the request and answers according to FAKE_MODE.
const fakePlugin = `package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

func main() {
	var req struct {
		API   int      ` + "`json:\"api\"`" + `
		Root  string   ` + "`json:\"root\"`" + `
		Files []string ` + "`json:\"files\"`" + `
	}
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil || req.API != 1 {
		fmt.Fprintln(os.Stderr, "bad request", err)
		os.Exit(3)
	}
	wd, _ := os.Getwd()
	switch os.Getenv("FAKE_MODE") {
	case "sarif":
		fmt.Println(` + "`" + `{"version": "2.1.0", "runs": [{"results": [{"ruleId": "R1", "level": "error", "message": {"text": "from sarif"},
  "locations": [{"physicalLocation": {"artifactLocation": {"uri": "main.tf"}, "region": {"startLine": 2}}}]}]}]}` + "`" + `)
	case "escape":
		fmt.Println(` + "`" + `[{"rule_id": "FAKE-1", "file": "../outside.tf"}]` + "`" + `)
	case "fail":
		fmt.Fprintln(os.Stderr, "boom")
		os.Exit(1)
	case "sleep":
		time.Sleep(10 * time.Second)
	default:
		out := []map[string]any{
			{"rule_id": "FAKE-001", "severity": "high", "title": "t", "message": fmt.Sprintf("%d files, wd=%v", len(req.Files), wd == req.Root), "file": "main.tf", "line": 1, "waived": true},
			{"rule_id": "TG-AWS-S3-001", "severity": "EXTREME", "file": req.Root + "/main.tf"},
		}
		json.NewEncoder(os.Stdout).Encode(out)
	}
}
`

func buildFakePlugin(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX paths")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(src, "go.mod"), []byte("module fake\n\ngo 1.21\n"), 0o644)
	os.WriteFile(filepath.Join(src, "main.go"), []byte(fakePlugin), 0o644)
	bin := filepath.Join(dir, "bin")
	cmd := exec.Command("go", "build", "-o", filepath.Join(bin, "terraguard-fake"), ".")
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "GOFLAGS=", "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fake plugin: %v\n%s", err, out)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return bin
}

func TestPlugins(t *testing.T) {
	buildFakePlugin(t)
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "main.tf"), []byte("resource \"null_resource\" \"x\" {}\n"), 0o644)
	files := map[string]string{filepath.Join(root, "main.tf"): "resource \"null_resource\" \"x\" {}\n"}
	opts := pluginOptions{Names: []string{"fake"}, Timeout: 20 * time.Second}
	ctx := context.Background()

	fs, err := runPlugins(ctx, opts, "", root, files)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("findings: %+v", fs)
	}
	a, b := fs[0], fs[1]
	if a.RuleID != "FAKE-001" || a.Severity != engine.High || a.Waived || a.Message != "1 files, wd=true" || a.File != filepath.Join(root, "main.tf") || a.Category != engine.CatPolicy {
		t.Errorf("first: %+v", a)
	}
	if b.RuleID != "FAKE-TG-AWS-S3-001" || b.Severity != engine.Medium || b.File != a.File {
		t.Errorf("second: %+v", b)
	}

	// Plugin findings get the same waivers and gate as built-in ones.
	policy := "fail_on: HIGH\nwaivers:\n  - rule: FAKE-001\n    reason: accepted\n"
	rep := engine.Scan(engine.Input{Files: files, Config: policy, Extra: fs})
	for _, f := range rep.Findings {
		if f.RuleID == "FAKE-001" && !f.Waived {
			t.Error("waiver did not apply to a plugin finding")
		}
	}

	t.Setenv("FAKE_MODE", "sarif")
	if fs, err := runPlugins(ctx, opts, "", root, files); err != nil || len(fs) != 1 || fs[0].RuleID != "FAKE-R1" || fs[0].Severity != engine.High || fs[0].Line != 2 {
		t.Errorf("sarif: %+v %v", fs, err)
	}
	for mode, want := range map[string]string{"escape": "outside the scanned folder", "fail": "boom", "sleep": "did not finish"} {
		t.Setenv("FAKE_MODE", mode)
		o := opts
		o.Timeout = 2 * time.Second
		if _, err := runPlugins(ctx, o, "", root, files); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error %v, want %q", mode, err, want)
		}
	}

	// Nothing runs unless asked, and a plugin inside the scanned folder is refused.
	if fs, err := runPlugins(ctx, pluginOptions{}, "", root, files); fs != nil || err != nil {
		t.Errorf("ran without being enabled: %v %v", fs, err)
	}
	if _, err := runPlugins(ctx, opts, "", filepath.Dir(filepath.Dir(mustLook(t))), files); err == nil || !strings.Contains(err.Error(), "inside the scanned folder") {
		t.Errorf("plugin inside root: %v", err)
	}
	if ps := findPlugins(""); len(ps) == 0 || ps[0].Name != "example" && ps[0].Name != "fake" {
		t.Errorf("list: %+v", ps)
	}
}

func mustLook(t *testing.T) string {
	p, err := exec.LookPath("terraguard-fake")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPluginOptions(t *testing.T) {
	o, err := pluginOptionsFrom("plugins: [license]\nplugin_timeout: 90s\n", "all,naming", 0)
	if err != nil || !o.All || o.Timeout != 90*time.Second || strings.Join(o.Names, ",") != "license,naming" {
		t.Errorf("%+v %v", o, err)
	}
	for _, bad := range []string{"plugins: [../evil]\n", "plugins: [tg]\n", "plugin_timeout: soon\n"} {
		if _, err := pluginOptionsFrom(bad, "", 0); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestExamplePlugin(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	ex, _ := filepath.Abs("../../examples/plugins")
	t.Setenv("PATH", ex+string(os.PathListSeparator)+os.Getenv("PATH"))
	root := t.TempDir()
	fs, err := runPlugins(context.Background(), pluginOptions{Names: []string{"example"}}, "", root, map[string]string{})
	if err != nil || len(fs) != 1 || fs[0].RuleID != "EXAMPLE-001" || fs[0].Severity != engine.Low {
		t.Errorf("%+v %v", fs, err)
	}
}

func TestPluginNamesCannotClaimBuiltInPrefixes(t *testing.T) {
	for _, n := range []string{"tg", "org", "tg-sec", "org-x"} {
		if checkPluginName(n) == nil {
			t.Errorf("%s: want refused", n)
		}
	}
	if checkPluginName("acme") != nil {
		t.Error("acme: want allowed")
	}
}
