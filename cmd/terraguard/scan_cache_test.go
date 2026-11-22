package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Karthik-099/TERRAGUARD/engine"
)

func reportJSON(t *testing.T, rep *engine.Report) []byte {
	t.Helper()
	r := *rep
	r.Trace = engine.Trace{} // timing differs run to run
	b, err := json.MarshalIndent(&r, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestScanCacheSameResult(t *testing.T) {
	cache := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	t.Setenv("HOME", cache)
	in, err := buildInput([]string{"../../examples/insecure", "../../examples/beyond-terraform"}, "../../examples/plan.json", "", "")
	if err != nil {
		t.Fatal(err)
	}
	want := reportJSON(t, engine.Scan(in))
	first := reportJSON(t, cachedScan(in, true))
	second := cachedScan(in, true)
	if !bytes.Equal(want, first) || !bytes.Equal(want, reportJSON(t, second)) {
		t.Fatal("a cached scan must give the same JSON as an uncached one")
	}
	if engine.Text(second) != engine.Text(engine.Scan(in)) {
		t.Error("a cached scan must give the same text report")
	}
	dir, _ := scanCacheDir()
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("want one cache entry, got %d", len(ents))
	}
	if info, _ := ents[0].Info(); info.Mode().Perm() != 0o600 {
		t.Errorf("cache entry mode %v, want 0600", info.Mode().Perm())
	}
	// Any change to the input is a new key.
	in2 := in
	in2.Files = map[string]string{}
	for k, v := range in.Files {
		in2.Files[k] = v
	}
	for k := range in2.Files {
		in2.Files[k] += "\n# changed\n"
		break
	}
	in3 := in
	in3.Config = "fail_on: LOW\n"
	for _, other := range []engine.Input{in2, in3} {
		if scanCacheKey(other) == scanCacheKey(in) {
			t.Error("a changed input must not reuse the cache entry")
		}
	}
}

func TestScanCacheEviction(t *testing.T) {
	dir := t.TempDir()
	old := scanCacheMax
	scanCacheMax = 10
	t.Cleanup(func() { scanCacheMax = old })
	writeCacheEntry(dir, filepath.Join(dir, "a.json"), []byte("123456"))
	os.Chtimes(filepath.Join(dir, "a.json"), time.Unix(1, 0), time.Unix(1, 0))
	writeCacheEntry(dir, filepath.Join(dir, "b.json"), []byte("123456"))
	if _, err := os.Stat(filepath.Join(dir, "b.json")); err != nil {
		t.Fatal("the newest entry must stay")
	}
	if _, err := os.Stat(filepath.Join(dir, "a.json")); err == nil {
		t.Fatal("the oldest entry must go once the folder is over the cap")
	}
}

func TestChangedDirs(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	t.Chdir(t.TempDir())
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("git", append([]string{"-c", "user.email=t@example.com", "-c", "user.name=t"}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %s", args, out)
		}
	}
	for _, f := range []string{"a/main.tf", "a/variables.tf", "a/sub/x.tf", "b/main.tf"} {
		os.MkdirAll(filepath.Dir(f), 0o755)
		os.WriteFile(f, []byte("# "+f+"\n"), 0o644)
	}
	run("init", "-q")
	run("add", ".")
	run("commit", "-qm", "one")
	run("commit", "-qm", "two", "--allow-empty")
	os.WriteFile("a/main.tf", []byte("# changed\n"), 0o644)
	os.WriteFile("c.tf", []byte("# new\n"), 0o644)

	if _, _, err := changedDirs("--output=x"); err == nil {
		t.Error("a base starting with - must be refused")
	}
	dirs, base, err := changedDirs("")
	if err != nil {
		t.Fatal(err)
	}
	if base != "HEAD~1" {
		t.Errorf("without origin/main the base is HEAD~1, got %s", base)
	}
	if len(dirs) != 2 || dirs[0] != "." || dirs[1] != "a" {
		t.Fatalf("dirs = %v, want [. a]", dirs)
	}
	files, err := loadFiles([]string{"."})
	if err != nil {
		t.Fatal(err)
	}
	keepDirs(files, dirs)
	if len(files) != 3 || files["a/variables.tf"] == "" || files["c.tf"] == "" {
		t.Errorf("want a/main.tf, a/variables.tf and c.tf, got %v", files)
	}
}
