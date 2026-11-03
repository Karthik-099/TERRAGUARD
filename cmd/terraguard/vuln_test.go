package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Karthik-099/TERRAGUARD/internal/vuln"
)

func vulnDB(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("GHSA-p6mc-m468-83gw.json")
	w.Write([]byte(`{"id": "GHSA-p6mc-m468-83gw", "aliases": ["CVE-2020-8203"], "summary": "Prototype Pollution in lodash",
	  "database_specific": {"severity": "HIGH"},
	  "affected": [{"package": {"ecosystem": "npm", "name": "lodash"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.19"}]}]}]}`))
	zw.Close()
	zp := filepath.Join(t.TempDir(), "all.zip")
	os.WriteFile(zp, buf.Bytes(), 0o644)
	if _, err := vuln.IndexZip(zp, dir, "npm"); err != nil {
		t.Fatal(err)
	}
	meta, _ := json.Marshal(vuln.Meta{Updated: time.Now(), Ecosystems: map[string]vuln.EcosystemStats{"npm": {}}})
	os.WriteFile(filepath.Join(dir, "meta.json"), meta, 0o644)
	return dir
}

func TestRunVuln(t *testing.T) {
	db := vulnDB(t)
	repo := t.TempDir()
	lock := `{"lockfileVersion": 3, "packages": {"": {}, "node_modules/lodash": {"version": "4.17.15"}}}`
	os.WriteFile(filepath.Join(repo, "package-lock.json"), []byte(lock), 0o644)
	os.MkdirAll(filepath.Join(repo, "node_modules", "x"), 0o755)
	os.WriteFile(filepath.Join(repo, "node_modules", "x", "package-lock.json"), []byte("not json"), 0o644)

	if code, err := runVuln([]string{repo, "--db", db, "--format", "sarif"}); code != 1 || err != nil {
		t.Errorf("HIGH finding: code %d, err %v", code, err)
	}
	if code, err := runVuln([]string{repo, "--db", db, "--fail-on", "critical"}); code != 0 || err != nil {
		t.Errorf("--fail-on critical: code %d, err %v", code, err)
	}
	if code, err := runVuln([]string{repo, "--db", t.TempDir()}); code != 2 || err == nil || !strings.Contains(err.Error(), "vuln update") {
		t.Errorf("missing database: code %d, err %v", code, err)
	}
	if code, err := runVuln([]string{"image", "--db", db}); code != 2 || err == nil || !strings.Contains(err.Error(), "docker save") {
		t.Errorf("image without archive: code %d, err %v", code, err)
	}
	if code, _ := runVuln([]string{repo, "--db", db, "--fail-on", "sometimes"}); code != 2 {
		t.Errorf("bad --fail-on: code %d", code)
	}
}

func TestWriteVulnFormats(t *testing.T) {
	d, err := vuln.Open(vulnDB(t))
	if err != nil {
		t.Fatal(err)
	}
	pkgs := []vuln.Package{{Ecosystem: "npm", Name: "lodash", Version: "4.17.15", File: "package-lock.json", Line: 2}}
	ms, err := vuln.MatchAll(d, pkgs)
	if err != nil || len(ms) != 1 {
		t.Fatalf("matches %v, err %v", ms, err)
	}
	ms = append(ms, vuln.Match{Package: pkgs[0], ID: "UNRATED-1", Severity: "UNKNOWN"})
	for format, want := range map[string]string{
		"text":     "GHSA-p6mc-m468-83gw",
		"json":     `"rule_id": "GHSA-p6mc-m468-83gw"`,
		"sarif":    `"level": "note"`,
		"markdown": "| HIGH | `lodash` | 4.17.15 |",
	} {
		var b bytes.Buffer
		if err := writeVuln(&b, format, d, pkgs, ms, nil); err != nil || !strings.Contains(b.String(), want) {
			t.Errorf("%s: err %v, output lacks %q:\n%s", format, err, want, b.String())
		}
	}
}
