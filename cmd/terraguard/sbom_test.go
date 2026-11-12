package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Karthik-099/TERRAGUARD/internal/vuln"
)

func TestSBOMRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	os.WriteFile("main.tf", []byte(`module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.2"
}
`), 0o644)
	os.WriteFile("Dockerfile", []byte("FROM nginx:1.25\n"), 0o644)
	os.WriteFile("package-lock.json", []byte(`{"lockfileVersion": 3, "packages": {"": {}, "node_modules/@scope/pkg": {"version": "1.2.3"}, "node_modules/lodash": {"version": "4.17.20"}}}`), 0o644)
	out := filepath.Join(dir, "bom.json")
	if err := runSBOM([]string{"--out", out, "."}); err != nil {
		t.Fatal(err)
	}
	pkgs, err := sbomPackages(out)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, p := range pkgs {
		got[p.Ecosystem+"/"+p.Name+"@"+p.Version] = true
	}
	for _, want := range []string{"npm/@scope/pkg@1.2.3", "npm/lodash@4.17.20"} {
		if !got[want] {
			t.Errorf("SBOM round trip lost %s; got %v", want, got)
		}
	}
	if len(pkgs) != 2 {
		t.Errorf("only lockfile packages should come back for vuln, got %v", got)
	}
	if p := packagePURL(vuln.Package{Ecosystem: "Maven", Name: "org.apache:commons", Version: "1.0"}); p != "pkg:maven/org.apache/commons@1.0" {
		t.Errorf("maven purl %s", p)
	}
}

func TestSecretFilesNotRead(t *testing.T) {
	t.Chdir(t.TempDir())
	os.WriteFile("main.tf", []byte(""), 0o644)
	os.WriteFile(".env", []byte("SECRET=1"), 0o000) // unreadable: reading it would fail the load
	os.WriteFile("credentials.json", []byte(`{"k":"v"}`), 0o000)
	files, err := loadFiles([]string{"."})
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := files[".env"]; !ok || v != "" {
		t.Errorf(".env should be listed by name only")
	}
	if v, ok := files["credentials.json"]; !ok || v != "" {
		t.Errorf("credentials.json should be listed by name only")
	}
}

func TestFindCodeOwners(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	os.MkdirAll("infra/.github", 0o755)
	os.WriteFile("infra/.github/CODEOWNERS", []byte("* @org/infra\n"), 0o644)
	os.WriteFile("infra/CODEOWNERS", []byte("* @org/ignored\n"), 0o644)
	text, root := findCodeOwners([]string{"infra"})
	if text != "* @org/infra\n" || root != "infra" {
		t.Errorf("findCodeOwners = %q, %q", text, root)
	}
}
