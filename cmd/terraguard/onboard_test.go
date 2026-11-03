package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Karthik-099/TERRAGUARD/engine"
)

func TestInitWritesValidFilesAndKeepsExisting(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, ".github"), 0o755)
	devnull, _ := os.Open(os.DevNull)
	stdout := os.Stdout
	os.Stdout = devnull
	t.Cleanup(func() { os.Stdout = stdout })
	if err := runInit([]string{dir, "--pack", "strict"}); err != nil {
		t.Fatal(err)
	}
	policy, _ := os.ReadFile(filepath.Join(dir, ".terraguard.yml"))
	if !strings.Contains(string(policy), "terraguard:strict") {
		t.Fatalf("policy: %s", policy)
	}
	if r := engine.Scan(engine.Input{Files: map[string]string{"main.tf": ""}, Config: string(policy)}); r.FailOn != engine.Medium || len(r.Errors) > 0 {
		t.Errorf("the written policy must load: %s %v", r.FailOn, r.Errors)
	}
	if !exists(filepath.Join(dir, ".github/workflows/terraguard.yml")) || !exists(filepath.Join(dir, ".pre-commit-config.yaml")) {
		t.Error("CI workflow and pre-commit config expected")
	}
	os.WriteFile(filepath.Join(dir, ".terraguard.yml"), []byte("fail_on: LOW\n"), 0o644)
	runInit([]string{dir})
	if b, _ := os.ReadFile(filepath.Join(dir, ".terraguard.yml")); string(b) != "fail_on: LOW\n" {
		t.Error("init must not overwrite without --force")
	}
	if err := runInit([]string{dir, "--pack", "nope"}); err == nil {
		t.Error("unknown pack must be an error")
	}
	if err := runExplain([]string{"tg-aws-s3-001"}); err != nil {
		t.Errorf("explain: %v", err)
	}
	if err := runExplain([]string{"TG-NOPE-1"}); err == nil {
		t.Error("explain of an unknown rule is an error")
	}
}
