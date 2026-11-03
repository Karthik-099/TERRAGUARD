package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/Karthik-099/TERRAGUARD/engine"
)

// runInit sets a repository up in one step: a policy file on a built-in pack,
// a CI workflow and a pre-commit hook. Existing files are left alone unless
// --force is given.
func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	pack := fs.String("pack", "recommended", "built-in policy pack: "+strings.Join(engine.PackNames(), ", "))
	ci := fs.String("ci", "auto", "CI to set up: github, gitlab, none or auto (detect from the repository)")
	force := fs.Bool("force", false, "overwrite files that already exist")
	paths, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	dir := "."
	if len(paths) > 0 {
		dir = paths[0]
	}
	if _, ok := engine.PolicyPacks[*pack]; !ok {
		return fmt.Errorf("init: unknown pack %q (have %s)", *pack, strings.Join(engine.PackNames(), ", "))
	}
	if *ci == "auto" {
		*ci = "none"
		if exists(filepath.Join(dir, ".github")) {
			*ci = "github"
		} else if exists(filepath.Join(dir, ".gitlab-ci.yml")) {
			*ci = "gitlab"
		}
	}
	release := "v" + engine.Version
	files := map[string]string{
		".terraguard.yml": fmt.Sprintf(`# TerraGuard policy: https://github.com/Karthik-099/TERRAGUARD/blob/main/docs/REFERENCE.md
extends: [terraguard:%s]
# rules_version: %q        # pin: rules added later are reported but do not gate until you raise it
# disable: []                # rules that do not apply to your platform; say why in a comment
# waivers:                   # reviewed exceptions that expire
#   - { rule: TG-AWS-S3-003, resource: aws_s3_bucket.logs, reason: "...", approved_by: "...", expires: 2026-12-31 }
`, *pack, engine.RulesVersion),
		".pre-commit-config.yaml": fmt.Sprintf(`repos:
  - repo: https://github.com/Karthik-099/TERRAGUARD
    rev: %s
    hooks:
      - id: terraguard
`, release),
	}
	if *ci == "github" {
		files[".github/workflows/terraguard.yml"] = fmt.Sprintf(`name: terraguard
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
  pull-requests: write
  security-events: write
jobs:
  terraguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: Karthik-099/TERRAGUARD@%s
        with:
          command: ${{ github.event_name == 'pull_request' && 'review' || 'scan' }}
`, release)
	}
	var wrote, kept []string
	for _, name := range sortedNames(files) {
		p := filepath.Join(dir, name)
		if exists(p) && !*force {
			kept = append(kept, name)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte(files[name]), 0o644); err != nil {
			return err
		}
		wrote = append(wrote, name)
	}
	for _, n := range wrote {
		fmt.Println("wrote", n)
	}
	for _, n := range kept {
		fmt.Println("kept existing", n, "(use --force to replace)")
	}
	if *ci == "gitlab" {
		fmt.Printf("GitLab: add the job from templates/gitlab-ci.yml, pinned to %s.\n", release)
	}
	fmt.Println("Next: terraguard scan .   (or terraguard ui . for the workspace)")
	return nil
}

func sortedNames(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// runExplain prints everything about one rule.
func runExplain(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: terraguard explain RULE-ID")
	}
	id := strings.ToUpper(strings.TrimSpace(args[0]))
	for _, r := range engine.Catalog() {
		if r.ID != id {
			continue
		}
		fmt.Printf("%s  %s\n\n", r.ID, r.Title)
		fmt.Printf("Severity     %s%s\n", r.Severity, map[bool]string{true: "  (blocks apply)"}[r.Blocking])
		fmt.Printf("Category     %s\n", r.Category)
		if r.CWE != "" {
			fmt.Printf("CWE          %s  https://cwe.mitre.org/data/definitions/%s.html\n", r.CWE, strings.TrimPrefix(r.CWE, "CWE-"))
		}
		if r.Since != "" {
			fmt.Printf("Since        %s\n", r.Since)
		}
		if len(r.Types) > 0 {
			types := r.Types
			if len(types) > 12 {
				types = append(append([]string{}, types[:12]...), fmt.Sprintf("and %d more", len(r.Types)-12))
			}
			fmt.Printf("Applies to   %s\n", strings.Join(types, ", "))
		}
		if len(r.Themes) > 0 {
			fmt.Printf("Compliance   %s\n", strings.Join(r.Themes, ", "))
		}
		if a := engine.AliasesOf(r.ID); len(a) > 0 {
			fmt.Printf("Also answers %s (their skip comments apply)\n", strings.Join(a, ", "))
		}
		fmt.Printf("\nFix\n  %s\n\nSilence one finding with `# terraguard:ignore %s` above the block, or add a waiver with a reason and an expiry in .terraguard.yml.\n", r.Remediation, r.ID)
		return nil
	}
	return fmt.Errorf("no rule %s; `terraguard rules` lists them", id)
}

// runDoctor checks the installation and the tools optional features use.
func runDoctor(args []string) error {
	fmt.Printf("TerraGuard %s (%s/%s, %s), %d rules, packs: %s\n", engine.Version, runtime.GOOS, runtime.GOARCH, runtime.Version(), len(engine.Catalog()), strings.Join(engine.PackNames(), ", "))
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}
	if text, err := findConfig("", []string{dir}); err != nil {
		fmt.Println("policy       error:", err)
	} else if text == "" {
		fmt.Println("policy       none (terraguard init writes one)")
	} else if _, err := engine.ParseConfig(text); err != nil {
		fmt.Println("policy       invalid:", err)
	} else {
		fmt.Println("policy       ok")
	}
	tools := []struct{ name, use string }{
		{"terraform", "plans and provider schemas"}, {"tofu", "OpenTofu plans"}, {"helm", "--helm"}, {"kustomize", "--kustomize"},
		{"kubectl", "--kustomize fallback"}, {"bicep", "--bicep"}, {"az", "--bicep fallback, Azure preflight"},
		{"aws", "AWS preflight"}, {"gcloud", "Google Cloud preflight"},
	}
	for _, t := range tools {
		state := "not found"
		if p, err := exec.LookPath(t.name); err == nil {
			state = p
		}
		fmt.Printf("%-12s %-40s for %s\n", t.name, state, t.use)
	}
	fmt.Println("Every tool above is optional; scans need none of them and make no network calls.")
	return nil
}
