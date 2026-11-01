package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Karthik-099/TERRAGUARD/engine"
)

// resolvePolicy expands `extends` references: local paths are relative to the
// policy file's directory; https URLs let an organization publish one baseline
// that every repository inherits.
func resolvePolicy(text, dir string) (string, error) {
	if !strings.Contains(text, "extends") {
		return text, nil
	}
	return engine.ResolveExtends(text, func(ref string) (string, error) {
		if strings.HasPrefix(ref, "https://") {
			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Get(ref)
			if err != nil {
				return "", err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return "", fmt.Errorf("HTTP %d", resp.StatusCode)
			}
			b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			return string(b), err
		}
		if strings.Contains(ref, "://") {
			return "", fmt.Errorf("only local paths and https URLs are supported")
		}
		if !filepath.IsAbs(ref) {
			ref = filepath.Join(dir, ref)
		}
		b, err := os.ReadFile(ref)
		return string(b), err
	})
}

func readBaseline(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var keys []string
	if err := json.Unmarshal(b, &keys); err != nil {
		return nil, fmt.Errorf("baseline %s: %w", path, err)
	}
	return keys, nil
}

// writeBaselineFile records every current finding (active or waived) so later
// scans gate only on findings introduced after today.
func writeBaselineFile(path string, rep *engine.Report) error {
	keys := []string{}
	seen := map[string]bool{}
	for _, f := range rep.Findings {
		if k := engine.FindingKey(f); !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	b, _ := json.MarshalIndent(keys, "", "  ")
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

var fixtureHeader = regexp.MustCompile(`(?m)^#\s*(expect|forbid):\s*(.+)$`)

// runPolicy validates a policy or runs fixture tests against it, so teams can
// unit-test their own standards the same way TerraGuard tests its rules.
func runPolicy(args []string) (int, error) {
	if len(args) == 0 || (args[0] != "validate" && args[0] != "test") {
		return 2, fmt.Errorf("usage: terraguard policy validate [--config FILE] | terraguard policy test DIR [--config FILE]")
	}
	fset := flag.NewFlagSet("policy", flag.ContinueOnError)
	config := fset.String("config", "", "policy file (default: .terraguard.yml in the current or given directory)")
	paths, err := parseInterspersed(fset, args[1:])
	if err != nil {
		return 2, err
	}
	text, err := findConfig(*config, paths)
	if err != nil {
		return 2, err
	}
	cfg, err := engine.ParseConfig(text)
	if err != nil {
		return 1, err
	}
	if args[0] == "validate" {
		fmt.Printf("policy is valid: fail_on %s, %d custom rule(s), %d waiver(s), %d disabled pattern(s), %d budget(s)\n",
			cfg.FailOn, len(cfg.CustomRules), len(cfg.Waivers), len(cfg.Disable), len(cfg.MaxFindings))
		for _, cr := range cfg.CustomRules {
			fmt.Printf("  %-16s %-8s %s\n", cr.ID, cr.Severity, cr.Title)
		}
		return 0, nil
	}

	dir := paths[0]
	cases, _ := filepath.Glob(filepath.Join(dir, "*.tf"))
	if len(cases) == 0 {
		return 2, fmt.Errorf("no *.tf fixtures in %s", dir)
	}
	failed := 0
	for _, c := range cases {
		src, err := os.ReadFile(c)
		if err != nil {
			return 2, err
		}
		got := map[string]bool{}
		for _, f := range engine.Scan(engine.Input{Files: map[string]string{filepath.Base(c): string(src)}, Config: text}).Findings {
			if !f.Waived {
				got[f.RuleID] = true
			}
		}
		var problems []string
		for _, m := range fixtureHeader.FindAllStringSubmatch(string(src), -1) {
			for _, id := range strings.Split(m[2], ",") {
				id = strings.TrimSpace(id)
				if m[1] == "expect" && !got[id] {
					problems = append(problems, "expected "+id)
				}
				if m[1] == "forbid" && got[id] {
					problems = append(problems, "unexpected "+id)
				}
			}
		}
		if len(problems) > 0 {
			failed++
			fmt.Printf("FAIL %s: %s\n", c, strings.Join(problems, ", "))
		} else {
			fmt.Printf("ok   %s\n", c)
		}
	}
	fmt.Printf("\n%d fixture(s), %d failed\n", len(cases), failed)
	if failed > 0 {
		return 1, nil
	}
	return 0, nil
}
