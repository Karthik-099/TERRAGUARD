package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/Karthik-099/TERRAGUARD/internal/ai"
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

// resolvePolicy expands extends: local paths are relative to the policy file, or https URLs.
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

// writeBaselineFile saves today's findings so later scans gate on new ones only.
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

var (
	fixtureHeader = regexp.MustCompile(`(?m)^#\s*(expect|forbid):\s*(.+)$`)
	fixturePath   = regexp.MustCompile(`(?m)^#\s*path:\s*(.+)$`)
)

// runPolicy validates a policy or runs its fixture tests.
func runPolicy(args []string) (int, error) {
	if len(args) > 0 && args[0] == "suggest" {
		return runPolicySuggest(args[1:])
	}
	if len(args) == 0 || (args[0] != "validate" && args[0] != "test") {
		return 2, fmt.Errorf(`usage: terraguard policy validate [--config FILE] | terraguard policy test DIR [--config FILE] | terraguard policy suggest "standard" [paths]`)
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
	all, _ := filepath.Glob(filepath.Join(dir, "*"))
	var cases []string
	for _, c := range all {
		if engine.IsScannable(c) && !strings.HasPrefix(filepath.Base(c), ".terraguard") {
			cases = append(cases, c)
		}
	}
	if len(cases) == 0 {
		return 2, fmt.Errorf("no fixtures in %s", dir)
	}
	failed := 0
	for _, c := range cases {
		src, err := os.ReadFile(c)
		if err != nil {
			return 2, err
		}
		headers := string(src)
		if side, err := os.ReadFile(c + ".expect"); err == nil { // JSON cannot hold comments
			headers = string(side)
		}
		name := filepath.Base(c)
		if m := fixturePath.FindStringSubmatch(headers); m != nil {
			name = strings.TrimSpace(m[1]) // e.g. .github/workflows/ci.yml, where the path decides the format
		}
		got := map[string]bool{}
		for _, f := range engine.Scan(engine.Input{Files: map[string]string{name: string(src)}, Config: text}).Findings {
			if !f.Waived {
				got[f.RuleID] = true
			}
		}
		var problems []string
		for _, m := range fixtureHeader.FindAllStringSubmatch(headers, -1) {
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

// runPolicySuggest: AI drafts a rule, DraftRule checks it, one retry with the error.
// Only resource types are sent, never code.
func runPolicySuggest(args []string) (int, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return 2, fmt.Errorf(`usage: terraguard policy suggest "production databases keep 14 days of backups" [paths]`)
	}
	standard, paths := args[0], args[1:]
	if len(paths) == 0 {
		paths = []string{"."}
	}
	files, err := loadFiles(paths)
	if err != nil {
		return 2, err
	}
	msgs := []ai.Message{
		{Role: "system", Content: engine.RuleDraftPrompt},
		{Role: "user", Content: fmt.Sprintf("Resource types in this repository: %s\nStandard: %s", strings.Join(engine.ResourceTypes(files), ", "), standard)},
	}
	var d engine.RuleDraft
	for round := 0; round < 2; round++ {
		res, err := ai.Chat(context.Background(), msgs)
		if err != nil {
			return 2, err
		}
		if d = engine.DraftRule(res.Text, engine.Input{Files: files}); d.Error == "" {
			break
		}
		msgs = append(msgs, ai.Message{Role: "assistant", Content: res.Text}, ai.Message{Role: "user", Content: "That rule was rejected: " + d.Error + ". Answer with the corrected YAML only."})
	}
	if d.Error != "" {
		return 1, fmt.Errorf("the model did not produce a valid rule: %s", d.Error)
	}
	fmt.Printf("# Add under custom_rules: in .terraguard.yml\n%s\n\n", d.YAML)
	fmt.Printf("# Dry run: %d resource(s) would fail this rule\n", len(d.Hits))
	for _, h := range d.Hits {
		fmt.Printf("#   %s  %s:%d\n", h.Resource, h.File, h.Line)
	}
	return 0, nil
}
