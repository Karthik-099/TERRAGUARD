package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Karthik-099/TERRAGUARD/engine"
	"github.com/Karthik-099/TERRAGUARD/internal/ai"
)

// runReview gates on what a change introduces, not on existing debt.
func runReview(args []string) (int, error) {
	fset := flag.NewFlagSet("review", flag.ContinueOnError)
	base := fset.String("base", "origin/main", "git revision to compare against (e.g. the PR base SHA)")
	format := fset.String("format", "markdown", "stdout format: markdown or json")
	mdOut := fset.String("markdown", "", "also write Markdown to this file")
	jsonOut := fset.String("json", "", "also write JSON to this file")
	failOn := fset.String("fail-on", "", "override the policy threshold")
	config := fset.String("config", "", "policy file (default: .terraguard.yml, found automatically)")
	useAI := fset.Bool("ai", false, "add an advisory AI summary for full-tier reviews")
	schema := fset.String("schema", "", "check every argument against terraform providers schema -json output")
	paths, err := parseInterspersed(fset, args)
	if err != nil {
		return 2, err
	}
	head, err := buildInput(paths, "", *config, *failOn)
	if err != nil {
		return 2, err
	}
	if head.Schema, err = readOptional(*schema); err != nil {
		return 2, err
	}
	baseFiles, err := gitFilesAt(*base, paths)
	if err != nil {
		return 2, err
	}
	diff, err := git("diff", "--name-only", "--relative", *base, "--")
	if err != nil {
		return 2, err
	}
	// A change is judged by the policy it is merging into, so it cannot loosen
	// its own gate. An explicit --config is a location CI controls; use it as is.
	policy := head.Config
	if *config == "" {
		policy, err = basePolicy(*base, paths)
		if err != nil {
			return 2, err
		}
	}
	judged := head
	judged.Config = policy
	baseRep := engine.Scan(engine.Input{Files: baseFiles, Config: policy, FailOn: head.FailOn, Schema: head.Schema})
	headRep := engine.Scan(judged)
	rev := engine.NewReview(baseRep, headRep, engine.ChangedTerraform(strings.Fields(diff)))
	rev.PolicyChanges = engine.PolicyWeakening(policy, head.Config)
	rev.Silenced = engine.SilencedBy(baseRep, headRep)

	md := rev.Markdown()
	// Like model routing by risk tier: only full reviews are worth an AI call.
	if *useAI && rev.Tier == "full" && len(rev.New) > 0 {
		var list strings.Builder
		for _, f := range rev.New {
			fmt.Fprintf(&list, "- [%s] %s %s:%d %s: %s\n", f.Severity, f.RuleID, f.File, f.Line, f.Title, f.Message)
		}
		res, err := ai.Chat(context.Background(), []ai.Message{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: "A pull request introduces these Terraform findings:\n" + list.String() + "\nIn at most 5 bullets, explain the combined risk to a reviewer and the order to fix them. No preamble."},
		})
		if err == nil {
			md += fmt.Sprintf("### AI summary (advisory)\n\n%s\n\n<sub>%s %s. The findings above decide the review.</sub>\n", res.Text, res.Provider, res.Model)
		}
	}
	js, _ := json.MarshalIndent(rev, "", "  ")
	for path, content := range map[string]string{*mdOut: md, *jsonOut: string(js) + "\n"} {
		if path != "" {
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				return 2, err
			}
		}
	}
	if *format == "json" {
		fmt.Println(string(js))
	} else {
		fmt.Print(md)
	}
	if !rev.Passed {
		return 1, nil
	}
	return 0, nil
}

func git(args ...string) (string, error) {
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), strings.TrimSpace(string(ee.Stderr)))
		}
		return "", err
	}
	return string(out), nil
}

// gitFilesAt reads files at a revision, keyed like loadFiles.
// basePolicy returns the .terraguard.yml at the base revision ("" when it has
// none, which means the defaults), with extends resolved.
func basePolicy(rev string, paths []string) (string, error) {
	cands := []string{".terraguard.yml", ".terraguard.yaml"}
	for _, p := range paths {
		cands = append([]string{filepath.ToSlash(filepath.Join(p, ".terraguard.yml")), filepath.ToSlash(filepath.Join(p, ".terraguard.yaml"))}, cands...)
	}
	for _, c := range cands {
		if src, err := git("show", rev+":./"+c); err == nil {
			return resolvePolicy(src, filepath.Dir(c))
		}
	}
	return "", nil
}

func gitFilesAt(rev string, paths []string) (map[string]string, error) {
	list, err := git(append([]string{"ls-tree", "-r", "--name-only", rev, "--"}, paths...)...)
	if err != nil {
		return nil, err
	}
	files := map[string]string{}
	for _, p := range strings.Fields(list) {
		if !strings.HasSuffix(p, ".tf") && !strings.HasSuffix(p, ".tfvars") {
			continue
		}
		src, err := git("show", rev+":./"+p)
		if err != nil {
			return nil, err
		}
		files[p] = src
	}
	return files, nil
}
