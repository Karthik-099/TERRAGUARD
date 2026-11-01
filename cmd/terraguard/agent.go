package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Karthik-099/TERRAGUARD/engine"
	"github.com/Karthik-099/TERRAGUARD/internal/ai"
)

var codeBlock = regexp.MustCompile("(?s)```(?:hcl|terraform)?\\s*\\n(.*?)```")

// runAgent is a propose-and-verify loop: deterministic fixes first, then the
// LLM proposes a rewrite per file and the engine keeps it only if Verify
// accepts it. The model never decides what is "fixed".
func runAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	write := fs.Bool("write", false, "write accepted changes to disk (default: dry run)")
	rounds := fs.Int("rounds", 2, "maximum AI rounds")
	minSev := fs.String("min-severity", "MEDIUM", "only ask the AI about findings at or above this severity")
	config := fs.String("config", "", "")
	paths, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	in, err := buildInput(paths, "", *config, "")
	if err != nil {
		return err
	}
	orig := in.Files
	files := map[string]string{}
	for k, v := range orig {
		files[k] = v
	}
	scan := func() *engine.Report { return engine.Scan(engine.Input{Files: files, Config: in.Config}) }
	logf := func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) }

	rep := scan()
	start := engine.RiskWeight(rep)
	logf("start: risk weight %d, %d active finding(s)", start, active(rep))

	if changed, _ := engine.FixAll(engine.Input{Files: files, Config: in.Config}); len(changed) > 0 {
		for k, v := range changed {
			files[k] = v
		}
		next := scan()
		logf("deterministic fixes: %d file(s), risk weight %d to %d", len(changed), engine.RiskWeight(rep), engine.RiskWeight(next))
		rep = next
	}

	min := engine.ParseSeverity(*minSev)
loop:
	for round := 1; round <= *rounds; round++ {
		targets := map[string][]engine.Finding{}
		for _, f := range rep.Findings {
			if !f.Waived && f.Severity.Rank() >= min.Rank() && files[f.File] != "" {
				targets[f.File] = append(targets[f.File], f)
			}
		}
		if len(targets) == 0 {
			break
		}
		names := make([]string, 0, len(targets))
		for n := range targets {
			names = append(names, n)
		}
		sort.Strings(names)
		progress := false
		for _, name := range names {
			var list strings.Builder
			for _, f := range targets[name] {
				fmt.Fprintf(&list, "- line %d [%s] %s: %s Fix: %s\n", f.Line, f.RuleID, f.Title, f.Message, f.Remediation)
			}
			res, err := ai.Chat(context.Background(), []ai.Message{
				{Role: "system", Content: systemPrompt + " Return only the complete corrected file in one ```hcl block. Keep behaviour, names and comments; do not invent arguments."},
				{Role: "user", Content: fmt.Sprintf("File %s:\n```hcl\n%s\n```\n\nFindings to fix:\n%s", name, files[name], list.String())},
			})
			if errors.Is(err, ai.ErrNoProvider) {
				logf("no AI provider configured; stopping after deterministic fixes")
				break loop
			}
			if err != nil {
				logf("%s: AI unavailable (%v)", name, err)
				continue
			}
			m := codeBlock.FindStringSubmatch(res.Text)
			if m == nil {
				logf("%s: rejected: the AI did not return a file", name)
				continue
			}
			candidate := regexp.MustCompile(`(?m)\A#\s*file:.*\n`).ReplaceAllString(m[1], "")
			prev := files[name]
			files[name] = candidate
			next := scan()
			ok, why := engine.Verify(rep, next)
			logf("%s: %s (%s %s)", name, why, res.Provider, res.Model)
			if !ok {
				files[name] = prev
				continue
			}
			rep, progress = next, true
		}
		if !progress {
			break
		}
	}

	var changed []string
	for k, v := range files {
		if v != orig[k] {
			changed = append(changed, k)
		}
	}
	sort.Strings(changed)
	logf("result: risk weight %d to %d, %d active finding(s) left, %d file(s) changed", start, engine.RiskWeight(rep), active(rep), len(changed))
	if !*write {
		if len(changed) > 0 {
			logf("dry run: re-run with --write to apply, then review with git diff")
		}
		return nil
	}
	for _, k := range changed {
		if err := os.WriteFile(filepath.FromSlash(k), []byte(files[k]), 0o644); err != nil {
			return err
		}
		fmt.Println("wrote", k)
	}
	return nil
}

func active(r *engine.Report) int {
	n := 0
	for _, f := range r.Findings {
		if !f.Waived {
			n++
		}
	}
	return n
}
