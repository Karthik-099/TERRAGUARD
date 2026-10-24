package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Karthik-099/TERRAGUARD/engine"
	"github.com/Karthik-099/TERRAGUARD/internal/ai"
)

const systemPrompt = "You are TerraGuard's assistant, a senior platform engineer. Be concise and concrete. " +
	"TerraGuard's deterministic findings are authoritative; you explain them and suggest fixes, you never decide pass/fail."

// aiContext gives the model the code (truncated) and the active findings.
func aiContext(rep *engine.Report, files map[string]string, maxChars int) string {
	var b strings.Builder
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	b.WriteString("Terraform files:\n")
	for _, n := range names {
		src := files[n]
		if len(src) > maxChars {
			src = src[:maxChars] + "\n…(truncated)"
		}
		maxChars -= len(src)
		if maxChars <= 0 {
			break
		}
		fmt.Fprintf(&b, "--- %s ---\n%s\n", n, src)
	}
	b.WriteString("\nTerraGuard findings:\n")
	n := 0
	for _, f := range rep.Findings {
		if f.Waived || n == 40 {
			continue
		}
		n++
		fmt.Fprintf(&b, "- [%s] %s %s:%d %s: %s\n", f.Severity, f.RuleID, f.File, f.Line, f.Title, f.Message)
	}
	return b.String()
}

// aiSection never fails the scan: an LLM outage must not block a merge.
func aiSection(rep *engine.Report, in engine.Input) string {
	if len(rep.Findings) == 0 {
		return ""
	}
	res, err := ai.Chat(context.Background(), []ai.Message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: aiContext(rep, in.Files, 12000) + "\nWrite a short markdown section: 1) the single most important risk in one sentence, 2) a prioritized fix plan (max 5 bullets) with exact Terraform snippets where useful. No preamble."},
	})
	if err != nil {
		return "\n<details><summary>🤖 AI review unavailable</summary>\n\n```\n" + err.Error() + "\n```\n</details>\n"
	}
	return fmt.Sprintf("\n### 🤖 AI remediation plan\n\n%s\n\n<sub>%s · %s — AI suggestions are advisory; the deterministic findings above decide the gate.</sub>\n", res.Text, res.Provider, res.Model)
}

func runAsk(args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf(`usage: terraguard ask "question" [paths...]`)
	}
	question, paths := args[0], args[1:]
	if len(paths) == 0 {
		paths = []string{"."}
	}
	in, err := buildInput(paths, "", "", "")
	if err != nil {
		return err
	}
	rep := engine.Scan(in)
	res, err := ai.Chat(context.Background(), []ai.Message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: aiContext(rep, in.Files, 24000) + "\nQuestion: " + question},
	})
	if err != nil {
		return err
	}
	fmt.Println(res.Text)
	fmt.Fprintf(os.Stderr, "\n— %s · %s", res.Provider, res.Model)
	if len(res.Attempts) > 0 {
		fmt.Fprintf(os.Stderr, " (after %d fallback(s))", len(res.Attempts))
	}
	fmt.Fprintln(os.Stderr)
	return nil
}

func runAIStatus() {
	route := ai.Route()
	if ai.LocalOnly() {
		fmt.Println("mode: local-only (hosted providers disabled)")
	}
	if len(route) == 0 {
		fmt.Println(ai.ErrNoProvider)
		fmt.Println("The engine (scan, fix, gate) works without any model.")
		return
	}
	fmt.Println("AI fallback route (first success wins):")
	for i, s := range route {
		fmt.Printf("  %2d. %s\n", i+1, s)
	}
}
