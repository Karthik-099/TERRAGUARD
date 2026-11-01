// Command llmeval scores an LLM as a reviewer on the same cases as the rules.
//
//	go run ./evals/llmeval --provider groq [--summary $GITHUB_STEP_SUMMARY]
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Karthik-099/TERRAGUARD/engine"
	"github.com/Karthik-099/TERRAGUARD/internal/ai"
)

var (
	header  = regexp.MustCompile(`(?m)^#\s*(expect|forbid):\s*(.+)$`)
	comment = regexp.MustCompile(`(?m)^#.*$`)
)

type row struct {
	name          string
	missed, false []string
	seconds       float64
}

func main() {
	provider := flag.String("provider", "", "groq, openrouter, gemini, ollama, custom, openai or anthropic (default: the configured route)")
	model := flag.String("model", "", "model id (default: the provider's first model)")
	cases := flag.String("cases", "evals/cases", "directory of labelled .tf cases")
	summary := flag.String("summary", "", "append a Markdown report to this file")
	flag.Parse()
	_ = ai.LoadDotenv(".env")
	if *provider != "" {
		route := *provider
		if *model != "" {
			route += ":" + *model
		}
		os.Setenv("TERRAGUARD_AI_ROUTE", route)
	}

	var catalog strings.Builder
	for _, r := range engine.Catalog() {
		fmt.Fprintf(&catalog, "%s: %s\n", r.ID, r.Title)
	}
	system := "You are a Terraform security and correctness reviewer. Given a rule catalog and a Terraform file, answer ONLY with a JSON array of the rule IDs the file violates. No prose."

	files, _ := filepath.Glob(filepath.Join(*cases, "*.tf"))
	sort.Strings(files)
	var tp, fn, fp, tn int
	var rows []row
	usedModel := ""
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		expect, forbid := map[string]bool{}, map[string]bool{}
		for _, m := range header.FindAllStringSubmatch(string(src), -1) {
			for _, id := range strings.Split(m[2], ",") {
				if m[1] == "expect" {
					expect[strings.TrimSpace(id)] = true
				} else {
					forbid[strings.TrimSpace(id)] = true
				}
			}
		}
		start := time.Now()
		got := map[string]bool{}
		// Labels are hidden from the model.
		res, err := ai.Chat(context.Background(), []ai.Message{
			{Role: "system", Content: system},
			{Role: "user", Content: "Rule catalog:\n" + catalog.String() + "\nTerraform:\n" + comment.ReplaceAllString(string(src), "")},
		})
		if err == nil {
			usedModel = res.Provider + " " + res.Model
			text := res.Text
			if i, j := strings.Index(text, "["), strings.LastIndex(text, "]"); i >= 0 && j > i {
				var ids []string
				if json.Unmarshal([]byte(text[i:j+1]), &ids) == nil {
					for _, id := range ids {
						got[id] = true
					}
				}
			}
		} else if err == ai.ErrNoProvider {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		r := row{name: filepath.Base(f), seconds: time.Since(start).Seconds()}
		for id := range expect {
			if got[id] {
				tp++
			} else {
				fn++
				r.missed = append(r.missed, id)
			}
		}
		for id := range forbid {
			if got[id] {
				fp++
				r.false = append(r.false, id)
			} else {
				tn++
			}
		}
		sort.Strings(r.missed)
		sort.Strings(r.false)
		rows = append(rows, r)
		fmt.Printf("%-30s missed=%v false=%v\n", r.name, r.missed, r.false)
	}

	recall, precision := ratio(tp, tp+fn), ratio(tp, tp+fp)
	line := fmt.Sprintf("%s: recall %.0f%%, precision %.0f%% (%d tp, %d fn, %d fp, %d tn)", usedModel, recall*100, precision*100, tp, fn, fp, tn)
	fmt.Println("\n" + line)
	if *summary != "" {
		f, err := os.OpenFile(*summary, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			defer f.Close()
			fmt.Fprintf(f, "### LLM-as-reviewer eval\n\n%s\n\n| Case | Missed | False positives | Seconds |\n|---|---|---|---|\n", line)
			for _, r := range rows {
				fmt.Fprintf(f, "| %s | %s | %s | %.1f |\n", r.name, orDash(r.missed), orDash(r.false), r.seconds)
			}
			fmt.Fprintln(f, "\nThe deterministic engine scores 100% on the same cases (`make evals`), which is why it alone gates CI.")
		}
	}
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 1
	}
	return float64(a) / float64(b)
}

func orDash(s []string) string {
	if len(s) == 0 {
		return "-"
	}
	return strings.Join(s, ", ")
}
