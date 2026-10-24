// Command terraguard scans Terraform in CI, on a laptop, or as an MCP server.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Karthik-099/TERRAGUARD/engine"
	"github.com/Karthik-099/TERRAGUARD/internal/ai"
)

const usage = `TerraGuard — Terraform security, validation and plan-risk analysis

Usage:
  terraguard scan [paths...] [flags]   Scan .tf/.tfvars files (default: .)
  terraguard fix  [paths...]           Apply safe auto-fixes in place
  terraguard docs [path]               Generate module README (inputs, outputs, resources)
  terraguard ask "question" [paths]    Ask the AI assistant about your Terraform (optional)
  terraguard ai                        Show the AI fallback route built from .env
  terraguard serve [--addr host:port]  Self-host the web app + API (keys stay server-side)
  terraguard rules [--format json|markdown]
  terraguard mcp                       Run as an MCP server over stdio
  terraguard version

Scan flags:
  --format text|json|sarif|markdown   stdout format (default text)
  --plan plan.json                    also analyze 'terraform show -json' output
  --config .terraguard.yml            policy file (auto-detected)
  --fail-on CRITICAL|HIGH|MEDIUM|LOW|NONE  override the policy threshold
  --sarif FILE / --markdown FILE / --json FILE   extra outputs (for CI)
  --ai                                add an advisory LLM remediation plan to markdown

AI is optional. Keys are read from the environment or ./.env:
  GROQ_API_KEY, OPENROUTER_API_KEY, GEMINI_API_KEY   (free tiers; no paid APIs are used)
  TERRAGUARD_OLLAMA_URL=http://localhost:11434/v1   local model, nothing leaves your machine
  TERRAGUARD_AI_LOCAL_ONLY=true                     never call hosted providers
  TERRAGUARD_AI_ROUTE=groq:openai/gpt-oss-120b,openrouter,gemini   explicit fallback chain

Usage counters are OFF unless TERRAGUARD_TELEMETRY_URL is set (anonymous counts only, never code).

Exit codes: 0 passed, 1 policy failed, 2 error.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	// Missing .env is normal; keys may come from the real environment or CI secrets.
	_ = ai.LoadDotenv(".env")
	if f := os.Getenv("TERRAGUARD_ENV_FILE"); f != "" {
		if err := ai.LoadDotenv(f); err != nil {
			fmt.Fprintln(os.Stderr, "warning:", err)
		}
	}
	var err error
	code := 0
	switch os.Args[1] {
	case "scan":
		code, err = runScan(os.Args[2:])
	case "fix":
		err = runFix(os.Args[2:])
	case "rules":
		err = runRules(os.Args[2:])
	case "docs":
		err = runDocs(os.Args[2:])
	case "ask":
		err = runAsk(os.Args[2:])
	case "ai":
		runAIStatus()
	case "serve":
		err = runServe(os.Args[2:])
	case "mcp":
		err = runMCP()
	case "version", "--version":
		fmt.Println("terraguard", engine.Version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		code = 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		code = 2
	}
	os.Exit(code)
}

// parseInterspersed lets flags appear before or after paths.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
	if len(pos) == 0 {
		pos = []string{"."}
	}
	return pos, nil
}

// loadFiles reads .tf/.tfvars under paths, keyed by slash path relative to cwd.
func loadFiles(paths []string) (map[string]string, error) {
	files := map[string]string{}
	cwd, _ := os.Getwd()
	add := func(p string) error {
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		key := p
		if rel, err := filepath.Rel(cwd, p); err == nil && !strings.HasPrefix(rel, "..") {
			key = rel
		}
		files[filepath.ToSlash(key)] = string(b)
		return nil
	}
	for _, root := range paths {
		info, err := os.Stat(root)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			if err := add(root); err != nil {
				return nil, err
			}
			continue
		}
		err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && p != root && (d.Name() == ".terraform" || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			if !d.IsDir() && (strings.HasSuffix(p, ".tf") || strings.HasSuffix(p, ".tfvars")) {
				return add(p)
			}
			if !d.IsDir() && strings.Contains(d.Name(), ".tfstate") {
				files[filepath.ToSlash(p)] = "" // only the name matters: committed state is the finding
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return files, nil
}

func findConfig(explicit string, paths []string) (string, error) {
	if explicit != "" {
		b, err := os.ReadFile(explicit)
		return string(b), err
	}
	cands := []string{".terraguard.yml", ".terraguard.yaml"}
	for _, p := range paths {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			cands = append([]string{filepath.Join(p, ".terraguard.yml"), filepath.Join(p, ".terraguard.yaml")}, cands...)
		}
	}
	for _, c := range cands {
		if b, err := os.ReadFile(c); err == nil {
			return string(b), nil
		}
	}
	return "", nil
}

func buildInput(paths []string, planPath, configPath, failOn string) (engine.Input, error) {
	files, err := loadFiles(paths)
	if err != nil {
		return engine.Input{}, err
	}
	cfg, err := findConfig(configPath, paths)
	if err != nil {
		return engine.Input{}, err
	}
	// A broken policy must not silently fall back to defaults in CI.
	if _, err := engine.ParseConfig(cfg); err != nil {
		return engine.Input{}, err
	}
	in := engine.Input{Files: files, Config: cfg, FailOn: failOn}
	if planPath != "" {
		b, err := os.ReadFile(planPath)
		if err != nil {
			return in, err
		}
		in.Plan = string(b)
	}
	return in, nil
}

func runScan(args []string) (int, error) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	format := fs.String("format", "text", "")
	plan := fs.String("plan", "", "")
	config := fs.String("config", "", "")
	failOn := fs.String("fail-on", "", "")
	sarifOut := fs.String("sarif", "", "")
	mdOut := fs.String("markdown", "", "")
	jsonOut := fs.String("json", "", "")
	useAI := fs.Bool("ai", false, "")
	paths, err := parseInterspersed(fs, args)
	if err != nil {
		return 2, err
	}
	in, err := buildInput(paths, *plan, *config, *failOn)
	if err != nil {
		return 2, err
	}
	if len(in.Files) == 0 && in.Plan == "" {
		return 2, fmt.Errorf("no .tf or .tfvars files found in %v", paths)
	}
	t0 := time.Now()
	rep := engine.Scan(in)
	reportUsage(rep, int(time.Since(t0).Milliseconds()))

	md := ""
	render := func(f string) (string, error) {
		switch f {
		case "json":
			b, err := json.MarshalIndent(rep, "", "  ")
			return string(b) + "\n", err
		case "sarif":
			b, err := engine.SARIF(rep)
			return string(b) + "\n", err
		case "markdown", "md":
			if md == "" {
				md = engine.Markdown(rep)
				if *useAI {
					md += aiSection(rep, in)
				}
			}
			return md, nil
		case "text":
			return engine.Text(rep), nil
		}
		return "", fmt.Errorf("unknown format %q", f)
	}
	for path, f := range map[string]string{*sarifOut: "sarif", *mdOut: "markdown", *jsonOut: "json"} {
		if path == "" {
			continue
		}
		s, err := render(f)
		if err != nil {
			return 2, err
		}
		if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
			return 2, err
		}
	}
	s, err := render(*format)
	if err != nil {
		return 2, err
	}
	fmt.Print(s)
	if !rep.Passed {
		return 1, nil
	}
	return 0, nil
}

func runFix(args []string) error {
	fs := flag.NewFlagSet("fix", flag.ContinueOnError)
	config := fs.String("config", "", "")
	paths, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	in, err := buildInput(paths, "", *config, "")
	if err != nil {
		return err
	}
	changed, errs := engine.FixAll(in)
	for _, e := range errs {
		fmt.Fprintln(os.Stderr, "skipped:", e)
	}
	for name, src := range changed {
		if err := os.WriteFile(filepath.FromSlash(name), []byte(src), 0o644); err != nil {
			return err
		}
		fmt.Println("fixed", name)
	}
	if len(changed) == 0 {
		fmt.Println("nothing to fix")
	}
	return nil
}

func runRules(args []string) error {
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	format := fs.String("format", "text", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rules := engine.Catalog()
	switch *format {
	case "json":
		b, err := json.MarshalIndent(rules, "", "  ")
		fmt.Println(string(b))
		return err
	case "markdown":
		fmt.Println("| ID | Severity | Category | Title | Blocks apply |\n|---|---|---|---|---|")
		for _, r := range rules {
			blk := ""
			if r.Blocking {
				blk = "yes"
			}
			fmt.Printf("| `%s` | %s | %s | %s | %s |\n", r.ID, r.Severity, r.Category, r.Title, blk)
		}
	default:
		for _, r := range rules {
			fmt.Printf("%-15s %-8s %-13s %s\n", r.ID, r.Severity, r.Category, r.Title)
		}
	}
	return nil
}

func runDocs(args []string) error {
	paths := args
	if len(paths) == 0 {
		paths = []string{"."}
	}
	files, err := loadFiles(paths)
	if err != nil {
		return err
	}
	fmt.Print(engine.Docs(files))
	return nil
}
