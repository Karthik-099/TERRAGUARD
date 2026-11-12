// Command terraguard scans Terraform in CI, on a laptop, or as an MCP server.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/Karthik-099/TERRAGUARD/engine"
	"github.com/Karthik-099/TERRAGUARD/internal/ai"
)

const usage = `TerraGuard — Terraform security, validation and plan-risk analysis

Usage:
  terraguard scan [paths...] [flags]   Scan .tf/.tfvars files (default: .)
  terraguard review --base REV [paths] Review a change: new findings only, risk tier, resolved issues
  terraguard fix  [paths...]           Apply safe auto-fixes in place
  terraguard docs [path]               Generate module README (inputs, outputs, resources)
  terraguard graph [paths] [--format mermaid|dot|json]
                                       Resource graph with attack paths highlighted
  terraguard agents-md [path]          Generate AGENTS.md so AI coding agents follow your guardrails
  terraguard ask "question" [paths]    Ask the AI assistant about your Terraform (optional)
  terraguard agent [paths] [--write]   Fix findings: deterministic fixes, then AI proposals the engine verifies
  terraguard pulse [roots] [--baseline prev.json --json out.json]
                                       Control adoption, waivers and trend across many modules
  terraguard preflight --plan plan.json --live
                                       Check the plan against live cloud quotas before apply
  terraguard drift [dir] --state FILE | --live   Code vs state inventory; read-only refresh for drift
  terraguard cost --plan plan.json [--fail-above 500]    offline monthly cost estimate of a plan
  terraguard vuln [paths] | image IMAGE.tar | update   offline OSV scan of lockfiles and container images
  terraguard vuln --sbom bom.json      offline OSV scan of the packages in a CycloneDX SBOM
  terraguard sbom [paths] [--format cyclonedx|json] [--out FILE]
                                       CycloneDX 1.5 inventory: providers, modules, images, packages (offline)
  terraguard ui [path]                 Open the workspace on this machine with a folder loaded from disk
  terraguard lsp                       Language server for any editor (diagnostics and quick fixes over stdio)
  terraguard init [path] [--pack recommended|strict|minimal]   Policy, CI workflow and pre-commit in one step
  terraguard explain RULE-ID           Everything about one rule: why, fix, compliance, aliases
  terraguard doctor [path]             Check the installation, the policy and optional tools
  terraguard ai                        Show the AI fallback route built from .env
  terraguard serve [--addr host:port]  Self-host the web app + API (keys stay server-side)
  terraguard policy validate|test      Validate a policy (with extends) or run policy test fixtures
  terraguard policy suggest "standard" Draft a custom rule from plain English (AI drafts, engine validates)
  terraguard rules [--format json|markdown]
  terraguard plugins list | test NAME [path]   Plugins (terraguard-* on PATH) that add findings; see docs/PLUGINS.md
  terraguard mcp                       Run as an MCP server over stdio
  terraguard version

Scan flags:
  --format text|json|sarif|junit|codequality|markdown   stdout format (default text)
  --plan plan.json                    also analyze 'terraform show -json' output
  --schema schema.json                check arguments against 'terraform providers schema -json' 
  --config .terraguard.yml            policy file (auto-detected)
  --fail-on CRITICAL|HIGH|MEDIUM|LOW|NONE  override the policy threshold
  --sarif FILE / --junit FILE / --codequality FILE / --markdown FILE / --json FILE   extra outputs
  --write-baseline FILE               accept today's findings as existing debt
  --baseline FILE                     report baselined findings as waived; gate only on new ones
  --ai                                add an advisory LLM remediation plan to markdown
  --plugins all|NAME,...              run terraguard-* plugins from PATH (also plugins: in the policy)
  --plugin-timeout 60s                stop each plugin after this long
  --group-by owner                    group text and markdown output by CODEOWNERS owner (unowned last)

CODEOWNERS (.github/, root or docs/ of the scanned folder) sets code_owners on every finding.
Files such as .env, *.pem, *.key, id_rsa and kubeconfig are reported by name; their content is never read.

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
	case "graph":
		err = runGraph(os.Args[2:])
	case "docs":
		err = runDocs(os.Args[2:])
	case "agents-md":
		err = runAgentsMD(os.Args[2:])
	case "ask":
		err = runAsk(os.Args[2:])
	case "agent":
		err = runAgent(os.Args[2:])
	case "pulse":
		code, err = runPulse(os.Args[2:])
	case "preflight":
		code, err = runPreflight(os.Args[2:])
	case "cost":
		code, err = runCost(os.Args[2:])
	case "vuln":
		code, err = runVuln(os.Args[2:])
	case "sbom":
		err = runSBOM(os.Args[2:])
	case "drift":
		code, err = runDrift(os.Args[2:])
	case "ui":
		err = runUI(os.Args[2:])
	case "lsp":
		err = runLSP()
	case "init":
		err = runInit(os.Args[2:])
	case "explain":
		err = runExplain(os.Args[2:])
	case "doctor":
		err = runDoctor(os.Args[2:])
	case "policy":
		code, err = runPolicy(os.Args[2:])
	case "review":
		code, err = runReview(os.Args[2:])
	case "plugins":
		code, err = runPluginsCmd(os.Args[2:])
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
	switch {
	case errors.Is(err, flag.ErrHelp): // -h already printed the command's flags
		code = 0
	case err != nil:
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
// includeModules makes loadFiles also read modules terraform init downloaded.
var includeModules bool

func loadFiles(paths []string) (map[string]string, error) {
	files := map[string]string{}
	cwd, _ := os.Getwd()
	add := func(p string) error {
		key := p
		if rel, err := filepath.Rel(cwd, p); err == nil && !strings.HasPrefix(rel, "..") {
			key = rel
		}
		if engine.IsSecretFileName(p) {
			if !gitIgnored(p) { // a local, git-ignored .env is how it should be
				files[filepath.ToSlash(key)] = "" // only the name matters; never read a credentials file
			}
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
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
			if d.IsDir() && p != root {
				switch {
				case includeModules && d.Name() == ".terraform":
					return nil // only its modules folder is read, below
				case includeModules && filepath.Base(filepath.Dir(p)) == ".terraform":
					if d.Name() != "modules" {
						return filepath.SkipDir // providers and other init output
					}
				case strings.HasPrefix(d.Name(), ".") && d.Name() != ".github" && d.Name() != ".circleci",
					d.Name() == "node_modules", d.Name() == "vendor":
					return filepath.SkipDir
				}
			}
			if !d.IsDir() && (engine.IsScannable(p) || engine.IsSecretFileName(p)) {
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

// gitIgnored reports whether git would leave the file out of a commit. Without git it is false.
// core.fsmonitor is off: a scanned repository's .git/config must not run a command.
func gitIgnored(p string) bool {
	return exec.Command("git", "-c", "core.fsmonitor=false", "-C", filepath.Dir(p), "check-ignore", "-q", filepath.Base(p)).Run() == nil
}

// findConfig returns the policy text with `extends` already resolved.
func findConfig(explicit string, paths []string) (string, error) {
	if explicit != "" {
		b, err := os.ReadFile(explicit)
		if err != nil {
			return "", err
		}
		return resolvePolicy(string(b), filepath.Dir(explicit))
	}
	cands := []string{".terraguard.yml", ".terraguard.yaml"}
	for _, p := range paths {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			cands = append([]string{filepath.Join(p, ".terraguard.yml"), filepath.Join(p, ".terraguard.yaml")}, cands...)
		}
	}
	for _, c := range cands {
		if b, err := os.ReadFile(c); err == nil {
			return resolvePolicy(string(b), filepath.Dir(c))
		}
	}
	return "", nil
}

// readPolicyDirs reads every .yaml/.yml file with a definition block.
func readPolicyDirs(dirs []string) ([]string, error) {
	var out []string
	for _, d := range dirs {
		err := filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {
			if err != nil || e.IsDir() || !(strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")) {
				return err
			}
			b, err := os.ReadFile(p)
			if err == nil && strings.Contains(string(b), "definition:") {
				out = append(out, string(b))
			}
			return err
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// readOptional returns the file's contents, or "" when no path is given.
func readOptional(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path)
	return string(b), err
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
	in.CodeOwners, in.CodeOwnersRoot = findCodeOwners(paths)
	if planPath != "" {
		b, err := os.ReadFile(planPath)
		if err != nil {
			return in, err
		}
		in.Plan = string(b)
	}
	return in, nil
}

// findCodeOwners reads CODEOWNERS from the first scanned directory, in
// GitHub's order: .github/, the root, docs/. root is its Files key prefix.
func findCodeOwners(paths []string) (text, root string) {
	for _, p := range paths {
		if info, err := os.Stat(p); err != nil || !info.IsDir() {
			continue
		}
		for _, c := range []string{".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"} {
			if b, err := os.ReadFile(filepath.Join(p, c)); err == nil {
				return string(b), rootKey(p)
			}
		}
		return "", ""
	}
	return "", ""
}

func runScan(args []string) (int, error) {
	if rest, ok := cutFlag(args, "--watch"); ok {
		return watchScan(rest)
	}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	format := fs.String("format", "text", "stdout format: text, json, sarif, junit, codequality, checkstyle, github (annotations), azure (Azure DevOps) or markdown")
	plan := fs.String("plan", "", "also analyze a plan: the output of terraform show -json")
	config := fs.String("config", "", "policy file (default: .terraguard.yml, found automatically)")
	failOn := fs.String("fail-on", "", "override the policy threshold: CRITICAL, HIGH, MEDIUM, LOW or NONE")
	sarifOut := fs.String("sarif", "", "also write SARIF (GitHub code scanning) to this file")
	mdOut := fs.String("markdown", "", "also write a Markdown report (pull request comment) to this file")
	jsonOut := fs.String("json", "", "also write the JSON report to this file")
	junitOut := fs.String("junit", "", "also write JUnit XML (CI test reports) to this file")
	useAI := fs.Bool("ai", false, "add an advisory AI remediation plan to the Markdown report")
	baseline := fs.String("baseline", "", "treat findings in this baseline file as accepted debt; gate only on new ones")
	writeBaseline := fs.String("write-baseline", "", "write today's findings to this file as the baseline")
	cqOut := fs.String("codequality", "", "also write a GitLab Code Quality report to this file")
	schema := fs.String("schema", "", "check every argument against terraform providers schema -json output")
	renderHelm := fs.Bool("helm", false, "render Helm charts (Chart.yaml) with helm template and scan the manifests")
	renderBicep := fs.Bool("bicep", false, "compile .bicep files with bicep build (or az bicep build) and scan the ARM templates")
	renderKustomize := fs.Bool("kustomize", false, "render Kustomize overlays with kustomize build (or kubectl kustomize) and scan the manifests")
	fs.BoolVar(&includeModules, "include-modules", false, "also scan modules that terraform init downloaded into .terraform/modules")
	plugins := fs.String("plugins", "", "run plugins from PATH: all, or a comma list of names (terraguard-NAME); see docs/PLUGINS.md")
	pluginTimeout := fs.Duration("plugin-timeout", 0, "stop each plugin after this long (default 60s, or plugin_timeout in the policy)")
	coverage := fs.Bool("coverage", false, "list every resource with the number of rules that checked it and which failed")
	groupBy := fs.String("group-by", "", "owner: group text and markdown output by CODEOWNERS owner, unowned last")
	noBuiltinSchema := fs.Bool("no-builtin-schema", false, "do not check arguments against the bundled aws, azurerm and google schemas")
	var varFiles, skipPaths, only, skip, policyDirs, regoDirs, frameworks listFlag
	fs.Var(&frameworks, "framework", "scan only these formats: terraform, kubernetes, cloudformation, arm, dockerfile, docker-compose, github-actions, gitlab-ci, azure-pipelines, circleci, bitbucket-pipelines, serverless, ansible, openapi (repeatable or comma-separated)")
	fs.Var(&regoDirs, "rego", "folder of Rego policies (Conftest style: deny, violation and warn rules) to run as well (repeatable)")
	fs.Var(&policyDirs, "policy-dir", "folder of graph policies in Checkov's YAML format to run as well (repeatable; --external-checks-dir works too)")
	fs.Var(&policyDirs, "external-checks-dir", "same as --policy-dir")
	fs.Var(&varFiles, "var-file", "tfvars file to use like terraform -var-file (repeatable, later wins)")
	fs.Var(&skipPaths, "skip-path", "glob of paths not to scan, e.g. 'test/**' or '*/examples/*' (repeatable)")
	fs.Var(&only, "check", "run only these rule IDs or globs, e.g. TG-AWS-* (repeatable)")
	fs.Var(&skip, "skip-check", "skip these rule IDs or globs (repeatable)")
	paths, err := parseInterspersed(fs, args)
	if err != nil {
		return 2, err
	}
	if *groupBy != "" && *groupBy != "owner" {
		return 2, fmt.Errorf("--group-by %q: only owner is supported", *groupBy)
	}
	in, err := buildInput(paths, *plan, *config, *failOn)
	if err != nil {
		return 2, err
	}
	if len(in.Files) == 0 && in.Plan == "" {
		return 2, fmt.Errorf("no .tf or .tfvars files found in %v", paths)
	}
	if *baseline != "" {
		if in.Baseline, err = readBaseline(*baseline); err != nil {
			return 2, err
		}
	}
	if in.Schema, err = readOptional(*schema); err != nil {
		return 2, err
	}
	in.NoBuiltinSchema, in.Coverage = *noBuiltinSchema, *coverage
	if in.GraphPolicies, err = readPolicyDirs(policyDirs); err != nil {
		return 2, err
	}
	for name := range in.Files {
		if matchesAny(skipPaths, name) {
			delete(in.Files, name)
		}
	}
	for _, vf := range varFiles {
		b, err := os.ReadFile(vf)
		if err != nil {
			return 2, err
		}
		for _, p := range paths { // a var file belongs to the root module being scanned
			in.VarFiles = append(in.VarFiles, engine.VarFile{Dir: rootKey(p), Source: string(b)})
		}
	}
	if *renderHelm || *renderKustomize || *renderBicep {
		rendered, err := renderManifests(paths, *renderHelm, *renderKustomize, *renderBicep)
		if err != nil {
			return 2, err
		}
		for name, src := range rendered {
			in.Files[name] = src
		}
	}
	in.Only, in.Skip = only, skip
	for _, f := range frameworks {
		in.Frameworks = append(in.Frameworks, strings.Split(f, ",")...)
	}
	t0 := time.Now()
	if in.Extra, err = regoFindings(regoDirs, in.Files, in.Plan); err != nil {
		return 2, err
	}
	popts, err := pluginOptionsFrom(in.Config, *plugins, *pluginTimeout)
	if err != nil {
		return 2, err
	}
	for _, p := range paths { // before engine.Scan, so waivers, baselines and the gate apply
		pf, err := runPlugins(context.Background(), popts, in.Config, p, in.Files)
		if err != nil {
			return 2, err
		}
		in.Extra = append(in.Extra, pf...)
	}
	rep := engine.Scan(in)
	if *writeBaseline != "" {
		if err := writeBaselineFile(*writeBaseline, rep); err != nil {
			return 2, err
		}
		fmt.Fprintf(os.Stderr, "wrote baseline with %d accepted finding(s) to %s\n", rep.Waived+active(rep), *writeBaseline)
	}
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
				if *groupBy == "owner" {
					md = engine.MarkdownByOwner(rep)
				}
				if *useAI {
					md += aiSection(rep, in)
				}
			}
			return md, nil
		case "junit":
			b, err := engine.JUnit(rep)
			return string(b) + "\n", err
		case "codequality":
			b, err := engine.CodeQuality(rep)
			return string(b) + "\n", err
		case "checkstyle":
			b, err := engine.Checkstyle(rep)
			return string(b) + "\n", err
		case "github":
			return engine.GitHubAnnotations(rep), nil
		case "azure":
			return engine.AzureDevOps(rep), nil
		case "text":
			if *groupBy == "owner" {
				return engine.TextByOwner(rep), nil
			}
			return engine.Text(rep), nil
		}
		return "", fmt.Errorf("unknown format %q", f)
	}
	for path, f := range map[string]string{*sarifOut: "sarif", *mdOut: "markdown", *jsonOut: "json", *junitOut: "junit", *cqOut: "codequality"} {
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
	config := fs.String("config", "", "policy file (default: .terraguard.yml, found automatically)")
	pr := fs.Bool("pr", false, "commit the fixes on a new branch, push it and open a pull request (gh)")
	base := fs.String("base", "", "with --pr: the branch the pull request targets (default: current branch)")
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
	var written []string
	for name, src := range changed {
		if err := os.WriteFile(filepath.FromSlash(name), []byte(src), 0o644); err != nil {
			return err
		}
		fmt.Println("fixed", name)
		written = append(written, filepath.FromSlash(name))
	}
	if len(changed) == 0 {
		fmt.Println("nothing to fix")
	}
	if *pr {
		return openFixPR(written, *base)
	}
	return nil
}

func runRules(args []string) error {
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	format := fs.String("format", "text", "output format: text, json or markdown")
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
		fmt.Println("| ID | Severity | Category | Title | Blocks apply | Since |\n|---|---|---|---|---|---|")
		for _, r := range rules {
			blk := ""
			if r.Blocking {
				blk = "yes"
			}
			fmt.Printf("| `%s` | %s | %s | %s | %s | %s |\n", r.ID, r.Severity, r.Category, r.Title, blk, r.Since)
		}
	default:
		for _, r := range rules {
			fmt.Printf("%-15s %-8s %-13s %s\n", r.ID, r.Severity, r.Category, r.Title)
		}
	}
	return nil
}

func runDocs(args []string) error {
	paths, err := parseInterspersed(flag.NewFlagSet("docs", flag.ContinueOnError), args)
	if err != nil {
		return err
	}
	files, err := loadFiles(paths)
	if err != nil {
		return err
	}
	fmt.Print(engine.Docs(files))
	return nil
}

func runAgentsMD(args []string) error {
	paths, err := parseInterspersed(flag.NewFlagSet("agents-md", flag.ContinueOnError), args)
	if err != nil {
		return err
	}
	in, err := buildInput(paths, "", "", "")
	if err != nil {
		return err
	}
	fmt.Print(engine.AgentsMD(in.Files, in.Config))
	return nil
}

func runGraph(args []string) error {
	fs := flag.NewFlagSet("graph", flag.ContinueOnError)
	format := fs.String("format", "mermaid", "output format: mermaid (GitHub renders it), dot (Graphviz) or json")
	plan := fs.String("plan", "", "also include resources from terraform show -json output")
	paths, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	in, err := buildInput(paths, *plan, "", "")
	if err != nil {
		return err
	}
	rep := engine.Scan(in)
	switch *format {
	case "dot":
		fmt.Print(engine.GraphDOT(rep))
	case "json":
		b, err := json.MarshalIndent(rep.Graph, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
	case "mermaid":
		fmt.Print(engine.GraphMermaid(rep))
	default:
		return fmt.Errorf("unknown format %q (mermaid, dot or json)", *format)
	}
	return nil
}

// listFlag collects a repeatable string flag.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// matchesAny reports whether name, or any of its parent directories, matches a glob.
func matchesAny(globs []string, name string) bool {
	for _, g := range globs {
		g = strings.TrimSuffix(strings.TrimSuffix(g, "/**"), "/")
		for p := name; p != "." && p != "/" && p != ""; p = path.Dir(p) {
			if ok, _ := path.Match(g, p); ok {
				return true
			}
		}
	}
	return false
}

// rootKey is how loadFiles names a scanned directory, so var files and files line up.
func rootKey(p string) string {
	key := p
	if cwd, err := os.Getwd(); err == nil {
		if abs, err := filepath.Abs(p); err == nil {
			if rel, err := filepath.Rel(cwd, abs); err == nil && !strings.HasPrefix(rel, "..") {
				key = rel
			}
		}
	}
	if info, err := os.Stat(p); err == nil && !info.IsDir() {
		key = filepath.Dir(key)
	}
	return path.Clean(filepath.ToSlash(key))
}
