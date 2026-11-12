package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Karthik-099/TERRAGUARD/engine"
	"gopkg.in/yaml.v3"
)

// Plugins are executables named terraguard-<name>, found on PATH only, never
// in the scanned folder. They run only when --plugins or the policy's
// plugins: list asks for them. See docs/PLUGINS.md for the protocol.

const (
	pluginPrefix         = "terraguard-"
	pluginAPI            = 1
	defaultPluginTimeout = 60 * time.Second
	maxPluginOutput      = 8 << 20
	maxPluginFindings    = 10000
	maxPluginText        = 4096
)

var pluginNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// pluginOptions says which plugins a scan runs.
type pluginOptions struct {
	Names   []string // from --plugins and the policy's plugins:
	All     bool     // --plugins all: every terraguard-* on PATH
	Timeout time.Duration
}

// pluginOptionsFrom merges the --plugins flag ("all" or a comma list), the
// --plugin-timeout flag and the policy's plugins: and plugin_timeout: keys.
func pluginOptionsFrom(policy, flagNames string, flagTimeout time.Duration) (pluginOptions, error) {
	var pol struct {
		Plugins       []string `yaml:"plugins"`
		PluginTimeout string   `yaml:"plugin_timeout"`
	}
	if err := yaml.Unmarshal([]byte(policy), &pol); err != nil {
		return pluginOptions{}, fmt.Errorf(".terraguard.yml: %w", err)
	}
	o := pluginOptions{Timeout: defaultPluginTimeout, Names: pol.Plugins}
	if pol.PluginTimeout != "" {
		d, err := time.ParseDuration(pol.PluginTimeout)
		if err != nil || d <= 0 {
			return o, fmt.Errorf(".terraguard.yml: plugin_timeout %q is not a duration such as 90s", pol.PluginTimeout)
		}
		o.Timeout = d
	}
	if flagTimeout > 0 {
		o.Timeout = flagTimeout
	}
	for _, n := range strings.Split(flagNames, ",") {
		switch n = strings.TrimSpace(n); n {
		case "":
		case "all":
			o.All = true
		default:
			o.Names = append(o.Names, n)
		}
	}
	for _, n := range o.Names {
		if err := checkPluginName(n); err != nil {
			return o, err
		}
	}
	return o, nil
}

func checkPluginName(n string) error {
	if !pluginNameRE.MatchString(n) || n == "tg" || n == "org" || strings.HasPrefix(n, "tg-") || strings.HasPrefix(n, "org-") { // TG- and ORG- belong to built-in and custom rules
		return fmt.Errorf("plugin name %q must be lower-case letters, digits, - or _ (and not start with tg or org)", n)
	}
	return nil
}

// pluginInfo is one plugin found on PATH.
type pluginInfo struct{ Name, Path string }

// findPlugins lists terraguard-* executables on PATH; the first of a name wins,
// as with a shell. Relative PATH entries and folders inside exclude are skipped.
func findPlugins(exclude string) []pluginInfo {
	seen := map[string]bool{}
	var out []pluginInfo
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if !filepath.IsAbs(dir) || inside(exclude, dir) {
			continue
		}
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			name := strings.TrimSuffix(strings.TrimPrefix(e.Name(), pluginPrefix), ".exe")
			if !strings.HasPrefix(e.Name(), pluginPrefix) || seen[name] || checkPluginName(name) != nil {
				continue
			}
			p := filepath.Join(dir, e.Name())
			if info, err := os.Stat(p); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
				seen[name] = true
				out = append(out, pluginInfo{name, p})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// inside reports whether p is root or below it, after resolving symlinks.
func inside(root, p string) bool {
	if root == "" {
		return false
	}
	real := func(s string) string {
		if a, err := filepath.Abs(s); err == nil {
			s = a
		}
		if r, err := filepath.EvalSymlinks(s); err == nil {
			s = r
		}
		return s
	}
	rel, err := filepath.Rel(real(root), real(p))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// lookPlugin finds terraguard-<name> on PATH, refusing one inside root.
func lookPlugin(name, root string) (string, error) {
	if err := checkPluginName(name); err != nil {
		return "", err
	}
	p, err := exec.LookPath(pluginPrefix + name) // never resolves a relative PATH entry (Go returns ErrDot)
	if err != nil {
		return "", fmt.Errorf("plugin %s: no executable %s%s on PATH", name, pluginPrefix, name)
	}
	if p, err = filepath.Abs(p); err != nil {
		return "", err
	}
	if inside(root, p) {
		return "", fmt.Errorf("plugin %s: refusing %s because it is inside the scanned folder", name, p)
	}
	return p, nil
}

// pluginRequest is written to the plugin's stdin.
type pluginRequest struct {
	API     int            `json:"api"`
	Version string         `json:"version"`
	Root    string         `json:"root"`
	Files   []string       `json:"files"` // slash paths relative to root
	Policy  *engine.Config `json:"policy"`
}

// runPlugins runs the enabled plugins against root and returns their
// validated findings, with File set to the same keys as files. Append them
// to engine.Input.Extra so waivers, baselines and the gate apply.
func runPlugins(ctx context.Context, opts pluginOptions, policy, root string, files map[string]string) ([]engine.Finding, error) {
	if !opts.All && len(opts.Names) == 0 {
		return nil, nil
	}
	if info, err := os.Stat(root); err == nil && !info.IsDir() {
		root = filepath.Dir(root)
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	cfg, err := engine.ParseConfig(policy)
	if err != nil {
		return nil, err
	}
	req := pluginRequest{API: pluginAPI, Version: engine.Version, Root: absRoot, Files: []string{}, Policy: cfg}
	keys := map[string]string{} // absolute path -> files key
	for k := range files {
		abs, err := filepath.Abs(k)
		if err != nil {
			continue
		}
		if rel, err := filepath.Rel(absRoot, abs); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			keys[abs] = k
			req.Files = append(req.Files, filepath.ToSlash(rel))
		}
	}
	sort.Strings(req.Files)
	stdin, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	plugins := map[string]string{}
	if opts.All {
		for _, p := range findPlugins(absRoot) {
			plugins[p.Name] = p.Path
		}
	}
	for _, n := range opts.Names {
		if plugins[n] == "" {
			if plugins[n], err = lookPlugin(n, absRoot); err != nil {
				return nil, err
			}
		}
	}
	names := make([]string, 0, len(plugins))
	for n := range plugins {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []engine.Finding
	for _, n := range names {
		raw, err := execPlugin(ctx, n, plugins[n], absRoot, stdin, opts.Timeout)
		if err != nil {
			return nil, err
		}
		fs, err := pluginFindings(n, raw, absRoot)
		if err != nil {
			return nil, fmt.Errorf("plugin %s: %w", n, err)
		}
		for i := range fs {
			if fs[i].File != "" {
				abs := filepath.Join(absRoot, filepath.FromSlash(fs[i].File))
				if k, ok := keys[abs]; ok {
					fs[i].File = k
				} else if rel, err := filepath.Rel(mustGetwd(), abs); err == nil && !strings.HasPrefix(rel, "..") {
					fs[i].File = filepath.ToSlash(rel)
				} else {
					fs[i].File = filepath.ToSlash(abs)
				}
			}
		}
		out = append(out, fs...)
	}
	return out, nil
}

func mustGetwd() string { wd, _ := os.Getwd(); return wd }

// capWriter keeps at most max bytes and remembers that it overflowed.
type capWriter struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	if room := w.max - w.buf.Len(); len(p) > room {
		w.over = true
		w.buf.Write(p[:max(room, 0)])
		return len(p), nil
	}
	return w.buf.Write(p)
}

// execPlugin runs one plugin with the request on stdin, in root, under a timeout.
func execPlugin(ctx context.Context, name, bin, root string, stdin []byte, timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		timeout = defaultPluginTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin)
	cmd.Dir = root
	cmd.Stdin = bytes.NewReader(stdin)
	cmd.WaitDelay = 5 * time.Second // do not hang on a grandchild holding stdout open
	stdout := &capWriter{max: maxPluginOutput}
	stderr := &capWriter{max: 4096}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	detail := strings.TrimSpace(stderr.buf.String())
	if detail != "" {
		detail = ": " + detail
	}
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return nil, fmt.Errorf("plugin %s (%s) did not finish within %s; raise plugin_timeout or --plugin-timeout", name, bin, timeout)
	case err != nil:
		return nil, fmt.Errorf("plugin %s (%s) failed: %v%s", name, bin, err, detail)
	case stdout.over:
		return nil, fmt.Errorf("plugin %s wrote more than %d bytes to stdout", name, maxPluginOutput)
	}
	return stdout.buf.Bytes(), nil
}

// sarifLog is the part of SARIF 2.1.0 a plugin's results need.
type sarifLog struct {
	Runs []struct {
		Results []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

var sarifSeverity = map[string]engine.Severity{"error": engine.High, "warning": engine.Medium, "note": engine.Low, "none": engine.Info}

// pluginFindings decodes a plugin's stdout (TerraGuard findings as a list or
// {"findings": [...]}, or SARIF 2.1.0) and validates every finding.
func pluginFindings(name string, raw []byte, root string) ([]engine.Finding, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, nil
	}
	var fs []engine.Finding
	switch raw[0] {
	case '[':
		if err := json.Unmarshal(raw, &fs); err != nil {
			return nil, fmt.Errorf("output is not a list of findings: %w", err)
		}
	case '{':
		var probe struct {
			Runs     json.RawMessage  `json:"runs"`
			Findings []engine.Finding `json:"findings"`
		}
		if err := json.Unmarshal(raw, &probe); err != nil {
			return nil, fmt.Errorf("output is not JSON: %w", err)
		}
		fs = probe.Findings
		if probe.Runs != nil {
			var s sarifLog
			if err := json.Unmarshal(raw, &s); err != nil {
				return nil, fmt.Errorf("output is not SARIF 2.1.0: %w", err)
			}
			for _, run := range s.Runs {
				for _, r := range run.Results {
					f := engine.Finding{RuleID: r.RuleID, Severity: sarifSeverity[r.Level], Message: r.Message.Text}
					if f.Severity == "" {
						f.Severity = engine.Medium // SARIF's default level is warning
					}
					if len(r.Locations) > 0 {
						loc := r.Locations[0].PhysicalLocation
						f.File, f.Line = strings.TrimPrefix(loc.ArtifactLocation.URI, "file://"), loc.Region.StartLine
					}
					fs = append(fs, f)
				}
			}
		}
	default:
		return nil, errors.New("output must be JSON: a list of findings, {\"findings\": [...]} or SARIF 2.1.0")
	}
	if len(fs) > maxPluginFindings {
		return nil, fmt.Errorf("reported %d findings, more than the limit of %d", len(fs), maxPluginFindings)
	}
	prefix := strings.ToUpper(name) + "-"
	for i := range fs {
		f := &fs[i]
		id := strings.TrimSpace(f.RuleID)
		if id == "" {
			return nil, fmt.Errorf("finding %d has no rule_id", i+1)
		}
		if !strings.HasPrefix(strings.ToUpper(id), prefix) {
			id = prefix + id // a plugin can never report as a built-in (TG-) or custom (ORG-) rule
		}
		file, err := pluginFile(f.File, root)
		if err != nil {
			return nil, fmt.Errorf("finding %s: %w", id, err)
		}
		sev := engine.ParseSeverity(string(f.Severity))
		if sev.Rank() == 0 {
			sev = engine.Medium
		}
		cat := f.Category
		switch cat {
		case engine.CatSecurity, engine.CatValidate, engine.CatReliability, engine.CatBestPrac, engine.CatPolicy, engine.CatCost:
		default:
			cat = engine.CatPolicy
		}
		// Only descriptive fields pass; a plugin cannot waive, block apply or edit files.
		*f = engine.Finding{
			RuleID: clip(id, 128), Severity: sev, Category: cat, Title: clip(f.Title, maxPluginText),
			Message: clip(f.Message, maxPluginText), Resource: clip(f.Resource, 512), File: file, Line: max(f.Line, 0),
			Remediation: clip(f.Remediation, maxPluginText), Owner: clip(f.Owner, 256), Docs: clip(f.Docs, 1024), CWE: clip(f.CWE, 32),
		}
		if f.Title == "" {
			f.Title = f.RuleID
		}
		if f.Message == "" {
			f.Message = f.Title
		}
	}
	return fs, nil
}

// pluginFile turns a reported path into a slash path relative to root, rejecting escapes.
func pluginFile(p, root string) (string, error) {
	if p == "" {
		return "", nil
	}
	p = filepath.FromSlash(p)
	if !filepath.IsAbs(p) {
		p = filepath.Join(root, p)
	}
	rel, err := filepath.Rel(root, filepath.Clean(p))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("file %q is outside the scanned folder", p)
	}
	return filepath.ToSlash(rel), nil
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

// runPluginsCmd is `terraguard plugins list` and `terraguard plugins test NAME [path]`.
func runPluginsCmd(args []string) (int, error) {
	if len(args) == 0 || args[0] == "list" {
		ps := findPlugins("")
		if len(ps) == 0 {
			fmt.Println("no terraguard-* plugins on PATH")
			return 0, nil
		}
		for _, p := range ps {
			fmt.Printf("%-24s %s\n", p.Name, p.Path)
		}
		return 0, nil
	}
	if args[0] != "test" {
		return 2, fmt.Errorf("usage: terraguard plugins list | plugins test NAME [path] [--timeout 60s]")
	}
	fs := flag.NewFlagSet("plugins test", flag.ContinueOnError)
	timeout := fs.Duration("timeout", defaultPluginTimeout, "stop the plugin after this long")
	config := fs.String("config", "", "policy file (default: .terraguard.yml, found automatically)")
	pos, err := parseInterspersed(fs, args[1:])
	if err != nil {
		return 2, err
	}
	if len(args) < 2 {
		return 2, errors.New("usage: terraguard plugins test NAME [path]")
	}
	name, root := pos[0], "."
	if len(pos) > 1 {
		root = pos[1]
	}
	files, err := loadFiles([]string{root})
	if err != nil {
		return 2, err
	}
	policy, err := findConfig(*config, []string{root})
	if err != nil {
		return 2, err
	}
	found, err := runPlugins(context.Background(), pluginOptions{Names: []string{name}, Timeout: *timeout}, policy, root, files)
	if err != nil {
		return 2, err
	}
	b, _ := json.MarshalIndent(found, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "plugin %s: %d valid finding(s)\n", name, len(found))
	return 0, nil
}
