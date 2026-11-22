package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Karthik-099/TERRAGUARD/engine"
	"github.com/Karthik-099/TERRAGUARD/internal/ai"
)

// runReview gates on what a change introduces, not on existing debt.
func runReview(args []string) (int, error) {
	fset := flag.NewFlagSet("review", flag.ContinueOnError)
	base := fset.String("base", "origin/main", "git revision to compare against (e.g. the PR base SHA)")
	format := fset.String("format", "markdown", "stdout format: markdown, json or github-review (pull-request review payload)")
	out := fset.String("out", "", "write the --format output to this file instead of stdout")
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
	if strings.HasPrefix(*base, "-") {
		return 2, fmt.Errorf("--base %q is not a git revision", *base)
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
	stdout := md
	switch *format {
	case "json":
		stdout = string(js) + "\n"
	case "github-review":
		gr, err := githubReviewFromGit(rev, head.Files, *base)
		if err != nil {
			return 2, err
		}
		b, _ := json.MarshalIndent(gr, "", "  ")
		stdout = string(b) + "\n"
	}
	if *out != "" {
		if err := os.WriteFile(*out, []byte(stdout), 0o644); err != nil {
			return 2, err
		}
	} else {
		fmt.Print(stdout)
	}
	if !rev.Passed {
		return 1, nil
	}
	return 0, nil
}

func git(args ...string) (string, error) {
	out, err := exec.Command("git", append([]string{"-c", "core.fsmonitor=false"}, args...)...).Output()
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
		if !engine.IsTerraformFile(p) {
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

// reviewMarker finds TerraGuard's own review and comments so the Action can
// replace them instead of stacking duplicates.
const reviewMarker = "<!-- terraguard-review -->"

type ghComment struct {
	Path      string `json:"path"`
	Line      int    `json:"line"`
	Side      string `json:"side"`
	StartLine int    `json:"start_line,omitempty"`
	StartSide string `json:"start_side,omitempty"`
	Body      string `json:"body"`
}

// ghReview is the body of POST /repos/{owner}/{repo}/pulls/{n}/reviews.
type ghReview struct {
	Body     string      `json:"body"`
	Event    string      `json:"event"`
	Comments []ghComment `json:"comments"`
}

func githubReviewFromGit(rev *engine.Review, files map[string]string, base string) (ghReview, error) {
	diff, err := git("diff", "-U0", "--relative", "--no-color", "--no-ext-diff", base, "--")
	if err != nil {
		return ghReview{}, err
	}
	prefix, err := git("rev-parse", "--show-prefix") // GitHub paths are relative to the repository root
	if err != nil {
		return ghReview{}, err
	}
	return buildGitHubReview(rev, files, addedLines(diff), strings.TrimSpace(prefix)), nil
}

var hunkRE = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@`)

// addedLines maps each file in a unified diff to its added (RIGHT side) lines.
func addedLines(diff string) map[string]map[int]bool {
	out := map[string]map[int]bool{}
	var cur map[int]bool
	for _, l := range strings.Split(diff, "\n") {
		if name, ok := strings.CutPrefix(l, "+++ "); ok {
			cur = nil
			// Quoted names (unusual characters) and deletions get no inline comments.
			if name, ok = strings.CutPrefix(name, "b/"); ok {
				cur = map[int]bool{}
				out[name] = cur
			}
			continue
		}
		if m := hunkRE.FindStringSubmatch(l); m != nil && cur != nil {
			start, _ := strconv.Atoi(m[1])
			n := 1
			if m[2] != "" {
				n, _ = strconv.Atoi(m[2])
			}
			for i := start; i < start+n; i++ {
				cur[i] = true
			}
		}
	}
	return out
}

// buildGitHubReview puts each new finding on a changed line inline, with a
// suggestion block when its safe fix only touches the changed lines around it.
// Everything else is listed in the review body.
func buildGitHubReview(rev *engine.Review, files map[string]string, added map[string]map[int]bool, prefix string) ghReview {
	status := "passed"
	if !rev.Passed {
		status = "changes requested"
	}
	var body strings.Builder
	fmt.Fprintf(&body, "%s\n## TerraGuard review: %s (%s risk tier)\n\n%d new finding(s) · %d resolved · %d pre-existing.\n",
		reviewMarker, status, rev.Tier, len(rev.New), len(rev.Resolved), rev.Existing)
	gr := ghReview{Event: "COMMENT", Comments: []ghComment{}}
	var rest []engine.Finding
	for _, f := range rev.New {
		lines := added[f.File]
		if f.Line <= 0 || !lines[f.Line] {
			rest = append(rest, f)
			continue
		}
		lo, hi := f.Line, f.Line // the run of changed lines around the finding
		for lines[lo-1] {
			lo--
		}
		for lines[hi+1] {
			hi++
		}
		c := ghComment{Path: prefix + f.File, Line: f.Line, Side: "RIGHT"}
		text := fmt.Sprintf("%s\n**%s** %s **%s**\n\n%s", reviewMarker, f.Severity, mdCode(f.RuleID), mdText(f.Title), mdText(f.Message))
		if f.Remediation != "" {
			text += "\n\nFix: " + mdText(f.Remediation)
		}
		if s, e, repl, ok := suggestion(files, f); ok && lo <= s && e <= hi {
			c.Line = e
			if s < e {
				c.StartLine, c.StartSide = s, "RIGHT"
			}
			fence := strings.Repeat("`", max(3, longestRun(strings.Join(repl, "\n"), '`')+1))
			text += "\n\n" + fence + "suggestion\n" + strings.Join(repl, "\n") + "\n" + fence
		} else if ok {
			text += "\n\nThe safe fix also changes lines outside this change; run `terraguard fix` to apply it."
		}
		c.Body = text
		gr.Comments = append(gr.Comments, c)
	}
	if len(rest) > 0 {
		body.WriteString("\nNot on a changed line:\n\n")
		for i, f := range rest {
			if i == 50 {
				fmt.Fprintf(&body, "- and %d more\n", len(rest)-50)
				break
			}
			fmt.Fprintf(&body, "- **%s** %s %s: %s\n", f.Severity, mdCode(f.RuleID), mdCode(fmt.Sprintf("%s:%d", prefix+f.File, f.Line)), mdText(f.Title))
		}
	}
	gr.Body = body.String()
	return gr
}

// suggestion returns the old line range s..e (1-based) a finding's fix
// replaces and the replacement lines. A pure insertion is widened to the line
// before it, because a suggestion must replace at least one line.
func suggestion(files map[string]string, f engine.Finding) (s, e int, repl []string, ok bool) {
	h, ok := engine.FixHunkFor(files, f) // never for secret findings
	if !ok || h.File != f.File {
		return 0, 0, nil, false
	}
	old := strings.Split(files[h.File], "\n")
	s, e, repl = h.Start, h.End, h.Lines
	if e < s {
		if s > 1 {
			s, e = s-1, s-1
			repl = append([]string{old[s-1]}, repl...)
		} else {
			e = s
			repl = append(append([]string{}, repl...), old[0])
		}
	}
	return s, e, repl, true
}

func longestRun(s string, c byte) int {
	best, n := 0, 0
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			n++
			best = max(best, n)
		} else {
			n = 0
		}
	}
	return best
}

// mdText makes untrusted text inert in Markdown: one line, punctuation
// that could open a code span, link, table cell, entity or HTML escaped, and
// @mentions broken so a resource name cannot notify anyone.
func mdText(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune("\\`*[]<>|~&", r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
		if r == '@' {
			b.WriteString("&#8203;")
		}
	}
	return b.String()
}

// mdCode is an inline code span that untrusted text cannot break out of.
func mdCode(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	fence := strings.Repeat("`", longestRun(s, '`')+1)
	return fence + " " + s + " " + fence
}
