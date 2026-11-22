package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Karthik-099/TERRAGUARD/engine"
)

func TestReviewAgainstGitBase(t *testing.T) {
	t.Chdir(t.TempDir())
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	os.WriteFile("main.tf", []byte("resource \"aws_kms_key\" \"k\" {\n}\n"), 0o644)
	run("add", ".")
	run("commit", "-qm", "base")

	// The legacy KMS finding is pre-existing; only the new open SG should fail the review.
	os.WriteFile("main.tf", []byte("resource \"aws_kms_key\" \"k\" {\n}\n"+openSSH), 0o644)
	if code, err := runReview([]string{"--base", "HEAD", "--format", "json", "."}); err != nil || code != 1 {
		t.Fatalf("new high finding must fail the review: code=%d err=%v", code, err)
	}
	os.WriteFile("main.tf", []byte("resource \"aws_kms_key\" \"k\" {\n  description = \"x\"\n}\n"), 0o644)
	if code, err := runReview([]string{"--base", "HEAD", "."}); err != nil || code != 0 {
		t.Fatalf("pre-existing debt must not fail the review: code=%d err=%v", code, err)
	}
}

func TestReviewCannotLoosenItsOwnGate(t *testing.T) {
	t.Chdir(t.TempDir())
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	os.WriteFile(".terraguard.yml", []byte("fail_on: HIGH\n"), 0o644)
	os.WriteFile("main.tf", []byte("resource \"aws_kms_key\" \"k\" {\n  enable_key_rotation = true\n}\n"), 0o644)
	run("add", ".")
	run("commit", "-qm", "base")

	// The change adds an open security group, turns the gate off, and hides a
	// second risk with an inline ignore.
	os.WriteFile(".terraguard.yml", []byte("fail_on: NONE\ndisable: [\"TG-AWS-SG-*\"]\n"), 0o644)
	os.WriteFile("main.tf", []byte("resource \"aws_kms_key\" \"k\" {\n  enable_key_rotation = true\n}\n"+openSSH+
		"# terraguard:ignore TG-AWS-S3-001\nresource \"aws_s3_bucket\" \"b\" {\n  bucket = \"loophole-bucket\"\n  acl    = \"public-read\"\n}\n"), 0o644)
	md := filepath.Join(t.TempDir(), "review.md")
	code, err := runReview([]string{"--base", "HEAD", "--markdown", md, "."})
	if err != nil || code != 1 {
		t.Fatalf("a change must be judged by the base policy: code=%d err=%v", code, err)
	}
	out, _ := os.ReadFile(md)
	for _, want := range []string{"fail_on loosened from HIGH to NONE", "disables TG-AWS-SG-*", "Silenced by new inline ignores", "TG-AWS-S3-001"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("review does not mention %q:\n%s", want, out)
		}
	}
}

const ebsVolume = "resource \"aws_ebs_volume\" \"v\" {\n  availability_zone = \"us-east-1a\"\n  size              = 10\n}\n"

func TestGitHubReviewPayload(t *testing.T) {
	t.Chdir(t.TempDir())
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	os.MkdirAll("infra", 0o755)
	os.WriteFile("infra/main.tf", []byte("resource \"aws_kms_key\" \"k\" {\n  enable_key_rotation = true\n}\n"), 0o644)
	run("add", ".")
	run("commit", "-qm", "base")
	head := "resource \"aws_kms_key\" \"k\" {\n  enable_key_rotation = true\n}\n" + ebsVolume
	os.WriteFile("infra/main.tf", []byte(head), 0o644)
	run("add", ".")
	run("commit", "-qm", "head")

	// Run from the subdirectory: comment paths must still be repository-relative.
	t.Chdir("infra")
	out := filepath.Join(t.TempDir(), "review.json")
	if _, err := runReview([]string{"--base", "HEAD~1", "--format", "github-review", "--out", out, "."}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	var gr ghReview
	if err := json.Unmarshal(b, &gr); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	if gr.Event != "COMMENT" || !strings.HasPrefix(gr.Body, reviewMarker) {
		t.Fatalf("bad review header: %+v", gr)
	}
	var c *ghComment
	for i := range gr.Comments {
		if strings.Contains(gr.Comments[i].Body, "TG-AWS-EBS-001") {
			c = &gr.Comments[i]
		}
	}
	if c == nil || c.Path != "infra/main.tf" || c.Side != "RIGHT" || !strings.HasPrefix(c.Body, reviewMarker) {
		t.Fatalf("no inline EBS comment in:\n%s", b)
	}
	_, sug, ok := strings.Cut(c.Body, "```suggestion\n")
	if !ok {
		t.Fatalf("no suggestion block:\n%s", c.Body)
	}
	sug, _, _ = strings.Cut(sug, "\n```")

	// Replacing lines start..line with the suggestion must give the fixed file.
	rep := engine.Scan(engine.Input{Files: map[string]string{"main.tf": head}})
	var fixes []*engine.Fix
	for _, f := range rep.Findings {
		if f.RuleID == "TG-AWS-EBS-001" {
			fixes = append(fixes, f.Fix)
		}
	}
	fixed, errs := engine.ApplyFixes(map[string]string{"main.tf": head}, fixes)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	old := strings.Split(head, "\n")
	start := c.StartLine
	if start == 0 {
		start = c.Line
	}
	got := strings.Join(append(append(append([]string{}, old[:start-1]...), strings.Split(sug, "\n")...), old[c.Line:]...), "\n")
	if got != fixed["main.tf"] {
		t.Fatalf("suggestion %q at %d-%d does not reproduce the fix:\n%s\nwant:\n%s", sug, start, c.Line, got, fixed["main.tf"])
	}
}

func TestGitHubReviewFixOutsideChangeAndSecrets(t *testing.T) {
	files := map[string]string{"main.tf": ebsVolume}
	rep := engine.Scan(engine.Input{Files: files})
	rev := &engine.Review{Passed: true, Tier: "lite"}
	for _, f := range rep.Findings {
		if f.RuleID == "TG-AWS-EBS-001" {
			rev.New = append(rev.New, f)
		}
	}
	secret := engine.Finding{RuleID: "TG-SECRET-002", Severity: engine.Critical, Title: "GitHub token committed", Message: "GitHub token (ghp_...) is committed.",
		File: "main.tf", Line: 1, Fix: &engine.Fix{File: "main.tf", Block: "resource.aws_ebs_volume.v", Path: []string{"tags"}, Value: "x"}}
	rev.New = append(rev.New, secret)
	// Only the resource header changed, and the fix inserts near the end of the block.
	gr := buildGitHubReview(rev, files, map[string]map[int]bool{"main.tf": {1: true}}, "")
	if len(gr.Comments) != 2 {
		t.Fatalf("want 2 inline comments, got %+v", gr.Comments)
	}
	for _, c := range gr.Comments {
		if strings.Contains(c.Body, "suggestion") || c.Line != 1 || c.StartLine != 0 {
			t.Errorf("must be a plain comment on line 1: %+v", c)
		}
	}
	if !strings.Contains(gr.Comments[0].Body, "outside this change") {
		t.Errorf("fix outside the change not explained: %s", gr.Comments[0].Body)
	}
}

func TestMarkdownEscaping(t *testing.T) {
	evil := "x\n```\n</details><!-- terraguard-review --> @org/team [a](javascript:1) | y"
	got := mdText(evil)
	if strings.Contains(got, "\n") || strings.Contains(got, "@org") {
		t.Errorf("mdText kept a newline or a mention: %q", got)
	}
	for i := 0; i < len(got); i++ { // every special character must be backslash-escaped
		if strings.IndexByte("`<>[]|", got[i]) >= 0 && (i == 0 || got[i-1] != '\\') {
			t.Errorf("unescaped %q at %d in %q", got[i], i, got)
		}
	}
	if c := mdCode("a``b"); c != "``` a``b ```" {
		t.Errorf("mdCode = %q", c)
	}
	if got := addedLines("+++ b/a.tf\n@@ -0,0 +1,3 @@\n+x\n@@ -9 +12 @@\n+++ /dev/null\n@@ -1 +0,0 @@\n"); len(got) != 1 || !got["a.tf"][3] || !got["a.tf"][12] || got["a.tf"][4] {
		t.Errorf("addedLines = %v", got)
	}
}
