package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
