package main

import (
	"os"
	"os/exec"
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
