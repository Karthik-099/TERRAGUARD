package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A scanned repository's .git/config must not be able to run a command.
func TestGitIgnoredDoesNotRunFsmonitor(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "ran")
	if err := exec.Command("git", "init", "-q", dir).Run(); err != nil {
		t.Skip(err)
	}
	exec.Command("git", "-C", dir, "config", "core.fsmonitor", "touch "+marker+"; false").Run()
	os.WriteFile(filepath.Join(dir, ".env"), []byte("x"), 0o600)
	gitIgnored(filepath.Join(dir, ".env"))
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("core.fsmonitor from the scanned repository ran")
	}
}
