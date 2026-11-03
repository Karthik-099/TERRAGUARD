package main

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// openFixPR puts the fixed files on a new branch, pushes it and opens a pull
// request with the gh CLI when it is installed. Without gh it prints the
// commands to finish by hand. Only the files the fixer wrote are committed.
func openFixPR(files []string, base string) error {
	if len(files) == 0 {
		return nil
	}
	sort.Strings(files)
	if out, err := git("rev-parse", "--is-inside-work-tree"); err != nil || strings.TrimSpace(out) != "true" {
		return fmt.Errorf("--pr needs a git repository")
	}
	if base == "" {
		out, _ := git("rev-parse", "--abbrev-ref", "HEAD")
		base = strings.TrimSpace(out)
	}
	branch := "terraguard/fix-" + time.Now().UTC().Format("20060102-150405")
	msg := fmt.Sprintf("fix: apply %d TerraGuard fix(es)", len(files))
	steps := [][]string{
		{"switch", "-c", branch},
		append([]string{"add", "--"}, files...),
		append([]string{"commit", "-m", msg, "--"}, files...),
		{"push", "-u", "origin", branch},
	}
	for _, s := range steps {
		if _, err := git(s...); err != nil {
			return err
		}
	}
	body := "Fixes applied by `terraguard fix`. Each change is one the engine marks safe; review before merging.\n\nFiles:\n- " + strings.Join(files, "\n- ")
	if _, err := exec.LookPath("gh"); err != nil {
		fmt.Printf("pushed %s. gh is not installed; open the pull request with:\n  gh pr create --base %s --head %s --title %q\n", branch, base, branch, msg)
		return nil
	}
	cmd := exec.Command("gh", "pr", "create", "--base", base, "--head", branch, "--title", msg, "--body", body)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}
