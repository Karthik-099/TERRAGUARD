package main

import (
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
)

// changedDirs returns the directories (slash paths relative to the working
// directory, "." for it) holding a file changed since base, including
// uncommitted and untracked files. An empty base means origin/main, or
// HEAD~1 when there is no origin/main.
func changedDirs(base string) (dirs []string, used string, err error) {
	if strings.HasPrefix(base, "-") {
		return nil, "", fmt.Errorf("--base %q is not a git revision", base)
	}
	used = base
	if used == "" {
		used = "origin/main"
		if _, err := git("rev-parse", "--verify", "--quiet", "origin/main^{commit}"); err != nil {
			used = "HEAD~1"
		}
	}
	diff, err := git("diff", "--name-only", "--relative", used, "--")
	if err != nil {
		return nil, used, err
	}
	untracked, err := git("ls-files", "--others", "--exclude-standard")
	if err != nil {
		return nil, used, err
	}
	seen := map[string]bool{}
	for _, f := range strings.Split(diff+"\n"+untracked, "\n") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		d := path.Dir(f)
		// A deleted file still changes its directory's result, if the directory is left.
		if info, err := os.Stat(d); err == nil && info.IsDir() && !seen[d] {
			seen[d] = true
			dirs = append(dirs, d)
		}
	}
	sort.Strings(dirs)
	return dirs, used, nil
}

// keepDirs drops every file whose directory is not in dirs. Only the
// directory itself counts, not its subdirectories: Terraform evaluates a
// module per directory, so a changed main.tf needs its variables.tf beside it.
func keepDirs(files map[string]string, dirs []string) {
	in := map[string]bool{}
	for _, d := range dirs {
		in[d] = true
	}
	for name := range files {
		if !in[path.Dir(name)] {
			delete(files, name)
		}
	}
}
