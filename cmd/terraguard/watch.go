package main

import (
	"fmt"
	"hash/fnv"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Karthik-099/TERRAGUARD/engine"
)

// cutFlag removes a boolean flag from args.
func cutFlag(args []string, name string) ([]string, bool) {
	var out []string
	found := false
	for _, a := range args {
		if a == name || a == "-"+strings.TrimLeft(name, "-") {
			found = true
			continue
		}
		out = append(out, a)
	}
	return out, found
}

// watchScan reruns the scan whenever a file it reads changes: polling, so it
// works the same on every OS and needs no dependency.
func watchScan(args []string) (int, error) {
	roots := []string{}
	for _, a := range args {
		if !strings.HasPrefix(a, "-") && exists(a) {
			roots = append(roots, a)
		}
	}
	if len(roots) == 0 {
		roots = []string{"."}
	}
	var last uint64
	for {
		if sum := fingerprint(roots); sum != last {
			last = sum
			fmt.Print("\033[H\033[2J") // clear the terminal between runs
			fmt.Printf("terraguard: watching %s (Ctrl+C to stop) %s\n\n", strings.Join(roots, ", "), time.Now().Format("15:04:05"))
			if _, err := runScan(args); err != nil {
				fmt.Fprintln(os.Stderr, "terraguard:", err)
			}
		}
		time.Sleep(700 * time.Millisecond)
	}
}

// fingerprint hashes the names, sizes and modification times of scannable files.
func fingerprint(roots []string) uint64 {
	h := fnv.New64a()
	for _, root := range roots {
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() && p != root && (strings.HasPrefix(d.Name(), ".") && d.Name() != ".github" || d.Name() == "node_modules" || d.Name() == "vendor") {
				return filepath.SkipDir
			}
			if !d.IsDir() && (engine.IsScannable(p) || strings.HasPrefix(d.Name(), ".terraguard")) {
				if info, err := d.Info(); err == nil {
					fmt.Fprintf(h, "%s|%d|%d\n", p, info.Size(), info.ModTime().UnixNano())
				}
			}
			return nil
		})
	}
	return h.Sum64()
}
