package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Karthik-099/TERRAGUARD/engine"
	"github.com/Karthik-099/TERRAGUARD/internal/pulse"
)

// runPulse reports control adoption, waivers and trend across modules.
func runPulse(args []string) (int, error) {
	fset := flag.NewFlagSet("pulse", flag.ContinueOnError)
	format := fset.String("format", "markdown", "stdout format: markdown or json")
	jsonOut := fset.String("json", "", "also write JSON to this file (use it as the next --baseline)")
	mdOut := fset.String("markdown", "", "also write Markdown to this file")
	baseline := fset.String("baseline", "", "previous pulse JSON, to report the trend")
	minAdoption := fset.Int("min-adoption", 0, "exit 1 if any control's adoption is below this percentage")
	roots, err := parseInterspersed(fset, args)
	if err != nil {
		return 2, err
	}

	var mods []pulse.Module
	for _, root := range roots {
		dirs, err := moduleDirs(root)
		if err != nil {
			return 2, err
		}
		owners, _ := findCodeOwners([]string{root})
		for _, dir := range dirs {
			m, err := scanModule(root, dir)
			if err != nil {
				return 2, err
			}
			if owners != "" {
				co := engine.ParseCodeOwners(owners)
				rel, _ := filepath.Rel(root, dir)
				for i, f := range m.Report.Findings {
					if f.File != "" { // pulse keys files by name within the module
						m.Report.Findings[i].CodeOwners = co.Owners(filepath.ToSlash(filepath.Join(rel, f.File)))
					}
				}
			}
			mods = append(mods, m)
		}
	}
	if len(mods) == 0 {
		return 2, fmt.Errorf("no Terraform modules found under %v", roots)
	}

	var base *pulse.Result
	if *baseline != "" {
		b, err := os.ReadFile(*baseline)
		if err != nil && !os.IsNotExist(err) { // a missing baseline is normal on the first run
			return 2, err
		}
		if err == nil {
			base = &pulse.Result{}
			if err := json.Unmarshal(b, base); err != nil {
				return 2, fmt.Errorf("baseline %s: %w", *baseline, err)
			}
		}
	}
	res := pulse.Build(mods, time.Now(), base)
	js, _ := json.MarshalIndent(res, "", "  ")
	md := pulse.Markdown(res)
	for path, content := range map[string]string{*jsonOut: string(js) + "\n", *mdOut: md} {
		if path != "" {
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				return 2, err
			}
		}
	}
	if *format == "json" {
		fmt.Println(string(js))
	} else {
		fmt.Print(md)
	}
	for _, a := range res.Adoption {
		if a.Percent < *minAdoption {
			return 1, nil
		}
	}
	return 0, nil
}

// moduleDirs returns every directory under root that directly contains .tf files.
func moduleDirs(root string) ([]string, error) {
	set := map[string]bool{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && p != root && (d.Name() == ".terraform" || strings.HasPrefix(d.Name(), ".") || d.Name() == "node_modules") {
			return filepath.SkipDir
		}
		if !d.IsDir() && engine.IsTerraformFile(p) && !strings.HasSuffix(p, ".tfvars") {
			set[filepath.Dir(p)] = true
		}
		return nil
	})
	dirs := make([]string, 0, len(set))
	for d := range set {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	return dirs, err
}

// scanModule scans one directory with the nearest policy file above it.
func scanModule(root, dir string) (pulse.Module, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return pulse.Module{}, err
	}
	files := map[string]string{}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !(engine.IsTerraformFile(n) || strings.Contains(n, ".tfstate")) {
			continue
		}
		if strings.Contains(n, ".tfstate") {
			files[n] = "" // the presence of state is the finding; never read its secrets
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return pulse.Module{}, err
		}
		files[n] = string(b)
	}
	policy, found := nearestPolicy(root, dir)
	policy, err = resolvePolicy(policy, dir)
	if err != nil {
		return pulse.Module{}, fmt.Errorf("%s: %w", dir, err)
	}
	cfg, err := engine.ParseConfig(policy)
	if err != nil {
		return pulse.Module{}, fmt.Errorf("%s: %w", dir, err)
	}
	return pulse.Module{Path: filepath.ToSlash(dir), Report: engine.Scan(engine.Input{Files: files, Config: policy}), Config: cfg, HasPolicy: found}, nil
}

func nearestPolicy(root, dir string) (string, bool) {
	absRoot, _ := filepath.Abs(root)
	for d, _ := filepath.Abs(dir); ; d = filepath.Dir(d) {
		for _, n := range []string{".terraguard.yml", ".terraguard.yaml"} {
			if b, err := os.ReadFile(filepath.Join(d, n)); err == nil {
				return string(b), true
			}
		}
		if d == absRoot || d == filepath.Dir(d) {
			return "", false
		}
	}
}
