package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/Karthik-099/TERRAGUARD/engine"
	"github.com/Karthik-099/TERRAGUARD/internal/vuln"
)

const vulnUsage = `usage:
  terraguard vuln update [--ecosystems npm,PyPI,Go,...] [--dir DIR]   download the OSV database (network)
  terraguard vuln [paths] [--format text|json|sarif|markdown] [--fail-on SEVERITY] [--db DIR]
  terraguard vuln image IMAGE.tar [same flags]   scan a 'docker save IMAGE -o image.tar' archive`

// runVuln scans lockfiles and image archives against an offline OSV copy.
func runVuln(args []string) (int, error) {
	if len(args) > 0 {
		switch args[0] {
		case "update":
			return runVulnUpdate(args[1:])
		case "image":
			return runVulnScan(args[1:], true)
		}
	}
	return runVulnScan(args, false)
}

func runVulnUpdate(args []string) (int, error) {
	fs := flag.NewFlagSet("vuln update", flag.ContinueOnError)
	ecos := fs.String("ecosystems", strings.Join(vuln.DefaultEcosystems, ","), "comma-separated OSV ecosystems")
	dir := fs.String("dir", vuln.DefaultDir(), "database directory")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	var list []string
	for _, e := range strings.Split(*ecos, ",") {
		if e = strings.TrimSpace(e); e != "" {
			list = append(list, e)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	fmt.Fprintf(os.Stderr, "Downloading OSV data into %s\n", *dir)
	if err := vuln.Update(ctx, *dir, list, os.Stderr); err != nil {
		return 2, err
	}
	return 0, nil
}

var vulnFailOn = map[string]bool{"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true, "UNKNOWN": true, "NONE": true}

func runVulnScan(args []string, image bool) (int, error) {
	fs := flag.NewFlagSet("vuln", flag.ContinueOnError)
	format := fs.String("format", "text", "text, json, sarif or markdown")
	failOn := fs.String("fail-on", "HIGH", "exit 1 at or above CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN, or NONE")
	dbDir := fs.String("db", vuln.DefaultDir(), "database directory from terraguard vuln update")
	fs.Usage = func() { fmt.Fprintln(fs.Output(), vulnUsage); fs.PrintDefaults() }
	paths, err := parseInterspersed(fs, args)
	if err != nil {
		return 2, err
	}
	threshold := strings.ToUpper(*failOn)
	if !vulnFailOn[threshold] {
		return 2, fmt.Errorf("--fail-on %q: use CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN or NONE", *failOn)
	}
	db, err := vuln.Open(*dbDir)
	if err != nil {
		return 2, err
	}
	if age := time.Since(db.Meta.Updated); age > 7*24*time.Hour {
		fmt.Fprintf(os.Stderr, "warning: the vulnerability database is %d days old; run terraguard vuln update\n", int(age.Hours()/24))
	}
	var pkgs []vuln.Package
	var notes []string
	if image {
		if len(paths) != 1 || paths[0] == "." {
			return 2, errors.New("usage: terraguard vuln image IMAGE.tar (create it with: docker save IMAGE -o image.tar)")
		}
		img, err := scanImageFile(paths[0])
		if err != nil {
			return 2, err
		}
		pkgs, notes = img.Packages, img.Notes
		if img.OS != "" {
			notes = append(notes, "operating system: "+img.OS)
		}
	} else {
		files, err := vuln.FindLockfiles(paths)
		if err != nil {
			return 2, err
		}
		pkgs, notes = vuln.ReadLockfiles(files)
	}
	matches, err := vuln.MatchAll(db, pkgs)
	if err != nil {
		return 2, err
	}
	if err := writeVuln(os.Stdout, *format, db, pkgs, matches, notes); err != nil {
		return 2, err
	}
	if threshold == "NONE" {
		return 0, nil
	}
	for _, m := range matches {
		if engine.Severity(m.Severity).Rank() >= engine.Severity(threshold).Rank() {
			return 1, nil
		}
	}
	return 0, nil
}

func scanImageFile(p string) (*vuln.Image, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	img, err := vuln.ScanImage(f, st.Size())
	if err != nil {
		return nil, fmt.Errorf("%s: %w (create the archive with: docker save IMAGE -o image.tar)", p, err)
	}
	for i := range img.Packages {
		img.Packages[i].File = p + "!/" + img.Packages[i].File
	}
	return img, nil
}

func writeVuln(w io.Writer, format string, db *vuln.DB, pkgs []vuln.Package, matches []vuln.Match, notes []string) error {
	findings := make([]engine.Finding, len(matches))
	for i, m := range matches {
		findings[i] = m.Finding()
	}
	switch format {
	case "json":
		b, err := json.MarshalIndent(map[string]any{
			"database_updated": db.Meta.Updated, "packages": len(pkgs), "findings": findings, "notes": notes,
		}, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(b))
		return err
	case "sarif":
		for i := range findings {
			if findings[i].Severity.Rank() == 0 {
				findings[i].Severity = engine.Info // SARIF has no level for an unrated advisory
			}
		}
		b, err := engine.SARIF(&engine.Report{Findings: findings})
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(b))
		return err
	case "markdown", "md":
		fmt.Fprintf(w, "## TerraGuard vulnerabilities: %d in %d packages\n\n", len(matches), len(pkgs))
		if len(matches) > 0 {
			fmt.Fprintln(w, "| Severity | Package | Version | Vulnerability | Fixed in | Location |\n|---|---|---|---|---|---|")
		}
		for _, m := range matches {
			fmt.Fprintf(w, "| %s | `%s` | %s | [%s](https://osv.dev/vulnerability/%s) | %s | `%s` |\n",
				m.Severity, m.Package.Name, m.Package.Version, m.ID, m.ID, orDash(m.Fixed), location(m.Package))
		}
	case "text":
		for _, m := range matches {
			fmt.Fprintf(w, "%-8s %-22s %s %s  %s  fixed: %s\n", m.Severity, m.ID, m.Package.Name, m.Package.Version, location(m.Package), orDash(m.Fixed))
		}
		fmt.Fprintf(w, "\n%d vulnerabilities in %d packages (database updated %s)\n", len(matches), len(pkgs), db.Meta.Updated.Format("2006-01-02"))
	default:
		return fmt.Errorf("unknown --format %q: use text, json, sarif or markdown", format)
	}
	for _, n := range notes {
		fmt.Fprintln(os.Stderr, "note:", n)
	}
	return nil
}

func location(p vuln.Package) string {
	if p.Line > 0 {
		return fmt.Sprintf("%s:%d", p.File, p.Line)
	}
	return p.File
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
