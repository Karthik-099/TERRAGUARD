package vuln

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Karthik-099/TERRAGUARD/engine"
)

const maxLockfile = 64 << 20

// FindLockfiles walks roots for lockfiles, skipping installed trees and hidden directories.
func FindLockfiles(roots []string) ([]string, error) {
	var out []string
	for _, root := range roots {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			name := d.Name()
			if d.IsDir() {
				if p != root && (name == "node_modules" || name == "vendor" || strings.HasPrefix(name, ".")) {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type().IsRegular() && IsLockfile(name) && !(name == "go.sum" && exists(filepath.Join(filepath.Dir(p), "go.mod"))) {
				out = append(out, p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func anyIn(set map[string]bool, keys []string) bool {
	for _, k := range keys {
		if set[k] {
			return true
		}
	}
	return false
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// ReadLockfiles parses each lockfile; a broken one is reported, not fatal.
func ReadLockfiles(files []string) (pkgs []Package, notes []string) {
	for _, f := range files {
		st, err := os.Stat(f)
		if err == nil && st.Size() > maxLockfile {
			err = fmt.Errorf("larger than %d bytes", maxLockfile)
		}
		var b []byte
		if err == nil {
			b, err = os.ReadFile(f)
		}
		if err == nil {
			var ps []Package
			ps, err = ParseLockfile(filepath.ToSlash(f), b)
			pkgs = append(pkgs, ps...)
		}
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s: %v", f, err))
		}
	}
	return pkgs, notes
}

// Match is one package affected by one vulnerability.
type Match struct {
	Package Package  `json:"package"`
	ID      string   `json:"id"`
	Aliases []string `json:"aliases,omitempty"`
	Summary string   `json:"summary"`
	// Severity is CRITICAL, HIGH, MEDIUM, LOW or UNKNOWN.
	Severity string `json:"severity"`
	Fixed    string `json:"fixed,omitempty"`
}

// MatchAll looks every package up. A missing ecosystem is an error, so a scan
// never passes just because its data was not downloaded.
func MatchAll(db *DB, pkgs []Package) ([]Match, error) {
	var out []Match
	seen := map[string]bool{}
	for _, p := range pkgs {
		key := strings.Join([]string{p.Ecosystem, p.Name, p.Version, p.File}, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		entries, err := db.Lookup(p.Ecosystem, p.Name)
		if err != nil {
			return nil, err
		}
		var hits []Match
		for _, e := range entries {
			if hit, fixed := e.Affects(p.Ecosystem, p.Version); hit {
				hits = append(hits, Match{Package: p, ID: e.ID, Aliases: e.Aliases, Summary: e.Summary, Severity: e.Severity, Fixed: fixed})
			}
		}
		// One flaw is often published twice (GO-... and GHSA-...); keep the rated copy.
		sort.SliceStable(hits, func(i, j int) bool {
			return engine.Severity(hits[i].Severity).Rank() > engine.Severity(hits[j].Severity).Rank()
		})
		ids := map[string]bool{}
		for _, m := range hits {
			if ids[m.ID] || anyIn(ids, m.Aliases) {
				continue
			}
			ids[m.ID] = true
			for _, a := range m.Aliases {
				ids[a] = true
			}
			out = append(out, m)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ra, rb := engine.Severity(a.Severity).Rank(), engine.Severity(b.Severity).Rank(); ra != rb {
			return ra > rb
		}
		if a.Package.File != b.Package.File {
			return a.Package.File < b.Package.File
		}
		return a.Package.Line < b.Package.Line
	})
	return out, nil
}

// IsMissing reports whether err asks the user to download an ecosystem.
func IsMissing(err error) bool {
	var m *MissingEcosystemError
	return errors.As(err, &m) || errors.Is(err, ErrNoDatabase)
}

// Finding turns a match into the engine's finding so its formatters apply.
func (m Match) Finding() engine.Finding {
	p := m.Package
	ref := m.ID
	if cves := cveAliases(m.Aliases); len(cves) > 0 {
		ref += " (" + strings.Join(cves, ", ") + ")"
	}
	msg := fmt.Sprintf("%s %s (%s) is affected by %s", p.Name, p.Version, p.Ecosystem, ref)
	if m.Summary != "" {
		msg += ": " + m.Summary
	}
	fix := "No fixed version is published yet; consider an alternative or mitigate."
	if m.Fixed != "" {
		msg += ". Fixed in " + m.Fixed + "."
		fix = fmt.Sprintf("Upgrade %s to %s or later.", p.Name, m.Fixed)
	}
	return engine.Finding{
		RuleID: m.ID, Severity: engine.Severity(m.Severity), Category: "vulnerability",
		Title:    fmt.Sprintf("%s %s: %s", p.Name, p.Version, m.ID),
		Message:  msg,
		Resource: p.Ecosystem + "/" + p.Name + "@" + p.Version,
		File:     p.File, Line: p.Line, Remediation: fix,
		Docs: "https://osv.dev/vulnerability/" + m.ID, Related: m.Aliases,
	}
}

func cveAliases(as []string) []string {
	var out []string
	for _, a := range as {
		if strings.HasPrefix(a, "CVE-") {
			out = append(out, a)
		}
	}
	return out
}
