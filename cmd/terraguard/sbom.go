package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Karthik-099/TERRAGUARD/engine"
	"github.com/Karthik-099/TERRAGUARD/internal/vuln"
)

// purlTypes maps OSV ecosystems to package URL types, both ways.
var purlTypes = map[string]string{
	"npm": "npm", "PyPI": "pypi", "Go": "golang", "Maven": "maven", "RubyGems": "gem",
	"crates.io": "cargo", "Packagist": "composer", "NuGet": "nuget",
}

// runSBOM writes a CycloneDX 1.5 inventory of the project. No network.
func runSBOM(args []string) error {
	fs := flag.NewFlagSet("sbom", flag.ContinueOnError)
	format := fs.String("format", "cyclonedx", "cyclonedx (CycloneDX 1.5 JSON) or json (TerraGuard's component list)")
	out := fs.String("out", "", "write to this file instead of stdout")
	paths, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if *format != "cyclonedx" && *format != "json" {
		return fmt.Errorf("--format %q: use cyclonedx or json", *format)
	}
	files, err := loadFiles(paths)
	if err != nil {
		return err
	}
	comps := engine.SBOMComponents(files)
	locks, err := vuln.FindLockfiles(paths)
	if err != nil {
		return err
	}
	pkgs, notes := vuln.ReadLockfiles(locks)
	for _, n := range notes {
		fmt.Fprintln(os.Stderr, "note:", n)
	}
	seen := map[string]bool{}
	for _, p := range pkgs {
		if k := p.Ecosystem + "|" + p.Name + "|" + p.Version; !seen[k] {
			seen[k] = true
			comps = append(comps, engine.SBOMComponent{Type: "library", Kind: "package", Name: p.Name, Version: p.Version,
				PURL: packagePURL(p), Ecosystem: p.Ecosystem, File: p.File, Line: p.Line})
		}
	}
	var b []byte
	if *format == "json" {
		b, err = json.MarshalIndent(comps, "", "  ")
	} else {
		b, err = engine.CycloneDX(comps, time.Now().UTC().Format(time.RFC3339))
	}
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if *out != "" {
		return os.WriteFile(*out, b, 0o644)
	}
	_, err = os.Stdout.Write(b)
	return err
}

// packagePURL builds pkg:<type>/<namespace>/<name>@<version> for a lockfile package.
func packagePURL(p vuln.Package) string {
	t := purlTypes[p.Ecosystem]
	if t == "" || p.Name == "" {
		return ""
	}
	name := p.Name
	switch t {
	case "maven":
		name = strings.Replace(name, ":", "/", 1)
	case "pypi":
		name = strings.ToLower(strings.ReplaceAll(name, "_", "-"))
	case "npm":
		name = strings.Replace(name, "@", "%40", 1)
	}
	s := "pkg:" + t + "/" + name
	if p.Version != "" {
		s += "@" + url.PathEscape(p.Version)
	}
	return s
}

// sbomPackages reads the packages of a CycloneDX JSON SBOM from their purls,
// so terraguard vuln can scan an SBOM made here or by another tool.
func sbomPackages(file string) ([]vuln.Package, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var bom struct {
		BOMFormat  string `json:"bomFormat"`
		Components []struct {
			PURL string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(b, &bom); err != nil || bom.BOMFormat != "CycloneDX" {
		return nil, fmt.Errorf("%s: not a CycloneDX JSON SBOM", file)
	}
	eco := map[string]string{}
	for e, t := range purlTypes {
		eco[t] = e
	}
	var out []vuln.Package
	for _, c := range bom.Components {
		rest, ok := strings.CutPrefix(c.PURL, "pkg:")
		if !ok {
			continue
		}
		rest, _, _ = strings.Cut(rest, "#")
		rest, _, _ = strings.Cut(rest, "?")
		t, rest, _ := strings.Cut(rest, "/")
		e := eco[strings.ToLower(t)]
		if e == "" {
			continue // providers, images and OS packages are not in the lockfile ecosystems
		}
		name, version, _ := strings.Cut(rest, "@")
		if name, err = url.PathUnescape(name); err != nil {
			continue
		}
		if version, err = url.PathUnescape(version); err != nil || version == "" {
			continue
		}
		if e == "Maven" {
			name = strings.Replace(name, "/", ":", 1)
		}
		out = append(out, vuln.Package{Ecosystem: e, Name: name, Version: version, File: file})
	}
	return out, nil
}
