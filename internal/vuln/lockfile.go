package vuln

import (
	"bufio"
	"bytes"
	"encoding/json"
	"path"
	"regexp"
	"strings"
)

// Package is one installed dependency found in a lockfile or image.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	File      string `json:"file"`
	Line      int    `json:"line,omitempty"`
}

type parser func(content []byte) ([]Package, error)

var lockParsers = map[string]parser{
	"go.mod":             parseGoMod,
	"go.sum":             parseGoSum,
	"package-lock.json":  parseNpmLock,
	"yarn.lock":          parseYarnLock,
	"pnpm-lock.yaml":     parsePnpmLock,
	"poetry.lock":        tomlPackages("PyPI"),
	"Pipfile.lock":       parsePipfileLock,
	"Cargo.lock":         tomlPackages("crates.io"),
	"Gemfile.lock":       parseGemfileLock,
	"composer.lock":      parseComposerLock,
	"packages.lock.json": parseNugetLock,
	"gradle.lockfile":    parseGradleLock,
}

var requirementsName = regexp.MustCompile(`^requirements.*\.txt$`)

func parserFor(name string) parser {
	base := path.Base(name)
	if p, ok := lockParsers[base]; ok {
		return p
	}
	if requirementsName.MatchString(base) {
		return parseRequirements
	}
	return nil
}

// IsLockfile reports whether ParseLockfile understands the file name.
func IsLockfile(name string) bool { return parserFor(name) != nil }

// ParseLockfile returns the packages in a lockfile; file is used for reporting.
func ParseLockfile(file string, content []byte) ([]Package, error) {
	p := parserFor(file)
	if p == nil {
		return nil, nil
	}
	pkgs, err := p(content)
	seen := map[string]bool{}
	out := pkgs[:0]
	for _, pk := range pkgs {
		key := pk.Ecosystem + "\x00" + pk.Name + "\x00" + pk.Version
		if pk.Name == "" || pk.Version == "" || seen[key] {
			continue
		}
		seen[key] = true
		pk.File = file
		out = append(out, pk)
	}
	return out, err
}

func lineAt(b []byte, off int) int { return bytes.Count(b[:off], []byte("\n")) + 1 }

func eachLine(b []byte, fn func(n int, line string)) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for n := 1; sc.Scan(); n++ {
		fn(n, sc.Text())
	}
}

var jsonObjectKey = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"\s*:\s*\{`)

// keyLines maps each JSON object key to the line it first appears on.
// shortcut: first occurrence wins, so a nested duplicate name reports the outer line.
func keyLines(b []byte) map[string]int {
	out := map[string]int{}
	last, line := 0, 1
	for _, m := range jsonObjectKey.FindAllSubmatchIndex(b, -1) {
		line += bytes.Count(b[last:m[0]], []byte("\n"))
		last = m[0]
		if k := string(b[m[2]:m[3]]); out[k] == 0 {
			out[k] = line
		}
	}
	return out
}

func goVersion(v string) string {
	return strings.TrimSuffix(strings.TrimPrefix(v, "v"), "+incompatible")
}

// parseGoMod reads require directives; since Go 1.17 they list every module in the build.
// shortcut: replace directives are ignored; a replaced module reports its original version.
func parseGoMod(b []byte) ([]Package, error) {
	var out []Package
	inBlock := false
	eachLine(b, func(n int, line string) {
		line, _, _ = strings.Cut(line, "//")
		f := strings.Fields(line)
		switch {
		case len(f) == 0:
		case inBlock && f[0] == ")":
			inBlock = false
		case inBlock && len(f) >= 2:
			out = append(out, Package{Ecosystem: "Go", Name: f[0], Version: goVersion(f[1]), Line: n})
		case f[0] == "require" && len(f) >= 2 && f[1] == "(":
			inBlock = true
		case f[0] == "require" && len(f) >= 3:
			out = append(out, Package{Ecosystem: "Go", Name: f[1], Version: goVersion(f[2]), Line: n})
		}
	})
	return out, nil
}

// parseGoSum is used only without a go.mod; it may list versions the build no longer selects.
func parseGoSum(b []byte) ([]Package, error) {
	var out []Package
	eachLine(b, func(n int, line string) {
		f := strings.Fields(line)
		if len(f) == 3 && !strings.HasSuffix(f[1], "/go.mod") {
			out = append(out, Package{Ecosystem: "Go", Name: f[0], Version: goVersion(f[1]), Line: n})
		}
	})
	return out, nil
}

type npmDepV1 struct {
	Version      string              `json:"version"`
	Bundled      bool                `json:"bundled"`
	Dependencies map[string]npmDepV1 `json:"dependencies"`
}

func parseNpmLock(b []byte) ([]Package, error) {
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
			Link    bool   `json:"link"`
		} `json:"packages"`
		Dependencies map[string]npmDepV1 `json:"dependencies"`
	}
	if err := json.Unmarshal(b, &lock); err != nil {
		return nil, err
	}
	lines := keyLines(b)
	var out []Package
	if len(lock.Packages) > 0 { // lockfile v2 and v3
		for key, p := range lock.Packages {
			i := strings.LastIndex(key, "node_modules/")
			if i < 0 || p.Link {
				continue // the root project, or a workspace link
			}
			out = append(out, Package{Ecosystem: "npm", Name: key[i+len("node_modules/"):], Version: p.Version, Line: lines[key]})
		}
		return out, nil
	}
	var walk func(map[string]npmDepV1)
	walk = func(deps map[string]npmDepV1) {
		for name, d := range deps {
			out = append(out, Package{Ecosystem: "npm", Name: name, Version: d.Version, Line: lines[name]})
			walk(d.Dependencies)
		}
	}
	walk(lock.Dependencies)
	return out, nil
}

// npmSpecName returns the package name of "name@range", including scoped "@scope/name@range".
func npmSpecName(spec string) string {
	if i := strings.LastIndex(spec, "@"); i > 0 {
		return spec[:i]
	}
	return spec
}

var yarnVersion = regexp.MustCompile(`^\s+version:?\s+"?([^"\s]+)"?`)

func parseYarnLock(b []byte) ([]Package, error) {
	var out []Package
	name, at := "", 0
	eachLine(b, func(n int, line string) {
		if line == "" || line[0] == '#' {
			return
		}
		if line[0] != ' ' {
			first, _, _ := strings.Cut(strings.TrimSuffix(line, ":"), ",")
			first = strings.Trim(strings.TrimSpace(first), `"`)
			name, at = npmSpecName(first), n
			for _, local := range []string{"@workspace:", "@link:", "@portal:", "@file:"} {
				if strings.Contains(first, local) {
					name = ""
				}
			}
			if first == "__metadata" {
				name = ""
			}
			return
		}
		if m := yarnVersion.FindStringSubmatch(line); m != nil && name != "" {
			out = append(out, Package{Ecosystem: "npm", Name: name, Version: m[1], Line: at})
			name = ""
		}
	})
	return out, nil
}

var pnpmV5 = regexp.MustCompile(`(?m)^lockfileVersion:\s*'?[1-5][.']`)

func parsePnpmLock(b []byte) ([]Package, error) {
	v5 := pnpmV5.Match(b)
	var out []Package
	inPackages := false
	eachLine(b, func(n int, line string) {
		if line == "" || line[0] != ' ' {
			inPackages = strings.TrimSpace(line) == "packages:" || (inPackages && line == "")
			return
		}
		if !inPackages || len(line) < 4 || !strings.HasPrefix(line, "  ") || line[2] == ' ' || !strings.HasSuffix(line, ":") {
			return
		}
		key := strings.Trim(strings.TrimSuffix(strings.TrimSpace(line), ":"), `'"`)
		key = strings.TrimPrefix(key, "/")
		key, _, _ = strings.Cut(key, "(") // peer suffix in v6+
		sep := "@"                        // v6 "/a@1.0.0", v9 "a@1.0.0"
		if v5 {
			sep = "/" // v5 "/a/1.0.0_peer", where peers spell "/" as "+"
		}
		if i := strings.LastIndex(key, sep); i > 0 {
			ver, _, _ := strings.Cut(key[i+1:], "_")
			out = append(out, Package{Ecosystem: "npm", Name: key[:i], Version: ver, Line: n})
		}
	})
	return out, nil
}

var requirementPin = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9!+._-]+)\s*(?:$|;|#|\\)`)

// parseRequirements keeps only exact pins; ranges have no single installed version.
func parseRequirements(b []byte) ([]Package, error) {
	var out []Package
	eachLine(b, func(n int, line string) {
		if m := requirementPin.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			out = append(out, Package{Ecosystem: "PyPI", Name: m[1], Version: m[2], Line: n})
		}
	})
	return out, nil
}

var tomlString = regexp.MustCompile(`^(name|version)\s*=\s*"([^"]*)"`)

// tomlPackages reads [[package]] tables (poetry.lock, Cargo.lock) without a TOML library.
func tomlPackages(eco string) parser {
	return func(b []byte) ([]Package, error) {
		var out []Package
		var cur *Package
		eachLine(b, func(n int, line string) {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "[") {
				cur = nil
				if line == "[[package]]" {
					out = append(out, Package{Ecosystem: eco, Line: n})
					cur = &out[len(out)-1]
				}
				return
			}
			if m := tomlString.FindStringSubmatch(line); m != nil && cur != nil {
				if m[1] == "name" {
					cur.Name, cur.Line = m[2], n
				} else {
					cur.Version = m[2]
				}
			}
		})
		return out, nil
	}
}

func parsePipfileLock(b []byte) ([]Package, error) {
	type dep struct {
		Version string `json:"version"`
	}
	var lock struct {
		Default map[string]dep `json:"default"`
		Develop map[string]dep `json:"develop"`
	}
	if err := json.Unmarshal(b, &lock); err != nil {
		return nil, err
	}
	lines := keyLines(b)
	var out []Package
	for _, deps := range []map[string]dep{lock.Default, lock.Develop} {
		for name, d := range deps {
			if v, ok := strings.CutPrefix(d.Version, "=="); ok {
				out = append(out, Package{Ecosystem: "PyPI", Name: name, Version: v, Line: lines[name]})
			}
		}
	}
	return out, nil
}

var gemSpec = regexp.MustCompile(`^    ([^\s(]+) \(([^)]+)\)$`)

func parseGemfileLock(b []byte) ([]Package, error) {
	var out []Package
	inGem := false
	eachLine(b, func(n int, line string) {
		if line != "" && line[0] != ' ' {
			inGem = line == "GEM"
			return
		}
		if m := gemSpec.FindStringSubmatch(line); m != nil && inGem {
			ver, _, _ := strings.Cut(m[2], "-") // drop the platform, e.g. 1.15.0-x86_64-linux
			out = append(out, Package{Ecosystem: "RubyGems", Name: m[1], Version: ver, Line: n})
		}
	})
	return out, nil
}

var composerName = regexp.MustCompile(`"name"\s*:\s*"([^"]+)"`)

func parseComposerLock(b []byte) ([]Package, error) {
	type pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	var lock struct {
		Packages    []pkg `json:"packages"`
		PackagesDev []pkg `json:"packages-dev"`
	}
	if err := json.Unmarshal(b, &lock); err != nil {
		return nil, err
	}
	lines := map[string]int{}
	for _, m := range composerName.FindAllSubmatchIndex(b, -1) {
		if k := string(b[m[2]:m[3]]); lines[k] == 0 {
			lines[k] = lineAt(b, m[0])
		}
	}
	var out []Package
	for _, p := range append(lock.Packages, lock.PackagesDev...) {
		if strings.HasPrefix(p.Version, "dev-") {
			continue // a branch, not a release
		}
		out = append(out, Package{Ecosystem: "Packagist", Name: p.Name, Version: strings.TrimPrefix(p.Version, "v"), Line: lines[p.Name]})
	}
	return out, nil
}

func parseNugetLock(b []byte) ([]Package, error) {
	var lock struct {
		Dependencies map[string]map[string]struct {
			Type     string `json:"type"`
			Resolved string `json:"resolved"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(b, &lock); err != nil {
		return nil, err
	}
	lines := keyLines(b)
	var out []Package
	for _, deps := range lock.Dependencies {
		for name, d := range deps {
			if d.Type != "Project" {
				out = append(out, Package{Ecosystem: "NuGet", Name: name, Version: d.Resolved, Line: lines[name]})
			}
		}
	}
	return out, nil
}

func parseGradleLock(b []byte) ([]Package, error) {
	var out []Package
	eachLine(b, func(n int, line string) {
		coord, _, _ := strings.Cut(strings.TrimSpace(line), "=")
		if strings.HasPrefix(coord, "#") || coord == "empty" {
			return
		}
		if p := strings.Split(coord, ":"); len(p) == 3 {
			out = append(out, Package{Ecosystem: "Maven", Name: p[0] + ":" + p[1], Version: p[2], Line: n})
		}
	})
	return out, nil
}
