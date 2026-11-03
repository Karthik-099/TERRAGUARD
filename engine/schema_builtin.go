package engine

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Bundled schemas for the main providers (tools/schemagen), so argument checks
// run without terraform init. They are used only when the module's version
// constraint and lock file allow the bundled version.

//go:embed schemas/providers.json.gz
var builtinSchemaGz []byte

type bundledSchemas struct {
	providerSchemas
	Versions map[string]string `json:"versions"`
}

var bundled = sync.OnceValue(func() *bundledSchemas {
	zr, err := gzip.NewReader(bytes.NewReader(builtinSchemaGz))
	if err != nil {
		return nil
	}
	var s bundledSchemas
	if json.NewDecoder(zr).Decode(&s) != nil {
		return nil
	}
	return &s
})

var bundledPrefixRE = regexp.MustCompile(`^(aws|azurerm|google)_`)

var lockRE = regexp.MustCompile(`provider\s+"([^"]+)"\s*\{[^}]*?version\s*=\s*"([^"]+)"`)

// otherProvider is true when a block is served by a provider the bundled
// schemas do not describe: an explicit provider such as google-beta, or a
// module that requires google-beta (modules often map google to it).
func otherProvider(m *Module) func(*Block) bool {
	betaDirs := map[string]bool{}
	for _, blk := range m.Blocks {
		if blk.Kind != "terraform" {
			continue
		}
		for _, rp := range blk.blocksAttr("required_providers") {
			if _, ok := rp["google-beta"]; ok {
				betaDirs[path.Dir(blk.File)] = true
			}
		}
	}
	return func(b *Block) bool {
		prefix, _, _ := strings.Cut(b.Labels[0], "_")
		if prefix == "google" && betaDirs[path.Dir(b.File)] {
			return true
		}
		var expr string
		switch v := b.Attrs["provider"].(type) {
		case Unknown:
			expr = v.Expr
		case string:
			expr = v
		}
		name, _, _ := strings.Cut(expr, ".")
		return name != "" && name != prefix
	}
}

// builtinSchemaFor returns the bundled schemas this module can be checked
// against, or nil when none applies.
func builtinSchemaFor(m *Module) *providerSchemas {
	uses := false
	for _, blk := range m.Blocks {
		if (blk.Kind == "resource" || blk.Kind == "data") && len(blk.Labels) == 2 && bundledPrefixRE.MatchString(blk.Labels[0]) {
			uses = true
			break
		}
	}
	if !uses {
		return nil // skip decoding the schemas
	}
	b := bundled()
	if b == nil {
		return nil
	}
	locked := map[string]string{}
	for _, l := range m.Locks {
		for _, x := range lockRE.FindAllStringSubmatch(l, -1) {
			locked[x[1]] = x[2]
		}
	}
	constraints := map[string][]string{} // source -> constraints
	for _, blk := range m.Blocks {
		if blk.Kind != "terraform" {
			continue
		}
		for _, rp := range blk.blocksAttr("required_providers") {
			for name, v := range rp {
				src, ver := "hashicorp/"+name, ""
				switch t := v.(type) {
				case map[string]any:
					if s, ok := t["source"].(string); ok {
						src = s
					}
					ver, _ = t["version"].(string)
				case string:
					ver = t
				}
				constraints[fullSource(src)] = append(constraints[fullSource(src)], ver)
			}
		}
	}
	out := &providerSchemas{Providers: map[string]struct {
		Resources   map[string]schemaEntry `json:"resource_schemas"`
		DataSources map[string]schemaEntry `json:"data_source_schemas"`
	}{}}
	for src, p := range b.Providers {
		v := b.Versions[src]
		if lv, ok := locked[src]; ok && major(lv) != major(v) {
			continue
		}
		ok := true
		for _, c := range constraints[src] {
			if !versionAllowed(c, v) {
				ok = false
			}
		}
		if ok {
			out.Providers[src] = p
		}
	}
	if len(out.Providers) == 0 {
		return nil
	}
	return out
}

func fullSource(s string) string {
	switch strings.Count(s, "/") {
	case 0:
		return "registry.terraform.io/hashicorp/" + s
	case 1:
		return "registry.terraform.io/" + s
	}
	return s
}

func major(v string) string { m, _, _ := strings.Cut(strings.TrimPrefix(v, "v"), "."); return m }

// versionAllowed evaluates a Terraform version constraint such as
// ">= 5.0, < 7.0" or "~> 6.2" against v. An unparsable clause allows it.
func versionAllowed(constraint, v string) bool {
	have := semver(v)
	for _, clause := range strings.Split(constraint, ",") {
		clause = strings.TrimSpace(clause)
		if clause == "" {
			continue
		}
		op := "="
		for _, o := range []string{"~>", ">=", "<=", "!=", ">", "<", "="} {
			if strings.HasPrefix(clause, o) {
				op, clause = o, strings.TrimSpace(clause[len(o):])
				break
			}
		}
		want := semver(clause)
		if want == nil {
			continue
		}
		c := compareSemver(have, want)
		switch op {
		case "=":
			if c != 0 {
				return false
			}
		case "!=":
			if c == 0 {
				return false
			}
		case ">":
			if c <= 0 {
				return false
			}
		case ">=":
			if c < 0 {
				return false
			}
		case "<":
			if c >= 0 {
				return false
			}
		case "<=":
			if c > 0 {
				return false
			}
		case "~>": // the rightmost given part may grow
			parts := strings.Count(clause, ".") + 1
			upper := append([]int{}, want...)
			if parts == 1 {
				upper = []int{want[0] + 1, 0, 0}
			} else {
				upper[parts-2]++
				for i := parts - 1; i < 3; i++ {
					upper[i] = 0
				}
			}
			if c < 0 || compareSemver(have, upper) >= 0 {
				return false
			}
		}
	}
	return true
}

func semver(s string) []int {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	s, _, _ = strings.Cut(s, "-")
	out := []int{0, 0, 0}
	for i, p := range strings.SplitN(s, ".", 3) {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		out[i] = n
	}
	return out
}

func compareSemver(a, b []int) int {
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}
