package engine

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// SBOMComponent is one dependency of the scanned project.
type SBOMComponent struct {
	Type      string `json:"type"` // CycloneDX type: library or container
	Kind      string `json:"kind"` // terraform-provider, terraform-module, container-image or package
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	PURL      string `json:"purl,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	File      string `json:"file,omitempty"`
	Line      int    `json:"line,omitempty"`
}

var (
	lockProviderRE = regexp.MustCompile(`(?m)^\s*provider\s+"([^"]+)"\s*\{[^}]*?version\s*=\s*"([^"]+)"`)
	gitHubSourceRE = regexp.MustCompile(`^(?:git::)?(?:https://|ssh://git@|git@)?github\.com[/:]([^/]+)/([^/?.]+)(?:\.git)?(?://[^?]*)?(?:\?ref=([^&]+))?`)
	refQueryRE     = regexp.MustCompile(`[?&]ref=([^&]+)`)
)

// SBOMComponents lists Terraform providers (locked versions from
// .terraform.lock.hcl, else as declared), modules with their source and
// version, and container images from Dockerfiles, Kubernetes, compose and CI
// files. Lockfile packages are added by the caller, which can read files.
func SBOMComponents(files map[string]string) []SBOMComponent {
	var out []SBOMComponent
	seen := map[string]bool{}
	add := func(c SBOMComponent) {
		k := c.Kind + "|" + c.Name + "|" + c.Version
		if !seen[k] {
			seen[k] = true
			out = append(out, c)
		}
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	locked := map[string]bool{}
	for _, n := range names {
		if path.Base(n) != ".terraform.lock.hcl" {
			continue
		}
		for _, m := range lockProviderRE.FindAllStringSubmatch(files[n], -1) {
			src := fullSource(m[1])
			locked[src] = true
			add(SBOMComponent{Type: "library", Kind: "terraform-provider", Name: src, Version: m[2], PURL: providerPURL(src, m[2]), File: n})
		}
	}
	m := Parse(files)
	for _, b := range m.Blocks {
		switch b.Kind {
		case "terraform":
			for _, rp := range b.blocksAttr("required_providers") {
				for _, name := range sortedKeys(rp) {
					src := "hashicorp/" + name
					if t, ok := rp[name].(map[string]any); ok {
						if s, ok := t["source"].(string); ok {
							src = s
						}
					}
					if src = fullSource(src); !locked[src] {
						add(SBOMComponent{Type: "library", Kind: "terraform-provider", Name: src, PURL: providerPURL(src, ""), File: b.File, Line: b.Line})
					}
				}
			}
		case "module":
			src, _ := b.Attrs["source"].(string)
			src = stripURLUser(src)
			if src == "" || strings.HasPrefix(src, "./") || strings.HasPrefix(src, "../") {
				continue // local modules are part of this project
			}
			ver, _ := b.Attrs["version"].(string)
			c := SBOMComponent{Type: "library", Kind: "terraform-module", Name: src, Version: ver, File: b.File, Line: b.Lines["source"]}
			if c.Line == 0 {
				c.Line = b.Line
			}
			switch g := gitHubSourceRE.FindStringSubmatch(src); {
			case moduleRegistryRE.MatchString(src):
				c.Name = strings.SplitN(src, "//", 2)[0]
				c.PURL = "pkg:terraform/" + c.Name + atVersion(ver)
			case g != nil:
				c.Name, c.Version = "github.com/"+g[1]+"/"+g[2], g[3]
				c.PURL = "pkg:github/" + strings.ToLower(g[1]) + "/" + strings.ToLower(g[2]) + atVersion(g[3])
			default:
				if r := refQueryRE.FindStringSubmatch(src); r != nil && ver == "" {
					c.Version = r[1]
				}
			}
			add(c)
		}
	}
	for _, r := range m.Resources {
		for _, img := range resourceImages(r) {
			if c, ok := imageComponent(img.ref); ok {
				c.File, c.Line = r.File, r.line(img.path)
				add(c)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind > out[j].Kind // terraform first, then packages, then images
		}
		return out[i].Name+"@"+out[i].Version < out[j].Name+"@"+out[j].Version
	})
	return out
}

func atVersion(v string) string {
	if v == "" || strings.ContainsAny(v, "<>=~, ") {
		return "" // a constraint is not a version
	}
	return "@" + strings.ReplaceAll(v, "+", "%2B")
}

func providerPURL(src, ver string) string {
	parts := strings.Split(src, "/")
	if len(parts) != 3 {
		return ""
	}
	p := "pkg:terraform/" + parts[1] + "/" + parts[2] + atVersion(ver)
	if parts[0] != "registry.terraform.io" {
		p += "?repository_url=" + parts[0]
	}
	return p
}

type sbomImage struct{ ref, path string }

// resourceImages returns container image references in a resource.
func resourceImages(r *Resource) []sbomImage {
	if r.Type == "dockerfile_stage" {
		base, _ := r.Attrs["base"].(string)
		if p, _ := r.Attrs["parent"].(float64); p >= 0 || base == "" {
			return nil // FROM an earlier stage
		}
		return []sbomImage{{base, "base"}}
	}
	if r.Format == "" && !strings.HasPrefix(r.Type, "kubernetes_") {
		return nil // other Terraform "image" arguments are VM images
	}
	var out []sbomImage
	var walk func(p string, v any)
	walk = func(p string, v any) {
		switch t := v.(type) {
		case map[string]any:
			for _, k := range sortedKeys(t) {
				q := k
				if p != "" {
					q = p + "." + k
				}
				if strings.EqualFold(k, "image") {
					switch iv := t[k].(type) {
					case string:
						out = append(out, sbomImage{iv, q})
						continue
					case map[string]any: // GitLab CI: image: {name: ...}
						if n, ok := iv["name"].(string); ok {
							out = append(out, sbomImage{n, q + ".name"})
							continue
						}
					}
				}
				if s, ok := t[k].(string); ok && k == "uses" && strings.HasPrefix(s, "docker://") {
					out = append(out, sbomImage{s, q})
				}
				walk(q, t[k])
			}
		case []any:
			for i, e := range t {
				walk(fmt.Sprintf("%s.%d", p, i), e)
			}
		}
	}
	walk("", r.Attrs)
	return out
}

// imageComponent parses registry/name:tag@digest into a component with a docker purl.
func imageComponent(ref string) (SBOMComponent, bool) {
	ref = strings.TrimSpace(strings.TrimPrefix(ref, "docker://"))
	if ref == "" || ref == "scratch" || strings.ContainsAny(ref, "${} \t") {
		return SBOMComponent{}, false // unresolved variables are not a dependency we can name
	}
	name, digest, _ := strings.Cut(ref, "@")
	tag := ""
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		name, tag = name[:i], name[i+1:]
	}
	registry := ""
	if first, rest, ok := strings.Cut(name, "/"); ok && (strings.ContainsAny(first, ".:") || first == "localhost") {
		registry, name = first, rest
	}
	if name == "" {
		return SBOMComponent{}, false
	}
	version := tag
	if digest != "" {
		version = digest
	}
	purl := "pkg:docker/" + name
	if version != "" {
		purl += "@" + strings.ReplaceAll(version, ":", "%3A")
	}
	if registry != "" && registry != "docker.io" {
		purl += "?repository_url=" + registry
	}
	full := name
	if registry != "" {
		full = registry + "/" + name
	}
	return SBOMComponent{Type: "container", Kind: "container-image", Name: full, Version: version, PURL: purl}, true
}

// CycloneDX renders components as a CycloneDX 1.5 JSON BOM. timestamp is
// RFC 3339 or empty; the engine does not read the clock.
func CycloneDX(comps []SBOMComponent, timestamp string) ([]byte, error) {
	type prop struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	type comp struct {
		Ref        string `json:"bom-ref"`
		Type       string `json:"type"`
		Name       string `json:"name"`
		Version    string `json:"version,omitempty"`
		PURL       string `json:"purl,omitempty"`
		Properties []prop `json:"properties,omitempty"`
	}
	list := make([]comp, 0, len(comps))
	refs := map[string]int{}
	for _, c := range comps {
		ref := c.PURL
		if ref == "" {
			ref = c.Kind + ":" + c.Name + atVersion(c.Version)
		}
		if refs[ref]++; refs[ref] > 1 { // bom-ref must be unique
			ref = fmt.Sprintf("%s#%d", ref, refs[ref])
		}
		props := []prop{{"terraguard:kind", c.Kind}}
		if c.Ecosystem != "" {
			props = append(props, prop{"terraguard:ecosystem", c.Ecosystem})
		}
		if c.File != "" {
			loc := c.File
			if c.Line > 0 {
				loc = fmt.Sprintf("%s:%d", c.File, c.Line)
			}
			props = append(props, prop{"terraguard:location", loc})
		}
		list = append(list, comp{Ref: ref, Type: c.Type, Name: c.Name, Version: c.Version, PURL: c.PURL, Properties: props})
	}
	meta := map[string]any{"tools": map[string]any{"components": []map[string]string{{"type": "application", "name": "terraguard", "version": Version}}}}
	if timestamp != "" {
		meta["timestamp"] = timestamp
	}
	return json.MarshalIndent(map[string]any{
		"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "metadata": meta, "components": list,
	}, "", "  ")
}

// stripURLUser removes user:password@ from a module source so credentials never reach an SBOM.
func stripURLUser(src string) string {
	return urlUserRE.ReplaceAllString(src, "$1")
}

var urlUserRE = regexp.MustCompile(`(://)[^/@\s]+@`)
