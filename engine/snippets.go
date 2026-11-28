package engine

import (
	"path"
	"regexp"
	"strings"
)

// snippetKinds are the tfplugindocs example folders under examples/, with the
// number of path segments that follow the kind: examples/provider/provider.tf,
// examples/resources/<type>/resource.tf and so on.
var snippetKinds = map[string]int{
	"provider": 1, "resources": 2, "data-sources": 2, "functions": 2,
	"ephemeral-resources": 2, "actions": 2,
}

// IsSnippet reports whether file is a provider documentation example: a
// standalone snippet in the tfplugindocs layout, not a module of its own.
// examples/e2e/... or examples/complete/... are real modules and stay false.
func IsSnippet(file string) bool {
	if !strings.HasSuffix(file, ".tf") {
		return false
	}
	segs := strings.Split(strings.ReplaceAll(file, `\`, "/"), "/")
	for i := 0; i+2 < len(segs); i++ {
		if d, ok := snippetKinds[segs[i+1]]; ok && segs[i] == "examples" && len(segs)-i-2 == d {
			return true
		}
	}
	return false
}

// snippetFunc maps a --snippets mode to a predicate: auto (default) detects
// the layout by path, on treats every .tf file as a snippet, off none.
func snippetFunc(mode string) func(string) bool {
	switch mode {
	case "off":
		return nil
	case "on":
		return func(f string) bool { return strings.HasSuffix(f, ".tf") }
	}
	return IsSnippet
}

// withoutSnippets is m without snippet blocks and resources, for the checks
// that judge the module as a whole (backend, required_version, pinning).
func withoutSnippets(m *Module, snip func(string) bool) *Module {
	if snip == nil {
		return m
	}
	ns := *m
	ns.Blocks, ns.Resources = nil, nil
	for _, b := range m.Blocks {
		if !snip(b.File) {
			ns.Blocks = append(ns.Blocks, b)
		}
	}
	for _, r := range m.Resources {
		if !snip(r.File) {
			ns.Resources = append(ns.Resources, r)
		}
	}
	return &ns
}

// elisionRE is a comment that leaves arguments out: "# ...", "// ... name ...".
var elisionRE = regexp.MustCompile(`(#|//|/\*).*\.\.\.`)

// dropElided removes missing-argument findings (TG-SCHEMA-002) inside snippet
// blocks that leave arguments out: blocks with a "# ..." comment, and context
// blocks of another type than the one the snippet folder documents (the
// aws_eks_cluster a tls_certificate example reads from). The documented type
// itself, written out in full, still gets them.
func dropElided(fs []Finding, m *Module, snip func(string) bool) []Finding {
	if snip == nil {
		return fs
	}
	type span struct{ from, to int }
	elided := map[string][]span{}
	for _, b := range m.Blocks {
		if b.body == nil || !snip(b.File) {
			continue
		}
		r := b.body.Range()
		folder := path.Base(path.Dir(strings.ReplaceAll(b.File, `\`, "/")))
		context := len(b.Labels) == 2 && b.Labels[0] != folder && !strings.HasSuffix(b.Labels[0], "_"+folder)
		if src := m.Files[b.File]; context || (r.End.Byte <= len(src) && elisionRE.Match(src[r.Start.Byte:r.End.Byte])) {
			elided[b.File] = append(elided[b.File], span{b.Line, r.End.Line})
		}
	}
	out := fs[:0]
	for _, f := range fs {
		drop := false
		for _, s := range elided[f.File] {
			drop = drop || (f.RuleID == "TG-SCHEMA-002" && f.Line >= s.from && f.Line <= s.to)
		}
		if !drop {
			out = append(out, f)
		}
	}
	return out
}
