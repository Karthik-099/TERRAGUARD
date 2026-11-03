package engine

import (
	"fmt"
	"regexp"
	"strings"
)

var graphIDRE = regexp.MustCompile(`[^A-Za-z0-9_]`)

// GraphMermaid renders the resource graph as a Mermaid flowchart, which GitHub
// renders in READMEs and pull requests. Resources on attack paths are red and
// resources with high or critical findings amber.
func GraphMermaid(r *Report) string {
	var b strings.Builder
	b.WriteString("flowchart LR\n")
	id := func(s string) string { return "n_" + graphIDRE.ReplaceAllString(s, "_") }
	risky := attackPathResources(r)
	for _, n := range r.Graph.Nodes {
		fmt.Fprintf(&b, "  %s[\"%s\"]\n", id(n.ID), strings.ReplaceAll(n.ID, `"`, "'"))
	}
	for _, e := range r.Graph.Edges {
		fmt.Fprintf(&b, "  %s --> %s\n", id(e.Source), id(e.Target))
	}
	b.WriteString("  classDef path fill:#3b0d0d,stroke:#ff6b6b,color:#ffd7d7\n  classDef risk fill:#3a2a06,stroke:#f7c948,color:#fff3cf\n")
	for _, n := range r.Graph.Nodes {
		switch {
		case risky[n.ID]:
			fmt.Fprintf(&b, "  class %s path\n", id(n.ID))
		case n.Severity == Critical || n.Severity == High:
			fmt.Fprintf(&b, "  class %s risk\n", id(n.ID))
		}
	}
	return b.String()
}

// GraphDOT renders the resource graph for Graphviz (dot -Tsvg).
func GraphDOT(r *Report) string {
	var b strings.Builder
	b.WriteString("digraph terraform {\n  rankdir=LR;\n  node [shape=box, style=rounded];\n")
	risky := attackPathResources(r)
	for _, n := range r.Graph.Nodes {
		attr := ""
		switch {
		case risky[n.ID]:
			attr = `, color="#d92d20", penwidth=2`
		case n.Severity == Critical || n.Severity == High:
			attr = `, color="#e8590c"`
		}
		fmt.Fprintf(&b, "  %q [label=%q%s];\n", n.ID, n.ID, attr)
	}
	for _, e := range r.Graph.Edges {
		fmt.Fprintf(&b, "  %q -> %q;\n", e.Source, e.Target)
	}
	b.WriteString("}\n")
	return b.String()
}

func attackPathResources(r *Report) map[string]bool {
	out := map[string]bool{}
	for _, f := range r.Findings {
		if f.Category == CatAttackPath && !f.Waived {
			out[f.Resource] = true
		}
	}
	return out
}
