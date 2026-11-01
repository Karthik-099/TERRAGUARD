package engine

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// Checks against `terraform providers schema -json`, the same data terraform validate uses.

type providerSchemas struct {
	Providers map[string]struct {
		Resources   map[string]schemaEntry `json:"resource_schemas"`
		DataSources map[string]schemaEntry `json:"data_source_schemas"`
	} `json:"provider_schemas"`
}

type schemaEntry struct {
	Block schemaBlock `json:"block"`
}

type schemaBlock struct {
	Attributes map[string]schemaAttr      `json:"attributes"`
	BlockTypes map[string]schemaBlockType `json:"block_types"`
}

type schemaAttr struct {
	Required   bool `json:"required"`
	Optional   bool `json:"optional"`
	Computed   bool `json:"computed"`
	Deprecated bool `json:"deprecated"`
}

type schemaBlockType struct {
	Nesting  string      `json:"nesting_mode"`
	Block    schemaBlock `json:"block"`
	MinItems int         `json:"min_items"`
	MaxItems int         `json:"max_items"`
}

var schemaRules = []Rule{
	{ID: "TG-SCHEMA-001", Title: "Argument or block not supported by the provider", Severity: High, Category: CatValidate, Blocking: true,
		Remediation: "Fix the name (see the suggestion) or remove it; terraform validate rejects unknown and read-only arguments."},
	{ID: "TG-SCHEMA-002", Title: "Required argument or block is missing", Severity: High, Category: CatValidate, Blocking: true,
		Remediation: "Add the required argument or block; terraform validate fails without it."},
	{ID: "TG-SCHEMA-003", Title: "Deprecated argument", Severity: Low, Category: CatValidate,
		Remediation: "Move to the replacement named in the provider's upgrade guide before the next major version removes it."},
}

var metaArgs = map[string]bool{"count": true, "for_each": true, "provider": true, "depends_on": true}
var metaBlocks = map[string]bool{"lifecycle": true, "connection": true, "provisioner": true}

func parseSchemas(src string) (*providerSchemas, error) {
	var s providerSchemas
	if err := json.Unmarshal([]byte(src), &s); err != nil {
		return nil, fmt.Errorf("provider schema: %w", err)
	}
	if len(s.Providers) == 0 {
		return nil, fmt.Errorf("provider schema: no provider_schemas (expected terraform providers schema -json output)")
	}
	return &s, nil
}

func (s *providerSchemas) lookup(kind, typ string) (*schemaBlock, bool) {
	for _, p := range s.Providers {
		m := p.Resources
		if kind == "data" {
			m = p.DataSources
		}
		if e, ok := m[typ]; ok {
			return &e.Block, true
		}
	}
	return nil, false
}

// schemaChecks skips types the schema doesn't know.
func schemaChecks(m *Module, s *providerSchemas) []Finding {
	var out []Finding
	for _, b := range m.Blocks {
		if (b.Kind != "resource" && b.Kind != "data") || len(b.Labels) != 2 || b.body == nil {
			continue
		}
		sb, ok := s.lookup(b.Kind, b.Labels[0])
		if !ok {
			continue
		}
		v := schemaVisitor{file: b.File, addr: b.Address()}
		v.body(b.body, sb, b.Labels[0], true)
		out = append(out, v.out...)
	}
	return out
}

type schemaVisitor struct {
	file, addr string
	out        []Finding
}

func (v *schemaVisitor) add(id, msg string, line int) {
	v.out = append(v.out, newFinding(id, "", msg, v.addr, v.file, line))
}

func (v *schemaVisitor) body(body *hclsyntax.Body, sb *schemaBlock, where string, top bool) {
	for name, a := range body.Attributes {
		line := a.SrcRange.Start.Line
		if top && metaArgs[name] {
			continue
		}
		attr, ok := sb.Attributes[name]
		switch {
		case !ok && sb.BlockTypes[name].Nesting != "":
			v.add("TG-SCHEMA-001", fmt.Sprintf("%s: %q is a block, not an argument; write %s { ... }.", where, name, name), line)
		case !ok:
			v.add("TG-SCHEMA-001", fmt.Sprintf("%s does not support argument %q.%s", where, name, suggest(name, sb)), line)
		case attr.Computed && !attr.Optional && !attr.Required:
			v.add("TG-SCHEMA-001", fmt.Sprintf("%s: %q is read-only; the provider sets it.", where, name), line)
		case attr.Deprecated:
			v.add("TG-SCHEMA-003", fmt.Sprintf("%s: %q is deprecated.", where, name), line)
		}
	}
	counts := map[string]int{}
	for _, nb := range body.Blocks {
		typ, inner := nb.Type, nb.Body
		if top && metaBlocks[typ] {
			continue
		}
		if typ == "dynamic" && len(nb.Labels) == 1 {
			typ = nb.Labels[0]
			inner = nil
			for _, c := range nb.Body.Blocks {
				if c.Type == "content" {
					inner = c.Body
				}
			}
		}
		line := nb.TypeRange.Start.Line
		bt, ok := sb.BlockTypes[typ]
		if !ok {
			if _, isAttr := sb.Attributes[typ]; isAttr {
				v.add("TG-SCHEMA-001", fmt.Sprintf("%s: %q is an argument, not a block; write %s = { ... }.", where, typ, typ), line)
			} else {
				v.add("TG-SCHEMA-001", fmt.Sprintf("%s does not support block %q.%s", where, typ, suggest(typ, sb)), line)
			}
			continue
		}
		if nb.Type != "dynamic" {
			counts[typ]++
			if bt.MaxItems > 0 && counts[typ] == bt.MaxItems+1 {
				v.add("TG-SCHEMA-001", fmt.Sprintf("%s allows at most %d %q block(s).", where, bt.MaxItems, typ), line)
			}
		} else {
			counts[typ] += bt.MinItems // a dynamic block may satisfy the minimum
		}
		if inner != nil {
			v.body(inner, &bt.Block, where+"."+typ, false)
		}
	}
	line := body.SrcRange.Start.Line
	for _, name := range sortedKeys(sb.Attributes) {
		if sb.Attributes[name].Required && body.Attributes[name] == nil {
			v.add("TG-SCHEMA-002", fmt.Sprintf("%s is missing required argument %q.", where, name), line)
		}
	}
	for _, name := range sortedKeys(sb.BlockTypes) {
		if bt := sb.BlockTypes[name]; bt.MinItems > 0 && counts[name] < bt.MinItems {
			v.add("TG-SCHEMA-002", fmt.Sprintf("%s needs at least %d %q block(s).", where, bt.MinItems, name), line)
		}
	}
}

// suggest returns a " Did you mean ...?" hint for a likely typo.
func suggest(name string, sb *schemaBlock) string {
	best, bestD := "", 3
	for _, cands := range [][]string{sortedKeys(sb.Attributes), sortedKeys(sb.BlockTypes)} {
		for _, c := range cands {
			if d := editDistance(name, c); d < bestD {
				best, bestD = c, d
			}
		}
	}
	if best == "" {
		return ""
	}
	return fmt.Sprintf(" Did you mean %q?", best)
}

func editDistance(a, b string) int {
	if strings.EqualFold(a, b) {
		return 0
	}
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
