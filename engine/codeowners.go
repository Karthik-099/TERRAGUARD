package engine

import (
	"path"
	"regexp"
	"sort"
	"strings"
)

// CodeOwners is a parsed CODEOWNERS file.
type CodeOwners struct {
	rules []ownerRule
}

type ownerRule struct {
	re     *regexp.Regexp
	owners []string
}

// ParseCodeOwners reads CODEOWNERS text with GitHub's semantics: gitignore-style
// patterns, the last matching line wins, and a pattern with no owners clears them.
func ParseCodeOwners(text string) *CodeOwners {
	co := &CodeOwners{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, " #"); i >= 0 { // trailing comment
			line = strings.TrimSpace(line[:i])
		}
		fields := strings.Fields(line)
		pat := strings.ReplaceAll(fields[0], `\#`, "#")
		if re := ownerPattern(pat); re != nil {
			co.rules = append(co.rules, ownerRule{re: re, owners: fields[1:]})
		}
	}
	return co
}

// Owners returns the owners of a slash path relative to the CODEOWNERS root.
func (co *CodeOwners) Owners(file string) []string {
	file = strings.TrimPrefix(path.Clean("/"+file), "/")
	for i := len(co.rules) - 1; i >= 0; i-- {
		if co.rules[i].re.MatchString(file) {
			if len(co.rules[i].owners) == 0 {
				return nil
			}
			return co.rules[i].owners
		}
	}
	return nil
}

// OwnersUnder is Owners for a Files key, where root is the key prefix the
// CODEOWNERS paths are relative to. Files outside root have no owners.
func (co *CodeOwners) OwnersUnder(root, file string) []string {
	if file == "" {
		return nil
	}
	if root = strings.TrimSuffix(path.Clean(root), "/"); root != "" && root != "." {
		rest, ok := strings.CutPrefix(file, root+"/")
		if !ok {
			return nil
		}
		file = rest
	}
	return co.Owners(file)
}

// OwnersOf is a one-call helper for the browser: the owners of file under codeowners text.
func OwnersOf(codeowners, file string) []string { return ParseCodeOwners(codeowners).Owners(file) }

// ownerPattern turns one CODEOWNERS pattern into a regexp over slash paths.
func ownerPattern(p string) *regexp.Regexp {
	dirOnly := strings.HasSuffix(p, "/")
	// A slash at the start or in the middle anchors the pattern at the root.
	anchored := strings.Contains(strings.TrimSuffix(p, "/"), "/")
	// GitHub: docs/* matches files in docs but not in its subdirectories.
	shallow := strings.HasSuffix(p, "/*") && !strings.HasSuffix(p, "/**/*")
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	var b strings.Builder
	if anchored {
		b.WriteString("^")
	} else {
		b.WriteString("^(?:.*/)?")
	}
	for i := 0; i < len(p); i++ {
		switch c := p[i]; {
		case strings.HasPrefix(p[i:], "**/"):
			b.WriteString("(?:.*/)?")
			i += 2
		case strings.HasPrefix(p[i:], "/**") && i+3 == len(p):
			b.WriteString("/.*")
			i += 2
		case strings.HasPrefix(p[i:], "**"):
			b.WriteString(".*")
			i++
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	switch {
	case dirOnly:
		b.WriteString("/.*$")
	case shallow:
		b.WriteString("$")
	default:
		b.WriteString("(?:/.*)?$") // the path itself or anything under it
	}
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil
	}
	return re
}

// Unowned names the group of findings no CODEOWNERS line covers.
const Unowned = "unowned"

// OwnerGroup is the findings one code owner is responsible for.
type OwnerGroup struct {
	Owner    string    `json:"owner"`
	Findings []Finding `json:"findings"`
}

// GroupByOwner puts each finding under every one of its code owners, sorted
// by owner, with unowned findings last.
func GroupByOwner(fs []Finding) []OwnerGroup {
	idx := map[string]int{}
	var out []OwnerGroup
	add := func(owner string, f Finding) {
		i, ok := idx[owner]
		if !ok {
			i = len(out)
			idx[owner] = i
			out = append(out, OwnerGroup{Owner: owner})
		}
		out[i].Findings = append(out[i].Findings, f)
	}
	for _, f := range fs {
		if len(f.CodeOwners) == 0 {
			add(Unowned, f)
		}
		for _, o := range f.CodeOwners {
			add(o, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].Owner == Unowned) != (out[j].Owner == Unowned) {
			return out[j].Owner == Unowned
		}
		return out[i].Owner < out[j].Owner
	})
	return out
}
