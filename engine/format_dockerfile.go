package engine

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// A Dockerfile becomes one dockerfile_stage per FROM and one dockerfile for
// the whole file. A stage has index, name (its alias), base, platform,
// parent (index of the stage it builds on, or -1), final, shipped (final or
// an ancestor of it), user (last USER), env and args (name -> value), and
// instructions: maps {cmd, value, flags, args, json} with
// Lines["instructions.N"]. The file resource has stages (the stage maps),
// instructions and args (the ARGs before the first FROM); its stage maps
// leave out env and args, which the stages carry.

func init() { formatParsers[FormatDockerfile] = parseDockerfile }

var dockerKnown = map[string]bool{"FROM": true, "RUN": true, "CMD": true, "LABEL": true, "MAINTAINER": true, "EXPOSE": true,
	"ENV": true, "ADD": true, "COPY": true, "ENTRYPOINT": true, "VOLUME": true, "USER": true, "WORKDIR": true, "ARG": true,
	"ONBUILD": true, "STOPSIGNAL": true, "HEALTHCHECK": true, "SHELL": true}

var (
	dockerEscapeRE  = regexp.MustCompile(`(?i)^#\s*escape\s*=\s*(\S)`)
	dockerDirectRE  = regexp.MustCompile(`(?i)^#\s*[a-z]+\s*=`)
	dockerHeredocRE = regexp.MustCompile(`<<-?\s*["']?([A-Za-z_][A-Za-z0-9_]*)["']?`)
)

type dockerInstr struct {
	cmd, value string
	flags      []string
	args       []string
	json       bool
	line       int
}

// readDockerfile splits a Dockerfile into instructions; bad reports the
// first unknown instruction.
func readDockerfile(src string) (out []dockerInstr, bad *dockerInstr) {
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	escape := "\\"
	directives := true
	for i := 0; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		if directives {
			if m := dockerEscapeRE.FindStringSubmatch(t); m != nil {
				escape = m[1]
				continue
			}
			if !dockerDirectRE.MatchString(t) {
				directives = false
			}
		}
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		start := i + 1
		text := t
		for strings.HasSuffix(strings.TrimRight(text, " \t"), escape) && i+1 < len(lines) {
			text = strings.TrimRight(strings.TrimSuffix(strings.TrimRight(text, " \t"), escape), " \t")
			i++
			for i < len(lines) {
				n := strings.TrimSpace(lines[i])
				if n == "" || strings.HasPrefix(n, "#") {
					i++
					continue
				}
				break
			}
			if i < len(lines) {
				text += " " + strings.TrimSpace(lines[i])
			}
		}
		cmd, rest, _ := strings.Cut(text, " ")
		if c, r, ok := strings.Cut(text, "\t"); ok && len(c) < len(cmd) {
			cmd, rest = c, r
		}
		in := dockerInstr{cmd: strings.ToUpper(cmd), line: start}
		rest = strings.TrimSpace(rest)
		if in.cmd == "RUN" || in.cmd == "COPY" || in.cmd == "ADD" {
			for _, m := range dockerHeredocRE.FindAllStringSubmatch(rest, -1) {
				var body []string
				for i+1 < len(lines) {
					i++
					if strings.TrimSpace(lines[i]) == m[1] {
						break
					}
					body = append(body, lines[i])
				}
				rest += "\n" + strings.Join(body, "\n")
			}
		}
		for strings.HasPrefix(rest, "--") {
			f, r, _ := strings.Cut(rest, " ")
			in.flags = append(in.flags, f)
			rest = strings.TrimSpace(r)
		}
		in.value = rest
		var arr []string
		if strings.HasPrefix(rest, "[") && json.Unmarshal([]byte(rest), &arr) == nil {
			in.json, in.args = true, arr
		} else {
			in.args = strings.Fields(rest)
		}
		if !dockerKnown[in.cmd] && bad == nil {
			b := in
			bad = &b
		}
		out = append(out, in)
	}
	return out, bad
}

// dockerPairs reads ENV/ARG/LABEL key=value pairs (or the legacy "ENV key value").
func dockerPairs(cmd, v string) [][2]string {
	words := dockerWords(v)
	if len(words) == 0 {
		return nil
	}
	if cmd == "ENV" && !strings.Contains(words[0], "=") {
		k, rest, _ := strings.Cut(strings.TrimSpace(v), " ")
		return [][2]string{{k, strings.Trim(strings.TrimSpace(rest), `"'`)}}
	}
	var out [][2]string
	for _, w := range words {
		k, val, ok := strings.Cut(w, "=")
		if !ok && cmd == "ARG" {
			out = append(out, [2]string{k, "\x00"}) // no default
			continue
		}
		out = append(out, [2]string{k, val})
	}
	return out
}

// dockerWords splits on whitespace outside quotes and drops the quotes.
func dockerWords(s string) []string {
	var out []string
	var cur strings.Builder
	var q rune
	in := false
	for _, c := range s {
		switch {
		case q != 0 && c == q:
			q = 0
		case q == 0 && (c == '"' || c == '\''):
			q, in = c, true
		case q == 0 && (c == ' ' || c == '\t' || c == '\n'):
			if in {
				out = append(out, cur.String())
				cur.Reset()
				in = false
			}
		default:
			cur.WriteRune(c)
			in = true
		}
	}
	if in {
		out = append(out, cur.String())
	}
	return out
}

func parseDockerfile(name, src string) ([]*Resource, []Finding) {
	instrs, bad := readDockerfile(src)
	var syntax []Finding
	if bad != nil {
		f := formatSyntax(name, "Dockerfile", fmt.Errorf("unknown instruction %s", bad.cmd))
		f.Line = bad.line
		syntax = append(syntax, f)
	}
	if len(instrs) == 0 {
		return nil, syntax
	}
	file := &Resource{Type: "dockerfile", Name: path.Base(name), File: name, Line: 1, Lines: map[string]int{}, Mode: "managed"}
	file.Address = "dockerfile." + file.Name
	fileAttrs := map[string]any{"instructions": []any{}, "args": map[string]any{}}
	file.Attrs = fileAttrs
	var stages []*Resource
	var cur *Resource
	aliases := map[string]int{}
	seen := map[string]bool{}
	for _, in := range instrs {
		if in.cmd == "FROM" {
			idx := len(stages)
			base, alias := "", ""
			if len(in.args) > 0 {
				base = in.args[0]
			}
			if len(in.args) >= 3 && strings.EqualFold(in.args[1], "as") {
				alias = in.args[2]
			}
			platform := ""
			for _, f := range in.flags {
				if v, ok := strings.CutPrefix(f, "--platform="); ok {
					platform = v
				}
			}
			parent := -1
			if p, ok := aliases[strings.ToLower(base)]; ok {
				parent = p
			}
			if alias != "" {
				aliases[strings.ToLower(alias)] = idx
			}
			rname := alias
			if rname == "" || seen[rname] {
				rname = "stage" + strconv.Itoa(idx)
			}
			seen[rname] = true
			cur = &Resource{Type: "dockerfile_stage", Name: rname, Address: "dockerfile_stage." + rname, File: name, Line: in.line, Mode: "managed",
				Lines: map[string]int{"base": in.line, "platform": in.line, "name": in.line}}
			cur.Attrs = map[string]any{"index": float64(idx), "name": alias, "base": base, "platform": platform, "parent": float64(parent),
				"final": false, "shipped": false, "instructions": []any{}, "env": map[string]any{}, "args": map[string]any{}}
			stages = append(stages, cur)
		}
		target := file
		if cur != nil {
			target = cur
		}
		list := target.Attrs["instructions"].([]any)
		n := len(list)
		flags := make([]any, len(in.flags))
		for i, f := range in.flags {
			flags[i] = f
		}
		args := make([]any, len(in.args))
		for i, a := range in.args {
			args[i] = a
		}
		target.Attrs["instructions"] = append(list, map[string]any{"cmd": in.cmd, "value": in.value, "flags": flags, "args": args, "json": in.json})
		target.Lines["instructions."+strconv.Itoa(n)] = in.line
		switch in.cmd {
		case "USER":
			target.Attrs["user"] = strings.TrimSpace(in.value)
			target.Lines["user"] = in.line
		case "ENV", "ARG":
			key := "env"
			if in.cmd == "ARG" {
				key = "args"
			}
			m, ok := target.Attrs[key].(map[string]any)
			if !ok { // ENV before the first FROM
				m = map[string]any{}
				target.Attrs[key] = m
			}
			for _, kv := range dockerPairs(in.cmd, in.value) {
				if kv[1] == "\x00" {
					m[kv[0]] = nil
				} else {
					m[kv[0]] = kv[1]
				}
				target.Lines[key+"."+kv[0]] = in.line
			}
		}
	}
	if len(stages) == 0 {
		f := formatSyntax(name, "Dockerfile", fmt.Errorf("no FROM instruction"))
		f.Line = 1
		return nil, append(syntax, f)
	}
	for i := len(stages) - 1; i >= 0; {
		stages[i].Attrs["shipped"] = true
		if i == len(stages)-1 {
			stages[i].Attrs["final"] = true
		}
		p := int(stages[i].Attrs["parent"].(float64))
		if p >= i {
			break
		}
		i = p
	}
	list := make([]any, len(stages))
	for i, s := range stages {
		summary := ciCopy(s.Attrs)
		delete(summary, "env") // values are checked on the stage; keep them out of the file resource
		delete(summary, "args")
		list[i] = summary
		for k, v := range s.Lines {
			file.Lines["stages."+strconv.Itoa(i)+"."+k] = v
		}
	}
	fileAttrs["stages"] = list
	return append([]*Resource{file}, stages...), syntax
}
