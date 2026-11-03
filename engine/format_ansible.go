package engine

import (
	"sort"
	"strconv"
	"strings"
)

// Ansible playbooks and role task files become one resource per task: Type is
// ansible_ plus the module name without its collection (amazon.aws.s3_bucket ->
// ansible_s3_bucket), Attrs are the module arguments plus task keywords (the
// module wins on a clash), and become/no_log set on a play or block are
// inherited. Plays (ansible_play) and blocks (ansible_block) are resources too.
// Values with Jinja templates are Unknown, except shell command text (cmd).

func init() { formatParsers[FormatAnsible] = parseAnsible }

var ansTaskKeys = map[string]bool{
	"name": true, "action": true, "local_action": true, "args": true, "async": true, "become": true, "become_exe": true,
	"become_flags": true, "become_method": true, "become_user": true, "changed_when": true, "check_mode": true,
	"collections": true, "connection": true, "debugger": true, "delay": true, "delegate_facts": true, "delegate_to": true,
	"diff": true, "environment": true, "failed_when": true, "ignore_errors": true, "ignore_unreachable": true, "loop": true,
	"loop_control": true, "module_defaults": true, "no_log": true, "notify": true, "poll": true, "port": true,
	"register": true, "remote_user": true, "retries": true, "run_once": true, "tags": true, "throttle": true,
	"timeout": true, "until": true, "vars": true, "when": true, "listen": true, "any_errors_fatal": true,
}

// ansInherited are the keywords a task takes from its play or block.
var ansInherited = []string{"become", "become_user", "become_method", "no_log"}

// ansFreeForm modules take a command line rather than key=value arguments.
var ansFreeForm = map[string]bool{"shell": true, "command": true, "raw": true, "script": true, "win_shell": true, "win_command": true}

type ansParser struct {
	file string
	out  []*Resource
	n    int
}

func parseAnsible(name, src string) ([]*Resource, []Finding) {
	docs, err := decodeYAMLDocs(src)
	var syntax []Finding
	if err != nil {
		syntax = append(syntax, formatSyntax(name, "Ansible", err))
	}
	p := &ansParser{file: name}
	for _, d := range docs {
		list, _ := d.value.([]any)
		for i, it := range list {
			m, _ := it.(map[string]any)
			if m == nil {
				continue
			}
			if _, play := m["hosts"]; play || m["import_playbook"] != nil {
				p.play(m, strconv.Itoa(i), d.lines)
				continue
			}
			p.item(m, strconv.Itoa(i), d.lines, nil)
		}
	}
	for _, r := range p.out {
		r.Format = FormatAnsible
	}
	return p.out, syntax
}

func (p *ansParser) play(m map[string]any, path string, lines map[string]int) {
	attrs := map[string]any{}
	inherit := map[string]any{}
	for k, v := range m {
		switch k {
		case "tasks", "pre_tasks", "post_tasks", "handlers":
			continue
		}
		attrs[k] = ansValue(k, v)
	}
	for _, k := range ansInherited {
		if v, ok := attrs[k]; ok {
			inherit[k] = v
		}
	}
	name, _ := m["name"].(string)
	if name == "" {
		name, _ = m["hosts"].(string)
	}
	p.add("ansible_play", name, path, attrs, subLines(lines, path), lines[path])
	for _, sec := range []string{"pre_tasks", "tasks", "post_tasks", "handlers"} {
		for i, t := range asList(m[sec]) {
			if tm, ok := t.(map[string]any); ok {
				p.item(tm, path+"."+sec+"."+strconv.Itoa(i), lines, inherit)
			}
		}
	}
}

// item reads a task or a block (whose children inherit its keywords).
func (p *ansParser) item(m map[string]any, path string, lines map[string]int, inherit map[string]any) {
	if _, ok := m["block"]; ok {
		attrs := map[string]any{}
		child := map[string]any{}
		for k, v := range inherit {
			child[k] = v
		}
		for k, v := range m {
			if k != "block" {
				attrs[k] = ansValue(k, v)
			}
		}
		for _, k := range ansInherited {
			if v, ok := attrs[k]; ok {
				child[k] = v
			}
		}
		name, _ := m["name"].(string)
		p.add("ansible_block", name, path, attrs, subLines(lines, path), lines[path])
		for _, sec := range []string{"block", "rescue", "always"} {
			for i, t := range asList(m[sec]) {
				if tm, ok := t.(map[string]any); ok {
					p.item(tm, path+"."+sec+"."+strconv.Itoa(i), lines, child)
				}
			}
		}
		return
	}
	mod, args := ansModule(m)
	if mod == "" {
		return
	}
	short := mod[strings.LastIndex(mod, ".")+1:]
	attrs := map[string]any{}
	for k, v := range inherit {
		attrs[k] = v
	}
	for k, v := range m {
		if ansTaskKeys[k] && k != "name" && k != "args" && k != "action" && k != "local_action" {
			attrs[k] = ansValue(k, v)
		}
	}
	if extra, ok := m["args"].(map[string]any); ok {
		for k, v := range extra {
			attrs[k] = ansValue(k, v)
		}
	}
	switch a := args.(type) {
	case map[string]any:
		for k, v := range a {
			attrs[k] = ansValue(k, v)
		}
	case string:
		if ansFreeForm[short] {
			attrs["cmd"] = a
		} else if ansTemplated(a) {
			attrs["_args"] = Unknown{Expr: a}
		} else {
			// shortcut: key=value split on spaces, quoted values with spaces are cut; fine for flags rules read.
			for _, kv := range strings.Fields(a) {
				if k, v, ok := strings.Cut(kv, "="); ok {
					attrs[k] = ansScalar(strings.Trim(v, `"'`))
				}
			}
		}
	case Unknown:
		attrs["_args"] = a
	}
	sub := subLines(lines, path)
	out := map[string]int{}
	for k, l := range sub {
		switch {
		case strings.HasPrefix(k, mod+"."):
			out[strings.TrimPrefix(k, mod+".")] = l
		case strings.HasPrefix(k, "args."):
			if _, set := out[strings.TrimPrefix(k, "args.")]; !set {
				out[strings.TrimPrefix(k, "args.")] = l
			}
		default:
			if _, set := out[k]; !set {
				out[k] = l
			}
		}
	}
	name, _ := m["name"].(string)
	p.add("ansible_"+short, name, path, attrs, out, lines[path])
}

// ansModule finds the module a task calls and its raw arguments.
func ansModule(m map[string]any) (string, any) {
	for _, k := range []string{"action", "local_action"} {
		switch a := m[k].(type) {
		case string:
			mod, rest, _ := strings.Cut(strings.TrimSpace(a), " ")
			return mod, strings.TrimSpace(rest)
		case map[string]any:
			mod, _ := a["module"].(string)
			args := map[string]any{}
			for ak, av := range a {
				if ak != "module" {
					args[ak] = av
				}
			}
			return mod, args
		}
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !ansTaskKeys[k] && !strings.HasPrefix(k, "with_") && k != "block" && k != "rescue" && k != "always" {
			return k, m[k]
		}
	}
	return "", nil
}

func (p *ansParser) add(typ, name, path string, attrs map[string]any, lines map[string]int, line int) {
	p.n++
	label := name
	if label == "" {
		label = strconv.Itoa(p.n)
	}
	p.out = append(p.out, &Resource{Address: typ + "." + label, Mode: "managed", Type: typ, Name: label, File: p.file,
		Line: line, Attrs: attrs, Lines: lines})
}

func ansTemplated(s string) bool { return strings.Contains(s, "{{") || strings.Contains(s, "{%") }

// ansValue turns templated strings into Unknown, keeping shell text as written.
func ansValue(k string, v any) any {
	switch t := v.(type) {
	case string:
		if k != "cmd" && ansTemplated(t) {
			return Unknown{Expr: t}
		}
	case map[string]any:
		for mk, mv := range t {
			t[mk] = ansValue(mk, mv)
		}
	case []any:
		for i, e := range t {
			t[i] = ansValue("", e)
		}
	}
	return v
}

func ansScalar(s string) any {
	if ansTemplated(s) {
		return Unknown{Expr: s}
	}
	return s
}
