package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// Terraform's JSON syntax (.tf.json, as CDKTF writes) is converted into the
// equivalent native syntax so every rule runs on it. lines maps each line of
// the converted text back to the line in the JSON file.

type jNode struct {
	key   string
	line  int
	value any // scalar, []*jNode (object, in order), or []any (array)
}

type jObject []*jNode

// jsonToHCL converts a .tf.json document.
func jsonToHCL(src string) (string, map[int]int, error) {
	dec := json.NewDecoder(strings.NewReader(src))
	dec.UseNumber()
	lineAt := lineIndex(src)
	v, err := readJSON(dec, lineAt, 0)
	if err != nil {
		return "", nil, err
	}
	top, ok := v.(jObject)
	if !ok {
		return "", nil, fmt.Errorf("a .tf.json file must hold an object")
	}
	w := &hclWriter{lines: map[int]int{}}
	for _, n := range top {
		switch n.key {
		case "resource", "data":
			for _, t := range objects(n.value) {
				for _, typ := range t {
					for _, inst := range objects(typ.value) {
						for _, name := range inst {
							for _, body := range objects(name.value) {
								w.block(name.line, body, n.key, typ.key, name.key)
							}
						}
					}
				}
			}
		case "variable", "output", "module", "provider", "check", "removed", "import", "moved":
			for _, o := range objects(n.value) {
				for _, name := range o {
					for _, body := range objects(name.value) {
						w.block(name.line, body, n.key, name.key)
					}
				}
			}
		case "locals", "terraform":
			for _, body := range objects(n.value) {
				w.block(n.line, body, n.key)
			}
		}
	}
	return w.b.String(), w.lines, nil
}

// objects accepts an object or an array of objects, as the JSON syntax does.
func objects(v any) []jObject {
	switch t := v.(type) {
	case jObject:
		return []jObject{t}
	case []any:
		var out []jObject
		for _, e := range t {
			if o, ok := e.(jObject); ok {
				out = append(out, o)
			}
		}
		return out
	}
	return nil
}

func lineIndex(src string) func(int64) int {
	var starts []int
	for i, c := range src {
		if c == '\n' {
			starts = append(starts, i)
		}
	}
	return func(off int64) int { return sort.SearchInts(starts, int(off)) + 1 }
}

// maxJSONDepth bounds nesting so a crafted file cannot exhaust the stack.
const maxJSONDepth = 64

func readJSON(dec *json.Decoder, lineAt func(int64) int, depth int) (any, error) {
	if depth > maxJSONDepth {
		return nil, fmt.Errorf("nested deeper than %d levels", maxJSONDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			var o jObject
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return nil, err
				}
				off := dec.InputOffset() - 1 // the end of the key
				v, err := readJSON(dec, lineAt, depth+1)
				if err != nil {
					return nil, err
				}
				o = append(o, &jNode{key: fmt.Sprint(k), line: lineAt(off), value: v})
			}
			_, err := dec.Token()
			return o, err
		case '[':
			var l []any
			for dec.More() {
				v, err := readJSON(dec, lineAt, depth+1)
				if err != nil {
					return nil, err
				}
				l = append(l, v)
			}
			_, err := dec.Token()
			return l, err
		}
	case json.Number:
		return t, nil
	}
	if tok == nil {
		return nil, nil
	}
	if _, ok := tok.(json.Delim); ok {
		return nil, io.ErrUnexpectedEOF
	}
	return tok, nil
}

type hclWriter struct {
	b     strings.Builder
	n     int // lines written
	lines map[int]int
}

func (w *hclWriter) line(src int, s string) {
	w.n++
	w.lines[w.n] = src
	w.b.WriteString(s + "\n")
}

// metaBlocks are written as blocks; everything else becomes an argument,
// which the engine reads the same way as a nested block.
var jsonBlocks = map[string]bool{"lifecycle": true, "provisioner": true, "connection": true, "dynamic": true, "content": true,
	"required_providers": true, "backend": true, "cloud": true, "validation": true, "precondition": true, "postcondition": true}

func (w *hclWriter) block(line int, body jObject, labels ...string) {
	head := labels[0]
	for _, l := range labels[1:] {
		head += " " + strconv.Quote(l)
	}
	w.line(line, head+" {")
	w.body(body, labels[0])
	w.line(line, "}")
}

func (w *hclWriter) body(body jObject, kind string) {
	for _, n := range body {
		switch {
		case n.key == "//":
			continue // comments in the JSON syntax
		case n.key == "depends_on" || n.key == "providers" && kind == "module" || n.key == "provider" && kind != "terraform" || n.key == "type" && kind == "variable":
			w.line(n.line, n.key+" = "+bareRefs(n.value))
		case jsonBlocks[n.key] || n.key == "backend" && kind == "terraform":
			w.nested(n)
		default:
			w.attr(n.line, n.key, n.value, "  ")
		}
	}
}

func (w *hclWriter) nested(n *jNode) {
	for _, o := range objects(n.value) {
		labeled := n.key == "dynamic" || n.key == "provisioner" || n.key == "backend"
		if labeled {
			for _, inner := range o {
				for _, body := range objects(inner.value) {
					w.line(inner.line, n.key+" "+strconv.Quote(inner.key)+" {")
					w.body(body, n.key)
					w.line(inner.line, "}")
				}
			}
			continue
		}
		w.line(n.line, n.key+" {")
		if n.key == "required_providers" {
			for _, p := range o {
				w.attr(p.line, p.key, p.value, "  ")
			}
		} else {
			w.body(o, n.key)
		}
		w.line(n.line, "}")
	}
}

func (w *hclWriter) attr(line int, key string, v any, indent string) {
	name := key
	if !validIdent(key) {
		name = strconv.Quote(key)
	}
	switch t := v.(type) {
	case jObject:
		w.line(line, indent+name+" = {")
		for _, n := range t {
			w.attr(n.line, n.key, n.value, indent+"  ")
		}
		w.line(line, indent+"}")
	default:
		w.line(line, indent+name+" = "+hclValue(v))
	}
}

func validIdent(s string) bool {
	for i, c := range s {
		if !(c == '_' || c == '-' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return s != ""
}

func hclValue(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case bool:
		return strconv.FormatBool(t)
	case json.Number:
		return t.String()
	case string:
		return quoteTemplate(t)
	case jObject:
		var b bytes.Buffer
		b.WriteString("{")
		for i, n := range t {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(strconv.Quote(n.key) + " = " + hclValue(n.value))
		}
		b.WriteString("}")
		return b.String()
	case []any:
		parts := make([]string, len(t))
		for i, e := range t {
			parts[i] = hclValue(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}
	return "null"
}

// quoteTemplate writes a JSON string as an HCL template; ${...} stays live.
func quoteTemplate(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, c := range s {
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// bareRefs writes depends_on-style lists, whose strings are references.
func bareRefs(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSuffix(strings.TrimPrefix(t, "${"), "}")
	case []any:
		parts := make([]string, len(t))
		for i, e := range t {
			parts[i] = bareRefs(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case jObject:
		parts := make([]string, len(t))
		for i, n := range t {
			parts[i] = n.key + " = " + bareRefs(n.value)
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return hclValue(v)
}
