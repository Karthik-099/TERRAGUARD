package engine

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Fixes for formats other than Terraform. Kubernetes fixes edit the YAML node
// tree, so comments, key order and quoting survive; the rule's provider-style
// path (spec.0.template.0.spec.0.container.1.security_context.0.privileged)
// is matched against the manifest's own keys while walking. Dockerfile fixes
// replace text on one line, and only when the line still reads as expected.

// k8sKeyFor finds the manifest key that a provider-style segment came from.
func k8sKeyFor(m *yaml.Node, seg string) (*yaml.Node, *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		k := m.Content[i].Value
		if k == seg || k8sBlockNames[k] == seg || k8sSnake(k) == seg {
			return m.Content[i], m.Content[i+1]
		}
	}
	return nil, nil
}

// k8sManifestKey turns a provider-style segment back into a manifest key.
func k8sManifestKey(seg string) string {
	for k, v := range k8sBlockNames {
		if v == seg {
			return k
		}
	}
	parts := strings.Split(seg, "_")
	for i := 1; i < len(parts); i++ {
		switch p := parts[i]; p {
		case "pid", "ipc", "ip", "id", "uid", "gid", "tls", "url", "dns":
			parts[i] = strings.ToUpper(p) // hostPID, hostIPC, podIP
		default:
			if p != "" {
				parts[i] = strings.ToUpper(p[:1]) + p[1:]
			}
		}
	}
	return strings.Join(parts, "")
}

func scalarNode(v any) *yaml.Node {
	switch t := v.(type) {
	case bool:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: strconv.FormatBool(t)}
	case int:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(t)}
	case float64:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.FormatFloat(t, 'f', -1, 64)}
	}
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: fmt.Sprint(v)}
}

func applyYAMLFix(src string, fx *Fix) (string, error) {
	dec := yaml.NewDecoder(strings.NewReader(src))
	var docs []*yaml.Node
	for {
		var n yaml.Node
		if err := dec.Decode(&n); err != nil {
			if err.Error() == "EOF" {
				break
			}
			return "", fmt.Errorf("cannot parse: %w", err)
		}
		docs = append(docs, &n)
	}
	if fx.Doc >= len(docs) || len(docs[fx.Doc].Content) == 0 {
		return "", fmt.Errorf("document %d not found", fx.Doc)
	}
	node := docs[fx.Doc].Content[0]
	var segs []string
	if fx.Root != "" {
		segs = strings.Split(fx.Root, ".")
	}
	segs = append(segs, fx.Path...)
	for i, seg := range segs {
		last := i == len(segs)-1
		if n, err := strconv.Atoi(seg); err == nil {
			switch node.Kind {
			case yaml.SequenceNode:
				if n >= len(node.Content) {
					return "", fmt.Errorf("index %d out of range", n)
				}
				node = node.Content[n]
			case yaml.MappingNode: // a single block written as an object
			default:
				return "", fmt.Errorf("unexpected index %d", n)
			}
			continue
		}
		if node.Kind == yaml.SequenceNode && len(node.Content) > 0 {
			node = node.Content[0]
		}
		if node.Kind != yaml.MappingNode {
			return "", fmt.Errorf("%s: not an object", seg)
		}
		_, val := k8sKeyFor(node, seg)
		if last {
			if val != nil {
				nv := scalarNode(fx.Value)
				nv.HeadComment, nv.LineComment, nv.FootComment = val.HeadComment, val.LineComment, val.FootComment
				*val = *nv
			} else {
				node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k8sManifestKey(seg)}, scalarNode(fx.Value))
			}
			break
		}
		if val == nil {
			val = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k8sManifestKey(seg)}, val)
		}
		node = val
	}
	var b bytes.Buffer
	for i, d := range docs {
		if i > 0 || strings.HasPrefix(strings.TrimSpace(src), "---") {
			b.WriteString("---\n")
		}
		enc := yaml.NewEncoder(&b)
		enc.SetIndent(2)
		if err := enc.Encode(d); err != nil {
			return "", err
		}
		enc.Close()
	}
	return b.String(), nil
}

// applyLineEdit replaces Old with New on one line, only if the line still has Old.
func applyLineEdit(src string, fx *Fix) (string, error) {
	lines := strings.Split(src, "\n")
	if fx.Line < 1 || fx.Line > len(lines) || !strings.Contains(lines[fx.Line-1], fx.Old) {
		return "", fmt.Errorf("line %d changed since the scan", fx.Line)
	}
	lines[fx.Line-1] = strings.Replace(lines[fx.Line-1], fx.Old, fx.New, 1)
	return strings.Join(lines, "\n"), nil
}
