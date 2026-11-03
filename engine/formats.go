package engine

import (
	"bytes"
	"fmt"
	"path"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Formats other than Terraform are read into the same Resource model, so one
// engine, one policy and one gate cover them all. Each format registers a
// parser; detection is by file name and content, so unrelated YAML and JSON
// files are skipped.

// Format names, as used by Input.Frameworks and --framework.
const (
	FormatTerraform      = "terraform"
	FormatKubernetes     = "kubernetes"
	FormatCloudFormation = "cloudformation"
	FormatARM            = "arm"
	FormatDockerfile     = "dockerfile"
	FormatCompose        = "docker-compose"
	FormatGitHubActions  = "github-actions"
	FormatGitLabCI       = "gitlab-ci"
	FormatAzurePipelines = "azure-pipelines"
	FormatCircleCI       = "circleci"
	FormatBitbucket      = "bitbucket-pipelines"
	FormatServerless     = "serverless"
	FormatAnsible        = "ansible"
	FormatOpenAPI        = "openapi"
)

// formatParser turns one file into resources; it may also report syntax findings.
type formatParser func(name, src string) ([]*Resource, []Finding)

// formatParsers is filled by each format's file in an init function.
var formatParsers = map[string]formatParser{}

// maxDocSize skips generated or vendored files that are not configuration.
const maxDocSize = 4 << 20

// detectFormat names the format of a non-Terraform file, or "" to skip it.
func detectFormat(name, src string) string {
	base := path.Base(name)
	lower := strings.ToLower(base)
	switch {
	case len(src) > maxDocSize:
		return ""
	case isPulumiFile(lower, src):
		return FormatPulumi
	case lower == "dockerfile" || strings.HasPrefix(lower, "dockerfile.") || strings.HasSuffix(lower, ".dockerfile") || lower == "containerfile":
		return FormatDockerfile
	case strings.Contains(name, ".github/workflows/") && (strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")):
		return FormatGitHubActions
	case lower == ".gitlab-ci.yml" || lower == ".gitlab-ci.yaml":
		return FormatGitLabCI
	case lower == "azure-pipelines.yml" || lower == "azure-pipelines.yaml":
		return FormatAzurePipelines
	case strings.Contains(name, ".circleci/") && lower == "config.yml":
		return FormatCircleCI
	case lower == "bitbucket-pipelines.yml":
		return FormatBitbucket
	case lower == "serverless.yml" || lower == "serverless.yaml":
		return FormatServerless
	case strings.HasPrefix(lower, "docker-compose") || strings.HasPrefix(lower, "compose.") && (strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")):
		return FormatCompose
	}
	isYAML := strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")
	isJSON := strings.HasSuffix(lower, ".json") || strings.HasSuffix(lower, ".template")
	if !isYAML && !isJSON || isYAML && strings.Contains(src, "{{") && strings.Contains(src, "}}") {
		return "" // Helm and other Go templates are only manifests once rendered (--helm)
	}
	head := src
	if len(head) > 8192 {
		head = head[:8192]
	}
	switch {
	case isYAML && isDeploymentManager(head):
		return FormatDeploymentManager
	case isCrossplane(head):
		return FormatCrossplane
	case strings.Contains(head, "AWSTemplateFormatVersion") || strings.Contains(head, "AWS::Serverless") || cfnResourceRE(head):
		return FormatCloudFormation
	case strings.Contains(head, "deploymentTemplate.json#") || strings.Contains(head, "schema.management.azure.com"):
		return FormatARM
	case strings.Contains(head, "openapi:") || strings.Contains(head, `"openapi"`) || strings.Contains(head, "swagger:") || strings.Contains(head, `"swagger"`):
		return FormatOpenAPI
	case isYAML && strings.Contains(head, "apiVersion:") && strings.Contains(head, "kind:"),
		isJSON && strings.Contains(head, `"apiVersion"`) && strings.Contains(head, `"kind"`):
		return FormatKubernetes
	case isYAML && (strings.Contains(head, "hosts:") && (strings.Contains(head, "tasks:") || strings.Contains(head, "roles:"))),
		isYAML && (strings.Contains(name, "roles/") && (strings.Contains(name, "/tasks/") || strings.Contains(name, "/handlers/"))):
		return FormatAnsible
	}
	return ""
}

func cfnResourceRE(head string) bool {
	return strings.Contains(head, "Resources") && (strings.Contains(head, "Type: AWS::") || strings.Contains(head, "Type: 'AWS::") ||
		strings.Contains(head, `Type: "AWS::`) || strings.Contains(head, `"Type": "AWS::`) || strings.Contains(head, `"Type":"AWS::`))
}

// FormatOf reports the format TerraGuard reads a file as, or "" when it is skipped.
func FormatOf(name, src string) string {
	if isHCLFile(name) {
		return FormatTerraform
	}
	return detectFormat(name, src)
}

func isHCLFile(name string) bool {
	return strings.HasSuffix(name, ".tf") || strings.HasSuffix(name, ".tofu") || strings.HasSuffix(name, ".tfvars") ||
		strings.HasSuffix(name, ".tf.json") || path.Base(name) == "terragrunt.hcl" || path.Base(name) == ".terraform.lock.hcl"
}

// IsScannable reports whether a file name could hold configuration TerraGuard
// reads (the content decides for YAML and JSON).
func IsScannable(name string) bool {
	if IsTerraformFile(name) {
		return true
	}
	lower := strings.ToLower(path.Base(name))
	return strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".json") ||
		strings.HasSuffix(lower, ".template") || lower == "dockerfile" || strings.HasPrefix(lower, "dockerfile.") ||
		strings.HasSuffix(lower, ".dockerfile") || lower == "containerfile"
}

// YAML and JSON documents become plain values plus a line for every path, in
// the engine's dotted form (a.0.b) and without indexes (a.b) for the first match.

type docValue struct {
	value any
	lines map[string]int
}

// decodeYAMLDocs reads every document in a YAML (or JSON) file. Custom tags
// such as CloudFormation's !Ref become Unknown, so rules treat them as
// values decided at deploy time.
func decodeYAMLDocs(src string) ([]docValue, error) {
	dec := yaml.NewDecoder(bytes.NewReader([]byte(src)))
	var out []docValue
	for {
		var n yaml.Node
		if err := dec.Decode(&n); err != nil {
			if err.Error() == "EOF" {
				return out, nil
			}
			return out, err
		}
		if len(n.Content) == 0 {
			continue
		}
		lines := map[string]int{}
		v := nodeValue(n.Content[0], "", lines, 0)
		out = append(out, docValue{v, lines})
	}
}

const maxNodeDepth = 100

func nodeValue(n *yaml.Node, p string, lines map[string]int, depth int) any {
	if depth > maxNodeDepth {
		return nil
	}
	record := func(p string, line int) {
		if p == "" {
			return
		}
		if _, ok := lines[p]; !ok {
			lines[p] = line
		}
		if s := stripIndexes(p); s != p {
			if _, ok := lines[s]; !ok {
				lines[s] = line
			}
		}
	}
	join := func(k string) string {
		if p == "" {
			return k
		}
		return p + "." + k
	}
	if n.Kind == yaml.AliasNode && n.Alias != nil {
		return nodeValue(n.Alias, p, lines, depth+1)
	}
	if n.Tag != "" && !strings.HasPrefix(n.Tag, "!!") {
		// a custom tag: !Ref, !Sub, !GetAtt, !If ...
		return Unknown{Expr: strings.TrimSpace(n.Tag + " " + scalarText(n))}
	}
	switch n.Kind {
	case yaml.MappingNode:
		m := map[string]any{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i].Value
			if k == "<<" { // merge key
				if mm, ok := nodeValue(n.Content[i+1], p, lines, depth+1).(map[string]any); ok {
					for mk, mv := range mm {
						if _, set := m[mk]; !set {
							m[mk] = mv
						}
					}
				}
				continue
			}
			record(join(k), n.Content[i].Line)
			m[k] = nodeValue(n.Content[i+1], join(k), lines, depth+1)
		}
		return m
	case yaml.SequenceNode:
		l := make([]any, 0, len(n.Content))
		for i, c := range n.Content {
			record(join(strconv.Itoa(i)), c.Line)
			l = append(l, nodeValue(c, join(strconv.Itoa(i)), lines, depth+1))
		}
		return l
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!bool":
			return strings.EqualFold(n.Value, "true") || strings.EqualFold(n.Value, "yes") || strings.EqualFold(n.Value, "on")
		case "!!int", "!!float":
			if f, err := strconv.ParseFloat(strings.ReplaceAll(n.Value, "_", ""), 64); err == nil {
				return f
			}
		case "!!null":
			return nil
		}
		return n.Value
	}
	return nil
}

func scalarText(n *yaml.Node) string {
	if n.Kind == yaml.ScalarNode {
		return n.Value
	}
	var parts []string
	for _, c := range n.Content {
		parts = append(parts, scalarText(c))
	}
	return strings.Join(parts, " ")
}

// subLines returns the lines under prefix, re-rooted at the prefix.
func subLines(lines map[string]int, prefix string) map[string]int {
	out := map[string]int{}
	for k, v := range lines {
		if k == prefix {
			continue
		}
		if rest, ok := strings.CutPrefix(k, prefix+"."); ok {
			out[rest] = v
		}
	}
	return out
}

// formatSyntax is the finding for a file a parser could not read.
func formatSyntax(name, format string, err error) Finding {
	return Finding{RuleID: "TG-VAL-001", Severity: High, Category: CatValidate, Blocking: true,
		Title: "Syntax error", Message: fmt.Sprintf("Invalid %s file: %v", format, err), File: name,
		Remediation: "Fix the syntax; the tool that reads this file cannot parse it."}
}
