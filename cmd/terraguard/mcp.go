package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Karthik-099/TERRAGUARD/engine"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type scanArgs struct {
	Path   string            `json:"path,omitempty" jsonschema:"directory or file to scan on this machine; ignored when files is set"`
	Files  map[string]string `json:"files,omitempty" jsonschema:"inline sources keyed by file name: Terraform, Kubernetes, CloudFormation, ARM, Dockerfile, CI pipelines, Ansible, OpenAPI"`
	Plan   string            `json:"plan,omitempty" jsonschema:"output of terraform show -json tfplan"`
	Config string            `json:"config,omitempty" jsonschema:".terraguard.yml contents (policy, waivers, custom rules)"`
	Schema string            `json:"schema,omitempty" jsonschema:"optional terraform providers schema -json output, to check every argument"`
	// Frameworks limits the scan to some formats.
	Frameworks []string `json:"frameworks,omitempty" jsonschema:"only these formats, for example kubernetes or dockerfile"`
}

type costArgs struct {
	Path   string            `json:"path,omitempty" jsonschema:"directory to price on this machine; ignored when files or plan is set"`
	Files  map[string]string `json:"files,omitempty" jsonschema:"inline Terraform sources keyed by file name"`
	Plan   string            `json:"plan,omitempty" jsonschema:"output of terraform show -json tfplan; prices before and after"`
	Usage  string            `json:"usage,omitempty" jsonschema:"usage file YAML for usage-based charges"`
	Prices string            `json:"prices,omitempty" jsonschema:"price overrides YAML (price key: USD)"`
}

type fixArgs struct {
	scanArgs
	Write bool `json:"write,omitempty" jsonschema:"write fixed files back to disk (only with path)"`
}

// errRemotePath stops remote callers from reading the server's file system.
var errRemotePath = errors.New("path is only available in the local MCP server (terraguard mcp); send files instead")

// input builds the engine input. Only the local stdio server may read paths.
func (a scanArgs) input(local bool) (engine.Input, error) {
	if len(a.Files) > 0 {
		return engine.Input{Files: a.Files, Plan: a.Plan, Config: a.Config, Schema: a.Schema, Frameworks: a.Frameworks}, nil
	}
	if !local {
		return engine.Input{}, errRemotePath
	}
	p := a.Path
	if p == "" {
		p = "."
	}
	in, err := buildInput([]string{p}, "", "", "")
	if err != nil {
		return in, err
	}
	in.Plan, in.Schema, in.Frameworks = a.Plan, a.Schema, a.Frameworks
	if a.Config != "" {
		in.Config = a.Config
	}
	return in, nil
}

func jsonResult(v any) (*mcp.CallToolResult, any, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil, nil
}

// runMCP serves the tools over stdio for local agents.
func runMCP() error {
	if err := newMCPServer(true, nil).Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		return fmt.Errorf("mcp: %w", err)
	}
	return nil
}

// addTool runs every tool under the scan gate (nil for the local server).
func addTool[In any](s *mcp.Server, g *scanGate, t *mcp.Tool, h mcp.ToolHandlerFor[In, any]) {
	mcp.AddTool(s, t, func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
		var res *mcp.CallToolResult
		var out any
		var err error
		if gerr := g.run(ctx, func() { res, out, err = h(ctx, req, in) }); gerr != nil {
			return nil, nil, gerr
		}
		return res, out, err
	})
}

// newMCPServer: local=false (the /mcp endpoint) never touches the server's disk.
func newMCPServer(local bool, gate *scanGate) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "terraguard", Version: engine.Version}, nil)

	addTool(s, gate, &mcp.Tool{Name: "scan_terraform", Description: "Scan infrastructure code (Terraform and OpenTofu, Kubernetes manifests, CloudFormation and SAM, Serverless, ARM, Dockerfile, docker-compose, CI pipelines, Ansible, OpenAPI) for security issues, apply-time validation errors, attack paths and plan risks. Returns findings with exact lines and remediation."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a scanArgs) (*mcp.CallToolResult, any, error) {
			in, err := a.input(local)
			if err != nil {
				return nil, nil, err
			}
			return jsonResult(engine.Scan(in))
		})

	addTool(s, gate, &mcp.Tool{Name: "estimate_cost", Description: "Estimate the monthly cost of a Terraform plan (before and after) or of Terraform code, for AWS, Azure and Google Cloud, offline from bundled list prices; usage-based charges from an optional usage file."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a costArgs) (*mcp.CallToolResult, any, error) {
			opts := engine.CostOptions{Usage: a.Usage, Prices: a.Prices}
			if a.Plan != "" {
				est, err := engine.EstimateCostWith(a.Plan, opts)
				if err != nil {
					return nil, nil, err
				}
				return jsonResult(est)
			}
			files := a.Files
			if len(files) == 0 {
				if !local {
					return nil, nil, errRemotePath
				}
				p := a.Path
				if p == "" {
					p = "."
				}
				var err error
				if files, err = loadFiles([]string{p}); err != nil {
					return nil, nil, err
				}
			}
			est, err := engine.EstimateCostFromCode(files, opts)
			if err != nil {
				return nil, nil, err
			}
			return jsonResult(est)
		})

	addTool(s, gate, &mcp.Tool{Name: "fix_terraform", Description: "Apply TerraGuard's deterministic auto-fixes. Returns the fixed file contents; with path+write=true also writes them."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a fixArgs) (*mcp.CallToolResult, any, error) {
			in, err := a.input(local)
			if err != nil {
				return nil, nil, err
			}
			changed, errs := engine.FixAll(in)
			if a.Write && local && len(a.Files) == 0 {
				for name, src := range changed {
					if err := os.WriteFile(filepath.FromSlash(name), []byte(src), 0o644); err != nil {
						return nil, nil, err
					}
				}
			}
			var skipped []string
			for _, e := range errs {
				skipped = append(skipped, e.Error())
			}
			return jsonResult(map[string]any{"changed_files": changed, "skipped": skipped})
		})

	addTool(s, gate, &mcp.Tool{Name: "generate_docs", Description: "Generate terraform-docs style Markdown (inputs, outputs, providers, resources) for a module."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a scanArgs) (*mcp.CallToolResult, any, error) {
			in, err := a.input(local)
			if err != nil {
				return nil, nil, err
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: engine.Docs(in.Files)}}}, nil, nil
		})

	addTool(s, gate, &mcp.Tool{Name: "generate_agents_md", Description: "Generate an AGENTS.md describing the repository's providers, commands, guardrails, waivers and boundaries for coding agents."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a scanArgs) (*mcp.CallToolResult, any, error) {
			in, err := a.input(local)
			if err != nil {
				return nil, nil, err
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: engine.AgentsMD(in.Files, in.Config)}}}, nil, nil
		})

	addTool(s, gate, &mcp.Tool{Name: "validate_rule", Description: "Validate a proposed custom rule (YAML for one custom_rules item) and dry-run it. Rejects anything that is not exactly one rule, built-in TG- IDs and rules without resource_types. Use it before suggesting a .terraguard.yml change."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a struct {
			scanArgs
			Rule string `json:"rule" jsonschema:"YAML for one custom rule: id, title, severity, resource_types, where, assert or attribute plus one operator"`
		}) (*mcp.CallToolResult, any, error) {
			in, err := a.input(local)
			if err != nil {
				return nil, nil, err
			}
			return jsonResult(engine.DraftRule(a.Rule, in))
		})

	addTool(s, gate, &mcp.Tool{Name: "list_rules", Description: "List every TerraGuard rule with severity, category and remediation."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			return jsonResult(engine.Catalog())
		})

	addTool(s, gate, &mcp.Tool{Name: "explain_rule", Description: "Explain one TerraGuard rule by ID: title, severity, category, remediation, CWE, compliance themes and the resource types it checks."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a struct {
			ID string `json:"id" jsonschema:"rule ID, for example TG-AWS-S3-001"`
		}) (*mcp.CallToolResult, any, error) {
			for _, r := range engine.Catalog() {
				if strings.EqualFold(r.ID, strings.TrimSpace(a.ID)) {
					return jsonResult(r)
				}
			}
			return nil, nil, fmt.Errorf("no rule %q; list_rules shows every ID", a.ID)
		})

	addTool(s, gate, &mcp.Tool{Name: "review_diff", Description: "Review a change: scan the base and head versions of the files and return only the findings the change introduces or resolves, with a risk tier and pass/fail. Send both versions inline."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a struct {
			Base   map[string]string `json:"base_files" jsonschema:"files before the change, keyed by file name"`
			Head   map[string]string `json:"head_files" jsonschema:"files after the change, keyed by file name"`
			Config string            `json:"config,omitempty" jsonschema:".terraguard.yml the change is judged by (the base branch policy)"`
		}) (*mcp.CallToolResult, any, error) {
			if len(a.Head) == 0 && len(a.Base) == 0 {
				return nil, nil, errors.New("send base_files and head_files")
			}
			var changed []string
			for name, src := range a.Head {
				if old, ok := a.Base[name]; !ok || old != src {
					changed = append(changed, name)
				}
			}
			for name := range a.Base {
				if _, ok := a.Head[name]; !ok {
					changed = append(changed, name)
				}
			}
			base := engine.Scan(engine.Input{Files: a.Base, Config: a.Config})
			head := engine.Scan(engine.Input{Files: a.Head, Config: a.Config})
			rev := engine.NewReview(base, head, engine.ChangedTerraform(changed))
			rev.Silenced = engine.SilencedBy(base, head)
			return jsonResult(rev)
		})

	addTool(s, gate, &mcp.Tool{Name: "suggest_policy", Description: "Turn a plain-English standard into a custom rule without any AI call on the server: returns the rule-writing guide and the resource types in the files, so you can draft one rule; send it back as rule to validate and dry-run it."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a struct {
			scanArgs
			Standard string `json:"standard" jsonschema:"the standard in plain English, for example: production databases keep 14 days of backups"`
			Rule     string `json:"rule,omitempty" jsonschema:"your drafted YAML for one custom rule; when set, it is validated and dry-run"`
		}) (*mcp.CallToolResult, any, error) {
			in, err := a.input(local)
			if err != nil {
				return nil, nil, err
			}
			out := map[string]any{"standard": a.Standard, "guide": engine.RuleDraftPrompt, "resource_types": engine.ResourceTypes(in.Files),
				"next": "Draft exactly one custom rule as YAML following the guide, then call suggest_policy (or validate_rule) again with rule set."}
			if strings.TrimSpace(a.Rule) != "" {
				out["draft"] = engine.DraftRule(a.Rule, in)
			}
			return jsonResult(out)
		})

	addTool(s, gate, &mcp.Tool{Name: "generate_sbom", Description: "List the infrastructure components in the files (providers, modules, container images, charts) as a CycloneDX JSON SBOM, or as a plain component list with format=json."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a struct {
			scanArgs
			Format string `json:"format,omitempty" jsonschema:"cyclonedx (default) or json"`
		}) (*mcp.CallToolResult, any, error) {
			in, err := a.input(local)
			if err != nil {
				return nil, nil, err
			}
			comps := engine.SBOMComponents(in.Files)
			if a.Format == "json" {
				return jsonResult(comps)
			}
			b, err := engine.CycloneDX(comps, time.Now().UTC().Format(time.RFC3339))
			if err != nil {
				return nil, nil, err
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil, nil
		})

	addTool(s, gate, &mcp.Tool{Name: "check_plan", Description: "Check a Terraform plan (terraform show -json tfplan): counts of creates, updates, deletes and replacements, each change, drift, the risk findings (destructive changes, public exposure), the will-it-apply verdict and the cost change."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a struct {
			Plan   string `json:"plan" jsonschema:"output of terraform show -json tfplan"`
			Config string `json:"config,omitempty" jsonschema:".terraguard.yml contents"`
		}) (*mcp.CallToolResult, any, error) {
			if strings.TrimSpace(a.Plan) == "" {
				return nil, nil, errors.New("send plan: the output of terraform show -json tfplan")
			}
			rep := engine.Scan(engine.Input{Plan: a.Plan, Config: a.Config})
			if rep.Plan == nil {
				return nil, nil, fmt.Errorf("not a plan: %s", strings.Join(rep.Errors, "; "))
			}
			return jsonResult(map[string]any{"plan": rep.Plan, "passed": rep.Passed, "score": rep.Score, "grade": rep.Grade,
				"verdict": rep.Verdict, "summary": rep.Summary, "findings": rep.Findings, "cost": rep.Cost})
		})

	return s
}
