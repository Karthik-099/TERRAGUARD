package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Karthik-099/TERRAGUARD/engine"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type scanArgs struct {
	Path   string            `json:"path,omitempty" jsonschema:"directory or file to scan on this machine; ignored when files is set"`
	Files  map[string]string `json:"files,omitempty" jsonschema:"inline Terraform sources keyed by file name"`
	Plan   string            `json:"plan,omitempty" jsonschema:"output of terraform show -json tfplan"`
	Config string            `json:"config,omitempty" jsonschema:".terraguard.yml contents (policy, waivers, custom rules)"`
	Schema string            `json:"schema,omitempty" jsonschema:"optional terraform providers schema -json output, to check every argument"`
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
		return engine.Input{Files: a.Files, Plan: a.Plan, Config: a.Config, Schema: a.Schema}, nil
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
	in.Plan, in.Schema = a.Plan, a.Schema
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
	if err := newMCPServer(true).Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		return fmt.Errorf("mcp: %w", err)
	}
	return nil
}

// newMCPServer: local=false (the /mcp endpoint) never touches the server's disk.
func newMCPServer(local bool) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "terraguard", Version: engine.Version}, nil)

	mcp.AddTool(s, &mcp.Tool{Name: "scan_terraform", Description: "Scan Terraform for security issues, apply-time validation errors, attack paths and plan risks. Returns findings with exact lines and remediation."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a scanArgs) (*mcp.CallToolResult, any, error) {
			in, err := a.input(local)
			if err != nil {
				return nil, nil, err
			}
			return jsonResult(engine.Scan(in))
		})

	mcp.AddTool(s, &mcp.Tool{Name: "fix_terraform", Description: "Apply TerraGuard's deterministic auto-fixes. Returns the fixed file contents; with path+write=true also writes them."},
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

	mcp.AddTool(s, &mcp.Tool{Name: "generate_docs", Description: "Generate terraform-docs style Markdown (inputs, outputs, providers, resources) for a module."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a scanArgs) (*mcp.CallToolResult, any, error) {
			in, err := a.input(local)
			if err != nil {
				return nil, nil, err
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: engine.Docs(in.Files)}}}, nil, nil
		})

	mcp.AddTool(s, &mcp.Tool{Name: "generate_agents_md", Description: "Generate an AGENTS.md describing the repository's providers, commands, guardrails, waivers and boundaries for coding agents."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a scanArgs) (*mcp.CallToolResult, any, error) {
			in, err := a.input(local)
			if err != nil {
				return nil, nil, err
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: engine.AgentsMD(in.Files, in.Config)}}}, nil, nil
		})

	mcp.AddTool(s, &mcp.Tool{Name: "validate_rule", Description: "Validate a proposed custom rule (YAML for one custom_rules item) and dry-run it. Rejects anything that is not exactly one rule, built-in TG- IDs and rules without resource_types. Use it before suggesting a .terraguard.yml change."},
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

	mcp.AddTool(s, &mcp.Tool{Name: "list_rules", Description: "List every TerraGuard rule with severity, category and remediation."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			return jsonResult(engine.Catalog())
		})

	return s
}
