package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// bearer adds the server token to every request the MCP client makes.
type bearer string

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+string(b))
	return http.DefaultTransport.RoundTrip(r)
}

func TestRemoteMCPScansInlineFilesOnly(t *testing.T) {
	srv := httptest.NewServer(newServer("s3cret"))
	defer srv.Close()
	ctx := context.Background()
	connect := func(token string) (*mcp.ClientSession, error) {
		c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
		return c.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: srv.URL + "/mcp", HTTPClient: &http.Client{Transport: bearer(token)}, DisableStandaloneSSE: true, MaxRetries: -1}, nil)
	}
	if _, err := connect("wrong"); err == nil {
		t.Fatal("connected with a wrong token")
	}
	cs, err := connect("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "scan_terraform", Arguments: map[string]any{
		"files": map[string]string{"main.tf": `resource "aws_s3_bucket" "b" { acl = "public-read" }`}}})
	if err != nil || res.IsError {
		t.Fatalf("scan failed: %v %+v", err, res)
	}
	if text := res.Content[0].(*mcp.TextContent).Text; !strings.Contains(text, "TG-AWS-S3-001") {
		t.Fatalf("scan result misses the public ACL finding:\n%.300s", text)
	}

	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "validate_rule", Arguments: map[string]any{
		"files": map[string]string{"main.tf": `resource "aws_s3_bucket" "b" {}`},
		"rule":  "id: ORG-TAG-001\nresource_types: [aws_s3_bucket]\nattribute: tags.owner\nexists: true"}})
	if err != nil || res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "aws_s3_bucket.b") {
		t.Fatalf("validate_rule did not dry-run the rule: %v %+v", err, res)
	}

	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "scan_terraform", Arguments: map[string]any{
		"files": map[string]string{"Dockerfile": "FROM node:latest\nUSER root\n"}}})
	if err != nil || res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "TG-DOCKER") {
		t.Fatalf("the scan tool must read other formats: %v %+v", err, res)
	}
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "estimate_cost", Arguments: map[string]any{
		"files": map[string]string{"main.tf": `resource "aws_nat_gateway" "n" {}`}}})
	if err != nil || res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, `"after": 32.85`) {
		t.Fatalf("estimate_cost: %v %+v", err, res)
	}
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "estimate_cost", Arguments: map[string]any{"path": "/etc"}})
	if err == nil && !res.IsError {
		t.Fatal("remote cost estimate of a server path was allowed")
	}

	// Remote callers must never read the server's disk.
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "scan_terraform", Arguments: map[string]any{"path": "/etc"}})
	if err == nil && !res.IsError {
		t.Fatal("remote scan of a server path was allowed")
	}
}

func TestRemoteMCPNewTools(t *testing.T) {
	srv := httptest.NewServer(newServer("s3cret"))
	defer srv.Close()
	ctx := context.Background()
	c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	cs, err := c.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: srv.URL + "/mcp", HTTPClient: &http.Client{Transport: bearer("s3cret")}, DisableStandaloneSSE: true, MaxRetries: -1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	call := func(name string, args map[string]any) (string, bool) {
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return res.Content[0].(*mcp.TextContent).Text, res.IsError
	}
	plan, err := os.ReadFile("../../examples/plan.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		tool string
		args map[string]any
		want string
	}{
		{"explain_rule", map[string]any{"id": "tg-aws-s3-001"}, `"remediation"`},
		{"review_diff", map[string]any{"base_files": map[string]string{"main.tf": `resource "aws_s3_bucket" "b" {}`},
			"head_files": map[string]string{"main.tf": `resource "aws_s3_bucket" "b" { acl = "public-read" }`}}, "TG-AWS-S3-001"},
		{"suggest_policy", map[string]any{"standard": "buckets have an owner tag", "files": map[string]string{"main.tf": `resource "aws_s3_bucket" "b" {}`},
			"rule": "id: ORG-TAG-001\nresource_types: [aws_s3_bucket]\nattribute: tags.owner\nexists: true"}, "aws_s3_bucket.b"},
		{"generate_sbom", map[string]any{"files": map[string]string{"main.tf": "terraform {\n  required_providers {\n    aws = { source = \"hashicorp/aws\", version = \"5.0.0\" }\n  }\n}\n"}}, `"bomFormat": "CycloneDX"`},
		{"check_plan", map[string]any{"plan": string(plan)}, `"verdict"`},
	} {
		if text, isErr := call(c.tool, c.args); isErr || !strings.Contains(text, c.want) {
			t.Errorf("%s: error=%v, missing %q:\n%.400s", c.tool, isErr, c.want, text)
		}
	}
	if _, isErr := call("explain_rule", map[string]any{"id": "TG-NOPE"}); !isErr {
		t.Error("unknown rule must be an error")
	}
	for _, tool := range []string{"generate_sbom", "suggest_policy"} {
		if _, isErr := call(tool, map[string]any{"path": "/etc", "standard": "x"}); !isErr {
			t.Errorf("remote %s read a server path", tool)
		}
	}
	if _, isErr := call("check_plan", map[string]any{"plan": "{}"}); !isErr {
		t.Error("check_plan accepted something that is not a plan")
	}
}
