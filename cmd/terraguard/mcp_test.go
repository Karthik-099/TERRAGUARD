package main

import (
	"context"
	"net/http"
	"net/http/httptest"
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

	// Remote callers must never read the server's disk.
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "scan_terraform", Arguments: map[string]any{"path": "/etc"}})
	if err == nil && !res.IsError {
		t.Fatal("remote scan of a server path was allowed")
	}
}
