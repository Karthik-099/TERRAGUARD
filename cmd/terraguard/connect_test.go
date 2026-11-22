package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestConnectCursorMergesKeepingOtherEntries(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".cursor", "mcp.json")
	os.MkdirAll(filepath.Dir(p), 0o755)
	old := "{\n    \"mcpServers\": {\n        \"zeta\": {\n            \"command\": \"z\"\n        },\n        \"alpha\": {\n            \"url\": \"https://a\"\n        }\n    },\n    \"other\": 1\n}\n"
	os.WriteFile(p, []byte(old), 0o600)
	var out strings.Builder
	if err := connect([]string{"cursor", "--dir", dir, "--url", "https://tg.example.com/mcp"}, &out); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	got := string(b)
	if !strings.Contains(got, "\n    \"mcpServers\"") || strings.Index(got, "zeta") > strings.Index(got, "alpha") || !strings.Contains(got, `"other": 1`) {
		t.Fatalf("indentation, order or other entries lost:\n%s", got)
	}
	var cfg struct {
		MCPServers map[string]struct {
			URL     string
			Headers map[string]string
		}
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	tg := cfg.MCPServers["terraguard"]
	if tg.URL != "https://tg.example.com/mcp" || tg.Headers["Authorization"] != "Bearer ${env:TERRAGUARD_SERVER_TOKEN}" || len(cfg.MCPServers) != 3 {
		t.Fatalf("entry = %+v", cfg)
	}
	if bak, _ := os.ReadFile(p + ".bak"); string(bak) != old {
		t.Fatal("old file was not backed up")
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want the old file's 0600", st.Mode().Perm())
	}
	// Comments: refuse rather than lose them.
	os.WriteFile(p, []byte("{ // comment\n}"), 0o644)
	if err := connect([]string{"cursor", "--dir", dir}, &out); err == nil || !strings.Contains(err.Error(), "by hand") {
		t.Fatalf("JSONC must be refused: %v", err)
	}
}

func TestConnectVSCodeGlobalPromptsForToken(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)
	t.Setenv("HOME", cfg)
	t.Setenv("APPDATA", cfg)
	t.Setenv("TERRAGUARD_SERVER_TOKEN", "tok_do_not_write_123")
	var out strings.Builder
	for i := 0; i < 2; i++ { // twice: the input must not be duplicated
		if err := connect([]string{"vscode", "--global", "--url", "https://tg.example.com"}, &out); err != nil {
			t.Fatal(err)
		}
	}
	dir, _ := os.UserConfigDir()
	b, err := os.ReadFile(filepath.Join(dir, "Code", "User", "mcp.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "tok_do_not_write") || strings.Contains(out.String(), "tok_do_not_write") {
		t.Fatal("the token must not be written or printed")
	}
	if strings.Count(string(b), "terraguard-token\"") != 1 || !strings.Contains(string(b), `"type": "http"`) || !strings.Contains(string(b), "${input:terraguard-token}") {
		t.Fatalf("vscode config:\n%s", b)
	}
}

func TestConnectRefusesPlainHTTPBeyondLoopback(t *testing.T) {
	var out strings.Builder
	if err := connect([]string{"print", "--url", "http://tg.example.com"}, &out); err == nil {
		t.Fatal("plain http to a remote host was accepted")
	}
	if err := connect([]string{"print", "--url", "http://127.0.0.1:8080"}, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "Authorization") {
		t.Fatal("loopback without a token needs no header")
	}
	if err := connect([]string{"claude-ai", "--url", "http://127.0.0.1:8080"}, &out); err == nil {
		t.Fatal("claude.ai cannot reach loopback")
	}
}

func TestConnectClaudeCodeRunsClaude(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fake")
	}
	bin := t.TempDir()
	argsFile := filepath.Join(bin, "args")
	os.WriteFile(filepath.Join(bin, "claude"), []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > "+argsFile+"\n"), 0o755)
	t.Setenv("PATH", bin)
	t.Setenv("TERRAGUARD_SERVER_TOKEN", "tok_secret_456")
	var out strings.Builder
	if err := connect([]string{"claude-code", "--url", "https://tg.example.com"}, &out); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(argsFile)
	want := "mcp\nadd\n--transport\nhttp\n--scope\nuser\nterraguard\nhttps://tg.example.com/mcp\n--header\nAuthorization: Bearer tok_secret_456\n"
	if string(b) != want {
		t.Fatalf("claude got:\n%s", b)
	}
	if strings.Contains(out.String(), "tok_secret_456") {
		t.Fatalf("token printed: %s", out.String())
	}
	out.Reset()
	if err := connect([]string{"claude-code", "--scope", "project"}, &out); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(argsFile)
	if !strings.HasPrefix(string(b), "mcp\nadd\n--scope\nproject\nterraguard\n--\n") || !strings.HasSuffix(string(b), "\nmcp\n") {
		t.Fatalf("stdio args:\n%s", b)
	}
	// Without claude on PATH: print the command, token masked unless asked.
	t.Setenv("PATH", t.TempDir())
	out.Reset()
	connect([]string{"claude-code", "--url", "https://tg.example.com"}, &out)
	if !strings.Contains(out.String(), `"Authorization: Bearer $TERRAGUARD_SERVER_TOKEN"`) || strings.Contains(out.String(), "tok_secret") {
		t.Fatalf("printed command: %s", out.String())
	}
	out.Reset()
	connect([]string{"claude-code", "--url", "https://tg.example.com", "--show-secret"}, &out)
	if !strings.Contains(out.String(), "tok_secret_456") {
		t.Fatalf("--show-secret: %s", out.String())
	}
}

func TestConnectClaudeAIShowsLinkOnlyOnRequest(t *testing.T) {
	t.Setenv("TERRAGUARD_MCP_KEY", "")
	dir := t.TempDir()
	key, err := writeMCPKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := connect([]string{"claude-ai", "--url", "https://tg.example.com", "--cert-dir", dir}, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), key) || !strings.Contains(out.String(), "Add custom connector") {
		t.Fatalf("without --show-secret: %s", out.String())
	}
	out.Reset()
	connect([]string{"claude-ai", "--url", "https://tg.example.com", "--cert-dir", dir, "--show-secret"}, &out)
	if !strings.Contains(out.String(), "https://tg.example.com/mcp/"+key) {
		t.Fatalf("with --show-secret: %s", out.String())
	}
	if err := connect([]string{"claude-ai", "--url", "https://tg.example.com:8443"}, &out); err == nil {
		t.Fatal("claude.ai needs port 443")
	}
}
