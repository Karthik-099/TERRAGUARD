package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func frame(v any) string {
	b, _ := json.Marshal(v)
	return fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(b), b)
}

func TestLanguageServer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "main.tf")
	src := "resource \"aws_instance\" \"web\" {\n  ami           = \"ami-123\"\n  instance_type = \"t3.micro\"\n}\n"
	os.WriteFile(path, []byte(src), 0o644)
	uri := pathURI(path)
	in := frame(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"rootUri": pathURI(dir)}}) +
		frame(map[string]any{"jsonrpc": "2.0", "method": "textDocument/didOpen", "params": map[string]any{"textDocument": map[string]any{"uri": uri, "text": src}}}) +
		frame(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "textDocument/codeAction", "params": map[string]any{"textDocument": map[string]any{"uri": uri},
			"context": map[string]any{"diagnostics": []any{map[string]any{"code": "TG-AWS-EC2-001", "range": map[string]any{"start": map[string]any{"line": 0, "character": 0}, "end": map[string]any{"line": 0, "character": 1}}}}}}}) +
		frame(map[string]any{"jsonrpc": "2.0", "method": "exit"})
	var out bytes.Buffer
	s := &lspServer{out: bufio.NewWriter(&out), open: map[string]string{}}
	if err := s.serve(bufio.NewReader(strings.NewReader(in))); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(&out)
	var diags, action bool
	for {
		body, err := readFrame(r)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		text := string(body)
		diags = diags || strings.Contains(text, "publishDiagnostics") && strings.Contains(text, "TG-AWS-EC2-001")
		action = action || strings.Contains(text, `"quickfix"`) && strings.Contains(text, "http_tokens")
	}
	if !diags || !action {
		t.Errorf("diagnostics %v, quick fix %v:\n%.2000s", diags, action, out.String())
	}
}
