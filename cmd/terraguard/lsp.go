package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/Karthik-099/TERRAGUARD/engine"
)

// runLSP serves the Language Server Protocol over stdio, so any editor with an
// LSP client (Neovim, JetBrains, Zed, Helix, Emacs, Sublime) shows TerraGuard
// findings as diagnostics and offers the safe Terraform fixes as code actions.
// Each change rescans the folder of the file, with unsaved edits included.
func runLSP() error {
	s := &lspServer{out: bufio.NewWriter(os.Stdout), open: map[string]string{}}
	return s.serve(bufio.NewReader(os.Stdin))
}

type lspServer struct {
	mu   sync.Mutex
	out  *bufio.Writer
	open map[string]string // path -> text of open documents
	root string
	last map[string]*engine.Report // dir -> last report, for code actions
}

type rpcMsg struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   any             `json:"error,omitempty"`
}

func (s *lspServer) serve(r *bufio.Reader) error {
	for {
		body, err := readFrame(r)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		var m rpcMsg
		if json.Unmarshal(body, &m) != nil {
			continue
		}
		if m.Method == "exit" {
			return nil
		}
		s.handle(m)
	}
}

// readFrame reads one Content-Length framed message; frames over 32 MB are refused.
func readFrame(r *bufio.Reader) ([]byte, error) {
	n := -1
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		if v, ok := strings.CutPrefix(line, "Content-Length:"); ok {
			n, _ = strconv.Atoi(strings.TrimSpace(v))
		}
	}
	if n < 0 || n > 32<<20 {
		return nil, fmt.Errorf("lsp: bad Content-Length %d", n)
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

func (s *lspServer) send(m rpcMsg) {
	m.JSONRPC = "2.0"
	b, _ := json.Marshal(m)
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Fprintf(s.out, "Content-Length: %d\r\n\r\n%s", len(b), b)
	s.out.Flush()
}

func (s *lspServer) reply(id json.RawMessage, result any) { s.send(rpcMsg{ID: id, Result: result}) }

func (s *lspServer) handle(m rpcMsg) {
	var p struct {
		RootURI      string `json:"rootUri"`
		TextDocument struct {
			URI  string `json:"uri"`
			Text string `json:"text"`
		} `json:"textDocument"`
		ContentChanges []struct {
			Text string `json:"text"`
		} `json:"contentChanges"`
		Range   json.RawMessage `json:"range"`
		Context struct {
			Diagnostics []lspDiag `json:"diagnostics"`
		} `json:"context"`
	}
	json.Unmarshal(m.Params, &p)
	switch m.Method {
	case "initialize":
		s.root = uriPath(p.RootURI)
		s.reply(m.ID, map[string]any{
			"capabilities": map[string]any{"textDocumentSync": map[string]any{"openClose": true, "change": 1, "save": true}, "codeActionProvider": true},
			"serverInfo":   map[string]any{"name": "terraguard", "version": engine.Version},
		})
	case "shutdown":
		s.reply(m.ID, nil)
	case "textDocument/didOpen":
		s.setOpen(uriPath(p.TextDocument.URI), p.TextDocument.Text)
	case "textDocument/didChange":
		if n := len(p.ContentChanges); n > 0 {
			s.setOpen(uriPath(p.TextDocument.URI), p.ContentChanges[n-1].Text)
		}
	case "textDocument/didSave":
		s.rescan(filepath.Dir(uriPath(p.TextDocument.URI)))
	case "textDocument/didClose":
		path := uriPath(p.TextDocument.URI)
		s.mu.Lock()
		delete(s.open, path)
		s.mu.Unlock()
	case "textDocument/codeAction":
		s.reply(m.ID, s.codeActions(uriPath(p.TextDocument.URI), p.Context.Diagnostics))
	default:
		if len(m.ID) > 0 { // unknown request: answer so the client does not wait
			s.send(rpcMsg{ID: m.ID, Error: map[string]any{"code": -32601, "message": "method not found"}})
		}
	}
}

func (s *lspServer) setOpen(path, text string) {
	s.mu.Lock()
	s.open[path] = text
	s.mu.Unlock()
	s.rescan(filepath.Dir(path))
}

// rescan checks one folder (files on disk, overlaid with open documents) and
// publishes diagnostics for every file in it, including empty lists to clear.
func (s *lspServer) rescan(dir string) {
	files := map[string]string{}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if e.IsDir() || !engine.IsScannable(p) {
			continue
		}
		if b, err := os.ReadFile(p); err == nil && len(b) < 4<<20 {
			files[p] = string(b)
		}
	}
	s.mu.Lock()
	for p, t := range s.open {
		if filepath.Dir(p) == dir {
			files[p] = t
		}
	}
	s.mu.Unlock()
	policy, _ := findConfig("", []string{dir, s.root})
	rep := engine.Scan(engine.Input{Files: files, Config: policy})
	s.mu.Lock()
	if s.last == nil {
		s.last = map[string]*engine.Report{}
	}
	s.last[dir] = rep
	s.mu.Unlock()
	byFile := map[string][]lspDiag{}
	for p := range files {
		byFile[p] = []lspDiag{}
	}
	for _, f := range rep.Findings {
		if f.Waived || f.File == "" || byFile[f.File] == nil {
			continue
		}
		line := max(f.Line-1, 0)
		sev := 3
		switch f.Severity {
		case engine.Critical, engine.High:
			sev = 1
		case engine.Medium:
			sev = 2
		case engine.Info:
			sev = 4
		}
		if f.Blocking {
			sev = 1
		}
		byFile[f.File] = append(byFile[f.File], lspDiag{
			Range:    lspRange{Start: lspPos{line, 0}, End: lspPos{line, 200}},
			Severity: sev, Code: f.RuleID, Source: "terraguard",
			Message: f.Title + ": " + f.Message + "\nFix: " + f.Remediation,
		})
	}
	for p, d := range byFile {
		s.send(rpcMsg{Method: "textDocument/publishDiagnostics", Params: mustJSON(map[string]any{"uri": pathURI(p), "diagnostics": d})})
	}
}

// codeActions offers the engine's safe fix for each TerraGuard diagnostic that has one.
func (s *lspServer) codeActions(path string, diags []lspDiag) []any {
	s.mu.Lock()
	rep := s.last[filepath.Dir(path)]
	text, isOpen := s.open[path]
	s.mu.Unlock()
	if rep == nil {
		return []any{}
	}
	if !isOpen {
		b, _ := os.ReadFile(path)
		text = string(b)
	}
	want := map[string]bool{}
	for _, d := range diags {
		want[fmt.Sprintf("%v:%d", d.Code, d.Range.Start.Line+1)] = true
	}
	var out []any
	for _, f := range rep.Findings {
		if f.Fix == nil || f.File != path || !want[fmt.Sprintf("%s:%d", f.RuleID, f.Line)] {
			continue
		}
		fixed, errs := engine.ApplyFixes(map[string]string{path: text}, []*engine.Fix{f.Fix})
		if len(errs) > 0 || fixed[path] == "" || fixed[path] == text {
			continue
		}
		end := strings.Count(text, "\n") + 1
		out = append(out, map[string]any{
			"title": "TerraGuard: " + f.Fix.Description, "kind": "quickfix",
			"edit": map[string]any{"changes": map[string]any{pathURI(path): []any{map[string]any{
				"range": lspRange{Start: lspPos{0, 0}, End: lspPos{end, 0}}, "newText": fixed[path]}}}},
		})
	}
	if out == nil {
		return []any{}
	}
	return out
}

type lspPos struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}

type lspRange struct {
	Start lspPos `json:"start"`
	End   lspPos `json:"end"`
}

type lspDiag struct {
	Range    lspRange `json:"range"`
	Severity int      `json:"severity"`
	Code     any      `json:"code"`
	Source   string   `json:"source"`
	Message  string   `json:"message"`
}

func uriPath(u string) string {
	if p, err := url.Parse(u); err == nil && p.Scheme == "file" {
		path := p.Path
		if len(path) > 2 && path[0] == '/' && path[2] == ':' { // file:///C:/x on Windows
			path = path[1:]
		}
		return filepath.FromSlash(path)
	}
	return u
}

func pathURI(p string) string {
	p = filepath.ToSlash(p)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return (&url.URL{Scheme: "file", Path: p}).String()
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
