package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const connectUsage = `usage: terraguard connect <claude-code|cursor|vscode|claude-ai|print> [--url https://host] [--scope user|project|local] [--global] [--dir DIR] [--show-secret]`

func runConnect(args []string) error { return connect(args, os.Stdout) }

// connect adds TerraGuard to an MCP client: the local stdio server by default,
// or the remote server at --url.
func connect(args []string, out io.Writer) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errors.New(connectUsage)
	}
	client := args[0]
	fset := flag.NewFlagSet("connect", flag.ContinueOnError)
	rawURL := fset.String("url", "", "remote terraguard serve address (https; http only for loopback); default: the local stdio server")
	scope := fset.String("scope", "user", "Claude Code scope: user, project or local")
	global := fset.Bool("global", false, "Cursor and VS Code: write the user-wide config instead of the project's")
	dir := fset.String("dir", ".", "Cursor and VS Code: project directory")
	certDir := fset.String("cert-dir", defaultCertDir(), "claude-ai: where terraguard serve --domain stored the MCP key")
	show := fset.Bool("show-secret", false, "print the token or secret link instead of masking it")
	if err := fset.Parse(args[1:]); err != nil {
		return err
	}
	base, err := remoteBase(*rawURL)
	if err != nil {
		return err
	}
	token := os.Getenv("TERRAGUARD_SERVER_TOKEN")
	needsAuth := base != "" && (token != "" || !loopbackURL(base))
	switch client {
	case "claude-code":
		return connectClaudeCode(out, base, token, needsAuth, *scope, *show)
	case "cursor":
		p := filepath.Join(*dir, ".cursor", "mcp.json")
		if *global {
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			p = filepath.Join(home, ".cursor", "mcp.json")
		}
		return mergeMCPConfig(out, p, "mcpServers", cursorEntry(base, needsAuth), nil)
	case "vscode":
		p := filepath.Join(*dir, ".vscode", "mcp.json")
		if *global {
			cfg, err := os.UserConfigDir()
			if err != nil {
				return err
			}
			p = filepath.Join(cfg, "Code", "User", "mcp.json")
		}
		var input map[string]any
		if needsAuth {
			input = vscodeTokenInput
		}
		return mergeMCPConfig(out, p, "servers", vscodeEntry(base, needsAuth), input)
	case "claude-ai":
		return connectClaudeAI(out, base, *certDir, *show)
	case "print":
		fmt.Fprintf(out, "Claude Code:\n  %s\n\n", shellJoin(claudeArgs(base, token, needsAuth, *scope, *show)))
		for _, c := range []struct {
			name, key string
			entry     any
		}{{"Cursor (.cursor/mcp.json)", "mcpServers", cursorEntry(base, needsAuth)}, {"VS Code (.vscode/mcp.json)", "servers", vscodeEntry(base, needsAuth)}} {
			doc := map[string]any{c.key: map[string]any{"terraguard": c.entry}}
			if c.key == "servers" && needsAuth {
				doc["inputs"] = []any{vscodeTokenInput}
			}
			b, _ := json.MarshalIndent(doc, "", "  ")
			fmt.Fprintf(out, "%s:\n%s\n\n", c.name, b)
		}
		return nil
	}
	return fmt.Errorf("unknown client %q\n%s", client, connectUsage)
}

// remoteBase checks --url and returns it without a trailing /mcp ("" for stdio).
func remoteBase(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", fmt.Errorf("--url must look like https://host: %q", raw)
	}
	if u.Scheme != "https" && !loopbackHost(u.Host) {
		return "", errors.New("--url must use https unless the host is loopback; serve with --domain or --tls-cert")
	}
	u.Path = strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), "/mcp")
	u.RawQuery, u.Fragment = "", ""
	return strings.TrimSuffix(u.String(), "/"), nil
}

func loopbackURL(base string) bool {
	u, err := url.Parse(base)
	return err == nil && loopbackHost(u.Host)
}

// localCommand prefers the name on PATH, so a project config stays portable.
func localCommand() string {
	if _, err := exec.LookPath("terraguard"); err == nil {
		return "terraguard"
	}
	if exe, err := os.Executable(); err == nil {
		return exe
	}
	return "terraguard"
}

func claudeArgs(base, token string, needsAuth bool, scope string, show bool) []string {
	if base == "" {
		return []string{"claude", "mcp", "add", "--scope", scope, "terraguard", "--", localCommand(), "mcp"}
	}
	args := []string{"claude", "mcp", "add", "--transport", "http", "--scope", scope, "terraguard", base + "/mcp"}
	if needsAuth {
		secret := "$TERRAGUARD_SERVER_TOKEN" // the shell fills it in when the command is pasted
		if show && token != "" {
			secret = token
		}
		args = append(args, "--header", "Authorization: Bearer "+secret)
	}
	return args
}

func connectClaudeCode(out io.Writer, base, token string, needsAuth bool, scope string, show bool) error {
	switch scope {
	case "user", "project", "local":
	default:
		return fmt.Errorf("--scope must be user, project or local, not %q", scope)
	}
	shown := claudeArgs(base, token, needsAuth, scope, show)
	claude, err := exec.LookPath("claude")
	if err != nil {
		fmt.Fprintf(out, "claude is not on PATH. Run this to add TerraGuard to Claude Code:\n\n  %s\n", shellJoin(shown))
		return nil
	}
	if needsAuth && token == "" {
		return errors.New("set TERRAGUARD_SERVER_TOKEN to the server's token first (or use `terraguard connect claude-ai` for the secret link)")
	}
	real := claudeArgs(base, token, needsAuth, scope, true)
	fmt.Fprintf(out, "Running: %s\n", shellJoin(shown))
	cmd := exec.Command(claude, real[1:]...)
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("claude mcp add failed (if terraguard is already added, run `claude mcp remove terraguard` first): %w", err)
	}
	return nil
}

func cursorEntry(base string, needsAuth bool) map[string]any {
	if base == "" {
		return map[string]any{"command": localCommand(), "args": []string{"mcp"}}
	}
	e := map[string]any{"url": base + "/mcp"}
	if needsAuth {
		e["headers"] = map[string]string{"Authorization": "Bearer ${env:TERRAGUARD_SERVER_TOKEN}"}
	}
	return e
}

// vscodeTokenInput makes VS Code prompt for the token and keep it out of the file.
var vscodeTokenInput = map[string]any{"type": "promptString", "id": "terraguard-token", "description": "TerraGuard server token", "password": true}

func vscodeEntry(base string, needsAuth bool) map[string]any {
	if base == "" {
		return map[string]any{"type": "stdio", "command": localCommand(), "args": []string{"mcp"}}
	}
	e := map[string]any{"type": "http", "url": base + "/mcp"}
	if needsAuth {
		e["headers"] = map[string]string{"Authorization": "Bearer ${input:terraguard-token}"}
	}
	return e
}

func connectClaudeAI(out io.Writer, base, certDir string, show bool) error {
	if base == "" || loopbackURL(base) || !strings.HasPrefix(base, "https://") {
		return errors.New("claude.ai connects from Anthropic's cloud: pass --url https://<public host> of a server started with terraguard serve --domain <host>")
	}
	if u, _ := url.Parse(base); u.Port() != "" && u.Port() != "443" {
		return errors.New("claude.ai only reaches servers on the standard HTTPS port 443")
	}
	key := os.Getenv("TERRAGUARD_MCP_KEY")
	if key == "" {
		if b, err := os.ReadFile(mcpKeyPath(certDir)); err == nil {
			key = strings.TrimSpace(string(b))
		}
	}
	link := "(hidden: run again with --show-secret to print it; anyone with the link can use the server)"
	switch {
	case key == "":
		link = fmt.Sprintf("(no key found: run this on the server, where terraguard serve --domain stores it in %s, or set TERRAGUARD_MCP_KEY)", mcpKeyPath(certDir))
	case show:
		link = base + "/mcp/" + key
	}
	fmt.Fprintf(out, `claude.ai custom connectors are added in the claude.ai settings; this command cannot add one for you.
The server must be reachable from the public internet on port 443 (terraguard serve --domain <host>).

  1. Pro and Max: open Customize > Connectors.
     Team and Enterprise: an Owner opens Organization settings > Connectors.
  2. Click "+ Add", then "Add custom connector" (Team and Enterprise: Add > Custom > Web).
  3. Name: TerraGuard
     URL:  %s
  4. Authentication: No sign in (the secret link carries the key). Finish with Add.

Instead of the link you can enter %s/mcp and add the request header
"Authorization: Bearer <TERRAGUARD_SERVER_TOKEN>" in the same dialog.
To replace a leaked link: terraguard serve --rotate-mcp-key, then restart the server.
`, link, base)
	return nil
}

// mergeMCPConfig sets <key>.terraguard in a JSON config, keeping the other
// entries, their order and the file's indentation. The old file goes to .bak.
func mergeMCPConfig(out io.Writer, path, key string, entry, input map[string]any) error {
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	exists := err == nil
	snippet, _ := json.MarshalIndent(map[string]any{key: map[string]any{"terraguard": entry}}, "", "  ")
	top := []member{}
	if exists && len(bytes.TrimSpace(old)) > 0 {
		if top, err = members(old); err != nil {
			return fmt.Errorf("%s is not plain JSON (comments or trailing commas?); add this by hand:\n%s", path, snippet)
		}
	}
	servers := []member{}
	if raw, ok := getMember(top, key); ok {
		if servers, err = members(raw); err != nil {
			return fmt.Errorf("%s: %q is not an object; add this by hand:\n%s", path, key, snippet)
		}
	}
	e, _ := json.Marshal(entry)
	servers = setMember(servers, "terraguard", e)
	top = setMember(top, key, encodeMembers(servers))
	if input != nil {
		var inputs []map[string]any
		if raw, ok := getMember(top, "inputs"); ok {
			if err := json.Unmarshal(raw, &inputs); err != nil {
				return fmt.Errorf("%s: inputs is not a list; add this by hand:\n%s", path, snippet)
			}
		}
		found := false
		for _, in := range inputs {
			found = found || in["id"] == input["id"]
		}
		if !found {
			inputs = append(inputs, input)
		}
		b, _ := json.Marshal(inputs)
		top = setMember(top, "inputs", b)
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, encodeMembers(top), "", detectIndent(old)); err != nil {
		return err
	}
	buf.WriteByte('\n')
	mode := os.FileMode(0o644)
	if exists {
		if st, err := os.Stat(path); err == nil {
			mode = st.Mode().Perm()
		}
		if err := os.WriteFile(path+".bak", old, mode); err != nil {
			return fmt.Errorf("backup: %w", err)
		}
	}
	if err := writeAtomic(path, buf.Bytes(), mode); err != nil {
		return err
	}
	fmt.Fprintf(out, "Added terraguard to %s", path)
	if exists {
		fmt.Fprintf(out, " (previous file saved as %s.bak)", path)
	}
	fmt.Fprintln(out, ". Restart or reload the editor to pick it up.")
	return nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name()) // no-op after the rename
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func detectIndent(b []byte) string {
	for _, line := range strings.Split(string(b), "\n")[1:] {
		if t := strings.TrimLeft(line, " \t"); t != "" && len(t) < len(line) {
			return line[:len(line)-len(t)]
		}
	}
	return "  "
}

// member is one key of a JSON object; a slice keeps the file's key order.
type member struct {
	k string
	v json.RawMessage
}

func members(raw []byte) ([]member, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	var ms []member
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		ms = append(ms, member{t.(string), v})
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after the JSON object")
	}
	return ms, nil
}

func getMember(ms []member, k string) (json.RawMessage, bool) {
	for _, m := range ms {
		if m.k == k {
			return m.v, true
		}
	}
	return nil, false
}

func setMember(ms []member, k string, v json.RawMessage) []member {
	for i := range ms {
		if ms[i].k == k {
			ms[i].v = v
			return ms
		}
	}
	return append(ms, member{k, v})
}

func encodeMembers(ms []member) []byte {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, m := range ms {
		if i > 0 {
			b.WriteByte(',')
		}
		k, _ := json.Marshal(m.k)
		b.Write(k)
		b.WriteByte(':')
		b.Write(m.v)
	}
	b.WriteByte('}')
	return b.Bytes()
}

// shellJoin quotes arguments for copy and paste; $TERRAGUARD_SERVER_TOKEN stays expandable.
func shellJoin(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		switch {
		case a != "" && strings.Trim(a, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./:=@") == "":
			out[i] = a
		case strings.Contains(a, "$TERRAGUARD_SERVER_TOKEN") && !strings.ContainsAny(a, "\"\\`"):
			out[i] = `"` + a + `"`
		default:
			out[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
	}
	return strings.Join(out, " ")
}
