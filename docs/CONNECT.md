# Connect TerraGuard to an AI client

TerraGuard's MCP tools (scan, fix, review a diff, check a plan, explain a rule,
SBOM, cost, custom rules) work in Claude Code, claude.ai, Cursor and VS Code.

There are two ways to run them:

- **Local** (`terraguard mcp`, over stdio). Needs no network and can read your
  working folder. This is the default for every client except claude.ai.
- **Remote** (`terraguard serve`, at `https://host/mcp`). Shared by a team,
  takes inline files only and never touches the server's disk.

`terraguard connect print` shows every snippet below without changing anything.

## Claude Code

```bash
terraguard connect claude-code                  # local, --scope user
terraguard connect claude-code --scope project  # writes .mcp.json for the repo
```

If `claude` is on PATH this runs `claude mcp add`; otherwise it prints the
command. The local command is:

```bash
claude mcp add --scope user terraguard -- terraguard mcp
```

Remote, with the server token in `TERRAGUARD_SERVER_TOKEN`:

```bash
terraguard connect claude-code --url https://terraguard.example.com
# or by hand:
claude mcp add --transport http --scope user terraguard https://terraguard.example.com/mcp \
  --header "Authorization: Bearer $TERRAGUARD_SERVER_TOKEN"
```

## Cursor

```bash
terraguard connect cursor            # .cursor/mcp.json in this project
terraguard connect cursor --global   # ~/.cursor/mcp.json
terraguard connect cursor --url https://terraguard.example.com
```

The entry it adds (other entries are kept, the old file is saved as `.bak`):

```json
{
  "mcpServers": {
    "terraguard": { "command": "terraguard", "args": ["mcp"] }
  }
}
```

Remote: `{"url": "https://terraguard.example.com/mcp", "headers": {"Authorization": "Bearer ${env:TERRAGUARD_SERVER_TOKEN}"}}`.
Cursor reads the token from the environment, so it is never written to the file.

## VS Code

```bash
terraguard connect vscode            # .vscode/mcp.json in this project
terraguard connect vscode --global   # your user mcp.json
terraguard connect vscode --url https://terraguard.example.com
```

```json
{
  "servers": {
    "terraguard": { "type": "stdio", "command": "terraguard", "args": ["mcp"] }
  }
}
```

Remote entries use `"type": "http"` and a `${input:terraguard-token}` header;
VS Code asks for the token once and stores it itself.

## claude.ai

claude.ai connects to MCP servers from Anthropic's cloud, so the server must be
reachable from the public internet on port 443. A custom connector is added in
the claude.ai settings by hand; TerraGuard cannot add it for you.

1. Start the server with automatic HTTPS on a host name that points at it
   (ports 80 and 443 open):

   ```bash
   terraguard serve --domain terraguard.example.com
   ```

   This gets a Let's Encrypt certificate, redirects HTTP to HTTPS and creates
   the secret link key in the certificate folder.

2. On the server, print the link (treat it like a password):

   ```bash
   terraguard connect claude-ai --url https://terraguard.example.com --show-secret
   ```

3. In claude.ai open **Customize > Connectors**, click **+ Add**, then
   **Add custom connector**. On Team and Enterprise plans an Owner does this in
   **Organization settings > Connectors** (**Add > Custom > Web**).
4. Name it TerraGuard, paste the link as the URL, choose **No sign in** and
   click **Add**.

Instead of the link you can use `https://terraguard.example.com/mcp` and add
the request header `Authorization: Bearer <token>` in the same dialog.

If the link leaks, replace it and restart the server:

```bash
terraguard serve --rotate-mcp-key
```

## Remote server checklist

- Set `TERRAGUARD_SERVER_TOKEN` (or use the secret link). Beyond loopback,
  MCP without either is refused.
- Use `--domain`, or `--tls-cert` and `--tls-key` with `--https-only`.
  `connect` refuses a plain `http://` URL unless it is loopback.
- `--scan-timeout` (30 s) and `--max-scans` (one per CPU) bound the work each
  request can cause; a busy server answers 503 with `Retry-After`.
