# Plugins

A plugin adds findings from your own script or tool to a TerraGuard scan.
Plugin findings go through the same waivers, baselines, severity overrides,
`disable` lists and gate as built-in rules, and appear in every output format.

The design follows kubectl and git plugins: a plugin is any executable named
`terraguard-<name>` on your `PATH`.

## Running plugins

Plugins never run unless you ask for them:

```bash
terraguard scan --plugins all              # every terraguard-* on PATH
terraguard scan --plugins license,naming   # only these
terraguard scan --plugin-timeout 2m        # default 60s per plugin
```

or in `.terraguard.yml`:

```yaml
plugins: [license, naming]
plugin_timeout: 90s
```

```bash
terraguard plugins list                 # plugins found on PATH
terraguard plugins test NAME [path]     # run one and print its validated findings as JSON
```

### Safety

- A plugin is looked up on `PATH` only. TerraGuard never runs a file from the
  scanned folder, even if `PATH` points into it, and ignores relative `PATH`
  entries such as `.`. A `plugins:` list in a scanned repository's policy can
  therefore only choose among plugins you installed yourself.
- Plugin names are lower-case letters, digits, `-` and `_`; `tg` and `org` are
  reserved.
- Each plugin has a timeout. A plugin that exits non-zero, times out or writes
  invalid output fails the scan with exit code 2 and its stderr in the error,
  so a broken plugin never passes silently.
- `terraguard serve`, the MCP server and the browser never run plugins.

## Protocol

TerraGuard starts the plugin with the scanned folder as its working directory
and writes one JSON request to its stdin:

```json
{
  "api": 1,
  "version": "3.0.0",
  "root": "/abs/path/to/scanned/folder",
  "files": ["main.tf", "k8s/deploy.yaml"],
  "policy": { "fail_on": "HIGH", "waivers": [], "...": "the parsed .terraguard.yml" }
}
```

`files` are the files TerraGuard scans, relative to `root`, with `/` separators.

The plugin writes findings to stdout, in either form (detected automatically):

1. TerraGuard findings: a JSON list, or `{"findings": [...]}`:

   ```json
   [{"rule_id": "LICENSE-001", "severity": "MEDIUM", "category": "policy",
     "title": "Module has no license header", "message": "main.tf has no SPDX header.",
     "file": "main.tf", "line": 1, "resource": "", "remediation": "Add an SPDX-License-Identifier line.",
     "docs": "https://wiki.example.com/license", "owner": "platform", "cwe": ""}]
   ```

2. SARIF 2.1.0 (`{"version": "2.1.0", "runs": [...]}`): each result's `ruleId`,
   `level` (`error` HIGH, `warning` MEDIUM, `note` LOW, `none` INFO),
   `message.text` and first physical location are used.

Print `[]` (or nothing) when there is nothing to report.

## Validation

- `rule_id` is required. IDs are prefixed with the upper-case plugin name and a
  dash when they do not already start with it, so `R1` from plugin `license`
  becomes `LICENSE-R1`. A plugin cannot report as a built-in (`TG-`) or custom
  (`ORG-`) rule.
- Severity must be CRITICAL, HIGH, MEDIUM, LOW or INFO (any case); anything
  else becomes MEDIUM.
- Category must be one of security, validate, reliability, best-practice,
  policy or cost; anything else becomes policy.
- `file` may be relative to `root` or absolute, but must be inside `root`;
  otherwise the plugin fails.
- Only descriptive fields are kept: a plugin cannot mark findings waived,
  blocking or auto-fixable.
- Limits: 8 MB of stdout, 10,000 findings, 4 KB per text field.

## Example

[`examples/plugins/terraguard-example`](../examples/plugins/terraguard-example)
is a POSIX shell plugin that reports one finding when the scanned folder has no
README.md:

```bash
cp examples/plugins/terraguard-example ~/.local/bin/
terraguard plugins test example examples/secure
terraguard scan --plugins example examples/secure
```

Waive or disable plugin findings like any other rule:

```yaml
disable: [EXAMPLE-001]
waivers:
  - rule: LICENSE-*
    reason: vendored code
    expires: 2027-01-31
    approved_by: platform
```
