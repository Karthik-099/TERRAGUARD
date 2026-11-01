const vscode = require("vscode");
const path = require("path");
const { execFile } = require("child_process");
const { toDiagnostics, parseScanOutput } = require("./lib");

let diagnostics;
const timers = new Map();

function cfg() {
  const c = vscode.workspace.getConfiguration("terraguard");
  return { bin: c.get("path"), onSave: c.get("scanOnSave"), min: c.get("minSeverity") };
}

function run(args, cwd) {
  return new Promise((resolve) =>
    execFile(cfg().bin, args, { cwd, maxBuffer: 64 << 20 }, (err, stdout, stderr) =>
      resolve({ code: err ? (typeof err.code === "number" ? err.code : 2) : 0, stdout, stderr, missing: err?.code === "ENOENT" })));
}

async function scanFolder(folder) {
  const res = await run(["scan", ".", "--format", "json", "--fail-on", "NONE"], folder.uri.fsPath);
  if (res.missing) {
    vscode.window.showWarningMessage("TerraGuard CLI not found. Install it with: go install github.com/Karthik-099/TERRAGUARD/cmd/terraguard@latest");
    return;
  }
  let report;
  try {
    report = parseScanOutput(res.stdout, res.code);
  } catch {
    vscode.window.showErrorMessage(`TerraGuard: ${res.stderr.trim() || "scan failed"}`);
    return;
  }
  // Clear this folder's old results, then publish the new ones.
  diagnostics.forEach((uri) => { if (uri.fsPath.startsWith(folder.uri.fsPath)) diagnostics.delete(uri); });
  for (const [file, items] of Object.entries(toDiagnostics(report, cfg().min))) {
    const uri = vscode.Uri.file(path.join(folder.uri.fsPath, file));
    diagnostics.set(uri, items.map((d) => {
      const range = new vscode.Range(d.line, 0, d.line, Number.MAX_SAFE_INTEGER);
      const diag = new vscode.Diagnostic(range, d.message, d.severity);
      diag.source = "TerraGuard";
      diag.code = d.code;
      diag.fixable = d.fixable;
      return diag;
    }));
  }
}

async function scanAll() {
  for (const f of vscode.workspace.workspaceFolders || []) await scanFolder(f);
}

class Actions {
  provideCodeActions(doc, _range, ctx) {
    const out = [];
    for (const d of ctx.diagnostics.filter((x) => x.source === "TerraGuard")) {
      if (d.fixable) {
        const fix = new vscode.CodeAction(`Apply TerraGuard auto-fixes to ${path.basename(doc.fileName)}`, vscode.CodeActionKind.QuickFix);
        fix.command = { command: "terraguard.fixFile", title: "fix", arguments: [doc.uri] };
        fix.diagnostics = [d];
        fix.isPreferred = true;
        out.push(fix);
      }
      const ignore = new vscode.CodeAction(`Ignore ${d.code} on this line`, vscode.CodeActionKind.QuickFix);
      const line = doc.lineAt(d.range.start.line);
      ignore.edit = new vscode.WorkspaceEdit();
      ignore.edit.insert(doc.uri, line.range.start, `${line.text.match(/^\s*/)[0]}# terraguard:ignore ${d.code} -- reason: \n`);
      ignore.diagnostics = [d];
      out.push(ignore);
    }
    return out;
  }
}

function activate(context) {
  diagnostics = vscode.languages.createDiagnosticCollection("terraguard");
  context.subscriptions.push(
    diagnostics,
    vscode.commands.registerCommand("terraguard.scan", scanAll),
    vscode.commands.registerCommand("terraguard.fixFile", async (uri) => {
      uri ||= vscode.window.activeTextEditor?.document.uri;
      const folder = uri && vscode.workspace.getWorkspaceFolder(uri);
      if (!folder) return;
      await vscode.workspace.saveAll(false);
      const res = await run(["fix", uri.fsPath], folder.uri.fsPath);
      vscode.window.setStatusBarMessage(`TerraGuard: ${res.stdout.trim() || "done"}`, 4000);
      await scanFolder(folder);
    }),
    vscode.languages.registerCodeActionsProvider([{ pattern: "**/*.tf" }, { pattern: "**/*.tfvars" }], new Actions(), { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }),
    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (!cfg().onSave || !/\.(tf|tfvars)$/.test(doc.fileName)) return;
      const folder = vscode.workspace.getWorkspaceFolder(doc.uri);
      if (!folder) return;
      clearTimeout(timers.get(folder.uri.fsPath));
      timers.set(folder.uri.fsPath, setTimeout(() => scanFolder(folder), 400));
    }),
  );
  scanAll();
}

module.exports = { activate, deactivate() {} };
