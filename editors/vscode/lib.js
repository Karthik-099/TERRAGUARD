// Report-to-diagnostics mapping, kept free of the vscode import so it's testable.
const RANK = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
// VS Code DiagnosticSeverity: 0 Error, 1 Warning, 2 Information, 3 Hint
const LEVEL = { CRITICAL: 0, HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3 };

function toDiagnostics(report, minSeverity = "LOW") {
  const byFile = {};
  for (const f of report.findings || []) {
    if (f.waived || !f.file || f.file === "plan.json" || (RANK[f.severity] || 0) < (RANK[minSeverity] || 0)) continue;
    (byFile[f.file] ||= []).push({
      line: Math.max((f.line || 1) - 1, 0), // editors are 0-based
      severity: LEVEL[f.severity] ?? 2,
      code: f.rule_id,
      message: `${f.title}: ${f.message}${f.remediation ? `\nFix: ${f.remediation}` : ""}${f.blocking ? "\n(terraform apply is expected to fail)" : ""}`,
      fixable: !!f.fix,
    });
  }
  return byFile;
}

// The CLI prints the report even when the policy fails (exit 1); only 2 is an error.
function parseScanOutput(stdout, exitCode) {
  if (exitCode >= 2 || !stdout.trim()) throw new Error("terraguard scan failed");
  return JSON.parse(stdout);
}

module.exports = { toDiagnostics, parseScanOutput };
