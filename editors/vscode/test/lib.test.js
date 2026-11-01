const { test } = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const path = require("node:path");
const { toDiagnostics, parseScanOutput } = require("../lib");

test("maps a real CLI report to 0-based diagnostics", () => {
  const bin = path.resolve(__dirname, "../../../bin/terraguard");
  const cwd = path.resolve(__dirname, "../../../examples/insecure");
  let out;
  try { out = execFileSync(bin, ["scan", ".", "--format", "json", "--fail-on", "NONE"], { cwd }); } catch (e) { out = e.stdout; }
  const diags = toDiagnostics(parseScanOutput(out.toString(), 1), "HIGH");
  const bucket = diags["main.tf"].find((d) => d.code === "TG-VAL-005");
  assert.equal(bucket.line, 13); // main.tf:14 in the report
  assert.equal(bucket.severity, 0);
  assert.match(bucket.message, /apply is expected to fail/);
  assert.ok(Object.values(diags).flat().every((d) => d.severity <= 0), "HIGH filter keeps only errors");
});

test("exit code 2 is an error", () => {
  assert.throws(() => parseScanOutput("", 2));
});
