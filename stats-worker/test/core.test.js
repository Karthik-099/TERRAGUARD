import { test } from "node:test";
import assert from "node:assert/strict";
import { newState, record, snapshot } from "../src/core.js";

test("aggregates, clamps and never stores code", () => {
  const s = newState();
  const now = new Date("2026-10-25T12:00:00Z");
  record(s, { surface: "web", scans: 2, files: 3, resources: 9, findings: 4, rules: { "TG-AWS-S3-001": 2, "<script>": 5 }, code: "resource {}" }, now);
  record(s, { surface: "evil", scans: 1e9, fixes: -3 }, now);
  const sessions = new Map([["a", now.getTime()], ["old", now.getTime() - 300000]]);
  const snap = snapshot(s, sessions, now);
  assert.equal(snap.today.scans, 502);
  assert.equal(snap.today.files, 3);
  assert.equal(snap.total.resources, 9);
  assert.equal(snap.today.fixes, 0);
  assert.equal(snap.by_surface.other, 500);
  assert.equal(snap.active_now, 1);
  assert.deepEqual(snap.top_rules, [{ id: "TG-AWS-S3-001", count: 2 }]);
  assert.equal(snap.days.length, 7);
  assert.ok(!JSON.stringify(s).includes("resource {}"));
});

test("prunes history older than 60 days", () => {
  const s = newState();
  record(s, { scans: 1 }, new Date("2026-01-01T00:00:00Z"));
  record(s, { scans: 1 }, new Date("2026-10-25T00:00:00Z"));
  assert.deepEqual(Object.keys(s.days), ["2026-10-25"]);
  assert.equal(s.total.scans, 2);
});
