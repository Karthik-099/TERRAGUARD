// Tests for the browser zip reader in web/app.js, run with node --test (no DOM).
// The functions are read out of app.js itself, so the code under test is the code that ships.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { deflateRawSync, crc32 } from "node:zlib";

const src = readFileSync(new URL("../app.js", import.meta.url), "utf8");

// Source of a function declaration in app.js, up to its matching closing brace.
function fn(name) {
  const m = new RegExp(`^\\s*(async )?function ${name}\\(`, "m").exec(src);
  assert.ok(m, `app.js has no function ${name}`);
  let i = src.indexOf("{", src.indexOf(")", m.index)), depth = 0;
  for (let j = i; j < src.length; j++) {
    if (src[j] === "{") depth++;
    else if (src[j] === "}" && --depth === 0) return src.slice(m.index, j + 1);
  }
  throw new Error(`unbalanced function ${name}`);
}
// Source of a one-line const declaration in app.js.
function line(name) {
  const m = new RegExp(`^\\s*const ${name} = .*;$`, "m").exec(src);
  assert.ok(m, `app.js has no one-line const ${name}`);
  return m[0];
}

// ingest's collaborators are stubbed; setFiles records what would be opened.
function load() {
  const env = {
    S: { files: {}, active: null, config: "", aiFindings: [], codeOwners: "", filter: {} },
    $: () => ({}), fmtN: (n) => String(n), progress: () => {}, renderTabs: () => {}, scan: () => {}, toast: () => {},
    addFile: () => {}, openFile: () => {}, setTimeout: () => 0, clearTimeout: () => {},
    opened: null,
  };
  env.setFiles = (files) => { env.opened = files; };
  const body = [line("SCANNABLE"), line("SKIP_DIR"), line("OWNERS_FILE"), line("LIMIT"), line("unsafePath"),
    fn("inflateRaw"), fn("zipEntries"), fn("ingest"), "return { inflateRaw, zipEntries, ingest, LIMIT, unsafePath };"].join("\n");
  const names = Object.keys(env).filter((k) => k !== "opened");
  return { env, ...new Function(...names, body)(...names.map((k) => env[k])) };
}

// A zip writer: entries are { name, data, method (0 stored, 8 deflate), size (declared, default the real size) }.
function zip(entries) {
  const locals = [], centrals = [];
  let off = 0;
  for (const e of entries) {
    const raw = Buffer.from(e.data ?? "");
    const method = e.method ?? 8;
    const body = method === 8 ? deflateRawSync(raw) : raw;
    const name = Buffer.from(e.name);
    const size = e.size ?? raw.length, crc = crc32(raw);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(method, 8);
    lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(body.length, 18); lh.writeUInt32LE(size, 22); lh.writeUInt16LE(name.length, 26);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(method, 10);
    ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(body.length, 20); ch.writeUInt32LE(size, 24); ch.writeUInt16LE(name.length, 28);
    ch.writeUInt32LE(off, 42);
    locals.push(lh, name, body);
    centrals.push(ch, name);
    off += 30 + name.length + body.length;
  }
  const cd = Buffer.concat(centrals), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(off, 16);
  return new Blob([...locals, cd, end]);
}

const TF = 'resource "aws_s3_bucket" "b" {}\n';

test("reads a normal zip, stored and deflated entries", async () => {
  const { zipEntries, ingest, env } = load();
  const entries = await zipEntries(zip([{ name: "main.tf", data: TF }, { name: "mod/vars.tf", data: "variable \"x\" {}\n", method: 0 }, { name: "docs/", data: "" }]));
  assert.deepEqual(entries.map((e) => e.path), ["main.tf", "mod/vars.tf"]);
  assert.equal(await entries[0].read(), TF);
  await ingest(entries, true);
  assert.deepEqual(env.opened, { "main.tf": TF, "mod/vars.tf": "variable \"x\" {}\n" });
});

test("refuses .. and absolute paths", async () => {
  const { zipEntries, ingest, env, unsafePath } = load();
  for (const p of ["../evil.tf", "a/../../evil.tf", "/etc/evil.tf", "C:/evil.tf", "c:evil.tf"]) assert.ok(unsafePath(p), p);
  assert.ok(!unsafePath("a/..b/ok.tf"));
  const names = ["../evil.tf", "ok/../../evil2.tf", "/abs.tf", "C:/win.tf", "ok/main.tf", "ok/other.tf"];
  await ingest(await zipEntries(zip(names.map((name) => ({ name, data: TF })))), true);
  // The unsafe entries are gone before the shared top folder "ok" is dropped.
  assert.deepEqual(Object.keys(env.opened).sort(), ["main.tf", "other.tf"]);
});

test("skips a file over the per-file limit without reading it", async () => {
  const { zipEntries, ingest, env, LIMIT } = load();
  const entries = await zipEntries(zip([{ name: "big.tf", data: TF, size: LIMIT.file + 1 }, { name: "small.tf", data: TF }]));
  entries[0].read = () => assert.fail("an entry over the limit must not be read");
  await ingest(entries, true);
  assert.deepEqual(Object.keys(env.opened), ["small.tf"]);
});

test("stops at the file-count limit", async () => {
  const { zipEntries, ingest, env, LIMIT } = load();
  const n = LIMIT.files + 3;
  await ingest(await zipEntries(zip(Array.from({ length: n }, (_, i) => ({ name: `f${i}.tf`, data: "#\n", method: 0 })))), true);
  assert.equal(Object.keys(env.opened).length, LIMIT.files);
});

test("stops at the total-size limit, counted on declared sizes", async () => {
  const { zipEntries, ingest, env, LIMIT } = load();
  const each = LIMIT.file - 1, n = Math.ceil(LIMIT.total / each) + 2;
  await ingest(await zipEntries(zip(Array.from({ length: n }, (_, i) => ({ name: `f${i}.tf`, data: "#\n", size: each })))), true);
  assert.equal(Object.keys(env.opened).length, Math.floor(LIMIT.total / each));
});

test("an entry that inflates past its declared size is refused (zip bomb)", async () => {
  const { zipEntries, ingest, env } = load();
  const bomb = "#".repeat(4 << 20); // 4 MB of one byte deflates to a few KB
  const entries = await zipEntries(zip([{ name: "bomb.tf", data: bomb, size: 100 }, { name: "ok.tf", data: TF }]));
  await assert.rejects(entries[0].read(), /expands beyond its limit/);
  await ingest(entries, true);
  assert.deepEqual(Object.keys(env.opened), ["ok.tf"]);
});

test("a stored entry whose size does not match is refused", async () => {
  const { zipEntries } = load();
  const [e] = await zipEntries(zip([{ name: "a.tf", data: TF, method: 0, size: TF.length + 10 }]));
  await assert.rejects(e.read(), /size mismatch/);
});

test("refuses a zip over 200 MB and a file that is not a zip", async () => {
  const { zipEntries } = load();
  await assert.rejects(zipEntries({ size: 201 << 20, arrayBuffer: () => assert.fail("must not be read") }), /larger than 200 MB/);
  await assert.rejects(zipEntries(new Blob(["not a zip at all, just text that is long enough"])), /not a zip/);
});
