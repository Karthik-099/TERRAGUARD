// TerraGuard web app: Monaco editor + Go/WASM engine + optional AI.
(() => {
  const CFG = window.TERRAGUARD_CONFIG || {};
  const REPO = CFG.repo || "Karthik-099/TERRAGUARD";
  const REPO_URL = `https://github.com/${REPO}`;
  const SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const sevColor = (s) => `var(--${{ CRITICAL: "crit", HIGH: "high", MEDIUM: "med", LOW: "low", INFO: "info" }[s] || "info"})`;
  const SEV_HEX = { CRITICAL: "#ef4444", HIGH: "#f97316", MEDIUM: "#eab308", LOW: "#3b82f6", INFO: "#64748b" };
  const CLOUDS = {
    aws: "AWS", google: "Google Cloud", azurerm: "Azure", cloudflare: "Cloudflare", digitalocean: "DigitalOcean",
    hcloud: "Hetzner", linode: "Akamai / Linode", openstack: "OpenStack / OVH", ovh: "OVHcloud", oci: "Oracle Cloud",
    alicloud: "Alibaba Cloud", vultr: "Vultr", kubernetes: "Kubernetes", helm: "Helm",
  };
  const CATEGORY = { security: "Security", validate: "Apply-time validation", reliability: "Reliability", "best-practice": "Best practice", "attack-path": "Attack paths", plan: "Plan risk", policy: "Policy", cost: "Cost" };
  const EXAMPLES = {
    insecure: ["main.tf", "variables.tf", "terraform.tfvars", ".terraguard.yml"],
    multicloud: ["main.tf"],
    secure: ["main.tf"],
  };
  const POLICY_FILE = ".terraguard.yml";
  const STORE = "tg.state";

  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const md = (s) => DOMPurify.sanitize(marked.parse(s || ""));
  const fmtN = (n) => new Intl.NumberFormat().format(n || 0);
  const cloudOf = (addr) => (addr || "").replace(/^data\./, "").split("_")[0];

  const S = {
    files: {}, active: null, config: "", plan: "",
    report: null, aiFindings: [], chat: [],
    filter: { q: "", sev: new Set(), cloud: "" }, tab: "overview",
    session: { scans: 0, files: 0, resources: 0, fixes: 0, ai: 0 },
  };
  let editor, monacoRef, models = {}, graph, statsTimer;

  // ── theme ───────────────────────────────────────────────────────────────
  const isDark = () => (document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark")) === "dark";
  function applyTheme() {
    monacoRef?.editor.setTheme(isDark() ? "vs-dark" : "vs");
    if (S.tab === "graph") renderGraph();
  }

  // ── persistence ─────────────────────────────────────────────────────────
  function persist() {
    try { localStorage.setItem(STORE, JSON.stringify({ files: S.files, active: S.active, config: S.config, plan: S.plan, chat: S.chat.slice(-40) })); } catch {}
  }
  function restore() {
    try { return JSON.parse(localStorage.getItem(STORE)); } catch { return null; }
  }
  const b64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  async function encodeShare(obj) {
    const stream = new Blob([JSON.stringify(obj)]).stream().pipeThrough(new CompressionStream("deflate-raw"));
    return b64(await new Response(stream).arrayBuffer());
  }
  async function decodeShare(s) {
    const bin = Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
    const stream = new Blob([bin]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
    return JSON.parse(await new Response(stream).text());
  }

  function toast(msg) {
    const t = $("#toast");
    t.textContent = msg;
    t.classList.add("show");
    clearTimeout(t._h);
    t._h = setTimeout(() => t.classList.remove("show"), 2600);
  }

  // ── anonymous usage counters (numbers only, never code) ─────────────────
  const T = { pending: null, last: 0, session: crypto.randomUUID?.() || String(Math.random()).slice(2) };
  const resetPending = () => ({ scans: 0, files: 0, resources: 0, findings: 0, fixes: 0, ai: 0, ms: 0, rules: {} });
  T.pending = resetPending();
  function telemetryTarget() {
    const s = AI.load();
    if (s.telemetry === false || s.private || navigator.doNotTrack === "1" || navigator.globalPrivacyControl) return null;
    if (AI.server()) return "api/stats/hit";
    return CFG.statsUrl ? CFG.statsUrl.replace(/\/$/, "") + "/hit" : null;
  }
  function count(kind, n = 1) { T.pending[kind] += n; S.session[kind] = (S.session[kind] || 0) + n; }
  function countScan(r) {
    const now = Date.now();
    if (now - T.last < 5000) return; // live typing re-scans constantly; count an evaluation at most every 5s
    T.last = now;
    count("scans");
    count("files", r.stats.files);
    count("resources", r.stats.resources);
    T.pending.findings += r.findings.filter((f) => !f.waived).length;
    T.pending.ms += r.ms;
    for (const f of r.findings) if (!f.waived) T.pending.rules[f.rule_id] = (T.pending.rules[f.rule_id] || 0) + 1;
  }
  function flush(beacon = false) {
    const url = telemetryTarget();
    if (!url) return;
    const body = JSON.stringify({ session: T.session, surface: "web", ...T.pending });
    T.pending = resetPending();
    // text/plain keeps it a "simple" request: no CORS preflight.
    if (beacon && navigator.sendBeacon) navigator.sendBeacon(url, new Blob([body], { type: "text/plain" }));
    else fetch(url, { method: "POST", body, headers: { "Content-Type": "text/plain" }, keepalive: true }).catch(() => {});
  }

  // ── engine ──────────────────────────────────────────────────────────────
  async function bootEngine() {
    const go = new Go();
    let inst;
    try {
      inst = await WebAssembly.instantiateStreaming(fetch("terraguard.wasm"), go.importObject);
    } catch { // servers that don't send application/wasm
      inst = await WebAssembly.instantiate(await (await fetch("terraguard.wasm")).arrayBuffer(), go.importObject);
    }
    go.run(inst.instance);
    $("#engine-status").textContent = `engine v${terraguard.version} · WASM`;
    $("#engine-status").className = "pill ok";
  }

  const input = () => ({ files: S.files, plan: S.plan, config: S.config });

  function scan() {
    if (!window.terraguard) return;
    const t0 = performance.now();
    S.report = JSON.parse(terraguard.scan(JSON.stringify(input())));
    S.report.ms = Math.round(performance.now() - t0);
    if (Object.keys(S.files).length || S.plan) countScan(S.report);
    persist();
    renderAll();
  }
  let scanTimer;
  const scanSoon = () => { clearTimeout(scanTimer); scanTimer = setTimeout(scan, 250); };

  // ── files & editor ──────────────────────────────────────────────────────
  const langOf = (n) => (n.endsWith(".json") ? "json" : /\.ya?ml$/.test(n) ? "yaml" : "hcl");

  function setFiles(files, active) {
    for (const m of Object.values(models)) m.dispose();
    models = {};
    S.files = {};
    for (const [n, c] of Object.entries(files)) addFile(n, c, false);
    openFile(active && S.files[active] !== undefined ? active : Object.keys(S.files)[0] || null);
  }

  function addFile(name, content, open = true) {
    if (name === POLICY_FILE || name.endsWith("/" + POLICY_FILE)) { S.config = content; $("#policy-input").value = content; return; }
    if (name.endsWith(".json") && !name.endsWith(".tf.json")) { S.plan = content; $("#plan-input").value = content; return; }
    S.files[name] = content;
    if (monacoRef) {
      models[name]?.dispose();
      const m = monacoRef.editor.createModel(content, langOf(name), monacoRef.Uri.file(name));
      m.onDidChangeContent(() => { S.files[name] = m.getValue(); scanSoon(); });
      models[name] = m;
    }
    if (open) openFile(name);
  }

  function openFile(name) {
    S.active = name;
    $(".drop-hint")?.toggleAttribute("hidden", !!name);
    if (editor) editor.setModel(name ? models[name] : null);
    renderTabs();
  }

  function setFileContent(name, content) {
    if (models[name]) models[name].setValue(content); // triggers scan via listener
    else { S.files[name] = content; scanSoon(); }
  }

  function jump(file, line) {
    if (!file || !models[file]) return;
    openFile(file);
    if (line > 0) {
      editor.revealLineInCenter(line);
      editor.setPosition({ lineNumber: line, column: 1 });
      editor.focus();
    }
  }

  function renderTabs() {
    const worst = {};
    for (const f of S.report?.findings || []) {
      if (f.waived) continue;
      if (!worst[f.file] || SEVS.indexOf(f.severity) < SEVS.indexOf(worst[f.file])) worst[f.file] = f.severity;
    }
    $("#file-tabs").innerHTML = Object.keys(S.files).map((n) => `
      <button class="tab ${n === S.active ? "active" : ""}" data-file="${esc(n)}" role="tab">
        ${worst[n] ? `<span class="dot" style="background:${sevColor(worst[n])}" title="${worst[n]}"></span>` : ""}${esc(n)}
        <span class="x" data-close="${esc(n)}" title="Close file">×</span></button>`).join("");
  }

  function setMarkers() {
    if (!monacoRef) return;
    const sevMap = { CRITICAL: 8, HIGH: 8, MEDIUM: 4, LOW: 2, INFO: 1 };
    const byFile = {};
    for (const f of [...(S.report?.findings || []), ...S.aiFindings]) {
      if (f.waived || !models[f.file]) continue;
      const m = models[f.file];
      const line = Math.min(Math.max(f.line || 1, 1), m.getLineCount());
      (byFile[f.file] ||= []).push({
        severity: sevMap[f.severity] || 1, startLineNumber: line, endLineNumber: line, startColumn: 1, endColumn: m.getLineMaxColumn(line),
        message: `[${f.rule_id}] ${f.title}\n${f.message}\nFix: ${f.remediation || ""}`, source: "TerraGuard",
      });
    }
    for (const [n, m] of Object.entries(models)) monacoRef.editor.setModelMarkers(m, "terraguard", byFile[n] || []);
  }

  // ── rendering helpers ───────────────────────────────────────────────────
  // Horizontal bars: one hue for magnitude, labels and values always visible.
  function bars(entries, { label = (k) => k, empty = "Nothing to show." } = {}) {
    const max = Math.max(1, ...entries.map(([, v]) => v));
    if (!entries.length) return `<div class="empty-sm">${empty}</div>`;
    return `<div class="bars">${entries.map(([k, v]) => `
      <div class="bar-row" title="${esc(label(k))}: ${fmtN(v)}"><span class="lbl">${esc(label(k))}</span>
        <div class="track"><div class="fill" style="width:${(v / max) * 100}%"></div></div><span class="val">${fmtN(v)}</span></div>`).join("")}</div>`;
  }

  function ring(score, grade) {
    const r = 38, c = 2 * Math.PI * r, color = score >= 90 ? "var(--ok)" : score >= 75 ? "#65a30d" : score >= 60 ? "var(--med)" : score >= 40 ? "var(--high)" : "var(--crit)";
    return `<svg class="ring" viewBox="0 0 92 92" role="img" aria-label="Security score ${score} of 100, grade ${grade}">
      <circle cx="46" cy="46" r="${r}" fill="none" stroke="var(--bg-3)" stroke-width="8"/>
      <circle cx="46" cy="46" r="${r}" fill="none" stroke="${color}" stroke-width="8" stroke-linecap="round" stroke-dasharray="${(score / 100) * c} ${c}" transform="rotate(-90 46 46)"/>
      <text x="46" y="47" text-anchor="middle" font-size="26" font-weight="800" fill="var(--text)">${grade}</text>
      <text x="46" y="63" text-anchor="middle" font-size="10" fill="var(--muted)">${score}/100</text></svg>`;
  }

  // ── rendering ───────────────────────────────────────────────────────────
  function renderAll() {
    renderTabs();
    setMarkers();
    renderScorecard();
    const tab = S.tab;
    if (tab === "overview") renderOverview();
    if (tab === "findings") renderFindings();
    if (tab === "apply") renderApply();
    if (tab === "plan") renderPlan();
    if (tab === "graph") renderGraph();
    if (tab === "compliance") renderCompliance();
    if (tab === "docs") renderDocs();
  }

  function renderScorecard() {
    const r = S.report;
    if (!r) return;
    const counts = SEVS.map((s) => `<span class="count"><span class="sevdot" style="background:${sevColor(s)}"></span><b>${r.summary[s] || 0}</b>${s.toLowerCase()}</span>`).join("");
    $("#scorecard").innerHTML = `
      <div class="grade g-${r.grade}">${r.grade}<small>${r.score}/100</small></div>
      <div>
        <div class="verdict ${r.verdict.will_apply ? "ok" : "bad"}">${r.verdict.will_apply ? "✓ Looks applyable" : "✕ Apply will fail"} · ${r.passed ? `<span class="pill ok">policy passed</span>` : `<span class="pill bad">policy failed (fail_on ${esc(r.fail_on)})</span>`}</div>
        <div class="counts">${counts}<span class="count">${r.waived} waived</span><span class="count">${r.fixable} auto-fixable</span><span class="count">${r.stats.files} files · ${r.stats.resources} resources · ${r.ms} ms</span></div>
      </div>`;
  }

  function renderOverview() {
    const r = S.report;
    if (!r) return;
    const active = r.findings.filter((f) => !f.waived);
    const top = active.slice(0, 6);
    const cats = Object.entries(r.by_category || {}).sort((a, b) => b[1] - a[1]);
    const clouds = Object.entries(r.providers || {}).sort((a, b) => b[1] - a[1]);
    const comp = r.compliance || [];
    $("#tab-overview").innerHTML = `
      <div class="dash">
        <div class="tile w6"><h4>Security posture</h4>
          <div class="hero">${ring(r.score, r.grade)}
            <div><div class="verdict ${r.verdict.will_apply ? "ok" : "bad"}">${r.verdict.will_apply ? "✓ Expected to apply" : "✕ Apply is expected to fail"}</div>
              <div class="hint" style="margin:0 0 6px">${esc(r.verdict.message)}</div>
              ${r.passed ? `<span class="pill ok">✓ policy gate passes</span>` : `<span class="pill bad">✕ policy gate fails at ${esc(r.fail_on)}</span>`}</div></div></div>
        <div class="tile"><h4>Auto-fixable</h4><div class="kpi">${r.fixable}</div><div class="kpi-label">one click · comments preserved</div>
          ${r.fixable ? `<div class="row"><button class="btn primary sm" id="ov-fix">Fix all</button></div>` : ""}</div>
        <div class="tile"><h4>Scope</h4><div class="kpi">${fmtN(r.stats.resources)}</div><div class="kpi-label">resources in ${r.stats.files} file(s) · ${clouds.length} provider(s)</div></div>
        <div class="tile w12"><h4>Active findings by severity</h4><div class="counts" style="gap:18px">${SEVS.map((s) => `<div><div class="kpi">${r.summary[s] || 0}</div><div class="kpi-label"><span class="sevdot" style="background:${sevColor(s)}"></span>${s.toLowerCase()}</div></div>`).join("")}<div><div class="kpi">${r.waived}</div><div class="kpi-label">waived</div></div></div></div>
        <div class="tile w6"><h4>Findings by category</h4>${bars(cats, { label: (k) => CATEGORY[k] || k, empty: "No active findings 🎉" })}</div>
        <div class="tile w6"><h4>Resources by cloud / provider</h4>${bars(clouds, { label: (k) => CLOUDS[k] || k, empty: "No resources yet." })}</div>
        <div class="tile w8"><h4>Top risks</h4>${top.length ? `<ul class="toplist">${top.map((f) => `<li><span class="sev ${f.severity}">${f.severity}</span><span class="grow"><b>${esc(f.title)}</b> — <span class="rid">${esc(f.resource || f.file)}</span></span><button class="loc" data-jump="${esc(f.file)}" data-line="${f.line || 0}">${esc(f.file)}${f.line ? ":" + f.line : ""}</button></li>`).join("")}</ul>` : `<div class="empty-sm">No active findings.</div>`}</div>
        <div class="tile w4"><h4>Compliance snapshot</h4><ul class="toplist">${comp.map((c) => `<li><span class="grow">${esc(c.name)}</span><span class="pill ${c.passing === c.total ? "ok" : "bad"}">${c.passing}/${c.total} clear</span></li>`).join("")}</ul><div class="hint" style="margin:8px 0 0"><button class="loc" data-tab-go="compliance">Control details →</button></div></div>
        ${r.plan ? `<div class="tile w12"><h4>Plan</h4><div class="counts"><span class="count"><b>${r.plan.create}</b>to add</span><span class="count"><b>${r.plan.update}</b>to change</span><span class="count"><b style="color:var(--crit)">${r.plan.delete}</b>to destroy</span><span class="count"><b style="color:var(--high)">${r.plan.replace}</b>to replace</span></div></div>` : ""}
        <div class="tile w12"><h4>Everything here runs in your browser</h4><div class="feature-grid">
          ${[["Will it apply?", "Syntax, references, CIDRs, bucket names, runtimes — no init"], [`${catalogSize()} rules · ${Object.keys(CLOUDS).length} providers`, "AWS, GCP, Azure, Cloudflare, DO, Hetzner, OVH, OCI, K8s…"], ["Attack paths", "Cross-resource risks from the dependency graph"], ["Plan risk", "Data-loss destroys & replaces, with the reason"], ["Policy-as-code", "Waivers with approver and expiry"], ["Compliance", "CIS · SOC 2 · PCI · ISO 27001 · HIPAA"], ["Docs", "terraform-docs style README"], ["AI (optional)", "Explain, fix, generate tests — or run fully local"]].map(([t, d]) => `<div class="feature"><b>${t}</b>${d}</div>`).join("")}
        </div></div>
      </div>`;
    $("#ov-fix")?.addEventListener("click", () => $("#btn-fixall").click());
  }

  function findingCard(f, i, isAI) {
    const loc = f.file ? `${f.file}${f.line ? ":" + f.line : ""}` : "";
    const issueURL = `${REPO_URL}/issues/new?template=false_positive.yml&title=${encodeURIComponent(`False positive: ${f.rule_id}`)}&rule=${encodeURIComponent(f.rule_id)}`;
    return `<article class="card ${f.severity} ${f.waived ? "waived" : ""}">
      <div class="card-head">
        <span class="sev ${f.severity}">${f.severity}</span>
        <span class="card-title">${esc(f.title)}</span>
        <span class="rid">${esc(f.rule_id)}</span>
        ${f.blocking ? `<span class="badge block">blocks apply</span>` : ""}
        ${isAI ? `<span class="badge ai">AI suggestion</span>` : `<span class="badge">${esc(CATEGORY[f.category] || f.category)}</span>`}
        ${f.cwe ? `<span class="badge">${esc(f.cwe)}</span>` : ""}
      </div>
      <p>${esc(f.message)}</p>
      ${loc ? `<button class="loc" data-jump="${esc(f.file)}" data-line="${f.line || 0}">${esc(loc)}</button>` : ""}
      ${f.resource ? ` <span class="rid">${esc(f.resource)}</span>` : ""}
      ${f.remediation ? `<p class="remedy">↳ ${esc(f.remediation)}</p>` : ""}
      ${f.waived ? `<p class="remedy">Waived: ${esc(f.waiver_reason)}</p>` : ""}
      <div class="card-actions">
        ${f.fix && !f.waived ? `<button class="btn primary sm" data-fix="${i}">Apply fix: ${esc(f.fix.description)}</button>` : ""}
        <button class="btn sm" data-ask="${isAI ? "ai" : ""}${i}">Ask AI</button>
        ${!isAI && f.file && models[f.file] && f.line ? `<button class="btn sm" data-ignore="${i}">Ignore inline</button>` : ""}
        ${!isAI ? `<button class="btn sm" data-waive="${i}">Add waiver</button>
        <a class="btn sm ghost" href="${issueURL}" target="_blank" rel="noopener">False positive?</a>` : ""}
      </div>
    </article>`;
  }

  function matches(f) {
    const q = S.filter.q.toLowerCase();
    if (S.filter.sev.size && !S.filter.sev.has(f.severity)) return false;
    if (S.filter.cloud && cloudOf(f.resource) !== S.filter.cloud) return false;
    return !q || [f.rule_id, f.title, f.message, f.resource, f.file, f.category].join(" ").toLowerCase().includes(q);
  }

  function renderFindings() {
    const r = S.report;
    $("#sev-chips").innerHTML = SEVS.map((s) => `<button class="chip ${S.filter.sev.has(s) ? "on" : ""}" data-sev="${s}"><span class="sevdot" style="background:${sevColor(s)}"></span>${s.toLowerCase()} ${r?.summary[s] || 0}</button>`).join("");
    const clouds = Object.entries(r?.by_provider || {}).sort((a, b) => b[1] - a[1]);
    $("#cloud-chips").innerHTML = clouds.length > 0 ? `<button class="chip ${!S.filter.cloud ? "on" : ""}" data-cloud="">All clouds</button>` + clouds.map(([c, n]) => `<button class="chip ${S.filter.cloud === c ? "on" : ""}" data-cloud="${esc(c)}">${esc(CLOUDS[c] || c)} ${n}</button>`).join("") : "";
    $("#btn-fixall").disabled = !r?.fixable;
    $("#btn-fixall").textContent = `Fix all auto-fixable (${r?.fixable || 0})`;
    const rows = (r?.findings || []).map((f, i) => [f, i]).filter(([f]) => matches(f));
    const ai = S.aiFindings.map((f, i) => [f, i]).filter(([f]) => matches(f));
    if (!Object.keys(S.files).length && !S.plan) {
      $("#findings-list").innerHTML = `<div class="empty">Paste Terraform into the editor, drop a folder, or pick an example to start.</div>`;
      return;
    }
    $("#findings-list").innerHTML = (rows.length || ai.length)
      ? rows.map(([f, i]) => findingCard(f, i, false)).join("") + ai.map(([f, i]) => findingCard(f, i, true)).join("")
      : `<div class="empty">No findings match. ${r?.findings.length ? "" : "🎉 Clean scan."}</div>`;
  }

  function renderApply() {
    const r = S.report;
    if (!r) return;
    const blocking = r.findings.filter((f) => f.blocking && !f.waived);
    const has = (id) => blocking.some((f) => f.rule_id === id);
    const checks = [
      ["TG-VAL-001", "HCL syntax parses (what terraform init/validate checks first)"],
      ["TG-VAL-002", "No duplicate resources, variables, outputs, modules or locals"],
      ["TG-VAL-003", "Every var., local., module., data. and resource reference resolves"],
      ["TG-VAL-007", "count and for_each are not combined"],
      ["TG-VAL-004", "CIDR blocks are valid network addresses (provider rejects at apply)"],
      ["TG-VAL-005", "S3 bucket names follow AWS naming rules (fails at apply, not plan)"],
      ["TG-VAL-006", "Security group port ranges are not inverted"],
      ["TG-AWS-LAMBDA-002", "Lambda runtimes are still supported (AWS blocks deprecated ones)"],
    ];
    const warn = r.findings.filter((f) => !f.waived && ["TG-VAL-008", "TG-VAL-009", "TG-STATE-001", "TG-TF-001", "TG-TF-003"].includes(f.rule_id));
    $("#tab-apply").innerHTML = `
      <div class="verdict-big" style="border-color:${r.verdict.will_apply ? "var(--ok-line)" : "var(--bad-line)"}">
        <h3 class="verdict ${r.verdict.will_apply ? "ok" : "bad"}">${r.verdict.will_apply ? "✓ Expected to apply" : "✕ Expected to fail"}</h3>
        <div class="hint" style="margin:0">${esc(r.verdict.message)}</div>
      </div>
      <ul class="checks">${checks.map(([id, label]) => `<li><span class="ic">${has(id) ? "❌" : "✅"}</span><span>${label} <span class="rid">${id}</span></span></li>`).join("")}
        ${warn.map((f) => `<li><span class="ic">⚠️</span><span>${esc(f.message)} <span class="rid">${f.rule_id}</span></span></li>`).join("")}
      </ul>
      ${blocking.length ? `<h3 class="sec">Blocking issues</h3><div class="list">${blocking.map((f) => findingCard(f, r.findings.indexOf(f), false)).join("")}</div>` : ""}
      <h3 class="sec">What a static check can't know</h3>
      <p class="hint">Provider-side validation (does the AMI exist? is the name taken? quotas, IAM permissions) needs real credentials. Run <code>terraform plan</code> in CI with OIDC (see the CI/CD tab) and paste the JSON plan into the Plan tab — TerraGuard then reviews resolved values and destroy/replace risk.</p>`;
  }

  function renderPlan() {
    const p = S.report?.plan;
    const errs = (S.report?.errors || []).filter((e) => /plan/i.test(e));
    if (!p) {
      $("#plan-view").innerHTML = errs.map((e) => `<div class="msg error">${esc(e)}</div>`).join("");
      return;
    }
    const risky = S.report.findings.filter((f) => f.category === "plan");
    const act = { create: "🟢 create", update: "🟡 update", delete: "🔴 destroy", replace: "🟠 replace", read: "read" };
    $("#plan-view").innerHTML = `
      <div class="plan-bars">
        <div class="plan-stat create"><b>${p.create}</b>to add</div>
        <div class="plan-stat update"><b>${p.update}</b>to change</div>
        <div class="plan-stat delete"><b>${p.delete}</b>to destroy</div>
        <div class="plan-stat replace"><b>${p.replace}</b>to replace</div>
      </div>
      ${risky.length ? `<div class="list">${risky.map((f) => findingCard(f, S.report.findings.indexOf(f), false)).join("")}</div>` : `<p class="hint">No destructive changes.</p>`}
      <h3 class="sec">Changes</h3>
      <table><thead><tr><th>Action</th><th>Address</th><th>Forced by</th></tr></thead><tbody>
      ${(p.changes || []).map((c) => `<tr><td>${act[c.action] || c.action}</td><td class="mono">${esc(c.address)}</td><td class="mono">${esc((c.reasons || []).join(", "))}</td></tr>`).join("")}
      </tbody></table>`;
  }

  function renderGraph() {
    const g = S.report?.graph;
    if (!g || !window.cytoscape) return;
    const pathNodes = new Set();
    for (const f of S.report.findings) if (f.category === "attack-path" && !f.waived) (f.related || []).forEach((n) => pathNodes.add(n));
    const els = [
      ...g.nodes.map((n) => ({ data: { id: n.id, label: n.id.replace(/^data\./, "data·"), color: SEV_HEX[n.severity] || "#94a3b8", file: n.file, line: n.line, path: pathNodes.has(n.id) } })),
      ...g.edges.map((e) => ({ data: { id: e.source + ">" + e.target, source: e.source, target: e.target, path: pathNodes.has(e.source) && pathNodes.has(e.target) } })),
    ];
    graph?.destroy();
    graph = null;
    if (!g.nodes.length) { $("#graph").innerHTML = `<div class="empty">No resources yet.</div>`; return; }
    $("#graph").innerHTML = "";
    const ink = isDark() ? "#cbd5e1" : "#334155", edge = isDark() ? "#334155" : "#cbd5e1";
    graph = cytoscape({
      container: $("#graph"), elements: els,
      layout: { name: "cose", animate: false, padding: 24, nodeRepulsion: 9000 },
      style: [
        { selector: "node", style: { "background-color": "data(color)", label: "data(label)", color: ink, "font-size": 9, "text-valign": "bottom", "text-margin-y": 4, width: 18, height: 18, "border-width": 2, "border-color": isDark() ? "#0a0e16" : "#ffffff" } },
        { selector: "node[?path]", style: { "border-color": "#ef4444", "border-width": 3, width: 24, height: 24 } },
        { selector: "edge", style: { width: 1.2, "line-color": edge, "target-arrow-color": edge, "target-arrow-shape": "triangle", "curve-style": "bezier", "arrow-scale": 0.8 } },
        { selector: "edge[?path]", style: { "line-color": "#ef4444", "target-arrow-color": "#ef4444", width: 2.5 } },
      ],
    });
    graph.on("tap", "node", (e) => jump(e.target.data("file"), e.target.data("line")));
  }

  function renderCompliance() {
    const comp = S.report?.compliance || [];
    $("#tab-compliance").innerHTML = `
      <p class="hint">Indicative mapping of TerraGuard findings to framework controls. A control "fails" when an active finding is evidence against it. This helps you prepare for audits — it is not a certification.</p>
      ${comp.map((fw) => `
        <h3 class="sec">${esc(fw.name)} <span class="pill ${fw.passing === fw.total ? "ok" : "bad"}">${fw.passing}/${fw.total} controls clear</span></h3>
        <table><thead><tr><th style="width:120px">Control</th><th>Area</th><th style="width:90px">Status</th><th>Evidence</th></tr></thead><tbody>
        ${fw.controls.map((c) => `<tr><td class="mono">${esc(c.id)}</td><td>${esc(c.theme)}</td>
          <td><span class="status ${c.findings ? "fail" : "pass"}">${c.findings ? `✕ ${c.findings} finding(s)` : "✓ clear"}</span></td>
          <td>${(c.rules || []).map((id) => `<button class="loc" data-filter-rule="${esc(id)}">${esc(id)}</button>`).join(" ")}</td></tr>`).join("")}
        </tbody></table>`).join("")}`;
  }

  function renderDocs() {
    if (!window.terraguard) return;
    S.docs = terraguard.docs(JSON.stringify({ files: S.files }));
    $("#docs-view").innerHTML = md(S.docs);
  }

  function renderRules() {
    const rules = JSON.parse(terraguard.rules("{}"));
    $("#rules-list").innerHTML = `
      <p class="hint">${rules.length} built-in rules across ${Object.keys(CLOUDS).length} providers. The same catalog runs in the browser, CLI, GitHub Action, MCP server and self-hosted server. <a href="${REPO_URL}/blob/main/CONTRIBUTING.md#adding-a-rule" target="_blank" rel="noopener">Add a rule →</a></p>
      <input type="search" id="rules-q" placeholder="Search rules (e.g. hetzner, encryption, TG-K8S)…" style="width:100%;margin-bottom:10px">
      <table><thead><tr><th>ID</th><th>Severity</th><th>Rule</th></tr></thead><tbody id="rules-body">
      ${rules.map((r) => `<tr data-search="${esc([r.id, r.title, r.remediation, (r.resource_types || []).join(" "), (r.compliance_themes || []).join(" ")].join(" ").toLowerCase())}"><td class="mono">${esc(r.id)}</td><td><span class="sev ${r.severity}">${r.severity}</span></td><td><b>${esc(r.title)}</b>${r.blocking ? ` <span class="badge block">blocks apply</span>` : ""} <span class="badge">${esc(CATEGORY[r.category] || r.category)}</span>${(r.compliance_themes || []).map((t) => ` <span class="badge">${esc(t)}</span>`).join("")}<div class="remedy">${esc(r.remediation)}</div></td></tr>`).join("")}
      </tbody></table>`;
    $("#rules-q").oninput = (e) => {
      const q = e.target.value.toLowerCase();
      $$("#rules-body tr").forEach((tr) => (tr.hidden = q && !tr.dataset.search.includes(q)));
    };
  }

  function renderCICD() {
    const o = {
      dir: $("#ci-dir")?.value ?? ".", cloud: $("#ci-cloud")?.value ?? "aws", role: $("#ci-role")?.value ?? "",
      region: $("#ci-region")?.value ?? "us-east-1", failOn: $("#ci-failon")?.value ?? "HIGH",
      plan: $("#ci-plan")?.checked ?? true, apply: $("#ci-apply")?.checked ?? false,
      drift: $("#ci-drift")?.checked ?? false, ai: $("#ci-ai")?.value ?? "",
    };
    if (!$("#ci-dir")) {
      $("#tab-cicd").innerHTML = `
        <p class="hint">Generate a GitOps pipeline for <em>your</em> Terraform repo. It runs only when <code>.tf</code> files change — no schedules unless you opt in.</p>
        <div class="cicd-opts">
          <label>Terraform directory <input id="ci-dir" value="."></label>
          <label>Fail the PR on <select id="ci-failon">${["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"].map((s) => `<option ${s === "HIGH" ? "selected" : ""}>${s}</option>`).join("")}</select></label>
          <label>Cloud credentials <select id="ci-cloud"><option value="aws">AWS via OIDC (no stored keys)</option><option value="none">None / provider env secrets</option></select></label>
          <label>OIDC role ARN <input id="ci-role" placeholder="arn:aws:iam::123456789012:role/terraform-plan"></label>
          <label>AWS region <input id="ci-region" value="us-east-1"></label>
          <label>AI summary in PR comment <select id="ci-ai"><option value="">Off</option><option value="groq">Groq</option><option value="openrouter">OpenRouter</option><option value="gemini">Gemini</option></select></label>
          <label class="check"><input type="checkbox" id="ci-plan" checked> Run terraform plan + plan-risk analysis</label>
          <label class="check"><input type="checkbox" id="ci-apply"> Apply on merge to main (approval gate)</label>
          <label class="check"><input type="checkbox" id="ci-drift"> Daily drift detection (scheduled — opt-in)</label>
        </div>
        <div class="row"><button class="btn primary sm" data-copy="ci-yaml">Copy workflow</button><span class="hint" style="margin:0">Save as <code>.github/workflows/terraform.yml</code></span></div>
        <pre class="code" id="ci-yaml"></pre>
        <h3 class="sec">Local CLI &amp; pre-commit</h3>
        <div class="row"><button class="btn sm" data-copy="ci-cli">Copy</button></div>
        <pre class="code" id="ci-cli"></pre>
        <h3 class="sec">MCP server for AI coding agents</h3>
        <p class="hint">Let Claude Code, Cursor or any MCP client scan and fix Terraform before it proposes changes.</p>
        <div class="row"><button class="btn sm" data-copy="ci-mcp">Copy</button></div>
        <pre class="code" id="ci-mcp"></pre>
        <pre class="code" id="ci-mcp-json"></pre>
        <h3 class="sec">Self-host for your team (private, keys server-side)</h3>
        <pre class="code" id="ci-self"></pre>`;
      $$("#tab-cicd input, #tab-cicd select").forEach((el) => el.addEventListener("input", renderCICD));
      return renderCICD();
    }
    $("#ci-yaml").textContent = CICD.workflow(o);
    $("#ci-cli").textContent = CICD.cli();
    $("#ci-mcp").textContent = CICD.mcpClaude();
    $("#ci-mcp-json").textContent = "// Cursor / Claude Desktop (mcp.json)\n" + CICD.mcpJson();
    $("#ci-self").textContent = CICD.selfHost();
  }

  // ── live stats ──────────────────────────────────────────────────────────
  async function fetchStats() {
    const url = AI.server() ? "api/stats" : CFG.statsUrl ? CFG.statsUrl.replace(/\/$/, "") + "/stats" : null;
    if (!url) return null;
    try {
      const r = await fetch(url, { cache: "no-store" });
      return r.ok ? await r.json() : null;
    } catch { return null; }
  }

  async function renderStats() {
    flush();
    const st = await fetchStats();
    if (S.tab !== "stats") return;
    const sess = S.session;
    const local = `<div class="tile w12"><h4>This browser session</h4><div class="counts">
      <span class="count"><b>${fmtN(sess.scans)}</b>evaluations</span><span class="count"><b>${fmtN(sess.files)}</b>Terraform files checked</span>
      <span class="count"><b>${fmtN(sess.resources)}</b>resources analyzed</span><span class="count"><b>${fmtN(sess.fixes)}</b>fixes applied</span><span class="count"><b>${fmtN(sess.ai)}</b>AI answers</span></div></div>`;
    if (!st) {
      $("#tab-stats").innerHTML = `<div class="dash">${local}
        <div class="tile w12"><h4>Public dashboard</h4><p>Public counters aren't configured for this site yet.</p>
        <p class="hint">Deploy <code>stats-worker/</code> (Cloudflare Worker + Durable Object, free tier) and set <code>statsUrl</code> in <code>web/config.js</code> — or run <code>terraguard serve</code>, which has a built-in <code>/api/stats</code>. Only anonymous numbers are counted: never code, file names, IPs or keys.</p>
        <a class="btn sm" href="${REPO_URL}/blob/main/docs/SELF_HOSTING.md#public-usage-dashboard" target="_blank" rel="noopener">How to enable →</a></div></div>`;
      return;
    }
    const t = st.today || {}, tot = st.total || {};
    const days = st.days || [];
    const maxDay = Math.max(1, ...days.map((d) => d.files || 0));
    const kpi = (v, l) => `<div class="tile"><div class="kpi">${fmtN(v)}</div><div class="kpi-label">${l}</div></div>`;
    $("#tab-stats").innerHTML = `
      <div class="row" style="margin-top:0"><span class="pill ok"><span class="live-dot"></span>${fmtN(st.active_now)} active now</span>
        ${st.running_now ? `<span class="pill">${st.running_now} executing on server</span>` : ""}
        <span class="hint" style="margin:0">${st.source === "server" ? "Self-hosted server" : "Public, all users"} · updated ${new Date(st.updated).toLocaleTimeString()} · anonymous counts only</span></div>
      <div class="dash">
        <h3 class="sec" style="grid-column:span 12;margin:4px 0 0">Today</h3>
        ${kpi(t.scans, "evaluations today")}${kpi(t.files, "Terraform files checked today")}${kpi(t.resources, "resources analyzed today")}${kpi(t.findings, "issues found today")}
        ${kpi(t.fixes, "auto-fixes applied today")}${kpi(t.ai, "AI answers today")}${kpi(t.scans ? Math.round(t.ms_total / t.scans) : 0, "avg ms per evaluation")}${kpi(tot.files, "Terraform files checked, all time")}
        <div class="tile w8"><h4>Terraform files checked — last 7 days</h4>
          <div class="cols">${days.map((d) => `<div class="col" title="${d.date}: ${fmtN(d.files)} files, ${fmtN(d.scans)} evaluations"><span class="n">${fmtN(d.files)}</span><div class="stick" style="height:${((d.files || 0) / maxDay) * 80}%"></div><span class="d">${new Date(d.date + "T00:00:00Z").toLocaleDateString(undefined, { weekday: "short", timeZone: "UTC" })}</span></div>`).join("")}</div></div>
        <div class="tile w4"><h4>Where scans ran</h4>${bars(Object.entries(st.by_surface || {}).sort((a, b) => b[1] - a[1]), { label: (k) => ({ web: "Web app", cli: "CLI", action: "GitHub Action", api: "Server API", mcp: "MCP" }[k] || k), empty: "No data yet." })}</div>
        <div class="tile w12"><h4>Most common issues</h4>${bars((st.top_rules || []).map((r) => [r.id, r.count]), { empty: "No data yet." })}</div>
        <div class="tile w12"><h4>All time</h4><div class="counts"><span class="count"><b>${fmtN(tot.scans)}</b>evaluations</span><span class="count"><b>${fmtN(tot.files)}</b>files</span><span class="count"><b>${fmtN(tot.resources)}</b>resources</span><span class="count"><b>${fmtN(tot.findings)}</b>issues found</span><span class="count"><b>${fmtN(tot.fixes)}</b>fixes</span><span class="count">since ${new Date(st.since).toLocaleDateString()}</span></div></div>
        ${local}
      </div>`;
  }

  // ── community ───────────────────────────────────────────────────────────
  async function githubStats() {
    try {
      const cached = JSON.parse(sessionStorage.getItem("tg.gh") || "null");
      if (cached && Date.now() - cached.at < 600000) return cached.data;
    } catch {}
    try {
      const [repo, contrib] = await Promise.all([
        fetch(`https://api.github.com/repos/${REPO}`).then((r) => (r.ok ? r.json() : null)),
        fetch(`https://api.github.com/repos/${REPO}/contributors?per_page=100`).then((r) => (r.ok ? r.json() : [])),
      ]);
      if (!repo) return null;
      const data = { stars: repo.stargazers_count, forks: repo.forks_count, issues: repo.open_issues_count, watchers: repo.subscribers_count, contributors: Array.isArray(contrib) ? contrib.length : 0, pushed: repo.pushed_at };
      try { sessionStorage.setItem("tg.gh", JSON.stringify({ at: Date.now(), data })); } catch {}
      return data;
    } catch { return null; }
  }

  async function renderCommunity() {
    const g = CFG.giscus || {};
    $("#tab-community").innerHTML = `
      <div class="dash" id="gh-stats"></div>
      <h3 class="sec">TerraGuard is open source (MIT) — built in public</h3>
      <p>Every rule is a small Go function with a test. If you've hit a Terraform failure that a tool could have caught, it belongs here.</p>
      <div class="list">
        <a class="card" href="${REPO_URL}/discussions" target="_blank" rel="noopener"><b>💬 Discussions</b><p class="remedy">Ask questions, share how you use TerraGuard, propose features.</p></a>
        <a class="card" href="${REPO_URL}/issues/new?template=rule_request.yml" target="_blank" rel="noopener"><b>💡 Suggest a rule</b><p class="remedy">Describe the misconfiguration or apply failure; include a minimal .tf snippet.</p></a>
        <a class="card" href="${REPO_URL}/issues/new?template=false_positive.yml" target="_blank" rel="noopener"><b>🐞 Report a false positive / bug</b><p class="remedy">Every finding card has a pre-filled “False positive?” link too.</p></a>
        <a class="card" href="${REPO_URL}/blob/main/CONTRIBUTING.md" target="_blank" rel="noopener"><b>🛠️ Contributing guide</b><p class="remedy">Local setup in two commands; add a rule in ~20 lines plus two eval cases.</p></a>
        <a class="card" href="${REPO_URL}/blob/main/docs/SELF_HOSTING.md" target="_blank" rel="noopener"><b>🏠 Self-hosting &amp; private AI</b><p class="remedy">One binary or Docker; local LLMs via Ollama so nothing leaves your network.</p></a>
        <a class="card" href="${REPO_URL}/blob/main/docs/ARCHITECTURE.md" target="_blank" rel="noopener"><b>📐 Architecture (HLD / LLD)</b><p class="remedy">One Go engine → WASM, CLI, Action, MCP, server. Diagrams for every flow.</p></a>
      </div>
      <h3 class="sec">Comments</h3>
      <div id="giscus-box">${g.repoId && g.categoryId ? "" : `<p class="hint">Inline comments appear here once Discussions + <a href="https://giscus.app" target="_blank" rel="noopener">giscus</a> are enabled (set the IDs in <code>web/config.js</code>). Until then, join the <a href="${REPO_URL}/discussions" target="_blank" rel="noopener">Discussions</a>.</p>`}</div>`;
    if (g.repoId && g.categoryId && !$("#giscus-box script")) {
      const sc = document.createElement("script");
      Object.entries({ src: "https://giscus.app/client.js", "data-repo": REPO, "data-repo-id": g.repoId, "data-category": g.category || "General", "data-category-id": g.categoryId,
        "data-mapping": "specific", "data-term": "TerraGuard web app", "data-reactions-enabled": "1", "data-input-position": "top", "data-theme": isDark() ? "dark" : "light", "data-loading": "lazy", crossorigin: "anonymous" })
        .forEach(([k, v]) => sc.setAttribute(k, v));
      sc.async = true;
      $("#giscus-box").appendChild(sc);
    }
    const s = await githubStats();
    if (s && $("#gh-stats")) {
      $("#gh-stats").innerHTML = [["★", s.stars, "stars"], ["⑂", s.forks, "forks"], ["👥", s.contributors, "contributors"], ["◎", s.issues, "open issues & PRs"]]
        .map(([i, v, l]) => `<div class="tile"><div class="kpi">${i} ${fmtN(v)}</div><div class="kpi-label">${l}</div></div>`).join("");
      if (s.stars > 0) $("#gh-link").textContent = `★ ${fmtN(s.stars)} GitHub`;
    }
  }

  // Built-in rules only; report.stats.rules also counts the policy's custom rules.
  let catalogCount;
  const catalogSize = () => (catalogCount ??= window.terraguard ? JSON.parse(terraguard.rules("{}")).length : "");

  // ── why TerraGuard ──────────────────────────────────────────────────────
  const PROBLEMS = [
    ["💥", "“Plan was green, apply failed.”", "A bad S3 bucket name, a wrong CIDR or a deprecated Lambda runtime — discovered 10 minutes into a deploy.", "“Will it apply?” catches these in milliseconds — no <code>terraform init</code>, no credentials, no cloud account.", "apply"],
    ["🔓", "Security holes reach production", "SSH open to the world, a public database, an admin IAM role, a hardcoded password — missed in a 500-line PR.", "Every PR is checked automatically. Issues show on the exact line; serious ones block the merge.", "findings"],
    ["🕸️", "Risks hidden across resources", "Each file looks fine, but public API → Lambda → admin role is an account takeover.", "The graph finds attack paths and draws them in red.", "graph"],
    ["🗑️", "A plan silently deletes data", "Renaming one field replaces the production database.", "Plan analysis: “this will DESTROY your database because <code>identifier</code> changed.”", "plan"],
    ["☁️", "Every cloud is different", "AWS, Hetzner, DigitalOcean and OVH each spell “firewall” differently — most tools only know AWS.", "One tool, the same rules, across 14 providers.", "rules"],
    ["🛠️", "Fixing is tedious", "Hunting down the right argument for every finding, in every file.", "One click fixes many issues — your formatting and comments are kept.", "findings"],
    ["📝", "Exceptions get lost", "“Who approved this public bucket, and why?” — lost in a Slack thread.", "Waivers live in git with a reason, an approver and an expiry date — and come back when they expire.", "policy"],
    ["📋", "Audit prep is painful", "Collecting evidence for auditors by hand, every quarter.", "The Compliance tab maps issues to SOC 2, ISO 27001, PCI DSS, HIPAA and CIS.", "compliance"],
    ["📚", "Docs drift from the code", "Module READMEs describe inputs that no longer exist.", "A terraform-docs style README, generated from your code.", "docs"],
    ["💸", "Security tools cost money or need sign-ups", "Licences, accounts, and uploading your code to someone's SaaS.", "Free, open source, no account — your code never leaves the browser.", "overview"],
  ];

  function renderWhy() {
    const rules = catalogSize();
    $("#tab-why").innerHTML = `
      <section class="why-hero">
        <p class="eyebrow">Before you run <code>terraform apply</code></p>
        <h2>Will this <span class="hl">break</span>, <span class="hl">leak</span>, or <span class="hl">cost</span> me?</h2>
        <p class="lead">Today you usually find out the hard way — after apply. TerraGuard tells you before: in your browser, your pull request, your AI agent or your own server.</p>
        <div class="row"><button class="btn primary" data-tab-go="overview">See it on the example →</button><button class="btn" data-tab-go="findings">Browse findings</button>
          <a class="btn ghost" href="${REPO_URL}" target="_blank" rel="noopener">Star on GitHub</a></div>
      </section>

      <h3 class="sec">The problems it solves</h3>
      <div class="problems">${PROBLEMS.map(([icon, title, before, after, tab]) => `
        <article class="problem">
          <div class="problem-title"><span class="problem-icon" aria-hidden="true">${icon}</span>${title}</div>
          <div class="ba"><span class="ba-tag before">Without</span><p>${before}</p></div>
          <div class="ba"><span class="ba-tag after">With TerraGuard</span><p>${after}</p></div>
          <button class="loc" data-tab-go="${tab}">Try it →</button>
        </article>`).join("")}</div>

      <h3 class="sec">Who it helps</h3>
      <div class="feature-grid">
        <div class="feature"><b>👩‍💻 Developers</b>Paste code, see what's wrong and how to fix it — in seconds.</div>
        <div class="feature"><b>🏗️ Platform teams</b>Turn engineering standards into automatic PR checks (policy-as-code).</div>
        <div class="feature"><b>🛡️ Security teams</b>Consistent reviews, waivers with an audit trail, compliance evidence.</div>
        <div class="feature"><b>🤖 AI coding agents</b>Claude Code and Cursor check their own Terraform via the MCP server before suggesting it.</div>
      </div>

      <h3 class="sec">Why the design matters</h3>
      <div class="principles">
        <div class="principle"><b>The rules decide. The AI only explains.</b><p>Results are identical every time, work offline and cost nothing. An AI can make things up, so it never blocks a PR — it explains, suggests fixes and writes tests.</p></div>
        <div class="principle"><b>One engine, five places.</b><p>Browser, CLI, GitHub Action, MCP server and self-hosted server run the same ${rules ? rules + " " : ""}rules — the result in your browser is the result your CI gives.</p></div>
        <div class="principle"><b>Private by default.</b><p>Analysis runs on your device. Want AI without sharing code? Use a local model — nothing leaves your machine.</p></div>
      </div>

      <blockquote class="pitch">TerraGuard catches Terraform security holes, apply failures and data-loss plans before they reach production — one open-source Go engine that runs in the browser, CI, AI agents and self-hosted, across 14 clouds, at zero cost.</blockquote>`;
  }

  // ── AI ──────────────────────────────────────────────────────────────────
  function contextBlock(maxChars = 24000) {
    let budget = maxChars;
    const files = Object.entries(S.files).map(([n, c]) => {
      const part = c.slice(0, Math.max(0, budget));
      budget -= part.length;
      return `--- ${n} ---\n${part}`;
    }).join("\n");
    const fs = (S.report?.findings || []).filter((f) => !f.waived).slice(0, 40)
      .map((f) => `- [${f.severity}] ${f.rule_id} ${f.file}:${f.line} ${f.title}: ${f.message}`).join("\n");
    return `Terraform files:\n${files}\n\nTerraGuard deterministic findings:\n${fs || "(none)"}${S.report?.plan ? `\n\nPlan summary: ${JSON.stringify(S.report.plan).slice(0, 3000)}` : ""}`;
  }

  const SYSTEM = `You are TerraGuard's assistant: a senior platform engineer who knows Terraform/OpenTofu and AWS, GCP, Azure, Cloudflare, DigitalOcean, Hetzner, OVH, Oracle Cloud and Kubernetes deeply.
You only explain and suggest; TerraGuard's deterministic findings decide pass/fail. Be concise and concrete.
When you change Terraform, return the COMPLETE updated file in one \`\`\`hcl block whose first line is a comment "# file: <name>".
Prefer least privilege, encryption, private networking, pinned versions. Never invent resource arguments; if unsure, say so.`;

  function renderChat() {
    const st = AI.status();
    $("#ai-provider-label").textContent = (st.private ? "🔒 " : "") + st.label;
    $("#ai-provider-label").className = "pill " + (st.ready ? (st.private ? "ok" : "") : "muted");
    $("#chat-log").innerHTML = S.chat.length ? S.chat.map((m, i) => `
      <div class="msg ${m.role} ${m.error ? "error" : ""}">${m.role === "user" || m.error ? esc(m.content) : md(m.content)}
        ${m.role === "assistant" && /```(hcl|terraform)/.test(m.content) ? `<div class="row"><button class="btn primary sm" data-apply-ai="${i}">Apply code to editor</button></div>` : ""}
        ${m.meta ? `<div class="meta">${esc(m.meta)}</div>` : ""}</div>`).join("")
      : `<div class="empty">Ask anything about your Terraform. The assistant sees your files and TerraGuard's findings.<br><br>
          <b>AI is optional.</b> Every scan, fix and validation runs locally without it.<br>
          Free keys: Groq, OpenRouter, Gemini — or run a <b>local model</b> (Ollama) so nothing leaves your machine.</div>`;
    $("#chat-log").scrollTop = $("#chat-log").scrollHeight;
  }

  async function ask(text, { silent = false } = {}) {
    showTab("ai");
    S.chat.push({ role: "user", content: text });
    S.chat.push({ role: "assistant", content: "", pending: true });
    renderChat();
    $("#chat-log").lastElementChild.classList.add("typing");
    const history = S.chat.filter((m) => !m.pending && !m.error).slice(-12).map(({ role, content }) => ({ role, content }));
    const messages = [{ role: "system", content: SYSTEM + "\n\n" + contextBlock() }, ...history];
    try {
      const r = await AI.chat(messages);
      count("ai");
      Object.assign(S.chat[S.chat.length - 1], { content: r.text, pending: false, meta: `${r.provider} · ${r.model}${r.tried?.length ? ` · after ${r.tried.length} fallback(s)` : ""}` });
      return r.text;
    } catch (e) {
      Object.assign(S.chat[S.chat.length - 1], { content: e.message, pending: false, error: true });
      if (!silent) toast("AI request failed — details in the AI tab");
      return null;
    } finally {
      persist();
      renderChat();
    }
  }

  const QUICK = {
    explain: "Explain the 3 most important risks in this Terraform in plain English, and what an attacker or outage would look like for each.",
    plan: "Write a prioritized remediation plan (max 7 steps). For each step, give the exact Terraform change. Mention which changes force resource replacement.",
    rewrite: () => `Rewrite ${S.active || "the main file"} to fix every finding you safely can, keeping behaviour the same. Return the complete file.`,
    test: () => `Write a Terraform native test file (tests/main.tftest.hcl, terraform >= 1.6 \`terraform test\`) for ${S.active || "this configuration"}: use command = plan runs and assert blocks that verify the security-relevant settings (encryption, public access, IAM). Return it with "# file: tests/main.tftest.hcl".`,
    cost: "Review this configuration for cost: oversized or previous-generation instances, gp2 volumes, NAT gateways, unbounded log retention, missing lifecycle rules, idle resources. Estimate monthly impact where you can and say how confident you are.",
    migrate: () => {
      const what = prompt("Which provider upgrade?", "hashicorp/aws v4 → v5");
      return what && `I'm upgrading ${what}. List the breaking changes that affect THIS configuration (renamed/removed arguments, split resources, new defaults) and return the updated files.`;
    },
    generate: () => {
      const what = prompt("What should the module create?", "A private S3 bucket for logs with KMS encryption, versioning and lifecycle to Glacier after 90 days");
      return what && `Generate production-ready Terraform for: ${what}. Pin provider versions, follow TerraGuard rules, include variables and outputs. Return it as one file named generated.tf.`;
    },
    explainplan: () => S.plan ? "Explain this terraform plan in plain English for a reviewer: what changes, what is risky (destroys/replacements and why), and what to double-check before approving." : (toast("Paste a plan first"), null),
  };

  function applyAICode(i) {
    const m = S.chat[i];
    const blocks = [...m.content.matchAll(/```(?:hcl|terraform)\s*\n([\s\S]*?)```/g)].map((x) => x[1]);
    let applied = 0;
    for (const code of blocks) {
      const name = (code.match(/^#\s*file:\s*(\S+)/m) || [])[1] || S.active || "main.tf";
      if (S.files[name] !== undefined) setFileContent(name, code);
      else addFile(name, code);
      applied++;
    }
    toast(`Applied ${applied} file(s) — rescanning`);
    scanSoon();
  }

  async function aiReview() {
    toast("Asking the LLM for issues beyond the rule set…");
    const text = await ask(`Act as a reviewer looking for issues the deterministic findings above MISSED (logic errors, risky defaults, missing resources, cost or reliability traps). Respond ONLY with a JSON array of objects: {"severity":"CRITICAL|HIGH|MEDIUM|LOW|INFO","title":"","file":"","line":0,"message":"","remediation":""}. Return [] if nothing new.`, { silent: true });
    if (!text) return toast("AI review failed — see AI tab");
    try {
      const json = text.slice(text.indexOf("["), text.lastIndexOf("]") + 1);
      S.aiFindings = JSON.parse(json).map((f) => ({ ...f, rule_id: "AI-REVIEW", category: "ai", severity: SEVS.includes(String(f.severity).toUpperCase()) ? String(f.severity).toUpperCase() : "INFO" }));
      toast(`AI review added ${S.aiFindings.length} suggestion(s)`);
    } catch { toast("AI returned non-JSON; see AI tab"); }
    showTab("findings");
    setMarkers();
  }

  // ── actions ─────────────────────────────────────────────────────────────
  function applyFixes(fixes) {
    const res = JSON.parse(terraguard.applyFixes(JSON.stringify({ files: S.files, fixes })));
    for (const [n, c] of Object.entries(res.files || {})) setFileContent(n, c);
    count("fixes", fixes.length - (res.errors?.length || 0));
    toast(res.errors?.length ? res.errors[0] : `Applied ${fixes.length} fix(es)`);
  }

  function ignoreInline(f) {
    const m = models[f.file];
    const line = f.line;
    const indent = (m.getLineContent(line).match(/^\s*/) || [""])[0];
    m.pushEditOperations([], [{ range: new monacoRef.Range(line, 1, line, 1), text: `${indent}# terraguard:ignore ${f.rule_id} -- reason: \n` }], () => null);
    jump(f.file, line);
  }

  function addWaiver(f) {
    const exp = new Date(Date.now() + 90 * 864e5).toISOString().slice(0, 10);
    const entry = `  - rule: ${f.rule_id}\n    resource: "${f.resource || "*"}"\n    reason: "TODO: why this risk is accepted"\n    expires: "${exp}"\n    approved_by: "TODO"\n`;
    let c = S.config || "fail_on: HIGH\n";
    c = /^waivers:\s*$/m.test(c) ? c.replace(/^waivers:\s*$/m, "waivers:\n" + entry.trimEnd()) : c.trimEnd() + "\n\nwaivers:\n" + entry;
    S.config = c;
    $("#policy-input").value = c;
    showTab("policy");
    scan();
  }

  function download(name, content, type = "text/plain") {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([content], { type }));
    a.download = name.split("/").pop();
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  async function loadExample(name) {
    try {
      if (name === "plan") {
        S.plan = await (await fetch("examples/plan.json")).text();
        $("#plan-input").value = S.plan;
        showTab("plan");
        return scan();
      }
      const files = {};
      for (const f of EXAMPLES[name]) files[f] = await (await fetch(`examples/${name}/${f}`)).text();
      S.config = files[POLICY_FILE] || "";
      delete files[POLICY_FILE];
      $("#policy-input").value = S.config;
      S.plan = "";
      $("#plan-input").value = "";
      S.aiFindings = [];
      setFiles(files, "main.tf");
      scan();
    } catch { toast("Could not load example"); }
  }

  async function readUploads(fileList) {
    const ok = /\.(tf|tfvars|json|ya?ml)$|\.tfstate/;
    let n = 0;
    for (const f of fileList) {
      const path = f.webkitRelativePath || f.name;
      if (!ok.test(path) || /(^|\/)\.terraform\//.test(path)) continue;
      const name = path.split("/").slice(f.webkitRelativePath ? 1 : 0).join("/") || f.name;
      // A committed state file is itself the finding; never load its secrets into the editor.
      addFile(name, /\.tfstate/.test(name) ? "" : await f.text(), false);
      n++;
    }
    if (!S.active) openFile(Object.keys(S.files)[0] || null);
    renderTabs();
    toast(`Loaded ${n} file(s)`);
    scan();
  }

  function showTab(tab) {
    S.tab = tab;
    $$(".panel-tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
    $$(".tab-body").forEach((el) => (el.hidden = el.id !== "tab-" + tab));
    clearInterval(statsTimer);
    if (tab === "graph") requestAnimationFrame(renderGraph);
    if (tab === "rules" && !$("#rules-list").innerHTML) renderRules();
    if (tab === "cicd") renderCICD();
    if (tab === "community") renderCommunity();
    if (tab === "why") renderWhy();
    if (tab === "ai") renderChat();
    if (tab === "stats") { renderStats(); statsTimer = setInterval(renderStats, 15000); }
    if (["overview", "findings", "apply", "plan", "compliance", "docs"].includes(tab)) renderAll();
  }

  // ── settings dialog ─────────────────────────────────────────────────────
  function fillSettings(provider) {
    const s = AI.load();
    const p = provider || s.provider || "groq";
    const P = AI.PROVIDERS[p];
    $("#ai-provider").value = p;
    $("#ai-private").checked = s.private;
    $("#ai-models").innerHTML = P.models.map((m) => `<option value="${esc(m)}">`).join("");
    $("#ai-model").value = s.models[p] || P.models[0];
    $("#ai-key").value = s.keys[p] || "";
    $("#ai-base").value = s.baseUrl;
    $("#ai-token").value = s.serverToken;
    $("#ai-fallback").checked = s.fallback;
    $("#ai-telemetry").checked = s.telemetry !== false;
    $("#row-base").hidden = p !== "local";
    $("#row-key").hidden = p === "server";
    $("#row-model").hidden = p === "server";
    $("#row-token").hidden = p !== "server";
    const srv = AI.server();
    $("#ai-help").innerHTML = {
      groq: `Free key: <a href="${P.keyUrl}" target="_blank" rel="noopener">${P.keyUrl}</a>`,
      openrouter: `Free key: <a href="${P.keyUrl}" target="_blank" rel="noopener">${P.keyUrl}</a> · models ending in <code>:free</code> cost nothing.`,
      gemini: `Free key: <a href="${P.keyUrl}" target="_blank" rel="noopener">${P.keyUrl}</a>`,
      local: `Install <a href="https://ollama.com/download" target="_blank" rel="noopener">Ollama</a>, run <code>ollama pull llama3.2</code>, and start it with <code>OLLAMA_ORIGINS=${esc(location.origin)} ollama serve</code>. Your code never leaves this machine.`,
      server: srv ? `Connected: ${esc((srv.ai?.route || []).length)} route step(s)${srv.ai?.local_only ? " · local-only" : ""}.` : `Run <code>terraguard serve</code> and open the app from it; keys stay in the server's <code>.env</code>.`,
    }[p];
    $$("#ai-provider option").forEach((o) => (o.disabled = s.private && AI.PROVIDERS[o.value].hosted));
  }

  // ── wiring ──────────────────────────────────────────────────────────────
  function wire() {
    $(".panel-tabs").addEventListener("click", (e) => e.target.dataset.tab && showTab(e.target.dataset.tab));

    $("#file-tabs").addEventListener("click", (e) => {
      const close = e.target.dataset.close;
      if (close) {
        if (!confirm(`Close ${close}? Unsaved edits to it will be lost.`)) return;
        models[close]?.dispose();
        delete models[close];
        delete S.files[close];
        openFile(Object.keys(S.files)[0] || null);
        return scan();
      }
      const t = e.target.closest("[data-file]");
      if (t) openFile(t.dataset.file);
    });

    $("#btn-theme").onclick = () => {
      const next = isDark() ? "light" : "dark";
      document.documentElement.dataset.theme = next;
      try { localStorage.setItem("tg.theme", next); } catch {}
      applyTheme();
    };
    $("#btn-new").onclick = () => {
      const name = prompt("File name", "new.tf");
      if (name && !S.files[name]) { addFile(name, ""); scan(); }
    };
    $("#upload").onchange = (e) => readUploads(e.target.files);
    $("#upload-dir").onchange = (e) => readUploads(e.target.files);
    $("#example-select").onchange = (e) => { if (e.target.value) loadExample(e.target.value); e.target.value = ""; };
    $("#btn-download").onclick = () => S.active && download(S.active, S.files[S.active]);
    $("#btn-format").onclick = () => {
      if (!S.active || !/\.(tf|tfvars)$/.test(S.active)) return;
      setFileContent(S.active, terraguard.fmt(S.files[S.active]));
      toast("Formatted (terraform fmt)");
    };
    $("#btn-docs-copy").onclick = () => { navigator.clipboard.writeText(S.docs || ""); toast("Copied"); };
    $("#btn-docs-download").onclick = () => download("README.md", S.docs || "", "text/markdown");

    const ed = $("#editor");
    ed.addEventListener("dragover", (e) => { e.preventDefault(); ed.classList.add("dragging"); });
    ed.addEventListener("dragleave", () => ed.classList.remove("dragging"));
    ed.addEventListener("drop", async (e) => {
      e.preventDefault();
      ed.classList.remove("dragging");
      const files = [];
      const walk = async (entry, prefix = "") => {
        if (entry.isFile) {
          const f = await new Promise((r) => entry.file(r));
          files.push(new File([f], prefix + f.name));
        } else if (entry.isDirectory && entry.name !== ".terraform" && entry.name !== ".git") {
          const reader = entry.createReader();
          let batch;
          while ((batch = await new Promise((r) => reader.readEntries(r))).length) for (const c of batch) await walk(c, prefix + entry.name + "/");
        }
      };
      const items = [...e.dataTransfer.items].map((i) => i.webkitGetAsEntry?.()).filter(Boolean);
      if (items.length) for (const it of items) await walk(it);
      else files.push(...e.dataTransfer.files);
      readUploads(files);
    });

    $("#filter-q").oninput = (e) => { S.filter.q = e.target.value; renderFindings(); };
    $("#sev-chips").onclick = (e) => {
      const s = e.target.closest("[data-sev]")?.dataset.sev;
      if (!s) return;
      S.filter.sev.has(s) ? S.filter.sev.delete(s) : S.filter.sev.add(s);
      renderFindings();
    };
    $("#cloud-chips").onclick = (e) => {
      const c = e.target.closest("[data-cloud]");
      if (!c) return;
      S.filter.cloud = c.dataset.cloud;
      renderFindings();
    };

    // finding card actions (shared by several tabs)
    document.addEventListener("click", (e) => {
      const el = e.target.closest("[data-jump],[data-fix],[data-ignore],[data-waive],[data-ask],[data-apply-ai],[data-copy],[data-q],[data-tab-go],[data-filter-rule]");
      if (!el) return;
      const d = el.dataset;
      const all = S.report?.findings || [];
      if (d.jump !== undefined) jump(d.jump, +d.line);
      else if (d.fix !== undefined) applyFixes([all[+d.fix].fix]);
      else if (d.ignore !== undefined) ignoreInline(all[+d.ignore]);
      else if (d.waive !== undefined) addWaiver(all[+d.waive]);
      else if (d.ask !== undefined) {
        const f = d.ask.startsWith("ai") ? S.aiFindings[+d.ask.slice(2)] : all[+d.ask];
        ask(`Explain finding ${f.rule_id} "${f.title}" at ${f.file}:${f.line} (${f.resource || ""}): ${f.message}\nWhy does it matter, how would it be exploited or cause an outage, and what exact Terraform change fixes it? Note side effects such as forced replacement.`);
      } else if (d.applyAi !== undefined) applyAICode(+d.applyAi);
      else if (d.copy) { navigator.clipboard.writeText($("#" + d.copy).textContent); toast("Copied"); }
      else if (d.tabGo) showTab(d.tabGo);
      else if (d.filterRule) { S.filter.q = d.filterRule; $("#filter-q").value = d.filterRule; showTab("findings"); }
      else if (d.q) {
        const q = typeof QUICK[d.q] === "function" ? QUICK[d.q]() : QUICK[d.q];
        if (q) ask(q);
      }
    });

    $("#btn-fixall").onclick = () => {
      const fixes = (S.report?.findings || []).filter((f) => f.fix && !f.waived).map((f) => f.fix);
      if (fixes.length) applyFixes(fixes);
    };
    $("#btn-ai-review").onclick = aiReview;
    $("#btn-export").onclick = () => ($("#export-menu").hidden = !$("#export-menu").hidden);
    $("#export-menu").onclick = (e) => {
      const f = e.target.dataset.export;
      if (!f) return;
      $("#export-menu").hidden = true;
      const out = terraguard.render(JSON.stringify(input()), f);
      download({ markdown: "terraguard-report.md", json: "terraguard-report.json", sarif: "terraguard.sarif" }[f], out);
    };

    $("#plan-input").oninput = (e) => { S.plan = e.target.value; scanSoon(); };
    $("#plan-upload").onchange = async (e) => { S.plan = await e.target.files[0].text(); $("#plan-input").value = S.plan; scan(); };
    $("#btn-plan-clear").onclick = () => { S.plan = ""; $("#plan-input").value = ""; scan(); };

    $("#policy-input").oninput = (e) => { S.config = e.target.value; scanSoon(); };
    $("#btn-policy-example").onclick = async () => {
      S.config = await (await fetch("examples/insecure/.terraguard.yml")).text();
      $("#policy-input").value = S.config;
      scan();
    };

    $("#chat-form").onsubmit = (e) => {
      e.preventDefault();
      const v = $("#chat-input").value.trim();
      if (!v) return;
      $("#chat-input").value = "";
      ask(v);
    };
    $("#chat-input").onkeydown = (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); $("#chat-form").requestSubmit(); } };
    $("#btn-chat-clear").onclick = () => { S.chat = []; persist(); renderChat(); };

    $("#btn-settings").onclick = () => { fillSettings(); $("#settings").showModal(); };
    $("#ai-provider").onchange = (e) => fillSettings(e.target.value);
    $("#ai-private").onchange = (e) => {
      const s = AI.load();
      s.private = e.target.checked;
      AI.save(s);
      fillSettings(s.private && AI.PROVIDERS[$("#ai-provider").value].hosted ? "local" : undefined);
    };
    $("#ai-save").onclick = () => {
      const s = AI.load();
      const p = $("#ai-provider").value;
      s.provider = p;
      s.private = $("#ai-private").checked;
      if (p !== "server") s.models[p] = $("#ai-model").value.trim();
      if (p !== "server" && p !== "local") s.keys[p] = $("#ai-key").value.trim();
      if (p === "local") s.keys.local = $("#ai-key").value.trim();
      s.baseUrl = $("#ai-base").value.trim() || "http://localhost:11434/v1";
      s.serverToken = $("#ai-token").value.trim();
      s.fallback = $("#ai-fallback").checked;
      s.telemetry = $("#ai-telemetry").checked;
      AI.save(s);
      renderChat();
      updatePrivacyPill();
      toast("AI settings saved in this browser");
    };

    $("#btn-share").onclick = async () => {
      const total = Object.values(S.files).join("").length;
      if (total > 60000) return toast("Too large to share as a link; export instead");
      const url = `${location.origin}${location.pathname}#s=${await encodeShare({ files: S.files, config: S.config })}`;
      await navigator.clipboard.writeText(url);
      toast("Share link copied — the code is inside the link, nothing is uploaded");
    };

    setInterval(() => flush(), 60000); // heartbeat keeps "active now" accurate
    addEventListener("pagehide", () => flush(true));
  }

  function updatePrivacyPill() {
    const st = AI.status();
    $("#privacy-pill").textContent = st.ready && !st.private ? "🔒 code local · AI hosted" : "🔒 code stays local";
    $("#privacy-pill").title = st.ready && !st.private
      ? "Scans run on this device. When you ask the AI, your files are sent to the selected AI provider."
      : "Your Terraform is analyzed on this device and never uploaded.";
  }

  // ── boot ────────────────────────────────────────────────────────────────
  async function main() {
    wire();
    const serverPromise = AI.detectServer();
    const enginePromise = bootEngine().catch((e) => {
      $("#engine-status").textContent = "engine failed to load";
      $("#engine-status").className = "pill bad";
      console.error(e);
    });

    await new Promise((resolve) => {
      require.config({ paths: { vs: "https://cdn.jsdelivr.net/npm/monaco-editor@0.52.2/min/vs" } });
      require(["vs/editor/editor.main"], (monaco) => {
        monacoRef = monaco;
        editor = monaco.editor.create($("#editor"), {
          theme: isDark() ? "vs-dark" : "vs", automaticLayout: true, fontSize: 13, fontFamily: "JetBrains Mono, monospace",
          minimap: { enabled: false }, scrollBeyondLastLine: false, tabSize: 2, renderLineHighlight: "all",
        });
        resolve();
      });
    });
    matchMedia("(prefers-color-scheme: light)").addEventListener("change", applyTheme);

    let state = null;
    if (location.hash.startsWith("#s=")) {
      try { state = await decodeShare(location.hash.slice(3)); toast("Loaded shared configuration"); } catch { toast("Share link is corrupted"); }
      history.replaceState(null, "", location.pathname);
    }
    state ||= restore();
    await Promise.all([enginePromise, serverPromise]);
    if (AI.server()) $("#engine-status").textContent += " · self-hosted";
    updatePrivacyPill();
    if (state && Object.keys(state.files || {}).length) {
      S.config = state.config || "";
      S.plan = state.plan || "";
      S.chat = state.chat || [];
      $("#policy-input").value = S.config;
      $("#plan-input").value = S.plan;
      setFiles(state.files, state.active);
      scan();
    } else {
      await loadExample("insecure");
    }
    showTab(location.hash === "#stats" ? "stats" : "overview");
  }

  main();
})();
