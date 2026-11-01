// TerraGuard site: product page + workspace (Monaco editor, Go/WASM engine, optional AI).
(() => {
  const CFG = window.TERRAGUARD_CONFIG || {};
  const REPO = CFG.repo || "Karthik-099/TERRAGUARD";
  const REPO_URL = `https://github.com/${REPO}`;
  const SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const sevColor = (s) => `var(--${{ CRITICAL: "crit", HIGH: "high", MEDIUM: "med", LOW: "low", INFO: "info" }[s] || "info"})`;
  const SEV_HEX = { CRITICAL: "#d92d20", HIGH: "#e8590c", MEDIUM: "#b88700", LOW: "#2e6be6", INFO: "#667085" };
  const CLOUDS = {
    aws: "AWS", google: "Google Cloud", azurerm: "Azure", cloudflare: "Cloudflare", digitalocean: "DigitalOcean",
    hcloud: "Hetzner", linode: "Akamai / Linode", openstack: "OpenStack / OVH", ovh: "OVHcloud", oci: "Oracle Cloud",
    alicloud: "Alibaba Cloud", vultr: "Vultr", kubernetes: "Kubernetes", helm: "Helm",
  };
  const CATEGORY = { security: "Security", validate: "Validation", reliability: "Reliability", "best-practice": "Best practice", "attack-path": "Attack path", plan: "Plan risk", policy: "Policy", cost: "Cost" };
  const EXAMPLES = { insecure: ["main.tf", "variables.tf", "terraform.tfvars", ".terraguard.yml"], multicloud: ["main.tf"], secure: ["main.tf"] };
  const CDN = {
    monaco: "https://cdn.jsdelivr.net/npm/monaco-editor@0.52.2/min/vs",
    cytoscape: "https://cdn.jsdelivr.net/npm/cytoscape@3.30.2/dist/cytoscape.min.js",
  };
  const POLICY_FILE = ".terraguard.yml";
  const STORE = "tg.state";

  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const md = (s) => DOMPurify.sanitize(marked.parse(s || ""));
  const fmtN = (n) => new Intl.NumberFormat().format(n || 0);
  const cloudOf = (addr) => (addr || "").replace(/^data\./, "").split("_")[0];
  const icon = (id, cls = "ic") => `<svg class="${cls}"><use href="#i-${id}"/></svg>`;
  const loadScript = (src) => new Promise((ok, fail) => { const s = document.createElement("script"); s.src = src; s.onload = ok; s.onerror = fail; document.head.appendChild(s); });

  const S = {
    files: {}, active: null, config: "", plan: "", report: null, aiFindings: [], chat: [],
    filter: { q: "", sev: new Set(), cloud: "" }, tab: "overview",
    session: { scans: 0, files: 0, resources: 0, fixes: 0, ai: 0 },
  };
  let editor, monacoRef, models = {}, graph, appReady;

  // ── theme ───────────────────────────────────────────────────────────────
  const isDark = () => (document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")) === "dark";
  function toggleTheme() {
    const next = isDark() ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("tg.theme", next); } catch {}
    monacoRef?.editor.setTheme(next === "dark" ? "vs-dark" : "vs");
    if (S.tab === "graph") renderGraph();
  }

  // ── persistence & share links ───────────────────────────────────────────
  function persist() {
    try { localStorage.setItem(STORE, JSON.stringify({ files: S.files, active: S.active, config: S.config, plan: S.plan, chat: S.chat.slice(-40) })); } catch {}
  }
  function restore() { try { return JSON.parse(localStorage.getItem(STORE)); } catch { return null; } }
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
    t._h = setTimeout(() => t.classList.remove("show"), 3200);
  }

  // ── anonymous usage counters (numbers only, never code) ─────────────────
  const T = { session: crypto.randomUUID?.() || String(Math.random()).slice(2), last: 0 };
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
    if (Date.now() - T.last < 5000) return; // live typing re-scans constantly; count at most every 5 s
    T.last = Date.now();
    count("scans");
    count("files", r.stats.files);
    count("resources", r.stats.resources);
    T.pending.ms += r.ms;
    for (const f of r.findings) if (!f.waived) { T.pending.findings++; T.pending.rules[f.rule_id] = (T.pending.rules[f.rule_id] || 0) + 1; }
  }
  function flush(beacon = false) {
    const url = telemetryTarget();
    if (!url) return;
    const body = JSON.stringify({ session: T.session, surface: "web", ...T.pending });
    T.pending = resetPending();
    // text/plain keeps it a simple request: no CORS preflight
    if (beacon && navigator.sendBeacon) navigator.sendBeacon(url, new Blob([body], { type: "text/plain" }));
    else fetch(url, { method: "POST", body, headers: { "Content-Type": "text/plain" }, keepalive: true }).catch(() => {});
  }

  // ── routing: product page <-> workspace ─────────────────────────────────
  const inApp = () => location.hash.startsWith("#/app") || location.hash.startsWith("#s=");
  function route() {
    const app = inApp();
    $("#landing").hidden = app;
    $("#app").hidden = !app;
    document.body.classList.toggle("app-open", app);
    if (app) { appReady ||= enterApp(); return; }
    const target = location.hash.length > 1 && document.getElementById(location.hash.slice(1));
    if (target) requestAnimationFrame(() => target.scrollIntoView());
  }

  // ── engine & editor (loaded only when the workspace opens) ──────────────
  async function bootEngine() {
    await loadScript("wasm_exec.js");
    const go = new Go();
    let inst;
    try {
      inst = await WebAssembly.instantiateStreaming(fetch("terraguard.wasm"), go.importObject);
    } catch { // servers that don't send application/wasm
      inst = await WebAssembly.instantiate(await (await fetch("terraguard.wasm")).arrayBuffer(), go.importObject);
    }
    go.run(inst.instance);
    $("#engine-status").textContent = `Engine v${terraguard.version}${AI.server() ? " · self-hosted" : ""}`;
    $("#engine-status").className = "pill ok";
  }

  async function bootEditor() {
    await loadScript(`${CDN.monaco}/loader.js`);
    await new Promise((resolve) => {
      require.config({ paths: { vs: CDN.monaco } });
      require(["vs/editor/editor.main"], (monaco) => {
        monacoRef = monaco;
        editor = monaco.editor.create($("#editor"), {
          theme: isDark() ? "vs-dark" : "vs", automaticLayout: true, fontSize: 13, fontFamily: "JetBrains Mono, monospace",
          minimap: { enabled: false }, scrollBeyondLastLine: false, tabSize: 2, renderLineHighlight: "all",
        });
        resolve();
      });
    });
  }

  async function enterApp() {
    let shared = null;
    if (location.hash.startsWith("#s=")) {
      try { shared = await decodeShare(location.hash.slice(3)); toast("Loaded shared configuration"); } catch { toast("Share link is invalid"); }
      history.replaceState(null, "", "#/app");
    }
    loadScript(CDN.cytoscape).catch(() => {});
    try {
      await Promise.all([bootEngine(), bootEditor()]);
    } catch (e) {
      $("#engine-status").textContent = "Engine failed to load";
      $("#engine-status").className = "pill bad";
      console.error(e);
      return;
    }
    updatePrivacyPill();
    const state = shared || restore();
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
    showTab("overview");
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

  // ── files ───────────────────────────────────────────────────────────────
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
    if (models[name]) models[name].setValue(content); // triggers a scan via the model listener
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
      if (!f.waived && (!worst[f.file] || SEVS.indexOf(f.severity) < SEVS.indexOf(worst[f.file]))) worst[f.file] = f.severity;
    }
    $("#file-tabs").innerHTML = Object.keys(S.files).map((n) => `
      <button class="tab ${n === S.active ? "active" : ""}" data-file="${esc(n)}" role="tab">
        ${worst[n] ? `<span class="dot" style="background:${sevColor(worst[n])}" title="${worst[n]}"></span>` : ""}${esc(n)}
        <span class="x" data-close="${esc(n)}" title="Close file" aria-label="Close ${esc(n)}">×</span></button>`).join("");
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

  // ── small chart helpers ─────────────────────────────────────────────────
  function bars(entries, { label = (k) => k, empty = "Nothing to show." } = {}) {
    if (!entries.length) return `<div class="empty-sm">${empty}</div>`;
    const max = Math.max(1, ...entries.map(([, v]) => v));
    return `<div class="bars">${entries.map(([k, v]) => `
      <div class="bar-row" title="${esc(label(k))}: ${fmtN(v)}"><span class="lbl">${esc(label(k))}</span>
        <div class="track"><div class="fill" style="width:${(v / max) * 100}%"></div></div><span class="val">${fmtN(v)}</span></div>`).join("")}</div>`;
  }

  function ring(score, grade) {
    const r = 36, c = 2 * Math.PI * r;
    const color = score >= 90 ? "var(--ok)" : score >= 60 ? "var(--med)" : score >= 40 ? "var(--high)" : "var(--crit)";
    return `<svg class="ring" viewBox="0 0 88 88" role="img" aria-label="Score ${score} of 100, grade ${grade}">
      <circle cx="44" cy="44" r="${r}" fill="none" stroke="var(--bg-3)" stroke-width="8"/>
      <circle cx="44" cy="44" r="${r}" fill="none" stroke="${color}" stroke-width="8" stroke-linecap="round" stroke-dasharray="${(score / 100) * c} ${c}" transform="rotate(-90 44 44)"/>
      <text x="44" y="46" text-anchor="middle" font-size="24" font-weight="800" fill="var(--text)" font-family="Inter">${grade}</text>
      <text x="44" y="62" text-anchor="middle" font-size="10" fill="var(--muted)" font-family="Inter">${score}/100</text></svg>`;
  }

  // ── workspace rendering ─────────────────────────────────────────────────
  function renderAll() {
    renderTabs();
    setMarkers();
    renderScorecard();
    ({ overview: renderOverview, findings: renderFindings, plan: renderPlan, graph: renderGraph, compliance: renderCompliance, docs: renderDocs }[S.tab] || (() => {}))();
  }

  function renderScorecard() {
    const r = S.report;
    if (!r) return;
    const counts = SEVS.map((s) => `<span class="count"><span class="sevdot" style="background:${sevColor(s)}"></span><b>${r.summary[s] || 0}</b>${s.toLowerCase()}</span>`).join("");
    $("#scorecard").innerHTML = `
      <div class="grade g-${r.grade}">${r.grade}<small>${r.score}/100</small></div>
      <div>
        <div class="verdict ${r.verdict.will_apply ? "ok" : "bad"}">${r.verdict.will_apply ? "Expected to apply" : "Apply is expected to fail"}
          ${r.passed ? `<span class="pill ok">Policy passed</span>` : `<span class="pill bad">Policy failed at ${esc(r.fail_on)}</span>`}</div>
        <div class="counts">${counts}<span class="count">${r.waived} waived</span><span class="count">${r.fixable} fixable</span><span class="count">${r.stats.files} files · ${r.stats.resources} resources · ${r.ms} ms</span></div>
      </div>`;
  }

  const VALIDATION = [
    ["TG-VAL-001", "HCL syntax parses"],
    ["TG-VAL-002", "No duplicate resources, variables, outputs, modules or locals"],
    ["TG-VAL-003", "Every reference resolves (var, local, module, data, resource)"],
    ["TG-VAL-007", "count and for_each are not combined"],
    ["TG-VAL-004", "CIDR blocks are valid network addresses"],
    ["TG-VAL-005", "S3 bucket names follow AWS naming rules"],
    ["TG-VAL-006", "Port ranges are not inverted"],
    ["TG-AWS-LAMBDA-002", "Lambda runtimes are supported"],
  ];

  function renderOverview() {
    const r = S.report;
    if (!r) return;
    const active = r.findings.filter((f) => !f.waived);
    const blocking = new Set(active.filter((f) => f.blocking).map((f) => f.rule_id));
    const warn = active.filter((f) => ["TG-VAL-008", "TG-VAL-009", "TG-STATE-001", "TG-TF-001", "TG-TF-003"].includes(f.rule_id));
    const comp = r.compliance || [];
    $("#tab-overview").innerHTML = `
      <div class="dash">
        <div class="tile w8"><h4>Posture</h4>
          <div class="hero-tile">${ring(r.score, r.grade)}
            <div><div class="verdict ${r.verdict.will_apply ? "ok" : "bad"}">${r.verdict.will_apply ? "Expected to apply" : "Apply is expected to fail"}</div>
              <p class="hint">${esc(r.verdict.message)}</p>
              ${(r.gate_failures || []).map((g) => `<p class="hint" style="color:var(--crit);margin:0 0 4px">Gate: ${esc(g)}</p>`).join("")}
              <div class="kpis">${SEVS.map((s) => `<div><div class="kpi">${r.summary[s] || 0}</div><div class="kpi-label"><span class="sevdot" style="background:${sevColor(s)}"></span>${s.toLowerCase()}</div></div>`).join("")}</div></div></div></div>
        <div class="tile w4"><h4>Fix</h4><div class="kpi">${r.fixable}</div><div class="kpi-label">findings fixable in one click</div>
          <div class="row">${r.fixable ? `<button class="btn primary sm" data-fixall>Fix all</button>` : ""}<button class="btn sm" data-ai-fix>AI fix (verified)</button></div></div>
        <div class="tile"><h4>Will it apply?</h4><ul class="checks">
          ${VALIDATION.map(([id, label]) => `<li><span class="status ${blocking.has(id) ? "fail" : "pass"}">${blocking.has(id) ? "Fail" : "Pass"}</span><span>${label}</span></li>`).join("")}
          ${warn.slice(0, 4).map((f) => `<li><span class="status warn">Warn</span><span>${esc(f.message)}</span></li>`).join("")}</ul>
          <p class="hint" style="margin:10px 0 0">Provider-side checks (quotas, permissions, name availability) need a real plan. Add one in the Plan tab.</p></div>
        <div class="tile"><h4>Top risks</h4>${active.length ? `<ul class="toplist">${active.slice(0, 8).map((f) => `<li><span class="sev ${f.severity}">${f.severity}</span><span class="grow">${esc(f.title)}</span><button class="loc" data-jump="${esc(f.file)}" data-line="${f.line || 0}">${esc(f.file)}${f.line ? ":" + f.line : ""}</button></li>`).join("")}</ul>` : `<div class="empty-sm">No active findings.</div>`}</div>
        <div class="tile"><h4>Findings by category</h4>${bars(Object.entries(r.by_category || {}).sort((a, b) => b[1] - a[1]), { label: (k) => CATEGORY[k] || k, empty: "No active findings." })}</div>
        <div class="tile"><h4>Resources by provider</h4>${bars(Object.entries(r.providers || {}).sort((a, b) => b[1] - a[1]), { label: (k) => CLOUDS[k] || k, empty: "No resources yet." })}</div>
        <div class="tile w12"><h4>Compliance</h4><div class="kpis">${comp.map((c) => `<div><div class="kpi">${c.passing}/${c.total}</div><div class="kpi-label">${esc(c.name)}</div></div>`).join("")}</div>
          <p class="hint" style="margin:10px 0 0">Controls with no failing evidence. <button class="loc" data-tab-go="compliance">View controls</button></p></div>
        ${r.plan ? `<div class="tile w12"><h4>Plan</h4><div class="kpis"><div><div class="kpi">${r.plan.create}</div><div class="kpi-label">to add</div></div><div><div class="kpi">${r.plan.update}</div><div class="kpi-label">to change</div></div><div><div class="kpi" style="color:var(--crit)">${r.plan.delete}</div><div class="kpi-label">to destroy</div></div><div><div class="kpi" style="color:var(--high)">${r.plan.replace}</div><div class="kpi-label">to replace</div></div></div></div>` : ""}
      </div>`;
  }

  function findingCard(f, i, isAI) {
    const loc = f.file ? `${f.file}${f.line ? ":" + f.line : ""}` : "";
    const issueURL = `${REPO_URL}/issues/new?template=false_positive.yml&title=${encodeURIComponent(`False positive: ${f.rule_id}`)}`;
    return `<article class="finding ${f.severity} ${f.waived ? "waived" : ""}">
      <div class="f-head">
        <span class="sev ${f.severity}">${f.severity}</span>
        <span class="f-title">${esc(f.title)}</span>
        <span class="rid">${esc(f.rule_id)}</span>
        ${f.blocking ? `<span class="badge block">Blocks apply</span>` : ""}
        ${isAI ? `<span class="badge ai">AI suggestion</span>` : `<span class="badge">${esc(CATEGORY[f.category] || f.category)}</span>`}
        ${f.cwe ? `<span class="badge">${esc(f.cwe)}</span>` : ""}
      </div>
      <p>${esc(f.message)}</p>
      ${loc ? `<button class="loc" data-jump="${esc(f.file)}" data-line="${f.line || 0}">${esc(loc)}</button>` : ""}
      ${f.resource ? ` <span class="rid">${esc(f.resource)}</span>` : ""}
      ${f.remediation ? `<p class="remedy">Fix: ${esc(f.remediation)}</p>` : ""}
      ${f.owner || f.docs ? `<p class="remedy">${f.owner ? `Owner: ${esc(f.owner)}` : ""}${f.owner && f.docs ? " · " : ""}${f.docs && /^https?:\/\//.test(f.docs) ? `<a href="${esc(f.docs)}" target="_blank" rel="noopener">Standard</a>` : ""}</p>` : ""}
      ${f.waived ? `<p class="remedy">Waived: ${esc(f.waiver_reason)}</p>` : ""}
      <div class="f-actions">
        ${f.fix && !f.waived ? `<button class="btn primary sm" data-fix="${i}">${esc(f.fix.description)}</button>` : ""}
        <button class="btn sm" data-ask="${isAI ? "ai" : ""}${i}">Explain</button>
        ${!isAI && f.file && models[f.file] && f.line ? `<button class="btn sm" data-ignore="${i}">Ignore here</button>` : ""}
        ${!isAI ? `<button class="btn sm" data-waive="${i}">Add waiver</button><a class="btn sm ghost" href="${issueURL}" target="_blank" rel="noopener">Report false positive</a>` : ""}
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
    $("#cloud-chips").innerHTML = clouds.length ? `<button class="chip ${!S.filter.cloud ? "on" : ""}" data-cloud="">All providers</button>` + clouds.map(([c, n]) => `<button class="chip ${S.filter.cloud === c ? "on" : ""}" data-cloud="${esc(c)}">${esc(CLOUDS[c] || c)} ${n}</button>`).join("") : "";
    $("#btn-fixall").disabled = !r?.fixable;
    $("#btn-fixall").textContent = `Fix all (${r?.fixable || 0})`;
    if (!Object.keys(S.files).length && !S.plan) {
      $("#findings-list").innerHTML = `<div class="empty">Paste Terraform into the editor, drop a folder, or load an example.</div>`;
      return;
    }
    const rows = (r?.findings || []).map((f, i) => [f, i]).filter(([f]) => matches(f));
    const ai = S.aiFindings.map((f, i) => [f, i]).filter(([f]) => matches(f));
    $("#findings-list").innerHTML = rows.length || ai.length
      ? rows.map(([f, i]) => findingCard(f, i, false)).join("") + ai.map(([f, i]) => findingCard(f, i, true)).join("")
      : `<div class="empty">${r?.findings.length ? "No findings match the filters." : "No findings. Clean scan."}</div>`;
  }

  function renderPlan() {
    const p = S.report?.plan;
    if (!p) {
      $("#plan-view").innerHTML = (S.report?.errors || []).filter((e) => /plan/i.test(e)).map((e) => `<div class="msg error">${esc(e)}</div>`).join("");
      return;
    }
    const risky = S.report.findings.filter((f) => f.category === "plan");
    $("#plan-view").innerHTML = `
      <div class="plan-bars">
        <div class="plan-stat create"><b>${p.create}</b>to add</div><div class="plan-stat"><b>${p.update}</b>to change</div>
        <div class="plan-stat delete"><b>${p.delete}</b>to destroy</div><div class="plan-stat replace"><b>${p.replace}</b>to replace</div>
      </div>
      ${risky.length ? `<div class="list">${risky.map((f) => findingCard(f, S.report.findings.indexOf(f), false)).join("")}</div>` : `<p class="hint">No destructive changes.</p>`}
      <h3 class="sec">Changes</h3>
      <table><thead><tr><th>Action</th><th>Address</th><th>Forced by</th></tr></thead><tbody>
      ${(p.changes || []).map((c) => `<tr><td><span class="act ${c.action}">${c.action === "delete" ? "destroy" : c.action}</span></td><td class="mono">${esc(c.address)}</td><td class="mono">${esc((c.reasons || []).join(", "))}</td></tr>`).join("")}
      </tbody></table>`;
  }

  function renderGraph() {
    const g = S.report?.graph;
    if (!g) return;
    if (!window.cytoscape) { $("#graph").innerHTML = `<div class="empty">Loading graph</div>`; setTimeout(renderGraph, 400); return; }
    const pathNodes = new Set();
    for (const f of S.report.findings) if (f.category === "attack-path" && !f.waived) (f.related || []).forEach((n) => pathNodes.add(n));
    graph?.destroy();
    graph = null;
    if (!g.nodes.length) { $("#graph").innerHTML = `<div class="empty">No resources yet.</div>`; return; }
    $("#graph").innerHTML = "";
    const ink = isDark() ? "#b4bfd1" : "#3b4658", edge = isDark() ? "#2f3a4f" : "#cfd6e1";
    graph = cytoscape({
      container: $("#graph"),
      elements: [
        ...g.nodes.map((n) => ({ data: { id: n.id, label: n.id, color: SEV_HEX[n.severity] || "#94a3b8", file: n.file, line: n.line, path: pathNodes.has(n.id) } })),
        ...g.edges.map((e) => ({ data: { id: e.source + ">" + e.target, source: e.source, target: e.target, path: pathNodes.has(e.source) && pathNodes.has(e.target) } })),
      ],
      layout: { name: "cose", animate: false, padding: 24, nodeRepulsion: 9000 },
      style: [
        { selector: "node", style: { "background-color": "data(color)", label: "data(label)", color: ink, "font-size": 9, "text-valign": "bottom", "text-margin-y": 4, width: 16, height: 16 } },
        { selector: "node[?path]", style: { "border-color": "#d92d20", "border-width": 3, width: 22, height: 22 } },
        { selector: "edge", style: { width: 1.2, "line-color": edge, "target-arrow-color": edge, "target-arrow-shape": "triangle", "curve-style": "bezier", "arrow-scale": 0.8 } },
        { selector: "edge[?path]", style: { "line-color": "#d92d20", "target-arrow-color": "#d92d20", width: 2.5 } },
      ],
    });
    graph.on("tap", "node", (e) => jump(e.target.data("file"), e.target.data("line")));
  }

  function renderCompliance() {
    $("#tab-compliance").innerHTML = `
      <p class="hint">Indicative mapping of findings to framework controls. A control fails when an active finding is evidence against it. Use it to prepare for audits; it is not a certification.</p>
      ${(S.report?.compliance || []).map((fw) => `
        <h3 class="sec">${esc(fw.name)} <span class="pill ${fw.passing === fw.total ? "ok" : "bad"}">${fw.passing}/${fw.total} clear</span></h3>
        <table><thead><tr><th style="width:130px">Control</th><th>Area</th><th style="width:110px">Status</th><th>Evidence</th></tr></thead><tbody>
        ${fw.controls.map((c) => `<tr><td class="mono">${esc(c.id)}</td><td>${esc(c.theme)}</td>
          <td><span class="status ${c.findings ? "fail" : "pass"}">${c.findings ? `${c.findings} failing` : "Clear"}</span></td>
          <td>${(c.rules || []).map((id) => `<button class="loc" data-filter-rule="${esc(id)}">${esc(id)}</button>`).join(" ")}</td></tr>`).join("")}
        </tbody></table>`).join("")}`;
  }

  function renderDocs() {
    if (!window.terraguard) return;
    S.docs = $("#docs-kind").value === "agents" ? terraguard.agentsMD(JSON.stringify(input())) : terraguard.docs(JSON.stringify({ files: S.files }));
    $("#docs-view").innerHTML = md(S.docs);
  }

  function renderRules() {
    const rules = JSON.parse(terraguard.rules("{}"));
    $("#rules-list").innerHTML = `
      <p class="hint">${rules.length} built-in rules. The same catalog runs in the browser, CLI, GitHub Action, VS Code, MCP server and self-hosted server. <a href="${REPO_URL}/blob/main/CONTRIBUTING.md#adding-a-rule" target="_blank" rel="noopener">Add a rule</a></p>
      <input type="search" id="rules-q" placeholder="Search rules, providers or controls" style="width:100%;margin-bottom:10px">
      <table><thead><tr><th>ID</th><th>Severity</th><th>Rule</th></tr></thead><tbody id="rules-body">
      ${rules.map((r) => `<tr data-search="${esc([r.id, r.title, r.remediation, (r.resource_types || []).join(" "), (r.compliance_themes || []).join(" ")].join(" ").toLowerCase())}"><td class="mono">${esc(r.id)}</td><td><span class="sev ${r.severity}">${r.severity}</span></td><td><b>${esc(r.title)}</b>${r.blocking ? ` <span class="badge block">Blocks apply</span>` : ""} <span class="badge">${esc(CATEGORY[r.category] || r.category)}</span><div class="remedy">${esc(r.remediation)}</div></td></tr>`).join("")}
      </tbody></table>`;
    $("#rules-q").oninput = (e) => {
      const q = e.target.value.toLowerCase();
      $$("#rules-body tr").forEach((tr) => (tr.hidden = q && !tr.dataset.search.includes(q)));
    };
  }

  function renderCICD() {
    if (!$("#ci-dir")) {
      $("#tab-cicd").innerHTML = `
        <p class="hint">Generate a GitOps pipeline for your Terraform repository. It runs only when Terraform files change; nothing is scheduled unless you opt in.</p>
        <div class="cicd-opts">
          <label>Terraform directory <input id="ci-dir" value="."></label>
          <label>Fail the PR on <select id="ci-failon">${["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"].map((s) => `<option ${s === "HIGH" ? "selected" : ""}>${s}</option>`).join("")}</select></label>
          <label>Cloud credentials <select id="ci-cloud"><option value="aws">AWS via OIDC (no stored keys)</option><option value="none">None or provider secrets</option></select></label>
          <label>OIDC role ARN <input id="ci-role" placeholder="arn:aws:iam::123456789012:role/terraform-plan"></label>
          <label>AWS region <input id="ci-region" value="us-east-1"></label>
          <label>AI summary in PR comment <select id="ci-ai"><option value="">Off</option><option value="groq">Groq</option><option value="openrouter">OpenRouter</option><option value="gemini">Gemini</option></select></label>
          <label class="check"><input type="checkbox" id="ci-plan" checked> Run terraform plan and analyze it</label>
          <label class="check"><input type="checkbox" id="ci-apply"> Apply on merge to main, with approval</label>
          <label class="check"><input type="checkbox" id="ci-drift"> Daily drift detection (scheduled, opt-in)</label>
        </div>
        <div class="row"><button class="btn primary sm" data-copy="ci-yaml">Copy workflow</button><span class="hint inline">Save as <code>.github/workflows/terraform.yml</code></span></div>
        <pre class="code" id="ci-yaml"></pre>
        <h3 class="sec">CLI, agent and pre-commit</h3>
        <div class="row"><button class="btn sm" data-copy="ci-cli">Copy</button></div><pre class="code" id="ci-cli"></pre>
        <h3 class="sec">MCP server for AI coding agents</h3>
        <div class="row"><button class="btn sm" data-copy="ci-mcp">Copy</button></div><pre class="code" id="ci-mcp"></pre><pre class="code" id="ci-mcp-json"></pre>
        <h3 class="sec">Docker and self-hosting</h3><pre class="code" id="ci-self"></pre>`;
      $$("#tab-cicd input, #tab-cicd select").forEach((el) => el.addEventListener("input", renderCICD));
    }
    $("#ci-yaml").textContent = CICD.workflow({
      dir: $("#ci-dir").value, cloud: $("#ci-cloud").value, role: $("#ci-role").value, region: $("#ci-region").value,
      failOn: $("#ci-failon").value, plan: $("#ci-plan").checked, apply: $("#ci-apply").checked, drift: $("#ci-drift").checked, ai: $("#ci-ai").value,
    });
    $("#ci-cli").textContent = CICD.cli();
    $("#ci-mcp").textContent = CICD.mcpClaude();
    $("#ci-mcp-json").textContent = "// Cursor / Claude Desktop (mcp.json)\n" + CICD.mcpJson();
    $("#ci-self").textContent = CICD.selfHost();
  }

  // ── product page: live usage and GitHub stats ───────────────────────────
  async function renderLiveStats() {
    const url = AI.server() ? "api/stats" : CFG.statsUrl ? CFG.statsUrl.replace(/\/$/, "") + "/stats" : null;
    if (!url) return;
    let st;
    try { st = await (await fetch(url, { cache: "no-store" })).json(); } catch { return; }
    const t = st.today || {}, tot = st.total || {};
    const days = st.days || [];
    const max = Math.max(1, ...days.map((d) => d.files || 0));
    const box = $("#live-stats");
    box.hidden = false;
    box.innerHTML = `
      <h3 class="sec"><span class="live-dot"></span>Live usage · ${fmtN(st.active_now)} active now <span class="hint inline">${st.source === "server" ? "this server" : "all users"} · anonymous counts</span></h3>
      <div class="metrics">
        <div class="metric"><b>${fmtN(t.files)}</b><span>Terraform files checked today</span></div>
        <div class="metric"><b>${fmtN(t.resources)}</b><span>resources analyzed today</span></div>
        <div class="metric"><b>${fmtN(tot.files)}</b><span>files checked in total</span></div>
      </div>
      <div class="card"><h3>Files checked, last 7 days</h3><div class="cols">${days.map((d) => `<div class="col" title="${d.date}: ${fmtN(d.files)} files, ${fmtN(d.scans)} evaluations"><span class="n">${fmtN(d.files)}</span><div class="stick" style="height:${((d.files || 0) / max) * 80}%"></div><span class="d">${new Date(d.date + "T00:00:00Z").toLocaleDateString(undefined, { weekday: "short", timeZone: "UTC" })}</span></div>`).join("")}</div></div>`;
  }

  async function renderGitHub() {
    let data;
    try { data = JSON.parse(sessionStorage.getItem("tg.gh") || "null"); } catch {}
    if (!data || Date.now() - data.at > 600000) {
      try {
        const [repo, contrib] = await Promise.all([
          fetch(`https://api.github.com/repos/${REPO}`).then((r) => (r.ok ? r.json() : null)),
          fetch(`https://api.github.com/repos/${REPO}/contributors?per_page=100`).then((r) => (r.ok ? r.json() : [])),
        ]);
        if (!repo) return;
        data = { at: Date.now(), stars: repo.stargazers_count, forks: repo.forks_count, issues: repo.open_issues_count, contributors: Array.isArray(contrib) ? contrib.length : 0 };
        try { sessionStorage.setItem("tg.gh", JSON.stringify(data)); } catch {}
      } catch { return; }
    }
    $("#gh-stats").innerHTML = [[data.stars, "stars"], [data.forks, "forks"], [data.contributors, "contributors"], [data.issues, "open issues and PRs"]]
      .map(([v, l]) => `<div class="metric"><b>${fmtN(v)}</b><span>${l}</span></div>`).join("");
    if (data.stars > 0) $$(".gh-stars").forEach((el) => (el.textContent = `GitHub · ${fmtN(data.stars)}`));
  }

  function mountGiscus() {
    const g = CFG.giscus || {};
    if (!g.repoId || !g.categoryId) return;
    const sc = document.createElement("script");
    Object.entries({ src: "https://giscus.app/client.js", "data-repo": REPO, "data-repo-id": g.repoId, "data-category": g.category || "General", "data-category-id": g.categoryId,
      "data-mapping": "specific", "data-term": "TerraGuard", "data-reactions-enabled": "1", "data-input-position": "top", "data-theme": isDark() ? "dark" : "light", "data-loading": "lazy", crossorigin: "anonymous" })
      .forEach(([k, v]) => sc.setAttribute(k, v));
    sc.async = true;
    $("#giscus-box").appendChild(sc);
  }

  // ── AI assistant ────────────────────────────────────────────────────────
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

  const SYSTEM = `You are TerraGuard's assistant: a senior platform engineer who knows Terraform/OpenTofu and AWS, Google Cloud, Azure, Cloudflare, DigitalOcean, Hetzner, OVH, Oracle Cloud and Kubernetes.
You only explain and suggest; TerraGuard's deterministic findings decide pass or fail. Be concise and concrete. Do not use emojis.
When you change Terraform, return the COMPLETE updated file in one \`\`\`hcl block whose first line is a comment "# file: <name>".
Prefer least privilege, encryption, private networking and pinned versions. Never invent resource arguments; say so when unsure.`;

  function renderChat() {
    const st = AI.status();
    $("#ai-provider-label").textContent = st.label;
    $("#ai-provider-label").className = "pill " + (st.ready ? (st.private ? "ok" : "") : "muted");
    $("#chat-log").innerHTML = S.chat.length ? S.chat.map((m, i) => `
      <div class="msg ${m.role} ${m.error ? "error" : ""}">${m.role === "user" || m.error ? esc(m.content) : md(m.content)}
        ${m.role === "assistant" && /```(hcl|terraform)/.test(m.content) ? `<div class="row"><button class="btn primary sm" data-apply-ai="${i}">Verify and apply</button></div>` : ""}
        ${m.meta ? `<div class="meta">${esc(m.meta)}</div>` : ""}</div>`).join("")
      : `<div class="empty">Ask about your Terraform. The assistant sees your files and the engine's findings.<br><br>
          AI is optional: every scan, fix and validation works without it. Use a free key from Groq, OpenRouter or Gemini, or a local model so nothing leaves your machine.</div>`;
    $("#chat-log").scrollTop = $("#chat-log").scrollHeight;
  }

  async function ask(text, { silent = false } = {}) {
    showTab("ai");
    S.chat.push({ role: "user", content: text }, { role: "assistant", content: "", pending: true });
    renderChat();
    $("#chat-log").lastElementChild.classList.add("typing");
    const history = S.chat.filter((m) => !m.pending && !m.error).slice(-12).map(({ role, content }) => ({ role, content }));
    try {
      const r = await AI.chat([{ role: "system", content: SYSTEM + "\n\n" + contextBlock() }, ...history]);
      count("ai");
      Object.assign(S.chat.at(-1), { content: r.text, pending: false, meta: `${r.provider} · ${r.model}${r.tried?.length ? ` · after ${r.tried.length} fallback(s)` : ""}` });
      return r.text;
    } catch (e) {
      Object.assign(S.chat.at(-1), { content: e.message, pending: false, error: true });
      if (!silent) toast("AI request failed. Details are in the Assistant tab.");
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
    test: () => `Write a Terraform native test file (tests/main.tftest.hcl, terraform >= 1.6) for ${S.active || "this configuration"}: use command = plan runs and assert blocks that verify encryption, public access and IAM settings. Return it with "# file: tests/main.tftest.hcl".`,
    cost: "Review this configuration for cost: oversized or previous-generation instances, gp2 volumes, NAT gateways, unbounded log retention, missing lifecycle rules, idle resources. Estimate monthly impact where you can and state your confidence.",
    migrate: () => { const w = prompt("Which provider upgrade?", "hashicorp/aws v4 to v5"); return w && `I'm upgrading ${w}. List the breaking changes that affect THIS configuration and return the updated files.`; },
    generate: () => { const w = prompt("What should the module create?", "A private S3 bucket for logs with KMS encryption, versioning and lifecycle to Glacier after 90 days"); return w && `Generate production-ready Terraform for: ${w}. Pin provider versions, follow TerraGuard rules, include variables with descriptions and outputs. Return one file named generated.tf.`; },
    explainplan: () => (S.plan ? "Explain this terraform plan for a reviewer: what changes, what is risky (destroys/replacements and why), and what to check before approving." : (toast("Add a plan first"), null)),
  };

  // AI proposes, the engine decides: changes to existing files are kept only if
  // engine.Verify (via WASM) accepts them. New files (tests, modules) are added as-is.
  function verifyAndApply(changed) {
    const existing = Object.fromEntries(Object.entries(changed).filter(([n]) => S.files[n] !== undefined));
    if (Object.keys(existing).length) {
      const v = JSON.parse(terraguard.verifyChange(JSON.stringify({ ...input(), changed: existing })));
      if (!v.ok) { toast(`Engine ${v.reason}. Nothing was changed.`); return false; }
      toast(`Engine ${v.reason}`);
    }
    for (const [n, c] of Object.entries(changed)) S.files[n] !== undefined ? setFileContent(n, c) : addFile(n, c);
    scanSoon();
    return true;
  }

  const extractFiles = (text) => Object.fromEntries([...text.matchAll(/```(?:hcl|terraform)?\s*\n([\s\S]*?)```/g)].map(([, code]) => {
    const name = (code.match(/^#\s*file:\s*(\S+)/m) || [])[1] || S.active || "main.tf";
    return [name, code.replace(/^#\s*file:.*\n/, "")];
  }));

  async function aiVerifiedFix() {
    const file = S.active;
    const list = (S.report?.findings || []).filter((f) => !f.waived && f.file === file);
    if (!file || !list.length) return toast("No active findings in this file");
    toast(`Asking the AI to fix ${list.length} finding(s) in ${file}. The engine will verify the result.`);
    const text = await ask(`Fix these findings in ${file} without changing behaviour or names. Return only the complete corrected file in one hcl block starting with "# file: ${file}".\n\n${list.map((f) => `- line ${f.line} [${f.rule_id}] ${f.title}: ${f.message}`).join("\n")}`, { silent: true });
    if (!text) return toast("AI request failed. See the Assistant tab.");
    const files = extractFiles(text);
    if (!files[file]) return toast("The AI did not return the file");
    verifyAndApply({ [file]: files[file] });
  }

  async function aiReview() {
    toast("Asking the AI for issues the rules cannot detect");
    const text = await ask(`Act as a reviewer looking for issues the deterministic findings above MISSED (logic errors, risky defaults, missing resources, cost or reliability traps). Respond ONLY with a JSON array of objects: {"severity":"CRITICAL|HIGH|MEDIUM|LOW|INFO","title":"","file":"","line":0,"message":"","remediation":""}. Return [] if nothing new.`, { silent: true });
    if (!text) return toast("AI review failed. See the Assistant tab.");
    try {
      S.aiFindings = JSON.parse(text.slice(text.indexOf("["), text.lastIndexOf("]") + 1))
        .map((f) => ({ ...f, rule_id: "AI-REVIEW", category: "ai", severity: SEVS.includes(String(f.severity).toUpperCase()) ? String(f.severity).toUpperCase() : "INFO" }));
      toast(`AI review added ${S.aiFindings.length} suggestion(s)`);
    } catch { toast("AI returned an unexpected format. See the Assistant tab."); }
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
  const fixAll = () => {
    const fixes = (S.report?.findings || []).filter((f) => f.fix && !f.waived).map((f) => f.fix);
    if (fixes.length) applyFixes(fixes);
  };

  function ignoreInline(f) {
    const m = models[f.file];
    const indent = (m.getLineContent(f.line).match(/^\s*/) || [""])[0];
    m.pushEditOperations([], [{ range: new monacoRef.Range(f.line, 1, f.line, 1), text: `${indent}# terraguard:ignore ${f.rule_id} -- reason: \n` }], () => null);
    jump(f.file, f.line);
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
    } catch { toast("Could not load the example"); }
  }

  async function readUploads(fileList) {
    let n = 0;
    for (const f of fileList) {
      const path = f.webkitRelativePath || f.name;
      if (!/\.(tf|tfvars|json|ya?ml)$|\.tfstate/.test(path) || /(^|\/)\.terraform\//.test(path)) continue;
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
    $$(".ws-nav button").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
    $$("#app .tab-body").forEach((el) => (el.hidden = el.id !== "tab-" + tab));
    if (tab === "rules" && !$("#rules-list").innerHTML) renderRules();
    if (tab === "cicd") renderCICD();
    if (tab === "ai") renderChat();
    if (tab === "graph") requestAnimationFrame(renderGraph);
    else renderAll();
  }

  // ── AI settings dialog ──────────────────────────────────────────────────
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
      openrouter: `Free key: <a href="${P.keyUrl}" target="_blank" rel="noopener">${P.keyUrl}</a>. Models ending in <code>:free</code> cost nothing.`,
      gemini: `Free key: <a href="${P.keyUrl}" target="_blank" rel="noopener">${P.keyUrl}</a>`,
      local: `Install <a href="https://ollama.com/download" target="_blank" rel="noopener">Ollama</a>, run <code>ollama pull llama3.2</code>, then start it with <code>OLLAMA_ORIGINS=${esc(location.origin)} ollama serve</code>. Your code never leaves this machine.`,
      server: srv ? `Connected. ${esc((srv.ai?.route || []).length)} route step(s)${srv.ai?.local_only ? ", local-only" : ""}.` : `Run <code>terraguard serve</code> and open the app from it. Keys stay in the server's <code>.env</code>.`,
    }[p];
    $$("#ai-provider option").forEach((o) => (o.disabled = s.private && AI.PROVIDERS[o.value].hosted));
  }

  function updatePrivacyPill() {
    const st = AI.status();
    const hosted = st.ready && !st.private;
    $("#privacy-pill").innerHTML = `${icon("lock", "ic sm")}${hosted ? "Code local · AI hosted" : "Code stays local"}`;
    $("#privacy-pill").title = hosted
      ? "Scans run on this device. When you ask the assistant, your files are sent to the selected AI provider."
      : "Your Terraform is analyzed on this device and never uploaded.";
  }

  // ── wiring ──────────────────────────────────────────────────────────────
  function wire() {
    addEventListener("hashchange", route);
    $$("[data-theme-toggle]").forEach((b) => (b.onclick = toggleTheme));
    $(".ws-nav").addEventListener("click", (e) => e.target.dataset.tab && showTab(e.target.dataset.tab));

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

    $("#btn-new").onclick = () => { const n = prompt("File name", "new.tf"); if (n && !S.files[n]) { addFile(n, ""); scan(); } };
    $("#upload").onchange = (e) => readUploads(e.target.files);
    $("#upload-dir").onchange = (e) => readUploads(e.target.files);
    $("#example-select").onchange = (e) => { if (e.target.value) loadExample(e.target.value); e.target.value = ""; };
    $("#btn-download").onclick = () => S.active && download(S.active, S.files[S.active]);
    $("#btn-format").onclick = () => {
      if (!S.active || !/\.(tf|tfvars)$/.test(S.active)) return;
      setFileContent(S.active, terraguard.fmt(S.files[S.active]));
      toast("Formatted");
    };
    $("#btn-docs-copy").onclick = () => { navigator.clipboard.writeText(S.docs || ""); toast("Copied"); };
    $("#btn-docs-download").onclick = () => download($("#docs-kind").value === "agents" ? "AGENTS.md" : "README.md", S.docs || "", "text/markdown");
    $("#docs-kind").onchange = renderDocs;

    const ed = $("#editor");
    ed.addEventListener("dragover", (e) => { e.preventDefault(); ed.classList.add("dragging"); });
    ed.addEventListener("dragleave", () => ed.classList.remove("dragging"));
    ed.addEventListener("drop", async (e) => {
      e.preventDefault();
      ed.classList.remove("dragging");
      const files = [];
      const walk = async (entry, prefix = "") => {
        if (entry.isFile) files.push(new File([await new Promise((r) => entry.file(r))], prefix + entry.name));
        else if (entry.isDirectory && entry.name !== ".terraform" && entry.name !== ".git") {
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
      if (c) { S.filter.cloud = c.dataset.cloud; renderFindings(); }
    };

    // Actions on finding cards and tiles, shared across tabs.
    document.addEventListener("click", (e) => {
      const el = e.target.closest("[data-jump],[data-fix],[data-fixall],[data-ai-fix],[data-ignore],[data-waive],[data-ask],[data-apply-ai],[data-copy],[data-q],[data-tab-go],[data-filter-rule]");
      if (!el) return;
      const d = el.dataset;
      const all = S.report?.findings || [];
      if (d.jump !== undefined) jump(d.jump, +d.line);
      else if (d.fix !== undefined) applyFixes([all[+d.fix].fix]);
      else if (d.fixall !== undefined) fixAll();
      else if (d.aiFix !== undefined) aiVerifiedFix();
      else if (d.ignore !== undefined) ignoreInline(all[+d.ignore]);
      else if (d.waive !== undefined) addWaiver(all[+d.waive]);
      else if (d.ask !== undefined) {
        const f = d.ask.startsWith("ai") ? S.aiFindings[+d.ask.slice(2)] : all[+d.ask];
        ask(`Explain finding ${f.rule_id} "${f.title}" at ${f.file}:${f.line} (${f.resource || ""}): ${f.message}\nWhy does it matter, how would it be exploited or cause an outage, and what exact Terraform change fixes it? Note side effects such as forced replacement.`);
      } else if (d.applyAi !== undefined) verifyAndApply(extractFiles(S.chat[+d.applyAi].content));
      else if (d.copy) { navigator.clipboard.writeText($("#" + d.copy).textContent); toast("Copied"); }
      else if (d.tabGo) showTab(d.tabGo);
      else if (d.filterRule) { S.filter.q = d.filterRule; $("#filter-q").value = d.filterRule; showTab("findings"); }
      else if (d.q) { const q = typeof QUICK[d.q] === "function" ? QUICK[d.q]() : QUICK[d.q]; if (q) ask(q); }
    });

    $("#btn-fixall").onclick = fixAll;
    $("#btn-ai-review").onclick = aiReview;
    $("#btn-export").onclick = () => ($("#export-menu").hidden = !$("#export-menu").hidden);
    $("#export-menu").onclick = (e) => {
      const f = e.target.dataset.export;
      if (!f) return;
      $("#export-menu").hidden = true;
      download({ markdown: "terraguard-report.md", json: "terraguard-report.json", sarif: "terraguard.sarif", junit: "terraguard-junit.xml", codequality: "gl-code-quality.json" }[f], terraguard.render(JSON.stringify(input()), f));
    };

    $("#plan-input").oninput = (e) => { S.plan = e.target.value; scanSoon(); };
    $("#plan-upload").onchange = async (e) => { S.plan = await e.target.files[0].text(); $("#plan-input").value = S.plan; scan(); };
    $("#btn-plan-clear").onclick = () => { S.plan = ""; $("#plan-input").value = ""; scan(); };
    $("#policy-input").oninput = (e) => { S.config = e.target.value; scanSoon(); };
    $("#btn-policy-example").onclick = async () => { S.config = await (await fetch("examples/insecure/.terraguard.yml")).text(); $("#policy-input").value = S.config; scan(); };

    $("#chat-form").onsubmit = (e) => {
      e.preventDefault();
      const v = $("#chat-input").value.trim();
      if (v) { $("#chat-input").value = ""; ask(v); }
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
      Object.assign(s, { provider: p, private: $("#ai-private").checked, baseUrl: $("#ai-base").value.trim() || "http://localhost:11434/v1",
        serverToken: $("#ai-token").value.trim(), fallback: $("#ai-fallback").checked, telemetry: $("#ai-telemetry").checked });
      if (p !== "server") { s.models[p] = $("#ai-model").value.trim(); s.keys[p] = $("#ai-key").value.trim(); }
      AI.save(s);
      renderChat();
      updatePrivacyPill();
      toast("AI settings saved in this browser");
    };

    $("#btn-share").onclick = async () => {
      if (Object.values(S.files).join("").length > 60000) return toast("Too large for a link. Use Export instead.");
      const url = `${location.origin}${location.pathname}#s=${await encodeShare({ files: S.files, config: S.config })}`;
      await navigator.clipboard.writeText(url);
      toast("Link copied. The code is inside the link; nothing is uploaded.");
    };

    setInterval(() => flush(), 60000); // heartbeat keeps "active now" accurate
    addEventListener("pagehide", () => flush(true));
  }

  // ── boot ────────────────────────────────────────────────────────────────
  wire();
  route();
  AI.detectServer().then(renderLiveStats);
  renderGitHub();
  mountGiscus();
})();
