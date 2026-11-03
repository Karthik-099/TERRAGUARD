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
  const BRANDS = { aws: "aws", google: "gcp", azurerm: "azure", cloudflare: "cloudflare", digitalocean: "digitalocean", oci: "oracle", kubernetes: "kubernetes", helm: "helm" };
  const brandIcon = (c) => BRANDS[c] ? `<img class="brand-ic" src="assets/brands/${BRANDS[c]}.svg" alt="" width="16" height="16">` : "";
  const CATEGORY = { security: "Security", validate: "Validation", reliability: "Reliability", "best-practice": "Best practice", "attack-path": "Attack path", plan: "Plan risk", policy: "Policy", cost: "Cost" };
  const EXAMPLES = { insecure: ["main.tf", "variables.tf", "terraform.tfvars", ".terraguard.yml"], "aws-network": ["main.tf"], multicloud: ["main.tf"], secure: ["main.tf"],
    "beyond-terraform": ["deployment.yaml", "template.yaml", "Dockerfile", "docker-compose.yml", ".github/workflows/ci.yml"] };
  // assetsBase: serve libraries from this origin (air-gapped Docker image).
  const JSD = "https://cdn.jsdelivr.net/npm";
  const LOCAL = CFG.assetsBase ? CFG.assetsBase.replace(/\/$/, "") : "";
  const CDN = {
    monaco: LOCAL ? `${LOCAL}/monaco/min/vs` : `${JSD}/monaco-editor@0.52.2/min/vs`,
    cytoscape: LOCAL ? `${LOCAL}/cytoscape.min.js` : `${JSD}/cytoscape@3.30.2/dist/cytoscape.min.js`,
    marked: LOCAL ? `${LOCAL}/marked.min.js` : `${JSD}/marked@12.0.2/marked.min.js`,
    dompurify: LOCAL ? `${LOCAL}/purify.min.js` : `${JSD}/dompurify@3.1.6/dist/purify.min.js`,
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
  // Pinned CDN files carry Subresource Integrity hashes: a modified file is refused.
  const SRI = {
    "https://cdn.jsdelivr.net/npm/cytoscape@3.30.2/dist/cytoscape.min.js": "sha384-IWROdLKRsN1UuJywMlWl7/blXQ8GEooN2n7dzTxfEPd7ybYIKCUJ2Ol/1Gpf3YV4",
    "https://cdn.jsdelivr.net/npm/monaco-editor@0.52.2/min/vs/loader.js": "sha384-pHG02SG8pId94Np3AbPmBEJ1yPqaH0IkJGLSNGXYmuGhkazT8Lr/57WYpbkGjJtu",
    "https://cdn.jsdelivr.net/npm/marked@12.0.2/marked.min.js": "sha384-/TQbtLCAerC3jgaim+N78RZSDYV7ryeoBCVqTuzRrFec2akfBkHS7ACQ3PQhvMVi",
    "https://cdn.jsdelivr.net/npm/dompurify@3.1.6/dist/purify.min.js": "sha384-+VfUPEb0PdtChMwmBcBmykRMDd+v6D/oFmB3rZM/puCMDYcIvF968OimRh4KQY9a",
  };
  const scripts = {};
  const loadScript = (src) => (scripts[src] ||= new Promise((ok, fail) => {
    const s = document.createElement("script");
    s.src = src;
    if (SRI[src]) { s.integrity = SRI[src]; s.crossOrigin = "anonymous"; }
    s.onload = ok;
    s.onerror = () => { delete scripts[src]; fail(new Error(`failed to load ${src}`)); };
    document.head.appendChild(s);
  }));

  const S = {
    files: {}, active: null, config: "", plan: "", report: null, aiFindings: [], chat: [], activity: [],
    filter: { q: "", sev: new Set(), cloud: "" }, tab: "overview",
    session: { scans: 0, files: 0, resources: 0, fixes: 0, ai: 0 },
  };
  let editor, monacoRef, models = {}, graph, appReady;

  // Theme: dark by default, light is remembered.
  const isDark = () => document.documentElement.dataset.theme !== "light";
  function toggleTheme() {
    const next = isDark() ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("tg.theme.v2", next); } catch {}
    monacoRef?.editor.setTheme(next === "dark" ? "vs-dark" : "vs");
    if (S.tab === "graph") renderGraph();
  }

  // Persistence & share links
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
    const reader = new Blob([bin]).stream().pipeThrough(new DecompressionStream("deflate-raw")).getReader();
    const chunks = [];
    let size = 0;
    for (;;) { // cap the expanded size so a crafted link cannot exhaust memory
      const { done, value } = await reader.read();
      if (done) break;
      if ((size += value.length) > SHARE_MAX) { reader.cancel(); throw new Error("share link too large"); }
      chunks.push(value);
    }
    const obj = JSON.parse(await new Blob(chunks).text());
    const files = obj?.files;
    if (!files || typeof files !== "object" || Array.isArray(files) || Object.keys(files).length > 500
      || Object.entries(files).some(([k, v]) => typeof v !== "string" || k.length > 300 || /(^|\/)\.\.(\/|$)/.test(k))
      || (obj.config != null && typeof obj.config !== "string")) throw new Error("share link has an unexpected shape");
    return { files, config: obj.config || "" };
  }
  const SHARE_MAX = 5 << 20;

  function toast(msg) {
    const t = $("#toast");
    t.textContent = msg;
    t.classList.add("show");
    clearTimeout(t._h);
    t._h = setTimeout(() => t.classList.remove("show"), 3200);
  }

  // Anonymous usage counters (numbers only, never code)
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

  // Routing: product page <-> workspace
  const PAGES = ["home", "product", "ai", "policy", "compare", "integrations", "docs", "architecture", "open-source"];
  const inApp = () => location.hash.startsWith("#/app") || location.hash.startsWith("#s=");
  function route() {
    const app = inApp();
    $("#landing").hidden = app;
    $("#app").hidden = !app;
    document.body.classList.toggle("app-open", app);
    if (app) {
      appReady ||= enterApp();
      if (location.hash.includes("demo")) appReady.then(() => { fillSettings(); $("#settings").showModal(); });
      return;
    }
    let name = (location.hash.match(/^#\/([\w-]+)/) || [])[1];
    // the old Enterprise page now lives under Integrations ("Run it anywhere")
    const anchor = name === "enterprise" ? "deploy" : (location.hash.match(/\?([\w-]+)$/) || [])[1];
    if (name === "enterprise") name = "integrations";
    const page = PAGES.includes(name) ? name : "home";
    $$("#landing .page").forEach((p) => (p.hidden = p.dataset.page !== page));
    $$(".nav-links a").forEach((a) => a.classList.toggle("on", a.getAttribute("href") === `#/${page}`));
    document.title = page === "home" ? "TerraGuard: open-source Terraform security scanner and validator" : `${$(`.nav-links a[href="#/${page}"]`)?.textContent || "TerraGuard"} · TerraGuard`;
    if (page === "docs") renderDoc((location.hash.match(/^#\/docs\/([\w-]+)/) || [])[1] || "guide");
    const target = anchor && document.getElementById(anchor);
    if (target) requestAnimationFrame(() => target.scrollIntoView({ behavior: "instant" }));
    else scrollTo({ top: 0, behavior: "instant" });
  }

  // Documentation: the repository's Markdown, rendered in the site
  const DOCS = {
    guide: "GUIDE.md", reference: "REFERENCE.md", limits: "LIMITS.md", rules: "RULES.md", "self-hosting": "SELF_HOSTING.md",
    security: "SECURITY.md", academy: "ACADEMY.md", architecture: "ARCHITECTURE.md", contributing: "CONTRIBUTING.md",
  };
  const DOC_SLUG = Object.fromEntries(Object.entries(DOCS).map(([k, v]) => [v, k]));
  const REPO_DOC = (file) => `https://github.com/${CFG.repo}/blob/main/${["SECURITY.md", "CONTRIBUTING.md"].includes(file) ? "" : "docs/"}${file}`;
  async function renderDoc(slug) {
    const file = DOCS[slug] || DOCS.guide, body = $("#docs-body");
    $$(".docs-nav [data-doc]").forEach((a) => a.classList.toggle("on", a.dataset.doc === (DOCS[slug] ? slug : "guide")));
    $("#docs-edit").href = REPO_DOC(file);
    try {
      const [res] = await Promise.all([fetch(`docs/${file}`), loadScript(CDN.marked), loadScript(CDN.dompurify)]);
      if (!res.ok) throw new Error(res.status);
      // Diagrams are Mermaid source; link to GitHub, which renders them.
      const text = (await res.text()).replace(/```mermaid[\s\S]*?```/g, `> Diagram: [view it on GitHub](${REPO_DOC(file)}).`);
      body.innerHTML = DOMPurify.sanitize(marked.parse(text));
    } catch {
      body.innerHTML = `<p>Could not load this page. Read it on <a href="${esc(REPO_DOC(file))}" target="_blank" rel="noopener">GitHub</a>.</p>`;
      return;
    }
    addCopyButtons(body);
    // Links between docs stay in the site; other repository links open GitHub.
    for (const a of $$("a[href]", body)) {
      const href = a.getAttribute("href"), name = href.split("#")[0].split("/").pop();
      if (/^https?:/.test(href)) { a.target = "_blank"; a.rel = "noopener"; }
      else if (href.startsWith("#") && !href.startsWith("#/")) a.onclick = (e) => { e.preventDefault(); document.getElementById(href.slice(1))?.scrollIntoView({ behavior: "smooth" }); };
      else if (DOC_SLUG[name]) a.href = `#/docs/${DOC_SLUG[name]}`;
      else if (!href.startsWith("#")) { a.href = `https://github.com/${CFG.repo}/blob/main/${href.replace(/^(\.\.\/)+/, "")}`; a.target = "_blank"; a.rel = "noopener"; }
    }
  }

  // Engine & editor (loaded only when the workspace opens)
  let enginePromise;
  const bootEngine = () => (enginePromise ||= loadEngine());
  async function loadEngine() {
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
    try {
      // Load UMD libraries before Monaco's AMD loader, or they register with its define().
      await Promise.all([loadScript(CDN.marked), loadScript(CDN.dompurify), loadScript(CDN.cytoscape)]);
      await Promise.all([bootEngine(), bootEditor()]);
    } catch (e) {
      $("#engine-status").textContent = "Engine failed to load";
      $("#engine-status").className = "pill bad";
      console.error(e);
      return;
    }
    updatePrivacyPill();
    let tried = null;
    try { tried = JSON.parse(sessionStorage.getItem("tg.try")); sessionStorage.removeItem("tg.try"); } catch {}
    const state = shared || tried || restore();
    if (LOCAL_TOKEN && await loadLocal()) {
      addEventListener("focus", () => loadLocal(true)); // pick up edits made in another editor
    } else if (state && Object.keys(state.files || {}).length) {
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

  const input = () => ({ files: S.files, plan: S.plan, config: S.config, coverage: true });

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

  // Files
  const langOf = (n) => (n.endsWith(".json") ? "json" : /\.ya?ml$/.test(n) ? "yaml" : /(^|\/)(Dockerfile|Containerfile)|\.dockerfile$/i.test(n) ? "dockerfile" : "hcl");

  function setFiles(files, active) {
    for (const m of Object.values(models)) m.dispose();
    models = {};
    S.files = {};
    for (const [n, c] of Object.entries(files)) addFile(n, c, false);
    openFile(active && S.files[active] !== undefined ? active : Object.keys(S.files)[0] || null);
  }

  function addFile(name, content, open = true) {
    if (name === POLICY_FILE || name.endsWith("/" + POLICY_FILE)) { S.config = content; $("#policy-input").value = content; return; }
    // Only plan JSON goes to the Plan tab; CloudFormation and ARM templates are files.
    if (name.endsWith(".json") && !name.endsWith(".tf.json") && /"(resource_changes|planned_values)"/.test(content.slice(0, 200000))) { S.plan = content; $("#plan-input").value = content; return; }
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

  // Small chart helpers
  function bars(entries, { label = (k) => k, empty = "Nothing to show." } = {}) {
    if (!entries.length) return `<div class="empty-sm">${empty}</div>`;
    const max = Math.max(1, ...entries.map(([, v]) => v));
    return `<div class="bars">${entries.map(([k, v]) => `
      <div class="bar-row" title="${esc(label(k))}: ${fmtN(v)}"><span class="lbl">${esc(label(k))}</span>
        <div class="track"><div class="fill" style="width:${(v / max) * 100}%"></div></div><span class="val">${fmtN(v)}</span></div>`).join("")}</div>`;
  }

  // Workspace rendering
  function renderAll() {
    renderTabs();
    setMarkers();
    renderScorecard();
    ({ overview: renderOverview, findings: renderFindings, plan: renderPlan, graph: renderGraph, compliance: renderCompliance, docs: renderDocs }[S.tab] || (() => {}))();
  }

  function renderScorecard() {
    const r = S.report;
    if (!r) return;
    const perr = (r.errors || []).find((e) => /terraguard\.yml|custom_rules|policy|max_findings|fail_on/.test(e));
    if ($("#policy-status")) { $("#policy-status").textContent = perr ? `Policy error: ${perr}` : S.config ? "Policy applied" : ""; $("#policy-status").style.color = perr ? "var(--crit)" : ""; }
    const total = SEVS.reduce((n, v) => n + (r.summary[v] || 0), 0);
    const bar = SEVS.filter((v) => r.summary[v]).map((v) => `<span style="flex:${r.summary[v]};background:${sevColor(v)}" title="${r.summary[v]} ${v.toLowerCase()}"></span>`).join("");
    $("#scorecard").innerHTML = `
      <div class="grade g-${r.grade}">${r.grade}<small>${r.score}/100</small></div>
      <div class="sc-main">
        <div class="sc-line"><span class="verdict ${r.verdict.will_apply ? "ok" : "bad"}">${icon(r.verdict.will_apply ? "check" : "x", "ic sm")}${r.verdict.will_apply ? "Expected to apply" : "Apply is expected to fail"}</span>
          ${r.passed ? `<span class="pill ok">Policy passed</span>` : `<span class="pill bad">Policy failed at ${esc(r.fail_on)}</span>`}
          <span class="sc-meta">${r.stats.files} files · ${r.stats.resources} resources · ${r.ms} ms</span></div>
        <div class="sevbar" aria-label="${total} active findings by severity">${bar || `<span style="flex:1;background:var(--ok)"></span>`}</div>
        <div class="sc-legend">${SEVS.map((v) => `<span><i style="background:${sevColor(v)}"></i><b>${r.summary[v] || 0}</b> ${v.toLowerCase()}</span>`).join("")}<span class="muted">${r.fixable} fixable · ${r.waived} waived</span></div>
      </div>`;
    const setCount = (id, n, bad) => { const el = $(id); if (el) { el.hidden = !n; el.textContent = n; el.classList.toggle("bad", !!bad); } };
    setCount("#count-findings", total, r.summary.CRITICAL || r.summary.HIGH);
    setCount("#count-plan", r.plan ? r.plan.create + r.plan.update + r.plan.delete + r.plan.replace : 0, r.plan && (r.plan.delete || r.plan.replace));
    setCount("#count-compliance", (r.compliance || []).reduce((n, c) => n + c.total - c.passing, 0), true);
  }
  const VALIDATION = [
    ["TG-VAL-001", "HCL syntax parses"],
    ["TG-VAL-002", "No duplicate resources, variables, outputs, modules or locals"],
    ["TG-VAL-003", "Every reference resolves (var, local, module, data, resource)"],
    ["TG-VAL-011", "Local module calls pass only declared inputs"],
    ["TG-VAL-012", "Local module calls set every required input"],
    ["TG-VAL-007", "count and for_each are not combined"],
    ["TG-VAL-004", "CIDR blocks are valid network addresses"],
    ["TG-VAL-005", "S3 bucket names follow AWS naming rules"],
    ["TG-VAL-006", "Port ranges are not inverted"],
    ["TG-AWS-LAMBDA-002", "Lambda runtimes are supported"],
  ];

  // A pass, fail or warning mark for checklists.
  const mark = (ok) => `<span class="mark ${ok === null ? "warn" : ok ? "pass" : "fail"}">${icon(ok === null ? "spark" : ok ? "check" : "x", "ic sm")}</span>`;

  // What was checked: every resource, how many rules judged it, which failed.
  function coverageTile(c) {
    if (!c || !c.resources) return "";
    const pct = c.checks ? Math.round((c.passed / c.checks) * 100) : 0;
    const rows = (c.items || []).map((it) => {
      const st = it.failed?.length ? `<span class="sev HIGH">${it.failed.length} failed</span>` : it.checks ? `<span class="sev LOW">passed</span>` : `<span class="sev INFO">no rules</span>`;
      return `<tr><td>${st}</td><td class="mono"><button class="loc" data-jump="${esc(it.file)}" data-line="${it.line || 0}">${esc(it.address)}</button></td><td>${it.checks}</td><td class="mono">${esc((it.failed || []).join(", "))}</td></tr>`;
    }).join("");
    return `<div class="tile w12"><h4>Coverage</h4>
      <div class="kpis"><div><div class="kpi">${c.resources}</div><div class="kpi-label">resources</div></div><div><div class="kpi">${c.checks}</div><div class="kpi-label">checks run</div></div><div><div class="kpi" style="color:var(--ok, #4fe3c1)">${c.passed}</div><div class="kpi-label">passed (${pct}%)</div></div><div><div class="kpi" style="color:var(--high)">${c.failed}</div><div class="kpi-label">failed</div></div></div>
      ${c.uncovered?.length ? `<p class="hint">No rule is written for: ${esc(c.uncovered.join(", "))}. Generic checks (secrets, references, policy) still ran on them.</p>` : ""}
      <details><summary>Every resource</summary><div class="table-wrap"><table><thead><tr><th>Status</th><th>Resource</th><th>Checks</th><th>Failed rules</th></tr></thead><tbody>${rows}</tbody></table></div></details></div>`;
  }

  function renderOverview() {
    const r = S.report;
    if (!r) return;
    const active = r.findings.filter((f) => !f.waived);
    const blocking = new Set(active.filter((f) => f.blocking).map((f) => f.rule_id));
    const warn = active.filter((f) => ["TG-VAL-008", "TG-VAL-009", "TG-STATE-001", "TG-TF-001", "TG-TF-003"].includes(f.rule_id));
    const comp = r.compliance || [];
    let guide = true;
    try { guide = localStorage.getItem("terraguard.guide") !== "done"; } catch {}
    $("#tab-overview").innerHTML = `${guide ? `
      <div class="guide">
        <div><b>Start here</b><span class="hint inline">Three steps. Nothing you paste leaves this browser. Press <kbd>?</kbd> for shortcuts.</span></div>
        <ol>
          <li><span>1</span><div><b>Add your Terraform</b><p>Paste into the editor, or use Upload, Folder or Examples above it.</p></div></li>
          <li><span>2</span><div><b>Read the verdict, then fix</b><p>The score and "will it apply" update as you type. <button class="loc" data-tab-go="findings">Open findings</button> to fix one, or all at once.</p></div></li>
          <li><span>3</span><div><b>Keep it fixed</b><p>Add your own rules in <button class="loc" data-tab-go="policy">Policy</button>, then gate every pull request from <button class="loc" data-tab-go="cicd">Pipeline</button>.</p></div></li>
        </ol>
        <button class="btn sm ghost" id="guide-close" aria-label="Hide the guide">Got it</button>
      </div>` : ""}
      <div class="dash">
        <div class="tile w8"><h4>Why</h4>
          <p class="why ${r.verdict.will_apply ? "ok" : "bad"}">${esc(r.verdict.message)}</p>
          ${(r.gate_failures || []).length ? `<ul class="checks">${r.gate_failures.map((g) => `<li>${mark(false)}<span>${esc(g)}</span></li>`).join("")}</ul>` : `<ul class="checks"><li>${mark(true)}<span>Nothing at or above ${esc(r.fail_on)} is active, so the gate passes.</span></li></ul>`}</div>
        <div class="tile w4 fix-tile"><h4>Fix</h4><div class="kpi">${r.fixable}</div><div class="kpi-label">findings fixable in one click</div>
          <div class="row">${r.fixable ? `<button class="btn primary sm" data-fixall>${icon("wrench", "ic sm")}Fix all</button>` : ""}<button class="btn sm" data-ai-fix>${icon("spark", "ic sm")}AI fix (verified)</button></div></div>
        <div class="tile"><h4>Will it apply?</h4><ul class="checks">
          ${VALIDATION.map(([id, label]) => `<li>${mark(!blocking.has(id))}<span>${label}</span></li>`).join("")}
          ${warn.slice(0, 4).map((f) => `<li>${mark(null)}<span>${esc(f.message)}</span></li>`).join("")}</ul>
          <p class="hint" style="margin:10px 0 0">Quotas and global names are only enforced by the cloud at apply time: run <code>terraguard preflight --live</code> before apply.</p></div>
        <div class="tile"><h4>Top risks</h4>${active.length ? `<ul class="toplist">${active.slice(0, 8).map((f) => `<li><span class="sev ${f.severity}">${f.severity}</span><span class="grow">${esc(f.title)}</span><button class="loc" data-jump="${esc(f.file)}" data-line="${f.line || 0}">${esc(f.file)}${f.line ? ":" + f.line : ""}</button></li>`).join("")}</ul>` : `<div class="empty-sm">No active findings.</div>`}</div>
        <div class="tile"><h4>Findings by category</h4>${bars(Object.entries(r.by_category || {}).sort((a, b) => b[1] - a[1]), { label: (k) => CATEGORY[k] || k, empty: "No active findings." })}</div>
        <div class="tile"><h4>Resources by provider</h4>${bars(Object.entries(r.providers || {}).sort((a, b) => b[1] - a[1]), { label: (k) => CLOUDS[k] || k, empty: "No resources yet." })}</div>
        <div class="tile w12"><h4>Compliance</h4><div class="comp-grid">${comp.map((c) => `<div class="comp"><div class="comp-head"><span>${esc(c.name)}</span><b>${c.passing}/${c.total}</b></div><div class="meter"><span style="width:${c.total ? (100 * c.passing) / c.total : 100}%"></span></div></div>`).join("")}</div>
          <p class="hint" style="margin:10px 0 0">Controls with no failing evidence. <button class="loc" data-tab-go="compliance">View controls</button></p></div>
        <div class="tile"><h4>How this result was produced</h4>${r.trace ? `<ul class="checks">
          ${[["Parse", r.trace.parse_ms], ["Resource rules", r.trace.rules_ms], ["Module and graph checks", r.trace.checks_ms], ["Policy", r.trace.policy_ms]].map(([n, ms]) => `<li><span class="num">${ms.toFixed(1)} ms</span><span>${n}</span></li>`).join("")}
          <li><span class="num">${fmtN(r.trace.evaluations)}</span><span>rule evaluations on ${r.stats.resources} resources</span></li>
          <li><span class="num">${r.stats.rules}</span><span>rules active, fail_on ${esc(r.fail_on)}${r.trace.custom_rules ? `, ${r.trace.custom_rules} custom` : ""}</span></li></ul>` : `<div class="empty-sm">Trace unavailable.</div>`}</div>
        <div class="tile"><h4>Activity</h4>${S.activity.length ? `<ul class="checks">${S.activity.slice(0, 8).map((a) => `<li><span class="status ${a.ok ? "pass" : "fail"}">${esc(a.kind)}</span><span>${esc(a.text)} <span class="muted">${a.at.toLocaleTimeString()}</span></span></li>`).join("")}</ul>` : `<div class="empty-sm">Fixes and AI proposals appear here, with the engine's decision.</div>`}</div>
        ${coverageTile(r.coverage)}
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
        ${!isAI ? `<button class="btn sm ghost" data-copy-finding="${i}" title="Copy as text for a ticket or chat">Copy</button>` : ""}
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
    $("#cloud-chips").innerHTML = clouds.length ? `<button class="chip ${!S.filter.cloud ? "on" : ""}" data-cloud="">All providers</button>` + clouds.map(([c, n]) => `<button class="chip ${S.filter.cloud === c ? "on" : ""}" data-cloud="${esc(c)}">${brandIcon(c)}${esc(CLOUDS[c] || c)} ${n}</button>`).join("") : "";
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

  const usd = (n) => "$" + Number(n || 0).toFixed(2);
  function costView(c) {
    if (!c) return "";
    const d = (c.after || 0) - (c.before || 0);
    return `<h3 class="sec">Estimated monthly cost</h3>
      <p><b>${usd(c.before)}</b> to <b>${usd(c.after)}</b> <span class="${d > 0 ? "sev HIGH" : "sev LOW"}">${d >= 0 ? "+" : "-"}${usd(Math.abs(d))}</span></p>
      <table><thead><tr><th>Resource</th><th>Detail</th><th>Before</th><th>After</th></tr></thead><tbody>
      ${(c.lines || []).slice(0, 12).map((l) => `<tr><td class="mono">${esc(l.address)}</td><td>${esc(l.detail)}</td><td>${usd(l.before)}</td><td>${usd(l.after)}</td></tr>`).join("")}
      </tbody></table>
      <p class="hint">${esc(c.basis)}. Usage-based charges are not included${c.unpriced?.length ? "; not priced: " + esc(c.unpriced.join(", ")) : ""}.</p>`;
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
        ${p.import ? `<div class="plan-stat"><b>${p.import}</b>to import</div>` : ""}${p.moved ? `<div class="plan-stat"><b>${p.moved}</b>moved</div>` : ""}
      </div>
      ${risky.length ? `<div class="list">${risky.map((f) => findingCard(f, S.report.findings.indexOf(f), false)).join("")}</div>` : `<p class="hint">No destructive changes.</p>`}
      ${costView(S.report.cost)}
      <h3 class="sec">Changes</h3>
      <table><thead><tr><th>Action</th><th>Address</th><th>Forced by</th></tr></thead><tbody>
      ${(p.changes || []).map((c) => `<tr><td><span class="act ${c.action}">${c.action === "delete" ? "destroy" : c.action}</span></td><td class="mono">${esc(c.address)}${c.from ? `<div class="hint">moved from ${esc(c.from)}</div>` : ""}</td><td class="mono">${esc((c.reasons || []).join(", "))}</td></tr>`).join("")}
      </tbody></table>
      ${p.drift?.length ? `<h3 class="sec">Changed outside Terraform</h3>
      <table><thead><tr><th>Drift</th><th>Address</th><th>Attributes</th></tr></thead><tbody>
      ${p.drift.map((c) => `<tr><td><span class="act ${c.action}">${c.action === "delete" ? "deleted" : "changed"}</span></td><td class="mono">${esc(c.address)}</td><td class="mono">${esc((c.reasons || []).join(", "))}</td></tr>`).join("")}
      </tbody></table>` : ""}
      ${p.outputs?.length ? `<h3 class="sec">Outputs that change</h3><p class="mono">${p.outputs.map((o) => esc(o.address)).join(", ")}</p>` : ""}`;
  }

  // Graph colours and our own line icons (vendor logos are trademarks).
  const PROVIDER_COLOR = {
    aws: "#FF9900", google: "#4285F4", azurerm: "#0078D4", cloudflare: "#FBAD41", digitalocean: "#0080FF", hcloud: "#D50C2D",
    linode: "#00A95C", openstack: "#ED1944", ovh: "#123F6D", oci: "#C74634", alicloud: "#FF6A00", vultr: "#007BFC",
    kubernetes: "#326CE5", helm: "#0F1689", module: "#8B5CF6",
  };
  // Own line icons per kind of resource (no vendor logos: they are trademarks).
  const KIND_ICON = {
    bucket: '<path d="M5 7c0-1.7 3.1-3 7-3s7 1.3 7 3-3.1 3-7 3-7-1.3-7-3z"/><path d="M5 7l1.5 11c.3 1.2 2.6 2 5.5 2s5.2-.8 5.5-2L19 7"/>',
    volume: '<rect x="4" y="6" width="16" height="12" rx="2"/><circle cx="16" cy="12" r="1.5"/><path d="M7 12h5"/>',
    database: '<ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3"/>',
    cache: '<path d="M13 3L6 13h5l-1 8 7-10h-5z"/><ellipse cx="12" cy="20" rx="7" ry="1.6"/>',
    queue: '<rect x="3" y="7" width="4" height="10" rx="1"/><rect x="10" y="7" width="4" height="10" rx="1"/><rect x="17" y="7" width="4" height="10" rx="1"/>',
    function: '<path d="M8 4c-2 0-2 2-2 4v1c0 1.5-1 3-2 3 1 0 2 1.5 2 3v1c0 2 0 4 2 4M16 4c2 0 2 2 2 4v1c0 1.5 1 3 2 3-1 0-2 1.5-2 3v1c0 2 0 4-2 4M10 9l4 6M14 9l-4 6"/>',
    container: '<path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z"/><path d="M4 7.5l8 4.5 8-4.5M12 12v9"/>',
    cluster: '<path d="M12 2l8 4.5v11L12 22l-8-4.5v-11z"/><circle cx="12" cy="12" r="3"/><path d="M12 5v4M12 15v4M6 8.5l3.4 2M14.6 13.5L18 15.5M6 15.5l3.4-2M14.6 10.5L18 8.5"/>',
    compute: '<rect x="5" y="5" width="14" height="14" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 1v4M15 1v4M9 19v4M15 19v4M1 9h4M1 15h4M19 9h4M19 15h4"/>',
    vpc: '<rect x="3" y="4" width="18" height="16" rx="2" stroke-dasharray="3 2"/><path d="M7 9h4v4H7zM13 11h4v4h-4z"/>',
    subnet: '<rect x="4" y="4" width="16" height="16" rx="2"/><path d="M4 12h16M12 4v16"/>',
    nat: '<rect x="3" y="8" width="18" height="8" rx="4"/><path d="M7 12h10M14 9.5l3 2.5-3 2.5"/>',
    gateway: '<path d="M4 20V10l8-6 8 6v10"/><path d="M9 20v-6h6v6"/>',
    route: '<circle cx="6" cy="18" r="2"/><circle cx="18" cy="6" r="2"/><path d="M8 18h6a4 4 0 0 0 0-8h-4a4 4 0 0 1 0-8h6"/>',
    firewall: '<rect x="3" y="4" width="18" height="16" rx="1"/><path d="M3 9h18M3 15h18M9 4v5M15 9v6M9 15v5"/>',
    lb: '<circle cx="12" cy="5" r="2.5"/><circle cx="5" cy="19" r="2.5"/><circle cx="12" cy="19" r="2.5"/><circle cx="19" cy="19" r="2.5"/><path d="M12 7.5v9M11 7L6 16.5M13 7l5 9.5"/>',
    api: '<path d="M8 6l-5 6 5 6M16 6l5 6-5 6M14 4l-4 16"/>',
    dns: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/>',
    cdn: '<circle cx="12" cy="12" r="3"/><circle cx="4" cy="6" r="2"/><circle cx="20" cy="6" r="2"/><circle cx="4" cy="18" r="2"/><circle cx="20" cy="18" r="2"/><path d="M6 7l3.5 3M18 7l-3.5 3M6 17l3.5-3M18 17l-3.5-3"/>',
    waf: '<path d="M12 3l8 3v6c0 4.6-3.4 7.7-8 9-4.6-1.3-8-4.4-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
    key: '<circle cx="8" cy="12" r="4"/><path d="M12 12h9M18 12v3M21 12v3"/>',
    secret: '<rect x="5" y="10" width="14" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v2"/>',
    cert: '<rect x="3" y="4" width="18" height="12" rx="1"/><circle cx="15" cy="15" r="3"/><path d="M13.5 17.5L13 22l2-1 2 1-.5-4.5M7 8h8M7 11h4"/>',
    identity: '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-8 8-8s8 3.6 8 8"/>',
    logs: '<path d="M6 3h9l4 4v14H6z"/><path d="M9 11h7M9 15h7"/>',
    monitor: '<path d="M3 12h4l3-7 4 14 3-7h4"/>',
    scope: '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
    module: '<rect x="3" y="3" width="8" height="8" rx="1"/><rect x="13" y="3" width="8" height="8" rx="1"/><rect x="3" y="13" width="8" height="8" rx="1"/><rect x="13" y="13" width="8" height="8" rx="1"/>',
    other: '<rect x="4" y="4" width="16" height="16" rx="3"/>',
  };
  // First match wins, so specific kinds come before broad ones.
  const KINDS = [
    ["cluster", /eks_cluster|kubernetes_cluster|container_cluster|containerengine_cluster|lke_cluster|cs_managed_kubernetes|cs_kubernetes|vultr_kubernetes|gke|aks|_k8s|node_pool|node_group/],
    ["function", /lambda|function|workers?_script|worker_route/],
    ["bucket", /s3_bucket|storage_bucket|storage_account|storage_container|spaces_bucket|objectstorage|object_storage|oss_bucket|r2_bucket|_bucket/],
    ["container", /^(kubernetes_|helm_)|ecs_|ecr_|container|cloud_run|app_service|_app$/],
    ["nat", /nat_gateway|_nat\b|_nat_|_eip$|eip_address|public_ip|floating_?ip|reserved_ip|primary_ip|_address$/], ["waf", /waf|ruleset|firewall_policy|ddos/],
    ["api", /api_gateway|apigateway|api_management|apigee/],
    ["lb", /lb|load_?balancer|nodebalancer|listener|target_group|backend_service|forwarding_rule|alb|elb|application_gateway/], ["cdn", /cloudfront|cdn|front_?door/],
    ["dns", /route53|dns|record|zone|_domain$/], ["gateway", /internet_gateway|vpn_gateway|transit_gateway|egress_only|router$|_gateway|private_endpoint|vpc_endpoint|privatelink/],
    ["route", /route_table|route|peering/], ["subnet", /subnet|vswitch/], ["vpc", /_vpc$|_vpc_|virtual_network|compute_network|networking_network|_network$|vcn/],
    ["firewall", /security_group|firewall|network_security|secgroup|network_acl|security_list/],
    ["cache", /elasticache|redis|memcache|memorystore/], ["queue", /sqs|sns|pubsub|queue|servicebus|eventhub|kinesis|kafka|msk|event_bus/],
    ["database", /db_instance|rds|sql|dynamodb|database|cosmos|docdb|neptune|opensearch|elasticsearch|bigtable|spanner|firestore|redshift|bigquery|warehouse/],
    ["volume", /ebs|volume|disk|efs|filestore|file_share|block_storage/], ["secret", /secret|ssm_parameter|key_vault_secret/], ["key", /kms|key_vault|crypto_key|_key$/],
    ["cert", /certificate|acm_|_cert/], ["logs", /cloudtrail|log/], ["monitor", /cloudwatch|monitor|alarm|alert|insights/],
    ["scope", /resource_group|_project$|_folder$|organization|management_group|compartment/],
    ["identity", /iam|role|policy|identity|service_account|user|principal/],
    ["compute", /instance|droplet|server|vm|virtual_machine|launch_template|autoscaling|scale_set|compute/],
  ];
  const PROVIDER_TAG = { aws: "AWS", google: "GCP", azurerm: "AZURE", cloudflare: "CF", digitalocean: "DO", hcloud: "HETZNER", linode: "LINODE", openstack: "OPENSTACK", ovh: "OVH", oci: "OCI", alicloud: "ALIBABA", vultr: "VULTR", kubernetes: "K8S", helm: "HELM", module: "MODULE" };
  const kindOf = (type) => (type === "module" ? "module" : (KINDS.find(([, re]) => re.test(type.replace(/^data\./, ""))) || ["other"])[0]);
  // Each node is one image: provider colour, icon and tag.
  const nodeImage = (kind, prov, fill) => "data:image/svg+xml;utf8," + encodeURIComponent(`<svg xmlns="http://www.w3.org/2000/svg" width="96" height="96" viewBox="0 0 48 48"><rect width="48" height="48" rx="7" fill="${fill}"/><g transform="translate(10.4 4.5) scale(1.13)" fill="none" stroke="#fff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${KIND_ICON[kind]}</g><text x="24" y="43" text-anchor="middle" font-family="monospace" font-size="${(PROVIDER_TAG[prov] || prov).length > 6 ? 5.5 : 7}" font-weight="700" fill="#fff" fill-opacity=".92">${esc((PROVIDER_TAG[prov] || prov).slice(0, 9))}</text></svg>`);
  let graphLayout = "cose";

  function renderGraph() {
    const g = S.report?.graph;
    if (!g) return;
    if (!window.cytoscape) { $("#graph").innerHTML = `<div class="empty">Loading graph</div>`; setTimeout(renderGraph, 400); return; }
    const pathNodes = new Set();
    for (const f of S.report.findings) if (f.category === "attack-path" && !f.waived) (f.related || []).forEach((n) => pathNodes.add(n));
    graph?.destroy();
    graph = null;
    if (!g.nodes.length) { $("#graph").innerHTML = `<div class="empty">No resources yet.</div>`; $("#graph-legend").innerHTML = ""; return; }
    $("#graph").innerHTML = "";
    const provOf = (n) => (n.type === "module" ? "module" : n.type.replace(/^data\./, "").split("_")[0]);
    const present = [...new Set(g.nodes.map(provOf))];
    $("#graph-legend").innerHTML = present.map((p) => `<span><i style="background:${PROVIDER_COLOR[p] || "#64748b"}"></i>${esc(CLOUDS[p] || (p === "module" ? "Module" : p))}</span>`).join("")
      + `<span><i style="background:transparent;border:2px solid #d92d20"></i>Attack path</span>`;
    const ink = isDark() ? "#c9d2e3" : "#334155", edge = isDark() ? "#6b7c9e" : "#8a96ab";
    graph = cytoscape({
      container: $("#graph"),
      elements: [
        ...g.nodes.map((n) => ({ data: {
          id: n.id, label: n.type === "module" ? n.id : `${n.id.split(".").slice(-1)[0]}\n${n.type.replace(/^data\./, "").replace(/^[a-z]+_/, "")}`, type: n.type, file: n.file, line: n.line, findings: n.findings, sev: n.severity || "",
          fill: PROVIDER_COLOR[provOf(n)] || "#64748b", ring: SEV_HEX[n.severity] || (isDark() ? "#2a303d" : "#cfd5df"), icon: nodeImage(kindOf(n.type), provOf(n), PROVIDER_COLOR[provOf(n)] || "#64748b"), kind: kindOf(n.type), path: pathNodes.has(n.id),
        } })),
        ...g.edges.map((e) => ({ data: { id: e.source + ">" + e.target, source: e.source, target: e.target, path: pathNodes.has(e.source) && pathNodes.has(e.target) } })),
      ],
      layout: graphLayout === "cose" ? { name: "cose", animate: !reduceMotion, animationDuration: 500, padding: 30, nodeRepulsion: 22000, idealEdgeLength: 110, edgeElasticity: 80, gravity: 0.6, numIter: 1500 } : { name: "breadthfirst", directed: true, spacingFactor: 1.6, padding: 30, animate: !reduceMotion },
      style: [
        { selector: "node", style: { "background-color": "data(fill)", "background-image": "data(icon)", "background-width": "100%", "background-height": "100%", "background-clip": "node",
          shape: "round-rectangle", width: 52, height: 52, "border-width": 3, "border-color": "data(ring)", label: "data(label)", color: ink, "font-size": 12, "font-family": "JetBrains Mono, monospace",
          "text-valign": "bottom", "text-margin-y": 7, "text-wrap": "wrap", "line-height": 1.25, "text-background-color": isDark() ? "#0b0d12" : "#ffffff", "text-background-opacity": 0.75, "text-background-padding": 2,
          "transition-property": "opacity, border-width", "transition-duration": "200ms" } },
        { selector: "node[?path]", style: { "border-color": "#d92d20", "border-width": 5, "underlay-color": "#d92d20", "underlay-padding": 8, "underlay-opacity": 0.25, "underlay-shape": "round-rectangle" } },
        { selector: "edge", style: { width: 2, "line-color": edge, "target-arrow-color": edge, "target-arrow-shape": "triangle", "curve-style": "bezier", "arrow-scale": 1, opacity: 0.85, "transition-property": "opacity, line-color, width", "transition-duration": "200ms" } },
        { selector: "edge.hot", style: { "line-color": "#5eead4", "target-arrow-color": "#5eead4", width: 3, opacity: 1 } },
        { selector: "edge[?path]", style: { "line-color": "#d92d20", "target-arrow-color": "#d92d20", width: 3 } },
        { selector: ".faded", style: { opacity: 0.15 } },
        { selector: "node:selected", style: { "border-width": 5, "border-color": isDark() ? "#ffffff" : "#0b0d12" } },
      ],
    });
    const tip = $("#graph-tip");
    graph.on("mouseover", "node", (e) => {
      const d = e.target.data(), p = e.renderedPosition;
      tip.innerHTML = `<b>${esc(d.id)}</b>${esc(CLOUDS[d.type.replace(/^data\./, "").split("_")[0]] || (d.type === "module" ? "Module" : d.type))} · ${esc(d.kind)}<br>${d.findings} finding(s)${d.sev ? ` · worst <span class="sev ${d.sev}">${d.sev}</span>` : ""}${d.path ? "<br><span style='color:var(--crit)'>Part of an attack path</span>" : ""}`;
      tip.style.left = `${p.x + 18}px`;
      tip.style.top = `${p.y - 10}px`;
      tip.hidden = false;
    });
    graph.on("mouseout", "node", () => { tip.hidden = true; graph.edges().removeClass("hot"); });
    graph.on("mouseover", "node", (e) => e.target.connectedEdges().addClass("hot"));
    graph.on("tap", "node", (e) => {
      const hood = e.target.closedNeighborhood();
      graph.elements().addClass("faded");
      hood.removeClass("faded");
      jump(e.target.data("file"), e.target.data("line"));
    });
    graph.on("tap", (e) => { if (e.target === graph) graph.elements().removeClass("faded"); });
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

  const RULE_PROVIDER = { AWS: "AWS", AZ: "Azure", GCP: "Google Cloud", K8S: "Kubernetes", HELM: "Kubernetes", CF: "Cloudflare", DO: "DigitalOcean", HZ: "Hetzner",
    LIN: "Akamai / Linode", OCI: "Oracle Cloud", ALI: "Alibaba Cloud", OS: "OpenStack", OVH: "OVHcloud", VULTR: "Vultr", GH: "GitHub" };
  const ruleProvider = (id) => RULE_PROVIDER[id.split("-")[1]] || "Any provider";

  function renderRules() {
    const rules = JSON.parse(terraguard.rules("{}"));
    const providers = [...new Set(rules.map((r) => ruleProvider(r.id)))].sort();
    const cats = [...new Set(rules.map((r) => r.category))].sort();
    $("#rules-list").innerHTML = `
      <p class="hint">${rules.length} built-in rules, the same in the browser, CLI, GitHub Action, VS Code, MCP and server. Missing one? Write it in the Policy tab and propose it, or <a href="${REPO_URL}/blob/main/CONTRIBUTING.md#adding-a-rule" target="_blank" rel="noopener">add it in Go</a>.</p>
      <div class="rules-filters">
        <input type="search" id="rules-q" placeholder="Search: s3, encryption, CWE-284, aws_db_instance" aria-label="Search rules">
        <select id="rules-provider" aria-label="Provider"><option value="">All providers</option>${providers.map((p) => `<option>${esc(p)}</option>`).join("")}</select>
        <select id="rules-sev" aria-label="Severity"><option value="">All severities</option>${SEVS.map((v) => `<option>${v}</option>`).join("")}</select>
        <select id="rules-cat" aria-label="Category"><option value="">All categories</option>${cats.map((c) => `<option value="${esc(c)}">${esc(CATEGORY[c] || c)}</option>`).join("")}</select>
        <label class="inline-check"><input type="checkbox" id="rules-blocking"> Blocks apply</label>
      </div>
      <p class="hint" id="rules-count"></p>
      <table><thead><tr><th>ID</th><th>Severity</th><th>Rule</th></tr></thead><tbody id="rules-body">
      ${rules.map((r) => `<tr data-provider="${esc(ruleProvider(r.id))}" data-sev="${r.severity}" data-cat="${esc(r.category)}" data-blocking="${r.blocking ? 1 : ""}"
        data-search="${esc([r.id, r.title, r.remediation, r.cwe, ruleProvider(r.id), (r.resource_types || []).join(" "), (r.compliance_themes || []).join(" ")].join(" ").toLowerCase())}">
        <td class="mono">${esc(r.id)}</td><td><span class="sev ${r.severity}">${r.severity}</span></td>
        <td><b>${esc(r.title)}</b>${r.blocking ? ` <span class="badge block">Blocks apply</span>` : ""} <span class="badge">${esc(CATEGORY[r.category] || r.category)}</span> <span class="badge">${esc(ruleProvider(r.id))}</span>${r.cwe ? ` <span class="badge">${esc(r.cwe)}</span>` : ""}
          <div class="remedy">${esc(r.remediation)}</div>${r.resource_types?.length ? `<div class="rid">${esc(r.resource_types.slice(0, 6).join(", "))}${r.resource_types.length > 6 ? ` and ${r.resource_types.length - 6} more` : ""}</div>` : ""}</td></tr>`).join("")}
      </tbody></table>`;
    const apply = () => {
      const q = $("#rules-q").value.toLowerCase().trim(), p = $("#rules-provider").value, sev = $("#rules-sev").value, cat = $("#rules-cat").value, blk = $("#rules-blocking").checked;
      let n = 0;
      for (const tr of $$("#rules-body tr")) {
        const d = tr.dataset;
        tr.hidden = (q && !q.split(/\s+/).every((w) => d.search.includes(w))) || (p && d.provider !== p) || (sev && d.sev !== sev) || (cat && d.cat !== cat) || (blk && !d.blocking);
        n += tr.hidden ? 0 : 1;
      }
      $("#rules-count").textContent = `Showing ${n} of ${rules.length}`;
    };
    for (const id of ["#rules-q", "#rules-provider", "#rules-sev", "#rules-cat", "#rules-blocking"]) $(id).addEventListener("input", apply);
    apply();
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

  // Product page: live usage and GitHub stats
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

  // AI assistant
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
    addCopyButtons($("#chat-log"));
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

  // AI proposes, Verify decides; new files are added as-is.
  function verifyAndApply(changed) {
    const existing = Object.fromEntries(Object.entries(changed).filter(([n]) => S.files[n] !== undefined));
    if (Object.keys(existing).length) {
      const v = JSON.parse(terraguard.verifyChange(JSON.stringify({ ...input(), changed: existing })));
      log("AI proposal", `${Object.keys(existing).join(", ")}: engine ${v.reason}`, v.ok);
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

  // Actions (log records what changed and why)
  function log(kind, text, ok = true) {
    S.activity.unshift({ at: new Date(), kind, text, ok });
    S.activity.length = Math.min(S.activity.length, 30);
  }

  function applyFixes(fixes) {
    const before = S.report?.score;
    const res = JSON.parse(terraguard.applyFixes(JSON.stringify({ files: S.files, fixes })));
    for (const [n, c] of Object.entries(res.files || {})) setFileContent(n, c);
    count("fixes", fixes.length - (res.errors?.length || 0));
    log("Fix", `Applied ${fixes.length - (res.errors?.length || 0)} deterministic fix(es)${before !== undefined ? `; score was ${before}` : ""}`);
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

  // Custom rule builder: writes valid YAML into the policy
  const yamlScalar = (v) => (/^-?\d+(\.\d+)?$/.test(v) ? v : v === "true" || v === "false" ? v : JSON.stringify(v));

  function addCustomRule() {
    const val = (id) => $(id).value.trim();
    const id = val("#cr-id").toUpperCase(), attr = val("#cr-attr"), op = $("#cr-op").value, raw = val("#cr-value");
    const msg = (t, bad) => { $("#cr-msg").textContent = t; $("#cr-msg").style.color = bad ? "var(--crit)" : ""; };
    if (!/^[A-Z0-9][A-Z0-9-]{2,39}$/.test(id)) return msg("Rule ID: 3-40 characters, letters, digits and dashes (e.g. ORG-OWNER-001).", true);
    if (!attr) return msg("Attribute is required, e.g. tags.owner.", true);
    if (op !== "exists" && !raw) return msg("Value is required for this check.", true);
    let cond;
    if (op === "exists") cond = `exists: ${raw === "false" ? "false" : "true"}`;
    else if (op === "in" || op === "not_in") cond = `${op}: [${raw.split(",").map((x) => yamlScalar(x.trim())).join(", ")}]`;
    else if (op === "min" || op === "max") {
      if (!/^-?\d+(\.\d+)?$/.test(raw)) return msg("Value must be a number for at least / at most.", true);
      cond = `${op}: ${raw}`;
    } else cond = `${op}: ${yamlScalar(raw)}`;
    const types = val("#cr-types").split(",").map((t) => t.trim()).filter(Boolean);
    const lines = [`  - id: ${id}`, `    title: ${JSON.stringify(val("#cr-title") || id)}`, `    severity: ${$("#cr-sev").value}`];
    if (types.length) lines.push(`    resource_types: [${types.map((t) => JSON.stringify(t)).join(", ")}]`);
    if (val("#cr-where-attr")) lines.push(`    where: [{ attribute: ${JSON.stringify(val("#cr-where-attr"))}, equals: ${yamlScalar(val("#cr-where-val"))} }]`);
    lines.push(`    attribute: ${JSON.stringify(attr)}`, `    ${cond}`);
    if (val("#cr-fix")) lines.push(`    remediation: ${JSON.stringify(val("#cr-fix"))}`);
    let c = S.config.trimEnd();
    if (new RegExp(`^\\s*-\\s*id:\\s*${id}\\s*$`, "m").test(c)) return msg(`${id} already exists in the policy.`, true);
    c = /^custom_rules:\s*$/m.test(c) ? c.replace(/^custom_rules:\s*$/m, "custom_rules:\n" + lines.join("\n")) : `${c}${c ? "\n\n" : ""}custom_rules:\n${lines.join("\n")}`;
    S.config = c + "\n";
    $("#policy-input").value = S.config;
    scan();
    if (S.report.errors?.length) return msg(S.report.errors[0], true);
    const hits = S.report.findings.filter((f) => f.rule_id === id && !f.waived).length;
    log("Policy", `Added ${id}: ${hits} resource(s) currently fail it`);
    msg(`${id} added. ${hits} resource(s) currently fail it.`);
    $("#cr-propose").hidden = false;
    $("#cr-propose").onclick = () => proposeRule(lines.join("\n"), val("#cr-title") || id);
  }

  // Plain-English standards: AI drafts one rule, the engine validates it
  let draft = null;
  async function draftFromText() {
    const text = $("#nl-rule").value.trim(), msg = (t, bad) => { $("#nl-msg").textContent = t; $("#nl-msg").style.color = bad ? "var(--crit)" : ""; };
    if (!text) return msg("Describe the standard first.", true);
    $("#nl-preview").hidden = true;
    msg("Drafting...");
    const input = JSON.stringify({ files: S.files });
    const types = JSON.parse(terraguard.resourceTypes(input)).join(", ") || "none yet";
    const msgs = [{ role: "system", content: terraguard.ruleDraftPrompt }, { role: "user", content: `Resource types in this project: ${types}\nStandard: ${text}` }];
    try {
      for (let round = 0; round < 2; round++) { // one repair round with the validation error
        const r = await AI.chat(msgs);
        draft = JSON.parse(terraguard.draftRule(r.text, input));
        if (!draft.error) break;
        msgs.push({ role: "assistant", content: r.text }, { role: "user", content: `That rule was rejected: ${draft.error}. Answer with the corrected YAML only.` });
      }
    } catch (e) { draft = null; return msg(e.message.split("\n")[0], true); }
    if (draft.error) return msg(`Rejected: ${draft.error}`, true);
    if (new RegExp(`^\\s*-\\s*id:\\s*${draft.rule.id}\\s*$`, "m").test(S.config)) return msg(`${draft.rule.id} already exists in the policy.`, true);
    $("#nl-yaml").textContent = draft.yaml;
    $("#nl-hits").innerHTML = draft.hits.length
      ? `Would flag ${draft.hits.length} resource(s): ${draft.hits.slice(0, 8).map((h) => `<button class="loc" data-jump="${esc(h.file)}" data-line="${h.line || 0}">${esc(h.resource)}</button>`).join(" ")}`
      : "Would flag nothing in the current files.";
    $("#nl-preview").hidden = false;
    msg("Validated by the engine. Review it before adding.");
  }
  // Opens a pre-filled GitHub issue; a maintainer reviews it and adds the rule in Go with tests.
  function proposeRule(yaml, problem) {
    const offending = (draft?.hits || []).slice(0, 1).map((h) => resourceSource(h.file, h.line)).join("");
    const q = new URLSearchParams({ template: "rule_proposal.yml", title: `Rule proposal: ${problem.slice(0, 80)}`, problem, rule: yaml.replace(/^ {2}/gm, ""), bad: offending });
    window.open(`${REPO_URL}/issues/new?${q}`, "_blank", "noopener");
  }
  // The resource block starting at line, for a proposal's example.
  function resourceSource(file, line) {
    const lines = (S.files[file] || "").split("\n");
    let i = line - 1, depth = 0, out = [];
    for (; i < lines.length && out.length < 40; i++) {
      out.push(lines[i]);
      depth += (lines[i].match(/{/g) || []).length - (lines[i].match(/}/g) || []).length;
      if (depth <= 0 && out.length > 1) break;
    }
    return out.join("\n");
  }

  function addDraft() {
    if (!draft || draft.error) return;
    const c = S.config.trimEnd();
    S.config = (/^custom_rules:\s*$/m.test(c) ? c.replace(/^custom_rules:\s*$/m, "custom_rules:\n" + draft.yaml) : `${c}${c ? "\n\n" : ""}custom_rules:\n${draft.yaml}`) + "\n";
    $("#policy-input").value = S.config;
    scan();
    log("Policy", `Added ${draft.rule.id} from a plain-English standard`);
    $("#nl-preview").hidden = true;
    $("#nl-msg").textContent = `${draft.rule.id} added.`;
    draft = null;
  }

  function download(name, content, type = "text/plain") {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([content], { type }));
    a.download = name.split("/").pop();
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  // terraguard ui: the folder on disk, served read-only to this page with a one-time token.
  const LOCAL_TOKEN = (location.hash.match(/[?&]local=([a-f0-9]{32})/) || [])[1] || "";
  async function loadLocal(quiet) {
    try {
      const res = await fetch("api/local/files", { headers: { "X-TerraGuard-Local": LOCAL_TOKEN }, cache: "no-store" });
      if (!res.ok) throw new Error(res.status);
      const { files, root } = await res.json();
      const config = files[".terraguard.yml"] || files[".terraguard.yaml"] || "";
      delete files[".terraguard.yml"]; delete files[".terraguard.yaml"];
      if (quiet && JSON.stringify(files) === JSON.stringify(S.files) && config === S.config) return true;
      S.config = config;
      $("#policy-input").value = S.config;
      setFiles(files, S.active);
      scan();
      if (!quiet) toast(`Loaded ${Object.keys(files).length} file(s) from ${root}`);
      return true;
    } catch {
      if (!quiet) toast("Could not read the local folder");
      return false;
    }
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
      if (!/\.(tf|tofu|tfvars|json|ya?ml|template|dockerfile)$|(^|\/)(terragrunt\.hcl|Dockerfile[^/]*|Containerfile)$|\.tfstate/i.test(path) || /(^|\/)(\.terraform|node_modules|vendor)\//.test(path)) continue;
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

  // AI settings dialog
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
    $("#row-header").hidden = p !== "local";
    $("#ai-header").value = s.authHeader || "";
    $("#row-key").hidden = p === "server";
    $("#row-model").hidden = p === "server";
    $("#row-token").hidden = p !== "server";
    const srv = AI.server();
    $("#ai-help").innerHTML = {
      groq: `Free key: <a href="${P.keyUrl}" target="_blank" rel="noopener">${P.keyUrl}</a>`,
      openrouter: `Free key: <a href="${P.keyUrl}" target="_blank" rel="noopener">${P.keyUrl}</a>. Models ending in <code>:free</code> cost nothing.`,
      gemini: `Free key: <a href="${P.keyUrl}" target="_blank" rel="noopener">${P.keyUrl}</a>`,
      local: `Any OpenAI-compatible endpoint. Local: install <a href="https://ollama.com/download" target="_blank" rel="noopener">Ollama</a>, run <code>ollama pull llama3.2</code> and start it with <code>OLLAMA_ORIGINS=${esc(location.origin)} ollama serve</code>. Enterprise: your gateway URL (LiteLLM, Azure OpenAI <code>https://NAME.openai.azure.com/openai/v1</code>, an internal proxy) with your key.`,
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

  // Wiring
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
      if (!S.active || !/\.(tf|tofu|tfvars)$/.test(S.active)) return;
      setFileContent(S.active, terraguard.fmt(S.files[S.active]));
      toast("Formatted");
    };
    $("#graph-fit").onclick = () => graph?.animate({ fit: { padding: 30 } }, { duration: reduceMotion ? 0 : 300 });
    $("#graph-layout").onclick = (e) => {
      graphLayout = graphLayout === "cose" ? "breadthfirst" : "cose";
      e.target.textContent = graphLayout === "cose" ? "Layered layout" : "Organic layout";
      renderGraph();
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
      const el = e.target.closest("[data-jump],[data-fix],[data-fixall],[data-ai-fix],[data-ignore],[data-waive],[data-ask],[data-apply-ai],[data-copy],[data-copy-finding],[data-q],[data-tab-go],[data-filter-rule]");
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
      else if (d.copyFinding !== undefined) {
        const f = all[+d.copyFinding];
        navigator.clipboard.writeText(`[${f.severity}] ${f.rule_id} ${f.title}\n${f.file}${f.line ? ":" + f.line : ""}${f.resource ? " (" + f.resource + ")" : ""}\n${f.message}${f.remediation ? "\nFix: " + f.remediation : ""}`);
        toast("Finding copied");
      }
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
      download({ markdown: "terraguard-report.md", json: "terraguard-report.json", sarif: "terraguard.sarif", junit: "terraguard-junit.xml", codequality: "gl-code-quality.json", checkstyle: "terraguard-checkstyle.xml" }[f], terraguard.render(JSON.stringify(input()), f));
    };

    $("#plan-input").oninput = (e) => { S.plan = e.target.value; scanSoon(); };
    $("#plan-upload").onchange = async (e) => { S.plan = await e.target.files[0].text(); $("#plan-input").value = S.plan; scan(); };
    $("#btn-plan-clear").onclick = () => { S.plan = ""; $("#plan-input").value = ""; scan(); };
    $("#policy-input").oninput = (e) => { S.config = e.target.value; scanSoon(); };
    $("#cr-add").onclick = addCustomRule;
    // Shortcuts work everywhere except while typing in a field or the editor.
    document.addEventListener("keydown", (e) => {
      if ($("#app").hidden || e.ctrlKey || e.metaKey) return;
      const typing = /INPUT|TEXTAREA|SELECT/.test(e.target.tagName) || e.target.closest(".monaco-editor");
      const tabs = $$(".ws-nav [data-tab]");
      if (e.altKey && /^[1-9]$/.test(e.key) && tabs[+e.key - 1]) { e.preventDefault(); showTab(tabs[+e.key - 1].dataset.tab); }
      else if (e.altKey && e.code === "KeyF") { e.preventDefault(); fixAll(); }
      else if (e.altKey && e.code === "KeyS") { e.preventDefault(); $("#btn-share").click(); }
      else if (typing || e.altKey) return;
      else if (e.key === "/") { e.preventDefault(); if (S.tab !== "rules") showTab("findings"); $(S.tab === "rules" ? "#rules-q" : "#filter-q")?.focus(); }
      else if (e.key === "?") { e.preventDefault(); $("#shortcuts").showModal(); }
    });
    $("#nl-draft").onclick = draftFromText;
    $("#nl-add").onclick = addDraft;
    $("#nl-propose").onclick = () => draft && proposeRule(draft.yaml, $("#nl-rule").value.trim() || draft.rule.title);
    $("#nl-discard").onclick = () => { draft = null; $("#nl-preview").hidden = true; $("#nl-msg").textContent = ""; };
    $("#tab-overview").addEventListener("click", (e) => {
      if (e.target.id !== "guide-close") return;
      try { localStorage.setItem("terraguard.guide", "done"); } catch {}
      e.target.closest(".guide").remove();
    });
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
      Object.assign(s, { provider: p, private: $("#ai-private").checked, baseUrl: $("#ai-base").value.trim() || "http://localhost:11434/v1", authHeader: $("#ai-header").value.trim(),
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

  // Product page: motion, live try panel, install tabs
  const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;

  // Every code block gets a copy button; commands are meant to be pasted.
  function addCopyButtons(root) {
    for (const pre of $$("pre", root)) {
      if (pre.parentElement.classList.contains("copy-wrap") || pre.classList.contains("code")) continue;
      const wrap = document.createElement("div");
      wrap.className = "copy-wrap";
      pre.replaceWith(wrap);
      wrap.append(pre);
      const b = document.createElement("button");
      b.className = "copy-btn";
      b.type = "button";
      b.textContent = "Copy";
      b.setAttribute("aria-label", "Copy to clipboard");
      b.onclick = async () => {
        try { await navigator.clipboard.writeText(pre.innerText.trim()); b.textContent = "Copied"; } catch { b.textContent = "Press Ctrl+C"; }
        setTimeout(() => (b.textContent = "Copy"), 1600);
      };
      wrap.append(b);
    }
  }

  // Install commands per platform; selecting one never downloads anything.
  const RELEASE_URL = "https://github.com/Karthik-099/TERRAGUARD/releases/latest/download/terraguard_";
  function installCommand(p) {
    if (p.startsWith("windows")) {
      return `# PowerShell
Invoke-WebRequest -Uri ${RELEASE_URL}${p}.exe -OutFile terraguard.exe
.\\terraguard.exe scan .`;
    }
    return `curl -fsSL -o terraguard ${RELEASE_URL}${p}
chmod +x terraguard && sudo mv terraguard /usr/local/bin/
terraguard scan .`;
  }
  function selectPlatform(p) {
    for (const b of $$("[data-platform]")) {
      const on = b.dataset.platform === p;
      b.classList.toggle("on", on);
      b.setAttribute("aria-checked", on);
    }
    $("#install-cmd").textContent = installCommand(p);
    const ext = p.startsWith("windows") ? ".exe" : "";
    $("#dl-binary").href = `${RELEASE_URL}${p}${ext}`;
    $("#dl-binary").textContent = `Download terraguard_${p}${ext}`;
  }
  function setupDownloads() {
    if (!$("#install-cmd")) return;
    const ua = navigator.userAgent, arm = /arm|aarch64/i.test(navigator.userAgentData?.architecture || ua);
    const detected = /Windows/.test(ua) ? "windows_amd64" : /Mac/.test(ua) ? (arm || !/Intel/.test(ua) ? "darwin_arm64" : "darwin_amd64") : arm ? "linux_arm64" : "linux_amd64";
    $(`[data-platform="${detected}"]`)?.insertAdjacentHTML("beforeend", ` <span class="mine">(yours)</span>`);
    for (const b of $$("[data-platform]")) b.onclick = () => selectPlatform(b.dataset.platform);
    selectPlatform(detected);
  }

  // Background: a slowly drifting graph of nodes, like the infrastructure it
  // checks. Links follow the pointer; it pauses when hidden or in the workspace.
  function network(canvas) {
    if (!canvas) return;
    const ctx = canvas.getContext("2d"), dpr = Math.min(devicePixelRatio || 1, 2), pointer = { x: -1e4, y: -1e4 };
    let nodes = [], w = 0, h = 0;
    const size = () => {
      w = canvas.width = innerWidth * dpr; h = canvas.height = innerHeight * dpr;
      const n = Math.min(90, Math.round((innerWidth * innerHeight) / 18000));
      nodes = Array.from({ length: n }, () => ({ x: Math.random() * w, y: Math.random() * h, vx: (Math.random() - 0.5) * 0.25 * dpr, vy: (Math.random() - 0.5) * 0.25 * dpr, r: (Math.random() * 1.4 + 0.8) * dpr }));
    };
    const draw = () => {
      const dark = isDark(), reach = 150 * dpr;
      ctx.clearRect(0, 0, w, h);
      for (const a of nodes) {
        a.x += a.vx; a.y += a.vy;
        if (a.x < 0 || a.x > w) a.vx *= -1;
        if (a.y < 0 || a.y > h) a.vy *= -1;
      }
      ctx.lineWidth = dpr;
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i], b = nodes[j], d = Math.hypot(a.x - b.x, a.y - b.y);
          if (d < reach) {
            ctx.strokeStyle = dark ? `rgba(79,227,193,${(1 - d / reach) * 0.22})` : `rgba(13,148,136,${(1 - d / reach) * 0.18})`;
            ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
          }
        }
        const a = nodes[i], d = Math.hypot(a.x - pointer.x, a.y - pointer.y);
        if (d < reach * 1.4) {
          ctx.strokeStyle = `rgba(167,139,250,${(1 - d / (reach * 1.4)) * 0.5})`;
          ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(pointer.x, pointer.y); ctx.stroke();
        }
        ctx.fillStyle = dark ? "rgba(154,245,223,.7)" : "rgba(13,148,136,.55)";
        ctx.beginPath(); ctx.arc(a.x, a.y, a.r, 0, Math.PI * 2); ctx.fill();
      }
    };
    let raf = 0;
    const loop = () => { draw(); raf = requestAnimationFrame(loop); };
    const run = () => {
      cancelAnimationFrame(raf);
      if (document.hidden || $("#landing").hidden) return;
      reduceMotion ? draw() : loop();
    };
    size();
    addEventListener("resize", () => { size(); run(); });
    addEventListener("pointermove", (e) => { pointer.x = e.clientX * dpr; pointer.y = e.clientY * dpr; }, { passive: true });
    document.addEventListener("visibilitychange", run);
    addEventListener("hashchange", () => setTimeout(run));
    run();
  }

  function setupMotion() {
    const targets = $$("#landing .section-head, #landing .card, #landing .stage, #landing .metric, #landing .lane, #landing .diagram, #landing .table-wrap, #landing .policy-code, #landing .cap-list > div, #landing .try-panel, #landing .install, #landing .layer, #landing .flow");
    const io = new IntersectionObserver((entries) => {
      for (const e of entries) {
        if (!e.isIntersecting) continue;
        e.target.classList.add("in");
        io.unobserve(e.target);
        countUp(e.target);
      }
    }, { rootMargin: "0px 0px -8% 0px" });
    for (const el of targets) {
      const siblings = [...el.parentElement.children].filter((c) => c.matches(el.tagName));
      el.style.setProperty("--d", `${Math.min(siblings.indexOf(el), 6) * 70}ms`);
      el.classList.add("reveal");
      io.observe(el);
    }
    countUp($(".facts"));
    network($("#net"));
    if (reduceMotion) return;
    // Background orbs drift with scroll; cards tilt slightly toward the pointer.
    let ticking = false;
    addEventListener("scroll", () => {
      if (ticking) return;
      ticking = true;
      requestAnimationFrame(() => {
        const y = scrollY;
        document.documentElement.style.setProperty("--sx", `${Math.sin(y / 900) * 60}px`);
        document.documentElement.style.setProperty("--sy", `${(y % 1200) / 20}px`);
        const max = document.documentElement.scrollHeight - innerHeight;
        document.documentElement.style.setProperty("--progress", max > 0 ? (y / max).toFixed(4) : 0);
        document.documentElement.style.setProperty("--hx", `${Math.max(0, 14 - y / 30)}deg`);
        ticking = false;
      });
    }, { passive: true });
    for (const card of $$("#landing .grid-3 > .card, #landing .grid-4 > .card, #landing .demo-steps > .card, #landing .deploy-grid > .card")) {
      card.classList.add("tilt");
      card.addEventListener("pointermove", (e) => {
        const r = card.getBoundingClientRect();
        card.style.setProperty("--ry", `${((e.clientX - r.left) / r.width - 0.5) * 6}deg`);
        card.style.setProperty("--rx", `${-((e.clientY - r.top) / r.height - 0.5) * 6}deg`);
        card.style.setProperty("--mx", `${e.clientX - r.left}px`);
        card.style.setProperty("--my", `${e.clientY - r.top}px`);
        card.style.setProperty("--ty", "-3px");
      });
      card.addEventListener("pointerleave", () => { card.style.setProperty("--rx", "0deg"); card.style.setProperty("--ry", "0deg"); card.style.setProperty("--ty", "0"); });
    }
  }

  // Animate the leading number in metric labels like "2,400" or "0.25 s".
  function countUp(root) {
    if (reduceMotion || !root) return;
    for (const b of root.querySelectorAll(".metric b, .facts b, .result-steps b")) {
      const m = b.textContent.match(/^([\d,.]+)(.*)$/);
      if (!m || b.dataset.counted) continue;
      b.dataset.counted = "1";
      const target = parseFloat(m[1].replace(/,/g, "")), decimals = (m[1].split(".")[1] || "").length, rest = m[2];
      const t0 = performance.now();
      const tick = (now) => {
        const k = Math.min((now - t0) / 900, 1), v = target * (1 - Math.pow(1 - k, 3));
        b.textContent = (decimals ? v.toFixed(decimals) : fmtN(Math.round(v))) + rest;
        if (k < 1) requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
    }
  }

  function setupTry() {
    const area = $("#try-input");
    let timer;
    const run = async () => {
      $("#try-status").textContent = "Loading engine";
      try { await bootEngine(); } catch { $("#try-status").textContent = "Engine failed to load"; return; }
      const t0 = performance.now();
      const r = JSON.parse(terraguard.scan(JSON.stringify({ files: { "main.tf": area.value } })));
      const ms = (performance.now() - t0).toFixed(1);
      $("#try-status").textContent = `Engine v${terraguard.version} · runs locally`;
      const active = r.findings.filter((f) => !f.waived);
      $("#try-verdict").innerHTML = `<span class="grade g-${r.grade}" style="width:40px;height:40px;font-size:18px">${r.grade}</span>
        <span class="verdict ${r.verdict.will_apply ? "ok" : "bad"}" style="margin:0">${r.verdict.will_apply ? "Expected to apply" : "Apply is expected to fail"}</span>
        <span class="count">${active.length} findings</span><span class="count">${r.fixable} auto-fixable</span>`;
      $("#try-results").innerHTML = active.length ? active.map((f) => `<div class="try-item"><span class="sev ${f.severity}">${f.severity}</span>
        <span><span class="t">${esc(f.title)}</span><span class="m">${esc(f.message)}</span></span><span class="ln">line ${f.line || "-"}</span></div>`).join("")
        : `<div class="empty">No findings. Clean configuration.</div>`;
      $("#try-meta").textContent = `Scanned in ${ms} ms · ${r.stats.resources} resources · ${r.stats.rules} rules`;
    };
    area.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(run, 200); });
    const io = new IntersectionObserver((e) => { if (e.some((x) => x.isIntersecting)) { io.disconnect(); run(); } }, { rootMargin: "200px" });
    io.observe($("#try"));
    $("#try-open").addEventListener("click", () => {
      try { sessionStorage.setItem("tg.try", JSON.stringify({ files: { "main.tf": area.value }, active: "main.tf" })); } catch {}
    });
  }

  function setupScrollButtons() {
    document.addEventListener("click", (e) => {
      const b = e.target.closest("[data-scroll]");
      if (b) document.getElementById(b.dataset.scroll)?.scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth" });
    });
  }

  function setupInstall() {
    $("#install-box .install-tabs").addEventListener("click", (e) => {
      const b = e.target.closest("[data-install]");
      if (!b) return;
      $$("#install-box [data-install]").forEach((x) => x.classList.toggle("on", x === b));
      $$("#install-box [data-panel]").forEach((p) => (p.hidden = p.dataset.panel !== b.dataset.install));
    });
  }

  // Boot (fonts are self-hosted; GitHub stats are skipped when air-gapped)
  wire();
  setupMotion();
  setupDownloads();
  addCopyButtons($("#landing"));
  setupTry();
  setupInstall();
  setupScrollButtons();
  route();
  AI.detectServer().then(renderLiveStats);
  if (!LOCAL) renderGitHub();
  mountGiscus();
})();
