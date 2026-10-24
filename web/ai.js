// Optional AI assistant. Routes across providers and models with fallback.
// The engine never depends on this: scans, fixes and gates run without it.
const AI = (() => {
  const openaiCompat = (urlFn, extraHeaders = () => ({})) => async (key, model, messages, s) => {
    const headers = { "Content-Type": "application/json", ...extraHeaders(s) };
    if (key) headers.Authorization = `Bearer ${key}`;
    const res = await fetch(urlFn(s), { method: "POST", headers, body: JSON.stringify({ model, messages, temperature: 0.2 }) });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw httpError(res.status, data.error?.message || data.error || res.statusText);
    const text = data.choices?.[0]?.message?.content;
    if (!text) throw httpError(502, "empty response");
    return text;
  };

  const gemini = async (key, model, messages) => {
    const system = messages.filter((m) => m.role === "system").map((m) => m.content).join("\n\n");
    const contents = messages.filter((m) => m.role !== "system")
      .map((m) => ({ role: m.role === "assistant" ? "model" : "user", parts: [{ text: m.content }] }));
    const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-goog-api-key": key },
      body: JSON.stringify({ systemInstruction: { parts: [{ text: system }] }, contents, generationConfig: { temperature: 0.2 } }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw httpError(res.status, data.error?.message || res.statusText);
    const text = data.candidates?.[0]?.content?.parts?.map((p) => p.text).join("");
    if (!text) throw httpError(502, data.promptFeedback?.blockReason || "empty response");
    return text;
  };

  const server = async (_key, _model, messages, s) => {
    const headers = { "Content-Type": "application/json" };
    if (s.serverToken) headers.Authorization = `Bearer ${s.serverToken}`;
    const res = await fetch("api/ai/chat", { method: "POST", headers, body: JSON.stringify({ messages }) });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw httpError(res.status, data.error || res.statusText);
    return { text: data.text, provider: `server → ${data.provider}`, model: data.model };
  };

  function httpError(status, message) {
    const e = new Error(`${status}: ${typeof message === "string" ? message : JSON.stringify(message)}`);
    e.status = status;
    return e;
  }

  const PROVIDERS = {
    groq: {
      label: "Groq", hosted: true, keyUrl: "https://console.groq.com/keys",
      models: ["openai/gpt-oss-120b", "llama-3.3-70b-versatile", "openai/gpt-oss-20b"],
      call: openaiCompat(() => "https://api.groq.com/openai/v1/chat/completions"),
    },
    openrouter: {
      label: "OpenRouter", hosted: true, keyUrl: "https://openrouter.ai/keys",
      // Free slugs change often; openrouter/free routes to any live free model.
      models: ["nvidia/nemotron-3-super-120b-a12b:free", "google/gemma-4-31b-it:free", "openrouter/free"],
      call: openaiCompat(() => "https://openrouter.ai/api/v1/chat/completions", () => ({ "HTTP-Referer": location.origin, "X-Title": "TerraGuard" })),
    },
    gemini: {
      label: "Gemini", hosted: true, keyUrl: "https://aistudio.google.com/apikey",
      models: ["gemini-2.5-flash", "gemini-2.5-flash-lite"],
      call: gemini,
    },
    local: {
      label: "Local model", hosted: false, keyOptional: true, keyUrl: "https://ollama.com/download",
      models: ["llama3.2", "qwen2.5-coder", "mistral"],
      call: openaiCompat((s) => `${(s.baseUrl || "http://localhost:11434/v1").replace(/\/$/, "")}/chat/completions`),
    },
    server: {
      label: "Self-hosted server", hosted: false, keyOptional: true, models: ["(server route)"],
      call: server,
    },
  };

  const KEY = "tg.ai";
  let serverInfo = null;

  function load() {
    let s = {};
    try { s = JSON.parse(localStorage.getItem(KEY)) || {}; } catch {}
    return { provider: "", fallback: true, private: false, keys: {}, models: {}, baseUrl: "http://localhost:11434/v1", serverToken: "", ...s };
  }
  function save(s) { try { localStorage.setItem(KEY, JSON.stringify(s)); } catch {} }

  // `terraguard serve` exposes /api/config; on GitHub Pages this 404s and is ignored.
  async function detectServer() {
    if (location.hostname.endsWith("github.io")) return null;
    try {
      const ctl = new AbortController();
      setTimeout(() => ctl.abort(), 1500);
      const r = await fetch("api/config", { signal: ctl.signal });
      if (r.ok) serverInfo = await r.json();
    } catch {}
    return serverInfo;
  }

  function usable(name, s) {
    if (name === "server") return !!serverInfo?.ai?.enabled && (!s.private || serverInfo.ai.local_only);
    if (s.private && PROVIDERS[name].hosted) return false;
    return PROVIDERS[name].keyOptional ? (name !== "local" || !!s.models.local || s.provider === "local") : !!s.keys[name];
  }

  function chosen(s) {
    if (s.provider && usable(s.provider, s)) return s.provider;
    return Object.keys(PROVIDERS).find((p) => usable(p, s)) || "";
  }

  function status() {
    const s = load();
    const p = chosen(s);
    if (!p) return { ready: false, label: s.private ? "Private mode: configure a local model" : "AI off — add a free key (optional)" };
    const model = p === "server" ? (serverInfo.ai.route?.[0] || "") : (s.models[p] || PROVIDERS[p].models[0]);
    return { ready: true, private: s.private || !PROVIDERS[p].hosted, label: `${PROVIDERS[p].label} · ${model}` };
  }

  // Provider order: chosen first, then every other usable provider (if fallback).
  // Within a provider: chosen model first, then that provider's defaults.
  async function chat(messages) {
    const s = load();
    const first = chosen(s);
    if (!first) throw new Error(s.private ? "Private mode is on: start a local model (see docs/SELF_HOSTING.md) and select “Local model”." : "No AI provider configured. Open “AI settings” — or keep going without AI; every scan and fix works offline.");
    const order = [first, ...(s.fallback ? Object.keys(PROVIDERS).filter((p) => p !== first && usable(p, s)) : [])];
    const tried = [];
    for (const p of order) {
      const models = [...new Set([s.models[p] || PROVIDERS[p].models[0], ...(s.fallback ? PROVIDERS[p].models : [])])];
      for (const model of models) {
        try {
          const out = await PROVIDERS[p].call(s.keys[p], model, messages, s);
          if (typeof out === "object") return { ...out, tried };
          return { text: out, provider: PROVIDERS[p].label, model, tried };
        } catch (e) {
          tried.push(`${PROVIDERS[p].label}:${model} → ${e.message}`);
          if (e.status === 401 || e.status === 403) break; // bad key: skip this provider's other models
        }
      }
    }
    throw new Error("All AI routes failed:\n" + tried.join("\n"));
  }

  return { PROVIDERS, load, save, chat, status, detectServer, server: () => serverInfo };
})();
