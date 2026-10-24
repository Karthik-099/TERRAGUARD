// TerraGuard public usage counters: Cloudflare Worker + one Durable Object.
//   POST /hit    {session, surface, scans, files, resources, fixes, ai, findings, ms, rules}
//   GET  /stats  public dashboard JSON (same shape as `terraguard serve` /api/stats)
import { newState, record, snapshot } from "./core.js";

export class Stats {
  constructor(ctx) {
    this.ctx = ctx;
    this.sessions = new Map(); // in-memory only: "active now" needs no persistence
  }

  async fetch(request) {
    const url = new URL(request.url);
    const state = (await this.ctx.storage.get("state")) || newState();
    if (request.method === "POST" && url.pathname === "/hit") {
      const hit = await request.json();
      if (typeof hit.session === "string" && hit.session.length <= 64) this.sessions.set(hit.session, Date.now());
      await this.ctx.storage.put("state", record(state, hit));
      return new Response(null, { status: 204 });
    }
    return Response.json(snapshot(state, this.sessions));
  }
}

const buckets = new Map(); // per-isolate rate limit; the IP is never stored or logged

function rateLimited(ip) {
  const now = Date.now();
  const b = buckets.get(ip) || { tokens: 30, at: now };
  b.tokens = Math.min(30, b.tokens + ((now - b.at) / 1000) * 0.5);
  b.at = now;
  buckets.set(ip, b);
  if (buckets.size > 10000) buckets.clear();
  if (b.tokens < 1) return true;
  b.tokens -= 1;
  return false;
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const allowed = (env.ALLOWED_ORIGINS || "*").split(",").map((s) => s.trim());
    const cors = {
      "Access-Control-Allow-Origin": allowed.includes("*") ? "*" : allowed.includes(origin) ? origin : allowed[0],
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      Vary: "Origin",
    };
    if (request.method === "OPTIONS") return new Response(null, { headers: cors });

    const url = new URL(request.url);
    const stub = env.STATS.get(env.STATS.idFromName("global"));

    if (request.method === "POST" && url.pathname === "/hit") {
      if (rateLimited(request.headers.get("CF-Connecting-IP") || "")) return new Response("slow down", { status: 429, headers: cors });
      const body = await request.text();
      if (body.length > 16384) return new Response("too large", { status: 413, headers: cors });
      let hit;
      try { hit = JSON.parse(body); } catch { return new Response("bad json", { status: 400, headers: cors }); }
      const res = await stub.fetch("https://do/hit", { method: "POST", body: JSON.stringify(hit) });
      return new Response(null, { status: res.status, headers: cors });
    }
    if (request.method === "GET" && (url.pathname === "/stats" || url.pathname === "/")) {
      const res = await stub.fetch("https://do/stats");
      return new Response(res.body, { headers: { ...cors, "Content-Type": "application/json", "Cache-Control": "public, max-age=10" } });
    }
    return new Response("not found", { status: 404, headers: cors });
  },
};
