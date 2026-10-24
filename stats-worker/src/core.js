// Pure counter logic shared by the Durable Object and the tests.
// Stores numbers only: never code, file names, IP addresses or keys.

const SURFACES = new Set(["web", "cli", "action", "api", "mcp"]);
const clamp = (n, max) => Math.max(0, Math.min(max, Number.isFinite(+n) ? Math.floor(+n) : 0));
const empty = () => ({ scans: 0, files: 0, resources: 0, fixes: 0, ai: 0, findings: 0, ms_total: 0 });

export function newState() {
  return { total: empty(), days: {}, surfaces: {}, rules: {}, since: new Date().toISOString() };
}

export function record(state, hit, now = new Date()) {
  const c = {
    scans: clamp(hit.scans, 500), files: clamp(hit.files, 20000), resources: clamp(hit.resources, 100000),
    fixes: clamp(hit.fixes, 500), ai: clamp(hit.ai, 100), findings: clamp(hit.findings, 50000), ms_total: clamp(hit.ms, 600000),
  };
  const day = now.toISOString().slice(0, 10);
  state.days[day] ||= empty();
  for (const target of [state.days[day], state.total]) for (const k in c) target[k] += c[k];
  const surface = SURFACES.has(hit.surface) ? hit.surface : "other";
  state.surfaces[surface] = (state.surfaces[surface] || 0) + c.scans;
  for (const [id, n] of Object.entries(hit.rules || {}).slice(0, 100)) {
    if (/^[A-Z0-9-]{3,40}$/.test(id) && (id in state.rules || Object.keys(state.rules).length < 500)) state.rules[id] = (state.rules[id] || 0) + clamp(n, 1000);
  }
  // keep 60 days of history
  const cutoff = new Date(now.getTime() - 60 * 864e5).toISOString().slice(0, 10);
  for (const d of Object.keys(state.days)) if (d < cutoff) delete state.days[d];
  return state;
}

export function snapshot(state, sessions, now = new Date()) {
  const days = [];
  for (let i = 6; i >= 0; i--) {
    const date = new Date(now.getTime() - i * 864e5).toISOString().slice(0, 10);
    days.push({ date, ...(state.days[date] || empty()) });
  }
  let active = 0;
  for (const [id, t] of sessions) {
    if (now - t <= 120000) active++;
    else sessions.delete(id);
  }
  const top_rules = Object.entries(state.rules).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 10).map(([id, count]) => ({ id, count }));
  return { source: "global", today: days[6], total: state.total, days, active_now: active, running_now: 0, by_surface: state.surfaces, top_rules, since: state.since, updated: now.toISOString() };
}
