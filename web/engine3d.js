// Hero scene: every format flows into one engine, and results flow out to
// every place TerraGuard runs. Falls back to the screenshot without WebGL,
// renders one still frame for reduced motion, and pauses when off screen.
import * as THREE from "./vendor/three.module.min.js";

const INPUTS = ["Terraform", "OpenTofu", "Kubernetes", "Helm", "CloudFormation", "ARM / Bicep", "Dockerfile", "Compose", "CI pipelines", "Ansible", "OpenAPI", "Pulumi", "Crossplane", "Plan JSON"];
const OUTPUTS = ["CLI", "CI gate", "Browser", "VS Code", "AI agents (MCP)", "Cluster admission", "Server API", "Pull request"];

function css(name, fallback) {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || fallback;
}

function label(text, color) {
  const c = document.createElement("canvas");
  const dpr = 2, pad = 14, font = 600 * 1;
  const ctx = c.getContext("2d");
  ctx.font = `${font} ${26 * dpr}px Manrope, system-ui, sans-serif`;
  const w = Math.ceil(ctx.measureText(text).width) + pad * 2 * dpr, h = 44 * dpr;
  c.width = w; c.height = h;
  ctx.font = `${font} ${26 * dpr}px Manrope, system-ui, sans-serif`;
  ctx.fillStyle = "rgba(10,14,24,0.72)";
  const r = 14 * dpr;
  ctx.beginPath(); ctx.roundRect(0, 0, w, h, r); ctx.fill();
  ctx.strokeStyle = color; ctx.globalAlpha = 0.55; ctx.lineWidth = 2 * dpr; ctx.stroke(); ctx.globalAlpha = 1;
  ctx.fillStyle = "#e8eefc"; ctx.textBaseline = "middle"; ctx.fillText(text, pad * dpr, h / 2 + dpr);
  const tex = new THREE.CanvasTexture(c);
  tex.colorSpace = THREE.SRGBColorSpace; tex.anisotropy = 4;
  const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false }));
  s.scale.set(w / h * 0.42, 0.42, 1);
  return s;
}

export function mount(host) {
  const probe = document.createElement("canvas");
  if (!host || !(probe.getContext("webgl2") || probe.getContext("webgl"))) return false;
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const accent = new THREE.Color(css("--accent", "#4fe3c1"));
  const violet = new THREE.Color(css("--accent-2", "#a78bfa"));
  const danger = new THREE.Color(css("--crit", "#ff5d6c"));

  const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: "low-power" });
  renderer.setPixelRatio(Math.min(devicePixelRatio || 1, 1.75));
  renderer.domElement.className = "engine3d-canvas";
  renderer.domElement.setAttribute("aria-hidden", "true");
  host.appendChild(renderer.domElement);
  host.classList.add("live");

  const scene = new THREE.Scene();
  scene.fog = new THREE.Fog(0x070a12, 9, 22);
  const camera = new THREE.PerspectiveCamera(42, 1, 0.1, 100);
  camera.position.set(0, 0, 11);

  // The engine core: a faceted shell around a glowing heart.
  const core = new THREE.Group();
  const shell = new THREE.Mesh(new THREE.IcosahedronGeometry(1.25, 1), new THREE.MeshBasicMaterial({ color: accent, wireframe: true, transparent: true, opacity: 0.55 }));
  const heart = new THREE.Mesh(new THREE.SphereGeometry(0.72, 32, 32), new THREE.MeshBasicMaterial({ color: violet, transparent: true, opacity: 0.85 }));
  const halo = new THREE.Mesh(new THREE.SphereGeometry(1.7, 32, 32), new THREE.MeshBasicMaterial({ color: accent, transparent: true, opacity: 0.06, side: THREE.BackSide }));
  core.add(shell, heart, halo);
  const coreLabel = label("One engine", accent.getStyle());
  coreLabel.position.set(0, -2.05, 0);
  core.add(coreLabel);
  scene.add(core);

  // Inputs on an arc to the left, outputs on an arc to the right: the flow reads left to right.
  const arc = (names, side, color) => names.map((name, i) => {
    const t = names.length === 1 ? 0.5 : i / (names.length - 1);
    const a = (t - 0.5) * Math.PI * 0.86;
    const p = new THREE.Vector3(side * (2.3 + Math.cos(a) * 0.9), (0.5 - t) * 6.6, 0); // even vertical spacing keeps labels apart
    const node = new THREE.Mesh(new THREE.OctahedronGeometry(0.12), new THREE.MeshBasicMaterial({ color }));
    node.position.copy(p);
    const l = label(name, color.getStyle());
    l.center.set(side < 0 ? 1 : 0, 0.5); // labels sit outside the arc
    l.position.copy(p).add(new THREE.Vector3(side * 0.24, 0, 0));
    scene.add(node, l);
    return { node, pos: p };
  });
  const ins = arc(INPUTS, -1, accent);
  const outs = arc(OUTPUTS, 1, violet);

  // Faint links from each node to the core.
  const linkMat = new THREE.LineBasicMaterial({ color: 0x6b7a99, transparent: true, opacity: 0.18 });
  const curves = [];
  for (const { pos } of ins) curves.push({ curve: new THREE.QuadraticBezierCurve3(pos, new THREE.Vector3(pos.x * 0.45, pos.y * 0.2, 0.4), new THREE.Vector3()), dir: 1 });
  for (const { pos } of outs) curves.push({ curve: new THREE.QuadraticBezierCurve3(new THREE.Vector3(), new THREE.Vector3(pos.x * 0.45, pos.y * 0.2, 0.4), pos), dir: -1 });
  for (const c of curves) scene.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(c.curve.getPoints(32)), linkMat));

  // Particles: code travelling in (teal), results going out (violet); a few
  // findings bounce back red, the way a gate refuses a change.
  const N = reduced ? 0 : 260;
  const geo = new THREE.BufferGeometry();
  const posArr = new Float32Array(N * 3), colArr = new Float32Array(N * 3);
  const state = Array.from({ length: N }, () => ({ c: (Math.random() * curves.length) | 0, t: Math.random(), v: 0.0025 + Math.random() * 0.004, bad: Math.random() < 0.08 }));
  geo.setAttribute("position", new THREE.BufferAttribute(posArr, 3));
  geo.setAttribute("color", new THREE.BufferAttribute(colArr, 3));
  const dots = new THREE.Points(geo, new THREE.PointsMaterial({ size: 0.07, vertexColors: true, transparent: true, opacity: 0.95, depthWrite: false, blending: THREE.AdditiveBlending }));
  scene.add(dots);

  // A slow starfield for depth.
  const stars = new THREE.BufferGeometry();
  const sp = new Float32Array(600 * 3);
  for (let i = 0; i < sp.length; i++) sp[i] = (Math.random() - 0.5) * 30;
  stars.setAttribute("position", new THREE.BufferAttribute(sp, 3));
  scene.add(new THREE.Points(stars, new THREE.PointsMaterial({ size: 0.02, color: 0x8899bb, transparent: true, opacity: 0.5 })));

  const pointer = { x: 0, y: 0 };
  host.addEventListener("pointermove", (e) => {
    const r = host.getBoundingClientRect();
    pointer.x = ((e.clientX - r.left) / r.width - 0.5) * 2;
    pointer.y = ((e.clientY - r.top) / r.height - 0.5) * 2;
  });

  const resize = () => {
    const w = host.clientWidth, h = host.clientHeight || w * 0.75;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    camera.position.z = camera.aspect < 1.25 ? 17 : 12;
    camera.updateProjectionMatrix();
  };
  new ResizeObserver(resize).observe(host);
  resize();

  let visible = true, last = 0;
  new IntersectionObserver(([e]) => { visible = e.isIntersecting; if (visible) requestAnimationFrame(frame); }).observe(host);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) requestAnimationFrame(frame); });

  const tmp = new THREE.Vector3();
  function frame(now) {
    if (!visible || document.hidden) return;
    const dt = Math.min(48, now - (last || now)) / 16.7;
    last = now;
    core.rotation.y += 0.004 * dt;
    shell.rotation.x += 0.002 * dt;
    heart.scale.setScalar(1 + Math.sin(now / 700) * 0.04);
    for (let i = 0; i < N; i++) {
      const s = state[i];
      s.t += s.v * dt;
      const c = curves[s.c];
      if (s.bad && c.dir === 1 && s.t > 0.82) { s.t = 0; s.c = (Math.random() * curves.length) | 0; }
      if (s.t > 1) { s.t = 0; s.c = (Math.random() * curves.length) | 0; s.bad = Math.random() < 0.08; }
      c.curve.getPoint(s.t, tmp);
      posArr.set([tmp.x, tmp.y, tmp.z], i * 3);
      const col = s.bad && c.dir === 1 && s.t > 0.6 ? danger : c.dir === 1 ? accent : violet;
      colArr.set([col.r, col.g, col.b], i * 3);
    }
    geo.attributes.position.needsUpdate = true;
    geo.attributes.color.needsUpdate = true;
    camera.position.x += (pointer.x * 1.2 - camera.position.x) * 0.04;
    camera.position.y += (-pointer.y * 0.8 - camera.position.y) * 0.04;
    camera.lookAt(0, 0, 0);
    renderer.render(scene, camera);
    if (!reduced) requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
  return true;
}

mount(document.getElementById("engine3d"));
