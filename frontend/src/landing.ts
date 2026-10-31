/**
 * FaceVault landing page.
 * - Hero: a face mesh assembles, is scanned into a feature vector, dissolves into ciphertext glyphs
 *   and is sealed in the database vault. The mesh reacts to the cursor.
 * - "Try the crypto": real AES-256-GCM in the browser (WebCrypto), including a live tamper test.
 * - Scroll reveals, a sticky layer counter, count-ups, an "attacker's view" that keeps re-scrambling,
 *   flip cards for the threat model, and a live API status check.
 * Everything respects prefers-reduced-motion. No inline scripts or style attributes (strict CSP).
 */
import "./styles.css";
import { $, el } from "./dom";
import { initMarquee, initTheme } from "./effects";

const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;
const HEX = "0123456789abcdef";
const randHex = (n: number) => Array.from(crypto.getRandomValues(new Uint8Array(Math.ceil(n / 2))), (b) => b.toString(16).padStart(2, "0")).join("").slice(0, n);
const toHex = (buf: ArrayBuffer | Uint8Array) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const clamp01 = (v: number) => Math.max(0, Math.min(1, v));
const easeOut = (t: number) => 1 - (1 - t) ** 3;
const easeInOut = (t: number) => (t < 0.5 ? 4 * t * t * t : 1 - (-2 * t + 2) ** 3 / 2);
const cssVar = (name: string) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

/* ====================================================================== text scramble */
const scrambling = new WeakMap<Element, number>();

/** Reveal `text` left to right; characters not yet revealed flicker as random hex. */
function scramble(node: Element, text: string, ms = 650): void {
  cancelAnimationFrame(scrambling.get(node) ?? 0);
  if (reduceMotion) {
    node.textContent = text;
    return;
  }
  const start = performance.now();
  const step = (now: number) => {
    const p = clamp01((now - start) / ms);
    const shown = Math.floor(text.length * easeOut(p));
    let out = text.slice(0, shown);
    for (let i = shown; i < text.length; i++) out += text[i] === " " ? " " : HEX[(Math.random() * 16) | 0];
    node.textContent = out;
    if (p < 1) scrambling.set(node, requestAnimationFrame(step));
  };
  scrambling.set(node, requestAnimationFrame(step));
}

/* ====================================================================== hero animation */
type Particle = {
  hx: number; hy: number;          // home position on the face (normalised, -1..1)
  sx: number; sy: number;          // scattered start position (canvas px)
  ox: number; oy: number;          // smoothed cursor push (canvas px)
  vaultX: number;                  // landing slot inside the vault (0..1)
  delay: number; glyph: string;
};

function seeded(seed: number) {
  return () => {
    seed = (seed * 1664525 + 1013904223) >>> 0;
    return seed / 2 ** 32;
  };
}

/** Face landmarks in normalised coordinates, plus which points are joined by lines. */
function buildFace(): { pts: [number, number][]; edges: [number, number][] } {
  const pts: [number, number][] = [];
  const edges: [number, number][] = [];
  const contour = (points: [number, number][], closed: boolean) => {
    const base = pts.length;
    pts.push(...points);
    for (let i = 0; i < points.length - 1; i++) edges.push([base + i, base + i + 1]);
    if (closed) edges.push([base + points.length - 1, base]);
  };
  const ellipse = (cx: number, cy: number, rx: number, ry: number, n: number): [number, number][] =>
    Array.from({ length: n }, (_, i) => {
      const a = (i / n) * Math.PI * 2;
      return [cx + rx * Math.cos(a), cy + ry * Math.sin(a)];
    });
  // head outline
  contour(Array.from({ length: 28 }, (_, i) => {
    const a = (i / 28) * Math.PI * 2;
    const jaw = Math.sin(a) > 0 ? 0.9 : 0.86; // slightly longer chin
    return [0.74 * Math.cos(a) * (Math.sin(a) > 0.55 ? 1 - (Math.sin(a) - 0.55) * 0.35 : 1), 0.06 + jaw * Math.sin(a)];
  }), true);
  for (const side of [-1, 1]) {
    contour(Array.from({ length: 5 }, (_, i) => [side * (0.14 + i * 0.1), -0.27 - 0.07 * Math.sin((i / 4) * Math.PI)]), false); // brow
    contour(ellipse(side * 0.33, -0.1, 0.15, 0.055, 8), true); // eye
    pts.push([side * 0.33, -0.1]); // pupil
  }
  contour([[0, -0.12], [0, 0.02], [0.02, 0.15], [0.06, 0.26], [0, 0.3], [-0.06, 0.26], [-0.02, 0.15], [0, 0.02]], false); // nose
  contour(ellipse(0, 0.54, 0.25, 0.085, 12), true); // mouth outer
  contour(ellipse(0, 0.54, 0.14, 0.025, 8), true); // mouth inner
  // interior mesh points, each joined to its two nearest neighbours
  const rnd = seeded(1704);
  const meshStart = pts.length;
  while (pts.length < meshStart + 34) {
    const x = (rnd() * 2 - 1) * 0.68, y = (rnd() * 2 - 1) * 0.86 + 0.04;
    if ((x / 0.68) ** 2 + ((y - 0.06) / 0.86) ** 2 < 0.9) pts.push([x, y]);
  }
  for (let i = meshStart; i < pts.length; i++) {
    const near = pts.map((p, j) => [j, Math.hypot(p[0] - pts[i][0], p[1] - pts[i][1])] as const)
      .filter(([j]) => j !== i).sort((a, b) => a[1] - b[1]).slice(0, 2);
    for (const [j] of near) edges.push([i, j]);
  }
  return { pts, edges };
}

const PHASES = [
  { label: "capturing", from: 0, to: 2.2 },
  { label: "128-d vector", from: 2.2, to: 4.6 },
  { label: "encrypting", from: 4.6, to: 7.2 },
  { label: "sealed · AES-256-GCM", from: 7.2, to: 10 },
];
const LOOP = 10;

function initHero(): void {
  const canvas = $<HTMLCanvasElement>("#hero-canvas");
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  const { pts, edges } = buildFace();
  let w = 0, h = 0, dpr = 1;
  let particles: Particle[] = [];
  const mouse = { x: -1e4, y: -1e4 };
  let colors = { acid: "", mint: "", teal: "", muted: "", edge: "", text: "", surface: "" };
  const readColors = () => {
    colors = {
      acid: cssVar("--acid"), mint: cssVar("--mint"), teal: cssVar("--teal"), muted: cssVar("--text-muted"),
      edge: cssVar("--border-strong"), text: cssVar("--text-primary"), surface: cssVar("--surface-2"),
    };
  };

  const scatter = () => {
    const rnd = Math.random;
    particles = pts.map(([hx, hy], i) => {
      const a = rnd() * Math.PI * 2, r = Math.max(w, h) * (0.6 + rnd() * 0.3);
      return {
        hx, hy, sx: w / 2 + Math.cos(a) * r, sy: h * 0.42 + Math.sin(a) * r, ox: 0, oy: 0,
        vaultX: (i + 0.5) / pts.length, delay: rnd() * 0.9, glyph: HEX[(rnd() * 16) | 0],
      };
    });
  };

  const resize = () => {
    dpr = Math.min(2, window.devicePixelRatio || 1);
    w = canvas.clientWidth;
    h = canvas.clientHeight;
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    scatter();
  };

  canvas.addEventListener("pointermove", (e) => {
    const r = canvas.getBoundingClientRect();
    mouse.x = e.clientX - r.left;
    mouse.y = e.clientY - r.top;
  });
  canvas.addEventListener("pointerleave", () => { mouse.x = mouse.y = -1e4; });

  const phaseBadge = $("#hero-phase");
  const steps = [...document.querySelectorAll<HTMLElement>(".phase-step")];
  let lastPhase = -1;
  const setPhase = (i: number) => {
    if (i === lastPhase) return;
    lastPhase = i;
    phaseBadge.textContent = PHASES[i].label;
    phaseBadge.className = `badge ${i === 3 ? "badge-good" : i === 2 ? "badge-warn" : "badge-neutral"}`;
    steps.forEach((s, j) => s.classList.toggle("on", j === i));
  };

  const draw = (t: number) => {
    const cx = w / 2, cy = h * 0.42, s = Math.min(w, h) * 0.34;
    const vault = { x: w * 0.2, y: h * 0.84, w: w * 0.6, h: h * 0.1 };
    ctx.clearRect(0, 0, w, h);

    // dot grid backdrop
    ctx.fillStyle = colors.edge;
    for (let gx = 12; gx < w; gx += 24) for (let gy = 12; gy < h; gy += 24) ctx.fillRect(gx, gy, 1, 1);

    const phase = PHASES.findIndex((p) => t >= p.from && t < p.to);
    setPhase(Math.max(0, phase));
    const scanY = -1.05 + 2.2 * clamp01((t - 2.2) / 2.2);       // normalised y of the scan line
    const encrypting = clamp01((t - 4.6) / 2.4);
    const sealed = clamp01((t - 7.2) / 0.5);
    const fadeOut = clamp01((t - 9.4) / 0.6);

    // positions
    const pos = particles.map((p) => {
      const hx = cx + p.hx * s, hy = cy + p.hy * s;
      // cursor push (only while the face is intact)
      const d = Math.hypot(hx - mouse.x, hy - mouse.y), R = 90;
      const push = d < R && encrypting === 0 ? ((R - d) / R) * 26 : 0;
      p.ox += ((push ? ((hx - mouse.x) / (d || 1)) * push : 0) - p.ox) * 0.15;
      p.oy += ((push ? ((hy - mouse.y) / (d || 1)) * push : 0) - p.oy) * 0.15;
      const assemble = easeOut(clamp01((t - p.delay) / 1.3));
      let x = p.sx + (hx - p.sx) * assemble + p.ox;
      let y = p.sy + (hy - p.sy) * assemble + p.oy;
      const e = easeInOut(clamp01((encrypting * 2.4 - p.delay * 0.8) / 1.4));
      if (e > 0) { // arc down into the vault
        const tx = vault.x + p.vaultX * vault.w, ty = vault.y + vault.h / 2;
        const mx = (x + tx) / 2 + (p.hx > 0 ? 40 : -40), my = Math.min(y, ty) - 30;
        x = (1 - e) ** 2 * x + 2 * (1 - e) * e * mx + e * e * tx;
        y = (1 - e) ** 2 * y + 2 * (1 - e) * e * my + e * e * ty;
      }
      return { x, y, e, scanned: p.hy < scanY };
    });

    // mesh lines
    const lineAlpha = (1 - encrypting) * (1 - fadeOut);
    if (lineAlpha > 0) {
      ctx.lineWidth = 1;
      for (const [a, b] of edges) {
        const pa = pos[a], pb = pos[b];
        ctx.strokeStyle = pa.scanned && pb.scanned ? colors.acid : colors.edge;
        ctx.globalAlpha = lineAlpha * (pa.scanned && pb.scanned ? 0.75 : 0.55);
        ctx.beginPath();
        ctx.moveTo(pa.x, pa.y);
        ctx.lineTo(pb.x, pb.y);
        ctx.stroke();
      }
      ctx.globalAlpha = 1;
    }

    // scan line
    if (t >= 2.2 && t < 4.6) {
      const y = cy + scanY * s;
      const g = ctx.createLinearGradient(0, y - 40, 0, y);
      g.addColorStop(0, "transparent");
      g.addColorStop(1, colors.acid);
      ctx.globalAlpha = 0.25;
      ctx.fillStyle = g;
      ctx.fillRect(cx - s * 0.95, y - 40, s * 1.9, 40);
      ctx.globalAlpha = 1;
      ctx.fillStyle = colors.acid;
      ctx.fillRect(cx - s * 0.95, y - 1, s * 1.9, 2);
    }

    // points / glyphs
    ctx.font = `bold ${Math.max(10, s * 0.075)}px "Space Mono", monospace`;
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    pos.forEach((q, i) => {
      if (sealed >= 1 || fadeOut > 0) return;
      const p = particles[i];
      ctx.globalAlpha = 1 - sealed;
      if (q.e > 0.05) {
        if (Math.random() < 0.12) p.glyph = HEX[(Math.random() * 16) | 0];
        ctx.fillStyle = i % 3 === 0 ? colors.mint : colors.acid;
        ctx.fillText(p.glyph, q.x, q.y);
      } else {
        ctx.fillStyle = q.scanned ? colors.acid : colors.text;
        ctx.beginPath();
        ctx.arc(q.x, q.y, q.scanned ? 2.6 : 2, 0, Math.PI * 2);
        ctx.fill();
      }
    });
    ctx.globalAlpha = 1;

    // vault
    const glow = sealed * (1 - fadeOut);
    ctx.lineWidth = 2;
    ctx.strokeStyle = glow > 0 ? colors.acid : colors.edge;
    ctx.fillStyle = colors.surface;
    ctx.beginPath();
    ctx.roundRect(vault.x, vault.y, vault.w, vault.h, 8);
    ctx.fill();
    ctx.stroke();
    if (glow > 0) {
      ctx.save();
      ctx.beginPath();
      ctx.roundRect(vault.x, vault.y, vault.w, vault.h, 8);
      ctx.clip();
      ctx.globalAlpha = glow * 0.9;
      ctx.fillStyle = colors.acid;
      ctx.font = `${Math.max(9, vault.h * 0.28)}px "Space Mono", monospace`;
      ctx.textAlign = "left";
      const stream = randHex(160);
      ctx.fillText(stream, vault.x + 10 - ((t * 60) % 40), vault.y + vault.h * 0.32);
      ctx.restore();
      ctx.globalAlpha = glow;
      ctx.fillStyle = colors.text;
      ctx.font = `bold ${Math.max(10, vault.h * 0.3)}px "Space Mono", monospace`;
      ctx.textAlign = "center";
      ctx.fillText("🔒 SEALED · AES-256-GCM", vault.x + vault.w / 2, vault.y + vault.h * 0.72);
      ctx.globalAlpha = 1;
    } else {
      ctx.fillStyle = colors.muted;
      ctx.font = `${Math.max(9, vault.h * 0.3)}px "Space Mono", monospace`;
      ctx.textAlign = "center";
      ctx.fillText("biometric.db", vault.x + vault.w / 2, vault.y + vault.h / 2);
    }

    // HUD
    ctx.textAlign = "left";
    ctx.font = `${Math.max(9, s * 0.06)}px "Space Mono", monospace`;
    ctx.fillStyle = colors.muted;
    const scannedCount = pos.filter((q) => q.scanned).length;
    const hud = t < 2.2 ? "locating landmarks…" : t < 4.6 ? `features ${Math.min(128, Math.round((scannedCount / pos.length) * 128))}/128`
      : t < 7.2 ? "AES-256-GCM · fresh DEK · AAD=id" : "plaintext discarded";
    ctx.fillText(hud, 14, 22);
  };

  let start = performance.now();
  let raf = 0;
  let running = false;
  const frame = (now: number) => {
    let t = (now - start) / 1000;
    if (t >= LOOP) {
      start = now;
      t = 0;
      scatter();
    }
    draw(t);
    raf = requestAnimationFrame(frame);
  };
  const run = (on: boolean) => {
    if (on === running) return;
    running = on;
    if (on) {
      start = performance.now() - 0.001;
      raf = requestAnimationFrame(frame);
    } else {
      cancelAnimationFrame(raf);
    }
  };

  readColors();
  resize();
  new ResizeObserver(resize).observe(canvas);
  new MutationObserver(readColors).observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });

  if (reduceMotion) {
    draw(4.0); // static frame: the scanned mesh
    new MutationObserver(() => { readColors(); draw(4.0); })
      .observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    return;
  }
  new IntersectionObserver(([entry]) => run(entry.isIntersecting && !document.hidden)).observe(canvas);
  document.addEventListener("visibilitychange", () => run(!document.hidden));
}

/* ====================================================================== scroll effects */
function initScroll(): void {
  const bar = $("#scroll-progress");
  const onScroll = () => {
    const max = document.documentElement.scrollHeight - innerHeight;
    bar.style.transform = `scaleX(${max > 0 ? scrollY / max : 0})`;
  };
  addEventListener("scroll", onScroll, { passive: true });
  onScroll();

  const reveal = new IntersectionObserver((entries) => {
    for (const e of entries) if (e.isIntersecting) {
      e.target.classList.add("in");
      reveal.unobserve(e.target);
    }
  }, { threshold: 0.15 });
  document.querySelectorAll(".reveal").forEach((n) => reveal.observe(n));

  const counters = new IntersectionObserver((entries) => {
    for (const e of entries) if (e.isIntersecting) {
      counters.unobserve(e.target);
      countUp(e.target as HTMLElement);
    }
  }, { threshold: 0.6 });
  document.querySelectorAll("[data-count]").forEach((n) => counters.observe(n));
}

/** Count up to the target; a target of 0 counts *down* from 512 (the plaintext bytes that disappear). */
function countUp(node: HTMLElement): void {
  const target = Number(node.dataset.count);
  const from = target === 0 ? 512 : 0;
  if (reduceMotion) {
    node.textContent = String(target);
    return;
  }
  const start = performance.now(), ms = 1400;
  const step = (now: number) => {
    const p = easeOut(clamp01((now - start) / ms));
    node.textContent = String(Math.round(from + (target - from) * p));
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

/* ====================================================================== layers */
const LAYERS: [string, string, string][] = [
  ["Capture in browser", "📷", "face-api.js turns your face into 128 numbers inside the browser. The photo itself never leaves your device."],
  ["Transport encryption", "🛰️", "A fresh AES-256-GCM key encrypts the vector; RSA-OAEP-3072 wraps that key. A timestamp and a random nonce make every request single-use."],
  ["Envelope encryption", "✉️", "Each person gets their own random data key (DEK), wrapped by a versioned master key (KEK). One leaked DEK exposes one person, not everyone."],
  ["Row binding", "🔗", "The record ID is bound in as AAD. Copy Alice's ciphertext onto Bob's row and decryption fails."],
  ["Blind index", "🙈", "Emails are encrypted too. Lookups use an HMAC-SHA256 blind index, so they're never stored readably."],
  ["Match in memory", "🧠", "Templates are decrypted only in RAM to measure distance, then discarded. A failed match never reveals its score."],
  ["Tamper-evident audit", "⛓️", "Every action is chained with HMAC-SHA256. Edit or delete one log line and the chain breaks at that exact entry."],
];

function initLayers(): void {
  const list = $("#layers");
  list.replaceChildren(...LAYERS.map(([title, icon, text], i) =>
    el("li", { class: "layer reveal", "data-index": String(i) },
      el("div", { class: "flex items-start gap-5" },
        el("span", { class: "layer-no" }, String(i + 1).padStart(2, "0")),
        el("div", {},
          el("p", { class: "text-lg font-bold text-primary" }, `${icon} ${title}`),
          el("p", { class: "mt-1.5 text-[0.9375rem] leading-relaxed text-secondary" }, text))))));

  const num = $("#layer-num"), name = $("#layer-name"), bar = $("#layer-bar");
  const items = [...list.querySelectorAll<HTMLElement>(".layer")];
  const activate = (i: number) => {
    items.forEach((n, j) => n.classList.toggle("active", j === i));
    const label = String(i + 1).padStart(2, "0");
    if (num.textContent !== label) scramble(num, label, 300);
    name.textContent = LAYERS[i][0];
    bar.style.width = `${((i + 1) / LAYERS.length) * 100}%`;
  };
  const io = new IntersectionObserver((entries) => {
    for (const e of entries) if (e.isIntersecting) activate(Number((e.target as HTMLElement).dataset.index));
  }, { rootMargin: "-45% 0px -45% 0px" });
  items.forEach((n) => io.observe(n));
  activate(0);
}

/* ====================================================================== try the crypto */
async function vectorFrom(name: string): Promise<Float32Array> {
  const bytes = new Uint8Array(128);
  for (let block = 0; block < 4; block++) {
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${name.trim().toLowerCase()}#${block}`)));
    bytes.set(digest, block * 32);
  }
  return Float32Array.from(bytes, (b) => ((b - 128) / 128) * 0.25);
}

function initTry(): void {
  const input = $<HTMLInputElement>("#try-name");
  const grid = $("#try-vector"), head = $("#try-vector-head");
  const nonceEl = $("#try-nonce"), ctEl = $("#try-ct"), sizeEl = $("#try-size"), resultEl = $("#try-result");
  let sealedBox: { key: CryptoKey; iv: Uint8Array<ArrayBuffer>; ct: ArrayBuffer; aad: Uint8Array<ArrayBuffer>; plain: Float32Array } | null = null;

  const cells = Array.from({ length: 128 }, () => el("i", { class: "block h-3 rounded-[2px] transition-colors duration-500" }));
  grid.replaceChildren(...cells);

  const notice = (tone: "good" | "critical", title: string, detail: string) => {
    resultEl.replaceChildren(el("div", { class: `notice notice-${tone}`, role: tone === "good" ? "status" : "alert" },
      el("span", { class: `mt-px shrink-0 font-mono font-bold ${tone === "good" ? "text-good" : "text-critical"}`, "aria-hidden": "true" }, tone === "good" ? "✓" : "✕"),
      el("div", { class: "min-w-0 flex-1 space-y-1 text-secondary" }, el("h4", {}, title), el("p", { class: "font-mono text-[0.75rem] break-all" }, detail))));
  };

  const seal = async () => {
    const plain = await vectorFrom(input.value || "anonymous");
    plain.forEach((v, i) => {
      const t = Math.max(-1, Math.min(1, v / 0.25));
      cells[i].style.background = t >= 0 ? `rgb(35 248 113 / ${0.1 + 0.9 * t})` : `rgb(255 77 61 / ${0.1 + 0.9 * -t})`;
    });
    head.textContent = `[${Array.from(plain.slice(0, 6), (v) => v.toFixed(4)).join(", ")}, …]  · 128 × float32 = 512 bytes`;
    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const aad = new TextEncoder().encode(`bfe:template:v1:demo-${randHex(8)}`);
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, key, plain.buffer as ArrayBuffer);
    sealedBox = { key, iv, ct, aad, plain };
    scramble(nonceEl, toHex(iv), 500);
    scramble(ctEl, toHex(ct), 900);
    sizeEl.textContent = `(${ct.byteLength} B = 512 + 16-byte tag)`;
    resultEl.replaceChildren();
  };

  let debounce = 0;
  input.addEventListener("input", () => {
    clearTimeout(debounce);
    debounce = window.setTimeout(() => void seal(), 220);
  });
  $("#try-reseal").addEventListener("click", () => void seal());
  $("#try-decrypt").addEventListener("click", async () => {
    if (!sealedBox) return;
    const { key, iv, ct, aad, plain } = sealedBox;
    const out = new Float32Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: aad }, key, ct));
    const same = out.every((v, i) => v === plain[i]);
    notice(same ? "good" : "critical", same ? "Decrypted: all 128 values match" : "Mismatch",
      "GCM tag verified, so the ciphertext is authentic and unmodified.");
  });
  $("#try-tamper").addEventListener("click", async () => {
    if (!sealedBox) return;
    const { key, iv, ct, aad } = sealedBox;
    const bad = new Uint8Array(ct.slice(0));
    const byte = Math.floor(Math.random() * bad.length), bit = Math.floor(Math.random() * 8);
    bad[byte] ^= 1 << bit;
    try {
      await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: aad }, key, bad);
      notice("critical", "Tampering NOT detected", "This should never happen.");
    } catch (e) {
      notice("good", "Tampering detected: decryption refused",
        `Flipped bit ${bit} of byte ${byte}. WebCrypto threw ${(e as Error).name}: the authentication tag no longer matches.`);
    }
  });
  void seal();
}

/* ====================================================================== attacker's view */
function initDump(): void {
  const fields: [string, () => string][] = [
    ["id", () => `${randHex(8)}-${randHex(4)}-4${randHex(3)}-a${randHex(3)}-${randHex(12)}`],
    ["email_index", () => `${randHex(48)}…`],
    ["template_ct", () => `${randHex(56)}… (528 B)`],
    ["template_nonce", () => randHex(24)],
    ["pii_ct", () => `${randHex(40)}…`],
    ["wrapped_dek", () => `${randHex(40)}…`],
    ["key_version", () => String(1 + Math.floor(Math.random() * 3))],
  ];
  const dump = $("#dump");
  const values: HTMLElement[] = [];
  dump.replaceChildren(...[0, 1].map(() =>
    el("dl", { class: "space-y-1 border-l-2 border-[#333337] pl-3" }, fields.map(([k, gen]) => {
      const dd = el("dd", {}, gen());
      values.push(dd);
      (dd as HTMLElement & { gen?: () => string }).gen = gen;
      return el("div", { class: "dump-row" }, el("dt", {}, k), dd);
    }))));
  if (reduceMotion) return;
  setInterval(() => {
    if (document.hidden) return;
    const dd = values[Math.floor(Math.random() * values.length)] as HTMLElement & { gen?: () => string };
    if (dd.gen) scramble(dd, dd.gen(), 600);
  }, 700);
}

/* ====================================================================== threats */
const THREATS: [string, string, string][] = [
  ["💾", "Database file stolen", "Everything is ciphertext. The keys live in a separate, scrypt-locked keyring."],
  ["🕵️", "Insider swaps two faces", "The GCM tag fails and the record is flagged TAMPERED; AAD binds each ciphertext to its row."],
  ["📡", "Man in the middle", "TLS, plus hybrid RSA-OAEP + AES-GCM payload encryption, plus a key fingerprint you can compare."],
  ["🔁", "Replaying a captured scan", "Every envelope carries a timestamp and a single-use nonce. Replays are rejected."],
  ["🧗", "Hill-climbing the score", "Failed matches never return a distance, and verification is rate-limited."],
  ["🔨", "Password brute force", "scrypt hashing, rate limits, and a 15-minute lockout after 5 failures."],
  ["🧹", "Covering tracks in the log", "The HMAC-chained audit log names the exact entry that was edited or deleted."],
  ["🔑", "Master key compromised", "Rotate the KEK in one click, then crypto-shred the old one."],
];

function initThreats(): void {
  $("#threat-grid").replaceChildren(...THREATS.map(([icon, attack, defence], i) => {
    const card = el("div", { class: "flip reveal", tabindex: "0", role: "button", "aria-label": `${attack}. Defence: ${defence}` },
      el("div", { class: "flip-inner" },
        el("div", { class: "flip-face flip-front" },
          el("span", { class: "font-mono text-[0.6875rem] font-bold tracking-wider text-critical uppercase" }, `attack ${String(i + 1).padStart(2, "0")}`),
          el("span", { class: "mt-4 text-4xl", "aria-hidden": "true" }, icon),
          el("p", { class: "mt-auto text-xl leading-tight font-black text-primary" }, attack)),
        el("div", { class: "flip-face flip-back" },
          el("span", { class: "font-mono text-[0.6875rem] font-bold tracking-wider uppercase" }, "defence ✓"),
          el("p", { class: "mt-auto text-[0.9375rem] leading-snug font-semibold" }, defence))));
    card.addEventListener("click", () => card.classList.toggle("flipped"));
    card.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        card.classList.toggle("flipped");
      }
    });
    return card;
  }));
}

/* ====================================================================== live status */
async function initStatus(): Promise<void> {
  const status = $("#status-online"), note = $("#status-note");
  const set = (online: boolean, text: string) => {
    const dot = el("span", { class: `size-2.5 rounded-full ${online ? "animate-pulse bg-acid" : "bg-[#ff4d3d]"}` });
    status.replaceChildren(dot, online ? "Online" : "Offline");
    status.classList.toggle("text-acid", online);
    status.classList.toggle("text-[#ff4d3d]", !online);
    note.textContent = text;
  };
  const slow = window.setTimeout(() => { note.textContent = "waking the backend (free plan: up to a minute)…"; }, 4000);
  try {
    const ctrl = new AbortController();
    const timeout = window.setTimeout(() => ctrl.abort(), 75000);
    const r = await fetch("/api/health", { signal: ctrl.signal, cache: "no-store" });
    clearTimeout(timeout);
    const h = (await r.json()) as { status: string; tls: boolean };
    set(h.status === "ok", `API healthy · ${h.tls ? "TLS on" : "TLS off (local)"}`);
  } catch {
    set(false, "API unreachable. Running locally? Use start.bat.");
  } finally {
    clearTimeout(slow);
  }
}

/* ====================================================================== boot */
document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  initMarquee();
  initHero();
  initLayers();
  initTry();
  initDump();
  initThreats();
  initScroll(); // last, so it also observes the .reveal items created above
  void initStatus();
});
