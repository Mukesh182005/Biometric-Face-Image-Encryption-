/** One loader / action per screen. All DOM text goes through el() so API data can never inject markup. */
import { api } from "./api";
import { getServerKey, sealForTransport, serverFingerprint } from "./crypto";
import { $, el, errorMessage, kv, pill, result, sleep, table, toast, withBusy } from "./dom";
import { playLoader } from "./effects";
import { captureDescriptor, snapshot, vectorHeatmap } from "./face";
import { state, type View } from "./state";
import type {
  AuditEntry, ChainResult, DemoResponse, EnrollResponse, IdentifyResponse, InspectorRow, KeyStatus, KeyVersion,
  LoginResponse, Operator, ResultKind, RotateResponse, Stats, Subject, VerifyResponse,
} from "./types";

const HEADINGS: Record<View, { eyebrow: string; title: string; sub: string }> = {
  login: { eyebrow: "super admin access", title: "Welcome back", sub: "FaceVault is restricted to its super administrator. Sign in to manage the encrypted face database." },
  dashboard: { eyebrow: "overview", title: "Dashboard", sub: "Live counters from the encrypted template store and the audit chain." },
  enroll: { eyebrow: "enroll · write", title: "Enroll a subject", sub: "Capture a face, average three samples into one template, and seal it with a fresh per-record key." },
  verify: { eyebrow: "verify · 1:1 · public", title: "Verify identity", sub: "No sign-in needed. Enter the e-mail you were enrolled with, then prove it's you with your face. No score is disclosed on failure." },
  identify: { eyebrow: "identify · 1:n", title: "Identify a face", sub: "Search every encrypted template for the closest match." },
  lab: { eyebrow: "crypto lab", title: "Crypto lab", sub: "Watch one capture travel through transport encryption, envelope encryption and tamper tests." },
  subjects: { eyebrow: "subjects · read", title: "Subjects", sub: "Every enrolled identity, with an integrity check on each encrypted record." },
  inspector: { eyebrow: "db.dump", title: "DB inspector", sub: "Exactly what the database file holds on disk." },
  audit: { eyebrow: "root · audit", title: "Audit log", sub: "Tamper-evident record of every action, chained with HMAC-SHA256." },
  keys: { eyebrow: "root · keyring", title: "Key management", sub: "Versioned key-encryption keys, rotation and crypto-shredding." },
  operators: { eyebrow: "root · access", title: "Operators", sub: "Who can sign in. There is exactly one account, and creating new ones is disabled." },
};

const CAMERA_VIEWS = new Set<View>(["enroll", "verify", "identify", "lab"]);
const LOADERS: Partial<Record<View, () => Promise<void>>> = {
  dashboard: loadDashboard, subjects: loadSubjects, inspector: loadInspector,
  audit: loadAudit, keys: loadKeys, operators: loadOperators,
};

type AuthRule = "none" | "any" | "admin";

/** Verify is public; every other screen needs a session, which only the super administrator can obtain. */
function allowed(rule: string | undefined): boolean {
  switch (rule as AuthRule) {
    case "none": return true;
    case "any": return !!state.token;
    case "admin": return state.role === "admin";
    default: return false;
  }
}

export function renderNav(): void {
  document.querySelectorAll<HTMLElement>("#nav [data-auth]").forEach((n) => (n.hidden = !allowed(n.dataset.auth)));
  const session = $("#session");
  if (state.token) {
    session.replaceChildren(
      el("span", { class: "hidden max-w-44 truncate text-[0.8125rem] text-muted md:block" }, `${state.user} · super admin`),
      el("button", { class: "btn-secondary btn-sm", onclick: () => signOut() }, "Sign out"),
    );
  } else {
    session.replaceChildren(el("button", { class: "btn-primary btn-sm", onclick: () => show("login") }, "Sign in"));
  }
}

export function show(requested: View): void {
  let view = requested;
  const btn = document.querySelector<HTMLElement>(`#nav [data-view="${view}"]`);
  if (view !== "login" && (!btn || !allowed(btn.dataset.auth))) view = state.token ? "dashboard" : "verify";
  if (view === "login" && state.token) view = "dashboard";
  const changed = state.view !== view;
  state.view = view;

  document.querySelectorAll<HTMLElement>(".view").forEach((v) => (v.hidden = v.id !== `view-${view}`));
  document.querySelectorAll<HTMLElement>("#nav [data-view]").forEach((b) => b.classList.toggle("active", b.dataset.view === view));

  const h = HEADINGS[view];
  $("#view-eyebrow").textContent = h.eyebrow;
  const title = $("#view-title");
  title.textContent = h.title;
  title.dataset.text = h.title;
  $("#view-sub").textContent = h.sub;

  const cam = $("#camera-card");
  if (CAMERA_VIEWS.has(view)) {
    $(`#view-${view} .slot`).append(cam);
    cam.hidden = false;
  } else {
    cam.hidden = true;
  }
  if (changed) {
    playLoader(view === "login" ? "auth gateway" : h.title);
    window.scrollTo({ top: 0 });
  }
  LOADERS[view]?.().catch((e) => toast(errorMessage(e), true));
}

export function signOut(expired = false): void {
  if (state.token && !expired) api("/api/auth/logout", { method: "POST" }).catch(() => {});
  Object.assign(state, { token: null, user: null, role: null });
  renderNav();
  show("verify");
}

const formValue = (form: HTMLFormElement, name: string): string =>
  (form.elements.namedItem(name) as HTMLInputElement | HTMLSelectElement).value;

/* ------------------------------------------------------------------ login */
export async function login(ev: SubmitEvent): Promise<void> {
  ev.preventDefault();
  const form = ev.target as HTMLFormElement;
  await withBusy(form.querySelector("button")!, async () => {
    const r = await api<LoginResponse>("/api/auth/login", {
      method: "POST",
      body: { username: formValue(form, "username"), password: formValue(form, "password") },
    });
    Object.assign(state, { token: r.token, user: r.username, role: r.role });
    form.reset();
    renderNav();
    show("dashboard");
    toast(`Welcome, ${r.username}`);
  }).catch(() => {});
}

/* ------------------------------------------------------------------ dashboard */
const PIPELINE: [string, string][] = [
  ["Capture in browser", "face-api.js turns the image into a 128-number feature vector. The photo never leaves the device."],
  ["Transport encryption", "A one-time AES-256-GCM key encrypts the vector; RSA-OAEP-3072 wraps that key. Timestamp + nonce block replays."],
  ["Envelope encryption", "Each record gets its own random DEK (AES-256-GCM), wrapped by a versioned KEK. The record ID is bound as AAD."],
  ["Blind index", "The e-mail is encrypted; lookups use an HMAC-SHA256 blind index, so it never sits in the clear."],
  ["Match in memory", "Templates are decrypted only in RAM to compute Euclidean distance; failures never reveal a score."],
  ["Tamper-evident audit", "Every action is chained with HMAC-SHA256, so editing or deleting a log entry is detectable."],
];

async function loadDashboard(): Promise<void> {
  const s = await api<Stats>("/api/stats");
  const stat = (value: string | number, label: string, hint?: string) =>
    el("div", { class: "stat card-hover animate-fade-up" },
      el("p", { class: "text-[0.6875rem] font-semibold tracking-wider text-muted uppercase" }, label),
      el("p", { class: "wide tnum mt-1 text-[1.75rem] font-black tracking-tight text-primary" }, value),
      hint ? el("p", { class: "mt-0.5 text-[0.75rem] text-muted" }, hint) : null);
  $("#stats").replaceChildren(
    stat(s.subjects, "Encrypted templates", "AES-256-GCM"),
    stat(s.verifications_ok, "Verified", "1:1 matches"),
    stat(s.verifications_fail, "Rejected", "no score leaked"),
    stat(`v${s.active_key_version}`, "Active KEK", "HKDF-derived"),
    stat(s.threshold, "Match threshold", "L2 distance"),
    stat(s.audit_entries, "Audit entries", "HMAC chained"),
  );
  $("#pipeline").replaceChildren(...PIPELINE.map(([title, text], i) =>
    el("li", { class: "card card-hover bg-surface-2 p-5" },
      el("span", { class: "wide text-[2rem] leading-none font-black text-acid" }, String(i + 1).padStart(2, "0")),
      el("p", { class: "mt-3 font-bold text-primary" }, title),
      el("p", { class: "mt-1 text-[0.8125rem] leading-relaxed text-muted" }, text))));
}

/* ------------------------------------------------------------------ enroll */
export async function enroll(ev: SubmitEvent): Promise<void> {
  ev.preventDefault();
  const form = ev.target as HTMLFormElement;
  const btn = form.querySelector("button")!;
  await withBusy(btn, async () => {
    const thumbs = $("#enroll-samples");
    thumbs.replaceChildren();
    const descriptors: number[][] = [];
    for (let i = 0; i < 3; i++) {
      btn.textContent = `Capturing sample ${i + 1}/3…`;
      descriptors.push(await captureDescriptor());
      const c = el("canvas");
      snapshot(c);
      thumbs.append(c);
      if (i < 2) await sleep(state.source === "video" ? 700 : 50);
    }
    btn.textContent = "Encrypting & uploading…";
    const envelope = await sealForTransport({ descriptors });
    const r = await api<EnrollResponse>("/api/subjects", {
      method: "POST",
      body: { name: formValue(form, "name"), email: formValue(form, "email"), envelope },
    });
    result("#enroll-result", "ok", "Enrolled and encrypted", kv({
      "Record ID": r.id, "Samples averaged": r.samples, "Sample spread": r.spread, "KEK version": r.key_version,
      "Stored ciphertext": `${r.stored.template_ciphertext_bytes} bytes`, Ciphertext: r.stored.template_ciphertext_preview,
      "Wrapped DEK": r.stored.wrapped_dek_preview, "E-mail blind index": r.stored.email_blind_index,
    }));
    form.reset();
  })
    .catch((e) => result("#enroll-result", "bad", "Enrollment failed", errorMessage(e)))
    .finally(() => (btn.textContent = "Capture 3 samples & enroll"));
}

/* ------------------------------------------------------------------ verify */
export async function verify(ev: SubmitEvent): Promise<void> {
  ev.preventDefault();
  const form = ev.target as HTMLFormElement;
  await withBusy(form.querySelector("button")!, async () => {
    const descriptor = await captureDescriptor();
    const envelope = await sealForTransport({ descriptor });
    const r = await api<VerifyResponse>("/api/verify", { method: "POST", body: { email: formValue(form, "email"), envelope } });
    if (r.match) result("#verify-result", "ok", r.message, kv({ Distance: r.distance, Threshold: r.threshold }));
    else result("#verify-result", "bad", "Verification failed", "The face does not match the claimed identity. No score is disclosed on failure.");
  }).catch((e) => result("#verify-result", "bad", "Error", errorMessage(e)));
}

/* ------------------------------------------------------------------ identify */
export async function identify(): Promise<void> {
  await withBusy($<HTMLButtonElement>("#btn-identify"), async () => {
    const descriptor = await captureDescriptor();
    const r = await api<IdentifyResponse>("/api/identify", { method: "POST", body: { envelope: await sealForTransport({ descriptor }) } });
    if (r.match) result("#identify-result", "ok", r.name, kv({ "E-mail": r.email, Record: r.id, Distance: r.distance, Threshold: r.threshold }));
    else result("#identify-result", "warn", "No match", `Searched ${r.gallery_size} encrypted template(s).`);
  }).catch((e) => result("#identify-result", "bad", "Error", errorMessage(e)));
}

/* ------------------------------------------------------------------ crypto lab */
export async function runLab(): Promise<void> {
  await withBusy($<HTMLButtonElement>("#btn-lab"), async () => {
    const descriptor = await captureDescriptor();
    const envelope = await sealForTransport({ descriptor });
    const heading = (t: string) => el("h3", { class: "mt-6 mb-2 card-title" }, t);
    $("#lab-client").replaceChildren(
      heading("In the browser"),
      el("p", { class: "text-[0.8125rem] text-muted" }, "128-d embedding (green = positive, red = negative):"),
      vectorHeatmap(descriptor),
      el("p", { class: "text-[0.8125rem] text-muted" }, "Transport envelope actually sent over the network:"),
      el("pre", { class: "mt-2 max-h-56 overflow-auto rounded-lg border-2 border-edge-strong bg-surface-2 p-3 font-mono text-[0.6875rem] text-accent" },
        JSON.stringify({ ...envelope, ek: `${envelope.ek.slice(0, 64)}…`, ct: `${envelope.ct.slice(0, 96)}…` }, null, 2)),
    );
    const r = await api<DemoResponse>("/api/crypto/demo", { method: "POST", body: { envelope } });
    $("#lab-result").replaceChildren(
      heading("On the server"),
      el("ol", { class: "space-y-2" }, r.steps.map((s, i) => {
        const li = el("li", { class: "animate-fade-up rounded-lg border-[1.5px] border-edge-strong bg-surface-2 px-4 py-3" },
          el("p", { class: "text-[0.875rem] font-bold text-primary" }, s.step),
          el("p", { class: "mt-1 font-mono text-[0.6875rem] break-all text-muted" }, s.detail));
        li.style.animationDelay = `${i * 60}ms`; // CSSOM, allowed by the CSP
        return li;
      })),
    );
  }).catch(() => {});
}

/* ------------------------------------------------------------------ subjects */
async function loadSubjects(): Promise<void> {
  const rows = await api<Subject[]>("/api/subjects");
  const cols = [
    { label: "Name", render: (r: Subject) => el("span", { class: "font-medium text-primary" }, r.name) },
    { label: "E-mail", key: "email" as const },
    { label: "Integrity", render: (r: Subject) => pill(r.integrity === "ok" ? "✓ intact" : "✕ tampered", r.integrity === "ok" ? "ok" : "bad") },
    { label: "KEK", render: (r: Subject) => pill(`v${r.key_version}`, "neutral") },
    { label: "Samples", key: "samples" as const },
    { label: "Enrolled", render: (r: Subject) => new Date(r.created_at).toLocaleString() },
    { label: "By", key: "created_by" as const },
  ];
  if (state.role === "admin") {
    cols.push({ label: "", render: (r: Subject) => el("button", { class: "btn-danger btn-sm", onclick: () => void deleteSubject(r) }, "Delete") });
  }
  $("#subjects-table").replaceChildren(table<Subject>(cols, rows));
}

async function deleteSubject(r: Subject): Promise<void> {
  if (!confirm(`Permanently delete ${r.name}'s encrypted template?`)) return;
  try {
    await api(`/api/subjects/${encodeURIComponent(r.id)}`, { method: "DELETE" });
    toast("Subject deleted");
    await loadSubjects();
  } catch (e) {
    toast(errorMessage(e), true);
  }
}

/* ------------------------------------------------------------------ inspector */
async function loadInspector(): Promise<void> {
  const rows = await api<InspectorRow[]>("/api/inspector");
  $("#inspector-table").replaceChildren(table<InspectorRow>([
    { label: "id", key: "id", mono: true },
    { label: "email_index (HMAC)", key: "email_index", mono: true },
    { label: "template_ct", render: (r) => `${r.template_ct} (${r.template_ct_len} B)`, mono: true },
    { label: "template_nonce", key: "template_nonce", mono: true },
    { label: "pii_ct", key: "pii_ct", mono: true },
    { label: "wrapped_dek", key: "wrapped_dek", mono: true },
    { label: "kek", render: (r) => pill(`v${r.key_version}`, "neutral") },
  ], rows));
}

/* ------------------------------------------------------------------ audit */
const outcomeKind = (o: string): ResultKind =>
  ["ok", "match"].includes(o) ? "ok" : ["error", "denied", "locked", "broken"].includes(o) ? "bad" : "warn";

async function loadAudit(): Promise<void> {
  const rows = await api<AuditEntry[]>("/api/audit");
  $("#audit-table").replaceChildren(table<AuditEntry>([
    { label: "#", key: "id" },
    { label: "Time", render: (r) => new Date(r.ts).toLocaleString() },
    { label: "Actor", render: (r) => el("span", { class: "font-medium text-primary" }, r.actor) },
    { label: "Action", render: (r) => el("span", { class: "font-mono text-[0.75rem]" }, r.action) },
    { label: "Outcome", render: (r) => pill(r.outcome, outcomeKind(r.outcome)) },
    { label: "Target", render: (r) => (r.target ?? "").slice(0, 13) },
    { label: "IP", key: "ip" },
    { label: "Details", render: (r) => r.details ?? "" },
    { label: "HMAC", render: (r) => `${r.entry_mac.slice(0, 16)}…`, mono: true },
  ], rows));
}

export async function verifyChain(): Promise<void> {
  const r = await api<ChainResult>("/api/audit/verify");
  if (r.valid) result("#chain-result", "ok", `Chain intact: ${r.checked} entries verified`, kv({ "Head HMAC": r.head }));
  else result("#chain-result", "bad", "Chain broken", `Tampering detected at entry #${r.broken_at} (after ${r.checked} valid entries).`);
}

/* ------------------------------------------------------------------ keys */
async function loadKeys(): Promise<void> {
  const k = await api<KeyStatus>("/api/keys");
  $("#keys-table").replaceChildren(table<KeyVersion>([
    { label: "Version", render: (r) => el("span", { class: "wide font-black text-primary" }, `v${r.version}`) },
    { label: "Status", render: (r) => pill(r.active ? "active" : "decrypt-only", r.active ? "ok" : "warn") },
    { label: "Created", render: (r) => new Date(r.created).toLocaleString() },
    { label: "Records", key: "records" },
    { label: "", render: (r) => (!r.active && r.records === 0)
      ? el("button", { class: "btn-danger btn-sm", onclick: () => void retireKey(r.version) }, "Retire") : "" },
  ], k.versions));
  await getServerKey();
  $("#fingerprint").textContent = serverFingerprint?.match(/.{2}/g)?.join(":") ?? "";
}

export async function rotate(): Promise<void> {
  if (!confirm("Create a new KEK and re-wrap every record's DEK?")) return;
  await withBusy($<HTMLButtonElement>("#btn-rotate"), async () => {
    const r = await api<RotateResponse>("/api/keys/rotate", { method: "POST" });
    result("#keys-result", r.failed ? "warn" : "ok", `Rotated to KEK v${r.active}`, `${r.rewrapped} record(s) re-wrapped, ${r.failed} failed.`);
    await loadKeys();
  }).catch(() => {});
}

async function retireKey(v: number): Promise<void> {
  if (!confirm(`Permanently destroy KEK v${v}? Backups that still use it become unreadable.`)) return;
  try {
    await api(`/api/keys/${v}/retire`, { method: "POST" });
    toast(`KEK v${v} destroyed`);
    await loadKeys();
  } catch (e) {
    toast(errorMessage(e), true);
  }
}

/* ------------------------------------------------------------------ operators */
async function loadOperators(): Promise<void> {
  const rows = await api<Operator[]>("/api/operators");
  $("#operators-table").replaceChildren(table<Operator>([
    { label: "Username", render: (r) => el("span", { class: "font-medium text-primary" }, r.username) },
    { label: "Role", render: () => pill("super admin", "ok") },
    { label: "Created", render: (r) => new Date(r.created_at).toLocaleDateString() },
    { label: "Status", render: (r) => (r.locked_until && r.locked_until * 1000 > Date.now()) ? pill("locked", "bad") : pill("active", "ok") },
  ], rows));
}
