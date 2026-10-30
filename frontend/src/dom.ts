import type { ResultKind } from "./types";

/** Typed querySelector that fails loudly if the markup and code drift apart. */
export function $<T extends Element = HTMLElement>(selector: string): T {
  const node = document.querySelector<T>(selector);
  if (!node) throw new Error(`Missing element: ${selector}`);
  return node;
}

type Child = Node | string | number | null | undefined | false;
type Attrs = Record<string, string | EventListener>;

/** Build a DOM element. Text always goes through text nodes, never innerHTML, so API data cannot inject markup. */
export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  ...children: (Child | Child[])[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (typeof value === "function") node.addEventListener(key.replace(/^on/, ""), value);
    else if (key === "class") node.className = value;
    else node.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

let toastTimer: number | undefined;
export function toast(message: string, bad = false): void {
  const t = $("#toast");
  t.textContent = message;
  t.className = bad ? "toast bad" : "toast";
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => (t.hidden = true), 4000);
}

const TONE: Record<ResultKind, string> = { ok: "good", bad: "critical", warn: "warn" };
const ICON: Record<ResultKind, string> = { ok: "✓", bad: "✕", warn: "!" };
// Full class names (not `text-${tone}`) so Tailwind's scanner can see them.
const ICON_COLOR: Record<ResultKind, string> = { ok: "text-good", bad: "text-critical", warn: "text-warn" };

/** Inline notice (DeepSentinel style): tinted panel, icon + title, then detail. */
export function result(target: string, kind: ResultKind, title: string, ...body: Child[]): void {
  $(target).replaceChildren(
    el(
      "div",
      { class: `notice notice-${TONE[kind]}`, role: kind === "ok" ? "status" : "alert" },
      el("span", { class: `mt-px shrink-0 font-mono font-bold ${ICON_COLOR[kind]}`, "aria-hidden": "true" }, ICON[kind]),
      el("div", { class: "min-w-0 flex-1 space-y-2 text-secondary" }, el("h4", {}, title), ...body),
    ),
  );
}

export function kv(obj: Record<string, string | number>): HTMLDListElement {
  return el(
    "dl",
    { class: "m-0 grid grid-cols-[max-content_1fr] gap-x-3.5 gap-y-1.5" },
    Object.entries(obj).flatMap(([k, v]) => [
      el("dt", { class: "text-[0.75rem] font-medium tracking-wide text-muted uppercase" }, k),
      el("dd", { class: "m-0 font-mono text-[0.75rem] break-all text-primary" }, v),
    ]),
  );
}

export interface Column<T> {
  label: string;
  key?: keyof T;
  mono?: boolean;
  render?: (row: T) => Child;
}

export function table<T>(columns: Column<T>[], rows: T[]): HTMLElement {
  if (!rows.length) {
    return el("div", { class: "px-6 py-14 text-center" },
      el("p", { class: "font-semibold text-primary" }, "Nothing here yet"),
      el("p", { class: "mt-1 text-[0.8125rem] text-muted" }, "Records will appear here as they are created."));
  }
  return el(
    "table",
    { class: "data-table" },
    el("thead", {}, el("tr", {}, columns.map((c) => el("th", {}, c.label)))),
    el(
      "tbody",
      {},
      rows.map((row) =>
        el(
          "tr",
          {},
          columns.map((c) => {
            const value = c.render ? c.render(row) : c.key ? (row[c.key] as Child) : "";
            return el("td", c.mono ? { class: "mono" } : {}, value);
          }),
        ),
      ),
    ),
  );
}

export const pill = (text: string, kind: ResultKind | "neutral"): HTMLSpanElement =>
  el("span", { class: `badge badge-${kind === "neutral" ? "neutral" : TONE[kind]}` }, text);

export const errorMessage = (e: unknown): string => (e instanceof Error ? e.message : String(e));

/** Disable a button while work runs; show any error as a toast and re-throw it. */
export async function withBusy<T>(button: HTMLButtonElement, fn: () => Promise<T>): Promise<T> {
  button.disabled = true;
  try {
    return await fn();
  } catch (e) {
    toast(errorMessage(e), true);
    throw e;
  } finally {
    button.disabled = false;
  }
}

export const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
