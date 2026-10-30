/** Presentation-only effects: theme toggle, page-change bubble loader, marquee band. */
import { $, el } from "./dom";

const THEME_KEY = "facevault-theme";
type Theme = "dark" | "light";

function applyTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  $("#icon-sun").hidden = theme === "light";
  $("#icon-moon").hidden = theme === "dark";
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", theme === "dark" ? "#191919" : "#c2c2c5");
}

export function initTheme(): void {
  let theme: Theme = "dark";
  try {
    const saved = localStorage.getItem(THEME_KEY);
    if (saved === "light" || saved === "dark") theme = saved;
  } catch {
    /* storage blocked: keep the default */
  }
  applyTheme(theme);
  $("#theme-toggle").addEventListener("click", () => {
    const next: Theme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    applyTheme(next);
    try {
      localStorage.setItem(THEME_KEY, next);
    } catch {
      /* not persisted, still applied */
    }
  });
}

const LOADER_MS = 750;
let loaderTimer: number | undefined;

/** Page-change loader: bouncing bubbles, a field of rising bubbles and a progress bar. */
export function playLoader(label: string): void {
  const loader = $("#loader");
  $("#loader-label").textContent = `decrypting ${label.toLowerCase()}`;

  // Fresh set of rising bubbles with random size, position, speed and drift (CSSOM: allowed by the CSP).
  const field = $("#loader-field");
  field.replaceChildren(
    ...Array.from({ length: 22 }, () => {
      const b = el("i", { class: "rise" });
      const size = 8 + Math.random() * 34;
      b.style.width = b.style.height = `${size}px`;
      b.style.left = `${Math.random() * 100}%`;
      b.style.animationDuration = `${0.9 + Math.random() * 1.1}s`;
      b.style.animationDelay = `${Math.random() * 0.25}s`;
      b.style.setProperty("--drift", `${(Math.random() - 0.5) * 120}px`);
      return b;
    }),
  );

  loader.classList.remove("show");
  void loader.offsetWidth; // restart the progress-bar animation
  loader.classList.add("show");
  clearTimeout(loaderTimer);
  loaderTimer = window.setTimeout(() => loader.classList.remove("show"), LOADER_MS);
}

const MARQUEE = [
  "AES-256-GCM", "RSA-OAEP-3072", "HKDF-SHA256", "HMAC blind index", "scrypt keyring",
  "envelope encryption", "replay guard", "audit hash chain", "128-d face embedding", "zero plaintext at rest",
];

export function initMarquee(): void {
  const items = [...MARQUEE, ...MARQUEE].map((t) => el("span", { class: "flex items-center gap-10" }, t, el("span", { "aria-hidden": "true" }, "✱")));
  $("#marquee").replaceChildren(...items);
}
