/**
 * FaceVault frontend entry point (TypeScript + Tailwind CSS, bundled by Vite).
 * - Face feature extraction runs entirely in the browser; images never leave the device.
 * - Every descriptor is sealed with hybrid RSA-OAEP + AES-GCM before it is sent.
 * - The session token is kept in memory only (never localStorage).
 */
import "./styles.css";
import { api, setSessionExpiredHandler } from "./api";
import { getServerKey, serverFingerprint } from "./crypto";
import { $, errorMessage, toast } from "./dom";
import { initMarquee, initTheme } from "./effects";
import { loadModels, toggleCamera, useUpload } from "./face";
import type { View } from "./state";
import {
  enroll, identify, login, renderNav, rotate, runLab, show, signOut, verify, verifyChain,
} from "./views";

function on<K extends keyof HTMLElementEventMap>(selector: string, type: K, handler: (ev: HTMLElementEventMap[K]) => unknown): void {
  $(selector).addEventListener(type, (ev) => void handler(ev as HTMLElementEventMap[K]));
}

function setOnline(online: boolean): void {
  const status = $("#status-online");
  status.replaceChildren();
  const dot = document.createElement("span");
  dot.className = `size-2.5 rounded-full ${online ? "animate-pulse bg-acid" : "bg-[#ff4d3d]"}`;
  status.append(dot, online ? "Online" : "Offline");
  status.classList.toggle("text-acid", online);
  status.classList.toggle("text-[#ff4d3d]", !online);
  $("#server-warning").hidden = online;
}

function init(): void {
  initTheme();
  initMarquee();
  setSessionExpiredHandler(() => signOut(true));

  document.querySelectorAll<HTMLElement>("#nav [data-view], [data-goto]").forEach((b) =>
    b.addEventListener("click", () => show((b.dataset.view ?? b.dataset.goto) as View)));
  $("[data-home]").addEventListener("click", () => show("dashboard"));

  on("#login-form", "submit", (e) => login(e as SubmitEvent));
  on("#enroll-form", "submit", (e) => enroll(e as SubmitEvent));
  on("#verify-form", "submit", (e) => verify(e as SubmitEvent));
  on("#btn-identify", "click", identify);
  on("#btn-lab", "click", runLab);
  on("#btn-camera", "click", toggleCamera);
  on("#btn-rotate", "click", rotate);
  on("#btn-verify-chain", "click", () => verifyChain().catch((e) => toast(errorMessage(e), true)));
  for (const id of ["subjects", "inspector", "audit"]) {
    on(`#btn-refresh-${id}`, "click", () => show(id as View));
  }

  const fileInput = $<HTMLInputElement>("#file-input");
  fileInput.addEventListener("change", () => {
    const file = fileInput.files?.[0];
    if (file) useUpload(file).catch((e) => toast(`Could not read image: ${errorMessage(e)}`, true));
    fileInput.value = "";
  });

  const tls = $("#badge-tls");
  const local = ["localhost", "127.0.0.1"].includes(location.hostname);
  tls.textContent = location.protocol === "https:" ? "tls on" : local ? "tls off · localhost" : "tls off";
  tls.className = `badge ${location.protocol === "https:" ? "badge-good" : "badge-warn"} hidden md:inline-flex`;
  if (!window.isSecureContext) toast("Not a secure context: camera and WebCrypto need https:// or localhost", true);

  renderNav();
  show("verify");
  void loadModels();

  api<{ status: string }>("/api/health")
    .then((h) => setOnline(h.status === "ok"))
    .then(getServerKey)
    .then(() => ($("#foot-fp").textContent = `transport key · ${serverFingerprint?.slice(0, 24)}…`))
    .catch(() => setOnline(false));
}

document.addEventListener("DOMContentLoaded", init);
