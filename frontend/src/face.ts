/**
 * Face capture and feature extraction. face-api.js (two detectors, 68-point landmarks and a ResNet-34
 * embedding network) runs entirely in the browser, so the photo never leaves the device: only the
 * 128-number descriptor is sent, and only after transport encryption.
 *
 * Detection has to work for every skin tone, every lighting condition, and for people standing a metre
 * or more from the camera. A single detector pass on the raw frame misses darker skin in dim or
 * back-lit scenes, washed-out lighter skin under harsh light, and small, distant faces. So detection
 * runs as a cascade of different "views" of the same frame:
 *   1. the raw frame;
 *   2. an adaptively light-corrected frame (measured from the frame itself, so no skin tone is
 *      treated as the default);
 *   3. a second, independently trained detector;
 *   4. zoomed, upscaled crops of the frame (digital zoom) for distant faces.
 */
import * as faceapi from "@vladmandic/face-api";
import { $, el, toast } from "./dom";
import { state } from "./state";

const MODEL_URL = "/models";
// face-api re-exports TensorFlow.js, but its typings omit these two runtime functions.
const tf = faceapi.tf as unknown as { ready(): Promise<void>; getBackend(): string };

type Box = { x: number; y: number; width: number; height: number };
type Source = HTMLVideoElement | HTMLImageElement | HTMLCanvasElement;

function setCameraState(text: string, tone: "neutral" | "good" | "warn" | "critical"): void {
  const badge = $("#camera-state");
  badge.textContent = text;
  badge.className = `badge badge-${tone}`;
}

function setLabel(text: string | null): void {
  const label = $("#camera-label");
  label.textContent = text ?? "";
  label.classList.toggle("hidden", !text);
}

export async function loadModels(): Promise<void> {
  const badge = $("#badge-models");
  try {
    await tf.ready();
    await Promise.all([
      faceapi.nets.ssdMobilenetv1.loadFromUri(MODEL_URL),
      faceapi.nets.tinyFaceDetector.loadFromUri(MODEL_URL),
      faceapi.nets.faceLandmark68Net.loadFromUri(MODEL_URL),
      faceapi.nets.faceRecognitionNet.loadFromUri(MODEL_URL),
    ]);
    state.modelsReady = true;
    badge.replaceChildren(`models ready · ${tf.getBackend()}`);
    badge.className = "badge badge-good hidden md:inline-flex";
  } catch (e) {
    badge.replaceChildren("models offline");
    badge.className = "badge badge-critical hidden md:inline-flex";
    toast(`Face models failed to load: ${e instanceof Error ? e.message : e}`, true);
  }
}

function sourceElement(): HTMLVideoElement | HTMLImageElement | null {
  if (state.source === "video") return $<HTMLVideoElement>("#video");
  if (state.source === "image") return $<HTMLImageElement>("#upload-preview");
  return null;
}

const sourceSize = (src: Source): [number, number] =>
  src instanceof HTMLVideoElement ? [src.videoWidth, src.videoHeight]
    : src instanceof HTMLImageElement ? [src.naturalWidth, src.naturalHeight] : [src.width, src.height];

function clearOverlay(): void {
  const c = $<HTMLCanvasElement>("#overlay");
  c.getContext("2d")?.clearRect(0, 0, c.width, c.height);
}

/** Corner brackets around the detected face; filled when the capture is locked in. */
function drawBox(box: Box | null, locked = false): void {
  const src = sourceElement();
  const c = $<HTMLCanvasElement>("#overlay");
  const ctx = c.getContext("2d");
  if (!src || !ctx) return;
  [c.width, c.height] = sourceSize(src);
  ctx.clearRect(0, 0, c.width, c.height);
  if (!box) return;
  const { x, y, width: w, height: h } = box;
  const len = Math.min(w, h) * 0.25;
  ctx.lineWidth = Math.max(3, c.width / 200);
  ctx.strokeStyle = locked ? "#23f871" : "#57c690";
  ctx.beginPath();
  for (const [cx, cy, dx, dy] of [[x, y, 1, 1], [x + w, y, -1, 1], [x, y + h, 1, -1], [x + w, y + h, -1, -1]]) {
    ctx.moveTo(cx, cy + dy * len);
    ctx.lineTo(cx, cy);
    ctx.lineTo(cx + dx * len, cy);
  }
  ctx.stroke();
  if (locked) {
    ctx.fillStyle = "rgba(35,248,113,0.10)";
    ctx.fillRect(x, y, w, h);
  }
}

/* ------------------------------------------------------------------ lighting */
type Region = { x: number; y: number; w: number; h: number };

/** Region used to measure lighting: the face if we know where it is, otherwise the centre of the frame. */
function meteringRegion(width: number, height: number, face?: Box | null): Region {
  if (face) {
    const x = Math.max(0, face.x), y = Math.max(0, face.y);
    return { x, y, w: Math.min(width - x, face.width), h: Math.min(height - y, face.height) };
  }
  return { x: width * 0.2, y: height * 0.1, w: width * 0.6, h: height * 0.8 };
}

/** Mean luminance (0..1) and the 1st / 99th percentiles of a region. */
function measure(data: Uint8ClampedArray, width: number, r: Region): { mean: number; lo: number; hi: number } {
  const hist = new Uint32Array(256);
  let sum = 0;
  let n = 0;
  const x0 = Math.floor(r.x), y0 = Math.floor(r.y), x1 = Math.floor(r.x + r.w), y1 = Math.floor(r.y + r.h);
  for (let y = y0; y < y1; y += 2) {
    for (let x = x0; x < x1; x += 2) {
      const i = (y * width + x) * 4;
      const l = (0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2]) | 0;
      hist[l]++;
      sum += l;
      n++;
    }
  }
  if (!n) return { mean: 0.5, lo: 0, hi: 1 };
  const pick = (q: number) => {
    let acc = 0;
    for (let v = 0; v < 256; v++) if ((acc += hist[v]) >= q * n) return v / 255;
    return 1;
  };
  return { mean: sum / n / 255, lo: pick(0.01), hi: pick(0.99) };
}

/**
 * Adaptive light correction: stretch the metered region to its own 1st–99th percentile range, then
 * gamma-correct so its mean lands mid-grey. The same curve is applied to R, G and B, so skin hue is
 * preserved; only exposure and contrast change.
 */
function lightCorrect(canvas: HTMLCanvasElement): HTMLCanvasElement {
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  if (!ctx) return canvas;
  const { width, height } = canvas;
  const img = ctx.getImageData(0, 0, width, height);
  const { mean, lo, hi } = measure(img.data, width, meteringRegion(width, height));
  const range = Math.max(hi - lo, 0.08);
  const stretchedMean = Math.min(0.95, Math.max(0.05, (mean - lo) / range));
  const gamma = Math.min(3, Math.max(0.33, Math.log(0.5) / Math.log(stretchedMean)));
  const lut = new Uint8ClampedArray(256);
  for (let v = 0; v < 256; v++) {
    const t = Math.min(1, Math.max(0, (v / 255 - lo) / range));
    lut[v] = Math.round(255 * t ** gamma);
  }
  const d = img.data;
  for (let i = 0; i < d.length; i += 4) {
    d[i] = lut[d[i]];
    d[i + 1] = lut[d[i + 1]];
    d[i + 2] = lut[d[i + 2]];
  }
  ctx.putImageData(img, 0, 0);
  return canvas;
}

/** Lighting verdict for the live badge, measured on the face (or frame centre). */
function lightingOf(src: Source, face?: Box | null): "dark" | "bright" | "ok" {
  const [width, height] = sourceSize(src);
  if (!width || !height) return "ok";
  const scale = Math.min(1, 320 / width);
  const c = el("canvas");
  c.width = Math.round(width * scale);
  c.height = Math.round(height * scale);
  const ctx = c.getContext("2d", { willReadFrequently: true });
  if (!ctx) return "ok";
  ctx.drawImage(src, 0, 0, c.width, c.height);
  const box = face && { x: face.x * scale, y: face.y * scale, width: face.width * scale, height: face.height * scale };
  const { mean } = measure(ctx.getImageData(0, 0, c.width, c.height).data, c.width, meteringRegion(c.width, c.height, box));
  return mean < 0.22 ? "dark" : mean > 0.82 ? "bright" : "ok";
}

/* ------------------------------------------------------------------ views (crop / zoom / correct) */
/** A canvas derived from the source, plus how to map its coordinates back onto the source. */
type View = { canvas: Source; ox: number; oy: number; scale: number };

/**
 * Crop a region of the source (fractions of width/height), upscale it so the face is large enough
 * for the detector, and optionally light-correct it. zoom = 1 with the full region is the plain frame.
 */
function makeView(src: Source, region: [number, number, number, number], opts: { correct?: boolean; target?: number } = {}): View | null {
  const [width, height] = sourceSize(src);
  if (!width || !height) return null;
  const [fx, fy, fw, fh] = region;
  const sx = fx * width, sy = fy * height, sw = fw * width, sh = fh * height;
  const target = opts.target ?? Math.max(sw, sh);
  const scale = target / Math.max(sw, sh);
  if (!opts.correct && scale === 1 && fw === 1 && fh === 1) return { canvas: src, ox: 0, oy: 0, scale: 1 };
  const canvas = el("canvas");
  canvas.width = Math.round(sw * scale);
  canvas.height = Math.round(sh * scale);
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  if (!ctx) return null;
  ctx.imageSmoothingQuality = "high";
  ctx.drawImage(src, sx, sy, sw, sh, 0, 0, canvas.width, canvas.height);
  return { canvas: opts.correct ? lightCorrect(canvas) : canvas, ox: sx, oy: sy, scale };
}

const toSource = (box: Box, v: View): Box => ({
  x: v.ox + box.x / v.scale, y: v.oy + box.y / v.scale, width: box.width / v.scale, height: box.height / v.scale,
});

const ssd = (minConfidence: number) => new faceapi.SsdMobilenetv1Options({ minConfidence });
const tiny = (inputSize: number, scoreThreshold: number) => new faceapi.TinyFaceDetectorOptions({ inputSize, scoreThreshold });

type Pass = {
  label: string;
  view: (src: Source) => View | null;
  options: faceapi.SsdMobilenetv1Options | faceapi.TinyFaceDetectorOptions;
};

const FULL: [number, number, number, number] = [0, 0, 1, 1];
// Digital zoom for distant faces: centre crop, then the upper-centre (where a standing person's face is).
const ZOOM_CENTRE: [number, number, number, number] = [0.25, 0.15, 0.5, 0.6];
const ZOOM_UPPER: [number, number, number, number] = [0.2, 0, 0.6, 0.6];

/** Ordered from cheapest/strictest to most permissive. */
const PASSES: Pass[] = [
  { label: "standard", view: (s) => makeView(s, FULL), options: ssd(0.5) },
  { label: "light-corrected", view: (s) => makeView(s, FULL, { correct: true }), options: ssd(0.4) },
  { label: "alt detector · distance", view: (s) => makeView(s, FULL, { correct: true }), options: tiny(608, 0.4) },
  { label: "zoom · centre", view: (s) => makeView(s, ZOOM_CENTRE, { correct: true, target: 900 }), options: ssd(0.4) },
  { label: "zoom · upper", view: (s) => makeView(s, ZOOM_UPPER, { correct: true, target: 900 }), options: ssd(0.4) },
  { label: "zoom · alt detector", view: (s) => makeView(s, ZOOM_CENTRE, { correct: true, target: 900 }), options: tiny(608, 0.35) },
  { label: "low-confidence", view: (s) => makeView(s, FULL), options: ssd(0.3) },
];
// The live preview runs ~3 times a second, so it uses the cheaper subset.
const LIVE_PASSES = [PASSES[0], PASSES[2], PASSES[3]];

/* ------------------------------------------------------------------ live preview */
let liveBusy = false;
async function liveDetect(): Promise<void> {
  const video = $<HTMLVideoElement>("#video");
  if (!state.modelsReady || liveBusy || state.source !== "video" || !video.videoWidth) return;
  liveBusy = true;
  try {
    let found: { box: Box; score: number; label: string } | null = null;
    for (const pass of LIVE_PASSES) {
      const v = pass.view(video);
      const det = v && (await faceapi.detectSingleFace(v.canvas, pass.options));
      if (v && det) {
        found = { box: toSource(det.box, v), score: det.score, label: pass.label };
        break;
      }
    }
    drawBox(found?.box ?? null);
    const light = lightingOf(video, found?.box);
    if (found) {
      const far = found.box.width < video.videoWidth * 0.12;
      const note = light === "dark" ? "low light" : light === "bright" ? "bright" : far ? "far · ok" : `${(found.score * 100).toFixed(0)}%`;
      setCameraState(`face · ${note}`, light === "ok" ? "good" : "warn");
    } else {
      setCameraState(light === "dark" ? "too dark · add light" : light === "bright" ? "too bright · avoid glare" : "no face · step closer", "warn");
    }
  } finally {
    liveBusy = false;
  }
}

export async function toggleCamera(): Promise<void> {
  if (state.stream) return stopCamera();
  try {
    // Higher resolution keeps a face 1-2 m away large enough to recognise.
    state.stream = await navigator.mediaDevices.getUserMedia({
      video: { width: { ideal: 1920 }, height: { ideal: 1080 }, facingMode: "user" },
      audio: false,
    });
  } catch (e) {
    toast(`Camera unavailable: ${e instanceof Error ? e.message : e}. You can upload a photo instead.`, true);
    return;
  }
  // Ask for continuous auto-exposure and white balance where the camera supports it (ignored otherwise).
  const [track] = state.stream.getVideoTracks();
  const caps = (track.getCapabilities?.() ?? {}) as Record<string, unknown>;
  const advanced: Record<string, string>[] = [];
  if (Array.isArray(caps.exposureMode) && caps.exposureMode.includes("continuous")) advanced.push({ exposureMode: "continuous" });
  if (Array.isArray(caps.whiteBalanceMode) && caps.whiteBalanceMode.includes("continuous")) advanced.push({ whiteBalanceMode: "continuous" });
  if (advanced.length) await track.applyConstraints({ advanced } as MediaTrackConstraints).catch(() => {});

  const video = $<HTMLVideoElement>("#video");
  video.srcObject = state.stream;
  video.hidden = false;
  $<HTMLImageElement>("#upload-preview").hidden = true;
  $("#overlay").classList.add("-scale-x-100");
  $("#camera-hint").hidden = true;
  $("#camera-wrap").classList.add("live");
  $("#camera-wrap").classList.remove("has-image");
  state.source = "video";
  $("#btn-camera").textContent = "Stop camera";
  setCameraState("live", "good");
  const { width, height } = track.getSettings();
  setLabel(`● live · ${width ?? "?"}×${height ?? "?"}`);
  state.liveTimer = window.setInterval(() => void liveDetect(), 350);
}

export function stopCamera(): void {
  clearInterval(state.liveTimer);
  state.stream?.getTracks().forEach((t) => t.stop());
  state.stream = null;
  $<HTMLVideoElement>("#video").srcObject = null;
  $("#camera-wrap").classList.remove("live");
  $("#btn-camera").textContent = "Start camera";
  clearOverlay();
  if (state.source === "video") {
    state.source = "none";
    $("#camera-hint").hidden = false;
    setCameraState("offline", "neutral");
    setLabel(null);
  }
}

/* ------------------------------------------------------------------ capture */
/** Which cascade pass found the face in the last capture. */
export let lastPass = "";

/** Returns the 128-float descriptor of the single face in view. */
export async function captureDescriptor(): Promise<number[]> {
  if (!state.modelsReady) throw new Error("Face models are still loading");
  const src = sourceElement();
  if (!src) throw new Error("Start the camera or upload a photo first");
  const wrap = $("#camera-wrap");
  wrap.classList.add("scanning");
  try {
    for (const pass of PASSES) {
      const v = pass.view(src);
      if (!v) continue;
      // Landmarks and descriptor come from the same view that found the face, so they line up.
      const det = await faceapi.detectSingleFace(v.canvas, pass.options).withFaceLandmarks().withFaceDescriptor();
      if (det) {
        drawBox(toSource(det.detection.box, v), true);
        lastPass = pass.label;
        return Array.from(det.descriptor);
      }
    }
    const light = lightingOf(src);
    throw new Error(
      light === "dark" ? "No face found: the scene is very dark. Add light in front of the face, not behind it."
        : light === "bright" ? "No face found: the image is overexposed. Move away from direct light or glare."
          : "No face found. Face the camera with the whole face visible; within about 2 m works best.",
    );
  } finally {
    wrap.classList.remove("scanning");
  }
}

function loadImage(src: string): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error("unsupported image"));
    img.src = src;
  });
}

/** Show an uploaded photo. Tight or small crops are padded and upscaled so the detector can find the face. */
export async function useUpload(blob: Blob, label = blob instanceof File ? blob.name : "photo"): Promise<void> {
  stopCamera();
  const url = URL.createObjectURL(blob);
  const raw = await loadImage(url).finally(() => URL.revokeObjectURL(url));
  const scale = Math.max(1, 480 / Math.max(raw.naturalWidth, raw.naturalHeight));
  const w = raw.naturalWidth * scale;
  const h = raw.naturalHeight * scale;
  const pad = Math.round(Math.max(w, h) * 0.3);
  const canvas = el("canvas");
  canvas.width = w + 2 * pad;
  canvas.height = h + 2 * pad;
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("Canvas unavailable");
  ctx.fillStyle = "#808080";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.drawImage(raw, pad, pad, w, h);
  const padded = await new Promise<Blob | null>((r) => canvas.toBlob(r, "image/png"));
  if (!padded) throw new Error("Could not process image");
  const img = $<HTMLImageElement>("#upload-preview");
  const paddedUrl = URL.createObjectURL(padded);
  await new Promise((r) => {
    img.onload = r;
    img.src = paddedUrl;
  });
  URL.revokeObjectURL(paddedUrl);
  img.hidden = false;
  $<HTMLVideoElement>("#video").hidden = true;
  $("#overlay").classList.remove("-scale-x-100");
  $("#camera-hint").hidden = true;
  $("#camera-wrap").classList.add("has-image");
  clearOverlay();
  state.source = "image";
  setCameraState("photo", "good");
  setLabel(label);
}

/** Small thumbnail of the current frame (enrollment samples). */
export function snapshot(canvas: HTMLCanvasElement): void {
  const src = sourceElement();
  const ctx = canvas.getContext("2d");
  if (!src || !ctx) return;
  canvas.width = 144;
  canvas.height = 108;
  ctx.drawImage(src, 0, 0, canvas.width, canvas.height);
}

/** 128-cell heatmap of the embedding (green = positive, red = negative). Colours are set via CSSOM, CSP-safe. */
export function vectorHeatmap(vec: number[]): HTMLDivElement {
  return el(
    "div",
    { class: "my-3 grid grid-cols-16 gap-0.5 rounded-lg border-2 border-edge-strong bg-surface-2 p-2", title: "128-d face embedding" },
    vec.map((v) => {
      const cell = el("i", { class: "block h-3.5 rounded-[2px]" });
      const t = Math.max(-1, Math.min(1, v / 0.25));
      cell.style.background = t >= 0 ? `rgb(35 248 113 / ${0.1 + 0.9 * t})` : `rgb(255 77 61 / ${0.1 + 0.9 * -t})`;
      return cell;
    }),
  );
}
