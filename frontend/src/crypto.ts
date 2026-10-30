/**
 * Client-side transport encryption (WebCrypto).
 * Every face descriptor is sealed with a one-time AES-256-GCM key, and that key is wrapped with the
 * server's RSA-OAEP-3072 (SHA-256) public key. A timestamp + random nonce inside the ciphertext
 * let the server reject replays. This runs in addition to TLS.
 */
import { api } from "./api";
import type { PublicKeyInfo, TransportEnvelope } from "./types";

const TRANSPORT_AAD = new TextEncoder().encode("bfe-transport-v1");

const b64 = (buf: ArrayBuffer | Uint8Array): string => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s: string): Uint8Array<ArrayBuffer> => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
export const hex = (buf: ArrayBuffer | Uint8Array): string =>
  [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

let serverKey: CryptoKey | null = null;
export let serverFingerprint: string | null = null;

export async function getServerKey(): Promise<CryptoKey> {
  if (serverKey) return serverKey;
  const info = await api<PublicKeyInfo>("/api/crypto/public-key");
  const spki = unb64(info.spki);
  // Check the advertised fingerprint matches the key bytes we actually received.
  const digest = hex(await crypto.subtle.digest("SHA-256", spki));
  if (digest !== info.fingerprint) throw new Error("Server key fingerprint mismatch");
  serverFingerprint = digest;
  serverKey = await crypto.subtle.importKey("spki", spki, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
  return serverKey;
}

export async function sealForTransport(payload: Record<string, unknown>): Promise<TransportEnvelope> {
  const rsaKey = await getServerKey();
  const aesKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const nonce = hex(crypto.getRandomValues(new Uint8Array(16)));
  const plaintext = new TextEncoder().encode(JSON.stringify({ ...payload, ts: Date.now(), nonce }));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: TRANSPORT_AAD }, aesKey, plaintext);
  const ek = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, rsaKey, await crypto.subtle.exportKey("raw", aesKey));
  return { v: 1, alg: "RSA-OAEP-256+A256GCM", ek: b64(ek), iv: b64(iv), ct: b64(ct) };
}
