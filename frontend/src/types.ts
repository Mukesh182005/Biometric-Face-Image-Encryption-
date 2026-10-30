/** Shapes of the JSON returned by the Flask API (backend/app.py). */

export type Role = "admin" | "operator";
export type ResultKind = "ok" | "bad" | "warn";

export interface TransportEnvelope {
  v: 1;
  alg: "RSA-OAEP-256+A256GCM";
  ek: string;
  iv: string;
  ct: string;
}

export interface PublicKeyInfo {
  alg: string;
  key_size: number;
  spki: string;
  fingerprint: string;
}

export interface LoginResponse {
  token: string;
  expires_in: number;
  username: string;
  role: Role;
}

export interface Stats {
  subjects: number;
  operators: number;
  audit_entries: number;
  verifications_ok: number;
  verifications_fail: number;
  active_key_version: number;
  threshold: number;
  transport_fingerprint: string;
  tls: boolean;
}

export interface EnrollResponse {
  id: string;
  key_version: number;
  samples: number;
  spread: number;
  stored: {
    template_ciphertext_bytes: number;
    template_ciphertext_preview: string;
    wrapped_dek_preview: string;
    email_blind_index: string;
  };
}

export type VerifyResponse =
  | { match: true; message: string; distance: number; threshold: number }
  | { match: false; message: string };

export type IdentifyResponse =
  | { match: true; id: string; name: string; email: string; distance: number; threshold: number }
  | { match: false; gallery_size: number };

export interface Subject {
  id: string;
  name: string;
  email: string;
  key_version: number;
  samples: number;
  created_at: string;
  created_by: string;
  integrity: "ok" | "failed";
}

export interface InspectorRow {
  id: string;
  email_index: string;
  template_ct: string;
  template_ct_len: number;
  template_nonce: string;
  pii_ct: string;
  wrapped_dek: string;
  key_version: number;
}

export interface AuditEntry {
  id: number;
  ts: string;
  actor: string;
  action: string;
  target: string | null;
  ip: string | null;
  outcome: string;
  details: string | null;
  prev_mac: string;
  entry_mac: string;
}

export type ChainResult =
  | { valid: true; checked: number; head: string }
  | { valid: false; checked: number; broken_at: number };

export interface KeyVersion {
  version: number;
  created: string;
  active: boolean;
  records: number;
}

export interface KeyStatus {
  active: number;
  versions: KeyVersion[];
}

export interface RotateResponse {
  active: number;
  rewrapped: number;
  failed: number;
}

export interface Operator {
  id: number;
  username: string;
  role: Role;
  created_at: string;
  locked_until: number | null;
}

export interface DemoResponse {
  steps: { step: string; detail: string }[];
}
