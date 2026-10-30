import type { Role } from "./types";

export type View =
  | "login" | "dashboard" | "enroll" | "verify" | "identify" | "lab"
  | "subjects" | "inspector" | "audit" | "keys" | "operators";

export type Source = "none" | "video" | "image";

/** All mutable client state. The JWT lives here only (never localStorage) to limit XSS token theft. */
export const state: {
  token: string | null;
  user: string | null;
  role: Role | null;
  view: View | null;
  modelsReady: boolean;
  stream: MediaStream | null;
  liveTimer: number | undefined;
  source: Source;
} = {
  token: null,
  user: null,
  role: null,
  view: null,
  modelsReady: false,
  stream: null,
  liveTimer: undefined,
  source: "none",
};
