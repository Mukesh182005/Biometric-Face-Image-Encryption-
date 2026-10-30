import { state } from "./state";

type Method = "GET" | "POST" | "DELETE";

let onSessionExpired: () => void = () => {};
export function setSessionExpiredHandler(handler: () => void): void {
  onSessionExpired = handler;
}

/** JSON fetch wrapper: attaches the bearer token and turns API errors into thrown Errors. */
export async function api<T>(path: string, { method = "GET", body }: { method?: Method; body?: unknown } = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (state.token) headers.Authorization = `Bearer ${state.token}`;

  let res: Response;
  try {
    res = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "same-origin",
      cache: "no-store",
    });
  } catch {
    throw new Error("Cannot reach the FaceVault server. Is the backend running?");
  }
  const data = (await res.json().catch(() => ({}))) as { error?: string };
  if (res.status === 401 && state.token && path !== "/api/auth/login") {
    onSessionExpired();
    throw new Error("Session expired, please sign in again");
  }
  if (!res.ok) throw new Error(data.error ?? `Request failed (${res.status})`);
  return data as T;
}
