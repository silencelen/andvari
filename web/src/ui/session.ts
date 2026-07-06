import { ApiClient, type Tokens } from "../api/client";

/**
 * Non-secret session metadata persisted across reloads. Tokens are here too (MVP);
 * the vault KEY is NEVER persisted — a reload always re-prompts for the master
 * password (spec 01 §8: web has no quick-unlock).
 */
export interface Session {
  baseUrl: string;
  userId: string;
  personalVaultId: string;
  email: string;
  tokens: Tokens | null;
}

const KEY = "andvari.session";

export function loadSession(): Session | null {
  const raw = localStorage.getItem(KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as Session;
  } catch {
    return null;
  }
}

export function saveSession(s: Session): void {
  localStorage.setItem(KEY, JSON.stringify(s));
}

export function clearSession(): void {
  localStorage.removeItem(KEY);
}

export function defaultBaseUrl(): string {
  // Same-origin when served by the andvari server; overridable for dev.
  return localStorage.getItem("andvari.baseUrl") ?? "";
}

export function makeClient(session: Session | null, baseUrl: string): ApiClient {
  return new ApiClient(baseUrl, session?.tokens ?? null, (tokens) => {
    const cur = loadSession();
    if (cur) saveSession({ ...cur, tokens });
  });
}
