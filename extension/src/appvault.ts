import type { BuildTarget } from "./buildtarget.ts";

/**
 * Safari on iOS: the extension has no sign-in and no vault of its own. Its popup fills from the andvari app's vault,
 * which the native handler opens behind Face ID (app-ios/AndvariSafari/SafariWebExtensionHandler.swift, AppVaultSession;
 * the same read-only core object as system AutoFill: the app's quick-unlock gates, no network, no tokens).
 *
 * Least disclosure across the native-message hop:
 *  - `vaultOpen` answers with names, usernames and web addresses. No password, no one-time code.
 *  - `vaultSecret` answers with ONE login's secret, for the item id asked.
 * This worker keeps the list and the handler's ticket in memory only ([AppVault]); nothing decrypted is written to any
 * storage, and both are dropped when the popup closes, on Lock, and after [APP_VAULT_LIFETIME_MS].
 *
 * LEAF module: no chrome import. The worker passes the native-message call in.
 */

export const APP_VAULT_LIFETIME_MS = 90_000;
/** Face ID is a person's time: the handler may take this long to answer an unlock. */
export const APP_VAULT_PROMPT_TIMEOUT_MS = 60_000;

/** A login as the handler lists it. No secret. */
export type AppVaultItem = { itemId: string; name: string; username: string; uris: string[]; hasTotp: boolean };

export type AppVaultOpened =
  | { state: "open"; ticket: string; email: string | null; items: AppVaultItem[] }
  /** Nothing can be opened here now; `message` says what to do in the app. */
  | { state: "openApp"; message: string }
  | { state: "cancelled" }
  | { state: "unavailable" };

export type AppVaultSecret =
  | { state: "secret"; username: string; password: string; totpCode: string | null }
  | { state: "openApp"; message: string }
  | { state: "cancelled" }
  | { state: "refused" }
  | { state: "unavailable" };

const OPEN_APP_FALLBACK = "Open andvari and unlock it, then try again.";
const TICKET_RE = /^[0-9a-f]{64}$/;
const MAX_ITEMS = 5000;
const text = (v: unknown, max: number): string | null => (typeof v === "string" && v.length <= max ? v : null);

function parseItem(v: unknown): AppVaultItem | null {
  if (typeof v !== "object" || v === null) return null;
  const r = v as Record<string, unknown>;
  const itemId = text(r.itemId, 128);
  const name = text(r.name, 4096);
  const username = text(r.username, 4096);
  if (itemId === null || itemId === "" || name === null || username === null || !Array.isArray(r.uris)) return null;
  const uris = r.uris.filter((u): u is string => typeof u === "string" && u.length <= 4096).slice(0, 64);
  return { itemId, name, username, uris, hasTotp: r.hasTotp === true };
}

/** Read the handler's `vaultOpen` reply. Anything malformed is "unavailable": it opens nothing. */
export function parseOpenReply(reply: unknown): AppVaultOpened {
  if (typeof reply !== "object" || reply === null) return { state: "unavailable" };
  const r = reply as Record<string, unknown>;
  if (r.ok !== true || r.type !== "vaultOpen") return { state: "unavailable" };
  if (r.state === "cancelled") return { state: "cancelled" };
  if (r.state === "openApp") return { state: "openApp", message: text(r.message, 300) ?? OPEN_APP_FALLBACK };
  if (r.state !== "open" || typeof r.ticket !== "string" || !TICKET_RE.test(r.ticket) || !Array.isArray(r.items) || r.items.length > MAX_ITEMS) {
    return { state: "unavailable" };
  }
  const items: AppVaultItem[] = [];
  for (const raw of r.items) {
    const item = parseItem(raw);
    if (item === null) return { state: "unavailable" };
    items.push(item);
  }
  return { state: "open", ticket: r.ticket, email: text(r.email, 320), items };
}

/** Read the handler's `vaultSecret` reply. */
export function parseSecretReply(reply: unknown): AppVaultSecret {
  if (typeof reply !== "object" || reply === null) return { state: "unavailable" };
  const r = reply as Record<string, unknown>;
  if (r.ok !== true || r.type !== "vaultSecret") return { state: "unavailable" };
  if (r.state === "cancelled") return { state: "cancelled" };
  if (r.state === "refused") return { state: "refused" };
  if (r.state === "openApp") return { state: "openApp", message: text(r.message, 300) ?? OPEN_APP_FALLBACK };
  const username = text(r.username, 4096);
  const password = text(r.password, 4096);
  if (r.state !== "secret" || username === null || password === null) return { state: "unavailable" };
  return { state: "secret", username, password, totpCode: text(r.totpCode, 16) };
}

type NativeSend = (msg: { type: string; ticket?: string; itemId?: string }) => Promise<unknown>;

function bounded(p: Promise<unknown>, ms: number): Promise<unknown> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const silence = new Promise<undefined>((resolve) => {
    timer = setTimeout(() => resolve(undefined), ms);
  });
  return Promise.race([p, silence]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  });
}

/**
 * The worker's view of the app's vault: the list (no secrets) and the handler's ticket, in memory, for one popup.
 * Never throws; a native failure reads as "unavailable".
 */
export class AppVault {
  private opened: { ticket: string; email: string | null; items: AppVaultItem[]; until: number } | null = null;
  private readonly send: NativeSend;
  private readonly now: () => number;

  constructor(send: NativeSend, now: () => number = Date.now) {
    this.send = send;
    this.now = now;
  }

  private live(): { ticket: string; email: string | null; items: AppVaultItem[]; until: number } | null {
    if (this.opened !== null && this.now() >= this.opened.until) this.close();
    return this.opened;
  }

  get unlocked(): boolean {
    return this.live() !== null;
  }

  get email(): string | null {
    return this.live()?.email ?? null;
  }

  /** The logins, by name. Empty while locked. */
  items(): AppVaultItem[] {
    return this.live()?.items ?? [];
  }

  item(itemId: string): AppVaultItem | null {
    return this.items().find((i) => i.itemId === itemId) ?? null;
  }

  /** Face ID in the handler, then the list. A second open replaces the first. */
  async open(): Promise<AppVaultOpened> {
    this.close();
    let result: AppVaultOpened;
    try {
      result = parseOpenReply(await bounded(this.send({ type: "vaultOpen" }), APP_VAULT_PROMPT_TIMEOUT_MS));
    } catch {
      result = { state: "unavailable" };
    }
    if (result.state === "open") {
      const items = [...result.items].sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()));
      this.opened = { ticket: result.ticket, email: result.email, items, until: this.now() + APP_VAULT_LIFETIME_MS };
    }
    return result;
  }

  /**
   * One login's secret, only for an item of the open list. The handler may have to prompt again (iOS can end its
   * process between two messages); that is its decision, and the answer is the same shape.
   */
  async secret(itemId: string): Promise<AppVaultSecret> {
    const live = this.live();
    if (live === null) return { state: "cancelled" };
    if (!live.items.some((i) => i.itemId === itemId)) return { state: "refused" };
    try {
      return parseSecretReply(await bounded(this.send({ type: "vaultSecret", ticket: live.ticket, itemId }), APP_VAULT_PROMPT_TIMEOUT_MS));
    } catch {
      return { state: "unavailable" };
    }
  }

  /** Drop the list and tell the handler to wipe its keys. Idempotent. */
  close(): void {
    const was = this.opened;
    this.opened = null;
    if (was !== null) {
      try {
        void this.send({ type: "vaultClose", ticket: was.ticket }).catch(() => {});
      } catch {
        /* nothing to close */
      }
    }
  }
}

/** Only the Safari build uses the app's vault; the others have their own session. */
export function vaultFromApp(target: BuildTarget): boolean {
  return target === "safari";
}
