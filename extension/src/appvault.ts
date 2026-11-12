import type { BuildTarget } from "./buildtarget.ts";

/**
 * Safari on iOS: the extension has no sign-in and no vault of its own. Its popup fills from the andvari app's vault,
 * which the native handler opens behind Face ID (app-ios/AndvariSafari/SafariWebExtensionHandler.swift, AppVaultSession;
 * the same read-only core object as system AutoFill: the app's quick-unlock gates, no network, no tokens).
 *
 * Least disclosure across the native-message hop:
 *  - `vaultOpen` answers with names, usernames and web addresses. No password, no one-time code.
 *  - `vaultSecret` answers with ONE thing of one login, for the item id asked: its username and password, or its
 *    current one-time code. Never both in one answer.
 * This worker keeps the list and the handler's ticket in memory only ([AppVault]); nothing decrypted is written to any
 * storage, and both are dropped on Lock and after [APP_VAULT_LIFETIME_MS]. They are NOT tied to the popup's page: on
 * iOS the Face ID sheet dismisses the popup, and the unlock has to be there when it is opened again.
 *
 * LEAF module: no chrome import. The worker passes the native-message call in.
 */

export const APP_VAULT_LIFETIME_MS = 90_000;
/** Face ID is a person's time: the handler may take this long to answer an unlock. */
export const APP_VAULT_PROMPT_TIMEOUT_MS = 60_000;

/** A login as the handler lists it. No secret. */
export type AppVaultItem = { itemId: string; name: string; username: string; uris: string[]; hasTotp: boolean };

/** A payment card as the handler lists it: a name and a masked line ("Visa ••4242"). No number, date or code. */
export type AppVaultCard = { itemId: string; name: string; subtitle: string; hasNumber: boolean; hasExpiry: boolean; hasCvv: boolean; hasName: boolean };

/** The stored fields of a card that one ask may name. */
export const CARD_FIELDS = ["number", "expMonth", "expYear", "cvv", "name", "postal"] as const;
export type CardFieldName = (typeof CARD_FIELDS)[number];

/** The fields one ask released, as stored. Only what was asked for, and only what the card has. */
export type AppVaultCardFields = Partial<Record<CardFieldName, string>>;

export type AppVaultOpened =
  | { state: "open"; ticket: string; email: string | null; items: AppVaultItem[]; cards: AppVaultCard[] }
  /** Nothing can be opened here now; `message` says what to do in the app. */
  | { state: "openApp"; message: string }
  | { state: "cancelled" }
  | { state: "unavailable" };

/** ONE thing of one login per ask: its username and password, or its current one-time code. Never both. */
export type AppVaultWant = "login" | "code";

export type AppVaultSecret =
  | { state: "login"; username: string; password: string }
  | { state: "code"; code: string }
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

function parseCard(v: unknown): AppVaultCard | null {
  if (typeof v !== "object" || v === null) return null;
  const r = v as Record<string, unknown>;
  const itemId = text(r.itemId, 128);
  const name = text(r.name, 4096);
  const subtitle = text(r.subtitle, 200);
  if (itemId === null || itemId === "" || name === null || subtitle === null) return null;
  return { itemId, name, subtitle, hasNumber: r.hasNumber === true, hasExpiry: r.hasExpiry === true, hasCvv: r.hasCvv === true, hasName: r.hasName === true };
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
  // Cards are optional in the reply (an app build from before they were listed sends none).
  const cards: AppVaultCard[] = [];
  if (r.cards !== undefined) {
    if (!Array.isArray(r.cards) || r.cards.length > MAX_ITEMS) return { state: "unavailable" };
    for (const raw of r.cards) {
      const card = parseCard(raw);
      if (card === null) return { state: "unavailable" };
      cards.push(card);
    }
  }
  return { state: "open", ticket: r.ticket, email: text(r.email, 320), items, cards };
}

export type AppVaultCardSecret =
  | { state: "card"; fields: AppVaultCardFields }
  | { state: "openApp"; message: string }
  | { state: "cancelled" }
  | { state: "refused" }
  | { state: "unavailable" };

/** Read the handler's answer to a card ask: only the fields that were asked for are kept, whatever came back. */
export function parseCardReply(reply: unknown, asked: readonly CardFieldName[]): AppVaultCardSecret {
  if (typeof reply !== "object" || reply === null) return { state: "unavailable" };
  const r = reply as Record<string, unknown>;
  if (r.ok !== true || r.type !== "vaultSecret") return { state: "unavailable" };
  if (r.state === "cancelled") return { state: "cancelled" };
  if (r.state === "refused") return { state: "refused" };
  if (r.state === "openApp") return { state: "openApp", message: text(r.message, 300) ?? OPEN_APP_FALLBACK };
  if (r.state !== "secret" || typeof r.card !== "object" || r.card === null) return { state: "unavailable" };
  const fields: AppVaultCardFields = {};
  for (const name of CARD_FIELDS) {
    if (!asked.includes(name)) continue;
    const value = text((r.card as Record<string, unknown>)[name], 256);
    if (value !== null && value !== "") fields[name] = value;
  }
  return { state: "card", fields };
}

/**
 * Read the handler's `vaultSecret` reply for what was asked. Only that is kept: a password in an answer to a code
 * request (or the reverse) is dropped here, whatever the handler sent.
 */
export function parseSecretReply(reply: unknown, want: AppVaultWant): AppVaultSecret {
  if (typeof reply !== "object" || reply === null) return { state: "unavailable" };
  const r = reply as Record<string, unknown>;
  if (r.ok !== true || r.type !== "vaultSecret") return { state: "unavailable" };
  if (r.state === "cancelled") return { state: "cancelled" };
  if (r.state === "refused") return { state: "refused" };
  if (r.state === "openApp") return { state: "openApp", message: text(r.message, 300) ?? OPEN_APP_FALLBACK };
  if (r.state !== "secret") return { state: "unavailable" };
  if (want === "code") {
    const code = text(r.totpCode, 16);
    return code === null || code === "" ? { state: "unavailable" } : { state: "code", code };
  }
  const username = text(r.username, 4096);
  const password = text(r.password, 4096);
  return username === null || password === null ? { state: "unavailable" } : { state: "login", username, password };
}

/**
 * What the handler said about its own process in a reply (`diag`): its pid and age, and whether it still held the
 * vault and recognised the ticket. No secret. Shown in the popup's Details, because whether iOS keeps the handler's
 * process between two messages can only be seen on a device.
 */
export function describeDiag(reply: unknown): string | null {
  if (typeof reply !== "object" || reply === null) return null;
  const d = (reply as { diag?: unknown }).diag;
  if (typeof d !== "object" || d === null) return null;
  const out: string[] = [];
  for (const [k, v] of Object.entries(d as Record<string, unknown>).slice(0, 12)) {
    if (typeof v === "number" || typeof v === "boolean") out.push(`${k.slice(0, 24)}=${String(v)}`);
  }
  return out.length > 0 ? out.join(" ") : null;
}

type NativeSend = (msg: { type: string; ticket?: string; itemId?: string; want?: AppVaultWant | "card"; name?: string; fields?: CardFieldName[] }) => Promise<unknown>;

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
  private opened: { ticket: string; email: string | null; items: AppVaultItem[]; cards: AppVaultCard[]; until: number } | null = null;
  private readonly send: NativeSend;
  private readonly now: () => number;
  /** The handler's own account of its process at the last open and the last secret (Details). */
  readonly diag: { open: string | null; secret: string | null } = { open: null, secret: null };

  constructor(send: NativeSend, now: () => number = Date.now) {
    this.send = send;
    this.now = now;
  }

  private live(): { ticket: string; email: string | null; items: AppVaultItem[]; cards: AppVaultCard[]; until: number } | null {
    if (this.opened !== null && this.now() >= this.opened.until) this.close();
    return this.opened;
  }

  get unlocked(): boolean {
    return this.live() !== null;
  }

  get email(): string | null {
    return this.live()?.email ?? null;
  }

  /**
   * The answer to every list the popup asks for (this site's logins, all logins, cards): ONE notion of locked, the
   * vault's. The popup returns to its unlock screen when any list says locked, so a list answered from anywhere else
   * (the worker's own, absent session said "locked" for cards) made it flip between the two screens without end.
   */
  listAnswer<T>(items: T[]): { locked: boolean; items: T[] } {
    return this.live() === null ? { locked: true, items: [] } : { locked: false, items };
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
      const reply = await bounded(this.send({ type: "vaultOpen" }), APP_VAULT_PROMPT_TIMEOUT_MS);
      this.diag.open = describeDiag(reply);
      result = parseOpenReply(reply);
    } catch {
      result = { state: "unavailable" };
    }
    if (result.state === "open") {
      const items = [...result.items].sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()));
      const cards = [...result.cards].sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()));
      this.opened = { ticket: result.ticket, email: result.email, items, cards, until: this.now() + APP_VAULT_LIFETIME_MS };
    }
    return result;
  }

  /**
   * One thing of one login ([want]), only for an item of the open list. The handler may have to prompt again (iOS can
   * end its process between two messages); its prompt then names the login, which is why the name travels with the
   * ask (the handler checks it against the item before it releases anything).
   */
  async secret(itemId: string, want: AppVaultWant): Promise<AppVaultSecret> {
    const live = this.live();
    if (live === null) return { state: "cancelled" };
    const item = live.items.find((i) => i.itemId === itemId);
    if (item === undefined) return { state: "refused" };
    try {
      const reply = await bounded(this.send({ type: "vaultSecret", ticket: live.ticket, itemId, want, name: item.name }), APP_VAULT_PROMPT_TIMEOUT_MS);
      this.diag.secret = describeDiag(reply);
      const result = parseSecretReply(reply, want);
      // The app's gates refuse now (signed out, policy, Face ID off): this vault is over. A cancel, or a handler
      // that had to prompt again, changes nothing here.
      if (result.state === "openApp") this.close();
      return result;
    } catch {
      return { state: "unavailable" };
    }
  }

  /** The payment cards, by name (names and masked lines only). Empty while locked. */
  cards(): AppVaultCard[] {
    return this.live()?.cards ?? [];
  }

  card(itemId: string): AppVaultCard | null {
    return this.cards().find((c) => c.itemId === itemId) ?? null;
  }

  /**
   * The named stored fields of ONE listed card: what a detected form declared, or the one field being copied. Never
   * the whole card unless every field was asked for.
   */
  async cardFields(itemId: string, fields: readonly CardFieldName[]): Promise<AppVaultCardSecret> {
    const live = this.live();
    if (live === null) return { state: "cancelled" };
    const card = live.cards.find((c) => c.itemId === itemId);
    if (card === undefined) return { state: "refused" };
    const asked = CARD_FIELDS.filter((f) => fields.includes(f));
    if (asked.length === 0) return { state: "card", fields: {} };
    try {
      const reply = await bounded(this.send({ type: "vaultSecret", ticket: live.ticket, itemId, want: "card", name: card.name, fields: asked }), APP_VAULT_PROMPT_TIMEOUT_MS);
      this.diag.secret = describeDiag(reply);
      const result = parseCardReply(reply, asked);
      if (result.state === "openApp") this.close();
      return result;
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
