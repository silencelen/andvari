// Runtime (value) imports carry the .ts extension so this leaf resolves under `node --test` (serverchoice.test.ts).
import { canonicalizeServerUrl, NO_SERVER_ORIGIN, nsKey, originKeyFor, originMatchPattern, SERVER_URL_KEY } from "./serverurl.ts";
import { decodeStoredPin, PIN_KEY, type StoredPin } from "./pinstore.ts";
import type { KvArea } from "./trustedkv.ts";

/**
 * Which server the worker may dial, and when it may dial none (design 2026-11-15-onboarding-trust §4.4, §12.2).
 *
 * The extension dials a server, and sends it anything derived from the password, only through a password pin for its
 * origin (§4.4 password rule; the extension's two roots, the baked public instance and the Trust Gate's typed address,
 * are both password pins). So the worker dials nothing while any of these blocks stands:
 *  - `no_server`: no server is chosen yet (no build has a default, §0.2 O), or the chosen server has no pin.
 *  - `no_store`: this browser mode has no trusted store (no IndexedDB: Firefox's "Never remember history"), so neither
 *    a server choice nor a pin can be kept.
 *  - `unsettled`: the trusted store did not answer in time; the worker cannot tell which server the person chose.
 *  - `pin_damaged`: the origin's pin record does not decode. Never read as "no pin" (§4.4).
 *  - `fork`: the origin's chain forked (durable, §4.4). Only "Forget this server" goes on.
 * Every message that would reach a server is refused (dialRefusal), the api sends nothing (background makeApi), and
 * autofill stays out of the origin (autofillExcludeMatches).
 *
 * Safari keeps its own model unchanged: it signs in nowhere by itself, its origin is the andvari app's (appserver.ts),
 * and it holds no card pin, so only `no_server` (the app named none yet) and `unsettled` apply there.
 *
 * Chrome-free; the stores are injected.
 */

export type ServerBlock =
  | { kind: "no_server" }
  | { kind: "no_store" }
  | { kind: "unsettled" }
  | { kind: "pin_damaged"; origin: string }
  | { kind: "fork"; origin: string };

export interface ServerState {
  /** The origin the worker's api is built for ([NO_SERVER_ORIGIN] when none). While [block] stands it is NOT dialed. */
  url: string;
  /** Whether this browser can keep a server choice (the trusted store answered). */
  trustedStore: boolean;
  block: ServerBlock | null;
  /** The pin for [url], when one decoded. */
  pin: StoredPin | null;
}

/** The answer to a block on a message that would reach a server. */
export type DialRefusal = { ok: false; code: "confirm_server" };

/** The message types that would send a sign-in, a password-derived value, or any request to the server. */
export const DIAL_TYPES = ["unlock", "unlockTotp", "unlockWithPin", "unlockWithBio", "ping"] as const;
const DIALS: ReadonlySet<string> = new Set(DIAL_TYPES);

/** The refusal for [type] while [block] stands, or null when the message may run. */
export function dialRefusal(type: string, block: ServerBlock | null): DialRefusal | null {
  return block !== null && DIALS.has(type) ? { ok: false, code: "confirm_server" } : null;
}

/** The block a stored pin leaves for [origin] (null: none). */
export function pinBlock(origin: string, raw: unknown): { block: ServerBlock | null; pin: StoredPin | null } {
  const read = decodeStoredPin(raw, origin);
  if (read.kind === "none") return { block: { kind: "no_server" }, pin: null };
  if (read.kind === "damaged") return { block: { kind: "pin_damaged", origin }, pin: null };
  if (read.stored.fork) return { block: { kind: "fork", origin }, pin: read.stored };
  return { block: null, pin: read.stored };
}

/**
 * The server state at worker start. Never throws. [storeOutcome] says how the trusted store answered its first
 * operation: `ok`, `unavailable` (refused: no IndexedDB here) or `timedOut`. [pins] is false for Safari, which holds no
 * card pin.
 */
export async function loadServerState(storeOutcome: "ok" | "unavailable" | "timedOut", trusted: KvArea, pins = true): Promise<ServerState> {
  if (storeOutcome === "timedOut") return { url: NO_SERVER_ORIGIN, trustedStore: false, block: { kind: "unsettled" }, pin: null };
  if (storeOutcome === "unavailable") return { url: NO_SERVER_ORIGIN, trustedStore: false, block: { kind: pins ? "no_store" : "no_server" }, pin: null };
  let stored: unknown;
  try {
    stored = (await trusted.get(SERVER_URL_KEY))[SERVER_URL_KEY];
  } catch {
    return { url: NO_SERVER_ORIGIN, trustedStore: true, block: { kind: "unsettled" }, pin: null };
  }
  const url = (typeof stored === "string" ? canonicalizeServerUrl(stored) : null) ?? NO_SERVER_ORIGIN;
  if (url === NO_SERVER_ORIGIN) return { url, trustedStore: true, block: { kind: "no_server" }, pin: null };
  if (!pins) return { url, trustedStore: true, block: null, pin: null };
  const key = nsKey(originKeyFor(url), PIN_KEY);
  let raw: unknown;
  try {
    raw = (await trusted.get(key))[key];
  } catch {
    return { url, trustedStore: true, block: { kind: "unsettled" }, pin: null };
  }
  return { url, trustedStore: true, ...pinBlock(url, raw) };
}

/**
 * The autofill content script's excludeMatches: the dialed origin and the public instance — the person's own vault
 * UI never gets the autofill script. Null means fail CLOSED (register no autofill at all): an origin that cannot be
 * written as a match pattern, or an `unsettled` block, where the person's vault origin is not known.
 */
export function autofillExcludeMatches(url: string, block: ServerBlock | null, publicOrigin: string): string[] | null {
  if (block?.kind === "unsettled") return null;
  const out: string[] = [];
  for (const o of new Set([url, publicOrigin])) {
    const p = originMatchPattern(o);
    if (p === null) return null;
    if (!out.includes(p)) out.push(p);
  }
  return out;
}
