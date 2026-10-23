// Runtime (value) imports carry the .ts extension so this leaf resolves under `node --test` (serverstate.test.ts).
import { canonicalizeServerUrl, DEFAULT_SERVER_URL, originMatchPattern, SERVER_URL_KEY } from "./serverurl.ts";
import type { KvArea } from "./trustedkv.ts";
import { LEGACY_SERVER_KEY, UNATTESTED_SERVER_KEY, type MigrationOutcome } from "./trustmigrate.ts";

/**
 * Which server the worker may dial, and when it may dial none (security review 2026-10, A15 review F1).
 *
 * After the A15 update a self-hoster's choice is not adopted (trustmigrate.ts: it sat in storage.local, which a content
 * script could write); it waits for a confirm through the Trust Gate. Before F1 the worker dialed DEFAULT_SERVER_URL in
 * the meantime, with nothing stopping a sign-in: storage.session is cleared by the update, so the user signed in again
 * with the email prefilled, and the reference instance — which answers an unknown email with a deterministic fake salt
 * — received the email and an authKey derived from the master password under a salt it chose. The update channel polled
 * it, the open-vault / forgot / must-change buttons opened it, and the self-host vault lost its autofill exclusion.
 *
 * So while a server is PENDING, the worker dials NO server at all — the default included — until the user decides:
 *  - [ServerBlock] `confirm`: a previous server awaits the user's confirm. `keepable` is false when the origin came from
 *    storage.local, read ONLY to refuse sign-in, never adopted and never offered for connecting: either this browser
 *    cannot keep a server choice at all (no trusted store: Firefox's "Never remember history"), or (A16 review R3) a
 *    start found no migration flag and nothing attesting the upgrade while storage.local still names another server.
 *  - [ServerBlock] `unsettled`: the trusted store did not answer in time, or an owed migration did not complete, so the
 *    worker cannot tell which server the user chose. Retried at the next worker start.
 * Only a Trust-Gate Connect (setServerUrl) or "Not mine" ([forgetPendingServer]) clears a `confirm`. While any block
 * stands, [dialRefusal] refuses every sign-in lane and the connection test, and (A16 review R4) the worker's api sends
 * no request at all — no sync, socket, save, refresh or sign-out revoke — the update check does not run, the pages open
 * nothing on a server, and [autofillExcludeMatches] keeps autofill out of the pending origin (failing closed).
 *
 * Chrome-free; the stores are injected.
 */

export type ServerBlock = { kind: "confirm"; origin: string; keepable: boolean } | { kind: "unsettled" };

export interface ServerState {
  /** The origin the worker's api is built for. While [block] stands it is NOT dialed. */
  url: string;
  /** Whether this browser can keep a server choice (the trusted store answered). */
  trustedStore: boolean;
  block: ServerBlock | null;
}

/** The answer to a `confirm` or `unsettled` block on a message that would reach a server. */
export type DialRefusal = { ok: false; code: "confirm_server" };

/** The message types that would send a sign-in, a password-derived value, or any request to the server. */
export const DIAL_TYPES = ["unlock", "unlockTotp", "unlockWithPin", "unlockWithBio", "ping"] as const;
const DIALS: ReadonlySet<string> = new Set(DIAL_TYPES);

/** The refusal for [type] while [block] stands, or null when the message may run. */
export function dialRefusal(type: string, block: ServerBlock | null): DialRefusal | null {
  return block !== null && DIALS.has(type) ? { ok: false, code: "confirm_server" } : null;
}

/** A canonical non-default origin from a raw stored value, or null. */
function otherServer(v: unknown): string | null {
  const c = typeof v === "string" ? canonicalizeServerUrl(v) : null;
  return c !== null && c !== DEFAULT_SERVER_URL ? c : null;
}

/** The one read of storage.local here: its `serverUrl`, as a non-default origin to block on — never to adopt. */
async function previousServer(legacy: KvArea): Promise<string | null> {
  try {
    return otherServer((await legacy.get(SERVER_URL_KEY))[SERVER_URL_KEY]);
  } catch {
    return null; // storage.local unreadable: nothing names another server
  }
}

/**
 * The server state at worker start, from the migration's [outcome] (trustmigrate.migrateTrustState). Never throws.
 *  - Store answered: the stored choice (or the default); a pending suggestion blocks unless a choice was made since.
 *  - Store refused (no IndexedDB in this mode): the default — but if storage.local still names another server, that is
 *    read ONLY to block (`keepable: false`): the user's previous server cannot be kept here, and signing in to the
 *    default in its place is exactly what F1 forbids. Read at every such start, never adopted, never connectable.
 *  - Store timed out, or an owed migration failed: `unsettled`.
 *  - A16 review R3: a start that skipped the migration (no flag, nothing attested the upgrade) — it wrote the
 *    [UNATTESTED_SERVER_KEY] mark with the flag — with no choice and no suggestion in the store: if storage.local names
 *    another server, the same read-only block as with no store (`keepable: false`: decline-only, never offered for
 *    connecting, so a planted value is only a denial of service). The origin is then kept in the mark, so later starts
 *    block on it without reading storage.local again (a content script that deletes the value there cannot lift the
 *    block); the mark goes when storage.local names no other server at that start, when a server is chosen, or on
 *    "Not mine". Before this the start that skipped the migration — the next one after an attested upgrade whose
 *    "owed" write failed — dialed the default, and so did every start after it, while storage.local still named the
 *    self-hoster's server: the A15 review's F1 harm again.
 */
export async function loadServerState(outcome: MigrationOutcome, trusted: KvArea, legacy: KvArea): Promise<ServerState> {
  const unsettled: ServerState = { url: DEFAULT_SERVER_URL, trustedStore: true, block: { kind: "unsettled" } };
  if (outcome.kind === "unavailable") {
    if (outcome.timedOut) return { ...unsettled, trustedStore: false };
    const previous = await previousServer(legacy);
    return { url: DEFAULT_SERVER_URL, trustedStore: false, block: previous === null ? null : { kind: "confirm", origin: previous, keepable: false } };
  }
  if (outcome.kind === "failed") return unsettled;
  let got: Record<string, unknown>;
  try {
    got = await trusted.get([SERVER_URL_KEY, LEGACY_SERVER_KEY, UNATTESTED_SERVER_KEY]);
  } catch {
    return unsettled; // it answered a moment ago; whatever it is now, the choice cannot be read
  }
  const stored = got[SERVER_URL_KEY];
  const url = (typeof stored === "string" ? canonicalizeServerUrl(stored) : null) ?? DEFAULT_SERVER_URL;
  if (stored !== undefined) {
    // A choice made through the gate stands; a suggestion or an unattested mark left beside it (its removal failed) is moot.
    const moot = [LEGACY_SERVER_KEY, UNATTESTED_SERVER_KEY].filter((k) => got[k] !== undefined);
    if (moot.length > 0) await trusted.remove(moot).catch(() => {});
    return { url, trustedStore: true, block: null };
  }
  const pending = otherServer(got[LEGACY_SERVER_KEY]);
  if (pending !== null) return { url, trustedStore: true, block: { kind: "confirm", origin: pending, keepable: true } };
  const mark = got[UNATTESTED_SERVER_KEY];
  const kept = otherServer(mark); // an origin a skipped start read from storage.local: block on it, never re-read
  if (kept !== null) return { url, trustedStore: true, block: { kind: "confirm", origin: kept, keepable: false } };
  if (outcome.kind === "skipped" || mark === true) {
    const previous = await previousServer(legacy);
    if (previous !== null) {
      await trusted.set({ [UNATTESTED_SERVER_KEY]: previous }).catch(() => {}); // best effort: the start that skipped blocks anyway
      return { url, trustedStore: true, block: { kind: "confirm", origin: previous, keepable: false } };
    }
  }
  if (mark !== undefined) await trusted.remove(UNATTESTED_SERVER_KEY).catch(() => {});
  return { url, trustedStore: true, block: null };
}

/**
 * "Not mine": drop a `confirm` block's origin where it is kept — the trusted store's suggestion, or (keepable false)
 * storage.local's old `serverUrl`, the only write this extension makes there besides removals by the purge — and, A16
 * review R3, the unattested mark, best effort (with no store there is none). An `unsettled` block cannot be dismissed
 * (there is nothing to dismiss: the store did not answer). Returns whether the block may be lifted.
 */
export async function forgetPendingServer(block: ServerBlock | null, trusted: KvArea, legacy: KvArea): Promise<boolean> {
  if (block === null) return true;
  if (block.kind !== "confirm") return false;
  try {
    if (block.keepable) await trusted.remove(LEGACY_SERVER_KEY);
    else await legacy.remove(SERVER_URL_KEY);
    // The unattested mark goes either way (with no store there is none): a declined server does not come back.
    await trusted.remove(UNATTESTED_SERVER_KEY).catch(() => {});
    return true;
  } catch {
    return false;
  }
}

/**
 * The autofill content script's excludeMatches (design §5.1, B2-5): the dialed origin, the shipped default, and a
 * pending origin — the user's own vault UI must not get the autofill script while it waits for a confirm (excluding a
 * planted origin is harmless). Null means fail CLOSED (register no autofill at all): an origin that cannot be written
 * as a match pattern (a bracketed IPv6 literal), or an `unsettled` block, where the user's vault origin is not known.
 */
export function autofillExcludeMatches(url: string, block: ServerBlock | null): string[] | null {
  if (block?.kind === "unsettled") return null;
  const origins = new Set([url, DEFAULT_SERVER_URL]);
  if (block?.kind === "confirm") origins.add(block.origin);
  const out: string[] = [];
  for (const o of origins) {
    const p = originMatchPattern(o);
    if (p === null) return null;
    if (!out.includes(p)) out.push(p);
  }
  return out;
}
