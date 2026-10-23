// Runtime (value) imports carry the .ts extension so this leaf resolves under `node --test` (trustmigrate.test.ts).
import { canonicalizeServerUrl, DEFAULT_SERVER_URL, SERVER_URL_KEY } from "./serverurl.ts";
import { TrustedStoreUnavailable, type KvArea } from "./trustedkv.ts";
import { decodeItemHomes, decodePersonalWrap, encodeItemHomes } from "./trustrecords.ts";
import { isNewerVersion } from "./version.ts";
import { isUuid } from "./wireids.ts";

/**
 * The one-time move of the extension's trust state from chrome.storage.local into the trusted store (security review
 * 2026-10, branch A15; trustedkv.ts says why). Settled at every worker start; it reads storage.local only while it is
 * owed, which only the browser's report of the upgrade it exists for can make it (below).
 *
 * The rule: a pre-A15 storage.local value may already have been PLANTED by a content script, and nothing in that
 * area can be told apart from a genuine value. So nothing content-reachable becomes trusted, canonical, pinned or
 * adopted on the way in:
 *  - `serverUrl` is NEVER adopted. A non-default value is kept only as a display-only suggestion
 *    ([LEGACY_SERVER_KEY]) that the options page offers for re-confirmation through the Trust Gate; until the user
 *    connects again or says "Not mine", the worker dials NO server, the default included (serverstate.ts, F1).
 *  - The update channel is NOT migrated: no offer, no throttle stamp, no quiet marker, and no anti-rollback seq (the
 *    floor restarts at MIN_SEQ; a planted seq is indistinguishable from a real one). The forced start check re-derives
 *    the rest.
 *  - A pending personal change (`personalChange:<userId>`) is dropped: the next unlock re-stages it.
 *  - Item homes and the personal-wrap cache move under their strict decoders: the same trust they had in storage.local
 *    (homes are ids the server already knows; the wrap is AEAD-sealed under the UVK and re-opened before use).
 *  - The conveniences move too, shape-checked: `lastEmail` (closing its read by content scripts on Firefox),
 *    `quBioCred`, `quOfferDismissed`.
 *  - The flag that says "done" lives in the TRUSTED store only, so a content script can neither skip the migration
 *    nor make it run again. Once it is set, this module never reads storage.local again (the server state may read its
 *    `serverUrl`, only ever to block: serverstate.ts).
 *  - Nothing is deleted from storage.local until the copy has been read back and compared. A value the trusted store
 *    already holds is never overwritten (a retry after a partial run, or a choice made since).
 *
 * WHEN it reads storage.local (A15 review F2): only when the BROWSER attested an upgrade from a pre-A15 build —
 * `runtime.onInstalled` with reason "update" and a `previousVersion` no newer than [LAST_PRE_A15_VERSION]. That event is
 * recorded in the trusted store as "owed" ([A15_OWED_KEY]) before anything is read, so a migration cut short after that
 * (the worker died, a later write failed) is finished at the next start, and the flag and the owed mark are swapped in
 * ONE write when it completes. Every other start without the flag — a fresh install, an update from an A15 build, or a later start with
 * no install event at all (the trusted store was unavailable at the upgrade, or lost its data while storage.local kept
 * its own) — sets the flag WITHOUT reading storage.local (and, A16 review R3, the [UNATTESTED_SERVER_KEY] mark with it). Before F2 any flagless start migrated, so whatever a content
 * script had written to storage.local in the meantime (a planted server suggestion, homes, an older wrap, an email,
 * a credential id) moved into the trusted store.
 *  - The store unavailable at the attested upgrade (Firefox "Never remember history"): "owed" cannot be recorded, so
 *    nothing migrates, then or ever; there is nothing trustworthy to remember the event in. The fail-safe is the
 *    worker's: while the store is unavailable it reads storage.local's `serverUrl` ONLY to refuse sign-in while that
 *    names another server (serverstate.ts), and once the store is available again the first start sets the flag
 *    without reading. The device is then on the default server with nothing migrated (a fresh install's posture), and
 *    the user re-enters their server in Options.
 *  - The install event arrives after the bounded wait ([awaitInstall] answered null): the worker re-runs this with the
 *    late event once it lands (background.ts); the owed mark makes that run migrate even though the flag was set.
 *  - The store answers but refuses or times out the "owed" write at the attested upgrade ([migrateTrustState] answers
 *    `failed` or `unavailable`): nothing is recorded, so a migration cut short there does NOT finish at the next start.
 *    The worker retries the write within the same worker life, where the event is still in memory (background.ts,
 *    A16 review R3); should that life end first, the next start skips the migration, and the mark it writes with the
 *    flag ([UNATTESTED_SERVER_KEY]) keeps sign-in blocked while storage.local names another server (serverstate.ts).
 */

/** The migration's "done" flag — trusted store only. */
export const A15_MIGRATED_KEY = "a15Migrated";
/** A15 review F2: the browser attested an upgrade from a pre-A15 build and the migration has not completed yet. Trusted
 *  store only; set before storage.local is read, cleared in the same write that sets [A15_MIGRATED_KEY]. */
export const A15_OWED_KEY = "a15MigrationOwed";
/** The newest extension release WITHOUT the trusted store (A15). An update FROM this version or an older one owes the
 *  migration. If another release without A15 ships before A15 does, raise this to that release's version. A release of
 *  this tree must be NEWER than it: package.mjs refuses to package one that is not (releasegate.ts). */
export const LAST_PRE_A15_VERSION = "0.28.1";

/** What `runtime.onInstalled` reported (the two fields this needs). */
export interface InstallSignal {
  reason: string;
  previousVersion?: string;
}

/** True only for the browser's own report of an update from a pre-A15 build ([LAST_PRE_A15_VERSION] or older). A
 *  missing or malformed previous version attests nothing. */
export function attestsPreA15Upgrade(sig: InstallSignal | null | undefined): boolean {
  if (!sig || sig.reason !== "update" || typeof sig.previousVersion !== "string") return false;
  const v = sig.previousVersion.trim();
  return /^\d{1,9}(\.\d{1,9}){0,3}$/.test(v) && !isNewerVersion(v, LAST_PRE_A15_VERSION);
}
/** A pre-A15 non-default server choice awaiting re-confirmation through the Trust Gate. Display only, never dialed. */
export const LEGACY_SERVER_KEY = "legacyServerUrl";
/** A16 review R3: the flag was set WITHOUT reading storage.local (nothing attested the upgrade). Written in the same
 *  write as the flag; while it stands, each start reads storage.local's `serverUrl` ONLY to block while it names
 *  another server (serverstate.ts), and it goes once it does not, or once a server is chosen. Trusted store only. */
export const UNATTESTED_SERVER_KEY = "a15UnattestedServer";
/** The email the user last signed in with (non-secret; the popup prefills it). */
export const LAST_EMAIL_KEY = "lastEmail";

/** Pre-A15 global keys of ours in storage.local: dropped (the two A15 names too, should one be planted there). */
const LEGACY_GLOBAL_DROP = new Set([
  "nsAdoptedOnce", // the pre-namespacing adoption flag (that adoption's flag now lives in the trusted store)
  // pre-namespacing bare keys the 0.16 adoption should already have moved
  "quOfferDismissed",
  "updateInfo",
  "updateCheckedAt",
  "updateAcceptedSeq",
  "updateChannelQuiet",
  A15_MIGRATED_KEY,
  A15_OWED_KEY,
  LEGACY_SERVER_KEY,
  UNATTESTED_SERVER_KEY,
]);

const NS_RE = /^ns\.([0-9a-f]{16})\.(.+)$/;
const B64URLISH = /^[A-Za-z0-9+/_=-]{1,512}$/;

/** A remembered email: a short, single-line string (it only prefills the popup's field). */
export function rememberableEmail(v: unknown): string | null {
  if (typeof v !== "string" || v.length === 0 || v.length > 320) return null;
  if (/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(v)) return null;
  return v;
}

function bioCredOf(v: unknown): { credentialId: string; prfSalt: string; userId: string } | null {
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  if (Object.keys(o).length !== 3) return null;
  const { credentialId, prfSalt, userId } = o;
  if (typeof credentialId !== "string" || !B64URLISH.test(credentialId)) return null;
  if (typeof prfSalt !== "string" || !B64URLISH.test(prfSalt)) return null;
  if (!isUuid(userId)) return null;
  return { credentialId, prfSalt, userId };
}

interface Plan {
  put: Record<string, unknown>;
  remove: string[];
  legacyServer: string | null;
}

/** Decide, from a full storage.local dump, what moves (and in what checked form) and what goes. Pure. */
function plan(all: Record<string, unknown>): Plan {
  const put: Record<string, unknown> = {};
  const remove: string[] = [];
  let legacyServer: string | null = null;
  for (const [k, v] of Object.entries(all)) {
    if (k === SERVER_URL_KEY) {
      remove.push(k);
      const c = typeof v === "string" ? canonicalizeServerUrl(v) : null;
      if (c !== null && c !== DEFAULT_SERVER_URL) legacyServer = c; // a suggestion, never the choice
      continue;
    }
    if (k === LAST_EMAIL_KEY) {
      remove.push(k);
      const e = rememberableEmail(v);
      if (e !== null) put[k] = e;
      continue;
    }
    if (LEGACY_GLOBAL_DROP.has(k)) {
      remove.push(k);
      continue;
    }
    const m = NS_RE.exec(k);
    if (!m) continue; // not one of ours: left alone
    remove.push(k); // after A15 nothing namespaced belongs in storage.local
    const rest = m[2]!;
    if (rest.startsWith("itemHomes:") && isUuid(rest.slice("itemHomes:".length))) {
      const d = decodeItemHomes(v);
      if (d.value.size > 0) put[k] = encodeItemHomes(d.value);
    } else if (rest.startsWith("personalWrap:") && isUuid(rest.slice("personalWrap:".length))) {
      const d = decodePersonalWrap(v);
      if (d.value !== null) put[k] = { vaultId: d.value.vaultId, wrappedVk: d.value.wrappedVk };
    } else if (rest === "quBioCred") {
      const b = bioCredOf(v);
      if (b !== null) put[k] = b;
    } else if (rest === "quOfferDismissed") {
      if (v === true) put[k] = true;
    }
    // Everything else under ns. is dropped: personalChange:<userId> (re-staged at the next unlock), the update
    // channel (re-derived; the seq floor restarts at MIN_SEQ), and anything that never belonged in storage.local.
  }
  return { put, remove, legacyServer };
}

/** Order-independent JSON, for the read-back comparison. */
function stable(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v) ?? "undefined";
  if (Array.isArray(v)) return `[${v.map(stable).join(",")}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${stable(o[k])}`)
    .join(",")}}`;
}

export type MigrationOutcome =
  | { kind: "already" }
  /** The flag was set without reading storage.local: a fresh install, an update from an A15 build, or a start with no
   *  install event within the wait (`signal: "none"` — background re-runs the migration if a late event attests one). */
  | { kind: "skipped"; signal: "none" | "other" }
  /** No trusted store (it refused, or did not answer in time): nothing was read or written. */
  | { kind: "unavailable"; timedOut: boolean }
  /** An owed migration did not complete; it stays owed and runs again at the next start. */
  | { kind: "failed" }
  | { kind: "migrated"; legacyServer: string | null; moved: string[]; removed: number };

const unavailable = (e: unknown): MigrationOutcome => ({ kind: "unavailable", timedOut: e instanceof TrustedStoreUnavailable && e.timedOut });

/**
 * Settle the one-time migration at worker start (see the module comment). [awaitInstall] answers the browser's install
 * event for this start, or null when none arrives within the wait; it is asked only when the store holds neither the
 * flag nor the owed mark. Never throws.
 */
export async function migrateTrustState(
  legacy: KvArea,
  trusted: KvArea,
  awaitInstall: () => Promise<InstallSignal | null>,
): Promise<MigrationOutcome> {
  let owed: boolean;
  try {
    const got = await trusted.get([A15_MIGRATED_KEY, A15_OWED_KEY]);
    owed = got[A15_OWED_KEY] === true;
    if (!owed && got[A15_MIGRATED_KEY] === true) return { kind: "already" };
  } catch (e) {
    return unavailable(e); // no trusted store: touch nothing — and record nothing, for there is nowhere to
  }
  if (!owed) {
    let sig: InstallSignal | null = null;
    try {
      sig = await awaitInstall();
    } catch {
      sig = null;
    }
    if (!attestsPreA15Upgrade(sig)) {
      // F2: nothing attests a pre-A15 upgrade, so storage.local is NOT read — whatever sits there may be a content
      // script's. Best effort: a flag that could not be written is simply set at a later start, the same way. A16 review
      // R3: with the flag, in the same write, the mark that says it was set unread — so a self-hoster whose attested
      // upgrade could not record "owed" is blocked (serverstate.ts), not signed in to the default, at this start and after.
      await trusted.set({ [A15_MIGRATED_KEY]: true, [UNATTESTED_SERVER_KEY]: true }).catch(() => {});
      return { kind: "skipped", signal: sig === null ? "none" : "other" };
    }
    try {
      await trusted.set({ [A15_OWED_KEY]: true }); // recorded BEFORE storage.local is read
    } catch (e) {
      return e instanceof TrustedStoreUnavailable && e.timedOut ? unavailable(e) : { kind: "failed" };
    }
  }
  return runOwedMigration(legacy, trusted);
}

/** The owed migration proper: read storage.local, move what may move, verify, then swap owed for done in one write. */
async function runOwedMigration(legacy: KvArea, trusted: KvArea): Promise<MigrationOutcome> {
  let all: Record<string, unknown>;
  try {
    all = await legacy.get(null);
  } catch {
    return { kind: "failed" };
  }
  const p = plan(all);
  try {
    const candidates: Record<string, unknown> = { ...p.put };
    if (p.legacyServer !== null) candidates[LEGACY_SERVER_KEY] = p.legacyServer;
    // Never overwrite what the trusted store already holds; and a server already chosen there needs no suggestion.
    const existing = await trusted.get([...Object.keys(candidates), SERVER_URL_KEY]);
    if (existing[SERVER_URL_KEY] !== undefined) delete candidates[LEGACY_SERVER_KEY];
    const put = Object.fromEntries(Object.entries(candidates).filter(([k]) => existing[k] === undefined));
    const keys = Object.keys(put);
    if (keys.length > 0) {
      await trusted.set(put);
      const back = await trusted.get(keys);
      for (const k of keys) if (stable(back[k]) !== stable(put[k])) return { kind: "failed" }; // keep storage.local, retry
    }
    // One write, so no start can see "done" while still owed, or "owed" once done.
    await trusted.set({ [A15_MIGRATED_KEY]: true, [A15_OWED_KEY]: false });
    let removed = 0;
    try {
      if (p.remove.length > 0) await legacy.remove(p.remove);
      removed = p.remove.length;
    } catch {
      /* the flag is set, so nothing reads these again; the per-origin purge also sweeps storage.local */
    }
    return { kind: "migrated", legacyServer: put[LEGACY_SERVER_KEY] === undefined ? null : p.legacyServer, moved: keys, removed };
  } catch {
    return { kind: "failed" };
  }
}
