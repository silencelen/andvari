// Runtime (value) imports carry the .ts extension so this leaf resolves under `node --test` (trustmigrate.test.ts).
import { canonicalizeServerUrl, DEFAULT_SERVER_URL, SERVER_URL_KEY } from "./serverurl.ts";
import type { KvArea } from "./trustedkv.ts";
import { decodeItemHomes, decodePersonalWrap, encodeItemHomes } from "./trustrecords.ts";
import { isUuid } from "./wireids.ts";

/**
 * The one-time move of the extension's trust state from chrome.storage.local into the trusted store (security review
 * 2026-10, branch A15; trustedkv.ts says why). Runs at worker start until it has completed once.
 *
 * The rule: a pre-A15 storage.local value may already have been PLANTED by a content script, and nothing in that
 * area can be told apart from a genuine value. So nothing content-reachable becomes trusted, canonical, pinned or
 * adopted on the way in:
 *  - `serverUrl` is NEVER adopted. A non-default value is kept only as a display-only suggestion
 *    ([LEGACY_SERVER_KEY]) that the options page offers for re-confirmation through the Trust Gate; until the user
 *    connects again, the worker dials DEFAULT_SERVER_URL.
 *  - The update channel is NOT migrated: no offer, no throttle stamp, no quiet marker, and no anti-rollback seq (the
 *    floor restarts at MIN_SEQ; a planted seq is indistinguishable from a real one). The forced start check re-derives
 *    the rest.
 *  - A pending personal change (`personalChange:<userId>`) is dropped: the next unlock re-stages it.
 *  - Item homes and the personal-wrap cache move under their strict decoders: the same trust they had in storage.local
 *    (homes are ids the server already knows; the wrap is AEAD-sealed under the UVK and re-opened before use).
 *  - The conveniences move too, shape-checked: `lastEmail` (closing its read by content scripts on Firefox),
 *    `quBioCred`, `quOfferDismissed`.
 *  - The flag that says "done" lives in the TRUSTED store only, so a content script can neither skip the migration
 *    nor make it run again. Once it is set, storage.local is never read again.
 *  - Nothing is deleted from storage.local until the copy has been read back and compared. A value the trusted store
 *    already holds is never overwritten (a retry after a partial run, or a choice made since).
 *  - If the trusted store is unavailable, the migration does nothing at all and retries at the next start; the callers
 *    meanwhile use their safe defaults (never storage.local).
 */

/** The migration's "done" flag — trusted store only. */
export const A15_MIGRATED_KEY = "a15Migrated";
/** A pre-A15 non-default server choice awaiting re-confirmation through the Trust Gate. Display only, never dialed. */
export const LEGACY_SERVER_KEY = "legacyServerUrl";
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
  LEGACY_SERVER_KEY,
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
  | { kind: "unavailable" }
  | { kind: "failed" }
  | { kind: "migrated"; legacyServer: string | null; moved: string[]; removed: number };

/** Run the migration once (see the module comment). Never throws. */
export async function migrateTrustState(legacy: KvArea, trusted: KvArea): Promise<MigrationOutcome> {
  try {
    if ((await trusted.get(A15_MIGRATED_KEY))[A15_MIGRATED_KEY] === true) return { kind: "already" };
  } catch {
    return { kind: "unavailable" }; // no trusted store: touch nothing, retry at the next start
  }
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
    await trusted.set({ [A15_MIGRATED_KEY]: true });
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
