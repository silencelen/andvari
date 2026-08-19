// Runtime imports carry the .ts extension so this module resolves under `node --test` (its test
// imports it) — the quickunlock.ts rule; esbuild + tsc (allowImportingTsExtensions) accept it.
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { toB64 } from "./crypto.ts";
import { normalizeHost, parseSavedUri, type PslResolve } from "./urimatch.ts";

/**
 * Known-logins digest — the locked save-prompt check (owner decision 2026-08-18; spec 01 §8.4
 * amendment). While the vault is locked the SW has NOTHING to dedupe a captured credential
 * against (matchesFor() is empty by design), so every re-login to an already-saved site
 * bannered "unlock to save". This module gives the locked state a membership test that carries
 * NO password material: a set of truncated HMACs over (site key, normalized username) pairs,
 * keyed by a random per-install key, rebuilt from the decrypted items while unlocked and
 * retained across a lock under its own storage.session key (the QKEY posture — memory-backed,
 * browser-exit-cleared, trusted contexts only; wiped at sign-out and on an untrusted
 * compartment, exactly like the quick-unlock blob).
 *
 * Honest disclosure bound: someone who can read the locked compartment can test GUESSED
 * (site, username) pairs for membership — strictly less than the plaintext pendings the same
 * compartment already holds, but real, which is why this is a named spec amendment and not a
 * quiet cache. Digests are truncated to 16 bytes: membership fidelity, no useful preimage.
 *
 * The site key is the SAME authority notion as autofill matching and the web duplicate
 * checker (eTLD+1 via the PSL; unresolvable hosts — IPs, single-label, public-suffix — key as
 * the normalized host itself): the three systems must agree on what "the same login" means,
 * or the quiet-list would disagree with the banner's own post-unlock dedupe.
 *
 * Pure and chrome-free (the savetarget.ts idiom) so node --test pins every decision below;
 * background.ts owns storage and wiring.
 */

/** The storage.session record under nsk(KLKEY): the b64 random HMAC key + the digest set. */
export interface KnownLoginsRecord {
  key: string;
  digests: string[];
}

/** How long a pending minted WHILE LOCKED may sit (plaintext, storage.session) before it is
 *  dropped unoffered — the owner-picked bound (2026-08-18) on the walk-away tail. Distinct from
 *  APPROVED_SAVE_TTL_MS (that bounds an explicit Save click; this bounds an unanswered capture). */
export const LOCKED_PENDING_TTL_MS = 30 * 60_000;

/** Locked-state re-offer throttle (owner decision 2026-08-18): after the immediate first banner,
 *  a still-unanswered new-login pending re-offers at most once per this gap — persistent enough
 *  to not lose the save, quiet enough to stop the every-page-load nag. */
export const REOFFER_MIN_GAP_MS = 10 * 60_000;

/** The clustering/matching site key for one page host: eTLD+1 when the PSL resolves it, else the
 *  normalized host itself (web duplicates.ts siteKeysOf parity). null = garbage host. */
export function siteKeyOfHost(host: string, resolve: PslResolve): string | null {
  const h = normalizeHost(host);
  if (!h) return null;
  const r = resolve(h);
  return r.kind === "registrable" ? r.domain : h;
}

/** One digest: truncated HMAC-SHA256 over the NUL-joined pair (the duplicates.ts separator rule —
 *  a username containing the delimiter cannot forge another pair's key; written as the escape,
 *  never a literal 0x00, for the same git-binary reason). Username normalization mirrors the
 *  web checker: trim + lowercase. */
export function knownLoginDigest(key: Uint8Array, siteKey: string, username: string): string {
  const msg = new TextEncoder().encode(`${siteKey}\u0000${username.trim().toLowerCase()}`);
  return toB64(hmac(sha256, key, msg).subarray(0, 16));
}

/** The minimal item shape the builder reads — structural, so background's DecryptedItem and any
 *  test fixture both satisfy it without an import cycle. */
export interface KnownLoginSource {
  doc: {
    type: string;
    login?: { username?: string; uris?: string[] };
  };
}

/** The full digest set for a decrypted item list: every (site key, username) pair of every login,
 *  one digest per pair, deduped. androidapp:// uris are skipped (a web capture can never be one);
 *  items with no resolvable site contribute nothing (without a site, the pair means nothing —
 *  duplicates.ts parity). */
export function buildKnownLoginDigests(key: Uint8Array, items: KnownLoginSource[], resolve: PslResolve): string[] {
  const out = new Set<string>();
  for (const it of items) {
    if (it.doc.type !== "login") continue;
    const username = it.doc.login?.username ?? "";
    for (const raw of it.doc.login?.uris ?? []) {
      const saved = parseSavedUri(raw);
      if (!saved || saved.kind !== "web") continue;
      const r = resolve(saved.host);
      out.add(knownLoginDigest(key, r.kind === "registrable" ? r.domain : saved.host, username));
    }
  }
  return [...out];
}

/** Locked-state re-offer verdict for a pending save — the one gate every RE-offer surface
 *  (tabs.onUpdated, the content load poll) consults. Extracted pure (the locksequence idiom) so
 *  the ordering below is pinnable:
 *   1. a locked-minted pending past LOCKED_PENDING_TTL_MS is `expired` (drop it) — even when the
 *      vault has since unlocked, and BEFORE quiet/throttle, so plaintext never outlives the bound;
 *   2. unlocked → `offer` (reofferPendingSaves owns the unlock moment's dedupe);
 *   3. a quiet pending (known login captured while locked) stays `quiet` for the whole locked life;
 *   4. otherwise throttle to one offer per REOFFER_MIN_GAP_MS.
 *  The IMMEDIATE banner at capture time never routes through this — only re-offers do. */
export type ReofferVerdict = "offer" | "expired" | "quiet" | "throttled";
export function reofferDecision(
  pending: { lockedAt?: number; quiet?: boolean; offeredAt?: number },
  nowMs: number,
  unlocked: boolean,
): ReofferVerdict {
  if (pending.lockedAt !== undefined && nowMs - pending.lockedAt > LOCKED_PENDING_TTL_MS) return "expired";
  if (unlocked) return "offer";
  if (pending.quiet) return "quiet";
  // No stamp = never offered → offer now (an absent stamp must not read as "offered at epoch").
  if (pending.offeredAt !== undefined && nowMs - pending.offeredAt < REOFFER_MIN_GAP_MS) return "throttled";
  return "offer";
}
