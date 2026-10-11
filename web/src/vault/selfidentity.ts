import { fromB64, toB64 } from "../crypto/bytes";
import type { Account } from "./account";

/**
 * The recovered-member backstop (security review 2026-10, root cause A §2.4; twin of core
 * `SelfIdentityPin`): the seed-derived identityPub this browser saw the first time it unlocked an
 * account, passed to {@link Account.unlock} on every later unlock so a recovery that swapped the
 * identity seed hard-fails with the spec 01 §5 security-fault copy.
 *
 * PUBLIC data (the server holds the same key), kept in localStorage OUTSIDE the session record and the
 * offline cache, and deliberately NOT removed by sign-out, revocation or a cache wipe: an admin recovery
 * revokes every session first, so a pin wiped with the session would protect nothing. Written once, from
 * an unlock that passed; never overwritten from a server value. localStorage is origin-partitioned, so
 * the key needs only the userId. A malformed record is treated as absent (local corruption is not an
 * adversary capability; refusing on it would lock the member out). Spec 05 T6 caveat: web code is
 * server-served, so on web this guards an honest bundle against a server that tampers with data only.
 */
const PREFIX = "andvari.selfIdentityPub.";

export function loadSelfIdentityPub(userId: string): Uint8Array | null {
  try {
    const raw = typeof localStorage === "undefined" ? null : localStorage.getItem(PREFIX + userId);
    if (raw == null) return null;
    const pub = fromB64(raw.trim());
    return pub.length === 32 ? pub : null;
  } catch {
    return null;
  }
}

export function recordSelfIdentityPub(userId: string, account: Account): void {
  try {
    if (typeof localStorage === "undefined" || localStorage.getItem(PREFIX + userId) != null) return;
    localStorage.setItem(PREFIX + userId, toB64(account.identityPub));
  } catch {
    /* storage unavailable (privacy mode): the backstop is best-effort on web */
  }
}
