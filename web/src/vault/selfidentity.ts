import { fromB64, toB64 } from "../crypto/bytes";
import { IdentityMismatchError, type Account } from "./account";

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

// Security review 2026-10, branch A11 (q08): the userId above is the SERVER's choice (the login response), so a
// server that answered the same typed email with a new userId got a pin miss and its identity became the new pin.
// The browser now also keeps an email binding: the email the user TYPED (normalised) → the (userId, identityPub) of
// its first passing unlock, `<userId>\n<identityPub>`. A changed userId for that email is the §5 fault. A pre-A11 pin
// is bound to the saved session's email (on every read while that session exists), so existing pins carry over.
const BY_EMAIL = "andvari.selfIdentityByEmail.";
const SESSION_KEY = "andvari.session"; // ui/session.ts SESSION_STORAGE_KEY (vault/ must not import ui/)
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export const normalizeEmail = (email: string): string => email.trim().toLowerCase();

function pub32(raw: string | null | undefined): Uint8Array | null {
  if (raw == null) return null;
  try {
    const pub = fromB64(raw.trim());
    return pub.length === 32 ? pub : null;
  } catch {
    return null;
  }
}

function get(k: string): string | null {
  try {
    return typeof localStorage === "undefined" ? null : localStorage.getItem(k);
  } catch {
    return null;
  }
}

function putOnce(k: string, v: string): void {
  try {
    if (typeof localStorage === "undefined" || localStorage.getItem(k) != null) return;
    localStorage.setItem(k, v);
  } catch {
    /* storage unavailable (privacy mode): the backstop is best-effort on web */
  }
}

function decodeBinding(raw: string | null): { userId: string; pub: Uint8Array } | null {
  const parts = raw?.trim().split("\n");
  if (!parts || parts.length !== 2 || !UUID_RE.test(parts[0]!)) return null;
  const pub = pub32(parts[1]);
  return pub ? { userId: parts[0]!, pub } : null;
}

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((x, i) => x === b[i]);

/** Migration (A11): bind the saved session's pre-A11 userId-keyed pin to that session's email, once. */
export function bindLegacySelfIdentity(): void {
  let raw: unknown;
  try {
    raw = JSON.parse(get(SESSION_KEY) ?? "null");
  } catch {
    return;
  }
  if (!raw || typeof raw !== "object") return;
  const { userId, email } = raw as { userId?: unknown; email?: unknown };
  if (typeof userId !== "string" || !UUID_RE.test(userId) || typeof email !== "string" || !email.trim()) return;
  const pub = pub32(get(PREFIX + userId));
  if (pub) putOnce(BY_EMAIL + normalizeEmail(email), `${userId}\n${toB64(pub)}`);
}

/**
 * The §2.4 pin for an unlock of `userId` (server-supplied) reached by typing `email`. Throws
 * {@link IdentityMismatchError} when this browser bound `email` to another userId, or its two records disagree.
 * Without `email` (callers that never had one), the userId-keyed pin alone.
 */
export function loadSelfIdentityPub(userId: string, email?: string): Uint8Array | null {
  const legacy = pub32(get(PREFIX + userId));
  if (!email || !email.trim()) return legacy;
  bindLegacySelfIdentity();
  const b = decodeBinding(get(BY_EMAIL + normalizeEmail(email)));
  if (!b) return legacy;
  if (b.userId !== userId) throw new IdentityMismatchError();
  if (legacy && !sameBytes(legacy, b.pub)) throw new IdentityMismatchError();
  return b.pub;
}

/** Record the pin (and, with `email`, the email binding) once, from an unlock that passed; never overwritten. */
export function recordSelfIdentityPub(userId: string, account: Account, email?: string): void {
  putOnce(PREFIX + userId, toB64(account.identityPub));
  if (email && email.trim() && UUID_RE.test(userId)) putOnce(BY_EMAIL + normalizeEmail(email), `${userId}\n${toB64(account.identityPub)}`);
}
