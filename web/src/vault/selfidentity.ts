import { fromB64, toB64 } from "../crypto/bytes";
import { emailNorm } from "../crypto/trust/grammar";
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

/**
 * The email binding's key: the address in the shared §2.2 grammar (crypto/trust/grammar.ts emailNorm, the one every
 * client and the server use), or null for a string that is not an address, for which no binding is read or written.
 */
const bindingKey = (email: string): string | null => {
  const n = emailNorm(email);
  return n === null ? null : BY_EMAIL + n;
};

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

function putOnce(k: string, v: string): boolean {
  try {
    if (typeof localStorage === "undefined" || localStorage.getItem(k) != null) return false;
    localStorage.setItem(k, v);
    return true;
  } catch {
    /* storage unavailable (privacy mode): the backstop is best-effort on web */
    return false;
  }
}

/**
 * After a forgetting (decided on 2026-11-17; the notice survives a reload, a lock and a closed tab): the addresses whose
 * next account is still to be taken, and those whose new account was taken and whose one-time notice is not yet dismissed.
 * Two device-wide keys holding addresses only.
 */
const REMEMBER_NEXT_KEY = "andvari.rememberNext";
const REMEMBERED_KEY = "andvari.rememberedNew";
/** The key of the notices to show (an open tab redraws them when another tab changes it). */
export const REMEMBERED_NOTICES_KEY = REMEMBERED_KEY;

function addressList(k: string): string[] {
  try {
    const raw: unknown = JSON.parse(get(k) ?? "[]");
    return Array.isArray(raw) ? raw.filter((e): e is string => typeof e === "string") : [];
  } catch {
    return [];
  }
}

function setAddressList(k: string, list: readonly string[]): void {
  try {
    if (list.length === 0) localStorage.removeItem(k);
    else localStorage.setItem(k, JSON.stringify([...new Set(list)]));
  } catch {
    /* storage unavailable: the notice is a notice, not a record */
  }
}

/**
 * The forgetting of [email]'s earlier account is complete: the next account taken under it is said once. Where one was
 * already taken (a forgetting stopped part-way and finished after the next account's record was written), it is said now.
 */
export function rememberNextAt(email: string): void {
  const k = bindingKey(email);
  if (k !== null && decodeBinding(get(k)) !== null) setAddressList(REMEMBERED_KEY, [...addressList(REMEMBERED_KEY), k.slice(BY_EMAIL.length)]);
  else setAddressList(REMEMBER_NEXT_KEY, [...addressList(REMEMBER_NEXT_KEY), email]);
}

/** The addresses whose notice "this browser now remembers the new account" is to be shown, until dismissed. */
export function rememberedNotices(): string[] {
  return addressList(REMEMBERED_KEY);
}

/** The person dismissed [email]'s notice: it is not shown again. */
export function dismissRemembered(email: string): void {
  setAddressList(REMEMBERED_KEY, addressList(REMEMBERED_KEY).filter((e) => e !== email));
}

/** A record now ties [k]'s address to an account: where that address was forgotten, its notice is raised. */
function boundAfresh(k: string): void {
  const n = k.slice(BY_EMAIL.length);
  const next = addressList(REMEMBER_NEXT_KEY);
  if (!next.includes(n)) return;
  setAddressList(REMEMBERED_KEY, [...addressList(REMEMBERED_KEY), n]);
  setAddressList(REMEMBER_NEXT_KEY, next.filter((e) => e !== n));
}

/** The address's notices go with the account under it (its deletion here, or a forgetting of it). */
function dropNotices(n: string): void {
  setAddressList(REMEMBER_NEXT_KEY, addressList(REMEMBER_NEXT_KEY).filter((e) => e !== n));
  setAddressList(REMEMBERED_KEY, addressList(REMEMBERED_KEY).filter((e) => e !== n));
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
  const k = bindingKey(email);
  if (pub && k && putOnce(k, `${userId}\n${toB64(pub)}`)) boundAfresh(k);
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
  const k = bindingKey(email);
  const b = k === null ? null : decodeBinding(get(k));
  if (!b) return legacy;
  if (b.userId !== userId) throw new IdentityMismatchError();
  if (legacy && !sameBytes(legacy, b.pub)) throw new IdentityMismatchError();
  return b.pub;
}

/** The account this browser's record binds [email] to, whatever else its records say; null where none does (or not an address). */
export function boundAccountAt(email: string): string | null {
  bindLegacySelfIdentity();
  const k = bindingKey(email);
  return k === null ? null : (decodeBinding(get(k))?.userId ?? null);
}

/**
 * The earlier account behind a refusal that is this browser's own record of [email] (decided on 2026-11-17, "Forget the
 * earlier account on this device"): the address's record names an account, and that account's id-keyed pin, where one
 * is kept, agrees with it. Null where no record names the address, and where its two records disagree: a record that
 * disagrees with itself is not this case, and nothing is offered on it.
 */
export function earlierAccountAt(email: string): string | null {
  bindLegacySelfIdentity();
  const k = bindingKey(email);
  const b = k === null ? null : decodeBinding(get(k));
  if (!b) return null;
  const legacy = pub32(get(PREFIX + b.userId));
  return legacy && !sameBytes(legacy, b.pub) ? null : b.userId;
}

/**
 * A forgetting of an earlier account that was begun (decided on 2026-11-17): written before anything of it is removed and
 * taken away only when the removal is complete, so that a forgetting stopped part-way (a tab closed, a store that threw)
 * is finished at the next start or the next click, and never answered as "nothing to forget". One key for the browser,
 * not scoped to an account; it holds the address and the earlier account's id, nothing else.
 */
export const FORGETTING_KEY = "andvari.forgetting";

export interface ForgettingMark {
  readonly email: string;
  readonly userId: string;
}

/** The forgettings begun and not finished. A mark that cannot be read is none: nothing is removed on its word. */
export function forgettingMarks(): ForgettingMark[] {
  try {
    const raw: unknown = JSON.parse(get(FORGETTING_KEY) ?? "[]");
    if (!Array.isArray(raw)) return [];
    return raw.filter((m): m is ForgettingMark => !!m && typeof m === "object" && typeof (m as ForgettingMark).email === "string" && UUID_RE.test(String((m as ForgettingMark).userId)));
  } catch {
    return [];
  }
}

/** Writes the mark for [email]'s earlier account [userId]. Throws where it cannot be written: then nothing may be removed. */
export function markForgetting(email: string, userId: string): void {
  const marks = forgettingMarks().filter((m) => !(m.email === email && m.userId === userId));
  localStorage.setItem(FORGETTING_KEY, JSON.stringify([...marks, { email, userId }]));
}

/** Takes the mark away, once the removal it stands for is complete. */
export function unmarkForgetting(email: string, userId: string): void {
  const marks = forgettingMarks().filter((m) => !(m.email === email && m.userId === userId));
  if (marks.length === 0) localStorage.removeItem(FORGETTING_KEY);
  else localStorage.setItem(FORGETTING_KEY, JSON.stringify(marks));
}

/** The key of [userId]'s id-keyed pin, the record of that account's identity key. */
export function selfIdentityPinKey(userId: string): string {
  return PREFIX + userId;
}

/**
 * The forgetting's first removal: the record that ties [email] to the earlier account [userId] (only where it still names
 * that account). A store that fails throws: the caller's mark stands. That account's id-keyed pin, the record of its
 * identity key, is KEPT: with it the earlier account can never come back on this browser under another key, also after a
 * forgetting (a server that showed another account under the address to obtain the forgetting, and then serves the old
 * account with a key of its own, is refused); served again with its own key, it is taken as itself. It is public (the
 * server holds the same key) and names nothing else; it goes with the site's data, and with a deletion of that account
 * run here and confirmed by the server ({@link forgetSelfIdentity}).
 */
export function forgetEarlierRecords(userId: string, email: string): void {
  const k = bindingKey(email);
  if (k !== null && decodeBinding(localStorage.getItem(k))?.userId === userId) {
    localStorage.removeItem(k);
    dropNotices(k.slice(BY_EMAIL.length));
  }
}

function remove(k: string): void {
  try {
    if (typeof localStorage !== "undefined") localStorage.removeItem(k);
  } catch {
    /* storage unavailable */
  }
}

/**
 * Account deletion (spec 03 §13; spec 01 §5 as amended 2026-11-10): the browser that RAN a deletion the server confirmed
 * forgets its records for that account, so the address can register again here as a new account instead of tripping
 * the security fault on the first unlock. The userId-keyed pin goes; the email binding goes only when it names THIS
 * userId — a binding at the same address for another account is not this deletion's to remove. Called only from the
 * deletion's own success, which the user's typed address and master password produced on this device; every other
 * device keeps its records (spec 05 R19(c)).
 */
export function forgetSelfIdentity(userId: string, email?: string): void {
  remove(PREFIX + userId);
  if (!email || !email.trim()) return;
  const k = bindingKey(email);
  if (k !== null && decodeBinding(get(k))?.userId === userId) {
    remove(k);
    dropNotices(k.slice(BY_EMAIL.length));
  }
}

/** Record the pin (and, with `email`, the email binding) once, from an unlock that passed; never overwritten. */
export function recordSelfIdentityPub(userId: string, account: Account, email?: string): void {
  putOnce(PREFIX + userId, toB64(account.identityPub));
  const k = email ? bindingKey(email) : null;
  if (k !== null && UUID_RE.test(userId) && putOnce(k, `${userId}\n${toB64(account.identityPub)}`)) boundAfresh(k);
}
