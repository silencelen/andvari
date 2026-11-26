/**
 * Which account an address is, and each account's identity key, as this extension knows them at a server (decided on
 * 2026-11-17; the web app keeps the same two records, web/src/vault/selfidentity.ts, which the extension cannot import:
 * there is no build path from extension/ to web/src). Both are kept per server (the background's namespaced keys), in the
 * trusted store, and outlive a sign-out on purpose: they are what stops a server from handing this extension another
 * account under a known address, or the same account under another key. They go when the server itself is forgotten
 * ("Forget this server"); "Remove data for this server" keeps them, as it keeps the server's pin (isTrustRecord).
 *
 * Pure: the background reads the two records, asks [judgeServed], and writes [recordsFor] once a sign-in is installed.
 */

/** The address record's name (namespaced per server by the caller): the account id the address was last taken as. */
export const ADDRESS_RECORD_PREFIX = "selfIdentityByEmail:";
/** The key record's name: the identity public key (base64url, as served) an account id was taken under. */
export const KEY_RECORD_PREFIX = "selfIdentityPub:";

/** The address as the records key it: trimmed, lower-cased, NFC. */
export function addressNorm(email: string): string {
  return email.trim().normalize("NFC").toLowerCase();
}

export const addressRecordName = (email: string): string => ADDRESS_RECORD_PREFIX + addressNorm(email);
export const keyRecordName = (userId: string): string => KEY_RECORD_PREFIX + userId;

/** What the extension knows for one sign-in: the account its address names, and the key it holds for the SERVED account. */
export interface Known {
  readonly boundUserId: string | null;
  readonly keyOfServed: string | null;
}

export type Verdict =
  | { readonly ok: true }
  /** The same account under another identity key: the substitution the record exists for. Nothing is offered. */
  | { readonly ok: false; readonly code: "identity_mismatch" }
  /** Another account under a known address: refused with both possibilities said (remade, or the server is wrong). */
  | { readonly ok: false; readonly code: "remade_account" };

/**
 * The served account ([servedUserId], [servedPub]) against what this extension knows. The served account's own key
 * record comes first, whatever the address names (section ES's second point): an account this extension knows, served
 * under another key, is the identity fault even where the address is tied to another account. A record that does not
 * read counts as a record that differs: refused, never taken.
 */
export function judgeServed(known: Known, servedUserId: string, servedPub: string): Verdict {
  if (known.keyOfServed !== null && known.keyOfServed !== servedPub) return { ok: false, code: "identity_mismatch" };
  if (known.boundUserId !== null && known.boundUserId !== servedUserId) return { ok: false, code: "remade_account" };
  return { ok: true };
}

/** A stored value as a record: a non-empty string, or (anything else stored, null included) a value that never equals a
 *  served one. Only a name under which nothing is stored is "no record". */
export function readRecord(v: unknown): string | null {
  if (v === undefined) return null;
  return typeof v === "string" && v.length > 0 ? v : UNREADABLE;
}

/** What a record that does not read stands for: never an account id nor a base64url key, so it equals no served value. */
const UNREADABLE = "?";

/** The two records a taken sign-in writes: the address names the account, and the account's key is the served one. */
export function recordsFor(email: string, userId: string, identityPub: string): Record<string, string> {
  return { [addressRecordName(email)]: userId, [keyRecordName(userId)]: identityPub };
}
