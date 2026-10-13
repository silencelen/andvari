import { ctEquals, fromB64 } from "../crypto/bytes";
import { matchesFull, matchesShort } from "../crypto/fingerprint";
import { identityFingerprint } from "../crypto/sharedgrant";
import { enrolInPerson, type InPersonEvidence } from "../enroll/enrollcheck";
import type { EnrollPayload } from "../enroll/enrolllink";
import type { AccountStateDoc, Contact } from "./accountstate";

/**
 * Identity QR + the ONLY ways a contact gets pinned (security review 2026-10, root cause A §4.2, §7.2) —
 * twin of core `Contacts.kt`. Every function compares a HUMAN-sourced value with SHA-256 of the key the
 * server served and returns null on any mismatch; nothing pins a served key on its own. Pairwise only
 * (owner decision Q4).
 */

export const IDENTITY_QR_PREFIX = "andvari-id:1:";
const QR_RE = /^andvari-id:1:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}):([0-9a-f]{64})$/;
const HEX64_RE = /^[0-9a-f]{64}$/;

/** `andvari-id:1:<userId>:<hex64>` over the member's SEED-DERIVED identity key. */
export async function composeIdentityQr(userId: string, identityPub: Uint8Array): Promise<string> {
  return `${IDENTITY_QR_PREFIX}${userId}:${await identityFingerprint(identityPub)}`;
}

/** Strict parse: exact prefix, lowercase uuid, exactly 64 lowercase hex. Null otherwise. */
export function parseIdentityQr(payload: string): { userId: string; fingerprint: string } | null {
  const m = QR_RE.exec(payload);
  return m ? { userId: m[1]!, fingerprint: m[2]! } : null;
}

/** What the server served for a user: untrusted until a human compares it. */
export interface ServedIdentity {
  userId: string;
  identityPub: string;
}

async function servedFingerprint(served: ServedIdentity): Promise<string | null> {
  let key: Uint8Array;
  try {
    key = fromB64(served.identityPub);
  } catch {
    return null;
  }
  if (key.length !== 32) return null;
  return identityFingerprint(key);
}

/** The member TYPED the other person's 32-hex short form from THEIR screen (A2 human-only prefix rule). */
export async function pinFromTyped(typedEntry: string, served: ServedIdentity, label: string, now: number): Promise<Contact | null> {
  const fp = await servedFingerprint(served);
  if (fp === null || !matchesShort(typedEntry, fp)) return null;
  return { userId: served.userId, identityPub: served.identityPub, label, verifiedAt: now, method: "typed" };
}

/** A camera scan of the other person's identity QR, compared at FULL length. */
export async function pinFromQr(qrPayload: string, served: ServedIdentity, label: string, now: number): Promise<Contact | null> {
  const qr = parseIdentityQr(qrPayload);
  if (!qr || qr.userId !== served.userId) return null;
  const fp = await servedFingerprint(served);
  if (fp === null || !matchesFull(qr.fingerprint, fp)) return null;
  return { userId: served.userId, identityPub: served.identityPub, label, verifiedAt: now, method: "qr" };
}

/**
 * The enrolment mutual pin (root cause A §7.2): the link's `ifp`/`iu`, honoured ONLY on in-person evidence
 * re-checked HERE from the raw inputs (A5c): the human typed the link's in-person code from the admin's screen
 * AND affirmed, first person, that they are reading that screen right now (`enrolInPerson`). A navigated link
 * plus a correct code is not evidence on its own: the server that composed the link can supply both. Compared
 * at full length; null leaves the admin a pending verification, never an error.
 */
export async function pinFromEnrolLink(
  payload: EnrollPayload,
  evidence: InPersonEvidence,
  served: ServedIdentity,
  label: string,
  now: number,
): Promise<Contact | null> {
  if (!payload.ifp || !payload.iu) return null;
  if (!(await enrolInPerson(payload, evidence))) return null;
  if (!HEX64_RE.test(payload.ifp) || payload.iu !== served.userId) return null;
  const fp = await servedFingerprint(served);
  if (fp === null || !matchesFull(payload.ifp, fp)) return null;
  return { userId: served.userId, identityPub: served.identityPub, label, verifiedAt: now, method: "enrol" };
}

export type PinState = "pinned-match" | "pinned-mismatch" | "unpinned";

/** How a served key relates to this account's pins, for the sharing flow. */
export function pinState(state: AccountStateDoc | null, served: ServedIdentity): PinState {
  const c = state?.contacts.find((x) => x.userId === served.userId);
  if (!c) return "unpinned";
  try {
    return ctEquals(fromB64(c.identityPub), fromB64(served.identityPub)) ? "pinned-match" : "pinned-mismatch";
  } catch {
    return "pinned-mismatch";
  }
}
