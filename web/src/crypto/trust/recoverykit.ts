import { ctEquals, toB64, utf8 } from "../bytes";
import { randomBytes } from "../provider";
import { CryptoError } from "../sodium";
import { type Checked, ok, refused } from "./checked";
import { emailNorm, fromB64Canonical, fromB64Exact, isHex64, isOrigin, stripAsciiSpace } from "./grammar";

/**
 * The recovery kit's encodings (design 2026-11-15 §10): how the 32-byte `recoverySecret` is shown,
 * typed back and confirmed, and the kit QR. The secret and its key split are unchanged (spec 01 §2.1):
 * it is never typed into a KDF, only decoded back to the same bytes. Twin of core `RecoveryKit`, graded
 * off the same `recoverykit.json`.
 *
 * Where a kit is ACCEPTED (only on Sign in → Forgot your master password? → Scan your recovery kit,
 * FS-B1) is the flow's rule, not this file's.
 */

/** §2.4 "Small cases": a recovery-kit text that does not parse. */
export type KitVerdict = "bad_kit";

export const SECRET_BYTES = 32;
/** §10: 43 base64url characters in 11 groups, ten of 4 and one of 3. */
export const KIT_GROUPS = 11;
/** §10: the confirmation asks for three distinct groups. */
export const CONFIRM_GROUPS = 3;
/** The kit QR's fixed prefix. Deliberately not a URL, so a camera app offers nothing for it. */
export const KIT_QR_PREFIX = "andvari-kit:2:";
/** §10: at most 1,024 characters after the white space is stripped (links have 512). */
export const MAX_KIT_QR_LENGTH = 1024;

/** A parsed kit QR. `secret` is the caller's to wipe. */
export interface Kit {
  readonly origin: string;
  readonly card0Hash: string;
  readonly emailNorm: string;
  readonly secret: Uint8Array;
}

/**
 * The 11 display groups of a 32-byte secret: its 43 base64url characters, ten groups of 4 and a last one of 3.
 * The secret becomes TEXT here because a person reads it: a string cannot be wiped, so these groups live until
 * the engine collects them, and the same holds for {@link composeKitQr} and for whatever a person types back.
 */
export function kitGroups(recoverySecret: Uint8Array): string[] {
  if (recoverySecret.length !== SECRET_BYTES) throw new CryptoError("recovery kit: the secret must be 32 bytes");
  const text = toB64(recoverySecret);
  const groups: string[] = [];
  for (let i = 0; i < text.length; i += 4) groups.push(text.slice(i, i + 4));
  return groups;
}

/** The display form: the 11 {@link kitGroups} separated by single spaces. */
export const kitDisplayForm = (recoverySecret: Uint8Array): string => kitGroups(recoverySecret).join(" ");

/** §10: a typed kit secret ignores U+0020, CR and LF, and nothing else (not a tab, not a dash: base64url uses `-`, FI-B10). */
const stripKitSpace = (text: string): string => text.replace(/[ \r\n]/g, "");

/**
 * A secret typed by hand, or `bad_kit`. Total. What is left after {@link stripKitSpace} must be the
 * canonical unpadded base64url of exactly 32 bytes (43 characters).
 */
export function parseTypedSecret(typed: string): Checked<Uint8Array, KitVerdict> {
  const text = stripKitSpace(typed);
  if (text.length !== 43) return refused("bad_kit");
  const secret = fromB64Exact(text, SECRET_BYTES);
  return secret === null ? refused("bad_kit") : ok(secret);
}

/** A valid challenge: exactly three DISTINCT group numbers in 1..11. */
export function isValidGroupChoice(groupNumbers: readonly number[]): boolean {
  if (groupNumbers.length !== CONFIRM_GROUPS) return false;
  if (new Set(groupNumbers).size !== CONFIRM_GROUPS) return false;
  return groupNumbers.every((n) => Number.isInteger(n) && n >= 1 && n <= KIT_GROUPS);
}

/**
 * Three distinct group numbers, 1..11, chosen uniformly by the CSPRNG and returned in ascending order
 * ("Type groups 2, 7 and 10"). Rejection sampling keeps every group equally likely.
 */
export function confirmGroups(): number[] {
  const picked = new Set<number>();
  while (picked.size < CONFIRM_GROUPS) {
    for (const b of randomBytes(16)) {
      if (b >= 253) continue; // 253 = 11 * 23: bytes at or above it would favour the low groups
      picked.add((b % KIT_GROUPS) + 1);
      if (picked.size === CONFIRM_GROUPS) break;
    }
  }
  return [...picked].sort((a, b) => a - b);
}

/**
 * The confirmation (§10): `typed[i]` must be group `groupNumbers[i]` of the secret, compared exactly
 * and case-sensitively, in the order asked. Space, CR and LF around a typed group are ignored, as in a
 * typed secret (core does the same). False for any other shape: a wrong count, an invalid choice.
 */
export function confirmMatches(recoverySecret: Uint8Array, groupNumbers: readonly number[], typed: readonly string[]): boolean {
  if (!isValidGroupChoice(groupNumbers) || typed.length !== CONFIRM_GROUPS) return false;
  const all = kitGroups(recoverySecret);
  let matches = true;
  groupNumbers.forEach((n, i) => {
    if (!ctEquals(utf8(stripKitSpace(typed[i]!)), utf8(all[n - 1]!))) matches = false;
  });
  return matches;
}

/** Decoded bytes as text when every byte is printable ASCII (0x20..0x7E), checked BEFORE any decoding; else null. */
function asciiText(bytes: Uint8Array | null): string | null {
  if (bytes === null) return null;
  let text = "";
  for (const b of bytes) {
    if (b < 0x20 || b > 0x7e) return null;
    text += String.fromCharCode(b);
  }
  return text;
}

/**
 * Total, canonical parse of a kit QR text (§10, "exactly as for links", §6.1), or `bad_kit`:
 * ASCII white space (space, tab, CR, LF) is removed first; at most 1,024 characters remain; the exact
 * prefix `andvari-kit:2:`; exactly four `:`-separated fields after it; `O` the canonical base64url of
 * an `origin` (§2.2); `C` 64 lowercase hex; `E` the canonical base64url of an address that is its own
 * `emailNorm`; `S` the canonical base64url of 32 bytes.
 */
export function parseKitQr(payload: string): Checked<Kit, KitVerdict> {
  const text = stripAsciiSpace(payload);
  if (text.length > MAX_KIT_QR_LENGTH || !text.startsWith(KIT_QR_PREFIX)) return refused("bad_kit");
  const parts = text.slice(KIT_QR_PREFIX.length).split(":");
  if (parts.length !== 4) return refused("bad_kit");
  const [o, c, e, s] = parts as [string, string, string, string];
  const origin = asciiText(fromB64Canonical(o));
  if (origin === null || !isOrigin(origin)) return refused("bad_kit");
  if (!isHex64(c)) return refused("bad_kit");
  const email = asciiText(fromB64Canonical(e));
  if (email === null || emailNorm(email) !== email) return refused("bad_kit");
  const secret = fromB64Exact(s, SECRET_BYTES);
  if (secret === null) return refused("bad_kit");
  return ok({ origin, card0Hash: c, emailNorm: email, secret });
}

/**
 * The kit QR text (§10): `andvari-kit:2:<O>:<C>:<E>:<S>`. Throws `CryptoError` when a part is outside
 * its grammar: compose never makes a text {@link parseKitQr} would refuse.
 */
export function composeKitQr(origin: string, card0Hash: string, email: string, recoverySecret: Uint8Array): string {
  if (recoverySecret.length !== SECRET_BYTES) throw new CryptoError("recovery kit: the secret must be 32 bytes");
  const text = `${KIT_QR_PREFIX}${toB64(utf8(origin))}:${card0Hash}:${toB64(utf8(email))}:${toB64(recoverySecret)}`;
  const back = parseKitQr(text);
  if (back.ok) back.value.secret.fill(0); // the parse-back's own copy of the secret
  if (!back.ok || back.value.origin !== origin || back.value.card0Hash !== card0Hash || back.value.emailNorm !== email) throw new CryptoError("recovery kit: a part is outside its grammar");
  return text;
}
