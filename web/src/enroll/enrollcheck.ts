import { toHexLower, utf8 } from "../crypto/bytes";
import { matchesShort, shortForm } from "../crypto/fingerprint";
import { sha256 } from "../crypto/provider";
import type { EnrollPayload } from "./enrolllink";

/**
 * The IN-PERSON CODE for an enroll link's security fields (security review 2026-10, root cause A, A5) —
 * twin of core `EnrollLink.checkCode`. The first 32 lowercase hex of
 * `SHA-256(UTF-8("andvari/v1|enroll-check|" + (rfp ?? "-") + "|" + (ifp ?? "-") + "|" + (iu ?? "-")))`.
 *
 * The admin's screen shows it under the QR; the invitee TYPES it. That typed match is the in-person
 * provenance a navigated link otherwise lacks: the server can compose an /enroll link too (it emails
 * invites), with its own `rfp`/`ifp`, and the person holding such a link has no admin screen to read the
 * code from. One 128-bit code authenticates `rfp`, `ifp` and `iu` together. Null when the link carries
 * none of them. Lives outside enrolllink.ts because that module must stay sodium/WebCrypto-free (it runs
 * at module load, before initSodium).
 */
export async function enrollCheckCode(payload: EnrollPayload): Promise<string | null> {
  if (!payload.rfp && !payload.ifp) return null;
  const text = `andvari/v1|enroll-check|${payload.rfp ?? "-"}|${payload.ifp ?? "-"}|${payload.iu ?? "-"}`;
  return shortForm(toHexLower(await sha256(utf8(text))));
}

/** True iff the human-typed `entry` is the link's in-person code (32 hex, separators tolerated). */
export async function enrollCheckCodeMatches(payload: EnrollPayload, entry: string): Promise<boolean> {
  const code = await enrollCheckCode(payload);
  return code !== null && matchesShort(entry, code);
}

/**
 * The in-person evidence for a NAVIGATED enrol link (security review 2026-10, root cause A, A5c — API review
 * #4). Web has one intake, navigation: a QR scanned with the phone's camera app is a navigation too, and the
 * page cannot tell it from an emailed link. The code above is an unkeyed hash of the link, so the server that
 * composed the link can email "the code" beside it; and nothing the invitee's client can verify is beyond the
 * server's reach (its only inputs are the link and what the server serves), so no keyed variant would help.
 * The anchor is therefore the HUMAN, twice: the code they typed from the admin's screen, and their
 * first-person statement, made under {@link IN_PERSON_CODE_WARNING}, that they are reading that screen right
 * now. Both are re-checked from the raw inputs by whoever pins (`pinFromEnrolLink`), never taken as a boolean.
 */
export interface InPersonEvidence {
  /** The in-person code as the human typed it (32 hex, separators tolerated). */
  typedCode: string;
  /** The human's first-person affirmation that they are reading the admin's screen, in person, right now. */
  inPersonAffirmed: boolean;
}

/** The stop warning shown wherever the in-person code is typed, in every posture. */
export const IN_PERSON_CODE_WARNING =
  "Only type a code you are reading from your admin's screen right now. Never use a code from an email or message.";

/**
 * The in-person verdict: true iff the human affirmed in-person reading AND the typed code is the link's.
 * A navigated link plus a correct code, on its own, is pending verification (the admin is verified later
 * through "Verify a household member"), never a pin.
 */
export async function enrolInPerson(payload: EnrollPayload, evidence: InPersonEvidence): Promise<boolean> {
  if (!evidence.inPersonAffirmed) return false;
  return enrollCheckCodeMatches(payload, evidence.typedCode);
}
