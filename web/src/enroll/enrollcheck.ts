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
