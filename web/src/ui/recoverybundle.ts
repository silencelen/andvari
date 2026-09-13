/**
 * F59 recovery step 3 (spec 04 §4), the admin-panel half — H24 (audit 2026-09-13). The admin
 * runs `recovery-cli recover` on an OFFLINE machine and carries back a bundle: the server's
 * exact `RecoveryUpload` wire type, serialized by the CLI and also written to
 * `andvari-recovery-<userId>.json`. This module is the pre-flight check the panel runs before
 * posting it, and it decides three things and nothing more:
 *
 *  - the text is a bundle at all (parseable JSON object carrying every RecoveryUpload field,
 *    with `tempKdfParams` an OBJECT — the exact PRC-1 shape the server's non-lenient decoder
 *    needs), so the admin gets a plain sentence instead of the server's `bad_request`;
 *  - it names THIS member (a bundle pasted onto the wrong row would silently reset a different
 *    account's password — the server accepts any existing userId, so the row is the only guard);
 *  - the text is handed back VERBATIM (whitespace-trimmed) — never re-serialized, which is the
 *    PRC-1 lesson: `JSON.stringify(JSON.parse(text))` is byte-stable for this payload today, but
 *    the whole point of posting the CLI's bytes is that the panel cannot drift from the wire
 *    contract when the CLI's type grows a field.
 *
 * Pure so recoverybundle.test.ts pins the verdicts; the panel renders and posts, nothing more.
 */
export type RecoveryBundleCheck = { ok: true; text: string } | { ok: false; reason: string };

export const BUNDLE_EMPTY = "Paste the bundle recovery-cli printed, or pick the andvari-recovery-….json file it wrote.";
export const BUNDLE_NOT_A_BUNDLE = "That isn't a recovery bundle this server accepts — upload the file recovery-cli wrote, unedited.";

const REQUIRED_STRING_FIELDS = ["userId", "tempAuthKey", "tempWrappedUvk", "tempKdfSalt"] as const;

export function checkRecoveryBundle(text: string, expectedUserId: string): RecoveryBundleCheck {
  const trimmed = text.trim();
  if (!trimmed) return { ok: false, reason: BUNDLE_EMPTY };
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return { ok: false, reason: BUNDLE_NOT_A_BUNDLE };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return { ok: false, reason: BUNDLE_NOT_A_BUNDLE };
  const b = parsed as Record<string, unknown>;
  for (const f of REQUIRED_STRING_FIELDS) {
    if (typeof b[f] !== "string" || !(b[f] as string)) return { ok: false, reason: BUNDLE_NOT_A_BUNDLE };
  }
  // PRC-1: the CLI once emitted tempKdfParams as a STRING and the server 400'd the final step of
  // the ceremony. A hand-edited or old-tool bundle with that shape is refused here with a sentence
  // that names the file to use, instead of surfacing as an opaque bad_request.
  const kdf = b["tempKdfParams"];
  if (typeof kdf !== "object" || kdf === null || Array.isArray(kdf)) return { ok: false, reason: BUNDLE_NOT_A_BUNDLE };
  if (b["userId"] !== expectedUserId) {
    return {
      ok: false,
      reason: `This bundle is for a different account (its user id starts ${String(b["userId"]).slice(0, 8)}…) — apply it on that member's row.`,
    };
  }
  return { ok: true, text: trimmed };
}
