import {
  BACKUP_FLOOR,
  STRENGTH_LABELS,
  estimateStrength,
  masterPasswordHasNonAscii,
  meetsMasterPasswordFloor,
  patternWarning,
} from "./strength";

/**
 * The advisory half of every master-password / backup-passphrase field on web: the strength
 * label and the F31 pattern explanation, as ONE component the four surfaces share (enrollment,
 * change-password, self-recovery reset, backup passphrase).
 *
 * It lives in its own module rather than in Welcome.tsx because Welcome imports Recover, so the
 * hint Recover needed could never come from Welcome — and the copy that grew there instead is
 * exactly how the two surfaces drifted apart. One component, four call sites, no cycle.
 *
 * Everything here WARNS and nothing here BLOCKS. The gates stay in the forms' own canSubmit +
 * submit guards (`meetsMasterPasswordFloor` for a master password, {@link BACKUP_FLOOR} against
 * `estimateStrength` for a backup passphrase).
 *
 * NO BREACH CHECK, on purpose (security review 2026-10, root cause C). These fields used to send
 * the SHA-1 prefix of what was typed to the relay (`GET /api/v1/hibp/range/{prefix}`) on every
 * 700 ms pause, and once more after enrollment. That relay is the vault server, which also holds
 * the Argon2id verifier, kdfSalt and wrappedUvk; 20 bits of SHA-1 let it discard ~2^20 − 1 of
 * every 2^20 offline guesses before paying for Argon2id, and the typed partials leaked a
 * passphrase word by word. The backup passphrase is in the same class, since the export copy
 * suggests the master password for it. Nothing derived from either secret may reach the server
 * (spec 03 §8); item passwords keep their on-demand check (Vault's editor, Health).
 */

/**
 * Which floor a field is held to. They differ on purpose (strength.ts module doc): the master
 * password is gated on the PRE-pattern proxy so the F31 penalty can never lock a member out of
 * changing their own password, while a backup passphrase — always chosen fresh at export time —
 * is gated on the pattern-aware estimate.
 */
export type PasswordRole = "master" | "backup";

export interface PasswordAdvice {
  score: number;
  label: string;
  /** Clears the floor for its role — the same predicate the form's submit guard uses. */
  meetsFloor: boolean;
  /**
   * Render the affirmative treatment (the "✓" and the --ok colour)?
   *
   * Audit F31 follow-up: this is NOT `meetsFloor`. The gate and the displayed label became
   * different functions when the pattern collapse landed, so `Password1!Password1!` cleared the
   * master-password floor (raw proxy 4) while displaying as "weak" (pattern-aware 2) — and the
   * hint affirmed it: "strength: weak ✓". A field that is simultaneously telling the user their
   * password is weak and ticking it off is worse than either message alone, so the affirmation
   * is withheld whenever there is a caution to read.
   */
  affirmed: boolean;
  /** PATTERN_WARNING, or null. */
  pattern: string | null;
  /** spec 01 §1 SHOULD-warn: may not round-trip across keyboards/IMEs on another device. */
  nonAscii: boolean;
}

/** The whole hint decision, pure and exported so it is pinnable without rendering a card. */
export function passwordAdvice(password: string, role: PasswordRole = "master"): PasswordAdvice {
  const score = estimateStrength(password);
  const pattern = patternWarning(password);
  const meetsFloor = role === "master" ? meetsMasterPasswordFloor(password) : score >= BACKUP_FLOOR;
  return {
    score,
    label: STRENGTH_LABELS[score] ?? STRENGTH_LABELS[0],
    meetsFloor,
    affirmed: meetsFloor && !pattern,
    pattern,
    nonAscii: masterPasswordHasNonAscii(password),
  };
}

// ---- rendering ----

/** The caution line. Gold rather than red: it is advisory, and painting it like the blocking
 *  "needs at least “good”" refusal would misstate what happens next. */
export function PasswordCautions({ advice }: { advice: PasswordAdvice }) {
  return (
    <>
      {advice.pattern && (
        <span className="muted" style={{ display: "block", color: "var(--gold-text)" }}>{advice.pattern}</span>
      )}
    </>
  );
}

/**
 * F60 master-password hint — the live strength label, whether it clears the floor, the F31
 * pattern caution, and the non-ASCII caution (spec 01 §1). Shared by enrollment (Welcome),
 * change-password (Settings) and the self-recovery reset (Recover). Purely advisory: the actual
 * gate lives in each form's canSubmit + submit guards. Local only — it takes no API client, so
 * nothing typed here can reach the network.
 */
export function MasterPasswordHint({ password }: { password: string }) {
  if (!password) return null;
  const advice = passwordAdvice(password, "master");
  return (
    <>
      <span
        className="muted"
        style={{ color: advice.affirmed ? "var(--ok)" : advice.meetsFloor ? "var(--gold-text)" : "var(--danger)" }}
      >
        strength: {advice.label}
        {advice.affirmed ? " ✓" : advice.meetsFloor ? "" : " — needs at least “good”"}
      </span>
      <PasswordCautions advice={advice} />
      {advice.nonAscii && (
        <span className="muted" style={{ display: "block", color: "var(--gold-text)" }}>
          contains non-ASCII characters — fine here, but they can be hard to type on some devices; make sure you can reproduce it
        </span>
      )}
    </>
  );
}
