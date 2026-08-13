import { useEffect, useState } from "react";
import { hibpBreachCount } from "../crypto/hibp";
import {
  BACKUP_FLOOR,
  BREACHED_PASSWORD_WARNING,
  STRENGTH_LABELS,
  estimateStrength,
  masterPasswordHasNonAscii,
  meetsMasterPasswordFloor,
  patternWarning,
} from "./strength";

/**
 * The advisory half of every master-password / backup-passphrase field on web: the strength
 * label, the F31 pattern explanation, and the F31 k-anonymity breach warning — as ONE component
 * the four surfaces share (enrollment, change-password, self-recovery reset, backup passphrase).
 *
 * It lives in its own module rather than in Welcome.tsx because Welcome imports Recover, so the
 * hint Recover needed could never come from Welcome — and the copy that grew there instead is
 * exactly how the two surfaces drifted apart. One component, four call sites, no cycle.
 *
 * Everything here WARNS and nothing here BLOCKS. The gates stay in the forms' own canSubmit +
 * submit guards (`meetsMasterPasswordFloor` for a master password, {@link BACKUP_FLOOR} against
 * `estimateStrength` for a backup passphrase); a breach lookup that never answers, or answers
 * "breached", changes what is SAID and nothing else.
 *
 * KNOWN GAP, stated so nobody reads more into a silent field than is there: the relay route
 * (`GET /api/v1/hibp/range/{prefix}`, App.kt) goes through `requirePrincipal`, so it answers 401
 * to a client holding no access token. Two of the four surfaces below are exactly that —
 * enrollment (no account yet) and the self-recovery reset (a single-use ticket, not a session) —
 * so on those the LIVE hint runs, 401s, fails open, and says nothing while the field is being
 * typed. Change-password and the backup passphrase are in-vault and DO warn today. The wiring is
 * the same on all four and lights up the moment the route stops requiring a session; nothing here
 * needs to change for that, and nothing here may work around it by calling upstream directly
 * (that would hand the user's IP to a third party, which is the whole reason the relay exists).
 *
 * Enrollment closes its half of that gap on the OTHER side of the 401 instead: Welcome's enroll
 * re-runs the check through {@link breachWarningFor} once `register` has handed the client a
 * session, and shows the verdict as a dismissible advisory on the post-enroll card. Same fix, and
 * the same shape, as the natives' `checkEnrolledPasswordForBreach` (AndvariViewModel /
 * DesktopState). The self-recovery reset has no equivalent moment — it hands off to a sign-in —
 * so it stays on the live hint alone.
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
  /** BREACHED_PASSWORD_WARNING once the k-anonymity check has actually said so, else null. */
  breach: string | null;
  /** spec 01 §1 SHOULD-warn: may not round-trip across keyboards/IMEs on another device. */
  nonAscii: boolean;
}

/** The whole hint decision, pure and exported so it is pinnable without rendering a card. */
export function passwordAdvice(password: string, breached: boolean, role: PasswordRole = "master"): PasswordAdvice {
  const score = estimateStrength(password);
  const pattern = patternWarning(password);
  const breach = breached ? BREACHED_PASSWORD_WARNING : null;
  const meetsFloor = role === "master" ? meetsMasterPasswordFloor(password) : score >= BACKUP_FLOOR;
  return {
    score,
    label: STRENGTH_LABELS[score] ?? STRENGTH_LABELS[0],
    meetsFloor,
    affirmed: meetsFloor && !pattern && !breach,
    pattern,
    breach,
    nonAscii: masterPasswordHasNonAscii(password),
  };
}

// ---- the k-anonymity breach check (audit F31) ----

/**
 * How long a field must sit still before its prefix goes to the relay. Long enough that typing a
 * passphrase is one lookup rather than forty, short enough that the answer lands while the user
 * is still looking at the field.
 */
export const BREACH_CHECK_DEBOUNCE_MS = 700;

/** Just the relay call {@link createBreachWatch} needs — `ApiClient.hibpRange`, narrowed so the
 *  tests can hand it a stub and so nothing here can reach for the rest of the client. */
export interface BreachRangeSource {
  hibpRange(prefix: string): Promise<string>;
}

/**
 * The debounced, out-of-order-safe core of the breach check. Imperative and injectable (the
 * useAutoLock/createAutoLock idiom) so the properties that matter are testable without a
 * renderer: exactly one lookup per settled value, no verdict outliving the password it was
 * asked about, and nothing at all for an empty field.
 *
 * Privacy: this never touches the password beyond handing it to {@link hibpBreachCount}, whose
 * contract is that ONLY the 5-character hash prefix reaches [source]. Fail-open lives there too —
 * an unreachable relay resolves null, which reads here as "not breached", i.e. silence.
 */
export function createBreachWatch(
  source: BreachRangeSource,
  onBreached: (breached: boolean) => void,
  debounceMs: number = BREACH_CHECK_DEBOUNCE_MS,
): { check: (password: string) => void; stop: () => void } {
  let timer: ReturnType<typeof setTimeout> | null = null;
  let generation = 0;
  let stopped = false;

  const stop = (): void => {
    stopped = true;
    generation++; // an answer already in flight belongs to nobody now
    if (timer !== null) clearTimeout(timer);
    timer = null;
  };

  const check = (password: string): void => {
    if (stopped) return;
    if (timer !== null) clearTimeout(timer);
    // Every edit invalidates the answer in flight AND retracts the verdict on screen: a warning
    // that says "this password is breached" must never be describing the previous password.
    const gen = ++generation;
    onBreached(false);
    if (!password) return;
    timer = setTimeout(() => {
      timer = null;
      // hibpBreachCount is TOTAL (it swallows transport and crypto failures into null), so there
      // is no rejection path to handle here — that is the fail-open contract, not an oversight.
      void hibpBreachCount(password, (prefix) => source.hibpRange(prefix)).then((count) => {
        if (stopped || gen !== generation) return; // the field moved on; this answer is stale
        onBreached(count !== null && count > 0);
      });
    }, debounceMs);
  };

  return { check, stop };
}

/**
 * One-shot twin of {@link createBreachWatch}, for a password that is already CHOSEN rather than
 * being typed: returns {@link BREACHED_PASSWORD_WARNING}, or null. Byte-for-byte the natives'
 * `breachWarningVia` (AndvariViewModel / DesktopState), down to what null means — it deliberately
 * covers BOTH "not in any breach" and "couldn't check", because {@link hibpBreachCount} fails open
 * and so must every caller. A relay that is down may never become a thing the user has to deal
 * with on a surface that is otherwise finished.
 *
 * No debounce and no generation counter, unlike the watch: there is no field left to move on, so
 * there is no stale answer to guard against and no reason to wait. Everything else is the same
 * seam — ONLY the 5-character hash prefix reaches [source], and the password is neither logged nor
 * persisted. TOTAL, like `hibpBreachCount`: callers get null instead of a rejection, so a detached
 * `void breachWarningFor(...)` cannot become an unhandled rejection.
 */
export async function breachWarningFor(source: BreachRangeSource, password: string): Promise<string | null> {
  const count = await hibpBreachCount(password, (prefix) => source.hibpRange(prefix));
  return count !== null && count > 0 ? BREACHED_PASSWORD_WARNING : null;
}

/**
 * React binding for {@link createBreachWatch}. `false` until the relay actually answers
 * "breached", so a slow or unreachable server simply means the warning never appears — the
 * enrollment/change/reset/export it sits on stays completable throughout.
 *
 * `source` must be render-stable (an ApiClient instance, not a fresh closure), or the effect
 * re-arms on every keystroke; every call site passes the client it already holds.
 */
export function useBreachedPassword(password: string, source: BreachRangeSource | null): boolean {
  const [breached, setBreached] = useState(false);
  useEffect(() => {
    setBreached(false); // a changed password is UNKNOWN until this watch answers for it
    if (!source) return;
    const watch = createBreachWatch(source, setBreached);
    watch.check(password);
    return () => watch.stop();
  }, [password, source]);
  return breached;
}

// ---- rendering ----

/** The caution lines, in severity order. Gold rather than red: both are advisory, and painting
 *  them like the blocking "needs at least “good”" refusal would misstate what happens next. */
export function PasswordCautions({ advice }: { advice: PasswordAdvice }) {
  return (
    <>
      {advice.breach && (
        <span className="muted" style={{ display: "block", color: "var(--gold-text)" }}>{advice.breach}</span>
      )}
      {advice.pattern && (
        <span className="muted" style={{ display: "block", color: "var(--gold-text)" }}>{advice.pattern}</span>
      )}
    </>
  );
}

/**
 * F60 master-password hint — the live strength label, whether it clears the floor, the F31
 * pattern/breach cautions, and the non-ASCII caution (spec 01 §1). Shared by enrollment
 * (Welcome), change-password (Settings) and the self-recovery reset (Recover). Purely advisory:
 * the actual gate lives in each form's canSubmit + submit guards.
 *
 * `client` is optional only so a caller with no client in hand still gets the strength half; give
 * it one and the field also gets the breach check.
 */
export function MasterPasswordHint({ password, client }: { password: string; client?: BreachRangeSource | null }) {
  // Hooks before the empty-field early return — the field goes empty and non-empty as the user
  // types, and a conditionally-called hook would break on the first backspace to nothing.
  const breached = useBreachedPassword(password, client ?? null);
  if (!password) return null;
  const advice = passwordAdvice(password, breached, "master");
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
