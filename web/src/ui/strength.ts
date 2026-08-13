/**
 * Rough entropy proxy — class diversity × an EFFECTIVE length (not a substitute for a real
 * estimator). EXACT twin of core Strength.kt: same class weights, same 40/60/80/110-bit
 * thresholds, same pattern collapse, scores 0..4, pinned by spec/test-vectors/strength.json.
 *
 * Audit F31: the estimate used to be raw `length × classes`, which scores a doubled password as
 * twice the entropy — `Password1!Password1!` came out "strong" (4) and a 40-character run of one
 * letter cleared both floors. `effectiveLength` now collapses repeated blocks and ±1 character
 * sequences before the length term, so a repeat is worth the token plus one, not the whole span.
 *
 * WHAT THAT PENALTY MAY AND MAY NOT DO (owner decision, 0.21.0): it WARNS, it never refuses.
 * `meetsMasterPasswordFloor` therefore keeps scoring on `entropyProxyScore` — the pre-F31
 * arithmetic — so nothing that clears the master-password gate today can be refused tomorrow; no
 * household member can be locked out of *changing* their password by a stricter estimate. The
 * honest number surfaces as the displayed label plus `patternWarning`. The backup-passphrase
 * floor is deliberately the other way round: callers compare Strength.BACKUP_FLOOR against
 * `estimateStrength`, because a backup passphrase is chosen fresh at export time (opening an
 * existing `.andvari` never consults strength at all) — a stricter estimate can only steer that
 * one choice, never lock anyone out of a backup they already hold.
 */
export function estimateStrength(pw: string): number {
  return scoreOf(effectiveLength(pw), classCount(pw));
}

/** The pre-F31 proxy: class diversity × RAW length. Kept as the master-password gate so the
 *  pattern penalty can only warn (see the module doc) — not for display. */
export function entropyProxyScore(pw: string): number {
  return scoreOf(pw.length, classCount(pw));
}

export const STRENGTH_LABELS = ["very weak", "weak", "fair", "good", "strong"] as const;

/**
 * F60 (spec 05 T8 / spec 01 §1): the master-password floor, enforced identically at
 * enrollment and every change (Welcome + Settings, incl. the forced-change path). The old
 * length≥8 gate let a weak all-lowercase password wrap the whole vault while backup exports
 * already demanded score≥3 — this makes the master password itself meet that bar BEFORE real
 * secrets migrate. A "good" score (≥3, ≥80 bits) is the floor; the label hint drives the UI.
 * Non-ASCII is a SHOULD-warn only (§1): some platforms normalize/enter it inconsistently,
 * risking a password that won't round-trip — warn, never block.
 */
export const MASTER_PW_MIN_SCORE = 3;

/** spec 07 §2.3: backup passphrases must score at least this — compared against
 *  `estimateStrength` (the pattern-AWARE side), for the reason the module doc gives. Twin of
 *  core `Strength.BACKUP_FLOOR`; ExportPanel used to spell the 3 inline, which is how the two
 *  floors came to look interchangeable when they deliberately are not. */
export const BACKUP_FLOOR = 3;

/** F31 advisory (never blocks): the password is mostly a repeated block or a run, so it is
 *  worth less than its length. Byte-twin of core Strength.PATTERN_WARNING. */
export const PATTERN_WARNING =
  "This repeats a short pattern, so it is weaker than its length suggests — a few unrelated words are stronger than one block twice.";

/** F31 advisory (never blocks): this exact password is in a public breach corpus. Says what
 *  left the device, because on a zero-knowledge product that is the first thing a careful
 *  reader asks. Byte-twin of core Strength.BREACHED_PASSWORD_WARNING. */
export const BREACHED_PASSWORD_WARNING =
  "This password shows up in public breach lists — pick a different one. andvari checked without sending it anywhere: only the first five characters of its hash left this device.";

/** F31: the master-password gate is the PRE-pattern proxy on purpose (module doc). */
export function meetsMasterPasswordFloor(pw: string): boolean {
  return entropyProxyScore(pw) >= MASTER_PW_MIN_SCORE;
}

/** True when the repeat/sequence collapse actually bit — this password is shorter than it
 *  looks. Advisory input for the UI; never a gate. */
export function hasPatternWeakness(pw: string): boolean {
  return pw.length > 0 && effectiveLength(pw) < pw.length;
}

/** PATTERN_WARNING when the collapse cost this password a score, else null. Only fires when
 *  the pattern is what makes it weak — a long, strong passphrase that happens to contain
 *  "aaaa" keeps its score and stays quiet. */
export function patternWarning(pw: string): string | null {
  return estimateStrength(pw) < entropyProxyScore(pw) ? PATTERN_WARNING : null;
}

/** True if the password contains any character outside printable 7-bit ASCII (§1 warn). */
export function masterPasswordHasNonAscii(pw: string): boolean {
  // eslint-disable-next-line no-control-regex
  return /[^\x20-\x7e]/.test(pw);
}

// ---- internals (mirrored verbatim in core Strength.kt) ----

/** Longest repeated block treated as one token — long enough for a repeated word
 *  ("passwordpassword"), short enough that two different long phrases are never fused. */
const MAX_PERIOD = 12;

/** A repeat must cover at least this many characters to be charged as one. Below it the
 *  "pattern" is noise a random generator produces routinely (an incidental "aa", "abab"). */
const MIN_PATTERN_SPAN = 4;

/** Same idea for ±1 runs: "abc" is a coincidence, "abcd" is a sequence. */
const MIN_SEQUENCE_RUN = 4;

function classCount(pw: string): number {
  let classes = 0;
  if (/[a-z]/.test(pw)) classes++;
  if (/[A-Z]/.test(pw)) classes++;
  if (/[0-9]/.test(pw)) classes++;
  if (/[^a-zA-Z0-9]/.test(pw)) classes++;
  return classes;
}

function scoreOf(length: number, classes: number): number {
  const bits = length * (classes <= 1 ? 2 : classes === 2 ? 3.5 : classes === 3 ? 5 : 6);
  if (bits < 40) return 0;
  if (bits < 60) return 1;
  if (bits < 80) return 2;
  if (bits < 110) return 3;
  return 4;
}

/**
 * How many characters this password is really worth. Walks left to right, and at each position
 * charges either:
 *  - a block of `period` characters repeated back to back (period 1 = a run of one character):
 *    `period + 1`, no matter how many times it repeats — "aA1!" five times is a 4-character
 *    choice plus the decision to repeat it, not 20 characters of entropy;
 *  - an ascending/descending run of adjacent code units ("abcdef", "9876"): 2, because the run
 *    is fixed by its first character and direction;
 *  - otherwise the character itself: 1.
 * The smallest qualifying period wins, so "abababab" collapses as "ab", not "abab".
 */
function effectiveLength(pw: string): number {
  const n = pw.length;
  let eff = 0;
  let i = 0;
  while (i < n) {
    let consumed = 0;
    let cost = 0;
    let period = 1;
    while (period <= MAX_PERIOD && i + 2 * period <= n) {
      let reps = 1;
      while (i + (reps + 1) * period <= n && pw.slice(i, i + period) === pw.slice(i + reps * period, i + (reps + 1) * period)) {
        reps++;
      }
      if (reps >= 2 && reps * period >= MIN_PATTERN_SPAN) {
        consumed = reps * period;
        cost = period + 1;
        break;
      }
      period++;
    }
    if (consumed === 0) {
      const run = sequenceRun(pw, i);
      if (run >= MIN_SEQUENCE_RUN) {
        consumed = run;
        cost = 2;
      }
    }
    if (consumed === 0) {
      consumed = 1;
      cost = 1;
    }
    eff += cost;
    i += consumed;
  }
  return eff;
}

/** Length of the ±1 code-unit run starting at `i` (1 when there is no run). */
function sequenceRun(pw: string, i: number): number {
  if (i + 1 >= pw.length) return 1;
  const step = pw.charCodeAt(i + 1) - pw.charCodeAt(i);
  if (step !== 1 && step !== -1) return 1;
  let j = i + 1;
  while (j + 1 < pw.length && pw.charCodeAt(j + 1) - pw.charCodeAt(j) === step) j++;
  return j - i + 1;
}
