package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Hibp
import kotlin.coroutines.cancellation.CancellationException

/**
 * Shared passphrase-strength estimator — an EXACT Kotlin mirror of web/src/ui/strength.ts
 * (same class weights, same 40/60/80/110-bit thresholds, same pattern collapse, scores 0..4)
 * so both impls enforce the same spec 07 §2.3 backup-passphrase floor (score ≥ 3).
 *
 * Rough entropy proxy — character-class diversity times an EFFECTIVE length (not a substitute
 * for a real estimator). Length counts UTF-16 units, matching JS `String.length`.
 *
 * Audit F31: the estimate used to be raw `length × classes`, which scores a doubled password
 * as twice the entropy — `Password1!Password1!` came out "strong" (4) and a 40-character run
 * of one letter cleared both floors. [effectiveLength] now collapses repeated blocks and
 * ±1 character sequences before the length term, so a repeat is worth the token plus one, not
 * the whole span.
 *
 * WHAT THAT PENALTY MAY AND MAY NOT DO (owner decision, 0.21.0): it WARNS, it never refuses.
 * [meetsMasterPasswordFloor] therefore keeps scoring on [entropyProxyScore] — the pre-F31
 * arithmetic — so nothing that clears the master-password gate today can be refused tomorrow;
 * no household member can be locked out of *changing* their password by a stricter estimate.
 * The honest number surfaces as the displayed label plus [patternWarning].
 * [BACKUP_FLOOR] is deliberately the other way round: callers compare it against
 * [estimateStrength], because a backup passphrase is chosen fresh at export time (opening an
 * existing `.andvari` never consults strength at all, see Backup.open), so a stricter estimate
 * can only steer that one choice — it can never lock anyone out of a backup they already hold.
 */
object Strength {
    /** spec 07 §2.3: backup passphrases must score at least this (compared against
     *  [estimateStrength] — see the class KDoc for why that side is allowed to tighten). */
    const val BACKUP_FLOOR = 3

    /** F60: the master password wraps the whole vault — same floor web enforces
     *  (web/src/ui/strength.ts MASTER_PW_MIN_SCORE). */
    const val MASTER_PW_MIN_SCORE = 3

    /** F31 advisory (never blocks): shown when [estimateStrength] falls below the raw
     *  length × class proxy, i.e. the password is mostly a repeated block or a run. */
    const val PATTERN_WARNING =
        "This repeats a short pattern, so it is weaker than its length suggests — a few unrelated words are stronger than one block twice."

    /** F31 advisory (never blocks): shown when the k-anonymity check finds this exact
     *  password in a public breach corpus. Says what left the device, because on a
     *  zero-knowledge product that is the first thing a careful reader asks. */
    const val BREACHED_PASSWORD_WARNING =
        "This password shows up in public breach lists — pick a different one. andvari checked without sending it anywhere: only the first five characters of its hash left this device."

    /** F31: the master-password gate is the PRE-pattern proxy on purpose (class KDoc). */
    fun meetsMasterPasswordFloor(pw: String): Boolean = entropyProxyScore(pw) >= MASTER_PW_MIN_SCORE

    /** Advisory (never blocks): non-ASCII in a master password may not round-trip across
     *  IMEs/keyboards on other devices. Exact mirror of web strength.ts ([^\x20-\x7e]). */
    fun masterPasswordHasNonAscii(pw: String): Boolean = pw.any { it.code < 0x20 || it.code > 0x7e }

    /** Score → label, index-aligned with web's STRENGTH_LABELS. */
    val LABELS: List<String> = listOf("very weak", "weak", "fair", "good", "strong")

    /** The displayed estimate: class diversity × [effectiveLength] (pattern-aware). */
    fun estimateStrength(pw: String): Int = scoreOf(effectiveLength(pw), classCount(pw))

    /** The pre-F31 proxy: class diversity × raw length. Kept as the MASTER-password gate so
     *  the pattern penalty can only warn (class KDoc) — not for display. */
    fun entropyProxyScore(pw: String): Int = scoreOf(pw.length, classCount(pw))

    /** True when the repeat/sequence collapse actually bit — i.e. this password is shorter
     *  than it looks. Advisory input for the UI; never a gate. */
    fun hasPatternWeakness(pw: String): Boolean = pw.isNotEmpty() && effectiveLength(pw) < pw.length

    /** [PATTERN_WARNING] when the collapse cost this password a score, else null. Only fires
     *  when the pattern is what makes it weak — a long, strong passphrase that happens to
     *  contain "aaaa" keeps its score and stays quiet. */
    fun patternWarning(pw: String): String? =
        if (estimateStrength(pw) < entropyProxyScore(pw)) PATTERN_WARNING else null

    /**
     * spec 03 §8 k-anonymity breach check for a MASTER password / backup passphrase (audit F31 —
     * until now only item passwords were ever checked, on web, and core's Hibp.kt had no
     * production consumer at all).
     *
     * Native call sites (each renders [BREACHED_PASSWORD_WARNING] and nothing else):
     *  - the backup-passphrase dialogs (android MainActivity.BackupPreflightDialog, desktop
     *    Ui.BackupPreflightDialog) — fired once per CANDIDATE passphrase, when both fields agree,
     *    never per keystroke: a chain of prefixes for "p", "pa", "pas"… would narrow the password
     *    far more than one prefix for the finished one does;
     *  - enrollment (AndvariViewModel.enrollOp, DesktopState.enrollOp), on the master password,
     *    immediately after `register` — the relay is session-gated ([AndvariApi.hibpRange]), so
     *    that is the FIRST moment on the native enroll path a check can be made at all. The
     *    recovery-reset leg has no session at any point (the commit revokes every session of the
     *    account), so it deliberately does NOT call this: a check that could only ever fail open
     *    is a warning the user would never see.
     *
     * Privacy contract, and the reason this is a seam rather than a call: SHA-1 is computed on
     * this device and ONLY the 5-hex-character prefix is handed to [fetchRange] — never the
     * password, never the full hash, never anything derived from it that leaves here. Nothing is
     * logged or persisted; the hash is a local and the caller gets a count, not a digest. Callers
     * MUST pass the relay (`GET /api/v1/hibp/range/{prefix}`), never a direct upstream call: the
     * relay is what keeps the client's IP out of it.
     *
     * FAILS OPEN and SILENT: any transport, decode or crypto failure returns null — "unknown",
     * never "breached", never an error the caller has to render. A password manager must not
     * refuse an enrollment because a breach API was unreachable, and this check is advisory
     * anyway ([BREACHED_PASSWORD_WARNING] warns, nothing blocks).
     *
     * @return the breach count (0 = not found), or null when the check could not be made.
     */
    suspend fun breachCount(
        crypto: CryptoProvider,
        password: String,
        fetchRange: suspend (prefix: String) -> String,
    ): Long? {
        if (password.isEmpty()) return null
        return try {
            val hash = Hibp.sha1UpperHex(crypto, password)
            Hibp.countInRange(fetchRange(Hibp.prefix(hash)), hash)
        } catch (c: CancellationException) {
            throw c
        } catch (t: Throwable) {
            null // fail open — the network, not the password, is what failed
        }
    }

    fun label(score: Int): String = LABELS[score.coerceIn(0, LABELS.size - 1)]

    // ---- internals (mirrored verbatim in web/src/ui/strength.ts) ----

    /** Longest repeated block treated as one token — long enough for a repeated word
     *  ("passwordpassword"), short enough that two different long phrases are never fused. */
    private const val MAX_PERIOD = 12

    /** A repeat must cover at least this many characters to be charged as one. Below it the
     *  "pattern" is noise a random generator produces routinely (an incidental "aa", "abab"). */
    private const val MIN_PATTERN_SPAN = 4

    /** Same idea for ±1 runs: "abc" is a coincidence, "abcd" is a sequence. */
    private const val MIN_SEQUENCE_RUN = 4

    private fun classCount(pw: String): Int {
        var classes = 0
        if (pw.any { it in 'a'..'z' }) classes++
        if (pw.any { it in 'A'..'Z' }) classes++
        if (pw.any { it in '0'..'9' }) classes++
        if (pw.any { it !in 'a'..'z' && it !in 'A'..'Z' && it !in '0'..'9' }) classes++
        return classes
    }

    private fun scoreOf(length: Int, classes: Int): Int {
        val bits = length * when {
            classes <= 1 -> 2.0
            classes == 2 -> 3.5
            classes == 3 -> 5.0
            else -> 6.0
        }
        return when {
            bits < 40 -> 0
            bits < 60 -> 1
            bits < 80 -> 2
            bits < 110 -> 3
            else -> 4
        }
    }

    /**
     * How many characters this password is really worth. Walks left to right, and at each
     * position charges either:
     *  - a block of `period` characters repeated back to back (period 1 = a run of one
     *    character): `period + 1`, no matter how many times it repeats — "aA1!" five times is
     *    a 4-character choice plus the decision to repeat it, not 20 characters of entropy;
     *  - an ascending/descending run of adjacent code units ("abcdef", "9876"): 2, because the
     *    run is fixed by its first character and direction;
     *  - otherwise the character itself: 1.
     * The smallest qualifying period wins, so "abababab" collapses as "ab", not "abab".
     */
    private fun effectiveLength(pw: String): Int {
        val n = pw.length
        var eff = 0
        var i = 0
        while (i < n) {
            var consumed = 0
            var cost = 0
            var period = 1
            while (period <= MAX_PERIOD && i + 2 * period <= n) {
                var reps = 1
                while (i + (reps + 1) * period <= n && pw.regionMatches(i, pw, i + reps * period, period)) reps++
                if (reps >= 2 && reps * period >= MIN_PATTERN_SPAN) {
                    consumed = reps * period
                    cost = period + 1
                    break
                }
                period++
            }
            if (consumed == 0) {
                val run = sequenceRun(pw, i)
                if (run >= MIN_SEQUENCE_RUN) {
                    consumed = run
                    cost = 2
                }
            }
            if (consumed == 0) {
                consumed = 1
                cost = 1
            }
            eff += cost
            i += consumed
        }
        return eff
    }

    /** Length of the ±1 code-unit run starting at [i] (1 when there is no run). */
    private fun sequenceRun(pw: String, i: Int): Int {
        if (i + 1 >= pw.length) return 1
        val step = pw[i + 1].code - pw[i].code
        if (step != 1 && step != -1) return 1
        var j = i + 1
        while (j + 1 < pw.length && pw[j + 1].code - pw[j].code == step) j++
        return j - i + 1
    }
}
