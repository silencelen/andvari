package io.silencelen.andvari.core.client

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Pinned scores mirroring web/src/ui/strength.ts — the two impls must agree exactly,
 *  or the spec 07 §2.3 backup-passphrase floor (score ≥ 3) drifts between clients. */
class StrengthTest {
    @Test
    fun pinnedScores_matchWebEstimator() {
        assertEquals(0, Strength.estimateStrength(""))                        // 0 bits
        assertEquals(0, Strength.estimateStrength("abcdefgh"))                // an 8-long ±1 run → 2 effective × 2
        assertEquals(0, Strength.estimateStrength("aaaaaaaaaaaaaaaaaaaa"))    // one run → 2 effective × 2 (F31: was 20×2 = 40)
        assertEquals(2, Strength.estimateStrength("Tr0ub4dor&3"))             // 11×6 = 66
        assertEquals(2, Strength.estimateStrength("correct horse battery"))   // 21×3.5 = 73.5 (2 classes: lower+space)
        assertEquals(1, Strength.estimateStrength("Aa1!Aa1!Aa"))              // "Aa1!"×2 + "Aa" → 7×6 = 42 (F31: was 60)
        assertEquals(1, Strength.estimateStrength("Aa1!Aa1!Aa1!Aa1"))         // "Aa1!"×3 + "Aa1" → 8×6 = 48 (F31: was 90)
        assertEquals(2, Strength.estimateStrength("Abcdefgh12Abcdefgh12Ab"))  // block×2 + "Ab" → 13×5 = 65 (F31: was 110)
        assertEquals(0, Strength.estimateStrength("Aa1!Aa1!Aa1!Aa1!Aa1!"))    // 5×"Aa1!" → 5×6 = 30 (F31: was 120)
        // Unpatterned passphrases are untouched by F31 — the penalty must not tax real ones.
        assertEquals(3, Strength.estimateStrength("correct horse battery staple"))
        assertEquals(4, Strength.estimateStrength("the quick brown fox jumps over the lazy dog 42 TIMES!"))
    }

    /**
     * F31: the whole point — a doubled password no longer scores as double the entropy.
     * `Password1!Password1!` was the audit's example of "strong" (4) for a 10-character choice.
     */
    @Test
    fun repetitionAndSequences_collapseBeforeTheLengthTerm() {
        assertEquals(2, Strength.estimateStrength("Password1!Password1!"))    // the token + 1, not the span
        assertEquals(4, Strength.entropyProxyScore("Password1!Password1!"))   // what it used to score
        assertEquals(0, Strength.estimateStrength("a".repeat(40)))            // 40-char run: audit's other example
        assertEquals(3, Strength.entropyProxyScore("a".repeat(40)))
        assertEquals(0, Strength.estimateStrength("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm")) // two ±1 runs
        // The smallest period wins: "abab…" collapses as "ab", never as "abab".
        assertEquals(Strength.estimateStrength("ababababababababab"), Strength.estimateStrength("abababababab"))
        // Sub-threshold coincidences a random generator produces routinely are NOT patterns.
        assertEquals(Strength.entropyProxyScore("Xk7#mQ2\$vL9!pR4&"), Strength.estimateStrength("Xk7#mQ2\$vL9!pR4&"))
        assertEquals(Strength.entropyProxyScore("correct-horse-battery-staple"), Strength.estimateStrength("correct-horse-battery-staple"))
    }

    /**
     * F31 owner decision: the pattern penalty WARNS, it never refuses. Every password that
     * cleared the master-password floor before F31 still clears it — otherwise a household
     * member could be locked out of *changing* their password by a stricter estimator.
     */
    @Test
    fun masterPasswordFloor_neverTightenedByThePatternPenalty() {
        for (pw in listOf(
            "Password1!Password1!",
            "a".repeat(40),
            "aA1!aA1!aA1!aA1!aA1!",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm",
            "correct-horse-battery-staple",
        )) {
            assertTrue(Strength.meetsMasterPasswordFloor(pw), "F31 must not refuse '$pw'")
            assertEquals(Strength.entropyProxyScore(pw) >= Strength.MASTER_PW_MIN_SCORE, Strength.meetsMasterPasswordFloor(pw))
        }
        // …and it still refuses what F60 always refused.
        assertFalse(Strength.meetsMasterPasswordFloor("password"))
        assertFalse(Strength.meetsMasterPasswordFloor(""))
    }

    @Test
    fun patternWarning_firesOnlyWhenThePatternIsWhatMakesItWeak() {
        assertNotNull(Strength.patternWarning("Password1!Password1!"))
        assertEquals(Strength.PATTERN_WARNING, Strength.patternWarning("a".repeat(40)))
        assertTrue(Strength.hasPatternWeakness("a".repeat(40)))
        assertNull(Strength.patternWarning("correct-horse-battery-staple"))
        assertNull(Strength.patternWarning(""))
        assertFalse(Strength.hasPatternWeakness(""))
    }

    @Test
    fun labels_matchWeb() {
        assertEquals(listOf("very weak", "weak", "fair", "good", "strong"), Strength.LABELS)
        assertEquals("very weak", Strength.label(0))
        assertEquals("good", Strength.label(Strength.BACKUP_FLOOR))
        assertEquals("strong", Strength.label(4))
        assertEquals("strong", Strength.label(9)) // clamped
    }
}
