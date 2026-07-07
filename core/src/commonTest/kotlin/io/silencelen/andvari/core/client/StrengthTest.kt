package io.silencelen.andvari.core.client

import kotlin.test.Test
import kotlin.test.assertEquals

/** Pinned scores mirroring web/src/ui/strength.ts — the two impls must agree exactly,
 *  or the spec 07 §2.3 backup-passphrase floor (score ≥ 3) drifts between clients. */
class StrengthTest {
    @Test
    fun pinnedScores_matchWebEstimator() {
        assertEquals(0, Strength.estimateStrength(""))                        // 0 bits
        assertEquals(0, Strength.estimateStrength("abcdefgh"))                // 8×2 = 16
        assertEquals(1, Strength.estimateStrength("aaaaaaaaaaaaaaaaaaaa"))    // 20×2 = 40
        assertEquals(2, Strength.estimateStrength("Tr0ub4dor&3"))             // 11×6 = 66
        assertEquals(2, Strength.estimateStrength("correct horse battery"))   // 21×3.5 = 73.5 (2 classes: lower+space)
        assertEquals(2, Strength.estimateStrength("Aa1!Aa1!Aa"))              // 10×6 = 60 (boundary: not <60)
        assertEquals(3, Strength.estimateStrength("Aa1!Aa1!Aa1!Aa1"))         // 15×6 = 90
        assertEquals(4, Strength.estimateStrength("Abcdefgh12Abcdefgh12Ab"))  // 22×5 = 110 (boundary: not <110)
        assertEquals(4, Strength.estimateStrength("Aa1!Aa1!Aa1!Aa1!Aa1!"))    // 20-char 4-class → 120
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
