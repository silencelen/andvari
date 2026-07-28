package io.silencelen.andvari.desktop

import io.silencelen.andvari.core.client.HouseholdCopy
import io.silencelen.andvari.core.client.LifecycleNotice
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

/**
 * ux-copy--3 (polish audit 2026-07-27): the §11 "replay-denied" notice is the one lifecycle
 * sentence that interpolates (count + vault name), so no canon constant could carry it and all
 * three surfaces hand-wrote it — desktop/android had drifted from web in clause order, in the
 * explanation ("your role may have changed" vs "your access…") and in the singular form, while
 * this file's own comment claimed to mirror web. The sentence now lives in
 * [HouseholdCopy.replayDeniedNotice]; this pins that [noticeBody] RENDERS it rather than an
 * inlined copy, so re-inlining a literal fails here. The sentence itself is pinned verbatim by
 * core's HouseholdCopyTest, and web's byte-equal templates by web/src/ui/vault-copy.test.ts.
 */
class LifecycleNoticeCopyTest {

    private fun notice(parkedCount: Int?, vaultName: String = "Household") =
        LifecycleNotice(
            id = "n1",
            vaultId = "v1",
            vaultName = vaultName,
            kind = "replay-denied",
            parkedCount = parkedCount,
        )

    @Test
    fun replayDeniedRendersTheCanonSentence() {
        for (c in listOf(1, 2, 7)) {
            assertEquals(HouseholdCopy.replayDeniedNotice(c, "Household"), noticeBody(notice(c)).first)
        }
    }

    /** A null parkedCount is 0, not a crash and not a bare "recovered edits" — same as android. */
    @Test
    fun aMissingCountIsZero() {
        assertEquals(HouseholdCopy.replayDeniedNotice(0, "Household"), noticeBody(notice(null)).first)
    }

    /** The §11 blank-name fallback stays at the surface (the canon renders what it is given). */
    @Test
    fun aBlankVaultNameFallsBackToAVault() {
        assertEquals(HouseholdCopy.replayDeniedNotice(1, "a vault"), noticeBody(notice(1, "")).first)
    }

    /** Calm, never the danger tone — a refused replay is not an anomaly (C1). */
    @Test
    fun replayDeniedIsNeverAWarning() {
        assertFalse(noticeBody(notice(3)).second)
    }
}
