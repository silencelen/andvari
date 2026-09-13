package io.silencelen.andvari.app

import io.silencelen.andvari.core.client.HouseholdCopy
import io.silencelen.andvari.core.client.LifecycleNotice
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * ux-copy--3 (polish audit 2026-07-27): the §11 "replay-denied" notice is the one lifecycle
 * sentence that interpolates (count + vault name), so no canon constant could carry it and all
 * three surfaces hand-wrote it — android/desktop had drifted from web in clause order, in the
 * explanation ("your role may have changed" vs "your access…") and in the singular form, while
 * this file's own comment claimed to mirror web. The sentence now lives in
 * [HouseholdCopy.replayDeniedNotice]; this pins that [noticeBody] RENDERS it rather than an
 * inlined copy, so re-inlining a literal fails here. The sentence itself is pinned verbatim by
 * core's HouseholdCopyTest, and web's byte-equal templates by web/src/ui/vault-copy.test.ts.
 * Pure JVM (noticeBody is a plain function, not a composable) — no Android framework.
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

    /** A null parkedCount is 0, not a crash and not a bare "recovered edits" — same as desktop. */
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

    // ---- audit 2026-09-13: the two notice kinds web had and the natives lacked / needed ----

    /** H71: web's F20 "You were added to X" now has its native twin — calm, never a warning. */
    @Test
    fun addedRendersWebsSentence() {
        val n = LifecycleNotice(id = "n2", vaultId = "v2", vaultName = "Family", kind = "added")
        assertEquals("You were added to “Family”.", noticeBody(n).first)
        assertFalse(noticeBody(n).second)
        assertEquals("You were added to “a vault”.", noticeBody(n.copy(vaultName = "")).first)
    }

    /** H03/H19: a queue row the server definitively refused and the drain dropped renders the
     *  canon [HouseholdCopy.writeRejectedNotice] — reason clause and count included — as a
     *  warning (an edit was lost), never the permission sentence, never an inlined literal. */
    @Test
    fun writeRejectedRendersTheCanonSentenceWithItsReason() {
        for ((count, reason) in listOf(1 to "unknown_attachment", 3 to "attachment_mismatch", 1 to "body_too_large", 2 to "item_attachment_quota", 1 to null)) {
            val n = LifecycleNotice(id = "n3", vaultId = "v3", vaultName = "Family", kind = "write-rejected", parkedCount = count, reason = reason)
            val (body, warn) = noticeBody(n)
            assertEquals(HouseholdCopy.writeRejectedNotice(count, "Family", reason), body)
            assertTrue(warn)
            assertFalse(body.contains("permission"))
        }
        val missing = LifecycleNotice(id = "n4", vaultId = "v3", vaultName = "Family", kind = "write-rejected")
        assertEquals(HouseholdCopy.writeRejectedNotice(0, "Family", null), noticeBody(missing).first)
    }
}
