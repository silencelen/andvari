package io.silencelen.andvari.core.client

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class LifecycleNoticeCopyTest {
    @Test
    fun aDateIsSaidAsAndroidSaysItInEnglish() {
        assertEquals("November 11", LifecycleNoticeCopy.englishDay(1_794_355_200_000))
        assertEquals("soon", LifecycleNoticeCopy.englishDay(null))
        assertEquals("soon", LifecycleNoticeCopy.englishDay(0))
    }

    @Test
    fun anAnomalyNamesWhereTheSealedCopyIsOnlyWhereTheClientHasThatPlace() {
        val n = LifecycleNotice("n1", "v1", "Household", "anomaly")
        val (bare, warn) = LifecycleNoticeCopy.body(n)
        assertTrue(warn)
        assertTrue(bare.contains("kept on this device for 30 days. If nobody"), bare)
        assertTrue(LifecycleNoticeCopy.body(n, heldAt = "Sharing → the trash icon").first.contains("30 days (Sharing → the trash icon). If nobody"))
        assertFalse(LifecycleNoticeCopy.body(LifecycleNotice("n2", "v2", "", "restored")).second)
        assertEquals("“a vault” was restored.", LifecycleNoticeCopy.body(LifecycleNotice("n2", "v2", "", "restored")).first)
    }

    @Test
    fun aHandoverOfAnOfferThisAccountDidNotMakeIsAWarningThatKeepsTheOwnershipRecord() {
        // Sharing review 2026-11 (finding 1).
        val (text, warn) = LifecycleNoticeCopy.body(LifecycleNotice("n1", "v1", "Household", "transfer-anomaly", reason = SyncEngine.TRANSFER_NOT_OFFERED))
        assertTrue(warn)
        assertEquals(HouseholdCopy.transferNotOfferedNotice("Household"), text)
        assertTrue(text.contains("an offer you didn't make or had cancelled"), text)
    }

    @Test
    fun recentlyRemovedSaysHowTheRemovalChecked() {
        // Sharing review 2026-11 (item 6): every verdict in its own words; only what could not be checked warns.
        val day = { _: Long? -> "May 1" }
        fun held(reason: String, proof: String?, verified: Boolean) = HeldVaultInfo("v", "Household", reason, verified, null, 1, proof)
        val rows = listOf(
            held("removed", "VALID", true) to ("Your access was removed. Kept until May 1." to false),
            held("removed", "VALID_LEGACY", true) to ("Your access was removed (sent by an older app version). Kept until May 1." to false),
            held("removed", "ALREADY_RECORDED", true) to ("Your access was removed, as another of your devices already recorded. Kept until May 1." to false),
            held("removed", "REPLAY_DENIED", false) to ("The server sent a removal notice that was already used once, so andvari did not trust it. Kept until May 1." to true),
            held("removed", "ANOMALY", false) to ("The server says your access was removed, but this couldn't be verified. Kept until May 1." to true),
            held("removed", null, false) to ("The server says your access was removed, but this couldn't be verified. Kept until May 1." to true),
            held("left", "VALID", true) to ("You left. Kept until May 1." to false),
            held("left", null, false) to ("You left. Kept until May 1." to false),
            held("left", "LEFT_UNPROVEN", false) to ("The server says you left, with no proof from your device. Didn't do this? Tell your admin. Kept until May 1." to true),
            held("left", "ANOMALY", false) to ("The server says you left, but this couldn't be verified. Kept until May 1." to true),
            held("deleted", "VALID", true) to ("Deleted by its owner. Kept sealed until May 1." to false),
            held("deleted", "ANOMALY", false) to ("The server says it was deleted, but this couldn't be verified. Kept until May 1." to true),
        )
        for ((h, expected) in rows) {
            assertEquals(expected, HeldVaultCopy.sentence(h, day), "${h.reason} / ${h.proof}")
            assertEquals(expected.second, HeldVaultCopy.fragment(h, day).second, "the same warning in the lists: ${h.reason} / ${h.proof}")
        }
        assertEquals("access removed · kept until May 1" to false, HeldVaultCopy.fragment(held("removed", "VALID", true), day))
        assertEquals("unverified removal · kept until May 1" to true, HeldVaultCopy.fragment(held("removed", "ANOMALY", false), day))
    }
}
