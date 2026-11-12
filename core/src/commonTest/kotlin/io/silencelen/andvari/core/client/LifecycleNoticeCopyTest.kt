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
}
