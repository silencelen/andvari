package io.silencelen.andvari.desktop

import io.silencelen.andvari.core.client.CoHolder
import io.silencelen.andvari.core.client.HouseholdCopy
import io.silencelen.andvari.core.client.LifecycleNotice
import io.silencelen.andvari.core.client.PersonalChoiceInfo
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Security review 2026-10, root cause A, branch A6, desktop surface:
 *  - the "added" notice names the PINNED contact who signed the verified grant (core canon), and a grant
 *    anomaly renders in the danger tone;
 *  - A5b review LOW-2: every server-reported co-holder / origin detail is labelled as reported by the server;
 *  - A5b review LOW-1: on a personal-vault change, "Keep <current>" comes FIRST and "Use <new>" is offered only
 *    after describePersonalChange (the co-holder lookup) succeeded (the engine refuses it otherwise; pinned in
 *    core PersonalChoiceHardeningTest).
 */
class SignedGrantCopyTest {
    private fun notice(kind: String, byLabel: String? = null, reason: String? = null) =
        LifecycleNotice(id = "n", vaultId = "v", vaultName = "Household", kind = kind, reason = reason, byLabel = byLabel)

    @Test
    fun addedNamesTheVerifiedSender() {
        assertEquals("You were added to “Household” by Alice.", noticeBody(notice("added", byLabel = "Alice")).first)
        assertEquals(HouseholdCopy.addedNotice("Household", null), noticeBody(notice("added")).first)
        assertFalse(noticeBody(notice("added", byLabel = "Alice")).second)
    }

    @Test
    fun aGrantAnomalyIsAWarning() {
        val (body, warn) = noticeBody(notice("grant-anomaly", reason = "signer_not_pinned_key"))
        assertEquals(HouseholdCopy.GRANT_ANOMALY_NOTICE, body)
        assertTrue(warn)
    }

    @Test
    fun low2_serverReportedDetailsAreLabelled() {
        val info = PersonalChoiceInfo("v", "Household", 3, PersonalChoiceInfo.Origin.RECEIVED_BY_TRANSFER, listOf(CoHolder("u", "Bo", "b@example.com", "writer")), false)
        assertTrue(personalChoiceDetail(info).startsWith("As reported by the server:"), personalChoiceDetail(info))
    }

    private fun sourceFile(relative: String): File =
        listOf(File(relative), File("app-desktop/$relative")).firstOrNull { it.isFile }
            ?: error("could not locate $relative from ${File(".").absolutePath}")

    @Test
    fun low1_keepCurrentComesFirstAndUseNewWaitsForTheLookup() {
        val src = sourceFile("src/main/kotlin/io/silencelen/andvari/desktop/Household.kt").readText()
        val changed = src.substringAfter("status == Account.PersonalStatus.CHANGED").substringBefore("return\n    }")
        val keep = changed.indexOf("Text(\"Keep \$oldName\")")
        val use = changed.indexOf("Text(\"Use \$newName\")")
        assertTrue(keep in 0 until use, "Keep <current> must be offered before Use <new>")
        assertTrue(changed.contains("vm.describePersonalChange()"), "the co-holder lookup gates Use <new>")
        assertTrue(changed.substring(0, use).contains("if (d != null)"), "Use <new> renders only once the lookup returned details")
    }
}
