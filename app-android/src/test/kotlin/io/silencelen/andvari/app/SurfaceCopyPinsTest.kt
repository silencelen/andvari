package io.silencelen.andvari.app

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Source-level pins for audit fixes in the old controller ([AndvariViewModel]), which the autofill service still uses.
 * Same idiom as [BrowserAllowlistLockstepTest]: parse the real shipped source, so a one-sided edit fails
 * `testDebugUnitTest` instead of shipping.
 *
 * The overhaul deleted the old screens; the pins that read them went with them (the Trash caveat, the TOTP copy rows,
 * the CSV import's preflight, the pattern warning on the old forms, the old About card and update wall, the old
 * all-snoozed empty state, the attachment names in the old editor). The new path takes its sentences from the
 * content and the app API, and its own pins live in the trust/ tests.
 */
class SurfaceCopyPinsTest {

    private fun sourceFile(relative: String): File =
        listOf(File(relative), File("app-android/$relative")).firstOrNull { it.isFile }
            ?: error("could not locate $relative from ${File(".").absolutePath}")

    private val mainActivity by lazy { sourceFile("src/main/kotlin/io/silencelen/andvari/app/MainActivity.kt").readText() }
    private val viewModel by lazy { sourceFile("src/main/kotlin/io/silencelen/andvari/app/AndvariViewModel.kt").readText() }

    // ---- H72 (audit 2026-09-13): every duplicate/staleness action states its outcome ----

    @Test
    fun everyDuplicateAndStalenessActionStatesItsOutcome() {
        for (sentence in listOf(
            """"Merged — ${'$'}{if (n == 1) "the duplicate copy" else "${'$'}n duplicate copies"} moved to Deleted items (kept 30 days)."""",
            """"Kept one copy — ${'$'}{if (n == 1) "the other copy" else "${'$'}n other copies"} moved to Deleted items (kept 30 days); """",
            """"Marked as not duplicates — this group stays quiet unless its copies change."""",
            """"Couldn't update every copy — the group may reappear until a retry lands. Try again."""",
        )) {
            assertTrue(viewModel.contains(sentence), "missing web's outcome sentence: $sentence")
        }
        assertEquals(
            1,
            Regex(Regex.escape("""internal const val BACK_ON_THE_LIST = "Back on the list."""")).findAll(viewModel).count(),
            "the unsnooze / restore sentence must live in exactly one place",
        )
        assertEquals(2, Regex("BACK_ON_THE_LIST").findAll(viewModel).count() - 1, "…and be USED by both the unsnooze and the restore path")
    }

    @Test
    fun aMergeThatFailsAfterTheSurvivorSaveNamesTheHalfDoneState() {
        val helper = viewModel.substringAfter("private fun runMergePlan(").substringBefore("\n    /** \"Keep this one\"")
        assertTrue(helper.contains("for (id in plan.loserIds) engine!!.remove(id)"), "the loser loop must be inside the helper")
        assertTrue(helper.contains("healthMessage = partial"), "a throw after the survivor save must set the partial sentence")
        assertTrue(viewModel.contains("""internal const val MERGE_DIDNT_FINISH ="""), "the partial-merge sentence is a named constant")
        assertTrue(viewModel.contains("partial = MERGE_DIDNT_FINISH"), "…and the merge action must use it rather than the generic save error")
    }

    // ---- the version line still comes from core's constant ----

    @Test
    fun theVersionLineInterpolatesCoresConstant() {
        assertTrue(
            mainActivity.contains("""internal val VERSION_LINE = "andvari ${'$'}ANDVARI_CLIENT_VERSION · android""""),
            "the version line must interpolate core's constant, never a literal version",
        )
    }

    @Test
    fun noMasterPasswordDerivedRequestReachesTheServer() {
        // Security review 2026-10, root cause C: enrollment and the backup-passphrase dialog sent
        // the SHA-1 prefix of the master password to the vault server's relay. The check is gone.
        for (needle in listOf("breachWarning", "checkEnrolledPasswordForBreach", "breachAdvisory", "BreachAdvisoryBanner", "Strength.breachCount(", "BREACHED_PASSWORD_WARNING")) {
            assertFalse(viewModel.contains(needle), "AndvariViewModel must not carry the master-password breach path ($needle)")
            assertFalse(mainActivity.contains(needle), "MainActivity must not carry the master-password breach path ($needle)")
        }
        assertFalse(mainActivity.contains("breachNote"), "the backup dialog must not run a breach check on its passphrase")
        assertTrue(viewModel.contains("a.hibpRange(prefix)"), "the Health breach scan keeps the relay")
    }

    // ---- H15 (recheck R21): the two recovery ladders name a crypto-unavailable device ----

    @Test
    fun recoveryLaddersNameACryptoUnavailableDeviceFirst() {
        for (fn in listOf("private fun recoverVerifyError(t: Throwable): String = when {", "private fun recoverResetError(t: Throwable): String = when {")) {
            val body = viewModel.substringAfter(fn).substringBefore("\n    }\n")
            val rows = body.lines().map { it.trim() }.filter { it.startsWith("t is ") }
            assertTrue(rows.isNotEmpty(), "$fn: no rows?")
            assertTrue(rows.first().startsWith("t is CryptoUnavailableException -> HouseholdCopy.CRYPTO_UNAVAILABLE"), "$fn: the crypto row must be the FIRST row, got: ${rows.first()}")
            assertTrue(body.contains("else -> \"Recovery failed. Please try again.\""), "$fn: the terminal stays for the genuinely unknown")
        }
    }

    // The re-wrap of the keys at a change of the key-derivation settings: core's KdfReKeyCoreTest and KdfReKeyAdapterTest pin it (see their notes).
}
