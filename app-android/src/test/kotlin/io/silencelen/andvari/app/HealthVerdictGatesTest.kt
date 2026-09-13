package io.silencelen.andvari.app

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Audit 2026-09-13 — two pure gates in `AndvariViewModel.kt` that a JVM test can hold exactly:
 *
 *  - H12: the forgot-password reset step's 300 s idle cap (web Recover.tsx CR-02 twin). The
 *    constant and the notice are pinned AGAINST THE WEB SOURCE, because "the sibling that is
 *    right" is web and a twin that drifts in copy is the defect class this audit named.
 *  - H26: a breach verdict is rendered only while the item it was about is unchanged — the
 *    CHANGED-since-scan half of G35's "never a false none" rule.
 */
class HealthVerdictGatesTest {
    private fun repoFile(relative: String): File =
        listOf(File("../$relative"), File(relative)).firstOrNull { it.isFile }
            ?: error("could not locate $relative from ${File(".").absolutePath}")

    // ---- H12 ----

    @Test
    fun theRecoverySecretIsBoundedOnlyOnTheResetStep() {
        assertFalse(recoverSecretIdleExpired(onRecoverScreen = true, recoverVerified = false, idleSeconds = 10_000), "phase 1 holds no secret")
        assertFalse(recoverSecretIdleExpired(onRecoverScreen = false, recoverVerified = true, idleSeconds = 10_000), "off the wizard, nothing to bound")
        assertFalse(recoverSecretIdleExpired(onRecoverScreen = true, recoverVerified = true, idleSeconds = RECOVER_IDLE_TIMEOUT_S - 1))
        assertTrue(recoverSecretIdleExpired(onRecoverScreen = true, recoverVerified = true, idleSeconds = RECOVER_IDLE_TIMEOUT_S))
    }

    /** Web is the reference: the same 300 s and the same sentence, byte for byte. */
    @Test
    fun theCapAndTheNoticeMatchWebsRecoverScreen() {
        val web = repoFile("web/src/ui/Recover.tsx").readText()
        assertTrue(web.contains("const REVEAL_TIMEOUT_S = ${RECOVER_IDLE_TIMEOUT_S};"), "web's REVEAL_TIMEOUT_S moved — keep the natives in step")
        assertTrue(web.contains("\"$RECOVER_TIMEOUT_NOTICE\""), "web's REVEAL_TIMEOUT_NOTICE differs from the Android notice")
    }

    // ---- H26 ----

    @Test
    fun aVerdictSurvivesOnlyWhileTheItemIsUnchanged() {
        val scanned = mapOf("a" to 12_345L, "b" to 0L, "c" to 7L)
        val revs = mapOf("a" to 3L, "b" to 5L, "c" to 1L)
        val live = mapOf("a" to 3L, "b" to 6L /* edited since */) // c: deleted since
        val fresh = freshBreachVerdicts(scanned, revs) { live[it] }
        assertEquals(mapOf("a" to 12_345L), fresh, "the edited item's count and the deleted item's count are gone")
    }

    /** THE BUG's worse half: green "none" surviving an edit to a breached password. */
    @Test
    fun aCleanVerdictDoesNotOutliveAPasswordChange() {
        val fresh = freshBreachVerdicts(mapOf("x" to 0L), mapOf("x" to 1L)) { 2L }
        assertNull(fresh?.get("x"), "0 (rendered 'none') must not be asserted about a rev the scan never saw")
    }

    /** null keeps its meaning — never scanned this session — and a verdict with no recorded rev
     *  (impossible by construction, but the safe reading) is not shown either. */
    @Test
    fun neverScannedStaysNullAndAnUnrecordedRevIsNotShown() {
        assertNull(freshBreachVerdicts(null, emptyMap()) { 1L })
        assertEquals(emptyMap(), freshBreachVerdicts(mapOf("x" to 3L), emptyMap()) { 1L })
    }
}
