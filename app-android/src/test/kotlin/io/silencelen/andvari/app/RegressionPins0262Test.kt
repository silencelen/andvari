package io.silencelen.andvari.app

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Audit 2026-09-13 H41: regression pins for the 0.26.2 (2026-08-30 audit) Android fixes that
 * shipped with no test. Each block names its G-row and FAILS if that fix is reverted.
 *
 * The overhaul deleted the old screens these pins partly read (MainActivity.kt's old router, Trash and
 * clipboard note, HealthScreen.kt): G13, G22, G29, G32 and G60 went with them, and G33 and G62 keep
 * only their ViewModel halves. The new path's twins: the lock observer is TrustApp's, the trash is
 * the content's, health is trust/VaultHealthScreens.kt over the content's own sentences.
 *
 * Source pins: the fixes live inside ViewModel closures this module's pure-JVM suite cannot run,
 * so the shipped source is parsed and the wiring asserted. `code()` strips comments.
 */
class RegressionPins0262Test {
    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/$name").readText()

    private fun code(name: String): String = src(name)
        .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
        .lines().joinToString("\n") { it.substringBefore("//") }

    private val vm = src("AndvariViewModel.kt")
    private val vmCode = code("AndvariViewModel.kt")
    private val autofillCode = code("AutofillStatusScreen.kt")

    /** Both anchors present, in order — never a -1 < n pass. */
    private fun assertOrdered(hay: String, first: String, second: String, why: String) {
        val a = hay.indexOf(first)
        val b = hay.indexOf(second)
        assertTrue(a > -1, "$why: missing `$first`")
        assertTrue(b > -1, "$why: missing `$second`")
        assertTrue(a < b, why)
    }

    // ---- G23: a retried NEW-item save reuses its draft id (never a duplicate) ----

    @Test
    fun g23_theNewItemDraftIdIsMintedOncePerEditorSessionAndThreadedIntoTheSave() {
        assertTrue(vmCode.contains("if (itemId == null && draftItemId == null) draftItemId = account?.newItemId()"), "minted once, only for a NEW item")
        assertTrue(vmCode.contains("newItemId = if (itemId == null) draftItemId else null"), "…and handed to the engine by name")
        assertTrue(vmCode.contains("fun openEditor(itemId: String?, newType: String = \"login\", generate: Boolean = false) {"), "openEditor's signature moved — update this pin deliberately")
        val open = vmCode.substringAfter("fun openEditor(").substringBefore("\n    }")
        assertTrue(open.contains("draftItemId = null"), "a fresh editor session never inherits a draft id (reusing one would OVERWRITE that item)")
        val close = vmCode.substringAfter("fun closeEditor() {").substringBefore("\n    }")
        assertTrue(close.contains("draftItemId = null"), "cancel or success ends the draft")
        val afterSave = vmCode.substringAfter("engine!!.saveWithUploads(itemId, doc, uploads, vaultId, newItemId").substringBefore("refreshItems()")
        assertTrue(afterSave.contains("draftItemId = null"), "cleared once the save has LANDED, on the success path only")
    }

    // ---- G26 / G62: the breach scan states its verdict, and a failed scan is not a clean one ----

    @Test
    fun g26_theBreachScanAnnouncesCompletionWithItsCount() {
        assertTrue(vmCode.contains("\"Breach scan finished — \$breachedLogins login\${if (breachedLogins == 1) \"\" else \"s\"} found in known breaches.\""))
    }

    @Test
    fun g62_anAllFailedScanPublishesNoMapAndAPartialScanIsMarkedIncomplete() {
        // Raw `vm` on purpose (R49): the span END is a comment marker, which `vmCode` has stripped.
        val scan = vm.substringAfter("fun scanBreaches()").substringBefore("// ---- the check ledger ----")
        val allFailed = scan.substringAfter("if (failedRanges == byPrefix.size) {").substringBefore("return@launch")
        assertFalse(allFailed.contains("breachByItem ="), "an all-failed scan must not publish a map — that is what rendered 'Breached 0' offline")
        assertTrue(allFailed.contains("breachScanning = false"))
        assertTrue(allFailed.contains("\"Breach scan failed — the service is unavailable. Partial results were discarded.\""))
        assertTrue(scan.contains("breachScanIncomplete = failedRanges > 0,"), "a partial scan is flagged so the tile cannot claim a clean verdict")
        val cleared = vmCode.substringAfter("internal fun UiState.sessionCleared").substringBefore("\n)")
        assertTrue(cleared.contains("breachScanIncomplete = false"))
    }

    // ---- G33: a refused verdict does not advance the run ----

    @Test
    fun g33_aRefusedVerdictStaysPut() {
        val record = vmCode.substringAfter("fun recordCheck(").substringBefore("fun removeGoneItem(")
        val refusal = record.substringAfter("val write = plan.write ?: run {").substringBefore("}")
        assertTrue(refusal.contains("healthMessage = plan.refusal"), "the refusal is stored verbatim")
        assertFalse(refusal.contains("onDone()"), "…and the run must NOT advance on it — that made a reader-role login look recorded")
        assertTrue(record.contains("_ui.value = _ui.value.copy(healthMessage = null)"), "a new verdict clears the last refusal (web's setMsg(null))")
    }

    // ---- G58: the run's completion is stated, not implied by a closing dialog ----

    @Test
    fun g58_theVerificationRunStatesItsCompletion() {
        val advance = vmCode.substringAfter("fun verifyAdvance() {").substringBefore("\n    }")
        assertOrdered(
            advance,
            "stopVerifyRun()",
            "\"Run finished — every login in the list has been looked at.\"",
            "the finish sentence lands after the run stops, on the last advance",
        )
    }

    // ---- G64: 'Set as autofill service' is an armed excursion, disarmed if the launch fails ----

    @Test
    fun g64_theAutofillPickerLaunchArmsTheExcursionAndDisarmsOnFailure() {
        assertOrdered(autofillCode, "ExternalExcursion.begin()", "Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE", "armed BEFORE the launch")
        assertOrdered(autofillCode, "Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE", "if (!ok) ExternalExcursion.clear()", "disarmed after a refused launch")
        assertEquals(1, Regex("ExternalExcursion\\.begin\\(\\)").findAll(autofillCode).count(), "exactly one arm on this screen")
    }
}
