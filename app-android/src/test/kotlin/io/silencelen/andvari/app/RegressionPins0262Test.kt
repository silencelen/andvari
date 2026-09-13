package io.silencelen.andvari.app

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Audit 2026-09-13 H41: regression pins for the 0.26.2 (2026-08-30 audit) Android fixes that
 * shipped with no test. Of the ~57 fixes in that release only nine touched a suite; the phone's
 * untested ones include two security controls (G13, the lock-on-background observer surviving
 * the 426 wall; G22, the Trash reader gate) and a run of honesty fixes whose regression would be
 * silent. A fix nothing pins is a fix nothing keeps — each block names its G-row and FAILS if
 * that fix is reverted.
 *
 * Source pins in the [HealthSurfaceTest] / [SurfaceCopyPinsTest] idiom: the fixes live inside
 * composables and ViewModel closures this module's pure-JVM suite cannot render, so the shipped
 * source is parsed and the wiring asserted. `code()` strips comments — every rule here is
 * documented IN the source it pins, and a naive `contains` would match the prose. Ordering
 * assertions first prove both anchors present: `indexOf` of a deleted line is -1, which is less
 * than anything, so a bare `a < b` passes when `a` is gone.
 *
 * Already pinned elsewhere (not repeated): G01/G24 (HealthSurfaceTest), G11 (H55
 * SaveConfirmLaunderTest), G12 (H08 DeferredBackgroundLockTest), G07 (H78), G31 (H123
 * SurfaceCopyPinsTest), the refusal slot of G33 (H30 HealthSurfaceTest).
 */
class RegressionPins0262Test {
    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/$name").readText()

    private fun code(name: String): String = src(name)
        .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
        .lines().joinToString("\n") { it.substringBefore("//") }

    private val vm = src("AndvariViewModel.kt")
    private val vmCode = code("AndvariViewModel.kt")
    private val mainCode = code("MainActivity.kt")
    private val healthCode = code("HealthScreen.kt")
    private val autofillCode = code("AutofillStatusScreen.kt")

    /** Both anchors present, in order — never a -1 < n pass. */
    private fun assertOrdered(hay: String, first: String, second: String, why: String) {
        val a = hay.indexOf(first)
        val b = hay.indexOf(second)
        assertTrue(a > -1, "$why: missing `$first`")
        assertTrue(b > -1, "$why: missing `$second`")
        assertTrue(a < b, why)
    }

    // ---- G13 (security): the 426 wall must not uninstall lock-on-background ----

    /**
     * upgradeRequired can land mid-session with the vault still unlocked behind it. The lock
     * observer is a DisposableEffect: registered below the early return, the return disposes it
     * — i.e. the one moment the app is stuck on a wall is the one moment leaving it no longer
     * locks. Pinned as ordering INSIDE AndvariApp, above the `return`.
     */
    @Test
    fun g13_theLockObserverIsRegisteredAboveThe426EarlyReturn() {
        val app = mainCode.substringAfter("fun AndvariApp(vm: AndvariViewModel) {").substringBefore("Surface(Modifier.fillMaxSize()) {")
        assertOrdered(
            app,
            "androidx.lifecycle.ProcessLifecycleOwner.get()",
            "ui.upgradeRequired?.let { msg ->",
            "the process-lifecycle observer must be installed BEFORE the 426 early return",
        )
        val observer = app.substringAfter("androidx.lifecycle.ProcessLifecycleOwner.get()").substringBefore("ui.upgradeRequired?.let { msg ->")
        assertTrue(observer.contains("DisposableEffect(processOwner)"), "…as the DisposableEffect itself, not just the owner lookup")
        assertTrue(observer.contains("Lifecycle.Event.ON_STOP -> vm.lockFromBackground()"))
        // The wall IS an early return — which is exactly why the order matters.
        assertTrue(
            Regex("UpgradeRequiredScreen\\(msg, onSignOut = vm::signOut\\)\\s*return").containsMatchIn(app),
            "the 426 branch is an early return; if that ever changes, re-read this pin",
        )
    }

    // ---- G22 (security/usability): Trash actions are reader-gated ----

    /** The deleted-items route is role-agnostic, so a reader's Trash lists shared-vault
     *  tombstones — but the server refuses a reader's restore/purge. The controls are REMOVED for
     *  a reader (desktop H12 / web G22 twin), and the row says why. */
    @Test
    fun g22_trashRestoreAndPurgeAreHiddenFromAReader() {
        val trash = mainCode.substringAfter("fun TrashScreen(vm: AndvariViewModel, ui: UiState) {").substringBefore("@Composable")
        assertTrue(trash.contains("val readOnly = vm.roleFor(d.vaultId) == \"reader\""), "the row must derive the gate from the vault's role")
        assertTrue(trash.contains("(if (readOnly) \" · view only\" else \"\")"), "the deleted line carries the shared ' · view only' suffix")
        assertOrdered(trash, "if (!readOnly) {", "vm.restoreDeleted(d.itemId, d.vaultId, docToRestore)", "Restore sits inside the reader gate")
        assertOrdered(trash, "if (!readOnly) {", "confirmPurgeId = d.itemId", "Delete forever sits inside the reader gate")
    }

    // ---- G23: a retried NEW-item save reuses its draft id (never a duplicate) ----

    /** A transport-failed first attempt leaves its row durably QUEUED, so a retry that minted a
     *  fresh id applied as a SECOND item. The draft id is minted once per editor session,
     *  threaded into the save, and cleared only on success / with the editor session. */
    @Test
    fun g23_theNewItemDraftIdIsMintedOncePerEditorSessionAndThreadedIntoTheSave() {
        assertTrue(vmCode.contains("if (itemId == null && draftItemId == null) draftItemId = account?.newItemId()"), "minted once, only for a NEW item")
        assertTrue(vmCode.contains("newItemId = if (itemId == null) draftItemId else null"), "…and handed to the engine by name")
        val open = vmCode.substringAfter("fun openEditor(itemId: String?, newType: String = \"login\") {").substringBefore("\n    }")
        assertTrue(open.contains("draftItemId = null"), "a fresh editor session never inherits a draft id (reusing one would OVERWRITE that item)")
        val close = vmCode.substringAfter("fun closeEditor() {").substringBefore("\n    }")
        assertTrue(close.contains("draftItemId = null"), "cancel or success ends the draft")
        // Cleared AFTER a successful save — the failed-save path (op's catch) never reaches this
        // line, which is the whole mechanism.
        val afterSave = vmCode.substringAfter("engine!!.saveWithUploads(itemId, doc, uploads, vaultId, newItemId").substringBefore("refreshItems()")
        assertTrue(afterSave.contains("draftItemId = null"), "cleared once the save has LANDED, on the success path only")
    }

    // ---- G26 / G62: the breach scan states its verdict, and a failed scan is not a clean one ----

    @Test
    fun g26_theBreachScanAnnouncesCompletionWithItsCount() {
        assertTrue(vmCode.contains("\"Breach scan finished — \$breachedLogins login\${if (breachedLogins == 1) \"\" else \"s\"} found in known breaches.\""))
    }

    /** Every range failed = NO scan: breachByItem must stay exactly as it was (publishing an
     *  empty non-null map flipped the tile to a good-tone "Breached 0" fully offline). Some
     *  ranges failed = the tile's zero is "no verdict" (neutral), never a clean bill. */
    @Test
    fun g62_anAllFailedScanPublishesNoMapAndAPartialScanIsMarkedIncomplete() {
        // Raw `vm` on purpose (R49): the span END is a comment marker, which `vmCode` has stripped.
        val scan = vm.substringAfter("fun scanBreaches()").substringBefore("// ---- the check ledger ----")
        val allFailed = scan.substringAfter("if (failedRanges == byPrefix.size) {").substringBefore("return@launch")
        assertFalse(allFailed.contains("breachByItem ="), "an all-failed scan must not publish a map — that is what rendered 'Breached 0' offline")
        assertTrue(allFailed.contains("breachScanning = false"))
        assertTrue(allFailed.contains("\"Breach scan failed — the service is unavailable. Partial results were discarded.\""))
        assertTrue(scan.contains("breachScanIncomplete = failedRanges > 0,"), "a partial scan is flagged so the tile cannot claim a clean verdict")
        assertTrue(
            healthCode.contains("breached?.let { if (it > 0) true else if (breachIncomplete) null else false }"),
            "the Breached tile: findings red, an incomplete zero NEUTRAL, only a complete zero good-tone",
        )
        // The flag rides the wipe choke point with the map it qualifies.
        val cleared = vmCode.substringAfter("internal fun UiState.sessionCleared").substringBefore("\n)")
        assertTrue(cleared.contains("breachScanIncomplete = false"))
    }

    // ---- G29: the clipboard disclosure never promises an unconditional wipe ----

    /** copyToClipboard clears only when it can re-read its own clip, and on API 29+ a
     *  backgrounded read returns null — the copy-then-switch-apps flow skips the wipe. */
    @Test
    fun g29_theCopiedNoteIsHonestAboutTheWipesScope() {
        assertTrue(mainCode.contains("\"Copied — andvari clears it in \${clearSeconds}s while open; your device hides it from other apps\""))
        assertFalse(mainCode.contains("clears from the clipboard in"), "the unconditional promise must not return")
    }

    // ---- G32: merge / keep confirms name the vault (audit F03) ----

    @Test
    fun g32_theMergeAndKeepConfirmsNameTheVaultsTouched() {
        val dupes = healthCode.substringAfter("private fun DuplicatesTab(").substringBefore("private fun vaultLabel(")
        assertTrue(dupes.contains("\"Keep “\$survivorName” in “\$survivorVault” and move the other \${plan.loserIds.size} in “\$loserVaults” \""), "merge names the kept and emptied vaults")
        assertTrue(dupes.contains("\"It stays in “\$keepVault”. The other \${c.members.size - 1} in “\$loserVaults” go to Deleted items \""), "keep names the kept and emptied vaults")
    }

    // ---- G33: a refused verdict does not advance the run; verdict buttons can't double-fire ----

    @Test
    fun g33_aRefusedVerdictStaysPutAndTheRunButtonsDisableWhileSaving() {
        val record = vmCode.substringAfter("fun recordCheck(").substringBefore("fun removeGoneItem(")
        val refusal = record.substringAfter("val write = plan.write ?: run {").substringBefore("}")
        assertTrue(refusal.contains("healthMessage = plan.refusal"), "the refusal is stored verbatim")
        assertFalse(refusal.contains("onDone()"), "…and the run must NOT advance on it — that made a reader-role login look recorded")
        assertTrue(record.contains("_ui.value = _ui.value.copy(healthMessage = null)"), "a new verdict clears the last refusal (web's setMsg(null))")

        val dialog = healthCode.substringAfter("private fun VerifyRunDialog(").substringBefore("private fun openSite(")
        for (verdict in listOf("\"ok\"", "\"bad\"", "\"gone\"")) {
            assertTrue(
                dialog.contains("vm.recordCheck(row.itemId, $verdict) { vm.verifyAdvance() } }, enabled = !ui.busy)"),
                "the $verdict button must disable while a verdict is saving (a double-tap wrote TWO verdicts and skipped an item)",
            )
        }
        assertTrue(dialog.contains("vm.recordCheck(row.itemId, \"blocked\", Staleness.SNOOZE_MS) { vm.verifyAdvance() }\n                    }, enabled = !ui.busy)"))
        assertTrue(dialog.contains("TextButton(onClick = vm::verifyAdvance, enabled = !ui.busy) { Text(\"Skip\") }"))
        assertTrue(dialog.contains("TextButton(onClick = vm::stopVerifyRun, enabled = !ui.busy) { Text(\"Stop\") }"))
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

    // ---- G59: the quick-unlock re-stamp copy asserts nothing it cannot know ----

    /** isFresh also fails closed cross-boot with no server anchor, so the first unlock after a
     *  reboot while offline lands here too — "It's been 30 days" was simply false then. */
    @Test
    fun g59_theQuickUnlockNoticeNamesBothCausesInsteadOfAnElapsedTime() {
        val unlock = mainCode.substringAfter("fun UnlockScreen(vm: AndvariViewModel, ui: UiState, email: String) {").substringBefore("@Composable")
        assertTrue(unlock.contains("if (ui.quickUnlockEnrolled && !ui.quickUnlockFresh) {"))
        assertTrue(unlock.contains("\"Enter your master password to keep quick unlock active — needed at least every 30 days, and after a restart while offline.\""))
        assertFalse(mainCode.contains("It's been 30 days"), "the elapsed-time assertion must not return")
    }

    // ---- G60: FAILING staleness rows render curated verdicts, raw tokens only for unknowns ----

    @Test
    fun g60_theKnownVerdictsAreCuratedAndTheOpenVocabularyFallbackKeepsTheRawToken() {
        val label = healthCode.substringAfter("private fun bucketLabel(r: Staleness.StalenessRow): String = when (r.bucket) {").substringBefore("\n}")
        // Cut at the inner when's closing brace (4-space indent) — a bare "}" would stop at the
        // `${…}` template inside the fallback line.
        val failing = label.substringAfter("Staleness.StaleBucket.FAILING -> when (r.check?.result) {").substringBefore("\n    }")
        assertTrue(failing.contains("\"bad\" -> \"last check failed — wrong password\""))
        assertTrue(failing.contains("\"gone\" -> \"last check failed — account is gone\""))
        assertTrue(failing.contains("\"blocked\" -> \"last check failed — couldn't complete\""))
        assertTrue(failing.contains("else -> \"last check failed (\${r.check?.result})\""), "spec 02 §3 open vocabulary: an unknown verdict keeps its token")
    }

    // ---- G64: 'Set as autofill service' is an armed excursion, disarmed if the launch fails ----

    /** On some OEMs the picker is a full activity, so ON_STOP fires — without the arm, enabling
     *  autofill returned the user to a locked app with the setup flow gone. A refused launch must
     *  drop the unused arm, or it exempts a later, unrelated backgrounding. */
    @Test
    fun g64_theAutofillPickerLaunchArmsTheExcursionAndDisarmsOnFailure() {
        assertOrdered(autofillCode, "ExternalExcursion.begin()", "Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE", "armed BEFORE the launch")
        assertOrdered(autofillCode, "Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE", "if (!ok) ExternalExcursion.clear()", "disarmed after a refused launch")
        assertEquals(1, Regex("ExternalExcursion\\.begin\\(\\)").findAll(autofillCode).count(), "exactly one arm on this screen")
    }
}
