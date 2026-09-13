package io.silencelen.andvari.app

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Source-level pins for audit fixes that live INSIDE composables, where a pure-JVM unit test
 * cannot reach the rendered output (the module has no Compose test runtime, and adding one to
 * assert a handful of string call sites would be a poor trade). Same idiom as
 * [BrowserAllowlistLockstepTest]: parse the real shipped source, so a one-sided edit fails
 * `testDebugUnitTest` instead of shipping.
 *
 *  - F04: the Trash header and the delete confirm must RENDER
 *    [io.silencelen.andvari.core.client.HouseholdCopy.TRASH_RESTORE_NO_ATTACHMENTS], never an
 *    inlined copy of it — the sentence is byte-shared with web and desktop, and the whole defect
 *    was three surfaces each owning their own wording while claiming to mirror the others.
 *  - F25: the two TOTP-enrollment copy rows must pass the clipboard-clear window, not 0. A `0`
 *    takes copyToClipboard's early-out, which skips BOTH the auto-clear AND EXTRA_IS_SENSITIVE —
 *    i.e. it silently reclassifies the account's second-factor seed as non-secret.
 *  - F08 / F31: the export and strength warnings must be RENDERED, not merely computed. Both
 *    first shipped as core functions with no call site at all — the exact failure these pins
 *    exist to catch, which is why they assert the wiring and not the wording.
 */
class SurfaceCopyPinsTest {

    private fun sourceFile(relative: String): File =
        listOf(File(relative), File("app-android/$relative")).firstOrNull { it.isFile }
            ?: error("could not locate $relative from ${File(".").absolutePath}")

    private val mainActivity by lazy { sourceFile("src/main/kotlin/io/silencelen/andvari/app/MainActivity.kt").readText() }
    private val viewModel by lazy { sourceFile("src/main/kotlin/io/silencelen/andvari/app/AndvariViewModel.kt").readText() }
    private val healthScreen by lazy { sourceFile("src/main/kotlin/io/silencelen/andvari/app/HealthScreen.kt").readText() }

    // ---- F04 ----

    @Test
    fun trashAndDeleteSurfacesRenderTheSharedAttachmentCaveat() {
        val uses = Regex("HouseholdCopy\\.TRASH_RESTORE_NO_ATTACHMENTS").findAll(mainActivity).count()
        assertEquals(2, uses, "expected the canon sentence at BOTH moments — the delete confirm and the Trash header")
        // …and never re-inlined beside it: a literal fragment here means a copy that can drift.
        assertTrue(
            !mainActivity.contains("but not its attachments"),
            "the attachment caveat is inlined as a literal — render HouseholdCopy.TRASH_RESTORE_NO_ATTACHMENTS instead",
        )
    }

    // ---- F25 ----

    @Test
    fun totpEnrollmentRowsCopyAsVaultSecrets() {
        val rows = Regex("""SelectableCopyRow\("[^"]*", setup\.\w+, ctx(, \w+)?\)""").findAll(mainActivity).toList()
        assertEquals(2, rows.size, "expected the otpauth URI + base32 seed rows; did the TOTP card move?")
        for (r in rows) {
            assertTrue(
                r.groupValues[1] == ", clipClear",
                "the TOTP seed must copy with the clipboard window (EXTRA_IS_SENSITIVE + auto-clear), got: ${r.value}",
            )
        }
    }

    // ---- F08 ----

    @Test
    fun theCsvPreflightRendersTheFormulaRiskRow() {
        // ExportCsv.warnings() computes formulaRisk for every export; the dialog is the ONLY
        // place a user can ever learn about it (the writer deliberately mangles nothing).
        assertTrue(
            mainActivity.contains("NamedSkips(ExportCsv.FORMULA_WARNING, pre.warnings.formulaRisk)"),
            "the CSV preflight must enumerate the formula-risk items beside its five sibling categories",
        )
    }

    // ---- H23 (audit 2026-09-13) ----

    /**
     * The CSV preflight must show WHICH vaults the plaintext file spans and let the user leave
     * shared ones out (spec 07 intro, stated for both artifacts; web ExportPanel renders the rows
     * for both modes). The rows are ONE composable shared with the backup preflight — the copy
     * cannot drift between the two dialogs — and the write honours the selection.
     */
    @Test
    fun theCsvPreflightNamesEveryVaultAndHonoursTheOptOut() {
        val csv = mainActivity.substringAfter("private fun CsvPreflightDialog(").substringBefore("private fun NamedSkips(")
        assertTrue(
            csv.contains("ExportVaultRows(ui.csvVaults, ui.csvSelectedVaults) { vaultId, _ -> vm.csvToggleVault(vaultId) }"),
            "the CSV preflight must render the per-vault rows with the opt-out",
        )
        val backup = mainActivity.substringAfter("private fun BackupPreflightDialog(").substringBefore("private fun ExportVaultRows(")
        assertTrue(backup.contains("ExportVaultRows(pre.vaults, selected)"), "…the SAME rows the backup preflight renders")
        assertEquals(1, Regex("item\\(s\\), shared \\(").findAll(mainActivity).count(), "the shared-vault line is written once (inside ExportVaultRows), never re-inlined")
        val run = viewModel.substringAfter("fun csvRun(").substringBefore("private fun orderedDocs(")
        assertTrue(run.contains("val selected = _ui.value.csvSelectedVaults"), "the selection is read before the state is cleared")
        assertTrue(run.contains("orderedDocs(current, selected)"), "…and the write is filtered by it")
        assertTrue(viewModel.contains("filter { it.vaultId in selected }.map { it.vaultId }"), "orderedDocs filters vaultLines exactly as buildAndWriteBackup does")
    }

    // ---- F31 ----

    @Test
    fun everyPasswordSurfaceRendersThePatternWarning() {
        // MasterPasswordStrengthHints (enroll + the recovery reset leg, one shared composable)
        // and the backup-passphrase dialog. Both READ it — a computed warning nobody renders is
        // the defect, and the backup floor now runs on the pattern-aware score, so the refusal
        // is unexplainable without this sentence.
        assertEquals(
            2,
            Regex("Strength\\.patternWarning\\(").findAll(mainActivity).count(),
            "expected the pattern warning at the master-password hints AND the backup passphrase",
        )
        assertTrue(
            mainActivity.contains("pattern?.let { Text(it,"),
            "the backup dialog must render the pattern sentence, not just branch on it",
        )
    }

    // ---- H72 (audit 2026-09-13): every duplicate/staleness action states its outcome ----

    /**
     * Merge, "Keep this one", "Not duplicates", its Restore undo and Unsnooze all used to finish
     * in silence: the dialog closed, the cluster vanished, and nothing said that several logins
     * had just been moved to Deleted items. Web states each one. These pin the SENTENCES (web's,
     * verbatim) at the writes that produce them — a notice nobody sets is the defect.
     */
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
        // The two sentences said in more than one place are constants, not re-typed literals.
        assertEquals(
            1,
            Regex(Regex.escape("""internal const val BACK_ON_THE_LIST = "Back on the list."""")).findAll(viewModel).count(),
            "the unsnooze / restore sentence must live in exactly one place",
        )
        assertEquals(2, Regex("BACK_ON_THE_LIST").findAll(viewModel).count() - 1, "…and be USED by both the unsnooze and the restore path")
    }

    /**
     * The partial state is the one the old code lied about: the survivor IS saved before any
     * loser is removed, so a throw in the loser loop reported "Could not save — try again" over a
     * half-done merge. Pin the local catch AND that the sentence it sets is the named constant.
     */
    @Test
    fun aMergeThatFailsAfterTheSurvivorSaveNamesTheHalfDoneState() {
        val helper = viewModel.substringAfter("private fun runMergePlan(").substringBefore("\n    /** \"Keep this one\"")
        assertTrue(helper.contains("for (id in plan.loserIds) engine!!.remove(id)"), "the loser loop must be inside the helper")
        assertTrue(helper.contains("healthMessage = partial"), "a throw after the survivor save must set the partial sentence")
        assertTrue(
            viewModel.contains("""internal const val MERGE_DIDNT_FINISH ="""),
            "the partial-merge sentence is a named constant — it is the one most likely to be re-worded into a falsehood",
        )
        assertTrue(
            viewModel.contains("partial = MERGE_DIDNT_FINISH"),
            "…and the merge action must use it rather than the generic save error",
        )
    }

    // ---- H125 (audit 2026-09-13): the app can answer "which version are you on?" ----

    /**
     * The version must come from core's [io.silencelen.andvari.core.client.ANDVARI_CLIENT_VERSION]
     * — the same constant the wire header is built from, which verify.sh's lockstep check ties to
     * the gradle versionName — and never from a literal typed into a composable, which is how a
     * displayed version starts lying after a release. Both surfaces render the ONE line: Settings
     * (the place a user is sent to look) and the 426 wall (the place the version is being acted
     * on).
     */
    @Test
    fun theAppNamesItsOwnBuildOnSettingsAndOnTheUpgradeWall() {
        assertTrue(
            mainActivity.contains("""internal val VERSION_LINE = "andvari ${'$'}ANDVARI_CLIENT_VERSION · android""""),
            "the version line must interpolate core's constant, never a literal version",
        )
        assertEquals(
            2,
            Regex("\\bVERSION_LINE\\b").findAll(mainActivity).count() - 1,
            "both the Settings About card and the UpgradeRequiredScreen must render it",
        )
        val upgrade = mainActivity.substringAfter("private fun UpgradeRequiredScreen(").substringBefore("internal fun ErrorBar(")
        assertTrue(upgrade.contains("VERSION_LINE"), "the 426 wall must name the build it is calling too old")
        assertTrue(mainActivity.contains("AboutCard()"), "Settings must render the About card, not merely define it")
    }

    // ---- H123 (audit 2026-09-13): one sentence, both clients ----

    /**
     * G31 fixed the all-snoozed staleness empty state on web and on Android, and the two lanes
     * wrote two different sentences for the same state although the Android change cited "web's
     * twin". This is that drift as a gate: the pinned sentence is Android's (it names the control
     * the user has to tap), and the web twin must read identically, character for character.
     *
     * Cross-CLIENT on purpose — the drift this catches cannot be seen from inside one module.
     * A missing web checkout is tolerated (the Kotlin gate must not depend on the JS tree being
     * present); a web file that is present and DIFFERENT is the failure.
     */
    @Test
    fun theAllSnoozedEmptyStateReadsTheSameOnWebAndAndroid() {
        val sentence = "Every login is snoozed right now — Show snoozed to see them or bring one back early."
        assertTrue(healthScreen.contains("""Empty("$sentence")"""), "the Android empty state must render the pinned sentence")
        val web = listOf(File("../web/src/ui/Staleness.tsx"), File("web/src/ui/Staleness.tsx")).firstOrNull { it.isFile }
        if (web != null) {
            assertTrue(
                web.readText().contains(sentence),
                "web's all-snoozed empty state has drifted from Android's — one state, one sentence (H123)",
            )
        }
    }

    @Test
    fun theBreachCheckReachesASurfaceAUserCanSee() {
        // The seam (core Strength.breachCount) had ZERO production call sites. These are them:
        // the backup passphrase renders it inline, enrollment routes it into the root banner.
        assertTrue(mainActivity.contains("vm.breachWarning(candidate)"), "the backup dialog must run the breach check")
        assertTrue(mainActivity.contains("breachNote?.let { Text(it,"), "the backup dialog must RENDER the breach sentence")
        assertTrue(mainActivity.contains("BreachAdvisoryBanner(vm, ui)"), "the enrollment advisory needs a banner on screen")
        assertTrue(mainActivity.contains("ui.breachAdvisory ?: return"), "the banner must read the state the enroll check writes")
        assertTrue(viewModel.contains("checkEnrolledPasswordForBreach(a, password)"), "enrollOp must run the check once a session exists")
        assertTrue(viewModel.contains("Strength.breachCount("), "the check must go through the shared core seam")
    }
}
