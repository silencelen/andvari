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
