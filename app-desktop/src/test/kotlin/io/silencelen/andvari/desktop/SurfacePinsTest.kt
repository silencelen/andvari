package io.silencelen.andvari.desktop

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Source-level pins for the audit fixes that live inside `@Composable`s, where a pure-JVM suite
 * cannot reach the rendered output (this module has no Compose UI test runtime). Same idiom as
 * android's BrowserAllowlistLockstepTest: parse the REAL shipped source, so a one-sided edit
 * fails `:app-desktop:test` rather than shipping.
 *
 * `app-desktop/src/test/` had no accessibility assertion of any kind before this file — which is
 * how F38 happened: android's a11yand-09 rule ("name the button for ITS field") was written,
 * commented and pinned on the phone, and simply not carried across, on a card surface that
 * instantiates seven Copy buttons.
 *
 *  - F04: the delete confirm and the Trash header RENDER the shared attachment caveat.
 *  - F25: the TOTP enrollment rows copy as vault secrets, not through `copyPlain`.
 *  - F28: the attachment picker uses the bounded read, never `readBytes()`, and never the raw
 *    exception message.
 *  - F38: every Copy/reveal control is named for its own field.
 *  - F08 / F31: the export and strength warnings are RENDERED, not merely computed — both first
 *    shipped as core functions with no call site at all, which is why these pin the wiring.
 */
class SurfacePinsTest {

    private fun sourceFile(relative: String): File =
        listOf(File(relative), File("app-desktop/$relative")).firstOrNull { it.isFile }
            ?: error("could not locate $relative from ${File(".").absolutePath}")

    private val ui by lazy { sourceFile("src/main/kotlin/io/silencelen/andvari/desktop/Ui.kt").readText() }
    private val state by lazy { sourceFile("src/main/kotlin/io/silencelen/andvari/desktop/DesktopState.kt").readText() }
    private val main by lazy { sourceFile("src/main/kotlin/io/silencelen/andvari/desktop/Main.kt").readText() }

    // ---- F04 ----

    @Test
    fun trashAndDeleteSurfacesRenderTheSharedAttachmentCaveat() {
        assertEquals(
            2,
            Regex("HouseholdCopy\\.TRASH_RESTORE_NO_ATTACHMENTS").findAll(ui).count(),
            "expected the canon sentence at BOTH moments — the delete confirm and the Trash header",
        )
        assertTrue(
            !ui.contains("but not its attachments"),
            "the caveat is inlined as a literal — render HouseholdCopy.TRASH_RESTORE_NO_ATTACHMENTS instead",
        )
    }

    // ---- F25 ----

    @Test
    fun totpEnrollmentRowsCopyAsVaultSecrets() {
        // copyPlain never registers `lastSecretCopied`, so lock/sign-out/JVM-exit skip the value.
        // The account's second-factor seed is not setup material.
        assertEquals(0, Regex("CopyPlainRow\\(").findAll(ui).count(), "the TOTP rows must use CopySecretRow (copyWithAutoClear)")
        assertEquals(2, Regex("CopySecretRow\\(").findAll(ui).count() - 1, "expected exactly the two TOTP rows (plus the definition)")
        // copyPlain itself stays — for the genuinely non-secret /downloads link + server address.
        assertEquals(2, Regex("copyPlain\\(").findAll(ui).count(), "copyPlain should remain ONLY on the non-secret rows")
    }

    // ---- F28 ----

    @Test
    fun attachmentPickerReadsBoundedOffTheUiThreadAndUsesCanonCopy() {
        assertTrue(!ui.contains(".readBytes()"), "the picker must not buffer a pick before checking the cap")
        assertTrue(ui.contains("readBounded(it, cap)"), "expected the shared bounded read")
        assertTrue(ui.contains("withContext(Dispatchers.IO)"), "the read must not run on the Compose thread")
        assertTrue(
            !ui.contains("Couldn't read \$picked"),
            "#23: a local read failure takes HouseholdCopy.forImportError, never the raw exception text",
        )
    }

    // ---- F38 (a11ydesk-09) ----

    @Test
    fun everyCopyAndRevealControlIsNamedForItsField() {
        // The generic names the audit found: seven controls all reading "Copy", two reveals all
        // reading the same thing. Both generic reveal literals must be gone from the CODE.
        for (generic in listOf("\"show value\"", "\"hide value\"")) {
            assertEquals(0, Regex("Icon\\([^\n]*$generic").findAll(ui).count(), "a reveal control is still named $generic instead of its field")
        }
        // CopyRow's reveal and the editor's Secret field, both named for their own field.
        // Plain substring, not a Regex: the pattern contains a literal `$` (the Kotlin template
        // in the source), and an unescaped `$` in a Regex is an anchor that silently matches
        // nothing — a green-by-accident shape this file exists to avoid.
        val reveal = "if (show) \"Hide \$label\" else \"Show \$label\""
        assertEquals(2, ui.split(reveal).size - 1, "every reveal toggle must name its field")
        // CopyRow, CopySecretRow, and the inline expiry copy — every Copy button on a card.
        val named = Regex("""contentDescription = "Copy [^"]+"""").findAll(ui).count()
        assertEquals(3, named, "expected CopyRow + CopySecretRow + the inline Expiry copy to be named")
    }

    // ---- F08 ----

    @Test
    fun theCsvPreflightRendersTheFormulaRiskRow() {
        // ExportCsv.warnings() computes formulaRisk for every export; the dialog is the ONLY
        // place a user can ever learn about it (the writer deliberately mangles nothing).
        assertTrue(
            ui.contains("NamedSkips(ExportCsv.FORMULA_WARNING, pre.warnings.formulaRisk)"),
            "the CSV preflight must enumerate the formula-risk items beside its five sibling categories",
        )
    }

    // ---- F31 ----

    @Test
    fun everyPasswordSurfaceRendersThePatternWarning() {
        // MasterPasswordStrengthHints (enroll + the recovery reset leg, now one composable) and
        // the backup-passphrase dialog. The backup floor runs on the pattern-aware score, so
        // without this sentence its refusal cannot be explained to the person it refuses.
        assertEquals(
            2,
            Regex("Strength\\.patternWarning\\(").findAll(ui).count(),
            "expected the pattern warning at the master-password hints AND the backup passphrase",
        )
        assertTrue(
            ui.contains("pattern?.let { Text(it,"),
            "the backup dialog must render the pattern sentence, not just branch on it",
        )
    }

    @Test
    fun theBreachCheckReachesASurfaceAUserCanSee() {
        // The seam (core Strength.breachCount) had ZERO production call sites. These are them:
        // the backup passphrase renders it inline, enrollment routes it into the root banner.
        assertTrue(ui.contains("state.breachWarning(candidate)"), "the backup dialog must run the breach check")
        assertTrue(ui.contains("breachNote?.let { Text(it,"), "the backup dialog must RENDER the breach sentence")
        assertTrue(ui.contains("state.breachAdvisory?.let"), "the enrollment advisory needs a banner on screen")
        assertTrue(state.contains("checkEnrolledPasswordForBreach(a, password)"), "enrollOp must run the check once a session exists")
        assertTrue(state.contains("Strength.breachCount("), "the check must go through the shared core seam")
    }

    // ---- audit H10 (G10's remaining legs) ----

    @Test
    fun everyBusyHoldingNetworkLegIsBounded() {
        // op() itself: the flat bound every op{} site inherits (sign-in, unlock, enroll, delete,
        // rename, the transfer/leave/restore ops, Trash restore/purge, …).
        assertTrue(state.contains("withTimeoutOrNull(timeoutMs) { block() }"), "op() must run its block under the bound")
        // The byte-carrying legs the audit named, each scaled over the bytes it moves.
        assertTrue(state.contains("withTimeoutOrNull(uploadsTimeoutMs(uploads))"), "save-with-uploads")
        assertTrue(state.contains("withTimeoutOrNull(attachmentTimeoutMs(current.doc.attachments.sumOf { it.size }))"), "the move/copy gesture, sized from the SOURCE item's attachments")
        assertTrue(state.contains("withTimeoutOrNull(importTimeoutMs(plan.items.size))"), "the CSV import push")
        assertTrue(state.contains("e.copyAllToPersonal(vaultId)") && state.contains("InterruptedIOException(\"rescue copy timed out\")"), "the bulk rescue copy")
        // …and G10's own download keeps its inner bound (the outer op bound sits one window above it).
        assertTrue(state.contains("withTimeoutOrNull(attachmentTimeoutMs(ref.size)) { engine!!.downloadAttachment(ref) }"))
    }

    // ---- audit H12 ----

    @Test
    fun theRecoverySecretHasAClockAndTheExpiryHasASurface() {
        assertTrue(state.contains("armRecoverIdleWatch() // H12"), "verify-accept must arm the CR-02 watcher")
        assertTrue(state.contains("recoverIdleJob?.cancel(); recoverIdleJob = null"), "every exit of the flow must stop it")
        // The expiry lands on Unlock when a session exists — which composed no notice bar before.
        for (screen in listOf("private fun Welcome(", "private fun Unlock(")) {
            val body = ui.substringAfter(screen).substringBefore("\n@Composable")
            assertTrue(body.contains("NoticeBar(state.notice, state::clearNotice)"), "$screen must render the notice the expiry sets")
        }
    }

    // ---- audit H15 ----

    @Test
    fun theStartupSelfCheckVerdictReachesTheScreen() {
        assertTrue(main.contains("val selfCheck = DesktopDiagnostics.runStartupSelfCheck()"), "main() must HOLD the verdict")
        assertTrue(main.contains("it.applySelfCheck(selfCheck)"), "…and hand it to the state before start()")
        assertTrue(ui.contains("state.cryptoUnavailable?.let { msg ->"), "the blocking state must render (426 idiom)")
        assertTrue(ui.contains("state.diagnosticLogPath"), "…naming the log that holds the diagnosis")
        assertTrue(state.contains("if (isNativeCryptoLoadFailure(t)) {"), "op()'s belt for a load failure that first surfaces mid-session")
    }

    // ---- audit H23 (spec 07 intro — both artifacts get the per-vault opt-out) ----

    @Test
    fun theCsvPreflightNamesEveryVaultAndHonoursTheOptOut() {
        val csv = ui.substringAfter("private fun CsvPreflightDialog(")
        assertTrue(csv.contains("item(s), personal"), "the personal vault line")
        assertTrue(csv.contains("item(s), shared (${'$'}{v.role})"), "one opt-out row per shared vault, in the backup dialog's words")
        assertTrue(csv.contains("Checkbox(v.vaultId in selected, onCheckedChange = null)"), "…as a real toggle, not a label")
        assertTrue(ui.contains("state.csvRun(dest, selected)"), "the selection must reach the writer")
        assertTrue(state.contains("fun csvRun(dest: File, selectedVaults: Set<String>)"))
        assertTrue(state.contains("filter { it in selectedVaults }"), "csvRun must FILTER by the selection, never re-enumerate every held vault")
        assertTrue(state.contains("fun csvPreflightFor(selected: Set<String>)"), "the count/skip lines recompute for the selection")
    }

    // ---- audit H126 (the diagnostic log gets a door) ----

    @Test
    fun aboutNamesTheDiagnosticLog() {
        val about = ui.substringAfter("private fun AboutDialog(").substringBefore("\n@Composable")
        assertTrue(about.contains("state.diagnosticLogPath"), "About must name the file a support conversation will ask for")
        assertTrue(about.contains("SelectionContainer"), "…as selectable text, so it can be copied out")
        assertTrue(about.contains("openFolder(dir)"), "…with the folder button, since ~/.andvari-desktop is hidden by default")
        // The claim on screen must be the one the code enforces (H58's allowlist), not a softer one.
        assertTrue(about.contains("never anything from your vault"), "About must say what the log does NOT hold")
    }

    // ---- audit H127 (one Trash reader-gate treatment across all three clients) ----

    @Test
    fun theTrashReaderGateMatchesWebAndAndroid() {
        val trash = ui.substringAfter("val deleted = state.deletedItems").substringBefore("confirmPurgeId?.let")
        // web Vault.tsx:1419 / android MainActivity:2527 — the suffix on the deleted line…
        assertTrue(
            trash.contains("+ (if (reader) \" · view only\" else \"\")"),
            "the deleted line must carry the shared \" · view only\" suffix",
        )
        // …and the buttons REMOVED, not disabled (android MainActivity:2546 `if (!readOnly) {`).
        assertTrue(trash.contains("if (!reader) {"), "Restore/Delete forever must be hidden from a reader, not greyed out")
        assertTrue(
            !trash.contains("!state.busy && !reader"),
            "a disabled-but-visible control is the treatment H127 replaced",
        )
        // The desktop-only sentence is no longer RENDERED anywhere (it survives above only as the
        // comment explaining what it was replaced with, which is why this looks for a Text call).
        assertEquals(
            0,
            Regex("""Text\(\s*"view only""").findAll(ui).count(),
            "the desktop-only sentence is gone — the suffix is the whole copy now",
        )
    }

    // ---- audit H128 (the destructive choice is not the dismiss path) ----

    @Test
    fun theLaunchReconcilePromptDoesNotDiscardOnEscapeAndNamesWhatDiscardKeeps() {
        val dialog = ui.substringAfter("private fun PendingReconcileDialog(").substringBefore("\n@Composable")
        val onDismiss = dialog.substringAfter("onDismissRequest = {").substringBefore("}")
        assertTrue(
            !onDismiss.contains("discardPendingReconcile"),
            "Escape / click-away must not take the destructive branch: $onDismiss",
        )
        // Exactly one caller left — the explicit button.
        assertEquals(
            1,
            Regex("discardPendingReconcile\\(\\)").findAll(dialog).count(),
            "discard must be reachable only from the button the user chose",
        )
        assertTrue(
            dialog.contains("Text(\"Discard — stay on \${state.baseUrl}\")"),
            "the discard label must name the server the user ends up on (android's 'Discard — return to …')",
        )
    }
}
