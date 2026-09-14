package io.silencelen.andvari.desktop

import io.silencelen.andvari.core.client.HouseholdCopy
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
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
    // H130: the packaging metadata is source too — the only place the shipped .deb/.msi fields are
    // decided, and (unlike the composables above) nothing else in the suite ever reads it.
    private val buildScript by lazy { sourceFile("build.gradle.kts").readText() }

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
        // R13: the backup build's per-attachment fetch — the last busy-holding leg, which this
        // test's own name claimed and did not cover (a stalled body held `busy` forever, twice).
        assertTrue(state.contains("bytes = withTimeoutOrNull(attachmentTimeoutMs(p.ref.size)) { runCatching { e.downloadAttachment(p.ref) }.getOrNull() }"), "the backup attachment fetch")
        assertFalse(state.contains("bytes = runCatching { e.downloadAttachment(p.ref) }.getOrNull()"), "an unbounded backup fetch is the R13 regression")
        // R18: no hand copy of core's batch size.
        assertFalse(state.contains("IMPORT_BATCH_ROWS"), "size the import budget off SyncEngine.SERVER_BATCH_MAX, never a mirrored constant")
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
        // R23: HouseholdCopy's contract — desktop "may say more (the log) but must not say less".
        assertTrue(DesktopState.CRYPTO_UNAVAILABLE_NOTICE.startsWith(HouseholdCopy.CRYPTO_UNAVAILABLE), "the desktop notice must open with core's sentence verbatim")
        assertTrue(DesktopState.CRYPTO_UNAVAILABLE_NOTICE.contains("diagnostic log"), "…and add the one thing only desktop has")
    }

    // ---- H80 (recheck R22): the KDF-upgrade re-wrap zeroizes MK / wrapKey ----
    //
    // This WAS a source pin on the desktop's inline re-key ("assert the fill(0)s are written where
    // Account.enroll writes them"). Audit H85 hoisted that routine into core KdfReKeyCore, and the
    // pin went with it — as a STRONGER one: core's KdfReKeyCoreTest records the live arrays through
    // a CryptoProvider and asserts they are actually zero afterwards, which no amount of reading
    // this module's text could prove. What is left for this file is the wiring, below.

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

    // ---- audit H130 (the shipped package metadata is real, not jpackage's "Unknown" defaults) ----

    @Test
    fun theNativePackageMetadataIsRealAndNotJpackagesDefaults() {
        // jpackage substitutes literal defaults for every field the build leaves unset, so the
        // 0.26.3 .deb shipped `Maintainer: silencelen <Unknown>`, `Categories=Unknown` and a
        // copyright file reading `License: Unknown` for a GPL-3.0-or-later program. There is no
        // cheap runtime assertion for this — building a .deb takes minutes and needs jpackage — so
        // the pin is on the DSL that produces it.
        val nd = buildScript.substringAfter("nativeDistributions {")
        assertTrue(
            nd.contains("""copyright = "Copyright (c) 2026 silencelen""""),
            "the deb/msi copyright line must be the owner's wording, verbatim",
        )
        assertTrue(
            nd.contains("""licenseFile.set(rootProject.file("LICENSE"))"""),
            "the GPLv3 text must be wired for BOTH targets (deb copyright body + the MSI licence page)",
        )
        // …and the file that line names has to exist, or the packaging task dies at the cut.
        assertTrue(
            listOf(File("../LICENSE"), File("LICENSE")).any { it.isFile },
            "licenseFile points at the repo-root LICENSE — it must be there",
        )

        val linux = nd.substringAfter("linux {").substringBefore("\n            }")
        assertTrue(
            linux.contains("""debMaintainer = "silencelen@users.noreply.github.com""""),
            "the deb needs a real maintainer address (SECURITY.md publishes no mailbox — this is the owner's fallback)",
        )
        // jpackage writes `Maintainer: <vendor> <<debMaintainer>>`. A display name here nests twice
        // and lintian still flags maintainer-address-malformed, so the field is address-ONLY.
        val maintainer = linux.substringAfter("debMaintainer = \"").substringBefore("\"")
        assertFalse(maintainer.contains("<"), "debMaintainer carries the bare address, never \"Name <addr>\": $maintainer")
        // DEPLOY_BUNDLE_CATEGORY → the freedesktop Categories= list, semicolon-TERMINATED.
        // R21: `Utility;` and nothing else. Registration was never the problem — the PAIRING was:
        // `Security` is an Additional Category whose Related Categories are `Settings;System`, so
        // `Utility;Security;` still trips desktop-file-validate. Pin the exact value, not a
        // substring, so re-adding an unpaired additional category goes red here.
        assertEquals(
            "Utility;",
            linux.substringAfter("menuGroup = \"").substringBefore("\""),
            "the .desktop entry must declare a registered, correctly PAIRED freedesktop category (not jpackage's Unknown, and not an Additional Category without its Related main one)",
        )
        // …and no VALUE may re-introduce the literal default (the comments above quote "Unknown"
        // on purpose, so strip the comment lines before looking).
        assertFalse(
            buildScript.replace(Regex("""(?m)^\s*//.*$"""), "").contains("Unknown"),
            "no packaging field may re-introduce the literal jpackage default",
        )
    }

    // ---- audit H129 (the pre-unlock width cap, desktop half — R18) ----

    /**
     * H129 shipped on the phone (`AuthWidthCapTest`) and its desktop half was assigned to a lane
     * that never ran, so the row was closed with a maximized window still rendering the sign-in,
     * master-password and recovery-phrase fields as ~760dp lines of input. This pins the cap AND
     * its number: 480dp is the ONE house cap for the auth family across the natives, read out of
     * Android's own source rather than re-typed, so the two can never drift into "the desktop
     * number" and "the phone number".
     */
    @Test
    fun thePreUnlockFamilyIsCappedAtTheHouseAuthWidth() {
        assertTrue(ui.contains("private val AUTH_MAX_WIDTH = 480.dp"), "the house 480dp auth cap")
        // Cross-canon: the same literal, taken from Android's declaration.
        val android = listOf(
            File("../app-android/src/main/kotlin/io/silencelen/andvari/app/MainActivity.kt"),
            File("app-android/src/main/kotlin/io/silencelen/andvari/app/MainActivity.kt"),
        ).firstOrNull { it.isFile }?.readText()
        if (android != null) {
            val phone = Regex("""private val AUTH_MAX_WIDTH = (\d+)\.dp""").find(android)?.groupValues?.get(1)
            assertEquals("480", phone, "Android's auth cap moved — the natives must settle on ONE number")
        }
        // Applied, not merely declared, and centred inside the Cut I column.
        assertTrue(ui.contains("Box(Modifier.widthIn(max = AUTH_MAX_WIDTH).fillMaxSize())"), "the cap must be applied")
        assertTrue(ui.contains("Box(Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter)"), "centred, not left-hugged")
        // Every pre-unlock screen is routed through it — at the DISPATCH site, so a new one
        // inherits the cap by being routed rather than by remembering to opt in.
        for (screen in listOf(
            "is DesktopScreen.Welcome -> AuthPane { Welcome(state) }",
            "is DesktopScreen.Unlock -> AuthPane { Unlock(state, s.email) }",
            "is DesktopScreen.RecoverySetup -> AuthPane { RecoverySetupScreen(state) }",
            "is DesktopScreen.RecoveryCapture -> AuthPane { RecoveryCaptureScreen(state) }",
            "is DesktopScreen.Recover -> AuthPane { RecoverScreen(state) }",
        )) {
            assertTrue(ui.contains(screen), "pre-unlock screen not capped: $screen")
        }
        // …and the LIST surfaces are deliberately NOT capped: they use a wide window.
        for (list in listOf("is DesktopScreen.Vault -> Vault(state)", "is DesktopScreen.Settings -> SettingsScreen(state)")) {
            assertTrue(ui.contains(list), "the list surfaces must keep the full 760dp column: $list")
        }
    }

    // ---- audit H66 (the provenance-gated rfp rule, desktop half) ----

    @Test
    fun aPastedEnrollLinksRfpNeverReachesTheEnrollmentPosture() {
        // The rule: an enroll link's rfp may raise the ceremony to required-affirm ONLY when the
        // channel that delivered it proves in-person handover (web's same-origin QR navigation).
        // Desktop takes invites by paste/typing only, so the rfp is dropped — this pin is what
        // makes "dropped" mechanical rather than a promise in a comment. EnrollLink.parse DOES
        // return an rfp, so a one-line "improvement" here would silently re-open the leg.
        assertEquals(
            0,
            Regex("""\brfp\b""").findAll(ui.replace(Regex("""(?m)^\s*//.*$"""), "")).count(),
            "no non-comment line in the desktop UI may read a link's rfp",
        )
        // The posture function is rfp-free BY SIGNATURE — the strongest form of the pin.
        assertTrue(
            state.contains("fun enrollPosture(memberHasSheet: Boolean): EnrollPosture"),
            "enrollPosture must take the sheet declaration and nothing else",
        )
        assertEquals(
            2,
            Regex("""enrollPosture\(hasSheet\)""").findAll(ui).count(),
            "both call sites (the button visual and the submit re-check) pass only the sheet flag",
        )
        // The rule's statement at the invite field is load-bearing: it is the walk-through a
        // reader of THIS surface needs, and both it and DesktopState's KDoc now point at the
        // statement of record — design 2026-07-15-multi-tenant-endpoints §4.4's correction block
        // (R22: they used to claim an Android citation that was never written).
        assertTrue(ui.contains("PROVENANCE-GATED, not surface-gated"), "the ratified rule must stay stated at the invite field")
        assertTrue(ui.contains("every paste-fed invite field MUST drop the rfp"), "…including the clause that binds the Android twin's field too")
        // R22: and the pointer to the statement of record, on both desktop canons — a rule binding
        // on every surface belongs in the design, not in whichever client's comment is longest.
        assertTrue(ui.contains("2026-07-15-multi-tenant-endpoints"), "the invite-field note must cite the ratified design")
        assertTrue(state.contains("2026-07-15-multi-tenant-endpoints"), "…and so must enrollPosture's KDoc")
    }

    // ---- audit H85 (the F61 re-key hoist, desktop half) ----

    @Test
    fun theKdfReKeyIsDelegatedToCoreAndNotInlinedHere() {
        // The routine that derives a new master key, re-wraps the UVK and calls
        // `PUT /account/password` lived here as a hand-copy of Android's, under a comment
        // justifying itself with "app-android is not shared" — a reason the G39 hoist had already
        // removed. It now lives once in core KdfReKeyCore (core/src/jvmShared compiles into both
        // the JVM and Android targets) and is exercised by core's KdfReKeyCoreTest; this pin is
        // the wiring that suite cannot see.
        assertTrue(state.contains("KdfReKeyCore.maybeUpgrade("), "runKdfUpgrade must delegate to core")
        for (marker in listOf("Keys.masterKey(", "Keys.wrapKey(", "Envelope.sealB64(", "PasswordChangeRequest(")) {
            assertTrue(
                !state.contains(marker),
                "$marker belongs to core KdfReKeyCore — the desktop must not carry a second re-key",
            )
        }
        // The desktop-side pieces core deliberately does not know about, in the persist lambda:
        // the §5.3 cache gate and the §4.2 per-origin namespace. Losing the gate would write
        // vault-derived material to a device that opted out of a durable cache; losing the write
        // would make the next OFFLINE unlock derive with stale params and fail as a wrong password.
        val adapter = state.substring(state.indexOf("KdfReKeyCore.maybeUpgrade(")).take(800)
        assertTrue(adapter.contains("durableCacheEnabled()"), "the persist lambda must keep the cache gate")
        assertTrue(
            adapter.contains("store.saveAccountKeys(originKey(baseUrl), userId, updated)"),
            "an allowed cache must be updated in THIS origin's namespace",
        )
        // A5 stays caller-side (core cannot know about the F58 flag): a live admin recovery temp
        // password must never be silently re-keyed away.
        val gate = state.substringBefore("KdfReKeyCore.maybeUpgrade(").takeLast(1200)
        assertTrue(gate.contains("if (mustChangePassword) return"), "A5: the desktop must refuse on a temp password")
    }
}
