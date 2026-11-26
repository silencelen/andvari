package io.silencelen.andvari.desktop

import io.silencelen.andvari.core.client.HouseholdCopy
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Source-level pins for the audit fixes that live inside `@Composable`s, where a pure-JVM suite cannot reach the
 * rendered output (this module has no Compose UI test runtime): parse the REAL shipped source, so a one-sided edit
 * fails `:app-desktop:test` rather than shipping.
 *
 * The onboarding and trust overhaul replaced the old screens (`Ui.kt`) and state holder (`DesktopState.kt`) with the
 * new path in `trust/`. The pins whose rule still applies to the desktop are re-pointed at the new screens: F28 (a
 * picked file read bounded, off the UI thread), F38 (every reveal named for its field), F08 (the CSV's formula cells
 * listed and acknowledged), F31 (the pattern warning rendered), H15 (the crypto self-check), H126 (About names the
 * log), H129 (the auth width cap), H130 (package metadata), and root cause C (no master-password-derived request).
 * The rest pinned code that moved into core (the KDF re-key, the trash reader gate, the bounded network legs, the
 * enrolment posture) or is gone with the old design (the reconcile prompt, the recovery phrase's clock).
 */
class SurfacePinsTest {

    private fun sourceFile(relative: String): File =
        listOf(File(relative), File("app-desktop/$relative")).firstOrNull { it.isFile }
            ?: error("could not locate $relative from ${File(".").absolutePath}")

    private fun trust(name: String) = sourceFile("src/main/kotlin/io/silencelen/andvari/desktop/trust/$name").readText()

    private val main by lazy { sourceFile("src/main/kotlin/io/silencelen/andvari/desktop/Main.kt").readText() }
    // H130: the packaging metadata is source too — the only place the shipped .deb/.msi fields are decided.
    private val buildScript by lazy { sourceFile("build.gradle.kts").readText() }

    /** Every shipped Kotlin file of the desktop. */
    private val allMain by lazy {
        listOf(File("src/main/kotlin"), File("app-desktop/src/main/kotlin")).first { it.isDirectory }.walkTopDown().filter { it.isFile && it.extension == "kt" }.map { it.readText() }.joinToString("\n")
    }

    // ---- F28 ----

    @Test
    fun aPickedFileIsReadBoundedOffTheUiThread() {
        val files = trust("DesktopFiles.kt")
        val vault = trust("VaultItemsScreens.kt") + trust("VaultTransferScreens.kt")
        assertFalse((files + vault).contains(".readBytes()"), "a pick must never be buffered before its cap is checked")
        assertTrue(files.contains("val declared = runCatching { file.length() }"), "the size is asked first")
        assertTrue(files.contains("FileInputStream(file).use { readAtMost(it, max, declared) }"), "and the read stops at the cap")
        assertTrue(vault.contains("withContext(Dispatchers.IO) { PickedFiles.read(file, attachmentRoom(d)) }"), "a file added, off the UI thread")
        assertTrue(vault.contains("withContext(Dispatchers.IO) { PickedFiles.read(file, CsvImport.MAX_BYTES.toLong()) }"), "a CSV, off the UI thread")
    }

    // ---- F38 ----

    @Test
    fun everyRevealControlIsNamedForItsField() {
        val ui = trust("TrustUi.kt")
        for (generic in listOf("\"show value\"", "\"hide value\"")) assertFalse(allMain.contains(generic), "a reveal control is named $generic")
        assertTrue(ui.contains("eyeButtonName(show, label).shown()"), "the secret field's toggle names its field")
        assertTrue(ui.contains("UiText.ph(if (shown) Placeholder.HIDE_FIELD_NAMED else Placeholder.SHOW_FIELD_NAMED, field.shown())"), "on keys that carry the name")
    }

    // ---- F08 ----

    @Test
    fun theCsvExportListsTheFormulaCellsAndWaitsForTheAcknowledgement() {
        val panel = trust("VaultTransferScreens.kt").substringAfter("internal fun ExportPanel(")
        assertTrue(panel.contains("v.formulaCells.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }"), "every formula cell is listed")
        assertTrue(panel.contains("Tick(UiText.Plain(ExportCopy.FORMULA_ACK), ack) { ack = it }"), "in the shared canon's acknowledgement")
        // The content re-checks the tick against what it writes (a vault that changed writes nothing).
        assertTrue(panel.contains("c.csvFile(ack)"))
    }

    // ---- F31 ----

    @Test
    fun everyPasswordSurfaceRendersThePatternWarning() {
        val hints = trust("TrustUi.kt").substringAfter("internal fun MasterPasswordStrengthHints(")
        assertTrue(hints.contains("if (pattern != null) Text(pattern,"), "the master-password hints render the pattern sentence")
        val backup = trust("VaultTransferScreens.kt").substringAfter("private fun PassphraseStrength(")
        assertTrue(backup.contains("pattern?.let { Text(it,"), "the backup passphrase renders it too")
        assertTrue(trust("VaultTransferScreens.kt").contains("PassphraseStrength(passphrase)"))
    }

    // ---- security review 2026-10, root cause C ----

    @Test
    fun noMasterPasswordDerivedRequestReachesTheServer() {
        for (needle in listOf("breachWarning", "checkEnrolledPasswordForBreach", "breachAdvisory", "Strength.breachCount(", "BREACHED_PASSWORD_WARNING", "breachNote")) {
            assertFalse(allMain.contains(needle), "the desktop must not carry the master-password breach path ($needle)")
        }
    }

    // ---- audit H15 ----

    @Test
    fun theStartupSelfCheckVerdictReachesTheScreen() {
        assertTrue(main.contains("val selfCheck = DesktopDiagnostics.runStartupSelfCheck()"), "main() must HOLD the verdict")
        assertTrue(main.contains("val cryptoUnavailable = if (selfCheck is SelfCheck.CryptoUnavailable) CRYPTO_UNAVAILABLE_NOTICE else null"))
        // Note N4 moved the build behind the damaged-state-file check: still no home and no engine without crypto.
        assertTrue(main.contains("val home = if (cryptoUnavailable == null) runCatching { DesktopHome() }"), "…and no engine is built without crypto")
        assertTrue(main.contains("val first = if (home != null && damaged.isEmpty()) build(home) else null"))
        assertTrue(main.contains("TrustApp(model, cryptoUnavailable, DesktopDiagnostics.logFile.absolutePath)"), "…and hand it to the root")
        assertTrue(trust("TrustApp.kt").contains("CryptoUnavailableScreen(cryptoUnavailable ?: \"\", diagnosticLogPath)"), "the blocking state must render, naming the log")
        // R23: HouseholdCopy's contract — desktop "may say more (the log) but must not say less".
        assertTrue(CRYPTO_UNAVAILABLE_NOTICE.startsWith(HouseholdCopy.CRYPTO_UNAVAILABLE), "the desktop notice must open with core's sentence verbatim")
        assertTrue(CRYPTO_UNAVAILABLE_NOTICE.contains("diagnostic log"), "…and add the one thing only desktop has")
    }

    // ---- audit H126 (the diagnostic log gets a door) ----

    @Test
    fun aboutNamesTheDiagnosticLog() {
        val about = trust("AboutDialog.kt").substringAfter("internal fun AboutDialog(")
        assertTrue(about.contains("Text(logPath,"), "About must name the file a support conversation will ask for")
        assertTrue(about.contains("SelectionContainer"), "…as selectable text, so it can be copied out")
        assertTrue(about.contains("openFolder(dir)"), "…with the folder button, since ~/.andvari-desktop is hidden by default")
        assertTrue(main.contains("AboutDialog(webVault, updateAvailable, DesktopDiagnostics.logFile.absolutePath, updateStatusLines("))
    }

    // ---- audit H130 (the shipped package metadata is real, not jpackage's "Unknown" defaults) ----

    @Test
    fun theNativePackageMetadataIsRealAndNotJpackagesDefaults() {
        val nd = buildScript.substringAfter("nativeDistributions {")
        assertTrue(nd.contains("""copyright = "Copyright (c) 2026 silencelen""""), "the deb/msi copyright line must be the owner's wording, verbatim")
        assertTrue(nd.contains("""licenseFile.set(rootProject.file("LICENSE"))"""), "the GPLv3 text must be wired for BOTH targets")
        assertTrue(listOf(File("../LICENSE"), File("LICENSE")).any { it.isFile }, "licenseFile points at the repo-root LICENSE — it must be there")
        val linux = nd.substringAfter("linux {").substringBefore("\n            }")
        assertTrue(linux.contains("""debMaintainer = "silencelen@users.noreply.github.com""""), "the deb needs a real maintainer address")
        val maintainer = linux.substringAfter("debMaintainer = \"").substringBefore("\"")
        assertFalse(maintainer.contains("<"), "debMaintainer carries the bare address, never \"Name <addr>\": $maintainer")
        // R21: `Utility;` and nothing else (an Additional Category without its Related main one trips desktop-file-validate).
        assertEquals("Utility;", linux.substringAfter("menuGroup = \"").substringBefore("\""))
        assertFalse(buildScript.replace(Regex("""(?m)^\s*//.*$"""), "").contains("Unknown"), "no packaging field may re-introduce the literal jpackage default")
    }

    // ---- audit H129 (the pre-unlock width cap, desktop half — R18) ----

    /**
     * 480dp is the ONE house cap for the auth family across the natives, read out of Android's own source rather than
     * re-typed, so the two can never drift; the signed-in pages keep the old list surfaces' wider 760dp column.
     */
    @Test
    fun thePreUnlockFamilyIsCappedAtTheHouseAuthWidth() {
        val ui = trust("TrustUi.kt")
        assertTrue(ui.contains("internal val TRUST_AUTH_MAX_WIDTH = 480.dp"), "the house 480dp auth cap")
        val android = listOf(
            File("../app-android/src/main/kotlin/io/silencelen/andvari/app/MainActivity.kt"),
            File("app-android/src/main/kotlin/io/silencelen/andvari/app/MainActivity.kt"),
        ).firstOrNull { it.isFile }?.readText()
        if (android != null) {
            val phone = Regex("""private val AUTH_MAX_WIDTH = (\d+)\.dp""").find(android)?.groupValues?.get(1)
            assertEquals("480", phone, "Android's auth cap moved — the natives must settle on ONE number")
        }
        val column = ui.substringAfter("internal fun AuthColumn(")
        assertTrue(column.contains("Box(Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter)"), "centred, not left-hugged")
        assertTrue(column.contains("Modifier.widthIn(max = TRUST_AUTH_MAX_WIDTH)"), "the cap must be applied")
        assertTrue(trust("AccountScreens.kt").contains("internal val SIGNED_IN_MAX_WIDTH = 760.dp"), "the signed-in pages keep the full 760dp column")
    }
}
