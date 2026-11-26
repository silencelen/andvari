package io.silencelen.andvari.app.trust

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The rest of the screens that follow the current app: vault health's three tabs, the export as a dialog, the
 * confirmation before an earlier version is restored; and where a name is not known, no sentence shows a dash in
 * quotes: the words that stand there go in without the sentence's quotes, as the shared code fills its own lines.
 */
class FollowsCurrentAppRestTest {
    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    private fun body(code: String, start: String) = code.substringAfter(start).substringBefore("\n}\n")

    // ---- vault health's tabs (the current app's HealthScreen: TabRow under the tiles) ----

    @Test
    fun healthHasTheCurrentAppsThreeTabsUnderTheTilesInItsOrder() {
        assertEquals(listOf(HealthTab.PASSWORDS, HealthTab.DUPLICATES, HealthTab.STALENESS), HealthTab.entries.toList())
        assertEquals(listOf(Placeholder.HEALTH_TAB_PASSWORDS, Placeholder.HEALTH_TAB_DUPLICATES, Placeholder.HEALTH_TAB_STALENESS), HealthTab.entries.map { it.label })
        val panel = body(src("VaultHealthScreens.kt"), "internal fun HealthPanel(")
        val tiles = panel.indexOf("HealthTiles(healthTiles(t))")
        val tabs = panel.indexOf("TabRow(selectedTabIndex = tab.ordinal)")
        assertTrue(tiles in 0 until tabs, "the tabs stand under the tiles")
        assertTrue("rememberSaveable { mutableStateOf(drawnTab ?: HealthTab.PASSWORDS) }" in panel, "Passwords first, as the current app opens")
        assertTrue("val drawnTab = LocalFirstVaultView.current?.healthTab" in panel, "another tab only in the screen images")
        for (each in listOf("HealthTab.PASSWORDS -> PasswordsTab(h)", "HealthTab.DUPLICATES -> DuplicatesTab(", "HealthTab.STALENESS -> StalenessList(")) assertTrue(each in panel, each)
        assertFalse("h.passwords.forEach" in panel || "h.duplicates.forEach" in panel, "one list on show at a time")
        val dupes = body(src("VaultHealthScreens.kt"), "private fun DuplicatesTab(")
        assertTrue("h.duplicates.forEach" in dupes && "h.notDuplicates" in dupes && "HEALTH_PUT_BACK" in dupes)
        assertTrue("h.passwords.forEach" in body(src("VaultHealthScreens.kt"), "private fun PasswordsTab("))
    }

    // ---- the export as a dialog (the current app's ExportDialogs) ----

    @Test
    fun theExportIsADialogOverTheScreenItWasAskedFrom() {
        val panel = src("VaultTransferScreens.kt").substringAfter("internal fun ExportPanel(").substringBefore("/** What writing an export file came to. */")
        assertTrue("AlertDialog(" in panel)
        assertTrue("onDismissRequest = { if (idle) c.closeExport() }" in panel, "the way out waits while a file is being made")
        val confirm = panel.substringAfter("confirmButton = {").substringBefore("dismissButton =")
        assertTrue("saver.launch(" in confirm && "ExternalExcursion.begin()" in confirm, "the main action picks where the file goes")
        assertTrue("c.closeExport()" in panel.substringAfter("dismissButton ="))
        assertTrue("verticalScroll(rememberScrollState())" in panel, "a long list of vaults scrolls inside the dialog")

        val vault = src("VaultItemsScreens.kt")
        assertFalse("exporting == null" in vault.substringAfter("val onList =").substringBefore("\n    //"), "the vault stays on show under it")
        assertFalse("exporting != null -> ExportPanel" in vault)
        assertTrue("exporting?.let { ExportPanel(c, it) }" in vault)
        val settings = body(src("VaultHome.kt"), "internal fun VaultBackupSection(")
        assertTrue(settings.indexOf("Second(UiText.ph(Placeholder.EXPORT_CSV)") < settings.indexOf("state.exporting?.let { exporting -> ExportPanel(c, exporting) }"), "Settings keeps its buttons under the dialog")
    }

    // ---- the confirmation before an earlier version is restored ("Restore this version?") ----

    @Test
    fun anEarlierVersionIsRestoredOnlyAfterItsConfirmation() {
        val history = body(src("VaultItemsScreens.kt"), "private fun HistoryView(")
        assertEquals(1, Regex("c\\.restoreItemVersion\\(").findAll(history).count())
        val dialog = history.substringAfter("restoring?.let { (rev, archivedAt) ->").substringBefore("if (!inline)")
        assertTrue("AlertDialog(" in dialog && "Placeholder.HISTORY_RESTORE_CONFIRM)" in dialog)
        assertTrue("Placeholder.HISTORY_RESTORE_CONFIRM_BODY, Dates.date(archivedAt)" in dialog, "it says which version replaces the current one")
        assertTrue("c.restoreItemVersion(h.itemId, rev)" in dialog.substringAfter("confirmButton"), "only its confirm restores")
        assertTrue("dismissButton = { TextButton(onClick = { restoring = null }) { Say(CopyKey.CANCEL) } }" in dialog)
        assertTrue("{ restoring = v.rev to v.archivedAtMs }" in history, "the row's Restore asks first")
    }

    // ---- a name that is not known ----

    @Test
    fun aNameIsQuotedOnceByItsSentenceAndTheWordsForAMissingOneStandUnquoted() {
        val missing = UiText.ph(Placeholder.VAULT_NAME_IN_LINE_NOT_KNOWN).shown()
        val named = ownershipOfferQuestion("Bo", "Trips").title.shown()
        assertTrue("“Trips”" in named && "““" !in named)
        val unnamed = ownershipOfferQuestion("Bo", null).title.shown()
        assertFalse("—" in unnamed || "“”" in unnamed, unnamed)
        assertTrue(missing in unnamed && "“$missing" !in unnamed && "$missing”" !in unnamed, unnamed)
        assertEquals(ownershipOfferQuestion("Bo", "").title.shown(), unnamed, "a blank name is not a name either")

        val members = UiText.phNamed(Placeholder.VAULT_MEMBERS_OF, vaultSlot(null)).shown()
        assertFalse("—" in members || "“$missing" in members, members)
        assertEquals(UiText.ph(Placeholder.VAULT_MEMBERS_OF, "Trips").shown(), UiText.phNamed(Placeholder.VAULT_MEMBERS_OF, vaultSlot("Trips")).shown())
    }

    @Test
    fun fillingNamesIsOnePassAndOnlyTheUnnamedSlotsLoseTheirQuotes() {
        assertEquals("Move “A” into a vault now", fillNames("Move “{0}” into “{1}” now", listOf("A", "a vault"), setOf(1)))
        assertEquals("“{1}” b", fillNames("“{0}” {1}", listOf("{1}", "b"), setOf(1)), "a value that reads {1} is copied")
        assertEquals(fillTemplate("“{0}” {1}", listOf("x", "y")), fillNames("“{0}” {1}", listOf("x", "y"), emptySet()))
        assertEquals("“{2}”", fillNames("“{2}”", listOf("x"), setOf(0)), "a slot with no value stays as it is")
    }

    @Test
    fun noScreenFillsADashForAMissingName() {
        for (f in File("src/main/kotlin/io/silencelen/andvari/app/trust").listFiles()!!) {
            val code = f.readText()
            for (line in code.lines()) {
                if ("?: \"—\"" in line) assertFalse(Regex("UiText\\.(approved|ph|of)\\(").containsMatchIn(line), "${f.name}: $line")
            }
        }
    }
}
