package io.silencelen.andvari.app.trust

import io.silencelen.andvari.app.ThemeMode
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Settings' first cards and the import's sheet follow the current app: the account ID where its identity code is, the
 * server as a card of its own, appearance (Auto, Light, Dark), and the sheet that comes before the file picker.
 */
class SettingsAndImportFollowCurrentAppTest {
    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    private fun body(file: String, start: String): String = src(file).substringAfter(start).substringBefore("\n}\n")

    @Test
    fun settingsOpensWithTheAccountIdThenTheServerThenAppearanceEachACard() {
        val page = body("AccountScreens.kt", "private fun AccountSettingsPage(")
        val id = page.indexOf("SettingsCard { AccountIdCard(account) }")
        val server = page.indexOf("s.instance?.let { SettingsCard { ServerSection(model, s, it) } }")
        val look = page.indexOf("SettingsCard { AppearanceSection() }")
        val rest = page.indexOf("SettingsSections(model, s, account)")
        assertTrue(id in 0 until server && server < look && look < rest, "the current app's order: identity, server, appearance, then the rest")
        assertFalse("CopyKey.KIT_ACCOUNT_ID" in page, "the ID is no longer a small line above the cards")
        val serverCard = body("AccountScreens.kt", "private fun ServerSection(")
        assertTrue("Say(Placeholder.SERVER_SECTION, style = sectionTitleStyle())" in serverCard, "a card's title, as the others")
        assertTrue("SelectionContainer { InstanceName(" in serverCard, "the address can be selected, as in the current app")
    }

    @Test
    fun theAccountIdIsEightGroupsOfFourOnTwoLines() {
        val id = "5848752dca15f5b5e58e860bb75108ba"
        assertEquals("5848 752d ca15 f5b5\ne58e 860b b751 08ba", accountIdGroups(id))
        val card = body("SettingsScreens.kt", "internal fun AccountIdCard(")
        assertTrue("SelectionContainer {" in card && "FontFamily.Monospace" in card && "titleMedium" in card)
        assertTrue("Placeholder.ACCOUNT_ID_TITLE" in card && "Placeholder.ACCOUNT_ID_LINE" in card)
    }

    @Test
    fun appearanceOffersAutoLightAndDarkAndSetsTheDevicesChoice() {
        assertEquals(3, ThemeMode.entries.map { appearanceLabel(it) }.toSet().size, "each choice has its own label")
        val card = body("SettingsScreens.kt", "internal fun AppearanceSection(")
        assertTrue("selectable(selected = mode == m, role = Role.RadioButton, onClick = { io.silencelen.andvari.app.ThemePref.set(context, m) })" in card)
        assertTrue("RadioButton(selected = mode == m, onClick = null)" in card, "the row is the one target, as in the current app")
    }

    @Test
    fun everyAutofillWindowScrollsSoItsButtonsAreReachableAtTheLargestFont() {
        val dir = File("src/main/kotlin/io/silencelen/andvari/app/autofill")
        for ((file, start) in listOf(
            "AppFillConfirmActivity.kt" to "internal fun ConfirmCard(",
            "CardFillConfirmActivity.kt" to "internal fun CardConfirmCard(",
            "TrustBrowserActivity.kt" to "internal fun TrustCard(",
            "AutofillUnlockActivity.kt" to "internal fun UnlockCard(",
        )) {
            val card = File(dir, file).readText().substringAfter(start).substringBefore("\n}\n")
            assertTrue(Regex("Modifier\\.fillMaxSize\\(\\)[^\\n]*\\.verticalScroll\\(").containsMatchIn(card), "$file: the window's column scrolls")
        }
    }

    @Test
    fun theImportStartsWithItsSheetAndOnlyChooseFileOpensThePicker() {
        val actions = body("VaultTransferScreens.kt", "internal fun rememberTransferActions(")
        assertTrue("importCsv = { asking.value = true }" in actions, "the import button opens the sheet")
        assertEquals(1, Regex("picker\\.launch\\(").findAll(actions).count())
        val choose = actions.substringAfter("onChoose = {").substringBefore("onCancel =")
        assertTrue("picker.launch(" in choose && "asking.value = false" in choose, "only the sheet's choose-file opens the picker")
        val sheet = body("VaultTransferScreens.kt", "internal fun ImportSourceDialog(")
        assertTrue("Say(UiText.ph(Placeholder.IMPORT_PLAIN_TEXT), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)" in sheet)
        assertTrue("ImportHelp.SOURCES" in sheet && "Placeholder.IMPORT_CHOOSE_FILE" in sheet && "Say(CopyKey.CANCEL)" in sheet)
        assertTrue("Column(Modifier.verticalScroll(rememberScrollState()))" in sheet, "it scrolls at the largest font")
    }
}
