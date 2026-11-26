package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * What looking at the drawn screens found (ScreenImagesTest), each pinned here; the images themselves are
 * the before and after.
 */
class LookedAtScreensTest {
    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    /** recovery-warning: "(https://vault.family.exampl" over "e)" in the title, on a small phone at the normal font. */
    @Test
    fun aWebAddressBreaksOnlyBetweenItsOwnParts() {
        val title = "Let the person who runs Family (https://vault.family.example) restore your account?"
        val shown = addressBreaks(title)
        val z = ZERO_WIDTH_SPACE
        assertTrue(shown.contains("(https://vault${z}.family${z}.example)"), shown)
        assertEquals(title, shown.replace(z.toString(), ""), "only break opportunities are added")
        assertEquals("https://vault${z}.andvaripass${z}.com${z}/l", addressBreaks("https://vault.andvaripass.com/l"))
        assertEquals("no address here. Nor here.", addressBreaks("no address here. Nor here."))
        assertEquals("⟦invited by: https://a${z}.example⟧", addressBreaks("⟦invited by: https://a.example⟧"), "a placeholder's bracket is not part of it")
        assertTrue(src("TrustUi.kt").contains("Text(addressBreaks(label.origin)"), "the instance's origin line breaks the same way")
    }

    /** kit-reveal at the largest font: the third group of each row was cut in two ("T_" over "vn"). */
    @Test
    fun theKitGroupsGoFewerToARowWhenThreeDoNotFit() {
        assertEquals(3, kitGroupsPerRow(availablePx = 1000, cellPx = 300, gapPx = 12))
        assertEquals(2, kitGroupsPerRow(availablePx = 700, cellPx = 300, gapPx = 12))
        assertEquals(1, kitGroupsPerRow(availablePx = 600, cellPx = 300, gapPx = 12))
        assertEquals(1, kitGroupsPerRow(availablePx = 100, cellPx = 300, gapPx = 12), "never none")
        assertTrue(src("KitScreens.kt").contains("KitGroupRows(groups, perRow)"))
    }

    /** locked-wrong-password: the lock screen said "⟦result without wording: VaultUnlockResult.WRONG_PASSWORD⟧". */
    @Test
    fun aWrongPasswordOnTheLockScreenIsSaidInWords() {
        val said = assertIs<UiText.Ph>(unlockWords(VaultUnlockResult.WRONG_PASSWORD, 0))
        assertEquals(Placeholder.UNLOCK_WRONG_PASSWORD, said.placeholder)
        assertFalse(said.shown().contains("VaultUnlockResult"))
    }

    /** vault-states: a vault a stranger offers, whose name is not known yet, was a row reading "—". */
    @Test
    fun aSharedVaultWithNoNameYetSaysSo() {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULT_STATES)
        val row = assertNotNull(assertNotNull(api.snapshot.account).vaults.firstOrNull { it.name == null }, "the scene has a nameless row")
        val name = vaultRowName(row)
        assertTrue(name != "—" && name == UiText.ph(Placeholder.VAULT_NAME_NOT_KNOWN_TITLE).shown(), name)
    }

    /** links: a link's time left read "time left (minutes:seconds): 3600". */
    @Test
    fun aLinksTimeLeftIsInMinutesAndSeconds() {
        assertEquals("60:00", countdownText(3_600_000))
        val links = src("LinksScreens.kt")
        assertTrue(links.contains("Placeholder.LINK_TIME_LEFT, countdownText(left)"))
        assertFalse(links.contains("(left / 1000).toString()"))
    }

    /** link-device-code: six digits and nothing saying what to do with them. */
    @Test
    fun theLinkCodeSaysWhereToTypeIt() {
        val screen = src("LinkAndRecoveryScreens.kt").substringAfter("fun LinkDeviceCodeScreen").substringBefore("\n}\n")
        assertTrue(screen.contains("Say(Placeholder.LINK_CODE_TYPE_THERE)"))
    }

    /**
     * vault-list, vault-empty, health, history: a row of buttons too wide for a small phone squeezed its last buttons
     * to a letter a line, and on the vault's home screen pushed the search field and every item out of sight.
     */
    @Test
    fun buttonRowsOnTheVaultScreensWrapInsteadOfSqueezing() {
        for (file in listOf("VaultItemsScreens.kt", "VaultHealthScreens.kt", "VaultTransferScreens.kt")) {
            assertFalse(src(file).contains("Row(horizontalArrangement = Arrangement.spacedBy("), "$file still has a squeezing button row")
        }
        val list = src("VaultItemsScreens.kt").substringAfter("private fun VaultItemsList").substringBefore("TransferButtons(c, state)")
        assertTrue(list.contains("ButtonRow {"))
        // members: the third button of a member's row (offer ownership) was squeezed to nothing and left a tall gap.
        val members = src("VaultScreens.kt").substringAfter("if (screen.canManage && m.who !is PersonName.You").substringBefore("VAULT_OFFER_OWNERSHIP")
        assertTrue(members.contains("ButtonRow {"))
        assertFalse(src("LinksScreens.kt").contains("        Row {\n            Quieter(UiText.ph(Placeholder.LINK_SHARE))"))
        assertTrue(src("TrustUi.kt").contains("FlowRow(horizontalArrangement"))
    }
}
