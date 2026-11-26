package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Sharing's body as the current app's: one card per section, the vaults first, each vault as the current app's row. */
class SharingBodyTest {
    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    @Test
    fun eachSectionIsACardOfItsOwnInTheCurrentAppsOrder() {
        val page = src("AccountScreens.kt")
        val sharing = page.substring(page.indexOf("SignedInPage.SHARING ->"), page.indexOf("SignedInPage.SETTINGS ->"))
        val order = listOf(
            "SettingsCard { SharedVaultsSection(", "SettingsCard { PeopleSection(", "SettingsCard { LinksSection(", "RecentlyDeletedVaultsSection(",
        ).map { sharing.indexOf(it) }
        assertTrue(order.all { it >= 0 } && order == order.sorted(), "$order")
        // The recently deleted vaults draw their own card (nothing at all while the vault is locked).
        val home = src("VaultHome.kt")
        val deleted = home.substring(home.indexOf("internal fun RecentlyDeletedVaultsSection"))
        assertTrue(deleted.indexOf("SettingsCard {") in 0 until deleted.indexOf("DeletedVaultsView("))
        // Inside a card a section's top is the card's frame, and its title is the card's title.
        for (f in listOf("VaultScreens.kt", "PeopleScreens.kt", "LinksScreens.kt")) {
            assertTrue(src(f).contains("style = sectionTitleStyle())"), f)
        }
    }

    @Test
    fun aVaultsOwnPageOpensOnAVaultThatIsThereAndFallsBackToTheListOtherwise() {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS)
        val account = assertNotNull(api.snapshot.account)
        val family = account.vaults.first { it.name == "Family" }
        assertEquals(family.vaultId, sharingVaultShown(account, family.vaultId)?.vaultId)
        assertNull(sharingVaultShown(account, null), "no page is open")
        assertNull(sharingVaultShown(account, "a-vault-deleted-on-another-device"), "a vault gone from the list shows the list")
    }

    @Test
    fun theListRowsOpenTheVaultsPageAndItsActionsAreThere() {
        val vaults = src("VaultScreens.kt")
        val list = vaults.substringAfter("internal fun SharedVaultsSection(").substringBefore("\n}\n")
        // The current app's row: a settings button on every shared vault's row, opening its page; no actions in the list.
        assertTrue(list.contains("SharedVaultRowHead(v) { onOpen(v.vaultId) }"))
        assertFalse(list.contains("VaultActions("), "the vault's actions are on its own page, as the current app's vault settings")
        // What the row says, and what waits for this person's answer, stay on the list.
        assertTrue(list.contains("VaultStateLines(v)") && list.contains("VaultAnswers(model, s, v)"))
        val page = vaults.substringAfter("internal fun SharedVaultSettings(").substringBefore("\n}\n")
        for (part in listOf("VaultSettingsHead(model, s, v)", "VaultStateLines(v, moveOfferedAbove = ","VaultAnswers(model, s, v)", "VaultActions(model, s, v)", "MembersView(", "MoveEverythingView(")) {
            assertTrue(page.contains(part), part)
        }
        // Each action that answers or changes something is on exactly one of the two.
        for (call in listOf("vaults.acceptOwnership(v)", "vaults.cancelOffer(v)", "vaults.deleteVault(v)", "vaults.leaveVault(v)", "vaults.restoreVault(v)", "vaults.openMembers(v)")) {
            assertEquals(1, Regex(Regex.escape(call)).findAll(vaults).count(), call)
        }
        // The top bar names the vault and its arrow, like the system Back, returns to the list before leaving Sharing.
        val shell = src("AccountScreens.kt")
        assertTrue(shell.contains("PageScaffold(UiText.Plain(vaultRowName(sharingVault)), onBack = { sharingVaultId = null })"))
        assertTrue(shell.contains("if (page == SignedInPage.SHARING && sharingVault != null) sharingVaultId = null else page = SignedInPage.VAULT"))
    }

    @Test
    fun aSharedVaultsSecondLineSaysItIsSharedAndTheRoleInIt() {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS)
        val vaults = assertNotNull(api.snapshot.account).vaults
        assertTrue(vaults.isNotEmpty())
        val shared = UiText.ph(Placeholder.LIST_SHARED_VAULT).shown()
        for (v in vaults) {
            val line = sharedVaultRoleLine(v)
            assertEquals(listOfNotNull(shared, v.role?.name?.lowercase()).joinToString(" · "), line)
        }
        assertTrue(vaults.any { it.role != null }, "the scene has a vault with a role")
    }
}
