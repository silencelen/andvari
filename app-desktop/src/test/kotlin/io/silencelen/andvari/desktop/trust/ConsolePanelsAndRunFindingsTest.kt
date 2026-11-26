package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.RoleInVault
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
 * The console's panel inside its list in the current app's style, and what the run on the virtual display found: the
 * opened invite stood above the links card's title, a vault this account only reads in was offered to share, and a
 * shared vault's role was the enum's name.
 */
class ConsolePanelsAndRunFindingsTest {
    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/$name").readText()
    private fun body(text: String, head: String) = text.substringAfter(head).substringBefore("\n}\n")

    @Test
    fun anAccountsPanelIsACardOfItsOwnUnderItsRow() {
        val panel = body(src("OperatorScreens.kt"), "private fun AccountPanel(")
        assertTrue(panel.contains("PanelCard {"), panel)
        val card = body(src("TrustUi.kt"), "internal fun PanelCard(")
        // The current app's settings card: a 16 dp margin, nothing at its edge.
        assertTrue(card.contains("Card(") && card.contains("padding(16.dp)"), card)
        assertFalse(card.contains("border(") || card.contains("drawBehind"), "no edge marks a state")
        // The header keeps no room for lines that are not there.
        val header = body(src("OperatorScreens.kt"), "private fun ConsoleHeader(")
        assertTrue(header.contains("CappedSlot(CONSOLE_HEADER_SLOT) {") && !header.contains("FixedSlot("), header)
        assertTrue(body(src("TrustUi.kt"), "internal fun CappedSlot(").contains("heightIn(max = max)"))
    }

    @Test
    fun theLinksCardsTitleComesBeforeWhatAPastedLinkOpened() {
        val links = body(src("LinksScreens.kt"), "internal fun LinksSection(")
        // Past the closed section's branch: the open card.
        val open = links.substringAfter("return ClosedSection(Placeholder.LINKS,")
        assertTrue(open.indexOf("SectionTitle(Placeholder.LINKS)") < open.indexOf("answers()"), open)
    }

    @Test
    fun onlyAVaultThisAccountOwnsIsOfferedOnAConnectLink() {
        val api = FakeScenes.desktopAt(FakeScene.VAULTS)
        val account = assertNotNull(api.snapshot.account)
        assertTrue(account.vaults.any { it.role == RoleInVault.WRITER }, "the fake has a vault this account writes in")
        val offered = shareableVaults(account)
        assertTrue(offered.isNotEmpty() && offered.all { it.role == RoleInVault.OWNER }, "${offered.map { it.role }}")
        assertTrue(body(src("LinksScreens.kt"), "internal fun LinksSection(").contains("for (v in shareableVaults(account))"))
    }

    @Test
    fun aSharedVaultsRoleIsSaidInWordsOfItsOwn() {
        val lines = RoleInVault.entries.map { assertIs<UiText.Ph>(roleLine(it)).placeholder }
        assertEquals(RoleInVault.entries.size, lines.toSet().size, "one line per role")
        assertEquals(listOf(Placeholder.VAULT_ROLE_OWNER, Placeholder.VAULT_ROLE_WRITER, Placeholder.VAULT_ROLE_READER), lines)
        val rows = body(src("VaultScreens.kt"), "internal fun SharedVaultsSection(")
        assertTrue(rows.contains("LetterHead(vaultRowName(v), v.role?.let { roleLine(it) })") && !rows.contains("name.lowercase()"), rows)
    }
}
