package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.Density
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.content.FakeVaultContent
import io.silencelen.andvari.core.client.items.VaultAccess
import io.silencelen.andvari.core.client.items.VaultStanding
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Three small faults: an item that may only be viewed is offered the copy to another vault, never the move; where a
 * name is not known no line shows a dash, nor quotes around the plain words that stand there; the prompts stand in the
 * current app's attention cards.
 */
class SmallFaultsTest {
    private val personal = FakeVaultContent.PERSONAL_VAULT_ID
    private val family = "00000000-0000-4000-8000-0000000000aa"
    private val dir = "src/main/kotlin/io/silencelen/andvari/desktop/trust/"
    private fun src(name: String) = File(dir + name).readText()
    private fun body(text: String, head: String) = text.substringAfter(head).substringBefore("\n}\n")

    // ---- an item that may only be viewed ----

    @Test
    fun anItemThatMayOnlyBeViewedIsOfferedTheCopyAloneNeverTheMove() {
        val c = FakeVaultContent().also {
            it.addSharedVault(family, "Family", VaultAccess.ROLE_READER, VaultStanding.VERIFIED)
            it.seedLogin(personal, "Bank", "ana", "made-up-1", "https://bank.test")
            it.seedLogin(family, "Wifi", "home", "made-up-2", "")
        }
        val wifi = assertNotNull(c.itemDetail(c.state.items.single { it.name == "Wifi" }.itemId))
        assertFalse(wifi.editable)
        assertFalse(canMoveItem(c, wifi), "a reader's item is never moved")
        assertTrue(c.moveTargets(wifi.itemId).isNotEmpty(), "it can be copied out")
        assertEquals(Placeholder.COPY_TO_ANOTHER_VAULT, moveOrCopyLabel(canMoveItem(c, wifi)), "its button names the copy alone")

        val bank = assertNotNull(c.itemDetail(c.state.items.single { it.name == "Bank" }.itemId))
        assertEquals(c.canMoveOut(bank.itemId), canMoveItem(c, bank), "an item that may be edited follows the content")
        assertEquals(Placeholder.MOVE_OR_COPY, moveOrCopyLabel(true))

        val view = body(src("VaultItemsScreens.kt"), "private fun MoveOrCopy(")
        assertTrue(view.contains("Quieter(UiText.ph(moveOrCopyLabel(canMove)))"), view)
        assertTrue(view.contains("val canMove = guardedRead(vault, false) { canMoveItem(c, d) }"))
        assertTrue(view.indexOf("val canMove") < view.indexOf("if (!open)"), "the button knows before it opens")
        assertTrue(view.contains("if (canMove) {") && view.contains("Placeholder.MOVE_TO_VAULT"), "the move only where it can be")
    }

    // ---- a name not known ----

    @Test
    fun aSlotThatHoldsPlainWordsLosesTheSentencesQuotesAndANameKeepsThem() {
        val t = "Members of “{0}”, from {1}"
        assertEquals("Members of “Family”, from Ada", fillTemplate(t, listOf("Family", "Ada")))
        assertEquals("Members of a vault, from Ada", fillTemplate(t, listOf("a vault", "Ada"), setOf(0)))
        // A name that itself reads like a slot is copied, never filled again.
        assertEquals("Members of “{1}”, from Ada", fillTemplate(t, listOf("{1}", "Ada")))
        // An unquoted slot is the same either way.
        assertEquals("from a vault", fillTemplate("from {0}", listOf("a vault"), setOf(0)))
    }

    @Test
    fun noLineShowsADashOrQuotedPlainWordsWhereANameIsNotKnown() {
        val plain = vaultSlot(null).text
        assertEquals(UiText.ph(Placeholder.VAULT_NAME_UNREADABLE).shown(), plain)
        assertFalse(vaultSlot(null).named)
        assertEquals(plain, vaultSlot("").text)
        fun check(line: UiText, what: String) {
            val shown = line.shown()
            assertFalse(shown.contains("—"), "$what: $shown")
            assertFalse(shown.contains("“$plain”"), "$what: $shown")
            assertTrue(shown.contains(plain), "$what: $shown")
        }
        check(UiText.phWith(Placeholder.VAULT_MEMBERS_OF, vaultSlot(null)), "members of")
        check(UiText.phWith(Placeholder.DELETION_BLOCKER_SHARED, vaultSlot(null), said("2")), "deletion blocker")
        check(UiText.Plain(ApprovedCopy.wordsWith("OWNERSHIP_OFFER.title", said("Bo"), vaultSlot(null))), "offer title")
        check(UiText.Plain(ApprovedCopy.lineWith("OWNERSHIP_OFFER.body", 1, said("Bo"), vaultSlot(null), said("1 Dec"))), "offer note")
        check(keyLineWith(CopyKey.MOVE_STOPPED, said("New"), vaultSlot(null), said("1"), said("3")), "a stopped move")
        // With the name known, the line shows it.
        assertTrue(UiText.phWith(Placeholder.VAULT_MEMBERS_OF, vaultSlot("Family")).shown().contains("Family"))
    }

    @Test
    fun theKeptAccountWithNoAddressAndATrashRowNoVersionOfWhichCanBeReadSayItInWords() {
        val api = FakeScenes.desktopAt(FakeScene.VAULTS)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
        api.script.sessionEndedByServer()
        m.signInAgain()
        val kept = assertNotNull(api.snapshot.keptSignedOut)
        val line = assertIs<UiText.Ph>(keptAccountLine(kept))
        assertEquals(Placeholder.KEPT_ACCOUNT_SIGN_OUT_FIRST, line.placeholder)
        assertEquals(kept.email, line.args.first(), "the address, where it is known")
        assertTrue(line.unnamed.isEmpty())

        val trash = body(src("VaultItemsScreens.kt"), "internal fun trashRowName(")
        assertTrue(trash.contains("else -> UiText.ph(Placeholder.TRASH_NAME_UNREADABLE)"), trash)
        val refusal = body(src("KeptAccountRefusal.kt"), "internal fun keptAccountLine(")
        assertTrue(refusal.contains("Placeholder.KEPT_ACCOUNT_UNNAMED") && refusal.contains("named = false"), refusal)
        // Nowhere in the desktop's screens does a dash stand in for a name.
        for (f in File(dir).listFiles()!!.filter { it.name.endsWith(".kt") }) {
            val text = f.readText()
            for (dash in listOf("?: \"—\"", "{ \"—\" }", "Plain(\"—\")")) assertFalse(text.contains(dash), "${f.name}: $dash")
        }
    }

    // ---- the prompts in attention cards ----

    @Test
    fun thePromptsStandInTheCurrentAppsAttentionCardsInACappedArea() {
        val section = body(src("PeopleScreens.kt"), "internal fun PromptsSection(")
        assertTrue(section.contains("heightIn(max = ATTENTION_AREA_MAX.dp).verticalScroll(rememberScrollState())"), section)
        assertTrue(section.contains("AttentionCard(p) { PromptView(model, s, p, openSharing, openRecovery) }"))
        assertFalse(section.contains("HorizontalDivider"), "no plain list with dividers")
        assertEquals(360, ATTENTION_AREA_MAX)
        val card = body(src("PeopleScreens.kt"), "internal fun AttentionCard(")
        assertTrue(card.contains("Card(") && card.contains("Column(Modifier.padding(16.dp))"), card)
        for (mark in listOf("border(", "drawBehind", "BorderStroke", "width(4")) assertFalse(card.contains(mark), "no edge marks: $mark")

        // Every scene with prompts draws them, inside a page that scrolls itself.
        var drawn = 0
        for (scene in listOf(FakeScene.PROMPTS, FakeScene.PROMPT_RECOVERY_KEY_CHANGED, FakeScene.PROMPT_KEEP_OPERATOR_RECOVERY, FakeScene.PROMPT_CONNECTION_NOT_MADE, FakeScene.PEOPLE_LIST)) {
            val api = FakeScenes.desktopAt(scene)
            val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
            val s = api.snapshot
            val prompts = assertNotNull(s.account).prompts
            assertTrue(prompts.isNotEmpty(), scene.name)
            val image = ImageComposeScene(480, 900, Density(1f)) {
                MaterialTheme { Surface { Column(Modifier.verticalScroll(rememberScrollState())) { PromptsSection(m, s, prompts) } } }
            }
            try {
                image.render()
            } finally {
                image.close()
            }
            drawn++
        }
        assertEquals(5, drawn)
    }
}
