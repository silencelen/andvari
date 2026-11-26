package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.layout.Column
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.unit.Density
import io.silencelen.andvari.core.app.content.FakeVaultContent
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * What the rows and the item view can show now that the shared code gives it: a login's health line under its row and
 * in its view, a card's "expired" mark and the short expiry to copy, and the brand beside the card number while it is
 * typed. Each is drawn as the current app draws the same thing.
 */
class ItemLinesTest {
    private val personal = FakeVaultContent.PERSONAL_VAULT_ID
    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/$name").readText()
    private fun body(text: String, head: String) = text.substringAfter(head).substringBefore("\n}\n")
    private val items = src("VaultItemsScreens.kt")

    private fun render(content: @androidx.compose.runtime.Composable () -> Unit) {
        val scene = ImageComposeScene(480, 400, Density(1f)) { MaterialTheme { Surface { Column { content() } } } }
        try {
            scene.render()
        } finally {
            scene.close()
        }
    }

    @Test
    fun aLoginsHealthLineStandsUnderItsRowAndInItsView() {
        val c = FakeVaultContent()
        val bank = c.seedLogin(personal, "Bank", "ana", "made-up shared one", "https://bank.test")
        val shop = c.seedLogin(personal, "Shop", "ana", "made-up shared one", "https://shop.test")
        val bare = c.seedLogin(personal, "No password", "ana", "", "")
        val note = c.seedNote(personal, "A note", "text")
        val health = c.itemHealth()
        val line = assertNotNull(health[bank])
        assertEquals(1, line.reused, "the other login with the same password")
        assertEquals(1, assertNotNull(health[shop]).reused)
        assertNull(health[bare], "a login without a password has no line")
        assertNull(health[note])
        render { HealthLine(line) }

        // The list reads the lines once and gives each login its own; a row shows it under its second line.
        val list = body(items, "private fun VaultItemsList(")
        assertTrue(list.contains("c.itemHealth()") && list.contains("ItemRow(item, sharedMark(item), health[item.itemId])"), list)
        val row = body(items, "private fun ItemRow(")
        assertTrue(row.indexOf("rowSecondLine(item)") < row.indexOf("HealthLine(it)") && row.contains("if (item.type == \"login\") health?.let { HealthLine(it) }"), row)
        // The view shows it under the kind and the vault, as the current phone app's view does.
        val view = body(items, "private fun ItemDetailView(")
        assertTrue(view.contains("c.itemHealth()[d.itemId]") && view.indexOf("c.vaultName(d.vaultId)") < view.indexOf("HealthLine(h)") && view.indexOf("HealthLine(h)") < view.indexOf("SecretRow(Placeholder.ITEM_PASSWORD"), view)
        // The current phone app's line: strength (the error tone when weak), reused and breaches in the error tone.
        val drawn = body(items, "internal fun HealthLine(")
        for (part in listOf("Placeholder.HEALTH_STRENGTH, h.strength", "if (h.weak) warn else quiet", "if (h.reused > 0)", "reusedLine(h.reused)", "Placeholder.HEALTH_BREACHED", "Placeholder.HEALTH_LAST_USED")) {
            assertTrue(drawn.contains(part), part)
        }
    }

    @Test
    fun aCardsExpiryIsMarkedWhenOverAndItsShortFormIsWhatCopyTakes() {
        val c = FakeVaultContent()
        val old = c.seedCard(personal, "Old card", "4242424242424242", "01", "2020")
        val fresh = c.seedCard(personal, "New card", "4242424242424242", "12", "2099")
        val half = c.seedCard(personal, "Half card", "4242424242424242", "", "2099")
        val over = assertNotNull(c.cardExpiry(old))
        assertTrue(over.expired)
        assertEquals("01/20", over.shortExpiry)
        val good = assertNotNull(c.cardExpiry(fresh))
        assertFalse(good.expired)
        assertEquals("12/99", good.shortExpiry)
        c.cardExpiry(half)?.let { assertNull(it.shortExpiry, "a half-missing expiry is read only"); assertFalse(it.expired) }
        render { ExpiryRow(over) {} }
        render { ExpiryRow(good) {} }

        // As the current app's row: the expiry, "expired" beside it only when it is over, then Copy of the short form.
        val row = body(items, "internal fun ExpiryRow(")
        assertTrue(row.indexOf("Text(e.label") < row.indexOf("if (e.expired)") && row.indexOf("if (e.expired)") < row.indexOf("Placeholder.ITEM_EXPIRED"), row)
        assertTrue(row.contains("e.shortExpiry?.let { short -> TextButton(onClick = guarded(onClick = { copy(short) }))"), row)
        val view = body(items, "private fun ItemDetailView(")
        assertTrue(view.contains("c.cardExpiry(d.itemId)") && view.contains("ExpiryRow(expiry, ::copy)"), view)
    }

    @Test
    fun theBrandStandsBesideTheCardNumberWhileItIsTyped() {
        val c = FakeVaultContent()
        assertNull(c.cardBrandOf(""))
        val visa = assertNotNull(c.cardBrandOf("4242 42"))
        assertEquals(Placeholder.ITEM_CARD_NUMBER, assertIs<UiText.Ph>(cardNumberLabel(null)).placeholder)
        val labelled = assertIs<UiText.Ph>(cardNumberLabel(visa))
        assertEquals(Placeholder.ITEM_CARD_NUMBER_BRAND, labelled.placeholder)
        assertEquals(listOf(visa), labelled.args)
        // The editor asks for the brand of what is typed, at each change, and labels the field with it.
        val editor = body(items, "private fun ItemEditor(")
        assertTrue(editor.contains("c.cardBrandOf(number)") && editor.contains("SecretField(cardNumberLabel(brand), number)"), editor)
    }
}
