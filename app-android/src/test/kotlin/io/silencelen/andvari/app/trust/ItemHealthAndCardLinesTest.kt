package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.content.FakeVaultContent
import io.silencelen.andvari.core.app.content.VaultContent
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * What a login's view and a card's view and editor show now, from the shared code, beside the current app's code for
 * the same thing: a login's health line (ItemHealthLine), a card's "expired" mark with Copy of the short date
 * (ExpiryRow), and the brand beside the card number while it is typed.
 */
class ItemHealthAndCardLinesTest {
    private fun open(): Pair<FakeVaultContent, VaultContent> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.LOCKED)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(api.snapshot)
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        m.onSnapshot(api.snapshot)
        return assertNotNull(api.fakeContent) to assertNotNull(m.content.value)
    }

    private val screens = File("src/main/kotlin/io/silencelen/andvari/app/trust/VaultItemsScreens.kt").readText()

    @Test
    fun aWeakReusedLoginSaysItsStrengthInTheErrorToneAndHowManyOthersReuseIt() {
        val (fake, c) = open()
        val bank = fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Bank", "me", "abc", "https://bank.example")
        fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Shop", "me", "abc", "https://shop.example")
        val line = assertNotNull(c.itemHealth()[bank])
        val marks = healthMarks(line)
        val strength = marks.first()
        assertEquals(Placeholder.ITEM_HEALTH_STRENGTH, (strength.first as UiText.Ph).placeholder)
        assertEquals(listOf(line.strength), (strength.first as UiText.Ph).args, "the shared code's word for its strength")
        assertTrue(line.weak && strength.second, "weak: the error tone")
        val reused = marks[1]
        // One other login: the line for one (copy page, PQ17), whose words carry the 1.
        assertEquals(Placeholder.HEALTH_REUSED_ONE, (reused.first as UiText.Ph).placeholder)
        assertTrue(reused.second)
        assertEquals(2, marks.size, "no breach mark before a check")
        assertEquals(Placeholder.ITEM_HEALTH_NO_USE_RECORD, (lastUsedLine(line) as UiText.Ph).placeholder, "no record is not \"never used\"")
    }

    @Test
    fun aStrongLoginOfItsOwnHasOnlyItsStrengthAndANoteHasNoLine() {
        val (fake, c) = open()
        val strong = fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Mail", "me", "x7#Qp!vR2m@Lw9zK", "https://mail.example")
        val note = fake.seedNote(FakeVaultContent.PERSONAL_VAULT_ID, "Wifi", "hello")
        val marks = healthMarks(assertNotNull(c.itemHealth()[strong]))
        assertEquals(1, marks.size)
        assertFalse(marks.single().second, "not weak: the quiet tone")
        assertNull(c.itemHealth()[note])
    }

    @Test
    fun theHealthLineStandsUnderTheKindLineOfALoginAsInTheCurrentApp() {
        val view = screens.substringAfter("private fun ItemDetailView(").substringBefore("\n}\n")
        val kind = view.indexOf("kindWords(d.type).shown(), d.card?.summary")
        val health = view.indexOf("if (d.type == \"login\") LoginHealthLine(c, state, d.itemId)")
        assertTrue(kind in 0 until health && health < view.indexOf("d.username?.let"))
        val line = screens.substringAfter("private fun LoginHealthLine(").substringBefore("\n}\n")
        assertTrue("c.itemHealth()[itemId]" in line && "remember(state, itemId)" in line, "asked once per state, never once per row")
        assertTrue("healthMarks(line)" in line && "lastUsedLine(line)" in line)
    }

    @Test
    fun anExpiredCardIsMarkedAndItsShortDateIsCopied() {
        val (fake, c) = open()
        val old = fake.seedCard(FakeVaultContent.PERSONAL_VAULT_ID, "Old card", "4111111111111111", "07", "2001")
        val new = fake.seedCard(FakeVaultContent.PERSONAL_VAULT_ID, "New card", "4111111111111111", "07", "2099")
        val half = fake.seedCard(FakeVaultContent.PERSONAL_VAULT_ID, "Half", "4111111111111111", "07", "")
        val o = assertNotNull(c.cardExpiry(old))
        assertTrue(o.expired)
        assertEquals("07/01", o.shortExpiry)
        assertFalse(assertNotNull(c.cardExpiry(new)).expired)
        assertNull(c.cardExpiry(half)?.shortExpiry, "a half-missing expiry is read only")

        val row = screens.substringAfter("private fun ExpiryRow(").substringBefore("\n}\n")
        assertTrue("if (expiry.expired)" in row && "Placeholder.ITEM_EXPIRED" in row && "colorScheme.error" in row)
        assertTrue("expiry.shortExpiry?.let" in row && "CopyButton(copied) { copy(short)" in row)
        val view = screens.substringAfter("private fun ItemDetailView(").substringBefore("\n}\n")
        assertTrue("c.cardExpiry(d.itemId)" in view && "ExpiryRow(expiry, clearSeconds)" in view)
    }

    @Test
    fun theCardNumbersLabelNamesTheBrandWhileItIsTyped() {
        val (_, c) = open()
        val plain = UiText.ph(Placeholder.ITEM_CARD_NUMBER).shown()
        assertEquals(plain, cardNumberLabel(c, ""), "no brand while nothing is known")
        val visa = cardNumberLabel(c, "4111 1111")
        val brand = assertNotNull(c.cardBrandOf("4111 1111"))
        assertEquals("$plain · $brand", visa)
        assertTrue(screens.contains("MaskedField(cardNumberLabel(c, number), number, digits = true)"))
    }

    @Test
    fun theThreeCallsAreContainedLikeEveryOther() {
        val guarded = File("src/main/kotlin/io/silencelen/andvari/app/trust/Contained.kt").readText()
        for (call in listOf("inner.cardBrandOf(number)", "inner.cardExpiry(itemId)", "inner.itemHealth()")) assertTrue(guarded.contains(call), call)
    }
}
