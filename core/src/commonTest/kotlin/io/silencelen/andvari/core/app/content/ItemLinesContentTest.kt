package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.SecretField
import io.silencelen.andvari.core.client.Strength
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * What the current app shows on a row and in an item's view that the content now offers too: a login's health line, a
 * card's expiry with its "expired" mark and its short form for Copy, and the brand of a number being typed. Each is
 * built from what the device holds, with no call. Through the fake, whose controller is the real one.
 */
class ItemLinesContentTest {
    private val personal = FakeVaultContent.PERSONAL_VAULT_ID

    @Test
    fun aLoginsHealthLine_saysItsStrengthReuseAndLastUse_inOnePassForTheWholeVault() = runBlocking<Unit> {
        val c = FakeVaultContent()
        val a = c.seedLogin(personal, "A", "a", "hunter2", "")
        val b = c.seedLogin(personal, "B", "b", "hunter2", "")
        val strong = "correct-Horse-battery-staple-91!"
        val d = c.seedLogin(personal, "D", "d", strong, "")
        val note = c.seedNote(personal, "N", "text")
        val calls = c.syncCount

        val lines = c.itemHealth()
        assertEquals(setOf(a, b, d), lines.keys, "a login with a password has a line; a note has none")
        val la = lines.getValue(a)
        assertTrue(la.weak)
        assertEquals(1, la.reused)
        assertEquals(1, lines.getValue(b).reused)
        assertEquals(0, lines.getValue(d).reused)
        assertEquals(Strength.label(Strength.estimateStrength(strong)), lines.getValue(d).strength)
        assertFalse(lines.getValue(d).weak)
        assertNull(la.lastUsedAt, "never used")
        assertNull(la.breaches, "not checked")
        assertNull(lines[note])
        assertSame(lines, c.itemHealth(), "built once while nothing changed")
        assertEquals(calls, c.syncCount, "no call")

        assertNotNull(c.revealSecret(a, SecretField.PASSWORD))
        assertEquals(c.nowMs, c.itemHealth().getValue(a).lastUsedAt, "a use shows at once")
    }

    @Test
    fun aLoginWithoutAPassword_hasItsAgeAndLastUse_asTheCurrentAppsStalenessListShowsEveryLogin() = runBlocking<Unit> {
        val c = FakeVaultContent()
        val bare = c.seed(personal, io.silencelen.andvari.core.client.ItemDoc(type = "login", name = "Passkey site", login = io.silencelen.andvari.core.client.LoginData(username = "me"), notes = "uses a passkey"))
        val withPassword = c.seedLogin(personal, "A", "a", "hunter2", "")
        val note = c.seedNote(personal, "N", "text")
        val seededAt = c.nowMs
        val calls = c.syncCount

        assertNull(c.itemHealth()[bare], "the passwords list's line is for a login with a password")
        val ages = c.loginAges()
        assertEquals(setOf(bare, withPassword), ages.keys, "every login has its age; a note has none")
        val b = ages.getValue(bare)
        assertEquals(seededAt, b.changedAt, "last changed, by the server's clock")
        assertNull(b.lastUsedAt, "no use recorded")
        assertNull(b.checkedAt)
        assertEquals(io.silencelen.andvari.core.client.Staleness.StaleBucket.NEVER, b.stale)
        assertFalse(b.snoozed)
        assertNull(ages[note])
        assertSame(ages, c.loginAges(), "built once while nothing changed")
        assertEquals(calls, c.syncCount, "no call")

        c.nowMs = seededAt + 5_000
        assertNotNull(c.revealSecret(bare, SecretField.NOTES))
        assertEquals(seededAt + 5_000, c.loginAges().getValue(bare).lastUsedAt, "a use shows at once")
    }

    @Test
    fun aCardsExpiry_saysWhetherItIsOver_andGivesTheShortFormToCopy() {
        val c = FakeVaultContent()
        val old = c.seedCard(personal, "Old", "4111111111111111", "01", "2020")
        val fresh = c.seedCard(personal, "New", "4111111111111111", "12", "2099")
        val half = c.seedCard(personal, "Half", "4111111111111111", "07", "")
        val login = c.seedLogin(personal, "L", "l", "pw", "")

        val o = assertNotNull(c.cardExpiry(old))
        assertEquals("01/2020", o.label)
        assertTrue(o.expired)
        assertEquals("01/20", o.shortExpiry)
        val f = assertNotNull(c.cardExpiry(fresh))
        assertFalse(f.expired)
        assertEquals("12/99", f.shortExpiry)
        val h = c.cardExpiry(half)
        assertFalse(h?.expired ?: false)
        assertNull(h?.shortExpiry, "half an expiry has nothing to copy")
        assertNull(c.cardExpiry(login))
    }

    @Test
    fun theBrandOfANumberBeingTyped() {
        val c = FakeVaultContent()
        assertEquals("Visa", c.cardBrandOf("4111 1111 1111 1111"))
        assertEquals("Mastercard", c.cardBrandOf("5555 5555 5555 4444"))
        assertNull(c.cardBrandOf(""))
    }
}
