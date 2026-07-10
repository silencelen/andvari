package io.silencelen.andvari.core.client

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Web-parity pins for [CardDisplay] — the same expectations web/src/vault/card.test.ts
 *  puts on the display half of card.ts, so a card renders identically on every client.
 *  (Value canonicalization is vector-pinned separately in CardNormalizeVectorTest.) */
class CardDisplayTest {
    private fun doc(card: CardData? = null) = ItemDoc(type = "card", name = "x", card = card)

    @Test
    fun brandLabel_matchesWeb() {
        assertEquals("Visa", CardDisplay.brandLabel("visa"))
        assertEquals("Mastercard", CardDisplay.brandLabel("mastercard"))
        assertEquals("Amex", CardDisplay.brandLabel("amex"))
        assertEquals("Discover", CardDisplay.brandLabel("discover"))
        assertNull(CardDisplay.brandLabel(null))
        assertNull(CardDisplay.brandLabel("somefutureco"))
    }

    @Test
    fun groupNumber_fourBlocks_amex465_partialsGroupSanely() {
        assertEquals("4242 4242 4242 4242", CardDisplay.groupNumber("4242424242424242"))
        assertEquals("3782 822463 10005", CardDisplay.groupNumber("378282246310005")) // amex
        assertEquals("4917 6100 0000 0000 003", CardDisplay.groupNumber("4917610000000000003")) // 19-digit
        assertEquals("4242 4", CardDisplay.groupNumber("42424"))
        assertEquals("3782 822", CardDisplay.groupNumber("3782822")) // partial amex — progressive 4-6-5
        assertEquals("3782", CardDisplay.groupNumber("3782")) // no empty trailing groups
        assertEquals("4111 1111 1111 1111", CardDisplay.groupNumber("4111 1111-1111.1111")) // raw editor text
        assertEquals("", CardDisplay.groupNumber(""))
    }

    @Test
    fun maskedLast4_showsAtMostTheLastFourDigits() {
        assertEquals("••4242", CardDisplay.maskedLast4("4242424242424242"))
        assertEquals("••005", CardDisplay.maskedLast4("005")) // fewer than 4 → all shown
        assertEquals("••", CardDisplay.maskedLast4(""))
        assertEquals("••1111", CardDisplay.maskedLast4("4111 1111-1111.1111")) // sanitized first
    }

    @Test
    fun subtitle_fallsBackGracefully() {
        assertEquals("Visa ••4242", CardDisplay.subtitle(doc(CardData(number = "4242424242424242"))))
        assertEquals("Amex ••0005", CardDisplay.subtitle(doc(CardData(number = "378282246310005"))))
        assertEquals("Card ••1111", CardDisplay.subtitle(doc(CardData(number = "9792111111111111")))) // unknown IIN
        assertEquals("card", CardDisplay.subtitle(doc(CardData(cardholderName = "B")))) // no number
        assertEquals("card", CardDisplay.subtitle(doc(CardData())))
        assertEquals("card", CardDisplay.subtitle(doc(null)))
        // The STORED brand is display-only and never trusted — a stale value must not leak through.
        assertEquals("Visa ••4242", CardDisplay.subtitle(doc(CardData(number = "4242424242424242", brand = "discover"))))
    }

    @Test
    fun expiryLabel_rendersMissingHalvesAsDash_nullWhenNeitherSet() {
        assertEquals("12/2027", CardDisplay.expiryLabel(CardData(expMonth = "12", expYear = "2027")))
        assertEquals("12/—", CardDisplay.expiryLabel(CardData(expMonth = "12")))
        assertEquals("—/2027", CardDisplay.expiryLabel(CardData(expYear = "2027")))
        assertNull(CardDisplay.expiryLabel(CardData()))
        assertNull(CardDisplay.expiryLabel(null))
        assertNull(CardDisplay.expiryLabel(CardData(expMonth = "", expYear = ""))) // empty == unset (web falsy parity)
    }

    // ---- isExpired: expired strictly AFTER the last moment of the expiry month ----

    @Test
    fun isExpired_monthBoundaries() {
        assertFalse(CardDisplay.isExpired("06", "2027", 2027, 6)) // its own month — still valid
        assertTrue(CardDisplay.isExpired("06", "2027", 2027, 7)) // first month after — expired
        assertFalse(CardDisplay.isExpired("06", "2027", 2027, 1))
        assertTrue(CardDisplay.isExpired("01", "2020", 2027, 1))
        assertFalse(CardDisplay.isExpired("01", "2099", 2027, 1))
    }

    @Test
    fun isExpired_decemberRollsOverIntoTheNextYear() {
        assertFalse(CardDisplay.isExpired("12", "2027", 2027, 12))
        assertTrue(CardDisplay.isExpired("12", "2027", 2028, 1))
    }

    @Test
    fun isExpired_twoDigitYearsPivotLikeYearTo4() {
        assertFalse(CardDisplay.isExpired("12", "27", 2027, 12))
        assertTrue(CardDisplay.isExpired("12", "27", 2028, 1))
    }

    @Test
    fun isExpired_missingOrGarbledFieldsNeverScare() {
        assertFalse(CardDisplay.isExpired(null, null, 2099, 1))
        assertFalse(CardDisplay.isExpired("12", null, 2099, 1))
        assertFalse(CardDisplay.isExpired(null, "2020", 2099, 1))
        assertFalse(CardDisplay.isExpired("", "", 2099, 1))
        assertFalse(CardDisplay.isExpired("13", "2020", 2099, 1)) // bad month
        assertFalse(CardDisplay.isExpired("12", "20x0", 2099, 1)) // bad year
        assertFalse(CardDisplay.isExpired("１２", "2020", 2099, 1)) // non-ASCII digits
    }

    @Test
    fun pinsCreateEnabledFalse() {
        // The Option A dark gate (like web's CARD_CREATE_ENABLED pin): flipped DELIBERATELY
        // at the release that retires the 0.2.x MSI — never by accident. Editing this
        // assertion is the conscious act that enables card creation on the native clients.
        assertFalse(CardDisplay.CREATE_ENABLED)
    }
}
