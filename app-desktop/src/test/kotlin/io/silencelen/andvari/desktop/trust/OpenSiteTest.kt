package io.silencelen.andvari.desktop.trust

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** "Open the site" refuses an address with a user name or password before the host. */
class OpenSiteTest {
    @Test
    fun theReviewsAddressIsNotOpened() {
        // P11: opened evil.example as written.
        assertTrue(carriesUserInfo("https://bank.example@evil.example/"))
        assertNull(webAddress("https://bank.example@evil.example/"))
    }

    @Test
    fun everyFormOfUserInfoIsRefused() {
        for (bad in listOf(
            "https://user:pass@evil.example",
            "http://bank.example@evil.example/login",
            "bank.example@evil.example",
            "bank.example:pw@evil.example/x",
            "HTTPS://a@b.example",
            "https://a@b.example\\@c.example",
        )) {
            assertTrue(carriesUserInfo(bad), bad)
            assertNull(webAddress(bad), bad)
        }
    }

    @Test
    fun anAtAfterTheHostIsAnOrdinaryAddress() {
        for (ok in listOf("https://bank.example/u/@me", "https://bank.example/?to=a@b.example", "bank.example#a@b", "https://bank.example")) {
            assertFalse(carriesUserInfo(ok), ok)
        }
        assertEquals("https://bank.example/u/@me", webAddress("https://bank.example/u/@me"))
        assertEquals("https://bank.example", webAddress("bank.example"))
    }
}
