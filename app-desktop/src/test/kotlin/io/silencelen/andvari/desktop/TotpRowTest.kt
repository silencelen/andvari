package io.silencelen.andvari.desktop

import io.silencelen.andvari.core.crypto.Totp
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * ux-error--6 (polish audit 2026-07-27): the item detail's TOTP row answered an unreadable stored
 * `otpauth://` URI by putting the literal string "invalid" in the CODE slot — monospace headline,
 * a frozen "30s" beside it, and the copy button still live, so clicking it put the word "invalid"
 * on the clipboard with a scheduled auto-clear. The row now branches on the parse BEFORE it
 * renders anything code-shaped; these pin the two facts that branch rests on.
 */
class TotpRowTest {

    /** The parse the row's `remember(uri)` performs — garbage must be a clean null (never a
     *  throw escaping composition, and never a "code"). */
    @Test
    fun anUnreadableUriParsesToNullRatherThanACode() {
        for (bad in listOf("", "invalid", "otpauth://totp/", "https://example.org", "not a uri at all")) {
            assertNull(runCatching { Totp.parseUri(bad) }.getOrNull(), "'$bad' must not parse to a TOTP config")
        }
    }

    /** …and a real URI still parses, so the failure branch can't swallow working codes. */
    @Test
    fun aRealUriStillParses() {
        val cfg = assertNotNull(runCatching { Totp.parseUri("otpauth://totp/andvari:e@x?secret=JBSWY3DPEHPK3PXP&issuer=andvari") }.getOrNull())
        // The row seeds its countdown from the parsed period instead of a hardcoded 30 — so a
        // non-default-period URI no longer shows a wrong first frame.
        val remaining = Totp.secondsRemaining(cfg, 0)
        assertTrue(remaining in 1..cfg.periodSeconds, "the seeded countdown must be inside the parsed period")
    }

    /** The replacement copy: it names the fix the user can actually perform. Desktop-local (a
     *  stored-data problem, not one of the canon's mapped failures) — pinned so it can't drift
     *  back into a bare token. */
    @Test
    fun theUnreadableNoticeNamesTheRepair() {
        assertEquals("This one-time code isn't set up right — edit the item and add it again.", TOTP_URI_UNREADABLE)
    }
}
