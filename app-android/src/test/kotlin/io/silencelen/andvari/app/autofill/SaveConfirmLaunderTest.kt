package io.silencelen.andvari.app.autofill

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull

/**
 * The G11 untrusted-caller launder, pinned on BOTH domain-bearing fields (audit 2026-09-13 H55).
 *
 * G11's rule: `webDomain` comes out of an AssistStructure the CALLING app populates, so a package
 * that is not a cert-pinned browser can claim any host it likes. Everything derived from that
 * claim — the stored URI, the confirm sheet's "Site", and the master-password prompt's subject —
 * must fall back to the app's own identity instead. The fix shipped a `copy(webDomain = null)` on
 * [SavedCredentials], which does not reach the nested [SavedCard]'s own copy of the frame domain,
 * so a card-only capture still rendered "Unlock to save a card for paypal.com" over a prompt
 * asking for the master password.
 *
 * These pin the OUTCOME (no claimed host in the subject), not the two field names, because the
 * defect was precisely a new field the existing launder did not know about.
 */
class SaveConfirmLaunderTest {

    private fun capture(domain: String?, withCard: Boolean, withLogin: Boolean) = SavedCredentials(
        username = if (withLogin) "user@example.com" else null,
        password = if (withLogin) "hunter2" else null,
        webDomain = domain,
        appPackage = "com.example.evil",
        card = if (withCard) {
            SavedCard(
                number = "4242424242424242",
                cardholderName = "A Person",
                expMonth = "01",
                expYear = "2030",
                securityCode = "123",
                webDomain = domain,
                appPackage = "com.example.evil",
            )
        } else {
            null
        },
    )

    /** THE BUG: card-only capture from an untrusted app. The subject named the claimed host. */
    @Test
    fun anUntrustedCardOnlyCaptureNeverNamesTheClaimedDomain() {
        val laundered = launderUntrustedCapture(capture("paypal.com", withCard = true, withLogin = false), trusted = false)
        assertNull(laundered.card?.webDomain, "the card carries its own copy of the caller's claim")
        val subject = saveSubject(laundered)
        assertFalse("paypal.com" in subject, "the unlock prompt must never repeat an untrusted claim: $subject")
        assertEquals("a card for Evil", subject, "…it falls back to the app-derived title, like the login half")
    }

    /** The half G11 did fix, kept red-when-reverted alongside the new one. */
    @Test
    fun anUntrustedLoginCaptureStillNeverNamesTheClaimedDomain() {
        val laundered = launderUntrustedCapture(capture("github.com", withCard = false, withLogin = true), trusted = false)
        assertNull(laundered.webDomain)
        assertEquals("androidapp://com.example.evil", laundered.uri(), "the STORED identity is the app, not the claim")
        assertFalse("github.com" in saveSubject(laundered))
    }

    /** Both fields at once — the mixed checkout-with-login capture. */
    @Test
    fun aMixedCaptureLaundersBothHalves() {
        val laundered = launderUntrustedCapture(capture("bank.example", withCard = true, withLogin = true), trusted = false)
        assertNull(laundered.webDomain)
        assertNull(laundered.card?.webDomain)
        assertEquals("a card & a login for Evil", saveSubject(laundered))
    }

    /**
     * A cert-pinned browser's frame domain is REAL provenance and must survive untouched — the
     * launder is a trust boundary, not a blanket scrub (nulling it here would name every saved
     * login after the browser package).
     */
    @Test
    fun aTrustedBrowsersFrameDomainIsKept() {
        val raw = capture("github.com", withCard = true, withLogin = true)
        val kept = launderUntrustedCapture(raw, trusted = true)
        assertEquals("github.com", kept.webDomain)
        assertEquals("github.com", kept.card?.webDomain)
        assertEquals("a card & a login for github.com", saveSubject(kept))
    }

    /** Card-only from a trusted browser: the card's domain is the only site name there is. */
    @Test
    fun aTrustedCardOnlyCaptureStillNamesTheSite() {
        val kept = launderUntrustedCapture(capture("shop.example", withCard = true, withLogin = false), trusted = true)
        assertEquals("a card for shop.example", saveSubject(kept))
    }
}
