package io.silencelen.andvari.app.autofill

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * H124 (2026-09-13 audit): the stored site uri keeps the scheme the browser CAPTURED. `uri()`
 * always wrote `https://<host>`, so a login saved on a plain-http page (Pi-hole, router, loopback
 * dev server — the F27 intranet posture) named an origin that does not exist. Pinned on the data
 * class because that is the one place the uri is composed (SaveConfirmActivity stores `creds.uri()`
 * verbatim); the extension twin is `capturedSiteUri` in siteurl.test.ts.
 */
class SavedCredentialsUriTest {
    private fun creds(domain: String?, scheme: String?) =
        SavedCredentials(username = "u", password = "p", webDomain = domain, appPackage = "com.android.chrome", webScheme = scheme)

    /** THE BUG: an http capture stored https. */
    @Test
    fun anHttpCaptureStoresHttp() {
        assertEquals("http://pi.hole", creds("pi.hole", "http").uri())
        assertEquals("http://192.168.1.1", creds("192.168.1.1", "http").uri())
    }

    @Test
    fun anHttpsCaptureStoresHttpsUnchanged() {
        assertEquals("https://github.com", creds("github.com", "https").uri())
    }

    /** A browser that reports no scheme (or something that is not a web scheme) keeps the https default —
     *  a wrong `http://` on a real site would downgrade the link the user clicks. */
    @Test
    fun anAbsentOrUnknownSchemeKeepsTheHttpsDefault() {
        assertEquals("https://github.com", creds("github.com", null).uri())
        assertEquals("https://github.com", creds("github.com", "").uri())
        assertEquals("https://github.com", creds("github.com", "ftp").uri())
    }

    /** A native app has no web scheme and no domain — the androidapp:// identity is untouched, and
     *  the G11 launder (webDomain = null) still wins over any leftover scheme. */
    @Test
    fun aNativeAppCaptureIsUnaffected() {
        assertEquals("androidapp://com.example.app", SavedCredentials("u", "p", null, "com.example.app").uri())
        assertEquals("androidapp://com.example.evil", creds("paypal.com", "http").copy(webDomain = null, appPackage = "com.example.evil").uri())
    }
}
