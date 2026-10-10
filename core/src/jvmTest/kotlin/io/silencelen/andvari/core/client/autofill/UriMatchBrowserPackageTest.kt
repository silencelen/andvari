package io.silencelen.andvari.core.client.autofill

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Security review 2026-10 (root cause E): an `androidapp://<pkg>` URI names an APP, and a browser
 * app is a window onto every web origin. Matching it on package alone offered a login saved as
 * `androidapp://com.android.chrome` (a CSV import, a save from a browser dialog with no web domain,
 * a hand edit) on every site the user opened in Chrome, a phishing page included. An app-package
 * identity now never stands in for a web origin: it matches its own app, and never a known browser.
 */
class UriMatchBrowserPackageTest {
    private fun matches(saved: String, webHost: String?, pkg: String): Boolean =
        UriMatch.parseSavedUri(saved)!!.let { UriMatch.matches(it, FillTarget(webHost, pkg)) }

    @Test
    fun aBrowserPackageUriDoesNotMatchAWebOrigin() {
        assertFalse(matches("androidapp://com.android.chrome", "evil.example", "com.android.chrome"))
        assertFalse(matches("androidapp://com.android.chrome", "bank.example", "com.android.chrome"))
    }

    @Test
    fun aBrowserPackageUriDoesNotMatchAnUntrustedBrowserEither() {
        // An unpinned / untrusted browser reaches matching with webHost = null (the caller drops the
        // domain it cannot verify) — still a browser showing some web page, so still no match.
        assertFalse(matches("androidapp://com.android.chrome", null, "com.android.chrome"))
        assertFalse(matches("androidapp://org.mozilla.firefox", null, "org.mozilla.firefox"))
        assertFalse(matches("androidapp://com.sec.android.app.sbrowser", null, "com.sec.android.app.sbrowser"))
    }

    @Test
    fun everyKnownBrowserPackageIsRefused() {
        for (pkg in BrowserCertPins.TABLE.keys) {
            assertFalse(matches("androidapp://$pkg", null, pkg), pkg)
            assertFalse(matches("androidapp://$pkg", "example.com", pkg), pkg)
        }
    }

    @Test
    fun aNativeAppStillMatchesItsOwnPackage() {
        assertTrue(matches("androidapp://com.spotify.music", null, "com.spotify.music"))
        assertFalse(matches("androidapp://com.spotify.music", null, "com.evil.clone"))
    }

    @Test
    fun webUrisInATrustedBrowserAreUnchanged() {
        assertTrue(matches("https://bank.example", "bank.example", "com.android.chrome"))
        assertFalse(matches("https://bank.example", "evil.example", "com.android.chrome"))
    }
}
