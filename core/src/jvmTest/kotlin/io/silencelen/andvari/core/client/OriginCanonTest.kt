package io.silencelen.andvari.core.client

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Audit F37 — the byte-parity pins, in the module that now OWNS the implementation.
 *
 * These literals are the same ones app-android's and app-desktop's OriginNamespaceTest assert
 * (and the extension's serverurl tests). The difference is what a green run means: it used to
 * mean "three hand-written copies still happen to agree", and one-sided edits were caught only if
 * someone remembered to edit all three test files too. Now there is one implementation, so these
 * pin the RULES (a change here re-keys every namespace on every device) rather than the sync.
 */
class OriginCanonTest {

    @Test
    fun originKeyPinnedVectors() {
        assertEquals("45858d4d141c5edd", OriginCanon.originKey("https://vault.example.net"))
        assertEquals("4e629db6dc46b0f6", OriginCanon.originKey("http://192.168.1.9:8080"))
        assertEquals("50d7a905e3046b88", OriginCanon.originKey("https://example.org"))
        assertEquals("3e1098e31ab128b1", OriginCanon.originKey("https://example.org:8443"))
    }

    @Test
    fun canonicalizationRules() {
        // case-insensitive scheme+host; default port stripped; trailing slash ignored
        assertEquals("https://example.org", OriginCanon.canonicalOrigin("HTTPS://Example.ORG"))
        assertEquals("https://example.org", OriginCanon.canonicalOrigin("https://example.org:443"))
        assertEquals("https://example.org", OriginCanon.canonicalOrigin("https://example.org/"))
        assertEquals("http://example.org", OriginCanon.canonicalOrigin("http://example.org:80"))
        assertEquals("https://example.org:8443", OriginCanon.canonicalOrigin("https://Example.org:8443/"))
        // distinct scheme / non-default port = distinct namespace
        assertNotEquals(OriginCanon.originKey("https://example.org"), OriginCanon.originKey("http://example.org"))
        assertNotEquals(OriginCanon.originKey("https://example.org"), OriginCanon.originKey("https://example.org:8443"))
        // IPv6 keeps java.net.URI's bracketed host form, lowercased
        assertEquals("https://[::1]:8443", OriginCanon.canonicalOrigin("https://[::1]:8443"))
        // total on garbage: deterministic fallback, never a throw (a malformed persisted baseUrl
        // must keep mapping to ONE stable namespace instead of failing every store read)
        assertEquals("not a url", OriginCanon.canonicalOrigin("  NOT A URL  ").lowercase())
    }

    /** §4.4 / B2-6: the strict form refuses anything that isn't a bare http(s) origin, because
     *  the Trust Gate shows what this returns and the HTTP stack dials it. */
    @Test
    fun canonicalServerOriginRefusesEverythingSpoofable() {
        assertEquals("https://example.org", OriginCanon.canonicalServerOrigin("https://Example.org/"))
        assertEquals("http://192.168.1.9:8080", OriginCanon.canonicalServerOrigin("http://192.168.1.9:8080"))
        for (bad in listOf(
            "https://real.host@evil.example", // userinfo — the phishing vector
            "https://example.org/path",
            "https://example.org/?q=1",
            "https://example.org/#frag",
            "ftp://example.org",
            "javascript:alert(1)",
            "example.org",
            "",
        )) {
            assertNull(OriginCanon.canonicalServerOrigin(bad), "must refuse: '$bad'")
        }
    }

    /** §4.1 rule 2 against hostile INPUTS: a server-minted id can never traverse namespaces. */
    @Test
    fun pathSafeLaundersHostileServerSuppliedIds() {
        assertEquals("u1", OriginCanon.pathSafe("u1"))
        assertEquals("01H8XGJWBWBAQ4-Z5A_x9", OriginCanon.pathSafe("01H8XGJWBWBAQ4-Z5A_x9"))
        for (hostile in listOf("../../evil", "a/b", "a\\b", ".", "..", "", "x".repeat(65))) {
            val safe = OriginCanon.pathSafe(hostile)
            assertTrue(Regex("[0-9a-f]{16}").matches(safe), "expected a digest segment for '$hostile', got '$safe'")
        }
    }
}
