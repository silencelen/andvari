package io.silencelen.andvari.app

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Gate-2 (design 2026-07-15-multi-tenant-endpoints §4.2): the Android half of the originKey
 * byte-parity suite. These are the SAME literals `app-desktop`'s OriginNamespaceTest pins — a
 * household member's originKey MUST be identical across phone / desktop / browser, so any drift
 * in [OriginNamespace.canonicalOrigin] or the sha256-hex-16 rendering re-keys every namespace on
 * disk and silently strands the local vault. Change NOTHING here without a cross-lane migration
 * plan.
 *
 * Pure JVM (java.net.URI + MessageDigest + File) — runs under `testDebugUnitTest` with no Android
 * framework. The store-level adoption/purge round-trip is SharedPreferences/Context-bound
 * ([Session.adoptNamespacesOnce]); it is covered behaviorally by desktop's twin + the completed
 * native namespacing review, with android-store instrumentation tracked as a follow-up.
 */
class OriginNamespaceTest {

    // BYTE-PARITY PINS — identical literals to app-desktop OriginNamespaceTest.originKeyPinnedVectors.
    @Test
    fun originKeyPinnedVectors() {
        assertEquals("e1fd6516bf573c7f", OriginNamespace.originKey("https://andvari.monahanhosting.com"))
        assertEquals("45858d4d141c5edd", OriginNamespace.originKey("https://vault.example.net"))
        assertEquals("4e629db6dc46b0f6", OriginNamespace.originKey("http://192.168.1.9:8080"))
        assertEquals("50d7a905e3046b88", OriginNamespace.originKey("https://example.org"))
        assertEquals("3e1098e31ab128b1", OriginNamespace.originKey("https://example.org:8443"))
    }

    @Test
    fun originKeyCanonicalization() {
        // case-insensitive scheme+host; default port stripped; trailing slash ignored
        assertEquals(OriginNamespace.originKey("https://example.org"), OriginNamespace.originKey("HTTPS://Example.ORG"))
        assertEquals(OriginNamespace.originKey("https://example.org"), OriginNamespace.originKey("https://example.org:443"))
        assertEquals(OriginNamespace.originKey("https://example.org"), OriginNamespace.originKey("https://example.org/"))
        assertEquals(OriginNamespace.originKey("http://example.org"), OriginNamespace.originKey("http://example.org:80"))
        // distinct scheme / non-default port = distinct namespace
        assertNotEquals(OriginNamespace.originKey("https://example.org"), OriginNamespace.originKey("http://example.org"))
        assertNotEquals(OriginNamespace.originKey("https://example.org"), OriginNamespace.originKey("https://example.org:8443"))
        assertEquals("https://example.org:8443", OriginNamespace.canonicalOrigin("https://Example.org:8443/"))
    }

    // §4.1 rule 2 against hostile INPUTS (desktop pathSafe twin): a server-minted userId must never
    // traverse out of its own namespace; benign ids pass through UNCHANGED so adoption's moved
    // legacy filenames (vault-<userId>.db) stay addressable by the scoped readers.
    @Test
    fun pathSafeLaundersHostileServerSuppliedIds() {
        assertEquals("u1", OriginNamespace.pathSafe("u1"))
        assertEquals("01H8XGJWBWBAQ4-Z5A_x9", OriginNamespace.pathSafe("01H8XGJWBWBAQ4-Z5A_x9"))
        for (hostile in listOf("../../evil", "a/b", "a\\b", ".", "..", "", "x".repeat(65))) {
            val safe = OriginNamespace.pathSafe(hostile)
            assertTrue(Regex("[0-9a-f]{16}").matches(safe), "expected a digest segment for '$hostile', got '$safe'")
        }
        // dir() containment: a hostile userId (and originKey) is laundered, so the namespace dir
        // can never climb out of <base>/ns/ (§4.2 — the OriginNamespace.dir call site in Session).
        val base = File("build/tmp/andvari-ns-containment")
        val dir = OriginNamespace.dir(base, "k1", "../../escape")
        assertTrue(dir.canonicalFile.toPath().startsWith(File(base, "ns").canonicalFile.toPath()))
    }
}
