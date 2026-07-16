package io.silencelen.andvari.desktop

import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * §4.2 (origin, userId) namespacing + §5.3 consent + §2.3 clamps — the desktop half of the Gate-2
 * suite (design 2026-07-15-multi-tenant-endpoints): originKey byte-parity pins, the adoption
 * one-shot (incl. B1-4 continuity consent), origin-scoped purges (a forbidding origin's purge
 * leaves every other namespace intact; A→B→A preserves A's material), and the B1-1 timer clamps.
 */
class OriginNamespaceTest {
    private val root = Files.createTempDirectory("andvari-desktop-test").toFile()

    @AfterTest
    fun cleanup() {
        root.deleteRecursively()
    }

    // BYTE-PARITY PINS (§4.2): Android (and the extension) pin these SAME literals from the same
    // canonical input — `hex(sha256(lowercase scheme://host[:non-default port])).take(16)` — so a
    // household member's originKey is identical across phone/desktop/browser. Any drift here
    // re-keys every namespace on disk: change NOTHING without a cross-lane migration plan.
    @Test
    fun originKeyPinnedVectors() {
        assertEquals("e1fd6516bf573c7f", originKey("https://andvari.monahanhosting.com"))
        assertEquals("edfce5729b02fa19", originKey("https://andvari.taila2dff2.ts.net"))
        assertEquals("63572e635897bbf3", originKey("http://192.168.2.122:8080"))
        assertEquals("50d7a905e3046b88", originKey("https://example.org"))
        assertEquals("3e1098e31ab128b1", originKey("https://example.org:8443"))
    }

    @Test
    fun originKeyCanonicalization() {
        // case-insensitive scheme+host; default port stripped; trailing slash ignored
        assertEquals(originKey("https://example.org"), originKey("HTTPS://Example.ORG"))
        assertEquals(originKey("https://example.org"), originKey("https://example.org:443"))
        assertEquals(originKey("https://example.org"), originKey("https://example.org/"))
        assertEquals(originKey("http://example.org"), originKey("http://example.org:80"))
        // distinct scheme / non-default port = distinct namespace
        assertNotEquals(originKey("https://example.org"), originKey("http://example.org"))
        assertNotEquals(originKey("https://example.org"), originKey("https://example.org:8443"))
        assertEquals("https://example.org:8443", canonicalOrigin("https://Example.org:8443/"))
    }

    // §4.1 rule 2 against hostile INPUTS (Android OriginNamespace.pathSafe twin): a server-minted
    // userId must never traverse out of its own namespace; benign ids pass through unchanged so
    // the adoption one-shot's moved legacy filenames stay addressable.
    @Test
    fun pathSafeLaundersHostileServerSuppliedIds() {
        assertEquals("u1", pathSafe("u1"))
        assertEquals("01H8XGJWBWBAQ4-Z5A_x9", pathSafe("01H8XGJWBWBAQ4-Z5A_x9"))
        for (hostile in listOf("../../evil", "a/b", "a\\b", ".", "..", "", "x".repeat(65))) {
            val safe = pathSafe(hostile)
            assertTrue(Regex("[0-9a-f]{16}").matches(safe), "expected a digest segment for '$hostile', got '$safe'")
        }
        val store = DesktopSessionStore(root)
        val dir = store.nsDir("k1", "../../escape")
        assertTrue(dir.canonicalFile.toPath().startsWith(root.canonicalFile.toPath().resolve("ns")))
    }

    // §2.3 (B1-1): a server-supplied 0 ("never lock") clamps to the CEILING — a hostile server can
    // shorten the windows, never extend or disable them.
    @Test
    fun timerClamps() {
        assertEquals(900, clampAutoLockSeconds(0))
        assertEquals(900, clampAutoLockSeconds(-5))
        assertEquals(900, clampAutoLockSeconds(86400))
        assertEquals(900, clampAutoLockSeconds(900))
        assertEquals(300, clampAutoLockSeconds(300))
        assertEquals(1, clampAutoLockSeconds(1))
        assertEquals(1, clampClipboardClearSeconds(0))
        assertEquals(1, clampClipboardClearSeconds(-1))
        assertEquals(300, clampClipboardClearSeconds(3600))
        assertEquals(30, clampClipboardClearSeconds(30))
    }

    @Test
    fun adoptionMovesLegacyLayoutAndAdoptsConsent() {
        val store = DesktopSessionStore(root)
        store.baseUrl = "https://andvari.taila2dff2.ts.net"
        // legacy unscoped layout: a vault DB set + the single accountKeys cache + the session
        // naming its user
        File(root, "vault-u1.db").writeText("db")
        File(root, "vault-u1.db-wal").writeText("wal")
        File(root, "account-keys.json").writeText("{}")
        store.save(DesktopSession("https://andvari.taila2dff2.ts.net", "u1", "a@b.c", "at", "rt"))

        store.adoptNamespacesOnce()

        val key = originKey("https://andvari.taila2dff2.ts.net")
        assertTrue(File(root, "ns/$key/u1/vault-u1.db").exists())
        assertTrue(File(root, "ns/$key/u1/vault-u1.db-wal").exists())
        assertTrue(File(root, "ns/$key/u1/account-keys.json").exists())
        assertFalse(File(root, "vault-u1.db").exists())
        assertFalse(File(root, "account-keys.json").exists())
        // B1-4 continuity: an install that already held a cache adopts consent=ON — nobody's
        // offline access silently vanishes under the new default-OFF regime.
        assertEquals(true, store.cacheConsent(key))
        // one-shot: a second run must not re-adopt (new legacy-looking files stay put)
        File(root, "vault-u2.db").writeText("db2")
        store.adoptNamespacesOnce()
        assertTrue(File(root, "vault-u2.db").exists())
    }

    @Test
    fun adoptionOnFreshInstallLeavesConsentUnanswered() {
        val store = DesktopSessionStore(root)
        store.adoptNamespacesOnce()
        // §5.3: fresh installs owe the one-time prompt — consent unanswered, nothing persists.
        assertNull(store.cacheConsent(originKey(DesktopSessionStore.DEFAULT_BASE_URL)))
    }

    @Test
    fun adoptionSeedsLegacyOrgFallbacksForTheCurrentOrigin() {
        // A legacy prefs.json carrying the old GLOBAL fallbacks (cacheAllowed=false must survive
        // as the adopted origin's stance — a pre-namespacing forbid keeps governing its origin).
        File(root, "prefs.json").also { it.parentFile.mkdirs() }.writeText(
            """{"baseUrl":"https://andvari.taila2dff2.ts.net","cacheAllowed":false,"autoLockSeconds":120}""",
        )
        val store = DesktopSessionStore(root)
        store.adoptNamespacesOnce()
        val key = originKey("https://andvari.taila2dff2.ts.net")
        assertFalse(store.orgCacheAllowed(key))
        assertEquals(120, store.originAutoLockSeconds(key))
        // and a NEVER-probed origin defaults conservative (§2.3 fetch-failure posture: cache OFF)
        assertFalse(store.orgCacheAllowed(originKey("https://never-probed.example")))
    }

    // §4.2 (B2-3/B2-7): a purge triggered by one origin's verdict reaches ONLY that origin's own
    // namespace — the A→B→A round trip keeps A's material.
    @Test
    fun purgeIsScopedPerOriginAndRoundTripPreserves() {
        val store = DesktopSessionStore(root)
        val a = originKey("https://home.example")
        val b = originKey("https://forbidding.example")
        store.cacheDbFile(a, "u1").also { it.parentFile.mkdirs(); it.writeText("A") }
        File(store.nsDir(a, "u1"), "account-keys.json").writeText("{}")
        store.cacheDbFile(b, "u1").also { it.parentFile.mkdirs(); it.writeText("B") }
        File(store.nsDir(b, "u1"), "account-keys.json").writeText("{}")

        // B declares offlineCacheAllowed=false ⇒ purge B's namespace only
        store.deleteCacheDb(b, "u1")
        store.clearAccountKeys(b, "u1")

        assertFalse(store.cacheDbFile(b, "u1").exists())
        assertFalse(File(store.nsDir(b, "u1"), "account-keys.json").exists())
        assertTrue(store.cacheDbFile(a, "u1").exists()) // home origin untouched
        assertTrue(File(store.nsDir(a, "u1"), "account-keys.json").exists())
    }

    @Test
    fun clearDropsOnlyTheCurrentOriginsAccountKeys() {
        val store = DesktopSessionStore(root)
        store.baseUrl = "https://home.example"
        val a = originKey("https://home.example")
        val b = originKey("https://other.example")
        store.save(DesktopSession("https://home.example", "u1", "a@b.c", "at", "rt"))
        store.nsDir(a, "u1").mkdirs()
        File(store.nsDir(a, "u1"), "account-keys.json").writeText("{}")
        store.nsDir(b, "u1").mkdirs()
        File(store.nsDir(b, "u1"), "account-keys.json").writeText("{}")

        store.clear()

        assertNull(store.load())
        assertFalse(File(store.nsDir(a, "u1"), "account-keys.json").exists())
        assertTrue(File(store.nsDir(b, "u1"), "account-keys.json").exists()) // §4.2: B survives
    }

    @Test
    fun perOriginPrefsAreIsolated() {
        val store = DesktopSessionStore(root)
        store.setCacheConsent("k1", true)
        store.setOrgCacheAllowed("k1", true)
        store.setOriginAutoLockSeconds("k1", 120)
        assertEquals(true, store.cacheConsent("k1"))
        assertTrue(store.orgCacheAllowed("k1"))
        assertEquals(120, store.originAutoLockSeconds("k1"))
        // a different origin sees none of it
        assertNull(store.cacheConsent("k2"))
        assertFalse(store.orgCacheAllowed("k2"))
        assertEquals(0, store.originAutoLockSeconds("k2"))
    }
}
