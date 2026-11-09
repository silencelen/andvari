package io.silencelen.andvari.core.client

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

/**
 * Recheck R46 (H22): H22 made `bücher.de` and `xn--bcher-kva.de` ONE site key — the clustering
 * win — but `DuplicateCluster.sites` is user-facing (HealthScreen / Health.tsx render it), so the
 * household that H22 exists for started reading punycode. The key stays the A-label; the label
 * is the U-label the member typed. Web twin: duplicates.test.ts siteLabelsOf.
 */
class DuplicatesIdnLabelTest {
    private fun login(id: String, vararg uris: String) = VaultItem(
        id, "v1", 1, 1_000L,
        ItemDoc(type = "login", name = id, login = LoginData(username = "u@example.com", password = "pw", uris = uris.toList())),
    )

    @Test
    fun anIdnKeyIsLabelledWithTheTypedRegistrableDomain_andAsciiKeysLabelThemselves() {
        val labels = Duplicates.siteLabelsOf(login("x", "https://login.BÜCHER.de/x", "https://accounts.example.com").doc)
        assertEquals(mapOf("xn--bcher-kva.de" to "bücher.de", "example.com" to "example.com"), labels)
        assertEquals(setOf("xn--bcher-kva.de", "example.com"), Duplicates.siteKeysOf(login("x", "https://login.BÜCHER.de/x", "https://accounts.example.com").doc), "grouping still runs on the A-label")
    }

    @Test
    fun aClusterKeyedOnTheALabelDisplaysTheULabel() {
        val clusters = Duplicates.duplicateClusters(listOf(login("a", "https://bücher.de"), login("b", "https://xn--bcher-kva.de/login"))) { null }
        assertEquals(1, clusters.size, "the two spellings are one site")
        assertEquals(listOf("bücher.de"), clusters.single().sites)
        assertFalse(clusters.single().sites.any { it.contains("xn--") })
    }

    @Test
    fun theUnicodeNormalizerIsTheSameNormalizerStoppedBeforeTheALabel() {
        assertEquals("login.bücher.de", io.silencelen.andvari.core.client.autofill.UriMatch.normalizeHostUnicode("https://www.Login.BÜCHER.de:8443/x"))
        assertEquals("example.com", io.silencelen.andvari.core.client.autofill.UriMatch.normalizeHostUnicode("https://example.com/"))
    }
}
