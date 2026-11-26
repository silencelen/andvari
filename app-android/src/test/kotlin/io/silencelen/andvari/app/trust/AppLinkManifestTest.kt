package io.silencelen.andvari.app.trust

import org.w3c.dom.Element
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * §17 flow conformance, the manifest half: the app's only app link is `https://andvaripass.com/l`, as
 * spec/public-instance.json's `appLinks.android` records it, and nothing registers `/d` (§12.1, T2-B1).
 */
class AppLinkManifestTest {
    private val manifest = File("src/main/AndroidManifest.xml")
    private val spec = File("../spec/public-instance.json").readText()

    private fun Element.children(tag: String): List<Element> {
        val out = ArrayList<Element>()
        val nodes = getElementsByTagName(tag)
        for (i in 0 until nodes.length) out += nodes.item(i) as Element
        return out
    }

    @Test
    fun theOnlyViewFilterIsTheVerifiedSlashLLinkOnTheJoinHost() {
        val doc = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }.newDocumentBuilder().parse(manifest)
        val ns = "http://schemas.android.com/apk/res/android"
        val viewFilters = doc.documentElement.children("intent-filter").filter { f ->
            f.children("action").any { it.getAttributeNS(ns, "name") == "android.intent.action.VIEW" }
        }
        assertEquals(1, viewFilters.size, "exactly one VIEW filter in the whole manifest")
        val f = viewFilters.single()
        assertEquals("true", f.getAttributeNS(ns, "autoVerify"))
        val data = f.children("data")
        val schemes = data.mapNotNull { it.getAttributeNS(ns, "scheme").ifEmpty { null } }
        val hosts = data.mapNotNull { it.getAttributeNS(ns, "host").ifEmpty { null } }
        val paths = data.mapNotNull { it.getAttributeNS(ns, "path").ifEmpty { null } }
        assertEquals(listOf("https"), schemes)
        assertEquals(listOf("andvaripass.com"), hosts)
        assertEquals(listOf("/l"), paths)
        for (attr in listOf("pathPrefix", "pathPattern", "pathAdvancedPattern", "pathSuffix")) {
            assertTrue(data.all { it.getAttributeNS(ns, attr).isEmpty() }, "no $attr: /l exactly")
        }
        assertFalse(manifest.readText().contains("\"/d\""), "no /d anywhere")
        // The spec is the source: its android app-link host and paths.
        assertTrue(Regex(""""android"\s*:\s*\{\s*"host"\s*:\s*"andvaripass.com"\s*,\s*"paths"\s*:\s*\[\s*"/l"\s*]""").containsMatchIn(spec))
        assertTrue(BuildConstants.JOIN_BASE == "https://andvaripass.com")
    }
}
