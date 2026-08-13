package io.silencelen.andvari.app

import org.w3c.dom.Element
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Audit F36 — the cleartext exemption list, read off the SHIPPED files (the
 * BrowserAllowlistLockstepTest idiom: parse the real sources, never a copy).
 *
 * `10.0.2.2` is the emulator's alias for the developer host. On a real phone it is an ordinary
 * routable address inside 10.0.0.0/8 — a very common home and office LAN range — so while it sat
 * in `src/main`, with no debug overlay anywhere in the module, every release APK carved that one
 * address out of an otherwise total cleartext ban: sign-in traffic, bearer tokens and the derived
 * authKey would travel in plaintext to it with no OS backstop, while every other LAN address was
 * correctly refused. It now lives in `src/debug`, which AGP merges into the debug variant only.
 *
 * This is the kind of thing that regresses by someone "fixing" a dev inconvenience in the obvious
 * file, so both halves are asserted: main has loopback ONLY, debug adds exactly the emulator host.
 */
class NetworkSecurityConfigTest {

    /** Unit tests run with the MODULE dir as cwd; the repo-root fallback keeps the test honest if
     *  that changes, and a missing file FAILS rather than vacuously passing. */
    private fun sourceFile(relative: String): File =
        listOf(File(relative), File("app-android/$relative")).firstOrNull { it.isFile }
            ?: error("could not locate $relative from ${File(".").absolutePath}")

    private fun config(sourceSet: String): Element =
        DocumentBuilderFactory.newInstance().newDocumentBuilder()
            .parse(sourceFile("src/$sourceSet/res/xml/network_security_config.xml"))
            .documentElement

    private fun cleartextDomains(root: Element): List<String> {
        val out = mutableListOf<String>()
        val configs = root.getElementsByTagName("domain-config")
        for (i in 0 until configs.length) {
            val c = configs.item(i) as Element
            if (c.getAttribute("cleartextTrafficPermitted") != "true") continue
            val domains = c.getElementsByTagName("domain")
            for (j in 0 until domains.length) out += (domains.item(j) as Element).textContent.trim()
        }
        return out.sorted()
    }

    private fun baseCleartext(root: Element): String {
        val base = root.getElementsByTagName("base-config")
        assertTrue(base.length == 1, "expected exactly one <base-config>")
        return (base.item(0) as Element).getAttribute("cleartextTrafficPermitted")
    }

    @Test
    fun shippedConfigPermitsCleartextToLoopbackOnly() {
        val main = config("main")
        assertEquals(listOf("127.0.0.1"), cleartextDomains(main), "a host was added to the SHIPPED cleartext exemptions")
        assertEquals("false", baseCleartext(main), "the shipped default must stay cleartext-denied")
    }

    @Test
    fun theEmulatorHostIsDebugOnly() {
        val debug = config("debug")
        // A variant resource REPLACES the main file wholesale rather than merging, so the debug
        // overlay must re-list loopback as well as the emulator host.
        assertEquals(listOf("10.0.2.2", "127.0.0.1"), cleartextDomains(debug))
        assertEquals("false", baseCleartext(debug), "debug widens ONE host, it does not open the base config")
    }
}
