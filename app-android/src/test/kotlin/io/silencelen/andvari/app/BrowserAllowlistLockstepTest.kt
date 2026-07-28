package io.silencelen.andvari.app

import io.silencelen.andvari.core.client.autofill.BrowserCertPins
import org.w3c.dom.Element
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * quality-tests--10 (polish audit 2026-07-27): the browser allowlist is hand-synced across THREE
 * sources and, until now, only by comments —
 *  - core `BrowserCertPins.TABLE` (the trust table; an unknown package is never trusted),
 *  - `AndroidManifest.xml`'s `<queries>` block (package visibility — without an entry,
 *    `PackageManager.getPackageInfo` throws NameNotFound on API 30+, the cert check fails CLOSED,
 *    and that browser silently NEVER fills),
 *  - `res/xml/autofill_service.xml`'s `<compatibility-package>` list (the browsers that don't
 *    dispatch to third-party services natively).
 *
 * Adding a browser to one and missing another degrades autofill silently: nothing errors, the user
 * just reports "it never fills there". The manifest's own comment says "keep the two lists in
 * lockstep" — this is that sentence as a gate. Same idiom as web's token-lockstep test, which
 * parses its real sources rather than a copy: the XML here is read off the source tree, so a
 * one-sided edit fails at `testDebugUnitTest`. Pure JVM (DOM parse + File) — no Android framework.
 */
class BrowserAllowlistLockstepTest {

    /** Unit tests run with the MODULE dir as cwd; the repo-root fallback keeps the test honest if
     *  that ever changes, and a missing file FAILS rather than silently yielding an empty set (the
     *  vacuous-pass shape this whole test exists to prevent). */
    private fun sourceFile(relative: String): File {
        val candidates = listOf(File(relative), File("app-android/$relative"))
        return candidates.firstOrNull { it.isFile }
            ?: error("could not locate $relative from ${File(".").absolutePath} — tried ${candidates.map { it.path }}")
    }

    private fun packageNamesIn(file: File, tag: String): Set<String> {
        // Non-namespace-aware on purpose: the attribute is literally `android:name` in the source
        // text, and reading it verbatim is what keeps this a check on the SHIPPED file.
        val doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(file)
        val nodes = doc.getElementsByTagName(tag)
        return (0 until nodes.length)
            .map { (nodes.item(it) as Element).getAttribute("android:name") }
            .filter { it.isNotBlank() }
            .toSet()
    }

    private val manifest get() = sourceFile("src/main/AndroidManifest.xml")
    private val autofillService get() = sourceFile("src/main/res/xml/autofill_service.xml")

    @Test
    fun manifestQueriesCoverExactlyTheTrustTable() {
        val queried = packageNamesIn(manifest, "package")
        val trusted = BrowserCertPins.TABLE.keys
        // Sorted lists, not sets: the assertion message then names the drifting package.
        assertEquals(
            trusted.sorted(),
            queried.sorted(),
            "manifest <queries> and BrowserCertPins.TABLE have drifted — a table entry with no " +
                "<queries> package can never pass the cert check (fails closed, silently), and a " +
                "<queries> package with no table entry is never trusted anyway",
        )
    }

    /**
     * The compat list is deliberately a SUBSET, not a mirror: it opts specific browsers into the
     * platform's accessibility-tree compatibility mode. Pinned exactly, because both directions are
     * bugs — an unlisted Samsung/Edge dispatches nothing to us, and listing a browser that already
     * dispatches natively downgrades it to a dropdown-only experience.
     */
    @Test
    fun compatibilityPackagesArePinnedAndKnownToTheTrustTable() {
        val compat = packageNamesIn(autofillService, "compatibility-package")
        assertEquals(
            listOf("com.microsoft.emmx", "com.sec.android.app.sbrowser", "com.sec.android.app.sbrowser.beta"),
            compat.sorted(),
            "the compatibility-mode opt-ins changed — see autofill_service.xml's triage note",
        )
        for (pkg in compat) {
            assertTrue(pkg in BrowserCertPins.TABLE, "$pkg is opted into compat mode but is not a known browser, so it can never be trusted")
        }
    }

    /**
     * Chrome's absence from the compat list is a DECISION, not an omission (Google removed Chrome's
     * accessibility compat path; the supported route is Chrome's own "Autofill using another
     * service" setting). Pinned so a future "why doesn't Chrome fill?" doesn't get fixed by adding
     * an entry that cannot work.
     */
    @Test
    fun chromeIsDeliberatelyNotACompatibilityPackage() {
        val compat = packageNamesIn(autofillService, "compatibility-package")
        assertTrue("com.android.chrome" in BrowserCertPins.TABLE, "Chrome is still a pinned browser")
        assertTrue("com.android.chrome" !in compat, "Chrome's compat path was removed upstream — the in-Chrome setting is the route")
    }
}
