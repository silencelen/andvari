package io.silencelen.andvari.core.client.autofill

import io.silencelen.andvari.core.client.autofill.AppFillGate.Identity
import io.silencelen.andvari.core.client.autofill.AppFillGate.Verdict
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Security review 2026-10, A14 (F7) — owner decision: a package-only `androidapp://` match fills
 * silently only for a system app or one Play installed; anything else, or any failed lookup, needs
 * a one-tap confirm, remembered per (package, signer). A changed signer confirms again with a
 * warning. The table is the whole rule; the Android side only gathers [Identity] from PackageManager.
 */
class AppFillGateTest {
    private val signer = "a".repeat(64)
    private val other = "b".repeat(64)
    private fun id(system: Boolean? = false, installer: String? = null, digest: String? = signer, failed: Boolean = false, installerSystem: Boolean? = null) =
        Identity(pkg = "com.example.bank", label = "Bank", system = system, installer = installer, signerDigest = digest, lookupFailed = failed, installerSystem = installerSystem)
    private val play = AppFillGate.PLAY_INSTALLER

    @Test
    fun theDecisionTable() {
        data class Row(val name: String, val identity: Identity, val remembered: String?, val want: Verdict)
        val rows = listOf(
            Row("system app", id(system = true, installer = null), null, Verdict.SILENT),
            Row("system app, sideload installer recorded", id(system = true, installer = "com.android.packageinstaller"), null, Verdict.SILENT),
            Row("Play-installed (the installer is the system Play Store)", id(installer = play, installerSystem = true), null, Verdict.SILENT),
            Row("Play-installed, a stale binding for another signer", id(installer = play, installerSystem = true), other, Verdict.SILENT),
            // A14 review N1: "Play" is the installer's NAME only when the installer is itself a system app. On a device
            // with no real Play (a de-Googled ROM, Fire, Huawei) a sideloaded app can take com.android.vending.
            Row("Play-named installer that is NOT a system app", id(installer = play, installerSystem = false), null, Verdict.CONFIRM),
            Row("Play-named installer that could not be resolved", id(installer = play, installerSystem = null), null, Verdict.CONFIRM),
            Row("Play-named non-system installer, a remembered signer still counts", id(installer = play, installerSystem = false), signer, Verdict.SILENT),
            Row("Play-named unresolved installer, changed signer", id(installer = play, installerSystem = null), other, Verdict.CONFIRM_SIGNER_CHANGED),
            Row("another SYSTEM installer is not Play", id(installer = "com.example.vendorstore", installerSystem = true), null, Verdict.CONFIRM),
            Row("other installer", id(installer = "com.android.packageinstaller", installerSystem = true), null, Verdict.CONFIRM),
            Row("a third-party store", id(installer = "org.example.store", installerSystem = false), null, Verdict.CONFIRM),
            Row("installer unknown", id(installer = null), null, Verdict.CONFIRM),
            Row("remembered signer", id(installer = "com.android.packageinstaller"), signer, Verdict.SILENT),
            Row("remembered signer, installer unknown", id(installer = null), signer, Verdict.SILENT),
            Row("changed signer", id(installer = "com.android.packageinstaller"), other, Verdict.CONFIRM_SIGNER_CHANGED),
            Row("signer unreadable, even from Play", id(installer = play, installerSystem = true, digest = null), null, Verdict.CONFIRM),
            Row("signer unreadable, remembered", id(installer = null, digest = null), signer, Verdict.CONFIRM),
            Row("flags unreadable (package visibility)", id(system = null, installer = play, installerSystem = true), null, Verdict.CONFIRM),
            Row("a lookup threw, even if it looked like a system app", id(system = true, failed = true), null, Verdict.CONFIRM),
            Row("a lookup threw, remembered signer", id(installer = null, failed = true), signer, Verdict.CONFIRM),
        )
        for (r in rows) assertEquals(r.want, AppFillGate.decide(r.identity, r.remembered), r.name)
    }

    @Test
    fun theInstallerLineNamesThePackageAndWhetherItIsASystemApp() {
        // A14 review N2: a label is the installer's own choice ("Google Play Store" from any store), so the line names
        // the installer's PACKAGE and whether it is a system app, not only its label. A14 review 3 (A1): the line LEADS
        // with the package and kind and carries no label at all, so no label length can push them off a one-line row;
        // the label is its own line ([AppFillGate.installerLabelLine]).
        assertEquals("installed by com.android.vending (a system app)", AppFillGate.installerLine(play, true))
        assertEquals("installed by com.android.vending (NOT a system app)", AppFillGate.installerLine(play, false))
        assertEquals("installed by com.android.vending (could not check whether it is a system app)", AppFillGate.installerLine(play, null))
        assertEquals("installed by org.example.store (NOT a system app)", AppFillGate.installerLine("org.example.store", false))
        assertEquals("installer unknown", AppFillGate.installerLine(null, null))
        assertEquals("installer unknown", AppFillGate.installerLine("  ", true))
    }

    @Test
    fun theInstallerLabelIsItsOwnEscapedBoundedLine() {
        // A14 review 3 (A1): an 80-character installer label used to share the package's line, rendered maxLines=1, and
        // pushed the package and "NOT a system app" off-screen. The label is now a line of its own; the package line is
        // the same whatever the label says.
        val long = "Google Play Store " + "x".repeat(200)
        assertEquals("installed by org.example.store (NOT a system app)", AppFillGate.installerLine("org.example.store", false))
        val labelLine = AppFillGate.installerLabelLine("org.example.store", long)!!
        assertTrue(labelLine.startsWith("which calls itself Google Play Store "), labelLine)
        assertTrue(labelLine.length <= "which calls itself ".length + AppFillGate.ONE_LINE_MAX + 1 && labelLine.endsWith("\u2026"), labelLine)
        assertEquals("which calls itself Google Play Store", AppFillGate.installerLabelLine(play, "Google Play Store"))
        assertEquals(null, AppFillGate.installerLabelLine("org.example.store", "org.example.store"), "a label that is the package says nothing new")
        assertEquals(null, AppFillGate.installerLabelLine("org.example.store", "  "))
        assertEquals(null, AppFillGate.installerLabelLine(null, "Store"), "no installer, no label line")
        // An installer label with a newline or a bidi override cannot draw a second, fake line.
        assertEquals(
            "which calls itself Shop\\u000A(com.android.vending, a system app)",
            AppFillGate.installerLabelLine("org.example.store", "Shop\u000A(com.android.vending, a system app)"),
        )
    }

    @Test
    fun appAndItemTextIsOneEscapedBoundedLine() {
        // A14 review N2: the app label and the item's name and username are attacker- or co-member-authored. On the confirm
        // they are ONE line: every control, line separator and bidi control is shown escaped, and the text is bounded.
        assertEquals("Bank", AppFillGate.oneLine("  Bank  "))
        assertEquals(null, AppFillGate.oneLine("   "))
        assertEquals(null, AppFillGate.oneLine(null))
        assertEquals("Bank\\u000Acom.android.vending", AppFillGate.oneLine("Bank\u000Acom.android.vending"))
        assertEquals("gnp.\\u202Eexe", AppFillGate.oneLine("gnp.\u202Eexe"), "a right-to-left override is shown, never applied")
        assertEquals("a\\u2028b\\u2029c", AppFillGate.oneLine("a\u2028b\u2029c"))
        val long = "x".repeat(500)
        val bounded = AppFillGate.oneLine(long)!!
        assertTrue(bounded.length <= AppFillGate.ONE_LINE_MAX + 1 && bounded.endsWith("\u2026"), bounded)
    }

    @Test
    fun theIdentityAtTheTapMustBeTheOneTheConfirmShowed() {
        // A14 review N7: the live identity is read again at the tap; a signer, installer, installer kind or system flag
        // that moved since the confirm opened refuses the fill.
        val shown = id(installer = "org.example.store", installerSystem = false)
        assertTrue(AppFillGate.unchangedSince(shown, shown.copy(label = "Renamed")), "a label change is not an identity change")
        for ((what, live) in listOf(
            "signer" to shown.copy(signerDigest = other),
            "signer unreadable" to shown.copy(signerDigest = null),
            "installer" to shown.copy(installer = play),
            "installer kind" to shown.copy(installerSystem = true),
            "system flag" to shown.copy(system = true),
            "a lookup now fails" to shown.copy(lookupFailed = true),
            "another package" to shown.copy(pkg = "com.example.other"),
        )) assertFalse(AppFillGate.unchangedSince(shown, live), what)
        val unreadable = id(system = null, installer = null, digest = null, failed = true)
        assertTrue(AppFillGate.unchangedSince(unreadable, unreadable), "an identity that could not be read stays confirmable, unremembered")
    }

    @Test
    fun aSignerIsShownInShortFormOrSaidToBeUnknown() {
        val hex = "0123456789abcdef".repeat(4)
        assertEquals("0123 4567 89ab cdef\n0123 4567 89ab cdef", AppFillGate.signerLine(hex))
        assertEquals("signer unknown", AppFillGate.signerLine(null))
    }
}
