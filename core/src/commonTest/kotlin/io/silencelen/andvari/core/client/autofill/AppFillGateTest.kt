package io.silencelen.andvari.core.client.autofill

import io.silencelen.andvari.core.client.autofill.AppFillGate.Identity
import io.silencelen.andvari.core.client.autofill.AppFillGate.Verdict
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Security review 2026-10, A14 (F7) — owner decision: a package-only `androidapp://` match fills
 * silently only for a system app or one Play installed; anything else, or any failed lookup, needs
 * a one-tap confirm, remembered per (package, signer). A changed signer confirms again with a
 * warning. The table is the whole rule; the Android side only gathers [Identity] from PackageManager.
 */
class AppFillGateTest {
    private val signer = "a".repeat(64)
    private val other = "b".repeat(64)
    private fun id(system: Boolean? = false, installer: String? = null, digest: String? = signer, failed: Boolean = false) =
        Identity(pkg = "com.example.bank", label = "Bank", system = system, installer = installer, signerDigest = digest, lookupFailed = failed)

    @Test
    fun theDecisionTable() {
        data class Row(val name: String, val identity: Identity, val remembered: String?, val want: Verdict)
        val rows = listOf(
            Row("system app", id(system = true, installer = null), null, Verdict.SILENT),
            Row("system app, sideload installer recorded", id(system = true, installer = "com.android.packageinstaller"), null, Verdict.SILENT),
            Row("Play-installed", id(installer = AppFillGate.PLAY_INSTALLER), null, Verdict.SILENT),
            Row("Play-installed, a stale binding for another signer", id(installer = AppFillGate.PLAY_INSTALLER), other, Verdict.SILENT),
            Row("other installer", id(installer = "com.android.packageinstaller"), null, Verdict.CONFIRM),
            Row("a third-party store", id(installer = "org.example.store"), null, Verdict.CONFIRM),
            Row("installer unknown", id(installer = null), null, Verdict.CONFIRM),
            Row("remembered signer", id(installer = "com.android.packageinstaller"), signer, Verdict.SILENT),
            Row("remembered signer, installer unknown", id(installer = null), signer, Verdict.SILENT),
            Row("changed signer", id(installer = "com.android.packageinstaller"), other, Verdict.CONFIRM_SIGNER_CHANGED),
            Row("signer unreadable, even from Play", id(installer = AppFillGate.PLAY_INSTALLER, digest = null), null, Verdict.CONFIRM),
            Row("signer unreadable, remembered", id(installer = null, digest = null), signer, Verdict.CONFIRM),
            Row("flags unreadable (package visibility)", id(system = null, installer = AppFillGate.PLAY_INSTALLER), null, Verdict.CONFIRM),
            Row("a lookup threw, even if it looked like a system app", id(system = true, failed = true), null, Verdict.CONFIRM),
            Row("a lookup threw, remembered signer", id(installer = null, failed = true), signer, Verdict.CONFIRM),
        )
        for (r in rows) assertEquals(r.want, AppFillGate.decide(r.identity, r.remembered), r.name)
    }

    @Test
    fun theInstallerLineNamesTheInstallerOrSaysItIsUnknown() {
        assertEquals("installed by Google Play Store", AppFillGate.installerLine("Google Play Store"))
        assertEquals("installer unknown", AppFillGate.installerLine(null))
        assertEquals("installer unknown", AppFillGate.installerLine("  "))
    }

    @Test
    fun aSignerIsShownInShortFormOrSaidToBeUnknown() {
        val hex = "0123456789abcdef".repeat(4)
        assertEquals("0123 4567 89ab cdef\n0123 4567 89ab cdef", AppFillGate.signerLine(hex))
        assertEquals("signer unknown", AppFillGate.signerLine(null))
    }
}
