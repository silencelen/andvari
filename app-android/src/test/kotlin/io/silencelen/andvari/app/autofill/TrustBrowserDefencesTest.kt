package io.silencelen.andvari.app.autofill

import io.silencelen.andvari.app.trust.AutofillTrustRow
import io.silencelen.andvari.app.trust.autofillTrustRows
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * "Trust {browser}" trusted whatever sat on a browser's package name, showed
 * no package, installer or signer, had none of the app-fill confirm's defences, accepted an on-device approval for a
 * pinned id, and could not be seen or revoked on the new path.
 */
class TrustBrowserDefencesTest {
    private val chromePin = "8P1sW0EPJcslw7UzRsiXL64w+O50Ed+RBICtay1g24M="
    private val other = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    private val later = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="

    @Test
    fun aPinnedIdIsNeverTrustedByAnApprovalOnTheDevice() {
        assertTrue(TrustedBrowsers.decide("com.android.chrome", listOf(chromePin), null))
        // The reviewer's look-alike under com.android.chrome, approved on the device: before, trusted; now a mismatch.
        assertFalse(TrustedBrowsers.decide("com.android.chrome", listOf(other), other))
        assertEquals(ApprovedBrowsers.Offer.PINNED_MISMATCH, ApprovedBrowsers.offer("com.android.chrome", other, null))
        assertEquals(ApprovedBrowsers.Offer.PINNED_MISMATCH, ApprovedBrowsers.offer("com.chrome.beta", other, other))
    }

    @Test
    fun anApprovalHoldsOnlyForTheSignerItWasGivenTo() {
        val fx = "org.mozilla.firefox"
        assertTrue(TrustedBrowsers.decide(fx, listOf(other), other))
        assertFalse(TrustedBrowsers.decide(fx, listOf(later), other), "a different signer later is not trusted")
        assertEquals(ApprovedBrowsers.Offer.SIGNER_CHANGED, ApprovedBrowsers.offer(fx, later, other), "and it asks again with the warning")
        assertEquals(ApprovedBrowsers.Offer.FIRST_TIME, ApprovedBrowsers.offer(fx, other, null))
        assertFalse(TrustedBrowsers.decide("com.example.notabrowser", listOf(other), other), "an unknown id is never a browser")
    }

    private fun code(path: String): String = File("src/main/kotlin/io/silencelen/andvari/app/$path").readText()
        .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
        .lines().joinToString("\n") { it.substringBefore("//") }

    @Test
    fun theTrustCardShowsTheIdentityAndHasTheConfirmsDefences() {
        val a = code("autofill/TrustBrowserActivity.kt")
        assertTrue(a.contains("window.decorView.filterTouchesWhenObscured = true"))
        assertTrue(a.contains("view.filterTouchesWhenObscured = true"))
        assertTrue(a.contains("if (Build.VERSION.SDK_INT >= 31) window.setHideOverlayWindows(true)"))
        assertTrue(a.contains("if (!armed.value) return"))
        assertTrue(a.contains("Button(onClick = onTrust, enabled = armed"))
        // Package, installer line and signer, as the app-fill confirm shows them.
        assertTrue(a.contains("Text(identity.pkg,"))
        assertTrue(a.contains("AppFillGate.installerLine(identity.installer, identity.installerSystem)"))
        assertTrue(a.contains("AppFillGate.signerLine(identity.signerDigest)"))
        // A pinned mismatch has no Trust button; the signer is read again at the tap; approve refuses a pinned id.
        assertTrue(Regex("if \\(offer != ApprovedBrowsers\\.Offer\\.PINNED_MISMATCH\\) \\{[\\s\\S]*?Button\\(onClick = onTrust").containsMatchIn(a))
        val tap = a.substringAfter("private fun approveAndRefill(").substringBefore("override fun onWindowFocusChanged(")
        assertTrue(tap.contains("TrustedBrowsers.observedCertDigest(applicationContext, pkg) != digest || !ApprovedBrowsers.approve(applicationContext, pkg, digest)"))
        val ab = code("autofill/ApprovedBrowsers.kt")
        assertTrue(ab.contains("if (offer(pkg, digest, null) == Offer.PINNED_MISMATCH) return false"))
    }

    @Test
    fun settingsListsTrustedBrowsersAndRememberedAppsWithARevoke() {
        val rows = autofillTrustRows(mapOf("org.mozilla.firefox" to other, "com.brave.browser" to other), mapOf("com.example.b" to other, "com.example.a" to other))
        assertEquals(listOf("com.brave.browser", "org.mozilla.firefox", "com.example.a", "com.example.b"), rows.map { it.pkg })
        assertEquals(listOf(AutofillTrustRow.Kind.BROWSER, AutofillTrustRow.Kind.BROWSER, AutofillTrustRow.Kind.APP, AutofillTrustRow.Kind.APP), rows.map { it.kind })
        val s = code("trust/SettingsScreens.kt")
        assertTrue(s.substringAfter("internal fun SettingsSections(").substringBefore("\n}").contains("AutofillTrustSection()"))
        val section = s.substringAfter("internal fun AutofillTrustSection()")
        assertTrue(section.contains("ApprovedBrowsers.revoke(context, row.pkg)"))
        assertTrue(section.contains("AppSignerBindings.forget(context, row.pkg)"))
    }
}
