package io.silencelen.andvari.app.autofill

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Security review 2026-10, root cause G (HIGH): the autofill authentication activities used to
 * derive WHICH app or site they were filling from the `EXTRA_ASSIST_STRUCTURE` in their launch
 * intent. That extra is not in the PendingIntent's base intent — it rides the fill-in intent, which
 * the platform hands to the HOST app's process — so a malicious app could replace it with a
 * structure claiming `activityComponent = com.android.chrome` plus any web domain, and receive that
 * site's logins (and every card) in its own `onActivityResult`.
 *
 * The fix bakes the service's own verdict (the parsed form: package, per-field frame domains,
 * classified AutofillIds) into the BASE intent at fill time, where `Intent.fillIn` cannot override
 * it, and the activities fill only from that. [AutofillAuthGate] is the decision, factored pure
 * because neither `Intent` nor `AssistStructure` can be built in this module's JVM suite; the
 * activities' wiring is pinned by source text below (the [RegressionPins0262Test] idiom).
 */
class AutofillAuthBindingTest {

    /** Stand-in for the baked ParsedForm: the gate is generic over the form type. */
    private data class Form(override val appPackage: String) : PackageBound

    @Test
    fun forgedChromeStructureWithADifferentBakedPackageIsRefused() {
        val baked = Form("com.example.harvester")
        // The host app replaced the fill-in structure with one claiming to be Chrome on any domain.
        val verdict = AutofillAuthGate.resolve(bakedForm = baked, bakedPackage = baked.appPackage, injectedPackage = "com.android.chrome")
        assertNull(verdict, "a structure that disagrees with the baked package must refuse the fill")
    }

    @Test
    fun noBakedBindingIsRefusedEvenWhenTheInjectedStructureLooksFine() {
        // An IntentSender minted before this fix (or any launch without the binding) carries only
        // host-delivered identity, which is exactly what may not be trusted.
        assertNull(AutofillAuthGate.resolve<Form>(bakedForm = null, bakedPackage = null, injectedPackage = "com.android.chrome"))
        assertNull(AutofillAuthGate.resolve(bakedForm = Form("com.android.chrome"), bakedPackage = null, injectedPackage = "com.android.chrome"))
        assertNull(AutofillAuthGate.resolve(bakedForm = Form(""), bakedPackage = "", injectedPackage = null))
    }

    @Test
    fun theBakedFormIsUsedWhenTheStructureAgreesOrIsAbsent() {
        val baked = Form("com.android.chrome")
        assertEquals(baked, AutofillAuthGate.resolve(bakedForm = baked, bakedPackage = "com.android.chrome", injectedPackage = "com.android.chrome"))
        // The structure is only ever a cross-check — its absence costs nothing, identity comes from the bake.
        assertEquals(baked, AutofillAuthGate.resolve(bakedForm = baked, bakedPackage = "com.android.chrome", injectedPackage = null))
    }

    @Test
    fun aBakedPackageThatDisagreesWithItsOwnFormIsRefused() {
        // Both values are baked by the service, so this cannot happen without a bug — fail closed anyway.
        assertNull(AutofillAuthGate.resolve(bakedForm = Form("com.android.chrome"), bakedPackage = "com.example.app", injectedPackage = null))
    }

    // ---- wiring pins: the activities must fill from the bake, never from the injected structure ----

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/$name").readText()

    private fun code(name: String): String = src(name)
        .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
        .lines().joinToString("\n") { it.substringBefore("//") }

    @Test
    fun bothAuthActivitiesResolveTheFormThroughTheBindingAndNeverParseTheInjectedStructure() {
        for (name in listOf("autofill/AutofillUnlockActivity.kt", "autofill/TrustBrowserActivity.kt")) {
            val c = code(name)
            assertTrue(c.contains("FillBinding.resolve(intent)"), "$name must take its form from the baked binding")
            assertFalse(c.contains("StructureParser.parse("), "$name must never classify a host-delivered structure")
            assertFalse(Regex("responseForUnlocked\\([^)]*structure").containsMatchIn(c), "$name must not hand a structure to the dataset builder")
        }
        // The builder's unlocked entry point takes the parsed form, not a structure, so no caller can
        // re-derive identity from one by accident.
        val db = code("autofill/DatasetBuilder.kt")
        val entry = db.substring(db.indexOf("fun responseForUnlocked("), db.indexOf("fun buildUnlockedResponse("))
        assertTrue(entry.contains("form: ParsedForm"), "responseForUnlocked takes the baked ParsedForm")
        assertFalse(entry.contains("AssistStructure"), "responseForUnlocked must not accept an AssistStructure")
    }

    @Test
    fun everyAuthenticationIntentIsBakedAtFillTime() {
        val svc = code("autofill/AndvariAutofillService.kt")
        val locked = svc.substring(svc.indexOf("private fun lockedResponse("), svc.indexOf("override fun onSaveRequest("))
        assertTrue(locked.contains("FillBinding.bake("), "the Unlock row's PendingIntent must carry the service's verdict")
        val db = code("autofill/DatasetBuilder.kt")
        val trust = db.substring(db.indexOf("private fun trustBrowserDataset("), db.indexOf("fun lockedPresentation("))
        assertTrue(trust.contains("FillBinding.bake("), "the Trust-browser row's PendingIntent must carry the service's verdict")
    }

    // ---- adjacent wave-6 LOWs fixed in the same files ----

    @Test
    fun hostCapRejectsWhatDnsNeverAllowsAndAdmitsWhatItDoes() {
        assertTrue(HostCap.withinDnsLimits("accounts.example.com"))
        assertTrue(HostCap.withinDnsLimits("a".repeat(63) + ".example"))
        assertFalse(HostCap.withinDnsLimits("a".repeat(64) + ".example"), "a label is at most 63 characters")
        assertTrue(HostCap.withinDnsLimits(List(4) { "a".repeat(61) }.joinToString(".") + ".com"), "253 total is the ceiling")
        assertFalse(HostCap.withinDnsLimits(List(5) { "a".repeat(61) }.joinToString(".")), "over 253 total")
        // The wave-6 shape: one label of ~65k distinct non-ASCII code points. Must be rejected on
        // length alone — no normalisation, so no quadratic punycode work, ever runs on it.
        val hostile = buildString { for (cp in 0x4E00 until 0x4E00 + 65_000) appendCodePoint(cp) }
        val t0 = System.nanoTime()
        assertFalse(HostCap.withinDnsLimits(hostile))
        assertTrue(System.nanoTime() - t0 < 50_000_000L, "the cap must be a length check, not a parse")
    }

    @Test
    fun theDebugTraceCapsTheHostBeforeNormalisingIt() {
        val log = code("autofill/AutofillDebugLog.kt")
        val setForm = log.substring(log.indexOf("fun setForm("), log.indexOf("fun setTrust("))
        val cap = setForm.indexOf("HostCap.withinDnsLimits(")
        val norm = setForm.indexOf("UriMatch.normalizeHost(")
        assertTrue(cap > -1 && norm > cap, "the length cap must run before normalizeHost on the host-supplied webDomain")
    }

    @Test
    fun healthIsAmongTheScreensThatLockWhenTheSessionIsDroppedUnderneath() {
        val vm = code("AndvariViewModel.kt")
        val gate = vm.substring(vm.indexOf("if (VaultSession.get() == null) {"), vm.indexOf("if (s.busy || s.importBusy"))
        assertTrue(gate.contains("s.screen is Screen.Health"), "the Health screen holds decrypted state and must lock with the rest")
    }
}
