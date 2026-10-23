package io.silencelen.andvari.app

import io.silencelen.andvari.app.autofill.AppIdentityLookup
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Security review 2026-10, A14 (F7): an `androidapp://<pkg>` login filled into whichever app held
 * that package name. The decision is core AppFillGate (table-tested there); this pins the digest the
 * binding is keyed on and the wiring: identity from PackageManager on the service side, the verdict
 * and the identity baked into the confirm PendingIntent's base intent (root cause G), credentials
 * released only after the confirm, nothing silent on an error, bindings device-local and cleared on
 * sign-out. What a JVM test cannot prove (the system's real flags / installer / signer answers and
 * package visibility on API 30+) is an owner device check.
 */
class A14AppFillGateTest {
    @Test
    fun theSignerDigestIsTheCurrentSignersSha256InStableOrder() {
        val a = byteArrayOf(1, 2, 3)
        val b = byteArrayOf(4, 5, 6)
        val one = AppIdentityLookup.signerDigest(listOf(a))
        assertEquals(64, one.length)
        assertEquals("039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81", one, "SHA-256 of 01 02 03, lowercase hex")
        assertEquals(AppIdentityLookup.signerDigest(listOf(a, b)), AppIdentityLookup.signerDigest(listOf(b, a)), "multiple signers: order-free")
        assertNotEquals(one, AppIdentityLookup.signerDigest(listOf(a, b)), "a second signer changes the identity")
    }

    private fun sourceFile(relative: String): File =
        listOf(File(relative), File("app-android/$relative")).firstOrNull { it.isFile }
            ?: error("could not locate $relative from ${File(".").absolutePath}")
    private fun src(name: String) = sourceFile("src/main/kotlin/io/silencelen/andvari/app/$name").readText()

    @Test
    fun aGatedLoginReleasesNothingUntilTheConfirm() {
        val builder = src("autofill/DatasetBuilder.kt")
        assertTrue(builder.contains("val appGate = appGateFor(context, form)"), "the verdict is computed once per request, service-side")
        assertTrue(builder.contains("if (appGate != null && appGate.verdict != AppFillGate.Verdict.SILENT)"), "a non-silent verdict builds the confirm row")
        val confirm = builder.substring(builder.indexOf("private fun confirmDataset("), builder.indexOf("// ---- no-match fallback row ----"))
        assertTrue(confirm.contains("b.setValue(f.id, null)"), "the confirm row carries no credential value")
        assertTrue(confirm.contains("AppFillBinding.bake(FillBinding.bake(Intent(context, AppFillConfirmActivity::class.java), form), appGate, item.itemId)"))
        assertTrue(confirm.contains("b.setAuthentication(pi.intentSender)"))
    }

    @Test
    fun theConfirmActivityTrustsOnlyTheBakeAndTheLiveSigner() {
        val activity = src("autofill/AppFillConfirmActivity.kt")
        assertTrue(activity.contains("val form = FillBinding.resolve(intent)"), "the baked form, never the host-delivered structure")
        assertTrue(activity.contains("val bake = AppFillBinding.resolve(intent)"))
        assertTrue(activity.contains("AppIdentityLookup.lookup(applicationContext, bake.identity.pkg)"), "the signer is re-read live before anything is released")
        assertTrue(activity.contains("if (live.signerDigest != bake.identity.signerDigest)"), "a package replaced since the request is refused")
        assertTrue(activity.contains("AppSignerBindings.remember(applicationContext, bake.identity.pkg, digest)"))
        assertTrue(activity.contains("EXTRA_AUTHENTICATION_RESULT"))
    }

    @Test
    fun bindingsAreDeviceLocalAndClearedOnSignOut() {
        val vm = src("AndvariViewModel.kt")
        val signOut = vm.substring(vm.indexOf("fun signOut(reason: String? = null) {"), vm.indexOf("pendingBackupRequest = null", vm.indexOf("fun signOut(reason: String? = null) {")))
        assertTrue(signOut.contains("AppSignerBindings.clearAll(appContext)"), "sign-out forgets which apps this member confirmed")
        val store = src("autofill/AppSignerBindings.kt")
        assertTrue(store.contains("getSharedPreferences(PREFS, Context.MODE_PRIVATE)"), "a plain device-local preference")
        assertTrue(!store.contains("AndvariApi") && !store.contains("SyncEngine"), "never on the wire")
    }
}
