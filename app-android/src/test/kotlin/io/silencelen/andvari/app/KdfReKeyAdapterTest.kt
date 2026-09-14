package io.silencelen.andvari.app

import java.io.File
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Audit H85 — the phone's half of the F61 re-key hoist, pinned at the source level.
 *
 * The routine that derives a new master key, re-wraps the UVK and calls `PUT /account/password`
 * now lives once, in core `KdfReKeyCore` (`core/src/jvmShared`, which compiles into BOTH the JVM
 * and Android targets), and is exercised by `core`'s `KdfReKeyCoreTest`. What CANNOT be checked
 * from there is the wiring: that this module still routes through it instead of quietly growing a
 * second copy — the exact shape the audit found, where Android and the desktop had written the
 * same forty security-critical lines twice and nothing tied them together.
 *
 * Source-level for the same reason as BrowserAllowlistLockstepTest: these unit tests are pure JVM
 * with no Android framework, so `SessionStore`, `VaultSession` and the autofill service cannot be
 * instantiated here. Reading the SHIPPED source is what makes a one-sided edit fail
 * `:app-android:testDebugUnitTest` rather than reach a device.
 *
 * The caller-side gates are pinned too, because core deliberately does not know about them: the
 * A5 `mustChangePassword` refusal is Android state (the server's changePassword clears the flag,
 * so a silent re-key would erase an admin's recovery nudge), and so is the offline-cache gate.
 */
class KdfReKeyAdapterTest {

    /** Unit tests run with the MODULE dir as cwd; the repo-root fallback keeps this honest if that
     *  changes, and a missing file FAILS rather than vacuously passing. */
    private fun sourceFile(relative: String): File {
        val candidates = listOf(File(relative), File("app-android/$relative"))
        return candidates.firstOrNull { it.isFile }
            ?: error("could not locate $relative from ${File(".").absolutePath} — tried ${candidates.map { it.path }}")
    }

    private val quickUnlock by lazy { sourceFile("src/main/kotlin/io/silencelen/andvari/app/QuickUnlock.kt").readText() }
    private val viewModel by lazy { sourceFile("src/main/kotlin/io/silencelen/andvari/app/AndvariViewModel.kt").readText() }
    private val autofillUnlock by lazy { sourceFile("src/main/kotlin/io/silencelen/andvari/app/autofill/AutofillUnlock.kt").readText() }

    /** The adapter's body: from the delegation to the end of the object. */
    private val adapterBody by lazy {
        val at = quickUnlock.indexOf("KdfReKeyCore.maybeUpgrade(")
        assertTrue(at > 0, "KdfReKey must delegate to core KdfReKeyCore.maybeUpgrade")
        quickUnlock.substring(at)
    }

    @Test
    fun theReKeyIsDelegatedToCoreAndNotReImplementedHere() {
        // Any of these appearing in QuickUnlock.kt again means the hoisted routine has been
        // hand-copied back into the phone — the H85 defect, restored.
        for (marker in listOf(
            "Keys.masterKey(",
            "Keys.wrapKey(",
            "Envelope.sealB64(",
            "Account.deriveAuthKey(",
            "PasswordChangeRequest(",
        )) {
            assertFalse(
                quickUnlock.contains(marker),
                "$marker belongs to core KdfReKeyCore — the phone must not carry its own re-key",
            )
        }
    }

    @Test
    fun theAdapterSuppliesTheOfflineCacheGate() {
        // The one genuinely Android-side piece core does not own (design §4 step 3 + §5.3): the new
        // salt/params/wrappedUvk are cached ONLY when this device is allowed a durable cache. Losing
        // the gate would write vault-derived material to a device that opted out; losing the write
        // would make the next OFFLINE unlock derive with stale params and fail as a wrong password.
        assertTrue(adapterBody.contains("store.cacheAllowed"), "the persist lambda must keep the cache gate")
        assertTrue(adapterBody.contains("store.saveAccountKeys("), "an allowed cache must be updated")
    }

    @Test
    fun bothCallSitesStillRunTheReKeyBehindTheA5Gate() {
        // Core cannot check mustChangePassword — it is phone state. Both entry points must.
        assertTrue(viewModel.contains("KdfReKey.maybeUpgrade("), "the main app's unlock still re-keys")
        assertTrue(autofillUnlock.contains("KdfReKey.maybeUpgrade("), "the A6 autofill unlock still re-keys")
        val vmGate = viewModel.substringBefore("KdfReKey.maybeUpgrade(").takeLast(600)
        assertTrue(vmGate.contains("store.mustChangePassword"), "A5: the main app must refuse on a temp password")
        val afGate = autofillUnlock.substringBefore("KdfReKey.maybeUpgrade(").takeLast(600)
        assertTrue(afGate.contains("store.mustChangePassword"), "A5: the autofill path must refuse on a temp password")
    }
}
