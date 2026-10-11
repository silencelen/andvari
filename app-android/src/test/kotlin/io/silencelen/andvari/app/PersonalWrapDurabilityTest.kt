package io.silencelen.andvari.app

import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Security review 2026-10, root cause A, branch A5b (A5 re-review M-1), Android half. The phone may run an
 * in-memory offline cache (org-forbid policy) and wipes the durable one on a policy flip or a revocation
 * purge. The cached personal wrap used to live only in that cache, so after a restart a server that withheld
 * the wrap met a device with no history. It now lives in the (origin, user) namespace's device state, which
 * those purges do not remove; core `PersonalChoiceHardeningTest` proves the engine then reports WITHHELD
 * across a restart with an in-memory cache. (Pure JVM: the engine-level run needs libsodium, which the
 * Android unit-test JVM does not load; the desktop twin runs it end to end.)
 */
class PersonalWrapDurabilityTest {
    private val base = Files.createTempDirectory("andvari-android-a5b").toFile()

    @AfterTest
    fun cleanup() {
        base.deleteRecursively()
    }

    @Test
    fun theDeviceStateSurvivesTheCachePurgesAndARestart() {
        val origin = OriginNamespace.originKey("https://vault.example.net")
        val wrap = """{"vaultId":"v-personal","wrappedVk":"c2VhbGVk"}"""
        PersonalDeviceState.open(base, origin, "u1").apply {
            set("personal.wrap", wrap)
            set("personal.last", "v-personal")
        }
        // The vault-cache DB a policy flip / revocation purge deletes, and the quick-unlock blob.
        val ns = OriginNamespace.dir(base, origin, "u1")
        File(ns, "vault-u1.db").writeText("db")
        OfflineData.deleteVaultCache(base, origin, "u1")
        QuickUnlock.wipe(base, origin, "u1")
        assertTrue(!File(ns, "vault-u1.db").exists(), "the purge did run")

        // Restart: a fresh handle over the same namespace still knows the wrap this device authenticated.
        val again = PersonalDeviceState.open(base, origin, "u1")
        assertEquals(wrap, again.get("personal.wrap"))
        assertEquals("v-personal", again.get("personal.last"))
        // Another origin's namespace is separate (§4.2).
        assertEquals(null, PersonalDeviceState.open(base, OriginNamespace.originKey("https://example.org"), "u1").get("personal.wrap"))
    }

    /** Every engine the app builds is given that device state: the main app and the autofill-only process. */
    @Test
    fun everyEngineIsBuiltWithTheDurableDeviceState() {
        val src = File("src/main/kotlin/io/silencelen/andvari/app")
        val vm = File(src, "AndvariViewModel.kt").readText()
        val autofill = File(src, "autofill/AutofillUnlock.kt").readText()
        for ((name, text) in listOf("AndvariViewModel" to vm, "AutofillUnlock" to autofill)) {
            val builds = Regex("""SyncEngine\(""").findAll(text).count()
            val withState = Regex("""SyncEngine\([^\n]*deviceState = PersonalDeviceState\.open\(""").findAll(text).count()
            assertTrue(builds > 0, "$name builds an engine")
            assertEquals(builds, withState, "$name: every SyncEngine gets the durable device state")
        }
        // The purges never reach it.
        val purge = File(src, "QuickUnlock.kt").readText().substringAfter("object OfflineData").substringBefore("object KdfReKey")
        assertTrue(!purge.contains("PersonalDeviceState") && !purge.contains(io.silencelen.andvari.core.client.FileDeviceState.FILE_NAME))
    }
}
