package io.silencelen.andvari.app

import io.silencelen.andvari.app.autofill.AutofillDebugLog
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.engine.AppEngine
import io.silencelen.andvari.core.app.engine.EngineAppApi
import io.silencelen.andvari.core.client.CoreLog
import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.session.WireTransport
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.Dispatchers
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The shared engine's diagnostics reach this phone's technical log (the autofill status screen's ring) while its
 * debugging is on, by their code only: the sentence, which can name an account's id, a server's address and an email
 * address, is never written; the last fill's summary is never touched.
 */
class EngineDiagnosticsTest {
    private fun dir(): File = Files.createTempDirectory("engine-diagnostics").toFile()

    private fun ring(d: File): String {
        AutofillDebugLog.awaitWrites()
        return AutofillDebugLog.ringFileIn(d).takeIf { it.exists() }?.readText().orEmpty()
    }

    @Test
    fun aLineArrivesByItsCodeOnlyAndLeavesTheLastFillAlone() {
        val d = dir()
        val sink = EngineDiagnostics.sink(d, { true }, { 42L })
        sink.warn(CoreLog.EVENT_ACCOUNT_SWEEP_HELD_BACK, "the sweep … removed nothing: ovh.email|https://vault.example|ada@example.com could not be read")
        val text = ring(d)
        val event = kotlinx.serialization.json.Json.decodeFromString(AutofillDebugLog.FillEvent.serializer(), text.trim())
        assertEquals(EngineDiagnostics.ORIGIN, event.origin)
        assertEquals(CoreLog.EVENT_ACCOUNT_SWEEP_HELD_BACK, event.reason)
        assertEquals(42L, event.ts)
        assertNull(event.detail)
        assertFalse("ada@example.com" in text || "vault.example" in text, "nothing of the sentence")
        assertNull(AutofillDebugLog.lastEventIn(d), "the last fill's summary stays a fill")
    }

    @Test
    fun withDebuggingOffNothingIsWritten() {
        val d = dir()
        EngineDiagnostics.sink(d, { false }).warn(CoreLog.EVENT_ACCOUNT_SWEEP_STOPPED, "stopped")
        assertEquals("", ring(d))
        assertFalse(AutofillDebugLog.ringFileIn(d).exists())
    }

    /** A device state that cannot list its keys: the engine's sweep at its start removes nothing and says so. */
    private class KeysUnlisted : DeviceState {
        private val inner = MemoryDeviceState()
        override fun get(key: String): String? = inner.get(key)
        override fun set(key: String, value: String?) = inner.set(key, value)
        override fun keys(): Set<String>? = null
    }

    @Test
    fun theEnginesOwnLineArrivesFromItsStart() {
        val d = dir()
        val noServer = WireTransport { origin, _ -> throw IllegalStateException("no server in this test: $origin") }
        val api = EngineAppApi(
            AppEngine(
                AppPlatform.ANDROID, "Pixel", noServer, KeysUnlisted(), MemoryDeviceState(), createCryptoProvider(), { 1_700_000_000_000L },
                baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
            ),
        )
        api.diagnostics = EngineDiagnostics.sink(d, { true })
        api.start()
        val text = ring(d)
        assertTrue("\"reason\":\"${CoreLog.EVENT_ACCOUNT_SWEEP_HELD_BACK}\"" in text, "the sweep's line arrived: $text")
        assertTrue("\"origin\":\"${EngineDiagnostics.ORIGIN}\"" in text)
        assertFalse("store's keys" in text, "nothing of the sentence")
    }

    @Test
    fun thePhoneSetsTheSinkBeforeTheEngineStarts() {
        val seam = File("src/main/kotlin/io/silencelen/andvari/app/trust/TrustSeam.kt").readText()
        val set = seam.indexOf("engine.diagnostics = io.silencelen.andvari.app.EngineDiagnostics.sink(app.filesDir, { io.silencelen.andvari.app.autofill.AutofillDebugLog.debugEnabled(app) })")
        assertTrue(set > 0 && set < seam.indexOf("model.start()"), "set where the engine is built, before its start")
    }
}
