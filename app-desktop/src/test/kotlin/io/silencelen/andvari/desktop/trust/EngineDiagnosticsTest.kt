package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.engine.EngineAppApi
import io.silencelen.andvari.core.client.CoreLog
import io.silencelen.andvari.desktop.DesktopDiagnostics
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * The engine's diagnostics reach the desktop's own technical log: the app's composition root hands the engine its sink
 * before the engine starts, and a line the engine says arrives in the log with its event's code and the kind of record,
 * never the record's key (an account's id and its server's address).
 */
class EngineDiagnosticsTest {
    private val user = "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"
    private val server = "https://family.example"

    @Test
    fun aLineTheEngineSaysArrivesInTheDesktopsLogWithNothingOfAPersons() {
        val dir = Files.createTempDirectory("andvari-engine-diag").toFile()
        val log = File(dir, "diagnostic.log")
        DesktopDiagnostics.logFileOverride = log
        try {
            val model = TrustSeam.model(DesktopHome(File(dir, "home"), NoKeyStore, log = {}, keyStorePause = {}))
            val engine = model.api as EngineAppApi
            assertSame(TrustSeam.engineDiagnostics, engine.diagnostics, "the engine's sink is the desktop's log")
            engine.diagnostics.warn(
                CoreLog.EVENT_ACCOUNT_SWEEP_HELD_BACK,
                "the sweep of accounts this device no longer knows removed nothing: ovh.acct|$user|$server could not be read",
            )
            engine.diagnostics.warn(CoreLog.EVENT_ACCOUNT_SWEEP_STOPPED, "the sweep of accounts this device no longer knows stopped: the store refused to remove ovh.log|$user|$server")
            engine.diagnostics.warn(CoreLog.EVENT_ACCOUNT_SWEEP_HELD_BACK, "the sweep of accounts this device no longer knows removed nothing: the store's keys could not be read")
            val text = log.readText()
            println("ENGINE-LOG|${text.trim().replace("\n", " / ")}")
            assertTrue(text.contains("engine: account_sweep_held_back (record ovh.acct|…)"), text)
            assertTrue(text.contains("engine: account_sweep_stopped (record ovh.log|…)"), text)
            assertTrue(text.contains("engine: account_sweep_held_back (the store's keys)"), text)
            assertFalse(text.contains(user), "no account's id in the log")
            assertFalse(text.contains("family.example"), "no server's address in the log")
        } finally {
            DesktopDiagnostics.logFileOverride = null
        }
    }

    @Test
    fun aLineIsOneLineWhateverTheEventCarries() {
        assertEquals("engine: abc_d", TrustSeam.engineDiagnosticLine("abc\n_d", "no record"))
        assertEquals("engine: unnamed", TrustSeam.engineDiagnosticLine("\r\n", ""))
    }

    @Test
    fun theSinkIsHandedOverBeforeTheModelIsBuilt() {
        val seam = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/TrustSeam.kt").readText()
        val body = seam.substringAfter("fun model(").substringBefore("\n    }\n")
        val set = body.indexOf("api.diagnostics = engineDiagnostics")
        assertTrue(set >= 0, "the composition root sets the engine's sink")
        assertTrue(set < body.indexOf("return TrustModel("), "before the model, and so before the engine starts")
    }
}
