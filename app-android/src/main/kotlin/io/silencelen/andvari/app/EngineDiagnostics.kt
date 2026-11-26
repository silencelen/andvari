package io.silencelen.andvari.app

import io.silencelen.andvari.app.autofill.AutofillDebugLog
import io.silencelen.andvari.core.client.CoreLog
import java.io.File

/**
 * The shared engine's diagnostics ([io.silencelen.andvari.core.app.engine.EngineAppApi.diagnostics]) in this phone's own
 * technical log: the ring of the autofill status screen ([AutofillDebugLog]), while its debugging is on, as a line of its
 * own (`origin` "engine", `reason` the event's code).
 *
 * Only the event's code is kept, never its sentence. The engine's lines today are the sweep of the records kept by the id
 * of an account this device no longer knows ([CoreLog.EVENT_ACCOUNT_SWEEP_HELD_BACK], [CoreLog.EVENT_ACCOUNT_SWEEP_STOPPED]),
 * and their sentence names the record: its key holds an account's id, and for the records of which account an address is
 * at a server, the server's address and the person's email address. The ring is shown on screen and can be copied off the
 * phone, so, by the log's own rule (an enum or a count, never a value), the sentence stays out.
 */
internal object EngineDiagnostics {
    /** The ring's `origin` of the engine's lines. */
    const val ORIGIN = "engine"

    /** The sink for [filesDir]'s ring, written only while [armed]. A fault of the log never reaches the engine. */
    fun sink(filesDir: File, armed: () -> Boolean, now: () -> Long = System::currentTimeMillis): CoreLog = CoreLog { event, _ ->
        runCatching { AutofillDebugLog.noteIn(filesDir, AutofillDebugLog.FillEvent(ts = now(), origin = ORIGIN, reason = event), armed) }
    }
}
