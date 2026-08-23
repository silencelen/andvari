package io.silencelen.andvari.app

import io.silencelen.andvari.core.client.UsageLedger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * The usage ledger's Android half (spec 02 §8.2) — "when did I last use this login", the signal
 * behind the web client's vault-health staleness ranking.
 *
 * Process-wide beside [VaultSession] rather than owned by a ViewModel, because the two things
 * that record a use live in different processes' worth of lifecycle: the UI's copy buttons and
 * (later) the autofill service. Every rule about the data lives in core [UsageLedger]; this owns
 * only the buffer, the debounce and the network.
 *
 * **Batched, never per-use** — spec 03 §3: one PUT per copy would turn the blob's own `updatedAt`
 * into a keystroke-grade activity trace, which is the leak the single-blob shape exists to avoid.
 *
 * **Every failure is silent.** This is a ranking hint. It must never surface an error, block a
 * copy, or retry hard enough to be noticed.
 *
 * Known gap, deliberately not faked: an autofill FILL is not recorded, because the framework
 * gives the service no callback when the system fills a dataset (unlike the extension, which has
 * a `reveal()` choke point). In-app copies are what this records today; `FillEventHistory` /
 * `TYPE_DATASET_SELECTED` is the lead for fills and is its own pass. The UI rule that an item
 * with no recorded use renders "—" and never "never used" is what keeps that gap honest.
 */
object UsageRecorder {

    /** Shorter than the web client's window: a phone process is killed far more readily, and an
     *  unflushed buffer dies with it. */
    const val FLUSH_DEBOUNCE_MS = 15_000L

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val lock = Any()
    private var pending: Map<String, UsageLedger.Entry> = emptyMap()
    private var flushJob: Job? = null

    /** Record a use. In memory only; the flush is debounced. Safe from any thread. */
    fun record(itemId: String, now: Long = System.currentTimeMillis()) {
        if (VaultSession.get() == null) return
        synchronized(lock) {
            pending = UsageLedger.record(pending, itemId, now)
            if (flushJob?.isActive == true) return
            flushJob = scope.launch {
                delay(FLUSH_DEBOUNCE_MS)
                flush()
            }
        }
    }

    /** Debounced flush against the live session. */
    suspend fun flush() {
        val session = VaultSession.get() ?: return
        storeWith(session, take())
    }

    /**
     * Flush against an EXPLICITLY passed session. The lock path needs this: it calls in before
     * dropping `state`, so [flush]'s own `VaultSession.get()` would already read null and the
     * session's last uses would be silently discarded. Fire-and-forget — a ranking hint may never
     * delay a lock.
     */
    fun flushForSession(session: VaultSession.Unlocked) {
        val mine = take()
        if (mine.isEmpty()) return
        scope.launch { storeWith(session, mine) }
    }

    private fun take(): Map<String, UsageLedger.Entry> = synchronized(lock) {
        val m = pending
        pending = emptyMap()
        m
    }

    /**
     * Merge against the server's current copy, then store. The re-read is what keeps
     * last-writer-wins from meaning last-writer-DESTROYS: the laptop's and the browser's entries
     * survive this flush even though the endpoint has no merge semantics of its own.
     */
    private suspend fun storeWith(session: VaultSession.Unlocked, mine: Map<String, UsageLedger.Entry>) {
        if (mine.isEmpty()) return
        try {
            var merged = mine
            // Could not read the remote copy — store ours rather than lose this session's uses.
            runCatching {
                session.api.usage().sealedUsage?.let { sealed ->
                    merged = UsageLedger.merge(UsageLedger.parse(session.account.openUsage(sealed).decodeToString()), mine)
                }
            }
            session.api.putUsage(session.account.sealUsage(UsageLedger.serialize(merged).encodeToByteArray()))
        } catch (_: Throwable) {
            // Re-arm rather than drop — but ONLY while a session still stands. This resumes after
            // suspension points, so on the lock path it can run AFTER clear(); re-arming
            // unconditionally there would resurrect behavioural records into a locked process.
            synchronized(lock) {
                if (VaultSession.get() != null) pending = UsageLedger.merge(mine, pending)
            }
        }
    }

    /** Drop the buffer. Called wherever vault material is dropped — behavioural records about a
     *  user's items must not outlive the session that produced them. */
    fun clear() {
        synchronized(lock) {
            flushJob?.cancel()
            flushJob = null
            pending = emptyMap()
        }
    }
}
