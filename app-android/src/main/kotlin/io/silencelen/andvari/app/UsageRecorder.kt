package io.silencelen.andvari.app

import io.silencelen.andvari.core.client.UsageLedger
import io.silencelen.andvari.core.client.UsageRecorderCore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob

/**
 * The usage ledger's Android half (spec 02 §8.2) — "when did I last use this login", the signal
 * behind the web client's vault-health staleness ranking.
 *
 * Process-wide beside [VaultSession] rather than owned by a ViewModel, because the two things
 * that record a use live in different processes' worth of lifecycle: the UI's copy buttons and
 * (later) the autofill service. Every moving part — the buffer, the debounce, the take → merge →
 * store round trip, the session-gated re-arm, the G03 bounded teardown flush, and the G04
 * post-sync prune — lives in core [UsageRecorderCore] (audit G39), the F37 twin of the desktop's;
 * this object is only the phone's adapter: its window/timeout constants, its own IO scope, and
 * the [VaultSession]-derived session accessor + transport.
 *
 * **Batched, never per-use** — spec 03 §3: one PUT per copy would turn the blob's own `updatedAt`
 * into a keystroke-grade activity trace, which is the leak the single-blob shape exists to avoid.
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

    /** Bound on the lock-path flush ([flushForSession]) — the signOut logout precedent's shape:
     *  long enough for a GET+PUT round trip, short enough that a dead session's transport can
     *  never be held open noticeably. */
    const val LOCK_FLUSH_TIMEOUT_MS = 2_000L

    private val core = UsageRecorderCore<VaultSession.Unlocked>(
        scope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
        debounceMs = FLUSH_DEBOUNCE_MS,
        boundedFlushTimeoutMs = LOCK_FLUSH_TIMEOUT_MS,
        session = { VaultSession.get() },
        transportFor = { s ->
            object : UsageRecorderCore.Transport {
                override suspend fun fetchSealed(): String? = s.api.usage().sealedUsage
                override fun open(sealed: String): ByteArray = s.account.openUsage(sealed)
                override fun seal(plain: ByteArray): String = s.account.sealUsage(plain)
                override suspend fun put(sealed: String) = s.api.putUsage(sealed)
            }
        },
    )

    /** Record a use. In memory only; the flush is debounced. Safe from any thread. */
    fun record(itemId: String, now: Long = System.currentTimeMillis()) = core.record(itemId, now)

    /** Debounced flush against the live session. */
    suspend fun flush() = core.flush()

    /** Flush against an EXPLICITLY passed session, then run [then] (the G03 lock-path shape —
     *  [VaultSession.lock] hands `api.close()` in as [then]). See [UsageRecorderCore]. */
    fun flushForSession(session: VaultSession.Unlocked, then: () -> Unit = {}) = core.flushForSession(session, then)

    /** Flush AND prune against a COMPLETE live item set (audit G04) — the only caller is a
     *  successful full sync, where `engine.items()` is authoritative. Never the teardown path. */
    fun flushWithPrune(session: VaultSession.Unlocked, liveItemIds: Set<String>) =
        core.flushWithPrune(session, liveItemIds)

    /** The un-flushed buffer, for DISPLAY only — callers merge it over the server's copy. */
    fun peek(): Map<String, UsageLedger.Entry> = core.peek()

    /** Drop the buffer. Called wherever vault material is dropped — behavioural records about a
     *  user's items must not outlive the session that produced them. */
    fun clear() = core.clear()
}
