package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.SyncEngine
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.IOException

/**
 * Audit H10 — every user operation is BOUNDED. A UI layer holds a busy flag over its ops, and the
 * idle lock (and [VaultSession.getIfFresh]) defers while that flag is up, because a lock must
 * never close the engine under a running save. An op that waits on a server with no whole-call
 * cap therefore holds the vault unlocked past the policy window for as long as that server keeps
 * the connection open. Connect and read timeouts do not cover this: each read succeeds, the call
 * as a whole never ends. (The desktop fixed this first, in its `op`; this is that runner, so
 * every client gets the same bound.)
 *
 * A timeout surfaces as an [IOException], so every existing "can't reach the server" mapping and
 * every offline branch applies unchanged. Cancellation of the enclosing coroutine is not a
 * timeout and propagates as itself. Bounds nest: an inner bound's timeout is an IOException its
 * caller can handle, and an outer bound firing inside an inner one passes through the inner one
 * as a cancellation and surfaces as an IOException at the outer one.
 *
 * The bound takes effect at suspension points: blocking work inside [block] (a KDF on a worker)
 * finishes first and the timeout lands when it returns.
 */
suspend fun <T : Any> runBounded(timeoutMs: Long, block: suspend () -> T): T {
    val caller = currentCoroutineContext()[Job]
    val result = try {
        withTimeoutOrNull(timeoutMs) { block() }
    } catch (e: CancellationException) {
        // Our own timeout can come back as a cancellation withTimeoutOrNull does not recognise: a
        // library that cancels its work on our behalf may rethrow a fresh CancellationException
        // (Ktor does, carrying the timeout's message). While the caller is still active, nothing but
        // this bound cancelled the block, so it is the timeout, and it must read as one rather than
        // escape as a cancellation that skips every IOException branch.
        if (caller?.isActive != false) throw IOException("operation timed out", e)
        throw e
    }
    return result ?: throw IOException("operation timed out")
}

/**
 * Review 3: build something that holds key material ([make], CPU-bound: a KDF) off the caller's thread, and hand
 * it back; or [discard] it when the caller was cancelled while it was being built. `withContext` drops a result
 * that completes after its caller's cancellation, and a dropped account would keep its keys until the collector
 * came by.
 */
suspend fun <T : Any> handOff(make: () -> T, discard: (T) -> Unit): T {
    var made: T? = null
    try {
        return withContext(Dispatchers.Default) { make().also { made = it } }
    } catch (c: CancellationException) {
        made?.let(discard)
        throw c
    }
}

/** The whole-call budgets for the ops [runBounded] guards. */
object BoundedOps {
    /** The flat window for the small-JSON legs — generous for a policy probe, queued envelope
     *  pushes and a delta pull. Never carries attachment bytes. */
    const val FLAT_MS = 60_000L

    /** One authenticated recovery call: small JSON, and busy is held across it. */
    const val RECOVERY_CALL_MS = 30_000L

    /** The slowest household link a byte-carrying leg still has to fit. */
    const val ATTACHMENT_MIN_BYTES_PER_SEC = 16_384L

    /** Bytes above this add no more time (it is about the largest single attachment there is). */
    const val ATTACHMENT_CEILING_BYTES = 64L * 1024 * 1024

    /** Security review 2026-10 (A12, row 82): the hard ceiling on one rescue copy, however many
     *  items co-members put in the vault. */
    const val RESCUE_COPY_CEILING_MS = 90L * 60 * 1000

    /** Audit G10: a byte-carrying leg — [FLAT_MS] as the floor plus time for the bytes, so a large
     *  file over a slow link is never severed while a black-holed server still cannot hold on. */
    fun attachmentMs(sizeBytes: Long): Long =
        FLAT_MS + sizeBytes.coerceIn(0, ATTACHMENT_CEILING_BYTES) * 1000L / ATTACHMENT_MIN_BYTES_PER_SEC

    /** One flat window per pushed batch, so a large import gets a proportionate budget. */
    fun importMs(rows: Int): Long =
        FLAT_MS * (1 + (rows.coerceAtLeast(0) + SyncEngine.SERVER_BATCH_MAX - 1) / SyncEngine.SERVER_BATCH_MAX)

    /** A12 (row 82): the byte budget plus one [perItemMs] window per item, never above
     *  [RESCUE_COPY_CEILING_MS], and overflow-safe: the item count is co-member controlled. */
    fun rescueCopyMs(bytes: Long, itemCount: Int, perItemMs: Long = FLAT_MS): Long {
        val perItems = if (itemCount <= 0 || perItemMs <= 0) 0L
            else if (perItemMs > RESCUE_COPY_CEILING_MS / itemCount) RESCUE_COPY_CEILING_MS
            else itemCount * perItemMs
        return minOf(RESCUE_COPY_CEILING_MS, attachmentMs(bytes) + perItems)
    }
}
