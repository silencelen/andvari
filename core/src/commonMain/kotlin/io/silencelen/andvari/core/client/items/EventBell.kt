package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.model.wire.EventFrame
import io.silencelen.andvari.core.model.wire.EventsTicketResponse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlin.random.Random

/** One open event socket, as the bell sees it: text frames out and in. */
interface BellLink {
    /** Send the text frame [text]; false when the socket is gone. */
    suspend fun send(text: String): Boolean

    /** The next text frame, or null once the socket is closed. Other frames are skipped. */
    suspend fun receive(): String?
}

/**
 * The event socket of spec 03 §6 (`GET /api/v1/events?ticket=`) at [origin], which is always the session client's own
 * ([WireClient.origin], never a served value). [open] runs [block] over the open socket and answers its result, or
 * null when the socket could not be opened. Nothing throws but cancellation.
 */
interface BellSocket {
    suspend fun <T> open(origin: String, ticket: String, block: suspend (BellLink) -> T): T?
}

/** What the bell is doing now. */
enum class BellState {
    /** Not started, or stopped by its host. */
    IDLE,

    /** Minting a ticket or dialing. */
    CONNECTING,

    /** Registered: the server answered the first `ping` (spec 03 §6 "registration proof"). */
    OPEN,

    /** Between attempts, on the backoff ladder. */
    WAITING,

    /** The origin may not be dialed (its pin forked, damaged or moving): no ticket, no socket. The host starts it again after a move. */
    ORIGIN_STOPPED,

    /** The session is over (a `401`/`403` at ticket mint, or a `revoked` frame): the bell does not reconnect. */
    REVOKED,
}

/**
 * The event bell (spec 03 §6): a dirty-bell, never a data plane. The host starts it while the vault is unlocked and
 * stops it on lock; [onRing] gets the `rev` a frame names (pull when it is above the device's own), and `null` on
 * every registered (re)open, since bells missed while down are not replayed. [onRevoked] gets a dead session: one the
 * SERVER ended, so the host ends the session and keeps this device's copy (design §4.4; [CopyDeletion] has no value
 * for it): never a sign-out, never a cache deletion.
 *
 * **The guard.** The ticket is minted through the session's own [client], so its origin guard, bearer and single
 * refresh apply, and the socket dials only [WireClient.origin]. [WireClient.stopped] is asked before the ticket and
 * again right before the dial: a forked, damaged or moving origin gets no ticket and no socket, and the bell ends in
 * [BellState.ORIGIN_STOPPED].
 *
 * **Reconnection.** A fresh single-use ticket per attempt; the wait doubles from 1 s to a 60 s cap with jitter, and
 * the ladder resets only when a REGISTERED socket (the first `pong`, not the upgrade: security review 2026-10, A17) ends
 * after it stayed registered for [STABLE_MS]; a shorter one is a failed attempt.
 * [reset] (foreground, unlock) zeroes the ladder and dials at once. A `401`/`403` at mint and a `revoked` frame stop
 * the bell for good. A ticket that is not a plain token is a failed attempt, never a URL.
 *
 * The host calls [start], [stop] and [reset] from one thread.
 */
class EventBell(
    private val client: WireClient,
    private val socket: BellSocket,
    private val onRing: suspend (rev: Long?) -> Unit,
    private val onRevoked: suspend () -> Unit,
    private val jitter: (maxMs: Long) -> Long = { maxMs -> maxMs / 2 + Random.nextLong(maxMs / 2 + 1) },
    private val pause: suspend (ms: Long) -> Unit = { delay(it) },
    /** Milliseconds on a monotonic clock: how long a registered socket stayed registered ([STABLE_MS]). */
    private val now: () -> Long = monotonicMs(),
) {
    var state: BellState = BellState.IDLE
        private set

    /** Failed attempts since the last socket that stayed registered for [STABLE_MS]: the rung of the ladder. */
    var failures: Int = 0
        private set

    private var scope: CoroutineScope? = null
    private var job: Job? = null

    /** Start ringing in [scope] (the host's, cancelled on lock); a running bell is left as it is. */
    fun start(scope: CoroutineScope) {
        if (job?.isActive == true) return
        this.scope = scope
        state = BellState.CONNECTING
        job = scope.launch { run() }
    }

    /** Stop: the socket closes, nothing reconnects. */
    fun stop() {
        job?.cancel()
        job = null
        scope = null
        if (state != BellState.REVOKED && state != BellState.ORIGIN_STOPPED) state = BellState.IDLE
    }

    /** The app came to the foreground or was unlocked: the ladder goes to zero and a waiting bell dials now. */
    fun reset() {
        failures = 0
        val s = scope ?: return
        if (state == BellState.WAITING) {
            job?.cancel()
            state = BellState.CONNECTING
            job = s.launch { run() }
        }
    }

    /** The wait before the next attempt after [failures] failures: 1 s doubling to 60 s, jittered. */
    fun waitMs(failures: Int): Long {
        val cap = if (failures >= 6) MAX_WAIT_MS else minOf(MAX_WAIT_MS, FIRST_WAIT_MS shl failures)
        return jitter(cap).coerceIn(0, cap)
    }

    private suspend fun run() {
        while (true) {
            when (attempt()) {
                Outcome.STOP -> return
                Outcome.AGAIN -> {}
            }
            state = BellState.WAITING
            pause(waitMs(failures - 1))
            state = BellState.CONNECTING
        }
    }

    private enum class Outcome { AGAIN, STOP }

    private suspend fun attempt(): Outcome {
        if (client.stopped) return originStopped()
        val minted = client.call(WireRoute.EVENTS_TICKET, decode = { WireJson.json.decodeFromString(EventsTicketResponse.serializer(), it) })
        val ticket = when (minted) {
            is WireResult.Ok -> minted.value.ticket
            is WireResult.Refused -> {
                if (minted.status == 401 || minted.status == 403) return revoked()
                if (client.stopped) return originStopped()
                failures++
                return Outcome.AGAIN
            }
            is WireResult.NoAnswer -> {
                failures++
                return Outcome.AGAIN
            }
        }
        if (!TICKET.matches(ticket)) {
            failures++
            return Outcome.AGAIN
        }
        if (client.stopped) return originStopped()
        var registered = false
        var registeredAt = 0L
        var revokedFrame = false
        socket.open(client.origin, ticket) { link ->
            if (!link.send(EventFrame.PING)) return@open
            while (true) {
                val text = link.receive() ?: break
                if (text == EventFrame.PONG) {
                    if (!registered) {
                        registered = true
                        registeredAt = now()
                        state = BellState.OPEN
                        onRing(null)
                    }
                    continue
                }
                if (text.length > MAX_FRAME_CHARS) continue
                val frame = runCatching { WireJson.json.decodeFromString(EventFrame.serializer(), text) }.getOrNull() ?: continue
                when (frame.type) {
                    EventFrame.REV -> frame.rev?.takeIf { it >= 0 }?.let { onRing(it) }
                    EventFrame.REVOKED -> {
                        revokedFrame = true
                        break
                    }
                }
            }
        }
        if (revokedFrame) return revoked()
        // A socket that never registered is a failed attempt, and so is one that did but did not stay: a server (or a front)
        // that kills sockets after the first frames would otherwise get a ticket, a handshake and a pull about once a second
        // without end, which is what the ladder exists to prevent (spec 03 §6). Only a socket that stayed
        // registered for [STABLE_MS] starts the ladder again from the bottom.
        if (registered && now() - registeredAt >= STABLE_MS) failures = 0
        failures++
        return Outcome.AGAIN
    }

    private fun originStopped(): Outcome {
        state = BellState.ORIGIN_STOPPED
        return Outcome.STOP
    }

    private suspend fun revoked(): Outcome {
        state = BellState.REVOKED
        onRevoked()
        return Outcome.STOP
    }

    companion object {
        const val FIRST_WAIT_MS = 1_000L
        const val MAX_WAIT_MS = 60_000L

        /** How long a registered socket must stay registered before its end starts the ladder again from the bottom. */
        const val STABLE_MS = 30_000L

        /** A monotonic millisecond clock, counted from its own creation. */
        fun monotonicMs(): () -> Long {
            val mark = kotlin.time.TimeSource.Monotonic.markNow()
            return { mark.elapsedNow().inWholeMilliseconds }
        }

        /** Server frames are a few bytes; anything longer is not one of them. */
        const val MAX_FRAME_CHARS = 4096

        /**
         * A ticket is a base64 token (256-bit random, spec 03 §6; the server mints standard base64), encoded as a query
         * parameter when sent. Anything else never becomes part of a URL.
         */
        private val TICKET = Regex("^[A-Za-z0-9+/_-]{16,128}={0,2}$")
    }
}
