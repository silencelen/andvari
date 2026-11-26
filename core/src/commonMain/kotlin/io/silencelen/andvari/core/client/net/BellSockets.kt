package io.silencelen.andvari.core.client.net

import io.ktor.client.HttpClient
import io.ktor.client.plugins.websocket.ClientWebSocketSession
import io.ktor.client.request.header
import io.ktor.client.request.prepareRequest
import io.ktor.http.encodeURLParameter
import io.ktor.websocket.Frame
import io.silencelen.andvari.core.client.ANDVARI_CLIENT_VERSION
import io.silencelen.andvari.core.client.items.BellLink
import io.silencelen.andvari.core.client.items.BellSocket
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.io.IOException

/**
 * The seam through which a platform supplies the event bell's WebSocket itself (spec 03 §6), given to
 * `Dialer(pins, http, platform, bellSocket = …)`. A platform supplies one when its HTTP engine cannot bound a message
 * before it holds it (OkHttp, which Android's engine is, reads every frame of a message into one buffer whatever its
 * size); without one, the dialer opens the socket over the host's own HTTP engine.
 *
 * The dialer decides WHETHER and WHERE a socket opens (the origin guard, the origin's own address, the ticket) and
 * records what happened ([DialedBellSocket.failure]); the platform only carries frames. **The contract:**
 * - [connect] opens a WebSocket to exactly [url] (`wss://` + the origin's host + `/api/v1/events?ticket=…`; `ws://` only
 *   for the loopback development origins), sending every one of [headers] on the upgrade request. TLS is verified as
 *   the platform's own HTTP client verifies it, host name included. **No redirect is followed:** any answer but `101`
 *   with a correct `Sec-WebSocket-Accept` is a failure to open.
 * - A failure to open THROWS (any exception but cancellation; its class name, never its message, becomes the failure's
 *   detail, since a message can quote the address and so the ticket). It
 *   never answers silently. To say WHY, the platform throws [BellOpenFailed] with a [BellOpenFailed.Reason]: the dialer
 *   keeps that closed code ([BellFailure.reason]), never the message. The same holds for a failure while open.
 * - Once open, [connect] runs [block] over the socket and answers its result; when [block] returns or throws, the
 *   socket is closed at once (a close frame offered, the connection dropped without waiting for the server's reply).
 * - **Every message is bounded at [maxMessageBytes]** (64 KiB, `ResponseCaps.of(EVENTS)`), its fragments counted
 *   together, BEFORE more than that is held: a frame header that declares more, or fragments that add up to more, end
 *   the socket; the bytes held so far are zeroed; nothing of that message is handed up; and [BellLink.receive] throws
 *   [BellMessageTooLarge]. Control frames (ping, pong, close) are at most 125 bytes, as RFC 6455 says; a ping is
 *   answered with a pong.
 * - [BellLink.receive] answers the next TEXT message, skips binary messages (bounded the same way), and answers null
 *   once the socket is closed. Any other failure while open throws. [BellLink.send] sends one text message (masked, as
 *   a client must) and answers false when the socket is gone.
 *
 * The dialer checks every message it is handed against the cap again, so a reader that breaks the contract costs
 * memory once, never a message handed to the bell.
 */
interface PlatformBellSocket {
    suspend fun <T> connect(url: String, headers: Map<String, String>, maxMessageBytes: Int, block: suspend (BellLink) -> T): T
}

/** Thrown by a bell socket's [BellLink.receive] when a message would pass the cap: the socket is ended and nothing of the message is kept. */
class BellMessageTooLarge(message: String = "an event message above the cap ended the socket") : Exception(message)

/**
 * A platform bell socket's own failure ([PlatformBellSocket]), saying WHY as a closed code. The dialer keeps the class
 * name and [reason] ([BellFailure.reason], and `BellOpenFailed(REASON)` as the detail), NEVER [message]: a message is
 * free text from below and can quote the address, which carries the single-use ticket. So a host can tell the person
 * which of these went wrong without anything a platform wrote ever reaching a screen or a log.
 *
 * It is an `IOException` (on the JVM, `java.io.IOException`), as the platform's own failures to open are. A platform
 * WRAPS its library's own failures in it too (a connect refused or timed out: [Reason.UNREACHABLE]; a TLS handshake that
 * failed: [Reason.TLS_FAILED]; a read past its time: [Reason.PAST_DEADLINE]), with no cause attached, so the library's
 * text never travels up at all.
 *
 * [status] is the one bounded number a reason may carry: the three-digit HTTP status of [Reason.UPGRADE_REFUSED] (the
 * server's answer to the upgrade) or [Reason.PROXY_FAILED] (the proxy's answer to `CONNECT`). Any other number, or a
 * number with any other reason, is dropped here (null), so it is never text and never more than three digits.
 */
class BellOpenFailed(val reason: Reason, message: String = reason.name, status: Int? = null) : IOException(message) {
    /** A failure with a message only, as the first platform sockets threw it: the reason is [Reason.OTHER]. */
    constructor(message: String) : this(Reason.OTHER, message)

    /** The upgrade's or the proxy's status, 100..999, for the two reasons that carry one; otherwise null. */
    val status: Int? = status?.takeIf { it in 100..999 && reason.carriesStatus }

    /**
     * The closed list of reasons, one any platform's socket can use. A host maps each to its own words; it never shows
     * the exception's message. The list groups what a socket may tell apart more finely (Android's eight upgrade codes,
     * its six proxy codes) where no reader of the code needs the difference.
     */
    enum class Reason(internal val carriesStatus: Boolean = false) {
        /** Not an address this socket dials: not a socket address, or a plain socket to a host that may not have one. */
        BAD_ADDRESS,

        /** The dialer asked for something the socket does not send (a header, a missing message cap): a fault of this build, not the network's. */
        REQUEST_REFUSED,

        /** The server's name could not be looked up: not found, or the lookup did not finish in time. */
        NAME_LOOKUP_FAILED,

        /** A proxy the device is set to use did not open the way: its setting unreadable, no address, refused, malformed, or answered `CONNECT` with [status] (407 when it asks for a sign-in). */
        PROXY_FAILED(carriesStatus = true),

        /** No connection to the server: refused, or the connect did not finish in time. */
        UNREACHABLE,

        /** The socket was not opened within the opening's bound (the connection, TLS and the upgrade together). */
        TIMED_OUT_OPENING,

        /** The network the socket was being opened on went away while it opened. */
        NETWORK_GONE,

        /** No TLS this socket may use on this device: the platform gave none, offers neither TLS 1.3 nor 1.2, or would not check the host name. */
        NO_USABLE_TLS,

        /** The TLS handshake failed, or the server's certificate is not for its host name. */
        TLS_FAILED,

        /** The server answered the upgrade with [status], not `101` (no redirect is followed). */
        UPGRADE_REFUSED(carriesStatus = true),

        /** The upgrade answer was malformed or ended early, did not prove the key sent, was not a plain WebSocket upgrade, or chose an extension or subprotocol not asked for. */
        MALFORMED_ANSWER,

        /** Something the socket read was longer than it allows (the upgrade answer). A message above the cap is [BellMessageTooLarge]. */
        TOO_LARGE,

        /** A message, read or written on an open socket, did not complete within its deadline, or the server sent nothing for longer than the socket waits. */
        PAST_DEADLINE,

        /** The connection ended under the socket: closed, or ended inside a frame. */
        CONNECTION_LOST,

        /** The server broke the WebSocket protocol: reserved bits, a masked or malformed frame, a bad control frame, text that is not UTF-8. */
        PROTOCOL_ERROR,

        /** Anything else. */
        OTHER,
    }
}

/** Why the event socket is not open, as [DialedBellSocket.failure] keeps it: the last failure, until a socket opens. */
data class BellFailure(
    val kind: Kind,
    val detail: String,
    /** The platform's closed code when it threw [BellOpenFailed]; null for any other failure (the detail is then a class name or the dialer's own words). */
    val reason: BellOpenFailed.Reason? = null,
    /** [BellOpenFailed.status]: the upgrade's or the proxy's three-digit status, a field of its own, never in [detail]. */
    val status: Int? = null,
) {
    enum class Kind {
        /** The origin guard refused (no pin in force there, an address the origin grammar refuses, another origin): nothing was dialled. */
        ORIGIN_STOPPED,

        /** The socket could not be opened: no network, TLS, an upgrade the server refused or answered with anything but `101`, or an engine that could not open it. */
        NOT_OPENED,

        /** A message above the cap ([ResponseCaps.of]`(EVENTS)`) ended an open socket. */
        TOO_LARGE,

        /** An open socket failed (a read or a send threw), or the bell's own work over it did. */
        BROKEN,
    }
}

/**
 * The event bell's socket for ONE origin, as [Dialer.bellSocket] hands it out: the same dialer and the same rules as
 * every request (design §4.4 "The stop is enforced where the client dials").
 *
 * **The rule.** The socket's ticket is a credential, so it is a credentialed request, and stricter: it opens only when
 * [OriginGuard.mayOpenSocket] holds for the origin, which is
 * - the origin the socket was made for (an [open] for any other origin, served or typed, opens nothing);
 * - an address the origin grammar accepts (`TrustGrammar.isOrigin`: https with a DNS host name, no IP literal; the
 *   loopback forms for development), the rule for every address a client stores, dials or shows;
 * - with a PIN IN FORCE there: pinned, not forked, damaged, moving or unreadable. A kept setup offer, which lets the
 *   setup root's own requests go before card 0 is pinned, does not open a socket: no session exists yet to ring for.
 *
 * The rule is asked again before every frame the bell sends and every frame it reads: once the pin stops (a fork
 * marked, "Forget this server", a move begun) nothing more is sent on an open socket, and the next read ends it.
 *
 * **Bounded.** Every message handed to the bell is at most [ResponseCaps.of]`(EVENTS)` bytes of UTF-8, whichever reader
 * carried it (the engine's, below, or the platform's, [PlatformBellSocket]); a larger one ends the socket.
 *
 * **Nothing is silent.** [open] throws nothing but cancellation and answers null when no socket opened, as
 * [BellSocket] says; WHY is kept in [failure] (null again once a socket opens), and [connected] is true exactly while
 * one is open. So a host tells "no live updates" ([connected] false, [failure] set) from "connected" (true), and the
 * bell's own state (`EventBell.state`, OPEN once the server answered the first ping) from both.
 */
class DialedBellSocket internal constructor(
    private val origin: String,
    private val guard: OriginGuard,
    private val wire: PlatformBellSocket,
    platform: String,
    private val maxMessageBytes: Int = ResponseCaps.of(WireRoute.EVENTS).toInt(),
) : BellSocket {
    private val clientHeader = "$platform/$ANDVARI_CLIENT_VERSION"
    private val failureFlow = MutableStateFlow<BellFailure?>(null)
    private val connectedFlow = MutableStateFlow(false)

    /** The last reason no socket is open; null before any attempt and from the moment a socket opens. */
    val failure: StateFlow<BellFailure?> = failureFlow.asStateFlow()

    /** True exactly while a socket is open (upgraded, before its close). */
    val connected: StateFlow<Boolean> = connectedFlow.asStateFlow()

    private fun fail(kind: BellFailure.Kind, detail: String, reason: BellOpenFailed.Reason? = null, status: Int? = null) {
        failureFlow.value = BellFailure(kind, detail.take(200), reason, status)
    }

    /**
     * The exception's class name only, never its message: a networking library's message can quote the
     * request's address, and the single-use ticket travels in that address. A [BellOpenFailed] adds its closed reason,
     * still never its message.
     */
    private fun fail(kind: BellFailure.Kind, e: Throwable) {
        val name = e::class.simpleName ?: "error"
        val failed = e as? BellOpenFailed
        if (failed == null) fail(kind, name) else fail(kind, "$name(${failed.reason.name})", failed.reason, failed.status)
    }

    override suspend fun <T> open(origin: String, ticket: String, block: suspend (BellLink) -> T): T? {
        if (origin != this.origin || !guard.mayOpenSocket(origin)) {
            fail(BellFailure.Kind.ORIGIN_STOPPED, "the origin guard opens no socket for this address now")
            return null
        }
        val ws = when {
            origin.startsWith("https://") -> "wss://" + origin.removePrefix("https://")
            origin.startsWith("http://") -> "ws://" + origin.removePrefix("http://")
            else -> {
                fail(BellFailure.Kind.ORIGIN_STOPPED, "not an http origin")
                return null
            }
        }
        val url = ws + WireRoute.EVENTS.path + "?ticket=" + ticket.encodeURLParameter()
        var opened = false
        var done = false
        var result: T? = null
        try {
            wire.connect(url, mapOf("X-Andvari-Client" to clientHeader), maxMessageBytes) { link ->
                opened = true
                failureFlow.value = null
                connectedFlow.value = true
                try {
                    block(Link(link)).also { result = it; done = true }
                } finally {
                    connectedFlow.value = false
                }
            }
            done = true
        } catch (e: CancellationException) {
            currentCoroutineContext().ensureActive()
            if (!opened) fail(BellFailure.Kind.NOT_OPENED, e) else if (!done) fail(BellFailure.Kind.BROKEN, e)
        } catch (e: Throwable) {
            if (!opened) fail(BellFailure.Kind.NOT_OPENED, e) else if (!done) fail(BellFailure.Kind.BROKEN, e)
        } finally {
            connectedFlow.value = false
        }
        return result
    }

    /** The bell's view of one open socket: the guard before every frame, the cap on every message, and every failure kept. */
    private inner class Link(private val inner: BellLink) : BellLink {
        private var ended = false

        override suspend fun send(text: String): Boolean {
            if (ended) return false
            if (!guard.mayOpenSocket(origin)) {
                stop(BellFailure.Kind.ORIGIN_STOPPED, "the origin's pin stopped while the socket was open")
                return false
            }
            return try {
                inner.send(text)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                fail(BellFailure.Kind.BROKEN, e)
                ended = true
                false
            }
        }

        override suspend fun receive(): String? {
            if (ended) return null
            if (!guard.mayOpenSocket(origin)) return stop(BellFailure.Kind.ORIGIN_STOPPED, "the origin's pin stopped while the socket was open")
            val got: String? = try {
                inner.receive()
            } catch (e: CancellationException) {
                throw e
            } catch (e: BellMessageTooLarge) {
                // The platform's exception: its class name only, as every failure of this socket.
                return stop(BellFailure.Kind.TOO_LARGE, e::class.simpleName ?: "too large")
            } catch (e: Throwable) {
                fail(BellFailure.Kind.BROKEN, e)
                ended = true
                return null
            }
            if (got == null) {
                ended = true
                return null
            }
            val text: String = got
            if (utf8Above(text, maxMessageBytes)) return stop(BellFailure.Kind.TOO_LARGE, "a message above ${maxMessageBytes} bytes was handed up")
            if (!guard.mayOpenSocket(origin)) return stop(BellFailure.Kind.ORIGIN_STOPPED, "the origin's pin stopped while the socket was open")
            return text
        }

        private fun stop(kind: BellFailure.Kind, detail: String): String? {
            fail(kind, detail)
            ended = true
            return null
        }
    }

    internal companion object {
        /** True when [text]'s UTF-8 form is longer than [cap] bytes (at most 3 bytes per UTF-16 unit, 4 per surrogate pair). */
        fun utf8Above(text: String, cap: Int): Boolean {
            if (text.length > cap) return true
            if (text.length.toLong() * 3 <= cap) return false
            return text.encodeToByteArray().size > cap
        }
    }
}

/**
 * The socket over the dialer's own [http] (with the `WebSockets` plugin added in a derived client, so every
 * engine-level rule of the host's client applies to the socket too), for a platform that supplies none. Every request
 * carries the client header, as [KtorWireClient] does. Built only by [Dialer.bellSocket]: never without the guard.
 *
 * **The engine is ASKED for the frame limit, never told by its name.** The plugin is given no `maxFrameSize` (an engine
 * that refuses the setting would fail the upgrade itself, as ktor's OkHttp engine does: "Max frame size switch is not
 * supported"); the engine's session is offered the cap once open, and an engine that refuses it keeps the socket open.
 * Whether or not the engine bounds a frame before it reads, every fragment it hands up is counted here as it arrives:
 * past the cap the bytes held so far are zeroed and dropped, nothing of the message is returned, and
 * [BellLink.receive] throws [BellMessageTooLarge]. An engine that holds a whole message before it hands any of it up
 * (OkHttp) cannot be bounded from here: a platform with such an engine supplies its own [PlatformBellSocket].
 *
 * The socket is taken as the engine's own session (`ClientWebSocketSession`), not ktor's default session: the default
 * session reassembles fragments with no limit when the engine's session ignores `maxFrameSize`, as the JVM's engine
 * does. It is never held open by the close: when the block is done, a close frame is offered and the exchange is
 * cancelled, without waiting for a hostile server's reply.
 */
internal class KtorBellWire(private val http: HttpClient) : PlatformBellSocket {
    /** What the engine answered when last offered the cap: true it took it, false it refused; null before any socket opened. */
    var engineTookCap: Boolean? = null
        private set

    override suspend fun <T> connect(url: String, headers: Map<String, String>, maxMessageBytes: Int, block: suspend (BellLink) -> T): T {
        var result: Result<T>? = null
        try {
            http.prepareRequest(url) {
                headers.forEach { (k, v) -> header(k, v) }
            }.body<ClientWebSocketSession, Unit> { session ->
                engineTookCap = try {
                    session.maxFrameSize = maxMessageBytes.toLong()
                    true
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Throwable) {
                    false
                }
                try {
                    result = Result.success(block(Link(session, maxMessageBytes.toLong())))
                } finally {
                    session.outgoing.trySend(Frame.Close())
                    session.cancel()
                }
            }
        } catch (e: CancellationException) {
            // The session's own cancel above ends the exchange; a result already made stands.
            currentCoroutineContext().ensureActive()
            result?.let { return it.getOrThrow() }
            throw e
        }
        return (result ?: throw IllegalStateException("the socket closed before it opened")).getOrThrow()
    }

    /** One socket's frames: text messages up to [cap] bytes, fragments counted together as they arrive. */
    private class Link(private val session: ClientWebSocketSession, private val cap: Long) : BellLink {
        override suspend fun send(text: String): Boolean = try {
            session.outgoing.send(Frame.Text(text))
            true
        } catch (e: CancellationException) {
            throw e
        } catch (_: Throwable) {
            false
        }

        override suspend fun receive(): String? {
            var held: ByteArray? = null
            var size = 0
            var text = false
            try {
                while (true) {
                    val frame = session.incoming.receiveCatching().getOrNull() ?: return null
                    when (frame) {
                        is Frame.Ping, is Frame.Pong -> if (frame.data.size > cap) throw BellMessageTooLarge() else continue
                        is Frame.Text, is Frame.Binary -> {
                            if (held == null) text = frame is Frame.Text
                            val part = frame.data
                            if (size.toLong() + part.size > cap) {
                                part.fill(0)
                                throw BellMessageTooLarge()
                            }
                            if (frame.fin && held == null) {
                                if (!text) continue
                                return part.decodeToString()
                            }
                            val buf = held?.takeIf { it.size >= size + part.size } ?: ByteArray(minOf(cap, maxOf(1024L, 2L * (size + part.size))).toInt()).also { grown ->
                                held?.let { old -> old.copyInto(grown, 0, 0, size); old.fill(0) }
                            }
                            part.copyInto(buf, size)
                            size += part.size
                            held = buf
                            if (frame.fin) {
                                val whole = if (text) buf.decodeToString(0, size) else null
                                buf.fill(0)
                                held = null
                                size = 0
                                if (whole != null) return whole
                            }
                        }
                        // A close, or a frame type this socket has no use for, ends it.
                        else -> return null
                    }
                }
            } finally {
                held?.fill(0)
            }
        }
    }
}
