package io.silencelen.andvari.app

import io.silencelen.andvari.core.client.items.BellLink
import io.silencelen.andvari.core.client.net.BellMessageTooLarge
import io.silencelen.andvari.core.client.net.BellOpenFailed
import io.silencelen.andvari.core.client.net.BellOpenFailed.Reason
import io.silencelen.andvari.core.client.net.PlatformBellSocket
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.OkHttpClient
import java.io.BufferedInputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ProxySelector
import java.net.Socket
import java.net.SocketException
import java.net.URI
import java.net.URISyntaxException
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * The event bell's WebSocket on Android, given to the shared code's dialer as its
 * [PlatformBellSocket]. OkHttp, which is Android's HTTP engine, reads every frame of a message into one buffer whatever
 * its size, so the app carries the frames itself, over the platform's own TLS socket, with no new dependency.
 *
 * The contract is the one `PlatformBellSocket`'s documentation states; point by point:
 * 1. **Exactly the address, every header, the same trust.** [connect] opens [Target.of] the given url (`wss://`, or
 *    `ws://` to a loopback host the platform's network config permits cleartext to, as the HTTP client does) and sends
 *    every header given, refusing one that could split the request. TLS goes through [tls], which for the app is the
 *    socket factory of an OkHttp client built as [androidHttpClient]'s is (the platform's trust and the app's network
 *    config: no more). **The host name is verified twice:** the socket's endpoint identification is set to `HTTPS`
 *    before the handshake (and the open fails closed when the platform will not keep it), and OkHttp's own host-name
 *    check runs on the session after it, as the HTTP client's does.
 * 2. **No redirect.** Anything but `101` with the right `Sec-WebSocket-Accept` for the key sent (16 fresh random bytes
 *    every time), `Upgrade: websocket` and an upgrade `Connection`, and no extension or subprotocol (none was asked
 *    for), is a failure. A `Location` is never read.
 * 3. **Every failure is an [IOException]** (the one exception besides it is the cap's
 *    [BellMessageTooLarge], which the contract names): a failure to open, and a failure while open. What the platform
 *    throws that is not one (an argument the platform refuses, say) becomes one, without the platform's message. No
 *    message carries the address, so never the ticket. A failure of the bell's own block passes through as it is.
 * 4. **Closed at once** when the block returns or throws: a close frame is offered (bounded by the write timeout) and
 *    the connection is dropped without waiting for the server's.
 * 5. **Every message bounded** at the cap the dialer passes, BEFORE more is held: a frame header that declares more
 *    than is left (fragments counted together) ends the socket without reading the body; [BellLink.receive] throws
 *    [BellMessageTooLarge]. A length written in a longer form than it needs (RFC 6455 §5.2: "the minimal number of
 *    bytes MUST be used") ends the socket as a protocol failure.
 * 6. **Control frames** of more than 125 bytes, or fragmented, end the socket; a ping is answered with a pong.
 * 7. **receive** answers the next text message (strict UTF-8), skips binary messages (bounded the same way), answers
 *    null on the server's close or an end of stream between frames, and throws on anything else.
 * 8. **send** masks every frame with a fresh random mask and answers false once the socket is gone.
 *
 * **What is zeroed**: every buffer this socket makes or reads into that holds a message's bytes,
 * once it is done with them: the message buffer (after a whole message too), the buffer a skipped binary message is
 * read through, a control frame's payload, the part of its read buffer the frames were read from (after each message,
 * all of it at the end), and the upgrade request's bytes once written (the request is built as bytes, never as a
 * string builder). Not this socket's to zero, and so not zeroed: the immutable strings the dialer hands it (the
 * address, the ticket in it, the headers) and the text message it hands up, the TLS layer's and the system's own
 * buffers.
 *
 * **No thread is held for ever.** The name lookup and the TCP connect, the TLS handshake and the upgrade answer have,
 * together, the opening's deadline [Timeouts.openMs] (a server that dribbles its answer is dropped then); the lookup
 * runs where a cancellation or the deadline leaves it behind at once (the platform cannot interrupt a lookup), and the
 * TCP connect has [Timeouts.connectMs] of its own. An open socket's silence between frames has [Timeouts.readMs] (the
 * server pings every 30 s, spec 03 §6, so a healthy socket is never silent that long), and **every frame, and every
 * message from its first byte to its last fragment, has [Timeouts.messageMs]**: one byte, an empty fragment or a ping
 * at a time cannot hold a reader for ever while the dialer says "connected". (Pings with no message under way are the
 * server's keep-alive, and are answered as long as they come.) Every write has [Timeouts.writeMs]. A cancelled wait
 * closes the socket at once: the blocking read is ended by the close, never left behind.
 *
 * **A system proxy**: the socket takes the path the app's HTTP client takes. That client is
 * OkHttp with no proxy of its own, so it asks the system's [ProxySelector] for each address; so does this socket, for
 * a `wss://` address: a direct route connects to the server itself; an HTTP proxy is asked for a tunnel to the
 * server's host and port (`CONNECT`; only `200` opens it, and a proxy that asks for a sign-in is a failure, as OkHttp
 * without an authenticator answers it), and TLS with both host-name checks then runs end to end through it, exactly as
 * without a proxy; routes are tried in the order the system gives, a route that does not connect gives way to the
 * next. A SOCKS proxy, which Android's own settings never give, is refused (nothing is dialled). A plain `ws://`
 * socket, only ever to a loopback host, connects directly. What is dialled at the end, verified and bounded is the
 * same either way.
 *
 * **Nothing is logged:** no address, no ticket, no message, no header.
 */
class AndroidBellSocket internal constructor(
    private val tls: SSLSocketFactory,
    private val hostNames: HostnameVerifier,
    private val cleartextPermitted: (host: String) -> Boolean,
    private val timeouts: Timeouts = Timeouts(),
    private val random: SecureRandom = SecureRandom(),
    /** The name lookup (the platform's; a test's own). It may block: it runs where it can be left behind. */
    private val resolve: (host: String) -> List<InetAddress> = { InetAddress.getAllByName(it).toList() },
    /** The proxies for an address, as the system's [ProxySelector] gives them (what OkHttp asks too). */
    private val proxies: (URI) -> List<Proxy> = ::systemProxies,
) : PlatformBellSocket {

    /** Every bound on time, in milliseconds. */
    internal data class Timeouts(
        val connectMs: Int = 15_000,
        val openMs: Long = 30_000,
        val readMs: Int = 90_000,
        val writeMs: Long = 15_000,
        /** One frame, and one message from its first byte to its last fragment (64 KiB at most). */
        val messageMs: Long = 30_000,
    )

    /** Tests only: told of every buffer made to hold a message's bytes, so a test can see that each is zeroed. */
    @Volatile
    internal var heldProbe: ((ByteArray) -> Unit)? = null

    /** Tests only: told of the read buffer of each connection, so a test can see that it is zeroed at the end. */
    @Volatile
    internal var streamProbe: ((ByteArray) -> Unit)? = null

    /** Every connection being opened or open now, so that a network that went away can end them ([endAll]). */
    private val live: MutableSet<Conn> = java.util.Collections.newSetFromMap(java.util.concurrent.ConcurrentHashMap())

    /**
     * The network these sockets sit on went away ([BellNetworkWatch] calls it on the platform's
     * notice): every connection being opened or open now is dropped at once, so its blocking call ends at once instead
     * of after [Timeouts.readMs]. An open socket's read then throws (the dialer records BROKEN and the bell goes to its
     * ladder); an opening fails (NOT_OPENED). Nothing is dialled here: the dialer and the bell decide what happens next.
     * Answers how many were dropped.
     */
    internal fun endAll(): Int {
        var n = 0
        for (c in live.toList()) {
            c.dropForNetwork()
            n++
        }
        return n
    }

    override suspend fun <T> connect(url: String, headers: Map<String, String>, maxMessageBytes: Int, block: suspend (BellLink) -> T): T {
        val target = Target.of(url)
        if (maxMessageBytes < 1) throw BellOpenFailed(Reason.REQUEST_REFUSED, "no message cap")
        checkHeaders(headers)
        if (!target.secure && !(target.loopback && cleartextPermitted(target.host))) {
            throw BellOpenFailed(Reason.BAD_ADDRESS, "a plain socket is opened only to a loopback host the network config permits")
        }
        val conn = Conn()
        live += conn
        try {
            return opened(conn, target, headers, maxMessageBytes, block)
        } finally {
            live -= conn
        }
    }

    private suspend fun <T> opened(conn: Conn, target: Target, headers: Map<String, String>, maxMessageBytes: Int, block: suspend (BellLink) -> T): T =
        coroutineScope {
            // A cancelled wait closes the socket at once: the close ends whatever blocking call is under way.
            val onCancel = launch(start = CoroutineStart.UNDISPATCHED) {
                try {
                    awaitCancellation()
                } finally {
                    conn.drop()
                }
            }
            try {
                val startNs = System.nanoTime()
                // The name lookups first, inside the opening's deadline and ended by a cancellation (F10, the second note).
                val routes = withTimeoutOrNull(timeouts.openMs) { routes(target) }
                    ?: throw BellOpenFailed(Reason.NAME_LOOKUP_FAILED, "the server's name was not found in time")
                if (conn.networkGone) throw BellOpenFailed(Reason.NETWORK_GONE, "the network went away while the socket was opening")
                val deadline = launch {
                    delay(timeouts.openMs - (System.nanoTime() - startNs) / 1_000_000)
                    conn.dropIfOpening()
                }
                val link = try {
                    runInterruptible(Dispatchers.IO) { open(conn, target, routes, headers, maxMessageBytes) }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Throwable) {
                    // A wait cancelled while it blocked ends as the cancellation it is, not as the closed socket's error.
                    currentCoroutineContext().ensureActive()
                    if (conn.timedOut) throw BellOpenFailed(Reason.TIMED_OUT_OPENING, "the server did not open the socket in time")
                    if (conn.networkGone) throw BellOpenFailed(Reason.NETWORK_GONE, "the network went away while the socket was opening")
                    // Every failure is the shared code's BellOpenFailed with its reason (F10, the last note); the
                    // platform's own message is not kept.
                    throw openFailure(e)
                } finally {
                    deadline.cancel()
                }
                try {
                    block(link)
                } finally {
                    withContext(NonCancellable) { link.close() }
                }
            } finally {
                conn.drop()
                onCancel.cancel()
            }
        }

    /** One way to the server: through [proxy] (an HTTP proxy, at [addresses]:[port]) or, null, to the server itself. */
    private class Route(val proxy: Boolean, val addresses: List<InetAddress>, val port: Int)

    /**
     * The routes to [t] in the system's order, each with its addresses looked up (the system proxy, as the HTTP client
     * takes it: see the class's note). A route whose name is not found is left out; none left is a failure.
     */
    private suspend fun routes(t: Target): List<Route> {
        val chosen: List<Proxy> = if (!t.secure) {
            listOf(Proxy.NO_PROXY)
        } else {
            val given = try {
                proxies(URI("https", null, t.host.removePrefix("[").removeSuffix("]"), t.port, null, null, null))
            } catch (e: CancellationException) {
                throw e
            } catch (_: Throwable) {
                throw BellOpenFailed(Reason.PROXY_FAILED, "the system's proxy setting could not be read")
            }
            given.ifEmpty { listOf(Proxy.NO_PROXY) }
        }
        val routes = ArrayList<Route>()
        for (p in chosen) {
            val (proxied, host, port) = when (p.type()) {
                Proxy.Type.DIRECT -> Triple(false, t.host, t.port)
                Proxy.Type.HTTP -> {
                    val a = p.address() as? InetSocketAddress ?: throw BellOpenFailed(Reason.PROXY_FAILED, "the system names a proxy with no address")
                    Triple(true, a.hostString, a.port)
                }
                else -> throw BellOpenFailed(Reason.PROXY_FAILED, "the system names a SOCKS proxy, which this socket does not use")
            }
            val found = try {
                lookup(host)
            } catch (e: CancellationException) {
                throw e
            } catch (_: Throwable) {
                emptyList()
            }
            if (found.isNotEmpty()) routes += Route(proxied, found, port)
        }
        if (routes.isEmpty()) throw BellOpenFailed(Reason.NAME_LOOKUP_FAILED, "the server's name could not be found")
        return routes
    }

    /**
     * [resolve] on a thread of its own, so that the opening's deadline or a cancellation ends the wait at once: the
     * platform's lookup cannot be interrupted, so it is left to finish by itself, and its answer is dropped.
     */
    private suspend fun lookup(host: String): List<InetAddress> = suspendCancellableCoroutine { k ->
        val worker = Thread({
            val r = runCatching { resolve(host) }
            if (k.isActive) k.resumeWith(r)
        }, "andvari-bell-lookup")
        worker.isDaemon = true
        worker.start()
    }

    /** The blocking part of opening: TCP (through a proxy's tunnel where the route says), TLS with the host-name check, the upgrade. */
    private fun open(conn: Conn, t: Target, routes: List<Route>, headers: Map<String, String>, cap: Int): Link {
        val (plain, proxied) = connectFirst(conn, routes)
        if (proxied) tunnel(plain, t)
        val socket: Socket = if (t.secure) secure(conn, plain, t) else plain
        socket.soTimeout = timeouts.connectMs
        val input = ZeroingInput(socket.getInputStream())
        streamProbe?.invoke(input.probe())
        val output = socket.getOutputStream()

        val key = Base64.getEncoder().encodeToString(ByteArray(16).also(random::nextBytes))
        val parts = ArrayList<String>()
        parts += listOf("GET ", t.requestTarget, " HTTP/1.1\r\n", "Host: ", t.hostHeader, "\r\n", "Upgrade: websocket\r\n", "Connection: Upgrade\r\n")
        parts += listOf("Sec-WebSocket-Key: ", key, "\r\n", "Sec-WebSocket-Version: 13\r\n")
        headers.forEach { (k, v) -> parts += listOf(k, ": ", v, "\r\n") }
        parts += "\r\n"
        // As bytes from the start, in one buffer of the exact size: nothing of the request (the ticket is in it) is left
        // in a builder or a grown copy, and the one buffer is zeroed once written.
        val request = ByteArray(parts.sumOf { it.length })
        var at = 0
        for (s in parts) for (c in s) request[at++] = (if (c.code <= 0xFF) c.code else '?'.code).toByte()
        heldProbe?.invoke(request)
        try {
            output.write(request)
            output.flush()
        } finally {
            request.fill(0)
        }
        checkUpgrade(readHead(input), key)
        socket.soTimeout = timeouts.readMs
        conn.opened()
        return Link(conn, socket, input, output, cap)
    }

    /** TCP to the first address of the first route that answers; a refused or unreachable address gives way to the next. */
    private fun connectFirst(conn: Conn, routes: List<Route>): Pair<Socket, Boolean> {
        var last: IOException? = null
        for (r in routes) {
            for (a in r.addresses) {
                val plain = Socket()
                conn.set(plain, top = false)
                try {
                    plain.tcpNoDelay = true
                    plain.soTimeout = timeouts.connectMs
                    plain.connect(InetSocketAddress(a, r.port), timeouts.connectMs)
                    return plain to r.proxy
                } catch (e: IOException) {
                    try {
                        plain.close()
                    } catch (_: IOException) {
                        // Closed already.
                    }
                    if (conn.isDropped) throw e
                    last = e
                }
            }
        }
        // A refused or unreachable address, or a connect that did not finish in time: the server could not be reached.
        throw if (last == null || last is java.net.ConnectException || last is java.net.NoRouteToHostException || last is java.net.SocketTimeoutException) {
            BellOpenFailed(Reason.UNREACHABLE, "the server could not be reached")
        } else {
            openFailure(last)
        }
    }

    /**
     * An HTTP proxy's tunnel to [t]'s host and port (`CONNECT`, RFC 9110 §9.3.6), as OkHttp asks for one. Only `200`
     * opens it. The answer is read byte by byte from the socket itself, so nothing after it (the server's TLS) is read
     * here; it is bounded as the upgrade answer is, and inside the same deadline. No header but `Host` is sent: the
     * proxy learns the host and port, as it does for the HTTP client, and nothing else (the ticket travels inside TLS).
     */
    private fun tunnel(s: Socket, t: Target) {
        val authority = "${t.host}:${t.port}"
        s.soTimeout = timeouts.connectMs
        val out = s.getOutputStream()
        out.write("CONNECT $authority HTTP/1.1\r\nHost: $authority\r\n\r\n".toByteArray(Charsets.ISO_8859_1))
        out.flush()
        val head = readHead(s.getInputStream())
        val status = head.firstOrNull()?.let { PROXY_STATUS.matchEntire(it) }?.groupValues?.get(1)
            ?: throw BellOpenFailed(Reason.PROXY_FAILED, "a malformed answer from the proxy")
        if (status == "407") throw BellOpenFailed(Reason.PROXY_FAILED, "the proxy asks for a sign-in, which this socket does not give", status = 407)
        if (status != "200") throw BellOpenFailed(Reason.PROXY_FAILED, "the proxy answered $status: no tunnel", status = status.toIntOrNull())
    }

    /** TLS over [plain] to [t]'s host: the host name checked by the platform during the handshake and by OkHttp's check after it. */
    private fun secure(conn: Conn, plain: Socket, t: Target): Socket {
        val s = tls.createSocket(plain, t.host, t.port, true) as? SSLSocket
            ?: throw BellOpenFailed(Reason.NO_USABLE_TLS, "the platform gave no TLS socket")
        conn.set(s, top = true)
        val p = s.sslParameters
        p.endpointIdentificationAlgorithm = "HTTPS"
        if (t.host.any { it.isLetter() }) p.serverNames = listOf(SNIHostName(t.host))
        val protocols = MODERN_TLS.filter { it in s.supportedProtocols }
        if (protocols.isEmpty()) throw BellOpenFailed(Reason.NO_USABLE_TLS, "the platform offers neither TLS 1.3 nor TLS 1.2")
        p.protocols = protocols.toTypedArray()
        s.sslParameters = p
        // Fail closed: a platform that drops the setting would check no host name in the handshake.
        if (s.sslParameters.endpointIdentificationAlgorithm != "HTTPS") {
            throw BellOpenFailed(Reason.NO_USABLE_TLS, "the platform would not check the server's host name")
        }
        s.soTimeout = timeouts.connectMs
        s.startHandshake()
        if (!hostNames.verify(t.host, s.session)) throw BellOpenFailed(Reason.TLS_FAILED, "the server's certificate is not for its host name")
        return s
    }

    /** The status line and headers of the upgrade answer, at most [MAX_HEAD] bytes. */
    private fun readHead(input: InputStream): List<String> {
        val lines = ArrayList<String>()
        val line = StringBuilder()
        var total = 0
        while (true) {
            val b = input.read()
            if (b < 0) throw BellOpenFailed(Reason.MALFORMED_ANSWER, "the server ended the connection before it answered the upgrade")
            if (++total > MAX_HEAD) throw BellOpenFailed(Reason.TOO_LARGE, "the upgrade answer is too long")
            if (b == '\n'.code) {
                if (line.isEmpty() || line.last() != '\r') throw BellOpenFailed(Reason.MALFORMED_ANSWER, "a malformed upgrade answer")
                line.setLength(line.length - 1)
                if (line.isEmpty()) return lines
                lines += line.toString()
                line.setLength(0)
            } else {
                line.append(b.toChar())
            }
        }
    }

    private fun checkUpgrade(head: List<String>, key: String) {
        val status = head.firstOrNull()?.let { STATUS.matchEntire(it) }?.groupValues?.get(1)
            ?: throw BellOpenFailed(Reason.MALFORMED_ANSWER, "a malformed upgrade answer")
        if (status != "101") throw BellOpenFailed(Reason.UPGRADE_REFUSED, "the server answered $status, not 101: no socket (no redirect is followed)", status = status.toIntOrNull())
        val fields = HashMap<String, MutableList<String>>()
        for (h in head.drop(1)) {
            val colon = h.indexOf(':')
            if (colon <= 0) throw BellOpenFailed(Reason.MALFORMED_ANSWER, "a malformed upgrade answer")
            fields.getOrPut(h.substring(0, colon).trim().lowercase()) { ArrayList() } += h.substring(colon + 1).trim()
        }
        val expected = Base64.getEncoder().encodeToString(
            MessageDigest.getInstance("SHA-1").digest((key + WS_GUID).toByteArray(Charsets.ISO_8859_1)),
        )
        val accept = fields["sec-websocket-accept"]
        if (accept == null || accept.size != 1 || accept[0] != expected) throw BellOpenFailed(Reason.MALFORMED_ANSWER, "the upgrade answer does not prove the key sent")
        val upgrade = fields["upgrade"]
        if (upgrade == null || upgrade.size != 1 || !upgrade[0].equals("websocket", ignoreCase = true)) throw BellOpenFailed(Reason.MALFORMED_ANSWER, "the answer is not a WebSocket upgrade")
        if (fields["connection"].orEmpty().flatMap { it.split(',') }.none { it.trim().equals("upgrade", ignoreCase = true) }) {
            throw BellOpenFailed(Reason.MALFORMED_ANSWER, "the answer is not a WebSocket upgrade")
        }
        if (fields.containsKey("sec-websocket-extensions") || fields.containsKey("sec-websocket-protocol")) {
            throw BellOpenFailed(Reason.MALFORMED_ANSWER, "the server chose an extension or subprotocol that was not asked for")
        }
    }

    /** One open socket. Reads come from one caller at a time (the bell's loop); writes are serialised. */
    private inner class Link(
        private val conn: Conn,
        socket: Socket,
        input: ZeroingInput,
        private val output: OutputStream,
        cap: Int,
    ) : BellLink {
        private val reader = FrameReader(input, cap) { ms -> socket.soTimeout = ms }
        private val writeLock = Any()

        @Volatile
        private var ended = false

        override suspend fun send(text: String): Boolean {
            if (ended) return false
            val bytes = text.encodeToByteArray()
            return try {
                write(OP_TEXT, bytes)
                true
            } catch (e: CancellationException) {
                throw e
            } catch (_: Throwable) {
                end()
                currentCoroutineContext().ensureActive()
                false
            } finally {
                bytes.fill(0)
            }
        }

        override suspend fun receive(): String? {
            if (ended) return null
            while (true) {
                val event = try {
                    runInterruptible(Dispatchers.IO) { reader.next() }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Throwable) {
                    end()
                    currentCoroutineContext().ensureActive()
                    throw failure(e)
                }
                when (event) {
                    is Event.Text -> return event.text
                    is Event.Ping -> try {
                        write(OP_PONG, event.payload)
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Throwable) {
                        end()
                        currentCoroutineContext().ensureActive()
                        throw failure(e)
                    } finally {
                        event.payload.fill(0)
                    }
                    Event.Closed -> {
                        offerClose()
                        end()
                        return null
                    }
                }
            }
        }

        /** Offer a close frame and drop the connection, without waiting for the server's. */
        suspend fun close() {
            if (!ended) offerClose()
            end()
        }

        private suspend fun offerClose() {
            try {
                write(OP_CLOSE, byteArrayOf(0x03, 0xE8.toByte()))
            } catch (e: CancellationException) {
                throw e
            } catch (_: Throwable) {
                // The connection is dropped next whatever the write did.
            }
        }

        private fun end() {
            ended = true
            reader.zero()
            conn.drop()
            reader.zeroStream()
        }

        /** Every failure while open is an IOException, or the cap's own [BellMessageTooLarge] (F10, the last note). */
        private fun failure(e: Throwable): Throwable = openLinkFailure(e)

        /** One frame out, masked with a fresh random mask; the socket is dropped when it takes longer than the write timeout. */
        private suspend fun write(op: Int, payload: ByteArray) = coroutineScope {
            val dog = launch {
                delay(timeouts.writeMs)
                conn.drop()
            }
            try {
                runInterruptible(Dispatchers.IO) {
                    val frame = maskedFrame(op, payload)
                    try {
                        synchronized(writeLock) {
                            output.write(frame)
                            output.flush()
                        }
                    } finally {
                        frame.fill(0)
                    }
                }
            } finally {
                dog.cancel()
            }
        }

        private fun maskedFrame(op: Int, payload: ByteArray): ByteArray {
            val n = payload.size
            val lengthBytes = when {
                n <= 125 -> 0
                n <= 0xFFFF -> 2
                else -> 8
            }
            val frame = ByteArray(2 + lengthBytes + 4 + n)
            frame[0] = (0x80 or op).toByte()
            when (lengthBytes) {
                0 -> frame[1] = (0x80 or n).toByte()
                2 -> {
                    frame[1] = (0x80 or 126).toByte()
                    frame[2] = (n ushr 8).toByte()
                    frame[3] = n.toByte()
                }
                else -> {
                    frame[1] = (0x80 or 127).toByte()
                    for (i in 0 until 8) frame[2 + i] = (n.toLong() ushr (8 * (7 - i))).toByte()
                }
            }
            val maskAt = 2 + lengthBytes
            val mask = ByteArray(4).also(random::nextBytes)
            mask.copyInto(frame, maskAt)
            for (i in 0 until n) frame[maskAt + 4 + i] = (payload[i].toInt() xor mask[i and 3].toInt()).toByte()
            return frame
        }
    }

    private sealed interface Event {
        class Text(val text: String) : Event
        class Ping(val payload: ByteArray) : Event
        data object Closed : Event
    }

    /**
     * The server's frames, read blocking. A message's state lives across calls, so a ping between its fragments is
     * answered without losing it. The cap is checked against every frame HEADER before its body is read.
     */
    private inner class FrameReader(private val input: ZeroingInput, private val cap: Int, private val setReadTimeout: (Int) -> Unit) {
        private var held: ByteArray? = null
        private var size = 0L
        private var kind = 0

        /** When the frame or message under way must be whole (System.nanoTime); 0 while none is under way. */
        private var untilNs = 0L

        /**
         * Before each read: between frames with no message under way, the socket may be silent for [Timeouts.readMs];
         * inside a frame or a message, only for what is left of its [Timeouts.messageMs] (F10, the first note).
         */
        private fun arm() {
            if (untilNs == 0L) {
                setReadTimeout(timeouts.readMs)
                return
            }
            val leftMs = (untilNs - System.nanoTime()) / 1_000_000
            if (leftMs <= 0) throw BellMessageTimedOut()
            setReadTimeout(minOf(timeouts.readMs.toLong(), leftMs).toInt().coerceAtLeast(1))
        }

        /** A read inside a frame or message that timed out is the message's deadline. */
        private inline fun <T> timed(read: () -> T): T = try {
            arm()
            read()
        } catch (e: java.net.SocketTimeoutException) {
            if (untilNs != 0L && e !is BellMessageTimedOut) throw BellMessageTimedOut()
            throw e
        }

        fun next(): Event {
            while (true) {
                val b0 = timed { input.read() }
                if (b0 < 0) {
                    if (kind != 0) throw EOFException("the socket ended inside a message")
                    return Event.Closed
                }
                // A frame's deadline runs from its first byte; inside a message, the message's (from its first byte).
                if (untilNs == 0L) untilNs = System.nanoTime() + timeouts.messageMs * 1_000_000
                val b1 = readByte()
                val fin = b0 and 0x80 != 0
                if (b0 and 0x70 != 0) throw BellProtocolError("a frame with reserved bits set")
                val op = b0 and 0x0F
                if (b1 and 0x80 != 0) throw BellProtocolError("a masked frame from the server")
                var len = (b1 and 0x7F).toLong()
                if (len == 126L) {
                    len = readLength(2)
                    // RFC 6455 §5.2: the minimal number of bytes MUST be used (F10, the third note).
                    if (len < 126) throw BellProtocolError("a frame length in a longer form than it needs")
                } else if (len == 127L) {
                    len = readLength(8)
                    if (len < 0) throw BellProtocolError("a frame length above 2^63")
                    if (len <= 0xFFFF) throw BellProtocolError("a frame length in a longer form than it needs")
                }
                when (op) {
                    OP_CLOSE, OP_PING, OP_PONG -> {
                        if (!fin) throw BellProtocolError("a fragmented control frame")
                        if (len > 125) throw BellProtocolError("a control frame above 125 bytes")
                        val payload = ByteArray(len.toInt())
                        heldProbe?.invoke(payload)
                        try {
                            readFully(payload, 0, payload.size)
                        } catch (e: Throwable) {
                            payload.fill(0)
                            throw e
                        }
                        // The control frame is whole: with no message under way, the socket is between frames again.
                        if (kind == 0) untilNs = 0L
                        when (op) {
                            // The pong carries the ping's bytes; the receive zeroes them once it is written.
                            OP_PING -> return Event.Ping(payload)
                            OP_CLOSE -> {
                                payload.fill(0)
                                return Event.Closed
                            }
                            else -> {
                                payload.fill(0)
                                continue
                            }
                        }
                    }
                    OP_TEXT, OP_BINARY -> {
                        if (kind != 0) throw BellProtocolError("a new message inside a fragmented one")
                        kind = op
                    }
                    OP_CONTINUATION -> if (kind == 0) throw BellProtocolError("a continuation with no message")
                    else -> throw BellProtocolError("an unknown frame type")
                }
                // The bound, from the header alone: nothing of a frame that would pass it is read.
                if (len > cap - size) {
                    zero()
                    throw BellMessageTooLarge()
                }
                if (kind == OP_TEXT) {
                    val need = (size + len).toInt()
                    val buf = held.let { old ->
                        if (old != null && old.size >= need) {
                            old
                        } else {
                            val grown = ByteArray(minOf(cap, maxOf(need, 1024, 2 * (old?.size ?: 0))))
                            heldProbe?.invoke(grown)
                            old?.copyInto(grown, 0, 0, size.toInt())
                            old?.fill(0)
                            held = grown
                            grown
                        }
                    }
                    readFully(buf, size.toInt(), len.toInt())
                } else {
                    skip(len)
                }
                size += len
                if (!fin) continue
                if (kind == OP_BINARY) {
                    kind = 0
                    size = 0
                    untilNs = 0L
                    input.zeroConsumed()
                    continue
                }
                try {
                    return Event.Text(decode(held ?: ByteArray(0), size.toInt()))
                } finally {
                    zero()
                    input.zeroConsumed()
                }
            }
        }

        /** Zero and drop every byte of a message held. */
        fun zero() {
            held?.fill(0)
            held = null
            size = 0
            kind = 0
            untilNs = 0L
        }

        /** The socket is ended: its read buffer is zeroed whole. */
        fun zeroStream() = input.zeroAll()

        private fun decode(bytes: ByteArray, n: Int): String = try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes, 0, n))
                .toString()
        } catch (_: CharacterCodingException) {
            throw BellProtocolError("a text message that is not UTF-8")
        }

        private fun readByte(): Int {
            val b = timed { input.read() }
            if (b < 0) throw EOFException("the socket ended inside a frame")
            return b
        }

        private fun readLength(n: Int): Long {
            var v = 0L
            repeat(n) { v = (v shl 8) or readByte().toLong() }
            return v
        }

        private fun readFully(into: ByteArray, at: Int, n: Int) {
            var done = 0
            while (done < n) {
                val k = timed { input.read(into, at + done, n - done) }
                if (k < 0) throw EOFException("the socket ended inside a frame")
                done += k
            }
        }

        /** A skipped binary frame is read through a buffer of its own, zeroed after (F10, the fourth note). */
        private fun skip(n: Long) {
            val scratch = ByteArray(minOf(n, 4096L).toInt().coerceAtLeast(1))
            heldProbe?.invoke(scratch)
            try {
                var left = n
                while (left > 0) {
                    val k = timed { input.read(scratch, 0, minOf(left, scratch.size.toLong()).toInt()) }
                    if (k < 0) throw EOFException("the socket ended inside a frame")
                    left -= k
                }
            } finally {
                scratch.fill(0)
            }
        }
    }

    /**
     * The socket's read buffer, which it can zero: the part already read (the frames handed up or skipped) after each
     * message, and all of it once the socket is ended. Unread bytes (the next frames) are never touched while open.
     */
    private class ZeroingInput(source: InputStream) : BufferedInputStream(source, 8192) {
        fun probe(): ByteArray = buf

        @Synchronized
        fun zeroConsumed() {
            val b = buf ?: return
            java.util.Arrays.fill(b, 0, pos.coerceIn(0, b.size), 0)
        }

        @Synchronized
        fun zeroAll() {
            buf?.fill(0)
        }
    }

    /** The sockets of one connection: closing the TCP socket first ends every blocking call on it at once. */
    private class Conn {
        private var plain: Socket? = null
        private var top: Socket? = null
        private var dropped = false
        private var isOpen = false

        @Volatile
        var timedOut = false
            private set

        @Synchronized
        fun set(s: Socket, top: Boolean) {
            if (dropped) {
                closeQuietly(s)
                throw SocketException("the socket was closed")
            }
            if (top) this.top = s else plain = s
        }

        @Synchronized
        fun opened() {
            if (dropped) throw SocketException("the socket was closed")
            isOpen = true
        }

        /** The opening deadline: drops the connection only while it is still being opened. */
        @Synchronized
        fun dropIfOpening() {
            if (isOpen || dropped) return
            timedOut = true
            drop()
        }

        @Volatile
        var networkGone = false
            private set

        /** The network went away ([endAll]): dropped, and an opening says why. */
        @Synchronized
        fun dropForNetwork() {
            if (!dropped) networkGone = true
            drop()
        }

        val isDropped: Boolean
            @Synchronized get() = dropped

        @Synchronized
        fun drop() {
            dropped = true
            plain?.let(::closeQuietly)
            top?.let(::closeQuietly)
        }

        private fun closeQuietly(s: Socket) {
            try {
                s.close()
            } catch (_: Throwable) {
                // Already closed, or closing failed: either way nothing more is read or written.
            }
        }
    }

    /** The parts of a socket address this socket needs. Its messages never quote the address, which carries the ticket. */
    private class Target(
        val secure: Boolean,
        val host: String,
        val port: Int,
        val requestTarget: String,
        val hostHeader: String,
    ) {
        val loopback: Boolean get() = host == "127.0.0.1" || host == "localhost"

        companion object {
            fun of(url: String): Target {
                val u = try {
                    URI(url)
                } catch (_: URISyntaxException) {
                    throw BellOpenFailed(Reason.BAD_ADDRESS, "not a socket address")
                }
                val secure = when (u.scheme) {
                    "wss" -> true
                    "ws" -> false
                    else -> throw BellOpenFailed(Reason.BAD_ADDRESS, "not a socket address")
                }
                val host = u.host
                if (host.isNullOrEmpty() || u.rawUserInfo != null || u.rawFragment != null) throw BellOpenFailed(Reason.BAD_ADDRESS, "not a socket address")
                val port = if (u.port == -1) (if (secure) 443 else 80) else u.port
                // An address the dialer never builds fails as every failure does, never as the platform's argument error.
                if (port !in 1..65535) throw BellOpenFailed(Reason.BAD_ADDRESS, "not a socket address")
                val path = u.rawPath.orEmpty().ifEmpty { "/" }
                val requestTarget = if (u.rawQuery != null) path + "?" + u.rawQuery else path
                if (requestTarget.any { it <= ' ' || it.code >= 0x7F }) throw BellOpenFailed(Reason.BAD_ADDRESS, "not a socket address")
                return Target(secure, host, port, requestTarget, if (u.port == -1) host else "$host:$port")
            }
        }
    }

    companion object {
        /**
         * The app's socket: the trust and host-name check of an OkHttp client built as [androidHttpClient]'s engine is
         * (OkHttp's defaults: the platform's trust manager, which keeps the app's network security config), and that
         * config's cleartext rule for a plain loopback socket.
         */
        fun forApp(): AndroidBellSocket {
            val ok = OkHttpClient()
            return AndroidBellSocket(
                tls = ok.sslSocketFactory,
                hostNames = ok.hostnameVerifier,
                cleartextPermitted = { host -> android.security.NetworkSecurityPolicy.getInstance().isCleartextTrafficPermitted(host) },
            )
        }

        private const val OP_CONTINUATION = 0x0
        private const val OP_TEXT = 0x1
        private const val OP_BINARY = 0x2
        private const val OP_CLOSE = 0x8
        private const val OP_PING = 0x9
        private const val OP_PONG = 0xA
        private const val MAX_HEAD = 16 * 1024
        private const val WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        private val MODERN_TLS = listOf("TLSv1.3", "TLSv1.2")
        private val STATUS = Regex("HTTP/1\\.1 (\\d{3})(?: .*)?")
        private val PROXY_STATUS = Regex("HTTP/1\\.[01] (\\d{3})(?: .*)?")
        private val TOKEN = Regex("[!#$%&'*+.^_`|~0-9A-Za-z-]+")
        private val RESERVED = setOf("host", "upgrade", "connection", "sec-websocket-key", "sec-websocket-version", "sec-websocket-extensions", "sec-websocket-protocol")

        /** Headers that cannot split the request or override the upgrade's own. A refusal names no value. */
        private fun checkHeaders(headers: Map<String, String>) {
            for ((k, v) in headers) {
                if (!TOKEN.matches(k) || k.lowercase() in RESERVED) throw BellOpenFailed(Reason.REQUEST_REFUSED, "a header the socket will not send")
                if (v.any { (it < ' ' && it != '\t') || it.code >= 0x7F }) throw BellOpenFailed(Reason.REQUEST_REFUSED, "a header value the socket will not send")
            }
        }
    }
}

/**
 * The platform's own failure [e] while the socket was opening, as the shared code's [BellOpenFailed] with its reason
 * and a fixed message: the library's text (which can quote the address, and the ticket is in it) never travels up, and
 * no cause is attached.
 */
internal fun openFailure(e: Throwable): IOException = when (e) {
    is BellOpenFailed -> e
    is javax.net.ssl.SSLException -> BellOpenFailed(Reason.TLS_FAILED, "the TLS handshake failed or the certificate is not for the server's name")
    is java.net.SocketTimeoutException -> BellOpenFailed(Reason.TIMED_OUT_OPENING, "the server did not answer in time while the socket was opening")
    is java.net.ConnectException, is java.net.NoRouteToHostException -> BellOpenFailed(Reason.UNREACHABLE, "the server could not be reached")
    is EOFException, is SocketException -> BellOpenFailed(Reason.CONNECTION_LOST, "the connection ended while the socket was opening")
    else -> BellOpenFailed(Reason.OTHER, "the socket could not be opened")
}

/**
 * The platform's own failure [e] while the socket was open, as the shared code's [BellOpenFailed] with its reason: a
 * message or frame past its deadline, the connection gone, a server that broke the framing. A message too large stays
 * [BellMessageTooLarge] (the dialer records it as its own kind).
 */
internal fun openLinkFailure(e: Throwable): Throwable = when (e) {
    is BellMessageTooLarge, is BellOpenFailed -> e
    is BellProtocolError -> BellOpenFailed(Reason.PROTOCOL_ERROR, "the server broke the WebSocket framing")
    is java.net.SocketTimeoutException -> BellOpenFailed(Reason.PAST_DEADLINE, "a message or the next frame did not come in time")
    is EOFException, is SocketException -> BellOpenFailed(Reason.CONNECTION_LOST, "the connection ended")
    else -> BellOpenFailed(Reason.OTHER, "the socket failed")
}

/** A frame, or a message from its first byte to its last fragment, took longer than [AndroidBellSocket.Timeouts.messageMs]. */
internal class BellMessageTimedOut : java.net.SocketTimeoutException("a message took longer than its deadline")

/**
 * The proxies the system gives for [uri], as OkHttp asks for them when its client names no proxy of its own (the app's
 * HTTP client names none): the default [ProxySelector]; none, or no selector, is a direct route.
 */
internal fun systemProxies(uri: URI): List<Proxy> = ProxySelector.getDefault()?.select(uri).orEmpty()

/** The server broke the WebSocket framing (RFC 6455): the socket is ended. */
internal class BellProtocolError(message: String) : IOException(message)
