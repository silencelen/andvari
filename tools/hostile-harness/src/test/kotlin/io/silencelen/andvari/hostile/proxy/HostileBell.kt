package io.silencelen.andvari.hostile.proxy

import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.api.createClientPlugin
import io.ktor.http.URLProtocol
import io.ktor.http.Url
import java.io.BufferedInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/** One upgrade request to the hostile bell, recorded whole before its script ran. */
class BellUpgrade(val path: String, val query: String?, val headers: Map<String, String>) {
    fun header(name: String): String? = headers.entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value
    fun queryParam(name: String): String? = query?.split('&')?.firstOrNull { it.startsWith("$name=") }?.substringAfter('=')
}

/**
 * One accepted WebSocket on the hostile bell, after the handshake: what its script writes, frame by frame, over the
 * real TCP socket. [written] counts the frame bytes the device let it write (headers included); a write blocks once
 * the device stops reading, so a stall is the device refusing more, and [ended] is the device hanging up.
 */
class BellConn internal constructor(private val socket: Socket, val upgrade: BellUpgrade) {
    private val input: InputStream = BufferedInputStream(socket.getInputStream())
    private val output: OutputStream = socket.getOutputStream()

    val written = AtomicLong()

    @Volatile var ended: Boolean = false
        internal set

    /** The text of the device's next text frame (its `ping`), or null when it closed. Control frames are skipped. */
    fun readText(): String? {
        while (true) {
            val b0 = input.read()
            if (b0 < 0) return null
            val b1 = input.read()
            if (b1 < 0) return null
            var len = (b1 and 0x7f).toLong()
            if (len == 126L) len = ((input.read() shl 8) or input.read()).toLong()
            else if (len == 127L) { len = 0; repeat(8) { len = (len shl 8) or input.read().toLong() } }
            val mask = if (b1 and 0x80 != 0) ByteArray(4) { input.read().toByte() } else null
            val payload = input.readNBytes(len.toInt())
            if (mask != null) for (i in payload.indices) payload[i] = (payload[i].toInt() xor mask[i % 4].toInt()).toByte()
            when (b0 and 0x0f) {
                0x1 -> return payload.decodeToString()
                0x8 -> return null
                else -> continue
            }
        }
    }

    /** One whole text frame. */
    fun sendText(text: String) = frame(OP_TEXT, fin = true, text.encodeToByteArray())

    /** A frame with [opcode] and [payload], unmasked as a server's are. */
    fun frame(opcode: Int, fin: Boolean, payload: ByteArray) {
        val header = header(opcode, fin, payload.size.toLong())
        write(header, header.size)
        write(payload, payload.size)
    }

    /**
     * A text frame whose header declares [declaredLength] bytes, then [fill] bytes until [upTo] payload bytes are
     * written or the device stops taking them: the endless frame.
     */
    fun endlessFrame(declaredLength: Long, upTo: Long, fill: Byte = 0x41) {
        val h = header(OP_TEXT, fin = true, declaredLength)
        write(h, h.size)
        stream(upTo, fill)
    }

    /**
     * A text frame that never ends by fragments: a first text fragment (`fin` clear) of [piece] bytes, then continuation
     * fragments of [piece] bytes, none final, until [upTo] payload bytes are written or the device stops taking them.
     */
    fun endlessFragments(piece: Int, upTo: Long, fill: Byte = 0x41) {
        val body = ByteArray(piece) { fill }
        var sent = 0L
        var opcode = OP_TEXT
        while (sent < upTo) {
            val h = header(opcode, fin = false, piece.toLong())
            write(h, h.size)
            write(body, body.size)
            sent += piece
            opcode = OP_CONTINUATION
        }
    }

    private fun stream(upTo: Long, fill: Byte) {
        val piece = ByteArray(64 * 1024) { fill }
        var sent = 0L
        while (sent < upTo) {
            val n = minOf(piece.size.toLong(), upTo - sent).toInt()
            write(piece, n)
            sent += n
        }
    }

    private fun write(bytes: ByteArray, n: Int) {
        try {
            output.write(bytes, 0, n)
            output.flush()
            written.addAndGet(n.toLong())
        } catch (e: IOException) {
            ended = true
            throw e
        }
    }

    private fun header(opcode: Int, fin: Boolean, len: Long): ByteArray {
        val b0 = ((if (fin) 0x80 else 0) or opcode).toByte()
        return when {
            len < 126 -> byteArrayOf(b0, len.toByte())
            len <= 0xffff -> byteArrayOf(b0, 126, (len shr 8).toByte(), len.toByte())
            else -> byteArrayOf(b0, 127) + ByteArray(8) { i -> (len shr (8 * (7 - i))).toByte() }
        }
    }

    /**
     * Wait until the device has stopped taking bytes: it hung up ([ended]), the script finished, or [written] has not
     * moved for [quietMs]. Answers [written] at that point.
     */
    fun awaitQuiet(done: () -> Boolean, quietMs: Long = 3_000, maxMs: Long = 180_000): Long {
        val start = System.currentTimeMillis()
        var last = -1L
        var since = System.currentTimeMillis()
        while (System.currentTimeMillis() - start < maxMs) {
            if (ended || done()) return written.get()
            val now = written.get()
            if (now != last) { last = now; since = System.currentTimeMillis() } else if (System.currentTimeMillis() - since >= quietMs) return now
            Thread.sleep(50)
        }
        error("the device kept taking bytes for $maxMs ms: ${written.get()} so far")
    }

    fun close() = runCatching { socket.close() }

    companion object {
        const val OP_CONTINUATION = 0x0
        const val OP_TEXT = 0x1
    }
}

/**
 * The hostile event bell (spec 03 §6, `GET /api/v1/events?ticket=`): a raw WebSocket server on a real loopback socket,
 * since the proxy's HTTP server cannot upgrade. A device made with [clientFor] mints its ticket through the proxy from
 * the real server as always, and its socket comes here instead of to the server; each upgrade is recorded
 * ([upgrades]) and handed to [script], which writes whatever frames the test wants, honest or not.
 */
class HostileBell : AutoCloseable {
    private val server = ServerSocket(0, 16, InetAddress.getLoopbackAddress())
    private val clients = CopyOnWriteArrayList<HttpClient>()

    val port: Int get() = server.localPort

    val upgrades: MutableList<BellUpgrade> = CopyOnWriteArrayList()

    /** Each accepted socket, in order, as its script runs. */
    val conns = LinkedBlockingQueue<BellConn>()
    private val all = CopyOnWriteArrayList<BellConn>()

    /** What the bell does with each socket; the default answers the `ping` with `pong` and holds the socket open. */
    @Volatile var script: (BellConn) -> Unit = { c -> if (c.readText() == "ping") c.sendText("pong"); while (c.readText() != null) Unit }

    /** True once the script for the latest socket returned or threw. */
    @Volatile var scriptDone: Boolean = false
        private set

    /** A script that threw something other than the device hanging up: a mistake in the test. */
    val failures: MutableList<Throwable> = CopyOnWriteArrayList()

    init {
        Thread({
            while (!server.isClosed) {
                val s = try { server.accept() } catch (_: IOException) { break }
                Thread({ serve(s) }, "hostile-bell-conn").apply { isDaemon = true }.start()
            }
        }, "hostile-bell").apply { isDaemon = true }.start()
    }

    private fun serve(s: Socket) {
        val upgrade = try { handshake(s) } catch (_: IOException) { s.close(); return }
        upgrades += upgrade
        val c = BellConn(s, upgrade)
        scriptDone = false
        all += c
        conns += c
        try {
            script(c)
        } catch (_: IOException) {
            c.ended = true
        } catch (t: Throwable) {
            failures += t
        } finally {
            scriptDone = true
        }
    }

    private fun handshake(s: Socket): BellUpgrade {
        val input = s.getInputStream()
        val head = StringBuilder()
        while (!head.endsWith("\r\n\r\n")) {
            val b = input.read()
            if (b < 0) throw IOException("closed during the handshake")
            head.append(b.toChar())
            if (head.length > 16_384) throw IOException("handshake too long")
        }
        val lines = head.split("\r\n").filter { it.isNotEmpty() }
        val target = lines.first().split(' ')[1]
        val headers = lines.drop(1).associate { it.substringBefore(':').trim() to it.substringAfter(':').trim() }
        val upgrade = BellUpgrade(target.substringBefore('?'), target.substringAfter('?', "").ifEmpty { null }, headers)
        val key = upgrade.header("Sec-WebSocket-Key") ?: throw IOException("no key")
        val accept = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1").digest((key + GUID).encodeToByteArray()))
        s.getOutputStream().write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: $accept\r\n\r\n".encodeToByteArray())
        s.getOutputStream().flush()
        return upgrade
    }

    /** The next socket a device opens, within [timeoutMs]. */
    fun nextConn(timeoutMs: Long = 30_000): BellConn = conns.poll(timeoutMs, TimeUnit.MILLISECONDS) ?: error("no socket reached the hostile bell")

    /**
     * A device's HTTP client: every `http` request to [origin] goes to [dial] (the proxy's listener for the device), and
     * every `ws` request to [origin] comes to this bell. Anything else is refused, as the harness's other clients do.
     */
    fun clientFor(origin: String, dial: String): HttpClient {
        val o = Url(origin)
        val d = Url(dial)
        require(d.protocol.name == "http" && d.host == "127.0.0.1") { "a test redirects only to a loopback address: $dial" }
        return HttpClient(Java) {
            install(HttpTimeout) { requestTimeoutMillis = 60_000; connectTimeoutMillis = 10_000 }
            expectSuccess = false
            install(createClientPlugin("bell-redirect") {
                onRequest { req, _ ->
                    val port = req.url.port.takeIf { it != 0 } ?: req.url.protocol.defaultPort
                    check(req.url.host == o.host && port == o.port) { "refusing to dial ${req.url.host}:$port: this test redirects only ${o.host}" }
                    when (req.url.protocol) {
                        URLProtocol.HTTP -> { req.url.host = d.host; req.url.port = d.port }
                        URLProtocol.WS -> { req.url.host = "127.0.0.1"; req.url.port = this@HostileBell.port }
                        else -> error("refusing ${req.url.protocol.name}")
                    }
                }
            })
        }.also { clients += it }
    }

    override fun close() {
        runCatching { server.close() }
        all.forEach { it.close() }
        clients.forEach { it.close() }
    }

    private companion object {
        const val GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    }
}
