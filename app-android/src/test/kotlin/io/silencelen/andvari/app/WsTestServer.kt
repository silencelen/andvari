package io.silencelen.andvari.app

import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.File
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ServerSocketFactory
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import kotlin.concurrent.thread

/**
 * A raw WebSocket server on a loopback socket for the bell's tests: each connection runs [script] on its own thread,
 * over a [Peer] that reads and writes frames byte by byte, so a test can say exactly what a hostile server sends.
 * [tls]: a TLS server socket (the handshake runs on accept; [handshakes] counts the ones that completed).
 */
internal class WsTestServer(private val tls: SSLContext? = null, private val script: (Peer) -> Unit) : AutoCloseable {
    private val ss: ServerSocket = (tls?.serverSocketFactory ?: ServerSocketFactory.getDefault())
        .createServerSocket(0, 8, InetAddress.getLoopbackAddress())
    val port: Int get() = ss.localPort
    val accepted = AtomicInteger()
    val handshakes = AtomicInteger()
    val failures = CopyOnWriteArrayList<Throwable>()

    init {
        thread(isDaemon = true) {
            while (true) {
                val s = try {
                    ss.accept()
                } catch (_: IOException) {
                    break
                }
                accepted.incrementAndGet()
                thread(isDaemon = true) {
                    try {
                        s.use {
                            if (it is SSLSocket) {
                                it.soTimeout = 10_000
                                it.startHandshake()
                                handshakes.incrementAndGet()
                            }
                            script(Peer(it))
                        }
                    } catch (t: Throwable) {
                        failures += t
                    }
                }
            }
        }
    }

    override fun close() = ss.close()

    /** One client frame as the server read it. */
    class ClientFrame(val fin: Boolean, val op: Int, val masked: Boolean, val mask: ByteArray, val payload: ByteArray)

    class Peer(val socket: Socket) {
        val input = BufferedInputStream(socket.getInputStream())
        val out = socket.getOutputStream()!!

        /** The upgrade request's head, up to the empty line. */
        fun head(): String {
            val b = ByteArrayOutputStream()
            while (!b.toString(Charsets.ISO_8859_1).endsWith("\r\n\r\n")) {
                val c = input.read()
                if (c < 0) throw EOFException()
                b.write(c)
            }
            return b.toString(Charsets.ISO_8859_1)
        }

        /** Read the head and answer a correct `101`; answers the head. */
        fun upgrade(): String {
            val h = head()
            write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept(key(h))}\r\n\r\n")
            return h
        }

        fun write(text: String) {
            out.write(text.toByteArray(Charsets.ISO_8859_1))
            out.flush()
        }

        /** A server frame header (never masked) declaring [length]. */
        fun header(fin: Boolean, op: Int, length: Long) {
            val b0 = (if (fin) 0x80 else 0) or op
            when {
                length <= 125 -> out.write(byteArrayOf(b0.toByte(), length.toInt().toByte()))
                length <= 0xFFFF -> out.write(byteArrayOf(b0.toByte(), 126, (length ushr 8).toByte(), length.toByte()))
                else -> {
                    val h = ByteArray(10)
                    h[0] = b0.toByte()
                    h[1] = 127
                    for (i in 0 until 8) h[2 + i] = (length ushr (8 * (7 - i))).toByte()
                    out.write(h)
                }
            }
            out.flush()
        }

        fun frame(fin: Boolean, op: Int, payload: ByteArray) {
            header(fin, op, payload.size.toLong())
            out.write(payload)
            out.flush()
        }

        fun text(s: String) = frame(true, 1, s.toByteArray())

        fun clientFrame(): ClientFrame {
            val b0 = read()
            val b1 = read()
            var len = (b1 and 0x7F).toLong()
            if (len == 126L) len = ((read() shl 8) or read()).toLong()
            else if (len == 127L) {
                len = 0
                repeat(8) { len = (len shl 8) or read().toLong() }
            }
            val masked = b1 and 0x80 != 0
            val mask = if (masked) ByteArray(4) { read().toByte() } else ByteArray(0)
            val payload = ByteArray(len.toInt()) { read().toByte() }
            if (masked) for (i in payload.indices) payload[i] = (payload[i].toInt() xor mask[i and 3].toInt()).toByte()
            return ClientFrame(b0 and 0x80 != 0, b0 and 0x0F, masked, mask, payload)
        }

        private fun read(): Int {
            val c = input.read()
            if (c < 0) throw EOFException()
            return c
        }

        /** True when the client ends the connection within [ms] (whatever it sends first is read and dropped). */
        fun endsWithin(ms: Int): Boolean {
            socket.soTimeout = ms
            return try {
                while (input.read() >= 0) Unit
                true
            } catch (_: SocketTimeoutException) {
                false
            } catch (_: IOException) {
                true
            }
        }
    }

    companion object {
        const val WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

        fun key(head: String): String = Regex("(?im)^Sec-WebSocket-Key: *(\\S+)").find(head)!!.groupValues[1]

        fun accept(key: String): String =
            Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1").digest((key + WS_GUID).toByteArray()))
    }
}

/**
 * Self-signed certificates for the TLS tests, made once with the JDK's own `keytool` (no new dependency): one for
 * `localhost` and one for `other.example`, each in a PKCS12 key store, and a trust that trusts exactly those two.
 */
internal object TestCerts {
    private const val PASS = "changeit"
    private val dir: File by lazy { kotlin.io.path.createTempDirectory("bell-certs").toFile().also { it.deleteOnExit() } }

    private fun make(name: String): KeyStore {
        val file = File(dir, "$name.p12")
        if (!file.exists()) {
            val keytool = File(System.getProperty("java.home"), "bin/keytool").path
            val p = ProcessBuilder(
                keytool, "-genkeypair", "-alias", "k", "-keyalg", "EC", "-groupname", "secp256r1",
                "-dname", "CN=$name", "-ext", "SAN=dns:$name", "-validity", "2",
                "-keystore", file.path, "-storetype", "PKCS12", "-storepass", PASS, "-keypass", PASS,
            ).redirectErrorStream(true).start()
            p.inputStream.readBytes()
            check(p.waitFor() == 0) { "keytool failed" }
        }
        return KeyStore.getInstance("PKCS12").apply { file.inputStream().use { load(it, PASS.toCharArray()) } }
    }

    val localhost: KeyStore by lazy { make("localhost") }
    val other: KeyStore by lazy { make("other.example") }

    fun server(ks: KeyStore): SSLContext = SSLContext.getInstance("TLS").apply {
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(ks, PASS.toCharArray()) }
        init(kmf.keyManagers, null, null)
    }

    /** A client trust of exactly the two test certificates. */
    val trustBoth: SSLContext by lazy {
        val trust = KeyStore.getInstance("PKCS12").apply {
            load(null, null)
            setCertificateEntry("localhost", localhost.getCertificate("k") as X509Certificate)
            setCertificateEntry("other", other.getCertificate("k") as X509Certificate)
        }
        SSLContext.getInstance("TLS").apply {
            init(null, TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(trust) }.trustManagers, null)
        }
    }
}
