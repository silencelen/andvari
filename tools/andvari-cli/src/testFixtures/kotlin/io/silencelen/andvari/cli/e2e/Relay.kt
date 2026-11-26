package io.silencelen.andvari.cli.e2e

import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.Collections

/**
 * A byte relay on the loopback: it binds port 0 at construction and keeps that port ([port]) until [close], so a port
 * that a test names before anything listens on it (an origin a setup bakes into its card) can never be taken by another
 * process between a pick and a bind. Each connection is relayed, byte for byte both ways, to the loopback port [target]
 * names when the connection arrives; a port that is 0 (nothing to relay to yet) closes the connection. [bindPort] other
 * than 0 binds that port instead, for a port something else had to hold first.
 */
class Relay(@Volatile var target: Int = 0, bindPort: Int = 0) : AutoCloseable {
    private val server = ServerSocket(bindPort, 128, InetAddress.getLoopbackAddress())
    private val open: MutableSet<Socket> = Collections.synchronizedSet(HashSet())

    /** The port this relay holds. */
    val port: Int = server.localPort

    init {
        thread("relay-$port-accept") {
            while (!server.isClosed) {
                val inbound = try { server.accept() } catch (e: IOException) { break }
                thread("relay-$port-conn") { relay(inbound) }
            }
        }
    }

    private fun relay(inbound: Socket) {
        open += inbound
        val outbound = try {
            val t = target
            if (t == 0) throw IOException("nothing to relay to")
            Socket().apply { connect(InetSocketAddress(InetAddress.getLoopbackAddress(), t), 10_000) }
        } catch (e: IOException) {
            close(inbound)
            return
        }
        open += outbound
        val back = thread("relay-$port-back") { pump(outbound, inbound) }
        pump(inbound, outbound)
        back.join()
        close(inbound)
        close(outbound)
    }

    /** Copies [from] to [to] until [from] ends, then ends [to]'s output half (an orderly close carries over). */
    private fun pump(from: Socket, to: Socket) {
        try {
            val buf = ByteArray(16 * 1024)
            val input = from.getInputStream()
            val output = to.getOutputStream()
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                output.write(buf, 0, n)
                output.flush()
            }
            to.shutdownOutput()
        } catch (e: IOException) {
            close(from)
            close(to)
        }
    }

    private fun close(s: Socket) {
        open -= s
        try { s.close() } catch (e: IOException) { }
    }

    override fun close() {
        try { server.close() } catch (e: IOException) { }
        synchronized(open) { open.toList() }.forEach(::close)
    }

    private companion object {
        fun thread(name: String, body: () -> Unit): Thread = Thread(body, name).apply { isDaemon = true; start() }
    }
}
