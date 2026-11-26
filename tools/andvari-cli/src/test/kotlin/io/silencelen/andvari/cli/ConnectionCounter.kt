package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Await
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.Collections

/**
 * A loopback listener (bound to port 0) that only counts the connections it accepts and closes each: what a test points
 * the tool at to show that something was NOT dialed. Its own thread accepts, so a connection the tool made may be
 * counted a moment after the command returned. [settled] therefore never reads the count at once: it connects once more
 * itself and waits (with a bound) until that probe is accepted; the listener accepts in arrival order, so every
 * connection made before the probe has been counted by then.
 */
class ConnectionCounter : AutoCloseable {
    private val socket = ServerSocket(0, 50, InetAddress.getLoopbackAddress())

    /** The remote port of every connection accepted, in order. */
    private val accepted: MutableList<Int> = Collections.synchronizedList(ArrayList())
    private val probes: MutableSet<Int> = Collections.synchronizedSet(HashSet())

    val address = "http://127.0.0.1:${socket.localPort}"

    init {
        Thread {
            while (true) {
                val c = runCatching { socket.accept() }.getOrNull() ?: break
                accepted += c.port
                runCatching { c.close() }
            }
        }.apply { isDaemon = true; name = "connection-counter" }.start()
    }

    /** The connections accepted so far, the probes of [settled] left out, once every connection made before this call is counted. */
    fun settled(): Int {
        val mine = Socket(InetAddress.getLoopbackAddress(), socket.localPort).use { probe ->
            probe.localPort.also { port ->
                probes += port
                Await.until("this counter to accept its own probe connection (from port $port)", there = { "accepted so far: ${accepted.toList()}" }) {
                    if (port in accepted) Unit else null
                }
            }
        }
        return synchronized(accepted) { accepted.takeWhile { it != mine }.count { it !in probes } }
    }

    override fun close() = socket.close()
}
