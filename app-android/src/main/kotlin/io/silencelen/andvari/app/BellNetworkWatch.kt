package io.silencelen.andvari.app

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.os.Handler
import android.os.Looper
import android.os.SystemClock

/**
 * Live updates come back promptly after the network does.
 *
 * Before this, a socket on a network that went away was noticed only when its read timed out (90 s,
 * [AndroidBellSocket.Timeouts.readMs]), and a bell that had climbed its ladder while there was no network waited up to
 * 60 s more after the network came back. The platform's own notice that the default network changed now does two
 * things, and nothing else:
 *
 * - **The default network is lost, or another one takes its place:** every bell socket being opened or open is ended
 *   at once ([endSockets], which is [AndroidBellSocket.endAll]). The dialer records the end as it records any broken
 *   socket, and the bell goes to its ladder. Nothing is dialled by this.
 * - **A network is there again (or another one took over):** the bell is asked to dial now ([redial], which is the
 *   shared code's foreground reset: the ladder goes to zero and a WAITING bell dials). Bounded: at most ONE such redial
 *   every [minSpacingMs] (30 s). A notice inside that window is folded into a single redial at its end, and that one is
 *   skipped if no network is there by then. So however a network flaps, these notices cause at most two redials a
 *   minute; everything else is the bell's own ladder (1 s doubling to 60 s), as before.
 *
 * What is dialled, verified and bounded does not change: the shared code's dialer and bell still decide whether and
 * where a socket opens, with the same guard, ticket, trust and caps.
 *
 * Networks are opaque keys here ([Network] on a phone, anything in a JVM test), compared with `==`. The first network
 * is the one in place when the watch starts ([initial]): the platform's first notice for it is not a change.
 */
internal class BellNetworkWatch(
    initial: Any?,
    private val endSockets: () -> Unit,
    private val redial: () -> Unit,
    private val nowMs: () -> Long,
    private val later: (delayMs: Long, run: () -> Unit) -> Unit,
    private val minSpacingMs: Long = MIN_REDIAL_SPACING_MS,
) {
    private var current: Any? = initial
    private var lastRedialMs: Long? = null
    private var pending = false

    private val redialCount = java.util.concurrent.atomic.AtomicInteger()

    /** Redials asked of the bell so far. */
    val redials: Int get() = redialCount.get()

    /** The platform says [network] is now the default network. */
    fun available(network: Any) {
        val switched: Boolean
        synchronized(this) {
            if (network == current) return
            switched = current != null
            current = network
        }
        // A socket opened before the switch sits on the network that was the default: it may be gone.
        if (switched) endSockets()
        networkThere()
    }

    /** The platform says [network], the default network, is lost (and no other took its place). */
    fun lost(network: Any) {
        synchronized(this) {
            if (network != current) return
            current = null
        }
        endSockets()
    }

    private fun networkThere() {
        val now = nowMs()
        val wait: Long
        synchronized(this) {
            val last = lastRedialMs
            if (last == null || now - last >= minSpacingMs) {
                lastRedialMs = now
                wait = 0L
            } else {
                if (pending) return
                pending = true
                wait = last + minSpacingMs - now
            }
        }
        if (wait == 0L) dial() else later(wait) { deferred() }
    }

    private fun deferred() {
        synchronized(this) {
            pending = false
            // Gone again: nothing to dial on; the next notice that a network is there asks again.
            if (current == null) return
            lastRedialMs = nowMs()
        }
        dial()
    }

    private fun dial() {
        redialCount.incrementAndGet()
        redial()
    }

    companion object {
        /** At most one redial for network notices in this window (the rest fold into one at its end). */
        const val MIN_REDIAL_SPACING_MS = 30_000L

        /**
         * The phone's watch: the platform's default-network notices ([ConnectivityManager.registerDefaultNetworkCallback])
         * feed [BellNetworkWatch]; sockets are ended on the notice's own thread, and [redial] runs on the main thread,
         * which is the thread the app gives the shared code its lifecycle calls on.
         */
        fun register(context: Context, socket: AndroidBellSocket, redial: () -> Unit): BellNetworkWatch {
            val cm = context.getSystemService(ConnectivityManager::class.java)
            val main = Handler(Looper.getMainLooper())
            val watch = BellNetworkWatch(
                initial = cm.activeNetwork,
                endSockets = { socket.endAll() },
                redial = { main.post(redial) },
                nowMs = { SystemClock.elapsedRealtime() },
                later = { ms, run -> main.postDelayed(run, ms) },
            )
            cm.registerDefaultNetworkCallback(object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) = watch.available(network)
                override fun onLost(network: Network) = watch.lost(network)
            })
            return watch
        }
    }
}
