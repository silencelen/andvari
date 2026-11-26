package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

/**
 * A server in front of [inner] for the "a lock overtakes an intent" probes (in the style of
 * [EngineKeysAfterLockTest]): it holds one chosen route until released, and records every request with whether the lock
 * had come when it was sent.
 */
internal class LockProbe(private val inner: WireClient) : WireClient {
    /** A request held at the server: [reached] when it arrives, answered once [release] completes. */
    class Held {
        val reached = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
    }

    override val origin: String get() = inner.origin
    override val stopped: Boolean get() = inner.stopped

    /** Set by the probe when it locks the app: every request from then on is "after the lock". */
    var locked = false
    val log = ArrayList<Pair<WireRoute, Boolean>>()
    private val holds = HashMap<WireRoute, Held>()

    /** What an intent threw: an intent the lock overtook answers, it never crashes. */
    val crashes = ArrayList<Throwable>()

    fun hold(route: WireRoute): Held = Held().also { holds[route] = it }

    /** The requests that arrived after the lock. */
    fun sentAfterLock(): List<WireRoute> = log.filter { it.second }.map { it.first }

    override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
        log += route to locked
        holds.remove(route)?.let {
            it.reached.complete(Unit)
            it.release.await()
        }
        return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
    }

    /** Starts the intent [block] now (to its first wait); a throw is recorded in [crashes] rather than failing the test's scope. */
    fun CoroutineScope.intent(block: suspend () -> Unit): Job =
        launch(start = CoroutineStart.UNDISPATCHED) {
            try {
                block()
            } catch (c: CancellationException) {
                throw c
            } catch (t: Throwable) {
                crashes += t
            }
        }

    /**
     * The probe: [start] the intent, wait until it is held at [route], lock with [lock], let the answer through, and
     * wait for the intent to end.
     */
    suspend fun CoroutineScope.lockDuring(route: WireRoute, lock: () -> Unit, start: suspend () -> Unit) {
        val held = hold(route)
        val job = intent(start)
        // An intent that never sends [route] fails the probe here instead of hanging it; one that never answers after the
        // lock fails it at the second wait, each saying what it waited for.
        io.silencelen.andvari.core.app.waitFor("the $route request to reach the server") { held.reached.await() }
        locked = true
        lock()
        held.release.complete(Unit)
        io.silencelen.andvari.core.app.waitFor("the intent held at $route to answer after the lock") { job.join() }
    }
}
