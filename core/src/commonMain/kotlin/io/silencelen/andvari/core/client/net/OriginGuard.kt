package io.silencelen.andvari.core.client.net

import io.ktor.client.HttpClient
import io.silencelen.andvari.core.client.pin.OriginAccess
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.trust.TrustGrammar
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireRoute

/**
 * The [WireResult.Refused] code of a request the [OriginGuard] stopped before anything was sent (status 0, like
 * `bad_path_segment`): the origin's pin is forked, damaged, moving or could not be read, or the request carries a
 * credential and the origin holds no pin in force (design §4.4).
 */
const val ORIGIN_STOPPED = "origin_stopped"

/**
 * True when this result is the guard's stop: nothing was sent, and nothing will be until "Forget this server" (or,
 * for a credential at an origin with no pin record, until a pin is made there).
 */
val WireResult<*>.originStopped: Boolean get() = this is WireResult.Refused && status == 0 && code == ORIGIN_STOPPED

/**
 * Design §4.4 "The stop is enforced where the client dials" and "No credential goes to an origin without a pin in
 * force": the one check every request of the engine passes before it leaves the device.
 *
 * **The rule, per request:**
 * 1. An origin whose pin is forked, damaged, moving ([OriginAccess.MOVING]) or unreadable: nothing is sent, whatever
 *    the request.
 * 2. A request that carries a credential goes only when [mayDial] (the origin's pin is in force, or the origin holds no
 *    pin record and this device is setting it up, [PinStore.credentialsAllowed]). A request carries a credential when
 *    it is sent with `authenticated = true` (the bearer), or when its route is not one of the
 *    [io.silencelen.andvari.core.model.wire.WireRoute.credentialFree] routes: so the refresh, the logout, prelogin,
 *    login, registration, kit and assisted recovery, device-link claims and every session route are credentialed by
 *    their route, whatever flag a caller passes.
 * 3. A credential-free request (the card chain, the client policy, a link's offer, the public files) with no
 *    `authenticated` flag also goes to an origin with no pin record: that is what a first pin needs.
 *
 * So a host marks nothing: the route says what a request carries. The event WebSocket comes from the same dialer
 * ([Dialer.bellSocket], under [mayOpenSocket]); a host that still opens another connection outside a [WireClient] asks
 * [mayDial] first when it carries a credential, and [mayFetchPublic] when it carries none.
 *
 * The token refresh obeys the same rule (the refresh inside a guarded client, and any refresh the session keeper
 * makes through a client it opened here). "Forget this server" is local (it removes the pin), so it never needs to
 * dial. The check reads the pin store on every request, so a fork marked or a pin removed during a session stops the
 * very next request of every client already handed out.
 */
class OriginGuard(private val pins: PinStore) {
    /** What this device may do with [origin] now ([PinStore.access]). */
    fun access(origin: String): OriginAccess = pins.access(origin)

    /**
     * True when a request that carries a credential may be sent to [origin] now: its pin is in force (or this device is
     * setting the origin up, [PinStore.credentialsAllowed]). The event socket asks the stricter [mayOpenSocket].
     */
    fun mayDial(origin: String): Boolean = pins.credentialsAllowed(origin)

    /** True when a request that carries no credential may be sent to [origin] now: no pin record there, or a pin in force. */
    fun mayFetchPublic(origin: String): Boolean = access(origin) == OriginAccess.OPEN

    /**
     * True when the event socket may open (or go on) for [origin] now ([Dialer.bellSocket]): the origin grammar accepts
     * the address, and its pin is in force (pinned, access open). Stricter than [mayDial]: a kept setup offer opens no
     * socket. A store that cannot be read answers false.
     */
    fun mayOpenSocket(origin: String): Boolean = try {
        TrustGrammar.isOrigin(origin) && access(origin) == OriginAccess.OPEN && pins.state(origin) is PinState.Pinned
    } catch (e: Exception) {
        false
    }

    /** [client] behind this guard: a request to a stopped origin is refused with [ORIGIN_STOPPED] and never sent. */
    fun guard(client: WireClient): WireClient = client as? GuardedWireClient ?: GuardedWireClient(client, this)

    /** [tokens] behind this guard: no refresh is attempted for a stopped [origin]. */
    fun guard(origin: String, tokens: TokenSource): TokenSource = object : TokenSource {
        override fun accessToken(): String? = if (mayDial(origin)) tokens.accessToken() else null
        override suspend fun refresh(staleAccessToken: String): Boolean = mayDial(origin) && tokens.refresh(staleAccessToken)
    }
}

/**
 * The engine's only way to an HTTP client for an origin (design §4.4): every client it hands out goes through the
 * [OriginGuard] over this device's pin store, and so does its token source. [KtorWireClient]'s own constructor is
 * internal, so the engine's public surface has no unguarded client.
 *
 * Composition: a host builds ONE [Dialer] over the device's [PinStore] (the same store its `CardTrust` uses) and
 * opens every per-origin client through [open]: the session keeper's `WireTransport` is `WireTransport(dialer::open)`,
 * and a WebSocket is opened only when [OriginGuard.mayOpenSocket] says so.
 *
 * [bellSocket] is the platform's own WebSocket for the event bell ([PlatformBellSocket], whose contract bounds every
 * message at 64 KiB before it is held), for a platform whose HTTP engine cannot bound a message before it reads it
 * whole (Android's OkHttp). Null: the socket goes over [http]'s engine, which is asked for the bound (see
 * [KtorBellWire]). Either way the dialer keeps the guard, the address, the ticket and the cap check on what is handed up.
 */
class Dialer(
    pins: PinStore,
    http: HttpClient,
    private val platform: String,
    private val bellSocket: PlatformBellSocket? = null,
) {
    val guard: OriginGuard = OriginGuard(pins)

    /**
     * [http] with redirects off: a derived client over the same engine and the host's own plugins. No route of the
     * protocol answers with a redirect (spec 03 §0.1), so a `3xx` is read as no answer and its `Location` is never
     * dialled: a server cannot send a request, a credential or a password proof to another path, another host, plain
     * http, or an address the origin grammar refuses.
     */
    private val http: HttpClient = http.config { followRedirects = false }

    /** A guarded client for [origin]; [tokens] (null: no bearer) is guarded too. */
    fun open(origin: String, tokens: TokenSource?): WireClient =
        guard.guard(KtorWireClient(origin, http, platform, tokens?.let { guard.guard(origin, it) }))

    /**
     * [http] with the `WebSockets` plugin added: a derived client over the same engine and the host's own plugins. The
     * plugin is given NO `maxFrameSize`: an engine that refuses the setting (ktor's OkHttp engine throws) would fail the
     * upgrade itself. [KtorBellWire] asks the engine's session once open, and counts every fragment either way: a
     * message (reassembled from its fragments) above [ResponseCaps.of]`(EVENTS)` closes the socket before more of it is
     * kept: the bell's frames are a few dozen bytes, and an endless or endlessly fragmented one is a server's lie.
     */
    private val sockets: KtorBellWire by lazy {
        // `this.http`, the client with redirects off: the constructor's own `http` (which follows them) is in scope here too.
        KtorBellWire(this.http.config { install(io.ktor.client.plugins.websocket.WebSockets) })
    }

    /**
     * The event bell's socket for [origin] (spec 03 §6), from this dialer and under its rules ([DialedBellSocket]): it
     * opens only for [origin], only for an address the origin grammar accepts, and only while the pin there is in force
     * ([OriginGuard.mayOpenSocket]); that is asked again before every frame. Every message handed up is at most 64 KiB,
     * whichever reader carried it, and why no socket is open is kept in [DialedBellSocket.failure]. A host passes it to
     * the bell with the client [open] gave it for the same origin, `EventBell(client, dialer.bellSocket(client.origin),
     * …)`, and builds no socket of its own (a platform's own socket comes in through the constructor's `bellSocket`).
     */
    fun bellSocket(origin: String): DialedBellSocket = DialedBellSocket(origin, guard, bellSocket ?: sockets, platform)
}

/** A [WireClient] that asks the [OriginGuard] before every request. */
internal class GuardedWireClient(private val inner: WireClient, private val guard: OriginGuard) : WireClient {
    override val origin: String get() = inner.origin

    override val stopped: Boolean get() = !guard.mayDial(inner.origin)

    override suspend fun <T> call(
        route: WireRoute,
        pathParams: Map<String, String>,
        query: String?,
        bodyJson: String?,
        authenticated: Boolean,
        decode: (String) -> T,
    ): WireResult<T> {
        stop(route, authenticated)?.let { return it }
        return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
    }

    override suspend fun <T> callBytes(
        route: WireRoute,
        pathParams: Map<String, String>,
        query: String?,
        body: ByteArray,
        authenticated: Boolean,
        decode: (String) -> T,
    ): WireResult<T> {
        stop(route, authenticated)?.let { return it }
        return inner.callBytes(route, pathParams, query, body, authenticated, decode)
    }

    override suspend fun fetchBytes(route: WireRoute, pathParams: Map<String, String>, query: String?, authenticated: Boolean): WireResult<ByteArray> {
        stop(route, authenticated)?.let { return it }
        return inner.fetchBytes(route, pathParams, query, authenticated)
    }

    override suspend fun fetchBytes(route: WireRoute, pathParams: Map<String, String>, query: String?, authenticated: Boolean, maxBytes: Long?): WireResult<ByteArray> {
        stop(route, authenticated)?.let { return it }
        return inner.fetchBytes(route, pathParams, query, authenticated, maxBytes)
    }

    /** The [OriginGuard]'s rule for one request; null when it may be sent. */
    private fun stop(route: WireRoute, authenticated: Boolean): WireResult.Refused? {
        val access = guard.access(inner.origin)
        if (access != OriginAccess.OPEN) return WireResult.Refused(0, WireError(ORIGIN_STOPPED, "origin ${access.code}: nothing is sent"))
        if ((authenticated || !route.credentialFree) && !guard.mayDial(inner.origin)) {
            return WireResult.Refused(0, WireError(ORIGIN_STOPPED, "no pin in force: no credential is sent"))
        }
        return null
    }
}
