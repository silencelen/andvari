package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.net.TokenSource
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.model.wire.Caller
import io.silencelen.andvari.core.model.wire.RefreshRequest
import io.silencelen.andvari.core.model.wire.TokenPair
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute

/**
 * A [WireTransport] over in-memory servers (the engine tests' fakes, which do not look at bearers) that does what
 * [io.silencelen.andvari.core.client.net.KtorWireClient] does with a [TokenSource]: the bearer on an authenticated
 * route, one refresh after a `401`. It answers `/auth/refresh` and `/auth/logout` itself, with single-use refresh
 * tokens, and records the bearer of every call in [sent].
 */
class BearerTransport(private val servers: Map<String, WireClient>) : WireTransport {
    class Sent(val origin: String, val route: WireRoute, val bearer: String?)

    val sent = ArrayList<Sent>()

    /**
     * When true, a session route (`Caller.SESSION`) sent with no bearer answers `401` here, as the real server does; the
     * scripted servers behind this transport do not look at bearers at all (the gap that hid the desktop's failed server
     * setup).
     */
    var sessionRoutesNeedBearer = false

    /** Access tokens the server answers `401` for (expired). */
    val expired = HashSet<String>()

    /** Refresh tokens already used: a reuse is `refresh_reuse`. */
    private val usedRefresh = HashSet<String>()
    var refreshAnswer: ((String) -> WireResult<String>)? = null
    var rotations = 0

    /** The server's clock, for [graceMs]. */
    var clock: () -> Long = { 0L }

    /**
     * As the server's refresh grace: a replaced refresh token presented again within this many ms of its replacement (the
     * edge included), while the pair that replaced it is untouched, is answered with that same pair and makes no new
     * session. Null: no grace, every repeat is a reuse.
     */
    var graceMs: Long? = null

    /** The next refresh answers lost after the server made them: the token is replaced there, the device sees no answer. */
    var loseAnswers = 0

    /** Every refresh token the server received, in order. */
    val refreshTokensReceived = ArrayList<String>()

    /**
     * Run after the server made its answer to a refresh (the token is replaced there) and before the device gets it: a
     * hold here that never ends, then a cancelled caller or a new keeper over the same stores, is a refresh cut off while
     * its request was out (a lock that cancels a sync, a screen that closes, the end of the app).
     */
    var afterRefreshMade: (suspend (String) -> Unit)? = null

    private val answered = HashMap<String, Pair<TokenPair, Long>>()

    override fun open(origin: String, tokens: TokenSource?): WireClient = Client(origin, tokens)

    /** The bell socket this transport hands out for every origin (null: no bell), and the origins it was asked for. */
    var bell: io.silencelen.andvari.core.client.items.BellSocket? = null
    val bellsAsked = ArrayList<String>()

    override fun bellSocket(origin: String): io.silencelen.andvari.core.client.items.BellSocket? {
        bellsAsked += origin
        return bell
    }

    fun bearersFor(route: WireRoute): List<String?> = sent.filter { it.route == route }.map { it.bearer }

    private inner class Client(override val origin: String, private val tokens: TokenSource?) : WireClient {
        override suspend fun <T> call(
            route: WireRoute,
            pathParams: Map<String, String>,
            query: String?,
            bodyJson: String?,
            authenticated: Boolean,
            decode: (String) -> T,
        ): WireResult<T> {
            val bearer = if (authenticated) tokens?.accessToken() else null
            sent += Sent(origin, route, bearer)
            // As a real server does: a session route that arrives without a bearer is `401` (opt-in).
            if (sessionRoutesNeedBearer && authenticated && route.caller != Caller.NONE && bearer == null) {
                return WireResult.Refused(401, WireError("unauthorized", "unauthorized"))
            }
            var used = bearer
            if (authenticated && route.caller != Caller.NONE && bearer != null && bearer in expired) {
                if (!tokens!!.refresh(bearer)) return WireResult.Refused(401, WireError("unauthorized", "unauthorized"))
                val again = tokens.accessToken()
                sent += Sent(origin, route, again)
                if (again == null || again in expired) return WireResult.Refused(401, WireError("unauthorized", "unauthorized"))
                used = again
            }
            // The fake instance marks the caller's own device in its devices list by this bearer, as a server does.
            (servers[origin] as? io.silencelen.andvari.core.client.onboard.FakeInstance)?.bearer = used
            return when (route) {
                WireRoute.REFRESH -> refresh(bodyJson!!, decode)
                WireRoute.LOGOUT -> {
                    // A sign-out ends every session of the caller's device at the server (a fake that counts them is told).
                    (servers[origin] as? io.silencelen.andvari.core.client.onboard.FakeInstance)?.loggedOut(used)
                    WireResult.Ok(decode("{}"), 200)
                }
                else -> servers[origin]?.call(route, pathParams, query, bodyJson, authenticated, decode)
                    ?: WireResult.NoAnswer(io.silencelen.andvari.core.client.net.NoAnswerKind.TRANSPORT)
            }
        }

        /** A raw body (an attachment upload) goes to the server as it is, with the bearer recorded as for [call]. */
        override suspend fun <T> callBytes(
            route: WireRoute, pathParams: Map<String, String>, query: String?, body: ByteArray, authenticated: Boolean, decode: (String) -> T,
        ): WireResult<T> {
            sent += Sent(origin, route, if (authenticated) tokens?.accessToken() else null)
            return servers[origin]?.callBytes(route, pathParams, query, body, authenticated, decode)
                ?: WireResult.NoAnswer(io.silencelen.andvari.core.client.net.NoAnswerKind.TRANSPORT)
        }

        /**
         * A download goes to the server as it is, with the bearer recorded as for [call]. Before, the rig had no download:
         * the [WireClient] default answered no answer, so every download in it read as an unreachable server.
         */
        override suspend fun fetchBytes(route: WireRoute, pathParams: Map<String, String>, query: String?, authenticated: Boolean): WireResult<ByteArray> {
            sent += Sent(origin, route, if (authenticated) tokens?.accessToken() else null)
            return servers[origin]?.fetchBytes(route, pathParams, query, authenticated)
                ?: WireResult.NoAnswer(io.silencelen.andvari.core.client.net.NoAnswerKind.TRANSPORT)
        }

        override suspend fun fetchBytes(
            route: WireRoute, pathParams: Map<String, String>, query: String?, authenticated: Boolean, maxBytes: Long?,
        ): WireResult<ByteArray> {
            sent += Sent(origin, route, if (authenticated) tokens?.accessToken() else null)
            return servers[origin]?.fetchBytes(route, pathParams, query, authenticated, maxBytes)
                ?: WireResult.NoAnswer(io.silencelen.andvari.core.client.net.NoAnswerKind.TRANSPORT)
        }

        private suspend fun <T> refresh(body: String, decode: (String) -> T): WireResult<T> {
            val rt = WireJson.json.decodeFromString(RefreshRequest.serializer(), body).refreshToken
            refreshTokensReceived += rt
            refreshAnswer?.let { answer ->
                @Suppress("UNCHECKED_CAST")
                return when (val a = answer(rt)) { is WireResult.Ok -> WireResult.Ok(decode(a.value), 200); else -> a as WireResult<T> }
            }
            val pair = if (!usedRefresh.add(rt)) {
                val kept = answered[rt]
                val grace = graceMs
                if (grace == null || kept == null || clock() - kept.second > grace || kept.first.refreshToken in usedRefresh) {
                    return WireResult.Refused(401, WireError("refresh_reuse", "refresh_reuse"))
                }
                kept.first
            } else {
                rotations++
                TokenPair("at$rotations-$rt", "rt$rotations-$rt").also { answered[rt] = it to clock() }
            }
            afterRefreshMade?.invoke(rt)
            if (loseAnswers > 0) {
                loseAnswers--
                return WireResult.NoAnswer(io.silencelen.andvari.core.client.net.NoAnswerKind.TIMEOUT)
            }
            return WireResult.Ok(decode(WireJson.json.encodeToString(TokenPair.serializer(), pair)), 200)
        }
    }
}
