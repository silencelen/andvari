package io.silencelen.andvari.core.client.session

import io.ktor.client.HttpClient
import io.silencelen.andvari.core.client.AndvariApi

/**
 * The platform's HTTP stack, as the session layer needs it (design 2026-11-09, "HTTP clients").
 */
interface HttpClients {
    /** A new HTTP client. The [AndvariApi] built on it owns it and closes it. */
    fun create(): HttpClient

    /** The X-Andvari-Client platform tag (spec 03 §1) the server's minVersion pin keys on: "android", "ios". */
    val wirePlatform: String

    /** This device's name, as sign-in and enroll report it. */
    val deviceName: String
}

/**
 * Builds the session layer's API clients, so every one of them carries the right token rules: a probe
 * carries no token at all, and a token-holder writes its rotations only into the stored session it holds
 * ([updateTokensFor]) and reports a refused refresh to the coordinator ([PolicyCoordinator.onRefreshRefused]).
 */
class SessionClients(
    private val http: HttpClients,
    private val store: SessionPersistence,
    private val coordinator: PolicyCoordinator,
) {
    val wirePlatform: String get() = http.wirePlatform
    val deviceName: String get() = http.deviceName

    /** A tokenless client for [origin]: policy probes, prelogin, the recovery calls. It never writes tokens. */
    fun probe(origin: String): AndvariApi = AndvariApi(origin, http.create(), platform = http.wirePlatform)

    /**
     * The token-holder for the stored [session], dialing [dialed] (the same origin, canonically; callers
     * check [sessionBelongsTo] first). Its rotations land only in that session, and only while it still
     * holds the token this client started from.
     */
    fun forSession(session: StoredSession, dialed: String): AndvariApi {
        val owner = TokenOwner(session.baseUrl, session.userId, heldRefreshToken = session.refreshToken)
        return AndvariApi(dialed, http.create(), session.tokens(), { store.updateTokensFor(owner, it) }, http.wirePlatform, coordinator::onRefreshRefused)
    }

    /**
     * A client that will sign in or enroll at [origin]. It writes no tokens until its caller has saved the
     * session it commits and named the user on [NewSession.owner].
     */
    fun forNewSession(origin: String): NewSession {
        val owner = TokenOwner(origin)
        return NewSession(AndvariApi(origin, http.create(), null, { store.updateTokensFor(owner, it) }, http.wirePlatform, coordinator::onRefreshRefused), owner)
    }

    class NewSession(val api: AndvariApi, val owner: TokenOwner)
}
