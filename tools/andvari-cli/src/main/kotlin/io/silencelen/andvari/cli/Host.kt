package io.silencelen.andvari.cli

import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.ktor.client.plugins.HttpTimeout
import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.account.Reauth
import io.silencelen.andvari.core.client.account.ReauthKey
import io.silencelen.andvari.core.client.account.ReauthSession
import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.account.WireAccountSettings
import io.silencelen.andvari.core.client.account.WireAccountSettings.NewWrap as AccountSettingsNewWrap
import io.silencelen.andvari.core.model.wire.AccountKeys
import io.silencelen.andvari.core.client.link.LinkAccount
import io.silencelen.andvari.core.client.link.WireLinkFlows
import io.silencelen.andvari.core.client.net.BODY_OVER_LIMIT
import io.silencelen.andvari.core.client.net.Dialer
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.TokenSource
import io.silencelen.andvari.core.client.pin.OriginAccess
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.EstablishedSession
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.SessionSink
import io.silencelen.andvari.core.client.net.endSession
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.client.session.Establishing
import io.silencelen.andvari.core.model.wire.AccountRole
import io.silencelen.andvari.core.client.pin.CardTrust
import io.silencelen.andvari.core.client.pin.NamespaceMover
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.client.pin.ServerForgotten
import io.silencelen.andvari.core.client.pin.TrustCardChainVerifier
import io.silencelen.andvari.core.client.state.StoredAccountState
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WirePlatform
import io.silencelen.andvari.core.model.wire.RefreshRequest
import io.silencelen.andvari.core.model.wire.TokenPair
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute

/**
 * The session this host holds for one origin: the engine's [EstablishedSession] (its keys) and the token pair, which
 * rotates on refresh. Only one account per origin, as in the apps (design §9.5).
 */
class HeldSession(val session: EstablishedSession, var accessToken: String, var refreshToken: String) {
    val origin: String get() = session.origin
    val userId: String get() = session.userId
    val emailNorm: String get() = session.emailNorm

    /**
     * When a refresh of [refreshToken] was sent and no answer has come for it (null when none is out): written, and saved
     * with the session, BEFORE the refresh goes, so that a refresh cut off in any way (no connection, a timeout, the run
     * ended while it was out, a page that is not the server's, a body that does not read) leaves it; only an answer in the
     * server's own envelope clears it ([Host.refreshOut]). The server may have replaced [refreshToken] all
     * the same, and it takes the same token again only within a minute of that: so the token is sent once more only within
     * [Host.REFRESH_SECOND_TRY_MS] of this time, in this run or a later one, and never after it nor a third time
     * ([Host.refreshMay]). Past that, nothing is sent with it, and the next sign-in names it ([Host.signInReplaces]).
     */
    var refreshOutAt: Long? = null

    /** The one more try of the refresh out since [refreshOutAt] was sent: no further one goes. */
    var refreshTriedAgain: Boolean = false

    /**
     * The session whose own wrap every re-authentication proves its password against ([Host.reauth], through the engine's
     * [EstablishedSession.proveAuthKey]): [session] itself, whose wrap is what the typed password opened (or what this
     * device sealed under it) when it was established or reopened in this run. Once the server took a password change this
     * device made, it is a session the engine rebuilt over the new wrap ([Host.changePassword]); null when none could be
     * rebuilt, and then every proof is refused with nothing sent.
     */
    internal var proof: EstablishedSession? = session

    /** The same over the wrap of a password change sent from here whose answer never came: its password may be the one in force now. */
    internal var pendingProof: EstablishedSession? = null

    /**
     * Spec 01 §7, "never derived at a lower cost than the account already had": the hashing cost of the wrap [proof]
     * proves against, as the answer that opened it named it (the keys a reopen read, the session answer of a sign-in, a
     * device link or a recovery), then the cost of each wrap this run settled on or had taken. Null when this run does not
     * know it; then no new master password is derived here ([Host.changePassword]).
     */
    internal var proofCost: io.silencelen.andvari.core.crypto.KdfParams? = OpenedCosts.of(session)

    /** The cost of [pendingProof]'s wrap, while it is held. */
    internal var pendingCost: io.silencelen.andvari.core.crypto.KdfParams? = null

    /**
     * Spec 01 §7, the pending-record rule, for a host that holds its session itself: a quiet re-key in this run sent a
     * change, and the account's keys the server holds afterwards could not be settled against the account key this run
     * holds ([Host.reKeyAfterOpening]). Every proof of the password in this run is refused on this device, with nothing
     * sent ([Host.keysNotKnownError]).
     */
    internal var serverKeysNotKnown: Boolean = false

    /** Why [serverKeysNotKnown] is set: what the person is told ([keysNotKnownError]). */
    internal var keysNotKnownWhy: KeysNotKnown = KeysNotKnown.CHANGED
}

/**
 * Why a run does not know the account's keys on the server after it sent a change of them ([HeldSession.serverKeysNotKnown]).
 * A cost outside the fence in the keys read again is neither: it is the server's answer at fault, said as such
 * ([servedCostError], exit 3), ahead of these.
 */
enum class KeysNotKnown {
    /** They were read again, and what the server holds now does not open here to the account key this run holds. */
    CHANGED,

    /** They could not be read again: the server gave no usable answer. */
    NOT_READ,
}

/**
 * The hashing cost of the wrap each session this process was handed was opened over, as the answer that opened it named
 * it ([HeldSession.proofCost]); kept weakly, by the session itself, so that every [HeldSession] built over the same
 * session finds it.
 */
internal object OpenedCosts {
    private val costs = java.util.WeakHashMap<EstablishedSession, io.silencelen.andvari.core.crypto.KdfParams>()

    fun note(s: EstablishedSession, p: io.silencelen.andvari.core.crypto.KdfParams) { synchronized(costs) { costs[s] = p } }

    fun of(s: EstablishedSession): io.silencelen.andvari.core.crypto.KdfParams? = synchronized(costs) { costs[s] }
}

/**
 * What the CLI says when this device stopped a request to [origin] before sending it: [access] is not `OPEN`, or
 * [pinned] is false, that is no pin in force there (design §4.4 "No credential goes to an origin without a pin in
 * force"). Nothing was sent; each case says what to do.
 */
fun stoppedError(origin: String, access: OriginAccess, pinned: Boolean = true): CliError = CliError(
    when (access) {
        OriginAccess.FORKED -> "SECURITY: this device stopped using $origin: its identity card no longer follows the one pinned here (a fork). " +
            "Nothing is sent to it. Only `andvari-cli forget-server --yes` goes on"
        OriginAccess.MOVING -> "this device followed a move to $origin but has not finished moving what it keeps there, so nothing is sent to it yet. " +
            "Run `andvari-cli card follow --origin $origin` to finish the move, or `andvari-cli forget-server --yes --origin $origin`"
        OriginAccess.BLOCKED -> "SECURITY: this device stopped using $origin: its pin here is damaged or unreadable. " +
            "Nothing is sent to it. Only `andvari-cli forget-server --yes` goes on"
        OriginAccess.OPEN -> if (!pinned) {
            "nothing was sent: this device holds no pin of $origin in force, and no password, token or session goes to a server " +
                "it has not pinned. To use that server, sign in with `andvari-cli sign-in --origin $origin`, which shows its Trust Gate " +
                "first; to delete what this device still keeps for it, run `andvari-cli forget-server --yes --origin $origin`"
        } else {
            "nothing was sent: this device stopped the request to $origin (its pin changed meanwhile). Run the command again"
        }
    },
)

/**
 * The CLI's composition root: one device (its [state] and [secure] store) and the engine pieces over the JVM's HTTP
 * client. Everything here is the smallest platform glue the engine needs; every check is the engine's.
 *
 * [http] dials each origin by its own address ([defaultHttp]); every identity check uses the origin. `--connect` to
 * another address is refused ([connectsAsOrigin]).
 */
class Host(
    val state: DeviceState,
    val secure: DeviceState,
    val clock: () -> Long,
    val http: HttpClient = defaultHttp(),
    val crypto: CryptoProvider = createCryptoProvider(),
    val platform: String = WirePlatform.CLI,
    val deviceName: String = "andvari-cli",
) {
    private val held = HashMap<String, HeldSession>()

    /** Called when a session is established; the CLI persists it from here (null for the test devices). */
    var onSession: ((HeldSession) -> Unit)? = null

    fun session(origin: String): HeldSession? = held[origin]

    /** Hold a session reopened from the saved ones; its account checks its own operator key from now on ([ownKeyCheck]). */
    fun adopt(h: HeldSession) {
        recordIdentity(h.origin, h.session.userId, h.session.account.identityPub())
        recordAddress(h.origin, h.emailNorm, h.session.userId)
        offerSettled(h.origin, h.emailNorm)
        held[h.origin] = h
        ownKeyCheck(h)
    }

    fun dropSession(origin: String) {
        held.remove(origin)?.session?.account?.wipe()
        ended[origin]?.session?.session?.account?.wipe()
        ownKeyCheck(held.values.firstOrNull())
    }

    /** A session the server ended in this run ([endedByServer]): why, and the session, whose keys go at [dropSession]. */
    class Ended(val code: String, val session: HeldSession)

    private val ended = HashMap<String, Ended>()

    /** Called when the server ended the session [HeldSession] in this run; the CLI deletes its saved tokens from here. */
    var onEnded: ((HeldSession) -> Unit)? = null

    /** The session the server ended at [origin] in this run, or null. */
    fun endedByServer(origin: String): Ended? = ended[origin]

    /**
     * Design §4.4 "A session the server ends does not delete the device's copy": a refused refresh ends the session. Its
     * tokens go (no request carries them any more, and [onEnded] deletes the saved copy); its keys are wiped when the
     * command ends ([dropSession]), not mid-command under a flow still holding them. Nothing else this device keeps for
     * the account is touched: the pin, the device record, the account's records and the tool's own names stay, so
     * signing in again continues.
     */
    private fun endedByServer(h: HeldSession, code: String) {
        held.remove(h.origin)
        h.accessToken = ""
        h.refreshToken = ""
        ended[h.origin] = Ended(code, h)
        ownKeyCheck(held.values.firstOrNull())
        onEnded?.invoke(h)
    }

    /**
     * Where the engine hands each session it opened (sign-in, registration, a device link, a recovery). The session's
     * tokens are taken from it once ([EstablishedSession.takeTokens]). A session whose tokens were already handed over (the
     * same session handed in twice, or one rebuilt from kept tokens, which hands none out) is not held: it stops the
     * command with that said in words, and its keys are wiped unless a session this host holds shares them.
     */
    val sink = object : SessionSink {
        override suspend fun established(session: EstablishedSession) {
            val s = session
            val tokens = s.takeTokens()
            if (tokens == null) {
                if (held.values.none { it.session.account === s.account }) s.account.wipe()
                throw CliError(
                    "this device was handed a session for ${s.emailNorm} on ${s.origin} whose tokens had already been handed over, " +
                        "so it is not used and nothing of it is kept here: sign in again",
                )
            }
            synchronized(sessionCosts) { sessionCosts["${s.origin}|${s.userId}"] }?.let { OpenedCosts.note(s, it) }
            recordIdentity(s.origin, s.userId, s.account.identityPub())
            recordAddress(s.origin, s.emailNorm, s.userId)
            offerSettled(s.origin, s.emailNorm)
            val remade = "$CLI_REMADE${s.origin}|${s.emailNorm}"
            state.get(remade)?.let { earlier ->
                state.set(remade, null)
                if (earlier != s.userId) onNewAccountRemembered?.invoke(s.origin, s.emailNorm)
            }
            val h = HeldSession(s, tokens.accessToken, tokens.refreshToken)
            held.put(s.origin, h)?.takeIf { it.session !== s }?.session?.account?.wipe()
            ownKeyCheck(h)
            onSession?.invoke(h)
        }

        /**
         * A session the server opened after a commit (a registration, a recovery, a device link, a sign-in), handed over as
         * [established] does, unless what this home keeps changed while the flow was under way (another run kept another
         * account at that server meanwhile, [keptRefusal]): then it is not kept, its keys are wiped, exactly that session is
         * ended at the server ([endOne]), and the reason goes back to the flow, which says the commit happened. A home that
         * keeps a session of this very address goes on, as a sign-in does.
         */
        override suspend fun take(session: EstablishedSession): String? {
            // The address is recorded here as another account: refused on every road, a sign-in's included, also where a
            // session of the address is kept (which the record outlives, and which this check does not skip).
            val byAddress = addressRefusal(session.origin, session.emailNorm, session.userId)
            if (byAddress != null || (savedToken(session.origin, session.emailNorm) == null && held[session.origin]?.emailNorm != session.emailNorm)) {
                (byAddress ?: keptRefusal(session.origin, session.emailNorm, session.userId))?.let { reason ->
                    // The server already made the session, and with it the device row it names: a link must say so.
                    refusedAfterCommit = session.origin to session.deviceId
                    val tokens = session.takeTokens()
                    if (held.values.none { it.session.account === session.account }) session.account.wipe()
                    tokens?.let { endOne(session.origin, it.refreshToken) }
                    return reason
                }
            }
            established(session)
            return null
        }

        /**
         * A session the server opened that a flow refused on this device after the answer came (a sign-in, a recovery):
         * exactly that session is ended there by its own refresh token ([endOne]), and no other session of this device.
         */
        override suspend fun notTaken(origin: String, accessToken: String, refreshToken: String) = endOne(origin, refreshToken)

        /**
         * Asked by a recovery, a registration and a device link before what commits at the server is sent ([keptRefusal]):
         * a no stops the flow there, with nothing changed at the server.
         */
        override fun wouldRefuse(origin: String, emailNorm: String?, userId: String?, identityPub: ByteArray?): String? {
            // A known account under another identity key than this home took for it: the fault the record exists to catch.
            // Nothing is offered for it ([CLI_EARLIER] "key"); an account made again never comes back under its old id.
            if (userId != null && identityPub != null) knownIdentity(origin, userId)?.let { known ->
                if (!Bytes.ctEquals(known, identityPub)) {
                    emailNorm?.let { runCatching { state.set("$CLI_EARLIER$origin|$it", "key $userId") } }
                    return IDENTITY_KEY_NOT_KNOWN
                }
            }
            return keptRefusal(origin, emailNorm, userId)
        }

        /** The identity key this home took for [userId] ([Host.knownIdentity]): a device link's pickup is checked against it. */
        override fun knownIdentity(userId: String): ByteArray? = this@Host.knownIdentity(userId)

        /**
         * The user id of the account this home keeps at [origin] for [emailNorm] (a saved session's), or null: an answer to a
         * request for the operator's help is held to it before anything is asked (`not_the_kept_account`).
         */
        override fun keptAccountFor(origin: String, emailNorm: String): String? =
            keptAt(origin)?.firstOrNull { it.emailNorm == emailNorm && it.userId != null }?.userId

        /**
         * The session a password sign-in replaces, named by the refresh token this home holds for it ([signInReplaces]),
         * so that the server ends exactly that one with the sign-in and records it, also when an earlier refresh's answer
         * was lost and the server had already replaced the token.
         */
        override fun signInReplaces(origin: String, emailNorm: String, deviceId: String?): String? =
            this@Host.signInReplaces(origin, emailNorm, deviceId)
    }

    /**
     * The refresh token of the session this home keeps for [emailNorm] at [origin] on the device row [deviceId] (the one
     * this run holds, else the saved one, [savedToken]), or null: none is kept, it is of another address, origin or device
     * row, or it holds no tokens any more (one the server ended). Unlike the apps' keeper, an operator's account is named
     * too: the tool's home keeps the operator's session as any other, and naming it only lets the server record the end.
     */
    fun signInReplaces(origin: String, emailNorm: String, deviceId: String?): String? {
        if (deviceId == null) return null
        held[origin]?.takeIf { it.emailNorm == emailNorm }?.let { h ->
            return h.refreshToken.takeIf { h.session.deviceId == deviceId && it.isNotEmpty() }
        }
        return savedToken(origin, emailNorm)?.takeIf { (row, token) -> row == deviceId && token.isNotEmpty() }?.second
    }

    /** The saved session's (device row, refresh token) for an address at an origin, or null; set by the tool. */
    var savedToken: (origin: String, emailNorm: String) -> Pair<String, String>? = { _, _ -> null }

    /**
     * The accounts this home keeps at an origin ([KeptHere]), or null when they cannot be read. The tool sets it from its
     * saved sessions and the remembered account; a host that sets nothing keeps nothing here.
     */
    var keptAt: (String) -> List<KeptHere>? = { emptyList() }

    /**
     * Why a session of [userId] for [emailNorm] at [origin] could not be kept on this home, or null when it could: the tool
     * keeps one account per server on a home, so another account kept at [origin] stops it, as
     * [Establishing.OPERATOR_ACCOUNT_HELD] when that account is the server's operator's and else
     * [Establishing.ANOTHER_SESSION_KEPT]; another account is another address, or the same address under another user id.
     * A store that cannot list what it keeps stops it too ([KEPT_UNREADABLE]): it cannot tell. [origin] alone decides
     * nothing (a home keeps accounts at any number of servers): with neither [emailNorm] nor [userId], null. One rule, asked
     * by the shared flows through [sink] and by the tool itself where it knows the address before any flow asks.
     */
    fun keptRefusal(origin: String, emailNorm: String?, userId: String?): String? {
        if (emailNorm == null && userId == null) return null
        val kept = keptAt(origin) ?: return KEPT_UNREADABLE
        val other = kept.firstOrNull {
            (emailNorm != null && it.emailNorm != emailNorm) || (userId != null && it.userId != null && it.userId != userId)
        } ?: return if (emailNorm != null && userId != null) addressRefusal(origin, emailNorm, userId) else null
        if (other.role == AccountRole.OPERATOR) return Establishing.OPERATOR_ACCOUNT_HELD
        // The address asked for is tied here to another account id than the one the server serves under it: an account
        // deleted and made again, or a server not serving the account this home knows. Only here is the forgetting offered.
        if (emailNorm != null && userId != null && other.emailNorm == emailNorm && other.userId != null) {
            val marked = runCatching { state.set("$CLI_EARLIER$origin|$emailNorm", "${other.userId} $userId") }.isSuccess
            if (marked) { earlierRefused = origin to emailNorm; return EARLIER_ACCOUNT_KNOWN }
        }
        return Establishing.ANOTHER_SESSION_KEPT
    }

    /**
     * Ends exactly the one session that issued [refreshToken] at [origin] (`POST /auth/end-session`, spec 03 §2), best
     * effort, through the dialer: nothing goes to an origin whose pin is not in force. Never the logout, which ends every
     * session of this device there. What a refused session is ended with, on every road.
     */
    suspend fun endOne(origin: String, refreshToken: String) = bare(origin).endSession(refreshToken)

    /**
     * The operator's own device check (design §4.1, VR-11): while this host holds a session, every card chain it verifies
     * refuses a card that names that account as the operator under any key but its own (`operator_key_mismatch`). Set
     * at every sign-in and reopen (the session [h] just held), ended when no session is held (sign-out, the end of a
     * command). The engine checks one account at a time: the newest session's.
     */
    private fun ownKeyCheck(h: HeldSession?) {
        if (h == null) trust.signedOut() else trust.signedIn(h.session.account)
    }

    /** Sign-out: this host holds no session of [origin] any more and ends its own operator-key check. */
    fun signedOut(origin: String) {
        dropSession(origin)
        trust.signedOut()
    }

    /** This device's pins: the one store [trust] judges cards into and [dialer] asks before every request. */
    val pins: PinStore = PinStore(state)

    /**
     * The engine's dialer over [pins] (design §4.4 "The stop is enforced where the client dials"): EVERY client this host
     * uses comes from it, so a forked or damaged pin stops every request to that origin, the token refresh included.
     */
    val dialer: Dialer = Dialer(pins, http, platform)

    private val clients = HashMap<String, WireClient>()

    private val tooLarge = ArrayList<Pair<String, WireRoute>>()

    /**
     * The answers in this run the engine refused as larger than their route accepts ([BODY_OVER_LIMIT]), as (origin,
     * route), oldest first. Whatever a flow made of such an answer, it is the server's answer at fault: the command
     * reports it as such ([serverAnswerError]), never as a wrong password or "not found".
     */
    val answersTooLarge: List<Pair<String, WireRoute>> get() = synchronized(tooLarge) { tooLarge.toList() }

    /**
     * Every client this host uses: [dialer]'s guarded one, with each answer the engine refused as too large noted in
     * [answersTooLarge]. Nothing else about the answer is looked at or changed.
     */
    fun open(origin: String, tokens: TokenSource?): WireClient = TooLargeWatch(dialer.open(origin, tokens), { route ->
        synchronized(tooLarge) { tooLarge += origin to route }
    }, { params -> synchronized(costsRefused) { costsRefused += origin to params } }, { params ->
        synchronized(policyCosts) { policyCosts[origin] = params }
    }, { route, a -> synchronized(answerLog) { answerLog += Triple(origin, route, a) } }) { userId, params ->
        synchronized(sessionCosts) { sessionCosts["$origin|$userId"] = params }
    }

    private val answerLog = ArrayList<Triple<String, WireRoute, Answered>>()

    /** How many answers this run has had so far: a mark for [answersSince]. */
    fun answersMark(): Int = synchronized(answerLog) { answerLog.size }

    /**
     * What came back for each request since [mark], oldest first, as (origin, route, [Answered]): what a command reads to
     * say what is so when a shared step gives one word for several cases (a refusal, no answer, an answer it could not use).
     */
    fun answersSince(mark: Int): List<Triple<String, WireRoute, Answered>> = synchronized(answerLog) { answerLog.drop(mark) }

    /**
     * The hashing cost of the newest policy this run read per origin (the quiet re-key reads it right after every opening
     * with the password): what [newWrapCost] raises to, with no request of its own, so that a password change sends
     * nothing at all before its password is proven here.
     */
    private val policyCosts = HashMap<String, io.silencelen.andvari.core.crypto.KdfParams>()

    /**
     * The hashing cost of the account's keys in the newest session answer (a login's, a device link's, a recovery's) per
     * `origin|userId`, inside the fence: the wrap the engine opens such a session over is that answer's own (it checks its
     * salt and cost against what the device derived under, `KnownKdf`), so [sink] records it for the session it is handed.
     */
    private val sessionCosts = HashMap<String, io.silencelen.andvari.core.crypto.KdfParams>()

    private val costsRefused = ArrayList<Pair<String, io.silencelen.andvari.core.crypto.KdfParams>>()

    /**
     * Spec 01 §7, the client-side bounds, on every hashing cost a server serves: the costs in this run's answers (a
     * prelogin, the account's keys, a session's keys) that fall outside the whole fence (floor, ceiling, a whole number of
     * KiB), as (origin, cost), oldest first. Such an answer is never handed to the engine, so nothing is derived at that
     * cost; the command reports it as the server's fault ([servedCostError]), never as a wrong password.
     */
    val servedCostsRefused: List<Pair<String, io.silencelen.andvari.core.crypto.KdfParams>> get() = synchronized(costsRefused) { costsRefused.toList() }

    fun client(origin: String): WireClient = clients.getOrPut(origin) { open(origin, tokens(origin)) }

    /** An unauthenticated client (refresh itself, and nothing else). */
    private fun bare(origin: String): WireClient = open(origin, null)

    /** A client that sends [token] once and never refreshes it: signing a session out with its own token. */
    fun withToken(origin: String, token: String): WireClient = open(origin, object : TokenSource {
        override fun accessToken() = token
        override suspend fun refresh(staleAccessToken: String) = false
    })

    /** What this device may do with [origin] now: `OPEN`, or stopped by a fork (`FORKED`) or a damaged pin (`BLOCKED`). */
    fun access(origin: String): OriginAccess = dialer.guard.access(origin)

    private fun tokens(origin: String) = object : TokenSource {
        override fun accessToken(): String? = held[origin]?.accessToken

        override suspend fun refresh(staleAccessToken: String): Boolean {
            val h = held[origin] ?: return false
            if (h.accessToken != staleAccessToken) return true
            // A refresh of this token may be out with no answer: it is sent once more only inside the window, else never.
            val outAt = h.refreshOutAt
            val triedAgain = h.refreshTriedAgain
            when (refreshMay(outAt, triedAgain, clock())) {
                RefreshMay.NONE -> { refreshTrouble = RefreshTrouble(h, withheld = true); return false }
                RefreshMay.AGAIN -> h.refreshTriedAgain = true
                RefreshMay.FIRST -> h.refreshOutAt = clock()
            }
            // The mark is saved before the refresh goes: a run that ends while it is out leaves it.
            onSession?.invoke(h)
            val body = WireJson.json.encodeToString(RefreshRequest.serializer(), RefreshRequest(h.refreshToken))
            val r = bare(origin).call(WireRoute.REFRESH, bodyJson = body, decode = { WireJson.json.decodeFromString(TokenPair.serializer(), it) })
            if (held[origin] !== h) return r is WireResult.Ok
            when {
                // No answer: the server may have rotated the tokens all the same; the mark stays, saved with the session.
                refreshOut(r) -> { refreshTrouble = RefreshTrouble(h, withheld = false); return false }
                // Stopped on this device: nothing was sent, so what was out before is out still.
                r is WireResult.Refused && r.code == io.silencelen.andvari.core.client.net.ORIGIN_STOPPED -> {
                    h.refreshOutAt = outAt; h.refreshTriedAgain = triedAgain
                    onSession?.invoke(h)
                    return false
                }
            }
            // An answer in the server's own envelope: nothing of this token is out any more.
            h.refreshOutAt = null
            h.refreshTriedAgain = false
            if (refreshTrouble?.session === h) refreshTrouble = null
            if (r is WireResult.Refused && endsSession(r)) { endedByServer(h, r.code); return false }
            if (r !is WireResult.Ok) { onSession?.invoke(h); return false }
            h.accessToken = r.value.accessToken
            h.refreshToken = r.value.refreshToken
            onSession?.invoke(h)
            return true
        }
    }

    /** A refresh in this run whose answer did not come ([withheld] false), or that was not sent at all because no try was left. */
    class RefreshTrouble(val session: HeldSession, val withheld: Boolean)

    /** The latest [RefreshTrouble] of this run that no answer cleared since, or null. */
    private var refreshTrouble: RefreshTrouble? = null

    /**
     * What a command says when a refresh in this run got no answer or was not sent ([RefreshTrouble]): [refreshLostError]
     * while one more try is left, [refreshUnansweredError] when none is. Null when there was none.
     */
    fun refreshFault(): CliError? = refreshTrouble?.let { t ->
        val h = t.session
        if (!t.withheld && !h.refreshTriedAgain) refreshLostError(h.origin, h.emailNorm) else refreshUnansweredError(h.origin, h.emailNorm)
    }

    init {
        // The tool's own per-origin records in the device state follow a move with the pin and go with "Forget this server".
        PinStore.carryWithMoves(CLI_NAME)
        PinStore.carryWithMoves(CLI_EMAIL)
        for (p in listOf(CLI_IDENTITY, CLI_EARLIER, CLI_FORGETTING, CLI_REMADE, CLI_ADDRESS)) PinStore.carryWithMoves(p)
    }

    // ---- An earlier account under a known address (decided on 2026-11-17) ----

    /**
     * The identity key this home first took for [userId] ([CLI_IDENTITY]), or null: every flow and every reopening compares
     * the key it is served with it, so a server cannot hand this home a known account under another key.
     */
    fun knownIdentity(origin: String, userId: String): ByteArray? = state.get("$CLI_IDENTITY$origin|$userId")?.let { Bytes.fromB64Exact(it, 32) }

    /**
     * [knownIdentity] for a flow that names only the account ([SessionSink.knownIdentity], the recoveries): at the flow's
     * server ([flowOrigin], else the command's, [originNow]). Where neither is known, any server's record counts (stricter).
     */
    fun knownIdentity(userId: String): ByteArray? {
        (flowOrigin ?: originNow())?.let { return knownIdentity(it, userId) }
        val keys = try { state.keys() } catch (e: Exception) { null } ?: return null
        return keys.firstOrNull { it.startsWith(CLI_IDENTITY) && it.endsWith("|$userId") }?.let { k -> state.get(k)?.let { Bytes.fromB64Exact(it, 32) } }
    }

    /** The server of the flow under way, where it is not the command's (a kit names its own); set by the tool. */
    var flowOrigin: String? = null

    /** The command's server, or null where it names none; set by the tool. */
    var originNow: () -> String? = { null }

    /** Records [pub] as [userId]'s identity key at [origin] when this home keeps none for it there; never replaces one. */
    private fun recordIdentity(origin: String, userId: String, pub: ByteArray) {
        if (io.silencelen.andvari.core.trust.TrustGrammar.isUuid(userId) && knownIdentity(origin, userId) == null) state.set("$CLI_IDENTITY$origin|$userId", Bytes.toB64(pub))
    }

    /** The account [emailNorm] is at [origin] on this home ([CLI_ADDRESS]), or null where none is recorded. */
    fun addressAccount(origin: String, emailNorm: String): String? = state.get("$CLI_ADDRESS$origin|$emailNorm")

    /** Records [userId] as the account [emailNorm] is at [origin] when none is recorded; never replaces one. */
    private fun recordAddress(origin: String, emailNorm: String, userId: String) {
        if (io.silencelen.andvari.core.trust.TrustGrammar.isUuid(userId) && emailNorm.isNotEmpty() && addressAccount(origin, emailNorm) == null) {
            state.set("$CLI_ADDRESS$origin|$emailNorm", userId)
        }
    }

    /**
     * [EARLIER_ACCOUNT_KNOWN] where [emailNorm] is recorded at [origin] as another account than [userId] ([CLI_ADDRESS]),
     * with the mark that the forgetting is offered for it; null otherwise. The flows compare the served account's key
     * with its own record before they ask this (a known account under another key never reaches it).
     */
    private fun addressRefusal(origin: String, emailNorm: String, userId: String): String? {
        val earlier = addressAccount(origin, emailNorm)?.takeIf { it != userId } ?: return null
        val marked = runCatching { state.set("$CLI_EARLIER$origin|$emailNorm", "$earlier $userId") }.isSuccess
        if (marked) earlierRefused = origin to emailNorm
        return EARLIER_ACCOUNT_KNOWN
    }

    /** The account the address is tied to was taken or reopened: an offer made against an earlier one goes. */
    private fun offerSettled(origin: String, emailNorm: String) {
        runCatching { state.set("$CLI_EARLIER$origin|$emailNorm", null) }
    }

    /**
     * The origin and device row of a session this run's sink refused after the server had made it ([SessionSink.take]): the
     * server holds that device row for the account, with its session ended. Null when none was refused so.
     */
    var refusedAfterCommit: Pair<String, String>? = null
        private set

    /** The address at the origin of this run's refusal of another account under a known address ([keptRefusal]), or null. */
    var earlierRefused: Pair<String, String>? = null
        private set

    /** Told once when an account under an address whose earlier account was forgotten is taken ([CLI_REMADE]). */
    var onNewAccountRemembered: ((origin: String, emailNorm: String) -> Unit)? = null

    /** What [earlierOffer] finds for an address: the earlier account to forget, or the same account under another key. */
    sealed class EarlierOffer {
        class Account(val userId: String) : EarlierOffer()
        data object Key : EarlierOffer()
    }

    /**
     * The offer standing for [emailNorm] at [origin], or null where none stands. The tool's own guard: an account is offered
     * only where a refusal of this home found the server serving another account id under the address than the one its
     * saved session ([saved]) still ties the address to; the same id under another key offers nothing ([EarlierOffer.Key]).
     */
    fun earlierOffer(origin: String, emailNorm: String, saved: SavedSessions): EarlierOffer? {
        val mark = state.get("$CLI_EARLIER$origin|$emailNorm")?.split(' ') ?: return null
        if (mark.size == 2 && mark[0] == "key") return EarlierOffer.Key
        val tied = saved.accounts(origin)?.firstOrNull { it.emailNorm == emailNorm }?.userId ?: addressAccount(origin, emailNorm)
        if (mark.size != 2 || tied == null || tied != mark[0] || mark[1] == mark[0]) {
            state.set("$CLI_EARLIER$origin|$emailNorm", null)
            return null
        }
        return EarlierOffer.Account(tied)
    }

    /**
     * What forgetting [userId] under [emailNorm] at [origin] removes: the keys of both stores, the identity record excepted,
     * and never a record that names another server ([namesAnotherServer]), whatever account id it carries.
     * A request for the operator's help kept at [origin] goes with them where it names [emailNorm] or cannot be read: it was
     * made for the account under the address, and the account it would deliver is checked against the one this home keeps
     * there, which after the forgetting is none (one under another address stays, as every other account's record does).
     */
    fun earlierRecords(origin: String, emailNorm: String, userId: String): List<String>? {
        val assist = "$KEPT_ASSIST$origin"
        val request = secure.get(assist)?.let { text -> assist.takeIf { requestAddress(text).let { it == null || it == emailNorm } } }
        val tie = listOf("cli.session|$origin|$emailNorm", "ovh.dev|$origin|$emailNorm", "$CLI_EARLIER$origin|$emailNorm", "$CLI_ADDRESS$origin|$emailNorm") +
            listOfNotNull("$CLI_EMAIL$origin".takeIf { state.get(it) == emailNorm }, request)
        val all = (state.keys() ?: return null) + (secure.keys() ?: return null)
        return all.filter { k -> k in tie || (userId in k.split('|') && !k.startsWith(CLI_IDENTITY) && !namesAnotherServer(k, origin)) }.distinct().sorted()
    }

    /**
     * Forgets the earlier account [userId] under [emailNorm] at [origin], locally; nothing is sent. The mark that it was
     * begun is written first ([CLI_FORGETTING]), so that a run stopped half-way is finished by the next ([finishForgetting]).
     */
    fun forgetEarlier(origin: String, emailNorm: String, userId: String) {
        state.set("$CLI_FORGETTING$origin|$emailNorm", userId)
        finishForgetting(origin, emailNorm)
    }

    /**
     * Finishes a forgetting begun for [emailNorm] at [origin] and answers the forgotten id, or null when none was begun. It
     * removes the saved session that ties the address to that account, the device record for the address, the address
     * remembered as the account there, and every record of either store keyed by that account's id, except its identity key
     * ([CLI_IDENTITY]); it leaves the pin, the server's records and every other account. The mark goes last.
     */
    fun finishForgetting(origin: String, emailNorm: String): String? {
        val mark = "$CLI_FORGETTING$origin|$emailNorm"
        val userId = state.get(mark) ?: return null
        held[origin]?.takeIf { it.session.userId == userId }?.let { dropSession(origin) }
        val records = earlierRecords(origin, emailNorm, userId) ?: throw CliError("this device could not list what it keeps; run the command again to finish forgetting the earlier account")
        for (k in records) { state.set(k, null); secure.set(k, null) }
        // The request's place in the store's own list of kept requests goes with it.
        if ("$KEPT_ASSIST$origin" in records) io.silencelen.andvari.core.client.recovery.KeptAssistRequests.forget(secure, origin, null)
        if (state.get("$CLI_EMAIL$origin") == emailNorm) state.set("$CLI_EMAIL$origin", null)
        state.set("$CLI_REMADE$origin|$emailNorm", userId)
        state.set("$CLI_EARLIER$origin|$emailNorm", null)
        state.set(mark, null)
        return userId
    }

    /** Every forgetting begun and not finished, finished (at the start of a run). */
    fun settleForgettings() {
        val keys = try { state.keys() } catch (e: Exception) { null } ?: return
        for (k in keys.filter { it.startsWith(CLI_FORGETTING) }) {
            val rest = k.removePrefix(CLI_FORGETTING)
            runCatching { finishForgetting(rest.substringBeforeLast('|'), rest.substringAfterLast('|')) }
        }
    }

    /**
     * The tool's side of a followed move ([NamespaceMover], design §4.4 "A namespace's trust records move with its pin"):
     * what it keeps outside the engine's device state for [from] goes to [to]: the saved sessions in the secure store
     * (their tokens, which the same server takes at its new address), and the last-used origin when it was [from]. The
     * session held in memory for [from] is dropped. Idempotent, as the engine asks: a second call finds nothing left at
     * [from]. A saved session already at [to] for the same account and different from the one carried is a conflict:
     * nothing is replaced and the move stays unfinished (`MOVING`) until the person forgets one of the two.
     */
    private val mover = NamespaceMover { from, to ->
        val keys = secure.keys() ?: return@NamespaceMover false
        val carried = keys.filter { it.startsWith("cli.session|$from|") }.map { it to "cli.session|$to|" + it.removePrefix("cli.session|$from|") }
        for ((old, new) in carried) {
            val text = secure.get(old) ?: continue
            val moved = SavedSessions.atOrigin(text, to) ?: return@NamespaceMover false
            val there = secure.get(new)
            if (there != null && there != moved) return@NamespaceMover false
            secure.set(new, moved)
        }
        for ((old, _) in carried) secure.set(old, null)
        if (state.get(Ctx.K_ORIGIN) == from) state.set(Ctx.K_ORIGIN, to)
        dropSession(from)
        clients.remove(from)
        true
    }

    val trust: CardTrust = CardTrust(pins, TrustCardChainVerifier(crypto), ::client, crypto, null, false, onMoved = mover)
    val devices = KnownDevices(state, crypto)

    /**
     * "Forget this server" (design §4.4, §12.3): deletes everything this device keeps for [origin], locally, so it works
     * under a forked, damaged or unreadable pin and with no pin at all. Nothing is sent, not even a logout.
     * 1. The held session of [origin] is dropped and its keys wiped in memory.
     * 2. The engine's wipe ([CardTrust.forgetServer]): the records of the accounts kept there (the saved sessions' user
     *    ids and those the tool named, [CLI_NAME]), every per-origin record, and last the pin with its marks.
     * 3. Only when that is done, what the tool keeps itself: the saved sessions ([saved]), the kept assisted-recovery
     *    request (the secure store, outside the engine's wipe), the names and the remembered account ([CLI_NAME],
     *    [CLI_EMAIL]), and the last-used origin when it is this one. These are the tool's list of the accounts to wipe,
     *    so they are kept while the engine's wipe is partial: a second run finds the same accounts and finishes.
     * The tool keeps no item cache on disk ([itemCache] is in memory); the item engine's records are the engine's.
     */
    fun forgetServer(origin: String, saved: SavedSessions, rememberedEmail: String?): ServerForgotten {
        dropSession(origin)
        clients.remove(origin)
        val keys = try { state.keys() } catch (e: Exception) { null }
        val named = keys.orEmpty().filter { it.startsWith("$CLI_NAME$origin|") }
        val accounts = (saved.userIds(origin).orEmpty() + named.map { it.substringAfterLast('|') }).distinct()
        // The pin as it stood before the wipe, in force or forked (null when there was none or it cannot be read): with it,
        // a kept assisted-recovery request bound to this server goes even when it sits under another address. A fork is
        // read too (`pinFor` answers null under one): forgetting a forked server forgets what it issued.
        val issuer = try {
            when (val st = pins.state(origin)) {
                is PinState.Pinned -> st.pin
                is PinState.Forked -> st.pin
                else -> null
            }
        } catch (e: Exception) { null }
        val engine = trust.forgetServer(origin, accounts)
        if (engine is ServerForgotten.Partly) return engine
        var failed: String? = if (keys == null) ServerForgotten.CANNOT_LIST else null
        saved.forgetAll(origin, rememberedEmail)?.let { failed = failed ?: it }
        fun delete(f: () -> Unit) { try { f() } catch (e: Exception) { failed = failed ?: ServerForgotten.CANNOT_DELETE } }
        delete { io.silencelen.andvari.core.client.recovery.KeptAssistRequests.forget(secure, origin, issuer) }
        for (k in named + "$CLI_EMAIL$origin") delete { state.set(k, null) }
        delete { if (state.get(Ctx.K_ORIGIN) == origin) state.set(Ctx.K_ORIGIN, null) }
        return failed?.let { ServerForgotten.Partly(it) } ?: ServerForgotten.Done
    }

    /**
     * What this home still keeps of an account other than [userId] at [origin], said as the end of [DELETED_SERVER_KEPT], or
     * null where it keeps nothing of another account there (decided on 2026-11-19: a deletion forgets the server only
     * then). Another account's saved session or remembered address, its name, and the record of its identity key all
     * count: a forgetting keeps that record on purpose, and it must not go as a side effect of another account's deletion.
     * A store that cannot list what it keeps counts too (the safer side).
     */
    fun otherAccountKept(origin: String, userId: String, emailNorm: String): String? {
        val kept = keptAt(origin) ?: return KEPT_OTHER_UNREADABLE
        kept.firstOrNull { it.userId != userId }?.let { return fill(KEPT_OTHER_ACCOUNT, it.emailNorm) }
        // A request for the operator's help made for another address (or one this device cannot read) is that address's.
        secure.get("$KEPT_ASSIST$origin")?.let { text ->
            val named = requestAddress(text) ?: return KEPT_OTHER_REQUEST_UNREADABLE
            if (named != emailNorm) return fill(KEPT_OTHER_REQUEST, named)
        }
        val keys = try { state.keys() } catch (e: Exception) { null } ?: return KEPT_OTHER_UNREADABLE
        keys.firstOrNull { it.startsWith("$CLI_ADDRESS$origin|") && state.get(it) != userId }?.let { return fill(KEPT_OTHER_ACCOUNT, it.substringAfterLast('|')) }
        fun other(prefix: String) = keys.firstOrNull { it.startsWith("$prefix$origin|") && it.removePrefix("$prefix$origin|") != userId }
        other(CLI_IDENTITY)?.let { return fill(KEPT_OTHER_KEY, it.substringAfterLast('|')) }
        other(CLI_NAME)?.let { return fill(KEPT_OTHER_NAME, it.substringAfterLast('|')) }
        return null
    }

    /** The address a kept request for the operator's help ([KEPT_ASSIST]) was made for, normalized; null where it cannot be read. */
    fun requestAddress(text: String): String? = runCatching {
        ((WireJson.json.parseToJsonElement(text) as kotlinx.serialization.json.JsonObject)["email"] as kotlinx.serialization.json.JsonPrimitive).content
    }.getOrNull()?.let(io.silencelen.andvari.core.trust.TrustGrammar::emailNorm)

    /** The display name this device registered or was told, per (origin, userId); the server does not serve it. */
    fun displayName(origin: String, userId: String): String = state.get("$CLI_NAME$origin|$userId") ?: ""
    fun rememberName(origin: String, userId: String, name: String) = state.set("$CLI_NAME$origin|$userId", name)

    /** The name this home keeps for the account ([displayName]), or null when it keeps none ([LinkName]). */
    fun ownName(origin: String, userId: String): String? = state.get("$CLI_NAME$origin|$userId")?.takeIf { it.isNotEmpty() }

    fun accountState(h: HeldSession) = StoredAccountState.forAccount(h.session.account, client(h.origin), crypto, state)

    /**
     * The offline cache of the session [h], in the namespace of its origin and account (spec 02 §8). The CLI keeps none
     * between runs: each run pulls from 0 into memory. A host that wants a durable queue sets this (the journeys do).
     */
    var itemCache: (HeldSession) -> io.silencelen.andvari.core.client.VaultCache = { io.silencelen.andvari.core.client.InMemoryVaultCache() }

    fun linkAccount(origin: String): LinkAccount? = held[origin]?.let { LinkAccount.of(it.session, displayName(origin, it.userId), accountState(it)) }

    private val accounts = HashMap<HeldSession, AccountSession>()

    /** The signed-in account at [origin] with its vault-log engine and item layer, or null when signed out. */
    fun account(origin: String): AccountSession? = held[origin]?.let { h -> accounts.getOrPut(h) { AccountSession(this, h) } }

    /** The link engine; the CLI is a computer, so setup links are allowed (design §9.5). Shares go through the account's log engine. */
    val links: WireLinkFlows by lazy {
        WireLinkFlows(
            ::client, trust, state, crypto, clock, { held.values.firstOrNull()?.let { account(it.origin)?.link } }, setupAllowed = true,
            shares = { contact, share, uncompared ->
                val a = held.values.firstOrNull()?.let { account(it.origin) }
                a != null && io.silencelen.andvari.core.client.link.VaultLogShareRelease(a.logs).release(contact, share, uncompared)
            },
        )
    }

    /**
     * The device-link engine in both roles (design §8.2): the signed-in account shows a link; this device, with no
     * account, claims one. A session the engine refuses is ended at once, alone, by its own refresh token ([endOne]);
     * the logout given as `discard` is the shared flow's fallback for a host that names no such end, and is not used here.
     */
    val deviceLinks: io.silencelen.andvari.core.client.devicelink.WireDeviceLinks by lazy {
        io.silencelen.andvari.core.client.devicelink.WireDeviceLinks(
            ::client, trust, state, crypto, clock, { held.values.firstOrNull()?.let { account(it.origin)?.link } }, devices, sink,
            discard = { origin, token -> withToken(origin, token).call(WireRoute.LOGOUT, decode = { }) },
            deviceName = deviceName, platform = platform,
            endOne = { origin, refreshToken -> endOne(origin, refreshToken) },
        )
    }

    /** Kit recovery (design §10), only from the kit entry. */
    /**
     * True once a recovery in this run found this home's record of the key for the account it opens: its check and the
     * session its commit opens are both compared with the record ([recoveryKnownIdentity]), as the apps build theirs.
     */
    var recoveryKeyKnown = false
        private set

    private val recoveryKnownIdentity: (String) -> ByteArray? = { userId -> knownIdentity(userId)?.also { recoveryKeyKnown = true } }

    val kitRecovery by lazy {
        io.silencelen.andvari.core.client.recovery.WireKitRecovery(::client, trust, devices, sink, crypto, platform, deviceName, knownIdentity = recoveryKnownIdentity)
    }

    /**
     * Password change, kit rotation, devices and require-link for the session [h] (every † action through [reauth]). The
     * session's device id is given as `thisDevice`, so a devices list that does not mark exactly this device current
     * (another account's whole list, or another session's view) is refused.
     *
     * [newWrapCost] is the cost a new master password is derived at; only [changePassword] derives one, and it always
     * names it ([newWrapCost], spec 01 §7: never lower than the account already had). The other actions derive no new
     * wrap, and are given the account's own cost.
     */
    fun settings(h: HeldSession, newWrapCost: io.silencelen.andvari.core.crypto.KdfParams? = null) = io.silencelen.andvari.core.client.account.WireAccountSettings(
        h.origin, h.emailNorm, trust.pinFor(h.origin)?.card0Hash ?: "", h.session.account, client(h.origin), crypto, reauth(h),
        kdfParams = newWrapCost ?: h.proofCost ?: io.silencelen.andvari.core.crypto.KdfParams.DEFAULT,
        thisDevice = h.session.deviceId,
    )

    /**
     * Spec 01 §7, "never derived at a lower cost than the account already had": the cost of a new wrap of [h]'s account,
     * the cost of the wrap its proof stands on ([HeldSession.proofCost]; the pending one's when that is higher), raised to
     * the server's policy as this run last read it ([policyCosts]; nothing is dialed here, so a wrong password still sends
     * nothing), where that is a legitimate upgrade inside the fence ([io.silencelen.andvari.core.client.KdfUpgrade.shouldUpgrade]).
     * A policy that is lower, sideways, outside the fence or not read changes nothing. Null when this run does not know
     * the account's own cost.
     */
    internal fun newWrapCost(h: HeldSession): io.silencelen.andvari.core.crypto.KdfParams? {
        val own = h.proofCost ?: return null
        val pending = h.pendingCost
        val base = if (pending != null && io.silencelen.andvari.core.client.KdfUpgrade.shouldUpgrade(own, pending)) pending else own
        val policy = synchronized(policyCosts) { policyCosts[h.origin] } ?: return base
        return if (io.silencelen.andvari.core.client.KdfUpgrade.shouldUpgrade(base, policy)) policy else base
    }

    /** Recovery posture and escrow (design §4.5, §7.7) for the session [h]. */
    fun recoverySettings(h: HeldSession) = io.silencelen.andvari.core.client.account.WireRecoverySettings(
        h.origin, h.session.account, client(h.origin), crypto, state, trust, reauth(h), settings(h), clock,
    )

    /** Operator-assisted recovery (design §9.3); its kept requests live in the secure store. */
    val assisted by lazy {
        io.silencelen.andvari.core.client.recovery.WireAssistedRecovery(::client, trust, devices, sink, crypto, secure, platform, deviceName, clock, knownIdentity = recoveryKnownIdentity)
    }

    /** The live recovery requests of the session [h]'s account, and the veto (design §9.3). */
    fun recoveryRequests(h: HeldSession) =
        io.silencelen.andvari.core.client.recovery.WireRecoveryRequests(h.origin, h.session.account, client(h.origin), trust, crypto, clock)

    /**
     * The operator's routes (design §9.2, spec 03 rows 73 to 86) for the session [h]: the engine's own implementation over
     * the session's guarded client, this device's trust (a public card refuses operator recovery here) and the one
     * re-authentication path. It refuses on this device, sending nothing, when [role] is not the operator's: the commands
     * pass the pinned card's word ([Commands]' `operatorByCard`), which follows a hand-over at once, where the session's
     * own role is what the server said when this device signed in.
     */
    fun operator(h: HeldSession, role: String = h.session.role): io.silencelen.andvari.core.client.account.WireOperatorRoutes =
        io.silencelen.andvari.core.client.account.WireOperatorRoutes(h.userId, role, client(h.origin), trust, reauth(h))

    /**
     * The operator's card changes for the session [h]: the shared code's own path, the one the
     * desktop's console takes, over the session's guarded client, this device's trust and the one re-authentication path.
     */
    fun operatorCards(h: HeldSession): io.silencelen.andvari.core.client.account.WireOperatorCards =
        io.silencelen.andvari.core.client.account.WireOperatorCards(h.session, client(h.origin), crypto, trust, reauth(h), clock)

    /**
     * Spec 01 §7, "KDF upgrade": right after an opening of [h] that verified [password] (a reopen of a saved session, a
     * sign-in with the password), the engine's quiet re-key ([EstablishedSession.reKeyAfterOpening]) with that password,
     * wiped there whatever happens. Nothing of it is shown to the person: the opening already succeeded, and every
     * answer leaves the account openable with the same password. [lastReKey] keeps the answer, which holds no secret.
     */
    suspend fun reKeyAfterOpening(h: HeldSession, password: CharArray): io.silencelen.andvari.core.client.session.ReKeyOutcome {
        // The settle below borrows the same password; its copy is wiped on every path.
        val forSettle = password.copyOf()
        try {
            val out = h.session.reKeyAfterOpening(crypto, client(h.origin), reauth(h), password).also { lastReKey = it }
            if (out in SENT_A_CHANGE) settleAfterReKey(h, forSettle)
            return out
        } finally {
            forSettle.fill('\u0000')
        }
    }

    /** What the last [reKeyAfterOpening] in this run came to; never printed. */
    var lastReKey: io.silencelen.andvari.core.client.session.ReKeyOutcome? = null
        private set

    /**
     * Spec 01 §7, the pending-record rule, inside the run that re-keyed: the answer to the change may be a lie (a "done"
     * the server never stored, a refusal of one it did store), so the account's keys are read again and settled by the
     * engine's own open-and-compare ([EstablishedSession.settleServed], [password] a copy it wipes): the served wrap is
     * [h]'s own from now on only when its salt, cost and wrapped key are [h]'s own or pending wrap, or when, at a cost
     * inside the whole fence, it opens with [password] to exactly the account key [h] holds. Nothing derived here is
     * sent. Anything else (no answer, a cost outside the fence, a wrap that does not open or opens to another key, keys
     * wiped meanwhile) leaves [h] unsettled: every proof in this run is then refused here ([HeldSession.serverKeysNotKnown]).
     */
    private suspend fun settleAfterReKey(h: HeldSession, password: CharArray) {
        h.serverKeysNotKnown = true
        h.keysNotKnownWhy = KeysNotKnown.NOT_READ
        val r = client(h.origin).call(WireRoute.ACCOUNT_KEYS) { WireJson.json.decodeFromString(AccountKeys.serializer(), it) }
        val served = (r as? WireResult.Ok)?.value ?: return
        h.keysNotKnownWhy = KeysNotKnown.CHANGED
        val settled = h.session.settleServed(crypto, served, password.copyOf())
        if (settled != io.silencelen.andvari.core.client.session.ServedWrap.KNOWN && settled != io.silencelen.andvari.core.client.session.ServedWrap.ADOPTED) return
        // The session proves against the wrap it settled on, salt and cost included.
        h.proof = h.session
        h.proofCost = served.kdfParams
        h.pendingProof = null
        h.pendingCost = null
        h.serverKeysNotKnown = false
    }

    /** A proof of the password this run refused because the server's keys are not the ones it knows: that session. */
    private var refusedForUnknownKeys: HeldSession? = null

    /**
     * What a command's end must say instead of its own words, or null: a proof refused here because the server's keys are
     * not the ones this run knows ([keysNotKnownError]). A proof the server refused is the engine's own result
     * ([io.silencelen.andvari.core.client.account.Reauthed.PROOF_REFUSED]), which each command says as
     * [proofRefusedError]; a wrong password is only ever one this device found, with nothing sent.
     */
    fun proofFault(): CliError? = refusedForUnknownKeys?.let { keysNotKnownError(it.origin, it.keysNotKnownWhy) }

    fun onboarding(origin: String, kdf: io.silencelen.andvari.core.crypto.KdfParams = io.silencelen.andvari.core.crypto.KdfParams.DEFAULT) =
        WireOnboarding(origin, client(origin), trust, devices, sink, crypto, state, platform, deviceName, clock, links = links, kdfParams = kdf, knownIdentity = { knownIdentity(origin, it) })

    /**
     * The one re-authentication path (design §4.4; spec 01 §7 "In-session password proofs"): the
     * engine's [PasswordGate][io.silencelen.andvari.core.client.pin.PasswordGate] first ([Reauth]), then the typed password
     * proven on this device against the session's own wrap in one pass ([localProof]), with `currentAuthKey` from that
     * same derivation under the wrap's own salt and cost. Nothing is dialed for it: no prelogin, no `GET /account/keys`, so
     * no value a server names at this moment goes into what is sent, and a password that does not open the wrap is
     * [ReauthKey.WrongPassword] with nothing sent at all.
     */
    fun reauth(h: HeldSession): Reauth = Reauth(object : ReauthSession {
        override val origin: String get() = h.origin
        override val emailNorm: String get() = h.emailNorm
        override suspend fun deriveCurrentAuthKey(password: CharArray): String? = (localProof(h, password) as? ReauthKey.Key)?.currentAuthKey
        override suspend fun proveCurrentAuthKey(password: CharArray): ReauthKey = localProof(h, password)
    }, trust::gatePins)

    /**
     * Spec 01 §7: [password] (wiped) proven by the engine's [EstablishedSession.proveAuthKey] against [h]'s own wrap
     * ([HeldSession.proof]), one Argon2 pass that also gives `currentAuthKey`; then, only when that is a wrong password and
     * a password change's answer never came, against the pending wrap ([HeldSession.pendingProof]). Nothing is dialed and
     * no key leaves the engine. [ReauthKey.Refused], with nothing sent, when the proof cannot be made here: no pin of the
     * origin in force, the session's keys already wiped, no session rebuilt over a changed wrap, or a kept salt or cost the
     * engine will not use. None of these follows from a session this run opened; the action is refused, never sent anyway.
     */
    internal fun localProof(h: HeldSession, password: CharArray): ReauthKey =
        if (h.serverKeysNotKnown) {
            // Spec 01 §7: the server's keys are not the ones this run knows. A proof made now would be derived under a wrap
            // the server may not hold and read as a wrong password: none is made, and nothing is sent.
            password.fill('\u0000')
            refusedForUnknownKeys = h
            ReauthKey.Refused
        } else {
            proveHere(h, password)
        }

    private fun proveHere(h: HeldSession, password: CharArray): ReauthKey {
        val pending = h.pendingProof
        val spare = if (pending != null) password.copyOf() else null
        try {
            val first = proveWith(h, h.proof, password)
            if (first != ReauthKey.WrongPassword || pending == null || spare == null) return first
            return proveWith(h, pending, spare)
        } finally {
            spare?.fill('\u0000')
        }
    }

    private fun proveWith(h: HeldSession, proof: EstablishedSession?, password: CharArray): ReauthKey {
        // The shared code's own answer whether the account's keys were wiped (`identityPub()` reads public
        // material and never throws, so it could not tell).
        if (proof == null || trust.pinFor(h.origin) == null || h.session.account.isWiped) {
            password.fill('\u0000')
            return ReauthKey.Refused
        }
        return proof.proveAuthKey(crypto, password)
    }

    /**
     * A session the engine rebuilds ([EstablishedSession.reopened]) over [w], the wrap of a password change this device
     * sent, so that [EstablishedSession.proveAuthKey] proves against it. It is used for that proof alone: it holds [h]'s
     * own account and tokens, and of the account's keys document only the wrap (salt, cost, wrapped key) and the identity
     * key the engine checks against the account are filled; the encrypted identity seed, which nothing reads from it, is
     * left empty. Null when the engine will not build it (the keys are wiped, or [h]'s tokens are gone).
     */
    private fun proofOver(h: HeldSession, w: AccountSettingsNewWrap): EstablishedSession? {
        val s = h.session
        if (s.account.isWiped) return null
        val identity = Bytes.toB64(s.account.identityPub())
        val keys = AccountKeys(
            kdfSalt = w.kdfSalt, kdfParams = w.kdfParams, wrappedUvk = w.wrappedUvk, encryptedIdentitySeed = "", identityPub = identity,
            recoveryConfirmed = s.recoveryConfirmed,
        )
        return EstablishedSession.reopened(
            s.origin, s.emailNorm, s.userId, s.deviceId, s.role, s.totpEnrolled, s.mustEnrollTotp, s.how, h.accessToken, h.refreshToken, keys, s.account,
        )
    }

    /**
     * `account password` for [h]: the engine's change ([WireAccountSettings.changeWrap], its re-authentication through
     * [reauth]), with this session's proof kept in step so the next re-authentication in this run proves the password in
     * force. A session over the new wrap is kept as pending before the request goes; the server's taking it makes it the
     * session's own proof; a refusal drops it; a lost answer keeps it pending, so either password proves until the next
     * reopen settles it. Both passwords are wiped.
     *
     * The new wrap is derived at [newWrapCost] (spec 01 §7: never lower than the account already had). While the server's
     * keys are not the ones this run knows, nothing is derived and nothing is sent: the proof would be refused here anyway.
     */
    suspend fun changePassword(h: HeldSession, current: CharArray, next: CharArray): Reauthed<Unit> {
        if (h.serverKeysNotKnown) {
            current.fill('\u0000')
            next.fill('\u0000')
            refusedForUnknownKeys = h
            return Reauthed.NoSession
        }
        val cost = newWrapCost(h)
        if (cost == null) {
            current.fill('\u0000')
            next.fill('\u0000')
            throw CliError(
                "this run of the tool does not know the password-hashing cost of the account's keys on ${h.origin}, so it derives no new " +
                    "master password (one at a lower cost than the account has would weaken it). Nothing was sent and nothing changed: " +
                    "run the command again",
            )
        }
        return when (val r = settings(h, cost).changeWrap(current, next) { w -> h.pendingProof = proofOver(h, w); h.pendingCost = w.kdfParams }) {
            is Reauthed.Done -> {
                // The old wrap no longer opens on the server: when no session can be rebuilt over the new one, every
                // later proof in this run is refused rather than proven against the old password.
                h.proof = proofOver(h, r.value)
                h.proofCost = r.value.kdfParams
                h.pendingProof = null
                h.pendingCost = null
                Reauthed.Done(Unit)
            }
            Reauthed.Unknown -> Reauthed.Unknown
            Reauthed.NoSession -> Reauthed.NoSession.also { h.dropPending() }
            Reauthed.WrongPassword -> Reauthed.WrongPassword.also { h.dropPending() }
            Reauthed.PasswordTooWeak -> Reauthed.PasswordTooWeak.also { h.dropPending() }
            is Reauthed.Refused -> r.also { h.dropPending() }
        }
    }

    private fun HeldSession.dropPending() {
        pendingProof = null
        pendingCost = null
    }

    companion object {
        /** The tool's own per-origin records in the device state: `cli.name|<origin>|<userId>`, `cli.email|<origin>`. */
        const val CLI_NAME = "cli.name|"
        const val CLI_EMAIL = "cli.email|"

        /**
         * The tool's records for an earlier account under a known address (decided on 2026-11-17), all per origin, so that
         * they follow a move and go with "Forget this server": `cli.identity|<origin>|<userId>` the identity key this home
         * first took for an account (kept by the forgetting; it goes with the server, or with the account's confirmed
         * deletion); `cli.earlier|<origin>|<email>` the offer a refusal made ("<earlier id> <served id>", or "key <id>" for
         * the same account under another key, which offers nothing); `cli.forgetting|<origin>|<email>` a forgetting begun
         * (the earlier id), written first and taken away last; `cli.remade|<origin>|<email>` the forgotten id, until the
         * next account under the address is taken and the person is told once.
         */
        const val CLI_IDENTITY = "cli.identity|"
        const val CLI_EARLIER = "cli.earlier|"
        const val CLI_FORGETTING = "cli.forgetting|"
        const val CLI_REMADE = "cli.remade|"

        /**
         * Which account an address is at a server (`cli.address|<origin>|<email>` → the account's id): written when this
         * home first takes a session of the address, and never from a later value. It outlives a sign-out and the server's
         * end of a session, as the apps' record does; it goes with the forgetting of that account, with "Forget this
         * server", and with this home's own confirmed deletion of the account.
         */
        const val CLI_ADDRESS = "cli.address|"

        /** Where the shared code keeps a request for the operator's help, per server, in the secure store. */
        const val KEPT_ASSIST = "ovh.assist|"

        /**
         * True where the record [key] names a server other than [origin] (a component that is an origin). An account's id
         * is matched in a removal of [origin]'s account only outside such records: another server may serve the same id.
         */
        fun namesAnotherServer(key: String, origin: String): Boolean = key.split('|').any { it != origin && it.contains("://") }

        fun defaultHttp(): HttpClient = HttpClient(Java) {
            install(HttpTimeout) { requestTimeoutMillis = 60_000; connectTimeoutMillis = 10_000 }
            expectSuccess = false
        }

        /**
         * True when a refused refresh means the server ended the session (a `401`: an unknown, revoked, reused or expired
         * refresh token, a revoked device or an account no longer active). A stop on this device (`origin_stopped`, sent
         * nothing), a rate limit or any other refusal does not end it.
         */
        fun endsSession(r: WireResult.Refused): Boolean = r.status == 401 && r.code != io.silencelen.andvari.core.client.net.ORIGIN_STOPPED

        /**
         * True when a refresh that was sent got no answer in the server's own envelope: no connection, a timeout, a page
         * that is not the server's (a gateway's `502`, say), or a body that does not read (a `200` among them, which the
         * server certainly took). The server may have taken it all the same, so the refresh token held here may be one it
         * replaced ([HeldSession.refreshOutAt]). Only an answer in the server's own envelope (a token pair, or a refusal
         * the server wrote) is an answer. An answer this device stopped reading because it was larger than a refresh's
         * answer may be (`Refused(0, body_over_limit)`) is none either: something answered, but what it said cannot be
         * told. The device's own guard, which stops a request before anything is sent, is not among these: there nothing
         * left the device, and the caller puts the record back as it was.
         */
        fun refreshOut(r: WireResult<*>): Boolean =
            r is WireResult.NoAnswer ||
                (r is WireResult.Refused && r.status <= 0 && r.code != io.silencelen.andvari.core.client.net.ORIGIN_STOPPED)

        /**
         * How long after a refresh that got no answer was sent it may be sent once more: the server takes a token it has
         * replaced again only within sixty seconds of replacing it, and the second try has to arrive inside them; ten
         * seconds are the margin for the road. The edge counts as inside.
         */
        const val REFRESH_SECOND_TRY_MS = 50_000L

        /**
         * Whether a refresh of a token may be sent at [now], given the refresh of it out since [outAt] ([HeldSession.refreshOutAt],
         * null when none is) and whether it was [triedAgain] already: [RefreshMay.FIRST] when none is out; [RefreshMay.AGAIN]
         * once, within [REFRESH_SECOND_TRY_MS] of [outAt]; else [RefreshMay.NONE] (past the window, a third time, or a clock
         * that went back before [outAt]).
         */
        fun refreshMay(outAt: Long?, triedAgain: Boolean, now: Long): RefreshMay = when {
            outAt == null -> RefreshMay.FIRST
            triedAgain || now < outAt || now - outAt > REFRESH_SECOND_TRY_MS -> RefreshMay.NONE
            else -> RefreshMay.AGAIN
        }

        /** True for the loopback addresses `--connect` may name at all (design §9.5 R11); see [connectsAsOrigin]. */
        fun isLoopback(url: String): Boolean = Regex("^http://(127\\.0\\.0\\.1|localhost|\\[::1])(:[0-9]{1,5})?$").matches(url)

        /**
         * True when [connect] is [origin]'s own address (scheme, host and port): the only `--connect` (design §9.5 R11)
         * the tool honours, because a request to it names the origin by itself.
         *
         * A connection to any other address would name that address, not the origin: the tool's HTTP client (ktor's Java
         * engine) drops a `Host` header the caller sets (its `DISALLOWED_HEADERS`, before the JDK client sees it), and the
         * JDK's proxy route sends an absolute request target the server does not route (it answers with its web page).
         * The library that could name the origin (ktor's CIO engine) was declined by the owner on 2026-11-15.
         */
        fun connectsAsOrigin(origin: String, connect: String): Boolean {
            val o = io.ktor.http.Url(origin)
            val c = io.ktor.http.Url(connect)
            return o.protocol == c.protocol && o.host.equals(c.host, ignoreCase = true) && o.port == c.port
        }
    }
}

/** The exit code of a command stopped by an answer the server sent that this device cannot read (too large). */
const val EXIT_SERVER_ANSWER = 3

/**
 * The exit code of a password the server would not take now: too many wrong passwords for the account (`429
 * rate_limited` on a sign-in or on an action that asks for the password again, spec 03 §0.1, §8).
 * Not a wrong password: the right one waits as well.
 */
const val EXIT_TOO_MANY_PASSWORDS = 5

/** The message key printed with it. */
const val KEY_TOO_MANY_PASSWORDS = "too_many_wrong_passwords"

/**
 * The exit code of a command that needed a proof of the master password in a run where the account's keys on the server
 * are not the ones this run knows (spec 01 §7, the pending-record rule): no proof was made and nothing was sent. Running
 * the command again opens the keys the server holds.
 */
const val EXIT_KEYS_NOT_KNOWN = 6

/** The message key printed with it. */
const val KEY_KEYS_NOT_KNOWN = "server_keys_not_known_here"

/** The exit code of a proof of the master password the server refused although that password opened the account here. */
const val EXIT_PROOF_REFUSED = 7

/** The message key printed with it. */
const val KEY_PROOF_REFUSED = "proof_refused_by_server"

/** The outcomes of a quiet re-key in which a change may have been sent: its answer may be a lie, so the keys are read again. */
private val SENT_A_CHANGE = setOf(
    io.silencelen.andvari.core.client.session.ReKeyOutcome.DONE,
    io.silencelen.andvari.core.client.session.ReKeyOutcome.REFUSED,
    io.silencelen.andvari.core.client.session.ReKeyOutcome.UNKNOWN,
)

/**
 * What the person reads for [EXIT_KEYS_NOT_KNOWN]: what is so in each case ([why]), never "wrong password". A cost outside
 * the fence in the keys read again is not said here: it keeps its own words and code ([servedCostError], exit 3).
 */
fun keysNotKnownError(origin: String, why: KeysNotKnown): CliError = CliError(
    fill(when (why) {
        KeysNotKnown.CHANGED -> KEYS_CHANGED
        KeysNotKnown.NOT_READ -> KEYS_NOT_READ
    }, origin),
    EXIT_KEYS_NOT_KNOWN, KEY_KEYS_NOT_KNOWN,
)

/** [KeysNotKnown.CHANGED], in the approved words. `{0}` is the server's address. */
const val KEYS_CHANGED = "The account's keys on the server at {0} aren't the ones this run of andvari-cli knows: they changed " +
    "while it ran, and what the server holds now doesn't open here with this account's key. So this device didn't prove your " +
    "master password and sent nothing for this command. That isn't a wrong password. Run the command again: the next run opens " +
    "the keys the server holds."

/** [KeysNotKnown.NOT_READ], in the approved words. `{0}` is the server's address. */
const val KEYS_NOT_READ = "This run of andvari-cli doesn't know the account's keys on the server at {0}: it sent the server a " +
    "change of them, and couldn't read them again afterwards, because the server gave no usable answer. So this device didn't " +
    "prove your master password and sent nothing for this command. That isn't a wrong password. Run the command again: the next " +
    "run opens the keys the server holds."

/** What the person reads for [EXIT_PROOF_REFUSED]: the proof was sent, and the server refused it. */
fun proofRefusedError(origin: String): CliError = CliError(
    "the server at $origin refused the proof of your master password, although that password opened the account on this " +
        "device. The proof was sent; the server answered that it changed nothing. The account's keys on the server may not be " +
        "the ones this device opened: run the command again, and if the server keeps refusing, sign in again with `andvari-cli sign-in`",
    EXIT_PROOF_REFUSED, KEY_PROOF_REFUSED,
)

/** The wire code of that answer. */
const val RATE_LIMITED = "rate_limited"

/**
 * What the person reads when the server answered a password proof on this account's own session with its back-off
 * (spec 03 §8): exactly that, with the wait the server named ([retryAfterSeconds], its `Retry-After`), which for a
 * session's own device is the lock's real remaining wait; never "wrong password". The tool does not try again by itself.
 * [unchanged] says what did not happen ("Nothing changed").
 */
fun tooManyPasswords(retryAfterSeconds: Long?, unchanged: String): CliError = CliError(
    "too many wrong passwords for this account: the server takes no password for it now, the right one included. " +
        "Wait ${waitWords(retryAfterSeconds)}, then try again; " +
        "this tool does not try again by itself. $unchanged",
    EXIT_TOO_MANY_PASSWORDS, KEY_TOO_MANY_PASSWORDS,
)

/** The message key of [linkTooManyError]. */
const val KEY_LINK_TOO_MANY = "device_link_too_many_requests"

/**
 * A device link stopped because the server refused one of its requests as too many (a `429` on a check, the reveal,
 * the view, the nonce or the approval): at the tool's pace of one request every two seconds a link stays well inside
 * the server's limits, so this is another device asking from the same address at the same time. The tool's own
 * sentence, not yet on the wording page: `{0}` the server's address, `{1}` the wait the server named.
 */
const val LINK_TOO_MANY = "The server at {0} refused the device link's requests from this address as too many for now, so the " +
    "link stopped and nothing was linked. Wait {1}, then start again with a new link from your other device."

/**
 * [LINK_TOO_MANY] on the device that shows the link (the tool's own sentence, not yet on the wording page): the way on is a
 * new link shown here. `{0}` the server's address, `{1}` the wait the server named.
 */
const val LINK_TOO_MANY_SHOWN = "The server at {0} refused the device link's requests from this address as too many for now, " +
    "so the link stopped and nothing was linked. Wait {1}, then show a new link (andvari-cli link-device show)."

/** The wait a refusal named, in words; [WAIT_UNNAMED] when it named none this tool takes. */
private fun waitWords(retryAfterSeconds: Long?): String = retryAfterSeconds?.let(::seconds) ?: WAIT_UNNAMED

/** [LINK_TOO_MANY] for the refusal [r] (its `Retry-After`). */
fun linkTooManyError(origin: String, r: Answered.Refusal): CliError = linkTooManyError(origin, r.retryAfterSeconds)

/**
 * [LINK_TOO_MANY] with the wait the server named ([retryAfterSeconds]); on the device that shows the link ([shown])
 * [LINK_TOO_MANY_SHOWN]. Never "cannot be reached": the server answered.
 */
fun linkTooManyError(origin: String, retryAfterSeconds: Long?, shown: Boolean = false): CliError =
    CliError(fill(if (shown) LINK_TOO_MANY_SHOWN else LINK_TOO_MANY, origin, waitWords(retryAfterSeconds)), 1, KEY_LINK_TOO_MANY)

/**
 * A step of a device link that can wait was refused as too many (a check, the reveal, the view): the shared step waits
 * the time the server named, within the link's own time, and asks again. The tool's own line while it waits, not yet on
 * the wording page: `{0}` the server's address, `{1}` the wait the server named.
 */
const val LINK_WAITS = "The server at {0} asked this device to wait {1} before the device link's next request: too many " +
    "requests from this address just now. The link waits, within its own time, and goes on by itself."

/** [LINK_WAITS] for the refusal [r]. */
fun linkWaitsLine(origin: String, r: Answered.Refusal): String = fill(LINK_WAITS, origin, waitWords(r.retryAfterSeconds))

/**
 * A two-step code refused at a device link's pickup while the link stays (the server keeps it approved within its time):
 * the first two sentences of [WRONG_CODE_AT_LINK], and what comes next. The tool's own line, not yet on the wording page.
 * `{0}` is the server's address.
 */
const val WRONG_CODE_LINK_STAYS = "The server at {0} didn't take the two-step code. It gives the same answer for a wrong code as " +
    "for a wrong master password, but it had just asked for a code after this password, so most likely the code was wrong or " +
    "already used. The link is still open: give the master password and the current code again."

/**
 * A device link whose pickup the server refused for a master password that opens this device's copy of the account (the
 * shared step's `reauth_failed` at the pickup): not a wrong password. Under [EXIT_PROOF_REFUSED] and [KEY_PROOF_REFUSED],
 * the tool's own sentence, not yet on the wording page. `{0}` is the server's address.
 */
const val LINK_PROOF_REFUSED = "The server at {0} refused the master password at the device link, although that password opens " +
    "this device's copy of the account. That isn't a wrong password: the account's password on the server may have been " +
    "changed on another device since this device last opened it. Nothing was linked. If it was changed, start again with a " +
    "new link from your other device and the new master password; if not, tell the operator."

/** Whether a refresh may be sent ([Host.refreshMay]). */
enum class RefreshMay { FIRST, AGAIN, NONE }

/**
 * The same refusal within the link's time, where the link stays and the password is asked for again (the tool's own
 * sentence, not yet on the wording page). `{0}` is the server's address.
 */
const val LINK_PROOF_REFUSED_ASK_AGAIN = "The server at {0} refused the master password at the device link, although that " +
    "password opens this device's copy of the account. That isn't a wrong password: the account's password on the server may " +
    "have been changed on another device since this device last opened it. The link stays: type the account's current master password."

/** The message key of [RECOVERY_COMMITTED_NOT_KEPT] and [REGISTRATION_COMMITTED_NOT_KEPT]. */
const val KEY_COMMITTED_NOT_KEPT = "committed_session_not_kept"

/**
 * A recovery the server committed whose session this home did not keep, because what it keeps changed while the recovery
 * was under way (the tool's own sentence, not yet on the wording page). `{0}` the server's address, `{1}` the account's
 * address, `{2}` where the kit is ([COMMITTED_KIT_WRITTEN] or [COMMITTED_KIT_SHOWN]), `{3}` why ([NOT_KEPT_ANOTHER] and the rest).
 */
const val RECOVERY_COMMITTED_NOT_KEPT = "The recovery of {1} on {0} went through: the new master password is in force there, " +
    "and the old recovery kit no longer works. The account's new recovery kit is {2}: keep it, it is the account's only kit. " +
    "It could not be confirmed with the server, and nothing is signed in on this device, because this device did not keep the " +
    "account's session: {3}. Once that is resolved, sign in with the new master password."

/** Added to [RECOVERY_COMMITTED_NOT_KEPT] for a recovery with the operator's help. */
const val ASSISTED_REQUEST_USED = "The request for the operator's help is used up and cannot be used again."

/**
 * A registration the server made whose session this home did not keep, for the same reason (the tool's own sentence):
 * the same placeholders as [RECOVERY_COMMITTED_NOT_KEPT].
 */
const val REGISTRATION_COMMITTED_NOT_KEPT = "The account {1} was made on {0} under the master password you chose. Its recovery " +
    "kit is {2}: keep it, it is the account's only kit. It could not be confirmed with the server, and nothing is signed in on " +
    "this device, because this device did not keep the account's session: {3}. Once that is resolved, sign in with that master password."

/** Where the kit is, in those sentences: `{0}` the file. */
const val COMMITTED_KIT_WRITTEN = "written to {0}"

/** Where the kit is, in those sentences, when no file was named. */
const val COMMITTED_KIT_SHOWN = "shown above"

/** Why the session was not kept: `{0}` the other account's address. */
const val NOT_KEPT_ANOTHER = "it keeps {0} at that server now, and keeps one account per server"

/** Why: the operator's account. */
const val NOT_KEPT_OPERATOR = "it holds that server's operator account"

/** Why: the kept copy. */
const val NOT_KEPT_DAMAGED = "its own copy of the account is damaged"

/** Why: the accounts it keeps could not be read. */
const val NOT_KEPT_UNREADABLE = "it could not read which accounts it keeps"

/** Why, for a reason the tool has no words of its own for: `{0}` the reason's code. */
const val NOT_KEPT_OTHER = "the reason it gave is {0}"

/**
 * The same, where this home's record ties the address to another account than the one the commit gave (the tool's own
 * words, not yet on the wording page): `{0}` the address. `andvari-cli forget-earlier-account` is offered by that refusal.
 */
const val NOT_KEPT_EARLIER = "it knows {0} at that server as another account than the one the server gave it"

/** The message key of [REFRESH_UNANSWERED]. */
const val KEY_REFRESH_UNANSWERED = "session_refresh_unanswered"

/**
 * A command other than `sign-in` on a session whose refresh got no answer and may not be sent again (past the window, or
 * sent once more already): the tool's own sentence, not yet on the wording page. `{0}` the server's address, `{1}` the
 * account's address.
 */
const val REFRESH_UNANSWERED = "This device's refresh of its session of {1} on {0} got no answer, and the time in which it " +
    "could be sent once more has passed or it was sent once more already. The server may have replaced that session's token; " +
    "sent now, it could read as stolen and end every session of this device there, so it was not sent. Sign in again " +
    "(andvari-cli sign-in): the sign-in names that session, and the server ends it."

/** [REFRESH_UNANSWERED], with its exit code and key. */
fun refreshUnansweredError(origin: String, email: String): CliError =
    CliError(fill(REFRESH_UNANSWERED, origin, email), 1, KEY_REFRESH_UNANSWERED)

/** The message key of [REFRESH_LOST]. */
const val KEY_REFRESH_LOST = "session_refresh_lost"

/**
 * A command whose refresh of the session got no answer, with one more try left (the tool's own sentence, not yet on the
 * wording page): `{0}` the server's address, `{1}` the account's address, `{2}` the seconds of [Host.REFRESH_SECOND_TRY_MS].
 */
const val REFRESH_LOST = "{0} gave no answer this device could read to its refresh of its session of {1}. The server may have taken it all " +
    "the same, so this device sends it once more only if a command runs within {2} seconds of it; after that it sends it no " +
    "more, and you sign in again (andvari-cli sign-in)."

/** [REFRESH_LOST], with its exit code and key. */
fun refreshLostError(origin: String, email: String): CliError =
    CliError(fill(REFRESH_LOST, origin, email, Host.REFRESH_SECOND_TRY_MS / 1000), 1, KEY_REFRESH_LOST)

/** The same, said as `sign-in` goes on (the tool's own line). `{0}` the server's address, `{1}` the account's address. */
const val REFRESH_UNANSWERED_SIGN_IN = "This device's last refresh of its session of {1} on {0} got no answer, so it signs in " +
    "again and names that session: the server ends it with this sign-in."

/** [LINK_PROOF_REFUSED], with its exit code and key. */
fun linkProofRefusedError(origin: String): CliError = CliError(fill(LINK_PROOF_REFUSED, origin), EXIT_PROOF_REFUSED, KEY_PROOF_REFUSED)

/** The message key of [tooManyCodes], under [EXIT_TOO_MANY_PASSWORDS]. */
const val KEY_TOO_MANY_CODES = "too_many_wrong_codes"

/**
 * The codes' back-off (spec 03 §8), for an action whose request carried a two-step code (an account deletion with one):
 * the tool's own sentence, not yet on the wording page. The server counts the codes a session sends on their own
 * back-off, per device, apart from the password proofs'; such a request carried a proof as well, but this tool proves
 * the password on the device before it sends one, so a wrong password never reaches the server from here and what was
 * refused is the codes. `{0}` the wait the server named, `{1}` what did not happen.
 */
const val TOO_MANY_CODES = "Too many wrong two-step codes were sent from this device: the server takes no code from it now, " +
    "the right one included. Wait {0}, then try again; andvari-cli doesn't try again by itself. {1}"

/** [TOO_MANY_CODES] with the server's wait ([retryAfterSeconds], its `Retry-After`) and [unchanged]. */
fun tooManyCodes(retryAfterSeconds: Long?, unchanged: String): CliError = CliError(
    fill(TOO_MANY_CODES, waitWords(retryAfterSeconds), unchanged),
    EXIT_TOO_MANY_PASSWORDS, KEY_TOO_MANY_CODES,
)

/** [n] seconds in words: "1 second", "2 seconds". */
fun seconds(n: Long): String = "$n second${if (n == 1L) "" else "s"}"

/**
 * The sign-in's back-off and the device-link pickup's, in the words decided on 2026-11-17: the server answers a caller
 * who has proven nothing with a fixed `Retry-After: 60` whatever the lock (the real wait would tell that caller how many
 * wrong tries were made for the address lately), so the real wait can be longer and the tool says "at least a minute",
 * whatever number came. It names no address: the server refuses the same way for too many tries from one network address
 * as for one email address (it checks the network address first), so the tool cannot say which it was (the wording page's
 * line for the tool, entry PQ1).
 */
const val SIGN_IN_TOO_MANY_TRIES = "Too many tries to sign in: the server takes no password from here for now, the right one " +
    "included. Wait at least a minute, then try again. andvari-cli doesn't try again by itself."

/**
 * `account password`, when the change is done, in the approved words: `{0}` the account's email, `{1}` the server's
 * address. The server signs every other session of the account out at a password change.
 */
const val PASSWORD_CHANGED = "Your master password for {0} on {1} is changed. Use the new one from now on. Your other devices " +
    "were signed out: they need the new master password to sign in again. Your recovery kit, and operator recovery if you use " +
    "it, still work."

/**
 * `operator audit --type`, when the server's status names the kinds of audit record it keeps and the one asked for is not
 * among them, in the approved words: `{0}` the server's address, `{1}` the kind asked for, `{2}` the kinds, or "none".
 */
const val AUDIT_KIND_NOT_KEPT = "The server at {0} keeps no audit records of the kind {1}, so nothing was asked for. The kinds it keeps: {2}"

/** [template] with each `{n}` replaced by [args]`[n]`: how a sentence with slots is filled. */
fun fill(template: String, vararg args: Any): String =
    Regex("\\{(\\d)}").replace(template) { m -> args.getOrNull(m.groupValues[1].toInt())?.toString() ?: m.value }

/**
 * A two-step code refused at a device link's pickup. The server answers a wrong code exactly as it answers a wrong
 * password (`401 invalid_credentials`, spec 03 §2), and the shared step hands back one word for both, so the tool cannot
 * know which it was; it knows only that the server had asked for a code after it was given this password, so it says what
 * that makes most likely and claims no more. `{0}` is the server's address.
 */
const val WRONG_CODE_AT_LINK = "The server at {0} didn't take the two-step code. It gives the same answer for a wrong code as " +
    "for a wrong master password, but it had just asked for a code after this password, so most likely the code was wrong or " +
    "already used. Nothing was linked: start again with a new link from your other device and the current code."

/** The same at a sign-in ([WRONG_CODE_AT_LINK]). `{0}` is the server's address. */
const val WRONG_CODE_AT_SIGN_IN = "The server at {0} didn't take the two-step code. It gives the same answer for a wrong code as " +
    "for a wrong master password, but it had just asked for a code after this password, so most likely the code was wrong or " +
    "already used. Not signed in: run the command again with the current code."

/**
 * The device link's first exchange was answered, but with nothing this device could use (a body that is not the
 * exchange's answer, a server error, a salt that does not read): the server was reached, so not "cannot be reached".
 * `{0}` is the server's address.
 */
const val FIRST_STEP_UNUSABLE = "The server at {0} answered the device link's first step, but this device couldn't use the " +
    "answer, so the link stopped here. Nothing was worked out from your password, and nothing was sent with it. Try again " +
    "later, with a new link from your other device if this one has expired; if it keeps happening, tell the operator."

/**
 * The device link's first step got no answer at all, in the approved words: nothing was derived from the password and
 * nothing sent with it. `{0}` is the server's address.
 */
const val FIRST_STEP_NOT_REACHED = "The server at {0} can't be reached: the device link's first step got no usable answer, so " +
    "the link stopped here. Nothing was worked out from your password, and nothing was sent with it. Try again when the server " +
    "answers, with a new link from your other device if this one has expired."

/**
 * A later step of the device link got no answer at all, in the approved words. It claims nothing about what was sent:
 * this stop can come after the pickup was sent. `{0}` is the server's address.
 */
const val LATER_STEP_NOT_REACHED = "The server at {0} can't be reached: the device link got no usable answer and stopped before " +
    "it finished. Try again when the server answers, with a new link from your other device if this one has expired."

/** A later step of the device link was answered with nothing this device could use. `{0}` is the server's address. */
const val LATER_STEP_UNUSABLE = "The server at {0} answered the device link, but this device couldn't use the answer, so the " +
    "link stopped before it finished. Try again later, with a new link from your other device if this one has expired; if it " +
    "keeps happening, tell the operator."

/** A sign-in answered with nothing this device could use (a server error, a body that is not a sign-in's answer). */
const val SIGN_IN_UNUSABLE = "The server at {0} answered the sign-in, but this device couldn't use the answer, so you're not " +
    "signed in. Try again later; if it keeps happening, tell the operator."

/** The message key of a recovery, a registration or a device link stopped because this home keeps another account at that server. */
const val KEY_ANOTHER_ACCOUNT_KEPT = "another_account_kept"

/** The tool's own reason ([Host.keptRefusal]) when this home's store cannot list the accounts it keeps at a server. */
const val KEPT_UNREADABLE = "kept_accounts_unreadable"

/** What a stopped flow was, in the sentences below (`{2}` of [ANOTHER_ACCOUNT_KEPT] and [OPERATOR_ACCOUNT_HELD]). */
const val ACT_RECOVERY = "the recovery"
const val ACT_LINK = "the device link"
const val ACT_REGISTRATION = "the new account"
const val ACT_SIGN_IN = "the sign-in"

/**
 * A recovery, a registration or a device link stopped before the server changed anything, because this home keeps another
 * account at that server (the tool's own sentence, not yet on the wording page): `{0}` the server's address, `{1}` the
 * account kept, `{2}` what was stopped ([ACT_RECOVERY], [ACT_LINK], [ACT_REGISTRATION]).
 */
const val ANOTHER_ACCOUNT_KEPT = "This device keeps another account on {0}: {1}. andvari-cli keeps one account per server on a " +
    "device, so it stopped {2} before the server changed anything: no password, recovery kit, account or device was changed " +
    "or added, and a request for help is as it was. To go on on this device, sign {1} out first (andvari-cli sign-out --email " +
    "{1}), or use another home (--home)."

/** The message key of [OPERATOR_ACCOUNT_HELD]. */
const val KEY_OPERATOR_ACCOUNT_HELD = "operator_account_held"

/**
 * [ANOTHER_ACCOUNT_KEPT] when the account kept is the server's operator's (the tool's own sentence): this is the operator's
 * home, and the way on is another home, not signing the operator out. `{0}` the server's address, `{1}` the operator's
 * account, `{2}` what was stopped.
 */
const val OPERATOR_ACCOUNT_HELD = "This device holds the operator's account of {0}: {1}. andvari-cli keeps one account per server " +
    "on a device, so it stopped {2} before the server changed anything: no password, recovery kit, account or device was " +
    "changed or added, and a request for help is as it was. Use another home (--home) for any other account on this server; " +
    "remove the operator's account from this device (andvari-cli sign-out --email {1}) only if you mean to."

/**
 * The same stop when this home's store cannot list the accounts it keeps (the tool's own sentence). `{0}` the server's
 * address, `{1}` what was stopped.
 */
const val KEPT_ACCOUNTS_UNREADABLE = "This device can't read which accounts it keeps on {0}, so it stopped {1} before the server " +
    "changed anything: andvari-cli keeps one account per server on a device, and here it can't tell whether another is kept. " +
    "No password, recovery kit, account or device was changed or added, and a request for help is as it was."

/** The tool's reason ([Host.keptRefusal]) and message key: the address is tied here to another account id than the one served. */
const val EARLIER_ACCOUNT_KNOWN = "earlier_account_known"

/**
 * The refusal of another account under an address this device knows (decided on 2026-11-17; the tool's own sentence, not
 * yet on the wording page). It must say: what was stopped and that the server changed nothing; both possibilities, each a
 * sentence of its own and neither preferred (the account was deleted and made again and this device remembers the earlier
 * one; or the server isn't giving this device the account it knows, and then nothing should be forgotten); how to tell;
 * and the command that shows what forgetting would remove. `{0}` the server's address, `{1}` the address, `{2}` what was
 * stopped ([ACT_RECOVERY], [ACT_LINK], [ACT_REGISTRATION]).
 */
const val EARLIER_ACCOUNT_REFUSED = "This device knows {1} on {0} as another account than the one the server gives it now, so " +
    "andvari-cli stopped {2} before the server changed anything. Maybe the account under {1} was deleted and made again, and " +
    "this device still remembers the earlier one. Or maybe the server isn't giving this device the account it knows: then " +
    "something is wrong with the server, and nothing should be forgotten. You can tell which: you know whether you, or the " +
    "operator with your knowledge, deleted the account and made it again. If so, andvari-cli forget-earlier-account --email {1} " +
    "shows what this device would forget, and changes nothing until you add --yes."

/**
 * [EARLIER_ACCOUNT_REFUSED] at a device link, where the account is named by the other device that shows the link, not by
 * the server's answer to this one (the tool's own sentence, not yet on the wording page). It must say: who names the
 * account; what was stopped and that the server changed nothing; both possibilities, each its own sentence and neither
 * preferred; how to tell; the command. `{0}` the server's address, `{1}` the address, `{2}` what was stopped ([ACT_LINK]).
 */
const val EARLIER_ACCOUNT_REFUSED_LINK = "This device knows {1} on {0} as another account than the one the other device's " +
    "link names, so andvari-cli stopped {2} before the server changed anything. Maybe the account under {1} was deleted and " +
    "made again, and this device still remembers the earlier one. Or maybe the server isn't giving the account this device " +
    "knows: then something is wrong with the server, and nothing should be forgotten. You can tell which: you know whether " +
    "you, or the operator with your knowledge, deleted the account and made it again. If so, andvari-cli " +
    "forget-earlier-account --email {1} shows what this device would forget, and changes nothing until you add --yes."

/**
 * [EARLIER_ACCOUNT_REFUSED] at a new account made from this device, where the server served nothing yet (the tool's own
 * sentence, not yet on the wording page). It must say: what was stopped and that nothing was sent; both possibilities,
 * each its own sentence and neither preferred (the account under the address was deleted, and this device remembers it;
 * or it was not, and then the server should not take a new account under the address and nothing should be forgotten);
 * how to tell; and the command. `{0}` the server's address, `{1}` the address.
 */
const val EARLIER_ACCOUNT_REFUSED_NEW = "This device keeps an earlier account under {1} on {0}, so andvari-cli stopped the new " +
    "account before anything was sent. Maybe that account was deleted, and this device still remembers it. Or maybe it was " +
    "not: then the server should not take a new account under {1}, and nothing should be forgotten. You can tell which: you " +
    "know whether you, or the operator with your knowledge, deleted the account. If so, andvari-cli forget-earlier-account " +
    "--email {1} shows what this device would forget, and changes nothing until you add --yes."

/**
 * [EARLIER_ACCOUNT_REFUSED] where the server's answer had already opened a session (a sign-in): the tool's own sentence,
 * not yet on the wording page. It must say: what was stopped, that nothing of the answer was used and the session the
 * server opened was ended, so the person is not signed in (never "before the server changed anything"); both
 * possibilities, each a sentence of its own and neither preferred; how to tell; the command. `{0}` the server's address,
 * `{1}` the address, `{2}` what was stopped ([ACT_SIGN_IN]).
 */
const val EARLIER_ACCOUNT_REFUSED_OPENED = "This device knows {1} on {0} as another account than the one the server gave it " +
    "at {2}, so andvari-cli used nothing of the answer and ended the session the server had opened for it: you're not signed " +
    "in. Maybe the account under {1} was deleted and made again, and this device still remembers the earlier one. Or maybe " +
    "the server isn't giving this device the account it knows: then something is wrong with the server, and nothing should " +
    "be forgotten. You can tell which: you know whether you, or the operator with your knowledge, deleted the account and " +
    "made it again. If so, andvari-cli forget-earlier-account --email {1} shows what this device would forget, and changes " +
    "nothing until you add --yes."

/** The tool's reason and message key: a known account served under another identity key than this device took for it. */
const val IDENTITY_KEY_NOT_KNOWN = "identity_key_not_known"

/**
 * [IDENTITY_KEY_NOT_KNOWN] said (the tool's own sentence, not yet on the wording page). It must say: the server gives the
 * account this device knows under another key; that is the fault the record exists to catch; what was stopped and that
 * nothing changed; not to forget anything; to tell the operator. `{0}` the server's address, `{1}` what was stopped.
 */
const val IDENTITY_KEY_REFUSED = "The server at {0} gives this device an account it knows, but under another identity key than " +
    "the one this device took for it. That is what this device's record of the key exists to catch, so andvari-cli stopped {1} " +
    "before the server changed anything and used nothing from the answer. Don't forget anything on this device; tell the " +
    "server's operator."

/** The message key of [RECOVERY_KEY_REFUSED_AFTER_COMMIT]. */
const val KEY_RECOVERY_KEY_REFUSED = "recovery_committed_key_refused"

/**
 * A recovery (with the kit or the operator's help) the server took, whose answer gave the account this device knows under
 * another identity key than the one it took for it (the tool's own sentence, not yet on the wording page). It must say: the
 * server already took the recovery, so the new master password is in force and the earlier kit no longer works; the key
 * did not match, so nothing of the answer was used, no session is kept and no new kit was written; forget nothing; tell the
 * operator. Never "before the server changed anything". `{0}` the server's address, `{1}` the account's address.
 */
const val RECOVERY_KEY_REFUSED_AFTER_COMMIT = "The server at {0} took the recovery of {1}: your new master password is in " +
    "force there, and your earlier recovery kit no longer works. But the account the server then gave this device is under " +
    "another identity key than the one this device took for it, so andvari-cli used nothing of it: it kept no session and " +
    "wrote no new kit for that key. No recovery kit works for the account now, so keep the new master password. Don't forget " +
    "anything on this device; tell the server's operator."

/**
 * Said on the line after [RECOVERY_KEY_REFUSED_AFTER_COMMIT] (the tool's own sentence, not yet on the wording page; its own
 * wording key [KEY_RECOVERY_REFUSED_NEXT]): what the person can do next. Only the server can settle it, so the operator
 * must be told; what then decides is the key the server gives. `{0}` the server's address.
 */
const val RECOVERY_REFUSED_NEXT = "What comes next depends on {0}, so its operator must be told: once the server gives the " +
    "account under the identity key this device knows, sign in with the new master password (andvari-cli sign-in); while it " +
    "gives another key, every sign-in here is refused the same way."

/** The wording key of [RECOVERY_REFUSED_NEXT]. */
const val KEY_RECOVERY_REFUSED_NEXT = "recovery_refused_next"

/** What was stopped, in [IDENTITY_KEY_REFUSED_OPEN]: the reopening of a saved session. */
const val ACT_REOPEN = "opening this device's saved session"

/**
 * [IDENTITY_KEY_NOT_KNOWN] at a sign-in or at the reopening of a saved session (the tool's own sentence, not yet on the
 * wording page; key [IDENTITY_KEY_NOT_KNOWN]). It must say: the server gives the account this device knows under another
 * key; that is the fault the record exists to catch; nothing of the answer was used and the person is not signed in; not to
 * forget anything; to tell the operator. Never "before the server changed anything": a sign-in's answer is a session the
 * server opened (it is ended). `{0}` the server's address, `{1}` what was stopped ([ACT_SIGN_IN], [ACT_REOPEN]).
 */
const val IDENTITY_KEY_REFUSED_OPEN = "The server at {0} gives this device an account it knows, but under another identity key " +
    "than the one this device took for it. That is what this device's record of the key exists to catch, so andvari-cli " +
    "stopped {1} and used nothing from the answer: you're not signed in. Don't forget anything on this device; tell the " +
    "server's operator."

/** The message keys of a change to a shared vault that waits ([CHANGE_WAITS], [NEW_VAULT_WAITS]) and of a deletion that waits. */
const val KEY_CHANGE_WAITS = "change_waits"
const val KEY_DELETION_WAITS = "deletion_waits"

/**
 * A change to a vault got no answer, or one held earlier stops a new one (the tool's own sentence, not yet on the wording
 * page). It must say what the engine does with it (design §3.7): it may have been made; it is kept and sent again,
 * unchanged, only before the next change made to that vault from this device, and only within a day of when it was first
 * kept; after that it is not sent again, and the next change reads the vault first and drops it unless the vault holds it.
 */
const val CHANGE_WAITS = "No answer: the change may have been made. This device keeps it, unchanged, and sends it again " +
    "before the next change you make to this vault from here, if that comes within a day of when it was first kept; after a " +
    "day it is not sent again, and the next change to the vault reads the vault first and drops it unless the vault holds it."

/**
 * [CHANGE_WAITS] for a change the server's own answer called stored, which this device has not read back in the vault's
 * log yet (the tool's own sentence, not yet on the wording page; key [KEY_CHANGE_WAITS]). The engine sends it again as it
 * is until the log shows it and never gives it up after a day.
 */
const val CHANGE_WAITS_STORED = "The server answered that it took the change, but this device has not read it back in the " +
    "vault's log yet. It keeps the change, unchanged, and sends it again before the next change you make to this vault from " +
    "here, until the vault's log shows it; it never gives it up."

/**
 * [CHANGE_WAITS] for a change every send of which the server answered "slow down", which it says before it looks at a change:
 * known not made (the tool's own sentence, not yet on the wording page; key [KEY_CHANGE_WAITS]).
 */
const val CHANGE_WAITS_NOT_STORED = "The server asked this device to slow down and did not take the change. This device keeps " +
    "it, unchanged, and sends it again before the next change you make to this vault from here, if that comes within a day of " +
    "when it was first kept; after a day it is not sent again."

/** A new vault that got no answer (the tool's own sentence): it may have been made, and the list shows whether it was. */
const val NEW_VAULT_WAITS = "No answer: the new vault may have been made. andvari-cli vault list shows it if it was; this " +
    "device does not send it again."

/**
 * A vault's deletion that got no answer, or that stops a new change (the tool's own sentence): it may have been made; it
 * is never sent again by itself, and the vault takes no other change from here while it waits; the two commands. `{0}` the vault.
 */
const val DELETION_WAITS = "No answer: the deletion of vault {0} may have been made. This device keeps it and never sends it " +
    "again by itself, and it makes no other change to this vault while the deletion waits. To send it now, run andvari-cli " +
    "vault send-deletion {0}; to keep the vault instead, run andvari-cli vault keep {0}."

/** `vault send-deletion` or `keep` where no deletion of the vault waits (the tool's own sentence). `{0}` the vault. */
const val NO_DELETION_WAITS = "No deletion of vault {0} waits on this device, so nothing was sent and nothing changed."

/** The deletion is in the vault's log: done (the tool's own sentence). `{0}` the vault. */
const val DELETION_MADE = "Vault {0} is deleted: its log holds the deletion. It can be restored while the server's grace for it lasts (andvari-cli vault restore {0})."

/** The look before sending could not read the vault's log (the tool's own sentence): nothing was sent. `{0}` the vault. */
const val DELETION_NOT_READ = "This device could not read vault {0} from the server, so it sent nothing: the deletion still waits. Try again when the server answers."

/** The server refused the deletion sent again (the tool's own sentence; followed by the server's code). `{0}` the vault. */
const val DELETION_REFUSED = "The server refused the deletion of vault {0}, and this device dropped it"

/** Another entry took the deletion's place in the log (the tool's own sentence): it never happened and never will. `{0}` the vault. */
const val DELETION_PLACE_TAKEN = "Another change took the deletion's place in vault {0}'s log, so the vault was not deleted and this deletion never will be. Read the vault and decide again."

/** `vault keep`, where the server is known not to have taken the deletion (the tool's own sentence). `{0}` the vault. */
const val DELETION_KEPT_NOT_MADE = "The deletion of vault {0} was not made, and this device will never send it: the vault stays."

/**
 * `vault keep`, where the deletion may already have been made (the tool's own sentence): this device never sends it again,
 * but it cannot undo what the server may have taken; that a later run says what the vault's log shows ([FOUND_DELETION_MADE_AFTER_ALL]). `{0}` the vault.
 */
const val DELETION_KEPT_MAYBE_MADE = "This device will never send the deletion of vault {0} again. The server may already have " +
    "made it: this device reads the vault's log and says at a later run if the deletion is there, and a deleted vault can be " +
    "restored while the server's grace lasts (andvari-cli vault restore {0})."

/*
 * What this device found about a change it held (the engine's findings), each said once, on a line of its own, at the
 * signed-in run that finds it or the next one. The tool's own sentences, not yet on the wording page; one key each
 * (the constant's name, lower case). `{0}` the vault, `{1}` the change as it starts a sentence ("The deletion of", "The
 * addition of a member to", ...), `{2}` the server's code where there is one.
 */

/** The deletion the person asked for is in the vault's log (key `found_made`). */
const val FOUND_MADE = "Vault {0} is deleted: its log holds the deletion you asked for. It can be restored while the server's " +
    "grace for it lasts (andvari-cli vault restore {0})."

/** A deletion this device kept back or gave up is in the vault's log after all (key `found_deletion_made_after_all`). */
const val FOUND_DELETION_MADE_AFTER_ALL = "Vault {0} is deleted after all: its log holds the deletion this device no longer " +
    "sent. It can be restored while the server's grace for it lasts (andvari-cli vault restore {0})."

/** Another change this device withdrew or gave up is in the vault's log after all (key `found_made_after_all`). */
const val FOUND_MADE_AFTER_ALL = "{1} vault {0} was made after all: the vault's log holds it, although this device no longer sent it."

/** A change withdrawn is not made, and another took its place, so it never will be (key `found_not_made_final`). */
const val FOUND_NOT_MADE_FINAL = "{1} vault {0}, which this device withdrew, was not made, and never will be: another change took its place in the vault's log."

/** A change withdrawn is not in the log as read; it may still show up, and is then said (key `found_not_made`). */
const val FOUND_NOT_MADE = "{1} vault {0}, which this device withdrew, is not in the vault's log as this device read it. If it shows up later, this device says so."

/** A change held a day and known not stored, given up (key `found_given_up_not_made`). */
const val FOUND_GIVEN_UP_NOT_MADE = "{1} vault {0} waited a day without being taken, so this device stopped sending it: it was not made."

/** A change held a day, given up, not in the log as read (key `found_given_up_absent`). */
const val FOUND_GIVEN_UP_ABSENT = "{1} vault {0} waited a day, so this device stopped sending it: it is not in the vault's log as " +
    "this device read it. If it shows up later, this device says so."

/** A change held a day, given up, where the read could tell nothing (key `found_given_up_cannot_tell`). */
const val FOUND_GIVEN_UP_CANNOT_TELL = "{1} vault {0} waited a day, so this device stopped sending it, and it cannot tell yet " +
    "whether it was made. If it shows up in the vault's log, this device says so."

/** A change whose outcome could not be told, given up when the server refused it sent again (key `found_given_up_refused`). */
const val FOUND_GIVEN_UP_REFUSED = "{1} vault {0} was refused by the server when this device sent it again ({2}), so it stopped " +
    "sending it; an earlier send may still have been made. If it shows up in the vault's log, this device says so."

/** A change sent again will never be made: another entry took its place (key `found_place_taken`). */
const val FOUND_PLACE_TAKEN = "{1} vault {0} will never be made: another change took its place in the vault's log."

/** A change sent again, known not stored, refused for good (key `found_refused`). */
const val FOUND_REFUSED = "{1} vault {0} was refused by the server when this device sent it again ({2}), so it was dropped: it was not made."

/**
 * An addition not sent again because its contact is gone, has another key or is no longer compared, where an earlier send
 * may have reached the server (key `found_contact_changed`).
 */
const val FOUND_CONTACT_CHANGED = "{1} vault {0} was not sent again: the contact it names is gone from this device, has another " +
    "key now, or is no longer compared. An earlier send may still have been made. If it shows up in the vault's log, this device says so."

/** As [FOUND_CONTACT_CHANGED], where it was known not stored (key `found_contact_changed_not_made`). */
const val FOUND_CONTACT_CHANGED_NOT_MADE = "{1} vault {0} was not sent again: the contact it names is gone from this device, has " +
    "another key now, or is no longer compared. It was not made."

/**
 * `vault keep` that could not withdraw it because its first request is still out, which ends (the tool's own sentence).
 * `{0}` the vault, `{1}` the engine's reason.
 */
const val DELETION_NOT_WITHDRAWN = "The deletion of vault {0} could not be withdrawn now ({1}), so nothing changed. Try again in a moment."

/**
 * `vault keep` where the server's own answer called the deletion stored (the tool's own sentence, not yet on the wording
 * page). It says only what is so: the server answered that it took the deletion; a deletion the server has taken cannot be
 * undone by keeping; this device has not read it back in the vault's log yet; nothing changed. Never that the vault is
 * deleted: a server that said "stored" and whose log later holds another entry leaves the vault frozen, not deleted.
 * `{0}` the vault.
 */
const val DELETION_STORED_NOT_WITHDRAWN = "The server answered that it took the deletion of vault {0}, and a deletion the " +
    "server has taken cannot be undone by keeping the vault. This device has not read the deletion back in the vault's log " +
    "yet, and nothing changed."

/** `vault keep` where this device cannot read its records of the vault (the tool's own sentence, not yet on the wording page). `{0}` the vault. */
const val DELETION_UNREADABLE_NOT_WITHDRAWN = "This device cannot read its records of vault {0}, so it could not withdraw the deletion, and nothing changed."

/** `vault keep` for any other reason the engine gives, none of which clears by trying again (the tool's own sentence, not yet on the wording page). `{0}` the vault, `{1}` the reason. */
const val DELETION_NEVER_WITHDRAWN = "The deletion of vault {0} cannot be withdrawn ({1}), so nothing changed."

/**
 * `vault keep` where the sync that runs first found the deletion in the vault's log (the tool's own sentence, not yet on
 * the wording page): the vault is deleted, so it was not kept; how to restore. `{0}` the vault.
 */
const val DELETION_MADE_NOT_KEPT = "Vault {0} is deleted: its log holds the deletion, so it could not be kept. It can be " +
    "restored while the server's grace for it lasts (andvari-cli vault restore {0})."

/** The message key of [SESSION_KEPT_NOT_REFRESHED]. */
const val KEY_SESSION_KEPT_NOT_REFRESHED = "session_kept_not_refreshed"

/**
 * The server refused to refresh a saved session in its own envelope without ending it (the tool's own sentence, not yet
 * on the wording page): the session is kept for the next try. `{0}` the server's address, `{1}` the server's code.
 */
const val SESSION_KEPT_NOT_REFRESHED = "{0} did not refresh this device's saved session ({1}) and did not end it; the session is kept for the next try"

/**
 * The wait, where the server's answer gave none this tool takes (the tool's own words, not yet on the wording page; key
 * `wait_unnamed`): the shared code reads a `Retry-After` of no number, of a date, or of more than a day alike as none, so
 * the words must be true of each, and never say that the server named no time where it named more than a day.
 */
const val WAIT_UNNAMED = "a while (the server named no wait of a day or less)"

/** The message key of [SESSION_KEPT_NO_ANSWER]. */
const val KEY_SESSION_KEPT_NO_ANSWER = "session_kept_no_answer"

/**
 * Reopening a saved session got no answer from the server (the tool's own sentence, not yet on the wording page): nothing
 * changed on this device, and the session is kept for the next try. `{0}` the server's address.
 */
const val SESSION_KEPT_NO_ANSWER = "{0} did not answer; nothing changed on this device, and its saved session is kept for the next try"

/** The message key of the forgetting's first step ([EARLIER_FORGET_PLAN]). */
const val KEY_EARLIER_FORGET_PLAN = "earlier_forget_plan"

/**
 * `forget-earlier-account` without `--yes` (the tool's own sentence, not yet on the wording page): exactly what would be
 * removed (the lines after it name each record), how many of the earlier account's changes were not sent, that it cannot be
 * undone, what it means if the account was NOT made again, what stays, and that nothing changed now. `{0}` the server's
 * address, `{1}` the address, `{2}` the earlier account's id, `{3}` the number of records.
 */
const val EARLIER_FORGET_PLAN = "With --yes, this device forgets the earlier account under {1} on {0} (account {2}): the {3} " +
    "records it keeps for it, listed above, among them the record that ties {1} to it. andvari-cli keeps no changes " +
    "waiting to be sent between runs, so none of that account's changes are lost. This can't be undone. If the account was NOT " +
    "deleted and made again, forgetting means this device trusts whatever account the server gives under {1} from now on. It " +
    "keeps what it knows of the server (its card and its pin) and the earlier account's identity key, and sends nothing to the " +
    "server. Nothing was changed now."

/**
 * The forgetting done (the tool's own sentence, not yet on the wording page): what was forgotten, what stays, that nothing
 * was sent, and that the next account under the address is taken as new. `{0}` the server's address, `{1}` the address.
 */
const val EARLIER_FORGOTTEN = "This device forgot the earlier account under {1} on {0}. It still knows the server (its card " +
    "and its pin) and the earlier account's identity key, so that account is never taken here under another key. Nothing was " +
    "sent to the server. The next sign-in, recovery, new account or device link under {1} is taken as on a device that never knew it."

/**
 * Added to [EARLIER_FORGET_PLAN] where this device keeps a request for the operator's help under the address (the tool's
 * own sentence, not yet on the wording page; key [KEY_EARLIER_FORGET_PLAN]). It must say: the request is among what goes;
 * why (it was made for the account under the address); nothing of it is sent; the person can ask again afterwards.
 * `{0}` the server's address, `{1}` the address.
 */
const val EARLIER_PLAN_REQUEST = "Among those records is the request for the operator's help that this device keeps for {1} " +
    "on {0}: it was made for the account under {1}, so it goes too, and nothing of it is sent. If you still need the " +
    "operator's help afterwards, ask again (andvari-cli recover assist --email {1})."

/** Said after [EARLIER_FORGOTTEN] where that request went with it (the tool's own sentence). `{0}` the server, `{1}` the address. */
const val EARLIER_REQUEST_FORGOTTEN = "The request for the operator's help that this device kept for {1} on {0} went with it."

/** The message key of a `forget-earlier-account` that has nothing to forget. */
const val KEY_EARLIER_NOT_OFFERED = "earlier_not_offered"

/**
 * `forget-earlier-account` where no refusal offered it (the tool's own sentence, not yet on the wording page): nothing was
 * forgotten, and when it is offered. `{0}` the server's address, `{1}` the address.
 */
const val EARLIER_NOT_OFFERED = "This device has no earlier account under {1} on {0} to forget, so nothing was forgotten. " +
    "andvari-cli offers it only after it stopped a sign-in, a recovery, a new account or a device link because this device ties {1} to " +
    "an earlier account than the one asked for, and only while that earlier account is not signed in here again."

/**
 * `forget-earlier-account` after the server showed the account this device knows under another key (the tool's own
 * sentence, not yet on the wording page): why nothing can be forgotten for it. `{0}` the server's address, `{1}` the address.
 */
const val EARLIER_KEY_NOT_OFFERED = "The server at {0} showed this device the account it knows under {1}, but under another " +
    "identity key. That is the fault this device's record of the key exists to catch, not an account made again (one made " +
    "again never comes back under its old account id), so nothing is forgotten for it: nothing was forgotten. Tell the " +
    "server's operator."

/**
 * Said once when the next account under an address whose earlier account was forgotten is taken (the tool's own sentence,
 * not yet on the wording page). `{0}` the server's address, `{1}` the address.
 */
const val NEW_ACCOUNT_REMEMBERED = "This device now remembers the new account under {1} on {0}."

/**
 * After a deletion the server confirmed, where this device keeps nothing of another account at that server (the tool's own
 * sentence, not yet on the wording page; decided on 2026-11-19). It must say: everything kept for the account is gone; the
 * server is forgotten too (its pin and records), and why; how to use it again. `{0}` the server's address.
 */
const val DELETED_SERVER_FORGOTTEN = "This device forgot the account: its session and everything it kept for it are deleted. It " +
    "kept nothing of another account on {0}, so it forgot that server too, with its pin. To use {0} again, sign in or make an " +
    "account there: its Trust Gate is shown first."

/**
 * The same where this device still keeps something of another account at that server (the tool's own sentence, not yet on
 * the wording page): only the deleted account's records went; the server is kept, and why. `{0}` the server's address,
 * `{1}` what is kept ([KEPT_OTHER_ACCOUNT], [KEPT_OTHER_KEY], [KEPT_OTHER_NAME], [KEPT_OTHER_UNREADABLE]).
 */
const val DELETED_SERVER_KEPT = "This device forgot the account: its session and everything it kept for it are deleted. It " +
    "still knows the server {0} (its card and its pin), because it keeps {1} there."

/** What is kept, in [DELETED_SERVER_KEPT]: `{0}` the other account's address. */
const val KEPT_OTHER_ACCOUNT = "the account {0}"

/** The same: `{0}` the account's id. */
const val KEPT_OTHER_KEY = "the identity key of an account it knew there before (account {0}), so that that account is never taken here under another key"

/** The same: `{0}` the account's id. */
const val KEPT_OTHER_NAME = "the name of another account it knew there (account {0})"

/** The same, where the home's records could not be listed. */
const val KEPT_OTHER_UNREADABLE = "records it could not list, which may be another account's"

/** The same (the tool's own words, not yet on the wording page): `{0}` the address a kept request for the operator's help is for. */
const val KEPT_OTHER_REQUEST = "a request for the operator's help for {0}"

/** The same, where the kept request cannot be read (the tool's own words, not yet on the wording page). */
const val KEPT_OTHER_REQUEST_UNREADABLE = "a request for the operator's help that it cannot read, which may be for another account"

/** The message key of [LINK_ADDED_NOT_KEPT]. */
const val KEY_LINK_ADDED_NOT_KEPT = "link_added_not_kept"

/**
 * A device link whose pickup the server took (it added this device to the account) while another run kept another account
 * on this home (the tool's own sentence, not yet on the wording page). It must say: the server added this device to the
 * account and lists it; why this device kept nothing; that its session there was ended, so it is not signed in; and how to
 * remove the device (from another device of the account). Never "nothing was linked". `{0}` the server's address, `{1}`
 * the account's address, `{2}` the device's id at the server, `{3}` the account this home keeps.
 */
const val LINK_ADDED_NOT_KEPT = "The server at {0} added this device to {1} (device {2}), but meanwhile this device started " +
    "keeping {3} on that server, and andvari-cli keeps one account per server on a device. So it kept nothing of {1} and ended " +
    "this device's session for it at the server: this device is not signed in to {1}. The server still lists the device among " +
    "{1}'s devices: remove it from your other device with andvari-cli account revoke-device {2}."

/** The message key of [KEPT_COPY_DAMAGED]. */
const val KEY_KEPT_COPY_DAMAGED = "kept_copy_damaged"

/**
 * The shared flows' `kept_copy_damaged` (the tool's own sentence): this device's copy of the account is damaged, so the
 * server's answer was not compared with it and nothing of it was used. This tool keeps no unsent changes between runs,
 * so removing its copy loses none. `{0}` the server's address, `{1}` what was stopped.
 */
const val KEPT_COPY_DAMAGED = "This device's copy of the account on {0} is damaged, so andvari-cli stopped {1} and used " +
    "nothing from the server's answer; nothing changed at the server. andvari-cli keeps no unsent changes between runs, so " +
    "removing this device's copy loses none: sign the account out of this device (andvari-cli sign-out), then sign in or " +
    "recover it again."

/** The message key of [NOT_THE_KEPT_ACCOUNT]. */
const val KEY_NOT_THE_KEPT_ACCOUNT = "not_the_kept_account"

/**
 * The operator's answer to a request for help names another account than the one this home keeps for the address (the
 * tool's own sentence). Never "sign out": the account kept here is the one the address is known under. `{0}` the server's
 * address, `{1}` the address.
 */
const val NOT_THE_KEPT_ACCOUNT = "The operator's answer names another account than the one this device keeps for {1} on {0}, so " +
    "andvari-cli used nothing from it: no password was asked, nothing changed at the server, and this device keeps the request. " +
    "Tell the server's operator. To stop waiting for another answer, run andvari-cli recover assist --cancel."

/** [SIGN_IN_TOO_MANY_TRIES], under the same exit code and key as every back-off: not a wrong password. */
fun tooManySignIns(): CliError = CliError(SIGN_IN_TOO_MANY_TRIES, EXIT_TOO_MANY_PASSWORDS, KEY_TOO_MANY_PASSWORDS)

/** The message key of that fault, printed with it so a script can tell it from a refusal. */
const val KEY_SERVER_ANSWER_TOO_LARGE = "server_answer_too_large"

/**
 * The server at [origin] answered [route] with more than the engine accepts for it ([BODY_OVER_LIMIT], the engine's
 * per-route caps). That is a fault of the server's answer: not a wrong password, not a missing account or item, and not
 * a refusal the person can fix. Nothing of the answer was decoded or used.
 */
fun serverAnswerError(origin: String, route: WireRoute): CliError = CliError(
    "the server at $origin sent an answer to ${route.method} ${route.path} that is larger than this device accepts for it, " +
        "so this device read none of it and used nothing from it. That is a fault of the server's answer, not of your password, " +
        "your account or your data. Try again later; if it keeps happening, tell the server's operator",
    EXIT_SERVER_ANSWER, KEY_SERVER_ANSWER_TOO_LARGE,
)

/** The message key of an answer refused for a hashing cost outside the fence ([servedCostError]). */
const val KEY_SERVED_COST_REFUSED = "server_kdf_refused"

/**
 * The server at [origin] served [p], a hashing cost for this account outside the whole fence (spec 01 §7: not below the
 * floor, not above the ceiling, a whole number of KiB). The answer was not used and nothing was derived at that cost. A
 * fault of the server's answer, never a wrong password.
 */
fun servedCostError(origin: String, p: io.silencelen.andvari.core.crypto.KdfParams): CliError = CliError(
    fill(SERVED_COST_REFUSED, origin, p.ops, p.memBytes, io.silencelen.andvari.core.client.KdfUpgrade.MIN_OPS, io.silencelen.andvari.core.client.KdfUpgrade.MAX_OPS),
    EXIT_SERVER_ANSWER, KEY_SERVED_COST_REFUSED,
)

/**
 * [servedCostError], in the approved words: `{0}` the server's address, `{1}` the passes it sent, `{2}` the bytes of memory
 * it sent, `{3}` and `{4}` the fence's fewest and most passes, filled from its constants (3 and 10 today).
 */
const val SERVED_COST_REFUSED = "The server at {0} sent settings for your master password that andvari-cli can't use: {1} passes " +
    "over {2} bytes of memory (andvari takes {3} to {4} passes over 64 MiB to 1 GiB, in whole KiB). This device didn't use that " +
    "answer and worked out nothing from your password with those settings. That isn't a wrong password: tell the operator."

/** What came back for one request, as much as a sentence needs and nothing of its content ([Host.answersSince]). */
sealed class Answered {
    /** A success status with a body the engine read. */
    data object Usable : Answered()

    /** A refusal in the server's envelope: [status], [code], and the `Retry-After` of a 429. */
    data class Refusal(val status: Int, val code: String, val retryAfterSeconds: Long?) : Answered()

    /**
     * No usable answer, of [kind]: [NoAnswerKind.TRANSPORT] and [NoAnswerKind.TIMEOUT] are a server that was not reached
     * (or did not answer in time); [NoAnswerKind.SERVER_ERROR] and [NoAnswerKind.UNDECODABLE] are an answer that came
     * and could not be used.
     */
    data class NotUsable(val kind: NoAnswerKind) : Answered() {
        val reached: Boolean get() = kind == NoAnswerKind.SERVER_ERROR || kind == NoAnswerKind.UNDECODABLE
    }
}

/** The hashing cost an answer names for the account's password ([WireClient] answers a client derives at), or null. */
private fun servedCost(v: Any?): io.silencelen.andvari.core.crypto.KdfParams? = when (v) {
    is io.silencelen.andvari.core.model.wire.PreloginResponse -> v.kdfParams
    is AccountKeys -> v.kdfParams
    is io.silencelen.andvari.core.model.wire.SessionResponse -> v.accountKeys.kdfParams
    is io.silencelen.andvari.core.model.wire.DeviceLinkPickupResponse -> v.session.accountKeys.kdfParams
    else -> null
}

/** Thrown inside a decode so that the engine sees no usable answer ([WireResult.NoAnswer]) for a cost outside the fence. */
private class ServedCostRefused : RuntimeException("a served hashing cost outside the fence")

/**
 * [inner], with every answer the engine refused as too large ([BODY_OVER_LIMIT]) shown to [seen]; and every answer that
 * names a hashing cost outside the whole fence ([servedCost], [io.silencelen.andvari.core.client.KdfUpgrade.withinFence])
 * shown to [costRefused] and given to the engine as no usable answer, so that nothing is derived at it. Nothing else is
 * changed.
 */
private class TooLargeWatch(
    private val inner: WireClient, private val seen: (WireRoute) -> Unit, private val costRefused: (io.silencelen.andvari.core.crypto.KdfParams) -> Unit,
    private val policyCost: (io.silencelen.andvari.core.crypto.KdfParams) -> Unit,
    private val answered: (WireRoute, Answered) -> Unit,
    private val sessionCost: (String, io.silencelen.andvari.core.crypto.KdfParams) -> Unit,
) : WireClient {
    override val origin: String get() = inner.origin
    override val stopped: Boolean get() = inner.stopped

    private fun <T> watch(route: WireRoute, r: WireResult<T>): WireResult<T> {
        if (r is WireResult.Refused && r.code == BODY_OVER_LIMIT) seen(route)
        answered(route, when (r) {
            is WireResult.Ok -> Answered.Usable
            is WireResult.Refused -> Answered.Refusal(r.status, r.code, r.retryAfterSeconds)
            is WireResult.NoAnswer -> Answered.NotUsable(r.kind)
        })
        return r
    }

    private fun <T> fenced(decode: (String) -> T): (String) -> T = { text ->
        decode(text).also { v ->
            servedCost(v)?.let { p -> if (!io.silencelen.andvari.core.client.KdfUpgrade.withinFence(p)) { costRefused(p); throw ServedCostRefused() } }
            when (v) {
                is io.silencelen.andvari.core.model.wire.SessionResponse -> sessionCost(v.userId, v.accountKeys.kdfParams)
                is io.silencelen.andvari.core.model.wire.DeviceLinkPickupResponse -> sessionCost(v.session.userId, v.session.accountKeys.kdfParams)
                is io.silencelen.andvari.core.model.wire.ClientPolicy -> policyCost(v.kdfParams)
            }
        }
    }

    override suspend fun <T> call(
        route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T,
    ): WireResult<T> = watch(route, inner.call(route, pathParams, query, bodyJson, authenticated, fenced(decode)))

    override suspend fun <T> callBytes(
        route: WireRoute, pathParams: Map<String, String>, query: String?, body: ByteArray, authenticated: Boolean, decode: (String) -> T,
    ): WireResult<T> = watch(route, inner.callBytes(route, pathParams, query, body, authenticated, fenced(decode)))

    override suspend fun fetchBytes(route: WireRoute, pathParams: Map<String, String>, query: String?, authenticated: Boolean): WireResult<ByteArray> =
        watch(route, inner.fetchBytes(route, pathParams, query, authenticated))

    override suspend fun fetchBytes(
        route: WireRoute, pathParams: Map<String, String>, query: String?, authenticated: Boolean, maxBytes: Long?,
    ): WireResult<ByteArray> = watch(route, inner.fetchBytes(route, pathParams, query, authenticated, maxBytes))
}
