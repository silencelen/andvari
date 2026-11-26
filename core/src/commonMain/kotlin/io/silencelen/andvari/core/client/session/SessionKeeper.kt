package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.account.Reauth
import io.silencelen.andvari.core.client.account.ReauthKey
import io.silencelen.andvari.core.client.account.ReauthSession
import io.silencelen.andvari.core.client.net.OriginGuard
import io.silencelen.andvari.core.client.net.TokenSource
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.net.endSession
import io.silencelen.andvari.core.client.onboard.AccountOpen
import io.silencelen.andvari.core.client.onboard.AccountOpenResult
import io.silencelen.andvari.core.client.onboard.EstablishedSession
import io.silencelen.andvari.core.client.onboard.KeptAccountCheck
import io.silencelen.andvari.core.client.onboard.PasswordKeys
import io.silencelen.andvari.core.client.onboard.SessionHow
import io.silencelen.andvari.core.client.onboard.SessionSink
import io.silencelen.andvari.core.client.pin.InstanceTrust
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.model.wire.AccountKeys
import io.silencelen.andvari.core.model.wire.PreloginRequest
import io.silencelen.andvari.core.model.wire.PreloginResponse
import io.silencelen.andvari.core.model.wire.RefreshRequest
import io.silencelen.andvari.core.model.wire.TokenPair
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.TrustGrammar
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.atomicfu.locks.SynchronizedObject
import kotlinx.atomicfu.locks.synchronized
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable

/**
 * The platform's HTTP stack for the overhaul's routes: a [WireClient] that dials [origin] and, on an authenticated
 * route, carries the bearer [tokens] answers. [tokens] is null for a client that must carry none.
 *
 * In the apps it is `WireTransport(dialer::open)` over the engine's one
 * [io.silencelen.andvari.core.client.net.Dialer], built over the device's pin store
 * ([io.silencelen.andvari.core.app.engine.dialingTransport] does exactly that). Whatever it is, the [SessionKeeper]
 * puts every client it opens, and every token source it hands one, behind the engine's
 * [io.silencelen.andvari.core.client.net.OriginGuard] over the same pin store (design §4.4).
 */
fun interface WireTransport {
    fun open(origin: String, tokens: TokenSource?): WireClient

    /**
     * The event bell's socket for [origin] (spec 03 §6) from the same dialer and under its rules, or null: no bell. The
     * apps' transport ([io.silencelen.andvari.core.app.engine.dialingTransport]) answers
     * [io.silencelen.andvari.core.client.net.Dialer.bellSocket]; the app asks again for every opening of the vault, so a
     * followed move gets a socket for the new address.
     */
    fun bellSocket(origin: String): io.silencelen.andvari.core.client.items.BellSocket? = null
}

/** Where the kept session is. */
enum class KeptPhase {
    /** No session on this device. */
    NONE,

    /** A session is stored (its tokens, its account's served keys); the account's keys are not open. */
    LOCKED,

    /** The account's keys are open in memory. */
    UNLOCKED,
}

/** Why a kept session ended. */
enum class SessionEndReason {
    /** The person signed out on this device. */
    SIGNED_OUT,

    /** The server refused the refresh token (`invalid_refresh`, `refresh_reuse`, `refresh_expired`): the session is over there. */
    REFRESH_REFUSED,

    /** The account was deleted, or the server or account was forgotten on this device. */
    FORGOTTEN,

    /**
     * This device could not confirm its session with its server in time: a refresh was cut off while out, and no try was
     * left ([SessionKeeper.REFRESH_SECOND_TRY_MS]). Nothing was sent again, so no other session was ended; the account
     * and its copy stay, as at [REFRESH_REFUSED] ([KeptSession.endedByServer], [KeptSession.endedUnconfirmed]), and the
     * person signs in again. That sign-in names the session it replaces, so the server ends it as replaced.
     */
    SESSION_NOT_CONFIRMED,
}

/** What [SessionKeeper.forgetEarlierAccount] did. */
sealed interface ForgetEarlier {
    /**
     * The record that tied the address at the server to the earlier account [forgottenUserId] is gone, with that
     * account's identity record. [copyRemoved]: this device's kept session record of that account went too, as at the
     * person's own sign-out ([SessionKeeper.endedByOwnAct] names it until the app has deleted the account's data); nothing
     * was sent to the server. [unreadableRecordRemoved]: a session record this device kept and could not read (never
     * loaded) went too, because it named that account or did not read at all; its tokens and wrapped keys could never be
     * used, and nothing in it was readable here.
     */
    data class Forgotten(val forgottenUserId: String, val copyRemoved: Boolean, val unreadableRecordRemoved: Boolean = false) : ForgetEarlier

    /** No record ties the address at that server to any account on this device: nothing was removed. */
    data object NothingToForget : ForgetEarlier

    /**
     * A flow for that address at that server is under way on this device, from its first step to its end (a sign-in
     * through its two-step code, a registration from its ticket, a recovery from its start to its commit, a device link
     * from its start to its pickup, a request for the operator's help while it is kept, a take): nothing was removed.
     */
    data object FlowUnderWay : ForgetEarlier

    /**
     * The account the address is tied to is the one this device keeps: open here, kept under another address or at the
     * server's new address after a followed move, or held as its server's operator. Nothing was removed.
     */
    data object OpenForThatAccount : ForgetEarlier

    /**
     * The address's record names another account than the one the person's confirmation named (another process sharing
     * this device's records took one under the address in between): nothing was removed.
     */
    data object NoLongerHolds : ForgetEarlier
}

/**
 * What this device knows of an address at a server ([SessionKeeper.addressBinding]): the account it first took under the
 * address there (spec 01 §5, "bound to the typed email"), by its user id and its identity key as first taken, and where
 * that account stands on this device now. Facts only: asking changes nothing.
 */
data class AddressBinding(
    val userId: String,
    /** The account's identity public key as this device first took it, base64. */
    val identityKey: String,
    val here: BoundAccountHere,
)

/** Where the account an address is bound to stands on this device. */
enum class BoundAccountHere {
    /** Not kept here: no session record of it (a sign-out, a forgotten copy, never kept). */
    NOT_KEPT,

    /** Kept at this server under this address, its keys not open (locked, or signed out by its server or in time). */
    KEPT_LOCKED,

    /** Kept at this server under this address, and open here. */
    KEPT_OPEN,

    /** Kept here under another address or at another server (after a followed move, say), open or not. */
    KEPT_ELSEWHERE,

    /** Kept as its server's operator account, held ([KeptSession.heldAsOperator]). */
    HELD_AS_OPERATOR,
}

/** What [SessionKeeper.establish] did with a session an engine flow opened. */
sealed class Establishing {
    /** Kept: from now on it is the session. */
    data object Taken : Establishing()

    /** Not kept ([reason]): its keys were wiped, and exactly that session was ended at its own origin (by its refresh token). */
    data class Refused(val reason: String) : Establishing()

    companion object {
        /** Another account's session (or one at another origin) is kept: it is ended by its own act first. */
        const val ANOTHER_SESSION_KEPT = "another_session_kept"

        /** Spec 01 §5: the typed address is bound on this device to another account. */
        const val IDENTITY_MISMATCH = "self_identity_mismatch"

        /**
         * Spec 01 §7: the session is of the kept account, and its key does not open what the kept copy holds sealed under
         * the account's key. Nothing kept is replaced. The flows' own code for it is
         * [io.silencelen.andvari.core.client.onboard.WireOnboarding.SERVER_KEYS_NOT_KNOWN_HERE].
         */
        const val SERVER_KEYS_NOT_KNOWN_HERE = "server_keys_not_known_here"

        /**
         * The kept account is held on this device as its server's operator account ([KeptSession.heldAsOperator]): no new
         * session is kept beside it or over it, not even one of that very account. The way out is to remove it from this
         * device ([SessionKeeper.removeHeldOperator]), never to sign it out.
         */
        const val OPERATOR_ACCOUNT_HELD = "operator_account_held"

        /**
         * Spec 01 §7: the session is of the kept account, nothing compared its key with a wrap this device keeps (a
         * recovery, a device link onto a copy sealed under another password, a flow that compared nothing), and the copy's
         * sealed identity seed does not open because the copy itself is damaged
         * ([io.silencelen.andvari.core.client.onboard.KeptAccountCheck.copyDamaged]). Nothing kept is replaced. The way
         * out is to remove this device's copy (saying first how many changes were not sent, or that it cannot tell), then
         * sign in or recover. A sign-in whose typed password opened a kept wrap to the session's key is taken over such a
         * copy, and repairs it.
         */
        const val KEPT_COPY_DAMAGED = "kept_copy_damaged"

        /**
         * Design 2026-11-15 §2.2, strict decoding: the session's account-key texts (its sealed identity seed, its wraps)
         * are not in their canonical form, which is the server's fault; nothing of the session is kept. The flows' own code
         * for a server's answer that is not the session it must be
         * ([io.silencelen.andvari.core.client.onboard.WireOnboarding.BAD_RESPONSE]), which each flow checks first. The
         * keeper itself no longer gives it: its floor under them says [SERVED_KEY_FORM].
         */
        const val BAD_RESPONSE = "bad_response"

        /**
         * Design 2026-11-15 §2.2, strict decoding, the keeper's own reason: the account's keys were served in a form this
         * device does not take (its sealed identity seed, its wraps or its salt not in their canonical text), which is
         * the server's fault; nothing of them is used or kept. Given where the keeper itself reads the keys (a session it
         * is handed, an unlock that asks the server for them); never the identity fault, which says a key differs.
         */
        const val SERVED_KEY_FORM = "served_key_form"
    }
}

/** The kept session as the app layer shows it: ids only, never a token or a key. */
class KeptSession internal constructor(
    val origin: String,
    val emailNorm: String,
    val userId: String,
    val deviceId: String,
    val role: String,
    val how: SessionHow,
    val totpEnrolled: Boolean,
    val mustEnrollTotp: Boolean,
    val recoveryConfirmed: Boolean,
    /**
     * The server ended this session (a refused refresh, the bell's `revoked`; design §4.4): the account stands on this
     * device as signed out by the server. No token is kept; the account's keys open from the copy with the password,
     * and a sign-in to the same account at the same origin takes it back. Also true where this device could not confirm
     * the session in time ([endedUnconfirmed]), which this state handles alike.
     */
    val endedByServer: Boolean = false,
    /**
     * The master password was changed at the server from this device, and this device's copy could not be wrapped
     * again under the new one ([SessionKeeper.passwordChanged] answered false): here the PREVIOUS password still opens
     * it, until a later change or sign-in wraps it again.
     */
    val previousPasswordOpensCopy: Boolean = false,
    /**
     * The owner's decision of 2026-11-16 ("stop using it at once, keep the copy locked, let the person remove it"): a
     * verified card names this account as its server's operator, on a device that may not hold the operator account
     * (a phone). No token is kept, nothing is sent with it, and nothing opens it here (not the password, not quick
     * unlock, not a new session of it); its copy and its wrapped key stay until the person removes it
     * ([SessionKeeper.removeHeldOperator]).
     */
    val heldAsOperator: Boolean = false,
    /**
     * Spec 01 §7, the pending-record rule: the last opening with the full master password that read the account's keys
     * found there a wrap that is neither this device's own nor its pending one, and that the password it verified does
     * not open to the account key this device holds (or whose cost is outside the fence, so it was never tried). The
     * account's keys on the server are not the ones this device knows. This is never a wrong password: the password
     * opened this device's copy. A later opening that finds the server's wrap known, or adopts it, clears it.
     */
    val serverKeysNotKnownHere: Boolean = false,
    /**
     * With [endedByServer]: the session did not end by the server's word but because this device could not confirm it in
     * time ([SessionEndReason.SESSION_NOT_CONFIRMED]); kept through a restart, so the layer above says that end's own
     * sentence. Everything else is as for [endedByServer].
     */
    val endedUnconfirmed: Boolean = false,
    /**
     * Under its server's kept policy that forbids key material at rest (spec 02 §8, as on the released line): this device
     * keeps none of the account's wrapped keys, only its session's tokens and the account's public identity. An unlock
     * asks the server for the keys ([SessionKeeper.unlockAsking]); without the server there is no unlock.
     */
    val keysAtServer: Boolean = false,
)

/** What an unlock came to. */
sealed class KeptUnlock {
    data object Unlocked : KeptUnlock()

    /** Nothing is stored to unlock. */
    data object NoSession : KeptUnlock()

    /** The password does not open the stored account keys. Nothing was sent. */
    data object WrongPassword : KeptUnlock()

    /**
     * The origin's pin record is damaged or gone (design §4.4): the account is not opened against it. A forked pin
     * does not answer this: the account opens from this device's own copy, and nothing is sent while the fork stands.
     */
    data object Blocked : KeptUnlock()

    /** The stored KDF parameters fail the fence (spec 05 T1): nothing derived. */
    data object KdfRefused : KeptUnlock()

    /** The stored keys failed an identity check of design §5.2 ([reason] as [AccountOpenResult.IdentityFault]). */
    data class IdentityFault(val reason: String) : KeptUnlock()

    /** The kept account is held as its server's operator on this device ([KeptSession.heldAsOperator]): nothing was derived or opened. */
    data object HeldAsOperator : KeptUnlock()

    /**
     * Not opened: another unlock is running, or a lock or the session's end came while this
     * one ran. Whatever it opened is wiped; the vault stays locked.
     */
    data object Stale : KeptUnlock()

    /**
     * The account's keys are kept at the server only ([KeptSession.keysAtServer]) and it did not hand them over: no
     * answer, a refusal, or a stop. Nothing was derived from the password, nothing opened, and nothing was removed.
     * [signInNeeded]: the session holds no tokens (its server ended it), so nothing can be asked; a sign-in takes it back.
     */
    data class KeysAtServer(val signInNeeded: Boolean) : KeptUnlock()
}

/**
 * The owner of an established session (design §7.8, §18.1 IF-3), beside the old
 * [io.silencelen.andvari.core.app.SessionController], which it does not touch: that one keeps the pre-overhaul
 * session on its own stores and routes.
 *
 * - **[SessionSink].** [established] takes ownership of the session's tokens and the opened account's keys. From then
 *   on an authenticated call on [clientFor] that origin carries the session's bearer; a `401` refreshes once
 *   (`POST /auth/refresh`, single-use rotation), and a refused refresh ends the session.
 * - **Persistence.** The tokens, the ids and the account's served [AccountKeys] (ciphertext and public values) are
 *   kept in [secure], the session-grade store (the Keychain or the Keystore-backed store), so a restart finds the
 *   session [KeptPhase.LOCKED]. No key, UVK or password is ever persisted.
 * - **Lock and unlock.** [lock] wipes the account's keys and keeps the tokens; [unlock] derives from the stored KDF
 *   salt and parameters, opens the UVK and runs every identity check of §5.2 again ([AccountOpen]), against the
 *   origin's pin in force and this device's own record of the identity key. It sends nothing.
 * - **Sign-out.** [signOut] sends `POST /auth/logout` with the session's bearer and forgets the session, whatever the
 *   server answered. [discard] does the same for a session this keeper never owned (a device link's pickup that the
 *   pin step refused, §8.2 step 8).
 * - **Re-authentication.** [reauth] is the engine's [Reauth] over the session's origin and account: the password
 *   gate first, then the proof on this device (spec 01 §7): the KDF under the session's own kept salt and cost opens
 *   this device's wrap of the account's key, and `currentAuthKey` comes from that same pass. No prelogin is sent, and
 *   a wrong password sends no request at all.
 *
 * Identity records ([knownIdentity]): the first identity key this device opened for a user id, kept in [state] for
 * good, so a later open of the same account that serves another key is the identity fault (§2.4).
 *
 * **The stop (design §4.4, "enforced where the client dials").** Every request this keeper sends or lets a flow
 * send goes through [guard], the engine's [OriginGuard] over the pin store in [state] (the store the device's
 * `CardTrust` reads): a forked, damaged or unreadable pin refuses it with
 * [io.silencelen.andvari.core.client.net.ORIGIN_STOPPED] before anything leaves, the token refresh, the logout and
 * a re-authentication's prelogin included, and [WireClient.stopped] lets a flow refuse before it signs anything. A
 * host asks [mayDial] before it opens a WebSocket.
 */
class SessionKeeper(
    private val transport: WireTransport,
    private val secure: DeviceState,
    private val state: DeviceState,
    private val trust: InstanceTrust,
    private val crypto: CryptoProvider,
    /** Wall time in unix ms: the window ([REFRESH_SECOND_TRY_MS]) within which a refresh cut off while out is tried once more. */
    private val clock: () -> Long = { kotlinx.datetime.Clock.System.now().toEpochMilliseconds() },
) : SessionSink {
    @Serializable
    private data class Stored(
        val origin: String,
        val emailNorm: String,
        val userId: String,
        val deviceId: String,
        val role: String,
        val how: String,
        val totpEnrolled: Boolean,
        val mustEnrollTotp: Boolean,
        val recoveryConfirmed: Boolean,
        val accessToken: String,
        val refreshToken: String,
        val accountKeys: AccountKeys,
        /** The server ended this session (design §4.4): no tokens are kept, the account and its copy stay. */
        val endedByServer: Boolean = false,
        /** [KeptSession.previousPasswordOpensCopy]. */
        val previousPasswordOpens: Boolean = false,
        /**
         * A password change sent from this device whose answer never came: the new wrap,
         * kept before the request went. Until the server's word settles it, either password opens this device.
         */
        val pendingWrap: PendingWrap? = null,
        /** [KeptSession.heldAsOperator]: kept through a restart; an older record reads false. */
        val heldAsOperator: Boolean = false,
        /** [KeptSession.serverKeysNotKnownHere]; an older record reads false. */
        val serverKeysNotKnown: Boolean = false,
        /**
         * When a refresh of [refreshToken] was first sent, in wall ms, while no HTTP answer to it has come: written BEFORE
         * the request goes, so whatever cuts it off (no connection, a timeout, a cancelled caller, the end of the app)
         * leaves it; any HTTP answer clears it. Null while no refresh of it is out. Kept through a restart, so a restart
         * never earns a try. (Its stored name is the earlier one, which meant the same for the two cut-offs it covered.)
         */
        @kotlinx.serialization.SerialName("refreshLostAt")
        val refreshOutAt: Long? = null,
        /** The one second try of [refreshToken] was sent (whatever came of it): it is never sent again. */
        val refreshTriedAgain: Boolean = false,
        /**
         * [KeptSession.endedUnconfirmed]: no try was left for a refresh cut off while out. Set with [endedByServer]; an
         * older record reads false.
         */
        val endedUnconfirmed: Boolean = false,
        /**
         * The refresh token of the session that ended so ([endedUnconfirmed]), kept for ONE use: the next sign-in of the
         * same account at the same origin on the same device row names it as the session it replaces
         * ([signInReplaces]), so the server ends that chain as replaced and records no reuse. It is never sent as a
         * refresh or to end a session (the server may hold it as replaced, and would read either as a stolen token's
         * reuse); it goes with this record (a take, a sign-out, a removal of the account or the server).
         */
        val unconfirmedRefresh: String? = null,
        /** [KeptSession.keysAtServer]: this record holds no wrapped key of the account ([atRest]); an older record reads false. */
        val keysAtServer: Boolean = false,
        /**
         * The keys held here were served for a record that kept none, at an unlock that asked the server ([unlockAsking])
         * or a take over such a record ([establish]): they are kept at rest again only under a READABLE kept policy that
         * allows it ([atRest]). Never written.
         */
        @kotlinx.serialization.Transient
        val keysServed: Boolean = false,
    )

    /** The wrap a password change sent: its salt (base64), its KDF cost and the wrapped key. Public values only. */
    @Serializable
    private data class PendingWrap(val kdfSalt: String, val kdfParams: io.silencelen.andvari.core.crypto.KdfParams, val wrappedUvk: String)

    /** The engine's guard over this device's pin store: the one check before anything this keeper dials. */
    val guard: OriginGuard = OriginGuard(PinStore(state))

    // The record of an earlier account's key that a forgetting keeps is the server's: it moves with a followed move and
    // goes when the server is forgotten ([EARLIER_IDENTITY_PREFIX]).
    init { PinStore.carryWithMoves(EARLIER_IDENTITY_PREFIX) }

    private var stored: Stored? = load()
    private var open: EstablishedSession? = null
    private val refreshLock = Mutex()
    private val clients = HashMap<String, WireClient>()

    private val _phase = MutableStateFlow(if (stored == null) KeptPhase.NONE else KeptPhase.LOCKED)

    /** The phase, as a flow the app layer follows. */
    val phase: StateFlow<KeptPhase> get() = _phase

    /** Why the last session ended; null while one is kept or none has ended in this process. */
    var lastEnd: SessionEndReason? = null
        private set

    /** Called after a session ended without the app asking ([SessionEndReason.REFRESH_REFUSED]). */
    var onEnded: (SessionEndReason) -> Unit = {}

    /**
     * Called whenever the account's keys open on this device: a session established here (sign-up, sign-in, a link, a
     * recovery) and every unlock, a quick unlock included, which is also how a cold start reopens the account. The
     * host gives the device's trust the account's own key with it (`CardTrust.signedIn`, design §4.1 VR-11).
     */
    var onAccountOpened: (io.silencelen.andvari.core.client.onboard.OpenedAccount) -> Unit = {}

    /** Called whenever the kept session ends on this device, for any [SessionEndReason] (`CardTrust.signedOut`). A lock is not an end. */
    var onSessionEnded: () -> Unit = {}

    /** The kept session's ids, or null. */
    val session: KeptSession?
        get() = stored?.let {
            KeptSession(it.origin, it.emailNorm, it.userId, it.deviceId, it.role, how(it.how), it.totpEnrolled, it.mustEnrollTotp, it.recoveryConfirmed, it.endedByServer,
                it.previousPasswordOpens, it.heldAsOperator, it.serverKeysNotKnown, it.endedByServer && it.endedUnconfirmed, it.keysAtServer)
        }

    /** The open session (the account's keys in memory), or null when locked or signed out. Core only. */
    internal val established: EstablishedSession? get() = open

    // ---- SessionSink ----

    override suspend fun established(session: EstablishedSession) {
        establish(session)
    }

    /**
     * Spec 01 §7, a sign-in on a device that already keeps the account: the kept account at [origin] (signed out by its
     * server, locked, or open; with a password change's wrap whose answer never came), whose wraps and sealed records a
     * password sign-in there compares with the key it opened before [establish] may replace them. None for an account
     * held as its server's operator, which no new session opens ([establish] refuses it).
     */
    override fun keptForSignIn(origin: String): io.silencelen.andvari.core.client.onboard.KeptAccountKeys? =
        // A record that keeps no wrapped key ([Stored.keysAtServer]) has nothing to compare: the sign-in stands where a new
        // device stands, and this device's record of the account's identity is the floor ([establish]).
        stored?.takeIf { it.origin == origin && !it.heldAsOperator && !it.keysAtServer }?.let(::keysOf)

    private fun keysOf(s: Stored) = io.silencelen.andvari.core.client.onboard.KeptAccountKeys(
        s.userId, s.accountKeys, s.pendingWrap?.let { io.silencelen.andvari.core.client.onboard.KeptWrap(it.kdfSalt, it.kdfParams, it.wrappedUvk) },
    )

    /**
     * A session a flow refused after its server answered: exactly that session ends at its own origin, through the guard
     * ([endOne]); a logout would end every session of this device there, a kept one's too.
     */
    override suspend fun notTaken(origin: String, accessToken: String, refreshToken: String) = endOne(origin, refreshToken)

    /** [establish], answering its refusal's reason, or null when the session was taken. */
    override suspend fun take(session: EstablishedSession): String? = (establish(session) as? Establishing.Refused)?.reason

    /**
     * What [establish] would answer before it is handed anything: [Establishing.ANOTHER_SESSION_KEPT] while another
     * account (or one at another origin, or one held as its server's operator) is kept here, and
     * [Establishing.IDENTITY_MISMATCH] when the address is bound here to another account. Asked before a recovery's
     * commit, a registration and a device link's pickup are sent, so that a no costs the person nothing at the server
     * (before, the server took the new password and made a new kit, and only then was the session refused here). The
     * floor for the same account's key ([Establishing.SERVER_KEYS_NOT_KNOWN_HERE]) is the flows' own check, made with
     * the key they hold.
     */
    override fun wouldRefuse(origin: String, emailNorm: String?, userId: String?, identityPub: ByteArray?): String? {
        val kept = stored
        if (kept != null && kept.heldAsOperator) return Establishing.OPERATOR_ACCOUNT_HELD
        if (kept != null && (kept.origin != origin || (userId != null && kept.userId != userId))) return Establishing.ANOTHER_SESSION_KEPT
        // The key this device kept of an account it forgot under an address there: that account under another key is the
        // identity fault, under whatever address it comes.
        if (userId != null && identityPub != null && earlierKeyDiffers(origin, userId, identityPub)) return Establishing.IDENTITY_MISMATCH
        if (emailNorm != null && userId != null) {
            val (boundUser, boundKey) = emailBinding(origin, emailNorm) ?: return null
            if (boundUser != userId || (identityPub != null && boundKey != Bytes.toB64(identityPub))) return Establishing.IDENTITY_MISMATCH
        }
        return null
    }

    /**
     * Which of the two causes an identity refusal ([Establishing.IDENTITY_MISMATCH]) of the account [userId], served with
     * [identityPub], for the address [emailNorm] at [origin] has: true only where this device ties the address there to
     * ANOTHER account (by its user id) and nothing it knows of [userId]'s identity key differs from [identityPub] (its own
     * record, and the record a forgetting kept at [origin]): the case of an account deleted and made again under the
     * address, the one where forgetting the earlier account is offered. False where the address is tied to this very
     * account (under another key: the substitution the record exists to stop), where a record of this account's key
     * differs, where no record ties the address, and where it cannot be told ([identityPub] null while this device holds
     * a record of [userId]'s key). Facts only: it changes and sends nothing.
     */
    override fun refusalIsAnotherAccount(origin: String, emailNorm: String, userId: String, identityPub: ByteArray?): Boolean {
        val (boundUser, _) = emailBinding(origin, emailNorm) ?: return false
        if (boundUser == userId) return false
        val known = listOfNotNull(knownIdentity(userId), earlierKey(origin, userId))
        if (identityPub == null) return known.isEmpty()
        return known.all { Bytes.ctEquals(it, identityPub) }
    }

    /**
     * What this device knows of the address [emailNorm] at [origin] ([AddressBinding]), or null when no record ties it to
     * an account here. Facts only: it changes nothing and sends nothing. [BoundAccountHere] follows the same judgement as
     * [forgetEarlierAccount]: that call removes the record only for [BoundAccountHere.NOT_KEPT] and
     * [BoundAccountHere.KEPT_LOCKED] (with its copy then), and answers [ForgetEarlier.OpenForThatAccount] for the others.
     */
    override fun addressBinding(origin: String, emailNorm: String): AddressBinding? {
        val (userId, key) = emailBinding(origin, emailNorm) ?: return null
        val s = stored?.takeIf { it.userId == userId }
        val here = when {
            s == null -> BoundAccountHere.NOT_KEPT
            s.heldAsOperator -> BoundAccountHere.HELD_AS_OPERATOR
            s.origin != origin || s.emailNorm != emailNorm -> BoundAccountHere.KEPT_ELSEWHERE
            synchronized(keysLock) { open } != null -> BoundAccountHere.KEPT_OPEN
            else -> BoundAccountHere.KEPT_LOCKED
        }
        return AddressBinding(userId, key, here)
    }

    override fun keptAccountFor(origin: String, emailNorm: String): String? =
        stored?.takeIf { it.origin == origin && it.emailNorm == emailNorm }?.userId

    /**
     * The kept session's refresh token, for a sign-in to name ([SessionSink.signInReplaces]): only a session of the same
     * address at the same origin, on the row the login sends, not held as its server's operator, that still holds its
     * tokens, or that ended here because no try was left for a cut-off refresh ([Stored.unconfirmedRefresh]: its one use).
     * A refresh in flight may replace it meanwhile; the server then ends that session's chain all the same and records
     * the name as a replaced one, never as a reuse.
     */
    override fun signInReplaces(origin: String, emailNorm: String, deviceId: String?): String? =
        stored?.takeIf {
            deviceId != null && it.origin == origin && it.emailNorm == emailNorm && it.deviceId == deviceId && !it.heldAsOperator
        }?.let { it.refreshToken.ifEmpty { it.unconfirmedRefresh.orEmpty() } }?.takeIf { it.isNotEmpty() }

    /**
     * Told at every take ([establish], the one place a session is taken on every road: a sign-in, a registration, a device
     * link, a recovery that ends in a session), once the take's checks have passed and before it writes anything of its
     * own: the take's origin, the address it is taken under (as its address record is keyed) and the account's id. Runs
     * under the take's lock; a throw stops the take, and nothing of it is kept. Null: nothing is told.
     */
    var beforeTake: ((origin: String, emailNorm: String, userId: String) -> Unit)? = null

    /** How many sessions this keeper took ([Establishing.Taken]); an entry intent reads it before its engine call. */
    var takes: Long = 0L
        private set

    /** How many sessions this keeper refused ([Establishing.Refused]). */
    var refusals: Long = 0L
        private set

    /** How many of [refusals] were [Establishing.IDENTITY_MISMATCH]: the entry says the security fault for them. */
    var identityRefusals: Long = 0L
        private set

    /** The [takes] count at which the kept session was taken; 0 for one loaded at a start. */
    private var storedTake = 0L

    /**
     * Take [session]: it never silently replaces a DIFFERENT kept session (another origin or
     * another account). That one must be ended first by its own act (sign-out, forget, the server's end); until then the
     * new session is refused: its keys are wiped, exactly that session is ended at its own origin through the guard, and
     * nothing of it is kept. The same account at the same origin is taken again (a kit recovery, a re-link), and the kept
     * session it replaces, when it still holds its tokens, is ended at its server the same way once the take is done.
     */
    suspend fun establish(session: EstablishedSession): Establishing {
        // A flow whose own comparison held by a kept wrap hands the wrap key it used: checked here, wiped on every way out.
        val proof = session.takeKeptWrapKey()
        // A take is a flow under way for its address: the earlier account under it is not forgotten meanwhile.
        val done = underWay(session.origin, session.emailNorm)
        try {
            return establishWith(session, proof)
        } finally {
            done()
            proof?.fill(0)
        }
    }

    private suspend fun establishWith(session: EstablishedSession, proof: ByteArray?): Establishing {
        // The kept session whose place this take takes, ended at its server once the take is done (below).
        var endedHere: Stored? = null
        // Read and replaced under the refresh lock: no refresh of the kept session is in flight meanwhile, so the refresh
        // token whose session this take ends is the newest this device holds (an older one reads as reuse at the server,
        // which ends every session of the device, the new one too).
        refreshLock.withLock {
            val kept = stored
            // An account held as its server's operator is not opened by a new session of it either (the owner's decision
            // of 2026-11-16): the person removes it first. Refused as a different kept session is.
            if (kept != null && (kept.heldAsOperator || kept.origin != session.origin || kept.userId != session.userId)) {
                session.account.wipe()
                refusals++
                // Exactly the new session ends at its server (a logout would end every session of the device there).
                endOne(session.origin, session.refreshToken)
                return Establishing.Refused(if (kept.heldAsOperator) Establishing.OPERATOR_ACCOUNT_HELD else Establishing.ANOTHER_SESSION_KEPT)
            }
            // Design §2.2, strict decoding: account-key texts in another form than the canonical one are the server's fault,
            // and are never kept (kept, a tolerant opening would take them while a strict reading judged the copy damaged).
            if (!io.silencelen.andvari.core.client.onboard.ServedKeyForm.canonical(session.accountKeys)) {
                session.account.wipe()
                refusals++
                endOne(session.origin, session.refreshToken)
                return Establishing.Refused(Establishing.SERVED_KEY_FORM)
            }
            // Spec 01 §5: the typed address is bound here to another user id or key: the security
            // fault, never a fresh pin. Nothing of the session is kept.
            // So too an account this device forgot under an address there, served now under another key than the one kept.
            if (emailBindingRefuses(session.origin, session.emailNorm, session.userId, session.account.identityPub()) ||
                earlierKeyDiffers(session.origin, session.userId, session.account.identityPub())) {
                session.account.wipe()
                refusals++
                identityRefusals++
                endOne(session.origin, session.refreshToken)
                return Establishing.Refused(Establishing.IDENTITY_MISMATCH)
            }
            // Spec 01 §7, the one place a kept account is replaced: the new session's key must open what the kept copy
            // holds sealed under the account's key (each flow that can end over a kept account compares first, and says
            // why; this is the floor under all of them). Another key replaces nothing and keeps no session. A sign-in's own
            // rule is the exception, checked here by the keeper itself: a kept wrap that the flow's wrap key opens to this
            // session's key decides (a copy whose sealed seed is damaged is then taken, and the record written below from
            // this session, whose served seed opened, repairs it).
            if (kept != null) {
                // A record that keeps no wrapped key ([Stored.keysAtServer]) has no sealed seed to open and is no damaged
                // copy: only this device's record of the account's identity decides.
                val refusal = if (kept.keysAtServer) Establishing.IDENTITY_MISMATCH.takeUnless { identityOnRecordIs(kept, session.account.identityPub()) } else session.account.uvk.use { uvk ->
                    when {
                        KeptAccountCheck.opensKeptSeed(crypto, session.userId, uvk, kept.accountKeys) -> null
                        proof != null && KeptAccountCheck.keptWrapOpensTo(crypto, session.userId, uvk, keysOf(kept), proof) -> null
                        KeptAccountCheck.copyDamaged(kept.accountKeys, session.account.identityPub()) -> Establishing.KEPT_COPY_DAMAGED
                        else -> Establishing.SERVER_KEYS_NOT_KNOWN_HERE
                    }
                    // The key is the account's; the record written below (a repair, where the kept seed did not open) is
                    // held to the identity this device knows for the account: its own record, or the copy's where it reads.
                    // With neither, the device stands where a new device stands, and the take goes on.
                } ?: Establishing.IDENTITY_MISMATCH.takeUnless { identityOnRecordIs(kept, session.account.identityPub()) }
                if (refusal != null) {
                    session.account.wipe()
                    refusals++
                    if (refusal == Establishing.IDENTITY_MISMATCH) identityRefusals++
                    endOne(session.origin, session.refreshToken)
                    return Establishing.Refused(refusal)
                }
            }
            // Before anything of this take is written: what an end begun at this server and cut part-way would remove, and
            // this take uses from here on, is this take's ([beforeTake]: the app's engine ends the mark of a deletion of
            // this account, or of any account under this address, there). A failure stops the take, and nothing of it is kept.
            try {
                beforeTake?.invoke(session.origin, session.emailNorm, session.userId)
            } catch (e: Exception) {
                session.account.wipe()
                throw e
            }
            // The address's record first: from it on the device knows the account, so a sweep of accounts it does not know
            // (at a start here or in another process over the same stores) never falls on an identity record of this take
            // that nothing names yet. A stop between the two leaves the address's record, which holds the same key.
            recordEmailBinding(session.origin, session.emailNorm, session.userId, session.account.identityPub())
            recordIdentity(session.userId, session.account.identityPub())
            // Taken again under the key kept for it: the identity record holds that key from here on, and the kept record
            // goes (so that a deletion this device runs later leaves nothing of the account, as before).
            if (state.get(earlierKeyKey(session.origin, session.userId)) != null) state.set(earlierKeyKey(session.origin, session.userId), null)
            val s = Stored(
                session.origin, session.emailNorm, session.userId, session.deviceId, session.role, session.how.name, session.totpEnrolled,
                session.mustEnrollTotp, session.recoveryConfirmed, session.accessToken, session.refreshToken, session.accountKeys,
                // A take over a record whose keys were at the server brings none back at rest until a readable policy allows it.
                keysServed = kept?.let { it.keysAtServer || it.keysServed } == true,
            )
            // The kept session of the same account, when it still holds its tokens, ends with this take, so no session this
            // device no longer holds stays open at its server. A password sign-in on this device's own row is ended there by
            // the server itself (the sign-in named it, [signInReplaces]; a device has one live session), and its token is
            // never sent again here: when an earlier refresh was
            // answered and the answer lost, that token is one the server already replaced, and sending it reads as a stolen
            // token's reuse, which ends every session of the device, the new one too. Any other take (a recovery's commit,
            // a device link: each makes a new device row) ends it here by its own refresh token.
            val replacedLive = kept?.takeIf { it.refreshToken.isNotEmpty() && it.refreshToken != session.refreshToken }
            val endedByTheSignIn = replacedLive != null && session.how == SessionHow.PASSWORD && replacedLive.deviceId == session.deviceId
            endedHere = replacedLive?.takeUnless { endedByTheSignIn }
            // What this take replaces (the same account at the same origin, or nothing), for a call the person left: a
            // record whose session this take ended comes back as its server's end left it, with no tokens; a token kept
            // for one sign-in to name ([Stored.unconfirmedRefresh]) has had its use, and does not come back.
            replaced += (takes + 1) to (replacedLive?.copy(accessToken = "", refreshToken = "", endedByServer = true) ?: kept?.copy(unconfirmedRefresh = null))
            while (replaced.size > REPLACED_KEPT) replaced.removeAt(0)
            // An unlock still running opens nothing over this session.
            val previous = synchronized(keysLock) {
                generation++
                // A re-key may follow only a sign-in with the password itself (spec 01 §7), not a link, a recovery or a registration.
                fullPasswordGen = if (session.how == SessionHow.PASSWORD) generation else -1L
                open.also {
                    stored = s
                    open = session
                }
            }
            if (previous != null && previous !== session) previous.account.wipe()
            lastEnd = null
            storedTake = ++takes
            persist()
        }
        endedHere?.let { endOne(it.origin, it.refreshToken) }
        // Every way a session is established here took the master password in full.
        quick?.passwordUsed(session.origin, session.userId)
        _phase.value = KeptPhase.UNLOCKED
        onAccountOpened(session.account)
        return Establishing.Taken
    }

    /** The record each recent take replaced, by its [takes] count. */
    private val replaced = ArrayList<Pair<Long, Stored?>>()

    /**
     * An entry intent's engine call that began at [mark] (the [takes] count then) was left, or ran out of time: the
     * session it established, when it is still the kept one, ends at once on this device, and the answer is the
     * best-effort end of exactly that session at its own origin, by its own refresh token ([endOne], through the guard),
     * which the caller sends. Never the logout: that ends every session of the device there, a kept one's or another
     * device record's too. Null when nothing taken since [mark] is kept.
     *
     * When that session had replaced a kept record of the same account (signed out by its
     * server, its copy and its waiting changes on this device), the record is put back as it was instead, and the
     * account stays kept. Never an end the person made: nothing of the account's data may go because of it.
     */
    internal fun endTakenSince(mark: Long): (suspend () -> Unit)? {
        val now = stored ?: return null
        if (storedTake <= mark) return null
        val before = replaced.firstOrNull { it.first > mark }?.second
        if (before == null || before.userId != now.userId || before.origin != now.origin) {
            end(SessionEndReason.SIGNED_OUT, notify = false, ownAct = false)
            return { endOne(now.origin, now.refreshToken) }
        }
        val o = synchronized(keysLock) {
            generation++
            stored = before
            open.also { open = null }
        }
        o?.account?.wipe()
        storedTake = 0L
        replaced.clear()
        // A session its server ended keeps no quick-unlock key (as at [serverEnded]).
        if (before.endedByServer) quick?.wipe()
        persist()
        lastEnd = when {
            !before.endedByServer -> null
            before.endedUnconfirmed -> SessionEndReason.SESSION_NOT_CONFIRMED
            else -> SessionEndReason.REFRESH_REFUSED
        }
        _phase.value = KeptPhase.LOCKED
        return { endOne(now.origin, now.refreshToken) }
    }

    /**
     * The accounts, as (origin, user id), whose end on this device was the person's own act (a sign-out, "Forget this
     * server", the account's deletion) and whose data the app has not yet confirmed deleted. Kept durably in [state],
     * written before the session's record goes, so a start after a stop can tell such an account from one that is only
     * not kept: only these may have their data deleted at a start.
     */
    fun endedByOwnAct(): List<Pair<String, String>> = ownEnds().map { it.origin to it.userId }

    /**
     * [endedByOwnAct] with why each ended: `origin|userId|why`, [why] one of [OWN_END_DELETED], [OWN_END_FORGOTTEN] or a
     * [SessionEndReason]'s name. Earlier builds wrote `origin|userId`: its [OwnEnd.why] is null.
     */
    fun ownEnds(): List<OwnEnd> = state.get(OWN_ENDS_KEY).orEmpty().split('\n').mapNotNull { line ->
        val f = line.split('|')
        if (f.size !in 2..3 || f.any { it.isEmpty() }) null else OwnEnd(f[0], f[1], f.getOrNull(2))
    }

    /** An end of the person's own, at [origin], of [userId], and [why] (null: written by an earlier build). */
    class OwnEnd(val origin: String, val userId: String, val why: String?)

    /** The app deleted the data of [userId] at [origin] (or found none to delete): that record in [endedByOwnAct] goes. */
    fun ownEndSettled(origin: String, userId: String) {
        val now = ownEnds()
        val left = now.filterNot { it.origin == origin && it.userId == userId }
        if (left.size != now.size) state.set(OWN_ENDS_KEY, left.joinToString("\n") { line(it) }.ifEmpty { null })
    }

    private fun line(e: OwnEnd): String = listOfNotNull(e.origin, e.userId, e.why).joinToString("|")

    private fun noteOwnEnd(origin: String, userId: String, why: String) {
        val now = ownEnds()
        if (now.none { it.origin == origin && it.userId == userId }) state.set(OWN_ENDS_KEY, (now + OwnEnd(origin, userId, why)).joinToString("\n") { line(it) })
    }

    /** Quick unlock over this keeper, when the platform has one ([QuickUnlockKeeper] sets it). */
    internal var quick: QuickUnlockKeeper? = null

    // ---- The session's clients ----

    /**
     * The client for [origin]. An authenticated route carries the kept session's bearer only when the session is
     * [origin]'s: a session's tokens are sent to the origin that issued them and to no other (§7.8 single origin).
     */
    fun clientFor(origin: String): WireClient = clients.getOrPut(origin) { dial(origin, Tokens(origin)) }

    /**
     * True when a credential may go to [origin] now ([OriginGuard.mayDial]): its pin is in force and its access open
     * (design §4.4, "No credential goes to an origin without a pin in force"). A host asks this before it opens a
     * WebSocket to [origin]; the clients ask it before every request that carries a credential. A request without one
     * (fetching the card for a first pin) follows [OriginGuard.mayFetchPublic] instead.
     */
    fun mayDial(origin: String): Boolean = guard.mayDial(origin)

    /**
     * A client for [origin] behind [guard], its token source too (null: no bearer). The guard reads the pin store on
     * every request, so a fork marked while a client is out stops that client's very next request. The session's
     * tokens stay on this device under a stop, so "Forget this server" or a later sign-out still finds them, and no
     * request carries them.
     */
    private fun dial(origin: String, tokens: TokenSource?): WireClient =
        guard.guard(AnswerWatch(transport.open(origin, tokens?.let { guard.guard(origin, it) })) { route, r -> answered(origin, route, r) })

    // ---- "Update required", per server, as its answers say (spec 03 §1.1) ----

    private val updateRequiredFlow = MutableStateFlow<Set<String>>(emptySet())

    /**
     * The origins whose latest answer to one of this keeper's clients was "update required" (`upgrade_required`, or the
     * older `update_required` and `client_too_old`). A later answer from the same server that is not one, on a route
     * the server checks the version on ([WireRoute.versionChecked]), clears it; an answer on any other route, a
     * request that got no answer, or one refused on this device (a stopped origin, a body over its cap), changes nothing.
     * A state for a screen only: nothing here closes, locks or ends anything because of it. In memory: a start begins clear.
     */
    val updateRequired: StateFlow<Set<String>> get() = updateRequiredFlow

    /** Called after [updateRequired] changed, and after every "update required" answer (the app publishes a snapshot). */
    internal var onUpdateRequiredChanged: (() -> Unit)? = null

    private fun answered(origin: String, route: WireRoute, r: WireResult<*>) {
        val needed = when (r) {
            is WireResult.Ok -> false
            // Status 0 is this device's own refusal (a body over its cap): no answer from the server.
            is WireResult.Refused -> if (r.status <= 0) return else r.code in UPDATE_CODES
            is WireResult.NoAnswer -> return
        }
        // Only a route the server checks the build's version on (spec 03 §1, `V`) can clear it: the client policy, a
        // refresh or a link's fetch answer whatever the build, so their answers say nothing about it.
        if (!needed && !route.versionChecked) return
        var changed = false
        updateRequiredFlow.update { s ->
            val next = if (needed) s + origin else s - origin
            changed = next != s
            next
        }
        // Also on every "update required" that changed nothing: a vault composed meanwhile learns it stands.
        if (changed || needed) onUpdateRequiredChanged?.invoke()
    }

    /**
     * The session's bearer goes only to an origin whose pin is in force (design §4.4: a device never sends a credential to
     * an address it holds no pin in force for). With none there (a move left the session behind, a forgotten server),
     * a request goes out without it and a sign-out sends nothing.
     *
     * One exception, the same as the guard's ([OriginGuard.mayDial]): before card 0 is pinned, the setup offer this device
     * opened under its link's own key stands for the pin at its own origin (design §6.7 steps 2-3), and only for the
     * operator's session there. Without it the bearer never went with the setup's own authenticated requests (the
     * card 0 upload, the recovery record, "Finish setting up"), which a real server answered `401` (the
     * scripted servers ignored the bearer).
     */
    private fun pinInForce(origin: String): Boolean = when (trust.pinState(origin)) {
        is io.silencelen.andvari.core.client.pin.PinState.Pinned -> true
        io.silencelen.andvari.core.client.pin.PinState.None -> stored?.let { it.origin == origin && it.role == "operator" } == true && guard.mayDial(origin)
        else -> false
    }

    private inner class Tokens(private val origin: String) : TokenSource {
        override fun accessToken(): String? = stored?.takeIf { it.origin == origin && !it.endedByServer && !it.heldAsOperator && pinInForce(origin) }?.accessToken

        override suspend fun refresh(staleAccessToken: String): Boolean = refreshLock.withLock {
            val s = stored?.takeIf { it.origin == origin && !it.endedByServer && !it.heldAsOperator && pinInForce(origin) } ?: return@withLock false
            if (s.accessToken != staleAccessToken) return@withLock true
            // A refresh that was cut off while out may have been taken by the server, which then holds the token as
            // replaced and answers it again with the same pair for sixty seconds from the replacement only (spec 03, the
            // refresh's grace). So the token is tried once more, within [REFRESH_SECOND_TRY_MS] of its first try's
            // sending, and never again after that: a third try, or one after the window, would read as a stolen token's
            // reuse and end every session of the device. This is asked at a 401 to a request, so there is a connection
            // when the second try goes. Where no try is left, nothing is sent and the session ends here ([noTryLeft]).
            val outAt = s.refreshOutAt
            val asked = if (outAt != null) {
                val now = clock()
                if (s.refreshTriedAgain || now < outAt || now - outAt > REFRESH_SECOND_TRY_MS) {
                    noTryLeft()
                    return@withLock false
                }
                // Counted before it goes: whatever comes of it, the token is not sent a third time.
                s.copy(refreshTriedAgain = true)
            } else {
                // Written before the request goes: whatever cuts it off leaves it (a cancelled caller, the app's end).
                s.copy(refreshOutAt = clock())
            }
            stored = asked
            persist()
            val plain = dial(origin, null)
            val body = WireJson.json.encodeToString(RefreshRequest.serializer(), RefreshRequest(asked.refreshToken))
            when (val r = plain.call(WireRoute.REFRESH, bodyJson = body, authenticated = false) { WireJson.json.decodeFromString(TokenPair.serializer(), it) }) {
                is WireResult.Ok -> {
                    // Only the session that asked is rotated: a sign-out or another session meanwhile wins.
                    sameSession(asked)?.let { cur ->
                        stored = cur.copy(accessToken = r.value.accessToken, refreshToken = r.value.refreshToken, refreshOutAt = null, refreshTriedAgain = false)
                        persist()
                        true
                    } ?: false
                }
                is WireResult.Refused -> {
                    // Any 401 to a refresh ends the session (a revoked device, an inactive account, a spent or reused
                    // token), as do the refresh codes at any status; a 429, a 5xx or the guard's own stop never does.
                    val ends = (r.status == 401 || r.code in REFRESH_ENDS) && r.code != io.silencelen.andvari.core.client.net.ORIGIN_STOPPED
                    when {
                        ends -> if (sameSession(asked) != null) serverEnded()
                        // The guard's stop: nothing left this device, so the record stands as it was before this try.
                        r.status <= 0 && r.code == io.silencelen.andvari.core.client.net.ORIGIN_STOPPED -> settle(asked) { it.copy(refreshOutAt = s.refreshOutAt, refreshTriedAgain = s.refreshTriedAgain) }
                        // This device's own limit on the answer: an answer came, but not one it can read; cannot tell.
                        r.status <= 0 -> {}
                        // The server's answer to a first try (a 429, a 5xx in its envelope): it clears the record. To a
                        // second try, the first try is still unanswered: the record stays, and no third try goes.
                        !asked.refreshTriedAgain -> settle(asked) { it.copy(refreshOutAt = null) }
                    }
                    false
                }
                // No HTTP answer of the server's (no connection, a timeout, an answer that broke off, a page that is not
                // the server's envelope): the record stays, for the one second try. Where the transport says nothing of
                // the request left, the record stands as it was before this try, as at the guard's stop. That is the
                // transport's word, taken as it is: given only for a failure of the connect itself with no earlier attempt
                // attached (refused, no route to host, a name not resolved, a connect that timed out; a network the
                // platform reports as a failed connect among them). A secure setup that failed or a proxy's refusal is
                // never said so, nor is a failure that may come after bytes were written.
                is WireResult.NoAnswer -> {
                    if (r.neverLeft) settle(asked) { it.copy(refreshOutAt = s.refreshOutAt, refreshTriedAgain = s.refreshTriedAgain) }
                    false
                }
            }
        }
    }

    /** The kept record when it is still the session [asked] was taken from (the same account and refresh token). */
    private fun sameSession(asked: Stored): Stored? =
        stored?.takeIf { it.userId == asked.userId && it.refreshToken == asked.refreshToken && it.refreshToken.isNotEmpty() && !it.endedByServer && !it.heldAsOperator }

    private fun settle(asked: Stored, f: (Stored) -> Stored) {
        val cur = sameSession(asked) ?: return
        stored = f(cur)
        persist()
    }

    /**
     * A refresh was cut off while out and no try is left (after the window, after the second try, or a clock set back):
     * nothing is sent, and the session ends here as one its server ended would, with an end of its own
     * ([SessionEndReason.SESSION_NOT_CONFIRMED]). Its refresh token is kept for one use only, the next sign-in's name
     * for the session it replaces ([Stored.unconfirmedRefresh]).
     */
    private fun noTryLeft() {
        val s = stored ?: return
        endHere(s.copy(unconfirmedRefresh = s.refreshToken.ifEmpty { null }, endedUnconfirmed = true), SessionEndReason.SESSION_NOT_CONFIRMED)
    }

    // ---- Lock and unlock ----

    /**
     * Bumped by every [lock] and every end: an unlock that began under an older value opens nothing.
     * Read and written under [keysLock], with [open].
     */
    private var generation = 0L
    private val keysLock = SynchronizedObject()

    /** Held while an unlock runs: a second one is refused ([KeptUnlock.Stale]). */
    private val unlocking = Mutex()

    /** Wipe the account's keys; the session stays stored. An unlock still running opens nothing. */
    fun lock() {
        val o = synchronized(keysLock) {
            generation++
            // Under a policy that forbids key material at rest, what a lock leaves in memory is what is kept at rest.
            stored?.let { s -> atRest(s).let { if (it !== s) stored = it } }
            open.also { open = null }
        } ?: return
        o.account.wipe()
        if (stored != null) _phase.value = KeptPhase.LOCKED
    }

    /**
     * Open the stored account with [password] (wiped here). Sends nothing. It never answers Unlocked without checking
     * the password: keys found open are wiped first. One unlock at a time; a lock or an end meanwhile discards (and
     * wipes) what it opened.
     */
    fun unlock(password: CharArray): KeptUnlock {
        if (!unlocking.tryLock()) {
            password.fill('\u0000')
            return KeptUnlock.Stale
        }
        try {
            return unlockOnce(password)
        } finally {
            unlocking.unlock()
        }
    }

    private fun unlockOnce(password: CharArray): KeptUnlock {
        val s = stored
        if (s == null) {
            password.fill('\u0000')
            return KeptUnlock.NoSession
        }
        if (s.heldAsOperator) {
            password.fill('\u0000')
            return KeptUnlock.HeldAsOperator
        }
        // No wrapped key is kept here: only the server's can open the account ([unlockAsking]).
        if (s.keysAtServer) {
            password.fill('\u0000')
            return KeptUnlock.KeysAtServer(s.endedByServer)
        }
        val gen = wipeOpenKeys()
        val pin = pinToOpenAgainst(s)
        if (pin == null) {
            password.fill('\u0000')
            return KeptUnlock.Blocked
        }
        val salt = runCatching { Bytes.fromB64(s.accountKeys.kdfSalt) }.getOrNull()
        if (salt == null) {
            password.fill('\u0000')
            return KeptUnlock.IdentityFault(AccountOpen.SEED_UNOPENABLE)
        }
        // A change whose answer never came: the new password may be the one in force.
        val spare = s.pendingWrap?.let { password.copyOf() }
        try {
            val keys = PasswordKeys.derive(crypto, password, salt, s.accountKeys.kdfParams, served = true) ?: return KeptUnlock.KdfRefused
            val uvk = openUvk(keys, s) ?: spare?.let { openPending(it, s) } ?: return KeptUnlock.WrongPassword
            val answer = openWith(s, pin, uvk, gen)
            if (answer == KeptUnlock.Unlocked) {
                synchronized(keysLock) { if (generation == gen) fullPasswordGen = gen }
                quick?.passwordUsed(s.origin, s.userId)
            }
            return answer
        } finally {
            spare?.fill('\u0000')
        }
    }

    /** [password] (wiped) opens [s]'s pending wrap: the account's key, or null. */
    private fun openPending(password: CharArray, s: Stored): ByteArray? {
        val p = s.pendingWrap
        val salt = p?.let { runCatching { Bytes.fromB64(it.kdfSalt) }.getOrNull() }
        if (p == null || salt == null) {
            password.fill('\u0000')
            return null
        }
        val keys = try {
            PasswordKeys.derive(crypto, password, salt, p.kdfParams, served = true)
        } catch (e: CryptoException) {
            null
        } catch (e: IllegalArgumentException) {
            null
        } ?: return null
        return try {
            Envelope.openB64(crypto, keys.wrapKey, p.wrappedUvk, Ad.uvk(s.userId))
        } catch (e: CryptoException) {
            null
        } catch (e: IllegalArgumentException) {
            null
        } finally {
            keys.wipe()
        }
    }

    /**
     * [unlock], and for a record that keeps no wrapped key ([KeptSession.keysAtServer]) the unlock that asks the server,
     * as a sign-in proves the password: the account's keys are read as the server holds them (`GET /account/keys`, with
     * the session's bearer; nothing derived from [password] is sent), the password is derived at the served salt and cost
     * under the fence and opens the served wrap here, and the account opens with every identity check of §5.2 against
     * the pin in force and this device's record of the identity key. A password that does not open it is
     * [KeptUnlock.WrongPassword]; no answer, a refusal or a stop is [KeptUnlock.KeysAtServer], with nothing opened or
     * removed. The served keys stay in memory while the account is open and are kept at rest only where the server's
     * kept policy allows it again ([atRest]). [password] is wiped.
     */
    suspend fun unlockAsking(password: CharArray): KeptUnlock {
        val s = stored
        if (s == null || !s.keysAtServer) return unlock(password)
        if (!unlocking.tryLock()) {
            password.fill('\u0000')
            return KeptUnlock.Stale
        }
        try {
            return unlockAtServer(password, s)
        } finally {
            password.fill('\u0000')
            unlocking.unlock()
        }
    }

    private suspend fun unlockAtServer(password: CharArray, s: Stored): KeptUnlock {
        if (s.heldAsOperator) return KeptUnlock.HeldAsOperator
        // A session its server ended keeps no token: nothing can be asked.
        if (s.endedByServer || s.accessToken.isEmpty()) return KeptUnlock.KeysAtServer(signInNeeded = true)
        val gen = wipeOpenKeys()
        val pin = pinToOpenAgainst(s) ?: return KeptUnlock.Blocked
        val r = clientFor(s.origin).call(WireRoute.ACCOUNT_KEYS) { WireJson.json.decodeFromString(AccountKeys.serializer(), it) }
        // The read was a wait: a lock, an end or another session meanwhile opens nothing (a refresh rotates the tokens only).
        val now = stored
        // The server's end of this very session, learned by this read (its refresh refused), is asked first: the end moves
        // the keys' generation itself, and this unlock then answers what every later one does, never "an older state".
        if (now != null && now.userId == s.userId && now.origin == s.origin && !now.heldAsOperator && now.endedByServer) {
            return KeptUnlock.KeysAtServer(signInNeeded = true)
        }
        if (synchronized(keysLock) { generation != gen } || now == null || now.userId != s.userId || now.origin != s.origin || now.heldAsOperator) return KeptUnlock.Stale
        if (r !is WireResult.Ok) return KeptUnlock.KeysAtServer(signInNeeded = false)
        val served = r.value
        // Keys in a form this device does not take: the keeper's own reason, never the identity fault's.
        if (!io.silencelen.andvari.core.client.onboard.ServedKeyForm.canonical(served)) return KeptUnlock.IdentityFault(Establishing.SERVED_KEY_FORM)
        val salt = Bytes.fromB64Canonical(served.kdfSalt) ?: return KeptUnlock.IdentityFault(Establishing.SERVED_KEY_FORM)
        val keys = PasswordKeys.derive(crypto, password, salt, served.kdfParams, served = true) ?: return KeptUnlock.KdfRefused
        val uvk = try {
            Envelope.openB64(crypto, keys.wrapKey, served.wrappedUvk, Ad.uvk(s.userId))
        } catch (e: CryptoException) {
            null
        } catch (e: IllegalArgumentException) {
            null
        } finally {
            keys.wipe()
        } ?: return KeptUnlock.WrongPassword
        val full = now.copy(accountKeys = served, keysAtServer = false, keysServed = true)
        val placed = synchronized(keysLock) { (generation == gen && stored === now && open == null).also { if (it) stored = full } }
        if (!placed) {
            uvk.fill(0)
            return KeptUnlock.Stale
        }
        val answer = openWith(full, pin, uvk, gen)
        if (answer != KeptUnlock.Unlocked) {
            synchronized(keysLock) { if (stored === full) stored = now }
            return answer
        }
        synchronized(keysLock) { if (generation == gen) fullPasswordGen = gen }
        quick?.passwordUsed(s.origin, s.userId)
        // Kept at rest as the policy now says: without the keys while it forbids them, with them once it allows them again.
        persist()
        return answer
    }

    /**
     * A policy was recorded for [origin]: under one that forbids key material at rest, the kept record loses the account's
     * wrapped keys at once ([atRest]), in memory too while the account is locked; while it is open they go at its lock.
     * Called on whichever thread recorded it.
     */
    fun policyRecorded(origin: String) {
        // The quick-unlock key goes too, on every road that records such a policy (it is the account's key, sealed).
        KeptPolicies(state).get(origin)?.let { quick?.policySeen(origin, it) }
        if (stored?.origin != origin) return
        synchronized(keysLock) { if (open == null) stored?.let { s -> atRest(s).let { if (it !== s) stored = it } } }
        persist()
    }

    /** The kept policy of [origin]'s server forbids key material at rest (a record that cannot be read does not forbid). */
    private fun keysForbiddenAtRest(origin: String): Boolean = KeptPolicies(state).get(origin)?.offlineCacheAllowed == false

    /** The kept policy of [origin]'s server can be read and allows key material at rest. */
    private fun keysAllowedAtRest(origin: String): Boolean = KeptPolicies(state).get(origin)?.offlineCacheAllowed == true

    /** [s] holds any of the account's wrapped keys or a password change's wrap. */
    private fun carriesKeys(s: Stored): Boolean = s.accountKeys.let { k ->
        k.wrappedUvk.isNotEmpty() || k.kdfSalt.isNotEmpty() || k.encryptedIdentitySeed.isNotEmpty() || k.personalWrap != null
    } || s.pendingWrap != null

    /**
     * [s] as it may be kept at rest: under a kept policy that forbids key material at rest (spec 02 §8, as on the released
     * line), without the account's wrapped keys (the wrapped UVK with its salt, the sealed identity seed, the personal
     * vault's wrap) and without a password change's wrap; the tokens, the ids and the public identity stay. Keys the
     * server served for a record that kept none ([Stored.keysServed]) stay off the device the same way until a readable
     * kept policy allows them: a record that cannot be read, or none, brings no key back. A record marked
     * [Stored.keysAtServer] keeps none whatever was written into it meanwhile (a password change answered after a lock,
     * its pending wrap). [s] itself where nothing changes.
     */
    private fun atRest(s: Stored): Stored =
        if (if (s.keysAtServer) !carriesKeys(s) else !(keysForbiddenAtRest(s.origin) || (s.keysServed && !keysAllowedAtRest(s.origin)))) s else s.copy(
            accountKeys = s.accountKeys.copy(kdfSalt = "", wrappedUvk = "", encryptedIdentitySeed = "", personalWrap = null),
            pendingWrap = null,
            previousPasswordOpens = false,
            keysAtServer = true,
        )

    /** Keys found open where an unlock is asked for are wiped first; answers the generation the unlock runs under. */
    private fun wipeOpenKeys(): Long {
        val o = synchronized(keysLock) { open.also { open = null } }
        if (o != null) {
            o.account.wipe()
            if (stored != null) _phase.value = KeptPhase.LOCKED
        }
        return synchronized(keysLock) { generation }
    }

    /**
     * Open the stored account with its key [uvk] (taken: kept by the opened account or wiped), as [unlock] does after
     * the password opened the key: against the pin in force, with every identity check of §5.2. A quick unlock's way
     * in ([QuickUnlockKeeper]). Sends nothing; a damaged pin answers [KeptUnlock.Blocked], a fork opens.
     */
    internal fun unlockWithUvk(uvk: ByteArray): KeptUnlock {
        if (!unlocking.tryLock()) {
            uvk.fill(0)
            return KeptUnlock.Stale
        }
        try {
            val s = stored
            if (s == null) {
                uvk.fill(0)
                return KeptUnlock.NoSession
            }
            if (s.heldAsOperator) {
                uvk.fill(0)
                return KeptUnlock.HeldAsOperator
            }
            // No wrapped key is kept here, so nothing at rest opens the account: only the server's keys do.
            if (s.keysAtServer) {
                uvk.fill(0)
                return KeptUnlock.KeysAtServer(s.endedByServer)
            }
            val gen = wipeOpenKeys()
            val pin = pinToOpenAgainst(s)
            if (pin == null) {
                uvk.fill(0)
                return KeptUnlock.Blocked
            }
            // A quick unlock never counts as a full-password one (spec 01 §7): no re-key follows it.
            synchronized(keysLock) { fullPasswordGen = -1L }
            return openWith(s, pin, uvk, gen)
        } finally {
            unlocking.unlock()
        }
    }

    /**
     * A fork stops traffic, not reading (design §4.4): the stored account still opens against the pin the fork is
     * recorded with, from this device's own copy, and nothing is sent while it stands ([guard]). A damaged record,
     * or none, gives no pin to open against.
     */
    /**
     * The instance id the stored account opens against: its pin's. With no pin at all, the setup offer this device keeps
     * for the origin (design §6.7 step 2, "Resume"): the server's first operator, whose setup stopped before card 0 was
     * pinned, still opens its account here to finish it. The offer was opened under the setup
     * link's own key, so its instance id is the one the registration's genesis named; nothing served stands in for it.
     */
    private fun pinToOpenAgainst(s: Stored): String? {
        // The trust's own answer decides fork against damaged; only then is the pin itself read.
        if (!trust.access(s.origin).mayReadLocal) return null
        return when (val st = trust.pinState(s.origin)) {
            is io.silencelen.andvari.core.client.pin.PinState.Pinned -> st.pin.instanceId
            is io.silencelen.andvari.core.client.pin.PinState.Forked -> st.pin.instanceId
            io.silencelen.andvari.core.client.pin.PinState.None ->
                if (s.role != "operator") null else runCatching { io.silencelen.andvari.core.client.onboard.SetupOffers(state).get(s.origin)?.instanceId }.getOrNull()
            else -> null
        }
    }

    private fun openWith(s: Stored, instanceId: String, uvk: ByteArray, gen: Long): KeptUnlock {
        val account = when (val o = AccountOpen.open(crypto, s.userId, uvk, s.accountKeys, instanceId, knownIdentity(s.userId))) {
            is AccountOpenResult.IdentityFault -> return KeptUnlock.IdentityFault(o.reason)
            is AccountOpenResult.Opened -> o.account
        }
        // Spec 01 §5: the kept account's address is bound here to another account.
        if (emailBindingRefuses(s.origin, s.emailNorm, s.userId, account.identityPub())) {
            account.wipe()
            return KeptUnlock.IdentityFault(io.silencelen.andvari.core.client.onboard.AccountOpen.SELF_IDENTITY_MISMATCH)
        }
        val session = EstablishedSession(
            s.origin, s.emailNorm, s.userId, s.deviceId, s.role, s.totpEnrolled, s.mustEnrollTotp, s.recoveryConfirmed, how(s.how),
            s.accessToken, s.refreshToken, s.accountKeys, account,
        ).rebuiltByKeeper()
        // A lock or an end came while this unlock ran (or the session changed): what it opened is discarded.
        val taken = synchronized(keysLock) {
            if (generation != gen || stored !== s || open != null) false else {
                open = session
                true
            }
        }
        if (!taken) {
            account.wipe()
            return KeptUnlock.Stale
        }
        _phase.value = KeptPhase.UNLOCKED
        onAccountOpened(account)
        return KeptUnlock.Unlocked
    }

    private fun openUvk(keys: PasswordKeys, s: Stored): ByteArray? {
        try {
            return Envelope.openB64(crypto, keys.wrapKey, s.accountKeys.wrappedUvk, Ad.uvk(s.userId))
        } catch (e: CryptoException) {
            return null
        } catch (e: IllegalArgumentException) {
            return null
        } finally {
            keys.wipe()
        }
    }

    // ---- Ending a session ----

    /** `POST /auth/logout` with the session's bearer (best effort), then the session is forgotten on this device. */
    suspend fun signOut() {
        val s = stored ?: return
        // Under a fork or a damaged pin the guard sends the token nowhere: the session is only forgotten here.
        logout(s.origin, s.accessToken)
        if (stored === s) end(SessionEndReason.SIGNED_OUT, notify = false)
    }

    /**
     * End the kept session on this device at once (its keys wiped, nothing kept), and answer the best-effort
     * `POST /auth/logout` for exactly that session's token, which the caller sends when it can; null when none is kept.
     * For a caller that cannot wait for the server before the session must be gone (a phone refusing the operator
     * account, design §12.2 rule 7). The logout goes through the guard like every request.
     */
    internal fun endNow(ownAct: Boolean = true): (suspend () -> Unit)? {
        val s = stored ?: return null
        end(SessionEndReason.SIGNED_OUT, notify = false, ownAct = ownAct)
        return { logout(s.origin, s.accessToken) }
    }

    /**
     * The server at [origin] said the kept session is over by another answer than a refused refresh (the event bell's
     * `revoked` frame, a `401`/`403` at its ticket after the one refresh): it ends as a refused refresh does, and
     * [onEnded] is told. Nothing happens unless the kept session is [origin]'s.
     */
    fun endedByServer(origin: String) {
        if (stored?.origin != origin) return
        serverEnded()
    }

    /**
     * The server ended the kept session (design §4.4, "A session the server ends does not delete the device's copy"):
     * its tokens and the quick-unlock key go and the keys are wiped, as at a lock; the account stays, as signed out by
     * the server ([KeptSession.endedByServer]). [onEnded] is told [SessionEndReason.REFRESH_REFUSED]. The account's
     * public key stays with the trust (the account is still on this device). Only the person's own act ends it for good.
     */
    private fun serverEnded() {
        val s = stored ?: return
        endHere(s, SessionEndReason.REFRESH_REFUSED)
    }

    /** [serverEnded]'s end for [s] (the kept record, or a copy of it with what [noTryLeft] keeps), told as [reason]. */
    private fun endHere(s: Stored, reason: SessionEndReason) {
        if (s.endedByServer) return
        quick?.wipe()
        val o = synchronized(keysLock) {
            generation++
            // What the end leaves in memory is what is kept at rest, as at a lock: keys the server served for the opening
            // under a policy that keeps them there do not outlive the session until the app's next start.
            stored = atRest(s.copy(accessToken = "", refreshToken = "", endedByServer = true, refreshOutAt = null, refreshTriedAgain = false))
            open.also { open = null }
        }
        o?.account?.wipe()
        persist()
        lastEnd = reason
        _phase.value = KeptPhase.LOCKED
        onEnded(reason)
    }

    /**
     * The owner's decision of 2026-11-16: a verified card names the kept account as its server's operator on a device
     * that may not hold it. The keys are wiped at once (an unlock running opens nothing), the tokens go without a
     * logout (nothing more is sent with the account: no refresh, no logout, no request carries its bearer), and the
     * quick-unlock record is wiped: it holds the account's key sealed to this device, a way in that a password-free
     * unlock would otherwise still have. The record itself stays, with the account's wrapped key and its copy on the
     * device, marked [KeptSession.heldAsOperator] durably; [unlock], [unlockWithUvk] and [establish] refuse it until
     * [removeHeldOperator]. A request already on the wire keeps its bearer and is answered; its answer can no longer be
     * used (the keys are gone, and every flow checks them before it seals or sends anything more). Idempotent.
     */
    fun holdAsOperator() {
        val s = stored ?: return
        quick?.wipe()
        val o = synchronized(keysLock) {
            generation++
            stored = s.copy(accessToken = "", refreshToken = "", heldAsOperator = true, unconfirmedRefresh = null)
            open.also { open = null }
        }
        o?.account?.wipe()
        persist()
        _phase.value = KeptPhase.LOCKED
    }

    /**
     * The person removes the account held as the operator ([holdAsOperator]) from this device: the record goes as at a
     * sign-out, the person's own act (so the app deletes its copy), and nothing is sent (its tokens are already gone).
     * False, and nothing done, when the kept account is not held so.
     */
    fun removeHeldOperator(): Boolean {
        if (stored?.heldAsOperator != true) return false
        end(SessionEndReason.SIGNED_OUT, notify = false)
        return true
    }

    /**
     * Forget the session without telling the server (its tokens are already dead: the account was deleted, or the
     * server was forgotten). The identity record stays unless [forgetIdentity], and even then while something at another
     * server ties that account ([PinStore.tiedElsewhere]: one server's word does not undo what another serves). [tied]: that
     * answer as the caller read it before anything of the deletion was removed; null, read here.
     */
    fun forget(forgetIdentity: Boolean, tied: Boolean? = null) {
        val s = stored
        end(SessionEndReason.FORGOTTEN, notify = false, why = if (forgetIdentity) OWN_END_DELETED else OWN_END_FORGOTTEN)
        if (forgetIdentity && s != null) {
            if (!(tied ?: PinStore.tiedElsewhere(state, s.userId, s.origin))) state.set(identityKey(s.userId), null)
            // Spec 01 §5, amended for account deletion: the email binding goes only where it names the deleted account.
            if (emailBinding(s.origin, s.emailNorm)?.first == s.userId) state.set(emailBindingKey(s.origin, s.emailNorm), null)
        }
    }

    /**
     * A deletion of [userId] at [origin] that its server confirmed, finished after a stop that came once its session was
     * no longer kept here: what [forget] with its identity removes, where it is still there. The identity record goes
     * unless [tied] (read when the deletion began, as [forget] takes it); the address's record for [emailNorm] goes only
     * where it names that account. Nothing while this device keeps a session of [userId] at [origin]; one kept at another
     * origin keeps the identity record through [tied]. Sends nothing.
     */
    fun forgetDeleted(origin: String, emailNorm: String, userId: String, tied: Boolean) {
        if (stored?.let { it.userId == userId && it.origin == origin } == true) return
        if (!tied && state.get(identityKey(userId)) != null) state.set(identityKey(userId), null)
        if (emailBinding(origin, emailNorm)?.first == userId) state.set(emailBindingKey(origin, emailNorm), null)
    }

    /**
     * "Forget the account on this device" after a deletion whose outcome is not known (spec 03 §13; behind the layer
     * above's own confirmation, never on its own), for exactly the kept session of [userId] at [origin]. Removes the kept
     * session record (its tokens, its account keys and its flags) and its quick-unlock key, as a sign-out ends it. Leaves
     * the account's identity record (`ovh.identity|<userId>`) and the address's binding, as a sign-out does: the account
     * may still exist, and a server can produce the unknown outcome by ending the session during the request; only a
     * deletion the server confirmed removes them (decided on 2026-11-19). Leaves too the pin and every record of the
     * server, other accounts' records, and what the layer above keeps (the item cache files, the deletion's own mark):
     * those are the caller's.
     * Nothing is sent here. The answer is the best-effort end of exactly that session at its server, by its own refresh
     * token, which the caller sends: where the deletion did not happen, the session must not stay open there for a device
     * that no longer holds it; where it did, the server answers it as a session it does not know. Null, and nothing
     * removed, when the kept session is not that account's.
     */
    fun forgetAfterUnknownDeletion(origin: String, userId: String): (suspend () -> Unit)? {
        val s = stored?.takeIf { it.origin == origin && it.userId == userId } ?: return null
        val token = s.refreshToken.takeUnless { s.endedByServer || s.heldAsOperator }
        forget(forgetIdentity = false)
        return token?.let { t -> { endOne(origin, t) } }
    }

    /** Flows under way, by "origin|address": how many hold each ([underWay]). */
    private val flowsUnderWay = HashMap<String, Int>()
    private val flowsLock = SynchronizedObject()

    override fun underWay(origin: String, emailNorm: String): () -> Unit {
        val key = "$origin|$emailNorm"
        synchronized(flowsLock) { flowsUnderWay[key] = (flowsUnderWay[key] ?: 0) + 1 }
        var released = false
        return {
            synchronized(flowsLock) {
                if (!released) {
                    released = true
                    val left = (flowsUnderWay[key] ?: 1) - 1
                    if (left <= 0) flowsUnderWay.remove(key) else flowsUnderWay[key] = left
                }
            }
        }
    }

    /** What flows keep for an address across their steps and restarts ([underWayWhileKept]). */
    private val keptFlows = ArrayList<(String, String) -> Boolean>()

    override fun underWayWhileKept(isKept: (origin: String, emailNorm: String) -> Boolean) {
        synchronized(flowsLock) { keptFlows += isKept }
    }

    /** A flow for [emailNorm] at [origin] is under way: one held for it, one held for every address there, or one kept. */
    private fun flowUnderWay(origin: String, emailNorm: String): Boolean {
        val held = synchronized(flowsLock) {
            flowsUnderWay.containsKey("$origin|$emailNorm") || flowsUnderWay.containsKey("$origin|${SessionSink.ANY_ADDRESS}")
        }
        if (held) return true
        val asked = synchronized(flowsLock) { keptFlows.toList() }
        return asked.any { it(origin, emailNorm) }
    }

    /**
     * The person's own "Forget the earlier account on this device" (decided on 2026-11-17), for the address [emailNorm] at
     * [origin], after its second confirmation: this device removes the record that ties the address there to the account
     * it first knew under it ([EMAIL_BINDING_PREFIX]), that account's identity record (unless another address's record
     * on this device names the same account), and its kept copy of that account when it keeps one (the session record and
     * its secrets, locked, ended as at the person's own sign-out, so that the app deletes the account's data:
     * [endedByOwnAct]). The earlier account's id and identity key stay, as a record of the server's
     * ([EARLIER_IDENTITY_PREFIX]): that account is refused here under any other key, also after the forgetting (decided
     * on 2026-11-19). Nothing else: what the device knows of the server (its card, its pin), every other address's
     * record, every other account, the device's own id for the address; nothing is sent to the server. After it a
     * sign-in, a registration, a recovery or a link under the address is taken as on a device that never knew the
     * address, and this device ties the address to the account it takes then.
     *
     * Only the person's act calls it: it takes nothing a server, a link or a mail says, and no flow calls it. It refuses,
     * doing nothing, where the account the address is tied to is the one this device keeps, judged by its user id and not
     * by the address alone: open here, kept under another address or at the server's new address after a followed move,
     * or held as its server's operator ([ForgetEarlier.OpenForThatAccount]); so the identity record of a kept account is
     * never taken. It refuses too while a flow for that address is under way here, from its first step to its end
     * ([underWay], [underWayWhileKept]: [ForgetEarlier.FlowUnderWay]). How many changes of a kept copy were not sent is
     * for the caller to say BEFORE this is called; this does not ask. [earlierUserId]: the account the person's confirmation
     * named; where the address's record names another one, nothing is removed ([ForgetEarlier.NoLongerHolds]). Every call
     * behind a person's confirmation passes it.
     *
     * While the secure store holds a session record it cannot read now ([sessionRecordUnreadable]: the platform answers
     * "nothing" for a record that is there, or the read throws), the record may be that very account's: nothing is removed,
     * exactly as where the kept session names it ([ForgetEarlier.OpenForThatAccount]). [knownElsewhere]: the caller found the
     * account known on this device apart from what this forgetting removes (a copy held at another server, a session kept
     * there, something of it in flight there), read before anything was removed; its identity record then stays, as it
     * stays while another address's record names it.
     */
    fun forgetEarlierAccount(origin: String, emailNorm: String, earlierUserId: String? = null, knownElsewhere: Boolean = false): ForgetEarlier {
        if (sessionRecordUnreadable()) return ForgetEarlier.OpenForThatAccount
        val bound = emailBinding(origin, emailNorm)
        if (earlierUserId != null && bound != null && bound.first != earlierUserId) return ForgetEarlier.NoLongerHolds
        val s = stored
        // Judged by the account, not by the address alone: the bound account is the one this device keeps (by its user
        // id, at whatever origin and under whatever address: after a followed move it is kept at the new address while
        // the record stays at the old one).
        val keptAccount = bound != null && s != null && s.userId == bound.first
        // The one copy the forgetting removes: that very account kept at this origin under this address, locked, and not
        // held as its server's operator. Kept and open, kept elsewhere, or held as the operator: nothing is removed.
        val kept = s?.takeIf { keptAccount && it.origin == origin && it.emailNorm == emailNorm }
        if (keptAccount && (kept == null || kept.heldAsOperator || synchronized(keysLock) { open } != null)) return ForgetEarlier.OpenForThatAccount
        if (flowUnderWay(origin, emailNorm)) return ForgetEarlier.FlowUnderWay
        if (bound == null) return ForgetEarlier.NothingToForget
        val removeCopy = kept != null
        if (removeCopy) end(SessionEndReason.FORGOTTEN, notify = false)
        val boundUser = bound.first
        // The earlier account's id and its identity key stay, kept with the server's records (decided on 2026-11-19): that
        // account never comes back on this device under another key. Written before the address's record goes.
        if (TrustGrammar.isUuid(boundUser) && Bytes.fromB64Exact(bound.second, 32) != null) state.set(earlierKeyKey(origin, boundUser), bound.second)
        state.set(emailBindingKey(origin, emailNorm), null)
        // A store that cannot list its keys cannot tell: the identity record then stays (the safer side). It stays too
        // while any other address's record names the account, and while the device keeps that account (never here: such
        // a case answered above, and the copy just removed is no longer kept).
        val namedElsewhere = state.keys()?.any { k -> k.startsWith(EMAIL_BINDING_PREFIX) && state.get(k)?.substringBefore('|') == boundUser } ?: true
        if (!namedElsewhere && !knownElsewhere && stored?.userId != boundUser) state.set(identityKey(boundUser), null)
        // A session record in the secure store that this keeper cannot read (never loaded, so [stored] is null; it would be
        // overwritten at the next sign-in) goes too where nothing readable is lost: it names the forgotten account, or it
        // is not JSON at all. One that names another account, or that is JSON without a user id, stays.
        val unreadableRemoved = stored == null && secure.get(KEY)?.let { unreadableRecordGoes(it, boundUser) } == true
        if (unreadableRemoved) secure.set(KEY, null)
        return ForgetEarlier.Forgotten(boundUser, removeCopy, unreadableRemoved)
    }

    /**
     * A forgetting of [userId] at [origin] that was begun and cut after the address's record went is finished: its identity
     * record goes, as [forgetEarlierAccount] would have removed it, where no address's record on this device names that
     * account and this device does not keep it. The key stays on record as the forgetting keeps it ([EARLIER_IDENTITY_PREFIX]),
     * written from the identity record where the cut came before that. A store that cannot list its keys cannot tell: the
     * identity record then stays (the safer side). For the layer that settles a forgetting begun; it sends nothing.
     * [knownElsewhere]: as at [forgetEarlierAccount], the identity record then stays.
     */
    fun finishForgetting(origin: String, userId: String, knownElsewhere: Boolean = false) {
        if (stored?.userId == userId) return
        val keys = state.keys() ?: return
        if (keys.any { k -> k.startsWith(EMAIL_BINDING_PREFIX) && state.get(k)?.substringBefore('|') == userId }) return
        val key = state.get(identityKey(userId)) ?: return
        if (state.get(earlierKeyKey(origin, userId)) == null) {
            if (!TrustGrammar.isUuid(userId) || Bytes.fromB64Exact(key, 32) == null) return
            state.set(earlierKeyKey(origin, userId), key)
        }
        if (!knownElsewhere) state.set(identityKey(userId), null)
    }

    /**
     * The secure store holds a session record it cannot read now: the read throws, or the store says so
     * ([SessionRecordReadability]; read after the record, so that a store that tells it at each read tells it of this
     * one). A record the store hands over and this keeper cannot decode is not this: it is read, and [forgetEarlierAccount]
     * judges it by what it names.
     */
    fun sessionRecordUnreadable(): Boolean {
        if (runCatching { secure.get(KEY) }.isFailure) return true
        return (secure as? SessionRecordReadability)?.sessionRecordUnreadable == true
    }

    /** [text], a session record [load] could not read: true when it names [userId], or does not read as JSON at all. */
    private fun unreadableRecordGoes(text: String, userId: String): Boolean {
        val json = runCatching { WireJson.json.parseToJsonElement(text) }.getOrNull() ?: return true
        val named = ((json as? kotlinx.serialization.json.JsonObject)?.get("userId") as? kotlinx.serialization.json.JsonPrimitive)?.takeIf { it.isString }?.content
        return named == userId
    }

    /**
     * The session's server moved from [from] to [to] and the person followed the signed move (design §4.4): the
     * session goes with its namespace. It is the same instance at its new address, so from here on the session's
     * tokens are sent there and nowhere else. Nothing happens unless the kept session is [from]'s.
     */
    fun moved(from: String, to: String) {
        val s = stored?.takeIf { it.origin == from } ?: return
        // A quick-unlock key was sealed for the old address: the first unlock at the new one takes the password.
        quick?.wipe()
        stored = s.copy(origin = to)
        open?.let { o ->
            open = EstablishedSession(
                to, o.emailNorm, o.userId, o.deviceId, o.role, o.totpEnrolled, o.mustEnrollTotp, o.recoveryConfirmed, o.how,
                o.accessToken, o.refreshToken, o.accountKeys, o.account,
            ).rebuiltByKeeper()
        }
        persist()
    }

    /**
     * End a session this keeper does not own: `POST /auth/logout` on [origin] with [accessToken] as the bearer
     * (device links call it when the pin step refuses a pickup, §8.2 step 8). Best effort: no answer is retried.
     */
    suspend fun discard(origin: String, accessToken: String) = logout(origin, accessToken)

    private suspend fun logout(origin: String, accessToken: String) {
        // Nothing is dialed at a forked or damaged origin, a logout included (the guard refuses it): the token is only
        // forgotten here. Nor at an origin with no pin at all: the bearer goes only where a pin is in force.
        if (!pinInForce(origin)) return
        // A session the server ended keeps no token: there is nothing to end there.
        if (accessToken.isEmpty()) return
        val client = dial(origin, FixedToken(accessToken))
        try {
            client.call(WireRoute.LOGOUT, authenticated = true) { }
        } catch (e: CancellationException) {
            throw e
        } catch (_: Throwable) {
            // The session is forgotten on this device whatever the server did; its refresh token dies in 30 days.
        }
    }

    /**
     * End exactly the one session [refreshToken] belongs to at [origin] (`POST /auth/end-session`), and nothing else of
     * the device there; best effort, through the guard. Nothing is sent to an origin with no pin in force, or for an empty
     * token. The way this keeper ends a session it refuses or replaces: a logout ends every session of the device.
     */
    internal suspend fun endOne(origin: String, refreshToken: String) {
        if (!pinInForce(origin)) return
        if (refreshToken.isEmpty()) return
        dial(origin, null).endSession(refreshToken)
    }

    private class FixedToken(private val token: String) : TokenSource {
        override fun accessToken(): String = token
        override suspend fun refresh(staleAccessToken: String): Boolean = false
    }

    /**
     * [ownAct]: the person's own act ended it (every [SessionEndReason] but a left call's session, [endTakenSince]); the
     * account is noted in [endedByOwnAct] before its record goes.
     */
    private fun end(reason: SessionEndReason, notify: Boolean, ownAct: Boolean = true, why: String = reason.name) {
        stored?.let { if (ownAct) noteOwnEnd(it.origin, it.userId, why) }
        quick?.wipe()
        val o = synchronized(keysLock) {
            generation++
            open.also { open = null }
        }
        o?.account?.wipe()
        stored = null
        persist()
        lastEnd = reason
        _phase.value = KeptPhase.NONE
        onSessionEnded()
        if (notify) onEnded(reason)
    }

    // ---- Re-authentication ----

    /** The engine's [ReauthSession] over the kept session, or null when there is none. */
    fun reauthSession(): ReauthSession? {
        val s = stored ?: return null
        return object : ReauthSession {
            override val origin: String = s.origin
            override val emailNorm: String = s.emailNorm
            override suspend fun deriveCurrentAuthKey(password: CharArray): String? = (proveAuthKey(s, password) as? ReauthKey.Key)?.currentAuthKey
            override suspend fun proveCurrentAuthKey(password: CharArray): ReauthKey = proveAuthKey(s, password)
        }
    }

    /** The engine's one re-authentication path, over the kept session and this device's pins; null when signed out. */
    fun reauth(): Reauth? = reauthSession()?.let { Reauth(it) { trust.gatePins() } }

    /**
     * Spec 01 §7 ("In-session password proofs", normative): [password] is proven against this
     * device's own wrap of the account's key, under the session's own salt and KDF cost as kept in [s], and
     * `currentAuthKey` comes from that same derivation. Nothing is dialed: no value a server names now (a prelogin's
     * salt or cost) goes into it, and a password that does not open the wrap is [ReauthKey.WrongPassword] with nothing
     * sent. The key opened for the proof is wiped at once; it is never used. [password] is wiped.
     */
    private fun proveAuthKey(s: Stored, password: CharArray): ReauthKey {
        // A change whose answer never came: the pending wrap's password may be the one the server holds now.
        val p = s.pendingWrap ?: return proveWith(s.userId, s.accountKeys.kdfSalt, s.accountKeys.kdfParams, s.accountKeys.wrappedUvk, password)
        val spare = password.copyOf()
        try {
            val first = proveWith(s.userId, s.accountKeys.kdfSalt, s.accountKeys.kdfParams, s.accountKeys.wrappedUvk, password)
            if (first !is ReauthKey.WrongPassword) return first
            return proveWith(s.userId, p.kdfSalt, p.kdfParams, p.wrappedUvk, spare)
        } finally {
            spare.fill('\u0000')
        }
    }

    private fun proveWith(userId: String, kdfSalt: String, params: io.silencelen.andvari.core.crypto.KdfParams, wrappedUvk: String, password: CharArray): ReauthKey {
        // The kept cost came from a server: outside the whole fence it is never derived at, and that is never a wrong password.
        if (!io.silencelen.andvari.core.client.KdfUpgrade.withinFence(params)) {
            password.fill('\u0000')
            return ReauthKey.Refused
        }
        val salt = runCatching { Bytes.fromB64(kdfSalt) }.getOrNull()
        if (salt == null) {
            password.fill('\u0000')
            return ReauthKey.WrongPassword
        }
        val keys = try {
            PasswordKeys.derive(crypto, password, salt, params, served = true)
        } catch (e: CryptoException) {
            password.fill('\u0000')
            null
        } catch (e: IllegalArgumentException) {
            password.fill('\u0000')
            null
        } ?: return ReauthKey.WrongPassword
        return try {
            val opened = try {
                Envelope.openB64(crypto, keys.wrapKey, wrappedUvk, Ad.uvk(userId))
            } catch (e: CryptoException) {
                null
            } catch (e: IllegalArgumentException) {
                null
            }
            if (opened == null) ReauthKey.WrongPassword
            else {
                opened.fill(0)
                ReauthKey.Key(keys.authKeyB64)
            }
        } finally {
            keys.wipe()
        }
    }

    /**
     * The account's served keys changed on this device (a password change re-wraps the UVK, a kit rotation changes
     * `recoveryConfirmed`): keep [keys] so the next unlock opens with the new password.
     */
    internal fun replaceAccountKeys(keys: AccountKeys) {
        val s = stored ?: return
        // Design §2.2, strict decoding: served account-key texts are kept only in their canonical form.
        if (!io.silencelen.andvari.core.client.onboard.ServedKeyForm.canonical(keys)) return
        stored = s.copy(accountKeys = keys, recoveryConfirmed = keys.recoveryConfirmed, previousPasswordOpens = false, serverKeysNotKnown = false)
        persist()
    }

    /**
     * The master password of the kept account [userId] at [origin] was changed from this device and the server took
     * [wrap]: this device keeps exactly that wrap (the server's salt and cost), so the next unlock opens with the new
     * password and every re-authentication proves the password against the wrap the server holds too (spec 01 §7).
     * Nothing is derived here and no key is read: the wrap was sealed under the account's guard
     * before the request went, so a lock that came while the answer was on its way leaves
     * nothing to seal afterwards. Any pending wrap is settled by this answer. False, with nothing kept, when the kept
     * session is no longer that account's.
     */
    internal fun passwordChangedTo(userId: String, kdfSalt: String, kdfParams: io.silencelen.andvari.core.crypto.KdfParams, wrappedUvk: String): Boolean {
        val now = stored ?: return false
        if (now.userId != userId) return false
        // Design §2.2, strict decoding: a wrap is kept only in its canonical form (the server's answer to a change is one;
        // nothing of a text in another form is kept, and a pending wrap stays for the next opening to settle).
        if (!io.silencelen.andvari.core.client.onboard.ServedKeyForm.wrapCanonical(kdfSalt, wrappedUvk)) return false
        stored = now.copy(
            accountKeys = now.accountKeys.copy(kdfSalt = kdfSalt, kdfParams = kdfParams, wrappedUvk = wrappedUvk),
            previousPasswordOpens = false,
            pendingWrap = null,
            // The server took this device's own wrap: its keys are the ones this device knows.
            serverKeysNotKnown = false,
        )
        persist()
        quick?.passwordUsed(now.origin, userId)
        return true
    }

    /**
     * A password change of [userId] is about to be sent with this wrap. It is kept as pending
     * before the request goes, so a lost answer, a 5xx or a crash leaves this device able to open with whichever
     * password the server ends up holding; [settleWrap] settles it against the server's word.
     */
    internal fun passwordChangePending(userId: String, kdfSalt: String, kdfParams: io.silencelen.andvari.core.crypto.KdfParams, wrappedUvk: String) {
        val now = stored ?: return
        if (now.userId != userId) return
        // An unsettled pending wrap is never overwritten (its password may be the server's
        // now). The caller settles it first ([hasPendingWrap], [settleWrap]); this is the last line of that rule.
        if (now.pendingWrap != null && now.pendingWrap.wrappedUvk != wrappedUvk) return
        stored = now.copy(pendingWrap = PendingWrap(kdfSalt, kdfParams, wrappedUvk))
        persist()
    }

    /** A password change of [userId] was sent and is not settled yet: its wrap is kept as pending. */
    internal fun hasPendingWrap(userId: String): Boolean = stored?.takeIf { it.userId == userId }?.pendingWrap != null

    /**
     * The server answered that the change sent with [wrappedUvk] was not made (a wrong password, a refusal): that
     * request's pending wrap goes, and only that one: a pending wrap of another request stays.
     */
    internal fun passwordChangeNotTaken(userId: String, wrappedUvk: String) {
        val now = stored ?: return
        if (now.userId != userId || now.pendingWrap?.wrappedUvk != wrappedUvk) return
        stored = now.copy(pendingWrap = null)
        persist()
    }

    /**
     * The account's keys as the server holds them now ([served], `GET /account/keys` at an opening): a pending change
     * is settled by them. The server holds the pending wrap: it is this device's own from now on. The server holds this
     * device's wrap: the change never landed, and the pending one goes. Anything else (a change made elsewhere since)
     * leaves both, and the next answer settles it.
     */
    internal fun settleWrap(userId: String, served: AccountKeys) {
        val now = stored ?: return
        val p = now.pendingWrap ?: return
        if (now.userId != userId) return
        val own = now.accountKeys
        when {
            sameWrap(served, p.kdfSalt, p.kdfParams, p.wrappedUvk) -> passwordChangedTo(userId, p.kdfSalt, p.kdfParams, p.wrappedUvk)
            // A re-key whose request is still on its way: keys read before the server took it say nothing about it.
            sameWrap(served, own.kdfSalt, own.kdfParams, own.wrappedUvk) -> if (p.wrappedUvk != reKeyInFlight) passwordChangeNotTaken(userId, p.wrappedUvk)
        }
    }

    /** [served] is the wrap of [kdfSalt], [kdfParams] and [wrappedUvk] in all three ("known" means all three together). */
    private fun sameWrap(served: AccountKeys, kdfSalt: String, kdfParams: io.silencelen.andvari.core.crypto.KdfParams, wrappedUvk: String): Boolean =
        served.kdfSalt == kdfSalt && served.kdfParams == kdfParams && served.wrappedUvk == wrappedUvk

    // ---- The quiet re-key (spec 01 §7, "KDF upgrade") ----

    /**
     * The [generation] at which the open account was opened with the full master password: an unlock with it, or a
     * sign-in with it ([SessionHow.PASSWORD]). -1 after a quick unlock, which never counts as one. Under [keysLock].
     */
    private var fullPasswordGen = -1L

    /** The wrapped key of the re-key request on its way now, if any: [settleWrap] does not drop it meanwhile. */
    @kotlin.concurrent.Volatile
    private var reKeyInFlight: String? = null

    /**
     * The opened account whose opening already ran [reKeyAfterOpening] (or is running it now): a second call for the
     * same one answers [ReKeyOutcome.ALREADY_RAN] at once. A new opening opens a new account object. Under [keysLock].
     */
    private var reKeyOpening: EstablishedSession? = null

    /** What the last [reKeyAfterOpening] came to, for diagnostics and tests; never shown to the person. */
    var lastReKey: ReKeyOutcome? = null
        private set

    /**
     * Spec 01 §7, "KDF upgrade": called by the opening that verified the master password, right after it opened the
     * account ([unlock] answered [KeptUnlock.Unlocked], or a password sign-in was [establish]ed), with that password
     * ([password], wiped here whatever happens). When this device's own wrap's cost is below the cost the policy [policy]
     * reads through the session's client now on any figure ([io.silencelen.andvari.core.client.KdfUpgrade.belowServed]),
     * the account's key is wrapped again under the same password at the higher of the two, figure by figure, and sent as a password change
     * ([QuietReKey]), by the pending-record rule: a pending change is settled first, the new wrap is kept as pending
     * before the request goes, and the answer settles it. Before any of that, the account's keys are read once as the
     * server holds them, and a served wrap that is neither this device's own nor its pending one is tried with the same
     * password ([servedWrapAtOpening]; [lastServedWrap]).
     *
     * Nothing is done after a quick unlock or once the account opened by this opening is no longer the open one
     * ([ReKeyOutcome.NOT_FULL_PASSWORD]); [putOff] is the "not now" of an opening that must be fast (the Android
     * autofill overlay, [ReKeyOutcome.PUT_OFF]); nothing is sent under a stop or for a session its server ended. The
     * quick-unlock wrap is not touched: the account's key itself does not change. A failure of any kind is the answer
     * and changes nothing the person sees: the vault is open already, and the account opens with the same password
     * from whichever wrap this device ends up holding.
     */
    suspend fun reKeyAfterOpening(password: CharArray, putOff: Boolean = false, policy: suspend (WireClient) -> io.silencelen.andvari.core.crypto.KdfParams?): ReKeyOutcome {
        try {
            val s = stored
            val (gen, o) = synchronized(keysLock) { generation to open }
            val answer = when {
                s == null || o == null || o.userId != s.userId || o.origin != s.origin || synchronized(keysLock) { fullPasswordGen != gen } -> ReKeyOutcome.NOT_FULL_PASSWORD
                putOff -> ReKeyOutcome.PUT_OFF
                s.endedByServer || !guard.mayDial(s.origin) -> ReKeyOutcome.NO_POLICY
                else -> null
            }
            if (answer != null || s == null || o == null) {
                lastServedWrap = ServedWrap.NOT_READ
                return (answer ?: ReKeyOutcome.NOT_FULL_PASSWORD).also { lastReKey = it }
            }
            // Once per opening: a second call while the same opened account is open reads nothing, derives nothing and
            // sends nothing, so no caller can make one opening pay the served wrap's try or the re-key again.
            val first = synchronized(keysLock) {
                (reKeyOpening !== o && generation == gen && open === o).also { if (it) reKeyOpening = o }
            }
            if (!first) return ReKeyOutcome.ALREADY_RAN
            val client = clientFor(s.origin)
            // The account's keys as the server holds them, read once by this opening: the wrap there settled or tried first,
            // so that the re-key below is decided on, and proved against, the wrap the server holds.
            val served = servedWrapAtOpening(s.origin, s.userId, gen, o, client, password).also { lastServedWrap = it }
            if (served == ServedWrap.STALE) return ReKeyOutcome.STALE.also { lastReKey = it }
            val record = KeeperRecord(s.origin, s.userId, gen, o)
            return QuietReKey.run(crypto, client, o.account, record, password) { policy(client) }.also { lastReKey = it }
        } finally {
            password.fill('\u0000')
        }
    }

    /** What the last [reKeyAfterOpening] found when it read the account's keys; for diagnostics and tests, never shown. */
    var lastServedWrap: ServedWrap? = null
        private set

    /**
     * Spec 01 §7, the pending-record rule, at an opening with the full master password and the server reachable: the
     * account's keys are read as the server holds them (`GET /account/keys`). A served wrap that is this device's own or
     * its pending one is settled by that rule ([settleWrap]). One that is neither (a server that answered "done" to a
     * change it never stored, or stored one and answered with a refusal) is tried with [password], the password this
     * opening verified (borrowed, not wiped here), under the served salt and cost, and only when that cost passes the
     * fence a re-key target must pass ([io.silencelen.andvari.core.client.KdfUpgrade.withinFence]). It becomes this
     * device's own wrap only when it opens to exactly the account key this device holds: a server cannot make such a
     * wrap without the password, so it can only hand back one the person's own password made. Nothing derived here is
     * sent or kept: the keys and the opened key are wiped before this returns. A wrap that fails the fence, does not
     * open, or opens to another key changes nothing and is recorded as [ServedWrap.NOT_THIS_DEVICES]
     * ([KeptSession.serverKeysNotKnownHere]), never as a wrong password. A lock, an end or a change of the kept record
     * while it ran changes nothing ([ServedWrap.STALE]).
     */
    private suspend fun servedWrapAtOpening(origin: String, userId: String, gen: Long, opened: EstablishedSession, client: WireClient, password: CharArray): ServedWrap {
        fun mine(): Stored? = stored?.takeIf { it.userId == userId && it.origin == origin }
        fun current(): Boolean = synchronized(keysLock) { generation == gen && open === opened } && !opened.account.isWiped && mine() != null
        if (!current()) return ServedWrap.STALE
        val r = client.call(WireRoute.ACCOUNT_KEYS) { WireJson.json.decodeFromString(AccountKeys.serializer(), it) }
        // The read was a wait (rule 3): a lock that came during it ends this here.
        if (!current()) return ServedWrap.STALE
        if (r !is WireResult.Ok) return ServedWrap.NOT_READ
        val served = r.value
        val before = mine() ?: return ServedWrap.STALE
        // "Known" is the salt, the cost and the wrapped key together: a known wrap's bytes at another salt or cost are
        // not this device's wrap, and go the way of any other served wrap (the fence, the open, the comparison of keys).
        val own = before.accountKeys
        val pending = before.pendingWrap
        if (sameWrap(served, own.kdfSalt, own.kdfParams, own.wrappedUvk) ||
            (pending != null && sameWrap(served, pending.kdfSalt, pending.kdfParams, pending.wrappedUvk))
        ) {
            settleWrap(userId, served)
            serverKeysKnown(userId, origin, true)
            return ServedWrap.KNOWN
        }
        // Design §2.2, strict decoding: a served wrap in another form than the canonical one is never adopted (nor tried):
        // it is not a wrap this device takes as its own, whatever it opens to.
        if (!io.silencelen.andvari.core.client.onboard.ServedKeyForm.wrapCanonical(served.kdfSalt, served.wrappedUvk)) {
            serverKeysKnown(userId, origin, false)
            return ServedWrap.NOT_THIS_DEVICES
        }
        val opens = try {
            servedWrapOpensToOwnKey(userId, served, opened, password)
        } catch (e: io.silencelen.andvari.core.crypto.KeysGoneException) {
            // A lock during the derivation: the account's key is gone, and nothing is compared or adopted.
            return ServedWrap.STALE
        }
        if (!current()) return ServedWrap.STALE
        val now = mine() ?: return ServedWrap.STALE
        // The kept wrap changed while the password was tried (a settle, a password change): this try says nothing about it.
        if (now.accountKeys.wrappedUvk != before.accountKeys.wrappedUvk || now.pendingWrap != before.pendingWrap) return ServedWrap.STALE
        if (!opens) {
            serverKeysKnown(userId, origin, false)
            return ServedWrap.NOT_THIS_DEVICES
        }
        stored = now.copy(
            accountKeys = now.accountKeys.copy(kdfSalt = served.kdfSalt, kdfParams = served.kdfParams, wrappedUvk = served.wrappedUvk),
            serverKeysNotKnown = false,
        )
        persist()
        // The server holds this device's own wrap now: a pending change it does not hold is settled by the same rule.
        settleWrap(userId, served)
        return ServedWrap.ADOPTED
    }

    /**
     * [password] (borrowed: only a copy is derived from, and that copy is wiped) opens [served]'s wrap, under its salt and
     * cost, to exactly the key the open account [opened] holds. A cost outside the fence is never derived at. Throws
     * [io.silencelen.andvari.core.crypto.KeysGoneException] when a lock erased the account's key meanwhile.
     */
    private fun servedWrapOpensToOwnKey(userId: String, served: AccountKeys, opened: EstablishedSession, password: CharArray): Boolean =
        servedWrapOpensToKey(crypto, userId, served, opened.account, password)

    /** Keep [KeptSession.serverKeysNotKnownHere] for the kept account [userId] at [origin]; written only when it changes. */
    private fun serverKeysKnown(userId: String, origin: String, known: Boolean) {
        val now = stored ?: return
        if (now.userId != userId || now.origin != origin || now.serverKeysNotKnown == !known) return
        stored = now.copy(serverKeysNotKnown = !known)
        persist()
    }

    /** This keeper's record of the open account's wrap, for [QuietReKey]. */
    private inner class KeeperRecord(
        private val origin: String,
        override val userId: String,
        private val gen: Long,
        private val opened: EstablishedSession,
    ) : WrapRecord {
        private fun mine(): Stored? = stored?.takeIf { it.userId == userId && it.origin == origin }

        override fun ownParams() = mine()?.accountKeys?.kdfParams

        override fun hasPending() = mine()?.pendingWrap != null

        // This opening already read the account's keys ([servedWrapAtOpening]) and settled what the server's word
        // settles; no answer there leaves the pending change unsettled here too. Nothing is read twice.
        override suspend fun settle(): Boolean = mine() != null && !hasPending()

        override suspend fun prove(password: CharArray): ReauthKey {
            val r = reauth()
            if (r == null || mine() == null) {
                password.fill('\u0000')
                return ReauthKey.Refused
            }
            return r.currentAuthKey(password)
        }

        override fun current(): Boolean =
            synchronized(keysLock) { generation == gen && open === opened } && !opened.account.isWiped && mine() != null

        override fun keepPending(wrap: io.silencelen.andvari.core.client.account.WireAccountSettings.NewWrap): Boolean {
            passwordChangePending(userId, wrap.kdfSalt, wrap.kdfParams, wrap.wrappedUvk)
            return mine()?.pendingWrap?.wrappedUvk == wrap.wrappedUvk
        }

        override fun inFlight(wrap: io.silencelen.andvari.core.client.account.WireAccountSettings.NewWrap?) {
            reKeyInFlight = wrap?.wrappedUvk
        }

        override fun taken(wrap: io.silencelen.andvari.core.client.account.WireAccountSettings.NewWrap) {
            if (mine() != null) passwordChangedTo(userId, wrap.kdfSalt, wrap.kdfParams, wrap.wrappedUvk)
        }

        override fun notTaken(wrap: io.silencelen.andvari.core.client.account.WireAccountSettings.NewWrap) {
            passwordChangeNotTaken(userId, wrap.wrappedUvk)
        }
    }

    /** The KDF cost of the kept account's wrap on this device: the account's present cost (null with no session). */
    internal fun accountKdfParams(): io.silencelen.andvari.core.crypto.KdfParams? = stored?.accountKeys?.kdfParams

    private fun previousPasswordStillOpens(userId: String, origin: String) {
        val now = stored ?: return
        if (now.userId != userId || now.origin != origin || now.previousPasswordOpens) return
        stored = now.copy(previousPasswordOpens = true)
        persist()
    }

    /**
     * The local unlock an approval on this device asks for (a device link's approval, design §8.2 step 6): [password]
     * opens this device's copy of the open account's key, and it is the key held open now. Nothing is sent and the
     * open keys are left as they are. [password] is wiped. False when no account is open or the password does not open it.
     */
    internal fun passwordOpensOpenAccount(password: CharArray): Boolean {
        val s = stored
        val o = open
        if (s == null || o == null || o.userId != s.userId) {
            password.fill('\u0000')
            return false
        }
        val salt = runCatching { Bytes.fromB64(s.accountKeys.kdfSalt) }.getOrNull()
        if (salt == null) {
            password.fill('\u0000')
            return false
        }
        val keys = PasswordKeys.derive(crypto, password, salt, s.accountKeys.kdfParams, served = true) ?: return false
        val uvk = openUvk(keys, s) ?: return false
        return try {
            o.account.uvk.use { Bytes.ctEquals(uvk, it) }
        } finally {
            uvk.fill(0)
        }
    }

    /**
     * The account's kit is not confirmed: a kit was made and the server replaced the old one
     * (this device's rotation, or the account's served keys say so at an opening). Until a kit is confirmed, every unlock
     * makes a fresh one before the vault opens, as after a registration. Only ever lowers: the server's word that a kit
     * is confirmed never stops an ask this device knows is due.
     */
    internal fun recoveryUnconfirmed(userId: String) {
        val s = stored ?: return
        if (s.userId != userId || !s.recoveryConfirmed && !s.accountKeys.recoveryConfirmed) return
        stored = s.copy(recoveryConfirmed = false, accountKeys = s.accountKeys.copy(recoveryConfirmed = false))
        persist()
    }

    /** The kit was confirmed on this device (`POST /recovery/self/confirm` answered). */
    internal fun recoveryConfirmed() {
        val s = stored ?: return
        stored = s.copy(recoveryConfirmed = true, accountKeys = s.accountKeys.copy(recoveryConfirmed = true))
        persist()
    }

    // ---- Identity records ----

    /** This device's own record of [userId]'s identity key (design §2.4), or null when it has none. */
    override fun knownIdentity(userId: String): ByteArray? = state.get(identityKey(userId))?.let { Bytes.fromB64Exact(it, 32) }

    /**
     * [pub] (borrowed) is, compared in constant time, every identity key this device has on record for [kept]'s account:
     * its own record ([knownIdentity]) and the copy's (its `identityPub`, where that reads). True with no record at all.
     */
    private fun identityOnRecordIs(kept: Stored, pub: ByteArray): Boolean {
        val records = listOfNotNull(knownIdentity(kept.userId), Bytes.fromB64Exact(kept.accountKeys.identityPub, 32))
        return records.all { Bytes.ctEquals(it, pub) }
    }

    private fun recordIdentity(userId: String, pub: ByteArray) {
        if (!TrustGrammar.isUuid(userId)) return
        if (state.get(identityKey(userId)) == null) state.set(identityKey(userId), Bytes.toB64(pub))
    }

    private fun identityKey(userId: String) = "ovh.identity|$userId"

    /**
     * Spec 01 §5, "bound to the typed email": the (userId, identityPub) of the first session this
     * device took for an address at an origin, so that a server which hands the same address another user id (a
     * minted account) meets a mismatch, never a fresh pin. Written once, never from a later value.
     */
    private fun emailBindingKey(origin: String, emailNorm: String) = "$EMAIL_BINDING_PREFIX$origin|$emailNorm"

    private fun emailBinding(origin: String, emailNorm: String): Pair<String, String>? =
        state.get(emailBindingKey(origin, emailNorm))?.split('|')?.takeIf { it.size == 2 }?.let { it[0] to it[1] }

    /** The address [emailNorm] at [origin] is bound here to another user id, or to another identity key, than these. */
    internal fun emailBindingRefuses(origin: String, emailNorm: String, userId: String, pub: ByteArray): Boolean {
        val (boundUser, boundKey) = emailBinding(origin, emailNorm) ?: return false
        return boundUser != userId || boundKey != Bytes.toB64(pub)
    }

    /** The record a forgetting kept of [userId]'s identity key at [origin] ([EARLIER_IDENTITY_PREFIX]). */
    private fun earlierKeyKey(origin: String, userId: String) = "$EARLIER_IDENTITY_PREFIX$origin|$userId"

    private fun earlierKey(origin: String, userId: String): ByteArray? = state.get(earlierKeyKey(origin, userId))?.let { Bytes.fromB64Exact(it, 32) }

    /** A forgetting kept a key of [userId] at [origin], and [pub] is not it. */
    private fun earlierKeyDiffers(origin: String, userId: String, pub: ByteArray): Boolean =
        state.get(earlierKeyKey(origin, userId))?.let { it != Bytes.toB64(pub) } ?: false

    private fun recordEmailBinding(origin: String, emailNorm: String, userId: String, pub: ByteArray) {
        if (!TrustGrammar.isUuid(userId) || emailNorm.isEmpty() || emailBinding(origin, emailNorm) != null) return
        state.set(emailBindingKey(origin, emailNorm), "$userId|${Bytes.toB64(pub)}")
    }

    // ---- Persistence ----

    private fun persist() {
        val s = stored
        secure.set(KEY, s?.let { WireJson.json.encodeToString(Stored.serializer(), atRest(it)) })
    }

    private fun load(): Stored? {
        val text = secure.get(KEY) ?: return null
        val s = runCatching { WireJson.json.decodeFromString(Stored.serializer(), text) }.getOrNull() ?: return null
        if (!TrustGrammar.isUuid(s.userId) || !TrustGrammar.isUuid(s.deviceId) || SessionHow.entries.none { it.name == s.how }) return null
        // A record kept before its server's forbidding policy was applied to it loses the wrapped keys now.
        return atRest(s).also { if (it !== s) secure.set(KEY, WireJson.json.encodeToString(Stored.serializer(), it)) }
    }

    private fun how(name: String) = SessionHow.entries.firstOrNull { it.name == name } ?: SessionHow.PASSWORD

    companion object {
        /** The [secure] key the session is kept under. */
        const val KEY = "ovh.session"

        /**
         * The email binding's records (spec 01 §5): `<prefix><origin>|<emailNorm>` → `<userId>|<identityPub b64>`. Records
         * of their server: carried with a followed move and removed by "Forget this server", with the identity record of
         * each account they name there unless an address at another server still names it ([PinStore.wipeOrigin]).
         */
        const val EMAIL_BINDING_PREFIX = "ovh.identity-email|"

        /**
         * What a forgetting keeps of the earlier account ([forgetEarlierAccount]): `<prefix><origin>|<userId>` → its identity
         * public key (base64), as the address's record held it. Nothing else of the account. A per-origin record of the
         * server's ([PinStore.carryWithMoves]): it moves with a followed move and goes with "Forget this server". While it
         * stands, that account at that server is refused under any other key, as the identity fault; taken again under this
         * key, the record goes (the identity record holds the key again).
         */
        const val EARLIER_IDENTITY_PREFIX = "ovh.identity-earlier|"

        /** The [state] key of [endedByOwnAct]. */
        const val OWN_ENDS_KEY = "ovh.session.ownEnds"

        /** [OwnEnd.why]: the account's deletion was confirmed by its server ([forget] with its identity). */
        const val OWN_END_DELETED = "DELETED"

        /** [OwnEnd.why]: the session was forgotten without a word to the server ("Forget this server", and the like). */
        const val OWN_END_FORGOTTEN = "FORGOTTEN"

        /** How many takes' replaced records are remembered for [endTakenSince]. */
        private const val REPLACED_KEPT = 8
        private val REFRESH_ENDS = setOf(WireErrors.INVALID_REFRESH, WireErrors.REFRESH_REUSE, WireErrors.REFRESH_EXPIRED)

        /**
         * A refresh cut off while out is tried once more only within this long of its first try's sending (the edge
         * included). The server's grace for a replaced token is sixty seconds, and it runs from the moment the server
         * replaced the token, which is after this device sent it; the second try has to ARRIVE inside it. The ten seconds
         * between the two are the margin for the road: the first request's way to the server and its wait there before
         * the replacement, and the second request's way there.
         */
        const val REFRESH_SECOND_TRY_MS = 50_000L

        /** The refusal codes that say this build is too old for the server ([updateRequired]). */
        private val UPDATE_CODES = setOf(WireErrors.UPGRADE_REQUIRED, "update_required", "client_too_old")
    }
}

/** [inner], every answer of which is shown to [seen] (what the server said, whatever the caller does with it). */
private class AnswerWatch(private val inner: WireClient, private val seen: (WireRoute, WireResult<*>) -> Unit) : WireClient {
    override val origin: String get() = inner.origin
    override val stopped: Boolean get() = inner.stopped

    override suspend fun <T> call(
        route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T,
    ): WireResult<T> = inner.call(route, pathParams, query, bodyJson, authenticated, decode).also { seen(route, it) }

    override suspend fun <T> callBytes(
        route: WireRoute, pathParams: Map<String, String>, query: String?, body: ByteArray, authenticated: Boolean, decode: (String) -> T,
    ): WireResult<T> = inner.callBytes(route, pathParams, query, body, authenticated, decode).also { seen(route, it) }

    override suspend fun fetchBytes(route: WireRoute, pathParams: Map<String, String>, query: String?, authenticated: Boolean): WireResult<ByteArray> =
        inner.fetchBytes(route, pathParams, query, authenticated).also { seen(route, it) }

    override suspend fun fetchBytes(
        route: WireRoute, pathParams: Map<String, String>, query: String?, authenticated: Boolean, maxBytes: Long?,
    ): WireResult<ByteArray> = inner.fetchBytes(route, pathParams, query, authenticated, maxBytes).also { seen(route, it) }
}

/** The opened account's identity public key (X25519). */
internal fun io.silencelen.andvari.core.client.onboard.OpenedAccount.identityPub(): ByteArray = identity.publicKey
