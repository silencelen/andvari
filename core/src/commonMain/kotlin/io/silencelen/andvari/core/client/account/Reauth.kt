package io.silencelen.andvari.core.client.account

import io.silencelen.andvari.core.client.pin.GateDecision
import io.silencelen.andvari.core.client.pin.GateInput
import io.silencelen.andvari.core.client.pin.GatePin
import io.silencelen.andvari.core.client.pin.GatePurpose
import io.silencelen.andvari.core.client.pin.GateSession
import io.silencelen.andvari.core.client.pin.PasswordGate

/**
 * The signed-in session a re-authentication runs in, as the session keeper holds it: the origin the session
 * talks to, its account's `emailNorm`, and the derivation of `currentAuthKey`. The engine's session
 * ([io.silencelen.andvari.core.client.session.SessionKeeper]) derives it on this device, under the session's own
 * kept salt and cost, in the same pass that proves the password against the device's own wrap ([proveCurrentAuthKey]):
 * no prelogin is sent, and a wrong password sends no request at all (spec 01 §7). [deriveCurrentAuthKey] answers null
 * when no key could be derived; both are called only after [PasswordGate] said `proceed`.
 */
interface ReauthSession {
    val origin: String
    val emailNorm: String
    suspend fun deriveCurrentAuthKey(password: CharArray): String?

    /**
     * Spec 01 §7 ("In-session password proofs"): the password proven on this device first, and `currentAuthKey`
     * derived in that same pass, under the session's own salt and cost. A session that holds the device's own wrap
     * ([io.silencelen.andvari.core.client.session.SessionKeeper]) answers [ReauthKey.WrongPassword] for a password
     * that does not open it, having sent nothing. The default is [deriveCurrentAuthKey], for a session with no such wrap.
     */
    suspend fun proveCurrentAuthKey(password: CharArray): ReauthKey = deriveCurrentAuthKey(password)?.let { ReauthKey.Key(it) } ?: ReauthKey.Unreachable
}

/** What a re-authentication came to before anything was sent to a `†` route. */
sealed class ReauthKey {
    /** `currentAuthKey`, to send once to the session's origin. */
    class Key internal constructor(val currentAuthKey: String) : ReauthKey()

    /** The gate refused at the entry (no session for the account at the origin, or the origin is forked or damaged): nothing derived or sent. */
    data object Refused : ReauthKey()

    /**
     * No `currentAuthKey` could be derived ([ReauthSession.deriveCurrentAuthKey] answered null): nothing was sent. The
     * engine's own session never answers it (its proof is local); a session of another host that still derives the key
     * from a server's answer answers it when that answer was not usable.
     */
    data object Unreachable : ReauthKey()

    /**
     * The password does not open this device's own wrap of the account's key (spec 01 §7): nothing was sent, and the
     * action behind the re-authentication signs and sends nothing either.
     */
    data object WrongPassword : ReauthKey()
}

/**
 * The one re-authentication path of every `†` action in the engine (design §4.4 password rule, purpose
 * `reauth`): [PasswordGate] with this session's origin and account and this device's [pins], and only on
 * `proceed` the derivation. A forked or damaged pin of the session's origin refuses here too.
 */
class Reauth(private val session: ReauthSession, private val pins: () -> List<GatePin>) {
    /** The account this re-authentication is for: its normalised address. */
    internal val emailNorm: String get() = session.emailNorm

    /**
     * The gate alone, for a value that is not derived from the password but is still one of the account's secrets (a
     * TOTP code, design §4.4 password rule): true only when it may go to this session's origin.
     */
    internal fun proceeds(): Boolean = PasswordGate.decide(
        GateInput(
            purpose = GatePurpose.REAUTH, entry = null, payload = null, origin = session.origin,
            account = session.emailNorm, pins = pins(), session = GateSession(session.origin, session.emailNorm),
        ),
    ) == GateDecision.PROCEED

    /** [password] is wiped, whatever the answer. */
    suspend fun currentAuthKey(password: CharArray): ReauthKey {
        if (!proceeds()) {
            password.fill('\u0000')
            return ReauthKey.Refused
        }
        return try {
            session.proveCurrentAuthKey(password)
        } finally {
            password.fill('\u0000')
        }
    }
}
