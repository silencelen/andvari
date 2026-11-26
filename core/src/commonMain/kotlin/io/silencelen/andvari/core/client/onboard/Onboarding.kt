package io.silencelen.andvari.core.client.onboard

import io.silencelen.andvari.core.client.account.Fetched
import io.silencelen.andvari.core.crypto.KeyPairBytes
import io.silencelen.andvari.core.model.wire.AccountKeys

/**
 * Sign-up, registration and sign-in against the overhaul's routes (spec 03 §2, §14; design §7.2, §7.3, §8.7).
 * Every call that sends a secret-derived value runs [io.silencelen.andvari.core.client.pin.PasswordGate]
 * first; registration needs only a pin that may CREATE an account (any root, design §4.4), and a setup
 * registration none (no card exists yet; the setup root pins the card 0 this device signs).
 *
 * Passwords are [CharArray]s that the engine wipes once it has derived from them (or decided not to).
 */

/** The sign-up form's state, from the policy (a UI hint; the server enforces). */
data class SignupOffer(val mode: String, val full: Boolean, val ageConfirmRequired: Boolean, val powBits: Int)

/** `POST /signup/start`. */
sealed class SignupStart {
    /** Always the same answer whether or not the address has an account: "If no email arrives…". */
    data object Sent : SignupStart()

    /**
     * A refusal code of spec 03 §14.1 (`signup_closed`, `signup_full`, `invalid_email`, `email_domain_blocked`,
     * `age_confirm_required`, `pow_required`, `bad_pow`, `rate_limited`), or the engine's own before anything was
     * sent: `invalid_email`, `no_pin`, `instance_blocked`, `pow_too_hard` (the policy asks for more than
     * [WireOnboarding.MAX_POW_BITS] bits).
     */
    data class Refused(val code: String, val retryAfterSeconds: Long? = null) : SignupStart()

    /** `503 mail_unavailable`: "We can't send email right now." */
    data object MailUnavailable : SignupStart()
    data object Unreachable : SignupStart()
}

/** `POST /signup/verify`: a ticket bound to the address and origin, or the uniform bad code. */
sealed class SignupVerify {
    class Ticket internal constructor(
        val expiresAt: Long,
        internal val ticket: String,
        internal val emailNorm: String,
        internal val origin: String,
    ) : SignupVerify() {
        /**
         * The registration's hold on its address from this ticket to its end ([SessionSink.underWay]): released by the
         * registration's answer (all but [Registration.PasswordTooWeak], after which the person types again under the same
         * ticket) or by [Onboarding.leaveSignup].
         */
        internal var held: (() -> Unit)? = null

        internal fun release() {
            held?.invoke()
            held = null
        }
    }

    data object BadCode : SignupVerify()
    data class Refused(val code: String, val retryAfterSeconds: Long? = null) : SignupVerify()
    data object Unreachable : SignupVerify()
}

/** The person's recovery choice at registration (design §7.7); `OPERATOR` is never offered for a public card. */
enum class RecoveryChoiceKind { PRIVATE, OPERATOR }

/**
 * Operator recovery as this device may offer it at registration (design §4.5, §7.7): only for a pinned card
 * of kind `private` whose `recoveryFp` is not `none`, after the served recovery key hashed to that `recoveryFp`
 * at full length. [unsignedChange] is the first-consent walk from card 0 (FS-R2, FC-2): a `recoveryFp` change
 * that no rotation covers, so the choice shows the unsigned-change warning with "Only me" preselected. Made
 * by the engine alone; a registration re-checks it against the pin it was made from.
 */
class OperatorRecoveryOffer internal constructor(
    /** The pinned card's name and origin: the only names recovery copy uses (T2-R-f). */
    val instanceName: String,
    val origin: String,
    val unsignedChange: Boolean,
    internal val pinHash: String,
    internal val fp: String,
    internal val recoveryPub: ByteArray,
)

/**
 * The registration form. [password] is wiped by the engine once derived. [operatorOffer] and
 * [operatorUnderstood] (the "I understand that the operator could open my vault and act as me" box) are
 * required for [RecoveryChoiceKind.OPERATOR] and ignored otherwise.
 */
class RegistrationForm(
    val email: String,
    val displayName: String,
    val password: CharArray,
    val ageConfirmed: Boolean,
    val recovery: RecoveryChoiceKind,
    val deviceName: String,
    val platform: String,
    val operatorOffer: OperatorRecoveryOffer? = null,
    val operatorUnderstood: Boolean = false,
)

/** How the registration is authorised (spec 03 §14.3 `auth`). */
sealed class RegistrationAuth {
    data class Ticket(val ticket: SignupVerify.Ticket) : RegistrationAuth()

    /** A register link opened through [io.silencelen.andvari.core.client.link.LinkFlows] (its Confirm step). */
    data class RegisterLink(val step: io.silencelen.andvari.core.client.link.RecipientStep.Confirm) : RegistrationAuth()
    data class EnrolLink(val step: io.silencelen.andvari.core.client.link.RecipientStep.Confirm) : RegistrationAuth()
    data class SetupLink(val step: io.silencelen.andvari.core.client.link.RecipientStep.Confirm) : RegistrationAuth()
}

/**
 * What a confirmed link step authorises, as the link engine re-derives it from its own state (design §6.4,
 * §6.7, §6.8). Built only inside the engine; [LinkRegistrations] hands one back for a `Confirm` step.
 */
sealed class LinkRegistration {
    abstract val origin: String
    abstract val linkId: String
    internal abstract val registerToken: String

    /** A register link (§6.3): [answer] seals the 0x07 answer for the new account, or answers null when it cannot. */
    class Register internal constructor(
        override val origin: String,
        val instanceId: String,
        override val linkId: String,
        override val registerToken: String,
        internal val answer: (NewIdentity) -> String?,
    ) : LinkRegistration()

    /** A host-minted enrol link (§6.4); [boundEmailNorm] fixes the address when the link names one. */
    class Enrol internal constructor(
        override val origin: String,
        val instanceId: String,
        override val linkId: String,
        override val registerToken: String,
        val boundEmailNorm: String?,
    ) : LinkRegistration()

    /** The setup link (§6.4, §6.7): card 0 is signed from these fields after the registration. */
    class Setup internal constructor(
        override val origin: String,
        val instanceId: String,
        val name: String,
        val kind: String,
        val recoveryFp: String,
        override val linkId: String,
        override val registerToken: String,
    ) : LinkRegistration()
}

/** The new account's identity, for the answer a register link carries (§6.5). */
class NewIdentity internal constructor(
    val userId: String,
    val identityPub: ByteArray,
    internal val signing: KeyPairBytes,
    val displayName: String,
)

/** The link engine's side of a registration through a link (slice 4 binds [io.silencelen.andvari.core.client.link.LinkFlows] to it). */
interface LinkRegistrations {
    /** The registration [step] authorises, re-derived from the link engine's state; null when the step is stale. */
    fun resolve(step: io.silencelen.andvari.core.client.link.RecipientStep.Confirm): LinkRegistration?

    /**
     * The registration through [registration] succeeded and opened [session] (a register link pins its creator,
     * `compared = false`, in the new account's state, and keeps the comparison for the reveal).
     */
    suspend fun registered(registration: LinkRegistration, session: EstablishedSession)

    /**
     * The registration through [registration] was answered by the server (the link is spent there) and stopped on this
     * device all the same (the session keeper refused its session, or the answer did not open): the link's flow ends here
     * and its secret is wiped; nothing is pinned. The default does nothing.
     */
    fun stopped(registration: LinkRegistration) {}
}

/**
 * A recovery kit revealed to the person, which they must capture before the vault opens (the capture
 * gate). [groups] are the 11 display groups; [qr] the `andvari-kit:2:…` payload; [pieceId] binds the
 * confirmation to this piece; [accountId] the 32-hex short identity fingerprint printed on the kit.
 */
class RevealedKit internal constructor(
    val groups: List<String>,
    val qr: String,
    val pieceId: String,
    val accountId: String,
    internal val secret: ByteArray,
) {
    internal var challenge: List<Int>? = null
    internal var failures: Int = 0

    /** Drop the secret (the person left the capture gate, or it was confirmed). */
    fun wipe() = secret.fill(0)
}

/** What the person's type-back of three kit groups came to (design §10). */
sealed class KitConfirm {
    /** The groups matched and the server recorded the confirmation (`POST /recovery/self/confirm`). */
    data object Confirmed : KitConfirm()

    /** Not the groups asked for, or a wrong group. Ask again. */
    data object Wrong : KitConfirm()

    /** Three wrong answers: show the kit again, then a new [Onboarding.kitChallenge]. */
    data object ShowAgain : KitConfirm()

    /** The groups matched but the server did not record it ([code], or `unreachable`): try again. */
    data class Unrecorded(val code: String) : KitConfirm()
}

/** What a registration came to. */
sealed class Registration {
    /**
     * Registered and signed in; the kit must be captured ([kit]) before vault access. For setup, card 0 is signed
     * and pinned, unless [cardPending]: the upload had no clean answer, and "Finish setting up this server" runs again.
     */
    class Registered internal constructor(
        val userId: String,
        val kit: RevealedKit,
        val cardPending: Boolean = false,
        /**
         * Non-null: the account exists at the server under the chosen password, with [kit] as its kit, but the session
         * keeper refused the session (its reason: what the device keeps changed while the registration was under way) and
         * ended it there. Nothing is signed in and nothing more was done with the account here (no record sealed, no
         * contact pinned). The screen shows [kit] to be kept and says the account could not be opened on this device and
         * why; the person signs in with the chosen password once the reason is gone. Never for a setup (its card 0 was not
         * signed): that stops as [Refused] with the same reason, and its account is signed in to and set up again.
         */
        val notKept: String? = null,
    ) : Registration()

    /**
     * A refusal code of spec 03 §14.3's table (`email_taken`, `signup_full`, `link_used`, `setup_incomplete`, …), or
     * the engine's own before anything was sent: `invalid_email`, `bad_ticket` (a ticket for another address or
     * server), `email_mismatch` (a bound enrol link), `link_stale`, `card_mismatch`, `trust_gate_first`,
     * `instance_blocked`, `setup_done`, `operator_recovery_unavailable`, `stale_offer`, `consent_required`,
     * `bad_answer`; or `bad_response` when the server's answer is not the session it must be.
     */
    data class Refused(val code: String, val retryAfterSeconds: Long? = null) : Registration()

    /** The chosen password is below the local strength floor; nothing sent. */
    data object PasswordTooWeak : Registration()

    /**
     * The server's answer did not carry back the identity this device registered (design §5.2), or ([reason]
     * `self_identity_mismatch`) the address is known here under another account. Nothing was opened. [anotherAccountServed]:
     * the new account's id, set only where that refusal is the keeper's for an address tied here to ANOTHER account
     * ([SessionSink.refusalIsAnotherAccount]); null otherwise.
     */
    data class IdentityFault(val reason: String, val anotherAccountServed: String? = null) : Registration()

    /** No answer: the account may exist. The app offers sign-in. */
    data object Unknown : Registration()
}

/** What a password sign-in came to (spec 03 §2). */
sealed class SignIn {
    /**
     * Signed in. [copyUnderOtherPassword] (spec 01 §7, a sign-in over a kept account): this device kept the account,
     * none of the wraps it kept opened with the typed password, and the key the server's wrap opened did open what this
     * device's copy holds sealed under the account's key, so it is this account's key as this device knows it. The copy
     * was sealed under another master password than the one typed and now follows the server's wrap: a screen says so
     * in one line. False on every other sign-in.
     */
    class SignedIn internal constructor(
        val userId: String,
        val role: String,
        val mustEnrollTotp: Boolean,
        val recoveryConfirmed: Boolean,
        val copyUnderOtherPassword: Boolean = false,
    ) : SignIn()

    /** The uniform "wrong email, master password, or one-time code". */
    data object InvalidCredentials : SignIn()

    /**
     * `401 totp_required`: the password was right. [Onboarding.signInCode] sends the code with the keys derived
     * now; the password is not asked again. [Onboarding.cancelSignIn] drops them.
     */
    class TotpRequired internal constructor(internal val pending: PendingLogin) : SignIn()

    /** `403 link_required`: "New devices must be linked from one of yours." */
    data object LinkRequired : SignIn()

    /** The pin for the origin is not a password pin for this account: show the Trust Gate first (nothing sent). */
    data object TrustGateFirst : SignIn()

    /**
     * The served AccountKeys failed the identity checks (seed key, genesis, personal wrap, this device's record of the
     * account's key), or the session keeper refused the session ([reason] `self_identity_mismatch`): the identity fault.
     * [anotherAccountServed]: the served account's id, set only where the keeper's refusal is for an address tied here to
     * ANOTHER account ([SessionSink.refusalIsAnotherAccount]); null for the same account under another key and for every
     * other fault.
     */
    data class IdentityFault(val reason: String, val anotherAccountServed: String? = null) : SignIn()

    /**
     * A refusal code of spec 03 §2, or the engine's own: `invalid_email`, `instance_blocked` (a forked or
     * damaged pin), `kdf_refused` (served KDF parameters outside the fence, spec 05 T1), `bad_response`, and
     * [WireOnboarding.SERVER_KEYS_NOT_KNOWN_HERE]: this device keeps the account, and the key the server's wrap opened
     * is not that account's key as this device knows it; nothing this device keeps was replaced, and no session was kept.
     * Also the session layer's own refusal of the session the sign-in opened (`another_session_kept`: another account, or
     * one at another server, is kept here; `server_keys_not_known_here`), and an address bound here to another account
     * answers [IdentityFault] `self_identity_mismatch`. After every refusal once the login was answered, exactly the session
     * it opened was ended at the server.
     */
    data class Refused(val code: String, val retryAfterSeconds: Long? = null) : SignIn()
    data object Unreachable : SignIn()
}

/** A sign-in waiting for its two-step code: the derived keys, held only in memory. */
class PendingLogin internal constructor(
    internal val emailNorm: String,
    internal val email: String,
    internal val keys: PasswordKeys,
    internal val instanceId: String,
    /**
     * What this device keeps of the account at the sign-in's origin, with the typed password's wrap key under each kept
     * wrap whose salt or cost differ from the prelogin's ([KeptWrapKeys]); null when it keeps nothing there.
     */
    internal val kept: KeptWrapKeys? = null,
) {
    /**
     * The sign-in's hold on its address ([SessionSink.underWay]) while its code is asked for: released when this sign-in
     * ends ([wipe]: the code's answer, a cancel, a stop).
     */
    private var held: (() -> Unit)? = null

    internal fun holdUntilWiped(release: () -> Unit) {
        held?.invoke()
        held = release
    }

    /** Every derived key this sign-in holds, and its hold on its address. */
    internal fun wipe() {
        keys.wipe()
        kept?.wipe()
        held?.invoke()
        held = null
    }
}

/**
 * What a device keeps of an account for a sign-in over it to compare with (spec 01 §7, "a sign-in on a device that
 * already keeps this account"): public values only. [own] is the account's keys as this device keeps them (its own wrap
 * and the copy's records sealed under the account's key); [pending] the wrap of a password change sent from here whose
 * answer never came. A sink that keeps nothing between runs (the command-line tool) has none.
 */
class KeptAccountKeys internal constructor(
    internal val userId: String,
    internal val own: AccountKeys,
    internal val pending: KeptWrap?,
)

/** A wrap a device keeps: its salt (base64), its cost and the wrapped key. Public values only. */
class KeptWrap internal constructor(
    internal val kdfSalt: String,
    internal val kdfParams: io.silencelen.andvari.core.crypto.KdfParams,
    internal val wrappedUvk: String,
)

/**
 * [kept], with the typed password's wrap key derived under each kept wrap's own salt and cost where they differ from
 * the prelogin's (and pass the whole fence). Held in memory only, for the length of one sign-in; [wipe]d with it.
 */
class KeptWrapKeys internal constructor(
    internal val kept: KeptAccountKeys,
    /** Pairs of (kept wrap, the typed password's keys under it); a kept wrap at the prelogin's salt and cost uses the sign-in's own keys. */
    internal val wrapKeys: List<Pair<KeptWrap, PasswordKeys>>,
) {
    internal fun wipe() = wrapKeys.forEach { it.second.wipe() }
}

/** How the session came to be (design §8.6 `how`). */
enum class SessionHow { REGISTERED, PASSWORD, LINKED, RECOVERED }

/**
 * A session the engine opened, handed to the session layer through [SessionSink]. Every identity check of
 * design §5.2 has passed. The sink takes ownership of [account]'s keys and of the tokens.
 */
class EstablishedSession internal constructor(
    val origin: String,
    val emailNorm: String,
    val userId: String,
    val deviceId: String,
    val role: String,
    val totpEnrolled: Boolean,
    val mustEnrollTotp: Boolean,
    val recoveryConfirmed: Boolean,
    val how: SessionHow,
    internal val accessToken: String,
    internal val refreshToken: String,
    internal val accountKeys: AccountKeys,
    val account: OpenedAccount,
) {
    private val once = kotlinx.atomicfu.locks.SynchronizedObject()
    private var handed = false

    /**
     * Spec 01 §7: the wrap key under which a wrap this device keeps of the account opened to exactly this session's key,
     * set by a flow whose own comparison held that way (a password sign-in, or a device link, whose typed password opened
     * a kept wrap). The session keeper opens its own kept wrap with it before it takes this session over a copy whose
     * sealed identity seed does not open; it is a key the keeper checks, never a claim it believes, and a flow that
     * compared nothing has none to give. Taken once, by the keeper, which wipes it.
     */
    private var keptWrapKey: ByteArray? = null

    internal fun giveKeptWrapKey(key: ByteArray?) = kotlinx.atomicfu.locks.synchronized(once) {
        keptWrapKey?.fill(0)
        keptWrapKey = key
    }

    internal fun takeKeptWrapKey(): ByteArray? = kotlinx.atomicfu.locks.synchronized(once) { keptWrapKey.also { keptWrapKey = null } }

    /**
     * The session's token pair, handed over ONCE, to the host that keeps it (a host that holds the pair itself between
     * runs, such as the command-line tool): every later call answers null. A session rebuilt by [reopened] hands out
     * nothing (the host gave the tokens in). The engine's own keeper never calls it.
     */
    fun takeTokens(): SessionTokens? = kotlinx.atomicfu.locks.synchronized(once) {
        if (handed) null else SessionTokens(accessToken, refreshToken).also { handed = true }
    }

    /**
     * This session as the engine's keeper rebuilds it from what it keeps (at each unlock, after a followed move): it
     * hands out no tokens, ever ([takeTokens] answers null). Only the session a sign-in made hands
     * its pair over, once.
     */
    internal fun rebuiltByKeeper(): EstablishedSession = also { kotlinx.atomicfu.locks.synchronized(once) { handed = true } }

    /**
     * Spec 01 §7 ("In-session password proofs") for a host that holds this session itself (the command-line tool):
     * [password] is proven against this session's own wrap of the account's key, under its own kept salt and KDF cost,
     * in ONE pass, and `currentAuthKey` comes from that same derivation. Nothing is dialed. The answer is only a
     * [io.silencelen.andvari.core.client.account.ReauthKey]: [io.silencelen.andvari.core.client.account.ReauthKey.Key]
     * for the right password, `WrongPassword` for one that does not open the wrap, `Refused` when the kept salt or cost
     * cannot be used (a cost outside the fence). No key, wrap key or opened key leaves; [password] is wiped. It does not
     * run the password gate: the caller asks its gate first, as [io.silencelen.andvari.core.client.account.Reauth] does.
     *
     * The session's own wrap is the one it was opened over until a password change made through it is taken
     * ([passwordChanged]); while a change's answer is unknown ([passwordChangePending]) a password the own wrap refuses
     * is tried against the pending one too, so either password proves until it is settled. A host no longer rebuilds a
     * session to prove the new password.
     */
    fun proveAuthKey(crypto: io.silencelen.andvari.core.crypto.CryptoProvider, password: CharArray): io.silencelen.andvari.core.client.account.ReauthKey {
        val (own, pending) = kotlinx.atomicfu.locks.synchronized(once) { ownWrap to pendingWrap }
        // A change whose answer never came: the pending wrap's password may be the one the server holds now, so it is
        // tried when the session's own wrap says wrong password (as the engine's own keeper does).
        if (pending == null) return proveWith(crypto, own, password)
        val spare = password.copyOf()
        try {
            val first = proveWith(crypto, own, password)
            if (first !is io.silencelen.andvari.core.client.account.ReauthKey.WrongPassword) return first
            return proveWith(crypto, pending, spare)
        } finally {
            spare.fill('\u0000')
        }
    }

    /** A wrap of the account's key under a password: its salt, its KDF cost and the wrapped key. Never a key. */
    private class ProofWrap(val kdfSalt: String, val kdfParams: io.silencelen.andvari.core.crypto.KdfParams, val wrappedUvk: String) {
        /** The same wrap in all three: salt, cost and wrapped key ("known" means all three together). */
        fun sameAs(k: AccountKeys): Boolean = kdfSalt == k.kdfSalt && kdfParams == k.kdfParams && wrappedUvk == k.wrappedUvk
    }

    /** The wrap [proveAuthKey] proves against: the one this session was opened over, until a change the server took. */
    private var ownWrap = ProofWrap(accountKeys.kdfSalt, accountKeys.kdfParams, accountKeys.wrappedUvk)

    /** The wrap of a password change sent from here whose answer never came: either password proves until it is settled. */
    private var pendingWrap: ProofWrap? = null

    /**
     * A password change of this account is about to be sent with [wrap] (the engine's own, from
     * [io.silencelen.andvari.core.client.account.WireAccountSettings.changeWrap]'s before-send hook): it is held as
     * pending, so that while the answer is unknown either password proves ([proveAuthKey]). For a host that holds this
     * session itself (the command-line tool); the engine's keeper keeps its own. No key and no wrap key is handed out.
     */
    fun passwordChangePending(wrap: io.silencelen.andvari.core.client.account.WireAccountSettings.NewWrap): Boolean = kotlinx.atomicfu.locks.synchronized(once) {
        // An unsettled pending wrap is never replaced by another change's (its password may be
        // the server's now). False, and nothing held: settle the first (the server's keys), then send the second.
        val p = pendingWrap
        if (p != null && p.wrappedUvk != wrap.wrappedUvk) {
            false
        } else {
            pendingWrap = ProofWrap(wrap.kdfSalt, wrap.kdfParams, wrap.wrappedUvk)
            true
        }
    }

    /** A change sent through this session is not settled yet: its wrap is held as pending. */
    fun hasPendingWrap(): Boolean = kotlinx.atomicfu.locks.synchronized(once) { pendingWrap != null }

    /**
     * The server took the password change sent with [wrap] (`Reauthed.Done`): it is this session's own wrap from now on,
     * and every later proof is against the new password only. Any pending wrap is settled by it.
     */
    fun passwordChanged(wrap: io.silencelen.andvari.core.client.account.WireAccountSettings.NewWrap) {
        kotlinx.atomicfu.locks.synchronized(once) {
            ownWrap = ProofWrap(wrap.kdfSalt, wrap.kdfParams, wrap.wrappedUvk)
            pendingWrap = null
        }
    }

    /**
     * The server answered that the change sent with [wrap] was not made (a wrong password, a refusal, no session): that
     * request's pending wrap goes, and no other one.
     */
    fun passwordChangeNotTaken(wrap: io.silencelen.andvari.core.client.account.WireAccountSettings.NewWrap) {
        kotlinx.atomicfu.locks.synchronized(once) { if (pendingWrap?.wrappedUvk == wrap.wrappedUvk) pendingWrap = null }
    }

    /**
     * Spec 01 §7, "KDF upgrade", for a host that holds this session itself (the command-line tool): called by the opening
     * that verified [password] (a reopen through [AccountOpen.openWithPassword] and [reopened], or a password sign-in),
     * right after it, with that password (wiped here whatever happens). The policy is read through [client] (the session's
     * own, bearer included); when its cost is a legitimate upgrade of this session's own wrap's
     * ([io.silencelen.andvari.core.client.KdfUpgrade.shouldUpgrade]), the account's key is wrapped again under the same
     * password at that cost and sent as a password change, by the pending-record rule, the proof through [reauth] (the
     * host's one re-authentication: its password gate, then its proof against this session's own wrap). The answer
     * settles this session's wrap as a password change does ([passwordChanged], [passwordChangeNotTaken]). Nothing of it
     * is for the person to see: every answer leaves the account openable with the same password.
     */
    suspend fun reKeyAfterOpening(
        crypto: io.silencelen.andvari.core.crypto.CryptoProvider,
        client: io.silencelen.andvari.core.client.net.WireClient,
        reauth: io.silencelen.andvari.core.client.account.Reauth,
        password: CharArray,
    ): io.silencelen.andvari.core.client.session.ReKeyOutcome {
        val session = this
        val record = object : io.silencelen.andvari.core.client.session.WrapRecord {
            override val userId: String = session.userId
            override fun ownParams() = kotlinx.atomicfu.locks.synchronized(once) { ownWrap.kdfParams }
            override fun hasPending() = hasPendingWrap()
            override suspend fun settle(): Boolean {
                val r = client.call(io.silencelen.andvari.core.model.wire.WireRoute.ACCOUNT_KEYS) {
                    io.silencelen.andvari.core.model.wire.WireJson.json.decodeFromString(AccountKeys.serializer(), it)
                }
                if (r is io.silencelen.andvari.core.client.net.WireResult.Ok) {
                    kotlinx.atomicfu.locks.synchronized(once) {
                        val p = pendingWrap
                        // "Known" is the salt, the cost and the wrapped key together.
                        when {
                            p != null && p.sameAs(r.value) -> { ownWrap = p; pendingWrap = null }
                            ownWrap.sameAs(r.value) -> if (p?.wrappedUvk != inFlight) pendingWrap = null
                        }
                    }
                }
                return !hasPendingWrap()
            }
            override suspend fun prove(password: CharArray) = reauth.currentAuthKey(password)
            override fun current() = !account.isWiped
            override fun keepPending(wrap: io.silencelen.andvari.core.client.account.WireAccountSettings.NewWrap) = passwordChangePending(wrap)
            override fun inFlight(wrap: io.silencelen.andvari.core.client.account.WireAccountSettings.NewWrap?) {
                kotlinx.atomicfu.locks.synchronized(once) { inFlight = wrap?.wrappedUvk }
            }
            override fun taken(wrap: io.silencelen.andvari.core.client.account.WireAccountSettings.NewWrap) = passwordChanged(wrap)
            override fun notTaken(wrap: io.silencelen.andvari.core.client.account.WireAccountSettings.NewWrap) = passwordChangeNotTaken(wrap)
        }
        val policy: suspend () -> io.silencelen.andvari.core.crypto.KdfParams? = {
            val r = client.call(io.silencelen.andvari.core.model.wire.WireRoute.CLIENT_POLICY) {
                io.silencelen.andvari.core.model.wire.WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.ClientPolicy.serializer(), it)
            }
            (r as? io.silencelen.andvari.core.client.net.WireResult.Ok)?.value?.kdfParams
        }
        if (!reauth.proceeds()) {
            password.fill('\u0000')
            return io.silencelen.andvari.core.client.session.ReKeyOutcome.NO_POLICY
        }
        return io.silencelen.andvari.core.client.session.QuietReKey.run(crypto, client, account, record, password, policy)
    }

    /**
     * Spec 01 §7, the pending-record rule, for a host that holds this session itself (the command-line tool, after a
     * quiet re-key whose answer may be a lie): [served] is the account's keys as the server holds them now, and
     * [password] the password this opening verified (wiped here, whatever the answer). The served wrap becomes this
     * session's own, the one every later [proveAuthKey] proves against, only when it opens to exactly the account key
     * this session holds:
     * - [io.silencelen.andvari.core.client.session.ServedWrap.KNOWN]: its salt, cost and wrapped key together are this
     *   session's own wrap or its pending one; the pending one is settled by it, and nothing is derived.
     * - [io.silencelen.andvari.core.client.session.ServedWrap.ADOPTED]: neither, its cost is inside the whole fence, and
     *   [password] opens it under its own salt and cost to the key this session holds (compared in constant time, inside
     *   the account's guard). It is this session's own wrap from now on, and a pending change is settled by it.
     * - [io.silencelen.andvari.core.client.session.ServedWrap.NOT_THIS_DEVICES]: neither, and its cost fails the fence
     *   (nothing is derived), its salt does not decode, it does not open, or it opens to another key. Nothing of this
     *   session changes: the account's keys on the server are not the ones it knows, which is never a wrong password.
     * - [io.silencelen.andvari.core.client.session.ServedWrap.STALE]: this session's keys were wiped (a lock, a sign-out)
     *   before or while it was tried. Nothing changes.
     * Nothing derived is kept or sent: the derived keys and the opened key are wiped before this returns. Only the
     * served salt, cost and wrapped key are read from [served].
     */
    fun settleServed(
        crypto: io.silencelen.andvari.core.crypto.CryptoProvider,
        served: AccountKeys,
        password: CharArray,
    ): io.silencelen.andvari.core.client.session.ServedWrap {
        try {
            if (account.isWiped) return io.silencelen.andvari.core.client.session.ServedWrap.STALE
            val known = kotlinx.atomicfu.locks.synchronized(once) {
                val p = pendingWrap
                when {
                    p != null && p.sameAs(served) -> { ownWrap = p; pendingWrap = null; true }
                    ownWrap.sameAs(served) -> { if (p != null && p.wrappedUvk != inFlight) pendingWrap = null; true }
                    else -> false
                }
            }
            if (known) return io.silencelen.andvari.core.client.session.ServedWrap.KNOWN
            val opens = try {
                io.silencelen.andvari.core.client.session.servedWrapOpensToKey(crypto, userId, served, account, password)
            } catch (e: io.silencelen.andvari.core.crypto.KeysGoneException) {
                return io.silencelen.andvari.core.client.session.ServedWrap.STALE
            }
            if (!opens) return io.silencelen.andvari.core.client.session.ServedWrap.NOT_THIS_DEVICES
            kotlinx.atomicfu.locks.synchronized(once) {
                ownWrap = ProofWrap(served.kdfSalt, served.kdfParams, served.wrappedUvk)
                // The server holds this session's own wrap now: a pending change it does not hold is settled by that.
                val p = pendingWrap
                if (p != null && p.wrappedUvk != inFlight) pendingWrap = null
            }
            return io.silencelen.andvari.core.client.session.ServedWrap.ADOPTED
        } finally {
            password.fill('\u0000')
        }
    }

    /** The wrapped key of a re-key request on its way now: a settle meanwhile does not drop its pending wrap. */
    private var inFlight: String? = null

    private fun proveWith(
        crypto: io.silencelen.andvari.core.crypto.CryptoProvider, wrap: ProofWrap, password: CharArray,
    ): io.silencelen.andvari.core.client.account.ReauthKey {
        val salt = runCatching { io.silencelen.andvari.core.crypto.Bytes.fromB64(wrap.kdfSalt) }.getOrNull()
        if (salt == null) {
            password.fill('\u0000')
            return io.silencelen.andvari.core.client.account.ReauthKey.Refused
        }
        val keys = try {
            PasswordKeys.derive(crypto, password, salt, wrap.kdfParams, served = true)
        } catch (e: io.silencelen.andvari.core.crypto.CryptoException) {
            null
        } catch (e: IllegalArgumentException) {
            null
        } finally {
            password.fill('\u0000')
        } ?: return io.silencelen.andvari.core.client.account.ReauthKey.Refused
        return try {
            val opened = try {
                io.silencelen.andvari.core.crypto.Envelope.openB64(crypto, keys.wrapKey, wrap.wrappedUvk, io.silencelen.andvari.core.crypto.Ad.uvk(userId))
            } catch (e: io.silencelen.andvari.core.crypto.CryptoException) {
                null
            } catch (e: IllegalArgumentException) {
                null
            }
            if (opened == null) {
                io.silencelen.andvari.core.client.account.ReauthKey.WrongPassword
            } else {
                opened.fill(0)
                io.silencelen.andvari.core.client.account.ReauthKey.Key(keys.authKeyB64)
            }
        } finally {
            keys.wipe()
        }
    }

    companion object {
        /**
         * An established session rebuilt from the tokens a host kept and the account its password just opened
         * ([AccountOpen.openWithPassword] over [keys]): tokens in, none out ([takeTokens] answers null). Null, and nothing
         * built, when [account] is not the account [userId] names (another account's keys never stand behind these
         * tokens), when a token is empty, or when [keys] is not that account's (its served identity key differs).
         */
        fun reopened(
            origin: String, emailNorm: String, userId: String, deviceId: String, role: String, totpEnrolled: Boolean,
            mustEnrollTotp: Boolean, how: SessionHow, accessToken: String, refreshToken: String, keys: AccountKeys, account: OpenedAccount,
        ): EstablishedSession? {
            if (account.userId != userId || accessToken.isEmpty() || refreshToken.isEmpty()) return null
            val served = io.silencelen.andvari.core.crypto.Bytes.fromB64Exact(keys.identityPub, 32) ?: return null
            if (!io.silencelen.andvari.core.crypto.Bytes.ctEquals(served, account.identity.publicKey)) return null
            return EstablishedSession(
                origin, emailNorm, userId, deviceId, role, totpEnrolled, mustEnrollTotp, keys.recoveryConfirmed, how, accessToken, refreshToken, keys, account,
            ).also { it.handed = true }
        }
    }
}

/** A session's token pair, as [EstablishedSession.takeTokens] hands it over once. */
class SessionTokens internal constructor(val accessToken: String, val refreshToken: String)

/**
 * The session layer's side. [established] is called once per session, before the engine's result returns;
 * from then on an authenticated call on the same origin's [io.silencelen.andvari.core.client.net.WireClient]
 * carries this session (the engine's later steps in the same flow, such as the setup card upload or the kit
 * confirmation, rely on it).
 */
fun interface SessionSink {
    suspend fun established(session: EstablishedSession)

    /**
     * What this device keeps of an account at [origin] that a password sign-in there would replace (spec 01 §7): the
     * sign-in compares the key it opened with it before anything is handed to [established]. Null (the default): it
     * keeps nothing to compare with, and the sign-in's own checks are all there is.
     */
    fun keptForSignIn(origin: String): KeptAccountKeys? = null

    /**
     * A session the server opened at [origin] that is not handed to [established] (a refusal on this device after the
     * login or commit was answered): exactly that session is ended there, by its own [refreshToken] (`POST
     * /auth/end-session`), best effort, and no other session of the device. The default sends nothing.
     */
    suspend fun notTaken(origin: String, accessToken: String, refreshToken: String) {}

    /**
     * [session] handed over as [established] does, answering why it was not kept (the sink then ended it itself), or null
     * when it was kept. The default keeps every session.
     */
    suspend fun take(session: EstablishedSession): String? {
        established(session)
        return null
    }

    /**
     * Asked before a flow sends what commits at the server (a recovery's commit, a registration, a device link's
     * pickup), and wherever the answer is known earlier, before anything is sent at all: the reason [take] would refuse a
     * session of [userId] at [origin] for the address [emailNorm] as this device stands now, or null when it would take
     * it as far as can be told beforehand. [userId] null: what [origin] alone decides (a session kept at another origin,
     * or an account held as its server's operator there); [emailNorm] or [userId] null: the address's binding is not
     * compared, and [identityPub] null: only its user id. A no stops the flow with nothing sent and nothing changed at the
     * server. The default answers null: such a sink is asked only at [take].
     */
    fun wouldRefuse(origin: String, emailNorm: String?, userId: String?, identityPub: ByteArray? = null): String? = null

    /**
     * Of an identity refusal ([AccountOpen.SELF_IDENTITY_MISMATCH], from [wouldRefuse] or [take]) of the account [userId]
     * served with [identityPub] for [emailNorm] at [origin]: true only where the address is tied here to ANOTHER account
     * than [userId] and nothing this device knows of [userId]'s key differs ([io.silencelen.andvari.core.client.session
     * .SessionKeeper.refusalIsAnotherAccount]); false for the same account under another key, and wherever it cannot be
     * told. Only where it is true may the layer above offer to forget the earlier account. The default: false.
     */
    fun refusalIsAnotherAccount(origin: String, emailNorm: String, userId: String, identityPub: ByteArray?): Boolean = false

    /**
     * The user id of the account this device keeps at [origin] under the address [emailNorm] (its copy, in whatever state:
     * open, locked, signed out by its server, held as its server's operator), or null when it keeps none there under that
     * address. An answer that names the account for that address (a request for the operator's help) is held to it before
     * the person is asked anything: the answer's own id never decides what it is compared with. The default keeps nothing.
     */
    fun keptAccountFor(origin: String, emailNorm: String): String? = null

    /**
     * What this device knows of the address [emailNorm] at [origin]: the account it is bound to here and where that account
     * stands ([io.silencelen.andvari.core.client.session.SessionKeeper.addressBinding]); null when no record ties it. Facts
     * only. The default knows none.
     */
    fun addressBinding(origin: String, emailNorm: String): io.silencelen.andvari.core.client.session.AddressBinding? = null

    /**
     * The refresh token of the session a password sign-in for [emailNorm] at [origin] replaces, to name in the login
     * ([io.silencelen.andvari.core.model.wire.LoginRequest.replacesRefreshToken]): only when this device keeps a session
     * of that account there that still holds its tokens, and the login is made on that session's own device row
     * ([deviceId], the id the login sends); null otherwise, and for a login that sends no device id. The server ends
     * that session itself when the sign-in has succeeded; nothing else is sent for it. The default names none.
     */
    fun signInReplaces(origin: String, emailNorm: String, deviceId: String?): String? = null

    /**
     * A flow that can end in a take for the address [emailNorm] at [origin] is under way until the answer is called, from
     * its first step to its end, across its steps: a sign-in through its two-step code, a registration from its ticket,
     * a recovery from its start to its commit, a device link from its start to its pickup. While one is, this device does
     * not forget the earlier account under that address
     * ([io.silencelen.andvari.core.client.session.SessionKeeper.forgetEarlierAccount]). [emailNorm] [ANY_ADDRESS]: every
     * address at [origin] (a device link before its account is named). Calling the answer more than once releases once.
     * The default holds nothing.
     */
    fun underWay(origin: String, emailNorm: String): () -> Unit = {}

    /**
     * [isKept] answers whether a flow keeps something on this device for the address at the origin (a request for the
     * operator's help, for as long as it is kept, across restarts); while it answers yes, that address counts as under way
     * ([underWay]). Registered once by the flow that keeps it. The default asks nothing.
     */
    fun underWayWhileKept(isKept: (origin: String, emailNorm: String) -> Boolean) {}

    /**
     * This device's own record of [userId]'s identity key (design §2.4), or null when it has none: what a flow that is
     * handed no such record by its host (the device link's pickup) holds the account it opens to. The default has none.
     */
    fun knownIdentity(userId: String): ByteArray? = null

    companion object {
        /** [underWay]'s address for a flow that holds every address at its origin (one whose account is not named yet). */
        const val ANY_ADDRESS = ""
    }
}

/** Onboarding for one origin. */
interface Onboarding {
    val origin: String

    /** `GET /client-policy`'s `signup` block: which sign-up UI to show (a hint; the server enforces). */
    suspend fun signupOffer(): Fetched<SignupOffer>

    /** Start sign-up; computes the proof of work in the background when `powBits > 0` ([onProgress] 0..1). */
    suspend fun signupStart(email: String, ageConfirmed: Boolean, onProgress: (Float) -> Unit = {}): SignupStart

    suspend fun signupVerify(email: String, code: String): SignupVerify

    /** Operator recovery as it may be offered on this origin's pinned card, or null when it is not offered. */
    suspend fun operatorRecoveryOffer(): OperatorRecoveryOffer?

    /** Register through [auth]: genesis, personal vault, personal wrap, kit, recovery posture and the first device. */
    suspend fun register(auth: RegistrationAuth, form: RegistrationForm): Registration

    /**
     * The person left the registration [ticket] was for without registering: the flow under way for its address ends
     * ([SessionSink.underWay]). Nothing is sent. The default does nothing.
     */
    fun leaveSignup(ticket: SignupVerify.Ticket) {}

    /** Password sign-in; sends the device's `deviceSecret` always and its `deviceId` when it holds one (§8.7). */
    suspend fun signIn(email: String, password: CharArray, totp: String? = null): SignIn

    /** The two-step code for [step]. */
    suspend fun signInCode(step: SignIn.TotpRequired, code: String): SignIn

    /** Abandon [step]: its derived keys are wiped. */
    fun cancelSignIn(step: SignIn.TotpRequired)

    /** The three group indices (1..11, CSPRNG) the person is asked to type back; a new set after [KitConfirm.ShowAgain]. */
    fun kitChallenge(kit: RevealedKit): List<Int>

    /** The person typed back the groups of [kitChallenge] (design §10); on a match, `POST /recovery/self/confirm`. */
    suspend fun confirmKit(kit: RevealedKit, typed: Map<Int, String>): KitConfirm
}
