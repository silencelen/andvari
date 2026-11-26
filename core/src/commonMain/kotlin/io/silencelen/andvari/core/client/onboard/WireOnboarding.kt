package io.silencelen.andvari.core.client.onboard

import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.Strength
import io.silencelen.andvari.core.client.account.Fetched
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.pin.GateDecision
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.client.pin.GateInput
import io.silencelen.andvari.core.client.pin.GatePayload
import io.silencelen.andvari.core.client.pin.GatePurpose
import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.pin.InstanceTrust
import io.silencelen.andvari.core.client.pin.PasswordGate
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.client.recovery.EscrowRules
import io.silencelen.andvari.core.client.recovery.RecoveryMirror
import io.silencelen.andvari.core.client.state.AccountMerge
import io.silencelen.andvari.core.client.state.AccountStateWrite
import io.silencelen.andvari.core.client.state.RecoveryRecord
import io.silencelen.andvari.core.client.state.StoredAccountState
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.Fingerprint
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.KeyPairBytes
import io.silencelen.andvari.core.crypto.MemberRecovery
import io.silencelen.andvari.core.model.wire.ClientPolicy
import io.silencelen.andvari.core.model.wire.EscrowUpload
import io.silencelen.andvari.core.model.wire.InstanceCardPut
import io.silencelen.andvari.core.model.wire.InstanceCardPutResponse
import io.silencelen.andvari.core.model.wire.InstanceResponse
import io.silencelen.andvari.core.model.wire.LoginRequest
import io.silencelen.andvari.core.model.wire.MemberRecoveryBlock
import io.silencelen.andvari.core.model.wire.PersonalVaultUpload
import io.silencelen.andvari.core.model.wire.PersonalWrap
import io.silencelen.andvari.core.model.wire.PreloginRequest
import io.silencelen.andvari.core.model.wire.PreloginResponse
import io.silencelen.andvari.core.model.wire.RecoveryChoice
import io.silencelen.andvari.core.model.wire.RecoverySelfConfirmRequest
import io.silencelen.andvari.core.model.wire.RegisterAuth
import io.silencelen.andvari.core.model.wire.RegisterRequest
import io.silencelen.andvari.core.model.wire.SessionResponse
import io.silencelen.andvari.core.model.wire.SignupPow
import io.silencelen.andvari.core.model.wire.SignupStartRequest
import io.silencelen.andvari.core.model.wire.SignupStartResponse
import io.silencelen.andvari.core.model.wire.SignupVerifyRequest
import io.silencelen.andvari.core.model.wire.SignupVerifyResponse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.AccountGenesis
import io.silencelen.andvari.core.trust.CardFields
import io.silencelen.andvari.core.trust.Checked
import io.silencelen.andvari.core.trust.GenesisFields
import io.silencelen.andvari.core.trust.InstanceCard
import io.silencelen.andvari.core.trust.InstanceKind
import io.silencelen.andvari.core.trust.RecoveryKit
import io.silencelen.andvari.core.trust.SignedFrame
import io.silencelen.andvari.core.trust.SignupPow as Pow
import io.silencelen.andvari.core.trust.TrustGrammar
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlin.coroutines.CoroutineContext

/**
 * [Onboarding] over the wire for one [origin].
 *
 * Trust: nothing derived from a password is sent before [PasswordGate] answered `proceed` for this origin, purpose
 * and account; registration derives only a NEW account's keys and needs any pin (a setup registration none, since
 * no card exists yet). Every served session passes the identity checks of design §5.2 ([AccountOpen]) against the
 * pinned card's `instanceId` before it is handed to [sink]. The `deviceSecret` is made here and never leaves the
 * core except in the device object ([KnownDevices]).
 *
 * [knownIdentity] answers this device's own earlier record of an account's identity key (design §2.4), by userId.
 * [work] runs the proof of work.
 */
class WireOnboarding(
    override val origin: String,
    private val client: WireClient,
    private val trust: InstanceTrust,
    private val devices: KnownDevices,
    private val sink: SessionSink,
    private val crypto: CryptoProvider,
    private val state: DeviceState,
    private val platform: String,
    private val deviceName: String,
    private val clock: () -> Long,
    private val links: LinkRegistrations? = null,
    /** The least cost a registration's new wrap is made at; it is raised to the cost the server serves ([register]). */
    private val kdfParams: KdfParams = KdfParams.DEFAULT,
    private val knownIdentity: (String) -> ByteArray? = { null },
    private val work: CoroutineContext = Dispatchers.Default,
) : Onboarding {
    private val mirror = RecoveryMirror(state)

    // ---------------------------------------------------------------------------------------------
    // Sign-up (design §7.2, §7.5)
    // ---------------------------------------------------------------------------------------------

    override suspend fun signupOffer(): Fetched<SignupOffer> =
        when (val r = client.call(WireRoute.CLIENT_POLICY, decode = { WireJson.json.decodeFromString(ClientPolicy.serializer(), it) })) {
            is WireResult.Ok -> r.value.signup.let { Fetched.Ok(SignupOffer(it.mode, it.full, it.ageConfirmRequired, it.powBits)) }
            is WireResult.Refused -> if (r.status >= 500) Fetched.Unreachable else Fetched.Refused(r.code)
            is WireResult.NoAnswer -> Fetched.Unreachable
        }

    private fun pinBlocked(): Boolean = when (trust.pinState(origin)) {
        PinState.Damaged, is PinState.Forked -> true
        else -> false
    }

    override suspend fun signupStart(email: String, ageConfirmed: Boolean, onProgress: (Float) -> Unit): SignupStart {
        val emailNorm = TrustGrammar.emailNorm(email) ?: return SignupStart.Refused(INVALID_EMAIL)
        if (pinBlocked()) return SignupStart.Refused(INSTANCE_BLOCKED)
        if (trust.pinFor(origin) == null) return SignupStart.Refused(NO_PIN)
        val offer = when (val o = signupOffer()) {
            is Fetched.Ok -> o.value
            is Fetched.Refused -> return SignupStart.Refused(o.code)
            Fetched.Unreachable -> return SignupStart.Unreachable
        }
        val pow = if (offer.powBits > 0) {
            if (offer.powBits > MAX_POW_BITS) return SignupStart.Refused(POW_TOO_HARD)
            val date = utcDate(clock())
            val nonce = solve(emailNorm, date, offer.powBits, onProgress) ?: return SignupStart.Refused(POW_TOO_HARD)
            SignupPow(date, nonce)
        } else {
            null
        }
        val body = WireJson.json.encodeToString(SignupStartRequest.serializer(), SignupStartRequest(email, ageConfirmed, pow))
        return when (val r = client.call(WireRoute.SIGNUP_START, bodyJson = body, decode = { WireJson.json.decodeFromString(SignupStartResponse.serializer(), it) })) {
            is WireResult.Ok -> if (r.value.status == SignupStartResponse.SENT) SignupStart.Sent else SignupStart.Unreachable
            is WireResult.Refused -> when {
                r.code == "mail_unavailable" -> SignupStart.MailUnavailable
                r.status >= 500 -> SignupStart.Unreachable
                else -> SignupStart.Refused(r.code, r.retryAfterSeconds)
            }
            is WireResult.NoAnswer -> SignupStart.Unreachable
        }
    }

    /** The proof-of-work search on [work], in slices with progress between them; cancellable. */
    private suspend fun solve(emailNorm: String, date: String, bits: Int, onProgress: (Float) -> Unit): Long? = withContext(work) {
        val expected = 1L shl bits
        var from = 0L
        while (from < POW_SEARCH_LIMIT) {
            ensureActive()
            Pow.search(crypto, emailNorm, date, bits, from, POW_SLICE)?.let {
                onProgress(1f)
                return@withContext it
            }
            from += POW_SLICE
            onProgress(minOf(0.99f, from.toFloat() / expected.toFloat()))
        }
        null
    }

    override suspend fun signupVerify(email: String, code: String): SignupVerify {
        val emailNorm = TrustGrammar.emailNorm(email) ?: return SignupVerify.Refused(INVALID_EMAIL)
        if (code.length != 6 || !code.all { it in '0'..'9' }) return SignupVerify.BadCode
        val body = WireJson.json.encodeToString(SignupVerifyRequest.serializer(), SignupVerifyRequest(email, code))
        return when (val r = client.call(WireRoute.SIGNUP_VERIFY, bodyJson = body, decode = { WireJson.json.decodeFromString(SignupVerifyResponse.serializer(), it) })) {
            // From its ticket the registration is a flow under way for the address, until it is answered or left.
            is WireResult.Ok -> if (TrustGrammar.isB64_32(r.value.signupTicket)) {
                SignupVerify.Ticket(r.value.expiresAt, r.value.signupTicket, emailNorm, origin).also { it.held = sink.underWay(origin, emailNorm) }
            } else {
                SignupVerify.Refused(BAD_RESPONSE)
            }
            is WireResult.Refused -> when {
                r.code == "bad_code" -> SignupVerify.BadCode
                r.status >= 500 -> SignupVerify.Unreachable
                else -> SignupVerify.Refused(r.code, r.retryAfterSeconds)
            }
            is WireResult.NoAnswer -> SignupVerify.Unreachable
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Operator recovery at registration (design §4.5, §7.7)
    // ---------------------------------------------------------------------------------------------

    override suspend fun operatorRecoveryOffer(): OperatorRecoveryOffer? = OperatorRecovery.offer(client, trust, crypto, origin)

    // ---------------------------------------------------------------------------------------------
    // Registration (design §7.3, §5, §10)
    // ---------------------------------------------------------------------------------------------

    private class Target(val auth: (NewIdentity) -> RegisterAuth?, val instanceId: String, val card0Hash: String?, val setup: LinkRegistration.Setup?, val link: LinkRegistration?)

    override suspend fun register(auth: RegistrationAuth, form: RegistrationForm): Registration {
        val ticket = (auth as? RegistrationAuth.Ticket)?.ticket
        var answer: Registration? = null
        try {
            return heldFor(form.email) { registerHeld(auth, form) }.also { answer = it }
        } finally {
            // The ticket's flow ends with its answer (a throw included); only a password under the floor is typed again
            // under the same ticket.
            if (answer != Registration.PasswordTooWeak) ticket?.release()
        }
    }

    override fun leaveSignup(ticket: SignupVerify.Ticket) = ticket.release()

    private suspend fun registerHeld(auth: RegistrationAuth, form: RegistrationForm): Registration {
        val emailNorm = TrustGrammar.emailNorm(form.email)
        if (emailNorm == null) {
            form.password.fill('\u0000')
            return Registration.Refused(INVALID_EMAIL)
        }
        val target = when (val t = target(auth, emailNorm)) {
            is Registration -> {
                form.password.fill('\u0000')
                return t
            }
            else -> t as Target
        }
        if (!Strength.meetsMasterPasswordFloor(form.password)) {
            form.password.fill('\u0000')
            return Registration.PasswordTooWeak
        }
        // The posture, checked before any key exists.
        val operator = if (form.recovery == RecoveryChoiceKind.OPERATOR) {
            val refusal = operatorRefusal(target, form)
            if (refusal != null) {
                form.password.fill('\u0000')
                return Registration.Refused(refusal)
            }
            form.operatorOffer!!
        } else {
            null
        }
        // The new account's id, made here so that the session keeper can be asked before anything is derived or sent: a
        // device that keeps any account (a new account is never the kept one) could not keep the session the registration
        // opens, and the server would hold an account this device cannot open.
        val userId = Bytes.uuidV4FromBytes(crypto.randomBytes(16))
        keeperRefusal(emailNorm, userId)?.let {
            form.password.fill('\u0000')
            return it
        }
        // The new account's cost is the one the server serves now (no account has one yet), inside the fence, never below
        // the caller's [kdfParams] (spec 01 §7; decided on 2026-11-17). Before, the fixed default: on a server whose operator
        // raised the floor above it, every registration was refused, the operator's own setup through the setup link included.
        val cost = io.silencelen.andvari.core.client.KdfUpgrade.wrapCost(io.silencelen.andvari.core.client.recovery.ServedCost.read(client), kdfParams)
        val salt = crypto.randomBytes(KdfParams.SALT_BYTES)
        val keys = PasswordKeys.derive(crypto, form.password, salt, cost, served = false) ?: return Registration.Refused(BAD_KDF)
        try {
            return registerWith(keys, target, form, emailNorm, operator, userId)
        } finally {
            keys.wipe()
        }
    }

    /** Where [auth] registers, checked against this device's own state; a [Registration] when it stops here. */
    private suspend fun target(auth: RegistrationAuth, emailNorm: String): Any {
        if (auth is RegistrationAuth.Ticket) {
            val t = auth.ticket
            if (t.origin != origin || t.emailNorm != emailNorm) return Registration.Refused(BAD_TICKET)
            val pin = registerPin(null) ?: return gateRefusal(null)
            return Target({ RegisterAuth.Ticket(t.ticket) }, pin.instanceId, pin.card0Hash, null, null)
        }
        val step = when (auth) {
            is RegistrationAuth.RegisterLink -> auth.step
            is RegistrationAuth.EnrolLink -> auth.step
            is RegistrationAuth.SetupLink -> auth.step
            is RegistrationAuth.Ticket -> error("unreachable")
        }
        val reg = links?.resolve(step) ?: return Registration.Refused(LINK_STALE)
        if (reg.origin != origin) return Registration.Refused(LINK_STALE)
        val kindMatches = when (auth) {
            is RegistrationAuth.RegisterLink -> reg is LinkRegistration.Register
            is RegistrationAuth.EnrolLink -> reg is LinkRegistration.Enrol
            is RegistrationAuth.SetupLink -> reg is LinkRegistration.Setup
            is RegistrationAuth.Ticket -> false
        }
        if (!kindMatches) return Registration.Refused(LINK_STALE)
        return when (reg) {
            is LinkRegistration.Setup -> {
                // The setup root (design §4.4): no card exists yet, so there is no pin to ask; this device pins the
                // card 0 it signs. A pin for the origin, or a served card, means setup is done.
                if (trust.pinState(origin) != PinState.None) return Registration.Refused(SETUP_DONE)
                val served = client.call(WireRoute.INSTANCE, decode = { WireJson.json.decodeFromString(InstanceResponse.serializer(), it) })
                when (served) {
                    is WireResult.Ok -> if (served.value.cards.isNotEmpty()) return Registration.Refused(SETUP_DONE)
                    is WireResult.Refused -> return if (served.status >= 500) Registration.Unknown else Registration.Refused(served.code)
                    is WireResult.NoAnswer -> return Registration.Refused(UNREACHABLE)
                }
                Target({ RegisterAuth.Setup(reg.linkId, reg.registerToken) }, reg.instanceId, null, reg, reg)
            }
            is LinkRegistration.Enrol -> {
                if (reg.boundEmailNorm != null && reg.boundEmailNorm != emailNorm) return Registration.Refused(EMAIL_MISMATCH)
                val pin = registerPin(GatePayload.L) ?: return gateRefusal(GatePayload.L)
                if (pin.instanceId != reg.instanceId) return Registration.Refused(CARD_MISMATCH)
                Target({ RegisterAuth.Enrol(reg.linkId, reg.registerToken) }, pin.instanceId, pin.card0Hash, null, reg)
            }
            is LinkRegistration.Register -> {
                val pin = registerPin(GatePayload.L) ?: return gateRefusal(GatePayload.L)
                if (pin.instanceId != reg.instanceId) return Registration.Refused(CARD_MISMATCH)
                Target({ id -> reg.answer(id)?.let { RegisterAuth.Link(reg.linkId, reg.registerToken, it) } }, pin.instanceId, pin.card0Hash, null, reg)
            }
        }
    }

    private fun registerGate(payload: GatePayload?): GateDecision = PasswordGate.decide(
        GateInput(GatePurpose.REGISTER, entry = null, payload = payload, origin = origin, account = null, pins = trust.gatePins()),
    )

    /** The pin a registration needs (design §4.4: any root may create an account), or null. */
    private fun registerPin(payload: GatePayload?) = if (registerGate(payload) == GateDecision.PROCEED) trust.pinFor(origin) else null

    private fun gateRefusal(payload: GatePayload?): Registration = when (registerGate(payload)) {
        GateDecision.TRUST_GATE -> Registration.Refused(TRUST_GATE_FIRST)
        GateDecision.REFUSE_ENTRY -> Registration.Refused(INSTANCE_BLOCKED)
        GateDecision.PROCEED -> Registration.Refused(INSTANCE_BLOCKED) // a pin that is not Pinned (forked or damaged)
    }

    /** Why operator recovery cannot be chosen here, re-derived from this device's pin; null when it can. */
    private fun operatorRefusal(target: Target, form: RegistrationForm): String? {
        if (target.setup != null) return OPERATOR_RECOVERY_UNAVAILABLE
        val pin = trust.pinFor(origin) ?: return OPERATOR_RECOVERY_UNAVAILABLE
        if (pin.kind != InstanceKind.PRIVATE.literal || pin.recoveryFp == TrustGrammar.NONE) return OPERATOR_RECOVERY_UNAVAILABLE
        val offer = form.operatorOffer ?: return OPERATOR_RECOVERY_UNAVAILABLE
        if (offer.origin != origin || offer.pinHash != pin.hash || offer.fp != pin.recoveryFp) return STALE_OFFER
        if (!form.operatorUnderstood) return CONSENT_REQUIRED
        return null
    }

    /**
     * The session keeper's answer for a new account [userId] for [emailNorm] here, as the registration's own: another
     * account kept here is [Registration.Refused] with its code ([ANOTHER_SESSION_KEPT]), an address bound here to
     * another account the identity fault ([AccountOpen.SELF_IDENTITY_MISMATCH]); null when it would take the session.
     */
    private fun keeperRefusal(emailNorm: String, userId: String, identityPub: ByteArray? = null): Registration? =
        sink.wouldRefuse(origin, emailNorm, userId, identityPub)?.let {
            if (it == AccountOpen.SELF_IDENTITY_MISMATCH) {
                Registration.IdentityFault(it, userId.takeIf { sink.refusalIsAnotherAccount(origin, emailNorm, userId, identityPub) })
            } else {
                Registration.Refused(it)
            }
        }

    private suspend fun registerWith(keys: PasswordKeys, target: Target, form: RegistrationForm, emailNorm: String, operator: OperatorRecoveryOffer?, userId: String): Registration {
        val now = clock()
        val personalVaultId = Bytes.uuidV4FromBytes(crypto.randomBytes(16))
        val uvk = crypto.randomBytes(32)
        val seed = crypto.randomBytes(32)
        val vk = crypto.randomBytes(32)
        val identity: KeyPairBytes
        val signing: KeyPairBytes
        try {
            identity = crypto.boxKeypairFromSeed(seed)
            signing = crypto.signKeypairFromSeed(seed)
        } catch (e: CryptoException) {
            seed.fill(0); uvk.fill(0); vk.fill(0)
            throw e
        }
        var piece: MemberRecovery.Piece? = null
        // Once the server answered the registration a link it used is spent there: its flow ends here, through the link
        // engine's own registered() on success and its stopped() on every other way out.
        var linkSpent = false
        var linkHanded = false
        try {
            val identityB64 = Bytes.toB64(identity.publicKey)
            // Asked again with nothing more to wait for before the registration is sent.
            keeperRefusal(emailNorm, userId, identity.publicKey)?.let { return it }
            val wireAuth = target.auth(NewIdentity(userId, identity.publicKey, signing, form.displayName)) ?: return Registration.Refused(BAD_ANSWER)
            // §5.2: the one genesis this account ever has, signed here and nowhere else.
            val genesis = AccountGenesis.sign(crypto, signing, GenesisFields(userId, identityB64, target.instanceId, personalVaultId, now))
            val p = MemberRecovery.generate(crypto, userId, uvk)
            piece = p
            val recovery = if (operator != null) {
                RecoveryChoice("operator", EscrowUpload(Bytes.toB64(Escrow.sealUvkV3(crypto, operator.recoveryPub, operator.fp, userId, emailNorm, identity.publicKey, signing, uvk, now)), operator.fp))
            } else {
                RecoveryChoice("private")
            }
            val device = devices.newDevice(origin, emailNorm, form.platform, form.deviceName)
            val body = RegisterRequest(
                auth = wireAuth, email = form.email, displayName = form.displayName, userId = userId,
                kdfSalt = Bytes.toB64(keys.salt), kdfParams = keys.params, authKey = keys.authKeyB64,
                wrappedUvk = Envelope.sealB64(crypto, keys.wrapKey, uvk, Ad.uvk(userId)),
                identityPub = identityB64,
                encryptedIdentitySeed = Envelope.sealB64(crypto, uvk, seed, Ad.idkey(userId)),
                genesis = Bytes.toB64(genesis),
                personalVault = PersonalVaultUpload(
                    personalVaultId,
                    Envelope.sealB64(crypto, uvk, vk, Ad.vk(personalVaultId, userId)),
                    Envelope.sealB64(crypto, vk, """{"name":"Personal"}""".encodeToByteArray(), Ad.vaultMeta(personalVaultId)),
                ),
                personalWrap = PersonalWrap(personalVaultId, Envelope.sealB64(crypto, uvk, vk, Ad.vkPersonal(personalVaultId, userId))),
                memberRecovery = MemberRecoveryBlock(p.recoveryWrappedUvk, p.recoveryAuthKey),
                recovery = recovery,
                ageConfirmed = form.ageConfirmed,
                device = device,
            )
            val r = client.call(WireRoute.REGISTER, bodyJson = WireJson.json.encodeToString(RegisterRequest.serializer(), body),
                decode = { WireJson.json.decodeFromString(SessionResponse.serializer(), it) })
            val resp = when (r) {
                is WireResult.Ok -> r.value
                is WireResult.Refused -> return if (r.status >= 500) Registration.Unknown else Registration.Refused(r.code, r.retryAfterSeconds)
                is WireResult.NoAnswer -> return Registration.Unknown
            }
            linkSpent = true
            val pieceId = resp.recoveryPieceId
            // An opaque `ServerCrypto.newToken` (spec 03 §12): 32 bytes in base64url, echoed only in a confirm body.
            if (pieceId == null || !TrustGrammar.isB64_32(pieceId)) return Registration.Refused(BAD_RESPONSE)
            // The server's echo must open as exactly the account registered here (design §5.2).
            val opened = SessionOpener.open(crypto, origin, emailNorm, resp, uvk.copyOf(), userId, target.instanceId, null, device.deviceSecret,
                SessionHow.REGISTERED, devices, sink, KnownKdf(keys.salt, keys.params, body.wrappedUvk))
            val session = when (opened) {
                is Opening.Done -> opened.session
                is Opening.Fault -> return Registration.IdentityFault(opened.reason)
                Opening.Bad -> return Registration.Refused(BAD_RESPONSE)
            }
            // The person's choice: this device's own mirror first, then the UVK-sealed record (design §4.5, §7.7).
            val record = RecoveryRecord(if (operator != null) "operator" else "private", operator?.fp ?: TrustGrammar.NONE, now)
            mirror.put(userId, record)
            if (operator != null) io.silencelen.andvari.core.client.recovery.EscrowSeen(state).put(userId, operator.fp)
            // The session keeper refused the session all the same (what the device keeps changed while the registration was
            // under way): it wiped the session's keys and ended the session at the server. The account exists there, under
            // the password just chosen, and nothing more is done with it here: no record is sealed or sent, no contact is
            // pinned and no card is signed under keys that are gone. The device's own records of the choice stay (the next
            // sign-in writes the account's record from them).
            opened.notTaken?.let { reason ->
                // The kit is the account's from the registration on (the commit made it), so it goes to the caller with the
                // refusal. A setup's kit cannot be shown: its card 0 was never signed, and the kit's code names card 0.
                val card0 = target.card0Hash.takeIf { target.setup == null } ?: return Registration.Refused(reason)
                val qr = RecoveryKit.composeQr(origin, card0, emailNorm, p.recoverySecret) ?: return Registration.Refused(BAD_RESPONSE)
                val kit = RevealedKit(RecoveryKit.groups(p.recoverySecret), qr, pieceId, session.account.accountId(crypto), p.recoverySecret.copyOf())
                return Registration.Registered(userId, kit, notKept = reason)
            }
            target.link?.let {
                linkHanded = true
                links?.registered(it, session)
            }
            writeRecoveryRecord(session, record)
            var card0Hash = target.card0Hash
            var cardPending = false
            if (target.setup != null) {
                val (hash, pending) = finishSetup(target.setup, session, keys.authKeyB64, emailNorm)
                card0Hash = hash
                cardPending = pending
            }
            val qr = RecoveryKit.composeQr(origin, card0Hash!!, emailNorm, p.recoverySecret) ?: return Registration.Refused(BAD_RESPONSE)
            val kit = RevealedKit(RecoveryKit.groups(p.recoverySecret), qr, pieceId, session.account.accountId(crypto), p.recoverySecret.copyOf())
            return Registration.Registered(userId, kit, cardPending)
        } finally {
            if (linkSpent && !linkHanded) target.link?.let { links?.stopped(it) }
            seed.fill(0)
            vk.fill(0)
            uvk.fill(0)
            piece?.recoverySecret?.fill(0)
            // The session holds its own derivations (AccountOpen opened the echoed seed); these were the registration's.
            identity.privateKey.fill(0)
            signing.privateKey.fill(0)
        }
    }

    /** The `recovery` record in account state; a failed write leaves the mirror, from which a later posture read writes it. */
    private suspend fun writeRecoveryRecord(session: EstablishedSession, record: RecoveryRecord): Boolean {
        val store = StoredAccountState(session.userId, session.account.uvk, client, crypto, state)
        // The one stamping rule (design §5.4): a new account holds no record, so this is the choice's own time; should a
        // record exist already, the choice supersedes it, and the mirror follows the record as written.
        var written = record
        val w = store.update { doc -> written = AccountMerge.supersedingRecovery(record, doc.recovery); doc.copy(recovery = written) }
        if (w is AccountStateWrite.Written && written != record) mirror.put(session.userId, written)
        return w is AccountStateWrite.Written
    }

    /**
     * Setup (design §6.7 steps 2–3): sign card 0 from the setup offer with this account's own key, upload it with the
     * registration's `authKey` (a fresh password proof of this very session), and pin it through the setup root.
     * Answers card 0's hash and whether the upload is still pending.
     */
    private suspend fun finishSetup(setup: LinkRegistration.Setup, session: EstablishedSession, currentAuthKey: String, emailNorm: String): Pair<String, Boolean> {
        val kind = InstanceKind.fromLiteral(setup.kind) ?: return "" to true
        val card = CardFields(
            setup.instanceId, 0, TrustGrammar.ZERO_HASH, setup.origin, setup.name, kind, session.userId,
            Bytes.toB64(session.account.signing.publicKey), setup.recoveryFp.takeIf { it != TrustGrammar.NONE }, clock(),
        )
        val frame = session.account.signing.use { InstanceCard.sign(crypto, it, card) }
        val hash = SignedFrame.hash(crypto, frame)
        val frameB64 = Bytes.toB64(frame)
        val body = WireJson.json.encodeToString(InstanceCardPut.serializer(), InstanceCardPut(frameB64, currentAuthKey))
        val r = client.call(WireRoute.INSTANCE_CARD_PUT, bodyJson = body, decode = { WireJson.json.decodeFromString(InstanceCardPutResponse.serializer(), it) })
        if (r !is WireResult.Ok || r.value.seq != 0L || r.value.hash != hash) return hash to true
        val pinned = trust.pinFromOwnCard0(origin, frameB64, session.userId, emailNorm, session.account.signing.publicKey)
        // Card 0 is accepted and pinned: the kept offer has done its job (design §6.7 step 2).
        if (pinned is FirstPin.Pinned) SetupOffers(state).remove(origin)
        return hash to (pinned !is FirstPin.Pinned)
    }

    // ---------------------------------------------------------------------------------------------
    // Sign-in (spec 03 §2, design §4.4, §8.7)
    // ---------------------------------------------------------------------------------------------

    /** [block] as a flow under way for [email]'s address here ([SessionSink.underWay]); an address that is not one holds nothing. */
    private inline fun <T> heldFor(email: String, block: () -> T): T {
        val done = TrustGrammar.emailNorm(email)?.let { sink.underWay(origin, it) }
        try {
            return block()
        } finally {
            done?.invoke()
        }
    }

    override suspend fun signIn(email: String, password: CharArray, totp: String?): SignIn {
        val done = TrustGrammar.emailNorm(email)?.let { sink.underWay(origin, it) }
        var handed = false
        try {
            val r = signInHeld(email, password, totp)
            // A two-step code asked for: the sign-in is under way until the code's answer, a cancel or a stop ends it.
            if (r is SignIn.TotpRequired && done != null) {
                r.pending.holdUntilWiped(done)
                handed = true
            }
            return r
        } finally {
            if (!handed) done?.invoke()
        }
    }

    private suspend fun signInHeld(email: String, password: CharArray, totp: String?): SignIn {
        val emailNorm = TrustGrammar.emailNorm(email)
        if (emailNorm == null) {
            password.fill('\u0000')
            return SignIn.Refused(INVALID_EMAIL)
        }
        val decision = PasswordGate.decide(
            GateInput(GatePurpose.SIGN_IN, GateEntry.SERVER_CHOICE, null, origin, emailNorm, trust.gatePins()),
        )
        val pin = trust.pinFor(origin)
        if (decision != GateDecision.PROCEED || pin == null) {
            password.fill('\u0000')
            return if (decision == GateDecision.REFUSE_ENTRY || pinBlocked()) SignIn.Refused(INSTANCE_BLOCKED) else SignIn.TrustGateFirst
        }
        // Prelogin is itself a secret-derived send (design §4.4): after the gate only.
        val pre = client.call(WireRoute.PRELOGIN, bodyJson = WireJson.json.encodeToString(PreloginRequest.serializer(), PreloginRequest(email)),
            decode = { WireJson.json.decodeFromString(PreloginResponse.serializer(), it) })
        val p = when (pre) {
            is WireResult.Ok -> pre.value
            is WireResult.Refused -> {
                password.fill('\u0000')
                return if (pre.status >= 500) SignIn.Unreachable else SignIn.Refused(pre.code, pre.retryAfterSeconds)
            }
            is WireResult.NoAnswer -> {
                password.fill('\u0000')
                return SignIn.Unreachable
            }
        }
        val salt = Bytes.fromB64Canonical(p.kdfSalt)
        if (salt == null) {
            password.fill('\u0000')
            return SignIn.Refused(BAD_RESPONSE)
        }
        // Spec 01 §7: what this device keeps of an account here, which this sign-in would replace, is compared with the key
        // it opens. A kept wrap at another salt or cost is derived at now, while the typed password is still here.
        val keptHere = sink.keptForSignIn(origin)
        val kept = try {
            keptHere?.let {
                // Nothing is derived for it when the sign-in itself derives nothing (a salt or cost the fence refuses).
                if (salt.size == KdfParams.SALT_BYTES && io.silencelen.andvari.core.client.KdfUpgrade.withinFence(p.kdfParams)) KeptAccountCheck.prepare(crypto, it, password, salt, p.kdfParams)
                else KeptWrapKeys(it, emptyList())
            }
        } catch (e: Throwable) {
            password.fill('\u0000')
            throw e
        }
        val keys = PasswordKeys.derive(crypto, password, salt, p.kdfParams, served = true)
        if (keys == null) {
            kept?.wipe()
            return SignIn.Refused(KDF_REFUSED)
        }
        return login(PendingLogin(emailNorm, email, keys, pin.instanceId, kept), totp)
    }

    override suspend fun signInCode(step: SignIn.TotpRequired, code: String): SignIn = heldFor(step.pending.emailNorm) { signInCodeHeld(step, code) }

    private suspend fun signInCodeHeld(step: SignIn.TotpRequired, code: String): SignIn {
        // The password rule again before the second send: a pin that became forked or damaged (or was forgotten)
        // between the two steps stops authKey and the code here.
        val pending = step.pending
        val decision = PasswordGate.decide(
            GateInput(GatePurpose.SIGN_IN, GateEntry.SERVER_CHOICE, null, origin, pending.emailNorm, trust.gatePins()),
        )
        if (decision != GateDecision.PROCEED || trust.pinFor(origin) == null) {
            pending.wipe()
            return if (decision == GateDecision.REFUSE_ENTRY || pinBlocked()) SignIn.Refused(INSTANCE_BLOCKED) else SignIn.TrustGateFirst
        }
        return login(pending, code, afterCodeStep = true)
    }

    override fun cancelSignIn(step: SignIn.TotpRequired) = step.pending.wipe()

    /**
     * `POST /auth/login` with [pending]'s keys; they are wiped unless the answer is another code request. [afterCodeStep]:
     * the server asked for a code after this password ([SignIn.TotpRequired]), so its uniform refusal is
     * [REFUSED_AFTER_CODE], never a wrong password.
     */
    private suspend fun login(pending: PendingLogin, totp: String?, afterCodeStep: Boolean = false): SignIn {
        var keep = false
        try {
            val device = devices.loginDevice(origin, pending.emailNorm, platform, deviceName)
            // The kept session this sign-in replaces on its own device row is named, so the server ends exactly that one
            // with the sign-in (also after a refresh whose answer was lost); the device sends nothing else for it.
            val replaces = sink.signInReplaces(origin, pending.emailNorm, device.deviceId)
            val body = WireJson.json.encodeToString(LoginRequest.serializer(), LoginRequest(pending.email, pending.keys.authKeyB64, device, totp, replaces))
            val resp = when (val r = client.call(WireRoute.LOGIN, bodyJson = body, decode = { WireJson.json.decodeFromString(SessionResponse.serializer(), it) })) {
                is WireResult.Ok -> r.value
                is WireResult.Refused -> return when {
                    r.code == "totp_required" -> { keep = true; SignIn.TotpRequired(pending) }
                    // Once a code was asked for, the server answers a wrong code and a wrong password alike: what is
                    // known is that it refused after the code was sent, having taken this password a moment before.
                    r.code == "invalid_credentials" -> if (afterCodeStep) SignIn.Refused(REFUSED_AFTER_CODE) else SignIn.InvalidCredentials
                    r.code == "link_required" -> SignIn.LinkRequired
                    r.status >= 500 -> SignIn.Unreachable
                    else -> SignIn.Refused(r.code, r.retryAfterSeconds)
                }
                is WireResult.NoAnswer -> return SignIn.Unreachable
            }
            // From here the server has opened a session: every refusal on this device ends exactly that session there, and
            // no other session of the device (a kept one stays as it is).
            suspend fun refused(answer: SignIn): SignIn {
                sink.notTaken(origin, resp.accessToken, resp.refreshToken)
                return answer
            }
            if (!TrustGrammar.isUuid(resp.userId) || io.silencelen.andvari.core.client.UserIds.isNil(resp.userId)) return refused(SignIn.Refused(BAD_RESPONSE))
            // The server accepted authKey, so a wrappedUvk that does not open under the wrap key is not a wrong
            // password: it is key material this account never had (design §5.2's identity fault).
            val uvk = try {
                Envelope.openB64(crypto, pending.keys.wrapKey, resp.accountKeys.wrappedUvk, Ad.uvk(resp.userId))
            } catch (e: CryptoException) {
                null
            } catch (e: IllegalArgumentException) {
                null
            } ?: return refused(SignIn.IdentityFault(UVK_UNOPENABLE))
            // Spec 01 §7: a sign-in over an account this device keeps replaces nothing until the key it opened is shown to
            // be that account's key as this device knows it ([KeptAccountCheck]). Another key: nothing kept is touched,
            // the server's session is ended there, and no session is kept.
            val keptHere = pending.kept?.takeIf { it.kept.userId == resp.userId }
            val match = keptHere?.let { KeptAccountCheck.match(crypto, resp.userId, uvk, it, pending.keys, resp.accountKeys) }
            if (match == KeptMatch.DIFFERENT || match == KeptMatch.DAMAGED) {
                uvk.fill(0)
                return refused(SignIn.Refused(if (match == KeptMatch.DAMAGED) KEPT_COPY_DAMAGED else SERVER_KEYS_NOT_KNOWN_HERE))
            }
            // The comparison held by a kept wrap the typed password opened: the keeper is handed that wrap key and checks
            // it itself, so a copy whose sealed seed is damaged is taken (and repaired) by this sign-in.
            val proof = if (match == KeptMatch.OPENED && keptHere != null) KeptAccountCheck.provingKey(crypto, resp.userId, uvk, keptHere, pending.keys) else null
            val opened = SessionOpener.open(crypto, origin, pending.emailNorm, resp, uvk, null, pending.instanceId, knownIdentity(resp.userId),
                device.deviceSecret, SessionHow.PASSWORD, devices, sink, KnownKdf(pending.keys.salt, pending.keys.params), keptWrapKey = proof)
            return when (opened) {
                // The session layer refused it (and ended it there itself): the sign-in's own answer says so.
                is Opening.Done -> when (opened.notTaken) {
                    null -> SignIn.SignedIn(opened.session.userId, opened.session.role, opened.session.mustEnrollTotp, opened.session.recoveryConfirmed,
                        copyUnderOtherPassword = match == KeptMatch.SEALED)
                    // The address is bound on this device to another account, or to this one under another key (the session
                    // keeper's identity refusal): which of the two, the keeper says.
                    AccountOpen.SELF_IDENTITY_MISMATCH -> SignIn.IdentityFault(opened.notTaken, resp.userId.takeIf {
                        sink.refusalIsAnotherAccount(origin, pending.emailNorm, it, Bytes.fromB64Exact(resp.accountKeys.identityPub, 32))
                    })
                    else -> SignIn.Refused(opened.notTaken)
                }
                is Opening.Fault -> refused(SignIn.IdentityFault(opened.reason))
                Opening.Bad -> refused(SignIn.Refused(BAD_RESPONSE))
            }
        } finally {
            if (!keep) pending.wipe()
        }
    }

    // ---------------------------------------------------------------------------------------------
    // The kit's capture gate (design §10)
    // ---------------------------------------------------------------------------------------------

    override fun kitChallenge(kit: RevealedKit): List<Int> {
        kit.challenge?.let { return it }
        val groups = RecoveryKit.confirmGroups(crypto)
        kit.challenge = groups
        return groups
    }

    override suspend fun confirmKit(kit: RevealedKit, typed: Map<Int, String>): KitConfirm {
        val asked = kit.challenge ?: return KitConfirm.Wrong
        if (typed.keys != asked.toSet()) return KitConfirm.Wrong
        if (!RecoveryKit.confirmMatches(kit.secret, asked, asked.map { typed.getValue(it) })) {
            kit.failures++
            if (kit.failures >= MAX_KIT_FAILURES) {
                kit.failures = 0
                kit.challenge = null
                return KitConfirm.ShowAgain
            }
            return KitConfirm.Wrong
        }
        val body = WireJson.json.encodeToString(RecoverySelfConfirmRequest.serializer(), RecoverySelfConfirmRequest(kit.pieceId))
        return when (val r = client.call(WireRoute.RECOVERY_SELF_CONFIRM, bodyJson = body, decode = { }) ) {
            is WireResult.Ok -> {
                kit.wipe()
                KitConfirm.Confirmed
            }
            is WireResult.Refused -> KitConfirm.Unrecorded(r.code)
            is WireResult.NoAnswer -> KitConfirm.Unrecorded(UNREACHABLE)
        }
    }

    companion object {
        /** A policy asking for more is refused: 26 bits is about a minute on a phone, and a server cannot ask for hours. */
        const val MAX_POW_BITS = 26
        private const val POW_SLICE = 4096
        private const val POW_SEARCH_LIMIT = 1L shl 32
        private const val MAX_KIT_FAILURES = 3

        const val INVALID_EMAIL = "invalid_email"
        const val NO_PIN = "no_pin"
        const val INSTANCE_BLOCKED = "instance_blocked"
        const val POW_TOO_HARD = "pow_too_hard"
        const val BAD_RESPONSE = "bad_response"
        const val BAD_TICKET = "bad_ticket"
        const val EMAIL_MISMATCH = "email_mismatch"
        const val LINK_STALE = "link_stale"
        const val CARD_MISMATCH = "card_mismatch"
        const val TRUST_GATE_FIRST = "trust_gate_first"
        const val SETUP_DONE = "setup_done"
        const val OPERATOR_RECOVERY_UNAVAILABLE = "operator_recovery_unavailable"
        const val STALE_OFFER = "stale_offer"
        const val CONSENT_REQUIRED = "consent_required"
        const val BAD_ANSWER = "bad_answer"
        const val BAD_KDF = "bad_kdf"
        const val KDF_REFUSED = "kdf_refused"
        const val UVK_UNOPENABLE = "uvk_unopenable"
        const val UNREACHABLE = "unreachable"

        /**
         * A sign-in's refusal (spec 01 §7): this device keeps the account, and the key the server's wrap opened with the
         * typed password is not that account's key as this device knows it. Nothing this device keeps was replaced, the
         * server's new session was ended there, and no session was kept. Never a wrong password: the server took it.
         */
        const val SERVER_KEYS_NOT_KNOWN_HERE = "server_keys_not_known_here"

        /**
         * A registration on a device that keeps an account (any account: a new one is never the kept one): stopped before
         * anything was derived or sent, since the session the registration opens could not be kept. The way out is to sign
         * that account out first. The session keeper's own code.
         */
        const val ANOTHER_SESSION_KEPT = io.silencelen.andvari.core.client.session.Establishing.ANOTHER_SESSION_KEPT

        /**
         * The account kept here is held as its server's operator account: a registration or a sign-in (of that very
         * account too) is refused as [ANOTHER_SESSION_KEPT] is. The way out is to remove it from this device.
         */
        const val OPERATOR_ACCOUNT_HELD = io.silencelen.andvari.core.client.session.Establishing.OPERATOR_ACCOUNT_HELD

        /**
         * Spec 01 §7: this device keeps the account, no kept wrap opened with the typed password, and the copy's sealed
         * identity seed does not open because the copy itself is damaged: nothing could be compared, nothing kept was
         * replaced, no session was kept. The way out is to remove this device's copy, then sign in or recover. (A sign-in
         * whose typed password opens a kept wrap to the served key signs in and repairs such a copy.)
         */
        const val KEPT_COPY_DAMAGED = io.silencelen.andvari.core.client.session.Establishing.KEPT_COPY_DAMAGED

        /**
         * The server refused the sign-in after its two-step code was sent ([Onboarding.signInCode]). It had asked for the
         * code only after it accepted this password a moment before, and it answers a wrong code and a wrong password
         * alike from then on: so this is never "wrong password", and most likely the code was wrong or already used (a
         * password changed in between cannot be ruled out). The derived keys are wiped; signing in again starts over.
         */
        const val REFUSED_AFTER_CODE = "refused_after_code"

        /** `YYYY-MM-DD` of [ms] in UTC (the proof of work's date, design §2.3). */
        fun utcDate(ms: Long): String {
            val days = ms.floorDiv(86_400_000L)
            // Howard Hinnant's civil_from_days.
            val z = days + 719_468
            val era = z.floorDiv(146_097L)
            val doe = z - era * 146_097
            val yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365
            val y = yoe + era * 400
            val doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
            val mp = (5 * doy + 2) / 153
            val d = doy - (153 * mp + 2) / 5 + 1
            val m = if (mp < 10) mp + 3 else mp - 9
            val year = if (m <= 2) y + 1 else y
            return year.toString().padStart(4, '0') + "-" + m.toString().padStart(2, '0') + "-" + d.toString().padStart(2, '0')
        }

        /** The served recovery public key: 32 bytes as canonical base64url, white space around it ignored. */
        internal fun recoveryKeyBytes(text: String): ByteArray? = Bytes.fromB64Exact(text.trim(), 32)
    }
}
