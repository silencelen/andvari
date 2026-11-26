package io.silencelen.andvari.core.client.onboard

import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.pin.CardTrust
import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.client.pin.TrustCardChainVerifier
import io.silencelen.andvari.core.client.pin.TrustGateWording
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.KeyPairBytes
import io.silencelen.andvari.core.model.wire.AccountKeys
import io.silencelen.andvari.core.model.wire.AccountStatePut
import io.silencelen.andvari.core.model.wire.AccountStateResponse
import io.silencelen.andvari.core.model.wire.ClientPolicy
import io.silencelen.andvari.core.model.wire.InstanceCardPut
import io.silencelen.andvari.core.model.wire.InstanceCardPutResponse
import io.silencelen.andvari.core.model.wire.InstanceResponse
import io.silencelen.andvari.core.model.wire.LoginRequest
import io.silencelen.andvari.core.model.wire.MemberRecoveryBlock
import io.silencelen.andvari.core.model.wire.PersonalWrap
import io.silencelen.andvari.core.model.wire.PreloginRequest
import io.silencelen.andvari.core.model.wire.PreloginResponse
import io.silencelen.andvari.core.model.wire.RecoveryCommitRequest
import io.silencelen.andvari.core.model.wire.RecoverySelfConfirmRequest
import io.silencelen.andvari.core.model.wire.RecoveryVerifyRequest
import io.silencelen.andvari.core.model.wire.RecoveryVerifyResponse
import io.silencelen.andvari.core.model.wire.RegisterAuth
import io.silencelen.andvari.core.model.wire.RegisterRequest
import io.silencelen.andvari.core.model.wire.SessionResponse
import io.silencelen.andvari.core.model.wire.SignupPolicy
import io.silencelen.andvari.core.model.wire.SignupStartRequest
import io.silencelen.andvari.core.model.wire.SignupStartResponse
import io.silencelen.andvari.core.model.wire.SignupVerifyRequest
import io.silencelen.andvari.core.model.wire.SignupVerifyResponse
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.CardFields
import io.silencelen.andvari.core.trust.InstanceCard
import io.silencelen.andvari.core.trust.InstanceKind
import io.silencelen.andvari.core.trust.SignedFrame
import io.silencelen.andvari.core.trust.SignupPow
import io.silencelen.andvari.core.trust.TrustGrammar

/**
 * An in-memory instance for the onboarding and recovery tests: real card frames signed with the shared verifiers' code, and
 * the routes of spec 03 §2, §3 (account state), §12, §14 and §17 as an honest server answers them. Every
 * request is recorded in [calls]; [override] replaces the answer of one route.
 */
class FakeInstance(
    val crypto: CryptoProvider,
    override val origin: String = "https://h.example",
    val instanceId: String = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
    val kind: InstanceKind = InstanceKind.PRIVATE,
    val recoveryFp: String? = null,
    withCard: Boolean = true,
) : WireClient {
    val operatorSign: KeyPairBytes = crypto.signKeypairFromSeed(ByteArray(32) { 7 })
    val cards = ArrayList<ByteArray>()
    var now = 1_794_744_000_000L
    var powBits = 0
    var mode = "open"

    /** The KDF cost the client policy asks for. */
    var policyKdf: KdfParams = KdfParams.DEFAULT

    /**
     * The server's own floor (its `ANDVARI_MIN_KDF_*`): a registration, a password change or a kit recovery's commit below
     * it is `400 kdf_too_weak`. Null: none.
     */
    var minKdf: KdfParams? = null

    /** True when [p] is below [minKdf] on either axis. */
    fun belowFloor(p: KdfParams): Boolean = minKdf?.let { p.ops < it.ops || p.memBytes < it.memBytes } ?: false
    var recoveryPub: ByteArray? = null
    val rotations = ArrayList<ByteArray>()
    var setupBlock: io.silencelen.andvari.core.model.wire.InstanceSetup? = null

    class Account(
        val userId: String, var authKey: String, var kdfSalt: String, var kdfParams: KdfParams, var wrappedUvk: String,
        var encryptedIdentitySeed: String, var identityPub: String, var genesis: String?, var personalWrap: PersonalWrap?,
        var memberRecovery: MemberRecoveryBlock, var pieceId: String, var recoveryConfirmed: Boolean = false,
        val devices: MutableMap<String, String> = HashMap(), var requireLink: Boolean = false, var totp: String? = null,
        var sealedState: String? = null, var stateSeq: Long = 0, var escrowFp: String? = null, var posture: String = "private",
    )

    val accounts = HashMap<String, Account>()
    val calls = ArrayList<WireRoute>()
    val bodies = ArrayList<String>()
    val override = HashMap<WireRoute, WireResult<String>>()
    var codes = HashMap<String, String>()
    private var counter = 0

    init {
        if (withCard) {
            val f0 = InstanceCard.sign(crypto, operatorSign, CardFields(instanceId, 0, TrustGrammar.ZERO_HASH, origin, "Home", kind, "99999999-9999-4999-8999-999999999999",
                Bytes.toB64(operatorSign.publicKey), recoveryFp, now - 10_000))
            cards += f0
        }
    }

    val card0Hash: String get() = SignedFrame.hash(crypto, cards[0])

    private fun uuid(): String { counter++; return "00000000-0000-4000-8000-" + counter.toString().padStart(12, '0') }

    /** A `pieceId` as the server mints it: an opaque `ServerCrypto.newToken`, 32 random bytes in base64url (spec 03 §12). */
    private fun piece(): String { counter++; return Bytes.toB64(ByteArray(32) { (counter + it).toByte() }) }

    private fun refuse(status: Int, code: String): WireResult<Nothing> = WireResult.Refused(status, WireError(code, code))

    private fun <T> ok(text: String, decode: (String) -> T): WireResult<T> = WireResult.Ok(decode(text), 200)

    private fun session(a: Account, deviceId: String, pieceId: String?): String {
        lastSessionDevice = deviceId
        var access = "at-$deviceId"
        var refresh = "rt-$deviceId"
        if (countSessions) {
            sessionsMade++
            access = "at-s$sessionsMade-$deviceId"
            refresh = "rt-s$sessionsMade-$deviceId"
            live[refresh] = Live(a.userId, deviceId, access)
        }
        return WireJson.json.encodeToString(
            SessionResponse.serializer(),
            SessionResponse(a.userId, deviceId, access, refresh, keys(a), if (a.userId == operatorUserId) "operator" else "member", a.totp != null, false, pieceId),
        )
    }

    /**
     * When true, every session this server opens gets tokens of its own (`at-s<n>-<deviceId>`, which still end with the
     * device id) and stays in [live] until it is ended: by `POST /auth/end-session` with its refresh token (that one
     * session), by a sign-out with any of the device's access tokens (every session of that device, as the real server
     * does; the test transport reports it through [loggedOut]), by a sign-in on that known device while
     * [oneSessionPerDevice] (its earlier sessions), or by a recovery's commit (every session of the account).
     */
    var countSessions = false

    /**
     * A device has one live session, kept by the server itself: a sign-in on a known device ends that device's earlier
     * sessions in the same step, as the real server does since it took that rule. Off: a server from before it.
     */
    var oneSessionPerDevice = false

    /** What each sign-in this server took named as the session it replaces (`replacesRefreshToken`, null when none), in order. */
    val namedAtSignIn = ArrayList<String?>()

    /**
     * When true, this server reads `replacesRefreshToken` as the real server does: once the sign-in has succeeded on a known
     * device, a named session that is live, of the same account and on the same row ends with it; anything else named
     * changes nothing. Off: a server from before the field, which ignores it.
     */
    var endsNamedSession = false

    /** A session this server opened and has not ended. */
    class Live(val userId: String, val deviceId: String, val accessToken: String)

    /** The live sessions, by refresh token. */
    val live = LinkedHashMap<String, Live>()
    private var sessionsMade = 0

    /** `POST /auth/logout` with [accessToken]: every session of that device ends. */
    fun loggedOut(accessToken: String?) {
        val device = live.values.firstOrNull { it.accessToken == accessToken }?.deviceId ?: return
        live.values.removeAll { it.deviceId == device }
    }

    /** The device of the newest session this server opened: the caller `current` marks when no bearer is known. */
    private var lastSessionDevice: String? = null

    /**
     * The bearer of the request being answered, when the transport in front says (the test transport sets it): its
     * tokens end with `-<deviceId>`, so the devices list marks the caller's own device `current`, as the server does.
     */
    var bearer: String? = null

    var operatorUserId: String? = null

    fun keys(a: Account) = AccountKeys(a.kdfSalt, a.kdfParams, a.wrappedUvk, a.encryptedIdentitySeed, a.identityPub, a.recoveryConfirmed, a.personalWrap, a.genesis)

    fun account(email: String): Account = accounts.getValue(TrustGrammar.emailNorm(email)!!)

    @Suppress("UNCHECKED_CAST")
    override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
        calls += route
        bodies += bodyJson ?: ""
        override[route]?.let { o -> return if (o is WireResult.Ok) WireResult.Ok(decode(o.value), o.status) else o as WireResult<T> }
        return when (route) {
            WireRoute.INSTANCE -> ok(WireJson.json.encodeToString(InstanceResponse.serializer(), InstanceResponse(cards.map { Bytes.toB64(it) }, rotations.map { Bytes.toB64(it) }, if (cards.isEmpty()) setupBlock else null)), decode)
            WireRoute.CLIENT_POLICY -> ok(WireJson.json.encodeToString(ClientPolicy.serializer(), ClientPolicy(emptyMap(), policyKdf, 300, 30, true, 3600, 30, 1, 1, now,
                SignupPolicy(mode, false, true, powBits), false)), decode)
            WireRoute.RECOVERY_PUBKEY -> recoveryPub?.let { ok(Bytes.toB64(it), decode) } ?: refuse(404, "not_found")
            WireRoute.SIGNUP_START -> {
                val b = WireJson.json.decodeFromString(SignupStartRequest.serializer(), bodyJson!!)
                val norm = TrustGrammar.emailNorm(b.email) ?: return refuse(400, "invalid_email")
                if (powBits > 0) {
                    val pow = b.pow ?: return refuse(400, "pow_required")
                    val today = WireOnboarding.utcDate(now)
                    val yesterday = WireOnboarding.utcDate(now - 86_400_000L)
                    if (pow.date != today && pow.date != yesterday) return refuse(400, "bad_pow")
                    if (!SignupPow.accepts(crypto, norm, pow.date, pow.nonce, powBits)) return refuse(400, "bad_pow")
                }
                codes[norm] = "482915"
                ok(WireJson.json.encodeToString(SignupStartResponse.serializer(), SignupStartResponse("sent")), decode)
            }
            WireRoute.SIGNUP_VERIFY -> {
                val b = WireJson.json.decodeFromString(SignupVerifyRequest.serializer(), bodyJson!!)
                if (codes[TrustGrammar.emailNorm(b.email)] != b.code) return refuse(400, "bad_code")
                ok(WireJson.json.encodeToString(SignupVerifyResponse.serializer(), SignupVerifyResponse(Bytes.toB64(ByteArray(32) { 4 }), now + 1_800_000)), decode)
            }
            WireRoute.REGISTER -> {
                val b = WireJson.json.decodeFromString(RegisterRequest.serializer(), bodyJson!!)
                val norm = TrustGrammar.emailNorm(b.email)!!
                if (b.auth !is RegisterAuth.Setup && cards.isEmpty()) return refuse(409, "setup_incomplete")
                if (norm in accounts) return refuse(409, "email_taken")
                if (belowFloor(b.kdfParams)) return refuse(400, "kdf_too_weak")
                val pieceId = piece()
                val a = Account(b.userId, b.authKey, b.kdfSalt, b.kdfParams, b.wrappedUvk, b.encryptedIdentitySeed, b.identityPub, b.genesis, b.personalWrap,
                    b.memberRecovery!!, pieceId)
                if (b.auth is RegisterAuth.Setup) operatorUserId = b.userId
                a.posture = b.recovery.posture
                a.escrowFp = b.recovery.escrow?.fingerprint
                val deviceId = uuid()
                a.devices[deviceId] = b.device.deviceSecret
                accounts[norm] = a
                lastRegister = b
                ok(session(a, deviceId, pieceId), decode)
            }
            WireRoute.PRELOGIN -> {
                val b = WireJson.json.decodeFromString(PreloginRequest.serializer(), bodyJson!!)
                val a = accounts[TrustGrammar.emailNorm(b.email)]
                ok(WireJson.json.encodeToString(PreloginResponse.serializer(), PreloginResponse(a?.kdfSalt ?: Bytes.toB64(ByteArray(16) { 1 }), a?.kdfParams ?: KdfParams.DEFAULT)), decode)
            }
            WireRoute.LOGIN -> {
                val b = WireJson.json.decodeFromString(LoginRequest.serializer(), bodyJson!!)
                val a = accounts[TrustGrammar.emailNorm(b.email)] ?: return refuse(401, "invalid_credentials")
                if (a.authKey != b.authKey) return refuse(401, "invalid_credentials")
                if (a.totp != null) {
                    if (b.totp == null) return refuse(401, "totp_required")
                    if (b.totp != a.totp) return refuse(401, "invalid_credentials")
                }
                val known = b.device.deviceId?.let { a.devices[it] == b.device.deviceSecret } ?: false
                if (!known && a.requireLink) return refuse(403, "link_required")
                val deviceId = if (known) b.device.deviceId!! else uuid().also { a.devices[it] = b.device.deviceSecret }
                namedAtSignIn += b.replacesRefreshToken
                if (known && oneSessionPerDevice) live.values.removeAll { it.deviceId == deviceId }
                val named = b.replacesRefreshToken?.let { live[it] }
                if (endsNamedSession && known && named != null && named.userId == a.userId && named.deviceId == deviceId) live.remove(b.replacesRefreshToken)
                ok(session(a, deviceId, null), decode)
            }
            WireRoute.ACCOUNT_STATE_GET -> {
                val a = accounts.values.last()
                ok(WireJson.json.encodeToString(AccountStateResponse.serializer(), AccountStateResponse(a.sealedState, a.stateSeq)), decode)
            }
            WireRoute.ACCOUNT_STATE_PUT -> {
                val a = accounts.values.last()
                val b = WireJson.json.decodeFromString(AccountStatePut.serializer(), bodyJson!!)
                if (b.baseSeq != a.stateSeq) return refuse(409, "stale_state")
                a.sealedState = b.sealedState
                a.stateSeq++
                ok(WireJson.json.encodeToString(AccountStateResponse.serializer(), AccountStateResponse(a.sealedState, a.stateSeq)), decode)
            }
            WireRoute.ACCOUNT_RECOVERY_PUT -> {
                val b = WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.AccountRecoveryPut.serializer(), bodyJson!!)
                val a = accounts.values.firstOrNull { it.authKey == b.currentAuthKey } ?: return refuse(403, "reauth_failed")
                if (b.posture == "private" && b.escrow != null) return refuse(400, "escrow_not_allowed")
                if (b.posture == "operator" && b.escrow == null) return refuse(400, "bad_escrow")
                if (b.accountState.baseSeq != a.stateSeq) return refuse(409, "stale_state")
                a.sealedState = b.accountState.sealedState
                a.stateSeq++
                a.posture = b.posture
                a.escrowFp = b.escrow?.fingerprint
                ok(WireJson.json.encodeToString(AccountStateResponse.serializer(), AccountStateResponse(a.sealedState, a.stateSeq)), decode)
            }
            WireRoute.ESCROW_SELF -> {
                val b = WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.EscrowSelfPut.serializer(), bodyJson!!)
                val a = accounts.values.last()
                val from = a.escrowFp ?: return refuse(409, "escrow_not_due")
                if (io.silencelen.andvari.core.trust.RecoveryRotation.verifyChain(crypto, b.rotations.map { Bytes.fromB64(it) }, instanceId, from, b.fingerprint) != null) {
                    return refuse(409, "escrow_not_due")
                }
                a.escrowFp = b.fingerprint
                ok("{}", decode)
            }
            WireRoute.RECOVERY_SELF_CONFIRM -> {
                val b = WireJson.json.decodeFromString(RecoverySelfConfirmRequest.serializer(), bodyJson!!)
                val a = accounts.values.firstOrNull { it.pieceId == b.pieceId } ?: return refuse(409, "piece_mismatch")
                a.recoveryConfirmed = true
                ok("{}", decode)
            }
            WireRoute.INSTANCE_CARD_PUT -> {
                val b = WireJson.json.decodeFromString(InstanceCardPut.serializer(), bodyJson!!)
                if (accounts.values.none { it.authKey == b.currentAuthKey }) return refuse(403, "reauth_failed")
                val frame = Bytes.fromB64(b.card)
                if (cards.isNotEmpty()) return refuse(409, "card_head_moved")
                val chain = InstanceCard.verifyChain(crypto, listOf(frame))
                if (chain.verdict != null) return refuse(400, "bad_card")
                cards += frame
                ok(WireJson.json.encodeToString(InstanceCardPutResponse.serializer(), InstanceCardPutResponse(0, SignedFrame.hash(crypto, frame))), decode)
            }
            WireRoute.RECOVERY_SELF_VERIFY -> {
                val b = WireJson.json.decodeFromString(RecoveryVerifyRequest.serializer(), bodyJson!!)
                val a = accounts[TrustGrammar.emailNorm(b.email)] ?: return refuse(401, "invalid_credentials")
                if (a.memberRecovery.recoveryAuthKey != b.recoveryAuthKey) return refuse(401, "invalid_credentials")
                ok(WireJson.json.encodeToString(RecoveryVerifyResponse.serializer(),
                    RecoveryVerifyResponse(a.userId, "ticket-${a.userId}", a.memberRecovery.recoveryWrappedUvk, a.encryptedIdentitySeed, a.identityPub)), decode)
            }
            WireRoute.RECOVERY_SELF_COMMIT -> {
                val b = WireJson.json.decodeFromString(RecoveryCommitRequest.serializer(), bodyJson!!)
                val a = accounts.values.firstOrNull { "ticket-${it.userId}" == b.recoveryTicket } ?: return refuse(401, "invalid_credentials")
                if (belowFloor(b.newKdfParams)) return refuse(400, "kdf_too_weak")
                a.authKey = b.newAuthKey; a.kdfSalt = b.newKdfSalt; a.kdfParams = b.newKdfParams; a.wrappedUvk = b.newWrappedUvk
                a.memberRecovery = b.newMemberRecovery ?: return refuse(400, "recovery_required")
                a.pieceId = piece(); a.recoveryConfirmed = false; a.requireLink = false; a.totp = null
                a.devices.clear()
                live.values.removeAll { it.userId == a.userId }
                val deviceId = uuid()
                a.devices[deviceId] = b.device.deviceSecret
                ok(session(a, deviceId, a.pieceId), decode)
            }
            WireRoute.PASSWORD_CHANGE -> {
                val b = WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.PasswordChangeRequest.serializer(), bodyJson!!)
                val a = accounts.values.firstOrNull { it.authKey == b.currentAuthKey } ?: return refuse(403, "reauth_failed")
                if (belowFloor(b.newKdfParams)) return refuse(400, "kdf_too_weak")
                a.authKey = b.newAuthKey; a.kdfSalt = b.newKdfSalt; a.kdfParams = b.newKdfParams; a.wrappedUvk = b.newWrappedUvk
                ok("{}", decode)
            }
            WireRoute.RECOVERY_SELF_SETUP -> {
                val b = WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.RecoverySelfSetupRequest.serializer(), bodyJson!!)
                val a = accounts.values.firstOrNull { it.authKey == b.currentAuthKey } ?: return refuse(403, "reauth_failed")
                a.memberRecovery = b.memberRecovery!!; a.pieceId = piece(); a.recoveryConfirmed = false
                ok(WireJson.json.encodeToString(io.silencelen.andvari.core.model.wire.RecoverySelfSetupResponse.serializer(),
                    io.silencelen.andvari.core.model.wire.RecoverySelfSetupResponse(a.pieceId)), decode)
            }
            WireRoute.END_SESSION -> {
                val b = WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.RefreshRequest.serializer(), bodyJson!!)
                live.remove(b.refreshToken)
                ok("{}", decode)
            }
            WireRoute.ACCOUNT_KEYS -> ok(WireJson.json.encodeToString(AccountKeys.serializer(), keys(accounts.values.last())), decode)
            WireRoute.DEVICES -> {
                val a = accounts.values.last()
                val me = bearer?.let { b -> a.devices.keys.firstOrNull { b.endsWith("-$it") } } ?: lastSessionDevice
                ok(WireJson.json.encodeToString(kotlinx.serialization.builtins.ListSerializer(io.silencelen.andvari.core.model.wire.Device.serializer()),
                    a.devices.keys.map { io.silencelen.andvari.core.model.wire.Device(it, "android", "Pixel", null, now, null, true, "registered", current = it == me) }), decode)
            }
            WireRoute.DEVICE_REVOKE -> {
                val b = WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.ReauthRequest.serializer(), bodyJson!!)
                val a = accounts.values.firstOrNull { it.authKey == b.currentAuthKey } ?: return refuse(403, "reauth_failed")
                a.devices.remove(pathParams.getValue("deviceId")) ?: return refuse(404, "not_found")
                ok("{}", decode)
            }
            WireRoute.REQUIRE_LINK -> {
                val b = WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.RequireLinkPut.serializer(), bodyJson!!)
                val a = accounts.values.firstOrNull { it.authKey == b.currentAuthKey } ?: return refuse(403, "reauth_failed")
                a.requireLink = b.enabled
                ok("{}", decode)
            }
            else -> WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
        }
    }

    var lastRegister: RegisterRequest? = null

    /** A CardTrust over this instance, with the origin pinned through the typed-address Trust Gate. */
    suspend fun pinnedTrust(state: DeviceState = MemoryDeviceState()): CardTrust {
        val t = trust(state)
        val gate = t.beginTrustGate(origin, TrustGateWording.TYPED_ADDRESS) as FirstPin.NeedsTrustGate
        t.confirmTrustGate(gate.confirm) as FirstPin.Pinned
        return t
    }

    fun trust(state: DeviceState = MemoryDeviceState()) = CardTrust(PinStore(state), TrustCardChainVerifier(crypto), { this }, crypto, null, false)
}
