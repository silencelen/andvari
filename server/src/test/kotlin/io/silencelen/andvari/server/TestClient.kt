package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.silencelen.andvari.core.crypto.Base32
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Totp
import io.silencelen.andvari.core.crypto.TotpConfig
import io.silencelen.andvari.core.model.wire.EscrowUpload
import io.silencelen.andvari.core.model.wire.MemberRecoveryBlock
import io.silencelen.andvari.core.model.wire.NewDevice
import io.silencelen.andvari.core.model.wire.PersonalVaultUpload
import io.silencelen.andvari.core.model.wire.PersonalWrap
import io.silencelen.andvari.core.model.wire.RecoveryChoice
import io.silencelen.andvari.core.model.wire.RegisterAuth
import io.silencelen.andvari.core.model.wire.RegisterRequest
import io.silencelen.andvari.core.model.wire.SessionResponse
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.assertEquals

/** A would-be account, client side: everything a client chooses before registering. */
class Me(
    val email: String,
    val userId: String = uuid(),
    val identity: TestKit.Identity = TestKit.Identity(),
    val personalVaultId: String = uuid(),
    val authKey: String = Bytes.toB64(TestKit.crypto.randomBytes(32)),
    val deviceSecret: String = Bytes.toB64(TestKit.crypto.randomBytes(32)),
    val recoveryAuthKey: String = Bytes.toB64(TestKit.crypto.randomBytes(32)),
) {
    var session: SessionResponse? = null
    val token: String get() = session!!.accessToken
    val deviceId: String get() = session!!.deviceId

    fun genesis(instanceId: String, pv: String = personalVaultId): String = Bytes.toB64(
        identity.frame(
            5,
            "{\"v\":2,\"purpose\":\"account-genesis\",\"userId\":\"$userId\",\"identityKey\":\"${identity.identityPubB64}\"," +
                "\"instanceId\":\"$instanceId\",\"personalVaultId\":\"$pv\",\"createdAt\":1800000000000}",
        ),
    )

    fun register(
        s: Services, auth: RegisterAuth, posture: String = "private", escrow: EscrowUpload? = null,
        memberRecovery: MemberRecoveryBlock? = MemberRecoveryBlock("AAAAAAAAAAAAAAAA", recoveryAuthKey),
        ageConfirmed: Boolean = true, wrapVaultId: String = personalVaultId, platform: String = "linux",
    ): String = WireJson.json.encodeToString(
        RegisterRequest.serializer(),
        RegisterRequest(
            auth = auth, email = email, displayName = "Me", userId = userId,
            kdfSalt = Bytes.toB64(ByteArray(16) { 3 }), kdfParams = TestKit.FAST_KDF, authKey = authKey,
            wrappedUvk = "AAAAAAAAAAAAAAAA", identityPub = identity.identityPubB64, encryptedIdentitySeed = "AAAAAAAAAAAAAAAA",
            genesis = genesis(s.db.read { s.instance.instanceId(it) }),
            personalVault = PersonalVaultUpload(personalVaultId, "AAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAA"),
            personalWrap = PersonalWrap(wrapVaultId, "AAAAAAAAAAAAAAAA"),
            memberRecovery = memberRecovery, recovery = RecoveryChoice(posture, escrow), ageConfirmed = ageConfirmed,
            device = NewDevice(platform, "my laptop", deviceSecret),
        ),
    )

    fun loginBody(
        deviceId: String? = null, secret: String = deviceSecret, totp: String? = null, authKey: String = this.authKey,
        platform: String = "linux", replaces: String? = null,
    ): String =
        """{"email":"$email","authKey":"$authKey","device":{"platform":"$platform","name":"other laptop","deviceSecret":"$secret"${deviceId?.let { ",\"deviceId\":\"$it\"" } ?: ""}}${totp?.let { ",\"totp\":\"$it\"" } ?: ""}${replaces?.let { ",\"replacesRefreshToken\":\"$it\"" } ?: ""}}"""
}

/** When the proofs' back-off of [me]'s current session's device lapses (0 when it holds nothing). */
fun Services.proofLock(me: Me): Long = proofBackoff.lockedUntil(deviceCounterKey(me.deviceId))

/** When the codes' back-off of [me]'s current session's device lapses (0 when it holds nothing). */
fun Services.codeLock(me: Me): Long = codeBackoff.lockedUntil(deviceCounterKey(me.deviceId))

object Flow {
    /** Mint a link through [mint] and return what its recipient derives: (linkId, registerToken). */
    fun linkAuth(url: String): Pair<String, String> {
        val (linkId, _, token) = HostLinks.clientView(HostLinks.secretOf(url)!!)
        return linkId to token
    }

    fun setupAuth(s: Services): RegisterAuth.Setup {
        val url = s.db.tx { c -> HostLinks.mintSetup(c, s.config, s.instance.setupOn(c)!!, s.clock.now()).url }
        val (id, tok) = linkAuth(url)
        return RegisterAuth.Setup(id, tok)
    }

    fun enrolAuth(s: Services, bound: String? = null): RegisterAuth.Enrol {
        val url = s.db.tx { c -> HostLinks.mintEnrol(c, s.config, s.instance.instanceId(c), s.instance.card0Hash(c)!!, bound, Clock.DAY_MS, s.clock.now()).url }
        val (id, tok) = linkAuth(url)
        return RegisterAuth.Enrol(id, tok)
    }

    suspend fun register(
        client: HttpClient, s: Services, me: Me, auth: RegisterAuth, posture: String = "private", escrow: EscrowUpload? = null, platform: String = "linux",
    ): SessionResponse {
        val r = client.call(HttpMethod.Post, "/api/v1/auth/register", me.register(s, auth, posture, escrow, platform = platform))
        assertEquals(200, r.status.value, r.bodyAsText())
        return WireJson.json.decodeFromString(SessionResponse.serializer(), r.bodyAsText()).also { me.session = it }
    }

    /** Enrol the operator through the setup link and sign card 0: the instance is then ready. */
    suspend fun finishSetup(client: HttpClient, s: Services, recoveryFp: String = s.config.recoveryFpOrNone): Me {
        val op = Me("operator@example.com")
        register(client, s, op, setupAuth(s))
        finishSetupCardOnly(client, s, op, recoveryFp)
        return op
    }

    /** Sign card 0 as [op], already registered through the setup link. */
    suspend fun finishSetupCardOnly(client: HttpClient, s: Services, op: Me, recoveryFp: String = s.config.recoveryFpOrNone) {
        val setup = s.db.read { s.instance.setupOn(it)!! }
        val c0 = op.identity.frame(4, TestKit.cardStatement(setup.instanceId, 0, TestKit.ZERO64, s.config.canonicalOrigin, setup.name, s.config.instanceKind, op.userId, op.identity.edPub, recoveryFp, 1_800_000_000_000))
        val r = client.call(HttpMethod.Put, "/api/v1/instance/card", """{"card":"${Bytes.toB64(c0)}","currentAuthKey":"${op.authKey}"}""", op.token)
        assertEquals(200, r.status.value, r.bodyAsText())
    }

    /** Store card 0 for [op] directly (tests where the operator's session cannot sign it yet). */
    fun forceCard0(s: Services, op: Me) {
        val setup = s.db.read { s.instance.setupOn(it)!! }
        val c0 = op.identity.frame(4, TestKit.cardStatement(setup.instanceId, 0, TestKit.ZERO64, s.config.canonicalOrigin, setup.name, s.config.instanceKind, op.userId, op.identity.edPub, s.config.recoveryFpOrNone, 1))
        s.db.tx { it.exec("INSERT INTO instance_cards(seq,hash,frame,operatorId,name,recoveryFp,storedAt) VALUES(0,?,?,?,?,?,1)", sha256Hex(c0), Bytes.toB64(c0), op.userId, setup.name, s.config.recoveryFpOrNone) }
    }

    /**
     * A recovery copy of the one size the server stores for [email]'s address ([EscrowCopy.sealedBytes]): the server
     * cannot open a copy, so its bytes are filler. [fill] tells two copies apart.
     */
    fun escrowFor(email: String, fp: String, fill: Byte = 0): EscrowUpload =
        EscrowUpload(Bytes.toB64(ByteArray(EscrowCopy.sealedBytes(Grammar.emailNorm(email)!!)) { fill }), fp)

    /** [escrowFor] the address of [me]. */
    fun escrow(me: Me, fp: String, fill: Byte = 0): EscrowUpload = escrowFor(me.email, fp, fill)

    /** A member enrolled through a host enrol link; its first device row is made as [platform]'s (`web`: a browser's row). */
    suspend fun member(client: HttpClient, s: Services, email: String, platform: String = "linux"): Me =
        Me(email).also { register(client, s, it, enrolAuth(s), platform = platform) }

    /** Every message in the sink, oldest first: (template, to, text). */
    fun sink(s: Services): List<Triple<String, String, String>> {
        s.mail.drain()
        val dir = File(s.config.mailSinkDir!!)
        return (dir.listFiles()?.sortedBy { it.name } ?: emptyList()).map { f ->
            val o = WireJson.json.parseToJsonElement(f.readText()).jsonObject
            Triple(o["template"]!!.jsonPrimitive.content, o["to"]!!.jsonPrimitive.content, o["text"]!!.jsonPrimitive.content)
        }
    }

    fun codeIn(text: String): String = Regex("\\b(\\d{6})\\b").find(text)!!.groupValues[1]

    fun totp(secretBase32: String, nowMs: Long): String =
        Totp.code(TestKit.crypto, TotpConfig(secret = Base32.decode(secretBase32)), nowMs / 1000)
}
