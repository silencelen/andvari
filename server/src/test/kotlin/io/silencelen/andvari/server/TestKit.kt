package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.header
import io.ktor.client.request.request
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import io.ktor.http.contentType
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.nio.file.Files

/** Shared fixtures for the server tests. Nothing here is used by production code. */
object TestKit {
    val crypto = createCryptoProvider()

    /** Fast Argon2 parameters for test accounts (the floor is off in [config]). */
    val FAST_KDF = KdfParams(ops = 1, memBytes = 8 * 1024 * 1024)

    fun tempDir(prefix: String = "andvari-l3"): File = Files.createTempDirectory(prefix).toFile().also { it.deleteOnExit() }

    fun config(
        dir: File = tempDir(),
        kind: String = "private",
        mode: String = "links",
        recoveryKey: ByteArray? = null,
        totpRequired: Boolean = false,
        requireAgeConfirm: Boolean = false,
        signupCap: Long = 200,
        powBits: Int = 0,
        blocklist: Set<String> = emptySet(),
        registerLinks: String? = null,
        signupDailyMax: Long = 25,
        itemMaxBytes: Long = 2L * 1024 * 1024,
        uploadMaxConcurrentPerUser: Int = 4,
        downloadsDir: String? = null,
        webDir: String? = null,
        minKdfOps: Long = 0,
        minKdfMemBytes: Long = 0,
    ): Config = Config(
        minKdfOps = minKdfOps,
        minKdfMemBytes = minKdfMemBytes,
        webDir = webDir,
        itemMaxBytes = itemMaxBytes,
        uploadMaxConcurrentPerUser = uploadMaxConcurrentPerUser,
        downloadsDir = downloadsDir,
        dbPath = File(dir, "andvari.db").path,
        blobDir = File(dir, "blobs").path,
        canonicalOrigin = "http://127.0.0.1:8080",
        instanceKind = kind,
        recoveryPublicKey = recoveryKey ?: ByteArray(0),
        recoveryFingerprint = recoveryKey?.let { sha256Hex(it) } ?: "",
        enumSecret = ByteArray(32) { 7 },
        signupSecret = ByteArray(32) { 9 },
        signupMode = mode,
        signupCap = signupCap,
        signupDailyMax = signupDailyMax,
        signupPowBits = powBits,
        signupBlocklist = blocklist,
        requireAgeConfirm = requireAgeConfirm,
        registerLinks = registerLinks,
        totpRequired = totpRequired,
        testMode = true,
        mailSinkDir = File(dir, "mail").path,
    )

    /**
     * A server for one test. Unless [policyKdf] is null, a policy is stored whose hashing cost is [FAST_KDF] (when none is
     * stored yet), so that the test accounts' fast cost meets the cost the server serves: a new wrap is held to that cost
     * on each figure ([PolicyStore.requireWrapKdf]). The server never runs the hash, so the figures only label the wrap.
     */
    fun services(config: Config = config(), clock: Clock = MutableClock(), trust: TrustVerifiers = CoreTrust(), policyKdf: KdfParams? = FAST_KDF): Services =
        Services(config, clock, Db(config.dbPath, durable = false), trust).also { s ->
            s.backgroundWorkers = false
            if (policyKdf != null) s.db.tx { c ->
                if (c.queryOne("SELECT 1 FROM policies WHERE id=1") { 1 } == null) s.policy.storeOn(c, s.policy.defaults().copy(kdfParams = policyKdf))
            }
        }

    /** An Ed25519 identity whose X25519 image is the account's `identityPub` (spec 01 §5). */
    class Identity(seed: ByteArray = crypto.randomBytes(32)) {
        val sign = crypto.signKeypairFromSeed(seed)
        val edPub: ByteArray get() = sign.publicKey
        val curvePub: ByteArray = crypto.ed25519PkToCurve25519(sign.publicKey)
        val identityPubB64: String = Bytes.toB64(curvePub)

        /** A v2 signed-statement frame (spec 01 §5.1) over [statement]. */
        fun frame(purpose: Int, statement: String): ByteArray {
            val header = byteArrayOf(0x61, 0x76, 0x73, 0x02, purpose.toByte())
            val st = statement.encodeToByteArray()
            val m = "andvari/v2|signed-statement".encodeToByteArray() + byteArrayOf(0) + header + sign.publicKey + st
            val sig = crypto.signDetached(sign.privateKey, m)
            return header + sign.publicKey + sig + st
        }
    }

    /** A seeded account: its id, email, auth key and identity. */
    class Account(val userId: String, val email: String, val authKey: String, val identity: Identity, val personalVaultId: String)

    /** Insert an account straight into the database (the register route lands in slice 2). */
    fun seedAccount(s: Services, email: String, role: String = "member", identity: Identity = Identity()): Account {
        val userId = uuid()
        val authKey = Bytes.toB64(crypto.randomBytes(32))
        val pv = uuid()
        s.db.tx { c ->
            // A real genesis frame signed by the identity: the card checks compare against its signer key (spec 03 §17.2).
            val genesis = Bytes.toB64(
                identity.frame(
                    5,
                    "{\"v\":2,\"purpose\":\"account-genesis\",\"userId\":\"$userId\",\"identityKey\":\"${identity.identityPubB64}\"," +
                        "\"instanceId\":\"${s.instance.instanceId(c)}\",\"personalVaultId\":\"$pv\",\"createdAt\":1800000000000}",
                ),
            )
            c.exec(
                """INSERT INTO users(userId,email,displayName,kdfSalt,kdfParams,verifier,wrappedUvk,identityPub,encryptedIdentitySeed,genesis,personalVaultId,role,createdAt,registeredVia)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                userId, email, "Test", Bytes.toB64(ByteArray(16)), encodeParams(FAST_KDF), ServerCrypto.hashVerifier(authKey),
                "AAAA", identity.identityPubB64, "AAAA", genesis, pv, role, s.clock.now(), if (role == "operator") "setup" else "enrol",
            )
        }
        return Account(userId, email, authKey, identity, pv)
    }

    /** Mint a session for [a] on a fresh device, as a native client unless [platform] says otherwise. */
    fun session(s: Services, a: Account, platform: String = "linux"): String = s.db.tx { c ->
        val dev = s.sessions.createDevice(c, a.userId, platform, "test device", "registered", null, "1.0.0")
        s.sessions.issue(c, a.userId, dev, platform, passwordLogin = true).accessToken
    }

    fun cardStatement(
        instanceId: String, seq: Long, prev: String, origin: String, nameB64: String, kind: String,
        operator: String, operatorSignKey: ByteArray, recoveryFp: String, issuedAt: Long,
    ): String =
        "{\"v\":2,\"purpose\":\"instance-card\",\"instanceId\":\"$instanceId\",\"seq\":$seq,\"prev\":\"$prev\",\"origin\":\"$origin\"," +
            "\"name\":\"$nameB64\",\"kind\":\"$kind\",\"operator\":\"$operator\",\"operatorSignKey\":\"${Bytes.toB64(operatorSignKey)}\"," +
            "\"recoveryFp\":\"$recoveryFp\",\"issuedAt\":$issuedAt}"

    val ZERO64 = "0".repeat(64)
}

/** One JSON request with the client header. */
suspend fun HttpClient.call(
    method: HttpMethod, path: String, body: String? = null, token: String? = null,
    client: String = "linux/1.0.0", ip: String = randomIp(), extra: HttpRequestBuilder.() -> Unit = {},
): HttpResponse = request(path) {
    this.method = method
    header("X-Andvari-Client", client)
    header("X-Forwarded-For", ip)
    token?.let { header("Authorization", "Bearer $it") }
    if (body != null) { contentType(ContentType.Application.Json); setBody(body) }
    extra()
}

/** A fresh client address per request, so per-IP buckets do not couple unrelated test steps. */
fun randomIp(): String = "10.${(0..255).random()}.${(0..255).random()}.${(1..254).random()}"

suspend fun HttpResponse.errorCode(): String? =
    runCatching { WireJson.json.parseToJsonElement(bodyAsText()).jsonObject["error"]?.jsonPrimitive?.content }.getOrNull()
