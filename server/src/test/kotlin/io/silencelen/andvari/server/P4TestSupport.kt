package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.testing.ApplicationTestBuilder
import io.silencelen.andvari.core.crypto.Base32
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.Totp
import io.silencelen.andvari.core.crypto.TotpConfig
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AdminStatus
import io.silencelen.andvari.core.model.ApiError
import io.silencelen.andvari.core.model.Mutation
import io.silencelen.andvari.core.model.PushRequest
import io.silencelen.andvari.core.model.PushResponse
import io.silencelen.andvari.core.model.SessionResponse
import io.silencelen.andvari.core.model.SyncResponse
import io.silencelen.andvari.core.model.TotpStatus
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.assertEquals

/**
 * Shared scaffolding for the P4 feature tests (attachments, server TOTP,
 * password change, admin surface) — same house style as ServerIntegrationTest.
 */
abstract class P4TestSupport {
    protected val crypto = createCryptoProvider()
    protected val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
    protected val fingerprint = Escrow.fingerprint(crypto, recovery.publicKey)
    protected val bootstrapToken = "p4-bootstrap-token"
    protected val tmpDir: File = Files.createTempDirectory("andvari-p4").toFile()

    protected fun config(publicHostname: String? = null) = Config(
        host = "127.0.0.1", port = 0,
        dbPath = File(tmpDir, "p4-${System.nanoTime()}.db").absolutePath,
        blobDir = File(tmpDir, "blobs-${System.nanoTime()}").absolutePath, webDir = null,
        recoveryPublicKey = recovery.publicKey, recoveryFingerprint = fingerprint,
        enumSecret = ByteArray(32) { 7 }, publicHostname = publicHostname, bootstrapToken = bootstrapToken,
    )

    @AfterTest fun cleanupTmp() { tmpDir.deleteRecursively() }

    protected fun jsonClient(builder: ApplicationTestBuilder): HttpClient = builder.createClient {
        install(ContentNegotiation) { json(json) }
    }

    protected fun HttpRequestBuilder.authed(vc: VirtualClient) = authed(vc.accessToken)

    protected fun HttpRequestBuilder.authed(accessToken: String) {
        header("Authorization", "Bearer $accessToken")
        header("X-Andvari-Client", "test/1.0.0")
    }

    /** Register a VirtualClient (the bootstrap invite makes the first one admin). */
    protected suspend fun HttpClient.register(vc: VirtualClient, invite: String): SessionResponse {
        val resp = post("/api/v1/auth/register") {
            contentType(ContentType.Application.Json)
            header("X-Andvari-Client", "test/1.0.0")
            setBody(vc.buildRegister(invite, recovery.publicKey, fingerprint))
        }
        assertEquals(HttpStatusCode.OK, resp.status, "register: ${resp.bodyAsText()}")
        val session = json.decodeFromString(SessionResponse.serializer(), resp.bodyAsText())
        vc.userId = session.userId; vc.accessToken = session.accessToken; vc.refreshToken = session.refreshToken
        return session
    }

    protected suspend fun HttpClient.pushRaw(vc: VirtualClient, vararg mutations: Mutation): HttpResponse =
        post("/api/v1/sync/push") {
            contentType(ContentType.Application.Json)
            authed(vc)
            setBody(PushRequest(mutations.toList()))
        }

    protected suspend fun HttpClient.push(vc: VirtualClient, vararg mutations: Mutation): PushResponse {
        val resp = pushRaw(vc, *mutations)
        assertEquals(HttpStatusCode.OK, resp.status, "push: ${resp.bodyAsText()}")
        return json.decodeFromString(PushResponse.serializer(), resp.bodyAsText())
    }

    protected suspend fun HttpClient.sync(vc: VirtualClient, since: Long = 0): SyncResponse {
        val resp = get("/api/v1/sync?since=$since") { authed(vc) }
        assertEquals(HttpStatusCode.OK, resp.status, "sync: ${resp.bodyAsText()}")
        return json.decodeFromString(SyncResponse.serializer(), resp.bodyAsText())
    }

    protected fun putMutation(
        vc: VirtualClient,
        itemId: String,
        plaintext: String,
        baseRev: Long,
        attachmentIds: List<String> = emptyList(),
    ) = Mutation(uuid(), "put", itemId, vc.personalVaultId, baseRev, vc.encItem(itemId, plaintext).copy(attachmentIds = attachmentIds))

    /** Raw attachment upload: body = header(24) || ciphertext, exactly the wire shape. */
    protected suspend fun HttpClient.uploadAttachment(
        vc: VirtualClient,
        attachmentId: String,
        itemId: String,
        body: ByteArray,
        vaultId: String = vc.personalVaultId,
    ): HttpResponse = post("/api/v1/attachments/$attachmentId?vaultId=$vaultId&itemId=$itemId") {
        authed(vc)
        contentType(ContentType.Application.OctetStream)
        setBody(body)
    }

    protected suspend fun errorOf(resp: HttpResponse): String =
        json.decodeFromString(ApiError.serializer(), resp.bodyAsText()).error

    protected suspend fun HttpClient.totpStatus(vc: VirtualClient): TotpStatus {
        val resp = get("/api/v1/account/totp") { authed(vc) }
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
        return json.decodeFromString(TotpStatus.serializer(), resp.bodyAsText())
    }

    protected suspend fun HttpClient.adminStatus(vc: VirtualClient): AdminStatus {
        val resp = get("/api/v1/admin/status") { authed(vc) }
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
        return json.decodeFromString(AdminStatus.serializer(), resp.bodyAsText())
    }

    /** RFC 6238 code for the current step (+offset), same primitives a real authenticator uses. */
    protected fun totpCode(secretBase32: String, stepOffset: Long = 0): String {
        val cfg = TotpConfig(secret = Base32.decode(secretBase32))
        val step = now() / 1000 / cfg.periodSeconds + stepOffset
        return Totp.code(crypto, cfg, step * cfg.periodSeconds)
    }
}
