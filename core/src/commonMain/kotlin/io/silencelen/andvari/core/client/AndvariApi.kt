package io.silencelen.andvari.core.client

import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.delete
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.ApiError
import io.silencelen.andvari.core.model.AttachmentMeta
import io.silencelen.andvari.core.model.ClientPolicy
import io.silencelen.andvari.core.model.CreateVaultRequest
import io.silencelen.andvari.core.model.CreateVaultResponse
import io.silencelen.andvari.core.model.LoginRequest
import io.silencelen.andvari.core.model.UserLookupRequest
import io.silencelen.andvari.core.model.UserLookupResponse
import io.silencelen.andvari.core.model.VaultMemberAdd
import io.silencelen.andvari.core.model.VaultMemberRole
import io.silencelen.andvari.core.model.VaultMemberSummary
import io.silencelen.andvari.core.model.PasswordChangeRequest
import io.silencelen.andvari.core.model.PreloginRequest
import io.silencelen.andvari.core.model.PreloginResponse
import io.silencelen.andvari.core.model.PushRequest
import io.silencelen.andvari.core.model.PushResponse
import io.silencelen.andvari.core.model.RefreshRequest
import io.silencelen.andvari.core.model.RegisterRequest
import io.silencelen.andvari.core.model.SessionResponse
import io.silencelen.andvari.core.model.SyncResponse
import io.silencelen.andvari.core.model.TokenPair
import io.silencelen.andvari.core.model.TotpCodeRequest
import io.silencelen.andvari.core.model.TotpSetupResponse
import io.silencelen.andvari.core.model.TotpStatus
import kotlinx.serialization.json.Json

class ApiException(val status: Int, val code: String, message: String) : Exception(message)

data class Tokens(val accessToken: String, val refreshToken: String)

const val ANDVARI_CLIENT_VERSION = "0.3.0"

/**
 * Kotlin API client (sibling of web/src/api/client.ts). Auto-refreshes the access
 * token once on 401 and retries. The HttpClient engine is provided per platform
 * (okhttp on Android, java on JVM) — commonMain stays engine-free.
 */
class AndvariApi(
    val baseUrl: String,
    engine: HttpClient,
    private var tokens: Tokens? = null,
    private val onTokens: (Tokens?) -> Unit = {},
) {
    private val clientHeader = "android/$ANDVARI_CLIENT_VERSION"
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    private val http = engine.config {
        install(ContentNegotiation) { json(this@AndvariApi.json) }
    }

    fun currentTokens(): Tokens? = tokens

    fun setTokens(t: Tokens?) {
        tokens = t
        onTokens(t)
    }

    private suspend fun request(
        method: String,
        path: String,
        body: Any? = null,
        auth: Boolean = true,
        retry: Boolean = true,
    ): HttpResponse {
        val resp: HttpResponse = when (method) {
            "GET" -> http.get(baseUrl + path) { common(auth) }
            "POST" -> http.post(baseUrl + path) { common(auth); if (body != null) { contentType(ContentType.Application.Json); setBody(body) } }
            "PUT" -> http.put(baseUrl + path) { common(auth); if (body != null) { contentType(ContentType.Application.Json); setBody(body) } }
            "DELETE" -> http.delete(baseUrl + path) { common(auth) }
            else -> error("unsupported method $method")
        }
        if (resp.status == HttpStatusCode.Unauthorized && auth && retry && tokens != null) {
            if (tryRefresh()) return request(method, path, body, auth, retry = false)
        }
        return resp
    }

    private fun io.ktor.client.request.HttpRequestBuilder.common(auth: Boolean) {
        header("X-Andvari-Client", clientHeader)
        if (auth) tokens?.let { header("Authorization", "Bearer ${it.accessToken}") }
    }

    private suspend fun tryRefresh(): Boolean {
        val t = tokens ?: return false
        val resp = http.post(baseUrl + "/api/v1/auth/refresh") {
            header("X-Andvari-Client", clientHeader)
            contentType(ContentType.Application.Json)
            setBody(RefreshRequest(t.refreshToken))
        }
        if (!resp.status.isSuccess()) {
            setTokens(null)
            return false
        }
        val pair = resp.body<TokenPair>()
        setTokens(Tokens(pair.accessToken, pair.refreshToken))
        return true
    }

    private suspend inline fun <reified T> call(method: String, path: String, body: Any? = null, auth: Boolean = true): T {
        val resp = request(method, path, body, auth)
        if (!resp.status.isSuccess()) throw errorFrom(resp)
        return resp.body()
    }

    private suspend fun errorFrom(resp: HttpResponse): ApiException {
        val err = try {
            json.decodeFromString(ApiError.serializer(), resp.bodyAsText())
        } catch (e: Exception) {
            ApiError("http_${resp.status.value}", resp.status.description)
        }
        return ApiException(resp.status.value, err.error, err.message)
    }

    suspend fun clientPolicy(): ClientPolicy = call("GET", "/api/v1/client-policy", auth = false)

    suspend fun recoveryPubkey(): String {
        val resp = request("GET", "/api/v1/recovery-pubkey", auth = false)
        if (!resp.status.isSuccess()) throw errorFrom(resp)
        return resp.bodyAsText().trim()
    }

    suspend fun prelogin(email: String): PreloginResponse = call("POST", "/api/v1/auth/prelogin", PreloginRequest(email), auth = false)

    suspend fun register(req: RegisterRequest): SessionResponse {
        val s: SessionResponse = call("POST", "/api/v1/auth/register", req, auth = false)
        setTokens(Tokens(s.accessToken, s.refreshToken))
        return s
    }

    suspend fun login(req: LoginRequest): SessionResponse {
        val s: SessionResponse = call("POST", "/api/v1/auth/login", req, auth = false)
        setTokens(Tokens(s.accessToken, s.refreshToken))
        return s
    }

    suspend fun accountKeys(): AccountKeys = call("GET", "/api/v1/account/keys")

    suspend fun sync(since: Long): SyncResponse = call("GET", "/api/v1/sync?since=$since")

    suspend fun push(req: PushRequest): PushResponse = call("POST", "/api/v1/sync/push", req)

    // ---- shared vaults (spec 03 §10) ----

    suspend fun createVault(req: CreateVaultRequest): CreateVaultResponse = call("POST", "/api/v1/vaults", req)

    suspend fun lookupUser(email: String): UserLookupResponse = call("POST", "/api/v1/users/lookup", UserLookupRequest(email))

    suspend fun vaultMembers(vaultId: String): List<VaultMemberSummary> = call("GET", "/api/v1/vaults/$vaultId/members")

    suspend fun addVaultMember(vaultId: String, req: VaultMemberAdd): CreateVaultResponse =
        call("POST", "/api/v1/vaults/$vaultId/members", req)

    suspend fun setVaultMemberRole(vaultId: String, userId: String, role: String): CreateVaultResponse =
        call("PUT", "/api/v1/vaults/$vaultId/members/$userId", VaultMemberRole(role))

    suspend fun removeVaultMember(vaultId: String, userId: String): CreateVaultResponse =
        call("DELETE", "/api/v1/vaults/$vaultId/members/$userId")

    // ---- attachments (spec 02 §6: body = header || ciphertext chunks) ----

    suspend fun uploadAttachment(attachmentId: String, itemId: String, vaultId: String, body: ByteArray): AttachmentMeta {
        val path = "/api/v1/attachments/$attachmentId?vaultId=$vaultId&itemId=$itemId"
        suspend fun send(): HttpResponse = http.post(baseUrl + path) {
            common(auth = true)
            contentType(ContentType.Application.OctetStream)
            setBody(body)
        }
        var resp = send()
        if (resp.status == HttpStatusCode.Unauthorized && tokens != null && tryRefresh()) resp = send()
        if (!resp.status.isSuccess()) throw errorFrom(resp)
        return resp.body()
    }

    suspend fun downloadAttachment(attachmentId: String): ByteArray {
        val resp = request("GET", "/api/v1/attachments/$attachmentId")
        if (!resp.status.isSuccess()) throw errorFrom(resp)
        return resp.body()
    }

    // ---- server TOTP + password change ----

    suspend fun totpStatus(): TotpStatus = call("GET", "/api/v1/account/totp")
    suspend fun totpSetup(): TotpSetupResponse = call("POST", "/api/v1/account/totp/setup")
    suspend fun totpConfirm(code: String): TotpStatus = call("POST", "/api/v1/account/totp/confirm", TotpCodeRequest(code))
    suspend fun totpDisable(code: String): TotpStatus = call("POST", "/api/v1/account/totp/disable", TotpCodeRequest(code))

    suspend fun changePassword(req: PasswordChangeRequest) {
        val resp = request("PUT", "/api/v1/account/password", req)
        if (!resp.status.isSuccess()) throw errorFrom(resp)
    }

    suspend fun logout() {
        try {
            request("POST", "/api/v1/auth/logout")
        } finally {
            setTokens(null)
        }
    }

    fun close() = http.close()
}

private fun HttpStatusCode.isSuccess(): Boolean = value in 200..299
