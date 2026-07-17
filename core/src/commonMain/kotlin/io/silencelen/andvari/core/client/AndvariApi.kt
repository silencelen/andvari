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
import io.silencelen.andvari.core.model.DeletedVaultSummary
import io.silencelen.andvari.core.model.DeletedItem
import io.silencelen.andvari.core.model.DeletedItemsResponse
import io.silencelen.andvari.core.model.EscrowUpload
import io.silencelen.andvari.core.model.ItemRestoreResponse
import io.silencelen.andvari.core.model.ItemUpload
import io.silencelen.andvari.core.model.ItemVersion
import io.silencelen.andvari.core.model.ItemVersionsResponse
import io.silencelen.andvari.core.model.LoginRequest
import io.silencelen.andvari.core.model.TransferAcceptRequest
import io.silencelen.andvari.core.model.TransferOfferRequest
import io.silencelen.andvari.core.model.TransferOfferResponse
import io.silencelen.andvari.core.model.UserLookupRequest
import io.silencelen.andvari.core.model.UserLookupResponse
import io.silencelen.andvari.core.model.VaultDeleteRequest
import io.silencelen.andvari.core.model.VaultDeleteResponse
import io.silencelen.andvari.core.model.VaultMemberAdd
import io.silencelen.andvari.core.model.VaultMemberRemoveRequest
import io.silencelen.andvari.core.model.VaultMemberRole
import io.silencelen.andvari.core.model.VaultMemberSummary
import io.silencelen.andvari.core.model.VaultMetaUpdateRequest
import io.silencelen.andvari.core.model.VaultRestoreRequest
import io.silencelen.andvari.core.model.PasswordChangeRequest
import io.silencelen.andvari.core.model.PreloginRequest
import io.silencelen.andvari.core.model.PreloginResponse
import io.silencelen.andvari.core.model.PushRequest
import io.silencelen.andvari.core.model.PushResponse
import io.silencelen.andvari.core.model.RefreshRequest
import io.silencelen.andvari.core.model.RecoveryCommitRequest
import io.silencelen.andvari.core.model.RecoverySelfConfirmRequest
import io.silencelen.andvari.core.model.RecoverySelfSetupRequest
import io.silencelen.andvari.core.model.RecoverySelfSetupResponse
import io.silencelen.andvari.core.model.RecoveryVerifyRequest
import io.silencelen.andvari.core.model.RecoveryVerifyResponse
import io.silencelen.andvari.core.model.RegisterRequest
import io.silencelen.andvari.core.model.SessionResponse
import io.silencelen.andvari.core.model.SyncResponse
import io.silencelen.andvari.core.model.TokenPair
import io.silencelen.andvari.core.model.TotpCodeRequest
import io.silencelen.andvari.core.model.TotpSetupResponse
import io.silencelen.andvari.core.model.TotpStatus
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.Json

open class ApiException(val status: Int, val code: String, message: String) : Exception(message)

/**
 * Typed 426 surface (spec 03 §1): the server's policy pins minVersion above this build.
 * A subclass of [ApiException] so every existing `catch (e: ApiException)` keeps working;
 * UI layers catch this specifically to show a blocking "update required" screen (both
 * natives wire it via their state holders' upgradeRequired surface).
 */
class UpgradeRequiredException(code: String, message: String) : ApiException(426, code, message)

data class Tokens(val accessToken: String, val refreshToken: String)

/**
 * THE release version — the single Kotlin source of truth. SERVER_VERSION and
 * DESKTOP_VERSION alias this constant, and verify.sh asserts the Gradle-side copies
 * (android versionName, desktop packageVersion) stay equal to it, so a release bump can't
 * skew across artifacts again (0.4.0 shipped with two modules still claiming 0.3.0).
 */
const val ANDVARI_CLIENT_VERSION = "0.19.0"

/**
 * Kotlin API client (sibling of web/src/api/client.ts). Auto-refreshes the access
 * token once on 401 and retries. The HttpClient engine is provided per platform
 * (okhttp on Android, java on JVM) — commonMain stays engine-free.
 *
 * [platform] is the wire platform tag (X-Andvari-Client = "<platform>/<version>") that the
 * server's per-platform minVersion gate keys on. Defaults to "android" — the historical
 * value every fielded client sends; desktop passes "windows"/"linux" so a desktop pin is
 * actually addressable. Client-reported and therefore advisory-only: the 426 gate nudges
 * honest clients toward updating and must never be treated as a security control.
 */
class AndvariApi(
    val baseUrl: String,
    engine: HttpClient,
    private var tokens: Tokens? = null,
    private val onTokens: (Tokens?) -> Unit = {},
    platform: String = "android",
) {
    private val clientHeader = "$platform/$ANDVARI_CLIENT_VERSION"
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
            "DELETE" -> http.delete(baseUrl + path) { common(auth); if (body != null) { contentType(ContentType.Application.Json); setBody(body) } }
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

    // Serializes refresh: two concurrent 401s must not both POST the same rotating
    // refresh token — the server's reuse detection would revoke the whole device.
    private val refreshMutex = Mutex()

    private suspend fun tryRefresh(): Boolean {
        val observed = tokens ?: return false
        return refreshMutex.withLock {
            val current = tokens ?: return@withLock false // concurrently signed out
            // Another coroutine already rotated while we waited on the lock — the caller
            // just retries with the fresh pair; a second POST would double-spend.
            if (current !== observed) return@withLock true
            val resp = http.post(baseUrl + "/api/v1/auth/refresh") {
                header("X-Andvari-Client", clientHeader)
                contentType(ContentType.Application.Json)
                setBody(RefreshRequest(current.refreshToken))
            }
            if (!resp.status.isSuccess()) {
                // Only a definitive auth verdict kills the pair; a transient 502/503/429
                // from a proxy must not sign the device out — keep the tokens, fail this try.
                if (resp.status.value == 401 || resp.status.value == 403) setTokens(null)
                return@withLock false
            }
            val pair = resp.body<TokenPair>()
            setTokens(Tokens(pair.accessToken, pair.refreshToken))
            true
        }
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
        // upgrade_required is the min-version pin firing (spec 03 §1) — surface it typed
        // so callers can distinguish "this build is banned" from transient errors. The
        // BODY code is the contract (the server's pin always sends
        // ApiError("upgrade_required", …) alongside its 426 — App.kt StatusPages), NOT the
        // status: a bare 426 from an intermediary/captive portal with a non-JSON body must
        // fall through to a plain ApiException, never brick the client behind the blocking
        // upgrade screen.
        if (err.error == "upgrade_required") {
            return UpgradeRequiredException(err.error, err.message)
        }
        return ApiException(resp.status.value, err.error, err.message)
    }

    suspend fun clientPolicy(): ClientPolicy {
        // H1 fence (spec 05 T1): a server-chosen enrollment/upgrade KDF policy can never weaken or
        // DoS the master-password KDF. Closes the export/backup (R1) + password-change (R2) reuse paths.
        val p: ClientPolicy = call("GET", "/api/v1/client-policy", auth = false)
        KdfUpgrade.requireServerKdfParams(p.kdfParams)
        return p
    }

    suspend fun recoveryPubkey(): String {
        val resp = request("GET", "/api/v1/recovery-pubkey", auth = false)
        if (!resp.status.isSuccess()) throw errorFrom(resp)
        return resp.bodyAsText().trim()
    }

    /**
     * F57: re-upload this account's escrow blob, re-sealed to the current org recovery key
     * (`PUT /escrow/self`). The blob is built by [Account.resealEscrowFor], which binds the
     * fetched [recoveryPubkey] to a fingerprint the USER verified against the printed sheet.
     */
    suspend fun escrowSelf(upload: EscrowUpload) {
        val resp = request("PUT", "/api/v1/escrow/self", body = upload)
        if (!resp.status.isSuccess()) throw errorFrom(resp)
    }

    // ---- per-member self-service recovery (design 2026-07-12 §F.3 + 2026-07-13 piece-binding) ----
    // Shared surface for the native recovery screens + the vault-entry capture gate. Web keeps its own
    // client.ts twins; these mirror them so android/desktop stop hand-rolling raw Ktor calls (which
    // bypass the shared refresh/error path). verify/commit are unauthenticated (the forgot-password
    // entry, pre-session); setup/confirm are authenticated. All four are server-refused on the public
    // break-glass origin + per-IP rate-limited (spec 03 §12).

    /** Phase 1 of forgot-master-password: prove possession of the recovery piece; returns the single-
     *  use ticket + the wrapped UVK / identity material the client needs to derive the new session.
     *  Unauthenticated; the uniform 401 covers unknown-email / no-row / bad-key (anti-enumeration). */
    suspend fun recoverySelfVerify(email: String, recoveryAuthKey: String): RecoveryVerifyResponse =
        call("POST", "/api/v1/recovery/self/verify", RecoveryVerifyRequest(email, recoveryAuthKey), auth = false)

    /** Phase 2 of forgot-master-password: commit the reset (new verifier/wrappedUvk/kdf, sessions
     *  revoked) against the single-use ticket from [recoverySelfVerify]. Unauthenticated. */
    suspend fun recoverySelfCommit(req: RecoveryCommitRequest) {
        val resp = request("POST", "/api/v1/recovery/self/commit", body = req, auth = false)
        if (!resp.status.isSuccess()) throw errorFrom(resp)
    }

    /** Authenticated migration/rotation of the member-recovery piece (fresh currentAuthKey reauth).
     *  Returns the opaque [RecoverySelfSetupResponse.pieceId] of the piece just committed; a pre-
     *  binding server answers the text "ok", which we tolerate as `pieceId = null` (⇒ the caller's
     *  confirm rides the legacy device-scoped path). Never throws on body shape alone at 2xx. */
    suspend fun recoverySelfSetup(req: RecoverySelfSetupRequest): RecoverySelfSetupResponse {
        val resp = request("PUT", "/api/v1/recovery/self-setup", body = req)
        if (!resp.status.isSuccess()) throw errorFrom(resp)
        return try {
            json.decodeFromString(RecoverySelfSetupResponse.serializer(), resp.bodyAsText())
        } catch (_: Exception) {
            RecoverySelfSetupResponse(pieceId = null)
        }
    }

    /** Flip the durable, cross-device `recoveryConfirmed` flag after the user demonstrably typed the
     *  revealed phrase back. Send the [pieceId] you revealed (bound); a mismatch — a concurrent setup
     *  rotated the piece away — throws `ApiException(409, "recovery_piece_stale")`, and the caller
     *  MUST discard the shown phrase and re-run setup + reveal. `null` sends an empty body (the legacy
     *  wire shape; the server device-scopes acceptance). */
    suspend fun recoverySelfConfirm(pieceId: String?) {
        val resp = if (pieceId != null) {
            request("POST", "/api/v1/recovery/self/confirm", body = RecoverySelfConfirmRequest(pieceId))
        } else {
            request("POST", "/api/v1/recovery/self/confirm")
        }
        if (!resp.status.isSuccess()) throw errorFrom(resp)
    }

    /** Feature: item history — the archived ciphertext versions of an item, newest rev first
     *  (server keeps the last 10). Grant-checked; the caller decrypts each blob under the held VK. */
    suspend fun itemVersions(itemId: String): List<ItemVersion> =
        call<ItemVersionsResponse>("GET", "/api/v1/items/$itemId/versions").versions

    /** Item undelete (feature): the caller's tombstoned items (grant-scoped server-side). */
    suspend fun deletedItems(): List<DeletedItem> =
        call<DeletedItemsResponse>("GET", "/api/v1/items/deleted").items

    /** Item undelete (feature): restore a tombstoned item from a re-encrypted version; returns the new rev. */
    suspend fun restoreItem(itemId: String, upload: ItemUpload): Long =
        call<ItemRestoreResponse>("POST", "/api/v1/items/$itemId/restore", body = upload).rev

    /** Item undelete (F49): "Delete forever" — hard-delete a tombstoned item + its versions. */
    suspend fun purgeItem(itemId: String): Long =
        call<ItemRestoreResponse>("POST", "/api/v1/items/$itemId/purge").rev

    suspend fun prelogin(email: String): PreloginResponse {
        // H1 fence (spec 05 T1): the login KDF params the fresh-device client is about to derive
        // under must sit within [64 MiB, 1 GiB] / [t=3, t=10] — a weakened set makes the transmitted
        // authKey offline-crackable once a hostile server captures it.
        val p: PreloginResponse = call("POST", "/api/v1/auth/prelogin", PreloginRequest(email), auth = false)
        KdfUpgrade.requireServerKdfParams(p.kdfParams)
        return p
    }

    suspend fun register(req: RegisterRequest): SessionResponse {
        val s: SessionResponse = call("POST", "/api/v1/auth/register", req, auth = false)
        KdfUpgrade.requireServerKdfParams(s.accountKeys.kdfParams) // H1: fence BEFORE installing the session
        setTokens(Tokens(s.accessToken, s.refreshToken))
        return s
    }

    suspend fun login(req: LoginRequest): SessionResponse {
        val s: SessionResponse = call("POST", "/api/v1/auth/login", req, auth = false)
        KdfUpgrade.requireServerKdfParams(s.accountKeys.kdfParams) // H1: fence BEFORE installing the session
        setTokens(Tokens(s.accessToken, s.refreshToken))
        return s
    }

    suspend fun accountKeys(): AccountKeys {
        // H1 fence (spec 05 T1): re-unlock / KdfReKey / autofill all derive under these stored params.
        val k: AccountKeys = call("GET", "/api/v1/account/keys")
        KdfUpgrade.requireServerKdfParams(k.kdfParams)
        return k
    }

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

    /** [removal] is the optional removal proof (spec 03 §10/§11): minted by the removing
     *  owner's unlocked client and relayed to the victim via removedGrantsInfo so a 0.5.0
     *  client can verify the removal as a real owner action. Omitted → bare removal (the
     *  victim retains-and-warns). */
    suspend fun removeVaultMember(vaultId: String, userId: String, removal: VaultMemberRemoveRequest? = null): CreateVaultResponse =
        call("DELETE", "/api/v1/vaults/$vaultId/members/$userId", removal?.takeIf { it.proof != null || it.nonce != null })

    // ---- vault lifecycle (spec 03 §11) — refused on the public break-glass origin.
    // Foreground REST only: lifecycle ops are NEVER queued durably offline (design §2).

    suspend fun deleteVault(vaultId: String, req: VaultDeleteRequest): VaultDeleteResponse =
        call("POST", "/api/v1/vaults/$vaultId/delete", req)

    suspend fun restoreVault(vaultId: String, req: VaultRestoreRequest): CreateVaultResponse =
        call("POST", "/api/v1/vaults/$vaultId/restore", req)

    suspend fun deletedVaults(): List<DeletedVaultSummary> = call("GET", "/api/v1/vaults/deleted")

    suspend fun leaveVault(vaultId: String): CreateVaultResponse =
        call("POST", "/api/v1/vaults/$vaultId/leave")

    suspend fun offerTransfer(vaultId: String, req: TransferOfferRequest): TransferOfferResponse =
        call("POST", "/api/v1/vaults/$vaultId/transfer", req)

    /** Owner cancel or target decline. */
    suspend fun cancelTransfer(vaultId: String): CreateVaultResponse =
        call("DELETE", "/api/v1/vaults/$vaultId/transfer")

    suspend fun acceptTransfer(vaultId: String, req: TransferAcceptRequest): CreateVaultResponse =
        call("POST", "/api/v1/vaults/$vaultId/transfer/accept", req)

    suspend fun updateVaultMeta(vaultId: String, req: VaultMetaUpdateRequest): CreateVaultResponse =
        call("PUT", "/api/v1/vaults/$vaultId/meta", req)

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
