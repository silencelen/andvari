package io.silencelen.andvari.server

import io.ktor.client.HttpClient
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
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.AccountStatePut
import io.silencelen.andvari.core.model.AccountStateResponse
import io.silencelen.andvari.core.model.InviteRequest
import io.silencelen.andvari.core.model.InviteResponse
import io.silencelen.andvari.core.model.PersonalWrapPut
import io.silencelen.andvari.core.model.SessionResponse
import io.silencelen.andvari.core.model.UserLookupResponse
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Security review 2026-10, root cause A §4 (branch A5), server half:
 *  - `/account/state` stores one opaque blob per user behind a compare-and-set counter (409 `stale_state`),
 *    size-capped, never audited;
 *  - `personalWrap` arrives with the register or `PUT /account/personal-wrap`, is delivered in AccountKeys,
 *    and is write-once except with a fresh password reauth (owner decision Q9: re-designation allowed);
 *  - `GET /users/{id}/identity` serves a key for a HUMAN to verify.
 * The server can check none of the crypto; these pin who may write what.
 */
class AccountStatePersonalWrapTest : P4TestSupport() {

    private suspend fun HttpClient.state(vc: VirtualClient): AccountStateResponse =
        json.decodeFromString(AccountStateResponse.serializer(), get("/api/v1/account/state") { authed(vc) }.bodyAsText())

    private suspend fun HttpClient.putState(vc: VirtualClient, sealed: String, baseSeq: Long): HttpResponse =
        put("/api/v1/account/state") { authed(vc); contentType(ContentType.Application.Json); setBody(AccountStatePut(sealed, baseSeq)) }

    private suspend fun HttpClient.putWrap(vc: VirtualClient, body: PersonalWrapPut): HttpResponse =
        put("/api/v1/account/personal-wrap") { authed(vc); contentType(ContentType.Application.Json); setBody(body) }

    private suspend fun HttpClient.keys(vc: VirtualClient): AccountKeys =
        json.decodeFromString(AccountKeys.serializer(), get("/api/v1/account/keys") { authed(vc) }.bodyAsText())

    @Test
    fun accountStateIsCompareAndSetAndCapped() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val a = VirtualClient("state-a@x.com", "account state password one", fast = true)
        client.register(a, bootstrapToken)
        assertEquals(AccountStateResponse(null, 0), client.state(a), "never written: null + seq 0")

        val blob1 = Envelope.sealB64(crypto, a.uvk, "{}".encodeToByteArray(), Ad.accountState(a.userId))
        assertEquals(HttpStatusCode.OK, client.putState(a, blob1, 0).status)
        assertEquals(AccountStateResponse(blob1, 1), client.state(a))

        // A writer that read seq 0 and did not merge is refused: it must re-read and merge.
        val stale = client.putState(a, blob1, 0)
        assertEquals(HttpStatusCode.Conflict, stale.status)
        assertEquals("stale_state", errorOf(stale))
        assertEquals(HttpStatusCode.OK, client.putState(a, blob1, 1).status)
        assertEquals(2, client.state(a).seq)

        assertEquals(HttpStatusCode.BadRequest, client.putState(a, "A".repeat(ACCOUNT_STATE_SEALED_MAX + 4), 2).status, "size-capped")
        assertEquals(HttpStatusCode.BadRequest, client.putState(a, "not base64!", 2).status)
    }

    @Test
    fun personalWrapIsDeliveredAndWriteOnceExceptWithReauth() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val a = VirtualClient("wrap-a@x.com", "personal wrap password one", fast = true)
        // Register WITH the wrap (new enrolments send it).
        val resp = client.post("/api/v1/auth/register") {
            contentType(ContentType.Application.Json); header("X-Andvari-Client", "test/1.0.0")
            setBody(a.buildRegister(bootstrapToken, recovery.publicKey, fingerprint, includePersonalWrap = true))
        }
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
        val session = json.decodeFromString(SessionResponse.serializer(), resp.bodyAsText())
        a.userId = session.userId; a.accessToken = session.accessToken; a.refreshToken = session.refreshToken
        val served = session.accountKeys.personalWrap!!
        assertEquals(a.personalVaultId, served.vaultId)
        assertTrue(Envelope.openB64(crypto, a.uvk, served.wrappedVk, Ad.vkPersonal(served.vaultId, a.userId)).contentEquals(a.vk))
        assertEquals(served, client.keys(a).personalWrap)

        // A second vault this user owns; re-designating to it without a reauth is refused.
        val (createReq, handle) = a.buildCreateSharedVault()
        assertEquals(HttpStatusCode.Created, client.post("/api/v1/vaults") { authed(a); contentType(ContentType.Application.Json); setBody(createReq) }.status)
        val other = a.personalWrap(handle.vaultId, handle.vk)
        val plain = client.putWrap(a, PersonalWrapPut(other.vaultId, other.wrappedVk))
        assertEquals(HttpStatusCode.Conflict, plain.status)
        assertEquals("personal_wrap_exists", errorOf(plain))
        assertEquals(HttpStatusCode.Unauthorized, client.putWrap(a, PersonalWrapPut(other.vaultId, other.wrappedVk, "AAAA" + a.authKey.drop(4))).status)
        assertEquals(served, client.keys(a).personalWrap, "a refused write changes nothing")

        // Q9: with a fresh password proof, re-designation is allowed.
        assertEquals(HttpStatusCode.OK, client.putWrap(a, PersonalWrapPut(other.vaultId, other.wrappedVk, a.authKey)).status)
        assertEquals(other, client.keys(a).personalWrap)
        assertTrue(client.auditRows(a, "personal_wrap_redesignate").isNotEmpty())
    }

    @Test
    fun migrationFirstSetNeedsNoReauthButAGrant() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val a = VirtualClient("migrate-a@x.com", "personal wrap password two", fast = true)
        client.register(a, bootstrapToken) // a pre-A5 register: no wrap
        assertNull(client.keys(a).personalWrap)

        // A vault the caller holds no grant on is refused.
        val stranger = a.personalWrap("99999999-9999-4999-8999-999999999999")
        assertEquals(HttpStatusCode.Forbidden, client.putWrap(a, PersonalWrapPut(stranger.vaultId, stranger.wrappedVk)).status)
        val bad = client.putWrap(a, PersonalWrapPut("NOT-A-UUID", "AAAA"))
        assertEquals(HttpStatusCode.BadRequest, bad.status)

        val wrap = a.personalWrap()
        assertEquals(HttpStatusCode.OK, client.putWrap(a, PersonalWrapPut(wrap.vaultId, wrap.wrappedVk)).status)
        assertEquals(wrap, client.keys(a).personalWrap)
        assertTrue(client.auditRows(a, "personal_wrap_set").isNotEmpty())
    }

    @Test
    fun identityLookupServesTheKeyForAHumanToVerify() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("ident-admin@x.com", "identity lookup password one", fast = true)
        client.register(admin, bootstrapToken)
        val inv = client.post("/api/v1/admin/users") { authed(admin); contentType(ContentType.Application.Json); setBody(InviteRequest("ident-bob@x.com", isAdmin = false)) }
        val bob = VirtualClient("ident-bob@x.com", "identity lookup password two", fast = true)
        client.register(bob, json.decodeFromString(InviteResponse.serializer(), inv.bodyAsText()).inviteToken)

        val r = client.get("/api/v1/users/${admin.userId}/identity") { authed(bob) }
        assertEquals(HttpStatusCode.OK, r.status, r.bodyAsText())
        val info = json.decodeFromString(UserLookupResponse.serializer(), r.bodyAsText())
        assertEquals(admin.userId, info.userId)
        assertEquals(io.silencelen.andvari.core.crypto.Bytes.toB64(admin.identityPub), info.identityPub)
        assertEquals(HttpStatusCode.NotFound, client.get("/api/v1/users/99999999-9999-4999-8999-999999999999/identity") { authed(bob) }.status)
        assertEquals(HttpStatusCode.BadRequest, client.get("/api/v1/users/not-a-uuid/identity") { authed(bob) }.status)
    }
}
