package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.EscrowFormat
import io.silencelen.andvari.core.crypto.IdentityCheck
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.AdminEscrowDownload
import io.silencelen.andvari.core.model.EscrowDrillPass
import io.silencelen.andvari.core.model.EscrowDrillReceipt
import io.silencelen.andvari.core.model.EscrowDrillResult
import io.silencelen.andvari.core.model.EscrowUpload
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Escrow v2 server side (security review 2026-10, root cause A §2.5 / §8.4):
 * - the admin escrow download carries the identity file (`encryptedIdentitySeed`, `identityPub`);
 * - a re-seal keeps the PREVIOUS blob as `escrow_legacy` (the OLDEST undrilled one wins), served in
 *   the download, so a defective v2 seal can never strand a member;
 * - the drill hook drops it only for an account whose CURRENT blob is the drilled one;
 * - `escrowNeedsV2` is the migration hint for a v1-sized blob under the current org key.
 */
class EscrowLegacyRetentionTest : P4TestSupport() {
    private suspend fun HttpClient.escrowSelf(vc: VirtualClient, sealed: String) =
        put("/api/v1/escrow/self") { contentType(ContentType.Application.Json); authed(vc); setBody(EscrowUpload(sealed, fingerprint)) }

    private suspend fun HttpClient.download(admin: VirtualClient, userId: String): AdminEscrowDownload {
        val resp = get("/api/v1/admin/users/$userId/escrow") { authed(admin) }
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
        return json.decodeFromString(AdminEscrowDownload.serializer(), resp.bodyAsText())
    }

    private suspend fun HttpClient.keys(vc: VirtualClient): AccountKeys =
        json.decodeFromString(AccountKeys.serializer(), get("/api/v1/account/keys") { authed(vc) }.bodyAsText())

    private suspend fun HttpClient.drill(admin: VirtualClient, receipt: EscrowDrillReceipt) =
        post("/api/v1/admin/escrow/drill") { contentType(ContentType.Application.Json); authed(admin); setBody(receipt) }

    private fun sha(sealedB64: String) = Bytes.toHexLower(crypto.sha256(Bytes.fromB64(sealedB64)))

    @Test
    fun migration_retainsTheLegacyBlob_untilADrillPassesOnTheNewOne() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("admin@x.com", "legacy retention password 1")
        client.register(admin, bootstrapToken) // VirtualClient enrols like a pre-A4 client: a v1 blob

        // Design §2.5: the download is the identity file the recovery CLI checks against.
        val before = client.download(admin, admin.userId)
        assertEquals(admin.userId, before.userId)
        assertEquals(Bytes.toB64(admin.identityPub), before.identityPub)
        assertNull(before.legacySealed)
        val v1 = before.sealed
        assertEquals(ESCROW_V1_SEALED_BYTES, Bytes.fromB64(v1).size)
        assertTrue(client.keys(admin).escrowNeedsV2, "a v1 blob under the current key gets the migration hint")

        // The member migrates (§8.4): PUT /escrow/self with a v2 blob.
        val v2a = admin.sealEscrowV2(recovery.publicKey, fingerprint)
        assertEquals(HttpStatusCode.OK, client.escrowSelf(admin, v2a).status)
        val afterA = client.download(admin, admin.userId)
        assertEquals(v2a, afterA.sealed)
        assertEquals(v1, afterA.legacySealed, "the replaced v1 blob is retained")
        assertFalse(client.keys(admin).escrowNeedsV2, "migrated: no more hint")

        // Both blobs recover the member through the identity check — v2 as V2, the retained one as V1_LEGACY.
        val anchor = Escrow.fingerprint(crypto, admin.identityPub)
        val check = IdentityCheck(afterA.encryptedIdentitySeed, afterA.identityPub)
        assertEquals(EscrowFormat.V2, Escrow.open(crypto, recovery, Bytes.fromB64(afterA.sealed), admin.userId, anchor, check).format)
        assertEquals(EscrowFormat.V1_LEGACY, Escrow.open(crypto, recovery, Bytes.fromB64(afterA.legacySealed!!), admin.userId, anchor, check).format)

        // A SECOND re-seal before any drill keeps the OLDEST undrilled blob (the v1), not v2a.
        val v2b = admin.sealEscrowV2(recovery.publicKey, fingerprint)
        assertEquals(HttpStatusCode.OK, client.escrowSelf(admin, v2b).status)
        assertEquals(v1, client.download(admin, admin.userId).legacySealed)

        // A drill receipt for a blob that is NOT the current one (the drill ran on v2a) keeps the legacy copy.
        val stale = client.drill(admin, EscrowDrillReceipt(listOf(EscrowDrillPass(admin.userId, sha(v2a)))))
        assertEquals(HttpStatusCode.OK, stale.status, stale.bodyAsText())
        assertEquals(EscrowDrillResult(emptyList(), listOf(admin.userId)), json.decodeFromString(EscrowDrillResult.serializer(), stale.bodyAsText()))
        assertEquals(v1, client.download(admin, admin.userId).legacySealed)

        // The drill passed on the CURRENT blob → the legacy copy is dropped, and the drop is audited.
        val ok = client.drill(admin, EscrowDrillReceipt(listOf(EscrowDrillPass(admin.userId, sha(v2b)))))
        assertEquals(EscrowDrillResult(listOf(admin.userId), emptyList()), json.decodeFromString(EscrowDrillResult.serializer(), ok.bodyAsText()))
        assertNull(client.download(admin, admin.userId).legacySealed)
        assertEquals(admin.userId, client.auditRows(admin, "escrow_legacy_dropped").single().meta)
    }

    @Test
    fun identicalReupload_retainsNothing() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("admin@x.com", "legacy retention password 2")
        client.register(admin, bootstrapToken)
        val same = client.download(admin, admin.userId).sealed
        assertEquals(HttpStatusCode.OK, client.escrowSelf(admin, same).status)
        assertNull(client.download(admin, admin.userId).legacySealed)
    }

    @Test
    fun drillHook_isAdminOnly() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("admin@x.com", "legacy retention password 3")
        client.register(admin, bootstrapToken)
        val invite = client.post("/api/v1/admin/users") {
            contentType(ContentType.Application.Json); authed(admin)
            setBody(io.silencelen.andvari.core.model.InviteRequest("m@x.com", false))
        }
        val token = json.decodeFromString(io.silencelen.andvari.core.model.InviteResponse.serializer(), invite.bodyAsText()).inviteToken
        val member = VirtualClient("m@x.com", "legacy retention password 4")
        client.register(member, token)
        val resp = client.drill(member, EscrowDrillReceipt(listOf(EscrowDrillPass(member.userId, "0".repeat(64)))))
        assertEquals(HttpStatusCode.Forbidden, resp.status, resp.bodyAsText())
    }
}
