package io.silencelen.andvari.core.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.silencelen.andvari.core.model.WireIds
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Security review 2026-10 (plugin scan, F1): every server-supplied id is checked against the UUID grammar at the
 * wire boundary, in [AndvariApi], BEFORE it can reach account state or a device-local record. A row carrying an
 * id with a line break or a `|` (the device-local record delimiters the scan exploited) is REFUSED: dropped, with
 * the refusal reported through [AndvariApi.onRefusedIds]. One test per id field. Twin of web wireids.test.ts and
 * extension wireids.test.ts.
 */
class WireIdsTest {
    private val good = "0f8e2c1a-3b4d-4e5f-8a9b-0c1d2e3f4a5b"
    private val other = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
    private val hostile = listOf("$good\n$other|${"a".repeat(64)}|confirmed", "$good|x", "", "not-a-uuid", good.uppercase(), "$good ")

    private class Served(val body: String) {
        val refused = mutableListOf<Pair<String, List<WireIds.Refusal>>>()
        val api: AndvariApi = AndvariApi(
            "http://fake",
            HttpClient(MockEngine { respond(body, HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/json")) }),
            Tokens("at", "rt"),
        ).also { a -> a.onRefusedIds = { ep, r -> refused += ep to r } }
    }

    private fun vault(id: String) = """{"vaultId":${q(id)},"type":"shared","rev":3,"metaBlob":"m","createdAt":0}"""
    private fun grant(vaultId: String, userId: String) = """{"vaultId":${q(vaultId)},"userId":${q(userId)},"role":"writer","wrappedVk":"","rev":3,"sealedVk":"s"}"""
    private fun item(itemId: String, vaultId: String) =
        """{"itemId":${q(itemId)},"vaultId":${q(vaultId)},"rev":1,"createdAt":0,"updatedAt":0,"deleted":false,"conflict":false,"formatVersion":1,"attachmentIds":[],"blob":"b"}"""
    private fun sync(vaults: String = "", grants: String = "", items: String = "", removed: String = "", removedInfo: String = "") =
        """{"rev":9,"full":true,"vaults":[$vaults],"grants":[$grants],"items":[$items],"removedGrants":[$removed],"removedGrantsInfo":[$removedInfo]}"""
    private fun q(s: String) = kotlinx.serialization.json.JsonPrimitive(s).toString()

    @Test
    fun theGrammarIsLowercaseUuidOnly() {
        assertTrue(WireIds.isUuid(good))
        for (h in hostile) assertTrue(!WireIds.isUuid(h), "accepted: ${h.replace("\n", "\\n")}")
    }

    @Test
    fun aVaultRowWithAHostileVaultIdIsDroppedAndReported() = runBlocking {
        for (h in hostile) {
            val s = Served(sync(vaults = vault(h) + "," + vault(good)))
            val resp = s.api.sync(0)
            assertEquals(listOf(good), resp.vaults.map { it.vaultId }, "only the well-formed row survives for ${h.replace("\n", "\\n")}")
            assertEquals("sync", s.refused.single().first)
            assertEquals("vaultId", s.refused.single().second.single().field)
        }
    }

    @Test
    fun aVaultRowWhoseTransferNamesAHostileUserIdIsDropped() = runBlocking {
        val pending = """{"vaultId":${q(good)},"type":"shared","rev":3,"metaBlob":"m","createdAt":0,"pendingTransfer":{"toUserId":${q("$other\nx")},"offerId":"o","proof":"p","expiresAt":1,"seq":1}}"""
        val last = """{"vaultId":${q(other)},"type":"shared","rev":3,"metaBlob":"m","createdAt":0,"lastTransfer":{"offerId":"o","newOwnerUserId":${q("$good|x")},"acceptProof":"p","seq":1}}"""
        val s = Served(sync(vaults = "$pending,$last"))
        assertTrue(s.api.sync(0).vaults.isEmpty())
        assertEquals(setOf("pendingTransfer.toUserId", "lastTransfer.newOwnerUserId"), s.refused.flatMap { it.second }.map { it.field }.toSet())
    }

    @Test
    fun aGrantRowWithAHostileVaultIdOrUserIdIsDropped() = runBlocking {
        for (h in hostile) {
            val s = Served(sync(grants = grant(h, good) + "," + grant(good, h) + "," + grant(good, other)))
            val resp = s.api.sync(0)
            assertEquals(listOf(good to other), resp.grants.map { it.vaultId to it.userId })
            assertEquals(listOf("vaultId", "userId"), s.refused.single().second.map { it.field })
        }
    }

    @Test
    fun anItemRowWithAHostileItemIdOrVaultIdIsDropped() = runBlocking {
        for (h in hostile) {
            val s = Served(sync(items = item(h, good) + "," + item(good, h) + "," + item(other, good)))
            val resp = s.api.sync(0)
            assertEquals(listOf(other), resp.items.map { it.itemId })
            assertEquals(listOf("itemId", "vaultId"), s.refused.single().second.map { it.field })
        }
    }

    @Test
    fun aRemovedGrantEntryWithAHostileVaultIdIsDropped() = runBlocking {
        val h = "$good\n$other"
        val s = Served(sync(removed = "${q(h)},${q(good)}", removedInfo = """{"vaultId":${q(h)},"reason":"removed"},{"vaultId":${q(good)},"reason":"removed"}"""))
        val resp = s.api.sync(0)
        assertEquals(listOf(good), resp.removedGrants)
        assertEquals(listOf(good), resp.removedGrantsInfo.map { it.vaultId })
        assertEquals(listOf("removedGrants", "removedGrantsInfo.vaultId"), s.refused.single().second.map { it.field })
    }

    @Test
    fun aMemberRowWithAHostileUserIdIsDropped() = runBlocking {
        val h = "$good|${"b".repeat(64)}"
        val s = Served("""[{"userId":${q(h)},"email":"e","displayName":"d","role":"writer","identityPub":"p","addedAt":0},{"userId":${q(good)},"email":"e","displayName":"d","role":"owner","identityPub":"p","addedAt":0}]""")
        assertEquals(listOf(good), s.api.vaultMembers(other).map { it.userId })
        assertEquals("members", s.refused.single().first)
    }

    @Test
    fun aDeletedItemOrDeletedVaultWithAHostileIdIsDropped() = runBlocking {
        val h = "$good\n$other"
        val items = Served("""{"items":[{"itemId":${q(h)},"vaultId":${q(good)},"deletedAt":1},{"itemId":${q(good)},"vaultId":${q(h)},"deletedAt":1},{"itemId":${q(other)},"vaultId":${q(good)},"deletedAt":1}]}""")
        assertEquals(listOf(other), items.api.deletedItems().map { it.itemId })
        assertEquals(listOf("itemId", "vaultId"), items.refused.single().second.map { it.field })
        val vaults = Served("""[{"vaultId":${q(h)},"metaBlob":"m","wrappedVk":"w","deletedAt":1,"purgeAt":2,"deleteId":"d"},{"vaultId":${q(good)},"metaBlob":"m","wrappedVk":"w","deletedAt":1,"purgeAt":2,"deleteId":"d"}]""")
        assertEquals(listOf(good), vaults.api.deletedVaults().map { it.vaultId })
        assertEquals("deletedVaults", vaults.refused.single().first)
    }

    @Test
    fun aServedIdentityOrPersonalWrapWithAHostileIdIsRefused() = runBlocking {
        val h = "$good|x"
        val identity = Served("""{"userId":${q(h)},"displayName":"d","identityPub":"p"}""")
        assertFailsWith<ApiException> { identity.api.userIdentity(good) }.let { assertEquals("bad_wire_id", it.code) }
        val keys = Served("""{"kdfSalt":"s","kdfParams":{"v":1,"alg":"argon2id13","ops":3,"memBytes":67108864},"wrappedUvk":"w","encryptedIdentitySeed":"e","identityPub":"p","escrowFingerprint":"f","personalWrap":{"vaultId":${q(h)},"wrappedVk":"w"}}""")
        val k = keys.api.accountKeys()
        assertEquals(null, k.personalWrap, "a wrap naming a hostile vault id is dropped, not applied")
        assertEquals("accountKeys", keys.refused.single().first)
    }

    @Test
    fun aSessionWithAHostileUserIdOrDeviceIdIsRefused() = runBlocking {
        val h = "$good\nx"
        val session = { uid: String, did: String ->
            """{"userId":${q(uid)},"deviceId":${q(did)},"accessToken":"a","refreshToken":"r","isAdmin":false,"accountKeys":{"kdfSalt":"s","kdfParams":{"v":1,"alg":"argon2id13","ops":3,"memBytes":67108864},"wrappedUvk":"w","encryptedIdentitySeed":"e","identityPub":"p","escrowFingerprint":"f"}}"""
        }
        val req = io.silencelen.andvari.core.model.LoginRequest("e@x", "a", io.silencelen.andvari.core.model.DeviceInfo("android", "d"))
        assertFailsWith<ApiException> { Served(session(h, good)).api.login(req) }.let { assertEquals("bad_wire_id", it.code) }
        assertFailsWith<ApiException> { Served(session(good, h)).api.login(req) }.let { assertEquals("bad_wire_id", it.code) }
        assertEquals(good, Served(session(good, other)).api.login(req).userId)
    }
}
