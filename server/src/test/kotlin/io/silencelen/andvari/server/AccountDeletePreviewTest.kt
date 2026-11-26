package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.wire.AccountDeletePreview
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.trust.LogEntry
import io.silencelen.andvari.core.trust.MemberRole
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The deletion preview's `deletedVaults` (spec 03 §13; design 2026-11-10 §2, §3.1) holds the personal vault, the vaults
 * only the account holds, and the vaults it deleted that are still in their grace: all of them are purged with the
 * account. A vault in grace is told apart by the caller's `GET /vaults/deleted` (§11.2), which lists exactly those,
 * so a client can say it was already deleted instead of counting it among the vaults "only you hold".
 */
class AccountDeletePreviewTest {
    @Test
    fun aVaultInItsGrace_isInDeletedVaults_andInTheRecentlyDeletedList() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val m = Flow.member(c, s, "m@example.com")
        val solo = SharedVault(c, s, me).create()
        val shared = SharedVault(c, s, me).create()
        shared.add(m, MemberRole.WRITER)
        val gone = SharedVault(c, s, me).create()
        gone.add(m, MemberRole.WRITER)
        gone.ok(me, LogEntry.Delete(gone.vaultId, gone.next, gone.head, me.userId, gone.at, b16()))
        val p = WireJson.json.decodeFromString(AccountDeletePreview.serializer(), c.call(HttpMethod.Get, "/api/v1/account/delete/preview", token = me.token).bodyAsText())
        // The live shared vault with a member blocks; the one in grace does not, and goes with the account.
        assertEquals(listOf(shared.vaultId), p.blockers.map { it.vaultId })
        assertEquals(listOf(me.personalVaultId, solo.vaultId, gone.vaultId).sorted(), p.deletedVaults)
        val recentlyDeleted = WireJson.json.parseToJsonElement(c.call(HttpMethod.Get, "/api/v1/vaults/deleted", token = me.token).bodyAsText())
            .jsonArray.map { it.jsonObject["vaultId"]!!.jsonPrimitive.content }
        assertEquals(listOf(gone.vaultId), recentlyDeleted)
        assertEquals(listOf(me.personalVaultId, solo.vaultId).sorted(), p.deletedVaults - recentlyDeleted.toSet())
    }
}
