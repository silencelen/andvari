package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import io.ktor.utils.io.ByteReadChannel
import io.silencelen.andvari.core.crypto.Attachments
import io.silencelen.andvari.core.model.AccountDeleteBlocker
import io.silencelen.andvari.core.model.AccountDeleteBlockedError
import io.silencelen.andvari.core.model.AccountDeleteRequest
import io.silencelen.andvari.core.model.DeviceInfo
import io.silencelen.andvari.core.model.LoginRequest
import io.silencelen.andvari.core.model.PushResponse
import io.silencelen.andvari.core.model.SessionResponse
import io.silencelen.andvari.core.model.VaultMemberAdd
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Account deletion vs everything else that can commit while it runs (spec 03 §13; design 2026-11-10 §7). The gate
 * (typed email, TOTP, the master-password verify) runs OUTSIDE the writer lock; the refusal rules and every delete run
 * inside ONE tx. The window between them is driven deterministically through [Service.accountDeletePreTxProbe]: a share
 * that lands there must be seen (the deletion refuses), a push and an upload that land there must be purged with the
 * rest (no live ciphertext, no blob left on disk), and a password change that lands there must stop the deletion
 * (credential_changed). Then real concurrency: pushes, pulls and a second device's deletion racing the first.
 */
class AccountDeletionRaceTest : LifecycleTestSupport() {

    private suspend fun HttpClient.deleteAccount(vc: VirtualClient, accessToken: String = vc.accessToken): HttpResponse =
        post("/api/v1/account/delete") {
            authed(accessToken); contentType(ContentType.Application.Json)
            setBody(AccountDeleteRequest(vc.email, vc.authKey))
        }

    private suspend fun HttpClient.loginAgain(vc: VirtualClient): SessionResponse {
        val resp = post("/api/v1/auth/login") {
            contentType(ContentType.Application.Json); header("X-Andvari-Client", "test/1.0.0")
            setBody(LoginRequest(vc.email, vc.authKey, DeviceInfo("test", "second device")))
        }
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
        return json.decodeFromString(SessionResponse.serializer(), resp.bodyAsText())
    }

    private fun Services.count(sql: String, vararg args: Any?): Int = repo.db.read { c -> c.queryOne(sql, *args) { it.getInt(1) } ?: 0 }

    @Test
    fun aShareThatLandsAfterTheGate_isSeenByTheTx_andTheDeletionRefuses() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("admin@x.com", "race share admin password")
        client.register(admin, bootstrapToken)
        val u = client.enrollSecond(admin, "owner@x.com", "race share owner password")
        val b = client.enrollSecond(admin, "member@x.com", "race share member password")
        val (req, s) = u.buildCreateSharedVault(); client.createVault(u, req)
        // Another device of the same account shares the vault while the deletion is between its gate and its tx.
        val second = client.loginAgain(u)
        val otherDevice = services.service.authenticate(second.accessToken)!!
        services.service.accountDeletePreTxProbe = {
            runBlocking { services.service.addVaultMember(otherDevice, s.vaultId, VaultMemberAdd(b.userId, "writer", u.sealVkFor(b.identityPub, s.vaultId, s.vk)), "127.0.0.1") }
        }

        val resp = client.deleteAccount(u)
        services.service.accountDeletePreTxProbe = null
        assertEquals(HttpStatusCode.Conflict, resp.status, resp.bodyAsText())
        assertEquals(listOf(AccountDeleteBlocker("shared_vault", s.vaultId, 1)), json.decodeFromString(AccountDeleteBlockedError.serializer(), resp.bodyAsText()).blockers)
        assertNotNull(services.repo.userById(u.userId), "the refusal deleted nothing")
        assertEquals(1, client.sync(b).grants.count { it.vaultId == s.vaultId }, "the member keeps the share that won the race")
    }

    @Test
    fun aPushAndAnUploadThatLandAfterTheGate_arePurgedWithTheRest() = testApplication {
        val cfg = config()
        val services = buildServices(cfg, Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("admin@x.com", "race push admin password")
        client.register(admin, bootstrapToken)
        val u = client.enrollSecond(admin, "pusher@x.com", "race push member password")
        val principal = services.service.authenticate(u.accessToken)!!
        val lateItem = u.newItemId(); val lateAtt = uuid()
        services.service.accountDeletePreTxProbe = {
            runBlocking {
                val body = ByteArray(Attachments.HEADER_BYTES + 300) { 7 }
                services.service.attachments.store(u.userId, lateAtt, lateItem, u.personalVaultId, ByteReadChannel(body), services.service.policy())
                val pushed = services.service.push(principal, listOf(putMutation(u, lateItem, "written mid-deletion", 0, listOf(lateAtt))), "127.0.0.1")
                assertEquals("applied", pushed.results.single().status)
            }
        }

        val resp = client.deleteAccount(u)
        services.service.accountDeletePreTxProbe = null
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
        val row = services.repo.db.read { c -> c.queryOne("SELECT deleted, blob FROM items WHERE itemId=?", lateItem) { rs -> rs.getInt(1) to rs.getString(2) } }
        assertEquals(1 to null, row, "the late item is a ciphertext-free tombstone")
        assertEquals(0, services.count("SELECT COUNT(*) FROM attachments WHERE attachmentId=?", lateAtt))
        assertFalse(File(cfg.blobDir, lateAtt).exists(), "the late blob is gone from disk")
    }

    @Test
    fun aPasswordChangeThatLandsAfterTheGate_stopsTheDeletion() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("admin@x.com", "race password admin password")
        client.register(admin, bootstrapToken)
        val u = client.enrollSecond(admin, "changer@x.com", "race password member password")
        val second = client.loginAgain(u)
        val otherDevice = services.service.authenticate(second.accessToken)!!
        // The member (or whoever holds another of its sessions) changes the password: the old one proved nothing any more.
        services.service.accountDeletePreTxProbe = { services.service.changePassword(otherDevice, u.buildPasswordChange("the brand new password"), "127.0.0.1") }

        val resp = client.deleteAccount(u)
        services.service.accountDeletePreTxProbe = null
        assertEquals(HttpStatusCode.Unauthorized, resp.status, resp.bodyAsText())
        assertEquals("credential_changed", errorOf(resp))
        assertNotNull(services.repo.userById(u.userId), "nothing was deleted")
        assertEquals("credential_changed", client.auditRows(admin, "account_delete_reauth_fail").single().meta)
    }

    @Test
    fun concurrentPushesPullsAndASecondDeletion_neverLeaveLiveCiphertextOrARawId() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("admin@x.com", "race storm admin password")
        client.register(admin, bootstrapToken)
        val u = client.enrollSecond(admin, "storm@x.com", "race storm member password")
        val second = client.loginAgain(u)
        val gone = u.userId
        repeat(5) { client.push(u, putMutation(u, u.newItemId(), "before $it", 0)) }

        val (pushes, pulls, deletions) = coroutineScope {
            val pushes = (1..20).map { n ->
                async(Dispatchers.IO) {
                    val r = client.pushRaw(u, putMutation(u, u.newItemId(), "racing $n", 0))
                    r.status to (if (r.status == HttpStatusCode.OK) json.decodeFromString(PushResponse.serializer(), r.bodyAsText()).results.single().status else null)
                }
            }
            val pulls = (1..20).map { async(Dispatchers.IO) { client.get("/api/v1/sync?since=0") { authed(u) }.status } }
            val deletions = listOf(
                async(Dispatchers.IO) { client.deleteAccount(u).status },
                async(Dispatchers.IO) { client.deleteAccount(u, second.accessToken).status },
            )
            Triple(pushes.awaitAll(), pulls.awaitAll(), deletions.awaitAll())
        }

        // Exactly one deletion wins; the loser finds no account (its session went with it, or the tx saw it gone).
        assertEquals(1, deletions.count { it == HttpStatusCode.OK }, "deletions: $deletions")
        assertTrue(deletions.all { it == HttpStatusCode.OK || it == HttpStatusCode.Unauthorized }, "deletions: $deletions")
        // Every racing push landed before the deletion (applied) or was refused after it (401, or a denied row).
        assertTrue(pushes.all { (status, result) -> status == HttpStatusCode.Unauthorized || result == "applied" || result == "denied" }, "pushes: $pushes")
        assertTrue(pulls.all { it == HttpStatusCode.OK || it == HttpStatusCode.Unauthorized }, "pulls: $pulls")

        assertNull(services.repo.userById(gone))
        assertEquals(0, services.count("SELECT COUNT(*) FROM items WHERE vaultId=? AND (deleted=0 OR blob IS NOT NULL)", u.personalVaultId), "no live ciphertext survives, whichever push won")
        assertEquals(0, services.count("SELECT COUNT(*) FROM audit WHERE userId=? OR instr(COALESCE(meta,''), ?) > 0", gone, gone), "no row written during or after the race carries the raw id")
    }
}
