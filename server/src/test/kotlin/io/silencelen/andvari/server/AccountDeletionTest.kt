package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
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
import io.ktor.http.encodeURLParameter
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.testing.testApplication
import io.ktor.websocket.Frame
import io.ktor.websocket.readText
import io.silencelen.andvari.core.crypto.Attachments
import io.silencelen.andvari.core.crypto.Base32
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.AccountDeleteBlocker
import io.silencelen.andvari.core.model.AccountDeleteBlockedError
import io.silencelen.andvari.core.model.AccountDeletePreview
import io.silencelen.andvari.core.model.AccountDeleteRequest
import io.silencelen.andvari.core.model.AccountDeleteResponse
import io.silencelen.andvari.core.model.AccountStatePut
import io.silencelen.andvari.core.model.CreateVaultRequest
import io.silencelen.andvari.core.model.EscrowUpload
import io.silencelen.andvari.core.model.InviteRequest
import io.silencelen.andvari.core.model.InviteResponse
import io.silencelen.andvari.core.model.Mutation
import io.silencelen.andvari.core.model.PersonalWrapPut
import io.silencelen.andvari.core.model.PreloginRequest
import io.silencelen.andvari.core.model.PreloginResponse
import io.silencelen.andvari.core.model.RefreshRequest
import io.silencelen.andvari.core.model.TransferAcceptRequest
import io.silencelen.andvari.core.model.UsageUpload
import io.silencelen.andvari.core.model.VaultMemberSummary
import io.silencelen.andvari.core.model.WsTicketResponse
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.builtins.ListSerializer
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Account deletion (spec 03 §13; design docs/design/2026-11-10-account-deletion.md): the endpoint, its gate (typed
 * email, TOTP before the password, the master-password reauth, the break-glass refusal, the hourly bucket), the
 * refusal rules (an owned vault other accounts still use; the last admin), the atomic deletion of every row and blob
 * the account alone held, what the household sees afterwards, the audit trail's pseudonym and its 90-day purge, and
 * the email registering again as a new account. The races between the gate and the tx live in AccountDeletionRaceTest.
 */
class AccountDeletionTest : LifecycleTestSupport() {

    private suspend fun HttpClient.deleteAccount(vc: VirtualClient, body: AccountDeleteRequest = AccountDeleteRequest(vc.email, vc.authKey), host: String? = null): HttpResponse =
        post("/api/v1/account/delete") {
            authed(vc); contentType(ContentType.Application.Json)
            if (host != null) header("Host", host)
            setBody(body)
        }

    private suspend fun HttpClient.deletePreview(vc: VirtualClient): AccountDeletePreview {
        val resp = get("/api/v1/account/delete/preview") { authed(vc) }
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
        return json.decodeFromString(AccountDeletePreview.serializer(), resp.bodyAsText())
    }

    private suspend fun blockersOf(resp: HttpResponse): List<AccountDeleteBlocker> {
        assertEquals(HttpStatusCode.Conflict, resp.status, resp.bodyAsText())
        val body = json.decodeFromString(AccountDeleteBlockedError.serializer(), resp.bodyAsText())
        assertEquals("account_delete_blocked", body.error)
        return body.blockers
    }

    private suspend fun HttpClient.invite(admin: VirtualClient, email: String, isAdmin: Boolean = false): String {
        val resp = post("/api/v1/admin/users") { authed(admin); contentType(ContentType.Application.Json); setBody(InviteRequest(email, isAdmin = isAdmin)) }
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
        return json.decodeFromString(InviteResponse.serializer(), resp.bodyAsText()).inviteToken
    }

    private fun Services.count(sql: String, vararg args: Any?): Int = repo.db.read { c -> c.queryOne(sql, *args) { it.getInt(1) } ?: 0 }

    /** Every TEXT column of every table holding [needle], as `table.column (rows)` — the "nothing names it any more"
     *  check, which also covers a column added after this test was written. Ciphertext columns hold base64url: it has no
     *  `@`, and a random run of it matching a 36-character id exactly is out of reach, so a hit is a real reference. */
    private fun Services.cellsContaining(needle: String): List<String> = repo.db.read { c ->
        val tables = c.queryAll("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'") { it.getString(1) }
        tables.flatMap { t ->
            val cols = c.queryAll("SELECT name, type FROM pragma_table_info('$t')") { it.getString(1) to it.getString(2) }
            cols.filter { (_, type) -> type.equals("TEXT", ignoreCase = true) }.mapNotNull { (col, _) ->
                val n = c.queryOne("SELECT COUNT(*) FROM \"$t\" WHERE instr(\"$col\", ?) > 0", needle) { it.getInt(1) } ?: 0
                if (n > 0) "$t.$col ($n)" else null
            }
        }
    }

    /** Server TOTP straight into the row (the enrolment routes have their own suites): a fresh secret, no step used. */
    private fun enrollTotp(services: Services, vc: VirtualClient): String {
        val secret = Base32.encode(crypto.randomBytes(20))
        services.repo.db.tx { c -> c.exec("UPDATE users SET totpSecret=?, totpEnrolledAt=?, totpLastStep=0 WHERE userId=?", secret, now(), vc.userId) }
        return secret
    }

    // ---- the deletion itself ----

    @Test
    fun deletion_removesEveryRowAndBlobOnlyTheAccountHeld_leavesTheHouseholdsVaults_andTheEmailRegistersAgain() = testApplication {
        val cfg = config()
        val services = buildServices(cfg, Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("owner@x.com", "account deletion owner password")
        client.register(admin, bootstrapToken)
        val u = client.enrollSecond(admin, "leaver@x.com", "account deletion leaver password")

        // Personal vault: an item with an archived version, another item, and one carrying an attachment blob on disk.
        val i1 = u.newItemId(); val i2 = u.newItemId(); val attItem = u.newItemId(); val attId = uuid()
        val r1 = client.push(u, putMutation(u, i1, "first", 0)).results.single().newItemRev!!
        client.push(u, putMutation(u, i1, "first, edited", r1))
        client.push(u, putMutation(u, i2, "second", 0))
        val blob = ByteArray(Attachments.HEADER_BYTES + 200) { (it % 251).toByte() }
        assertEquals(HttpStatusCode.OK, client.uploadAttachment(u, attId, attItem, blob).status)
        assertEquals("applied", client.push(u, putMutation(u, attItem, "with a file", 0, listOf(attId))).results.single().status)
        val blobFile = File(cfg.blobDir, attId)
        assertTrue(blobFile.isFile, "the attachment blob is on disk before the deletion")
        assertEquals(1, services.count("SELECT COUNT(*) FROM item_versions WHERE itemId=?", i1))

        // A shared vault only the account holds, with an item in it.
        val (sReq, s) = u.buildCreateSharedVault()
        assertEquals(HttpStatusCode.Created, client.createVault(u, sReq).status)
        val sItem = uuid()
        client.push(u, Mutation(uuid(), "put", sItem, s.vaultId, 0, u.encItemIn(s.vaultId, s.vk, sItem, "solo shared")))

        // The household's vault: the admin owns it, the account is a writer and leaves an item in it.
        val (vReq, v) = admin.buildCreateSharedVault()
        assertEquals(HttpStatusCode.Created, client.createVault(admin, vReq).status)
        assertEquals(HttpStatusCode.Created, client.addMember(admin, v, u, "writer").status)
        val memberVk = client.openMemberVk(u, v.vaultId)
        val vItem = uuid()
        client.push(u, Mutation(uuid(), "put", vItem, v.vaultId, 0, u.encItemIn(v.vaultId, memberVk, vItem, "left for the household")))

        // Every per-account blob: usage ledger, account state, personal wrap, and an escrow re-seal (retains escrow_legacy).
        assertEquals(HttpStatusCode.OK, client.put("/api/v1/usage") { authed(u); contentType(ContentType.Application.Json); setBody(UsageUpload("dXNhZ2U")) }.status)
        assertEquals(HttpStatusCode.OK, client.put("/api/v1/account/state") { authed(u); contentType(ContentType.Application.Json); setBody(AccountStatePut("c3RhdGU", 0)) }.status)
        assertEquals(HttpStatusCode.OK, client.put("/api/v1/account/personal-wrap") { authed(u); contentType(ContentType.Application.Json); setBody(PersonalWrapPut(u.personalVaultId, u.personalWrap().wrappedVk)) }.status)
        val reseal = client.put("/api/v1/escrow/self") { authed(u); contentType(ContentType.Application.Json); setBody(EscrowUpload(u.sealEscrowV2(recovery.publicKey, fingerprint), fingerprint)) }
        assertEquals(HttpStatusCode.OK, reseal.status, reseal.bodyAsText())
        for (t in listOf("escrow", "escrow_legacy", "member_recovery", "usage_ledger", "account_state", "personal_wrap")) {
            assertEquals(1, services.count("SELECT COUNT(*) FROM $t WHERE userId=?", u.userId), "fixture: $t row exists")
        }
        val deviceIds = services.repo.db.read { c -> c.queryAll("SELECT deviceId FROM devices WHERE userId=?", u.userId) { it.getString(1) } }
        assertTrue(services.count("SELECT COUNT(*) FROM mutations WHERE deviceId=?", deviceIds.single()) > 0)

        // The preview names exactly what the deletion will do.
        val preview = client.deletePreview(u)
        assertEquals(emptyList(), preview.blockers)
        assertEquals(listOf(u.personalVaultId, s.vaultId).sorted(), preview.deletedVaults)
        assertEquals(listOf(v.vaultId), preview.leftVaults)
        assertFalse(preview.totpRequired)

        val gone = u.userId
        val resp = client.deleteAccount(u)
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
        assertTrue(json.decodeFromString(AccountDeleteResponse.serializer(), resp.bodyAsText()).deletedAt > 0)

        // The account and every row that referenced it.
        assertNull(services.repo.userById(gone))
        for (t in listOf("devices", "sessions", "grants", "escrow", "escrow_legacy", "member_recovery", "usage_ledger", "account_state", "personal_wrap")) {
            assertEquals(0, services.count("SELECT COUNT(*) FROM $t WHERE userId=?", gone), "$t keeps no row of the deleted account")
        }
        assertEquals(0, services.count("SELECT COUNT(*) FROM mutations WHERE deviceId=?", deviceIds.single()), "the device's idempotency journal goes too")

        // Both vaults only it held: purged tombstones — no ciphertext, no history, no attachments, no key material.
        for (vaultId in listOf(u.personalVaultId, s.vaultId)) {
            val row = services.repo.db.read { c -> c.queryOne("SELECT metaBlob, deletedAt, purgedAt, deletedBy FROM vaults WHERE vaultId=?", vaultId) { rs ->
                listOf(rs.getString(1), rs.getObject(2), rs.getObject(3), rs.getString(4))
            } }
            assertNotNull(row, "the vault row stays (a vaultId is never recycled)")
            assertEquals("", row[0]); assertNotNull(row[1]); assertNotNull(row[2]); assertNull(row[3])
            assertEquals(0, services.count("SELECT COUNT(*) FROM items WHERE vaultId=? AND (deleted=0 OR blob IS NOT NULL)", vaultId))
            assertEquals(0, services.count("SELECT COUNT(*) FROM item_versions WHERE itemId IN (SELECT itemId FROM items WHERE vaultId=?)", vaultId))
            assertEquals(0, services.count("SELECT COUNT(*) FROM attachments WHERE vaultId=?", vaultId))
            assertEquals(0, services.count("SELECT COUNT(*) FROM grants WHERE vaultId=? AND (wrappedVk<>'' OR sealedVk IS NOT NULL OR signedGrant IS NOT NULL)", vaultId))
        }
        assertFalse(blobFile.exists(), "the attachment blob is gone from disk")
        val reuse = client.createVault(admin, CreateVaultRequest(s.vaultId, sReq.metaBlob, sReq.wrappedVk))
        assertEquals(HttpStatusCode.BadRequest, reuse.status)
        assertEquals("vault_id_taken", errorOf(reuse), "a purged vaultId is never recycled")

        // The household's vault is untouched: the item the account wrote stays, its membership is gone.
        val adminView = client.sync(admin).items.single { it.itemId == vItem }
        assertEquals("left for the household", admin.decItemIn(v.vaultId, v.vk, vItem, adminView.blob!!))
        val members = client.get("/api/v1/vaults/${v.vaultId}/members") { authed(admin) }
        assertEquals(listOf(admin.userId), json.decodeFromString(ListSerializer(VaultMemberSummary.serializer()), members.bodyAsText()).map { it.userId })

        // Every session is dead: access, refresh, the event ticket.
        assertEquals(HttpStatusCode.Unauthorized, client.get("/api/v1/sync") { authed(u) }.status)
        assertEquals(HttpStatusCode.Unauthorized, client.post("/api/v1/events/ticket") { authed(u) }.status)
        val refresh = client.post("/api/v1/auth/refresh") { contentType(ContentType.Application.Json); header("X-Andvari-Client", "test/1.0.0"); setBody(RefreshRequest(u.refreshToken)) }
        assertEquals(HttpStatusCode.Unauthorized, refresh.status)

        // No audit row — and no column of any table — names the account's id or email any more.
        assertEquals(0, services.count("SELECT COUNT(*) FROM audit WHERE userId=? OR instr(COALESCE(meta,''), ?) > 0", gone, gone))
        assertEquals(0, services.count("SELECT COUNT(*) FROM audit WHERE instr(COALESCE(meta,''), ?) > 0", u.email))
        assertEquals(emptyList(), services.cellsContaining(gone))
        assertEquals(emptyList(), services.cellsContaining(u.email))
        // Nor the id of the device it used: its kept rows name that device by a fresh id instead.
        assertEquals(emptyList(), services.cellsContaining(deviceIds.single()))

        // The email registers again — as a brand-new account.
        val token = client.invite(admin, "leaver@x.com")
        val again = VirtualClient("leaver@x.com", "a brand new master password")
        client.register(again, token)
        assertNotEquals(gone, again.userId)
        val pre = client.post("/api/v1/auth/prelogin") { contentType(ContentType.Application.Json); setBody(PreloginRequest("leaver@x.com")) }
        assertEquals(Bytes.toB64(again.kdfSalt), json.decodeFromString(PreloginResponse.serializer(), pre.bodyAsText()).kdfSalt)
        assertEquals(emptyList(), client.sync(again).items, "the new account starts empty")
    }

    // ---- refusal rules ----

    @Test
    fun ownedVaultOthersStillUse_blocksDeletion_untilTransferredOrDeleted() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("admin@x.com", "blocked deletion admin password")
        client.register(admin, bootstrapToken)
        val u = client.enrollSecond(admin, "owner@x.com", "blocked deletion owner password")
        val b = client.enrollSecond(admin, "member@x.com", "blocked deletion member password")
        val (sReq, s) = u.buildCreateSharedVault(); client.createVault(u, sReq)
        val (tReq, t) = u.buildCreateSharedVault(); client.createVault(u, tReq)
        assertEquals(HttpStatusCode.Created, client.addMember(u, s, b, "writer").status)
        assertEquals(HttpStatusCode.Created, client.addMember(u, t, b, "reader").status)

        val expected = listOf(s.vaultId, t.vaultId).sorted().map { AccountDeleteBlocker("shared_vault", it, 1) }
        assertEquals(expected, client.deletePreview(u).blockers, "the preview names each blocking vault")
        assertEquals(expected, blockersOf(client.deleteAccount(u)), "the refusal names the same vaults")
        assertNotNull(services.repo.userById(u.userId), "a refused deletion deletes nothing")
        assertEquals(2, client.sync(u).vaults.count { it.vaultId == s.vaultId || it.vaultId == t.vaultId })
        assertEquals("shared_vault,shared_vault", client.auditRows(admin, "account_delete_denied").single().meta)

        // Resolve one by transferring it, the other by deleting it.
        val (offerId, _, offer) = client.offerWithProof(u, s, b, seq = 1)
        assertEquals(HttpStatusCode.Created, offer.status, offer.bodyAsText())
        val bVk = client.openMemberVk(b, s.vaultId)
        val wrapped = b.wrapVkUnderOwnUvk(s.vaultId, bVk)
        val accept = client.transferAccept(b, s.vaultId, TransferAcceptRequest(offerId, wrapped, b.mintAcceptProof(s.vaultId, bVk, offerId, b.userId, 1, wrapped)))
        assertEquals(HttpStatusCode.OK, accept.status, accept.bodyAsText())
        client.deleteWithProof(u, t)

        val after = client.deletePreview(u)
        assertEquals(emptyList(), after.blockers)
        assertEquals(listOf(u.personalVaultId, t.vaultId).sorted(), after.deletedVaults, "the soft-deleted vault goes with the account")
        assertEquals(listOf(s.vaultId), after.leftVaults, "the transferred vault is a membership now")
        assertEquals(HttpStatusCode.OK, client.deleteAccount(u).status)

        // The transferred vault lives on with its new owner; the soft-deleted one is purged at once.
        val bView = client.sync(b)
        assertEquals("owner", bView.grants.single { it.vaultId == s.vaultId }.role)
        assertNotNull(services.repo.db.read { c -> c.queryOne("SELECT purgedAt FROM vaults WHERE vaultId=?", t.vaultId) { it.getObject(1) } })
        assertEquals(0, services.count("SELECT COUNT(*) FROM grants WHERE vaultId=? AND (wrappedVk<>'' OR sealedVk IS NOT NULL)", t.vaultId), "the ex-member's sealed key goes with the purge")
    }

    @Test
    fun lastAdmin_withOtherAccounts_isBlocked_untilAnotherAdminExists() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("admin@x.com", "last admin deletion password")
        client.register(admin, bootstrapToken)
        val b = client.enrollSecond(admin, "member@x.com", "last admin member password")

        val expected = listOf(AccountDeleteBlocker("last_admin", null, 1))
        assertEquals(expected, client.deletePreview(admin).blockers)
        assertEquals(expected, blockersOf(client.deleteAccount(admin)))

        val second = VirtualClient("second@x.com", "the second admin password")
        client.register(second, client.invite(admin, "second@x.com", isAdmin = true))
        assertEquals(emptyList(), client.deletePreview(admin).blockers)
        assertEquals(HttpStatusCode.OK, client.deleteAccount(admin).status)
        assertEquals(setOf(b.userId, second.userId), services.repo.db.read { c -> c.queryAll("SELECT userId FROM users") { it.getString(1) }.toSet() })
    }

    @Test
    fun theOnlyAccount_mayDeleteItself_andTheNextStartReBootstraps() = testApplication {
        val cfg = config()
        val services = buildServices(cfg, Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("alone@x.com", "the only account password")
        client.register(admin, bootstrapToken)
        client.invite(admin, "never-came@x.com") // an unused invite of the household that is about to end
        assertEquals(emptyList(), client.deletePreview(admin).blockers, "no other account would be stranded")
        assertEquals(HttpStatusCode.OK, client.deleteAccount(admin).status)
        assertEquals(0, services.count("SELECT COUNT(*) FROM users"))
        assertEquals(0, services.count("SELECT COUNT(*) FROM invites"), "the last account takes every invite with it, the used bootstrap row included")

        // The next start: a fresh bootstrap invite, redeemable with the operator's token.
        val restarted = buildServices(config(dbPath = cfg.dbPath), Notifier())
        assertEquals(1, restarted.count("SELECT COUNT(*) FROM invites WHERE email='*' AND usedAt IS NULL AND expiresAt>?", now()))
        val next = VirtualClient("next@x.com", "the next first admin password")
        assertTrue(restarted.service.register(next.buildRegister(bootstrapToken, recovery.publicKey, fingerprint), "127.0.0.1").isAdmin)
    }

    @Test
    fun aDatabaseEmptiedWithInvitesLeftOver_stillReBootstrapsAtTheNextStart() {
        // What an instance emptied by an older build looks like: no account, the used `*` row it registered through, and
        // an invite its admin minted that nobody redeemed. The used row once counted as "an invite exists" and blocked the
        // re-mint, silently, until the janitor pruned it ~33 days later.
        val cfg = config()
        val first = buildServices(cfg, Notifier())
        first.repo.db.tx { c ->
            c.exec("UPDATE invites SET usedAt=? WHERE email=?", now(), BOOTSTRAP_ANY_EMAIL)
            c.exec(
                "INSERT INTO invites(tokenHash,email,isAdmin,createdAt,expiresAt) VALUES(?,?,0,?,?)",
                ServerCrypto.hashToken("an invite the gone admin minted"), "left@x.com", now(), now() + 3_600_000,
            )
        }
        val restarted = buildServices(config(dbPath = cfg.dbPath), Notifier())
        val live = restarted.repo.db.read { c -> c.queryAll("SELECT email FROM invites WHERE usedAt IS NULL") { it.getString(1) } }
        assertEquals(listOf(BOOTSTRAP_ANY_EMAIL), live, "only a fresh bootstrap invite survives a start with no account")
        assertEquals(1, restarted.count("SELECT COUNT(*) FROM invites"))
        assertTrue(restarted.service.register(VirtualClient("first@x.com", "first admin again password").buildRegister(bootstrapToken, recovery.publicKey, fingerprint), "127.0.0.1").isAdmin)
    }

    // ---- the gate ----

    @Test
    fun wrongProofOrEmail_isRefused_audited_andDeletesNothing() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("admin@x.com", "gate admin password one")
        client.register(admin, bootstrapToken)
        val u = client.enrollSecond(admin, "gate@x.com", "gate member password one")

        val email = client.deleteAccount(u, AccountDeleteRequest("someone-else@x.com", u.authKey))
        assertEquals(HttpStatusCode.BadRequest, email.status)
        assertEquals("confirm_email_mismatch", errorOf(email))

        val guess = VirtualClient(u.email, "a guessed master password").authKey
        val wrong = client.deleteAccount(u, AccountDeleteRequest(u.email, guess))
        assertEquals(HttpStatusCode.Forbidden, wrong.status, "a wrong proof is a 403, never a 401 that sends the client into a refresh")
        assertEquals("reauth_failed", errorOf(wrong))
        assertEquals(1, client.auditRows(admin, "account_delete_reauth_fail").size)
        assertNotNull(services.repo.userById(u.userId))
        assertEquals(HttpStatusCode.OK, client.get("/api/v1/sync") { authed(u) }.status, "the session survives a refused deletion")

        // The typed email is compared trimmed and lowercased.
        assertEquals(HttpStatusCode.OK, client.deleteAccount(u, AccountDeleteRequest("  GATE@X.com ", u.authKey)).status)
        assertNull(services.repo.userById(u.userId))
    }

    @Test
    fun totpEnrolled_theCodeIsCheckedBeforeThePassword() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("admin@x.com", "totp gate admin password")
        client.register(admin, bootstrapToken)
        val u = client.enrollSecond(admin, "totp@x.com", "totp gate member password")
        val secret = enrollTotp(services, u)
        assertTrue(client.deletePreview(u).totpRequired)

        val missing = client.deleteAccount(u)
        assertEquals(HttpStatusCode.BadRequest, missing.status)
        assertEquals("totp_code_required", errorOf(missing))

        val code = totpCode(secret)
        val badCode = code.map { if (it == '9') '0' else it + 1 }.joinToString("")
        val wrongCode = client.deleteAccount(u, AccountDeleteRequest(u.email, u.authKey, badCode))
        assertEquals(HttpStatusCode.BadRequest, wrongCode.status)
        assertEquals("bad_totp_code", errorOf(wrongCode), "a wrong code with the RIGHT password answers like any wrong code: no password oracle")
        assertEquals(0, client.auditRows(admin, "account_delete_reauth_fail").size, "the password was never evaluated")
        assertEquals("account_delete", client.auditRows(admin, "totp_verify_fail").single().meta)

        val guess = VirtualClient(u.email, "a guessed master password").authKey
        val wrongPassword = client.deleteAccount(u, AccountDeleteRequest(u.email, guess, code))
        assertEquals(HttpStatusCode.Forbidden, wrongPassword.status)
        assertEquals("reauth_failed", errorOf(wrongPassword))

        assertEquals(HttpStatusCode.OK, client.deleteAccount(u, AccountDeleteRequest(u.email, u.authKey, code)).status, "the code is consumed only by the deletion tx")
        assertNull(services.repo.userById(u.userId))
    }

    @Test
    fun totpCode_isSingleUse_evenWhenTheDeletionIsRefused() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("admin@x.com", "totp replay admin password")
        client.register(admin, bootstrapToken)
        val u = client.enrollSecond(admin, "replay@x.com", "totp replay member password")
        val b = client.enrollSecond(admin, "member@x.com", "totp replay other password")
        val (sReq, s) = u.buildCreateSharedVault(); client.createVault(u, sReq)
        client.addMember(u, s, b, "reader")
        val secret = enrollTotp(services, u)

        val code = totpCode(secret)
        assertEquals(listOf(AccountDeleteBlocker("shared_vault", s.vaultId, 1)), blockersOf(client.deleteAccount(u, AccountDeleteRequest(u.email, u.authKey, code))))
        val replay = client.deleteAccount(u, AccountDeleteRequest(u.email, u.authKey, code))
        assertEquals(HttpStatusCode.BadRequest, replay.status)
        assertEquals("bad_totp_code", errorOf(replay), "the refused attempt consumed the step")

        assertEquals(HttpStatusCode.OK, client.removeMember(u, s.vaultId, b.userId).status)
        assertEquals(HttpStatusCode.OK, client.deleteAccount(u, AccountDeleteRequest(u.email, u.authKey, totpCode(secret, stepOffset = 1))).status)
    }

    @Test
    fun breakGlassOrigin_refusesTheDeletionAndItsPreview() = testApplication {
        val public = "andvari.example.com"
        val services = buildServices(config(publicHostname = public), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("admin@x.com", "break glass deletion admin")
        client.register(admin, bootstrapToken)
        val u = client.enrollSecond(admin, "remote@x.com", "break glass deletion member")

        val preview = client.get("/api/v1/account/delete/preview") { authed(u); header("Host", public) }
        assertEquals(HttpStatusCode.Forbidden, preview.status)
        assertEquals("account_delete_public_disabled", errorOf(preview))
        val delete = client.deleteAccount(u, host = public)
        assertEquals(HttpStatusCode.Forbidden, delete.status)
        assertEquals("account_delete_public_disabled", errorOf(delete))
        assertNotNull(services.repo.userById(u.userId), "nothing is deleted from the emergency origin")

        assertEquals(HttpStatusCode.OK, client.deleteAccount(u).status, "the same session deletes from the home origin")
    }

    @Test
    fun theDeletionRoute_isBucketedPerHour() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("admin@x.com", "bucket admin password one")
        client.register(admin, bootstrapToken)
        val u = client.enrollSecond(admin, "bucket@x.com", "bucket member password one")
        val guess = VirtualClient(u.email, "a guessed master password").authKey
        repeat(5) { assertEquals(HttpStatusCode.Forbidden, client.deleteAccount(u, AccountDeleteRequest(u.email, guess)).status) }
        assertEquals(HttpStatusCode.TooManyRequests, client.deleteAccount(u).status, "the sixth attempt in an hour waits, even with the right proof")
        assertNotNull(services.repo.userById(u.userId))
    }

    // ---- what everyone else sees ----

    @Test
    fun aTransferOfferToTheAccount_isCleared_andTheHouseholdIsRung() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val ws = createClient { install(ContentNegotiation) { json(json) }; install(WebSockets) }
        val admin = VirtualClient("admin@x.com", "offer clear admin password")
        ws.register(admin, bootstrapToken)
        val u = ws.enrollSecond(admin, "target@x.com", "offer clear member password")
        val (vReq, v) = admin.buildCreateSharedVault(); ws.createVault(admin, vReq)
        ws.addMember(admin, v, u, "writer")
        val (offerId, _, offer) = ws.offerWithProof(admin, v, u, seq = 1)
        assertEquals(HttpStatusCode.Created, offer.status)
        assertEquals(offerId, ws.sync(admin).vaults.single { it.vaultId == v.vaultId }.pendingTransfer?.offerId)
        val cursor = ws.sync(admin).rev

        suspend fun ticket(vc: VirtualClient): String =
            json.decodeFromString(WsTicketResponse.serializer(), ws.post("/api/v1/events/ticket") { authed(vc) }.bodyAsText()).ticket.encodeURLParameter()
        val uTicket = ticket(u); val adminTicket = ticket(admin)
        ws.webSocket("/api/v1/events?ticket=$uTicket") {
            val uSocket = this
            outgoing.send(Frame.Text("ping")); assertEquals("pong", (incoming.receive() as Frame.Text).readText())
            ws.webSocket("/api/v1/events?ticket=$adminTicket") {
                outgoing.send(Frame.Text("ping")); assertEquals("pong", (incoming.receive() as Frame.Text).readText())
                assertEquals(HttpStatusCode.OK, ws.deleteAccount(u).status)
                val bell = withTimeout(10_000) { (incoming.receive() as Frame.Text).readText() }
                assertTrue(bell.contains("\"rev\""), "the co-member is rung: $bell")
            }
            val frame = withTimeout(10_000) { (uSocket.incoming.receive() as Frame.Text).readText() }
            assertTrue(frame.contains("\"revoked\""), "the deleted account's socket is told to lock: $frame")
            assertNotNull(withTimeout(10_000) { closeReason.await() }, "…and then closed")
        }

        val after = ws.sync(admin, cursor)
        assertNull(after.vaults.single { it.vaultId == v.vaultId }.pendingTransfer, "the offer banner clears for every member")
        val cancel = ws.auditRows(admin, "vault_transfer_cancel").single()
        assertEquals("${v.vaultId}:target_deleted", cancel.meta)
        assertNull(cancel.userId, "a system row of the vault's history, not the deleted account's")
        assertNotNull(ws.auditRows(admin, "account_delete").single().ip, "the deletion request had an address…")
        assertNull(cancel.ip, "…which the vault's history, kept past the deleted account's 90 days, does not carry")
    }

    // ---- audit: pseudonym, retention, the straggler belt ----

    @Test
    fun auditTrail_isPseudonymised_andPurgedNinetyDaysAfterTheDeletion() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("admin@x.com", "audit retention admin password")
        client.register(admin, bootstrapToken)
        val u = client.enrollSecond(admin, "audited@x.com", "audit retention member password")
        val (sReq, _) = u.buildCreateSharedVault(); client.createVault(u, sReq) // vault_create: activity, not kept
        val lookup = client.post("/api/v1/users/lookup") { authed(admin); contentType(ContentType.Application.Json); setBody(io.silencelen.andvari.core.model.UserLookupRequest(u.email)) }
        assertEquals(HttpStatusCode.OK, lookup.status) // the admin's user_lookup row names the account in meta
        val guess = VirtualClient(u.email, "a guessed master password").authKey
        client.deleteAccount(u, AccountDeleteRequest(u.email, guess)) // account_delete_reauth_fail: kept
        val gone = u.userId

        assertEquals(HttpStatusCode.OK, client.deleteAccount(u).status)
        val deletion = client.auditRows(admin, "account_delete").single()
        val pseudonym = deletion.userId!!
        assertNotEquals(gone, pseudonym)
        assertTrue(UUID_RE.matches(pseudonym), "the pseudonym is shaped like a userId, so every client's id grammar renders it")
        assertNull(services.repo.userById(pseudonym), "and names no account")
        assertEquals("vaults=2,left=0", deletion.meta)

        val kept = services.repo.db.read { c -> c.queryAll("SELECT type FROM audit WHERE userId=?", pseudonym) { it.getString(1) }.toSet() }
        assertEquals(setOf("register", "account_delete_reauth_fail", "account_delete"), kept, "the security record survives under the pseudonym")
        assertEquals(0, services.count("SELECT COUNT(*) FROM audit WHERE type='vault_create' AND userId IS NOT NULL AND userId<>?", admin.userId), "activity rows go")
        assertEquals(0, services.count("SELECT COUNT(*) FROM audit WHERE userId=? OR instr(COALESCE(meta,''), ?) > 0", gone, gone))
        assertEquals(pseudonym, client.auditRows(admin, "user_lookup").single { it.meta != null }.meta, "another account's row now names the pseudonym")

        val day = Service.DAY_MS
        assertEquals(0L, services.janitor.sweep(now() + 89 * day).prunedDeletedAccountAudit, "inside the window nothing goes")
        assertEquals(3L, services.janitor.sweep(now() + 91 * day).prunedDeletedAccountAudit)
        assertEquals(0, services.count("SELECT COUNT(*) FROM audit WHERE userId=?", pseudonym))
        assertEquals(1, services.count("SELECT COUNT(*) FROM audit WHERE type='user_lookup' AND meta=?", pseudonym), "the admin's own history keeps the ordinary year")
    }

    @Test
    fun aRowWrittenForTheDeletedAccountAfterward_neverCarriesItsId() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("admin@x.com", "straggler admin password one")
        client.register(admin, bootstrapToken)
        val u = client.enrollSecond(admin, "straggler@x.com", "straggler member password one")
        val gone = u.userId
        assertEquals(HttpStatusCode.OK, client.deleteAccount(u).status)

        // What a request that authenticated before the deletion committed writes after it (a queued push's denial).
        services.repo.audit("push_denied", gone, "a-device", "203.0.113.9", "vault:item")
        val row = services.repo.auditQuery(0, "push_denied", null, 10).single()
        assertNull(row.userId)
        assertNull(row.deviceId, "the account's device id is not written back either")
        assertNull(row.ip, "nor its address: the row outlives the 90 days the account's own rows keep one")
        assertEquals("deleted_account:vault:item", row.meta)
        assertEquals(0, services.count("SELECT COUNT(*) FROM audit WHERE userId=?", gone))
        // A live account's row is written as given.
        services.repo.audit("push_denied", admin.userId, "a-device", "203.0.113.9", "vault:item")
        val live = services.repo.auditQuery(0, "push_denied", admin.userId, 10).single()
        assertEquals("a-device", live.deviceId); assertEquals("203.0.113.9", live.ip); assertEquals("vault:item", live.meta)
    }

    @Test
    fun theAccountsDeviceIds_arePseudonymisedInEveryRow_anotherAccountsDeviceIsLeftAlone() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("admin@x.com", "device pseudonym admin password")
        client.register(admin, bootstrapToken)
        // U is a second admin (so it may delete itself) with two devices; M is a member whose device U revokes.
        val u = VirtualClient("second@x.com", "device pseudonym second admin")
        val uFirst = client.register(u, client.invite(admin, "second@x.com", isAdmin = true)).deviceId
        val m = client.enrollSecond(admin, "member@x.com", "device pseudonym member password")
        val mDevice = services.repo.db.read { c -> c.queryOne("SELECT deviceId FROM devices WHERE userId=?", m.userId) { it.getString(1) } }!!
        val login = client.post("/api/v1/auth/login") {
            contentType(ContentType.Application.Json); header("X-Andvari-Client", "test/1.0.0")
            setBody(io.silencelen.andvari.core.model.LoginRequest(u.email, u.authKey, io.silencelen.andvari.core.model.DeviceInfo("test", "second device")))
        }
        assertEquals(HttpStatusCode.OK, login.status, login.bodyAsText())
        val uSecond = json.decodeFromString(io.silencelen.andvari.core.model.SessionResponse.serializer(), login.bodyAsText()).deviceId
        assertEquals(HttpStatusCode.OK, client.post("/api/v1/admin/devices/$mDevice/revoke") { authed(u) }.status) // U's row names M's device
        assertEquals(HttpStatusCode.OK, client.post("/api/v1/admin/devices/$uSecond/revoke") { authed(admin) }.status) // the admin's names U's

        assertEquals(HttpStatusCode.OK, client.deleteAccount(u).status) // from U's first device
        val pseudonym = client.auditRows(admin, "account_delete").single().userId!!
        fun rowsOf(userId: String, type: String) = services.repo.auditQuery(0, type, userId, 50)

        // Neither of U's device ids is left anywhere.
        assertEquals(emptyList(), services.cellsContaining(uFirst))
        assertEquals(emptyList(), services.cellsContaining(uSecond))
        // Each is replaced by one fresh id of its own, the same in every row naming it — which device did what still reads.
        val first = rowsOf(pseudonym, "register").single().deviceId!!
        assertEquals(first, rowsOf(pseudonym, "account_delete").single().deviceId, "registered and deleted from one device")
        val second = rowsOf(pseudonym, "login").single().deviceId!!
        assertEquals(second, rowsOf(admin.userId, "device_revoke").single().deviceId, "the admin's row follows the device it revoked")
        assertTrue(UUID_RE.matches(first) && UUID_RE.matches(second))
        assertTrue(setOf(first, second).intersect(setOf(uFirst, uSecond, mDevice)).isEmpty() && first != second)
        // M's device is not U's to rename: U's kept revocation and M's own rows still name it.
        assertEquals(mDevice, rowsOf(pseudonym, "device_revoke").single().deviceId)
        assertEquals(mDevice, rowsOf(m.userId, "register").single().deviceId)
    }

    @Test
    fun anAdminActingOnADeletedAccountsIds_recordsTheAttempt_withoutWritingTheIdsBack() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("admin@x.com", "stale screen admin password")
        client.register(admin, bootstrapToken)
        val u = client.enrollSecond(admin, "deleted@x.com", "stale screen member password")
        val gone = u.userId
        val goneDevice = services.repo.db.read { c -> c.queryOne("SELECT deviceId FROM devices WHERE userId=?", gone) { it.getString(1) } }!!
        assertEquals(HttpStatusCode.OK, client.deleteAccount(u).status)

        // An admin screen opened before the deletion still holds both ids.
        assertEquals(HttpStatusCode.NotFound, client.get("/api/v1/admin/users/$gone/escrow") { authed(admin) }.status)
        val disable = client.post("/api/v1/admin/users/$gone/disable") { authed(admin) }
        assertEquals("no_such_user", errorOf(disable))
        val revoke = client.post("/api/v1/admin/devices/$goneDevice/revoke") { authed(admin) }
        assertEquals("no_such_device", errorOf(revoke))

        assertEquals("no_such_user", client.auditRows(admin, "escrow_admin_read").single().meta)
        assertEquals("no_such_user", client.auditRows(admin, "user_disable_denied").single().meta)
        val denied = client.auditRows(admin, "device_revoke_denied").single()
        assertNull(denied.deviceId); assertEquals("no_such_device", denied.meta)
        assertEquals(emptyList(), services.cellsContaining(gone))
        assertEquals(emptyList(), services.cellsContaining(goneDevice))
    }

    @Test
    fun theDeletedUserIdAndItsPseudonym_canNeverNameANewAccount() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("admin@x.com", "retired ids admin password")
        client.register(admin, bootstrapToken)
        val u = client.enrollSecond(admin, "retired@x.com", "retired ids member password")
        val gone = u.userId
        assertEquals(HttpStatusCode.OK, client.deleteAccount(u).status)
        val pseudonym = client.auditRows(admin, "account_delete").single().userId!!

        // The client chooses its userId at register. Neither id the deletion left behind may name a new account: the old
        // one would revive lookups of it, and the pseudonym would hand the new account rows the 90-day purge then erases.
        val token = client.invite(admin, "retired@x.com")
        val again = VirtualClient("retired@x.com", "a brand new password here")
        for (id in listOf(gone, pseudonym)) {
            val r = client.post("/api/v1/auth/register") {
                contentType(ContentType.Application.Json); header("X-Andvari-Client", "test/1.0.0")
                setBody(again.buildRegister(token, recovery.publicKey, fingerprint).copy(userId = id))
            }
            assertEquals(HttpStatusCode.BadRequest, r.status, r.bodyAsText())
            assertEquals("user_id_taken", errorOf(r))
        }
        // The refusals consumed nothing: the same invite registers the address under a fresh id.
        client.register(again, token)
        assertTrue(again.userId != gone && again.userId != pseudonym)
        // Kept as digests only: the table answers "retired?" for an id one already holds, and names nobody.
        assertEquals(2, services.count("SELECT COUNT(*) FROM retired_ids WHERE idHash IN (?,?)", sha256HexUtf8(gone), sha256HexUtf8(pseudonym)))
        assertEquals(emptyList(), services.cellsContaining(gone))
        assertEquals(emptyList(), services.cellsContaining(pseudonym).filter { !it.startsWith("audit.") }, "the pseudonym lives only in the audit rows it keys")
    }

    // ---- invites ----

    @Test
    fun invitesNamingTheAccount_andUnusedOnesItMinted_goWithIt() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("admin@x.com", "invite cleanup admin password")
        client.register(admin, bootstrapToken)
        // Two invites to the same address; the account registers with one, the other stays pending.
        val first = client.invite(admin, "coadmin@x.com", isAdmin = true)
        client.invite(admin, "coadmin@x.com", isAdmin = true)
        val u = VirtualClient("coadmin@x.com", "invite cleanup coadmin password")
        client.register(u, first)
        // As an admin it mints an invite nobody has used yet; the other admin's own invite is not its business.
        client.invite(u, "friend@x.com")
        client.invite(admin, "stranger@x.com")
        assertEquals(3, services.count("SELECT COUNT(*) FROM invites WHERE email IN ('coadmin@x.com','friend@x.com')"))

        assertEquals(HttpStatusCode.OK, client.deleteAccount(u).status)
        assertEquals(0, services.count("SELECT COUNT(*) FROM invites WHERE email IN ('coadmin@x.com','friend@x.com')"), "every invite to the address, used or not, and the unused one it minted")
        assertEquals(1, services.count("SELECT COUNT(*) FROM invites WHERE email='stranger@x.com'"))
        assertEquals(1, client.auditRows(admin, "invite_create").count { it.userId != admin.userId }, "its own invite_create row is kept, under the pseudonym")
    }

    // ---- no column anywhere names the account afterward ----

    @Test
    fun noColumnAnywhereNamesTheAccountAfterward_evenOnVaultsItNoLongerOwns() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("admin@x.com", "trace admin password one")
        client.register(admin, bootstrapToken)
        val u = client.enrollSecond(admin, "trace@x.com", "trace member password one")
        val b = client.enrollSecond(admin, "heir@x.com", "trace heir password one")

        // A vault it deleted, restored and then handed over: `deletedBy` survives a restore, so it still names the account.
        val (sReq, s) = u.buildCreateSharedVault(); client.createVault(u, sReq)
        client.addMember(u, s, b, "writer")
        val (deleteId, _) = client.deleteWithProof(u, s)
        assertEquals(HttpStatusCode.OK, client.vaultRestore(u, s.vaultId, deleteId, u.mintRestoreProof(s.vaultId, s.vk, deleteId)).status)
        val (offerId, _, offer) = client.offerWithProof(u, s, b, seq = 1)
        assertEquals(HttpStatusCode.Created, offer.status, offer.bodyAsText())
        val bVk = client.openMemberVk(b, s.vaultId)
        val wrapped = b.wrapVkUnderOwnUvk(s.vaultId, bVk)
        val accept = client.transferAccept(b, s.vaultId, TransferAcceptRequest(offerId, wrapped, b.mintAcceptProof(s.vaultId, bVk, offerId, b.userId, 1, wrapped)))
        assertEquals(HttpStatusCode.OK, accept.status, accept.bodyAsText())
        // And one it deleted that the janitor has already purged (outside the set a deletion purges).
        val (tReq, t) = u.buildCreateSharedVault(); client.createVault(u, tReq)
        client.addMember(u, t, b, "reader")
        client.deleteWithProof(u, t)
        assertTrue(services.janitor.purgeVault(t.vaultId, now() + 8 * Service.DAY_MS))
        val named = services.repo.db.read { c -> c.queryAll("SELECT vaultId FROM vaults WHERE deletedBy=?", u.userId) { it.getString(1) }.toSet() }
        assertEquals(setOf(s.vaultId, t.vaultId), named, "fixture: both rows still name the account")

        val gone = u.userId
        assertEquals(HttpStatusCode.OK, client.deleteAccount(u).status)
        assertEquals(emptyList(), services.cellsContaining(gone), "no column of any table names the deleted userId")
        assertEquals(emptyList(), services.cellsContaining(u.email), "…or its address")
        assertEquals("owner", client.sync(b).grants.single { it.vaultId == s.vaultId }.role, "the handed-over vault lives on")
    }

    // ---- the audit-type classification tripwire ----

    @Test
    fun everyAuditTypeTheServerWrites_isClassifiedRetainedOrDropped() {
        val dir = listOf(File("src/main/kotlin/io/silencelen/andvari/server"), File("server/src/main/kotlin/io/silencelen/andvari/server")).firstOrNull { it.isDirectory }
        assertNotNull(dir, "server sources not found from ${File(".").absolutePath}")
        val call = Regex("""audit(?:On|PseudonymOn)?\(\s*(?:c,\s*)?"([a-z_]+)"""")
        // The two types written through an expression rather than a literal argument.
        val computed = Regex(""""(totp_enroll|totp_rotate|personal_wrap_set|personal_wrap_redesignate)"""")
        val types = dir.walkTopDown().filter { it.extension == "kt" }.flatMap { f ->
            val text = f.readText()
            call.findAll(text).map { it.groupValues[1] } + computed.findAll(text).map { it.groupValues[1] }
        }.toSet()
        assertTrue(types.size >= 50, "the scan found only ${types.size} audit types — did the call shape change?")
        val sets = listOf(AccountDeletion.RETAINED_AUDIT_TYPES, AccountDeletion.VAULT_SCOPED_AUDIT_TYPES, AccountDeletion.DROPPED_AUDIT_TYPES)
        val unclassified = types - sets.flatten().toSet()
        assertEquals(
            emptySet(), unclassified,
            "classify each new audit type in AccountDeletion: retained (kept 90 days under the pseudonym), vault-scoped (kept while its vault outlives the deletion), or dropped",
        )
        for (i in sets.indices) for (j in sets.indices) if (i < j) assertEquals(emptySet(), sets[i] intersect sets[j], "the sets are disjoint")
        // The owner's list: revocations are security events, whatever vault they name.
        assertTrue(AccountDeletion.RETAINED_AUDIT_TYPES.containsAll(setOf("vault_member_remove", "vault_member_leave", "vault_delete")))
    }

    @Test
    fun auditRowsAboutDataThatOutlivesTheDeletion_stayUnderThePseudonym_onlyThoseAboutPurgedVaultsGo() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("admin@x.com", "audit integrity admin password")
        client.register(admin, bootstrapToken)
        val u = client.enrollSecond(admin, "writer@x.com", "audit integrity writer password")
        val b = client.enrollSecond(admin, "heir@x.com", "audit integrity heir password")

        // In the admin's vault V the account is a writer: it trashes an item and purges it for good, and leaves a file there.
        val (vReq, v) = admin.buildCreateSharedVault(); client.createVault(admin, vReq)
        client.addMember(admin, v, u, "writer")
        val vk = client.openMemberVk(u, v.vaultId)
        val trashed = uuid()
        val rev = client.push(u, Mutation(uuid(), "put", trashed, v.vaultId, 0, u.encItemIn(v.vaultId, vk, trashed, "short-lived"))).results.single().newItemRev!!
        client.push(u, Mutation(uuid(), "delete", trashed, v.vaultId, rev))
        assertEquals(HttpStatusCode.OK, client.post("/api/v1/items/$trashed/purge") { authed(u) }.status)
        val att = uuid(); val attItem = uuid()
        assertEquals(HttpStatusCode.OK, client.uploadAttachment(u, att, attItem, ByteArray(Attachments.HEADER_BYTES + 64) { 9 }, vaultId = v.vaultId).status)
        client.push(u, Mutation(uuid(), "put", attItem, v.vaultId, 0, u.encItemIn(v.vaultId, vk, attItem, "with a file").copy(attachmentIds = listOf(att))))
        // T: it creates a vault, shares it and hands it over — T outlives the deletion with its new owner.
        val (tReq, t) = u.buildCreateSharedVault(); client.createVault(u, tReq)
        client.addMember(u, t, b, "writer")
        val (offerId, _, offer) = client.offerWithProof(u, t, b, seq = 1)
        assertEquals(HttpStatusCode.Created, offer.status)
        val bVk = client.openMemberVk(b, t.vaultId)
        val wrapped = b.wrapVkUnderOwnUvk(t.vaultId, bVk)
        assertEquals(HttpStatusCode.OK, client.transferAccept(b, t.vaultId, TransferAcceptRequest(offerId, wrapped, b.mintAcceptProof(t.vaultId, bVk, offerId, b.userId, 1, wrapped))).status)
        // W: it shares a vault and removes the member again — a revocation; W itself is purged with the account.
        val (wReq, w) = u.buildCreateSharedVault(); client.createVault(u, wReq)
        client.addMember(u, w, b, "reader")
        assertEquals(HttpStatusCode.OK, client.removeMember(u, w.vaultId, b.userId).status)
        // S: a vault only it ever held; and a lookup.
        val (sReq, s) = u.buildCreateSharedVault(); client.createVault(u, sReq)
        client.post("/api/v1/users/lookup") { authed(u); contentType(ContentType.Application.Json); setBody(io.silencelen.andvari.core.model.UserLookupRequest(b.email)) }

        assertEquals(HttpStatusCode.OK, client.deleteAccount(u).status)
        val pseudonym = client.auditRows(admin, "account_delete").single().userId!!
        val rows = services.repo.db.read { c -> c.queryAll("SELECT type, meta FROM audit WHERE userId=?", pseudonym) { it.getString(1) to it.getString(2) } }

        // Kept: whatever touched data that is still there, and every revocation.
        assertTrue(("item_purge" to "${v.vaultId}:$trashed") in rows, "who purged a shared vault's item: $rows")
        assertTrue(rows.any { it.first == "attachment_upload" && it.second.startsWith("$att:") }, "who uploaded the file still in V")
        assertTrue(("vault_create" to t.vaultId) in rows && ("vault_transfer_offer" to "${t.vaultId}:${b.userId}") in rows, "the history of a vault someone else now owns")
        assertTrue(("vault_member_remove" to "${w.vaultId}:${b.userId}") in rows, "a revocation, though W itself was purged")
        // Gone: activity about vaults this deletion purged, and the lookup.
        assertTrue(rows.none { it.first == "vault_create" && (it.second == s.vaultId || it.second == w.vaultId) }, "$rows")
        assertTrue(rows.none { it.first == "vault_member_add" && it.second.startsWith(w.vaultId) })
        assertTrue(rows.none { it.first == "personal_wrap_set" || it.first == "user_lookup" })
        assertEquals(0, services.count("SELECT COUNT(*) FROM audit WHERE userId=?", u.userId))

        // …and the kept rows go with the rest, 90 days after the deletion.
        services.janitor.sweep(now() + 91 * Service.DAY_MS)
        assertEquals(0, services.count("SELECT COUNT(*) FROM audit WHERE userId=?", pseudonym))
    }
}
