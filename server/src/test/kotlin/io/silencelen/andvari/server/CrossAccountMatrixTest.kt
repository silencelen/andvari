package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.Caller
import io.silencelen.andvari.core.model.wire.EscrowUpload
import io.silencelen.andvari.core.model.wire.LogPage
import io.silencelen.andvari.core.model.wire.MutationStatus
import io.silencelen.andvari.core.model.wire.RecoveryRequestCreated
import io.silencelen.andvari.core.model.wire.SyncResponse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.LogEntry
import io.silencelen.andvari.core.trust.MemberRole
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Who may touch what (spec 03 §0.1, §8's hidden-as-403/404 rule, §10.6, §15, §16, §18.3): one account naming
 * another's objects, a member acting as owner, a reader writing, a removed member, a non-operator on every
 * operator route, and a restricted (two-step enrolment) session on every normal route. Every table row
 * names the route and the refusal the index gives it.
 */
class CrossAccountMatrixTest {
    private val post = HttpMethod.Post
    private val get = HttpMethod.Get
    private val put = HttpMethod.Put
    private val del = HttpMethod.Delete
    private val name = Grammar.nameOf("Pixel 9")!!

    /** B's objects, every one of a kind the index lets an account own. */
    private class World(
        val s: Services, val op: Me, val a: Me, val b: Me, val vault: SharedVault, val liveItem: String, val deletedItem: String,
        val attachment: String, val deviceLink: String, val link: String, val requestId: String,
    )

    private suspend fun world(c: HttpClient, s: Services, recoveryKey: ByteArray): World {
        val op = Flow.finishSetup(c, s)
        val a = Flow.member(c, s, "a@example.com")
        val b = Me("b@example.com")
        Flow.register(c, s, b, Flow.enrolAuth(s), "operator", Flow.escrow(b, sha256Hex(recoveryKey)))
        val v = SharedVault(c, s, b).create()
        // An item with an attachment, and a tombstoned item.
        val live = uuid(); val att = uuid()
        assertEquals(200, c.upload(b.token, att, v.vaultId, live).status.value)
        assertEquals(MutationStatus.APPLIED, c.putItem(b, v.vaultId, live, listOf(att)).status)
        val dead = uuid()
        val created = c.putItem(b, v.vaultId, dead)
        assertEquals(MutationStatus.APPLIED, c.deleteItem(b, v.vaultId, dead, created.newItemRev!!).status)
        // A claimed device link.
        val dl = b16()
        assertEquals(201, c.call(post, "/api/v1/device-links", """{"linkId":"$dl","expiresAt":${s.clock.now() + 60_000}}""", b.token).status.value)
        assertEquals(200, c.call(post, "/api/v1/device-links/$dl/claim", """{"nPub":"${b32()}","name":"$name","platform":"android","commitN":"${"c".repeat(64)}","mac":"${b32()}"}""").status.value)
        // An open connect link.
        val link = b16()
        assertEquals(201, c.call(post, "/api/v1/links", """{"linkId":"$link","kind":"connect","offer":"AAAAAAAAAAAA","expiresAt":${s.clock.now() + 3_600_000}}""", b.token).status.value)
        // A verified assisted-recovery request, and some account state.
        val poll = TestKit.crypto.randomBytes(32)
        val reqId = WireJson.json.decodeFromString(
            RecoveryRequestCreated.serializer(),
            c.call(post, "/api/v1/recovery/requests", """{"email":"${b.email}","rPub":"${b32()}","pollHash":"${sha256Hex(poll)}","platform":"ios"}""").bodyAsText(),
        ).requestId
        val code = Flow.codeIn(Flow.sink(s).last { it.first == "recovery_request_code" }.third)
        assertEquals(200, c.call(post, "/api/v1/recovery/requests/$reqId/verify", """{"code":"$code"}""").status.value)
        assertEquals(200, c.call(put, "/api/v1/account/state", """{"sealedState":"QkJCQg","baseSeq":0}""", b.token).status.value)
        assertEquals(200, c.call(put, "/api/v1/usage", """{"sealedUsage":"QkJCQg"}""", b.token).status.value)
        return World(s, op, a, b, v, live, dead, att, dl, link, reqId)
    }

    private fun app(block: suspend (HttpClient, World) -> Unit) = testApplication {
        val key = TestKit.Identity().curvePub
        val s = TestKit.services(TestKit.config(recoveryKey = key), MutableClock(1_800_000_000_000L))
        application { andvariModule(s) }
        block(client, world(client, s, key))
    }

    private fun veto(signer: Me, userId: String, reqId: String) =
        """{"statement":"${Bytes.toB64(signer.identity.frame(10, """{"v":2,"purpose":"recovery-veto","requestId":"$reqId","userId":"$userId","issuedAt":1800000000000}"""))}"}"""

    @Test
    fun accountA_namingAccountBsObjects_learnsAndChangesNothing() = app { c, w ->
        val a = w.a; val t = a.token; val v = w.vault.vaultId
        val restore = """{"formatVersion":2,"attachmentIds":[],"blob":"QUJD"}"""
        c.expectAll(listOf(
            // Device and device link.
            Expect("26/27 revoke B's device", post, "/api/v1/account/devices/${w.b.deviceId}/revoke", t, 404, "no_such_device", """{"currentAuthKey":"${a.authKey}"}"""),
            Expect("60 read B's device link", get, "/api/v1/device-links/${w.deviceLink}", t, 404, "link_unknown"),
            Expect("62 nonce on B's device link", post, "/api/v1/device-links/${w.deviceLink}/nonce", t, 404, "link_unknown", """{"nonceE":"${b32()}","proofHash":"${"a".repeat(64)}"}"""),
            Expect("65 approve B's device link", post, "/api/v1/device-links/${w.deviceLink}/approve", t, 404, "link_unknown", """{"outer":"QUFB","inner":"QUFB","approveMac":"${b32()}"}"""),
            Expect("67 cancel B's device link", del, "/api/v1/device-links/${w.deviceLink}", t, 404, "link_unknown"),
            // Link.
            Expect("55 reveal on B's link", post, "/api/v1/links/${w.link}/reveal", t, 404, "link_unknown", """{"nonce":"${b32()}"}"""),
            Expect("57 ack B's link", post, "/api/v1/links/${w.link}/ack", t, 404, "link_unknown"),
            Expect("58 revoke B's link", del, "/api/v1/links/${w.link}", t, 404, "link_unknown"),
            // Vault.
            Expect("46 append to B's vault", post, "/api/v1/vaults/$v/log", t, 403, "no_grant", """{"entry":"${w.vault.sign(a, LogEntry.Leave(v, w.vault.next, w.vault.head, a.userId, w.vault.at))}"}"""),
            Expect("47 read B's vault log", get, "/api/v1/vaults/$v/log", t, 403, "no_grant"),
            Expect("48 list B's vault members", get, "/api/v1/vaults/$v/members", t, 403, "no_grant"),
            Expect("50 rename B's vault", put, "/api/v1/vaults/$v/meta", t, 403, "not_vault_owner", """{"metaBlob":"AAAA"}"""),
            Expect("51 self-wrap in B's vault", put, "/api/v1/vaults/$v/grant/self-wrap", t, 403, "no_grant", """{"wrappedVk":"AAAA"}"""),
            // Items and attachments.
            Expect("38 versions of B's item", get, "/api/v1/items/${w.liveItem}/versions", t, 403, "no_grant"),
            Expect("40 restore B's item", post, "/api/v1/items/${w.deletedItem}/restore", t, 403, "no_grant", restore),
            Expect("41 purge B's item", post, "/api/v1/items/${w.deletedItem}/purge", t, 403, "no_grant"),
            Expect("43 read B's attachment", get, "/api/v1/attachments/${w.attachment}", t, 403, "no_grant"),
            // Assisted recovery: A's session, a statement A signed in B's name or its own.
            Expect("70 veto B's request (B's userId)", post, "/api/v1/recovery/requests/${w.requestId}/veto", t, 404, "request_unknown", veto(a, w.b.userId, w.requestId)),
            Expect("70 veto B's request (A's userId)", post, "/api/v1/recovery/requests/${w.requestId}/veto", t, 404, "request_unknown", veto(a, a.userId, w.requestId)),
            // Account state and escrow are the session's own: A's private posture has no escrow to re-seal.
            Expect("23 re-seal an escrow A does not have", put, "/api/v1/escrow/self", t, 400, "escrow_not_allowed", """{"sealed":"${Bytes.toB64(ByteArray(200))}","fingerprint":"${"a".repeat(64)}","rotations":["AAAAAAAA"]}"""),
        ))
        // Uploads into B's vault, and into A's own vault under B's attachment id.
        assertEquals("no_grant", c.upload(t, uuid(), v, w.liveItem).errorCode())
        val cross = c.upload(t, w.attachment, a.personalVaultId, uuid())
        assertEquals(403, cross.status.value, cross.bodyAsText()); assertEquals("no_grant", cross.errorCode())
        assertEquals(1L, w.s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type='attachment_cross_vault'") })
        // Pushes into B's vault, and an item of B's under A's own vault id, are denied.
        assertEquals(MutationStatus.DENIED, c.putItem(a, v, uuid()).status)
        assertEquals(MutationStatus.DENIED, c.putItem(a, v, w.liveItem, base = 999).status)
        assertEquals(MutationStatus.DENIED, c.putItem(a, a.personalVaultId, w.liveItem, base = 999).status)
        assertEquals(MutationStatus.DENIED, c.deleteItem(a, a.personalVaultId, w.liveItem, 999).status)
        // A's own views show none of B's.
        val sync = c.call(get, "/api/v1/sync?since=0", token = t).bodyAsText()
        for (secret in listOf(v, w.liveItem, w.deletedItem, w.attachment, "QkJCQg")) assertFalse(secret in sync, secret)
        assertFalse(w.deletedItem in c.call(get, "/api/v1/items/deleted", token = t).bodyAsText())
        assertTrue(c.call(get, "/api/v1/account/state", token = t).bodyAsText().let { "QkJCQg" !in it && "\"seq\":0" in it })
        assertFalse("QkJCQg" in c.call(get, "/api/v1/usage", token = t).bodyAsText())
        assertEquals("[]", c.call(get, "/api/v1/account/recovery-requests", token = t).bodyAsText())
        assertFalse(w.b.deviceId in c.call(get, "/api/v1/account/devices", token = t).bodyAsText())
        assertEquals(200, c.call(put, "/api/v1/account/state", """{"sealedState":"QUFBQQ","baseSeq":0}""", t).status.value)
        // And nothing of B's changed.
        val bt = w.b.token
        assertTrue(c.call(get, "/api/v1/device-links/${w.deviceLink}", token = bt).bodyAsText().contains("\"state\":\"claimed\""))
        assertTrue(c.call(get, "/api/v1/links/${w.link}").bodyAsText().contains("\"state\":\"open\""))
        assertTrue(c.call(get, "/api/v1/account/state", token = bt).bodyAsText().let { "\"sealedState\":\"QkJCQg\"" in it && "\"seq\":1" in it })
        assertTrue("QkJCQg" in c.call(get, "/api/v1/usage", token = bt).bodyAsText())
        assertTrue(c.call(get, "/api/v1/account/recovery-requests", token = bt).bodyAsText().contains(w.requestId))
        assertEquals(200, c.call(get, "/api/v1/attachments/${w.attachment}", token = bt).status.value)
        val bSync = WireJson.json.decodeFromString(SyncResponse.serializer(), c.call(get, "/api/v1/sync?since=0", token = bt).bodyAsText())
        assertEquals(setOf(w.liveItem, w.deletedItem), bSync.items.filter { it.vaultId == v }.map { it.itemId }.toSet())
        assertEquals(w.vault.seq, bSync.vaults.single { it.vaultId == v }.logHead!!.seq)
        assertTrue(w.s.db.read { it.count("SELECT COUNT(*) FROM escrow WHERE userId=?", w.b.userId) } == 1L)
        assertTrue(w.s.db.read { it.count("SELECT COUNT(*) FROM devices WHERE userId=? AND revokedAt IS NULL", w.b.userId) } >= 1L)
    }

    @Test
    fun aWriterActingAsOwner_aReaderWriting_andARemovedMember() = app { c, w ->
        val v = w.vault
        val writer = Flow.member(c, w.s, "writer@example.com")
        val reader = Flow.member(c, w.s, "reader@example.com")
        val gone = Flow.member(c, w.s, "gone@example.com")
        v.add(writer, MemberRole.WRITER); v.add(reader, MemberRole.READER); v.add(gone, MemberRole.WRITER)
        val removeAt = v.remove(gone).head.seq
        val vid = v.vaultId
        fun frame(me: Me, e: LogEntry) = """{"entry":"${v.sign(me, e)}"}"""
        val wt = writer.token
        c.expectAll(listOf(
            // A writer is not the owner (§10.1, §11.3).
            Expect("50 writer renames", put, "/api/v1/vaults/$vid/meta", wt, 403, "not_vault_owner", """{"metaBlob":"AAAA"}"""),
            Expect("46 writer removes", post, "/api/v1/vaults/$vid/log", wt, 403, "not_vault_owner", frame(writer, LogEntry.Remove(vid, v.next, v.head, writer.userId, v.at, reader.userId))),
            Expect("46 writer deletes", post, "/api/v1/vaults/$vid/log", wt, 403, "not_vault_owner", frame(writer, LogEntry.Delete(vid, v.next, v.head, writer.userId, v.at, b16()))),
            Expect("46 writer changes a role", post, "/api/v1/vaults/$vid/log", wt, 403, "not_vault_owner", frame(writer, LogEntry.Role(vid, v.next, v.head, writer.userId, v.at, reader.userId, MemberRole.WRITER))),
            Expect("46 writer offers ownership", post, "/api/v1/vaults/$vid/log", wt, 403, "not_vault_owner", frame(writer, LogEntry.Offer(vid, v.next, v.head, writer.userId, v.at, reader.userId, reader.identity.identityPubB64, b16(), v.at + 60_000))),
            Expect("46 writer adds", post, "/api/v1/vaults/$vid/log", wt, 403, "not_vault_owner", """{"entry":"${v.sign(writer, LogEntry.Add(vid, v.next, v.head, writer.userId, v.at, w.a.userId, w.a.identity.identityPubB64, MemberRole.READER, b16()))}","grant":"AAAA"}"""),
            // A reader writes nothing.
            Expect("40 reader restores", post, "/api/v1/items/${w.deletedItem}/restore", reader.token, 403, "no_grant", """{"formatVersion":2,"attachmentIds":[],"blob":"QUJD"}"""),
            Expect("41 reader purges", post, "/api/v1/items/${w.deletedItem}/purge", reader.token, 403, "no_grant"),
            // A removed member keeps nothing but the log up to its removal.
            Expect("48 removed lists members", get, "/api/v1/vaults/$vid/members", gone.token, 403, "no_grant"),
            Expect("38 removed reads versions", get, "/api/v1/items/${w.liveItem}/versions", gone.token, 403, "no_grant"),
            Expect("43 removed reads an attachment", get, "/api/v1/attachments/${w.attachment}", gone.token, 403, "no_grant"),
            Expect("51 removed self-wraps", put, "/api/v1/vaults/$vid/grant/self-wrap", gone.token, 403, "no_grant", """{"wrappedVk":"AAAA"}"""),
            Expect("46 removed leaves", post, "/api/v1/vaults/$vid/log", gone.token, 403, "no_grant", frame(gone, LogEntry.Leave(vid, v.next, v.head, gone.userId, v.at))),
            Expect("40 removed restores", post, "/api/v1/items/${w.deletedItem}/restore", gone.token, 403, "no_grant", """{"formatVersion":2,"attachmentIds":[],"blob":"QUJD"}"""),
        ))
        // What the reader and the writer may do.
        assertEquals(MutationStatus.DENIED, c.putItem(reader, vid, uuid()).status)
        assertEquals(MutationStatus.DENIED, c.deleteItem(reader, vid, w.liveItem, 999).status)
        val ro = c.upload(reader.token, uuid(), vid, w.liveItem)
        assertEquals(403, ro.status.value, ro.bodyAsText()); assertEquals("no_write_grant", ro.errorCode())
        assertEquals(200, c.call(get, "/api/v1/items/${w.liveItem}/versions", token = reader.token).status.value)
        assertEquals(200, c.call(get, "/api/v1/attachments/${w.attachment}", token = reader.token).status.value)
        assertEquals(200, c.call(get, "/api/v1/vaults/$vid/members", token = reader.token).status.value)
        assertEquals(MutationStatus.APPLIED, c.putItem(writer, vid, uuid()).status)
        assertEquals(200, c.call(put, "/api/v1/vaults/$vid/grant/self-wrap", """{"wrappedVk":"AAAA"}""", wt).status.value)
        // The removed member: pushes denied, the log cut at its removal, the sync says removed.
        assertEquals(MutationStatus.DENIED, c.putItem(gone, vid, uuid()).status)
        assertEquals(MutationStatus.DENIED, c.putItem(gone, vid, w.liveItem, base = 999).status)
        assertEquals("no_grant", c.upload(gone.token, uuid(), vid, w.liveItem).errorCode())
        v.ok(w.b, LogEntry.Role(vid, v.next, v.head, w.b.userId, v.at, reader.userId, MemberRole.WRITER))
        val page = WireJson.json.decodeFromString(LogPage.serializer(), c.call(get, "/api/v1/vaults/$vid/log", token = gone.token).bodyAsText())
        assertEquals(removeAt, page.head.seq); assertEquals(removeAt + 1, page.entries.size.toLong())
        assertTrue(v.seq > removeAt)
        val gs = WireJson.json.decodeFromString(SyncResponse.serializer(), c.call(get, "/api/v1/sync?since=0", token = gone.token).bodyAsText())
        assertTrue(gs.items.none { it.vaultId == vid })
        assertEquals("removed", gs.removedGrantsInfo.single { it.vaultId == vid }.reason)
        assertFalse(w.deletedItem in c.call(get, "/api/v1/items/deleted", token = gone.token).bodyAsText())
    }

    /** Fills a path template with ids of the right grammar (none of them names anything). */
    private fun fill(path: String) = path
        .replace("{userId}", uuid()).replace("{deviceId}", uuid()).replace("{itemId}", uuid()).replace("{attachmentId}", uuid())
        .replace("{vaultId}", uuid()).replace("{linkId}", b16()).replace("{requestId}", b16()).replace("{prefix}", "ABCDE")

    private fun method(r: WireRoute) = HttpMethod.parse(r.method)

    @Test
    fun aMember_onEveryOperatorRoute_isNotOperator_andTheOperatorsWebSession_isRefused() = app { c, w ->
        val operatorRoutes = WireRoute.entries.filter { it.caller == Caller.OPERATOR || it.caller == Caller.OPERATOR_REAUTH }
        assertEquals(16, operatorRoutes.size, "rows 3, 4 and 73–86")
        val web = w.s.db.tx { db ->
            val dev = w.s.sessions.createDevice(db, w.op.userId, "web", "browser", "password", null, "1.0.0")
            w.s.sessions.issue(db, w.op.userId, dev, "web", passwordLogin = true).accessToken
        }
        c.expectAll(operatorRoutes.flatMap { r ->
            val body = if (r.method == "GET") null else """{"currentAuthKey":"${w.a.authKey}"}"""
            listOf(
                Expect("${r.row} member", method(r), fill(r.path), w.a.token, 403, "not_operator", body),
                Expect("${r.row} no bearer", method(r), fill(r.path), null, 401, "missing_token", body),
                Expect("${r.row} operator on web", method(r), fill(r.path), web, 403, "operator_web_refused", body?.replace(w.a.authKey, w.op.authKey)),
            )
        })
        // Nothing the member sent was acted on: no account was disabled, deleted or changed.
        assertEquals(0L, w.s.db.read { it.count("SELECT COUNT(*) FROM users WHERE status<>'active'") })
    }

    @Test
    fun aRestrictedSession_reachesOnlyTotpSetupConfirmAndLogout() = testApplication {
        val s = TestKit.services(TestKit.config(totpRequired = true))
        application { andvariModule(s) }
        val member = TestKit.seedAccount(s, "r@example.com")
        val op = TestKit.seedAccount(s, "op@example.com", role = "operator")
        val allowed = setOf(WireRoute.TOTP_SETUP, WireRoute.TOTP_CONFIRM, WireRoute.LOGOUT)
        val sessionRoutes = WireRoute.entries.filter { it.caller in setOf(Caller.SESSION, Caller.SESSION_REAUTH, Caller.OPERATOR, Caller.OPERATOR_REAUTH) && it !in allowed }
        // R routes answer 404 only on a public instance; this one is private, so every row reaches the session check.
        val rows = sessionRoutes.map { r ->
            val tok = TestKit.session(s, if (r.caller == Caller.OPERATOR || r.caller == Caller.OPERATOR_REAUTH) op else member)
            Expect("${r.row} restricted", method(r), fill(r.path), tok, 403, "totp_enrollment_required", if (r.method == "GET") null else """{"currentAuthKey":"${member.authKey}"}""")
        }
        assertTrue(rows.size > 60, rows.size.toString())
        client.expectAll(rows)
        // The three it may reach: GET /account/totp is refused, setup answers a secret, logout ends the session.
        val tok = TestKit.session(s, member)
        // A restricted session gets no recent-login exemption (§2): the first enrolment needs the password.
        assertEquals("reauth_required", client.call(post, "/api/v1/account/totp/setup", "{}", tok).errorCode())
        val setup = client.call(post, "/api/v1/account/totp/setup", """{"currentAuthKey":"${member.authKey}"}""", tok)
        assertEquals(200, setup.status.value, setup.bodyAsText())
        val secret = Regex("\"secretBase32\":\"([A-Z2-7]+)\"").find(setup.bodyAsText())!!.groupValues[1]
        val code = Flow.totp(secret, s.clock.now())
        val wrong = if (code == "000000") "111111" else "000000"
        assertEquals("bad_totp_code", client.call(post, "/api/v1/account/totp/confirm", """{"code":"$wrong"}""", tok).errorCode())
        assertEquals(200, client.call(post, "/api/v1/auth/logout", token = tok).status.value)
        assertEquals("invalid_credentials", client.call(get, "/api/v1/account/keys", token = tok).errorCode())
        // The events socket refuses a restricted bearer too (§6): its ticket route is refused above (row 44).
    }
}
