package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.EscrowUpload
import io.silencelen.andvari.core.model.wire.RecoveryRequestCreated
import io.silencelen.andvari.core.model.wire.RecoveryRequestSummary
import io.silencelen.andvari.core.model.wire.RecoveryVerifyResponse
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The assisted-recovery state machine (spec 03 §18) beyond the happy path: listing and veto in every state
 * before the commit (including `ready`), expiry checked at commit time, and the account events that cancel a
 * pending request (posture to private, a kit commit, a password change).
 */
class AssistedRecoveryTest {
    private fun b32() = Bytes.toB64(TestKit.crypto.randomBytes(32))

    /** One private instance with a recovery key, its operator, and an operator-posture member. */
    class Fixture(val c: HttpClient, val s: Services, val clock: MutableClock, val op: Me, val me: Me)

    private suspend fun fixture(c: HttpClient, s: Services, clock: MutableClock, key: ByteArray): Fixture {
        val op = Flow.finishSetup(c, s)
        val me = Me("me@example.com")
        Flow.register(c, s, me, Flow.enrolAuth(s), "operator", Flow.escrow(me, sha256Hex(key)))
        Flow.sink(s)
        return Fixture(c, s, clock, op, me)
    }

    /** Each opened request's key, and the commit value of the answer uploaded last for each poll secret (spec 03 §18.5, §18.6). */
    private val rPubs = HashMap<String, String>()
    private val commits = HashMap<String, ByteArray>()
    private val pollOf = HashMap<String, String>()

    /** A request opened and verified for [f.me]: (requestId, pollSecret b64). */
    private suspend fun openVerified(f: Fixture): Pair<String, String> {
        val poll = TestKit.crypto.randomBytes(32)
        val rPub = b32()
        val body = """{"email":"${f.me.email}","rPub":"$rPub","pollHash":"${sha256Hex(poll)}","platform":"android"}"""
        val reqId = WireJson.json.decodeFromString(RecoveryRequestCreated.serializer(), f.c.call(HttpMethod.Post, "/api/v1/recovery/requests", body).bodyAsText()).requestId
        val code = Flow.codeIn(Flow.sink(f.s).last { it.first == "recovery_request_code" }.third)
        assertEquals(200, f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/verify", """{"code":"$code"}""").status.value)
        rPubs[reqId] = rPub
        pollOf[reqId] = Bytes.toB64(poll)
        return reqId to Bytes.toB64(poll)
    }

    /** A fresh access token on [me]'s current device (the clock moved past the access TTL). */
    private fun fresh(s: Services, me: Me): String = s.db.tx { c -> s.sessions.issue(c, me.userId, me.deviceId, "linux", passwordLogin = true).accessToken }

    /** The one size of an answer for [f.me]'s address: 525 + the length of its base64url (spec 03 §18.6). */
    private fun answerSize(f: Fixture) = io.silencelen.andvari.core.trust.AnswerToken.sealedBytes(f.me.email)

    private fun commitHash(commit: ByteArray) = io.silencelen.andvari.core.trust.AssistedRecovery.commitHash(TestKit.crypto, commit)

    /** The fulfil body as the shared reader yields it; each part can be replaced to make the wrong one. */
    private fun fulfilBody(f: Fixture, sealed: String, requestKey: String?, commitHash: String?) = buildString {
        append("""{"sealed":"$sealed"""")
        requestKey?.let { append(""","requestKey":"$it"""") }
        commitHash?.let { append(""","commitHash":"$it"""") }
        append(""","currentAuthKey":"${f.op.authKey}"}""")
    }

    private suspend fun upload(f: Fixture, reqId: String, body: String, waitItsTurn: Boolean = false): io.ktor.client.statement.HttpResponse {
        // A † route takes 5 a minute per account; a test that uploads more often than that waits its turn.
        if (waitItsTurn) f.clock.advance(13_000)
        return f.c.call(HttpMethod.Post, "/api/v1/admin/recovery-requests/$reqId/fulfil", body, fresh(f.s, f.op))
    }

    /** The operator uploads a well-formed answer for [reqId] (its own key, the one size, a fresh commit hash). */
    private suspend fun fulfil(f: Fixture, reqId: String): Int {
        val commit = TestKit.crypto.randomBytes(32)
        val r = upload(f, reqId, fulfilBody(f, Bytes.toB64(TestKit.crypto.randomBytes(answerSize(f))), rPubs.getValue(reqId), commitHash(commit)))
        if (r.status.value == 200) commits[pollOf.getValue(reqId)] = commit
        return r.status.value
    }

    private suspend fun list(f: Fixture, token: String): List<RecoveryRequestSummary> =
        WireJson.json.decodeFromString(ListSerializer(RecoveryRequestSummary.serializer()), f.c.call(HttpMethod.Get, "/api/v1/account/recovery-requests", token = token).bodyAsText())

    private suspend fun syncCount(f: Fixture, token: String): Int =
        Regex("\"recoveryRequests\":(\\d+)").find(f.c.call(HttpMethod.Get, "/api/v1/sync?since=0", token = token).bodyAsText())!!.groupValues[1].toInt()

    private suspend fun pollState(f: Fixture, reqId: String, poll: String): String =
        Regex("\"state\":\"([a-z_]+)\"").find(f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/poll", """{"pollSecret":"$poll"}""").bodyAsText())!!.groupValues[1]

    private fun veto(me: Me, reqId: String) =
        """{"statement":"${Bytes.toB64(me.identity.frame(10, """{"v":2,"purpose":"recovery-veto","requestId":"$reqId","userId":"${me.userId}","issuedAt":1800000000000}"""))}"}"""

    /** The commit value the device that opened the last answer would present, as `"commit":…,` (empty when none was uploaded). */
    private fun commitField(poll: String) = commits[poll]?.let { """"commit":"${Bytes.toB64(it)}",""" } ?: ""

    private fun commitBody(poll: String, commit: String = commitField(poll), platform: String = "ios") =
        """{"pollSecret":"$poll",$commit"newAuthKey":"${b32()}","newKdfSalt":"${Bytes.toB64(ByteArray(16) { 5 })}","newKdfParams":{"v":1,"alg":"argon2id13","ops":1,"memBytes":8388608},"newWrappedUvk":"AAAA","newMemberRecovery":{"recoveryWrappedUvk":"AAAA","recoveryAuthKey":"${b32()}"},"device":{"platform":"$platform","name":"x","deviceSecret":"${b32()}"}}"""

    /**
     * The kind of the device row decides the session an assisted recovery's commit makes (decided on 2026-11-17): a commit
     * that makes a browser's row gets a web session, whatever the request's header says (`linux`, the tests' default).
     * Before, the session was marked by the header, so a browser's row held a session that was not a web one.
     */
    @Test
    fun anAssistedCommitOnABrowsersRow_makesAWebSession() = app { f ->
        val (reqId, poll) = openVerified(f)
        f.clock.advance(Assisted.HOLD_MS)
        assertEquals(200, fulfil(f, reqId))
        val r = f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/commit", commitBody(poll, platform = "web"))
        assertEquals(200, r.status.value, r.bodyAsText())
        val session = WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.SessionResponse.serializer(), r.bodyAsText())
        val (row, mark) = f.s.db.read { c ->
            c.queryOne(
                "SELECT d.platform, s.clientPlatform FROM sessions s JOIN devices d ON d.deviceId=s.deviceId WHERE s.accessHash=?",
                ServerCrypto.hashToken(session.accessToken),
            ) { it.getString(1) to it.getString(2) }!!
        }
        assertEquals("web" to "web", row to mark)
    }

    private fun app(block: suspend (Fixture) -> Unit) = testApplication {
        val clock = MutableClock()
        val key = TestKit.Identity().curvePub
        val s = TestKit.services(TestKit.config(recoveryKey = key), clock)
        application { andvariModule(s) }
        block(fixture(client, s, clock, key))
    }

    @Test
    fun fulfilled_request_staysListed_counted_andVetoable_andTheVetoDiscardsTheAnswer() = app { f ->
        val (reqId, poll) = openVerified(f)
        assertEquals(listOf("holding"), list(f, f.me.token).map { it.state })
        f.clock.advance(Assisted.HOLD_MS)
        val tok = fresh(f.s, f.me)
        assertEquals(listOf("awaiting_operator"), list(f, tok).map { it.state })
        assertEquals(200, fulfil(f, reqId))
        // Still visible, as `ready`, and /sync agrees with the list.
        assertEquals(listOf(reqId to "ready"), list(f, tok).map { it.requestId to it.state })
        assertEquals(1, syncCount(f, tok))
        assertEquals("ready", pollState(f, reqId, poll))
        // The account's device can still stop it: the sealed answer is gone and the commit refused.
        assertEquals(200, f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/veto", veto(f.me, reqId), tok).status.value)
        assertEquals("vetoed", pollState(f, reqId, poll))
        assertEquals(null, f.s.db.read { c -> c.queryOne("SELECT sealed FROM recovery_requests WHERE requestId=?", reqId) { it.getString(1) } })
        assertEquals(emptyList(), list(f, tok))
        assertEquals(0, syncCount(f, tok))
        assertEquals("request_state", f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/commit", commitBody(poll)).errorCode())
        // A second veto finds nothing to stop.
        assertEquals("request_unknown", f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/veto", veto(f.me, reqId), tok).errorCode())
    }

    /**
     * The mails about a recovery request carry no account ID, against the real outbox:
     * the request's code, its opened, cancelled and private-posture notices, and the reset it ends in. Every other mail
     * keeps it (here the password change and a kit recovery's reset). Before, every one of them carried it.
     */
    @Test
    fun theMailsAboutARecoveryRequest_carryNoAccountId_andEveryOtherMailKeepsIt() = app { f ->
        val id = Mail.accountId(f.me.identity.identityPubB64)
        val other = Flow.member(f.c, f.s, "private@example.com")
        val otherId = Mail.accountId(other.identity.identityPubB64)
        Flow.sink(f.s)
        val seen = HashMap<String, MutableList<String>>()
        fun take() { for ((t, _, text) in Flow.sink(f.s)) seen.getOrPut(t) { ArrayList() } += text; File(f.s.config.mailSinkDir!!).listFiles()?.forEach { it.delete() } }
        // The code and the opened notice; then a veto, and its notice.
        val (vetoed, _) = openVerified(f)
        assertEquals(200, f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$vetoed/veto", veto(f.me, vetoed), f.me.token).status.value)
        // A request for a private-posture account: its notice.
        val body = """{"email":"${other.email}","rPub":"${b32()}","pollHash":"${sha256Hex(TestKit.crypto.randomBytes(32))}","platform":"android"}"""
        assertEquals(202, f.c.call(HttpMethod.Post, "/api/v1/recovery/requests", body).status.value)
        // A request answered and committed: the reset "with the operator's help".
        val (reqId, poll) = openVerified(f)
        f.clock.advance(Assisted.HOLD_MS)
        assertEquals(200, fulfil(f, reqId))
        assertEquals(200, f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/commit", commitBody(poll)).status.value)
        take()
        for (t in listOf("recovery_request_code", "recovery_request_open", "recovery_request_cancelled", "recovery_request_private", "recovery_applied")) {
            val texts = seen[t].orEmpty()
            assertTrue(texts.isNotEmpty(), "$t was sent: ${seen.keys}")
            for (text in texts) {
                assertFalse("account ID" in text || id in text || otherId in text, "$t names no account ID:\n$text")
            }
        }
        assertTrue(seen.getValue("recovery_applied").all { "with the operator's help" in it })
        // Every other mail keeps it: a password change, and a kit recovery's reset.
        val newKey = b32()
        val pw = """{"currentAuthKey":"${other.authKey}","newAuthKey":"$newKey","newKdfSalt":"${Bytes.toB64(ByteArray(16) { 5 })}","newKdfParams":{"v":1,"alg":"argon2id13","ops":1,"memBytes":8388608},"newWrappedUvk":"AAAA"}"""
        assertEquals(200, f.c.call(HttpMethod.Put, "/api/v1/account/password", pw, fresh(f.s, other)).status.value)
        val v = WireJson.json.decodeFromString(
            RecoveryVerifyResponse.serializer(),
            f.c.call(HttpMethod.Post, "/api/v1/recovery/self/verify", """{"email":"${other.email}","recoveryAuthKey":"${other.recoveryAuthKey}"}""").bodyAsText(),
        )
        val tail = """"newKdfSalt":"${Bytes.toB64(ByteArray(16) { 5 })}","newKdfParams":{"v":1,"alg":"argon2id13","ops":1,"memBytes":8388608},"newWrappedUvk":"AAAA","newMemberRecovery":{"recoveryWrappedUvk":"AAAA","recoveryAuthKey":"${b32()}"},"device":{"platform":"ios","name":"x","deviceSecret":"${b32()}"}"""
        val kc = f.c.call(HttpMethod.Post, "/api/v1/recovery/self/commit", """{"recoveryTicket":"${v.recoveryTicket}","newAuthKey":"${b32()}",$tail}""")
        assertEquals(200, kc.status.value, kc.bodyAsText())
        seen.clear(); take()
        assertTrue(seen.getValue("password_changed").all { "Your account ID: $otherId" in it }, seen.toString())
        assertTrue(seen.getValue("recovery_applied").all { "Your account ID: $otherId" in it && "with the operator's help" !in it }, seen.toString())
    }

    /**
     * Every mail the server sends because of an operator-assisted recovery carries no account ID, against the real
     * outbox: besides the request's own mails, the notices about what the assisted reset changed (`two_step_off`,
     * `require_link_cleared`) and the operator's download of the recovery copy (`operator_escrow_read`, which reaches the
     * person in the middle of that flow). The same two settings notices after a kit recovery keep it. Before, all three
     * carried it.
     */
    @Test
    fun theNoticesOfAnAssistedReset_andTheCopysDownload_carryNoAccountId() = app { f ->
        val id = Mail.accountId(f.me.identity.identityPubB64)
        val other = Flow.member(f.c, f.s, "private@example.com")
        val otherId = Mail.accountId(other.identity.identityPubB64)
        for (u in listOf(f.me, other)) f.s.db.tx { it.exec("UPDATE users SET requireLink=1, totpSecret='JBSWY3DPEHPK3PXP' WHERE userId=?", u.userId) }
        Flow.sink(f.s)
        val seen = HashMap<String, MutableList<String>>()
        fun take() { for ((t, _, text) in Flow.sink(f.s)) seen.getOrPut(t) { ArrayList() } += text; File(f.s.config.mailSinkDir!!).listFiles()?.forEach { it.delete() } }
        val (reqId, poll) = openVerified(f)
        f.clock.advance(Assisted.HOLD_MS)
        // The operator downloads the copy to answer the request.
        val read = f.c.call(HttpMethod.Post, "/api/v1/admin/accounts/${f.me.userId}/escrow", """{"currentAuthKey":"${f.op.authKey}"}""", fresh(f.s, f.op))
        assertEquals(200, read.status.value, read.bodyAsText())
        assertEquals(200, fulfil(f, reqId))
        assertEquals(200, f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/commit", commitBody(poll)).status.value)
        take()
        for (t in listOf("operator_escrow_read", "recovery_applied", "two_step_off", "require_link_cleared")) {
            val texts = seen[t].orEmpty()
            assertTrue(texts.isNotEmpty(), "$t was sent: ${seen.keys}")
            for (text in texts) assertFalse("account ID" in text || id in text, "$t names no account ID:\n$text")
        }
        // The same two notices after a kit recovery keep it.
        val v = WireJson.json.decodeFromString(
            RecoveryVerifyResponse.serializer(),
            f.c.call(HttpMethod.Post, "/api/v1/recovery/self/verify", """{"email":"${other.email}","recoveryAuthKey":"${other.recoveryAuthKey}"}""").bodyAsText(),
        )
        val tail = """"newKdfSalt":"${Bytes.toB64(ByteArray(16) { 5 })}","newKdfParams":{"v":1,"alg":"argon2id13","ops":1,"memBytes":8388608},"newWrappedUvk":"AAAA","newMemberRecovery":{"recoveryWrappedUvk":"AAAA","recoveryAuthKey":"${b32()}"},"device":{"platform":"ios","name":"x","deviceSecret":"${b32()}"}"""
        val kc = f.c.call(HttpMethod.Post, "/api/v1/recovery/self/commit", """{"recoveryTicket":"${v.recoveryTicket}","newAuthKey":"${b32()}",$tail}""")
        assertEquals(200, kc.status.value, kc.bodyAsText())
        seen.clear(); take()
        for (t in listOf("recovery_applied", "two_step_off", "require_link_cleared")) {
            assertTrue(seen[t].orEmpty().isNotEmpty() && seen.getValue(t).all { "Your account ID: $otherId" in it }, "$t keeps the account ID: $seen")
        }
    }

    /** Spec 03 §18.5: the assisted commit refuses a disabled account exactly as the kit commit does. */
    @Test
    fun assistedCommit_refusesADisabledAccount() = app { f ->
        val (reqId, poll) = openVerified(f)
        f.clock.advance(Assisted.HOLD_MS)
        assertEquals(200, fulfil(f, reqId))
        f.s.db.tx { it.exec("UPDATE users SET status='disabled', disabledAt=1 WHERE userId=?", f.me.userId) }
        val r = f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/commit", commitBody(poll))
        assertEquals(400, r.status.value, r.bodyAsText()); assertEquals("recovery_account_not_active", r.errorCode())
        // Nothing changed: the request is still ready, and once re-enabled the commit goes through.
        assertEquals("ready", pollState(f, reqId, poll))
        f.s.db.tx { it.exec("UPDATE users SET status='active', disabledAt=NULL WHERE userId=?", f.me.userId) }
        assertEquals(200, f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/commit", commitBody(poll)).status.value)
    }

    @Test
    fun fulfilled_request_pastItsLifetime_isRefusedAtCommit_beforeTheJanitorRuns() = app { f ->
        val (reqId, poll) = openVerified(f)
        f.clock.advance(Assisted.HOLD_MS)
        assertEquals(200, fulfil(f, reqId))
        // 30 days after the hold ended the request is dead, whether or not the janitor has swept it.
        f.clock.advance(Assisted.AFTER_HOLD_TTL_MS)
        val tok = fresh(f.s, f.me)
        assertEquals("expired", pollState(f, reqId, poll))
        assertEquals(emptyList(), list(f, tok))
        assertEquals(0, syncCount(f, tok))
        assertEquals("request_state", f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/commit", commitBody(poll)).errorCode())
        // One millisecond earlier it would still have committed.
        f.clock.advance(-1)
        val ok = f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/commit", commitBody(poll))
        assertEquals(200, ok.status.value, ok.bodyAsText())
    }

    @Test
    fun veto_isCheckedByCoresVerifier_inTheCorrectedOrder() = app { f ->
        val (reqId, poll) = openVerified(f)
        val crypto = TestKit.crypto
        fun post(frame: ByteArray) = Bytes.toB64(frame).let { b -> suspend { f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/veto", """{"statement":"$b"}""", f.me.token).errorCode() } }
        val good = io.silencelen.andvari.core.trust.VetoFields(reqId, f.me.userId, 1_800_000_000_000)
        val signed = io.silencelen.andvari.core.trust.RecoveryVeto.sign(crypto, f.me.identity.sign, good)
        assertEquals("bad_frame", post(byteArrayOf(1, 2, 3))())
        // Signer first: another key is bad_signer even when the fields are right.
        assertEquals("bad_signer", post(io.silencelen.andvari.core.trust.RecoveryVeto.sign(crypto, TestKit.Identity().sign, good))())
        // Then the signature: a flipped signature byte under the account's own key.
        assertEquals("bad_signature", post(signed.copyOf().also { it[40] = (it[40].toInt() xor 1).toByte() })())
        // Then the fields: the account's key over another user or another request is bad_signer.
        assertEquals("bad_signer", post(io.silencelen.andvari.core.trust.RecoveryVeto.sign(crypto, f.me.identity.sign, good.copy(userId = uuid())))())
        assertEquals("bad_signer", post(io.silencelen.andvari.core.trust.RecoveryVeto.sign(crypto, f.me.identity.sign, good.copy(requestId = Bytes.toB64(crypto.randomBytes(16)))))())
        assertEquals("holding", pollState(f, reqId, poll))
        assertEquals(null, post(signed)())
        assertEquals("vetoed", pollState(f, reqId, poll))
    }

    @Test
    fun passwordChange_cancelsPendingRequests() = app { f ->
        val (reqId, poll) = openVerified(f)
        val body = """{"currentAuthKey":"${f.me.authKey}","newAuthKey":"${b32()}","newKdfSalt":"${Bytes.toB64(ByteArray(16) { 5 })}","newKdfParams":{"v":1,"alg":"argon2id13","ops":1,"memBytes":8388608},"newWrappedUvk":"AAAA"}"""
        assertEquals(200, f.c.call(HttpMethod.Put, "/api/v1/account/password", body, f.me.token).status.value)
        assertEquals("vetoed", pollState(f, reqId, poll))
        assertEquals(emptyList(), list(f, f.me.token))
        f.clock.advance(Assisted.HOLD_MS)
        assertEquals(409, fulfil(f, reqId))
    }

    @Test
    fun postureToPrivate_cancelsPendingRequests_evenAFulfilledOne() = app { f ->
        val (reqId, poll) = openVerified(f)
        f.clock.advance(Assisted.HOLD_MS)
        assertEquals(200, fulfil(f, reqId))
        val tok = fresh(f.s, f.me)
        val body = """{"posture":"private","currentAuthKey":"${f.me.authKey}","accountState":{"sealedState":"AAAA","baseSeq":0}}"""
        val r = f.c.call(HttpMethod.Put, "/api/v1/account/recovery", body, tok)
        assertEquals(200, r.status.value, r.bodyAsText())
        assertEquals("vetoed", pollState(f, reqId, poll))
        assertEquals("request_state", f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/commit", commitBody(poll)).errorCode())
    }

    /** A recovery completed with the operator's help forgets every mailbox value of the address, and no other address's. */
    @Test
    fun assistedCommit_forgetsTheAddresssMailboxValues_andNoOtherAddresss() = app { f ->
        fun valuesOf(email: String) = f.s.db.read { c -> c.count("SELECT COUNT(*) FROM recovery_mailbox_values WHERE emailHash=?", f.s.config.addressHash(email)) }
        val elsewhere = f.s.config.addressHash("other@example.com")
        f.s.db.tx { c -> c.exec("INSERT INTO recovery_mailbox_values(valueHash,emailHash,expiresAt) VALUES(?,?,?)", Assisted.mailboxHash(f.s, elsewhere, "ABCDEFGHJKLMNPQR"), elsewhere, f.clock.now() + Assisted.MAILBOX_TTL_MS) }
        val (reqId, poll) = openVerified(f)
        assertEquals(1L, valuesOf(f.me.email))
        f.clock.advance(Assisted.HOLD_MS)
        assertEquals(200, fulfil(f, reqId))
        val r = f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/commit", commitBody(poll))
        assertEquals(200, r.status.value, r.bodyAsText())
        assertEquals(0L, valuesOf(f.me.email))
        assertEquals(1L, valuesOf("other@example.com"))
    }

    @Test
    fun kitCommit_cancelsPendingRequests_includingUnverifiedOnes() = app { f ->
        val (reqId, poll) = openVerified(f)
        // A second, still unverified request.
        val poll2 = TestKit.crypto.randomBytes(32)
        val req2 = WireJson.json.decodeFromString(
            RecoveryRequestCreated.serializer(),
            f.c.call(HttpMethod.Post, "/api/v1/recovery/requests", """{"email":"${f.me.email}","rPub":"${b32()}","pollHash":"${sha256Hex(poll2)}","platform":"ios"}""").bodyAsText(),
        ).requestId
        val code2 = Flow.codeIn(Flow.sink(f.s).last { it.first == "recovery_request_code" }.third)
        val v = WireJson.json.decodeFromString(
            RecoveryVerifyResponse.serializer(),
            f.c.call(HttpMethod.Post, "/api/v1/recovery/self/verify", """{"email":"${f.me.email}","recoveryAuthKey":"${f.me.recoveryAuthKey}"}""").bodyAsText(),
        )
        val commit = commitBody("x").replace(""""pollSecret":"x",""", """"recoveryTicket":"${v.recoveryTicket}",""")
        assertEquals(200, f.c.call(HttpMethod.Post, "/api/v1/recovery/self/commit", commit).status.value)
        assertEquals("vetoed", pollState(f, reqId, poll))
        // The unverified one is cancelled too, but its poll answers as before the recovery (since 2026-11-17): the cancel
        // is told at the code step, the right code answered request_state; then its poll says vetoed.
        assertEquals("unverified", pollState(f, req2, Bytes.toB64(poll2)))
        assertEquals("request_state", f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$req2/verify", """{"code":"$code2"}""").errorCode())
        assertEquals("vetoed", pollState(f, req2, Bytes.toB64(poll2)))
        assertEquals("bad_code", f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$req2/verify", """{"code":"$code2"}""").errorCode())
    }

    /**
     * Spec 04 §6 / §7 step 5 and spec 03 §12, §18.5, §16.8: after a recovery commit every earlier device is unknown,
     * so once requireLink is on again a correct password from one of them is `403 link_required`, while the
     * recovered device itself is known.
     */
    private suspend fun earlierDevicesAreNewAfter(f: Fixture, commit: suspend (newKey: String, secret: String) -> io.silencelen.andvari.core.model.wire.SessionResponse) {
        // Before: the registered device is known, so requireLink lets it in.
        f.s.db.tx { it.exec("UPDATE users SET requireLink=1 WHERE userId=?", f.me.userId) }
        assertEquals(200, f.c.call(HttpMethod.Post, "/api/v1/auth/login", f.me.loginBody(deviceId = f.me.deviceId)).status.value)
        val newKey = b32(); val secret = b32()
        val sess = commit(newKey, secret)
        assertEquals(200, f.c.call(HttpMethod.Put, "/api/v1/account/require-link", """{"enabled":true,"currentAuthKey":"$newKey"}""", sess.accessToken).status.value)
        val old = f.c.call(HttpMethod.Post, "/api/v1/auth/login", f.me.loginBody(deviceId = f.me.deviceId, authKey = newKey))
        assertEquals(403, old.status.value, old.bodyAsText()); assertEquals("link_required", old.errorCode())
        assertEquals(200, f.c.call(HttpMethod.Post, "/api/v1/auth/login", f.me.loginBody(deviceId = sess.deviceId, secret = secret, authKey = newKey)).status.value)
    }

    private fun recoveryBody(newKey: String, secret: String) =
        """"newAuthKey":"$newKey","newKdfSalt":"${Bytes.toB64(ByteArray(16) { 5 })}","newKdfParams":{"v":1,"alg":"argon2id13","ops":1,"memBytes":8388608},"newWrappedUvk":"AAAA","newMemberRecovery":{"recoveryWrappedUvk":"AAAA","recoveryAuthKey":"${b32()}"},"device":{"platform":"ios","name":"x","deviceSecret":"$secret"}"""

    @Test
    fun kitCommit_makesEveryEarlierDeviceNew_linkRequiredAfterACorrectPassword() = app { f ->
        earlierDevicesAreNewAfter(f) { newKey, secret ->
            val v = WireJson.json.decodeFromString(RecoveryVerifyResponse.serializer(), f.c.call(HttpMethod.Post, "/api/v1/recovery/self/verify", """{"email":"${f.me.email}","recoveryAuthKey":"${f.me.recoveryAuthKey}"}""").bodyAsText())
            val r = f.c.call(HttpMethod.Post, "/api/v1/recovery/self/commit", """{"recoveryTicket":"${v.recoveryTicket}",${recoveryBody(newKey, secret)}}""")
            assertEquals(200, r.status.value, r.bodyAsText())
            WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.SessionResponse.serializer(), r.bodyAsText())
        }
    }

    @Test
    fun assistedCommit_makesEveryEarlierDeviceNew_linkRequiredAfterACorrectPassword() = app { f ->
        val (reqId, poll) = openVerified(f)
        f.clock.advance(Assisted.HOLD_MS)
        assertEquals(200, fulfil(f, reqId))
        earlierDevicesAreNewAfter(f) { newKey, secret ->
            val r = f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/commit", """{"pollSecret":"$poll",${commitField(poll)}${recoveryBody(newKey, secret)}}""")
            assertEquals(200, r.status.value, r.bodyAsText())
            WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.SessionResponse.serializer(), r.bodyAsText())
        }
    }

    // ---- the upload names its request, and only a device that opened the answer commits ----

    private fun audits(f: Fixture, type: String): List<String?> =
        f.s.db.read { c -> c.queryAll("SELECT meta FROM audit WHERE type=? ORDER BY id", type) { it.getString(1) } }

    private fun stored(f: Fixture, reqId: String): Pair<String?, String?> =
        f.s.db.read { c -> c.queryOne("SELECT sealed,commitHash FROM recovery_requests WHERE requestId=?", reqId) { it.getString(1) to it.getString(2) } } ?: (null to null)

    @Test
    fun theUploadIsRefusedForAnotherRequestsKey_aWrongSize_orAMissingPart_andStoresNothing() = app { f ->
        val (reqId, _) = openVerified(f)
        f.clock.advance(Assisted.HOLD_MS)
        val right = Bytes.toB64(TestKit.crypto.randomBytes(answerSize(f)))
        val hash = commitHash(TestKit.crypto.randomBytes(32))
        // The shape first (before anything stored is read), then the row's key, then the one size for the account's address.
        assertEquals("bad_request_key", upload(f, reqId, fulfilBody(f, right, null, hash), true).errorCode())
        assertEquals("bad_commit_hash", upload(f, reqId, fulfilBody(f, right, rPubs.getValue(reqId), null), true).errorCode())
        assertEquals("bad_commit_hash", upload(f, reqId, fulfilBody(f, right, rPubs.getValue(reqId), "ab".repeat(31)), true).errorCode())
        assertEquals("request_key_mismatch", upload(f, reqId, fulfilBody(f, right, b32(), hash), true).errorCode())
        for (n in listOf(answerSize(f) - 1, answerSize(f) + 1, 459)) {
            assertEquals("bad_sealed", upload(f, reqId, fulfilBody(f, Bytes.toB64(TestKit.crypto.randomBytes(n)), rPubs.getValue(reqId), hash), true).errorCode(), "$n bytes")
        }
        // A part that is not a string is that part's refusal, and the parts are checked in the listed order.
        assertEquals("bad_sealed", upload(f, reqId, fulfilBody(f, right, rPubs.getValue(reqId), hash).replace("\"$right\"", "null"), true).errorCode())
        assertEquals("bad_request_key", upload(f, reqId, fulfilBody(f, right, rPubs.getValue(reqId), hash).replace("\"${rPubs.getValue(reqId)}\"", "5"), true).errorCode())
        assertEquals("bad_sealed", upload(f, reqId, fulfilBody(f, Bytes.toB64(TestKit.crypto.randomBytes(2000)), null, null), true).errorCode())
        assertEquals(null to null, stored(f, reqId))
        assertEquals(emptyList(), audits(f, "operator_recovery_fulfil"))
        // A wrong proof is refused before any of it.
        val wrong = fulfilBody(f, right, b32(), hash).replace(f.op.authKey, b32())
        assertEquals("reauth_failed", upload(f, reqId, wrong, true).errorCode())
        assertEquals(200, upload(f, reqId, fulfilBody(f, right, rPubs.getValue(reqId), hash), true).status.value)
        assertEquals(right to hash, stored(f, reqId))
    }

    @Test
    fun anUploadCanBeRepeatedUntilTheCommit_eachAudited_andOnlyTheNewestAnswersValueCommits() = app { f ->
        val (reqId, poll) = openVerified(f)
        f.clock.advance(Assisted.HOLD_MS)
        assertEquals(200, fulfil(f, reqId))
        val first = commits.getValue(poll)
        assertEquals(200, fulfil(f, reqId))
        val second = commits.getValue(poll)
        assertEquals(listOf("target=${f.me.userId}", "target=${f.me.userId};replaced=1"), audits(f, "operator_recovery_fulfil"))
        // The ready request is still on the operator's list, with its state.
        val listed = f.c.call(HttpMethod.Get, "/api/v1/admin/recovery-requests", token = fresh(f.s, f.op)).bodyAsText()
        assertTrue(""""requestId":"$reqId"""" in listed && """"state":"ready"""" in listed, listed)
        // The older answer's value is refused and audited; the newer one commits.
        assertEquals("commit_mismatch", f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/commit", commitBody(poll, """"commit":"${Bytes.toB64(first)}",""")).errorCode())
        assertEquals(listOf("at=check"), audits(f, "recovery_request_commit_mismatch"))
        val ok = f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/commit", commitBody(poll, """"commit":"${Bytes.toB64(second)}","""))
        assertEquals(200, ok.status.value, ok.bodyAsText())
        // After the commit there is nothing left to upload to.
        assertEquals(404, fulfil(f, reqId))
    }

    /**
     * A wrong commit value never cancels a request. Each is audited and the route keeps
     * its per-IP rate limit; nothing else happens, so any number of wrong values leaves the right one able to commit.
     * Before, the fifth wrong value cancelled the request.
     */
    @Test
    fun aCommitWithoutTheValue_orWithAWrongOne_isRefused_andNoNumberOfWrongValuesCancelsTheRequest() = app { f ->
        val (reqId, poll) = openVerified(f)
        f.clock.advance(Assisted.HOLD_MS)
        assertEquals(200, fulfil(f, reqId))
        val answer = stored(f, reqId)
        val r = f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/commit", commitBody(poll, ""))
        assertEquals(400, r.status.value); assertEquals("bad_commit", r.errorCode())
        assertEquals("bad_commit", f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/commit", commitBody(poll, """"commit":"AAAA",""")).errorCode())
        // Null, or a value that is not a string, is bad_commit too (the per-IP bucket: time moves on first).
        f.clock.advance(61_000)
        assertEquals("bad_commit", f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/commit", commitBody(poll, """"commit":null,""")).errorCode())
        assertEquals("bad_commit", f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/commit", commitBody(poll, """"commit":5,""")).errorCode())
        f.clock.advance(61_000)
        val wrong = 12
        for (i in 1..wrong) {
            val bad = f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/commit", commitBody(poll, """"commit":"${b32()}","""))
            assertEquals(403, bad.status.value, "attempt $i"); assertEquals("commit_mismatch", bad.errorCode())
            assertEquals("ready", pollState(f, reqId, poll), "after attempt $i")
            if (i % 5 == 0) f.clock.advance(61_000) // the per-IP commit bucket is 5 a minute, and it still holds:
        }
        // ... the sixth call inside one minute is that bucket's refusal, not the request's.
        f.clock.advance(61_000)
        val burst = (1..6).map {
            f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/commit", commitBody(poll, """"commit":"${b32()}","""), ip = "10.9.9.9")
                .let { r -> "${r.status.value}:${r.errorCode()}" }
        }
        assertEquals(List(5) { "403:commit_mismatch" } + "429:rate_limited", burst)
        f.clock.advance(61_000)
        // Every wrong value has its own audit row, and the request and its stored answer are as they were.
        assertEquals(List(wrong + 5) { "at=check" }, audits(f, "recovery_request_commit_mismatch"))
        assertEquals(answer, stored(f, reqId))
        assertEquals("ready", pollState(f, reqId, poll))
        val ok = f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/commit", commitBody(poll))
        assertEquals(200, ok.status.value, ok.bodyAsText())
    }

    /**
     * The comparison inside the commit's transaction (an upload replaced the answer between the first check and the
     * transaction): refused `commit_mismatch` and audited like any other wrong value
     * (spec 03 §18.5), with the request kept, so the newer answer's value then commits. Before, it was
     * refused without an audit row.
     */
    @Test
    fun aMismatchFoundInsideTheCommitsTransaction_isAuditedToo_andKeepsTheRequest() = app { f ->
        val (reqId, poll) = openVerified(f)
        f.clock.advance(Assisted.HOLD_MS)
        assertEquals(200, fulfil(f, reqId))
        val newer = TestKit.crypto.randomBytes(32)
        f.s.raceHook = { p ->
            if (p == "assistedCommit.afterCheck") f.s.db.tx { it.exec("UPDATE recovery_requests SET commitHash=? WHERE requestId=?", commitHash(newer), reqId) }
        }
        val raced = f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/commit", commitBody(poll))
        f.s.raceHook = null
        assertEquals(403, raced.status.value, raced.bodyAsText()); assertEquals("commit_mismatch", raced.errorCode())
        assertEquals(listOf("at=commit"), audits(f, "recovery_request_commit_mismatch"))
        assertEquals("ready", pollState(f, reqId, poll))
        assertEquals(0, f.s.db.read { c -> c.queryOne("SELECT COUNT(*) FROM audit WHERE type='recovery_request_commit'") { it.getInt(1) } })
        val ok = f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/commit", commitBody(poll, """"commit":"${Bytes.toB64(newer)}","""))
        assertEquals(200, ok.status.value, ok.bodyAsText())
    }

    /**
     * The poll's `ready` answer carries the stored commit hash (additive), so a device can tell
     * before it asks its person for anything that the answer on the server is not the one it opened. It follows a
     * re-upload, is absent before the answer, and a caller without the poll secret gets the uniform 404 and no hash.
     */
    @Test
    fun theReadyPoll_carriesTheStoredCommitHash_andOnlyPastThePollSecret() = app { f ->
        val (reqId, poll) = openVerified(f)
        fun pollBody(secret: String) = """{"pollSecret":"$secret"}"""
        suspend fun pollText(secret: String) = f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/poll", pollBody(secret)).bodyAsText()
        assertTrue("commitHash" !in pollText(poll), "holding")
        f.clock.advance(Assisted.HOLD_MS)
        assertTrue("commitHash" !in pollText(poll), "awaiting_operator")
        assertEquals(200, fulfil(f, reqId))
        val first = WireJson.json.parseToJsonElement(pollText(poll)).jsonObject
        assertEquals("ready", first["state"]!!.jsonPrimitive.content)
        assertEquals(commitHash(commits.getValue(poll)), first["commitHash"]!!.jsonPrimitive.content)
        assertEquals(stored(f, reqId).second, first["commitHash"]!!.jsonPrimitive.content)
        // The other fields are unchanged: the core type still reads the answer.
        val typed = WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.RecoveryPollResponse.serializer(), pollText(poll))
        assertEquals(stored(f, reqId).first, typed.sealed)
        // A re-upload: the poll names the newer answer's hash.
        f.clock.advance(13_000)
        assertEquals(200, fulfil(f, reqId))
        assertEquals(commitHash(commits.getValue(poll)), WireJson.json.parseToJsonElement(pollText(poll)).jsonObject["commitHash"]!!.jsonPrimitive.content)
        // Without the poll secret: the uniform 404, and no hash.
        for (secret in listOf(b32(), "AAAA", "")) {
            val r = f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/poll", pollBody(secret))
            assertEquals(404, r.status.value, secret); assertEquals("request_unknown", r.errorCode())
            assertTrue("commitHash" !in r.bodyAsText() && stored(f, reqId).second!! !in r.bodyAsText())
        }
    }

    /**
     * An attacker's path that once worked, as a test that now fails for the attacker: the
     * email-holder opens a request of their own for the same address; the operator makes the right answer for the
     * person's request and gives it to the other row. The upload is refused; forced past that with a hand-made body,
     * the other row's holder cannot commit, cannot use up the person's attempts, and the person's request is still
     * answerable and commits.
     */
    @Test
    fun theRightAnswerUploadedToTheWrongRow_isRefused_andForcedThere_cannotBeCommittedByThatRowsHolder() = app { f ->
        val (person, personPoll) = openVerified(f)
        val (attacker, attackerPoll) = openVerified(f)
        f.clock.advance(Assisted.HOLD_MS)
        val commit = TestKit.crypto.randomBytes(32)
        val answer = Bytes.toB64(TestKit.crypto.randomBytes(answerSize(f)))
        val forPerson = fulfilBody(f, answer, rPubs.getValue(person), commitHash(commit))
        // The token's request key is the person's: the attacker's row refuses it, and stores nothing.
        assertEquals("request_key_mismatch", upload(f, attacker, forPerson).errorCode())
        assertEquals(null to null, stored(f, attacker))
        // Forced: a hand-made body naming the attacker's key, with the person's answer and commit hash.
        assertEquals(200, upload(f, attacker, fulfilBody(f, answer, rPubs.getValue(attacker), commitHash(commit))).status.value)
        // The attacker never opened the answer (it is sealed to the person's key), so has no value to present.
        assertEquals("bad_commit", f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$attacker/commit", commitBody(attackerPoll, "")).errorCode())
        assertEquals("commit_mismatch", f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$attacker/commit", commitBody(attackerPoll, """"commit":"${b32()}",""")).errorCode())
        // The attacker's poll secret cannot spend the person's request: it is not that request's.
        assertEquals("request_unknown", f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$person/commit", commitBody(attackerPoll, """"commit":"${b32()}",""")).errorCode())
        assertEquals(listOf("at=check"), audits(f, "recovery_request_commit_mismatch"))
        // The account is untouched, and the person's request is still answerable: uploaded and committed.
        assertEquals("awaiting_operator", pollState(f, person, personPoll))
        assertEquals(200, upload(f, person, forPerson).status.value)
        val ok = f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$person/commit", commitBody(personPoll, """"commit":"${Bytes.toB64(commit)}","""))
        assertEquals(200, ok.status.value, ok.bodyAsText())
        // The commit cancelled the other request, as every recovery commit does.
        assertEquals("vetoed", pollState(f, attacker, attackerPoll))
    }

    @Test
    fun assistedCommit_clearsEveryEarlierDeviceSecret_andDeletesTheRequest() = app { f ->
        val (reqId, poll) = openVerified(f)
        f.clock.advance(Assisted.HOLD_MS)
        assertEquals(200, fulfil(f, reqId))
        val r = f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/commit", commitBody(poll))
        assertEquals(200, r.status.value, r.bodyAsText())
        f.s.db.read { c ->
            assertEquals(0L, c.count("SELECT COUNT(*) FROM recovery_requests WHERE requestId=?", reqId))
            assertEquals(0L, c.count("SELECT COUNT(*) FROM devices WHERE userId=? AND how<>'recovered' AND deviceSecretHash IS NOT NULL", f.me.userId))
        }
        assertTrue(Flow.sink(f.s).any { it.first == "recovery_applied" && it.third.contains("operator") })
    }
}
