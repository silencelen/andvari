package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.AccountDeletePreview
import io.silencelen.andvari.core.model.wire.AccountKeys
import io.silencelen.andvari.core.model.wire.EscrowUpload
import io.silencelen.andvari.core.model.wire.TotpSetupResponse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.trust.LogEntry
import io.silencelen.andvari.core.trust.MemberRole
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Index rows 17–31 (spec 03 §3, §3.1, §13, §16.7): the gaps the other test files leave. */
class RoutesAccountTest {
    private val post = HttpMethod.Post
    private val get = HttpMethod.Get
    private val put = HttpMethod.Put

    private fun kdf(ops: Int = 1, mem: Long = 8_388_608) = """{"v":1,"alg":"argon2id13","ops":$ops,"memBytes":$mem}"""
    private val salt16 = Bytes.toB64(ByteArray(16) { 5 })

    @Test
    fun row17_keys_carryTheGenesisAndThePersonalWrap() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val r = c.call(get, "/api/v1/account/keys", token = me.token)
        assertEquals(200, r.status.value)
        val k = WireJson.json.decodeFromString(AccountKeys.serializer(), r.bodyAsText())
        assertEquals(me.identity.identityPubB64, k.identityPub)
        assertEquals(me.personalVaultId, k.personalWrap!!.vaultId)
        assertEquals(me.genesis(s.db.read { s.instance.instanceId(it) }), k.genesis)
        assertEquals(false, k.recoveryConfirmed)
    }

    @Test
    fun rows18and19_accountState_casAndTheBlobCap() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val t = me.token
        assertTrue(c.call(get, "/api/v1/account/state", token = t).bodyAsText().let { "\"seq\":0" in it && "\"sealedState\":null" in it })
        val p1 = c.call(put, "/api/v1/account/state", """{"sealedState":"QUFB","baseSeq":0}""", t)
        assertEquals(200, p1.status.value); assertTrue("\"seq\":1" in p1.bodyAsText())
        assertTrue(c.call(get, "/api/v1/account/state", token = t).bodyAsText().let { "\"sealedState\":\"QUFB\"" in it && "\"seq\":1" in it })
        assertEquals("stale_state", c.call(put, "/api/v1/account/state", """{"sealedState":"QkJC","baseSeq":0}""", t).errorCode())
        // bad_account_state: empty, and one character over 1 MiB (the body cap leaves room for it).
        val empty = c.call(put, "/api/v1/account/state", """{"sealedState":"","baseSeq":1}""", t)
        assertEquals(400, empty.status.value); assertEquals("bad_account_state", empty.errorCode())
        val big = c.call(put, "/api/v1/account/state", """{"sealedState":"${"A".repeat(Items.ACCOUNT_STATE_SEALED_MAX + 1)}","baseSeq":1}""", t)
        assertEquals(400, big.status.value, big.bodyAsText()); assertEquals("bad_account_state", big.errorCode())
        assertEquals(200, c.call(put, "/api/v1/account/state", """{"sealedState":"${"A".repeat(Items.ACCOUNT_STATE_SEALED_MAX)}","baseSeq":1}""", t).status.value)
    }

    @Test
    fun row21_passwordChange_kdfChecks_andACredentialChangedInBetween() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val body = { params: String, salt: String -> """{"currentAuthKey":"${me.authKey}","newAuthKey":"${b32()}","newKdfSalt":"$salt","newKdfParams":$params,"newWrappedUvk":"AAAA"}""" }
        // password_change is 5 a minute; this walk is longer, and the bucket has its own test (RateBucketsTest).
        suspend fun pw(b: String) = s.limiter.clear().let { c.call(put, "/api/v1/account/password", b, me.token) }
        assertEquals("kdf_too_weak", pw(body(kdf(mem = 4096), salt16)).errorCode())
        assertEquals("kdf_too_weak", pw(body(kdf(ops = 0), salt16)).errorCode())
        assertEquals("kdf_mem_not_kib_multiple", pw(body(kdf(mem = 8_388_609), salt16)).errorCode())
        assertEquals("bad_kdf_salt", pw(body(kdf(), Bytes.toB64(ByteArray(8)))).errorCode())
        assertEquals("bad_kdf_salt", pw(body(kdf(), Bytes.toB64(ByteArray(65)))).errorCode())
        // A recovery or another device's change commits between the password check and the write.
        s.raceHook = { p -> if (p == "password.afterGate") s.db.tx { it.exec("UPDATE users SET verifier=? WHERE userId=?", ServerCrypto.hashVerifier(b32()), me.userId) } }
        val r = pw(body(kdf(), salt16))
        assertEquals(401, r.status.value, r.bodyAsText()); assertEquals("credential_changed", r.errorCode())
        s.raceHook = null
        assertEquals(0L, s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type='password_change'") })
    }

    @Test
    fun row22_recoveryPosture_eachRefusal() = testApplication {
        val key = TestKit.Identity().curvePub
        val fp = sha256Hex(key)
        val s = TestKit.services(TestKit.config(recoveryKey = key))
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val esc = ""","escrow":{"sealed":"${Flow.escrow(me, fp).sealed}","fingerprint":"$fp"}"""
        val body = { who: Me, posture: String, escrow: String, sealed: String, base: Long, key: String -> """{"posture":"$posture"$escrow,"currentAuthKey":"$key","accountState":{"sealedState":"$sealed","baseSeq":$base}}""" }
        // The † bucket is 5 a minute; this walk is longer, and the bucket has its own test (RateBucketsTest).
        suspend fun r(who: Me, b: String) = s.limiter.clear().let { c.call(put, "/api/v1/account/recovery", b, who.token) }
        assertEquals("reauth_failed", r(me, body(me, "operator", esc, "AAAA", 0, b32())).errorCode())
        assertEquals("escrow_not_allowed", r(me, body(me, "private", esc, "AAAA", 0, me.authKey)).errorCode())
        assertEquals("bad_escrow", r(me, body(me, "operator", "", "AAAA", 0, me.authKey)).errorCode())
        assertEquals("bad_escrow", r(me, body(me, "operator", esc.replace(fp, "a".repeat(64)), "AAAA", 0, me.authKey)).errorCode())
        // The operator account itself never has operator recovery.
        assertEquals("operator_recovery_unavailable", r(op, body(op, "operator", esc, "AAAA", 0, op.authKey)).errorCode())
        assertEquals("bad_account_state", r(me, body(me, "operator", esc, "", 0, me.authKey)).errorCode())
        assertEquals("stale_state", r(me, body(me, "operator", esc, "AAAA", 5, me.authKey)).errorCode())
        val ok = r(me, body(me, "operator", esc, "AAAA", 0, me.authKey))
        assertEquals(200, ok.status.value, ok.bodyAsText()); assertTrue("\"seq\":1" in ok.bodyAsText())
        assertEquals("operator", s.db.read { it.queryOne("SELECT recovery FROM users WHERE userId=?", me.userId) { r -> r.getString(1) } })
        assertEquals("recovery_changed", Flow.sink(s).last().first)
    }

    @Test
    fun row22_operatorRecoveryUnavailable_withoutARecoveryKey() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val b = """{"posture":"operator","escrow":{"sealed":"${Bytes.toB64(ByteArray(200))}","fingerprint":"${"a".repeat(64)}"},"currentAuthKey":"${me.authKey}","accountState":{"sealedState":"AAAA","baseSeq":0}}"""
        val r = c.call(put, "/api/v1/account/recovery", b, me.token)
        assertEquals(400, r.status.value); assertEquals("operator_recovery_unavailable", r.errorCode())
    }

    @Test
    fun rows24and25_usage_nullUntilWritten_lastWriterWins_andTheCap() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val t = me.token
        assertTrue(c.call(get, "/api/v1/usage", token = t).bodyAsText().contains("\"sealedUsage\":null"))
        val w = c.call(put, "/api/v1/usage", """{"sealedUsage":"QUFB"}""", t)
        assertEquals(200, w.status.value); assertEquals("ok", w.bodyAsText())
        clock.advance(1000)
        assertEquals(200, c.call(put, "/api/v1/usage", """{"sealedUsage":"QkJC"}""", t).status.value)
        assertEquals("""{"sealedUsage":"QkJC","updatedAt":${clock.now()}}""", c.call(get, "/api/v1/usage", token = t).bodyAsText())
        assertEquals("bad_usage_blob", c.call(put, "/api/v1/usage", """{"sealedUsage":""}""", t).errorCode())
        val big = c.call(put, "/api/v1/usage", """{"sealedUsage":"${"A".repeat(Items.USAGE_SEALED_MAX + 1)}"}""", t)
        assertEquals(400, big.status.value, big.bodyAsText()); assertEquals("bad_usage_blob", big.errorCode())
        assertEquals(200, c.call(put, "/api/v1/usage", """{"sealedUsage":"${"A".repeat(Items.USAGE_SEALED_MAX)}"}""", t).status.value)
        // Not audited (§3).
        assertEquals(0L, s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type LIKE '%usage%'") })
    }

    @Test
    fun row31_delete_totpGate_reauth_leaves_atAhead_credentialChanged() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val owner = Flow.member(c, s, "owner@example.com")
        val me = Flow.member(c, s, "me@example.com")
        val v = SharedVault(c, s, owner).create()
        v.add(me, MemberRole.WRITER)
        // Two-step sign-in on.
        val secret = WireJson.json.decodeFromString(TotpSetupResponse.serializer(), c.call(post, "/api/v1/account/totp/setup", """{"currentAuthKey":"${me.authKey}"}""", me.token).bodyAsText()).secretBase32
        assertEquals(200, c.call(post, "/api/v1/account/totp/confirm", """{"code":"${Flow.totp(secret, clock.now())}"}""", me.token).status.value)
        clock.advance(30_000)
        fun code() = Flow.totp(secret, clock.now())
        fun wrong() = if (code() == "000000") "111111" else "000000"
        val preview = WireJson.json.decodeFromString(AccountDeletePreview.serializer(), c.call(get, "/api/v1/account/delete/preview", token = me.token).bodyAsText())
        assertTrue(preview.totpRequired)
        val head = preview.memberships.single().head
        val leave = { at: Long -> v.sign(me, LogEntry.Leave(v.vaultId, head.seq + 1, head.hash, me.userId, at)) }
        val del = { totp: String?, key: String, leaves: List<String> ->
            """{"confirmEmail":"${me.email}","currentAuthKey":"$key"${totp?.let { ",\"totp\":\"$it\"" } ?: ""},"leaves":${leaves.joinToString(",", "[", "]") { "\"$it\"" }}}"""
        }
        // account_delete is 5 an hour; this walk is longer, and the bucket has its own test (RateBucketsTest).
        suspend fun d(b: String) = s.limiter.clear().let { c.call(post, "/api/v1/account/delete", b, me.token) }
        val good = leave(maxOf(clock.now(), head.at))
        assertEquals("totp_code_required", d(del(null, me.authKey, listOf(good))).errorCode())
        assertEquals("bad_totp_code", d(del(wrong(), me.authKey, listOf(good))).errorCode())
        // The password is checked before the code: a wrong one is reauth_failed whatever the code, and burns no step.
        assertEquals("reauth_failed", d(del(code(), b32(), listOf(good))).errorCode())
        assertEquals("reauth_failed", d(del(wrong(), b32(), listOf(good))).errorCode())
        assertEquals("reauth_failed", d(del(null, b32(), listOf(good))).errorCode())
        // bad_leaves: a leave for a vault the account is not in, two for one vault, and more than 500.
        val other = SharedVault(c, s, owner).create()
        val foreign = other.sign(me, LogEntry.Leave(other.vaultId, 1, other.head, me.userId, clock.now()))
        assertEquals("bad_leaves", d(del(code(), me.authKey, listOf(good, foreign))).errorCode())
        assertEquals("bad_leaves", d(del(code(), me.authKey, listOf(good, good))).errorCode())
        assertEquals("bad_leaves", d(del(code(), me.authKey, List(501) { good })).errorCode())
        assertEquals("bad_leaves", d(del(code(), me.authKey, listOf("!!"))).errorCode())
        // at_ahead: a leave more than 10 minutes in the server's future.
        val ahead = d(del(code(), me.authKey, listOf(leave(clock.now() + 11 * 60_000))))
        assertEquals(400, ahead.status.value, ahead.bodyAsText()); assertEquals("at_ahead", ahead.errorCode())
        // credential_changed: a password change commits between the gate and the transaction.
        clock.advance(30_000)
        s.raceHook = { p -> if (p == "delete.afterGate") s.db.tx { it.exec("UPDATE users SET verifier=? WHERE userId=?", ServerCrypto.hashVerifier(me.authKey + "x"), me.userId) } }
        val changed = d(del(code(), me.authKey, listOf(good)))
        assertEquals(401, changed.status.value, changed.bodyAsText()); assertEquals("credential_changed", changed.errorCode())
        s.raceHook = null
        assertNotNull(s.db.read { it.queryOne("SELECT userId FROM users WHERE userId=?", me.userId) { r -> r.getString(1) } })
        assertEquals(1L, s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type='account_delete_reauth_fail' AND meta='credential_changed'") })
    }

    @Test
    fun row31_delete_succeedsWithTheCode_andTheStepIsSpent() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val secret = WireJson.json.decodeFromString(TotpSetupResponse.serializer(), c.call(post, "/api/v1/account/totp/setup", """{"currentAuthKey":"${me.authKey}"}""", me.token).bodyAsText()).secretBase32
        assertEquals(200, c.call(post, "/api/v1/account/totp/confirm", """{"code":"${Flow.totp(secret, clock.now())}"}""", me.token).status.value)
        // The confirming step is spent: the same code cannot delete.
        assertEquals("bad_totp_code", c.call(post, "/api/v1/account/delete", """{"confirmEmail":"${me.email}","currentAuthKey":"${me.authKey}","totp":"${Flow.totp(secret, clock.now())}","leaves":[]}""", me.token).errorCode())
        clock.advance(30_000)
        val r = c.call(post, "/api/v1/account/delete", """{"confirmEmail":" ${me.email.uppercase()} ","currentAuthKey":"${me.authKey}","totp":"${Flow.totp(secret, clock.now())}","leaves":[]}""", me.token)
        assertEquals(200, r.status.value, r.bodyAsText())
        assertEquals("""{"deletedAt":${clock.now()}}""", r.bodyAsText())
        assertEquals("invalid_credentials", c.call(get, "/api/v1/account/keys", token = me.token).errorCode())
    }

    @Test
    fun row27_revoke_needsThePassword() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val other = c.login(me)
        val r = c.call(post, "/api/v1/account/devices/${other.deviceId}/revoke", """{"currentAuthKey":"${b32()}"}""", me.token)
        assertEquals(403, r.status.value); assertEquals("reauth_failed", r.errorCode())
        assertEquals(200, c.call(get, "/api/v1/account/keys", token = other.accessToken).status.value)
        // A malformed device id is the same 404 as an unknown one.
        assertEquals("no_such_device", c.call(post, "/api/v1/account/devices/not-a-uuid/revoke", """{"currentAuthKey":"${me.authKey}"}""", me.token).errorCode())
    }

    @Test
    fun row34_selfSetup_rotatesTheKit() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val kit = b32()
        assertEquals("reauth_failed", c.call(put, "/api/v1/recovery/self-setup", """{"currentAuthKey":"${b32()}","memberRecovery":{"recoveryWrappedUvk":"AAAA","recoveryAuthKey":"$kit"}}""", me.token).errorCode())
        assertEquals("recovery_required", c.call(put, "/api/v1/recovery/self-setup", """{"currentAuthKey":"${me.authKey}"}""", me.token).errorCode())
        assertEquals("recovery_required", c.call(put, "/api/v1/recovery/self-setup", """{"currentAuthKey":"${me.authKey}","memberRecovery":{"recoveryWrappedUvk":"","recoveryAuthKey":"$kit"}}""", me.token).errorCode())
        val r = c.call(put, "/api/v1/recovery/self-setup", """{"currentAuthKey":"${me.authKey}","memberRecovery":{"recoveryWrappedUvk":"AAAA","recoveryAuthKey":"$kit"}}""", me.token)
        assertEquals(200, r.status.value, r.bodyAsText())
        val pieceId = Regex("\"pieceId\":\"([^\"]+)\"").find(r.bodyAsText())!!.groupValues[1]
        // The old kit is dead, the new one verifies; confirm binds to the new piece.
        assertEquals("invalid_credentials", c.call(post, "/api/v1/recovery/self/verify", """{"email":"${me.email}","recoveryAuthKey":"${me.recoveryAuthKey}"}""").errorCode())
        assertEquals(200, c.call(post, "/api/v1/recovery/self/verify", """{"email":"${me.email}","recoveryAuthKey":"$kit"}""").status.value)
        assertEquals(200, c.call(post, "/api/v1/recovery/self/confirm", """{"pieceId":"$pieceId"}""", me.token).status.value)
        // A body-less confirm from the device that set the piece up is accepted too.
        assertEquals(200, c.call(post, "/api/v1/recovery/self/confirm", token = me.token).status.value)
    }

    @Test
    fun rows29and30_recoveryRequestsList_andDeletePreview_forAPlainAccount() = testApplication {
        val key = TestKit.Identity().curvePub
        val s = TestKit.services(TestKit.config(recoveryKey = key))
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Me("me@example.com")
        Flow.register(c, s, me, Flow.enrolAuth(s), "operator", Flow.escrow(me, sha256Hex(key)))
        assertEquals("[]", c.call(get, "/api/v1/account/recovery-requests", token = me.token).bodyAsText())
        val p = WireJson.json.decodeFromString(AccountDeletePreview.serializer(), c.call(get, "/api/v1/account/delete/preview", token = me.token).bodyAsText())
        assertEquals(emptyList(), p.blockers); assertEquals(listOf(me.personalVaultId), p.deletedVaults); assertEquals(false, p.totpRequired)
    }
}
