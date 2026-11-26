package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.model.wire.RegisterRequest
import io.silencelen.andvari.core.model.wire.WireJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Index rows 3, 4 and 8 (spec 03 §14.3, §17.2, §17.3): the refusals the other files leave. */
class RoutesInstanceTest {
    private val put = HttpMethod.Put
    private val post = HttpMethod.Post

    private fun card(
        s: Services, signer: TestKit.Account, seq: Long, prev: String, operator: TestKit.Account, recoveryFp: String = "none",
        operatorKey: ByteArray = operator.identity.edPub,
    ): ByteArray {
        val setup = s.db.read { s.instance.setupOn(it)!! }
        return signer.identity.frame(
            4,
            TestKit.cardStatement(setup.instanceId, seq, prev, s.config.canonicalOrigin, setup.name, s.config.instanceKind, operator.userId, operatorKey, recoveryFp, 1_800_000_000_000 + seq),
        )
    }

    /**
     * Spec 03 §17.2 (verifier review): `operatorSignKey` must be byte-equal to the key that signed the named
     * account's genesis. A key and its negation (the sign bit of the compressed point flipped) share an X25519
     * image, so a handover card naming the negation used to pass and then lock the instance out of signing
     * the next card. It is `400 bad_card`; the real key is accepted.
     */
    @Test
    fun row3_aHandoverNamingTheNegationOfTheIncomingOperatorsKey_isBadCard() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val op = TestKit.seedAccount(s, "op@example.com", role = "operator")
        val next = TestKit.seedAccount(s, "next@example.com")
        val tok = TestKit.session(s, op)
        val c0 = card(s, op, 0, TestKit.ZERO64, op)
        assertEquals(200, client.call(put, "/api/v1/instance/card", body(c0, op.authKey), tok).status.value)
        val negated = next.identity.edPub.copyOf().also { it[31] = (it[31].toInt() xor 0x80).toByte() }
        // The two keys share an X25519 image: the old check could not tell them apart.
        assertEquals(Bytes.toB64(TestKit.crypto.ed25519PkToCurve25519(next.identity.edPub)), Bytes.toB64(TestKit.crypto.ed25519PkToCurve25519(negated)))
        val bad = client.call(put, "/api/v1/instance/card", body(card(s, op, 1, sha256Hex(c0), next, operatorKey = negated), op.authKey), tok)
        assertEquals(400, bad.status.value, bad.bodyAsText()); assertEquals("bad_card", bad.errorCode())
        assertEquals("operator", s.db.read { it.queryOne("SELECT role FROM users WHERE userId=?", op.userId) { x -> x.getString(1) } })
        // The real key: the handover lands.
        val good = client.call(put, "/api/v1/instance/card", body(card(s, op, 1, sha256Hex(c0), next), op.authKey), tok)
        assertEquals(200, good.status.value, good.bodyAsText())
        assertEquals("operator", s.db.read { it.queryOne("SELECT role FROM users WHERE userId=?", next.userId) { x -> x.getString(1) } })
    }

    @Test
    fun card0_namingTheCallersNegatedKey_isBadCard() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val op = TestKit.seedAccount(s, "op@example.com", role = "operator")
        val negated = op.identity.edPub.copyOf().also { it[31] = (it[31].toInt() xor 0x80).toByte() }
        val r = client.call(put, "/api/v1/instance/card", body(card(s, op, 0, TestKit.ZERO64, op, operatorKey = negated), op.authKey), TestKit.session(s, op))
        assertEquals(400, r.status.value, r.bodyAsText()); assertEquals("bad_card", r.errorCode())
    }

    private fun body(card: ByteArray, key: String) = """{"card":"${Bytes.toB64(card)}","currentAuthKey":"$key"}"""

    @Test
    fun row3_handoverToAnAccountThatIsNotActive_isRefused() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val op = TestKit.seedAccount(s, "op@example.com", role = "operator")
        val next = TestKit.seedAccount(s, "next@example.com")
        val tok = TestKit.session(s, op)
        val c0 = card(s, op, 0, TestKit.ZERO64, op)
        assertEquals(200, client.call(put, "/api/v1/instance/card", body(c0, op.authKey), tok).status.value)
        s.db.tx { it.exec("UPDATE users SET status='disabled', disabledAt=1 WHERE userId=?", next.userId) }
        val c1 = card(s, op, 1, sha256Hex(c0), next)
        val r = client.call(put, "/api/v1/instance/card", body(c1, op.authKey), tok)
        assertEquals(409, r.status.value, r.bodyAsText()); assertEquals("handover_target_invalid", r.errorCode())
        assertEquals("operator", s.db.read { it.queryOne("SELECT role FROM users WHERE userId=?", op.userId) { x -> x.getString(1) } })
        assertEquals(1L, s.db.read { it.count("SELECT COUNT(*) FROM instance_cards") })
        // Re-enabled, the same card is a handover.
        s.db.tx { it.exec("UPDATE users SET status='active', disabledAt=NULL WHERE userId=?", next.userId) }
        assertEquals(200, client.call(put, "/api/v1/instance/card", body(c1, op.authKey), tok).status.value)
    }

    /** A handover target with operator recovery on is refused (spec 03 §17.2). */
    @Test
    fun row3_handoverToAnAccountWithOperatorRecovery_isRefused() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val op = TestKit.seedAccount(s, "op@example.com", role = "operator")
        val next = TestKit.seedAccount(s, "next@example.com")
        val tok = TestKit.session(s, op)
        val c0 = card(s, op, 0, TestKit.ZERO64, op)
        assertEquals(200, client.call(put, "/api/v1/instance/card", body(c0, op.authKey), tok).status.value)
        s.db.tx { it.exec("UPDATE users SET recovery='operator' WHERE userId=?", next.userId) }
        val c1 = card(s, op, 1, sha256Hex(c0), next)
        val r = client.call(put, "/api/v1/instance/card", body(c1, op.authKey), tok)
        assertEquals(409, r.status.value, r.bodyAsText()); assertEquals("handover_target_invalid", r.errorCode())
        assertEquals("operator", s.db.read { it.queryOne("SELECT role FROM users WHERE userId=?", op.userId) { x -> x.getString(1) } })
        assertEquals(1L, s.db.read { it.count("SELECT COUNT(*) FROM instance_cards") })
        // With the posture back to private, the same card is a handover.
        s.db.tx { it.exec("UPDATE users SET recovery='private' WHERE userId=?", next.userId) }
        assertEquals(200, client.call(put, "/api/v1/instance/card", body(c1, op.authKey), tok).status.value)
    }

    @Test
    fun row3_onAPublicInstance_aTargetThatOwnsASharedVault_isRefused() = testApplication {
        val s = TestKit.services(TestKit.config(kind = "public"))
        application { andvariModule(s) }
        val op = TestKit.seedAccount(s, "op@example.com", role = "operator")
        val next = TestKit.seedAccount(s, "next@example.com")
        val tok = TestKit.session(s, op)
        val c0 = card(s, op, 0, TestKit.ZERO64, op)
        assertEquals(200, client.call(put, "/api/v1/instance/card", body(c0, op.authKey), tok).status.value)
        val vid = uuid()
        s.db.tx { db ->
            db.exec("INSERT INTO vaults(vaultId,type,rev,metaBlob,createdAt) VALUES(?,?,?,?,?)", vid, "shared", 1, "AAAA", 1)
            db.exec("INSERT INTO grants(vaultId,userId,role,addedAt,wrappedVk,rev) VALUES(?,?,'owner',1,'AAAA',1)", vid, next.userId)
        }
        val c1 = card(s, op, 1, sha256Hex(c0), next)
        val r = client.call(put, "/api/v1/instance/card", body(c1, op.authKey), tok)
        assertEquals(409, r.status.value, r.bodyAsText()); assertEquals("handover_target_invalid", r.errorCode())
        s.db.tx { it.exec("DELETE FROM grants WHERE vaultId=?", vid) }
        assertEquals(200, client.call(put, "/api/v1/instance/card", body(c1, op.authKey), tok).status.value)
    }

    @Test
    fun row4_rotation_storedOnlyWhenItVerifies_andChains() = testApplication {
        val recovery = TestKit.Identity()
        val fp = sha256Hex(recovery.curvePub)
        val s = TestKit.services(TestKit.config(recoveryKey = recovery.curvePub))
        application { andvariModule(s) }
        val op = TestKit.seedAccount(s, "op@example.com", role = "operator")
        val tok = TestKit.session(s, op)
        val c0 = card(s, op, 0, TestKit.ZERO64, op, recoveryFp = fp)
        assertEquals(200, client.call(put, "/api/v1/instance/card", body(c0, op.authKey), tok).status.value)
        val instanceId = s.db.read { s.instance.instanceId(it) }
        val next = TestKit.Identity()
        val nextFp = sha256Hex(next.curvePub)
        fun rot(signer: TestKit.Identity, from: String, to: String, inst: String = instanceId) =
            Bytes.toB64(signer.frame(8, """{"v":2,"purpose":"recovery-rotation","instanceId":"$inst","fromFp":"$from","toFp":"$to","issuedAt":1800000000000}"""))
        // The † bucket is 5 a minute; RateBucketsTest has it.
        suspend fun send(st: String, key: String = op.authKey) = s.limiter.clear().let { _ -> client }.call(put, "/api/v1/instance/rotation", """{"statement":"$st","currentAuthKey":"$key"}""", tok)
        assertEquals("reauth_failed", send(rot(recovery, fp, nextFp), b32()).errorCode())
        for (bad in listOf("!!", rot(TestKit.Identity(), fp, nextFp), rot(recovery, fp, nextFp, uuid()), rot(recovery, "a".repeat(64), nextFp), rot(next, nextFp, fp))) {
            val r = send(bad)
            assertEquals(400, r.status.value, r.bodyAsText()); assertEquals("bad_rotation", r.errorCode())
        }
        assertEquals(0L, s.db.read { it.count("SELECT COUNT(*) FROM recovery_rotations") })
        val first = rot(recovery, fp, nextFp)
        val ok = send(first)
        assertEquals(200, ok.status.value, ok.bodyAsText()); assertEquals("ok", ok.bodyAsText())
        // A byte-identical repeat is ok and stores nothing new.
        assertEquals(200, send(first).status.value)
        assertEquals(1L, s.db.read { it.count("SELECT COUNT(*) FROM recovery_rotations") })
        // The chain continues from the stored rotation's toFp, signed by the key it names.
        val third = TestKit.Identity()
        assertEquals(200, send(rot(next, nextFp, sha256Hex(third.curvePub))).status.value)
        assertTrue(client.call(HttpMethod.Get, "/api/v1/instance").bodyAsText().contains("\"rotations\":["))
    }

    @Test
    fun row6_signupStart_whenTheCapIsReached_isFull() = testApplication {
        val s = TestKit.services(TestKit.config(mode = "open", signupCap = 1))
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        assertEquals(202, c.call(post, "/api/v1/signup/start", """{"email":"a@example.com","ageConfirmed":true}""").status.value)
        Flow.member(c, s, "m@example.com")
        val r = c.call(post, "/api/v1/signup/start", """{"email":"b@example.com","ageConfirmed":true}""")
        assertEquals(403, r.status.value, r.bodyAsText()); assertEquals("signup_full", r.errorCode())
    }

    @Test
    fun row8_register_ageConfirmation_andATakenPersonalVaultId() = testApplication {
        val s = TestKit.services(TestKit.config(requireAgeConfirm = true))
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val a = Me("a@example.com")
        val noAge = c.call(post, "/api/v1/auth/register", a.register(s, Flow.enrolAuth(s), ageConfirmed = false))
        assertEquals(400, noAge.status.value, noAge.bodyAsText()); assertEquals("age_confirm_required", noAge.errorCode())
        Flow.register(c, s, a, Flow.enrolAuth(s))
        val b = Me("b@example.com", personalVaultId = a.personalVaultId)
        val taken = c.call(post, "/api/v1/auth/register", b.register(s, Flow.enrolAuth(s)))
        assertEquals(409, taken.status.value, taken.bodyAsText()); assertEquals("vault_id_taken", taken.errorCode())
    }

    @Test
    fun row8_register_theKdfAndSaltChecks() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        fun bodyWith(kdf: KdfParams = TestKit.FAST_KDF, salt: String = Bytes.toB64(ByteArray(16) { 3 })): String {
            val me = Me("x${uuid().take(8)}@example.com")
            val req = WireJson.json.decodeFromString(RegisterRequest.serializer(), me.register(s, Flow.enrolAuth(s)))
            return WireJson.json.encodeToString(RegisterRequest.serializer(), req.copy(kdfParams = kdf, kdfSalt = salt))
        }
        for ((code, b) in listOf(
            "kdf_too_weak" to bodyWith(kdf = KdfParams(ops = 1, memBytes = 4096)),
            "kdf_too_weak" to bodyWith(kdf = KdfParams(ops = 65, memBytes = 8_388_608)),
            "kdf_mem_not_kib_multiple" to bodyWith(kdf = KdfParams(ops = 1, memBytes = 8_388_609)),
            "bad_kdf_salt" to bodyWith(salt = Bytes.toB64(ByteArray(15))),
            "bad_kdf_salt" to bodyWith(salt = "AwMDAwMDAwMDAwMDAwMDAw=="),
        )) {
            val r = c.call(post, "/api/v1/auth/register", b)
            assertEquals(400, r.status.value, "$code: ${r.bodyAsText()}"); assertEquals(code, r.errorCode())
        }
        assertEquals(200, c.call(post, "/api/v1/auth/register", bodyWith()).status.value)
    }
}
