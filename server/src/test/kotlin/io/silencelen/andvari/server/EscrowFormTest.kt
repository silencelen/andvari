package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.model.wire.EscrowUpload
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Only the version-3 form of recovery copy is stored (spec 04 §3, "every seal is version 3"). The server cannot open a
 * copy, but a version-3 copy has one size for each address ([EscrowCopy.sealedBytes], `455 + E`), so every route that
 * stores one refuses any other size with `400 escrow_wrong_form`: registration, `PUT /account/recovery` and
 * `PUT /escrow/self`. No client can store the old form (444 bytes at every address) and nobody can replace a new copy
 * by an old one. A copy an earlier development build stored in the old form is left as it is at start.
 *
 * Every route is driven at the shortest address the server accepts (`a@b.c`, 5 octets) and the longest (254 octets),
 * with real copies sealed by the shared code in both forms.
 */
class EscrowFormTest {
    private val shortest = "a@b.c"
    private val longest = "x".repeat(64) + "@" + "a".repeat(63) + "." + "b".repeat(63) + "." + "c".repeat(61)

    private val recovery = TestKit.Identity()
    private val key = recovery.curvePub
    private val fp = sha256Hex(key)
    private val uvk = TestKit.crypto.randomBytes(32)

    private fun v3(me: Me, emailNorm: String = me.email, pub: ByteArray = key, pubFp: String = fp): EscrowUpload = EscrowUpload(
        Bytes.toB64(Escrow.sealUvkV3(TestKit.crypto, pub, pubFp, me.userId, emailNorm, me.identity.curvePub, me.identity.sign, uvk, 1_800_000_000_000)),
        pubFp,
    )

    private fun v2(me: Me, pub: ByteArray = key, pubFp: String = fp): EscrowUpload = EscrowUpload(
        Bytes.toB64(Escrow.sealUvkV2(TestKit.crypto, pub, pubFp, me.userId, me.identity.curvePub, me.identity.sign, uvk, 1_800_000_000_000)),
        pubFp,
    )

    /** [sealedBytes] of filler, for the sizes either side of the one size. */
    private fun filler(bytes: Int, pubFp: String = fp) = EscrowUpload(Bytes.toB64(ByteArray(bytes) { 7 }), pubFp)

    private fun size(e: EscrowUpload) = Bytes.fromB64(e.sealed).size

    /** A `local@domain` of exactly [octets] octets that the server takes as an `emailNorm`. */
    private fun addressOf(octets: Int): String {
        val local = "x".repeat(minOf(64, octets - 4))
        var rem = octets - local.length - 1 - 2
        val labels = mutableListOf("b")
        while (rem > 63) { labels += "a".repeat(62); rem -= 63 }
        labels += "c".repeat(rem)
        return "$local@${labels.joinToString(".")}"
    }

    private fun storedCopy(s: Services, userId: String): Pair<String, String>? =
        s.db.read { it.queryOne("SELECT sealed,fingerprint FROM escrow WHERE userId=?", userId) { r -> r.getString(1) to r.getString(2) } }

    @Test
    fun theOneSize_isTheSharedSealsSize_atEveryAddressLength_andNeverTheOldForms() {
        for (octets in 5..254) {
            val address = addressOf(octets)
            assertEquals(octets, address.length)
            assertEquals(address, Grammar.emailNorm(address), "the server takes $address as it is")
            val me = Me(address)
            assertEquals(EscrowCopy.sealedBytes(address), size(v3(me)), "$octets octets")
            assertEquals(444, size(v2(me)), "the old form has no address")
            assertNotEquals(444, EscrowCopy.sealedBytes(address))
        }
        assertEquals(462, EscrowCopy.sealedBytes(shortest))
        assertEquals(794, EscrowCopy.sealedBytes(longest))
        assertEquals(longest, Grammar.emailNorm(longest))
    }

    /** The derivation graded by the specification's own worked examples (`spec/test-vectors/escrow-v3.json`, `seal`). */
    @Test
    fun theOneSize_agreesWithEverySealRowOfTheVectors() {
        val file = listOfNotNull(
            File("../spec/test-vectors/escrow-v3.json"), File("spec/test-vectors/escrow-v3.json"),
            System.getenv("ANDVARI_VECTORS_DIR")?.let { File(it, "escrow-v3.json") },
        ).firstOrNull { it.isFile }
        org.junit.Assume.assumeTrue("escrow-v3.json is not on this branch (and ANDVARI_VECTORS_DIR is not set)", file != null)
        val rows = Json.parseToJsonElement(file!!.readText()).jsonObject["seal"]!!.jsonArray
        assertTrue(rows.size >= 5)
        val octetsSeen = mutableSetOf<Int>()
        for (row in rows) {
            val expect = row.jsonObject["expect"] as JsonObject
            val emailNorm = expect["emailNorm"]!!.jsonPrimitive.content
            val sealed = expect["sealedBytes"]!!.jsonPrimitive.int
            assertEquals(sealed, EscrowCopy.sealedBytes(emailNorm), emailNorm)
            assertEquals(sealed, Bytes.fromB64(expect["sealedB64"]!!.jsonPrimitive.content).size, emailNorm)
            octetsSeen += expect["emailOctets"]!!.jsonPrimitive.int
        }
        assertTrue(5 in octetsSeen && 254 in octetsSeen, "the rows cover the shortest and the longest address: $octetsSeen")
    }

    private suspend fun HttpClient.register(s: Services, me: Me, escrow: EscrowUpload) =
        s.limiter.clear().let { call(HttpMethod.Post, "/api/v1/auth/register", me.register(s, Flow.enrolAuth(s), "operator", escrow)) }

    @Test
    fun registration_storesOnlyTheNewForm() = testApplication {
        val s = TestKit.services(TestKit.config(recoveryKey = key))
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        for (address in listOf(shortest, longest)) {
            val me = Me(address)
            val one = EscrowCopy.sealedBytes(address)
            val refused = listOf(
                "the old form" to v2(me),
                "a new copy for another address" to v3(me, emailNorm = "bob@example.org"),
                "a byte short" to filler(one - 1),
                "a byte over" to filler(one + 1),
            )
            for ((what, e) in refused) {
                val r = c.register(s, me, e)
                assertEquals(400, r.status.value, "$address, $what: ${r.bodyAsText()}")
                assertEquals("escrow_wrong_form", r.errorCode(), "$address, $what")
            }
            assertEquals(0L, s.db.read { it.count("SELECT COUNT(*) FROM users WHERE userId=?", me.userId) }, "$address: no account")
            // A malformed copy and a wrong fingerprint keep their own answer, before the size.
            assertEquals("bad_escrow", c.register(s, me, EscrowUpload("AAAA", fp)).errorCode())
            assertEquals("bad_escrow", c.register(s, me, v2(me).let { EscrowUpload(it.sealed, "b".repeat(64)) }).errorCode())
            val good = v3(me)
            assertEquals(one, size(good))
            val r = c.register(s, me, good)
            assertEquals(200, r.status.value, "$address: ${r.bodyAsText()}")
            assertEquals(good.sealed to fp, storedCopy(s, me.userId))
        }
    }

    @Test
    fun turningOperatorRecoveryOn_storesOnlyTheNewForm_andANewCopyIsNeverReplacedByAnOldOne() = testApplication {
        val s = TestKit.services(TestKit.config(recoveryKey = key))
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        for (address in listOf(shortest, longest)) {
            val me = Flow.member(c, s, address)
            val one = EscrowCopy.sealedBytes(address)
            suspend fun put(e: EscrowUpload, base: Long) = s.limiter.clear().let {
                c.call(
                    HttpMethod.Put, "/api/v1/account/recovery",
                    """{"posture":"operator","escrow":{"sealed":"${e.sealed}","fingerprint":"${e.fingerprint}"},"currentAuthKey":"${me.authKey}","accountState":{"sealedState":"AAAA","baseSeq":$base}}""",
                    me.token,
                )
            }
            val refused = listOf(
                "the old form" to v2(me),
                "a new copy for another address" to v3(me, emailNorm = "bob@example.org"),
                "a byte short" to filler(one - 1),
                "a byte over" to filler(one + 1),
            )
            for ((what, e) in refused) {
                val r = put(e, 0)
                assertEquals(400, r.status.value, "$address, $what: ${r.bodyAsText()}")
                assertEquals("escrow_wrong_form", r.errorCode(), "$address, $what")
            }
            assertEquals(null, storedCopy(s, me.userId), "$address: nothing stored")
            assertEquals("private", s.db.read { it.queryOne("SELECT recovery FROM users WHERE userId=?", me.userId) { r -> r.getString(1) } })
            val first = v3(me)
            assertEquals(200, put(first, 0).status.value)
            assertEquals(first.sealed to fp, storedCopy(s, me.userId))
            // Turning it on again with an old copy over the new one: refused, and the new copy stays.
            for ((what, e) in refused) assertEquals("escrow_wrong_form", put(e, 1).errorCode(), "$address, over a new copy: $what")
            assertEquals(first.sealed to fp, storedCopy(s, me.userId))
            val second = v3(me)
            assertEquals(200, put(second, 1).status.value)
            assertEquals(second.sealed to fp, storedCopy(s, me.userId))
        }
    }

    @Test
    fun theReSealAfterARotation_storesOnlyTheNewForm() = testApplication {
        val s = TestKit.services(TestKit.config(recoveryKey = key))
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val next = TestKit.Identity()
        val nextFp = sha256Hex(next.curvePub)
        val instanceId = s.db.read { s.instance.instanceId(it) }
        val rot = Bytes.toB64(recovery.frame(8, """{"v":2,"purpose":"recovery-rotation","instanceId":"$instanceId","fromFp":"$fp","toFp":"$nextFp","issuedAt":1800000000000}"""))
        for (address in listOf(shortest, longest)) {
            val me = Me(address)
            val first = v3(me)
            Flow.register(c, s, me, Flow.enrolAuth(s), "operator", first)
            val one = EscrowCopy.sealedBytes(address)
            suspend fun reseal(e: EscrowUpload) = s.limiter.clear().let {
                c.call(HttpMethod.Put, "/api/v1/escrow/self", """{"sealed":"${e.sealed}","fingerprint":"${e.fingerprint}","rotations":["$rot"]}""", me.token)
            }
            val refused = listOf(
                "the old form" to v2(me, next.curvePub, nextFp),
                "a new copy for another address" to v3(me, "bob@example.org", next.curvePub, nextFp),
                "a byte short" to filler(one - 1, nextFp),
                "a byte over" to filler(one + 1, nextFp),
            )
            for ((what, e) in refused) {
                val r = reseal(e)
                assertEquals(400, r.status.value, "$address, $what: ${r.bodyAsText()}")
                assertEquals("escrow_wrong_form", r.errorCode(), "$address, $what")
            }
            assertEquals(first.sealed to fp, storedCopy(s, me.userId), "$address: the new copy stays")
            val resealed = v3(me, pub = next.curvePub, pubFp = nextFp)
            val r = reseal(resealed)
            assertEquals(200, r.status.value, "$address: ${r.bodyAsText()}")
            assertEquals(resealed.sealed to nextFp, storedCopy(s, me.userId))
        }
    }

    /** A copy an earlier development build stored in the old form is not touched at start, and the operator reads it as it is. */
    @Test
    fun anOldFormCopyStoredEarlier_isLeftAsItIsAtStart() {
        val dir = TestKit.tempDir()
        var userId = ""
        var old = ""
        var op: Me? = null
        testApplication {
            val s = TestKit.services(TestKit.config(dir = dir, recoveryKey = key))
            application { andvariModule(s) }
            op = Flow.finishSetup(client, s)
            val me = Me("me@example.com")
            Flow.register(client, s, me, Flow.enrolAuth(s), "operator", v3(me))
            userId = me.userId
            old = v2(me).sealed
            // What an earlier build stored: the old form, written straight into the table.
            s.db.tx { it.exec("UPDATE escrow SET sealed=? WHERE userId=?", old, me.userId) }
            s.db.close()
        }
        testApplication {
            val s = TestKit.services(TestKit.config(dir = dir, recoveryKey = key))
            application { andvariModule(s) }
            assertEquals(old to fp, storedCopy(s, userId))
            assertEquals(444, Bytes.fromB64(old).size)
            assertEquals("operator", s.db.read { it.queryOne("SELECT recovery FROM users WHERE userId=?", userId) { r -> r.getString(1) } })
            // The operator's download serves it unchanged (the offline tool then says the truth about it).
            val r = client.call(HttpMethod.Post, "/api/v1/admin/accounts/$userId/escrow", """{"currentAuthKey":"${op!!.authKey}"}""", op!!.token)
            assertEquals(200, r.status.value, r.bodyAsText())
            assertTrue("\"sealed\":\"$old\"" in r.bodyAsText(), r.bodyAsText())
            assertEquals(old to fp, storedCopy(s, userId))
        }
    }
}
