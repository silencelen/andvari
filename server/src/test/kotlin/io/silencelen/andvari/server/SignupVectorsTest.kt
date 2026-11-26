package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.WireGrammar
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals

/** spec/test-vectors/signup.json: the code MAC, the address hash, the proof of work, verify, tickets. */
class SignupVectorsTest {
    private val v: JsonObject = WireJson.json.parseToJsonElement(
        listOf("../spec/test-vectors/signup.json", "spec/test-vectors/signup.json").map { File(it) }.first { it.isFile }.readText(),
    ).jsonObject

    private fun JsonObject.s(k: String) = this[k]!!.jsonPrimitive.content

    @Test
    fun codeMac_emailHash_pow() {
        for (r in v["codeMac"]!!.jsonArray.map { it.jsonObject }) {
            assertEquals(r.s("codeMacHex"), Signup.codeMac(Bytes.fromB64(r.s("signupSecretB64")), r.s("emailNorm"), r.s("code")), r.s("why"))
        }
        for (r in v["emailHash"]!!.jsonArray.map { it.jsonObject }) {
            assertEquals(r.s("emailHash"), Grammar.emailHash(WireGrammar.emailNorm(r.s("email"))!!), r.s("why"))
        }
        for (r in v["pow"]!!.jsonArray.map { it.jsonObject }) {
            val bits = r["powBits"]!!.jsonPrimitive.long.toInt()
            val pow = r["pow"].takeIf { it != null && it !is JsonNull }?.jsonObject
            // The order of `POST /signup/start` (spec 03 §14.1): the address is normalised and refused
            // (`invalid_email`) before any proof of work is looked at, and the work is over the normalised one.
            val email = Grammar.emailNorm(r.s("email"))
            val verdict = when {
                email == null -> "invalid_email"
                bits == 0 -> "accepted"
                pow == null -> "pow_required"
                Signup.powAccepted(email, pow.s("date"), pow["nonce"]!!.jsonPrimitive.long, bits, r["serverNow"]!!.jsonPrimitive.long) -> "accepted"
                else -> "bad_pow"
            }
            assertEquals(r["expect"]!!.jsonObject.s("verdict"), verdict, r.s("name"))
            val rowNorm = r["emailNorm"].takeIf { it != null && it !is JsonNull }?.jsonPrimitive?.content
            assertEquals(rowNorm, email, r.s("name") + ": the row's emailNorm")
        }
    }

    /**
     * Every `pow` row through the route itself: `POST /signup/start` at the row's clock with the row's
     * `powBits`, the address as typed. `accepted` is the one `202 {"status":"sent"}`; any other verdict is
     * `400` with that code.
     */
    @Test
    fun powRows_throughTheStartRoute() {
        for (r in v["pow"]!!.jsonArray.map { it.jsonObject }) testApplication {
            val clock = MutableClock(r["serverNow"]!!.jsonPrimitive.long)
            val s = TestKit.services(TestKit.config(mode = "open", powBits = r["powBits"]!!.jsonPrimitive.long.toInt()), clock)
            application { andvariModule(s) }
            val pow = r["pow"].takeIf { it != null && it !is JsonNull }
            val body = buildJsonObject {
                put("email", r.s("email"))
                put("ageConfirmed", true)
                if (pow != null) put("pow", pow)
            }.toString()
            val resp = client.call(HttpMethod.Post, "/api/v1/signup/start", body)
            val verdict = r["expect"]!!.jsonObject.s("verdict")
            if (verdict == "accepted") {
                assertEquals(202, resp.status.value, r.s("name") + ": " + resp.bodyAsText())
            } else {
                assertEquals(400, resp.status.value, r.s("name") + ": " + resp.bodyAsText())
                assertEquals(verdict, resp.errorCode(), r.s("name"))
            }
            r["expect"]!!.jsonObject["wire"]?.let { assertEquals(it.jsonPrimitive.content, "${resp.status.value} ${resp.errorCode()}", r.s("name")) }
        }
    }

    @Test
    fun tickets() {
        for (r in v["ticket"]!!.jsonArray.map { it.jsonObject }) {
            val t = r["ticket"].takeIf { it != null && it !is JsonNull }?.jsonObject
            // An unknown ticket finds no row: the same uniform refusal. The vectors' ticket rows carry the plain hash of
            // the address; the server stores and compares its keyed hash (Config.addressHash) instead, by the same
            // equality, so the register address is hashed here the way the vector's row was.
            val registerHash = Grammar.emailHash(WireGrammar.emailNorm(r.s("registerEmail"))!!)
            val ok = t != null && Signup.ticketOk(t.s("emailHash"), t["expiresAt"]!!.jsonPrimitive.long, t.s("used") == "true", registerHash, r["now"]!!.jsonPrimitive.long)
            assertEquals(r["expect"]!!.jsonObject.s("verdict") == "ok", ok, r.s("name"))
        }
    }

    @Test
    fun verifyRoute() {
        for (r in v["verify"]!!.jsonArray.map { it.jsonObject }) testApplication {
            val clock = MutableClock(r["now"]!!.jsonPrimitive.long)
            val cfg = TestKit.config(mode = "open")
            val s = TestKit.services(Config(dbPath = cfg.dbPath, blobDir = cfg.blobDir, canonicalOrigin = cfg.canonicalOrigin, enumSecret = cfg.enumSecret,
                signupSecret = Bytes.fromB64(r.s("signupSecretB64")), signupMode = "open", testMode = true, mailSinkDir = cfg.mailSinkDir), clock)
            application { andvariModule(s) }
            val email = r.s("emailNorm")
            val stored = r["stored"].takeIf { it != null && it !is JsonNull }?.jsonObject
            if (stored != null) s.db.tx { c ->
                c.exec("INSERT INTO signup_codes(emailHash,codeMac,expiresAt,attempts) VALUES(?,?,?,?)", s.config.addressHash(email),
                    Bytes.toHexLower(Bytes.fromB64(stored.s("codeMacB64"))), stored["expiresAt"]!!.jsonPrimitive.long, stored["attempts"]!!.jsonPrimitive.long)
            }
            val resp = client.call(HttpMethod.Post, "/api/v1/signup/verify", """{"email":"$email","code":"${r.s("code")}"}""")
            val e = r["expect"]!!.jsonObject
            assertEquals(e["status"]!!.jsonPrimitive.long.toInt(), resp.status.value, r.s("name") + ": " + resp.bodyAsText())
            e["code"]?.let { assertEquals(it.jsonPrimitive.content, resp.errorCode(), r.s("name")) }
            e["attemptsAfter"]?.let { a ->
                assertEquals(a.jsonPrimitive.long, s.db.read { c -> c.queryOne("SELECT attempts FROM signup_codes WHERE emailHash=?", s.config.addressHash(email)) { it.getLong(1) } }, r.s("name"))
            }
        }
    }
}
