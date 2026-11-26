package io.silencelen.andvari.cli

import com.sun.net.httpserver.HttpServer
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.client.account.OperatorDelete
import io.silencelen.andvari.core.client.account.ReauthKey
import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.account.Fetched
import io.silencelen.andvari.core.client.deletion.DeletionOutcome
import io.silencelen.andvari.core.client.onboard.PasswordKeys
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.PreloginResponse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Spec 01 §7 ("In-session password proofs", normative) in the tool: before any re-authentication
 * leaves the device, the typed password is proven against the session's own wrap, and what is sent is derived under the
 * session's own salt and cost, never under values a server names at that moment. A wrong password sends nothing at all.
 * Every request the devices make goes through a proxy that records it, and can lie in its answers.
 */
class LocalProofTest {
    private val wrong = "not the Master password 7"
    private val second = "a Second master password 22"
    private val third = "a Third master password 333"

    /** A request the proxy saw: method, path and body. */
    private data class Seen(val method: String, val path: String, val body: String) {
        fun isRoute(r: WireRoute) = method == r.method && path == r.path
        override fun toString() = "$method $path"
    }

    /**
     * A proxy in front of [s] that records every request. [lie] rewrites the JSON answer of the routes it names; [lose] is a
     * route whose request goes on to the server but whose answer is lost (502).
     */
    private class Proxy(private val s: TestServer) : AutoCloseable {
        @Volatile var lie: Map<WireRoute, (JsonObject) -> JsonObject> = emptyMap()
        @Volatile var lose: WireRoute? = null
        val seen: MutableList<Seen> = java.util.Collections.synchronizedList(ArrayList())
        private val http = HttpClient.newHttpClient()
        private val server = HttpServer.create(InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 50).apply {
            createContext("/") { ex ->
                try {
                    val body = ex.requestBody.readBytes()
                    val path = ex.requestURI.rawPath
                    seen += Seen(ex.requestMethod, path, String(body))
                    val req = HttpRequest.newBuilder(URI.create(s.origin + ex.requestURI.toString())).method(ex.requestMethod, HttpRequest.BodyPublishers.ofByteArray(body))
                    for ((k, vs) in ex.requestHeaders) if (k.lowercase() !in RESTRICTED) vs.forEach { req.header(k, it) }
                    val r = http.send(req.build(), HttpResponse.BodyHandlers.ofByteArray())
                    val route = WireRoute.entries.firstOrNull { it.method == ex.requestMethod && it.path == path }
                    if (route != null && route == lose) { ex.sendResponseHeaders(502, -1); return@createContext }
                    val rewrite = route?.let { lie[it] }
                    val answer = if (rewrite != null && r.statusCode() == 200) {
                        rewrite(Json.parseToJsonElement(String(r.body())).jsonObject).toString().toByteArray()
                    } else r.body()
                    for ((k, vs) in r.headers().map()) if (k.lowercase() !in RESTRICTED && k != ":status") vs.forEach { ex.responseHeaders.add(k, it) }
                    ex.sendResponseHeaders(r.statusCode(), if (answer.isEmpty()) -1 else answer.size.toLong())
                    if (answer.isNotEmpty()) ex.responseBody.write(answer)
                } finally {
                    ex.close()
                }
            }
            start()
        }
        val address = "http://127.0.0.1:${server.address.port}"
        fun mark(): Int = seen.size
        fun since(mark: Int): List<Seen> = synchronized(seen) { seen.drop(mark) }
        override fun close() = server.stop(0)

        companion object {
            val RESTRICTED = setOf("host", "content-length", "connection", "transfer-encoding", "upgrade", "expect", "keep-alive")
        }
    }

    /** The server's own prelogin answer for [email], asked directly (not through any device). */
    private fun honestPrelogin(s: TestServer, email: String): PreloginResponse {
        val r = HttpClient.newHttpClient().send(
            HttpRequest.newBuilder(URI.create(s.origin + WireRoute.PRELOGIN.path)).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("""{"email":"$email"}""")).build(),
            HttpResponse.BodyHandlers.ofString(),
        )
        return WireJson.json.decodeFromString(PreloginResponse.serializer(), r.body())
    }

    /** `currentAuthKey` for [password] under the account's honest salt and cost. */
    private fun honestKey(s: TestServer, email: String, password: String): String {
        val p = honestPrelogin(s, email)
        val k = PasswordKeys.derive(createCryptoProvider(), password.toCharArray(), Bytes.fromB64Canonical(p.kdfSalt)!!, p.kdfParams, served = true)!!
        try { return k.authKeyB64 } finally { k.wipe() }
    }

    private fun currentAuthKeyOf(seen: Seen): String = Json.parseToJsonElement(seen.body).jsonObject["currentAuthKey"]!!.jsonPrimitive.content

    @Test fun aWrongPasswordSendsNothingAtAllFromAnyReauthenticatedActionOfTheTool() {
        TestServer().use { srv -> Proxy(srv).use { p -> srv.journey { val s = this
            val op = s.device("operator", dial = p.address)
            Steps.registerThrough(op, s.origin, s.setupLink, "op@example.org")
            val me = s.device("me", dial = p.address)
            val meId = Steps.registerThrough(me, s.origin, Steps.enrolLink(s), "me@example.org", trustGate = true).userId
            val h = me.session(s.origin)!!
            val oh = op.session(s.origin)!!
            val ops = op.operator(oh)
            val policy = assertIs<Fetched.Ok<io.silencelen.andvari.core.model.wire.AdminPolicy>>(ops.policy()).value
            val deletion = me.account(s.origin)!!.deletion { }

            suspend fun nothingSent(what: String, block: suspend () -> Any?) {
                val mark = p.mark()
                val r = block()
                assertTrue(
                    r == Reauthed.WrongPassword || r == ReauthKey.WrongPassword || r == DeletionOutcome.WrongPassword ||
                        r == OperatorDelete.Other(Reauthed.WrongPassword) || r == io.silencelen.andvari.core.client.account.CardChangeResult.WrongPassword,
                    "$what: a wrong password is said as such: $r",
                )
                assertEquals(emptyList(), p.since(mark), "$what: a wrong password sends no request at all")
            }

            fun pw() = wrong.toCharArray()
            nothingSent("the re-authentication itself") { me.reauth(h).currentAuthKey(pw()) }
            nothingSent("account password") { me.changePassword(h, pw(), second.toCharArray()) }
            nothingSent("the engine's password change") { me.settings(h).change(pw(), second.toCharArray()) }
            nothingSent("account kit") { me.settings(h).rotateKit(pw()) }
            nothingSent("account revoke-device") { me.settings(h).revoke("00000000-0000-4000-8000-000000000000", pw()) }
            nothingSent("account require-link") { me.settings(h).setRequireLink(true, pw()) }
            nothingSent("recovery private") { me.recoverySettings(h).setPosture(RecoveryChoiceKind.PRIVATE, null, understood = false, password = pw()) }
            nothingSent("account delete") { deletion.delete("me@example.org", pw(), null) }
            nothingSent("operator disable") { ops.disable(meId, "other", pw()) }
            nothingSent("operator enable") { ops.enable(meId, pw()) }
            nothingSent("operator delete") { ops.deleteChecked(meId, pw()) }
            nothingSent("operator revoke-device") { ops.revokeDevice("00000000-0000-4000-8000-000000000000", pw()) }
            nothingSent("operator quota") { ops.setQuota(meId, 1_000_000, null, null, null, pw()) }
            nothingSent("operator policy set") { ops.setPolicy(policy, pw()) }
            nothingSent("operator escrow") { ops.escrow(meId, pw()) }
            nothingSent("operator fulfil") {
                val token = io.silencelen.andvari.core.trust.AnswerToken.format("AAAAAAAAAAAAAAAAAAAAAA", "A".repeat(43), "ab".repeat(32),
                    ByteArray(io.silencelen.andvari.core.trust.AnswerToken.sealedBytes("me@example.org")) { 1 })
                val answer = io.silencelen.andvari.core.trust.AnswerToken.read(token, "AAAAAAAAAAAAAAAAAAAAAA", "A".repeat(43), "me@example.org")
                ops.fulfil("AAAAAAAAAAAAAAAAAAAAAA", answer as io.silencelen.andvari.core.trust.AnswerRead.Ok, pw())
            }
            // A card change reads the public card chain first (the shared path refreshes the pin before it builds the card),
            // then derives the password: a wrong one sends nothing after that read.
            for ((what, change) in listOf<Pair<String, suspend () -> Any?>>(
                "card sign --name" to { op.operatorCards(oh).rename("Renamed", pw()) },
                "card sign --move-to" to { op.operatorCards(oh).move("https://moved.example.org", pw()) },
            )) {
                val mark = p.mark()
                assertEquals(io.silencelen.andvari.core.client.account.CardChangeResult.WrongPassword, change(), what)
                assertTrue(p.since(mark).all { it.method == "GET" && it.path == WireRoute.INSTANCE.path }, "$what: only the public card is read: ${p.since(mark)}")
            }

            // The right password works as before, and goes as one request.
            val mark = p.mark()
            assertEquals(Reauthed.Done(true), me.settings(h).setRequireLink(true, Steps.PASSWORD.toCharArray()))
            assertEquals(listOf(WireRoute.REQUIRE_LINK.path), p.since(mark).map { it.path })
            assertEquals(honestKey(s, "me@example.org", Steps.PASSWORD), currentAuthKeyOf(p.since(mark).single()))
            assertIs<Reauthed.Done<Unit>>(ops.disable(meId, "other", Steps.PASSWORD.toCharArray()))
            assertIs<Reauthed.Done<Unit>>(ops.enable(meId, Steps.PASSWORD.toCharArray()))
        } } }
    }

    /**
     * The proof's "keys already wiped" check called a function that never throws, so it never held.
     * Now it asks the account itself ([io.silencelen.andvari.core.client.onboard.OpenedAccount.isWiped]): a proof asked for
     * after the session's keys were wiped is refused, and nothing is sent, though the password is right.
     */
    @Test fun aProofAskedForAfterTheSessionsKeysWereWipedIsRefusedAndSendsNothing() {
        TestServer().use { srv -> Proxy(srv).use { p -> srv.journey { val s = this
            Steps.registerThrough(s.device("operator", dial = p.address), s.origin, s.setupLink, "op@example.org")
            val me = s.device("me", dial = p.address)
            Steps.registerThrough(me, s.origin, Steps.enrolLink(s), "me@example.org", trustGate = true)
            val h = me.session(s.origin)!!
            h.session.account.wipe()
            val mark = p.mark()
            assertEquals(ReauthKey.Refused, me.localProof(h, Steps.PASSWORD.toCharArray()), "the proof itself")
            assertEquals(ReauthKey.Refused, me.reauth(h).currentAuthKey(Steps.PASSWORD.toCharArray()), "the re-authentication")
            assertTrue(me.settings(h).setRequireLink(true, Steps.PASSWORD.toCharArray()) !is Reauthed.Done, "an action")
            assertEquals(emptyList(), p.since(mark), "nothing is sent for a session whose keys are wiped")
        } } }
    }

    @Test fun aServerThatNamesAnotherSaltOrAWeakerCostAtThatMomentChangesNothingThatIsSent() {
        TestServer().use { srv -> Proxy(srv).use { p -> srv.journey { val s = this
            Steps.registerThrough(s.device("operator", dial = p.address), s.origin, s.setupLink, "op@example.org")
            val me = s.device("me", dial = p.address)
            Steps.registerThrough(me, s.origin, Steps.enrolLink(s), "me@example.org", trustGate = true)
            val h = me.session(s.origin)!!
            val honest = honestKey(s, "me@example.org", Steps.PASSWORD)

            val otherSalt = Bytes.toB64(ByteArray(16) { (it * 7 + 1).toByte() })
            val weak = buildJsonObject {
                put("v", JsonPrimitive(1)); put("alg", JsonPrimitive("argon2id13")); put("ops", JsonPrimitive(1)); put("memBytes", JsonPrimitive(8192))
            }
            val lies = mapOf(
                "another salt" to { o: JsonObject -> JsonObject(o + ("kdfSalt" to JsonPrimitive(otherSalt))) },
                "a weaker cost" to { o: JsonObject -> JsonObject(o + ("kdfParams" to weak)) },
                "both" to { o: JsonObject -> JsonObject(o + ("kdfSalt" to JsonPrimitive(otherSalt)) + ("kdfParams" to weak)) },
            )
            var on = false
            for ((what, lie) in lies) {
                // Whatever asks the server for the salt and cost now gets the lie.
                p.lie = mapOf(WireRoute.PRELOGIN to lie, WireRoute.ACCOUNT_KEYS to lie)
                on = !on
                val mark = p.mark()
                assertEquals(Reauthed.Done(on), me.settings(h).setRequireLink(on, Steps.PASSWORD.toCharArray()), what)
                val sent = p.since(mark)
                assertEquals(listOf(WireRoute.REQUIRE_LINK.path), sent.map { it.path }, "$what: only the action's own request goes: $sent")
                assertEquals(honest, currentAuthKeyOf(sent.single()), "$what: the proof is derived under the session's own salt and cost")
            }
            p.lie = emptyMap()
        } } }
    }

    @Test fun afterAPasswordChangeHereTheNewPasswordProvesAndTheOldOneSendsNothingEvenWhenTheAnswerWasLost() {
        TestServer().use { srv -> Proxy(srv).use { p -> srv.journey { val s = this
            Steps.registerThrough(s.device("operator", dial = p.address), s.origin, s.setupLink, "op@example.org")
            val me = s.device("me", dial = p.address)
            Steps.registerThrough(me, s.origin, Steps.enrolLink(s), "me@example.org", trustGate = true)
            val h = me.session(s.origin)!!

            // The server takes the change: the session's own wrap is now the new one.
            assertEquals(Reauthed.Done(Unit), me.changePassword(h, Steps.PASSWORD.toCharArray(), second.toCharArray()))
            var mark = p.mark()
            assertEquals(Reauthed.WrongPassword, me.settings(h).setRequireLink(true, Steps.PASSWORD.toCharArray()), "the old password")
            assertEquals(emptyList(), p.since(mark), "the old password sends nothing")
            mark = p.mark()
            assertEquals(Reauthed.Done(true), me.settings(h).setRequireLink(true, second.toCharArray()), "the new password")
            assertEquals(honestKey(s, "me@example.org", second), currentAuthKeyOf(p.since(mark).single()))

            // The server takes the next change but its answer is lost: the pending wrap's password proves, and is the one in force.
            p.lose = WireRoute.PASSWORD_CHANGE
            assertEquals(Reauthed.Unknown, me.changePassword(h, second.toCharArray(), third.toCharArray()))
            p.lose = null
            mark = p.mark()
            assertEquals(Reauthed.Done(false), me.settings(h).setRequireLink(false, third.toCharArray()), "the password the server holds now")
            assertEquals(honestKey(s, "me@example.org", third), currentAuthKeyOf(p.since(mark).single()))
            mark = p.mark()
            assertEquals(Reauthed.WrongPassword, me.settings(h).setRequireLink(false, wrong.toCharArray()))
            assertEquals(emptyList(), p.since(mark), "a password that opens neither wrap sends nothing")
        } } }
    }
}
