package io.silencelen.andvari.cli.e2e

import com.sun.net.httpserver.HttpServer
import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.SavedSessions
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.pin.CardStatus
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.KeyPairBytes
import io.silencelen.andvari.core.crypto.Keys
import io.silencelen.andvari.core.model.wire.AccountKeys
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.CardFields
import io.silencelen.andvari.core.trust.InstanceCard
import io.silencelen.andvari.core.trust.InstanceKind
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.util.concurrent.Executors
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Design §4.1 (VR-11): while the tool holds a session, its account checks the operator key every card names
 * for it. A card that names the signed-in account as operator under another key is refused on that account's own device
 * (`operator_key_mismatch`, the pin stays), after a sign-in and after a reopen from the saved session; another account's
 * device follows it, and so does the operator's device once it has signed out.
 */
class OwnOperatorKeyTest {
    /**
     * A forwarder at the origin's port in front of the server's listener. With [extra] set, every served card chain gets
     * that frame appended: a card the server itself would never store (it names the operator under another key).
     */
    private class CardProxy(private val s: TestServer) : AutoCloseable {
        @Volatile var extra: String? = null
        private val upstream: HttpClient = HttpClient.newHttpClient()
        // Bound to port 0, then put in front of the server at the origin's port ([TestServer.interpose]), forwarding to the
        // server's own listener: no port is picked first and bound later.
        private val server: HttpServer = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 50).apply {
            createContext("/") { ex ->
                try {
                    val body = ex.requestBody.readBytes()
                    val req = HttpRequest.newBuilder(URI.create(s.serverAddress + ex.requestURI.toString()))
                        .method(ex.requestMethod, if (body.isEmpty()) HttpRequest.BodyPublishers.noBody() else HttpRequest.BodyPublishers.ofByteArray(body))
                    for ((k, vs) in ex.requestHeaders) if (k.lowercase() !in NOT_FORWARDED) vs.forEach { req.header(k, it) }
                    val r = upstream.send(req.build(), HttpResponse.BodyHandlers.ofByteArray())
                    var out = r.body()
                    val x = extra
                    if (x != null && ex.requestMethod == "GET" && ex.requestURI.path == "/api/v1/instance" && r.statusCode() == 200) {
                        val o = Json.parseToJsonElement(out.decodeToString()).jsonObject
                        out = JsonObject(o + ("cards" to JsonArray(o.getValue("cards").jsonArray + JsonPrimitive(x)))).toString().encodeToByteArray()
                    }
                    r.headers().firstValue("content-type").ifPresent { ex.responseHeaders.add("Content-Type", it) }
                    ex.sendResponseHeaders(r.statusCode(), if (out.isEmpty()) -1 else out.size.toLong())
                    ex.responseBody.use { it.write(out) }
                } catch (e: Exception) {
                    ex.sendResponseHeaders(502, -1)
                    ex.close()
                }
            }
            executor = Executors.newCachedThreadPool()
            start()
        }

        init { s.interpose(server.address.port) }

        override fun close() {
            s.interpose(null)
            server.stop(0)
        }

        companion object {
            private val NOT_FORWARDED = setOf("host", "connection", "content-length", "expect", "upgrade", "accept-encoding", "transfer-encoding")
        }
    }

    /**
     * The operator's own Ed25519 key pair, opened as spec 01 opens it, from [password] (the one this test registered with)
     * and the account's keys as the server serves them: the master key (Argon2id under the served salt and cost), its
     * wrap key, the UVK, the identity seed, the signing pair. Only the shared code's public primitives are used. The engine
     * itself never hands a key out (its own signer, `OpenedAccount.signInstanceCard`, signs only a card that names the
     * account's own key), so a test that must sign a card an honest operator never would opens the key itself.
     */
    private suspend fun operatorSigningKey(op: Host, origin: String, userId: String, password: String): KeyPairBytes {
        val served = op.client(origin).call(WireRoute.ACCOUNT_KEYS, decode = { WireJson.json.decodeFromString(AccountKeys.serializer(), it) })
        val keys = assertIs<WireResult.Ok<AccountKeys>>(served, "the operator's keys are served").value
        val mk = Keys.masterKey(op.crypto, password, Bytes.fromB64Canonical(keys.kdfSalt)!!, keys.kdfParams)
        val wrap = Keys.wrapKey(op.crypto, mk)
        mk.fill(0)
        val uvk = try { Envelope.openB64(op.crypto, wrap, keys.wrappedUvk, Ad.uvk(userId)) } finally { wrap.fill(0) }
        val seed = try { Envelope.openB64(op.crypto, uvk, keys.encryptedIdentitySeed, Ad.idkey(userId)) } finally { uvk.fill(0) }
        try { return op.crypto.signKeypairFromSeed(seed) } finally { seed.fill(0) }
    }

    @Test fun aCardNamingTheSignedInAccountAsOperatorUnderAnotherKeyIsRefusedOnItsOwnDevice() {
        TestServer().use { s -> CardProxy(s).use { proxy -> runBlocking {
            // Every device dials the origin, where the forwarder listens.
            val op = s.device("operator", dial = s.origin)
            Steps.registerThrough(op, s.origin, s.setupLink, "op@example.org")
            val me = s.device("me", dial = s.origin)
            Steps.registerThrough(me, s.origin, Steps.enrolLink(s, "me@example.org"), "me@example.org", trustGate = true)

            // Card 1, signed by the operator's real key (so the chain verifies), names the operator under another key.
            val held = op.session(s.origin)!!
            val pin = op.trust.pinFor(s.origin)!!
            val other = op.crypto.signKeypairFromSeed(ByteArray(32) { 9 })
            val fields = CardFields(
                pin.instanceId, pin.seq + 1, pin.hash, pin.origin, pin.name, InstanceKind.fromLiteral(pin.kind)!!, held.userId,
                Bytes.toB64(other.publicKey), pin.recoveryFp.takeIf { it != "none" }, s.now(),
            )
            val signer = operatorSigningKey(op, s.origin, held.userId, Steps.PASSWORD)
            assertEquals(held.session.account.signingKeyB64(), Bytes.toB64(signer.publicKey), "the key opened here is the operator's own")
            try {
                proxy.extra = Bytes.toB64(InstanceCard.sign(op.crypto, signer, fields))
            } finally {
                signer.privateKey.fill(0)
            }

            // The operator's device, signed in: refused, and its pin stays.
            val refused = assertIs<CardStatus.Refused>(op.trust.refresh(s.origin), "the operator's own device")
            assertEquals("operator_key_mismatch", refused.verdict)
            assertEquals(pin.seq, op.trust.pinFor(s.origin)!!.seq)

            // The same device restarted, its session reopened from the saved one: refused again.
            val saved = SavedSessions(op.secure)
            saved.save(held)
            val again = Host(op.state, op.secure, s::now, http = s.httpFor(s.origin), deviceName = "operator")
            assertEquals(SavedSessions.Reopen.Reopened, saved.reopen(again, s.origin, "op@example.org", Steps.PASSWORD.toCharArray()), "the saved session reopens")
            assertEquals("operator_key_mismatch", assertIs<CardStatus.Refused>(again.trust.refresh(s.origin)).verdict)

            // Another account's device follows the card: it names someone else.
            assertIs<CardStatus.Ok>(me.trust.refresh(s.origin), "another account's device")
            assertEquals(pin.seq + 1, me.trust.pinFor(s.origin)!!.seq)

            // Signed out, the operator's device no longer holds its key to compare: the card is followed.
            again.signedOut(s.origin)
            assertIs<CardStatus.Ok>(again.trust.refresh(s.origin), "after sign-out")
            assertEquals(pin.seq + 1, again.trust.pinFor(s.origin)!!.seq)
        } } }
    }
}
