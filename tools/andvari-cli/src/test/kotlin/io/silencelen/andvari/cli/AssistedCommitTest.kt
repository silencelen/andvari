package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.Keys
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.AccountGenesis
import io.silencelen.andvari.core.trust.GenesisFields
import io.silencelen.andvari.server.queryOne
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The commit of a recovery with the operator's help, over the real server, with the operator's side run as an operator
 * runs it (the escrow, `recovery-cli assist` offline, the upload): answered with the account this home knows under another
 * identity key; and taken while what this home keeps changed.
 */
class AssistedCommitTest {
    private val crypto = createCryptoProvider()
    private val recoverySeed = crypto.randomBytes(32)
    private val newPw = "recovered by the operator 4711"
    private fun pw(p: String): (String) -> String? = { if (it == "ANDVARI_PASSWORD") p else null }

    /** The server with operator recovery, the operator, and alice (operator recovery on), whose kit is [kit]. */
    private class World(val s: TestServer, val w: CliWorld, val alice: File, val userId: String, val accountId: String)

    private fun world(s: TestServer): World {
        val w = CliWorld(s)
        val alice = w.account("alice@example.org")
        assertTrue(w.run(alice, "recovery", "operator", "--i-understand").ok().contains("recovery: operator"))
        val accountId = Regex("account ([0-9a-f]{32})").find(w.kit("alice@example.org").readLines().first())!!.groupValues[1]
        return World(s, w, alice, w.userId("alice@example.org"), accountId)
    }

    /** A request for help made on [d], answered by the operator after its hold: the account is ready to confirm on [d]. */
    private fun answered(x: World, d: File) {
        val s = x.s
        val w = x.w
        val seen = Steps.mailCount(s, "alice@example.org", "recovery_request_code")
        val asked = w.run(d, "recover", "assist", "--email", "alice@example.org", "--trust-card", w.card0, env = pw(newPw),
            stdin = { Steps.awaitCode(s, "alice@example.org", "recovery_request_code", seen) })
        assertEquals(0, asked.code, asked.out + asked.err)
        val requestCode = Regex("request code: ([A-Za-z0-9 -]+?)\\s{3}").find(asked.out)!!.groupValues[1].trim()
        s.advance(7 * 86_400_000L + 60_000)
        val listed = w.run(w.op, "operator", "recovery-requests").ok()
        val m = Regex("^(\\S+)\\s+for alice@example.org\\s+request key (\\S+)\\s+user (\\S+)", RegexOption.MULTILINE).find(listed)!!
        val (requestId, rPub, userId) = m.destructured
        val escrow = File(w.tmp, "escrow-${d.name}.json")
        w.run(w.op, "operator", "escrow", "alice@example.org", "--out", escrow.path).ok()
        val instanceId = s.setup["instanceId"]!!.toString().trim('"')
        val assistOut = s.recoveryCli(
            listOf("assist", "--instance", instanceId, "--request", requestId, "--request-key", rPub, "--request-code", requestCode,
                "--email", "alice@example.org", "--user", userId, "--identity-fp", x.accountId, "--identity-file", escrow.path),
            Bytes.toB64(recoverySeed) + "\n" + "RECOVER ${userId.take(8)}\n",
        )
        val sealed = File(w.tmp, "answer-${d.name}.txt").apply { writeText(assistOut) }
        w.run(w.op, "operator", "fulfil", requestId, "--sealed-file", sealed.path).ok()
    }

    /**
     * Section FF, third point: the home knows alice's key (she was signed in here and signed out, which keeps the record).
     * The operator's answer is under her own key, so it is taken up to the commit; the server takes the commit, and its
     * answer is rewritten to alice under another key Q (a new seed sealed under her account key, with a genesis Q signs).
     * Refused after the commit, in the words that say the server took it; no session, no kit, the record unchanged, nothing
     * offered.
     */
    @Test fun anAssistedCommitAnsweredWithTheKnownAccountUnderAnotherKeyIsRefusedAndWritesNoKit() {
        TestServer(extraSetup = listOf("--recovery-pubkey", Bytes.toB64(crypto.boxKeypairFromSeed(recoverySeed).publicKey))).use { s ->
            LyingProxy(s).use { p ->
                val x = world(s)
                val w = x.w
                val d = File(w.tmp, "d")
                w.run(d, "sign-in", "--email", "alice@example.org", "--trust-card", w.card0).ok()
                w.run(d, "sign-out", "--email", "alice@example.org").ok()
                val record = "${Host.CLI_IDENTITY}${s.origin}|${x.userId}"
                val known = CliHome(d).deviceState().get(record)
                assertTrue(known != null, "the home keeps alice's key after the sign-out")
                answered(x, d)
                val instanceId = s.setup["instanceId"]!!.toString().trim('"')
                var committed = false
                p.answer = mapOf(WireRoute.RECOVERY_REQUEST_COMMIT to { body, forward ->
                    val sent = Json.parseToJsonElement(String(body)).jsonObject
                    val (status, answer) = forward()
                    assertEquals(200, status, "the server took the commit")
                    committed = true
                    // The account key, opened as the device that sent the commit can: the new password's wrap of it.
                    val params = WireJson.json.decodeFromJsonElement(KdfParams.serializer(), sent["newKdfParams"]!!)
                    val mk = Keys.masterKey(crypto, newPw, Bytes.fromB64(sent["newKdfSalt"]!!.jsonPrimitive.content), params)
                    val uvk = Envelope.openB64(crypto, Keys.wrapKey(crypto, mk), sent["newWrappedUvk"]!!.jsonPrimitive.content, Ad.uvk(x.userId))
                    val o = Json.parseToJsonElement(String(answer)).jsonObject
                    val keys = o["accountKeys"]!!.jsonObject
                    val seed = crypto.randomBytes(32)
                    val q = crypto.boxKeypairFromSeed(seed).publicKey
                    val vault = keys["personalWrap"]!!.jsonObject["vaultId"]!!.jsonPrimitive.content
                    val genesis = AccountGenesis.sign(crypto, crypto.signKeypairFromSeed(seed), GenesisFields(x.userId, Bytes.toB64(q), instanceId, vault, s.now()))
                    val other = JsonObject(keys + mapOf(
                        "encryptedIdentitySeed" to JsonPrimitive(Bytes.toB64(Envelope.seal(crypto, uvk, seed, Ad.idkey(x.userId)))),
                        "identityPub" to JsonPrimitive(Bytes.toB64(q)),
                        "genesis" to JsonPrimitive(Bytes.toB64(genesis)),
                    ))
                    status to JsonObject(o + ("accountKeys" to other)).toString()
                })
                val kit = File(w.tmp, "kit-new")
                val r = w.run(d, "recover", "assist", "--account-id", x.accountId, "--kit-out", kit.path, env = pw(newPw), dial = p.address)
                p.answer = emptyMap()
                assertTrue(committed, "the commit reached the server")
                assertEquals(1, r.code, r.out + r.err)
                assertTrue(r.err.contains("[$KEY_RECOVERY_KEY_REFUSED]: " + fill(RECOVERY_KEY_REFUSED_AFTER_COMMIT, s.origin, "alice@example.org")), r.err)
                assertTrue(r.err.lines().contains(fill(RECOVERY_REFUSED_NEXT, s.origin)), "what comes next, on a line of its own: ${r.err}")
                assertFalse(r.err.contains("before the server changed anything"), r.err)
                assertFalse(kit.exists(), "no kit written for the other key")
                assertEquals(known, CliHome(d).deviceState().get(record), "the record of the key is unchanged")
                assertNull(CliHome(d).secureState().get("cli.session|${s.origin}|alice@example.org"), "no session kept")
                val f = w.run(d, "forget-earlier-account", "--email", "alice@example.org")
                assertTrue(f.err.contains("[$KEY_EARLIER_NOT_OFFERED]: " + fill(EARLIER_KEY_NOT_OFFERED, s.origin, "alice@example.org")), f.err)
            }
        }
    }

    /**
     * What is left from the earlier run: the commit of a recovery with the operator's help that the server took while this
     * home started keeping another account (bo). The session is not kept and is ended at the server; the command says that
     * the recovery went through, where the kit is, why it was not kept, and that the request is used up; the new password
     * and the kit work; bo stays kept.
     */
    @Test fun anAssistedCommitTakenWhileAnotherAccountWasKeptHereKeepsTheKitAndSaysTheRequestIsUsed() {
        TestServer(extraSetup = listOf("--recovery-pubkey", Bytes.toB64(crypto.boxKeypairFromSeed(recoverySeed).publicKey))).use { s ->
            LyingProxy(s).use { p ->
                val x = world(s)
                val w = x.w
                w.account("bo@example.org")
                val d = File(w.tmp, "d")
                answered(x, d)
                NotKeptAfterCommitTest.boKeptMeanwhile(p, s, w, WireRoute.RECOVERY_REQUEST_COMMIT, d)
                val kit = File(w.tmp, "kit-new")
                val r = w.run(d, "recover", "assist", "--account-id", x.accountId, "--kit-out", kit.path, env = pw(newPw), dial = p.address)
                p.answer = emptyMap()
                assertEquals(1, r.code, r.out + r.err)
                val said = fill(RECOVERY_COMMITTED_NOT_KEPT, s.origin, "alice@example.org", fill(COMMITTED_KIT_WRITTEN, kit.path),
                    fill(NOT_KEPT_ANOTHER, "bo@example.org")) + " " + ASSISTED_REQUEST_USED
                assertTrue(r.err.contains("[$KEY_COMMITTED_NOT_KEPT]: $said"), r.err)
                assertTrue(kit.exists(), "the kit is kept")
                val live = s.services.db.read { c ->
                    c.queryOne("SELECT COUNT(*) FROM sessions WHERE userId=? AND revokedAt IS NULL AND refreshConsumedAt IS NULL AND refreshExpiresAt>?",
                        x.userId, s.now()) { it.getLong(1) }
                } ?: 0L
                assertEquals(0L, live, "the session this home did not keep is ended at the server, and the recovery ended the others")
                val after = w.run(d, "recover", "assist")
                assertEquals(2, after.code, after.out + after.err)
                assertTrue(after.err.contains("no request is kept for ${s.origin} on this device"), "the request is not kept any more: ${after.err}")
                w.run(File(w.tmp, "e"), "sign-in", "--email", "alice@example.org", "--trust-card", w.card0, env = pw(newPw)).ok()
                w.run(File(w.tmp, "f"), "recover", "kit", "--kit-file", kit.path, "--kit-out", File(w.tmp, "kit-3").path, origin = null, env = pw(newPw)).ok()
                w.run(d, "item", "list", "personal", "--email", "bo@example.org").ok()
            }
        }
    }
}
