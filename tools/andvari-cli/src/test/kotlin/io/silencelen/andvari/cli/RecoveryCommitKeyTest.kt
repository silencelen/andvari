package io.silencelen.andvari.cli

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.MemberRecovery
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.AccountGenesis
import io.silencelen.andvari.core.trust.GenesisFields
import io.silencelen.andvari.core.trust.RecoveryKit
import io.silencelen.andvari.cli.e2e.TestServer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * A recovery with the kit whose check is answered with the account this home knows, under its own key, and whose commit
 * is answered with that account under another key (one any holder of the account key can make: a new seed sealed under it,
 * with a genesis that seed signs). The server has taken the commit; the session its answer opens is compared with this
 * home's record of the key and refused: no session, no new kit for that key, the record unchanged, and the sentence says
 * that the server already took the new password and the earlier kit no longer works. Before, it was taken.
 */
class RecoveryCommitKeyTest {
    private val newPw: (String) -> String? = { when (it) { "ANDVARI_PASSWORD" -> io.silencelen.andvari.cli.e2e.Steps.PASSWORD; "ANDVARI_NEW_PASSWORD" -> "a brand new master password 77"; else -> null } }

    @Test fun aRecoveryCommitAnsweredWithTheKnownAccountUnderAnotherKeyIsRefusedAndWritesNoKit() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = "commit@example.org"
                val a = w.account(me)
                val u = w.userId(me)
                val record = "${Host.CLI_IDENTITY}${s.origin}|$u"
                val known = CliHome(a).deviceState().get(record)
                assertTrue(known != null, "the home keeps the account's key")
                val crypto = createCryptoProvider()
                val instanceId = s.setup["instanceId"]!!.toString().trim('"')
                val secret = RecoveryKit.parseQr(w.kit(me).readLines().map { it.trim() }.first { it.startsWith("andvari-kit:") })!!.secret
                var uvk: ByteArray? = null
                var committed = false
                p.answer = mapOf(
                    WireRoute.RECOVERY_SELF_VERIFY to { _, forward ->
                        val (status, body) = forward()
                        val o = Json.parseToJsonElement(String(body)).jsonObject
                        uvk = MemberRecovery.openUvk(crypto, secret, o["recoveryWrappedUvk"]!!.jsonPrimitive.content, u)
                        status to String(body)
                    },
                    WireRoute.RECOVERY_SELF_COMMIT to { _, forward ->
                        val (status, body) = forward()
                        assertEquals(200, status, "the server took the commit")
                        committed = true
                        val o = Json.parseToJsonElement(String(body)).jsonObject
                        val keys = o["accountKeys"]!!.jsonObject
                        val seed = crypto.randomBytes(32)
                        val q = crypto.boxKeypairFromSeed(seed).publicKey
                        val vault = keys["personalWrap"]!!.jsonObject["vaultId"]!!.jsonPrimitive.content
                        val genesis = AccountGenesis.sign(crypto, crypto.signKeypairFromSeed(seed), GenesisFields(u, Bytes.toB64(q), instanceId, vault, s.now()))
                        val other = JsonObject(keys + mapOf(
                            "encryptedIdentitySeed" to JsonPrimitive(Bytes.toB64(Envelope.seal(crypto, uvk!!, seed, Ad.idkey(u)))),
                            "identityPub" to JsonPrimitive(Bytes.toB64(q)),
                            "genesis" to JsonPrimitive(Bytes.toB64(genesis)),
                        ))
                        status to JsonObject(o + ("accountKeys" to other)).toString()
                    },
                )
                val out = File(w.tmp, "kit-new")
                val r = w.run(a, "recover", "kit", "--kit-file", w.kit(me).path, "--kit-out", out.path, origin = null, env = newPw, dial = p.address)
                p.answer = emptyMap()
                assertTrue(committed, "the commit reached the server")
                assertEquals(1, r.code, r.out + r.err)
                assertFalse(out.exists(), "no kit written for the other key")
                assertEquals(known, CliHome(a).deviceState().get(record), "the record of the key is unchanged")
                assertFalse(r.err.contains("before the server changed anything"), r.err)
                assertTrue(r.err.contains("[$KEY_RECOVERY_KEY_REFUSED]: " + fill(RECOVERY_KEY_REFUSED_AFTER_COMMIT, s.origin, me)), r.err)
                // Nothing is offered for it.
                assertTrue(w.run(a, "forget-earlier-account", "--email", me).err.contains("[$KEY_EARLIER_NOT_OFFERED]: " + fill(EARLIER_KEY_NOT_OFFERED, s.origin, me)))
            }
        }
    }
}
