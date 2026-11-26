package io.silencelen.andvari.hostile

import io.silencelen.andvari.core.client.recovery.AssistedStep
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.AssistedRecovery
import io.silencelen.andvari.core.trust.AssistedRecoveryFields
import io.silencelen.andvari.hostile.proxy.Frames
import io.silencelen.andvari.hostile.proxy.Resp
import io.silencelen.andvari.hostile.proxy.answer
import io.silencelen.andvari.hostile.proxy.obj
import io.silencelen.andvari.hostile.proxy.str
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlin.test.Test
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The assisted recovery's commit (`POST /recovery/requests/{id}/commit`, index row 72) answered with a session that is
 * not the one this commit made: another account's session, or the person's own from before the recovery (its old salt
 * and wrapped key). The device sent its own new salt and wrapped key, so neither may become the recovered session: no
 * session is kept, and the person is never told the new password is wrong.
 */
class AssistedCommitLiesTest {
    private val crypto = createCryptoProvider()
    private val seed = crypto.randomBytes(32)
    private val recoveryPub = crypto.boxKeypairFromSeed(seed).publicKey

    @Test fun anAssistedCommitAnswerOfAnotherAccountOrFromBeforeTheRecoveryIsNeverTheRecoveredSession() =
        world(extraSetup = listOf("--recovery-pubkey", Bytes.toB64(recoveryPub))) {
            val oh = operator()
            val ah = member("alice")
            member("bob")
            val alice = ah.session(origin)!!
            val alicesRegister = proxy.last(WireRoute.REGISTER, "alice")!!.upstream!!.json!!
            val bobsRegister = proxy.last(WireRoute.REGISTER, "bob")!!.upstream!!.json!!
            val keys = alicesRegister.obj("accountKeys")!!
            val instanceId = oh.trust.pinFor(origin)!!.instanceId
            val uvk = alice.session.account.uvk.copyOut()
            val signer = crypto.signKeypairFromSeed(seed)

            for ((i, lie) in listOf("Bob's session (A)" to bobsRegister, "Alice's own session from before the recovery (R)" to alicesRegister).withIndex()) {
                val tag = "d$i"
                val d = device(tag)
                val target = assertIs<AssistedStep.ConfirmTarget>(d.assisted.start("alice@example.org", origin))
                val requested = assertIs<AssistedStep.Requested>(d.assisted.request(target), "${lie.first}: the request is opened")
                val created = proxy.last(WireRoute.RECOVERY_REQUEST_CREATE, tag)!!
                val rPubText = created.req.json!!.str("rPub")!!
                val requestId = created.upstream!!.json!!.str("requestId")!!
                // What only the offline key could have made, for this request and this identity: the device goes on.
                val sealed = AssistedRecovery.seal(crypto, Frames.bytes(rPubText),
                    AssistedRecovery.sign(crypto, signer, AssistedRecoveryFields(instanceId, alice.userId, requestId, rPubText, uvk, server.now(),
                        email = "alice@example.org", commit = crypto.randomBytes(32))))
                val ready: JsonObject = buildJsonObject {
                    put("state", JsonPrimitive("ready")); put("sealed", JsonPrimitive(Bytes.toB64(sealed)))
                    put("encryptedIdentitySeed", JsonPrimitive(keys.str("encryptedIdentitySeed")!!)); put("identityPub", JsonPrimitive(keys.str("identityPub")!!))
                }
                proxy.on(WireRoute.RECOVERY_REQUEST_POLL, tag, handler = answer { Resp.json(200, ready) })
                val check = assertIs<AssistedStep.CheckAccount>(d.assisted.poll(requested), lie.first)
                val choose = assertIs<AssistedStep.ChoosePassword>(d.assisted.confirmAccount(check, same = true), lie.first)
                proxy.on(WireRoute.RECOVERY_REQUEST_COMMIT, tag, handler = answer { Resp.json(200, lie.second) })
                val out = d.assisted.commit(choose, "a new Passphrase for alice 4".toCharArray())
                assertTrue(out !is AssistedStep.Recovered, "${lie.first}: never the recovered session: $out")
                assertTrue((out as? AssistedStep.Stopped)?.reason != "wrong_password", "${lie.first}: never a password verdict: $out")
                assertNull(d.session(origin), "${lie.first}: no session is kept")
                assertTrue(proxy.requests(WireRoute.RECOVERY_REQUEST_COMMIT, tag).size == 1, "${lie.first}: the commit was sent once")
                proxy.honest()
            }
            // Alice's own account is untouched by the lies: her password still signs in (passwordDevice asserts it).
            passwordDevice("e", "alice@example.org")
        }
}
