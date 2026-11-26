package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.core.client.account.Fetched
import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.recovery.AssistedStep
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.AdminRecoveryRequest
import io.silencelen.andvari.core.model.wire.RecoveryRequestState
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.AnswerRead
import io.silencelen.andvari.core.trust.AnswerToken
import io.silencelen.andvari.core.trust.AssistedRecovery
import io.silencelen.andvari.core.trust.AssistedRecoveryFields
import io.silencelen.andvari.hostile.proxy.Resp
import io.silencelen.andvari.hostile.proxy.answer
import io.silencelen.andvari.hostile.proxy.editRequest
import io.silencelen.andvari.hostile.proxy.str
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The assisted recovery's upload and commit (index rows 86 and 72) against a server
 * that lies about them: it answers "done" to an upload it never stored; it puts the person's answer under another
 * request; it takes the commit's value away. What the operator's tool and the person's device show in each.
 */
class AssistedUploadLiesTest {
    private val crypto = createCryptoProvider()
    private val seed = crypto.randomBytes(32)
    private val recoveryPub = crypto.boxKeypairFromSeed(seed).publicKey

    /** A fresh device's verified request for Alice; its request is the last one created from [tag]. */
    private suspend fun World.asking(tag: String): Pair<Host, AssistedStep.Waiting> {
        val d = device(tag)
        val target = assertIs<AssistedStep.ConfirmTarget>(d.assisted.start("alice@example.org", origin))
        val seen = Steps.mailCount(server, "alice@example.org", "recovery_request_code")
        val requested = assertIs<AssistedStep.Requested>(d.assisted.request(target))
        val code = Steps.awaitCode(server, "alice@example.org", "recovery_request_code", seen)
        return d to assertIs<AssistedStep.Waiting>(d.assisted.verifyCode(requested, code))
    }

    /** What `recovery-cli assist` prints last for [row], made here with the offline seed: the token, read by the shared reader. */
    private fun answerFor(row: AdminRecoveryRequest, instanceId: String, uvk: ByteArray): AnswerRead.Ok {
        val commit = crypto.randomBytes(32)
        val fields = AssistedRecoveryFields(instanceId, row.userId, row.requestId, row.rPub, uvk, 1_800_000_000_000L, email = row.email, commit = commit)
        val sealed = AssistedRecovery.seal(crypto, Bytes.fromB64(row.rPub), AssistedRecovery.sign(crypto, crypto.signKeypairFromSeed(seed), fields))
        val token = AnswerToken.format(row.requestId, row.rPub, AssistedRecovery.commitHash(crypto, commit), sealed)
        return assertIs<AnswerRead.Ok>(AnswerToken.read(token, row.requestId, row.rPub, row.email))
    }

    @Test fun anUploadTheServerDidNotStore_anAnswerUnderAnotherRequest_andACommitWithoutItsValue() =
        world(extraSetup = listOf("--recovery-pubkey", Bytes.toB64(recoveryPub))) {
            val oh = operator()
            val ah = member("alice")
            val settings = ah.recoverySettings(ah.session(origin)!!)
            assertIs<Reauthed.Done<*>>(settings.setPosture(RecoveryChoiceKind.OPERATOR, settings.operatorOffer()!!, true, Steps.PASSWORD.toCharArray()))
            val uvk = ah.session(origin)!!.session.account.uvk.copyOut()
            val instanceId = oh.trust.pinFor(origin)!!.instanceId
            val (d, waiting) = asking("d")
            val (e, waitingE) = asking("e") // the email-holder's own request for the same address
            server.advance(7 * 86_400_000L + 60_000)
            val op = oh.operator(oh.session(origin)!!)
            suspend fun rows() = assertIs<Fetched.Ok<List<AdminRecoveryRequest>>>(op.recoveryRequests()).value
            val dRequest = proxy.last(WireRoute.RECOVERY_REQUEST_CREATE, "d")!!.upstream!!.json!!.str("requestId")!!
            val eRequest = proxy.last(WireRoute.RECOVERY_REQUEST_CREATE, "e")!!.upstream!!.json!!.str("requestId")!!
            val dRow = rows().single { it.requestId == dRequest }
            val eRow = rows().single { it.requestId == eRequest }
            val forD = answerFor(dRow, instanceId, uvk)

            // 1. "Done" to an upload it never stored. The tool cannot know; but the list it reads next still says the
            //    request awaits the operator (not `ready`), and the person's device is still waiting.
            proxy.on(WireRoute.ADMIN_RECOVERY_FULFIL, "op", times = 1, handler = answer { Resp.json(200, buildJsonObject { }) })
            assertIs<Reauthed.Done<Unit>>(op.fulfil(dRequest, forD, Steps.PASSWORD.toCharArray()), "the operator's tool is told done")
            assertEquals(RecoveryRequestState.AWAITING_OPERATOR, rows().single { it.requestId == dRequest }.state, "the list says it is not stored")
            val stillWaiting = assertIs<AssistedStep.Waiting>(d.assisted.poll(waiting))
            assertEquals(RecoveryRequestState.AWAITING_OPERATOR, stillWaiting.state)

            // 2. The person's answer under the email-holder's request. The operator's tool refuses it for that row (the
            //    token names the person's request), before any password (the server's own refusal, request_key_mismatch,
            //    is in its route tests); a server that serves it there anyway gives that device an answer it cannot open:
            //    unopenable, and it never commits (it has no commit value).
            val atTheOtherRow = assertIs<AnswerRead.Refused>(AnswerToken.read(forD.token, eRequest, eRow.rPub, eRow.email))
            assertEquals(dRequest, atTheOtherRow.namedRequest)
            assertEquals(Reauthed.Refused("bad_request_id"), op.fulfil(eRequest, forD, Steps.PASSWORD.toCharArray()), "an answer read for another request is never sent")
            assertIs<Reauthed.Done<Unit>>(op.fulfil(dRequest, forD, Steps.PASSWORD.toCharArray()), "stored at its own row")
            assertEquals(RecoveryRequestState.READY, rows().single { it.requestId == dRequest }.state)
            val keys = proxy.last(WireRoute.REGISTER, "alice")!!.upstream!!.json!!.let { it["accountKeys"] as JsonObject }
            proxy.on(WireRoute.RECOVERY_REQUEST_POLL, "e", handler = answer {
                Resp.json(200, buildJsonObject {
                    put("state", JsonPrimitive("ready")); put("sealed", JsonPrimitive(forD.sealed))
                    put("encryptedIdentitySeed", keys["encryptedIdentitySeed"]!!); put("identityPub", keys["identityPub"]!!)
                })
            })
            assertEquals(AssistedStep.Stopped("unopenable"), e.assisted.poll(waitingE))
            assertTrue(proxy.requests(WireRoute.RECOVERY_REQUEST_COMMIT, "e").isEmpty(), "the other row's holder commits nothing")
            proxy.honest()

            // 3. A commit whose value the server takes away: the real server refuses it (bad_commit); the device says so,
            //    keeps its request, and once the server stops lying the person finishes.
            proxy.on(WireRoute.RECOVERY_REQUEST_COMMIT, "d", times = 1, handler = editRequest { JsonObject(it - "commit") })
            val check = assertIs<AssistedStep.CheckAccount>(d.assisted.poll(stillWaiting))
            val choose = assertIs<AssistedStep.ChoosePassword>(d.assisted.confirmAccount(check, same = true))
            assertEquals(AssistedStep.Stopped("bad_commit"), d.assisted.commit(choose, "a new Passphrase for alice 4".toCharArray()))
            assertNull(d.session(origin), "no session")
            val again = assertIs<AssistedStep.CheckAccount>(d.assisted.resume(origin))
            val choose2 = assertIs<AssistedStep.ChoosePassword>(d.assisted.confirmAccount(again, same = true))
            assertIs<AssistedStep.Recovered>(d.assisted.commit(choose2, "a new Passphrase for alice 4".toCharArray()))
            // The device sent the value inside the answer it opened: its hash is the one the operator uploaded.
            val sent = proxy.requests(WireRoute.RECOVERY_REQUEST_COMMIT, "d").last().json!!.str("commit")!!
            assertEquals(forD.commitHash, AssistedRecovery.commitHashOf(crypto, sent))
        }
}
