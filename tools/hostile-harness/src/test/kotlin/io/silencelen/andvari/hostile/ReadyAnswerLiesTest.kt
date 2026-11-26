package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.core.client.account.Fetched
import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.recovery.AssistedStep
import io.silencelen.andvari.core.client.recovery.WireAssistedRecovery
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.AdminRecoveryRequest
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.AnswerRead
import io.silencelen.andvari.core.trust.AnswerToken
import io.silencelen.andvari.core.trust.AssistedRecovery
import io.silencelen.andvari.core.trust.AssistedRecoveryFields
import io.silencelen.andvari.hostile.proxy.Resp
import io.silencelen.andvari.hostile.proxy.answer
import io.silencelen.andvari.hostile.proxy.editAnswer
import io.silencelen.andvari.hostile.proxy.set
import io.silencelen.andvari.hostile.proxy.str
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The poll of an answered request (`POST /recovery/requests/{id}/poll`, index row 70; the commit hash it names, and
 * a `404`) against a server that names another answer's commit hash, or says it no longer knows the request.
 */
class ReadyAnswerLiesTest {
    private val crypto = createCryptoProvider()
    private val seed = crypto.randomBytes(32)
    private val recoveryPub = crypto.boxKeypairFromSeed(seed).publicKey

    private suspend fun World.asking(tag: String): Pair<Host, AssistedStep.Waiting> {
        val d = device(tag)
        val target = assertIs<AssistedStep.ConfirmTarget>(d.assisted.start("alice@example.org", origin))
        val seen = Steps.mailCount(server, "alice@example.org", "recovery_request_code")
        val requested = assertIs<AssistedStep.Requested>(d.assisted.request(target))
        val code = Steps.awaitCode(server, "alice@example.org", "recovery_request_code", seen)
        return d to assertIs<AssistedStep.Waiting>(d.assisted.verifyCode(requested, code))
    }

    private fun answerFor(row: AdminRecoveryRequest, instanceId: String, uvk: ByteArray): AnswerRead.Ok {
        val commit = crypto.randomBytes(32)
        val fields = AssistedRecoveryFields(instanceId, row.userId, row.requestId, row.rPub, uvk, 1_800_000_000_000L, email = row.email, commit = commit)
        val sealed = AssistedRecovery.seal(crypto, Bytes.fromB64(row.rPub), AssistedRecovery.sign(crypto, crypto.signKeypairFromSeed(seed), fields))
        val token = AnswerToken.format(row.requestId, row.rPub, AssistedRecovery.commitHash(crypto, commit), sealed)
        return assertIs<AnswerRead.Ok>(AnswerToken.read(token, row.requestId, row.rPub, row.email))
    }

    /**
     * - `ready` naming a commit hash that is not the stored answer's (W): "the answer on the server is not the one this
     *   device opened", before the person is asked anything; the request is kept and nothing more is sent.
     * - `ready` naming the stored answer's own hash: on to the account check. With no such field (a server from before it):
     *   as before.
     * - `404 request_unknown` to the poll of a live request (X): said as such, the request kept, and the next honest poll
     *   goes on.
     */
    @Test fun aReadyAnswerNamingAnotherCommitHashOrA404IsSaidAndTheRequestKept() =
        world(extraSetup = listOf("--recovery-pubkey", Bytes.toB64(recoveryPub))) {
            val oh = operator()
            val ah = member("alice")
            val settings = ah.recoverySettings(ah.session(origin)!!)
            assertIs<Reauthed.Done<*>>(settings.setPosture(RecoveryChoiceKind.OPERATOR, settings.operatorOffer()!!, true, Steps.PASSWORD.toCharArray()))
            val uvk = ah.session(origin)!!.session.account.uvk.copyOut()
            val instanceId = oh.trust.pinFor(origin)!!.instanceId
            val (d, waiting) = asking("d")
            server.advance(7 * 86_400_000L + 60_000)
            val op = oh.operator(oh.session(origin)!!)
            val dRequest = proxy.last(WireRoute.RECOVERY_REQUEST_CREATE, "d")!!.upstream!!.json!!.str("requestId")!!
            val dRow = assertIs<Fetched.Ok<List<AdminRecoveryRequest>>>(op.recoveryRequests()).value.single { it.requestId == dRequest }
            val answer = answerFor(dRow, instanceId, uvk)

            // Before the upload, a 404: said, kept, and the next poll asks again.
            proxy.on(WireRoute.RECOVERY_REQUEST_POLL, "d", times = 1, handler = answer {
                Resp.json(404, kotlinx.serialization.json.buildJsonObject {
                    put("error", kotlinx.serialization.json.JsonPrimitive("request_unknown")); put("message", kotlinx.serialization.json.JsonPrimitive("request_unknown"))
                })
            })
            assertEquals(AssistedStep.Stopped(WireAssistedRecovery.REQUEST_UNKNOWN), d.assisted.poll(waiting))
            assertEquals(listOf(origin), d.assisted.keptOrigins(), "the request is kept")
            val awaiting = assertIs<AssistedStep.Waiting>(d.assisted.poll(waiting), "the honest poll goes on")

            assertIs<Reauthed.Done<Unit>>(op.fulfil(dRequest, answer, Steps.PASSWORD.toCharArray()))
            val wrong = proxy.on(WireRoute.RECOVERY_REQUEST_POLL, "d", handler = editAnswer { it.set("commitHash", "0".repeat(64)) })
            val mark = proxy.mark()
            assertEquals(AssistedStep.Stopped(WireAssistedRecovery.COMMIT_MISMATCH), d.assisted.poll(awaiting), "W: said before any question")
            assertEquals(listOf(origin), d.assisted.keptOrigins(), "the request is kept")
            assertTrue(proxy.requests(tag = "d", since = mark).all { it.route == WireRoute.RECOVERY_REQUEST_POLL || it.route == WireRoute.INSTANCE }, "nothing more is sent")
            wrong.remove()
            val right = proxy.on(WireRoute.RECOVERY_REQUEST_POLL, "d", times = 1, handler = editAnswer { it.set("commitHash", answer.commitHash) })
            assertIs<AssistedStep.CheckAccount>(d.assisted.poll(awaiting), "the stored answer's own hash: on")
            right.remove()
            val again = assertIs<AssistedStep.CheckAccount>(d.assisted.resume(origin), "no field: as before")
            val choose = assertIs<AssistedStep.ChoosePassword>(d.assisted.confirmAccount(again, same = true))
            assertIs<AssistedStep.Recovered>(d.assisted.commit(choose, "a new Passphrase for alice 4".toCharArray()))
        }
}
