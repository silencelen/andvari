package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.core.client.account.Fetched
import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.recovery.AssistedStep
import io.silencelen.andvari.core.client.recovery.LiveRecoveryRequests
import io.silencelen.andvari.core.client.recovery.VetoOutcome
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
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

/**
 * The account's own list of recovery requests (`GET /account/recovery-requests`, index row 29): an
 * answered request is listed by the real server as `ready`, and the account's devices must keep seeing it, and be able to
 * cancel it, until it is committed. Then the server lies about that list.
 */
class RecoveryRequestListLiesTest {
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
     * Honest: after the operator's upload the real server lists the request as `ready`; Alice's device lists it (before,
     * the whole list was refused as `bad_response` from that moment) and cancels it, and the requester's device is told.
     * Lies (the list as the server sends it, with the honest rows in it): a row in a state the specification does not name,
     * a row whose id is not one, a row that is not an object (each: that row dropped and counted, the others kept); every
     * row unreadable (an empty list that says how many were dropped); a body that is not a list (no answer, `Unreachable`).
     */
    @Test fun anAnsweredRequestIsListedAndCancelledAndOneUnreadableRowNeverEmptiesTheList() =
        world(extraSetup = listOf("--recovery-pubkey", Bytes.toB64(recoveryPub))) {
            val oh = operator()
            val ah = member("alice")
            val settings = ah.recoverySettings(ah.session(origin)!!)
            assertIs<Reauthed.Done<*>>(settings.setPosture(RecoveryChoiceKind.OPERATOR, settings.operatorOffer()!!, true, Steps.PASSWORD.toCharArray()))
            val uvk = ah.session(origin)!!.session.account.uvk.copyOut()
            val instanceId = oh.trust.pinFor(origin)!!.instanceId
            val (d, waiting) = asking("d")
            val (_, _) = asking("e")
            server.advance(7 * 86_400_000L + 60_000)
            val op = oh.operator(oh.session(origin)!!)
            val dRequest = proxy.last(WireRoute.RECOVERY_REQUEST_CREATE, "d")!!.upstream!!.json!!.let { (it["requestId"] as JsonPrimitive).content }
            val dRow = assertIs<Fetched.Ok<List<AdminRecoveryRequest>>>(op.recoveryRequests()).value.single { it.requestId == dRequest }
            assertIs<Reauthed.Done<Unit>>(op.fulfil(dRequest, answerFor(dRow, instanceId, uvk), Steps.PASSWORD.toCharArray()))

            val requests = ah.recoveryRequests(ah.session(origin)!!)
            val listed = assertIs<LiveRecoveryRequests.Listed>(requests.live(), "the real server's list after an upload")
            assertEquals(RecoveryRequestState.READY, listed.requests.single { it.requestId == dRequest }.state)
            assertEquals(2, listed.requests.size)
            assertEquals(0, listed.unreadable)

            // The lies, each over the honest body.
            val honest = Json.parseToJsonElement(proxy.last(WireRoute.ACCOUNT_RECOVERY_REQUESTS, "alice")!!.upstream!!.text!!).jsonArray
            fun serve(rows: JsonElement) = proxy.on(WireRoute.ACCOUNT_RECOVERY_REQUESTS, "alice", times = 1, handler = answer { Resp.json(200, rows) })
            val bogusState = JsonObject(honest[0].jsonObject + ("state" to JsonPrimitive("granted")))
            val bogusId = JsonObject(honest[0].jsonObject + ("requestId" to JsonPrimitive("not an id")))
            for ((what, row) in listOf("a state not named" to bogusState, "an id that is not one" to bogusId, "a row that is not an object" to JsonPrimitive(7))) {
                serve(JsonArray(honest + row))
                val l = assertIs<LiveRecoveryRequests.Listed>(requests.live(), what)
                assertEquals(honest.size, l.requests.size, "$what: the honest rows are kept")
                assertEquals(1, l.unreadable, "$what: the row is dropped and counted")
            }
            serve(JsonArray(listOf(bogusState, bogusId)))
            val none = assertIs<LiveRecoveryRequests.Listed>(requests.live())
            assertEquals(0, none.requests.size)
            assertEquals(2, none.unreadable, "an empty list that says rows were dropped")
            serve(buildJsonObject { put("requests", JsonArray(honest)) })
            assertEquals(LiveRecoveryRequests.Unreachable, requests.live(), "a body that is not a list is no answer")

            // The answered request is cancelled from the account's device, and its requester is told.
            assertEquals(VetoOutcome.Vetoed, requests.veto(dRequest))
            assertEquals(AssistedStep.Stopped(RecoveryRequestState.VETOED), d.assisted.poll(waiting))
        }
}
