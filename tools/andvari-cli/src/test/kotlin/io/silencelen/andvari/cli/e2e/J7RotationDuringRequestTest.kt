package io.silencelen.andvari.cli.e2e

import io.silencelen.andvari.cli.CardOps
import io.silencelen.andvari.cli.CardWrite
import io.silencelen.andvari.core.client.account.Fetched
import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.recovery.AssistedStep
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.AdminEscrowResponse
import io.silencelen.andvari.core.model.wire.AdminRecoveryRequest
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.trust.AnswerRead
import io.silencelen.andvari.core.trust.AnswerToken
import java.io.File
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * A signed rotation of the recovery key while an assisted-recovery request is open, and an account that has not sealed a
 * new copy since (spec 04 §5, "A copy sealed to an outgoing key"). The copy is
 * sealed to the outgoing key, and every device now takes only an answer signed by the current one. With one sheet the
 * operator cannot answer: the current sheet does not open the copy, and the outgoing sheet's answer is refused by the
 * device. With the server's `GET /instance` answer and both sheets, `recovery-cli assist` opens with the outgoing seed and
 * signs with the current one, and the device takes the answer. Every seed here is a made-up test seed.
 */
class J7RotationDuringRequestTest {
    private val crypto = createCryptoProvider()
    private val outgoing = crypto.randomBytes(32)
    private val current = crypto.randomBytes(32)
    private val outgoingPub = crypto.boxKeypairFromSeed(outgoing).publicKey
    private val currentPub = crypto.boxKeypairFromSeed(current).publicKey

    /** The offline tool in its own process, as the operator runs it: its exit status, standard output and standard error. */
    private class Ran(val status: Int, val out: String, val err: String)

    private fun runTool(args: List<String>, stdin: String): Ran {
        val java = File(System.getProperty("java.home"), "bin/java").path
        val p = ProcessBuilder(listOf(java, "-cp", System.getProperty("java.class.path"), "io.silencelen.andvari.recovery.MainKt") + args).start()
        p.outputStream.use { it.write(stdin.toByteArray()) }
        val out = p.inputStream.bufferedReader().readText()
        val err = p.errorStream.bufferedReader().readText()
        return Ran(p.waitFor(), out, err)
    }

    @Test fun aRotationWhileARequestIsOpen_isAnsweredWithTwoSheets() {
        TestServer(extraSetup = listOf("--recovery-pubkey", Bytes.toB64(outgoingPub))).use { it.journey { val s = this
            val instanceId = s.setup["instanceId"]!!.toString().trim('"')
            val oh = s.device("operator")
            Steps.registerThrough(oh, s.origin, s.setupLink, "op@example.org")
            val ah = s.device("alice laptop")
            val reg = Steps.registerThrough(ah, s.origin, Steps.enrolLink(s), "alice@example.org", trustGate = true)
            val settings = ah.recoverySettings(ah.session(s.origin)!!)
            assertIs<Reauthed.Done<*>>(settings.setPosture(RecoveryChoiceKind.OPERATOR, settings.operatorOffer()!!, true, Steps.PASSWORD.toCharArray()))

            // Alice's request is open (verified, holding) on a new device.
            val d = s.device("alice new phone")
            val target = assertIs<AssistedStep.ConfirmTarget>(d.assisted.start("alice@example.org", s.origin))
            val requested = assertIs<AssistedStep.Requested>(d.assisted.request(target))
            val waiting = assertIs<AssistedStep.Waiting>(d.assisted.verifyCode(requested, Steps.awaitCode(s, "alice@example.org", "recovery_request_code")))

            // Meanwhile the operator rotates the recovery key, honestly: the statement stored, then card 1 signed.
            val rotateOut = runTool(listOf("rotate", "--instance", instanceId, "--to", Bytes.toB64(currentPub)), Bytes.toB64(outgoing) + "\n")
            assertEquals(0, rotateOut.status, rotateOut.err)
            val ops = CardOps(oh, oh.session(s.origin)!!)
            assertIs<CardWrite.Stored>(ops.storeRotation(rotateOut.out.trim().lines().last(), Steps.PASSWORD.toCharArray()))
            val currentFp = Escrow.fingerprint(crypto, currentPub)
            assertIs<CardWrite.Stored>(ops.sign(Steps.PASSWORD.toCharArray(), recoveryFp = currentFp))
            s.restart(mapOf("ANDVARI_RECOVERY_PUBKEY" to Bytes.toB64(currentPub), "ANDVARI_RECOVERY_FINGERPRINT" to currentFp))
            // Alice does not unlock anywhere: her copy stays sealed to the outgoing key.

            s.advance(7 * 86_400_000L + 60_000)
            val op = oh.operator(oh.session(s.origin)!!)
            val req = assertIs<Fetched.Ok<List<AdminRecoveryRequest>>>(op.recoveryRequests()).value.single()
            val escrow = assertIs<Reauthed.Done<AdminEscrowResponse>>(op.escrow(req.userId, Steps.PASSWORD.toCharArray())).value
            val idFile = File(s.dir, "escrow.json").also { f -> f.writeText(WireJson.json.encodeToString(AdminEscrowResponse.serializer(), escrow)) }
            val assist = listOf(
                "assist", "--instance", instanceId, "--request", req.requestId, "--request-key", req.rPub, "--request-code", requested.requestCode,
                "--email", "alice@example.org", "--user", req.userId, "--identity-fp", reg.kit.accountId, "--identity-file", idFile.path,
            )
            val confirm = "RECOVER ${req.userId.take(8)}\n"

            // 1. The current sheet alone does not open the copy (what the tool did before, and still does without the file).
            val one = runTool(assist, Bytes.toB64(current) + "\n" + confirm)
            assertEquals(1, one.status, one.err)
            assertTrue("REFUSED (unopenable)" in one.err && "--instance-file" in one.err, one.err)

            // 2. The outgoing sheet alone makes an answer, and the device refuses it: it takes only the current key's.
            val old = runTool(assist, Bytes.toB64(outgoing) + "\n" + confirm)
            assertEquals(0, old.status, old.err)
            val oldAnswer = assertIs<AnswerRead.Ok>(AnswerToken.read(old.out, req.requestId, req.rPub, req.email))
            assertIs<Reauthed.Done<Unit>>(op.fulfil(req.requestId, oldAnswer, Steps.PASSWORD.toCharArray()))
            val refused = d.assisted.poll(waiting)
            assertEquals(AssistedStep.Stopped("signer_not_pinned_key"), refused, "the device refuses an answer the outgoing key signed")

            // 3. With the server's GET /instance answer and both sheets: the outgoing one opens, the current one signs.
            val served = HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI("${s.listenAddress}/api/v1/instance")).build(), HttpResponse.BodyHandlers.ofString())
            assertEquals(200, served.statusCode())
            val instanceFile = File(s.dir, "instance.json").also { f -> f.writeText(served.body()) }
            // The file is the server's word: the tool checks it from the hash of the first card, which the operator's own
            // device pinned (what `card show` prints).
            val card0 = oh.trust.pinFor(s.origin)!!.card0Hash
            val two = runTool(assist + listOf("--instance-file", instanceFile.path, "--card0-hash", card0), Bytes.toB64(current) + "\n" + Bytes.toB64(outgoing) + "\n" + confirm)
            assertEquals(0, two.status, two.err)
            assertTrue("OUTGOING sheet: ${Escrow.fingerprint(crypto, outgoingPub).take(4)}" in two.err, two.err)
            val answer = assertIs<AnswerRead.Ok>(AnswerToken.read(two.out, req.requestId, req.rPub, req.email))
            assertIs<Reauthed.Done<Unit>>(op.fulfil(req.requestId, answer, Steps.PASSWORD.toCharArray()), "the upload is repeated until the commit")
            val check = assertIs<AssistedStep.CheckAccount>(d.assisted.poll(waiting), "the device takes the answer the current key signed")
            assertEquals(reg.kit.accountId, check.accountId)
            val choose = assertIs<AssistedStep.ChoosePassword>(d.assisted.confirmAccount(check, same = true))
            val done = assertIs<AssistedStep.Recovered>(d.assisted.commit(choose, "recovered after a rotation 88".toCharArray()), "the reset goes through")
            assertEquals(reg.userId, done.userId)
        } }
    }
}
