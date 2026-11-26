package io.silencelen.andvari.cli.e2e

import io.silencelen.andvari.cli.CardOps
import io.silencelen.andvari.cli.CardWrite
import io.silencelen.andvari.core.client.account.Fetched
import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.account.RecoveryPostureView
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.recovery.AssistedStep
import io.silencelen.andvari.core.client.recovery.LiveRecoveryRequests
import io.silencelen.andvari.core.client.recovery.VetoOutcome
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.AdminEscrowResponse
import io.silencelen.andvari.core.model.wire.WireJson
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Journey 7, a private instance: operator recovery turned on, a rotation of the recovery key, assisted recovery with
 * `recovery-cli assist` producing the sealed answer, the account check, the commit; and a veto from a signed-in device.
 */
class J7OperatorRecoveryTest {
    private val crypto = createCryptoProvider()
    private val seed1 = crypto.randomBytes(32)
    private val seed2 = crypto.randomBytes(32)
    private val pub1 = crypto.boxKeypairFromSeed(seed1).publicKey
    private val pub2 = crypto.boxKeypairFromSeed(seed2).publicKey
    private val newPw = "recovered by the Operator 77"

    @Test fun operatorRecoveryRotationAssistedRecoveryAndVeto() {
        TestServer(extraSetup = listOf("--recovery-pubkey", Bytes.toB64(pub1))).use { it.journey { val s = this
            val instanceId = s.setup["instanceId"]!!.toString().trim('"')
            val oh = s.device("operator")
            Steps.registerThrough(oh, s.origin, s.setupLink, "op@example.org")
            assertEquals(Escrow.fingerprint(crypto, pub1), oh.trust.pinFor(s.origin)!!.recoveryFp, "card 0 names the recovery key")
            val ah = s.device("alice laptop")
            val reg = Steps.registerThrough(ah, s.origin, Steps.enrolLink(s), "alice@example.org", trustGate = true)

            // Operator recovery turned on from Settings.
            val settings = ah.recoverySettings(ah.session(s.origin)!!)
            val offer = assertNotNull(settings.operatorOffer(), "a private card with a recovery key offers operator recovery")
            val on = settings.setPosture(RecoveryChoiceKind.OPERATOR, offer, understood = true, password = Steps.PASSWORD.toCharArray())
            assertEquals("operator", assertIs<Reauthed.Done<*>>(on, "operator recovery on: $on").value.let { (it as io.silencelen.andvari.core.client.state.RecoveryRecord).posture })

            // A rotation of the recovery key: the offline statement, stored; card 1 names the new key; the server serves it.
            val rotateOut = s.recoveryCli(listOf("rotate", "--instance", instanceId, "--to", Bytes.toB64(pub2)), Bytes.toB64(seed1) + "\n")
            val statement = rotateOut.trim().lines().last()
            val ops = CardOps(oh, oh.session(s.origin)!!)
            assertIs<CardWrite.Stored>(ops.storeRotation(statement, Steps.PASSWORD.toCharArray()), "the rotation is stored")
            val fp2 = Escrow.fingerprint(crypto, pub2)
            assertEquals(1L, assertIs<CardWrite.Stored>(ops.sign(Steps.PASSWORD.toCharArray(), recoveryFp = fp2), "card 1").seq)
            s.restart(mapOf("ANDVARI_RECOVERY_PUBKEY" to Bytes.toB64(pub2), "ANDVARI_RECOVERY_FINGERPRINT" to fp2))
            // Alice's device follows the signed rotation and re-seals her escrow to the new key without asking.
            val posture = assertIs<Fetched.Ok<RecoveryPostureView>>(ah.recoverySettings(ah.session(s.origin)!!).posture(), "posture").value
            assertEquals(fp2, posture.record?.fp, "the escrow follows the rotation: $posture")

            // Assisted recovery on a fresh device.
            val d = s.device("alice new phone")
            var st = d.assisted.start("alice@example.org", s.origin)
            val target = assertIs<AssistedStep.ConfirmTarget>(st, "assisted target: $st")
            val requested = assertIs<AssistedStep.Requested>(d.assisted.request(target), "requested")
            val code = Steps.awaitCode(s, "alice@example.org", "recovery_request_code")
            val waiting = assertIs<AssistedStep.Waiting>(d.assisted.verifyCode(requested, code), "the emailed code verifies")
            assertEquals("holding", waiting.state)
            s.advance(7 * 86_400_000L + 60_000)
            val op = oh.operator(oh.session(s.origin)!!)
            val req = assertIs<Fetched.Ok<List<io.silencelen.andvari.core.model.wire.AdminRecoveryRequest>>>(op.recoveryRequests()).value.single()
            assertEquals(reg.userId, req.userId)
            val escrow = assertIs<Reauthed.Done<AdminEscrowResponse>>(op.escrow(req.userId, Steps.PASSWORD.toCharArray()), "escrow download").value
            val idFile = File(s.dir, "escrow.json").also { it.writeText(WireJson.json.encodeToString(AdminEscrowResponse.serializer(), escrow)) }
            val assistOut = s.recoveryCli(
                listOf("assist", "--instance", instanceId, "--request", req.requestId, "--request-key", req.rPub, "--request-code", requested.requestCode,
                    "--email", "alice@example.org", "--user", req.userId, "--identity-fp", reg.kit.accountId, "--identity-file", idFile.path),
                Bytes.toB64(seed2) + "\n" + "RECOVER ${req.userId.take(8)}\n",
            )
            // The tool's whole output, read by the one shared reader of an answer (spec 04 §7 step 3).
            val answer = assertIs<io.silencelen.andvari.core.trust.AnswerRead.Ok>(io.silencelen.andvari.core.trust.AnswerToken.read(assistOut, req.requestId, req.rPub, req.email))
            assertIs<Reauthed.Done<Unit>>(op.fulfil(req.requestId, answer, Steps.PASSWORD.toCharArray()), "fulfil")
            val check = assertIs<AssistedStep.CheckAccount>(d.assisted.poll(waiting), "the answer verifies")
            assertEquals(reg.kit.accountId, check.accountId, "the delivered account is the one on the kit")
            val choose = assertIs<AssistedStep.ChoosePassword>(d.assisted.confirmAccount(check, same = true))
            val done = assertIs<AssistedStep.Recovered>(d.assisted.commit(choose, newPw.toCharArray()), "commit")
            Steps.confirmKit(d.onboarding(s.origin), done.newKit)

            // A second request from a stranger's device; the signed-in device sees it and vetoes.
            val e = s.device("attacker")
            val t2 = assertIs<AssistedStep.ConfirmTarget>(e.assisted.start("alice@example.org", s.origin))
            // The count waits until no earlier code mail is still on its way, so the next one awaited is this request's.
            val seen = Steps.mailCount(s, "alice@example.org", "recovery_request_code")
            val r2 = assertIs<AssistedStep.Requested>(e.assisted.request(t2))
            val w2 = assertIs<AssistedStep.Waiting>(e.assisted.verifyCode(r2, Steps.awaitCode(s, "alice@example.org", "recovery_request_code", seen)))
            val live = assertIs<LiveRecoveryRequests.Listed>(d.recoveryRequests(d.session(s.origin)!!).live(), "the signed-in device lists the request")
            val id = live.requests.single().requestId
            assertEquals(VetoOutcome.Vetoed, d.recoveryRequests(d.session(s.origin)!!).veto(id))
            val after = e.assisted.poll(w2)
            assertTrue(after is AssistedStep.Stopped, "a vetoed request stops: $after")
        } }
    }
}
