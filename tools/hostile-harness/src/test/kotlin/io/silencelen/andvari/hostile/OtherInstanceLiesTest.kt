package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.core.client.account.CardChangeResult
import io.silencelen.andvari.core.client.account.Fetched
import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.account.WireOperatorCards
import io.silencelen.andvari.core.client.account.WireOperatorRoutes
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.pin.CardStatus
import io.silencelen.andvari.core.client.recovery.AssistedStep
import io.silencelen.andvari.core.client.state.RecoveryRecord
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.AdminPolicy
import io.silencelen.andvari.core.model.wire.AdminRecoveryRequest
import io.silencelen.andvari.core.model.wire.AdminStatus
import io.silencelen.andvari.core.model.wire.AuditRow
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.AssistedRecovery
import io.silencelen.andvari.hostile.proxy.Handler
import io.silencelen.andvari.hostile.proxy.answer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * **A** lies that need a second instance: two real servers side by side ([World.another]), and one instance's real
 * answers, as its own operator read them, served for the other instance's routes. Most dangerous first: the operator's
 * card upload (a pin must never follow an answer), then the operator's reads (requests, audit, status, policy), which
 * are the operator's own server speaking (design §9.2) and so may show another instance's words, as long as they decide
 * nothing: only reads are sent, the pinned card still decides what the instance offers, and no request row of another
 * instance passes the code a person of this one reads out.
 */
class OtherInstanceLiesTest {
    private val crypto = createCryptoProvider()
    private val password get() = Steps.PASSWORD.toCharArray()

    private fun recoveryArgs() = listOf("--recovery-pubkey", Bytes.toB64(crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey))

    private suspend fun World.optIn(h: Host): RecoveryRecord {
        val s = h.recoverySettings(h.session(origin)!!)
        return assertIs<Reauthed.Done<RecoveryRecord>>(s.setPosture(RecoveryChoiceKind.OPERATOR, assertNotNull(s.operatorOffer()), understood = true, password = password)).value
    }

    private suspend fun World.verified(tag: String, email: String): AssistedStep.Waiting {
        val seen = Steps.mailCount(server, email, "recovery_request_code")
        val d = device(tag)
        val req = assertIs<AssistedStep.Requested>(d.assisted.request(assertIs<AssistedStep.ConfirmTarget>(d.assisted.start(email, origin))))
        return assertIs<AssistedStep.Waiting>(d.assisted.verifyCode(req, Steps.awaitCode(server, email, "recovery_request_code", seen)))
    }

    private fun World.ops(op: Host): WireOperatorRoutes = op.operator(op.session(origin)!!)

    /** Every request [tag] sent since [mark] was a read. */
    private fun World.onlyReads(tag: String, mark: Int, what: String) {
        val sent = proxy.requests(tag = tag, since = mark)
        assertTrue(sent.all { it.route?.method == "GET" }, "$what: nothing but reads is sent (${sent.map { it.route }})")
    }

    /**
     * `PUT /instance/card` (row 3) answered with the other instance's real answer to its own operator's card change (A):
     * stored here first, or never passed on. Either way the answer names a card this device did not sign: refused as
     * `card_mismatch`, never "changed" nor "stored", and the operator's and a member's pins follow only the chain this
     * server serves (the stored card when it was stored, the one held before when it was not).
     */
    @Test fun anotherInstancesCardUploadAnswerIsAMismatchAndMovesNoPin() = world {
        val oh = operator()
        val ah = member("alice")
        val cards = oh.operatorCards(assertNotNull(oh.session(origin)))
        suspend fun opPin() = assertIs<CardStatus.Ok>(oh.trust.refresh(origin)).pin
        suspend fun alicePin() = assertIs<CardStatus.Ok>(ah.trust.refresh(origin)).pin

        val other = another()
        val ob = other.operator()
        val theirCards = ob.operatorCards(assertNotNull(ob.session(other.origin)))
        assertIs<CardChangeResult.Changed>(theirCards.rename("Elsewhere 1", password))
        val theirs = other.realAnswer(WireRoute.INSTANCE_CARD_PUT, "op")
        assertTrue(theirs.ok, "the other instance's own operator changed its card: $theirs")

        // Stored here, answered with the other instance's answer.
        val stored = proxy.on(WireRoute.INSTANCE_CARD_PUT, "op", handler = Handler { x -> x.forward(); theirs })
        val got = cards.rename("Home 2", password)
        stored.remove()
        assertEquals(WireOperatorCards.CARD_MISMATCH, assertIs<CardChangeResult.Refused>(got, "$got").code)
        assertEquals("Home 2", opPin().name, "the operator's device pins the stored card, through this server's chain")
        assertEquals("Home 2", alicePin().name, "and so does a member's")
        val held = opPin()

        // Never passed on, answered with the other instance's answer: no pin moves.
        val notStored = proxy.on(WireRoute.INSTANCE_CARD_PUT, "op", handler = answer { theirs })
        val claimed = cards.rename("never stored", password)
        notStored.remove()
        assertEquals(WireOperatorCards.CARD_MISMATCH, assertIs<CardChangeResult.Refused>(claimed, "$claimed").code)
        assertEquals(held.hash, opPin().hash)
        assertEquals(held.hash, alicePin().hash)
        assertTrue(other.proxy.requests(tag = "op").none { it.route == WireRoute.INSTANCE_CARD_PUT && it.text.contains("never stored") },
            "nothing of this instance reached the other")
    }

    /**
     * The operator's reads answered with the other instance's real answers, as its own operator read them (A): the
     * recovery requests (row 84), the audit (82), status (83) and policy (80). Each is shown as served (the server
     * speaks about itself; nothing in these answers names the instance, so the device cannot tell: the stated limit, as
     * for W), and decides nothing: only reads are sent, the pinned card still decides that this instance offers operator
     * recovery, and no row of the other instance's requests passes the request code this instance's member reads out,
     * so `recovery-cli assist` would refuse to answer it.
     */
    @Test fun anotherInstancesOperatorViewsAreShownAsServedAndDecideNothing() = world(extraSetup = recoveryArgs()) {
        val op = operator()
        optIn(member("alice"))
        val aw = verified("areq", "alice@example.org")

        val other = another(extraSetup = recoveryArgs())
        val ob = other.operator()
        other.optIn(other.member("bob"))
        other.verified("breq", "bob@example.org")
        val bops = other.ops(ob)
        val theirRequests = assertIs<Fetched.Ok<List<AdminRecoveryRequest>>>(bops.recoveryRequests()).value
        val theirAudit = assertIs<Fetched.Ok<List<AuditRow>>>(bops.audit()).value
        val theirStatus = assertIs<Fetched.Ok<AdminStatus>>(bops.status()).value
        val theirPolicy = assertIs<Fetched.Ok<AdminPolicy>>(bops.policy()).value
        val served = listOf(WireRoute.ADMIN_RECOVERY_REQUESTS, WireRoute.ADMIN_AUDIT, WireRoute.ADMIN_STATUS, WireRoute.ADMIN_POLICY_GET)
            .associateWith { other.realAnswer(it, "op") }

        val ops = ops(op)
        val ours = assertIs<Fetched.Ok<List<AdminRecoveryRequest>>>(ops.recoveryRequests()).value
        assertTrue(ours.any { AssistedRecovery.requestCodeMatches(crypto, aw.requestCode, Bytes.fromB64(it.rPub)) }, "the honest list passes Alice's code")
        val mark = proxy.mark()
        val rules = served.map { (route, resp) -> proxy.on(route, "op", handler = answer { resp }) }

        val shown = assertIs<Fetched.Ok<List<AdminRecoveryRequest>>>(ops.recoveryRequests()).value
        assertEquals(theirRequests, shown, "the other instance's requests, shown as served")
        assertTrue(shown.isNotEmpty() && shown.none { AssistedRecovery.requestCodeMatches(crypto, aw.requestCode, Bytes.fromB64(it.rPub)) },
            "no row of another instance passes the code Alice reads out")
        assertEquals(theirAudit, assertIs<Fetched.Ok<List<AuditRow>>>(ops.audit()).value, "the other instance's audit, shown as served")
        assertEquals(theirStatus, assertIs<Fetched.Ok<AdminStatus>>(ops.status()).value, "the other instance's status, shown as served")
        assertEquals(theirPolicy, assertIs<Fetched.Ok<AdminPolicy>>(ops.policy()).value, "the other instance's policy, shown as served")
        assertTrue(ops.recoveryRequests() != Fetched.Refused(WireOperatorRoutes.OPERATOR_RECOVERY_UNAVAILABLE), "the pinned card decides, not the answers")
        rules.forEach { it.remove() }

        onlyReads("op", mark, "another instance's views")
        assertEquals(ours.map { it.requestId }, assertIs<Fetched.Ok<List<AdminRecoveryRequest>>>(ops.recoveryRequests()).value.map { it.requestId },
            "the honest list again, once the server stops lying")
    }
}
