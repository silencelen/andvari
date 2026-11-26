package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.core.client.account.Fetched
import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.account.RecoveryPostureView
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.RevealedKit
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.client.recovery.AssistedStep
import io.silencelen.andvari.core.client.recovery.KitRecoveryStep
import io.silencelen.andvari.core.client.state.RecoveryRecord
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.AdminEscrowResponse
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.RecoveryKit
import io.silencelen.andvari.hostile.proxy.Resp
import io.silencelen.andvari.hostile.proxy.answer
import io.silencelen.andvari.hostile.proxy.editAnswer
import io.silencelen.andvari.hostile.proxy.set
import io.silencelen.andvari.hostile.proxy.str
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.long
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The routes of the last row that carry key material, an identity, or a state the app shows, most dangerous first: the
 * assisted request's create and verify, `PUT /account/recovery`, `PUT /recovery/self-setup` and the operator's escrow
 * route. Each lie is another account's answer (A), an earlier one of the same account (R), the right answer with a field
 * changed (W), or a shape the route never gives (X).
 */
class RecoveryRouteLiesTest {
    private val crypto = createCryptoProvider()
    private val password get() = Steps.PASSWORD.toCharArray()
    private val seed = crypto.randomBytes(32)
    private val recoveryPub = crypto.boxKeypairFromSeed(seed).publicKey

    private fun recoveryWorld(block: suspend World.() -> Unit) = world(extraSetup = listOf("--recovery-pubkey", Bytes.toB64(recoveryPub)), block = block)

    private fun json(vararg fields: Pair<String, Any>): JsonObject = buildJsonObject {
        for ((k, v) in fields) put(k, if (v is Number) JsonPrimitive(v) else JsonPrimitive(v.toString()))
    }

    /** [h] opts in to operator recovery (the escrow sealed to the pinned card's key): `PUT /account/recovery`. */
    private suspend fun World.optIn(h: Host): RecoveryRecord {
        val s = h.recoverySettings(h.session(origin)!!)
        return assertIs<Reauthed.Done<RecoveryRecord>>(s.setPosture(RecoveryChoiceKind.OPERATOR, assertNotNull(s.operatorOffer()), understood = true, password = password)).value
    }

    /** A fresh device [tag] confirms "ask the operator" for [email]: the device, and the answer of `POST /recovery/requests`. */
    private suspend fun World.request(tag: String, email: String): Pair<Host, AssistedStep> {
        val d = device(tag)
        return d to d.assisted.request(assertIs<AssistedStep.ConfirmTarget>(d.assisted.start(email, origin)))
    }

    private fun World.created(tag: String): String = proxy.last(WireRoute.RECOVERY_REQUEST_CREATE, tag)!!.upstream!!.json!!.str("requestId")!!

    /**
     * `POST /recovery/requests` (index row 68) answered with an id that is not one, `ok`, or `{}` (not passed on): the
     * flow stops, nothing is kept and nothing more is sent. Passed on (the server opened Alice's real request and mailed
     * her the code) and answered with Bob's live request id (A) or Alice's own earlier one (R): the device cannot tell
     * and shows "requested", but the code from Alice's email is `bad_code` there, the step never becomes a hold, and a
     * poll is never "check the account": no request the device did not open leads anywhere.
     */
    @Test fun aRequestCreateAnswerThatIsNotThisRequestsIdNeverLeadsPastTheEmailedCode() = recoveryWorld {
        operator()
        optIn(member("alice"))
        optIn(member("bob"))
        assertIs<AssistedStep.Requested>(request("bobreq", "bob@example.org").second)
        val bobs = created("bobreq")
        assertIs<AssistedStep.Requested>(request("early", "alice@example.org").second)
        val earlier = created("early")

        val shapes = listOf(
            "an id that is not one (W)" to Resp.json(202, json("requestId" to "not-an-id")),
            "a plain ok (X)" to Resp.ok(),
            "an empty object (X)" to Resp.json(202, json()),
        )
        for ((i, lie) in shapes.withIndex()) {
            val tag = "w$i"
            proxy.on(WireRoute.RECOVERY_REQUEST_CREATE, tag, handler = answer { lie.second })
            val (dev, out) = request(tag, "alice@example.org")
            assertIs<AssistedStep.Stopped>(out, "${lie.first}: $out")
            assertTrue(dev.assisted.keptOrigins().isEmpty(), "${lie.first}: nothing is kept")
            val d = proxy.requests(tag = tag).filter { it.route == WireRoute.RECOVERY_REQUEST_VERIFY || it.route == WireRoute.RECOVERY_REQUEST_POLL }
            assertTrue(d.isEmpty(), "${lie.first}: nothing more is sent")
        }
        for ((i, lie) in listOf("Bob's live request (A)" to bobs, "Alice's own earlier request (R)" to earlier).withIndex()) {
            val tag = "a$i"
            val seen = Steps.mailCount(server, "alice@example.org", "recovery_request_code")
            proxy.on(WireRoute.RECOVERY_REQUEST_CREATE, tag, handler = editAnswer { it.set("requestId", lie.second) })
            val (dev, step) = request(tag, "alice@example.org")
            val requested = assertIs<AssistedStep.Requested>(step, lie.first)
            val code = Steps.awaitCode(server, "alice@example.org", "recovery_request_code", seen)
            val verified = dev.assisted.verifyCode(requested, code)
            assertEquals(AssistedStep.Stopped("bad_code"), verified, "${lie.first}: the code of Alice's request opens no other")
            assertEquals(lie.second, proxy.last(WireRoute.RECOVERY_REQUEST_VERIFY, tag)!!.req.param("requestId"))
            val polled = dev.assisted.poll(requested)
            assertTrue(polled !is AssistedStep.CheckAccount && polled !is AssistedStep.ChoosePassword && polled !is AssistedStep.Waiting, "${lie.first}: $polled")
        }
        assertEquals(0, Steps.mailCount(server, "alice@example.org", "recovery_request_open"), "no hold began for any request of Alice's")
    }

    /**
     * `POST /recovery/requests/{id}/verify` (row 69) answered, without passing it on, with a hold that ended long ago,
     * one that never ends with `ready` as the state, `{}`, or `ok`. The hold and the state are the server's word (R27: the
     * server can fake the code, the hold and "ready"), so the device shows a hold (`holding`, whatever state was named)
     * or stops with the step kept; nothing is sent on its own, and the next poll is never "check the account" without
     * the operator's signed answer. The honest code then verifies.
     */
    @Test fun aRequestVerifyAnswerThatLiesAboutTheHoldNeverLeadsPastWaiting() = recoveryWorld {
        operator()
        optIn(member("alice"))
        val seen = Steps.mailCount(server, "alice@example.org", "recovery_request_code")
        val (d, step) = request("v", "alice@example.org")
        val requested = assertIs<AssistedStep.Requested>(step)
        val code = Steps.awaitCode(server, "alice@example.org", "recovery_request_code", seen)
        for ((what, lie) in listOf("an empty object (X)" to Resp.json(200, json()), "a plain ok (X)" to Resp.ok())) {
            val rule = proxy.on(WireRoute.RECOVERY_REQUEST_VERIFY, "v", handler = answer { lie })
            assertEquals(AssistedStep.Stopped("unreachable"), d.assisted.verifyCode(requested, code), what)
            rule.remove()
        }
        // The step stayed: the honest code verifies Alice's request and the real hold begins.
        val honest = assertIs<AssistedStep.Waiting>(d.assisted.verifyCode(requested, code), "the honest verify after the lies")
        assertTrue((honest.holdEndsAt ?: 0) > server.now(), "$honest")

        for ((i, lie) in listOf(
            "a hold that ended long ago (W)" to json("state" to "holding", "holdEndsAt" to -1L),
            "ready, and a hold that never ends (W)" to json("state" to "ready", "holdEndsAt" to Long.MAX_VALUE),
        ).withIndex()) {
            val what = lie.first
            val tag = "w$i"
            val before = Steps.mailCount(server, "alice@example.org", "recovery_request_code")
            val (dw, sw) = request(tag, "alice@example.org")
            val step = assertIs<AssistedStep.Requested>(sw, what)
            val wCode = Steps.awaitCode(server, "alice@example.org", "recovery_request_code", before)
            proxy.on(WireRoute.RECOVERY_REQUEST_VERIFY, tag, handler = answer { Resp.json(200, lie.second) })
            val mark = proxy.mark()
            val waiting = assertIs<AssistedStep.Waiting>(dw.assisted.verifyCode(step, wCode), what)
            assertEquals("holding", waiting.state, "$what: the device's state, not the server's word")
            assertEquals(lie.second["holdEndsAt"]!!.jsonPrimitive.long, waiting.holdEndsAt, "$what: the hold is the server's word, shown as such")
            assertTrue(proxy.requests(tag = tag, since = mark).all { it.route == WireRoute.RECOVERY_REQUEST_VERIFY }, "$what: nothing else is sent")
            val polled = dw.assisted.poll(waiting)
            assertTrue(polled !is AssistedStep.CheckAccount && polled !is AssistedStep.ChoosePassword, "$what: $polled")
        }
    }

    /**
     * `PUT /account/recovery` (row 22) answered, after the server stored the change, with Bob's answer of the same route
     * (A), Alice's own earlier one (R), the right answer with its `seq` far ahead or negative (W), `{}` or `ok` (X).
     * Only the answer's `seq` is read (as the account state's next compare-and-set); the blob is never taken. The person's
     * choice is what the server then holds and shows, never Bob's, and the next change works (at most one `stale_state`
     * round, which the device absorbs).
     */
    @Test fun aRecoveryChoiceAnswerOfAnotherAccountOrAnEarlierOneLeavesTheChoiceAndTheNextChangeWorks() = recoveryWorld {
        operator()
        val ah = member("alice")
        optIn(ah)
        val alicesEarlier = proxy.last(WireRoute.ACCOUNT_RECOVERY_PUT, "alice")!!.upstream!!.json!!
        optIn(member("bob"))
        val bobs = proxy.last(WireRoute.ACCOUNT_RECOVERY_PUT, "bob")!!.upstream!!.json!!
        val lies: List<Pair<String, (Resp) -> Resp>> = listOf(
            "Bob's answer (A)" to { _ -> Resp.json(200, bobs) },
            "Alice's own earlier answer (R)" to { _ -> Resp.json(200, alicesEarlier) },
            "the seq far ahead (W)" to { r -> r.withJson { it.set("seq", JsonPrimitive(it["seq"]!!.jsonPrimitive.long + 1_000_000)) } },
            "a negative seq (W)" to { r -> r.withJson { it.set("seq", JsonPrimitive(-1L)) } },
            "an empty object (X)" to { _ -> Resp.json(200, json()) },
            "a plain ok (X)" to { _ -> Resp.ok() },
        )
        var operatorOn = true
        for ((what, lie) in lies) {
            server.advance(61_000) // past the server's per-minute limit on re-authenticated changes
            val settings = ah.recoverySettings(ah.session(origin)!!)
            // Only a stored change is lied about: a refusal (a `stale_state` after an earlier lie's seq) passes as it is.
            val rule = proxy.on(WireRoute.ACCOUNT_RECOVERY_PUT, "alice", handler = io.silencelen.andvari.hostile.proxy.Handler { x -> x.forward().let { if (it.ok) lie(it) else it } })
            val out = if (operatorOn) settings.setPosture(RecoveryChoiceKind.PRIVATE, null, understood = true, password = password)
            else settings.setPosture(RecoveryChoiceKind.OPERATOR, assertNotNull(settings.operatorOffer()), understood = true, password = password)
            operatorOn = !operatorOn
            rule.remove()
            assertTrue(out is Reauthed.Done || out is Reauthed.Unknown, "$what: the server stored it; the device says done or unknown: $out")
            assertTrue(out !is Reauthed.WrongPassword, what)
            val view = assertIs<Fetched.Ok<RecoveryPostureView>>(ah.recoverySettings(ah.session(origin)!!).posture(), what).value
            assertEquals(if (operatorOn) "operator" else "private", view.record!!.posture, "$what: the person's choice, as the server now holds it")
        }
        // The next change works, from the device that was lied to.
        server.advance(61_000)
        val settings = ah.recoverySettings(ah.session(origin)!!)
        val next = if (operatorOn) settings.setPosture(RecoveryChoiceKind.PRIVATE, null, understood = true, password = password)
        else settings.setPosture(RecoveryChoiceKind.OPERATOR, assertNotNull(settings.operatorOffer()), understood = true, password = password)
        assertIs<Reauthed.Done<RecoveryRecord>>(next, "the next change after the lies")
    }

    /**
     * `PUT /recovery/self-setup` (row 34, a new kit) answered, after the server stored the new piece, with Bob's piece id
     * (A), Alice's own earlier one (R), an id that is not one (W), `{}` (X). The piece id only binds the kit's
     * "I saved it" confirmation; the kit itself is the secret this device made. A and R: the kit is revealed and it
     * recovers Alice's account on a fresh device. W and X: `Unknown` (never a kit the server may not hold, never "wrong
     * password"), and the next rotation gives a kit that recovers the account.
     */
    @Test fun aKitRotationAnswerOfAnotherPieceStillRevealsAKitThatRecoversTheAccount() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        assertIs<Reauthed.Done<RevealedKit>>(bh.settings(bh.session(origin)!!).rotateKit(password))
        val bobsPiece = proxy.last(WireRoute.RECOVERY_SELF_SETUP, "bob")!!.upstream!!.json!!.str("pieceId")!!
        assertIs<Reauthed.Done<RevealedKit>>(ah.settings(ah.session(origin)!!).rotateKit(password))
        val earlierPiece = proxy.last(WireRoute.RECOVERY_SELF_SETUP, "alice")!!.upstream!!.json!!.str("pieceId")!!

        suspend fun recovers(kit: RevealedKit, tag: String, what: String) {
            val d = device(tag)
            val target = assertIs<KitRecoveryStep.ConfirmTarget>(d.kitRecovery.start(assertNotNull(RecoveryKit.parseQr(kit.qr)), GateEntry.KIT_RECOVERY_SCREEN), what)
            assertIs<KitRecoveryStep.ChoosePassword>(d.kitRecovery.verify(target), "$what: the revealed kit recovers Alice's account")
        }
        for ((i, lie) in listOf("Bob's piece (A)" to bobsPiece, "Alice's own earlier piece (R)" to earlierPiece).withIndex()) {
            val rule = proxy.on(WireRoute.RECOVERY_SELF_SETUP, "alice", handler = editAnswer { it.set("pieceId", lie.second) })
            val kit = assertIs<Reauthed.Done<RevealedKit>>(ah.settings(ah.session(origin)!!).rotateKit(password), lie.first).value
            rule.remove()
            assertEquals(lie.second, kit.pieceId, "${lie.first}: the device cannot tell a piece id")
            recovers(kit, "k$i", lie.first)
        }
        val shapes: List<Pair<String, (Resp) -> Resp>> = listOf(
            "an id that is not one (W)" to { r -> r.withJson { it.set("pieceId", JsonPrimitive("not-a-piece")) } },
            "an empty object (X)" to { _ -> Resp.json(200, json()) },
        )
        for ((what, lie) in shapes) {
            val rule = proxy.on(WireRoute.RECOVERY_SELF_SETUP, "alice", handler = io.silencelen.andvari.hostile.proxy.Handler { x -> x.forward().let { if (it.ok) lie(it) else it } })
            val out = ah.settings(ah.session(origin)!!).rotateKit(password)
            rule.remove()
            assertEquals(Reauthed.Unknown, out, what)
        }
        server.advance(61_000) // past the server's five new kits a minute
        recovers(assertIs<Reauthed.Done<RevealedKit>>(ah.settings(ah.session(origin)!!).rotateKit(password)).value, "k9", "the next rotation")
    }

    /**
     * `GET /account/recovery-requests` (row 70), the live requests a signed-in device shows so the person can stop one:
     * a row with an id that is not one, a platform that is not one or a state that is not live (W) refuses the whole
     * list, never a shorter one; `{}` or `ok` (X) is unreachable, never "no requests". Bob's live list served as Alice's
     * (A) and Alice's own list from before her veto (R) are shown (a row names no account: the stated limit), and a veto
     * of such a row cancels nothing: the frame names Alice's account, the request stays live where it belongs.
     */
    @Test fun aLiveRequestsListThatIsNotThisAccountsOwnNeverCancelsAnything() = recoveryWorld {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        optIn(ah)
        optIn(bh)
        suspend fun holding(tag: String, email: String) {
            val before = Steps.mailCount(server, email, "recovery_request_code")
            val (d, step) = request(tag, email)
            val code = Steps.awaitCode(server, email, "recovery_request_code", before)
            assertIs<AssistedStep.Waiting>(d.assisted.verifyCode(assertIs<AssistedStep.Requested>(step), code), "$tag: holding")
        }
        holding("x", "alice@example.org")
        holding("y", "bob@example.org")
        val alices = ah.recoveryRequests(ah.session(origin)!!)
        val bobsView = bh.recoveryRequests(bh.session(origin)!!)
        val alicesRequest = assertIs<io.silencelen.andvari.core.client.recovery.LiveRecoveryRequests.Listed>(alices.live()).requests.single()
        val alicesList = proxy.last(WireRoute.ACCOUNT_RECOVERY_REQUESTS, "alice")!!.upstream!!.text
        val bobsRequest = assertIs<io.silencelen.andvari.core.client.recovery.LiveRecoveryRequests.Listed>(bobsView.live()).requests.single()
        val bobsList = proxy.last(WireRoute.ACCOUNT_RECOVERY_REQUESTS, "bob")!!.upstream!!.text

        // A row this device cannot read is dropped and counted (it never empties the list); `ready`
        // is a live state of its own (an answered request, cancellable until its commit), not a lie.
        val broken = listOf(
            "an id that is not one" to alicesList.replace(alicesRequest.requestId, "not-an-id"),
            "a platform that is not one" to alicesList.replace("\"platform\":\"${alicesRequest.platform}\"", "\"platform\":\"<script>\""),
            "a state the specification does not name" to alicesList.replace("\"state\":\"${alicesRequest.state}\"", "\"state\":\"granted\""),
        )
        for ((what, body) in broken) {
            assertTrue(body != alicesList, "$what: the lie is told")
            val rule = proxy.on(WireRoute.ACCOUNT_RECOVERY_REQUESTS, "alice", handler = answer { Resp(200, mapOf("Content-Type" to "application/json"), body.encodeToByteArray()) })
            val l = assertIs<io.silencelen.andvari.core.client.recovery.LiveRecoveryRequests.Listed>(alices.live(), "$what (W)")
            assertTrue(l.requests.isEmpty(), "$what: the row is not shown")
            assertEquals(1, l.unreadable, "$what: and it is counted")
            rule.remove()
        }
        for ((what, lie) in listOf("an empty object (X)" to Resp.json(200, json()), "a plain ok (X)" to Resp.ok())) {
            val rule = proxy.on(WireRoute.ACCOUNT_RECOVERY_REQUESTS, "alice", handler = answer { lie })
            assertEquals(io.silencelen.andvari.core.client.recovery.LiveRecoveryRequests.Unreachable, alices.live(), what)
            rule.remove()
        }

        // Bob's list as Alice's: shown, and her veto of his request cancels nothing.
        val rule = proxy.on(WireRoute.ACCOUNT_RECOVERY_REQUESTS, "alice", handler = answer { Resp(200, mapOf("Content-Type" to "application/json"), bobsList.encodeToByteArray()) })
        val shown = assertIs<io.silencelen.andvari.core.client.recovery.LiveRecoveryRequests.Listed>(alices.live(), "the stated limit (A)").requests.single()
        rule.remove()
        assertEquals(bobsRequest.requestId, shown.requestId)
        assertTrue(alices.veto(shown.requestId) !is io.silencelen.andvari.core.client.recovery.VetoOutcome.Vetoed, "Alice's veto of Bob's request")
        assertEquals(bobsRequest.requestId, assertIs<io.silencelen.andvari.core.client.recovery.LiveRecoveryRequests.Listed>(bobsView.live()).requests.single().requestId, "Bob's request lives on")

        // Alice vetoes her own; her list from before the veto is shown again (R), and a second veto cancels nothing new.
        assertEquals(io.silencelen.andvari.core.client.recovery.VetoOutcome.Vetoed, alices.veto(alicesRequest.requestId))
        val replay = proxy.on(WireRoute.ACCOUNT_RECOVERY_REQUESTS, "alice", handler = answer { Resp(200, mapOf("Content-Type" to "application/json"), alicesList.encodeToByteArray()) })
        assertEquals(alicesRequest.requestId, assertIs<io.silencelen.andvari.core.client.recovery.LiveRecoveryRequests.Listed>(alices.live(), "the stated limit (R)").requests.single().requestId)
        replay.remove()
        assertTrue(alices.veto(alicesRequest.requestId) !is io.silencelen.andvari.core.client.recovery.VetoOutcome.Vetoed, "the request is already gone")
        assertTrue(assertIs<io.silencelen.andvari.core.client.recovery.LiveRecoveryRequests.Listed>(alices.live()).requests.isEmpty(), "the honest list")
    }

    /**
     * The operator's escrow route (`POST /admin/accounts/{id}/escrow`, row 85), which the operator hands to the offline
     * tool: Bob's whole answer, or Alice's with Bob's user id (A), is `bad_response` on the operator's device. Alice's user
     * id with Bob's sealed escrow, identity seed and key (W) is taken: the device cannot open an escrow sealed to the
     * offline key, and the offline tool checks the escrow against the request's user and identity fingerprint (the
     * stated limit; `recovery-cli`'s `EscrowVerifyTest`). `{}` and `ok` (X) are never a done escrow.
     */
    @Test fun anEscrowAnswerOfAnotherAccountIsRefusedOnTheOperatorsDevice() = recoveryWorld {
        val oh = operator()
        val ah = member("alice")
        val bh = member("bob")
        optIn(ah)
        optIn(bh)
        val alice = account(ah).userId
        val bob = account(bh).userId
        val ops = oh.operator(oh.session(origin)!!)
        val honest = assertIs<Reauthed.Done<AdminEscrowResponse>>(ops.escrow(alice, password)).value
        assertEquals(alice, honest.userId)
        assertIs<Reauthed.Done<AdminEscrowResponse>>(ops.escrow(bob, password))
        val bobs = proxy.last(WireRoute.ADMIN_ESCROW, "op")!!.upstream!!.json!!

        val refused: List<Pair<String, (Resp) -> Resp>> = listOf(
            "Bob's whole answer (A)" to { _ -> Resp.json(200, bobs) },
            "Alice's answer with Bob's user id (A)" to { r -> r.withJson { it.set("userId", JsonPrimitive(bob)) } },
        )
        for ((what, lie) in refused) {
            val rule = proxy.on(WireRoute.ADMIN_ESCROW, "op", handler = io.silencelen.andvari.hostile.proxy.Handler { x -> x.forward().let { if (it.ok) lie(it) else it } })
            assertEquals(Reauthed.Refused("bad_response"), ops.escrow(alice, password), what)
            rule.remove()
        }
        for ((what, lie) in listOf("an empty object (X)" to Resp.json(200, json()), "a plain ok (X)" to Resp.ok())) {
            val rule = proxy.on(WireRoute.ADMIN_ESCROW, "op", handler = answer { lie })
            val out = ops.escrow(alice, password)
            assertTrue(out !is Reauthed.Done && out !is Reauthed.WrongPassword, "$what: $out")
            rule.remove()
        }
        val swapped = proxy.on(WireRoute.ADMIN_ESCROW, "op", handler = editAnswer { r ->
            r.set("sealed", bobs["sealed"]!!).set("encryptedIdentitySeed", bobs["encryptedIdentitySeed"]!!).set("identityPub", bobs["identityPub"]!!)
        })
        val taken = assertIs<Reauthed.Done<AdminEscrowResponse>>(ops.escrow(alice, password), "the stated limit: the device cannot open the escrow").value
        swapped.remove()
        assertEquals(bobs.str("identityPub"), taken.identityPub, "passed on to the offline tool, which checks it against the request")
    }
}
