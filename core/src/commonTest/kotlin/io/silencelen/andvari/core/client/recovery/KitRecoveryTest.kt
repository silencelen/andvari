package io.silencelen.andvari.core.client.recovery

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.onboard.EstablishedSession
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.RegistrationForm
import io.silencelen.andvari.core.client.onboard.SessionHow
import io.silencelen.andvari.core.client.onboard.SessionSink
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.onboard.SignupVerify
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.client.pin.CardTrust
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.RecoveryKit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Kit recovery (design §10, §4.4, FS-B1; spec 03 §12) against [FakeInstance]. */
class KitRecoveryTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val newPw = "a whole new Passphrase 42 here"

    private class Sink : SessionSink {
        val sessions = ArrayList<EstablishedSession>()
        override suspend fun established(session: EstablishedSession) { sessions += session }
    }

    /** alice registered on [server] from another device; answers her kit as its QR text. */
    private suspend fun aliceKit(server: FakeInstance): String {
        val state = MemoryDeviceState()
        val o = WireOnboarding(server.origin, server, server.pinnedTrust(state), KnownDevices(state, crypto), Sink(), crypto, state, "android", "Old",
            { server.now }, work = Dispatchers.Unconfined)
        o.signupStart("alice@example.com", true)
        val t = o.signupVerify("alice@example.com", "482915") as SignupVerify.Ticket
        val reg = o.register(RegistrationAuth.Ticket(t), RegistrationForm("alice@example.com", "Alice", strong.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Old", "android"))
        return (reg as Registration.Registered).kit.qr
    }

    private class Fresh(val trust: CardTrust, val sink: Sink, val kits: WireKitRecovery, val state: MemoryDeviceState)

    private fun fresh(server: FakeInstance): Fresh {
        val state = MemoryDeviceState()
        val trust = server.trust(state)
        val sink = Sink()
        return Fresh(trust, sink, WireKitRecovery({ server }, trust, KnownDevices(state, crypto), sink, crypto, "android", "New"), state)
    }

    @Test fun aScannedKitPinsFromCardZeroRecoversAndReplacesTheKit() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val qr = aliceKit(server)
        val oldPiece = server.account("alice@example.com").pieceId
        server.account("alice@example.com").requireLink = true
        val f = fresh(server)
        // Only the kit screen takes a kit.
        assertEquals("wrong_screen_kit", assertIs<KitRecoveryStep.Stopped>(f.kits.start(RecoveryKit.parseQr(qr)!!, GateEntry.SCAN_INVITE)).reason)
        assertNull(f.trust.pinFor(server.origin))
        val target = assertIs<KitRecoveryStep.ConfirmTarget>(f.kits.start(RecoveryKit.parseQr(qr)!!, GateEntry.KIT_RECOVERY_SCREEN))
        assertEquals("Home", target.instanceName)
        assertEquals("alice@example.com", target.email)
        assertNull(target.gate)
        assertFalse(WireRoute.RECOVERY_SELF_VERIFY in server.calls, "nothing sent before the person confirms")
        assertEquals(PinRoot.KIT, f.trust.pinFor(server.origin)!!.root)
        val choose = assertIs<KitRecoveryStep.ChoosePassword>(f.kits.verify(target))
        assertEquals("password_too_weak", assertIs<KitRecoveryStep.Stopped>(f.kits.commit(choose, "weak".toCharArray())).reason)
        val pw = newPw.toCharArray()
        val done = assertIs<KitRecoveryStep.Recovered>(f.kits.commit(choose, pw))
        assertTrue(pw.all { it == '\u0000' })
        val a = server.account("alice@example.com")
        assertNotEquals(oldPiece, a.pieceId, "the commit replaced the kit")
        assertEquals(a.pieceId, done.newKit.pieceId)
        assertNotEquals(qr, done.newKit.qr)
        assertEquals(SessionHow.RECOVERED, f.sink.sessions.single().how)
        assertEquals(done.userId, f.sink.sessions.single().userId)
        assertFalse(a.requireLink)
        // The pin the flow made stays in force: the session it opened talks to this origin, and no credential goes to an
        // origin without a pin in force (design §4.4).
        assertEquals(PinRoot.KIT, f.trust.pinFor(server.origin)?.root, "the kit pin is kept once the recovery is done")
        // The old kit is dead.
        val g = fresh(server)
        val t2 = assertIs<KitRecoveryStep.ConfirmTarget>(g.kits.start(RecoveryKit.parseQr(qr)!!, GateEntry.KIT_RECOVERY_SCREEN))
        assertEquals(KitRecoveryStep.Rejected, g.kits.verify(t2))
        // The kit pin does not serve a sign-in, even to the kit's own account.
        val o = WireOnboarding(server.origin, server, f.trust, KnownDevices(f.state, crypto), f.sink, crypto, f.state, "android", "New", { server.now },
            work = Dispatchers.Unconfined)
        assertEquals(SignIn.TrustGateFirst, o.signIn("alice@example.com", newPw.toCharArray()))
    }

    @Test fun theCommitAsksThePasswordRuleAgain() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val qr = aliceKit(server)
        val oldPiece = server.account("alice@example.com").pieceId
        val f = fresh(server)
        val target = assertIs<KitRecoveryStep.ConfirmTarget>(f.kits.start(RecoveryKit.parseQr(qr)!!, GateEntry.KIT_RECOVERY_SCREEN))
        val choose = assertIs<KitRecoveryStep.ChoosePassword>(f.kits.verify(target))
        // The pin forks between the verify and the commit: newAuthKey is not sent.
        io.silencelen.andvari.core.client.pin.PinStore(f.state).markForked(f.trust.pinFor(server.origin)!!)
        val pw = newPw.toCharArray()
        assertEquals(WireKitRecovery.INSTANCE_BLOCKED, assertIs<KitRecoveryStep.Stopped>(f.kits.commit(choose, pw)).reason)
        assertTrue(pw.all { it == '\u0000' })
        assertFalse(WireRoute.RECOVERY_SELF_COMMIT in server.calls)
        assertEquals(oldPiece, server.account("alice@example.com").pieceId, "the kit is untouched")
        assertTrue(f.sink.sessions.isEmpty())
        // The pin is replaced between the two steps by one that is no password pin (a link offer's): not sent either.
        val g = fresh(server)
        val target2 = assertIs<KitRecoveryStep.ConfirmTarget>(g.kits.start(RecoveryKit.parseQr(qr)!!, GateEntry.KIT_RECOVERY_SCREEN))
        val choose2 = assertIs<KitRecoveryStep.ChoosePassword>(g.kits.verify(target2))
        g.trust.forget(server.origin)
        g.trust.pinFromLinkOffer(server.origin, server.instanceId, server.card0Hash)
        assertEquals(PinRoot.LINK_OFFER, g.trust.pinFor(server.origin)!!.root)
        assertEquals(WireKitRecovery.TRUST_GATE_FIRST, assertIs<KitRecoveryStep.Stopped>(g.kits.commit(choose2, newPw.toCharArray())).reason)
        assertFalse(WireRoute.RECOVERY_SELF_COMMIT in server.calls)
        assertEquals(oldPiece, server.account("alice@example.com").pieceId)
    }

    @Test fun aKitFromBeforeAnOperatorResetFallsBackToTheTrustGate() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val qr = aliceKit(server)
        val kit = RecoveryKit.parseQr(qr)!!
        val wrongAnchor = RecoveryKit.parseQr(RecoveryKit.composeQr(kit.origin, "f".repeat(64), kit.emailNorm, kit.secret)!!)!!
        val f = fresh(server)
        val target = assertIs<KitRecoveryStep.ConfirmTarget>(f.kits.start(wrongAnchor, GateEntry.KIT_RECOVERY_SCREEN))
        assertTrue(target.kitAnchorMismatch)
        assertNotNull(target.gate)
        assertNull(f.trust.pinFor(server.origin), "nothing pinned while the gate is up")
        assertIs<KitRecoveryStep.ChoosePassword>(f.kits.verify(target))
        assertEquals(PinRoot.TRUST_GATE, f.trust.pinFor(server.origin)!!.root)
    }

    @Test fun aTypedKitNeverUsesTheKitRoot() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val kit = RecoveryKit.parseQr(aliceKit(server))!!
        val f = fresh(server)
        val typed = RecoveryKit.displayForm(kit.secret)
        assertEquals("bad_origin", assertIs<KitRecoveryStep.Stopped>(f.kits.startTyped("alice@example.com", "h.example", typed, GateEntry.KIT_RECOVERY_SCREEN)).reason)
        assertEquals("bad_kit", assertIs<KitRecoveryStep.Stopped>(f.kits.startTyped("alice@example.com", server.origin, "abc", GateEntry.KIT_RECOVERY_SCREEN)).reason)
        // A secret of zeros is a bad kit, never "locked" (the floor would refuse its HKDF).
        val zeros = io.silencelen.andvari.core.trust.RecoveryKit.displayForm(ByteArray(32))
        assertEquals("bad_kit", assertIs<KitRecoveryStep.Stopped>(f.kits.startTyped("alice@example.com", server.origin, zeros, GateEntry.KIT_RECOVERY_SCREEN)).reason)
        val target = assertIs<KitRecoveryStep.ConfirmTarget>(f.kits.startTyped("alice@example.com", server.origin, typed, GateEntry.KIT_RECOVERY_SCREEN))
        val gate = assertNotNull(target.gate, "no pin: the Trust Gate, in the same confirmation")
        assertEquals("Home", gate.name)
        assertNull(f.trust.pinFor(server.origin))
        f.kits.cancel(target)
        assertNull(f.trust.pinFor(server.origin))
        // With a Trust Gate pin already held, no gate is asked again.
        val g = fresh(server)
        server.pinnedTrust(g.state)
        val again = assertIs<KitRecoveryStep.ConfirmTarget>(g.kits.startTyped("alice@example.com", server.origin, typed, GateEntry.KIT_RECOVERY_SCREEN))
        assertNull(again.gate)
        assertIs<KitRecoveryStep.Recovered>(g.kits.commit(assertIs(g.kits.verify(again)), newPw.toCharArray()))
    }

    /** Stopping is on the interface a host holds ([KitRecovery.cancel]), as it is for the assisted recovery. */
    @Test fun aHostStopsAKitRecoveryThroughTheInterfaceAndThePinItMadeGoes() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val kit = RecoveryKit.parseQr(aliceKit(server))!!
        val typed = RecoveryKit.displayForm(kit.secret)
        val f = fresh(server)
        val kits: KitRecovery = f.kits
        // A scanned kit pins at start (the kit root); the host then stops on its own after verify (no new password given).
        val target = assertIs<KitRecoveryStep.ConfirmTarget>(kits.start(kit, GateEntry.KIT_RECOVERY_SCREEN))
        assertEquals(PinRoot.KIT, f.trust.pinFor(server.origin)!!.root)
        val choose = assertIs<KitRecoveryStep.ChoosePassword>(kits.verify(target))
        kits.cancel(choose)
        assertNull(f.trust.pinFor(server.origin), "the pin this flow made is gone")
        kits.cancel(choose)
        assertEquals("stale", assertIs<KitRecoveryStep.Stopped>(kits.commit(choose, newPw.toCharArray())).reason, "the flow is over")
        // A typed kit: the Trust Gate the person confirmed at verify stays pinned, as every confirmed Trust Gate does.
        val t = fresh(server)
        val typedKits: KitRecovery = t.kits
        val tt = assertIs<KitRecoveryStep.ConfirmTarget>(typedKits.startTyped("alice@example.com", server.origin, typed, GateEntry.KIT_RECOVERY_SCREEN))
        typedKits.cancel(assertIs<KitRecoveryStep.ChoosePassword>(typedKits.verify(tt)))
        assertEquals(PinRoot.TRUST_GATE, t.trust.pinFor(server.origin)?.root)
        // After Recovered, a cancel changes nothing: the pin is the account's now.
        val g = fresh(server)
        val again: KitRecovery = g.kits
        val t2 = assertIs<KitRecoveryStep.ConfirmTarget>(again.startTyped("alice@example.com", server.origin, typed, GateEntry.KIT_RECOVERY_SCREEN))
        val c2 = assertIs<KitRecoveryStep.ChoosePassword>(again.verify(t2))
        val done = assertIs<KitRecoveryStep.Recovered>(again.commit(c2, newPw.toCharArray()))
        again.cancel(done)
        again.cancel(c2)
        assertNotNull(g.trust.pinFor(server.origin), "a finished recovery keeps its pin")
    }

    /** [inner], running [during] when [route] is sent, before its answer: a leave that lands while the request is in flight. */
    private class LeaveDuring(private val inner: io.silencelen.andvari.core.client.net.WireClient, private val route: WireRoute) :
        io.silencelen.andvari.core.client.net.WireClient by inner {
        var during: (() -> Unit)? = null

        /** When set, the server acts on nothing and this is its answer to [route] (a refusal, or no answer at all). */
        var answer: io.silencelen.andvari.core.client.net.WireResult<Nothing>? = null
        val sent = ArrayList<WireRoute>()

        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): io.silencelen.andvari.core.client.net.WireResult<T> {
            sent += route
            if (route == this.route) during?.also { during = null }?.invoke()
            if (route == this.route) answer?.let { return it }
            return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
        }
    }

    /**
     * The commit is sent, the person leaves, the server takes it. A
     * leave stays a leave (no session opened, nothing kept, nothing more sent), and what the late answer came to is
     * published once: the reset went through. Before, the flow published nothing, so the first screen could not say that
     * the master password had changed and that the next sign-in makes the new kit.
     */
    @Test fun aKitRecoveryLeftAfterItsCommitWasSentPublishesOnceThatTheResetWentThrough() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val kit = RecoveryKit.parseQr(aliceKit(server))!!
        val oldPiece = server.account("alice@example.com").pieceId
        val wire = LeaveDuring(server, WireRoute.RECOVERY_SELF_COMMIT)
        val state = MemoryDeviceState()
        val trust = server.trust(state)
        val sink = Sink()
        val kits: KitRecovery = WireKitRecovery({ wire }, trust, KnownDevices(state, crypto), sink, crypto, "android", "New")
        var told = 0
        kits.onLateOutcome = { told++ }
        val choose = assertIs<KitRecoveryStep.ChoosePassword>(kits.verify(assertIs(kits.start(kit, GateEntry.KIT_RECOVERY_SCREEN))))
        assertNull(kits.takeLateOutcome(), "nothing is published before a commit")
        wire.during = { kits.cancel(choose) }
        floorRefusals { heard ->
            assertEquals("stale", assertIs<KitRecoveryStep.Stopped>(kits.commit(choose, newPw.toCharArray())).reason)
            assertEquals(emptyList(), heard, "nothing was attempted under the wiped key")
        }
        assertNotEquals(oldPiece, server.account("alice@example.com").pieceId, "the server took the commit")
        assertEquals(1, told, "the host was told once")
        val outcome = assertNotNull(kits.takeLateOutcome())
        assertEquals(LateRecoveryOutcome.Result.RESET, outcome.result)
        assertEquals(LateRecoveryOutcome.Via.KIT, outcome.via)
        assertEquals(server.origin, outcome.origin)
        assertEquals("alice@example.com", outcome.email)
        assertNull(kits.takeLateOutcome(), "published once")
        assertTrue(sink.sessions.isEmpty(), "no session was opened")
        assertNull(trust.pinFor(server.origin), "the kit pin of the left flow is not kept")
        // The policy's read sets the new password's cost before the commit.
        assertEquals(listOf(WireRoute.RECOVERY_SELF_VERIFY, WireRoute.CLIENT_POLICY, WireRoute.RECOVERY_SELF_COMMIT), wire.sent, "nothing more was sent")
        assertEquals("stale", assertIs<KitRecoveryStep.Stopped>(kits.commit(choose, newPw.toCharArray())).reason)
        assertNull(kits.takeLateOutcome(), "a stale call publishes nothing")
    }

    /** The same leave, and the server refuses the commit, or gives no usable answer: each is published once as what it is. */
    @Test fun aKitRecoveryLeftAfterItsCommitWasSentPublishesARefusalOrAnUnknownAnswerOnce() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val kit = RecoveryKit.parseQr(aliceKit(server))!!
        val oldPiece = server.account("alice@example.com").pieceId
        val answers = listOf(
            io.silencelen.andvari.core.client.net.WireResult.Refused(401, io.silencelen.andvari.core.model.wire.WireError("unauthorized", "unauthorized")) to LateRecoveryOutcome.Result.REFUSED,
            io.silencelen.andvari.core.client.net.WireResult.Refused(409, io.silencelen.andvari.core.model.wire.WireError("conflict", "conflict")) to LateRecoveryOutcome.Result.REFUSED,
            io.silencelen.andvari.core.client.net.WireResult.Refused(503, io.silencelen.andvari.core.model.wire.WireError("unavailable", "unavailable")) to LateRecoveryOutcome.Result.UNKNOWN,
            io.silencelen.andvari.core.client.net.WireResult.NoAnswer(io.silencelen.andvari.core.client.net.NoAnswerKind.TIMEOUT) to LateRecoveryOutcome.Result.UNKNOWN,
        )
        for ((answer, expected) in answers) {
            val wire = LeaveDuring(server, WireRoute.RECOVERY_SELF_COMMIT)
            val state = MemoryDeviceState()
            val sink = Sink()
            val kits = WireKitRecovery({ wire }, server.trust(state), KnownDevices(state, crypto), sink, crypto, "android", "New")
            val choose = assertIs<KitRecoveryStep.ChoosePassword>(kits.verify(assertIs(kits.start(kit, GateEntry.KIT_RECOVERY_SCREEN))))
            wire.during = { kits.cancel(choose) }
            wire.answer = answer
            assertEquals("stale", assertIs<KitRecoveryStep.Stopped>(kits.commit(choose, newPw.toCharArray())).reason)
            assertEquals(expected, assertNotNull(kits.takeLateOutcome(), "$answer").result, "$answer")
            assertNull(kits.takeLateOutcome())
            assertTrue(sink.sessions.isEmpty())
            assertEquals(1, wire.sent.count { it == WireRoute.RECOVERY_SELF_COMMIT }, "nothing is sent again")
        }
        assertEquals(oldPiece, server.account("alice@example.com").pieceId)
    }

    /** A commit the person stayed for publishes nothing late: its own answer is on screen. */
    @Test fun aKitRecoveryThePersonStayedForPublishesNoLateOutcome() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val kit = RecoveryKit.parseQr(aliceKit(server))!!
        val f = fresh(server)
        var told = 0
        f.kits.onLateOutcome = { told++ }
        assertIs<KitRecoveryStep.Recovered>(f.kits.commit(assertIs(f.kits.verify(assertIs(f.kits.start(kit, GateEntry.KIT_RECOVERY_SCREEN)))), newPw.toCharArray()))
        assertNull(f.kits.takeLateOutcome())
        assertEquals(0, told)
    }

    /**
     * A typed kit left while its Trust Gate is being confirmed, or while the
     * proof after it is on its way. The pin that gate made stayed behind for a recovery the person left (the assisted
     * recovery drops it). Now it is dropped; a pin that existed before the flow is untouched.
     */
    @Test fun aKitRecoveryLeftDuringItsOwnTrustGateDropsThePinThatGateMade() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val typed = RecoveryKit.displayForm(RecoveryKit.parseQr(aliceKit(server))!!.secret)
        for (leaveAt in listOf("gate", "verify")) {
            val state = MemoryDeviceState()
            val real = server.trust(state)
            var during: (() -> Unit)? = null
            val trust = object : io.silencelen.andvari.core.client.pin.InstanceTrust by real {
                override suspend fun confirmTrustGate(ticket: io.silencelen.andvari.core.client.pin.TrustGateTicket) =
                    real.confirmTrustGate(ticket).also { if (leaveAt == "gate") during?.invoke() }
            }
            val wire = LeaveDuring(server, WireRoute.RECOVERY_SELF_VERIFY)
            val kits = WireKitRecovery({ wire }, trust, KnownDevices(state, crypto), Sink(), crypto, "android", "New")
            val target = assertIs<KitRecoveryStep.ConfirmTarget>(kits.startTyped("alice@example.com", server.origin, typed, GateEntry.KIT_RECOVERY_SCREEN))
            assertNotNull(target.gate)
            if (leaveAt == "gate") during = { kits.cancel(target) } else wire.during = { kits.cancel(target) }
            assertEquals("stale", assertIs<KitRecoveryStep.Stopped>(kits.verify(target)).reason, leaveAt)
            assertNull(real.pinFor(server.origin), "$leaveAt: the pin the flow's own gate made is dropped")
        }
        // A pin held before the flow began is not the flow's: a leave keeps it.
        val state = MemoryDeviceState()
        val held = server.pinnedTrust(state)
        val wire = LeaveDuring(server, WireRoute.RECOVERY_SELF_VERIFY)
        val kits = WireKitRecovery({ wire }, held, KnownDevices(state, crypto), Sink(), crypto, "android", "New")
        val target = assertIs<KitRecoveryStep.ConfirmTarget>(kits.startTyped("alice@example.com", server.origin, typed, GateEntry.KIT_RECOVERY_SCREEN))
        assertNull(target.gate)
        wire.during = { kits.cancel(target) }
        assertEquals("stale", assertIs<KitRecoveryStep.Stopped>(kits.verify(target)).reason)
        assertNotNull(held.pinFor(server.origin), "a pin from before the flow stays")
    }

    /** Runs [block] with every refusal of the shared floor recorded (the tripwire, if on, still hears each one). */
    private inline fun <T> floorRefusals(block: (List<String>) -> T): T {
        val heard = ArrayList<String>()
        val before = io.silencelen.andvari.core.crypto.KeyFloor.onRefusal
        io.silencelen.andvari.core.crypto.KeyFloor.onRefusal = { heard += it; before?.invoke(it) }
        try {
            return block(heard)
        } finally {
            io.silencelen.andvari.core.crypto.KeyFloor.onRefusal = before
        }
    }

    /**
     * The person leaves (start over, back) while the commit is in flight. The leave wiped the UVK
     * copy the flow held, and the commit's answer used to open the recovered session under it; only the shared floor
     * stopped that. Now nothing is opened or attempted under the wiped copy, no session reaches the host, and the answer
     * is STALE (the server took the commit: the next sign-in decides, as for an unknown answer).
     */
    @Test fun aKitRecoveryLeftWhileItsCommitIsInFlightOpensNothingUnderTheWipedKeyAndAnswersStale() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val kit = RecoveryKit.parseQr(aliceKit(server))!!
        val wire = LeaveDuring(server, WireRoute.RECOVERY_SELF_COMMIT)
        val state = MemoryDeviceState()
        val trust = server.trust(state)
        val sink = Sink()
        val kits = WireKitRecovery({ wire }, trust, KnownDevices(state, crypto), sink, crypto, "android", "New")
        val choose = assertIs<KitRecoveryStep.ChoosePassword>(kits.verify(assertIs(kits.start(kit, GateEntry.KIT_RECOVERY_SCREEN))))
        wire.during = { kits.cancel(choose) }
        floorRefusals { heard ->
            val answer = kits.commit(choose, newPw.toCharArray())
            assertEquals("stale", assertIs<KitRecoveryStep.Stopped>(answer).reason)
            assertEquals(emptyList(), heard, "nothing was attempted under the wiped key")
        }
        assertTrue(WireRoute.RECOVERY_SELF_COMMIT in server.calls, "the commit was sent before the leave")
        assertTrue(sink.sessions.isEmpty(), "no session was opened")
        assertEquals("stale", assertIs<KitRecoveryStep.Stopped>(kits.commit(choose, newPw.toCharArray())).reason, "the flow is over")
    }

    /** The same at the verify's wait: the kit secret the leave wiped is never derived from, and the flow is not handed on. */
    @Test fun aKitRecoveryLeftWhileItsVerifyIsInFlightDerivesNothingFromTheWipedKitAndAnswersStale() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val kit = RecoveryKit.parseQr(aliceKit(server))!!
        val wire = LeaveDuring(server, WireRoute.RECOVERY_SELF_VERIFY)
        val state = MemoryDeviceState()
        val kits = WireKitRecovery({ wire }, server.trust(state), KnownDevices(state, crypto), Sink(), crypto, "android", "New")
        val target = assertIs<KitRecoveryStep.ConfirmTarget>(kits.start(kit, GateEntry.KIT_RECOVERY_SCREEN))
        wire.during = { kits.cancel(target) }
        floorRefusals { heard ->
            assertEquals("stale", assertIs<KitRecoveryStep.Stopped>(kits.verify(target)).reason)
            assertEquals(emptyList(), heard, "nothing was derived from the wiped kit")
        }
        assertEquals("stale", assertIs<KitRecoveryStep.Stopped>(kits.verify(target)).reason, "the flow is over")
    }

    /** The same at a typed kit's Trust Gate, the verify's first wait: nothing is derived or sent after the leave. */
    @Test fun aTypedKitRecoveryLeftDuringItsTrustGateSendsNothingAndAnswersStale() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val typed = RecoveryKit.displayForm(RecoveryKit.parseQr(aliceKit(server))!!.secret)
        val state = MemoryDeviceState()
        val real = server.trust(state)
        var during: (() -> Unit)? = null
        val trust = object : io.silencelen.andvari.core.client.pin.InstanceTrust by real {
            override suspend fun confirmTrustGate(ticket: io.silencelen.andvari.core.client.pin.TrustGateTicket) =
                real.confirmTrustGate(ticket).also { during?.invoke() }
        }
        val kits = WireKitRecovery({ server }, trust, KnownDevices(state, crypto), Sink(), crypto, "android", "New")
        val target = assertIs<KitRecoveryStep.ConfirmTarget>(kits.startTyped("alice@example.com", server.origin, typed, GateEntry.KIT_RECOVERY_SCREEN))
        assertNotNull(target.gate)
        during = { kits.cancel(target) }
        floorRefusals { heard ->
            assertEquals("stale", assertIs<KitRecoveryStep.Stopped>(kits.verify(target)).reason)
            assertEquals(emptyList(), heard)
        }
        assertFalse(WireRoute.RECOVERY_SELF_VERIFY in server.calls, "nothing was sent after the leave")
    }

    @Test fun aServedIdentityKeyTheSeedDoesNotDeriveStopsBeforeAnyPassword() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val kit = RecoveryKit.parseQr(aliceKit(server))!!
        server.account("alice@example.com").identityPub = io.silencelen.andvari.core.crypto.Bytes.toB64(ByteArray(32) { 3 })
        val f = fresh(server)
        val target = assertIs<KitRecoveryStep.ConfirmTarget>(f.kits.start(kit, GateEntry.KIT_RECOVERY_SCREEN))
        // Design §2.4: one verdict name each; the identity fault is what the person is shown.
        assertEquals("identity_mismatch", assertIs<KitRecoveryStep.Stopped>(f.kits.verify(target)).reason)
        assertTrue(f.sink.sessions.isEmpty())
    }

    /** [inner], with the account's id [real] in the kit's verify answer replaced by the nil id: a server lying in that one field. */
    private class NilInVerify(private val inner: io.silencelen.andvari.core.client.net.WireClient, private val real: String) :
        io.silencelen.andvari.core.client.net.WireClient by inner {
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): io.silencelen.andvari.core.client.net.WireResult<T> =
            if (route != WireRoute.RECOVERY_SELF_VERIFY) inner.call(route, pathParams, query, bodyJson, authenticated, decode)
            else inner.call(route, pathParams, query, bodyJson, authenticated) { decode(it.replace(real, "00000000-0000-0000-0000-000000000000")) }
    }

    /**
     * A user id of all zeros is never an account: a verify answer that names it stops the kit recovery as a bad answer,
     * before the kit is tried against it, and nothing is committed or opened. Before, the kit was tried under the nil id's
     * associated data and the stop read as an identity mismatch.
     */
    @Test fun aVerifyAnswerNamingTheNilUserIdStopsAsABadAnswerAndOpensNothing() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val kit = RecoveryKit.parseQr(aliceKit(server))!!
        val real = server.account("alice@example.com").userId
        val state = MemoryDeviceState()
        val trust = server.trust(state)
        val sink = Sink()
        val kits = WireKitRecovery({ NilInVerify(server, real) }, trust, KnownDevices(state, crypto), sink, crypto, "android", "New")
        val target = assertIs<KitRecoveryStep.ConfirmTarget>(kits.start(kit, GateEntry.KIT_RECOVERY_SCREEN))
        assertEquals(WireKitRecovery.BAD_RESPONSE, assertIs<KitRecoveryStep.Stopped>(kits.verify(target)).reason)
        assertTrue(sink.sessions.isEmpty())
        assertFalse(WireRoute.RECOVERY_SELF_COMMIT in server.calls, "nothing was committed")
    }

    /** A kit recovery from a fresh device through to [KitRecoveryStep.Recovered], or the stop it came to. */
    private suspend fun recoverFresh(server: FakeInstance, qr: String, sink: SessionSink = Sink()): KitRecoveryStep {
        val state = MemoryDeviceState()
        val kits = WireKitRecovery({ server }, server.trust(state), KnownDevices(state, crypto), sink, crypto, "android", "New")
        val target = assertIs<KitRecoveryStep.ConfirmTarget>(kits.start(RecoveryKit.parseQr(qr)!!, GateEntry.KIT_RECOVERY_SCREEN))
        return kits.commit(assertIs(kits.verify(target)), newPw.toCharArray())
    }

    /**
     * A server whose operator raised the floor above the default, with the policy raised to match: the recovery derives
     * the new password at the policy, read through the pinned server during the flow. Before, every recovery derived at
     * the default and the server refused it as too weak: a dead end for exactly the person a recovery is for.
     */
    @Test fun aServerWhoseFloorIsAboveTheDefaultTakesAKitRecoveryAtItsPolicy() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val qr = aliceKit(server)
        val raised = io.silencelen.andvari.core.crypto.KdfParams(ops = 4)
        server.policyKdf = raised
        server.minKdf = raised
        assertIs<KitRecoveryStep.Recovered>(recoverFresh(server, qr))
        assertEquals(raised, server.account("alice@example.com").kdfParams)
        assertTrue(WireRoute.CLIENT_POLICY in server.calls)
    }

    /** A policy below the default, or outside the fence, lowers nothing and raises nothing: the default stands. */
    @Test fun aPolicyBelowTheDefaultOrOutsideTheFenceChangesNothing() = runBlocking<Unit> {
        for (policy in listOf(io.silencelen.andvari.core.crypto.KdfParams(ops = 2), io.silencelen.andvari.core.crypto.KdfParams(ops = 11),
            io.silencelen.andvari.core.crypto.KdfParams(memBytes = 2L * 1_073_741_824))) {
            val server = FakeInstance(crypto)
            val qr = aliceKit(server)
            server.policyKdf = policy
            assertIs<KitRecoveryStep.Recovered>(recoverFresh(server, qr), "policy $policy")
            assertEquals(io.silencelen.andvari.core.crypto.KdfParams.DEFAULT, server.account("alice@example.com").kdfParams, "policy $policy")
        }
    }

    /**
     * Where the device keeps a copy of the account, that copy's cost is a floor too: it is the cost the account had when
     * this device last opened it, and the recovery never derives below it, even under a server whose policy is lower.
     */
    @Test fun aDeviceThatKeepsTheAccountAtAHigherCostRecoversAtThatCost() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val qr = aliceKit(server)
        val a = server.account("alice@example.com")
        val higher = io.silencelen.andvari.core.crypto.KdfParams(ops = 4)
        val kept = io.silencelen.andvari.core.client.onboard.KeptAccountKeys(a.userId, server.keys(a).copy(kdfParams = higher), null)
        val sink = object : SessionSink {
            override suspend fun established(session: EstablishedSession) {}
            override fun keptForSignIn(origin: String) = kept
        }
        assertIs<KitRecoveryStep.Recovered>(recoverFresh(server, qr, sink))
        assertEquals(higher, server.account("alice@example.com").kdfParams)
    }

    /**
     * A device that keeps an account above the served cost on one figure (4 passes) and below it on the other (64 MiB,
     * where the floor was raised to 128 MiB) recovers at 4 passes and 128 MiB: figure by figure the higher (decided on
     * 2026-11-17). Before, a straddle raised nothing: the recovery was made at the kept cost, and the floor refused it.
     */
    @Test fun aDeviceThatKeepsAnAccountStraddlingTheServedCostRecoversAtTheHigherOnEachFigure() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val qr = aliceKit(server)
        val a = server.account("alice@example.com")
        val kept4 = io.silencelen.andvari.core.crypto.KdfParams(ops = 4)
        val raised = io.silencelen.andvari.core.crypto.KdfParams(ops = 3, memBytes = 128L * 1024 * 1024)
        server.policyKdf = raised
        server.minKdf = raised
        val kept = io.silencelen.andvari.core.client.onboard.KeptAccountKeys(a.userId, server.keys(a).copy(kdfParams = kept4), null)
        val sink = object : SessionSink {
            override suspend fun established(session: EstablishedSession) {}
            override fun keptForSignIn(origin: String) = kept
        }
        assertIs<KitRecoveryStep.Recovered>(recoverFresh(server, qr, sink))
        assertEquals(io.silencelen.andvari.core.crypto.KdfParams(ops = 4, memBytes = 128L * 1024 * 1024), server.account("alice@example.com").kdfParams)
    }
}
