package io.silencelen.andvari.core.client.devicelink

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.link.ContactCurrency
import io.silencelen.andvari.core.client.link.Currency
import io.silencelen.andvari.core.client.link.LinkAccount
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.EstablishedSession
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.RegistrationForm
import io.silencelen.andvari.core.client.onboard.SessionHow
import io.silencelen.andvari.core.client.onboard.SessionSink
import io.silencelen.andvari.core.client.onboard.SignupVerify
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.client.state.ContactRecord
import io.silencelen.andvari.core.client.state.StoredAccountState
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.DeviceLinkApproveRequest
import io.silencelen.andvari.core.model.wire.DeviceLinkClaim
import io.silencelen.andvari.core.model.wire.DeviceLinkCreateRequest
import io.silencelen.andvari.core.model.wire.DeviceLinkNonceRequest
import io.silencelen.andvari.core.model.wire.DeviceLinkPickupRequest
import io.silencelen.andvari.core.model.wire.DeviceLinkPickupResponse
import io.silencelen.andvari.core.model.wire.DeviceLinkPollRequest
import io.silencelen.andvari.core.model.wire.DeviceLinkPollResponse
import io.silencelen.andvari.core.model.wire.DeviceLinkRevealRequest
import io.silencelen.andvari.core.model.wire.DeviceLinkView
import io.silencelen.andvari.core.model.wire.LinkCreatedResponse
import io.silencelen.andvari.core.model.wire.SessionResponse
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.CardFields
import io.silencelen.andvari.core.trust.InstanceCard
import io.silencelen.andvari.core.trust.SignedFrame
import io.silencelen.andvari.core.trust.TrustGrammar
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** The device-link routes of spec 03 §16 as an honest server answers them, over a [FakeInstance]. */
class DeviceLinkServer(val instance: FakeInstance) {
    class Row(val linkId: String, val owner: String) {
        var state = "open"
        var claim: DeviceLinkClaim? = null
        var nonceE: String? = null
        var proofHash: String? = null
        var nonceN: String? = null
        var approve: DeviceLinkApproveRequest? = null
    }

    val crypto get() = instance.crypto
    val rows = HashMap<String, Row>()
    val calls = ArrayList<Pair<String, WireRoute>>()
    var swapInner: String? = null
    var pickupRole = "member"
    var pickupMustEnrollTotp = false
    var serveNonceE: String? = null
    /** The `ttlMs` the create answer names instead of the honest 5 minutes (a lying server). */
    var createTtl: Long? = null
    /** How many of the next requests on a route are refused as too many (`429`), each naming [waitSeconds]. */
    val tooMany = HashMap<WireRoute, Int>()
    var waitSeconds: Long? = 30

    private fun refuse(status: Int, code: String): WireResult<Nothing> = WireResult.Refused(status, WireError(code, code))

    fun client(caller: String?, origin: String = instance.origin): WireClient = object : WireClient {
        override val origin: String = origin
        @Suppress("UNCHECKED_CAST")
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            calls += origin to route
            fun <R> ok(text: String): WireResult<R> = WireResult.Ok(decode(text) as R, 200)
            val id = pathParams["linkId"]
            val row = id?.let { rows[it] }
            tooMany[route]?.takeIf { it > 0 }?.let { left ->
                tooMany[route] = left - 1
                return WireResult.Refused(429, WireError("rate_limited", "rate_limited"), retryAfterSeconds = waitSeconds)
            }
            fun proofOk(proof: String) = row?.proofHash == null || row.proofHash == Bytes.toHexLower(crypto.sha256(proof.encodeToByteArray()))
            return when (route) {
                WireRoute.DEVICE_LINK_CREATE -> {
                    val b = WireJson.json.decodeFromString(DeviceLinkCreateRequest.serializer(), bodyJson!!)
                    rows.values.removeAll { it.owner == caller }
                    rows[b.linkId] = Row(b.linkId, caller!!)
                    WireResult.Ok(decode(WireJson.json.encodeToString(LinkCreatedResponse.serializer(), LinkCreatedResponse(instance.now + 300_000, createTtl ?: 300_000))), 201)
                }
                WireRoute.DEVICE_LINK_VIEW -> {
                    val r = row?.takeIf { it.owner == caller } ?: return refuse(404, "link_unknown")
                    ok(WireJson.json.encodeToString(DeviceLinkView.serializer(), DeviceLinkView(r.state, instance.now, r.claim, r.nonceE, r.nonceN)))
                }
                WireRoute.DEVICE_LINK_CLAIM -> {
                    val r = row ?: return refuse(404, "link_unknown")
                    if (r.state != "open") return refuse(409, "link_claimed")
                    r.claim = WireJson.json.decodeFromString(DeviceLinkClaim.serializer(), bodyJson!!)
                    r.state = "claimed"
                    ok("{}")
                }
                WireRoute.DEVICE_LINK_NONCE -> {
                    val r = row?.takeIf { it.owner == caller } ?: return refuse(404, "link_unknown")
                    if (r.state != "claimed" || r.nonceE != null) return refuse(409, "link_state")
                    val b = WireJson.json.decodeFromString(DeviceLinkNonceRequest.serializer(), bodyJson!!)
                    r.nonceE = b.nonceE
                    r.proofHash = b.proofHash
                    ok("{}")
                }
                WireRoute.DEVICE_LINK_POLL -> {
                    val r = row ?: return refuse(404, "link_unknown")
                    if (!proofOk(WireJson.json.decodeFromString(DeviceLinkPollRequest.serializer(), bodyJson!!).proof)) return refuse(403, "bad_proof")
                    val a = r.approve
                    ok(WireJson.json.encodeToString(DeviceLinkPollResponse.serializer(), DeviceLinkPollResponse(r.state, serveNonceE ?: r.nonceE, a?.outer, a?.approveMac)))
                }
                WireRoute.DEVICE_LINK_REVEAL -> {
                    val r = row ?: return refuse(404, "link_unknown")
                    val b = WireJson.json.decodeFromString(DeviceLinkRevealRequest.serializer(), bodyJson!!)
                    if (!proofOk(b.proof)) return refuse(403, "bad_proof")
                    if (r.state != "claimed" || r.nonceE == null || r.nonceN != null) return refuse(409, "link_state")
                    r.nonceN = b.nonceN
                    r.state = "revealed"
                    ok("{}")
                }
                WireRoute.DEVICE_LINK_APPROVE -> {
                    val r = row?.takeIf { it.owner == caller } ?: return refuse(404, "link_unknown")
                    if (r.state != "revealed") return refuse(409, "link_state")
                    r.approve = WireJson.json.decodeFromString(DeviceLinkApproveRequest.serializer(), bodyJson!!)
                    r.state = "approved"
                    ok("{}")
                }
                WireRoute.DEVICE_LINK_CANCEL -> {
                    rows.remove(id) ?: return refuse(404, "link_unknown")
                    ok("{}")
                }
                WireRoute.DEVICE_LINK_PICKUP -> {
                    val r = row ?: return refuse(404, "link_unknown")
                    val b = WireJson.json.decodeFromString(DeviceLinkPickupRequest.serializer(), bodyJson!!)
                    if (!proofOk(b.proof)) return refuse(403, "bad_proof")
                    if (r.state != "approved") return refuse(409, "link_state")
                    val a = instance.accounts.values.firstOrNull { it.userId == r.owner } ?: return refuse(401, "invalid_credentials")
                    if (a.authKey != b.authKey) return refuse(401, "invalid_credentials")
                    if (a.totp != null && b.totp != a.totp) return refuse(401, if (b.totp == null) "totp_required" else "invalid_credentials")
                    val deviceId = "00000000-0000-4000-8000-0000000000d" + (a.devices.size % 10)
                    a.devices[deviceId] = b.device.deviceSecret
                    rows.remove(r.linkId)
                    ok(WireJson.json.encodeToString(DeviceLinkPickupResponse.serializer(),
                        DeviceLinkPickupResponse(swapInner ?: r.approve!!.inner, SessionResponse(a.userId, deviceId, "at-$deviceId", "rt-$deviceId",
                            instance.keys(a), pickupRole, a.totp != null, pickupMustEnrollTotp))))
                }
                else -> instance.call(route, pathParams, query, bodyJson, authenticated, decode)
            }
        }
    }
}

/** Device links end to end (design §8.2, §8.3) against [DeviceLinkServer], with a real registered account. */
class DeviceLinkFlowsTest {
    private val crypto = createCryptoProvider()
    private val password = "correct horse Battery 9 staple"
    private val bob = "22222222-2222-4222-8222-222222222222"
    private val bobKey = Bytes.toB64(ByteArray(32) { 5 })

    private class Sink : SessionSink {
        val sessions = ArrayList<EstablishedSession>()
        override suspend fun established(session: EstablishedSession) { sessions += session }
    }

    private inner class World {
        val instance = FakeInstance(crypto)
        val server = DeviceLinkServer(instance)
        val eState = MemoryDeviceState()
        lateinit var acct: LinkAccount
        lateinit var e: WireDeviceLinks
        val nState = MemoryDeviceState()
        val nSink = Sink()
        val discarded = ArrayList<String>()

        suspend fun setUp(nPinned: Boolean = true): World {
            val eTrust = instance.pinnedTrust(eState)
            val sink = Sink()
            val onboarding = WireOnboarding(instance.origin, server.client(null), eTrust, KnownDevices(eState, crypto), sink, crypto, eState, "desktop", "Laptop",
                { instance.now }, work = Dispatchers.Unconfined)
            onboarding.signupStart("alice@example.com", true)
            val ticket = assertIs<SignupVerify.Ticket>(onboarding.signupVerify("alice@example.com", "482915"))
            val reg = assertIs<Registration.Registered>(onboarding.register(RegistrationAuth.Ticket(ticket),
                RegistrationForm("alice@example.com", "Alice", password.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Laptop", "desktop")))
            val session = sink.sessions.single()
            val store = StoredAccountState(reg.userId, session.account.uvk, server.client(reg.userId), crypto, eState)
            // A contact current on E, which the bundle should make current on N too.
            store.update { it.copy(contacts = it.contacts + (bob to ContactRecord(bob, bobKey, TrustGrammar.encodeName("Bob")!!, verifiedAt = 7, compared = true, madeOn = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"))) }
            ContactCurrency(eState, crypto, instance.origin, reg.userId).mark(bob, bobKey, Currency.LINK)
            acct = LinkAccount.of(session, "Alice", store)
            e = WireDeviceLinks({ server.client(reg.userId, it) }, eTrust, eState, crypto, { instance.now }, { acct }, KnownDevices(eState, crypto), sink,
                { _, _ -> }, "Laptop", "desktop")
            if (nPinned) instance.pinnedTrust(nState)
            return this
        }

        val nTrust get() = instance.trust(nState)

        fun n() = WireDeviceLinks({ server.client(null, it) }, nTrust, nState, crypto, { instance.now }, { null }, KnownDevices(nState, crypto), nSink,
            { _, token -> discarded += token }, "Pixel 9", "android")

        /** Runs both sides to E's approval; returns N's engine and its PasswordNeeded step. */
        suspend fun approved(n: WireDeviceLinks = n()): Pair<WireDeviceLinks, NewStep.PasswordNeeded> {
            val shown = assertIs<ExistingStep.Shown>(e.create())
            val claimed = assertIs<NewStep.Claimed>(n.start(shown.url, GateEntry.LINK_DEVICE_SCREEN))
            val fixed = assertIs<ExistingStep.ClaimFixed>(e.advance(shown))
            assertEquals("Pixel 9", fixed.name)
            val code = assertIs<NewStep.ShowCode>(n.advance(claimed))
            val type = assertIs<ExistingStep.TypeDigits>(e.advance(fixed))
            val ok = assertIs<ExistingStep.Approvable>(e.typeDigits(type, code.code))
            assertIs<ExistingStep.Approved>(e.approve(ok))
            return n to assertIs<NewStep.PasswordNeeded>(n.advance(code))
        }
    }

    @Test fun linkEndToEndProvesThePasswordAndImportsTheBundle() = runBlocking<Unit> {
        val w = World().setUp()
        val (n, need) = w.approved()
        assertEquals("alice@example.com", need.email)
        assertEquals("Home", need.instanceName)
        // Nothing derived from the password went anywhere before this prompt.
        assertFalse(w.server.calls.any { it.second == WireRoute.PRELOGIN || it.second == WireRoute.DEVICE_LINK_PICKUP })
        val wrong = assertIs<NewStep.WrongPassword>(n.pickup(need, "not the password at all 1".toCharArray()))
        val pw = password.toCharArray()
        val linked = assertIs<NewStep.Linked>(n.pickup(wrong, pw))
        assertTrue(pw.all { it == '\u0000' }, "the password is wiped")
        val s = w.nSink.sessions.single()
        assertEquals(SessionHow.LINKED, s.how)
        assertEquals(linked.userId, s.userId)
        assertEquals(w.acct.userId, s.userId)
        // Prelogin and pickup went only to the pinned origin.
        assertTrue(w.server.calls.filter { it.second == WireRoute.PRELOGIN || it.second == WireRoute.DEVICE_LINK_PICKUP }.all { it.first == w.instance.origin })
        // The bundle conferred currency on the contact the account state holds with the same key.
        assertEquals(Currency.BUNDLE, ContactCurrency(w.nState, crypto, w.instance.origin, s.userId).currency(bob, bobKey),
            "E holds ${w.acct.store.local().contacts.keys}; E current: ${ContactCurrency(w.eState, crypto, w.instance.origin, s.userId).currency(bob, bobKey)}; N state ${StoredAccountState(s.userId, s.account.uvk, w.server.client(null), crypto, w.nState).local().contacts.keys}")
        assertEquals(linked.deviceId, KnownDevices(w.nState, crypto).deviceId(w.instance.origin, "alice@example.com"))
        assertTrue(w.discarded.isEmpty())
    }

    @Test fun twoStepSignInAsksForTheCodeWithoutThePasswordAgain() = runBlocking<Unit> {
        val w = World().setUp()
        w.instance.account("alice@example.com").totp = "123456"
        val (n, need) = w.approved()
        val totp = assertIs<NewStep.TotpNeeded>(n.pickup(need, password.toCharArray()))
        assertIs<NewStep.Linked>(n.pickup(totp, CharArray(0), "123456"))
        assertTrue(w.nSink.sessions.single().totpEnrolled)
    }

    /**
     * The server asked for the code after it took the password, then refused the pickup with the code: it answers a wrong
     * code and a wrong password alike from then on, so the step says what is known (refused after the code was sent),
     * never a wrong password. The server keeps the link approved within its time, so the link stays and asks for the
     * password and the code again; past the link's own time it ends. Before, a wrong code ended the link
     * (`REFUSED_AFTER_CODE`), and both devices had to start again.
     */
    @Test fun aRefusalAfterTheCodeStepIsNeverAWrongPasswordAndTheLinkStays() = runBlocking<Unit> {
        val w = World().setUp()
        w.instance.account("alice@example.com").totp = "123456"
        val (n, need) = w.approved()
        val totp = assertIs<NewStep.TotpNeeded>(n.pickup(need, password.toCharArray()))
        val again = assertIs<NewStep.WrongPassword>(n.pickup(totp, CharArray(0), "654321"))
        assertTrue(again.afterCode, "said as a refusal after the code, never a wrong password")
        assertTrue(w.nSink.sessions.isEmpty(), "nothing was linked")
        // Asked again with the password and a wrong code: still the same, and the link still stays.
        val still = assertIs<NewStep.WrongPassword>(n.pickup(again, password.toCharArray(), "111111"))
        assertTrue(still.afterCode)
        // The password and the right code: linked.
        assertIs<NewStep.Linked>(n.pickup(still, password.toCharArray(), "123456"))
        assertEquals(1, w.nSink.sessions.size)

        // Past the link's own time the refusal ends the link.
        val late = World().setUp()
        late.instance.account("alice@example.com").totp = "123456"
        val (l, asked) = late.approved()
        val code = assertIs<NewStep.TotpNeeded>(l.pickup(asked, password.toCharArray()))
        late.instance.now += WireDeviceLinks.LIFETIME_MS
        assertIs<NewStep.Stopped>(l.pickup(code, CharArray(0), "654321"))
        assertTrue(late.nSink.sessions.isEmpty())
        // The same 401 before any code was asked for stays a wrong password, and the step stays.
        val v = World().setUp()
        val (m, ask) = v.approved()
        assertIs<NewStep.WrongPassword>(m.pickup(ask, "not the password 1A!".toCharArray()))
    }

    @Test fun theRoleAndTwoStepFlagsComeFromThePickupAnswer() = runBlocking<Unit> {
        val w = World().setUp()
        w.server.pickupRole = "operator"
        w.server.pickupMustEnrollTotp = true
        val (n, need) = w.approved()
        assertIs<NewStep.Linked>(n.pickup(need, password.toCharArray()))
        val s = w.nSink.sessions.single()
        assertEquals("operator", s.role)
        assertTrue(s.mustEnrollTotp)
        assertFalse(s.totpEnrolled)
        // A role the engine does not know is not a session.
        val v = World().setUp()
        v.server.pickupRole = "admin"
        val (m, ask) = v.approved()
        assertEquals(DeviceLinkStop.IDENTITY_MISMATCH, assertIs<NewStep.Stopped>(m.pickup(ask, password.toCharArray())).reason)
        assertTrue(v.nSink.sessions.isEmpty())
    }

    /**
     * The create answer's `ttlMs` is the server's word. The countdown shown is never below 0 nor longer than
     * the 5 minutes this device asked for, at each edge and beyond it; within them it is the served value.
     */
    /**
     * A waiting link's poll (the new device) and view (the existing one) refused as too many: the link waits as long as
     * the answer says, sends nothing meanwhile, and asks again; refused twice and then answered, it goes on to the end.
     * Before, the first refusal stopped the link (the new device read it as an unreachable server).
     */
    @Test fun aWaitingLinkRefusedAsTooManyWaitsAsLongAsTheAnswerSaysAndAsksAgain() = runBlocking<Unit> {
        val w = World().setUp()
        val n = w.n()
        val shown = assertIs<ExistingStep.Shown>(w.e.create())
        val claimed = assertIs<NewStep.Claimed>(n.start(shown.url, GateEntry.LINK_DEVICE_SCREEN))
        val fixed = assertIs<ExistingStep.ClaimFixed>(w.e.advance(shown))
        fun sent(route: WireRoute) = w.server.calls.count { it.second == route }

        w.server.tooMany[WireRoute.DEVICE_LINK_POLL] = 2
        assertSame(claimed, n.advance(claimed), "refused as too many: the link is waiting")
        val polls = sent(WireRoute.DEVICE_LINK_POLL)
        w.instance.now += 29_000
        assertSame(claimed, n.advance(claimed), "nothing is asked before the wait is over")
        assertEquals(polls, sent(WireRoute.DEVICE_LINK_POLL))
        w.instance.now += 1_000
        assertSame(claimed, n.advance(claimed), "refused again: still waiting")
        assertEquals(polls + 1, sent(WireRoute.DEVICE_LINK_POLL))
        w.instance.now += 30_000
        val code = assertIs<NewStep.ShowCode>(n.advance(claimed), "answered: the link goes on")

        w.server.tooMany[WireRoute.DEVICE_LINK_VIEW] = 2
        assertSame(fixed, w.e.advance(fixed), "the existing device's view refused as too many: the link is waiting")
        val views = sent(WireRoute.DEVICE_LINK_VIEW)
        assertSame(fixed, w.e.advance(fixed))
        assertEquals(views, sent(WireRoute.DEVICE_LINK_VIEW), "nothing is asked before the wait is over")
        w.instance.now += 30_000
        assertSame(fixed, w.e.advance(fixed), "refused again: still waiting")
        w.instance.now += 30_000
        val type = assertIs<ExistingStep.TypeDigits>(w.e.advance(fixed))
        val ok = assertIs<ExistingStep.Approvable>(w.e.typeDigits(type, code.code))
        w.server.tooMany[WireRoute.DEVICE_LINK_VIEW] = 1
        assertSame(ok, w.e.approve(ok), "the approval's look refused as too many: nothing approved yet, the person may approve again")
        assertFalse(w.server.calls.any { it.second == WireRoute.DEVICE_LINK_APPROVE })
        w.instance.now += 30_000
        assertIs<ExistingStep.Approved>(w.e.approve(ok))
        val need = assertIs<NewStep.PasswordNeeded>(n.advance(code))
        assertIs<NewStep.Linked>(n.pickup(need, password.toCharArray()))
    }

    /**
     * A refusal for too many requests at a step that cannot wait (the claim, the nonce, the approval, the pickup) ends the
     * link said as what it is, with the wait the server named: never "unreachable". Before, each was `UNREACHABLE`.
     */
    @Test fun aRefusalForTooManyAtAStepThatCannotWaitIsSaidAsWhatItIsWithItsWait() = runBlocking<Unit> {
        run {
            val w = World().setUp()
            val shown = assertIs<ExistingStep.Shown>(w.e.create())
            w.server.tooMany[WireRoute.DEVICE_LINK_CLAIM] = 1
            assertEquals(NewStep.Stopped(DeviceLinkStop.TOO_MANY, retryAfterSeconds = 30), w.n().start(shown.url, GateEntry.LINK_DEVICE_SCREEN), "the claim")
        }
        run {
            val w = World().setUp()
            val shown = assertIs<ExistingStep.Shown>(w.e.create())
            assertIs<NewStep.Claimed>(w.n().start(shown.url, GateEntry.LINK_DEVICE_SCREEN))
            w.server.tooMany[WireRoute.DEVICE_LINK_NONCE] = 1
            assertEquals(ExistingStep.Stopped(DeviceLinkStop.TOO_MANY, 30), w.e.advance(shown), "the nonce")
        }
        run {
            val w = World().setUp()
            val n = w.n()
            val shown = assertIs<ExistingStep.Shown>(w.e.create())
            val claimed = assertIs<NewStep.Claimed>(n.start(shown.url, GateEntry.LINK_DEVICE_SCREEN))
            val fixed = assertIs<ExistingStep.ClaimFixed>(w.e.advance(shown))
            val code = assertIs<NewStep.ShowCode>(n.advance(claimed))
            val type = assertIs<ExistingStep.TypeDigits>(w.e.advance(fixed))
            val ok = assertIs<ExistingStep.Approvable>(w.e.typeDigits(type, code.code))
            w.server.waitSeconds = null
            w.server.tooMany[WireRoute.DEVICE_LINK_APPROVE] = 1
            assertEquals(ExistingStep.Stopped(DeviceLinkStop.TOO_MANY, null), w.e.approve(ok), "the approval, naming no wait")
        }
        run {
            val w = World().setUp()
            val n = w.n()
            val shown = assertIs<ExistingStep.Shown>(w.e.create())
            val claimed = assertIs<NewStep.Claimed>(n.start(shown.url, GateEntry.LINK_DEVICE_SCREEN))
            val fixed = assertIs<ExistingStep.ClaimFixed>(w.e.advance(shown))
            val code = assertIs<NewStep.ShowCode>(n.advance(claimed))
            val type = assertIs<ExistingStep.TypeDigits>(w.e.advance(fixed))
            assertIs<ExistingStep.Approved>(w.e.approve(assertIs<ExistingStep.Approvable>(w.e.typeDigits(type, code.code))))
            val need = assertIs<NewStep.PasswordNeeded>(n.advance(code))
            w.server.tooMany[WireRoute.DEVICE_LINK_PICKUP] = 1
            assertEquals(NewStep.Stopped(DeviceLinkStop.TOO_MANY, retryAfterSeconds = 30), n.pickup(need, password.toCharArray()), "the pickup")
        }
    }

    /**
     * A link step that waits within the link's time says for how long: the seconds left of the server's wait, rounded up,
     * while the step stays the same; nothing once the wait is over or the link went on.
     */
    @Test fun aWaitingLinkStepSaysHowLongItWaits() = runBlocking<Unit> {
        val w = World().setUp()
        val n = w.n()
        val shown = assertIs<ExistingStep.Shown>(w.e.create())
        val claimed = assertIs<NewStep.Claimed>(n.start(shown.url, GateEntry.LINK_DEVICE_SCREEN))
        assertIs<ExistingStep.ClaimFixed>(w.e.advance(shown))
        assertNull(n.waitingSeconds(claimed), "nothing holds it back yet")
        w.server.tooMany[WireRoute.DEVICE_LINK_POLL] = 1
        assertSame(claimed, n.advance(claimed))
        assertEquals(30L, n.waitingSeconds(claimed))
        w.instance.now += 29_500
        assertEquals(1L, n.waitingSeconds(claimed), "rounded up")
        w.instance.now += 500
        assertNull(n.waitingSeconds(claimed), "the wait is over")
        val code = assertIs<NewStep.ShowCode>(n.advance(claimed))
        assertNull(n.waitingSeconds(code))
    }

    /** A wait that would outlast the link's own time ends the link as expired; a refusal that names no wait waits 5 seconds. */
    @Test fun aWaitPastTheLinksOwnTimeEndsItAsExpired() = runBlocking<Unit> {
        val w = World().setUp()
        val n = w.n()
        val shown = assertIs<ExistingStep.Shown>(w.e.create())
        val claimed = assertIs<NewStep.Claimed>(n.start(shown.url, GateEntry.LINK_DEVICE_SCREEN))
        w.server.waitSeconds = null
        w.server.tooMany[WireRoute.DEVICE_LINK_POLL] = 1
        assertSame(claimed, n.advance(claimed))
        w.instance.now += 4_000
        assertSame(claimed, n.advance(claimed))
        assertEquals(1, w.server.calls.count { it.second == WireRoute.DEVICE_LINK_POLL }, "five seconds when the answer names none")
        w.instance.now += 236_000
        w.server.waitSeconds = 120
        w.server.tooMany[WireRoute.DEVICE_LINK_POLL] = 1
        assertEquals(NewStep.Stopped(DeviceLinkStop.EXPIRED), n.advance(claimed))
        assertEquals(NewStep.Stopped(DeviceLinkStop.STALE), n.advance(claimed), "the link is over on this device")
    }

    @Test fun theShownCountdownIsTheServedOneBoundedByTheLifetimeAsked() = runBlocking<Unit> {
        val w = World().setUp()
        val life = WireDeviceLinks.LIFETIME_MS
        for ((served, shown) in listOf(
            -1L to 0L, Long.MIN_VALUE to 0L, 0L to 0L, 1L to 1L, life - 1 to life - 1, life to life, life + 1 to life,
            240L * 3_600_000 to life, Long.MAX_VALUE to life,
        )) {
            w.server.createTtl = served
            assertEquals(shown, assertIs<ExistingStep.Shown>(w.e.create(), "ttlMs $served").ttlMs, "ttlMs $served")
        }
    }

    @Test fun mistypedDigitsCancelTheLink() = runBlocking<Unit> {
        val w = World().setUp()
        val n = w.n()
        val shown = assertIs<ExistingStep.Shown>(w.e.create())
        val claimed = assertIs<NewStep.Claimed>(n.start(shown.url, GateEntry.LINK_DEVICE_SCREEN))
        val fixed = assertIs<ExistingStep.ClaimFixed>(w.e.advance(shown))
        val code = assertIs<NewStep.ShowCode>(n.advance(claimed))
        val type = assertIs<ExistingStep.TypeDigits>(w.e.advance(fixed))
        val wrong = ((code.code.toInt() + 1) % 1_000_000).toString().padStart(6, '0')
        assertEquals(ExistingStep.Stopped(DeviceLinkStop.CODE_MISMATCH), w.e.typeDigits(type, wrong))
        assertTrue(w.server.rows.isEmpty(), "the link is cancelled")
        assertEquals(NewStep.Stopped(DeviceLinkStop.CANCELLED), n.advance(code))
    }

    @Test fun aServedNonceEOtherThanTheFirstHeldEndsTheLink() = runBlocking<Unit> {
        val w = World().setUp()
        val n = w.n()
        val shown = assertIs<ExistingStep.Shown>(w.e.create())
        val claimed = assertIs<NewStep.Claimed>(n.start(shown.url, GateEntry.LINK_DEVICE_SCREEN))
        w.e.advance(shown)
        val code = assertIs<NewStep.ShowCode>(n.advance(claimed))
        w.server.serveNonceE = Bytes.toB64(ByteArray(32) { 3 })
        assertEquals(NewStep.Stopped(DeviceLinkStop.NONCE_CHANGED), n.advance(code))
    }

    @Test fun onlyTheDeviceLinkScreenStartsAndNothingIsSentBeforeAPasswordPin() = runBlocking<Unit> {
        val w = World().setUp(nPinned = false)
        val n = w.n()
        val shown = assertIs<ExistingStep.Shown>(w.e.create())
        assertEquals(NewStep.Stopped(DeviceLinkStop.WRONG_ENTRY), n.start(shown.url, GateEntry.SCAN_INVITE))
        assertEquals(NewStep.Stopped(DeviceLinkStop.WRONG_ENTRY), n.start(shown.url, GateEntry.APP_LINK))
        assertEquals(NewStep.Stopped(DeviceLinkStop.BAD_LINK), n.start("https://andvaripass.com/d#v2.x.y", GateEntry.LINK_DEVICE_SCREEN))
        // An `/l` URL with a device link's three-part fragment is an invite that does not parse, and a `/d` URL with four parts too.
        assertEquals(NewStep.Stopped(DeviceLinkStop.BAD_LINK), n.start(shown.url.replace("/d#", "/l#"), GateEntry.LINK_DEVICE_SCREEN))
        assertEquals(NewStep.Stopped(DeviceLinkStop.BAD_LINK), n.start(shown.url + ".-", GateEntry.LINK_DEVICE_SCREEN))
        // No password pin: the device-link Trust Gate, and declining it sends nothing to the origin.
        val gate = assertIs<NewStep.TrustGate>(n.start(shown.url, GateEntry.LINK_DEVICE_SCREEN))
        assertEquals(w.instance.origin, gate.gate.origin)
        assertEquals(NewStep.Stopped(DeviceLinkStop.TRUST_GATE_DECLINED), n.afterTrustGate(gate, false))
        assertFalse(w.server.calls.any { it.second == WireRoute.DEVICE_LINK_CLAIM })
        assertNull(w.nTrust.pinFor(w.instance.origin))
    }

    @Test fun aBundleThatDisagreesWithThePinSignsOutAndDropsOnlyThePinThisLinkMade() = runBlocking<Unit> {
        val w = World().setUp(nPinned = false)
        // The instance has a second card, which E pinned; N pins it too through the Trust Gate of this link.
        val c0 = w.instance.cards[0]
        val c1 = InstanceCard.sign(crypto, w.instance.operatorSign, CardFields(w.instance.instanceId, 1, SignedFrame.hash(crypto, c0), w.instance.origin, "Home", w.instance.kind,
            "99999999-9999-4999-8999-999999999999", Bytes.toB64(w.instance.operatorSign.publicKey), null, w.instance.now))
        w.instance.cards += c1
        assertEquals(1L, (w.e.let { w.instance.trust(w.eState).refresh(w.instance.origin) } as io.silencelen.andvari.core.client.pin.CardStatus.Ok).pin.seq)
        val n = w.n()
        val shown = assertIs<ExistingStep.Shown>(w.e.create())
        val gate = assertIs<NewStep.TrustGate>(n.start(shown.url, GateEntry.LINK_DEVICE_SCREEN))
        val claimed = assertIs<NewStep.Claimed>(n.afterTrustGate(gate, true))
        assertNotNull(w.nTrust.pinFor(w.instance.origin))
        val fixed = assertIs<ExistingStep.ClaimFixed>(w.e.advance(shown))
        val code = assertIs<NewStep.ShowCode>(n.advance(claimed))
        assertIs<ExistingStep.Approved>(w.e.approve(assertIs(w.e.typeDigits(assertIs(w.e.advance(fixed)), code.code))))
        val need = assertIs<NewStep.PasswordNeeded>(n.advance(code))
        // The server now serves a chain that ends below the bundle's card checkpoint.
        w.instance.cards.removeAt(1)
        assertEquals(NewStep.Stopped(DeviceLinkStop.PIN_MISMATCH), n.pickup(need, password.toCharArray()))
        assertTrue(w.nSink.sessions.isEmpty(), "the session never reached the session sink")
        assertEquals(1, w.discarded.size, "and was signed out at once")
        assertNull(w.nTrust.pinFor(w.instance.origin), "the pin this link made is removed")
    }

    @Test fun aPinTheDeviceAlreadyHadIsNeverRemovedByAPinMismatch() = runBlocking<Unit> {
        val w = World().setUp(nPinned = true)
        val (n, need) = w.approved()
        val c0 = w.instance.cards[0]
        // E's pin is ahead of N's: E saw a card 1 that the server no longer serves to N.
        w.instance.cards += InstanceCard.sign(crypto, w.instance.operatorSign, CardFields(w.instance.instanceId, 1, SignedFrame.hash(crypto, c0), w.instance.origin, "Home",
            w.instance.kind, "99999999-9999-4999-8999-999999999999", Bytes.toB64(w.instance.operatorSign.publicKey), null, w.instance.now))
        // Re-run with E pinned at card 1.
        w.instance.trust(w.eState).refresh(w.instance.origin)
        val (n2, need2) = w.approved()
        w.instance.cards.removeAt(1)
        assertEquals(NewStep.Stopped(DeviceLinkStop.PIN_MISMATCH), n2.pickup(need2, password.toCharArray()))
        assertNotNull(w.nTrust.pinFor(w.instance.origin), "a pin made before the link stays")
        assertTrue(n.pickup(need, password.toCharArray()) is NewStep.Stopped, "the first link was replaced by the second")
    }

    @Test fun anInnerFromAnotherLinkIsBundleUnopenableAndTheSessionIsDiscarded() = runBlocking<Unit> {
        val w = World().setUp()
        val (_, first) = w.approved()
        val firstInner = w.server.rows.values.single().approve!!.inner
        val (n2, need2) = w.approved()
        w.server.swapInner = firstInner
        assertEquals(NewStep.Stopped(DeviceLinkStop.BUNDLE_UNOPENABLE), n2.pickup(need2, password.toCharArray()))
        assertEquals(1, w.discarded.size)
        assertTrue(w.nSink.sessions.isEmpty())
        assertNotNull(first)
    }

    @Test fun aVaultsCheckpointIsTheHigherOfItsRecordAndThisDevicesVerifiedHead() = runBlocking<Unit> {
        val w = World().setUp()
        val me = w.acct.userId
        val vaultId = "00000000-0000-4000-8000-0000000000aa"
        val member = "00000000-0000-4000-8000-0000000000bb"
        val memberKey = Bytes.toB64(crypto.sha256("member".encodeToByteArray()))
        val frames = ArrayList<ByteArray>()
        fun state() = io.silencelen.andvari.core.trust.VaultLog.replay(crypto, vaultId, frames, from = null, known = io.silencelen.andvari.core.trust.KnownHashes.NONE_HELD).state
        fun sign(entry: io.silencelen.andvari.core.trust.LogEntry) {
            val c = w.acct.signing.use { io.silencelen.andvari.core.trust.VaultLog.signChecked(crypto, it, if (frames.isEmpty()) null else state(), entry) }
            frames += (c as io.silencelen.andvari.core.trust.Checked.Ok).value.frame
        }
        val t = 1_763_164_800_000L
        sign(io.silencelen.andvari.core.trust.LogEntry.Genesis(vaultId, me, t, Bytes.toB64(w.acct.identity.publicKey),
            io.silencelen.andvari.core.trust.VaultLog.vkCommit(crypto, ByteArray(32) { 7 }, vaultId)))
        val s0 = state()!!
        var p = io.silencelen.andvari.core.trust.VaultLog.position(s0, t + 1)
        sign(io.silencelen.andvari.core.trust.LogEntry.Add(vaultId, p.seq, p.prev, me, p.at, member, memberKey, io.silencelen.andvari.core.trust.MemberRole.WRITER, Bytes.toB64(ByteArray(16))))
        p = io.silencelen.andvari.core.trust.VaultLog.position(state()!!, t + 2)
        sign(io.silencelen.andvari.core.trust.LogEntry.Remove(vaultId, p.seq, p.prev, me, p.at, member))
        val s2 = state()!!
        assertEquals(2, s2.head.seq)

        // The account's record lags at the genesis (records are written in batches); this device verified seq 2.
        val record = io.silencelen.andvari.core.client.state.VaultRecord(vaultId, s0.genesisHash, 0, s0.head.hash)
        w.acct.store.update { it.copy(vaults = it.vaults + (vaultId to record)) }
        fun bundled() = w.e.fill(w.acct, w.acct.personalVaultId!!, io.silencelen.andvari.core.trust.Checkpoint(0, "0".repeat(64)), w.instance.instanceId)!!
            .vaults.single { it.vaultId == vaultId }
        assertEquals(io.silencelen.andvari.core.trust.BundleVault(vaultId, 0, s0.head.hash), bundled(), "no verified state: the record")
        w.eState.set("ovh.log|$me|$vaultId|state", s2.encode())
        assertEquals(io.silencelen.andvari.core.trust.BundleVault(vaultId, 2, s2.head.hash), bundled(), "the verified head is higher")

        // A record above the verified head stays; a stored state of another log (another genesis) never raises it.
        w.acct.store.update { it.copy(vaults = it.vaults + (vaultId to record.copy(seq = 5, hash = "c".repeat(64)))) }
        assertEquals(io.silencelen.andvari.core.trust.BundleVault(vaultId, 5, "c".repeat(64)), bundled())
        w.acct.store.update { it.copy(vaults = it.vaults + (vaultId to record.copy(genesisHash = "d".repeat(64)))) }
        assertEquals(io.silencelen.andvari.core.trust.BundleVault(vaultId, 0, s0.head.hash), bundled())
        w.eState.set("ovh.log|$me|$vaultId|state", "not a state")
        w.acct.store.update { it.copy(vaults = it.vaults + (vaultId to record)) }
        assertEquals(io.silencelen.andvari.core.trust.BundleVault(vaultId, 0, s0.head.hash), bundled(), "an unreadable state raises nothing")
    }

    @Test fun theBundleFillsMostRecentlyVerifiedFirstUntilFull() = runBlocking<Unit> {
        val w = World().setUp()
        val many = (0 until 900).associate { i ->
            val id = "00000000-0000-4000-8000-" + i.toString().padStart(12, '0')
            val key = Bytes.toB64(crypto.sha256(byteArrayOf(i.toByte(), (i shr 8).toByte())))
            id to ContactRecord(id, key, TrustGrammar.encodeName("P$i")!!, verifiedAt = i.toLong(), compared = false, madeOn = "dddddddd-dddd-4ddd-8ddd-dddddddddddd")
        }
        w.acct.store.update { it.copy(contacts = it.contacts + many) }
        val cur = ContactCurrency(w.eState, crypto, w.instance.origin, w.acct.userId)
        many.values.forEach { cur.mark(it.userId, it.identityPub, Currency.LINK) }
        val bundle = w.e.fill(w.acct, w.acct.personalVaultId!!, io.silencelen.andvari.core.trust.Checkpoint(0, "0".repeat(64)), w.instance.instanceId)!!
        assertTrue(bundle.contacts.size in 1 until 901, "not everything fits: ${bundle.contacts.size} of ${w.acct.store.local().contacts.size}")
        assertTrue(io.silencelen.andvari.core.trust.DeviceLink.fits(bundle))
        assertEquals(899L, bundle.contacts.first().verifiedAt, "the most recently verified first")
        assertTrue(bundle.contacts.zipWithNext().all { (a, b) -> a.verifiedAt >= b.verifiedAt })
    }

    /**
     * The pickup derives at the cost the prelogin serves, so that cost passes the whole fence first: floor, ceiling and a
     * whole number of KiB. A ragged cost passes the floor and the ceiling; before, it was derived at (the Argon2id engines
     * round it differently) and a refused proof read as a wrong password. Now nothing is derived or sent, and the stop is
     * the server's fault.
     */
    @Test fun aPickupAtARaggedServedCostDerivesNothingAndStopsAsTheServersFault() = runBlocking<Unit> {
        val w = World().setUp()
        val derived = ArrayList<Long>()
        val counting = object : io.silencelen.andvari.core.crypto.CryptoProvider by crypto {
            override fun argon2id(password: ByteArray, salt: ByteArray, outLen: Int, opsLimit: Long, memLimitBytes: Long): ByteArray {
                derived += memLimitBytes
                return crypto.argon2id(password, salt, outLen, opsLimit, memLimitBytes)
            }
        }
        val n = WireDeviceLinks({ w.server.client(null, it) }, w.nTrust, w.nState, counting, { w.instance.now }, { null }, KnownDevices(w.nState, crypto), w.nSink,
            { _, token -> w.discarded += token }, "Pixel 9", "android")
        val (_, need) = w.approved(n)
        w.instance.accounts.values.single().kdfParams = io.silencelen.andvari.core.crypto.KdfParams(ops = 3, memBytes = 64L * 1024 * 1024 + 1)
        val stop = assertIs<NewStep.Stopped>(n.pickup(need, password.toCharArray()))
        assertEquals(DeviceLinkStop.KDF_REFUSED, stop.reason)
        assertEquals(emptyList(), derived, "nothing was derived at the ragged cost")
        assertFalse(w.server.calls.any { it.second == WireRoute.DEVICE_LINK_PICKUP }, "nothing derived from the password was sent")
        assertTrue(w.nSink.sessions.isEmpty())
    }

    /**
     * A pickup whose first exchange (the prelogin) gets no usable answer ends with what is so, in one exchange and with
     * nothing derived. Before, it handed the same password step back, and a caller that asks for the password on that
     * step (the command-line tool) asked again without end: an answer the device cannot read (as a host's fence at the
     * wire makes of a cost outside the limits) is the server's fault, [DeviceLinkStop.KDF_REFUSED]; no answer at all is
     * [DeviceLinkStop.UNREACHABLE].
     */
    @Test fun aPickupWhosePreloginGetsNoUsableAnswerEndsInOneExchangeWithNothingDerived() = runBlocking<Unit> {
        for ((kind, expected) in listOf(
            io.silencelen.andvari.core.client.net.NoAnswerKind.UNDECODABLE to DeviceLinkStop.KDF_REFUSED,
            io.silencelen.andvari.core.client.net.NoAnswerKind.TRANSPORT to DeviceLinkStop.UNREACHABLE,
            io.silencelen.andvari.core.client.net.NoAnswerKind.TIMEOUT to DeviceLinkStop.UNREACHABLE,
        )) {
            val w = World().setUp()
            var derived = 0
            var prelogins = 0
            val counting = object : io.silencelen.andvari.core.crypto.CryptoProvider by crypto {
                override fun argon2id(password: ByteArray, salt: ByteArray, outLen: Int, opsLimit: Long, memLimitBytes: Long): ByteArray {
                    derived++
                    return crypto.argon2id(password, salt, outLen, opsLimit, memLimitBytes)
                }
            }
            val n = WireDeviceLinks({ origin ->
                val inner = w.server.client(null, origin)
                object : io.silencelen.andvari.core.client.net.WireClient by inner {
                    override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): io.silencelen.andvari.core.client.net.WireResult<T> {
                        if (route != WireRoute.PRELOGIN) return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
                        prelogins++
                        return io.silencelen.andvari.core.client.net.WireResult.NoAnswer(kind)
                    }
                }
            }, w.nTrust, w.nState, counting, { w.instance.now }, { null }, KnownDevices(w.nState, crypto), w.nSink,
                { _, token -> w.discarded += token }, "Pixel 9", "android")
            val (_, need) = w.approved(n)
            val typed = password.toCharArray()
            val stop = assertIs<NewStep.Stopped>(n.pickup(need, typed), "$kind")
            assertEquals(expected, stop.reason, "$kind")
            assertEquals(1, prelogins, "$kind: one exchange")
            assertEquals(0, derived, "$kind: nothing derived")
            assertTrue(typed.all { it == '\u0000' }, "$kind: the password is wiped")
            assertFalse(w.server.calls.any { it.second == WireRoute.DEVICE_LINK_PICKUP }, "$kind: nothing derived from the password was sent")
            assertTrue(w.nSink.sessions.isEmpty())
            // The step it was handed is spent: handed back again, it is stale, and nothing more is sent.
            assertEquals(DeviceLinkStop.STALE, assertIs<NewStep.Stopped>(n.pickup(need, password.toCharArray())).reason, "$kind")
            assertEquals(1, prelogins, "$kind: still one exchange")
        }
    }

    /**
     * A user id of all zeros is never an account: a pickup answer whose session names it opens nothing, the session the
     * server handed out is given back, and nothing is kept. (The link names the approving account's own id, so this answer
     * is refused by that comparison as well; the nil check holds even where both would agree.)
     */
    @Test fun aPickupAnswerNamingTheNilUserIdOpensNothingAndGivesTheSessionBack() = runBlocking<Unit> {
        val w = World().setUp()
        val real = w.acct.userId
        val n = WireDeviceLinks({ origin ->
            val inner = w.server.client(null, origin)
            object : io.silencelen.andvari.core.client.net.WireClient by inner {
                override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): io.silencelen.andvari.core.client.net.WireResult<T> =
                    if (route != WireRoute.DEVICE_LINK_PICKUP) inner.call(route, pathParams, query, bodyJson, authenticated, decode)
                    else inner.call(route, pathParams, query, bodyJson, authenticated) { decode(it.replace(real, "00000000-0000-0000-0000-000000000000")) }
            }
        }, w.nTrust, w.nState, crypto, { w.instance.now }, { null }, KnownDevices(w.nState, crypto), w.nSink,
            { _, token -> w.discarded += token }, "Pixel 9", "android")
        val (_, need) = w.approved(n)
        val stop = assertIs<NewStep.Stopped>(n.pickup(need, password.toCharArray()))
        assertEquals(DeviceLinkStop.IDENTITY_MISMATCH, stop.reason)
        assertTrue(w.nSink.sessions.isEmpty(), "no session names the nil id")
        assertEquals(1, w.discarded.size, "the session the server handed out is given back")
        assertTrue(w.server.calls.any { it.second == WireRoute.DEVICE_LINK_PICKUP })
    }
}
