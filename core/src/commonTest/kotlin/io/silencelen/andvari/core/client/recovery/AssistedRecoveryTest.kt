package io.silencelen.andvari.core.client.recovery

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.items.copyOut
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
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.onboard.SignupVerify
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KeyPairBytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.RecoveryPollRequest
import io.silencelen.andvari.core.model.wire.RecoveryPollResponse
import io.silencelen.andvari.core.model.wire.RecoveryRequestCommit
import io.silencelen.andvari.core.model.wire.RecoveryRequestCreate
import io.silencelen.andvari.core.model.wire.RecoveryRequestCreated
import io.silencelen.andvari.core.model.wire.RecoveryRequestSummary
import io.silencelen.andvari.core.model.wire.RecoveryRequestVerified
import io.silencelen.andvari.core.model.wire.RecoveryRequestVerify
import io.silencelen.andvari.core.model.wire.RecoveryVetoRequest
import io.silencelen.andvari.core.model.wire.SessionResponse
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.AssistedRecoveryFields
import io.silencelen.andvari.core.trust.Checked
import io.silencelen.andvari.core.trust.InstanceKind
import io.silencelen.andvari.core.trust.RecoveryVeto
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.builtins.ListSerializer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import io.silencelen.andvari.core.trust.AssistedRecovery as AssistedRecoveryTrust

/** Operator-assisted recovery (design §9.3, §2.4; spec 03 §18) against [FakeInstance] with the §18 routes in [Assist]. */
class AssistedRecoveryTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val newPw = "a whole new Passphrase 42 here"
    private val recoverySigner: KeyPairBytes = crypto.signKeypairFromSeed(ByteArray(32) { 2 })
    private val recoveryFp = Escrow.fingerprint(crypto, crypto.boxKeypairFromSeed(ByteArray(32) { 2 }).publicKey)

    private class Sink : SessionSink {
        val sessions = ArrayList<EstablishedSession>()
        override suspend fun established(session: EstablishedSession) { sessions += session }
    }

    /** The §18 routes as an honest server answers them, over [inner]; the test plays the operator through [fulfil]. */
    private inner class Assist(val inner: FakeInstance) : WireClient {
        override val origin: String get() = inner.origin
        inner class Req(val email: String, val rPub: String, val pollHash: String, val userId: String) {
            var state = "unverified"
            /** The owner cancelled it before its code was entered: its poll stays `unverified`, its right code is `409`. */
            var cancelled = false
            var holdEndsAt: Long? = null
            var sealed: String? = null
            var served: FakeInstance.Account? = null
            /** The hash of the uploaded answer's commit value (spec 03 §18.6), and every commit value presented. */
            var commitHash: String? = null
            val presented = ArrayList<String?>()
        }
        val reqs = LinkedHashMap<String, Req>()
        val calls = ArrayList<WireRoute>()
        val bodies = ArrayList<String>()
        val code = "314159"
        private var n = 0

        private fun refuse(status: Int, code: String): WireResult<Nothing> = WireResult.Refused(status, WireError(code, code))

        fun accountById(userId: String) = inner.accounts.values.first { it.userId == userId }

        /** Whether `ready` carries the stored commit hash (a server from before that change does not), and a lie in its place. */
        var sendCommitHash = true
        var servedCommitHash: String? = null

        /** Rows a lying server adds to the account's list of requests. */
        var extraRows: List<kotlinx.serialization.json.JsonElement> = emptyList()

        /** Runs once the server has acted on a request of this route and before the device has its answer: a leave lands here. */
        var during: Pair<WireRoute, () -> Unit>? = null

        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> =
            answer(route, pathParams, query, bodyJson, authenticated, decode).also {
                during?.takeIf { it.first == route }?.let { (_, leave) -> during = null; leave() }
            }

        @Suppress("UNCHECKED_CAST")
        private suspend fun <T> answer(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            calls += route
            bodies += bodyJson ?: ""
            val assisted = route in setOf(WireRoute.RECOVERY_REQUEST_CREATE, WireRoute.RECOVERY_REQUEST_VERIFY, WireRoute.RECOVERY_REQUEST_POLL,
                WireRoute.RECOVERY_REQUEST_COMMIT, WireRoute.RECOVERY_REQUEST_VETO, WireRoute.ACCOUNT_RECOVERY_REQUESTS)
            if (!assisted) return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
            if (inner.kind == InstanceKind.PUBLIC) return refuse(404, "not_found")
            fun ok(text: String): WireResult<T> = WireResult.Ok(decode(text), 200)
            val id = pathParams["requestId"]
            return when (route) {
                WireRoute.RECOVERY_REQUEST_CREATE -> {
                    val b = WireJson.json.decodeFromString(RecoveryRequestCreate.serializer(), bodyJson!!)
                    n++
                    val requestId = Bytes.toB64(ByteArray(16) { (it + n).toByte() })
                    inner.accounts[io.silencelen.andvari.core.trust.TrustGrammar.emailNorm(b.email)]?.let { reqs[requestId] = Req(b.email, b.rPub, b.pollHash, it.userId) }
                    WireResult.Ok(decode(WireJson.json.encodeToString(RecoveryRequestCreated.serializer(), RecoveryRequestCreated(requestId))), 202)
                }
                WireRoute.RECOVERY_REQUEST_VERIFY -> {
                    val b = WireJson.json.decodeFromString(RecoveryRequestVerify.serializer(), bodyJson!!)
                    if (id !in reqs) return refuse(404, "request_unknown")
                    val r = reqs[id]?.takeIf { it.state == "unverified" && b.code == code } ?: return refuse(400, "bad_code")
                    if (r.cancelled) {
                        r.state = "vetoed"
                        return refuse(409, "request_state")
                    }
                    r.state = "holding"; r.holdEndsAt = inner.now + 7 * 86_400_000L
                    ok(WireJson.json.encodeToString(RecoveryRequestVerified.serializer(), RecoveryRequestVerified("holding", r.holdEndsAt!!)))
                }
                WireRoute.RECOVERY_REQUEST_POLL -> {
                    val b = WireJson.json.decodeFromString(RecoveryPollRequest.serializer(), bodyJson!!)
                    val r = byPoll(id, b.pollSecret) ?: return refuse(404, "request_unknown")
                    val s = r.served
                    val resp = when {
                        r.state == "vetoed" -> RecoveryPollResponse("vetoed")
                        r.sealed != null && s != null -> RecoveryPollResponse("ready", null, r.sealed, s.encryptedIdentitySeed, s.identityPub,
                            commitHash = if (sendCommitHash) servedCommitHash ?: r.commitHash else null)
                        r.state == "holding" && inner.now >= r.holdEndsAt!! -> RecoveryPollResponse("awaiting_operator", r.holdEndsAt)
                        else -> RecoveryPollResponse(r.state, r.holdEndsAt)
                    }
                    ok(WireJson.json.encodeToString(RecoveryPollResponse.serializer(), resp))
                }
                WireRoute.RECOVERY_REQUEST_COMMIT -> {
                    val b = WireJson.json.decodeFromString(RecoveryRequestCommit.serializer(), bodyJson!!)
                    val r = byPoll(id, b.pollSecret) ?: return refuse(404, "request_unknown")
                    if (r.sealed == null || r.state == "vetoed") return refuse(409, "request_state")
                    // spec 03 §18.5: only a device that opened the answer has its commit value.
                    r.presented += b.commit
                    val presentedHash = b.commit?.let { AssistedRecoveryTrust.commitHashOf(crypto, it) } ?: return refuse(400, "bad_commit")
                    if (presentedHash != r.commitHash) return refuse(403, "commit_mismatch")
                    if (inner.belowFloor(b.newKdfParams)) return refuse(400, "kdf_too_weak")
                    val a = accountById(r.userId)
                    a.authKey = b.newAuthKey; a.kdfSalt = b.newKdfSalt; a.kdfParams = b.newKdfParams; a.wrappedUvk = b.newWrappedUvk
                    a.memberRecovery = b.newMemberRecovery ?: return refuse(400, "recovery_required")
                    a.pieceId = Bytes.toB64(ByteArray(32) { (90 + n).toByte() }); a.recoveryConfirmed = false; a.requireLink = false; a.totp = null
                    a.devices.clear()
                    val deviceId = "00000000-0000-4000-8000-0000000008${n.toString().padStart(2, '0')}"
                    a.devices[deviceId] = b.device.deviceSecret
                    reqs.remove(id)
                    ok(WireJson.json.encodeToString(SessionResponse.serializer(),
                        SessionResponse(a.userId, deviceId, "at-$deviceId", "rt-$deviceId", inner.keys(a), "member", false, false, a.pieceId)))
                }
                // Spec 03 §18.3: every verified live request, `ready` once answered. [extraRows] are a lying server's own.
                WireRoute.ACCOUNT_RECOVERY_REQUESTS -> {
                    val rows = reqs.filter { it.value.state == "holding" }.map { (rid, r) ->
                        val state = when {
                            r.sealed != null -> "ready"
                            inner.now >= r.holdEndsAt!! -> "awaiting_operator"
                            else -> "holding"
                        }
                        WireJson.json.encodeToJsonElement(RecoveryRequestSummary.serializer(), RecoveryRequestSummary(rid, state, inner.now, inner.now, r.holdEndsAt!!, "android"))
                    }
                    ok(kotlinx.serialization.json.JsonArray(rows + extraRows).toString())
                }
                WireRoute.RECOVERY_REQUEST_VETO -> {
                    val b = WireJson.json.decodeFromString(RecoveryVetoRequest.serializer(), bodyJson!!)
                    val r = reqs[id] ?: return refuse(404, "request_unknown")
                    val a = accountById(r.userId)
                    val v = RecoveryVeto.verify(crypto, Bytes.fromB64(b.statement), Bytes.fromB64(a.identityPub), a.userId, id!!)
                    if (v !is Checked.Ok) return refuse(400, "bad_signer")
                    r.state = "vetoed"; r.sealed = null
                    ok("{}")
                }
                else -> error("unreachable")
            }
        }

        private fun byPoll(id: String?, pollSecret: String): Req? {
            val r = reqs[id] ?: return null
            return r.takeIf { Bytes.toHexLower(crypto.sha256(Bytes.fromB64(pollSecret))) == it.pollHash }
        }

        /**
         * The operator's `recovery-cli assist` and `fulfil`: a 0x09 payload for [account] signed by [signer], sealed to
         * the request's `rPub` (or [sealTo]), with the served identity fields of [served].
         */
        fun fulfil(
            requestId: String, account: FakeInstance.Account, uvk: ByteArray, signer: KeyPairBytes = recoverySigner, payloadRequestId: String = requestId,
            served: FakeInstance.Account = account, sealTo: ByteArray? = null,
            /** The address the answer names (the copy's own); null makes the old version-2 answer. */
            email: String? = inner.accounts.entries.first { it.value.userId == account.userId }.key,
        ) {
            val r = reqs.getValue(requestId)
            val rPub = Bytes.fromB64(r.rPub)
            val commit = crypto.randomBytes(32)
            val frame = AssistedRecoveryTrust.sign(crypto, signer, AssistedRecoveryFields(inner.instanceId, account.userId, payloadRequestId, r.rPub, uvk, inner.now,
                email = email, commit = email?.let { commit }))
            r.sealed = Bytes.toB64(AssistedRecoveryTrust.seal(crypto, sealTo ?: rPub, frame))
            r.commitHash = AssistedRecoveryTrust.commitHash(crypto, commit)
            r.served = served
        }
    }

    private class Registered(val session: EstablishedSession, val account: FakeInstance.Account)

    private suspend fun register(server: FakeInstance, email: String): Registered {
        val state = MemoryDeviceState()
        val sink = Sink()
        val o = WireOnboarding(server.origin, server, server.pinnedTrust(state), KnownDevices(state, crypto), sink, crypto, state, "android", "Old",
            { server.now }, work = Dispatchers.Unconfined)
        o.signupStart(email, true)
        val t = o.signupVerify(email, "482915") as SignupVerify.Ticket
        assertIs<Registration.Registered>(o.register(RegistrationAuth.Ticket(t), RegistrationForm(email, "A", strong.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Old", "android")))
        return Registered(sink.sessions.single(), server.account(email))
    }

    private class Fresh(val engine: WireAssistedRecovery, val sink: Sink, val pins: MemoryDeviceState, val secure: MemoryDeviceState)

    private fun fresh(a: Assist, pins: MemoryDeviceState = MemoryDeviceState(), secure: MemoryDeviceState = MemoryDeviceState()): Fresh {
        val sink = Sink()
        val engine = WireAssistedRecovery({ a }, a.inner.trust(pins), KnownDevices(pins, crypto), sink, crypto, secure, "android", "New", { a.inner.now })
        return Fresh(engine, sink, pins, secure)
    }

    private fun setup(kind: InstanceKind = InstanceKind.PRIVATE): Assist = Assist(FakeInstance(crypto, kind = kind, recoveryFp = recoveryFp))

    /** Start, pass the Trust Gate, request and verify the emailed code: the request is holding. */
    private suspend fun holding(a: Assist, f: Fresh, email: String = "alice@example.com"): Pair<String, AssistedStep.Waiting> {
        val target = assertIs<AssistedStep.ConfirmTarget>(f.engine.start(email, a.origin))
        val requested = assertIs<AssistedStep.Requested>(f.engine.request(target))
        val waiting = assertIs<AssistedStep.Waiting>(f.engine.verifyCode(requested, a.code))
        return a.reqs.keys.last() to waiting
    }

    @Test fun theFullFlowRequestsVerifiesHoldsPicksUpChecksTheAccountAndCommits() = runBlocking<Unit> {
        val a = setup()
        val alice = register(a.inner, "alice@example.com")
        val oldPiece = alice.account.pieceId
        a.inner.account("alice@example.com").requireLink = true
        val f = fresh(a)
        // Fresh install, no pin: the Trust Gate in the same confirmation, and nothing sent.
        val target = assertIs<AssistedStep.ConfirmTarget>(f.engine.start("Alice@Example.com", a.origin))
        assertNotNull(target.gate)
        assertEquals("Home", target.instanceName)
        assertFalse(WireRoute.RECOVERY_REQUEST_CREATE in a.calls, "nothing sent before the person confirms")
        assertNull(a.inner.trust(f.pins).pinFor(a.origin), "nothing pinned before the gate is confirmed")
        val requested = assertIs<AssistedStep.Requested>(f.engine.request(target))
        assertEquals(PinRoot.TRUST_GATE, a.inner.trust(f.pins).pinFor(a.origin)!!.root)
        val (requestId, req) = a.reqs.entries.single().toPair()
        // The request code is derived from this device's request key, as the operator's CLI will check it.
        assertTrue(AssistedRecoveryTrust.requestCodeMatches(crypto, requested.requestCode, Bytes.fromB64(req.rPub)))
        assertEquals(6, requested.requestCode.split(' ').size)
        // A wrong code and a code that cannot be one are the same answer, and the step stays.
        assertEquals("bad_code", assertIs<AssistedStep.Stopped>(f.engine.verifyCode(requested, "000000")).reason)
        val sent = a.calls.size
        assertEquals("bad_code", assertIs<AssistedStep.Stopped>(f.engine.verifyCode(requested, "12ab")).reason)
        assertEquals(sent, a.calls.size)
        val waiting = assertIs<AssistedStep.Waiting>(f.engine.verifyCode(requested, " ${a.code} "))
        assertEquals("holding", waiting.state)
        assertEquals(requested.requestCode, waiting.requestCode)
        // The poll secret travels in the body, and only its hash was sent at the request.
        assertIs<AssistedStep.Waiting>(f.engine.poll(waiting))
        assertTrue(a.bodies.last().contains("pollSecret"))
        // A restart: the request, rSec and pollSecret survive in the secure store.
        val g = fresh(a, f.pins, f.secure)
        assertEquals(listOf(a.origin), g.engine.keptOrigins())
        a.inner.now += 7 * 86_400_000L
        val again = assertIs<AssistedStep.Waiting>(g.engine.resume(a.origin))
        assertEquals("awaiting_operator", again.state)
        a.fulfil(requestId, alice.account, alice.session.account.uvk.copyOut())
        val check = assertIs<AssistedStep.CheckAccount>(g.engine.poll(again))
        assertEquals(alice.session.account.accountId(crypto), check.accountId)
        assertEquals("Alice@Example.com", check.email)
        // No way around the account check: a ChoosePassword made from its handle is refused, and nothing is sent.
        val before = a.calls.size
        assertEquals("stale", assertIs<AssistedStep.Stopped>(g.engine.commit(AssistedStep.ChoosePassword(check.handle), newPw.toCharArray())).reason)
        assertEquals(before, a.calls.size)
        val choose = assertIs<AssistedStep.ChoosePassword>(g.engine.confirmAccount(check, true))
        assertEquals("password_too_weak", assertIs<AssistedStep.Stopped>(g.engine.commit(choose, "weak".toCharArray())).reason)
        val pw = newPw.toCharArray()
        val done = assertIs<AssistedStep.Recovered>(g.engine.commit(choose, pw))
        assertTrue(pw.all { it == '\u0000' })
        val acct = a.inner.account("alice@example.com")
        assertEquals(alice.account.userId, done.userId)
        assertNotEquals(oldPiece, acct.pieceId, "the commit replaced the kit")
        assertEquals(acct.pieceId, done.newKit.pieceId)
        assertEquals(alice.session.account.accountId(crypto), done.newKit.accountId)
        assertFalse(acct.requireLink)
        assertEquals(SessionHow.RECOVERED, g.sink.sessions.single().how)
        assertTrue(g.engine.keptOrigins().isEmpty(), "rSec and pollSecret are gone after the commit")
        // spec 03 §18.5: the commit carried the value inside the answer this device opened.
        val presented = assertNotNull(req.presented.single())
        assertEquals(req.commitHash, AssistedRecoveryTrust.commitHashOf(crypto, presented))
    }

    /**
     * The answer says whose account it restores. The tool copies the address from the copy
     * it opened, so another member's genuine answer names that member, and the person's device, asking for alice and
     * holding no account (a fresh install), refuses it at the pick-up; and the old form, which names no address, too.
     */
    @Test fun aFreshInstallRefusesAnAnswerForAnotherAddress_andAnAnswerOfTheOldForm() = runBlocking<Unit> {
        val a = setup()
        val alice = register(a.inner, "alice@example.com")
        val mallory = register(a.inner, "mallory@example.com")
        val f = fresh(a)
        val (requestId, waiting) = holding(a, f)
        a.fulfil(requestId, mallory.account, mallory.session.account.uvk.copyOut())
        assertEquals("request_mismatch", assertIs<AssistedStep.Stopped>(f.engine.poll(waiting)).reason)
        // Alice's own account and key, but the old version 2: refused for its version alone.
        a.fulfil(requestId, alice.account, alice.session.account.uvk.copyOut(), email = null)
        assertEquals("bad_statement", assertIs<AssistedStep.Stopped>(f.engine.poll(waiting)).reason)
        assertTrue(WireRoute.RECOVERY_REQUEST_COMMIT !in a.calls && f.sink.sessions.isEmpty())
        // The request is kept: the right answer still goes through.
        a.fulfil(requestId, alice.account, alice.session.account.uvk.copyOut())
        assertIs<AssistedStep.CheckAccount>(f.engine.poll(waiting))
    }

    /** Spec 03 §18.6: an upload made after this device opened the answer replaces it; the commit is refused, and the next poll picks up the newer one. */
    @Test fun aNewerUploadMeansCommitMismatch_thenTheNextPollPicksItUpAndCommits() = runBlocking<Unit> {
        val a = setup()
        val alice = register(a.inner, "alice@example.com")
        val f = fresh(a)
        val (requestId, waiting) = holding(a, f)
        a.inner.now += 7 * 86_400_000L
        a.fulfil(requestId, alice.account, alice.session.account.uvk.copyOut())
        val check = assertIs<AssistedStep.CheckAccount>(f.engine.poll(waiting))
        val choose = assertIs<AssistedStep.ChoosePassword>(f.engine.confirmAccount(check, true))
        a.fulfil(requestId, alice.account, alice.session.account.uvk.copyOut())
        assertEquals("commit_mismatch", assertIs<AssistedStep.Stopped>(f.engine.commit(choose, newPw.toCharArray())).reason)
        assertTrue(f.sink.sessions.isEmpty())
        assertEquals(listOf(a.origin), f.engine.keptOrigins(), "the request is kept")
        val again = assertIs<AssistedStep.CheckAccount>(assertNotNull(f.engine.resume(a.origin)))
        val choose2 = assertIs<AssistedStep.ChoosePassword>(f.engine.confirmAccount(again, true))
        assertIs<AssistedStep.Recovered>(f.engine.commit(choose2, newPw.toCharArray()))
    }

    @Test fun aGenuinePayloadForAnotherAccountStopsAtTheAccountCheckAndSendsNothingFurther() = runBlocking<Unit> {
        val a = setup()
        val alice = register(a.inner, "alice@example.com")
        val mallory = register(a.inner, "mallory@example.com")
        val f = fresh(a)
        val (requestId, waiting) = holding(a, f)
        // A signer of the pinned recovery key who names alice's address over mallory's account and UVK, mallory's identity
        // served (the tool never makes this: it copies the address from the copy it opened, and a server holding the
        // recovery key of a chain it served on a fresh install could). Only the person's account check stands.
        a.fulfil(requestId, mallory.account, mallory.session.account.uvk.copyOut(), email = "alice@example.com")
        val check = assertIs<AssistedStep.CheckAccount>(f.engine.poll(waiting))
        assertEquals(mallory.session.account.accountId(crypto), check.accountId, "the person is shown the account actually delivered")
        assertNotEquals(alice.session.account.accountId(crypto), check.accountId)
        val sent = a.calls.size
        assertEquals("account_rejected", assertIs<AssistedStep.Stopped>(f.engine.confirmAccount(check, false)).reason)
        assertEquals(sent, a.calls.size, "rejecting sends nothing")
        assertTrue(f.engine.keptOrigins().isEmpty(), "rSec and pollSecret are dropped")
        assertEquals("stale", assertIs<AssistedStep.Stopped>(f.engine.confirmAccount(check, true)).reason)
        assertEquals("stale", assertIs<AssistedStep.Stopped>(f.engine.poll(waiting)).reason)
        assertEquals(sent, a.calls.size)
        assertTrue(f.sink.sessions.isEmpty())
        assertEquals(mallory.account.authKey, a.inner.account("mallory@example.com").authKey)
    }

    /** A sink that keeps [kept] (an account's copy as a device holds it, spec 01 §7) and takes every session it is handed. */
    private class KeptSink(private val kept: io.silencelen.andvari.core.client.onboard.KeptAccountKeys) : SessionSink {
        val sessions = ArrayList<EstablishedSession>()
        override suspend fun established(session: EstablishedSession) { sessions += session }
        override fun keptForSignIn(origin: String) = kept
    }

    /** A device that keeps [alice]'s copy, as the server served her keys. */
    private fun keeping(a: Assist, alice: Registered): Pair<Fresh, KeptSink> {
        val pins = MemoryDeviceState()
        val sink = KeptSink(io.silencelen.andvari.core.client.onboard.KeptAccountKeys(alice.account.userId, a.inner.keys(alice.account), null))
        val engine = WireAssistedRecovery({ a }, a.inner.trust(pins), KnownDevices(pins, crypto), sink, crypto, MemoryDeviceState(), "android", "New", { a.inner.now })
        return Fresh(engine, Sink(), pins, MemoryDeviceState()) to sink
    }

    /**
     * Spec 01 §7, an assisted recovery on a device that keeps the account: the delivered key opens the copy's sealed
     * identity seed (no kept wrap can be compared: the person has lost the password), and the recovery goes on as before.
     */
    @Test fun anAssistedRecoveryOverAKeptCopyOfTheSameAccountRecovers() = runBlocking<Unit> {
        val a = setup()
        val alice = register(a.inner, "alice@example.com")
        val (f, sink) = keeping(a, alice)
        val (_, check) = pickedUp(a, f, alice)
        val choose = assertIs<AssistedStep.ChoosePassword>(f.engine.confirmAccount(check, true))
        assertIs<AssistedStep.Recovered>(f.engine.commit(choose, newPw.toCharArray()))
        assertEquals(1, sink.sessions.size)
    }

    /**
     * A signer of the pinned recovery key who delivers, for the kept account's own id, another key with a seed sealed under
     * it and that seed's identity served beside it (a consistent lie, to a host that passes no record of identity keys).
     * Before, the person was asked to check an account ID and then to choose a password, and the commit would have been
     * sent. Now the pick-up stops before any question, what was opened goes, and the request is kept.
     */
    @Test fun anAssistedRecoveryWhoseDeliveredKeyIsNotTheKeptAccountsAsksNothingAndCommitsNothing() = runBlocking<Unit> {
        val a = setup()
        val alice = register(a.inner, "alice@example.com")
        val (f, sink) = keeping(a, alice)
        val (requestId, waiting) = holding(a, f)
        a.inner.now += 7 * 86_400_000L
        val awaiting = assertIs<AssistedStep.Waiting>(f.engine.poll(waiting))
        val other = crypto.randomBytes(32)
        val seed = crypto.randomBytes(32)
        val real = alice.account
        val lie = FakeInstance.Account(real.userId, real.authKey, real.kdfSalt, real.kdfParams, real.wrappedUvk,
            io.silencelen.andvari.core.crypto.Envelope.sealB64(crypto, other, seed, io.silencelen.andvari.core.crypto.Ad.idkey(real.userId)),
            Bytes.toB64(crypto.boxKeypairFromSeed(seed).publicKey), real.genesis, real.personalWrap, real.memberRecovery, real.pieceId)
        a.fulfil(requestId, real, other, served = lie)
        assertEquals(AssistedStep.Stopped(WireAssistedRecovery.SERVER_KEYS_NOT_KNOWN_HERE), f.engine.poll(awaiting))
        assertFalse(WireRoute.RECOVERY_REQUEST_COMMIT in a.calls)
        assertTrue(sink.sessions.isEmpty())
        assertEquals(listOf(a.origin), f.engine.keptOrigins(), "the request is kept")
        seed.fill(0)
        other.fill(0)
    }

    /**
     * An assisted recovery of alice's account on a device whose session keeper keeps bob's: the keeper would refuse the
     * session the commit opens, after the server had taken alice's new password and ended her request. Before, the person
     * was asked to check the account and to choose a password, and the commit was sent. Now the pick-up stops before any
     * question with nothing committed, and the request is kept; once bob is signed out, the next poll picks the answer up
     * again and the recovery completes.
     */
    @Test fun anAssistedRecoveryOnADeviceThatKeepsAnotherAccountCommitsNothingUntilThatOneIsSignedOut() = runBlocking<Unit> {
        val a = setup()
        val alice = register(a.inner, "alice@example.com")
        val pins = MemoryDeviceState()
        val trust = a.inner.pinnedTrust(pins)
        val keeper = io.silencelen.andvari.core.client.session.SessionKeeper(
            io.silencelen.andvari.core.client.session.BearerTransport(mapOf(a.origin to a)), MemoryDeviceState(), pins, trust, crypto,
        )
        val o = WireOnboarding(a.origin, keeper.clientFor(a.origin), trust, KnownDevices(pins, crypto), keeper, crypto, pins, "android", "New",
            { a.inner.now }, knownIdentity = keeper::knownIdentity, work = Dispatchers.Unconfined)
        o.signupStart("bob@example.com", true)
        val t = assertIs<SignupVerify.Ticket>(o.signupVerify("bob@example.com", "482915"))
        assertIs<Registration.Registered>(o.register(RegistrationAuth.Ticket(t),
            RegistrationForm("bob@example.com", "B", strong.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "New", "android")))
        keeper.lock()
        val engine = WireAssistedRecovery({ keeper.clientFor(it) }, trust, KnownDevices(pins, crypto), keeper, crypto, MemoryDeviceState(), "android", "New",
            { a.inner.now }, knownIdentity = keeper::knownIdentity)
        val f = Fresh(engine, Sink(), pins, MemoryDeviceState())
        val (requestId, waiting) = holding(a, f)
        a.inner.now += 7 * 86_400_000L
        val awaiting = assertIs<AssistedStep.Waiting>(f.engine.poll(waiting))
        a.fulfil(requestId, alice.account, alice.session.account.uvk.copyOut())
        val authBefore = a.inner.account("alice@example.com").authKey
        assertEquals(AssistedStep.Stopped(WireAssistedRecovery.ANOTHER_SESSION_KEPT), f.engine.poll(awaiting))
        assertFalse(WireRoute.RECOVERY_REQUEST_COMMIT in a.calls, "nothing was committed")
        assertEquals(authBefore, a.inner.account("alice@example.com").authKey, "alice's password is unchanged at the server")
        assertEquals(listOf(a.origin), f.engine.keptOrigins(), "the request is kept")
        assertEquals("bob@example.com", assertNotNull(keeper.session).emailNorm)
        keeper.signOut()
        val check = assertIs<AssistedStep.CheckAccount>(f.engine.poll(awaiting))
        val choose = assertIs<AssistedStep.ChoosePassword>(f.engine.confirmAccount(check, true))
        assertIs<AssistedStep.Recovered>(f.engine.commit(choose, newPw.toCharArray()))
        assertEquals(alice.account.userId, assertNotNull(keeper.session).userId, "the recovered account is the one kept now")
    }

    /** A device whose session keeper is [keeper], with the assisted recovery and the sign-in over it. */
    private class KeeperDevice(val keeper: io.silencelen.andvari.core.client.session.SessionKeeper, val f: Fresh, val onboarding: WireOnboarding)

    private suspend fun keeperDevice(a: Assist): KeeperDevice {
        val pins = MemoryDeviceState()
        val trust = a.inner.pinnedTrust(pins)
        val keeper = io.silencelen.andvari.core.client.session.SessionKeeper(
            io.silencelen.andvari.core.client.session.BearerTransport(mapOf(a.origin to a)), MemoryDeviceState(), pins, trust, crypto,
        )
        val o = WireOnboarding(a.origin, keeper.clientFor(a.origin), trust, KnownDevices(pins, crypto), keeper, crypto, pins, "android", "New",
            { a.inner.now }, knownIdentity = keeper::knownIdentity, work = Dispatchers.Unconfined)
        val engine = WireAssistedRecovery({ keeper.clientFor(it) }, trust, KnownDevices(pins, crypto), keeper, crypto, MemoryDeviceState(), "android", "New",
            { a.inner.now }, knownIdentity = keeper::knownIdentity)
        return KeeperDevice(keeper, Fresh(engine, Sink(), pins, MemoryDeviceState()), o)
    }

    /**
     * The device keeps alice. A signer of the pinned recovery key answers her request (her address) with mallory's id, key,
     * seed and identity. Before, the answer's own id decided what it was compared with, so nothing kept of alice was
     * compared: the person was asked to check an account and to choose a password and the commit was sent (later the
     * session keeper's question stopped it as "another account is kept", whose way out, signing alice out, would have let
     * the answer through). Now the pick-up refuses it with a reason of its own before anything is asked: no account to
     * check, no password, no commit, and the request kept, also while alice's copy stands signed out by its server. Her own
     * answer then recovers her.
     */
    @Test fun anAnswerThatNamesAnotherAccountThanTheOneKeptForTheAddressIsRefusedAtThePickUp() = runBlocking<Unit> {
        val a = setup()
        val mallory = register(a.inner, "mallory@example.com")
        val d = keeperDevice(a)
        d.onboarding.signupStart("alice@example.com", true)
        val t = assertIs<SignupVerify.Ticket>(d.onboarding.signupVerify("alice@example.com", "482915"))
        assertIs<Registration.Registered>(d.onboarding.register(RegistrationAuth.Ticket(t),
            RegistrationForm("alice@example.com", "A", strong.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "New", "android")))
        val alice = a.inner.account("alice@example.com")
        val aliceUvk = assertNotNull(d.keeper.established).account.uvk.copyOut()
        d.keeper.lock()
        val (requestId, waiting) = holding(a, d.f)
        a.inner.now += 7 * 86_400_000L
        val awaiting = assertIs<AssistedStep.Waiting>(d.f.engine.poll(waiting))
        a.fulfil(requestId, mallory.account, mallory.session.account.uvk.copyOut(), email = "alice@example.com")
        val takes = d.keeper.takes
        val refusals = d.keeper.refusals
        assertEquals(AssistedStep.Stopped(WireAssistedRecovery.NOT_THE_KEPT_ACCOUNT), d.f.engine.poll(awaiting))
        assertFalse(WireRoute.RECOVERY_REQUEST_COMMIT in a.calls, "nothing was committed")
        assertEquals(listOf(a.origin), d.f.engine.keptOrigins(), "the request is kept")
        assertEquals(takes to refusals, d.keeper.takes to d.keeper.refusals, "no session reached the keeper")
        // Signed out by its server, the copy is still the account this device keeps for the address.
        d.keeper.endedByServer(a.origin)
        assertEquals(AssistedStep.Stopped(WireAssistedRecovery.NOT_THE_KEPT_ACCOUNT), d.f.engine.poll(awaiting))
        assertFalse(WireRoute.RECOVERY_REQUEST_COMMIT in a.calls)
        // The answer for alice's own account goes through.
        a.fulfil(requestId, alice, aliceUvk)
        val check = assertIs<AssistedStep.CheckAccount>(d.f.engine.poll(awaiting))
        val choose = assertIs<AssistedStep.ChoosePassword>(d.f.engine.confirmAccount(check, true))
        assertIs<AssistedStep.Recovered>(d.f.engine.commit(choose, newPw.toCharArray()))
        assertEquals(alice.userId, assertNotNull(d.keeper.session).userId)
    }

    /**
     * Mallory's answer for alice's address reaches the password step on a device that kept nothing then (only the person's
     * account check stands there); alice is signed in on this device before the password is chosen. The commit is held to
     * the account kept for the address now: refused with nothing sent, the request kept. Before, it was stopped as
     * "another account is kept".
     */
    @Test fun anAccountKeptForTheAddressSinceThePickUpHoldsTheCommitToIt() = runBlocking<Unit> {
        val a = setup()
        register(a.inner, "alice@example.com")
        val mallory = register(a.inner, "mallory@example.com")
        val d = keeperDevice(a)
        val (requestId, waiting) = holding(a, d.f)
        a.inner.now += 7 * 86_400_000L
        val awaiting = assertIs<AssistedStep.Waiting>(d.f.engine.poll(waiting))
        a.fulfil(requestId, mallory.account, mallory.session.account.uvk.copyOut(), email = "alice@example.com")
        val check = assertIs<AssistedStep.CheckAccount>(d.f.engine.poll(awaiting))
        val choose = assertIs<AssistedStep.ChoosePassword>(d.f.engine.confirmAccount(check, true))
        assertIs<io.silencelen.andvari.core.client.onboard.SignIn.SignedIn>(d.onboarding.signIn("alice@example.com", strong.toCharArray()))
        val mallorysAuth = a.inner.account("mallory@example.com").authKey
        assertEquals(AssistedStep.Stopped(WireAssistedRecovery.NOT_THE_KEPT_ACCOUNT), d.f.engine.commit(choose, newPw.toCharArray()))
        assertFalse(WireRoute.RECOVERY_REQUEST_COMMIT in a.calls, "nothing was committed")
        assertEquals(mallorysAuth, a.inner.account("mallory@example.com").authKey)
        assertEquals(listOf(a.origin), d.f.engine.keptOrigins(), "the request is kept")
        assertEquals("alice@example.com", assertNotNull(d.keeper.session).emailNorm)
    }

    /**
     * A server whose operator raised the floor above the default, with the policy raised to match: the commit derives the
     * new password at the policy, read through the pinned server during the flow. Before, it derived at the default and
     * the server refused it as too weak, a dead end.
     */
    @Test fun aServerWhoseFloorIsAboveTheDefaultTakesAnAssistedRecoveryAtItsPolicy() = runBlocking<Unit> {
        val a = setup()
        val alice = register(a.inner, "alice@example.com")
        val raised = io.silencelen.andvari.core.crypto.KdfParams(ops = 4)
        a.inner.policyKdf = raised
        a.inner.minKdf = raised
        val f = fresh(a)
        val (_, check) = pickedUp(a, f, alice)
        val choose = assertIs<AssistedStep.ChoosePassword>(f.engine.confirmAccount(check, true))
        assertIs<AssistedStep.Recovered>(f.engine.commit(choose, newPw.toCharArray()))
        assertEquals(raised, a.inner.account("alice@example.com").kdfParams)
    }

    /**
     * The owner's decision of 2026-11-17, a way out through the mailbox: the request may carry the value a code mail
     * carried. Without one the body has no such field; with one, the field holds it without spaces or dashes and in
     * capitals. The server answers alike, and the flow's answer is the same in both cases (here, as a request).
     */
    @Test fun aRequestCarriesAMailboxValueOnlyWhenGivenAndTheFlowAnswersAlike() = runBlocking<Unit> {
        val a = setup()
        register(a.inner, "alice@example.com")
        suspend fun requested(value: String?): Pair<AssistedStep, String> {
            val f = fresh(a)
            val target = assertIs<AssistedStep.ConfirmTarget>(f.engine.start("alice@example.com", a.origin))
            val step = if (value == null) f.engine.request(target) else f.engine.request(target, value)
            return step to a.bodies[a.calls.lastIndexOf(WireRoute.RECOVERY_REQUEST_CREATE)]
        }
        val (without, plainBody) = requested(null)
        val (with, valueBody) = requested("abcd-efgh jkmn pqrs")
        val blank = requested("   ").second
        assertIs<AssistedStep.Requested>(without)
        assertIs<AssistedStep.Requested>(with)
        assertFalse("mailboxValue" in plainBody, "no value given: no field")
        assertFalse("mailboxValue" in blank, "a blank field is none")
        val sent = WireJson.json.decodeFromString(RecoveryRequestCreate.serializer(), valueBody)
        assertEquals("ABCDEFGHJKMNPQRS", sent.mailboxValue)
        val keys = { body: String -> WireJson.json.parseToJsonElement(body).let { it as kotlinx.serialization.json.JsonObject }.keys }
        assertEquals(keys(plainBody) + "mailboxValue", keys(valueBody), "the value is the one field added")
    }

    /** A typed value that cannot be one (another length, a symbol outside the alphabet) stops before anything is sent; the step stays. */
    @Test fun aMailboxValueThatCannotBeOneSendsNothingAndTheStepStays() = runBlocking<Unit> {
        val a = setup()
        register(a.inner, "alice@example.com")
        val f = fresh(a)
        val target = assertIs<AssistedStep.ConfirmTarget>(f.engine.start("alice@example.com", a.origin))
        for (typed in listOf("ABCD EFGH JKMN PQR", "ABCD EFGH JKMN PQRSA", "ABCD EFGH JKMN PQR0", "ABCD EFGH JKMN PQRI", "ABCD EFGH JKMN PQR_")) {
            assertEquals(AssistedStep.Stopped(WireAssistedRecovery.BAD_MAILBOX_VALUE), f.engine.request(target, typed), typed)
        }
        assertFalse(WireRoute.RECOVERY_REQUEST_CREATE in a.calls)
        assertIs<AssistedStep.Requested>(f.engine.request(target, "abcdefghjkmnpqrs"), "the same step goes on with a value that can be one")
    }

    /**
     * The rule decided on 2026-11-17: a typed value is brought to its form on the device exactly as on the server, ASCII
     * only. Characters outside ASCII whose capital form is one or two of the alphabet's letters (the long s, the sharp s,
     * the ligatures ff and st) and a full-width letter leave it not a value, refused before anything is sent; so does a
     * space that is not an ASCII space or tab. Before, the device's capitals turned the first four into a value and sent
     * it. A real value in lower case, with spaces, a tab and dashes, goes out in its form.
     */
    @Test fun aMailboxValueIsBroughtToItsFormInAsciiOnlyAsOnTheServer() = runBlocking<Unit> {
        val longS = Char(0x017F).toString()
        val sharpS = Char(0x00DF).toString()
        val ligatureFf = Char(0xFB00).toString()
        val ligatureSt = Char(0xFB06).toString()
        val fullWidthS = Char(0xFF53).toString()
        val noBreakSpace = Char(0x00A0).toString()
        val notValues = listOf(
            "abcdefghjkmnpqr$longS", "abcdefghjkmnpq$sharpS", "abcde${ligatureFf}hjkmnpqrs", "abcdefghjkmnpq$ligatureSt",
            "abcdefghjkmnpqr$fullWidthS", "abcd${noBreakSpace}efghjkmnpqrs",
        )
        for (typed in notValues) assertNull(WireAssistedRecovery.mailboxValueOf(typed), typed)
        assertEquals("ABCDEFGHJKMNPQRS", WireAssistedRecovery.mailboxValueOf("abcd-efgh\tjkmn pqrs"))
        val a = setup()
        register(a.inner, "alice@example.com")
        val f = fresh(a)
        val target = assertIs<AssistedStep.ConfirmTarget>(f.engine.start("alice@example.com", a.origin))
        for (typed in notValues) {
            assertEquals(AssistedStep.Stopped(WireAssistedRecovery.BAD_MAILBOX_VALUE), f.engine.request(target, typed), typed)
        }
        assertFalse(WireRoute.RECOVERY_REQUEST_CREATE in a.calls, "nothing was sent")
        assertIs<AssistedStep.Requested>(f.engine.request(target, "abcd-efgh\tjkmn pqrs"))
        val sent = WireJson.json.decodeFromString(RecoveryRequestCreate.serializer(), a.bodies[a.calls.lastIndexOf(WireRoute.RECOVERY_REQUEST_CREATE)])
        assertEquals("ABCDEFGHJKMNPQRS", sent.mailboxValue)
    }

    @Test fun thePickUpRunsSection24sOrder() = runBlocking<Unit> {
        val a = setup()
        val alice = register(a.inner, "alice@example.com")
        val bob = register(a.inner, "bob@example.com")
        val uvk = alice.session.account.uvk.copyOut()
        val f = fresh(a)
        val (requestId, waiting) = holding(a, f)
        suspend fun poll() = assertIs<AssistedStep.Stopped>(f.engine.poll(waiting)).reason
        a.fulfil(requestId, alice.account, uvk, sealTo = crypto.boxKeypairFromSeed(ByteArray(32) { 9 }).publicKey)
        assertEquals("unopenable", poll())
        // A server that holds no recovery key signs with a key of its own.
        a.fulfil(requestId, alice.account, uvk, signer = crypto.signKeypairFromSeed(ByteArray(32) { 5 }))
        assertEquals("signer_not_pinned_key", poll())
        a.fulfil(requestId, alice.account, uvk, payloadRequestId = Bytes.toB64(ByteArray(16) { 77 }))
        assertEquals("request_mismatch", poll())
        a.fulfil(requestId, alice.account, uvk, email = "bob@example.com")
        assertEquals("request_mismatch", poll())
        // The seed is alice's but the served identity key is bob's (R27); and a key that does not open the seed.
        a.fulfil(requestId, alice.account, uvk, served = alice.account)
        a.reqs.getValue(requestId).served = FakeInstance.Account(alice.account.userId, "", "", alice.account.kdfParams, "", alice.account.encryptedIdentitySeed,
            bob.account.identityPub, null, null, alice.account.memberRecovery, "")
        assertEquals("identity_mismatch", poll())
        a.fulfil(requestId, alice.account, ByteArray(32) { 4 })
        assertEquals("identity_mismatch", poll())
        assertTrue(f.sink.sessions.isEmpty())
        // Each refusal keeps the request: the genuine payload still goes through.
        a.fulfil(requestId, alice.account, uvk)
        assertIs<AssistedStep.CheckAccount>(f.engine.poll(waiting))
    }

    @Test fun neverOfferedOnAPublicInstance() = runBlocking<Unit> {
        val a = setup(InstanceKind.PUBLIC)
        val alice = register(setup().inner, "alice@example.com")
        // No pin: the card the gate would pin is public, so the person is not even asked and nothing is pinned.
        val f = fresh(a)
        assertEquals("not_offered", assertIs<AssistedStep.Stopped>(f.engine.start("alice@example.com", a.origin)).reason)
        assertNull(a.inner.trust(f.pins).pinFor(a.origin))
        // Pinned: the same.
        val g = fresh(a)
        a.inner.pinnedTrust(g.pins)
        assertEquals("not_offered", assertIs<AssistedStep.Stopped>(g.engine.start("alice@example.com", a.origin)).reason)
        val requests = WireRecoveryRequests(a.origin, alice.session.account, a, a.inner.pinnedTrust(), crypto) { a.inner.now }
        assertEquals(LiveRecoveryRequests.NotOffered, requests.live())
        assertEquals(VetoOutcome.NotOffered, requests.veto(Bytes.toB64(ByteArray(16))))
        assertTrue(a.calls.none { it.name.startsWith("RECOVERY_REQUEST") || it == WireRoute.ACCOUNT_RECOVERY_REQUESTS })
        // A card with no recovery key offers none either.
        val none = Assist(FakeInstance(crypto, recoveryFp = null))
        assertEquals("not_offered", assertIs<AssistedStep.Stopped>(fresh(none).engine.start("alice@example.com", none.origin)).reason)
    }

    @Test fun aKitPinIsNoPasswordPinHereSoItIsTheTrustGate() = runBlocking<Unit> {
        val a = setup()
        register(a.inner, "alice@example.com")
        val f = fresh(a)
        assertIs<FirstPin.Pinned>(a.inner.trust(f.pins).pinFromKit(a.origin, a.inner.card0Hash, "alice@example.com"))
        val target = assertIs<AssistedStep.ConfirmTarget>(f.engine.start("alice@example.com", a.origin))
        assertNotNull(target.gate, "a kit pin does not serve assisted recovery: the Trust Gate")
        assertIs<AssistedStep.Requested>(f.engine.request(target))
        assertEquals(PinRoot.TRUST_GATE, a.inner.trust(f.pins).pinFor(a.origin)!!.root)
        // With a Trust Gate pin, no gate is asked again.
        val g = fresh(a)
        a.inner.pinnedTrust(g.pins)
        assertNull(assertIs<AssistedStep.ConfirmTarget>(g.engine.start("alice@example.com", a.origin)).gate)
    }

    @Test fun aSignedInDeviceListsAndVetoesAndTheRequesterStops() = runBlocking<Unit> {
        val a = setup()
        val alice = register(a.inner, "alice@example.com")
        val f = fresh(a)
        val (requestId, waiting) = holding(a, f)
        val requests = WireRecoveryRequests(a.origin, alice.session.account, a, a.inner.pinnedTrust(), crypto) { a.inner.now }
        val listed = assertIs<LiveRecoveryRequests.Listed>(requests.live())
        assertEquals(listOf(requestId), listed.requests.map { it.requestId })
        assertEquals(VetoOutcome.Vetoed, requests.veto(requestId))
        assertEquals("vetoed", a.reqs.getValue(requestId).state)
        assertEquals("vetoed", assertIs<AssistedStep.Stopped>(f.engine.poll(waiting)).reason)
        assertTrue(f.engine.keptOrigins().isEmpty())
        // The veto is allowed in every state before the commit: also an unverified request.
        val g = fresh(a)
        val requested = assertIs<AssistedStep.Requested>(g.engine.request(assertIs(g.engine.start("alice@example.com", a.origin))))
        assertEquals(VetoOutcome.Vetoed, requests.veto(a.reqs.keys.last()))
        assertEquals("vetoed", assertIs<AssistedStep.Stopped>(g.engine.poll(requested)).reason)
    }

    /**
     * Once the operator answered a request, the account's own list read `ready`, which this device
     * refused, and the whole list became `bad_response`: one answered request hid every request in the very window the veto
     * is kept for. Now `ready` is listed, an answered request is cancelled like any other until it is committed, and a row
     * this device cannot read is dropped and counted while the others stay.
     */
    @Test fun anAnsweredRequestIsListedAndCancelledAndAnUnreadableRowIsDroppedAndCounted() = runBlocking<Unit> {
        val a = setup()
        val alice = register(a.inner, "alice@example.com")
        val f = fresh(a)
        val (requestId, waiting) = holding(a, f)
        val g = fresh(a)
        val (otherId, _) = holding(a, g)
        a.inner.now += 7 * 86_400_000L
        a.fulfil(requestId, alice.account, alice.session.account.uvk.copyOut())
        val requests = WireRecoveryRequests(a.origin, alice.session.account, a, a.inner.pinnedTrust(), crypto) { a.inner.now }
        val listed = assertIs<LiveRecoveryRequests.Listed>(requests.live())
        assertEquals(mapOf(requestId to "ready", otherId to "awaiting_operator"), listed.requests.associate { it.requestId to it.state })
        assertEquals(0, listed.unreadable)
        // A row in a state the specification does not name, one with no id, and one that is not an object.
        val good = WireJson.json.encodeToJsonElement(RecoveryRequestSummary.serializer(), listed.requests[0])
        a.extraRows = listOf(
            kotlinx.serialization.json.JsonObject(good.jsonObjectOrFail() + ("state" to kotlinx.serialization.json.JsonPrimitive("granted"))),
            kotlinx.serialization.json.JsonObject(good.jsonObjectOrFail() - "requestId"),
            kotlinx.serialization.json.JsonPrimitive(7),
        )
        val lying = assertIs<LiveRecoveryRequests.Listed>(requests.live())
        assertEquals(setOf(requestId, otherId), lying.requests.map { it.requestId }.toSet(), "the readable rows stay")
        assertEquals(3, lying.unreadable)
        a.extraRows = emptyList()
        // The answered request is cancelled before its commit, and its requester stops.
        assertEquals(VetoOutcome.Vetoed, requests.veto(requestId))
        assertEquals("vetoed", assertIs<AssistedStep.Stopped>(f.engine.poll(waiting)).reason)
    }

    private fun kotlinx.serialization.json.JsonElement.jsonObjectOrFail(): kotlinx.serialization.json.JsonObject = this as kotlinx.serialization.json.JsonObject

    @Test fun cancelDropsTheKeptRequest() = runBlocking<Unit> {
        val a = setup()
        register(a.inner, "alice@example.com")
        val f = fresh(a)
        val (_, waiting) = holding(a, f)
        assertEquals(listOf(a.origin), f.engine.keptOrigins())
        f.engine.cancel(waiting)
        assertTrue(f.engine.keptOrigins().isEmpty())
        assertNull(f.engine.resume(a.origin))
        // An unverified request is dropped 24 hours after creation.
        val g = fresh(a)
        g.engine.request(assertIs(g.engine.start("alice@example.com", a.origin)))
        assertEquals(listOf(a.origin), g.engine.keptOrigins())
        a.inner.now += 24 * 3_600_000L
        assertTrue(g.engine.keptOrigins().isEmpty())
    }

    // ---- a person who leaves while a request is on its way (the shape found in the kit recovery) ----

    /** Alice's request, held, fulfilled by the operator and picked up: the account check. */
    private suspend fun pickedUp(a: Assist, f: Fresh, alice: Registered): Pair<String, AssistedStep.CheckAccount> {
        val (requestId, waiting) = holding(a, f)
        a.inner.now += 7 * 86_400_000L
        val awaiting = assertIs<AssistedStep.Waiting>(f.engine.poll(waiting))
        a.fulfil(requestId, alice.account, alice.session.account.uvk.copyOut())
        return requestId to assertIs<AssistedStep.CheckAccount>(f.engine.poll(awaiting))
    }

    /**
     * The person leaves (start over, back) while the commit is in flight, after the server took it. The commit used to
     * open the recovered session anyway, for a person who had left, and hand back its new kit. Now nothing is opened, no
     * session reaches the host, nothing of the flow is kept, and the answer is STALE. The next attempt finds the server's
     * state: the request is gone, and the new password signs in.
     */
    @Test fun anAssistedRecoveryLeftWhileItsCommitIsInFlightOpensNoSessionAndAnswersStale() = runBlocking<Unit> {
        val a = setup()
        val alice = register(a.inner, "alice@example.com")
        val f = fresh(a)
        val (requestId, check) = pickedUp(a, f, alice)
        val choose = assertIs<AssistedStep.ChoosePassword>(f.engine.confirmAccount(check, true))
        a.during = WireRoute.RECOVERY_REQUEST_COMMIT to { f.engine.cancel(choose) }
        assertEquals("stale", assertIs<AssistedStep.Stopped>(f.engine.commit(choose, newPw.toCharArray())).reason)
        assertTrue(WireRoute.RECOVERY_REQUEST_COMMIT in a.calls, "the commit was sent before the leave")
        assertFalse(requestId in a.reqs, "the server took the commit")
        assertTrue(f.sink.sessions.isEmpty(), "no session was opened")
        assertTrue(f.engine.keptOrigins().isEmpty(), "nothing of the flow is kept")
        assertNull(f.engine.resume(a.origin))
        val sent = a.calls.size
        assertEquals("stale", assertIs<AssistedStep.Stopped>(f.engine.commit(choose, newPw.toCharArray())).reason, "the flow is over")
        assertEquals(sent, a.calls.size, "and nothing more is sent")
        // The next attempt: the new password signs in on this device.
        val o = WireOnboarding(a.origin, a, a.inner.trust(f.pins), KnownDevices(f.pins, crypto), f.sink, crypto, f.pins, "android", "New", { a.inner.now },
            work = Dispatchers.Unconfined)
        assertIs<SignIn.SignedIn>(o.signIn("alice@example.com", newPw.toCharArray()))
        assertEquals(alice.account.userId, f.sink.sessions.single().account.userId)
    }

    /**
     * On the assisted recovery: the commit is sent, the person leaves,
     * the server takes it. Nothing opens and nothing is kept, as before; what the late answer came to is now published
     * once (the reset went through), without a session, a key or another request. Before, nothing was published.
     */
    @Test fun anAssistedRecoveryLeftAfterItsCommitWasSentPublishesOnceThatTheResetWentThrough() = runBlocking<Unit> {
        val a = setup()
        val alice = register(a.inner, "alice@example.com")
        val f = fresh(a)
        val engine: AssistedRecovery = f.engine
        var told = 0
        engine.onLateOutcome = { told++ }
        val (requestId, check) = pickedUp(a, f, alice)
        val choose = assertIs<AssistedStep.ChoosePassword>(engine.confirmAccount(check, true))
        assertNull(engine.takeLateOutcome())
        a.during = WireRoute.RECOVERY_REQUEST_COMMIT to { engine.cancel(choose) }
        val sentBefore = a.calls.size
        assertEquals("stale", assertIs<AssistedStep.Stopped>(engine.commit(choose, newPw.toCharArray())).reason)
        assertFalse(requestId in a.reqs, "the server took the commit")
        assertEquals(1, told)
        val outcome = assertNotNull(engine.takeLateOutcome())
        assertEquals(LateRecoveryOutcome.Result.RESET, outcome.result)
        assertEquals(LateRecoveryOutcome.Via.OPERATOR, outcome.via)
        assertEquals(a.origin, outcome.origin)
        assertEquals("alice@example.com", outcome.email)
        assertNull(engine.takeLateOutcome(), "published once")
        assertTrue(f.sink.sessions.isEmpty(), "no session was opened")
        assertTrue(engine.keptOrigins().isEmpty(), "nothing of the flow is kept")
        // The policy's read sets the new password's cost before the commit.
        assertEquals(listOf(WireRoute.CLIENT_POLICY, WireRoute.RECOVERY_REQUEST_COMMIT), a.calls.drop(sentBefore), "nothing more was sent")
    }

    /** The same leave, and the server refuses the commit (vetoed meanwhile) or gives no usable answer: published once as what it is. */
    @Test fun anAssistedRecoveryLeftAfterItsCommitWasSentPublishesARefusalOrAnUnknownAnswerOnce() = runBlocking<Unit> {
        for (how in listOf("vetoed", "no_answer", "server_error")) {
            val a = setup()
            val alice = register(a.inner, "alice@example.com")
            var leave: (() -> Unit)? = null
            var commits = 0
            // For no_answer and server_error the server acts on nothing and the device gets that answer.
            val wire = object : WireClient by a {
                override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                    if (route != WireRoute.RECOVERY_REQUEST_COMMIT) return a.call(route, pathParams, query, bodyJson, authenticated, decode)
                    commits++
                    leave?.invoke()
                    return when (how) {
                        "vetoed" -> a.call(route, pathParams, query, bodyJson, authenticated, decode)
                        "no_answer" -> WireResult.NoAnswer(io.silencelen.andvari.core.client.net.NoAnswerKind.TRANSPORT)
                        else -> WireResult.Refused(502, WireError("bad_gateway", "bad_gateway"))
                    }
                }
            }
            val pins = MemoryDeviceState()
            val secure = MemoryDeviceState()
            val sink = Sink()
            val f = Fresh(WireAssistedRecovery({ wire }, a.inner.trust(pins), KnownDevices(pins, crypto), sink, crypto, secure, "android", "New", { a.inner.now }),
                sink, pins, secure)
            val (requestId, check) = pickedUp(a, f, alice)
            val choose = assertIs<AssistedStep.ChoosePassword>(f.engine.confirmAccount(check, true))
            if (how == "vetoed") a.reqs.getValue(requestId).state = "vetoed"
            leave = { f.engine.cancel(choose) }
            assertEquals("stale", assertIs<AssistedStep.Stopped>(f.engine.commit(choose, newPw.toCharArray())).reason, how)
            val expected = if (how == "vetoed") LateRecoveryOutcome.Result.REFUSED else LateRecoveryOutcome.Result.UNKNOWN
            assertEquals(expected, assertNotNull(f.engine.takeLateOutcome(), how).result, how)
            assertNull(f.engine.takeLateOutcome())
            assertTrue(sink.sessions.isEmpty())
            assertTrue(f.engine.keptOrigins().isEmpty())
            assertEquals(1, commits, "$how: nothing is sent again")
        }
    }

    /** Started over (a new request for the origin) while the commit was in flight: the same, and the new request is untouched. */
    @Test fun anAssistedCommitOvertakenByANewRequestOpensNothingAndLeavesTheNewRequestKept() = runBlocking<Unit> {
        val a = setup()
        val alice = register(a.inner, "alice@example.com")
        val f = fresh(a)
        val (_, check) = pickedUp(a, f, alice)
        val choose = assertIs<AssistedStep.ChoosePassword>(f.engine.confirmAccount(check, true))
        var again: AssistedStep? = null
        a.during = WireRoute.RECOVERY_REQUEST_COMMIT to {
            runBlocking { again = f.engine.request(assertIs(f.engine.start("alice@example.com", a.origin))) }
        }
        assertEquals("stale", assertIs<AssistedStep.Stopped>(f.engine.commit(choose, newPw.toCharArray())).reason)
        assertTrue(f.sink.sessions.isEmpty(), "no session was opened")
        val requested = assertIs<AssistedStep.Requested>(again, "the new attempt")
        assertEquals(listOf(a.origin), f.engine.keptOrigins(), "the new request is kept")
        assertIs<AssistedStep.Waiting>(f.engine.verifyCode(requested, a.code), "and goes on")
    }

    /** Left while the emailed code was on its way: the leave forgot the request, and it is not written back. */
    @Test fun anAssistedRecoveryLeftWhileItsCodeIsOnItsWayKeepsNothingAndAnswersStale() = runBlocking<Unit> {
        val a = setup()
        register(a.inner, "alice@example.com")
        val f = fresh(a)
        val requested = assertIs<AssistedStep.Requested>(f.engine.request(assertIs(f.engine.start("alice@example.com", a.origin))))
        a.during = WireRoute.RECOVERY_REQUEST_VERIFY to { f.engine.cancel(requested) }
        assertEquals("stale", assertIs<AssistedStep.Stopped>(f.engine.verifyCode(requested, a.code)).reason)
        assertTrue(f.engine.keptOrigins().isEmpty(), "rSec and pollSecret are not written back")
        assertNull(f.engine.resume(a.origin))
        // The next attempt starts a new request.
        val next = assertIs<AssistedStep.Requested>(f.engine.request(assertIs(f.engine.start("alice@example.com", a.origin))))
        assertIs<AssistedStep.Waiting>(f.engine.verifyCode(next, a.code))
    }

    /** Left while the request was on its way: no request, secret or pin of the ended flow is kept; the next attempt works. */
    @Test fun anAssistedRecoveryLeftWhileItsRequestIsOnItsWayKeepsNothingAndAnswersStale() = runBlocking<Unit> {
        val a = setup()
        register(a.inner, "alice@example.com")
        val f = fresh(a)
        val target = assertIs<AssistedStep.ConfirmTarget>(f.engine.start("alice@example.com", a.origin))
        assertNotNull(target.gate, "a fresh install: the Trust Gate in the same confirmation")
        a.during = WireRoute.RECOVERY_REQUEST_CREATE to { f.engine.cancel(target) }
        assertEquals("stale", assertIs<AssistedStep.Stopped>(f.engine.request(target)).reason)
        assertTrue(f.engine.keptOrigins().isEmpty(), "no request is kept")
        assertNull(a.inner.trust(f.pins).pinFor(a.origin), "the pin the ended flow made is dropped")
        assertEquals("stale", assertIs<AssistedStep.Stopped>(f.engine.request(target)).reason, "the flow is over")
        val next = assertIs<AssistedStep.Requested>(f.engine.request(assertIs(f.engine.start("alice@example.com", a.origin))))
        assertIs<AssistedStep.Waiting>(f.engine.verifyCode(next, a.code))
    }

    /** Left during the Trust Gate, the request's first wait: nothing is sent and no pin is kept. */
    @Test fun anAssistedRecoveryLeftDuringItsTrustGateSendsNothingAndAnswersStale() = runBlocking<Unit> {
        val a = setup()
        register(a.inner, "alice@example.com")
        val pins = MemoryDeviceState()
        val real = a.inner.trust(pins)
        var during: (() -> Unit)? = null
        val trust = object : io.silencelen.andvari.core.client.pin.InstanceTrust by real {
            override suspend fun confirmTrustGate(ticket: io.silencelen.andvari.core.client.pin.TrustGateTicket) =
                real.confirmTrustGate(ticket).also { during?.invoke() }
        }
        val engine = WireAssistedRecovery({ a }, trust, KnownDevices(pins, crypto), Sink(), crypto, MemoryDeviceState(), "android", "New", { a.inner.now })
        val target = assertIs<AssistedStep.ConfirmTarget>(engine.start("alice@example.com", a.origin))
        during = { engine.cancel(target) }
        assertEquals("stale", assertIs<AssistedStep.Stopped>(engine.request(target)).reason)
        assertFalse(WireRoute.RECOVERY_REQUEST_CREATE in a.calls, "nothing was sent")
        assertNull(real.pinFor(a.origin), "the pin the gate made is dropped")
        assertTrue(engine.keptOrigins().isEmpty())
    }

    /** Left while a poll was on its way, with the operator's answer ready: nothing is picked up or held, no account check. */
    @Test fun anAssistedRecoveryLeftWhileItsPollIsOnItsWayPicksUpNothingAndAnswersStale() = runBlocking<Unit> {
        val a = setup()
        val alice = register(a.inner, "alice@example.com")
        val f = fresh(a)
        val (requestId, waiting) = holding(a, f)
        a.inner.now += 7 * 86_400_000L
        val awaiting = assertIs<AssistedStep.Waiting>(f.engine.poll(waiting))
        a.fulfil(requestId, alice.account, alice.session.account.uvk.copyOut())
        a.during = WireRoute.RECOVERY_REQUEST_POLL to { f.engine.cancel(awaiting) }
        assertEquals("stale", assertIs<AssistedStep.Stopped>(f.engine.poll(awaiting)).reason, "never the account check of a flow the person ended")
        assertTrue(f.engine.keptOrigins().isEmpty())
        assertNull(f.engine.resume(a.origin))
        assertTrue(f.sink.sessions.isEmpty())

        // After a restart (no handle yet), a newer request made during the poll is the flow now: the resumed poll is stale.
        val g = fresh(a)
        val (_, held) = holding(a, g)
        val h = fresh(a, g.pins, g.secure)
        a.during = WireRoute.RECOVERY_REQUEST_POLL to { runBlocking { g.engine.cancel(held); g.engine.request(assertIs(g.engine.start("alice@example.com", a.origin))) } }
        assertEquals("stale", assertIs<AssistedStep.Stopped>(h.engine.resume(a.origin)!!).reason)
    }

    // ---- a request open across a followed move (the kept request is bound to its server, not its address) ----

    private val moved = "https://moved.example"

    /** The operator signs card 1 moving the instance to [moved]; the device [pins] refreshes and follows it for real. */
    private suspend fun followMove(a: Assist, pins: MemoryDeviceState) {
        val c0 = a.inner.cards[0]
        a.inner.cards += io.silencelen.andvari.core.trust.InstanceCard.sign(crypto, a.inner.operatorSign, io.silencelen.andvari.core.trust.CardFields(
            a.inner.instanceId, 1, io.silencelen.andvari.core.trust.SignedFrame.hash(crypto, c0), moved, "Home", a.inner.kind,
            "99999999-9999-4999-8999-999999999999", Bytes.toB64(a.inner.operatorSign.publicKey), recoveryFp, a.inner.now))
        val t = a.inner.trust(pins)
        val m = assertIs<io.silencelen.andvari.core.client.pin.CardStatus.Moved>(t.refresh(a.origin))
        assertIs<io.silencelen.andvari.core.client.pin.CardStatus.Ok>(t.followMove(m))
        assertNull(t.pinFor(a.origin))
        assertEquals(moved, t.pinFor(moved)!!.origin)
    }

    /** From the hold to a committed recovery at [moved], with the step held from before the move. */
    private suspend fun finishAtTheNewOrigin(a: Assist, f: Fresh, alice: Registered, requestId: String, before: AssistedStep.Waiting) {
        assertEquals(listOf(moved), f.engine.keptOrigins(), "the request is kept for its server's new address")
        val polled = assertIs<AssistedStep.Waiting>(f.engine.poll(before), "the step held from before the move still polls")
        assertEquals(moved, polled.origin)
        a.inner.now += 7 * 86_400_000L
        val again = assertIs<AssistedStep.Waiting>(f.engine.resume(moved))
        assertEquals("awaiting_operator", again.state)
        a.fulfil(requestId, alice.account, alice.session.account.uvk.copyOut())
        val check = assertIs<AssistedStep.CheckAccount>(f.engine.poll(again))
        val choose = assertIs<AssistedStep.ChoosePassword>(f.engine.confirmAccount(check, true))
        val done = assertIs<AssistedStep.Recovered>(f.engine.commit(choose, newPw.toCharArray()))
        assertEquals(alice.account.userId, done.userId)
        assertEquals(moved, f.sink.sessions.single().origin, "the session opens at the new address")
        assertTrue(f.engine.keptOrigins().isEmpty())
    }

    @Test fun aRequestOpenBeforeAFollowedMoveIsUsableAfterItFromTheSecureStore() = runBlocking<Unit> {
        val a = setup()
        val alice = register(a.inner, "alice@example.com")
        val f = fresh(a)
        val (requestId, waiting) = holding(a, f)
        followMove(a, f.pins)
        // The secure store is not the pins' store, so the move did not carry the record: it follows its server on read.
        assertNotNull(f.secure.get("ovh.assist|${a.origin}"))
        finishAtTheNewOrigin(a, f, alice, requestId, waiting)
    }

    @Test fun aRequestCarriedByAFollowedMoveInTheSameStoreIsUsableAfterIt() = runBlocking<Unit> {
        val a = setup()
        val alice = register(a.inner, "alice@example.com")
        val one = MemoryDeviceState()
        val f = fresh(a, one, one)
        val (requestId, waiting) = holding(a, f)
        // A setup offer carried by the same move stays unread at the new address: it is stale once a card chain exists.
        one.set("ovh.setup|${a.origin}", WireJson.json.encodeToString(io.silencelen.andvari.core.client.onboard.KeptSetup.serializer(),
            io.silencelen.andvari.core.client.onboard.KeptSetup(a.origin, a.inner.instanceId, "Home", "private", "none")))
        followMove(a, one)
        assertNull(one.get("ovh.assist|${a.origin}"))
        assertNotNull(one.get("ovh.assist|$moved"), "carried by the move")
        assertNull(io.silencelen.andvari.core.client.onboard.SetupOffers(one).get(moved))
        finishAtTheNewOrigin(a, f, alice, requestId, waiting)
    }

    @Test fun aKeptRequestNeverGoesToAnotherServerAtItsAddressOrAfterAMove() = runBlocking<Unit> {
        val a = setup()
        register(a.inner, "alice@example.com")
        // Another server pinned at the request's own address (the first was forgotten, another pinned): the request goes.
        val f = fresh(a)
        val (_, waiting) = holding(a, f)
        val store = io.silencelen.andvari.core.client.pin.PinStore(f.pins)
        val issuer = store.get(a.origin)!!
        store.put(issuer.copy(instanceId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd", card0Hash = "ab".repeat(32)))
        val sent = a.calls.size
        assertIs<AssistedStep.Stopped>(f.engine.poll(waiting))
        assertTrue(f.engine.keptOrigins().isEmpty())
        assertNull(f.engine.resume(a.origin))
        assertEquals(sent, a.calls.size, "no poll secret went to the other server")
        assertNull(f.secure.get("ovh.assist|${a.origin}"))

        // A carried record under an address whose pin is another server's: read as none and removed, nothing sent.
        val g = fresh(a)
        holding(a, g)
        val record = g.secure.get("ovh.assist|${a.origin}")!!
        val gs = io.silencelen.andvari.core.client.pin.PinStore(g.pins)
        gs.put(gs.get(a.origin)!!.copy(origin = "https://other.example", instanceId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd", card0Hash = "ab".repeat(32)))
        g.secure.set("ovh.assist|https://other.example", record)
        assertNull(g.engine.resume("https://other.example"))
        assertNull(g.secure.get("ovh.assist|https://other.example"))
        assertEquals(listOf(a.origin), g.engine.keptOrigins(), "the request at its issuer's address stays")

        // Two addresses whose pins both name the issuer while its old address holds none: which one is ambiguous, so
        // the request follows neither and is sent nowhere.
        val h = fresh(a)
        holding(a, h)
        val hs = io.silencelen.andvari.core.client.pin.PinStore(h.pins)
        val p = hs.get(a.origin)!!
        hs.put(p.copy(origin = moved))
        hs.put(p.copy(origin = "https://third.example"))
        hs.remove(a.origin)
        val before = a.calls.size
        assertTrue(h.engine.keptOrigins().isEmpty())
        assertNull(h.engine.resume(moved))
        assertNull(h.engine.resume("https://third.example"))
        assertEquals(before, a.calls.size)
        assertNotNull(h.secure.get("ovh.assist|${a.origin}"), "kept where it was, unused")
    }

    @Test fun aRequestKeptBeforeTheBindingExistedFailsClosedAfterAMove() = runBlocking<Unit> {
        val a = setup()
        register(a.inner, "alice@example.com")
        val f = fresh(a)
        holding(a, f)
        // Rewrite the record as an older build kept it: no instance id, no card 0 hash.
        val key = "ovh.assist|${a.origin}"
        val k = WireJson.json.decodeFromString(KeptAssistRequest.serializer(), f.secure.get(key)!!)
        f.secure.set(key, WireJson.json.encodeToString(KeptAssistRequest.serializer(), k.copy(instanceId = null, card0Hash = null)))
        assertEquals(listOf(a.origin), f.engine.keptOrigins(), "still read at its own address")
        followMove(a, f.pins)
        val sent = a.calls.size
        assertNull(f.engine.resume(moved))
        assertFalse(moved in f.engine.keptOrigins())
        assertEquals(sent, a.calls.size)
    }

    // ---- the answer on the server is not the one opened here ----

    /**
     * The poll's `ready` names a commit hash that is not the hash of the value inside the answer this device opened (a
     * damaged or replaced upload; here also a value that is not a hash at all). Before, the device asked the person to check
     * the account and choose a password, and only the commit was refused. Now it says so at once, asks nothing, holds
     * nothing opened, and keeps the request; the honest answer then goes on. A server that sends no such field is taken
     * exactly as before.
     */
    @Test fun aReadyAnswerWhoseStoredCommitHashIsNotTheOpenedOnesIsSaidBeforeAnyQuestionAndTheRequestKept() = runBlocking<Unit> {
        val a = setup()
        val alice = register(a.inner, "alice@example.com")
        val f = fresh(a)
        val (requestId, waiting) = holding(a, f)
        a.inner.now += 7 * 86_400_000L
        val awaiting = assertIs<AssistedStep.Waiting>(f.engine.poll(waiting))
        a.fulfil(requestId, alice.account, alice.session.account.uvk.copyOut())
        for (lie in listOf("0".repeat(64), "not a hash")) {
            a.servedCommitHash = lie
            assertEquals(WireAssistedRecovery.COMMIT_MISMATCH, assertIs<AssistedStep.Stopped>(f.engine.poll(awaiting), lie).reason, lie)
            assertFalse(f.engine.holdsOpened(a.origin), "$lie: nothing opened is held")
            assertEquals(listOf(a.origin), f.engine.keptOrigins(), "$lie: the request is kept")
        }
        a.servedCommitHash = null
        assertIs<AssistedStep.CheckAccount>(f.engine.poll(awaiting), "the stored hash is the opened one's: on")
        // A server that sends no commit hash: as before, the account check.
        val g = fresh(a, f.pins, f.secure)
        a.sendCommitHash = false
        assertIs<AssistedStep.CheckAccount>(g.engine.resume(a.origin), "no field: as today")
    }

    /**
     * The commit's own `403 commit_mismatch` (the operator uploaded again while the person typed) is the same outcome:
     * never "start again" or "too late". The request is kept, nothing opened is held, and the next look picks up the newer
     * answer and finishes. (The engine already kept the request here; the outcome now has its documented name.)
     */
    @Test fun aCommitTheServerRefusesAsAnotherAnswerKeepsTheRequestAndTheNewerAnswerFinishes() = runBlocking<Unit> {
        val a = setup()
        val alice = register(a.inner, "alice@example.com")
        val f = fresh(a)
        val (requestId, check) = pickedUp(a, f, alice)
        val choose = assertIs<AssistedStep.ChoosePassword>(f.engine.confirmAccount(check, true))
        a.fulfil(requestId, alice.account, alice.session.account.uvk.copyOut()) // a newer upload
        assertEquals(WireAssistedRecovery.COMMIT_MISMATCH, assertIs<AssistedStep.Stopped>(f.engine.commit(choose, newPw.toCharArray())).reason)
        assertFalse(f.engine.holdsOpened(a.origin))
        assertEquals(listOf(a.origin), f.engine.keptOrigins())
        val again = assertIs<AssistedStep.CheckAccount>(f.engine.resume(a.origin))
        assertIs<AssistedStep.Recovered>(f.engine.commit(assertIs(f.engine.confirmAccount(again, true)), newPw.toCharArray()))
    }

    // ---- leaving, and a request the server no longer knows ----

    /**
     * The person leaves the account check or the password screen without giving the request up. Before, only the app's
     * step went: the delivered key and its commit value stayed in this engine's memory. Now [AssistedRecovery.setAside]
     * drops them with the step and keeps the request, and the next look picks the answer up again; a cancel drops them too,
     * also when the kept request itself has already lapsed.
     */
    @Test fun leavingTheCheckOrThePasswordScreenDropsWhatWasOpenedAndKeepsTheRequest() = runBlocking<Unit> {
        val a = setup()
        val alice = register(a.inner, "alice@example.com")
        val f = fresh(a)
        val (_, check) = pickedUp(a, f, alice)
        assertTrue(f.engine.holdsOpened(a.origin))
        f.engine.setAside(check)
        assertFalse(f.engine.holdsOpened(a.origin), "the delivered key and commit value went with the screen")
        assertEquals(listOf(a.origin), f.engine.keptOrigins(), "the request is kept")
        assertEquals("stale", assertIs<AssistedStep.Stopped>(f.engine.confirmAccount(check, true)).reason)
        val again = assertIs<AssistedStep.CheckAccount>(f.engine.resume(a.origin), "picked up again")
        val choose = assertIs<AssistedStep.ChoosePassword>(f.engine.confirmAccount(again, true))
        f.engine.setAside(choose)
        assertFalse(f.engine.holdsOpened(a.origin))
        assertEquals("stale", assertIs<AssistedStep.Stopped>(f.engine.commit(choose, newPw.toCharArray())).reason)
        // A cancel after the kept request lapsed (its lifetime ended while the check was on screen): what was opened goes too.
        val check2 = assertIs<AssistedStep.CheckAccount>(f.engine.resume(a.origin))
        assertTrue(f.engine.holdsOpened(a.origin))
        a.inner.now += AssistRequests.VERIFIED_LIFETIME_MS + 1
        assertTrue(f.engine.keptOrigins().isEmpty(), "the request lapsed")
        f.engine.cancel(check2)
        assertFalse(f.engine.holdsOpened(a.origin), "nothing opened outlives the leave")
    }

    /**
     * A `404` for a kept request, at the code, the poll and the commit (the server lost the row, or lies). Before, the
     * device forgot the request at once and said "expired". Now it says that the server no longer knows the request, keeps
     * it, asks again at the next look, and lets it go when its own lifetime ends.
     */
    @Test fun aRequestTheServerNoLongerKnowsIsSaidAndKeptUntilItsLifetimeEnds() = runBlocking<Unit> {
        // At the code.
        val a = setup()
        val alice = register(a.inner, "alice@example.com")
        val f = fresh(a)
        val requested = assertIs<AssistedStep.Requested>(f.engine.request(assertIs(f.engine.start("alice@example.com", a.origin))))
        val id = a.reqs.keys.last()
        val lost = a.reqs.remove(id)!!
        assertEquals(WireAssistedRecovery.REQUEST_UNKNOWN, assertIs<AssistedStep.Stopped>(f.engine.verifyCode(requested, a.code)).reason)
        assertEquals(listOf(a.origin), f.engine.keptOrigins(), "kept")
        a.reqs[id] = lost
        val waiting = assertIs<AssistedStep.Waiting>(f.engine.verifyCode(requested, a.code), "the row is back: on")
        // At the poll: said at each look, kept, and gone once its lifetime ends.
        val (requestId, row) = a.reqs.entries.single().toPair()
        a.reqs.remove(requestId)
        repeat(2) { assertEquals(WireAssistedRecovery.REQUEST_UNKNOWN, assertIs<AssistedStep.Stopped>(f.engine.poll(waiting)).reason) }
        assertEquals(listOf(a.origin), f.engine.keptOrigins())
        // At the commit.
        a.reqs[requestId] = row
        a.inner.now += 7 * 86_400_000L
        val awaiting = assertIs<AssistedStep.Waiting>(f.engine.poll(waiting))
        a.fulfil(requestId, alice.account, alice.session.account.uvk.copyOut())
        val choose = assertIs<AssistedStep.ChoosePassword>(f.engine.confirmAccount(assertIs(f.engine.poll(awaiting)), true))
        a.reqs.remove(requestId)
        assertEquals(WireAssistedRecovery.REQUEST_UNKNOWN, assertIs<AssistedStep.Stopped>(f.engine.commit(choose, newPw.toCharArray())).reason)
        assertFalse(f.engine.holdsOpened(a.origin), "what was opened goes")
        assertEquals(listOf(a.origin), f.engine.keptOrigins(), "the request is kept")
        a.inner.now += AssistRequests.VERIFIED_LIFETIME_MS
        assertNull(f.engine.resume(a.origin), "its lifetime ended: gone")
        assertTrue(f.engine.keptOrigins().isEmpty())
    }

    /**
     * A request its account's owner cancelled before its code was entered (a password change, recovery switched to
     * private, a recovery of the account): the server leaves its poll `unverified` and answers the right code with
     * `409 request_state`. That is a final stop that forgets the kept request. Before, it was read as a refusal at which
     * the step stays, and the device kept a request the server had ended.
     */
    @Test fun theRightCodeForARequestTheOwnerCancelledIsAFinalStopThatForgetsTheRequest() = runBlocking<Unit> {
        val a = setup()
        register(a.inner, "alice@example.com")
        val f = fresh(a)
        val target = assertIs<AssistedStep.ConfirmTarget>(f.engine.start("alice@example.com", a.origin))
        val first = assertIs<AssistedStep.Requested>(f.engine.request(target))
        a.reqs.values.single().cancelled = true
        // The poll says nothing of it, and a wrong code is the uniform answer, at which the step stays.
        val requested = assertIs<AssistedStep.Requested>(f.engine.poll(first))
        assertEquals("bad_code", assertIs<AssistedStep.Stopped>(f.engine.verifyCode(requested, "000000")).reason)
        assertEquals(listOf(a.origin), f.engine.keptOrigins())
        // The right code: the request was cancelled, a stop of its own, and nothing is kept.
        assertEquals(WireAssistedRecovery.REQUEST_CANCELLED, assertIs<AssistedStep.Stopped>(f.engine.verifyCode(requested, a.code)).reason)
        assertEquals(emptyList(), f.engine.keptOrigins(), "the kept request is forgotten")
        assertNull(f.engine.resume(a.origin))
        val sent = a.calls.size
        assertEquals(WireAssistedRecovery.STALE, assertIs<AssistedStep.Stopped>(f.engine.verifyCode(requested, a.code)).reason, "the step does not stay")
        assertEquals(sent, a.calls.size, "and nothing more is sent")
        assertNull(fresh(a, f.pins, f.secure).engine.resume(a.origin), "nor after a restart")
    }

    // ---- a recovery-key change while a request is open (spec 04 §5) ----

    private val newSeed = ByteArray(32) { 5 }
    private val newSigner: KeyPairBytes = crypto.signKeypairFromSeed(newSeed)
    private val newFp = Escrow.fingerprint(crypto, crypto.boxKeypairFromSeed(newSeed).publicKey)

    /** The operator signs the next card naming [newFp]; [rotation], when given, is served beside the chain. */
    private fun rotateTo(a: Assist, rotation: ByteArray?) {
        val prev = a.inner.cards.last()
        a.inner.cards += io.silencelen.andvari.core.trust.InstanceCard.sign(crypto, a.inner.operatorSign, io.silencelen.andvari.core.trust.CardFields(
            a.inner.instanceId, a.inner.cards.size.toLong(), io.silencelen.andvari.core.trust.SignedFrame.hash(crypto, prev), a.origin, "Home", a.inner.kind,
            "99999999-9999-4999-8999-999999999999", Bytes.toB64(a.inner.operatorSign.publicKey), newFp, a.inner.now))
        rotation?.let { a.inner.rotations += it }
    }

    /** The genuine statement: the outgoing key (the one the request was made under) moves to [newFp]. */
    private fun signedRotation(a: Assist, at: Long): ByteArray = io.silencelen.andvari.core.trust.RecoveryRotation.sign(crypto, recoverySigner,
        io.silencelen.andvari.core.trust.RotationFields(a.inner.instanceId, recoveryFp, newFp, at))

    /** [frame]'s statement, unchanged, signed by [signer] instead (what a holder of the new key alone can make). */
    private fun resigned(frame: ByteArray, signer: KeyPairBytes): ByteArray {
        val sf = io.silencelen.andvari.core.trust.SignedFrame
        val statement = frame.copyOfRange(sf.STATEMENT_OFFSET, frame.size)
        val sig = crypto.signDetached(signer.privateKey, sf.signedMessage(frame[4].toInt() and 0xFF, signer.publicKey, statement))
        return frame.copyOfRange(0, sf.HEADER_BYTES) + signer.publicKey + sig + statement
    }

    /**
     * On the device's side: the operator stores a signed rotation and signs the card with the new key
     * while a request is open. The request goes on, the device says that the server's recovery key changed and when (the
     * statement's own signed time), that survives a restart, and from then on only an answer signed by the new key is taken.
     * Before, the device followed the change without a word.
     */
    @Test fun aSignedRotationWhileARequestIsOpenIsFollowedAndPublishedAndTheNewKeysAnswerIsTaken() = runBlocking<Unit> {
        val a = setup()
        val alice = register(a.inner, "alice@example.com")
        val f = fresh(a)
        val (requestId, waiting) = holding(a, f)
        assertNull(f.engine.recoveryKeyChange(a.origin))
        val at = a.inner.now - 60_000
        // The card that first names the new key is signed after the statement: that card's time is the "since" shown.
        val cardAt = a.inner.now
        rotateTo(a, signedRotation(a, at))
        a.inner.now += 7 * 86_400_000L
        val awaiting = assertIs<AssistedStep.Waiting>(f.engine.poll(waiting), "the request goes on")
        val change = assertNotNull(f.engine.recoveryKeyChange(a.origin), "the change is published")
        assertTrue(change.signed)
        assertEquals(recoveryFp, change.fromFp)
        assertEquals(newFp, change.toFp)
        assertEquals(cardAt, change.rotatedAt, "since: the time of the card that first named the new key, not the rotation's")
        assertEquals(cardAt, fresh(a, f.pins, f.secure).engine.recoveryKeyChange(a.origin)?.rotatedAt, "kept with the request across a restart")
        // An answer signed by the outgoing key is no longer the pinned card's.
        a.fulfil(requestId, alice.account, alice.session.account.uvk.copyOut(), signer = recoverySigner)
        assertEquals("signer_not_pinned_key", assertIs<AssistedStep.Stopped>(f.engine.poll(awaiting)).reason)
        // The honest answer after a signed rotation, signed by the new key: taken, and the recovery finishes.
        a.fulfil(requestId, alice.account, alice.session.account.uvk.copyOut(), signer = newSigner)
        val check = assertIs<AssistedStep.CheckAccount>(f.engine.poll(awaiting))
        val choose = assertIs<AssistedStep.ChoosePassword>(f.engine.confirmAccount(check, true))
        assertIs<AssistedStep.Recovered>(f.engine.commit(choose, newPw.toCharArray()))
    }

    /**
     * The unsigned case: the card names another recovery key and no rotation this device verifies
     * covers it (none served, one altered, one signed by the new key alone, a genuine one made for another instance). The
     * request stops with spec 04 §5's warning at every look, nothing is polled and nothing of an answer is opened, and it is
     * kept. Before, the device followed the change silently and took an answer signed by the new key.
     */
    @Test fun aRecoveryKeyChangeNoVerifiedRotationCoversStopsTheRequestWithTheWarningAndOpensNothing() = runBlocking<Unit> {
        for (how in listOf("missing", "altered", "signed_by_the_new_key", "another_instance")) {
            val a = setup()
            val alice = register(a.inner, "alice@example.com")
            val f = fresh(a)
            val (requestId, waiting) = holding(a, f)
            val good = signedRotation(a, a.inner.now)
            val served = when (how) {
                "missing" -> null
                "altered" -> good.copyOf().also { it[60] = (it[60].toInt() xor 1).toByte() } // a byte of the signature
                "signed_by_the_new_key" -> resigned(good, newSigner)
                else -> io.silencelen.andvari.core.trust.RecoveryRotation.sign(crypto, recoverySigner,
                    io.silencelen.andvari.core.trust.RotationFields("5d1f0c2e-7a3b-4c4d-9e5f-6a7b8c9d0e1f", recoveryFp, newFp, a.inner.now))
            }
            rotateTo(a, served)
            a.inner.now += 7 * 86_400_000L
            a.fulfil(requestId, alice.account, alice.session.account.uvk.copyOut(), signer = newSigner)
            val mark = a.calls.size
            repeat(2) {
                assertEquals(WireAssistedRecovery.RECOVERY_KEY_CHANGED, assertIs<AssistedStep.Stopped>(f.engine.poll(waiting), how).reason, "$how: never silently")
            }
            assertFalse(WireRoute.RECOVERY_REQUEST_POLL in a.calls.drop(mark), "$how: nothing was polled, so nothing of the answer was opened")
            val change = assertNotNull(f.engine.recoveryKeyChange(a.origin), how)
            assertFalse(change.signed)
            assertEquals(recoveryFp, change.fromFp)
            assertEquals(newFp, change.toFp)
            assertNull(change.rotatedAt)
            assertEquals(listOf(a.origin), f.engine.keptOrigins(), "$how: the request is kept")
            assertTrue(f.sink.sessions.isEmpty())
            if (how == "missing") {
                // The genuine rotation served later covers the change: the request goes on under the new key, and says so.
                a.inner.rotations += good
                assertIs<AssistedStep.CheckAccount>(f.engine.poll(waiting), "covered now")
                assertTrue(f.engine.recoveryKeyChange(a.origin)!!.signed)
            }
        }
    }

    /**
     * A request kept by a build that did not record the recovery key: the device cannot tell whether a change of key came
     * before or after the request, so it binds the request to the pinned key only when every change of `recoveryFp` along
     * the whole served chain from card 0 is covered by verified rotations (the first-consent walk), and otherwise stops it
     * with the warning, as an unsigned change. That is the safe reading: a covered change is one the outgoing key signed
     * whenever it happened, and an uncovered one might have happened while the request waited.
     */
    @Test fun aRequestKeptBeforeTheKeyWasRecordedIsBoundOnlyWhenTheWholeChainIsCovered() = runBlocking<Unit> {
        for (how in listOf("unchanged", "signed", "unsigned")) {
            val a = setup()
            val alice = register(a.inner, "alice@example.com")
            val f = fresh(a)
            val (requestId, waiting) = holding(a, f)
            val key = "ovh.assist|${a.origin}"
            val k = WireJson.json.decodeFromString(KeptAssistRequest.serializer(), f.secure.get(key)!!)
            assertEquals(recoveryFp, k.recoveryFp, "a request made now records the key")
            f.secure.set(key, WireJson.json.encodeToString(KeptAssistRequest.serializer(), k.copy(recoveryFp = null)))
            when (how) {
                "signed" -> rotateTo(a, signedRotation(a, a.inner.now))
                "unsigned" -> rotateTo(a, null)
            }
            a.inner.now += 7 * 86_400_000L
            a.fulfil(requestId, alice.account, alice.session.account.uvk.copyOut(), signer = if (how == "unchanged") recoverySigner else newSigner)
            val polled = f.engine.poll(waiting)
            val stored = WireJson.json.decodeFromString(KeptAssistRequest.serializer(), f.secure.get(key)!!)
            if (how == "unsigned") {
                assertEquals(WireAssistedRecovery.RECOVERY_KEY_CHANGED, assertIs<AssistedStep.Stopped>(polled).reason)
                val change = assertNotNull(f.engine.recoveryKeyChange(a.origin))
                assertNull(change.fromFp, "the key it was made under is not known")
                assertNull(stored.recoveryFp)
            } else {
                assertIs<AssistedStep.CheckAccount>(polled, how)
                assertEquals(if (how == "signed") newFp else recoveryFp, stored.recoveryFp, "$how: bound to the pinned key from now on")
                assertNull(f.engine.recoveryKeyChange(a.origin), "$how: no change seen while it waited")
            }
        }
    }

    /**
     * A request for the operator's help is a flow under way for its address from its confirmed target for as long as the
     * device keeps it, after a restart too: the forgetting of the earlier account answers so and removes nothing. Leaving
     * the request ends it. Before, only the commit call held, and a kept request held nothing.
     */
    @Test fun aKeptRequestBlocksTheForgettingForAsLongAsItIsKept() = runBlocking<Unit> {
        val a = setup()
        val email = "alice@example.com"
        val pins = MemoryDeviceState()
        val requests = MemoryDeviceState()
        val trust = a.inner.pinnedTrust(pins)
        fun keeper() = io.silencelen.andvari.core.client.session.SessionKeeper(
            io.silencelen.andvari.core.client.session.BearerTransport(mapOf(a.origin to a)), MemoryDeviceState(), pins, trust, crypto,
        )
        fun engine(k: io.silencelen.andvari.core.client.session.SessionKeeper) = WireAssistedRecovery({ k.clientFor(it) }, trust, KnownDevices(pins, crypto), k,
            crypto, requests, "android", "New", { a.inner.now }, knownIdentity = k::knownIdentity)
        val keeper = keeper()
        val o = WireOnboarding(a.origin, keeper.clientFor(a.origin), trust, KnownDevices(pins, crypto), keeper, crypto, pins, "android", "New",
            { a.inner.now }, knownIdentity = keeper::knownIdentity, work = Dispatchers.Unconfined)
        o.signupStart(email, true)
        val t = assertIs<SignupVerify.Ticket>(o.signupVerify(email, "482915"))
        val id = assertIs<Registration.Registered>(o.register(RegistrationAuth.Ticket(t),
            RegistrationForm(email, "A", strong.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "New", "android"))).userId
        keeper.signOut()
        val under = io.silencelen.andvari.core.client.session.ForgetEarlier.FlowUnderWay
        val engine = engine(keeper)
        val target = assertIs<AssistedStep.ConfirmTarget>(engine.start(email, a.origin))
        assertEquals(under, keeper.forgetEarlierAccount(a.origin, email), "at the confirmation")
        val requested = assertIs<AssistedStep.Requested>(engine.request(target))
        assertEquals(under, keeper.forgetEarlierAccount(a.origin, email), "requested and kept")
        assertEquals(io.silencelen.andvari.core.client.session.ForgetEarlier.NothingToForget, keeper.forgetEarlierAccount(a.origin, "bob@example.com"))
        // After a restart: a new keeper and a new engine over the same stores.
        val again = keeper()
        engine(again)
        assertEquals(under, again.forgetEarlierAccount(a.origin, email), "kept across a restart")
        engine.cancel(requested)
        assertEquals(io.silencelen.andvari.core.client.session.ForgetEarlier.Forgotten(id, copyRemoved = false), again.forgetEarlierAccount(a.origin, email))
    }

    /**
     * A request for the operator's help that the person sets aside (the screen left without giving it up) holds the
     * forgetting of the earlier account back no longer than what it keeps: at the step that confirms the target nothing is
     * kept, so the forgetting goes through after it; at every later step the kept request still holds it, until the request
     * is left. Before, a target set aside stayed in memory and the forgetting answered "under way" until a restart.
     */
    @Test fun aRequestSetAsideHoldsTheForgettingOnlyWhileItsRequestIsKept() = runBlocking<Unit> {
        val a = setup()
        val email = "alice@example.com"
        val alice = register(a.inner, email)
        val pins = MemoryDeviceState()
        val trust = a.inner.pinnedTrust(pins)
        val keeper = io.silencelen.andvari.core.client.session.SessionKeeper(
            io.silencelen.andvari.core.client.session.BearerTransport(mapOf(a.origin to a)), MemoryDeviceState(), pins, trust, crypto,
        )
        val o = WireOnboarding(a.origin, keeper.clientFor(a.origin), trust, KnownDevices(pins, crypto), keeper, crypto, pins, "android", "New",
            { a.inner.now }, knownIdentity = keeper::knownIdentity, work = Dispatchers.Unconfined)
        assertIs<SignIn.SignedIn>(o.signIn(email, strong.toCharArray()))
        keeper.signOut()
        val engine = WireAssistedRecovery({ keeper.clientFor(it) }, trust, KnownDevices(pins, crypto), keeper, crypto, MemoryDeviceState(),
            "android", "New", { a.inner.now }, knownIdentity = keeper::knownIdentity)
        val under = io.silencelen.andvari.core.client.session.ForgetEarlier.FlowUnderWay
        fun forget() = keeper.forgetEarlierAccount(a.origin, email)

        // The confirmation, set aside: nothing is kept, so nothing holds; the step is dead.
        val target = assertIs<AssistedStep.ConfirmTarget>(engine.start(email, a.origin))
        assertEquals(under, forget(), "at the confirmation")
        engine.setAside(target)
        assertEquals(io.silencelen.andvari.core.client.session.ForgetEarlier.Forgotten(alice.account.userId, copyRemoved = false), forget(),
            "the confirmation set aside")
        assertEquals(AssistedStep.Stopped(WireAssistedRecovery.STALE), engine.request(target))
        assertTrue(engine.keptOrigins().isEmpty(), "nothing was sent")

        // Every later step, set aside: the kept request holds, and the next step is picked up from it.
        val requested = assertIs<AssistedStep.Requested>(engine.request(assertIs<AssistedStep.ConfirmTarget>(engine.start(email, a.origin))))
        engine.setAside(requested)
        assertEquals(under, forget(), "requested, set aside, kept")
        val requestedAgain = assertIs<AssistedStep.Requested>(engine.resume(a.origin))
        val waiting = assertIs<AssistedStep.Waiting>(engine.verifyCode(requestedAgain, a.code))
        engine.setAside(waiting)
        assertEquals(under, forget(), "waiting, set aside, kept")
        a.inner.now += 7 * 86_400_000L
        val awaiting = assertIs<AssistedStep.Waiting>(engine.resume(a.origin))
        a.fulfil(a.reqs.keys.last(), alice.account, alice.session.account.uvk.copyOut())
        val check = assertIs<AssistedStep.CheckAccount>(engine.poll(awaiting))
        engine.setAside(check)
        assertEquals(under, forget(), "the account check, set aside, kept")
        val choose = assertIs<AssistedStep.ChoosePassword>(engine.confirmAccount(assertIs<AssistedStep.CheckAccount>(engine.resume(a.origin)), true))
        engine.setAside(choose)
        assertEquals(under, forget(), "the new password, set aside, kept")

        // Left: the request goes, and nothing holds the forgetting any more.
        engine.cancel(assertIs<AssistedStep.CheckAccount>(engine.resume(a.origin)))
        assertTrue(engine.keptOrigins().isEmpty())
        assertEquals(io.silencelen.andvari.core.client.session.ForgetEarlier.NothingToForget, forget(), "the request left")
    }
}
