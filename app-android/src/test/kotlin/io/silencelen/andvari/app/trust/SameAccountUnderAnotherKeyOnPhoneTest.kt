package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppApi
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.AskOperatorResult
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.DeletionResult
import io.silencelen.andvari.core.app.DeviceLinkHost
import io.silencelen.andvari.core.app.DeviceLinkScanResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.ForgetEarlierResult
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.KitDocument
import io.silencelen.andvari.core.app.KitRecoverResult
import io.silencelen.andvari.core.app.KitScanResult
import io.silencelen.andvari.core.app.LinkDeviceEnd
import io.silencelen.andvari.core.app.LinkPasswordResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ProofResult
import io.silencelen.andvari.core.app.ReplacePasswordResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.engine.AppEngine
import io.silencelen.andvari.core.app.engine.EngineAppApi
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.devicelink.DeviceLinkServer
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.client.session.SessionKeeper
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KeyPairBytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.RecoveryPollRequest
import io.silencelen.andvari.core.model.wire.RecoveryPollResponse
import io.silencelen.andvari.core.model.wire.RecoveryRequestCreate
import io.silencelen.andvari.core.model.wire.RecoveryRequestCreated
import io.silencelen.andvari.core.model.wire.RecoveryRequestVerified
import io.silencelen.andvari.core.model.wire.RecoveryRequestVerify
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.AssistedRecoveryFields
import io.silencelen.andvari.core.trust.InstanceKind
import io.silencelen.andvari.core.trust.TrustGrammar
import kotlinx.coroutines.CoroutineScope
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
import io.silencelen.andvari.core.trust.AssistedRecovery as AssistedRecoveryTrust

/**
 * The same account under another key, walked on the phone over the shared code's REAL engine and its own test server:
 * wherever the server serves the account this phone knows under an address with another identity key, the phone ends on
 * the identity fault's own line and offers NOTHING to forget, on that screen and on every screen the person can reach
 * from it (the first screen, the sign-in again, another account's open vault and Settings, its lock screen, a new start
 * of the app). "Forget the earlier account on this device" is for ANOTHER account under the address only (decided on
 * 2026-11-19): the same account under another key is the substitution the phone's record of the address exists to stop.
 *
 * "The same account under another key" is made at the test server the way a server could serve it: the account deleted
 * and registered again under the very id it had ([FixedId] gives the registration that id), consistent in itself, with an
 * identity key that is not the one this phone knows. Set-up the screens do not play goes to the engine's public calls.
 * A device link runs on both engines' own polls (every two seconds), so its walks wait for the screens they need.
 */
class SameAccountUnderAnotherKeyOnPhoneTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val replacement = "a brand new Master password 7"
    private val alice = "alice@example.com"
    private val bob = "bob@example.com"

    /** [inner], except that the next 16 random bytes asked for are [next], once: a registration's new account id. */
    private class FixedId(val inner: CryptoProvider) : CryptoProvider by inner {
        var next: ByteArray? = null
        override fun randomBytes(n: Int): ByteArray {
            val fixed = next
            if (n == 16 && fixed != null) {
                next = null
                return fixed.copyOf()
            }
            return inner.randomBytes(n)
        }
    }

    private class Phone(val state: MemoryDeviceState = MemoryDeviceState(), val secure: MemoryDeviceState = MemoryDeviceState())

    private val opened = ArrayList<EngineAppApi>()

    /** An engine of [phone] (a new one is a start of the app on the same phone), talking to [via] at its origin. */
    private fun app(via: WireClient, now: () -> Long, phone: Phone = Phone(), c: CryptoProvider = crypto): EngineAppApi = EngineAppApi(
        AppEngine(
            AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(via.origin to via)), phone.state, phone.secure, c, now,
            baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
        ),
    ).also { opened += it }

    private fun app(server: FakeInstance, phone: Phone = Phone(), c: CryptoProvider = crypto) = app(server, { server.now }, phone, c)

    private fun model(api: EngineAppApi): TrustModel =
        TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L }).also {
            it.start()
            it.onSnapshot(api.snapshot)
        }

    private fun walk(body: suspend () -> Unit) = try {
        runBlocking { body() }
    } finally {
        opened.forEach { runCatching { it.close() } }
    }

    private inline fun <reified T : EntryScreen> AppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    private fun <R : IntentResult> TrustModel.done(intent: suspend AppApi.() -> R): R {
        var result: R? = null
        runBlocking { run(intent) { result = it }.join() }
        onSnapshot(api.snapshot)
        return assertNotNull(result, "the intent ended without a result: ${wentWrong.value?.text}")
    }

    private fun TrustModel.step(intent: AppApi.() -> Unit) {
        act(intent)
        onSnapshot(api.snapshot)
    }

    /** Waits (up to 30 s) until [ready] holds of [api]'s snapshot: a device link moves on its engines' own polls. */
    private fun waitFor(api: AppApi, what: String, ready: () -> Boolean) {
        val until = System.currentTimeMillis() + 30_000
        while (!ready()) {
            check(System.currentTimeMillis() < until) { "waited 30 s for $what; on ${api.snapshot.entry}, link ${api.snapshot.account?.deviceLink}" }
            Thread.sleep(25)
        }
    }

    /** Registers [email] through the screens ([before] just before the account is made) and confirms its first kit. */
    private fun TrustModel.register(email: String, before: () -> Unit = {}): KitDocument {
        step { entry.openOwnServer(at()) }
        assertEquals(ServerResult.DONE, done { entry.submitServerAddress(at(), "h.example") })
        (api.snapshot.entry as? EntryScreen.TrustGate)?.let { gate -> assertEquals(ServerResult.DONE, done { entry.confirmTrustGate(gate) }) }
        assertEquals(ServerResult.DONE, done { entry.createAccountHere(at()) })
        assertEquals(SignUpStartResult.DONE, done { entry.startSignUp(at(), email, true) })
        assertEquals(CodeResult.DONE, done { entry.verifySignUpCode(at(), "482915") })
        before()
        assertEquals(CreateAccountResult.DONE, done { entry.createAccount(at(), NewAccountInput("", "P", strong, true)) })
        val reveal = api.at<EntryScreen.Kit>().kit
        val doc = assertNotNull(api.kit.kitDocument(reveal))
        step { kit.proceedToConfirm(reveal) }
        val confirm = api.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, done { kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        return doc
    }

    /** From the first screen to the password screen of a sign-in at [origin]. */
    private fun TrustModel.toSignIn(origin: String) {
        step { entry.openSignIn(at()) }
        step { entry.openPasswordSignIn(at()) }
        assertEquals(ServerResult.DONE, done { entry.chooseOwnServer(at(), origin) })
        (api.snapshot.entry as? EntryScreen.TrustGate)?.let { gate -> assertEquals(ServerResult.DONE, done { entry.confirmTrustGate(gate) }) }
        api.at<EntryScreen.SignIn>()
    }

    /**
     * The account under [alice] at [server] is deleted there and registered again on another device under the SAME id
     * [userId], with another identity key: the account this phone knows, served under another key. That device's engine
     * (open on the account) and the new kit.
     */
    private fun sameIdOtherKey(server: FakeInstance, userId: String, via: WireClient = server): Other {
        val before = server.account(alice).identityPub
        server.accounts.remove(alice)
        val fixed = FixedId(crypto)
        val other = app(via, { server.now }, Phone(), fixed)
        val om = model(other)
        val doc = om.register(alice) { fixed.next = assertNotNull(Bytes.fromHexLower(userId.replace("-", ""))) }
        assertEquals(userId, server.account(alice).userId, "the same account id")
        assertNotEquals(before, server.account(alice).identityPub, "another identity key")
        return Other(other, om, doc)
    }

    /** The other device, open on the account it registered, its model, and the account's kit. */
    private class Other(val api: EngineAppApi, val m: TrustModel, val doc: KitDocument)

    /** The phone's own record of the address: the account it ties [alice] to at [origin], as "id|key". */
    private fun Phone.bindingOf(origin: String): String? = state.get(SessionKeeper.EMAIL_BINDING_PREFIX + origin + "|" + alice)

    // ---- what the phone draws, and every screen the person can reach from the refusal ----

    /** The refused result's line as the phone draws it in place ([SaidHere]): its result and its words. */
    private fun TrustModel.said(): Pair<IntentResult?, String>? = saidOn(api.snapshot)?.let { it.result to it.text.shown() }

    /** The identity fault's own line, as the shared code hands it for the identity fault. */
    private val identityFaultLine get() = UiText.of(CopyKey.IDENTITY_FAULT_ADDRESS_KNOWN).shown()

    /**
     * From the refused screen on, every screen the person can reach, none with an offer to forget anything: [back] (the
     * screen's own way back) to the first screen; the sign-in again; another account ([bob], at the same server) signed in,
     * its vault and Settings; its lock screen; a new start of the app on the same phone. Nothing is taken for [alice].
     */
    private fun walkOnWithNoOffer(m: TrustModel, d: EngineAppApi, origin: String, via: WireClient, now: () -> Long, phone: Phone, back: TrustModel.() -> Unit) {
        assertNull(d.snapshot.earlierAccount, "the refused screen: no offer")
        m.back()
        val first = d.at<EntryScreen.FirstRun>()
        assertNull(d.snapshot.earlierAccount, "the first screen: no offer")
        assertNull(first.accountDeleted)
        m.toSignIn(origin)
        assertNull(d.snapshot.earlierAccount, "the sign-in again: no offer")
        assertNull(m.said(), "nothing said on the fresh sign-in")
        assertEquals(SignInAnswer.DONE, m.done { entry.submitSignIn(at(), bob, strong) })
        assertEquals(AppPhase.UNLOCKED, d.snapshot.phase)
        assertNull(d.snapshot.earlierAccount, "another account's vault and Settings: no offer")
        assertNull(d.snapshot.rememberedNewAccount, "nothing said of a remembered account")
        m.step { lock() }
        assertNotNull(d.snapshot.locked)
        assertNull(d.snapshot.earlierAccount, "its lock screen: no offer")
        val again = app(via, now, phone)
        val m2 = model(again)
        assertNotNull(again.snapshot.locked, "a new start of the app: the lock screen")
        assertNull(again.snapshot.earlierAccount, "a new start of the app: no offer")
        assertNull(m2.said())
    }

    // ---- (a) a sign-in ----

    /**
     * The phone knows [alice]'s account U (registered here, signed out); the server serves U under another key. The
     * sign-in is refused with the identity fault's own line and no offer; walked on. Both where the phone keeps its
     * record of U's key and where only its record of the address names U.
     */
    @Test
    fun aSignInServedTheKnownAccountUnderAnotherKeyEndsOnTheIdentityFaultsLineWithNoOfferAnywhere() = walk {
        for (keyRecord in listOf(true, false)) {
            val server = FakeInstance(crypto)
            model(app(server)).register(bob)
            val phone = Phone()
            val d = app(server, phone)
            val m = model(d)
            m.register(alice)
            val u = server.account(alice).userId
            assertEquals(PlainResult.DONE, m.done { signOut() })
            sameIdOtherKey(server, u)
            if (!keyRecord) phone.state.set("ovh.identity|$u", null)
            val bound = phone.bindingOf(server.origin)

            m.toSignIn(server.origin)
            assertEquals(SignInAnswer.IDENTITY_FAULT, m.done { entry.submitSignIn(at(), alice, strong) }, "record of the key: $keyRecord")
            assertEquals(SignInAnswer.IDENTITY_FAULT to identityFaultLine, m.said(), "the identity fault's own line (record of the key: $keyRecord)")
            assertNull(d.snapshot.earlierAccount, "no offer (record of the key: $keyRecord)")
            assertEquals(bound, phone.bindingOf(server.origin), "nothing forgotten")
            walkOnWithNoOffer(m, d, server.origin, server, { server.now }, phone) { step { entry.startOver() } }
            assertEquals(bound, phone.bindingOf(server.origin), "nothing forgotten after the walk")
        }
    }

    // ---- (b) a recovery with the kit ----

    /**
     * The kit of U under another key, scanned on a phone that knows U: the kit's check is refused with the identity
     * fault's own line and no offer, nothing is committed; walked on.
     */
    @Test
    fun aKitRecoveryOfTheKnownAccountUnderAnotherKeyEndsOnTheIdentityFaultsLineWithNoOfferAnywhere() = walk {
        val server = FakeInstance(crypto)
        model(app(server)).register(bob)
        val phone = Phone()
        val d = app(server, phone)
        val m = model(d)
        m.register(alice)
        val u = server.account(alice).userId
        assertEquals(PlainResult.DONE, m.done { signOut() })
        val swapped = sameIdOtherKey(server, u).doc
        val bound = phone.bindingOf(server.origin)

        m.step { entry.openSignIn(at()) }
        m.step { entry.openForgot(at()) }
        m.step { entry.openKitEntry(at()) }
        assertEquals(KitScanResult.DONE, m.done { entry.submitKit(at(), swapped.qrPayload, PayloadSource.SCANNED) })
        (d.snapshot.entry as? EntryScreen.TrustGate)?.let { gate -> assertEquals(ServerResult.DONE, m.done { entry.confirmTrustGate(gate) }) }
        assertEquals(KitRecoverResult.IDENTITY_FAULT, m.done { entry.confirmKitRecovery(at()) })
        assertEquals(KitRecoverResult.IDENTITY_FAULT to identityFaultLine, m.said(), "the identity fault's own line")
        assertNull(d.snapshot.earlierAccount, "no offer")
        assertFalse(WireRoute.RECOVERY_SELF_COMMIT in server.calls, "nothing committed")
        assertEquals(bound, phone.bindingOf(server.origin))
        walkOnWithNoOffer(m, d, server.origin, server, { server.now }, phone) { step { entry.startOver() } }
    }

    /**
     * The kit's commit, asked again just before it is sent: while the new password was being chosen, the same phone,
     * started a second time, signed in to the kit's own account served under ANOTHER key for that moment and out again,
     * so the phone now ties the address to that account under that key. The commit is refused with the identity fault's
     * line as the shared code hands it, nothing is committed, no offer; walked on.
     */
    @Test
    fun aKitCommitAfterTheAddressCameToNameTheSameAccountUnderAnotherKeyEndsOnTheIdentityFaultWithNoOfferAnywhere() = walk {
        val server = FakeInstance(crypto)
        model(app(server)).register(bob)
        val doc = model(app(server)).register(alice)
        val u = server.account(alice).userId
        val own = server.accounts.getValue(alice)

        val phone = Phone()
        val d = app(server, phone)
        val m = model(d)
        m.step { entry.openSignIn(at()) }
        m.step { entry.openForgot(at()) }
        m.step { entry.openKitEntry(at()) }
        assertEquals(KitScanResult.DONE, m.done { entry.submitKit(at(), doc.qrPayload, PayloadSource.SCANNED) })
        (d.snapshot.entry as? EntryScreen.TrustGate)?.let { gate -> assertEquals(ServerResult.DONE, m.done { entry.confirmTrustGate(gate) }) }
        assertEquals(KitRecoverResult.DONE, m.done { entry.confirmKitRecovery(at()) })
        d.at<EntryScreen.ReplacePassword>()

        // Meanwhile: U served under another key, taken by a second start of the app on this phone, and signed out.
        sameIdOtherKey(server, u)
        val second = app(server, phone)
        val m2 = model(second)
        m2.toSignIn(server.origin)
        assertEquals(SignInAnswer.DONE, m2.done { entry.submitSignIn(at(), alice, strong) })
        assertEquals(PlainResult.DONE, m2.done { signOut() })
        val taken = assertNotNull(phone.bindingOf(server.origin))
        assertTrue(taken.startsWith("$u|"), "the address names U, under the other key")
        server.accounts[alice] = own

        assertEquals(ReplacePasswordResult.IDENTITY_FAULT, m.done { entry.chooseReplacementPassword(at(), replacement) })
        assertEquals(ReplacePasswordResult.IDENTITY_FAULT to identityFaultLine, m.said(), "the line as the shared code hands it")
        assertNull(d.snapshot.earlierAccount, "no offer")
        assertFalse(WireRoute.RECOVERY_SELF_COMMIT in server.calls, "nothing committed")
        walkOnWithNoOffer(m, d, server.origin, server, { server.now }, phone) { step { entry.startOver() } }
        assertEquals(taken, phone.bindingOf(server.origin), "nothing forgotten")
    }

    // ---- (c) a recovery with the operator's help ----

    private val recoverySigner: KeyPairBytes = crypto.signKeypairFromSeed(ByteArray(32) { 2 })
    private val recoveryFp = Escrow.fingerprint(crypto, crypto.boxKeypairFromSeed(ByteArray(32) { 2 }).publicKey)

    /** The request routes of a recovery with the operator's help, as an honest server answers them, over [inner]. */
    private class Assist(val inner: FakeInstance, val crypto: CryptoProvider) : WireClient {
        override val origin: String get() = inner.origin

        class Req(val rPub: String, val pollHash: String, val userId: String) {
            var state = "unverified"
            var holdEndsAt: Long? = null
            var sealed: String? = null
        }

        val reqs = LinkedHashMap<String, Req>()
        val code = "314159"
        private var n = 0

        private fun refuse(status: Int, code: String): WireResult<Nothing> = WireResult.Refused(status, WireError(code, code))

        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            fun ok(text: String): WireResult<T> = WireResult.Ok(decode(text), 200)
            val id = pathParams["requestId"]
            fun byPoll(secret: String) = reqs[id]?.takeIf { Bytes.toHexLower(crypto.sha256(Bytes.fromB64(secret))) == it.pollHash }
            return when (route) {
                WireRoute.RECOVERY_REQUEST_CREATE -> {
                    val b = WireJson.json.decodeFromString(RecoveryRequestCreate.serializer(), bodyJson!!)
                    n++
                    val requestId = Bytes.toB64(ByteArray(16) { (it + n).toByte() })
                    inner.accounts[TrustGrammar.emailNorm(b.email)]?.let { reqs[requestId] = Req(b.rPub, b.pollHash, it.userId) }
                    WireResult.Ok(decode(WireJson.json.encodeToString(RecoveryRequestCreated.serializer(), RecoveryRequestCreated(requestId))), 202)
                }
                WireRoute.RECOVERY_REQUEST_VERIFY -> {
                    val b = WireJson.json.decodeFromString(RecoveryRequestVerify.serializer(), bodyJson!!)
                    val r = reqs[id]?.takeIf { it.state == "unverified" && b.code == code } ?: return refuse(400, "bad_code")
                    r.state = "holding"
                    r.holdEndsAt = inner.now + 7 * 86_400_000L
                    ok(WireJson.json.encodeToString(RecoveryRequestVerified.serializer(), RecoveryRequestVerified("holding", r.holdEndsAt!!)))
                }
                WireRoute.RECOVERY_REQUEST_POLL -> {
                    val b = WireJson.json.decodeFromString(RecoveryPollRequest.serializer(), bodyJson!!)
                    val r = byPoll(b.pollSecret) ?: return refuse(404, "request_unknown")
                    val a = inner.accounts.values.first { it.userId == r.userId }
                    val resp = when {
                        r.sealed != null -> RecoveryPollResponse("ready", null, r.sealed, a.encryptedIdentitySeed, a.identityPub)
                        r.state == "holding" && inner.now >= r.holdEndsAt!! -> RecoveryPollResponse("awaiting_operator", r.holdEndsAt)
                        else -> RecoveryPollResponse(r.state, r.holdEndsAt)
                    }
                    ok(WireJson.json.encodeToString(RecoveryPollResponse.serializer(), resp))
                }
                else -> inner.call(route, pathParams, query, bodyJson, authenticated, decode)
            }
        }

        /** The operator's answer: the account's key [uvk] for the request, signed by [signer]. */
        fun fulfil(requestId: String, uvk: ByteArray, signer: KeyPairBytes) {
            val r = reqs.getValue(requestId)
            val email = inner.accounts.entries.first { it.value.userId == r.userId }.key
            val frame = AssistedRecoveryTrust.sign(crypto, signer, AssistedRecoveryFields(inner.instanceId, r.userId, requestId, r.rPub, uvk, inner.now,
                email = email, commit = crypto.randomBytes(32)))
            r.sealed = Bytes.toB64(AssistedRecoveryTrust.seal(crypto, Bytes.fromB64(r.rPub), frame))
        }
    }

    /**
     * The operator's answer for U under another key (a seed sealed under another account key, and that seed's identity
     * served beside it), on a phone that knows U: nothing is offered, nothing committed; walked on (its way back is Start
     * over). Where only the phone's record of the address names U (its record of U's key gone), the request's screen says
     * the identity fault's own line in place of its stage; where the phone keeps U's key on record, the stage it draws is
     * printed for the report.
     */
    @Test
    fun anOperatorsAnswerForTheKnownAccountUnderAnotherKeyOffersNothingAnywhere() = walk { for (keyRecord in listOf(true, false)) {
        val inner = FakeInstance(crypto, kind = InstanceKind.PRIVATE, recoveryFp = recoveryFp)
        val server = Assist(inner, crypto)
        val now = { inner.now }
        model(app(server, now)).register(bob)
        val phone = Phone()
        val d = app(server, now, phone)
        val m = model(d)
        m.register(alice)
        val u = inner.account(alice).userId
        assertEquals(PlainResult.DONE, m.done { signOut() })
        if (!keyRecord) phone.state.set("ovh.identity|$u", null)
        val bound = phone.bindingOf(inner.origin)
        // U under another key, consistent in itself.
        val deliver = crypto.randomBytes(32)
        val seed = crypto.randomBytes(32)
        val real = inner.accounts.getValue(alice)
        inner.accounts[alice] = FakeInstance.Account(real.userId, real.authKey, real.kdfSalt, real.kdfParams, real.wrappedUvk,
            Envelope.sealB64(crypto, deliver, seed, Ad.idkey(real.userId)), Bytes.toB64(crypto.boxKeypairFromSeed(seed).publicKey),
            real.genesis, real.personalWrap, real.memberRecovery, real.pieceId, recoveryConfirmed = true)
        seed.fill(0)

        m.step { entry.openSignIn(at()) }
        m.step { entry.openForgot(at()) }
        m.step { entry.openAskOperator(at()) }
        assertEquals(ServerResult.DONE, m.done { entry.chooseOwnServer(at(), inner.origin) })
        (d.snapshot.entry as? EntryScreen.TrustGate)?.let { gate -> assertEquals(ServerResult.DONE, m.done { entry.confirmTrustGate(gate) }) }
        assertEquals(AskOperatorResult.DONE, m.done { entry.requestOperatorHelp(at(), alice) })
        assertEquals(CodeResult.DONE, m.done { entry.verifyOperatorHelp(at(), server.code) })
        inner.now += 7 * 86_400_000L
        server.fulfil(server.reqs.keys.single(), deliver, recoverySigner)
        deliver.fill(0)
        assertEquals(ServerResult.DONE, m.done { entry.refreshOperatorHelp(at()) })
        val help = d.at<EntryScreen.OperatorHelp>()
        if (keyRecord) {
            // The phone's record of U's key refuses the answer before the keeper is asked; what the request's screen draws
            // then is said in the report (it is the shared code's choice of stage), and nothing is offered.
            println("OPERATOR ANSWER, U UNDER ANOTHER KEY, KEY ON RECORD: stage=${help.stage} stop=${operatorHelpStop(help)?.line} line=${operatorHelpStageLine(help.stage).shown()}")
        } else {
            val stop = assertNotNull(operatorHelpStop(help), "said in place of the stage")
            assertEquals(CopyKey.IDENTITY_FAULT_ADDRESS_KNOWN, stop.line, "the identity fault's own line")
            // Try again asks once more: the same.
            assertEquals(ServerResult.DONE, m.done { entry.refreshOperatorHelp(at()) })
            assertEquals(CopyKey.IDENTITY_FAULT_ADDRESS_KNOWN, operatorHelpStop(d.at())?.line)
        }
        assertNull(d.snapshot.earlierAccount, "no offer")
        assertNull(m.said(), "nothing else said under it")
        assertFalse(WireRoute.RECOVERY_REQUEST_COMMIT in inner.calls, "nothing committed")
        assertEquals(bound, phone.bindingOf(inner.origin))
        walkOnWithNoOffer(m, d, inner.origin, server, now, phone) { step { entry.abandonOperatorHelp(at()) } }
        assertEquals(bound, phone.bindingOf(inner.origin), "nothing forgotten")
    } }

    // ---- (d) a device link's pickup; (f) a link the phone cannot tell ----

    /**
     * A device link from [host] (open on the account) to the phone [d]: scanned, its code typed on the host and approved
     * with the master password. Ends where the phone asks for the password, or where the link ended before it.
     */
    private fun link(hostSide: Other, d: EngineAppApi, m: TrustModel) {
        val host = hostSide.api
        val hostModel = hostSide.m
        if (host.snapshot.account?.deviceLink != null) hostModel.step { devices.dismissDeviceLink() }
        assertEquals(PlainResult.DONE, hostModel.done { devices.startDeviceLink() })
        val shown = assertIs<DeviceLinkHost.Shown>(host.snapshot.account?.deviceLink)
        val url = assertNotNull(host.devices.deviceLinkToShow(shown))
        m.step { entry.openSignIn(at()) }
        m.step { entry.openLinkDevice(at()) }
        assertEquals(DeviceLinkScanResult.DONE, m.done { entry.submitDeviceLink(at(), url, PayloadSource.SCANNED) })
        (d.snapshot.entry as? EntryScreen.TrustGate)?.let { gate -> assertEquals(ServerResult.DONE, m.done { entry.confirmTrustGate(gate) }) }
        waitFor(d, "the code on the phone and the digits asked on the host") {
            d.snapshot.entry is EntryScreen.LinkDeviceCode && host.snapshot.account?.deviceLink is DeviceLinkHost.TypeDigits
        }
        val code = d.at<EntryScreen.LinkDeviceCode>().code
        hostModel.done { devices.submitDeviceDigits(assertIs(host.snapshot.account?.deviceLink), code) }
        val approvable = assertIs<DeviceLinkHost.Approvable>(host.snapshot.account?.deviceLink)
        assertEquals(ProofResult.DONE, hostModel.done { devices.approveWithPassword(approvable, strong) })
        waitFor(d, "the phone's next step") { d.snapshot.entry is EntryScreen.LinkDevicePassword || d.snapshot.entry is EntryScreen.LinkDeviceEnded }
        m.onSnapshot(d.snapshot)
    }

    /** The link's end as the phone draws it: its sentence (the shared code's, where it hands one). */
    private fun TrustModel.endedLine(ended: EntryScreen.LinkDeviceEnded): String = OutcomeWords.linkDeviceEnd(ended.outcome, api.retryAfterSeconds()).shown()

    /**
     * (d) The phone knows U (registered here, signed out); a device open on U under another key links the phone. The
     * approval passes (the link names U, the account the phone ties the address to); at the pickup the served key is not
     * the one the phone knows: the link ends with the identity fault's own line, no offer, nothing taken; walked on.
     */
    @Test
    fun aDeviceLinksPickupOfTheKnownAccountUnderAnotherKeyEndsOnTheIdentityFaultsLineWithNoOfferAnywhere() = walk {
        val server = FakeInstance(crypto)
        val links = DeviceLinkServer(server)
        val via = links.client(null)
        val now = { server.now }
        model(app(server)).register(bob)
        val phone = Phone()
        val d = app(via, now, phone)
        val m = model(d)
        m.register(alice)
        val u = server.account(alice).userId
        assertEquals(PlainResult.DONE, m.done { signOut() })
        val host = sameIdOtherKey(server, u, links.client(u))
        val bound = phone.bindingOf(server.origin)

        link(host, d, m)
        d.at<EntryScreen.LinkDevicePassword>()
        assertNull(d.snapshot.earlierAccount, "the password step: no offer")
        assertEquals(LinkPasswordResult.IDENTITY_FAULT, m.done { entry.submitLinkPassword(at(), strong) })
        val ended = d.at<EntryScreen.LinkDeviceEnded>()
        assertEquals(LinkDeviceEnd.IDENTITY_FAULT, ended.outcome)
        assertEquals(identityFaultLine, m.endedLine(ended), "the identity fault's own line")
        assertNull(d.snapshot.earlierAccount, "no offer")
        assertTrue(d.snapshot.phase != AppPhase.UNLOCKED, "nothing taken")
        assertTrue(links.calls.any { it.second == WireRoute.DEVICE_LINK_PICKUP }, "it was the pickup that refused")
        assertEquals(bound, phone.bindingOf(server.origin))
        walkOnWithNoOffer(m, d, server.origin, via, now, phone) { step { entry.startOver() } }
        assertEquals(bound, phone.bindingOf(server.origin), "nothing forgotten")
    }

    /**
     * (f) The phone forgot U through its own offer and took V under the address; then a device open on U under another
     * key links it. At the approval the link names U and carries no key, the phone keeps U's key on record: it cannot
     * tell an account made again from a substitution. The link ends with the shared code's line for that, as handed, and
     * no offer; walked on. And the same two at the ask just before the pickup (the address's record and U's kept key
     * written while the password was asked: set by hand, as a second start of the app would write them): the identity
     * fault's own line, no offer.
     */
    @Test
    fun aDeviceLinkThePhoneCannotTellIsSaidInTheSharedCodesLineWithNoOfferAnywhereAndTheAskBeforeThePickupAsTheIdentityFault() = walk {
        val server = FakeInstance(crypto)
        val links = DeviceLinkServer(server)
        val via = links.client(null)
        val now = { server.now }
        model(app(server)).register(bob)
        val phone = Phone()
        val d = app(via, now, phone)
        val m = model(d)
        m.register(alice)
        val u = server.account(alice).userId
        assertEquals(PlainResult.DONE, m.done { signOut() })
        // Deleted and made again elsewhere (V); the phone forgets U through its offer and its second step, and takes V.
        server.accounts.remove(alice)
        model(app(server)).register(alice)
        m.toSignIn(server.origin)
        assertEquals(SignInAnswer.IDENTITY_FAULT, m.done { entry.submitSignIn(at(), alice, strong) })
        m.askToForgetEarlierAccount()
        m.forgetEarlierAccount()
        m.onSnapshot(d.snapshot)
        assertEquals(ForgetEarlierResult.FORGOTTEN, m.saidOn(d.snapshot)?.result)
        assertEquals(SignInAnswer.DONE, m.done { entry.submitSignIn(at(), alice, strong) })
        m.dismissNewAccountRemembered(assertNotNull(d.snapshot.rememberedNewAccount))
        assertEquals(PlainResult.DONE, m.done { signOut() })
        val tiedToV = assertNotNull(phone.bindingOf(server.origin))
        assertFalse(tiedToV.startsWith("$u|"))
        val keptU = SessionKeeper.EARLIER_IDENTITY_PREFIX + server.origin + "|" + u
        assertNotNull(phone.state.get(keptU), "U's key kept on record")

        // U back under another key, on a device open on it, which links the phone.
        val host = sameIdOtherKey(server, u, links.client(u))
        link(host, d, m)
        val ended = d.at<EntryScreen.LinkDeviceEnded>()
        assertEquals(LinkDeviceEnd.IDENTITY_FAULT_CANNOT_TELL, ended.outcome, "stopped at the approval")
        assertEquals(UiText.of(CopyKey.DEVICE_LINK_IDENTITY_CANNOT_TELL).shown(), m.endedLine(ended), "the shared code's line, as handed")
        assertNull(d.snapshot.earlierAccount, "no offer")
        assertFalse(links.calls.any { it.second == WireRoute.DEVICE_LINK_PICKUP }, "nothing picked up")
        assertEquals(tiedToV, phone.bindingOf(server.origin))
        // The line points to the sign-in with the master password: the ended screen offers it, beside another link.
        assertTrue(linkEndOffersPasswordSignIn(ended.outcome), "the password sign-in is offered where the line points to it")
        val endedScreen = java.io.File("src/main/kotlin/io/silencelen/andvari/app/trust/LinkAndRecoveryScreens.kt").readText()
            .substringAfter("internal fun LinkDeviceEndedScreen(").substringBefore("\n}\n")
        assertTrue(endedScreen.contains("Main(UiText.of(CopyKey.SIGN_IN_LINK_DEVICE)"), "another link stays offered")
        assertTrue(endedScreen.contains("if (linkEndOffersPasswordSignIn(screen.outcome)) {\n            Second(UiText.of(CopyKey.SIGN_IN_PASSWORD), enabled = !s.busy) { model.openPasswordSignInAfterLink(screen) }"))
        WalkPrint.draws("the link's cannot-tell end", listOf(OutcomeWords.linkDeviceEnd(ended.outcome, 0), UiText.of(CopyKey.SIGN_IN_LINK_DEVICE), UiText.of(CopyKey.SIGN_IN_PASSWORD)))
        m.openPasswordSignInAfterLink(ended)
        m.onSnapshot(d.snapshot)
        d.at<EntryScreen.SignInServer>()
        assertNull(d.snapshot.earlierAccount, "the password sign-in: no offer")
        assertNull(m.said())
        // At that server, the password sign-in, which can tell.
        assertEquals(ServerResult.DONE, m.done { entry.chooseOwnServer(at(), server.origin) })
        (d.snapshot.entry as? EntryScreen.TrustGate)?.let { gate -> assertEquals(ServerResult.DONE, m.done { entry.confirmTrustGate(gate) }) }
        d.at<EntryScreen.SignIn>()
        val signedIn = m.done { entry.submitSignIn(at(), alice, strong) }
        WalkPrint.note("the password sign-in after the link's cannot-tell end", "$signedIn ${m.said()?.second}")
        assertTrue(signedIn != SignInAnswer.DONE, "the account served under another key is not taken: $signedIn")
        assertNull(d.snapshot.earlierAccount, "the same account under another key: no offer")
        assertEquals(tiedToV, phone.bindingOf(server.origin))
        walkOnWithNoOffer(m, d, server.origin, via, now, phone) { step { entry.startOver() } }
        assertEquals(tiedToV, phone.bindingOf(server.origin), "nothing forgotten")

        // The ask just before the pickup: a phone that knew nothing of the address when the link was approved.
        val fresh = Phone()
        val d2 = app(via, now, fresh)
        val m2 = model(d2)
        link(host, d2, m2)
        d2.at<EntryScreen.LinkDevicePassword>()
        assertNull(d2.snapshot.earlierAccount, "the password step: no offer")
        fresh.state.set(SessionKeeper.EMAIL_BINDING_PREFIX + server.origin + "|" + alice, tiedToV)
        fresh.state.set(keptU, assertNotNull(phone.state.get(keptU)))
        assertEquals(LinkPasswordResult.IDENTITY_FAULT, m2.done { entry.submitLinkPassword(at(), strong) })
        val ended2 = d2.at<EntryScreen.LinkDeviceEnded>()
        assertEquals(LinkDeviceEnd.IDENTITY_FAULT, ended2.outcome)
        assertEquals(identityFaultLine, m2.endedLine(ended2), "the identity fault's own line")
        assertNull(d2.snapshot.earlierAccount, "no offer")
        assertTrue(d2.snapshot.phase != AppPhase.UNLOCKED, "nothing taken")
    }

    // ---- (e) the sequence the fix's checks named ----

    private fun deletable(server: FakeInstance) {
        server.override[WireRoute.ACCOUNT_DELETE_PREVIEW] = WireResult.Ok(
            """{"blockers":[],"deletedVaults":[],"leftVaults":[],"memberships":[],"totpRequired":false}""", 200)
        server.override[WireRoute.ACCOUNT_DELETE] = WireResult.Ok("""{"deletedAt":1}""", 200)
    }

    private fun TrustModel.deleteAccount(): DeletionResult {
        assertEquals(PlainResult.DONE, done { settings.openDeletion() })
        val screen = assertNotNull(assertNotNull(api.snapshot.account).deletion)
        var result: DeletionResult? = null
        runBlocking { runIn(DELETION_SECTION, { settings.deleteAccount(screen, alice, strong, null) }, { deletionWords(it, 0) }) { result = it; deletionAnswered(it) }.join() }
        onSnapshot(api.snapshot)
        return assertNotNull(result)
    }

    /**
     * U forgotten through the phone's own offer and its second step; V, the account made again, taken; V deleted with the
     * server's confirmation: the notice says the server was kept (the phone keeps U's key on record there); then U served
     * under another key: refused with the identity fault's own line, no offer; walked on.
     */
    @Test
    fun theEarlierAccountForgottenTheNextTakenAndDeletedThenTheEarlierUnderAnotherKeyIsRefusedWithNoOfferAnywhere() = walk {
        val server = FakeInstance(crypto)
        model(app(server)).register(bob)
        val phone = Phone()
        val d = app(server, phone)
        val m = model(d)
        m.register(alice)
        val u = server.account(alice).userId
        assertEquals(PlainResult.DONE, m.done { signOut() })
        server.accounts.remove(alice)
        model(app(server)).register(alice)

        // The refusal, the offer, its second step, forgotten.
        m.toSignIn(server.origin)
        assertEquals(SignInAnswer.IDENTITY_FAULT, m.done { entry.submitSignIn(at(), alice, strong) })
        val offer = assertNotNull(d.snapshot.earlierAccount, "another account: offered")
        assertFalse(offer.confirming)
        m.askToForgetEarlierAccount()
        val confirm = assertNotNull(d.snapshot.earlierAccount)
        assertTrue(confirm.confirming)
        m.forgetEarlierAccount()
        m.onSnapshot(d.snapshot)
        assertEquals(ForgetEarlierResult.FORGOTTEN, m.saidOn(d.snapshot)?.result)
        assertNull(d.snapshot.earlierAccount)

        // V taken, said once.
        assertEquals(SignInAnswer.DONE, m.done { entry.submitSignIn(at(), alice, strong) })
        val remembered = assertNotNull(d.snapshot.rememberedNewAccount)
        m.dismissNewAccountRemembered(remembered)

        // V deleted, the server confirming: the server is kept, and the notice says so.
        deletable(server)
        assertEquals(DeletionResult.DONE, m.deleteAccount())
        val first = d.at<EntryScreen.FirstRun>()
        val notice = assertNotNull(first.accountDeleted)
        assertFalse(notice.serverForgotten, "the server was kept")
        assertEquals(CopyKey.ACCOUNT_DELETED_SERVER_KEPT, notice.line.key)
        assertEquals(UiText.of(notice.line).shown(), assertNotNull(accountDeletedLine(first)).shown(), "the line as it comes")
        assertNull(d.snapshot.earlierAccount)
        val keptU = SessionKeeper.EARLIER_IDENTITY_PREFIX + server.origin + "|" + u
        assertNotNull(phone.state.get(keptU), "U's key stays on record")
        m.step { entry.dismissNotice(first) }

        // U served under another key: refused, no offer.
        sameIdOtherKey(server, u)
        m.toSignIn(server.origin)
        assertEquals(SignInAnswer.IDENTITY_FAULT, m.done { entry.submitSignIn(at(), alice, strong) })
        assertEquals(SignInAnswer.IDENTITY_FAULT to identityFaultLine, m.said(), "the identity fault's own line")
        assertNull(d.snapshot.earlierAccount, "no offer")
        assertTrue(d.snapshot.phase != AppPhase.UNLOCKED, "U under another key is not taken")
        walkOnWithNoOffer(m, d, server.origin, server, { server.now }, phone) { step { entry.startOver() } }
        assertNotNull(phone.state.get(keptU), "U's key still on record")
    }
}
