package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.client.items.copyOut
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.AskOperatorResult
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.FirstRunNotice
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.OperatorHelpStage
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.RecoveryRoute
import io.silencelen.andvari.core.app.ReplacePasswordResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KeyPairBytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.RecoveryPollRequest
import io.silencelen.andvari.core.model.wire.RecoveryPollResponse
import io.silencelen.andvari.core.model.wire.RecoveryRequestCommit
import io.silencelen.andvari.core.model.wire.RecoveryRequestCreate
import io.silencelen.andvari.core.model.wire.RecoveryRequestCreated
import io.silencelen.andvari.core.model.wire.RecoveryRequestVerified
import io.silencelen.andvari.core.model.wire.RecoveryRequestVerify
import io.silencelen.andvari.core.model.wire.SessionResponse
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.AssistedRecoveryFields
import io.silencelen.andvari.core.trust.InstanceKind
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import io.silencelen.andvari.core.trust.AssistedRecovery as AssistedRecoveryTrust

/** Assisted recovery on the engine (design §9.3): the journey from "Ask the operator" to a new password and kit. */
class EngineAssistedRecoveryTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val newPw = "a whole new Passphrase 42 here"
    private val recoverySigner: KeyPairBytes = crypto.signKeypairFromSeed(ByteArray(32) { 2 })
    private val recoveryFp = Escrow.fingerprint(crypto, crypto.boxKeypairFromSeed(ByteArray(32) { 2 }).publicKey)

    /** The §18 routes as an honest server answers them, over [inner]; the test plays the operator through [fulfil]. */
    private class Assist(val inner: FakeInstance, val crypto: io.silencelen.andvari.core.crypto.CryptoProvider) : WireClient {
        override val origin: String get() = inner.origin
        class Req(val rPub: String, val pollHash: String, val userId: String) {
            var state = "unverified"
            var holdEndsAt: Long? = null
            var sealed: String? = null
        }
        val reqs = LinkedHashMap<String, Req>()

        /** Every request's body, as the server received it. */
        val created = ArrayList<RecoveryRequestCreate>()
        val code = "314159"
        private var n = 0

        /** When set, the commit waits on it (then is taken as an honest server takes it); [commitReached] says it arrived. */
        var holdCommit: kotlinx.coroutines.CompletableDeferred<Unit>? = null
        val commitReached = kotlinx.coroutines.CompletableDeferred<Unit>()

        /** The commit is answered `403 commit_mismatch`: the answer stored is not the one the device opened. */
        var commitMismatch = false

        /**
         * The commit is taken as usual, but its answer carries an identity seed sealed under another key: the account cannot
         * be opened from it on the device (a fault while opening, after the commit).
         */
        var seedSwap = false

        /** Every route of a request answers `404 request_unknown`: the server lost the row, or lies. */
        var forgotten = false
        var cancelled = false

        private fun refuse(status: Int, code: String): WireResult<Nothing> = WireResult.Refused(status, WireError(code, code))

        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            fun ok(text: String): WireResult<T> = WireResult.Ok(decode(text), 200)
            val id = pathParams["requestId"]
            fun byPoll(secret: String) = reqs[id]?.takeIf { Bytes.toHexLower(crypto.sha256(Bytes.fromB64(secret))) == it.pollHash }
            if (forgotten && route in setOf(WireRoute.RECOVERY_REQUEST_VERIFY, WireRoute.RECOVERY_REQUEST_POLL, WireRoute.RECOVERY_REQUEST_COMMIT)) {
                return refuse(404, "request_unknown")
            }
            // The account's owner changed the password or the recovery setting after the request: the server cancelled it.
            if (cancelled && route == WireRoute.RECOVERY_REQUEST_VERIFY) return refuse(409, "request_state")
            return when (route) {
                WireRoute.RECOVERY_REQUEST_CREATE -> {
                    val b = WireJson.json.decodeFromString(RecoveryRequestCreate.serializer(), bodyJson!!)
                    created += b
                    n++
                    val requestId = Bytes.toB64(ByteArray(16) { (it + n).toByte() })
                    inner.accounts[io.silencelen.andvari.core.trust.TrustGrammar.emailNorm(b.email)]?.let { reqs[requestId] = Req(b.rPub, b.pollHash, it.userId) }
                    WireResult.Ok(decode(WireJson.json.encodeToString(RecoveryRequestCreated.serializer(), RecoveryRequestCreated(requestId))), 202)
                }
                WireRoute.RECOVERY_REQUEST_VERIFY -> {
                    val b = WireJson.json.decodeFromString(RecoveryRequestVerify.serializer(), bodyJson!!)
                    val r = reqs[id]?.takeIf { it.state == "unverified" && b.code == code } ?: return refuse(400, "bad_code")
                    r.state = "holding"; r.holdEndsAt = inner.now + 7 * 86_400_000L
                    ok(WireJson.json.encodeToString(RecoveryRequestVerified.serializer(), RecoveryRequestVerified("holding", r.holdEndsAt!!)))
                }
                WireRoute.RECOVERY_REQUEST_POLL -> {
                    val b = WireJson.json.decodeFromString(RecoveryPollRequest.serializer(), bodyJson!!)
                    val r = byPoll(b.pollSecret) ?: return refuse(404, "request_unknown")
                    val a = inner.accounts.values.first { it.userId == r.userId }
                    val resp = when {
                        r.state == "vetoed" -> RecoveryPollResponse("vetoed")
                        r.sealed != null -> RecoveryPollResponse("ready", null, r.sealed, a.encryptedIdentitySeed, a.identityPub)
                        r.state == "holding" && inner.now >= r.holdEndsAt!! -> RecoveryPollResponse("awaiting_operator", r.holdEndsAt)
                        else -> RecoveryPollResponse(r.state, r.holdEndsAt)
                    }
                    ok(WireJson.json.encodeToString(RecoveryPollResponse.serializer(), resp))
                }
                WireRoute.RECOVERY_REQUEST_COMMIT -> {
                    holdCommit?.let {
                        commitReached.complete(Unit)
                        it.await()
                    }
                    val b = WireJson.json.decodeFromString(RecoveryRequestCommit.serializer(), bodyJson!!)
                    val r = byPoll(b.pollSecret) ?: return refuse(404, "request_unknown")
                    if (r.sealed == null || r.state == "vetoed") return refuse(409, "request_state")
                    if (commitMismatch) return refuse(403, "commit_mismatch")
                    val a = inner.accounts.values.first { it.userId == r.userId }
                    a.authKey = b.newAuthKey; a.kdfSalt = b.newKdfSalt; a.kdfParams = b.newKdfParams; a.wrappedUvk = b.newWrappedUvk
                    a.memberRecovery = b.newMemberRecovery ?: return refuse(400, "recovery_required")
                    a.pieceId = Bytes.toB64(ByteArray(32) { (90 + n).toByte() }); a.recoveryConfirmed = false; a.requireLink = false; a.totp = null
                    a.devices.clear()
                    val deviceId = "00000000-0000-4000-8000-0000000008${n.toString().padStart(2, '0')}"
                    a.devices[deviceId] = b.device.deviceSecret
                    reqs.remove(id)
                    val keys = inner.keys(a).let { k ->
                        if (!seedSwap) return@let k
                        val otherKey = crypto.randomBytes(32)
                        val otherSeed = crypto.randomBytes(32)
                        val sealed = io.silencelen.andvari.core.crypto.Envelope.sealB64(crypto, otherKey, otherSeed, io.silencelen.andvari.core.crypto.Ad.idkey(a.userId))
                        otherKey.fill(0)
                        otherSeed.fill(0)
                        k.copy(encryptedIdentitySeed = sealed)
                    }
                    ok(WireJson.json.encodeToString(SessionResponse.serializer(),
                        SessionResponse(a.userId, deviceId, "at-$deviceId", "rt-$deviceId", keys, "member", false, false, a.pieceId)))
                }
                else -> inner.call(route, pathParams, query, bodyJson, authenticated, decode)
            }
        }

        /** The operator's `recovery-cli assist` and `fulfil`: a 0x09 payload for the request's account, signed by [signer]. */
        fun fulfil(requestId: String, uvk: ByteArray, signer: KeyPairBytes) {
            val r = reqs.getValue(requestId)
            // The version-3 answer (spec 04 §7 step 3): the account's address, as its copy names it, and a commit value.
            val email = inner.accounts.entries.first { it.value.userId == r.userId }.key
            val frame = AssistedRecoveryTrust.sign(crypto, signer, AssistedRecoveryFields(inner.instanceId, r.userId, requestId, r.rPub, uvk, inner.now,
                email = email, commit = crypto.randomBytes(32)))
            r.sealed = Bytes.toB64(AssistedRecoveryTrust.seal(crypto, Bytes.fromB64(r.rPub), frame))
        }
    }

    private fun app(server: Assist, state: DeviceState, secure: DeviceState, requests: DeviceState? = null): EngineAppApi = EngineAppApi(
        AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.origin to server)), state, secure, crypto,
            { server.inner.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
            requestStore = requests),
    ).also {
        it.linksFlow.answersPollMs = Long.MAX_VALUE
        it.start()
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    /** Alice's account on another device: registered with her kit confirmed. Answers the account's key, for the operator. */
    private suspend fun alice(server: Assist, a: EngineAppApi = app(server, MemoryDeviceState(), MemoryDeviceState())): ByteArray {
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), server.origin))
        assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(a.at()))
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), "alice@example.com", true))
        assertEquals(io.silencelen.andvari.core.app.CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "Alice", strong, true)))
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        return a.keeper.established!!.account.uvk.copyOut()
    }

    /** A fresh install: "I lost my master password and my recovery kit", the server behind its gate, the request and its code. */
    private suspend fun askAndVerify(b: EngineAppApi, server: Assist): EntryScreen.OperatorHelp {
        b.entry.openSignIn(b.at())
        b.entry.openForgot(b.at())
        b.entry.openAskOperator(b.at())
        assertEquals(ServerResult.DONE, b.entry.chooseOwnServer(b.at(), server.origin))
        assertEquals(ServerResult.DONE, b.entry.confirmTrustGate(b.at<EntryScreen.TrustGate>()))
        val ask = b.at<EntryScreen.AskOperator>()
        assertEquals(server.origin, ask.instance.origin)
        assertTrue(server.reqs.isEmpty(), "nothing sent before the address is given")
        assertEquals(AskOperatorResult.INVALID_EMAIL, b.entry.requestOperatorHelp(ask, "not an address"))
        assertEquals(AskOperatorResult.DONE, b.entry.requestOperatorHelp(ask, "alice@example.com"))
        val requested = b.at<EntryScreen.OperatorHelp>()
        assertEquals(OperatorHelpStage.CODE_NEEDED, requested.stage)
        assertEquals("alice@example.com", requested.email)
        // The request code comes from this device's own request key, as the operator's CLI checks it.
        assertEquals(6, requested.requestCode.size)
        assertTrue(AssistedRecoveryTrust.requestCodeMatches(crypto, requested.requestCode.joinToString(" "), Bytes.fromB64(server.reqs.values.single().rPub)))
        assertEquals(CodeResult.WRONG_CODE, b.entry.verifyOperatorHelp(requested, "000000"))
        assertEquals(CodeResult.DONE, b.entry.verifyOperatorHelp(b.at(), server.code))
        val holding = b.at<EntryScreen.OperatorHelp>()
        assertEquals(OperatorHelpStage.HOLDING, holding.stage)
        assertEquals(server.inner.now + 7 * 86_400_000L, holding.holdEndsAtMs)
        assertEquals(requested.requestCode, holding.requestCode)
        return holding
    }

    /** "It is the same", in its two steps: the comparison's sentence is on screen before it goes on. */
    private fun EngineAppApi.accept(check: EntryScreen.CheckAccount) {
        assertFalse(check.confirming)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.RECOVERY_CHECK_ACCOUNT_KIT, check.compareLine)
        entry.acceptRecoveredAccount(check)
        val second = at<EntryScreen.CheckAccount>()
        assertTrue(second.confirming, "one tap does not pass the comparison")
        assertEquals(io.silencelen.andvari.core.app.CopyKey.RECOVERY_CHECK_ACCOUNT_CONFIRM, second.confirmLine)
        assertEquals(check.accountId, second.accountId)
        entry.acceptRecoveredAccount(second)
    }

    /**
     * One tap on "it is the same" does not reach the new password; the screen names the kit
     * first. Before, one tap went on, under the sentence that sent the person to the server's own emails.
     */
    @Test fun oneTapDoesNotPassTheAccountIdCheck() = runBlocking<Unit> {
        val server = Assist(FakeInstance(crypto, kind = InstanceKind.PRIVATE, recoveryFp = recoveryFp), crypto)
        val uvk = alice(server)
        val b = app(server, MemoryDeviceState(), MemoryDeviceState(), MemoryDeviceState())
        val holding = askAndVerify(b, server)
        server.inner.now += 7 * 86_400_000L
        server.fulfil(server.reqs.keys.single(), uvk, recoverySigner)
        assertEquals(ServerResult.DONE, b.entry.refreshOperatorHelp(holding))
        val check = b.at<EntryScreen.CheckAccount>()
        assertEquals(io.silencelen.andvari.core.app.CopyKey.RECOVERY_CHECK_ACCOUNT_KIT, check.compareLine)
        b.entry.acceptRecoveredAccount(check)
        assertIs<EntryScreen.CheckAccount>(b.snapshot.entry, "still the check, on its second step")
        b.entry.acceptRecoveredAccount(b.at())
        assertIs<EntryScreen.ReplacePassword>(b.snapshot.entry)
    }

    /**
     * The commit is answered `403 commit_mismatch` (the operator uploaded another answer). The
     * result is its own, never "too late: start again"; the request is kept and the journey is on its screen, which says
     * the operator must upload it again. Before, it answered TOO_LATE and went to the first screen.
     */
    @Test fun aCommitMismatchKeepsTheRequestAndSaysTheOperatorMustUploadAgain() = runBlocking<Unit> {
        val server = Assist(FakeInstance(crypto, kind = InstanceKind.PRIVATE, recoveryFp = recoveryFp), crypto)
        val uvk = alice(server)
        val b = app(server, MemoryDeviceState(), MemoryDeviceState(), MemoryDeviceState())
        val holding = askAndVerify(b, server)
        server.inner.now += 7 * 86_400_000L
        server.fulfil(server.reqs.keys.single(), uvk, recoverySigner)
        assertEquals(ServerResult.DONE, b.entry.refreshOperatorHelp(holding))
        b.accept(b.at<EntryScreen.CheckAccount>())
        server.commitMismatch = true
        val r = b.entry.chooseReplacementPassword(b.at(), newPw)
        assertEquals(ReplacePasswordResult.ANSWER_REPLACED, r)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.ASSIST_ANSWER_REPLACED, r.sentence)
        val help = b.at<EntryScreen.OperatorHelp>()
        assertEquals(io.silencelen.andvari.core.app.CopyKey.ASSIST_ANSWER_REPLACED, help.answerReplaced)
        assertTrue(b.assisted.keptOrigins().isNotEmpty(), "the request is kept")
        // The operator uploads again: the request's next look picks it up.
        server.commitMismatch = false
        server.fulfil(server.reqs.keys.single(), uvk, recoverySigner)
        assertEquals(ServerResult.DONE, b.entry.refreshOperatorHelp(help))
        assertIs<EntryScreen.CheckAccount>(b.snapshot.entry)
    }

    @Test fun aRequestKeptAcrossARestartIsPickedUpCheckedAndCommittedWithANewKit() = runBlocking<Unit> {
        val server = Assist(FakeInstance(crypto, kind = InstanceKind.PRIVATE, recoveryFp = recoveryFp), crypto)
        val uvk = alice(server)
        val state = MemoryDeviceState()
        val secure = MemoryDeviceState()
        val requests = MemoryDeviceState()
        val b = app(server, state, secure, requests)
        assertFalse(b.at<EntryScreen.FirstRun>().operatorHelpWaiting)
        askAndVerify(b, server)
        assertTrue(secure.keys().none { it.startsWith("ovh.assist") }, "kept in the request store, not the session's")

        // A restart (the session store emptied, as without "keep me signed in"): the request is still kept.
        val c = app(server, state, MemoryDeviceState(), requests)
        val first = c.at<EntryScreen.FirstRun>()
        assertTrue(first.operatorHelpWaiting)
        server.inner.now += 7 * 86_400_000L
        assertEquals(ServerResult.DONE, c.entry.resumeOperatorHelp(first))
        val awaiting = c.at<EntryScreen.OperatorHelp>()
        assertEquals(OperatorHelpStage.AWAITING_OPERATOR, awaiting.stage)
        assertEquals("alice@example.com", awaiting.email)

        server.fulfil(server.reqs.keys.single(), uvk, recoverySigner)
        assertEquals(ServerResult.DONE, c.entry.refreshOperatorHelp(awaiting))
        val check = c.at<EntryScreen.CheckAccount>()
        assertEquals(32, check.accountId.length)
        // "Not now" keeps it; the check comes back.
        c.entry.recoveredAccountNotNow(check)
        assertTrue(c.at<EntryScreen.FirstRun>().operatorHelpWaiting)
        assertEquals(ServerResult.DONE, c.entry.resumeOperatorHelp(c.at()))
        val again = c.at<EntryScreen.CheckAccount>()
        assertEquals(check.accountId, again.accountId)
        c.accept(again)
        val choose = c.at<EntryScreen.ReplacePassword>()
        assertEquals(RecoveryRoute.OPERATOR_HELP, choose.after)
        assertEquals(ReplacePasswordResult.WEAK_PASSWORD, c.entry.chooseReplacementPassword(choose, "weak"))
        assertEquals(ReplacePasswordResult.DONE, c.entry.chooseReplacementPassword(choose, newPw))
        assertIs<EntryScreen.Kit>(c.snapshot.entry, "the new kit before the vault opens")
        assertTrue(c.assisted.keptOrigins().isEmpty(), "the request's secrets are gone after the commit")
    }

    /**
     * An assisted recovery left
     * while its commit is on its way, and the server took it. The commit's new kit was never shown and the old kit is
     * dead; the server's `recoveryConfirmed` is cleared by the commit (spec 03 §12). The intent answers STALE with no
     * session kept, and the next sign-in with the new password goes to a new kit before the vault opens.
     */
    @Test fun anAssistedRecoveryLeftWhileItsCommitIsOnItsWayLeavesNoKitAndTheNextSignInMakesOne() = runBlocking<Unit> {
        val server = Assist(FakeInstance(crypto, kind = InstanceKind.PRIVATE, recoveryFp = recoveryFp), crypto)
        val uvk = alice(server)
        val b = app(server, MemoryDeviceState(), MemoryDeviceState(), MemoryDeviceState())
        val holding = askAndVerify(b, server)
        server.inner.now += 7 * 86_400_000L
        server.fulfil(server.reqs.keys.single(), uvk, recoverySigner)
        assertEquals(ServerResult.DONE, b.entry.refreshOperatorHelp(holding))
        b.accept(b.at<EntryScreen.CheckAccount>())
        val choose = b.at<EntryScreen.ReplacePassword>()
        server.holdCommit = kotlinx.coroutines.CompletableDeferred()
        var result: ReplacePasswordResult? = null
        val job = launch { result = b.entry.chooseReplacementPassword(choose, newPw) }
        server.commitReached.await()
        b.entry.back()
        server.holdCommit!!.complete(Unit)
        job.join()
        assertEquals(ReplacePasswordResult.STALE, result)
        val account = server.inner.account("alice@example.com")
        assertFalse(account.recoveryConfirmed, "the server took the commit: the account holds no confirmed kit")
        assertEquals(null, b.keeper.session, "nothing of the commit's session is kept")

        repeat(6) { if (b.snapshot.entry !is EntryScreen.FirstRun) b.entry.back() }
        // What the late answer came to is said once on the first screen, until dismissed.
        val late = assertNotNull(b.at<EntryScreen.FirstRun>().lateRecovery, "the late outcome is said")
        assertEquals(io.silencelen.andvari.core.app.LateRecoveryResult.RESET, late.result)
        assertEquals(RecoveryRoute.OPERATOR_HELP, late.via)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.LATE_RECOVERY_RESET, late.line.key)
        assertEquals("alice@example.com", late.line.values[0])
        assertEquals(null, b.assisted.takeLateOutcome(), "published once")
        b.entry.dismissNotice(b.at())
        assertEquals(null, b.at<EntryScreen.FirstRun>().lateRecovery)
        b.entry.openSignIn(b.at())
        b.entry.openPasswordSignIn(b.at())
        assertEquals(ServerResult.DONE, b.entry.chooseOwnServer(b.at(), server.origin))
        (b.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, b.entry.confirmTrustGate(it)) }
        assertEquals(io.silencelen.andvari.core.app.SignInAnswer.DONE, b.entry.submitSignIn(b.at(), "alice@example.com", newPw))
        val kit = b.at<EntryScreen.Kit>()
        assertEquals(io.silencelen.andvari.core.app.KitReason.NEVER_SAVED, kit.kit.reason, "the next sign-in goes to a new kit")
        assertEquals(AppPhase.ENTRY, b.snapshot.phase, "the vault stays shut until it is saved")
        val doc = assertNotNull(b.kit.kitDocument(kit.kit))
        b.kit.proceedToConfirm(kit.kit)
        val confirm = b.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, b.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        assertEquals(AppPhase.UNLOCKED, b.snapshot.phase)
    }

    /**
     * A commit the person left whose answer is a refusal: the first screen says the reset did not go through (the
     * password is unchanged), once. Before, nothing was said.
     */
    @Test fun anAssistedRecoveryLeftWhoseCommitIsRefusedSaysSoOnTheFirstScreen() = runBlocking<Unit> {
        val server = Assist(FakeInstance(crypto, kind = InstanceKind.PRIVATE, recoveryFp = recoveryFp), crypto)
        val uvk = alice(server)
        val b = app(server, MemoryDeviceState(), MemoryDeviceState(), MemoryDeviceState())
        val holding = askAndVerify(b, server)
        server.inner.now += 7 * 86_400_000L
        server.fulfil(server.reqs.keys.single(), uvk, recoverySigner)
        assertEquals(ServerResult.DONE, b.entry.refreshOperatorHelp(holding))
        b.accept(b.at<EntryScreen.CheckAccount>())
        val choose = b.at<EntryScreen.ReplacePassword>()
        server.holdCommit = kotlinx.coroutines.CompletableDeferred()
        server.commitMismatch = true
        var result: ReplacePasswordResult? = null
        val job = launch { result = b.entry.chooseReplacementPassword(choose, newPw) }
        server.commitReached.await()
        b.entry.startOver()
        server.holdCommit!!.complete(Unit)
        job.join()
        assertEquals(ReplacePasswordResult.STALE, result)
        val late = assertNotNull(b.at<EntryScreen.FirstRun>().lateRecovery)
        assertEquals(io.silencelen.andvari.core.app.LateRecoveryResult.REFUSED, late.result)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.LATE_RECOVERY_REFUSED, late.line.key)
    }

    // ---- the recovery key changed while a request was open (spec 04 §5) ----

    private val newSeed = ByteArray(32) { 5 }
    private val newSigner: KeyPairBytes = crypto.signKeypairFromSeed(newSeed)
    private val newFp = Escrow.fingerprint(crypto, crypto.boxKeypairFromSeed(newSeed).publicKey)

    /** The operator signs the next card, naming [newFp]; [rotation], when given, is served beside the chain. */
    private fun rotateTo(a: Assist, rotation: ByteArray?) {
        val i = a.inner
        val prev = i.cards.last()
        i.cards += io.silencelen.andvari.core.trust.InstanceCard.sign(crypto, i.operatorSign, io.silencelen.andvari.core.trust.CardFields(
            i.instanceId, i.cards.size.toLong(), io.silencelen.andvari.core.trust.SignedFrame.hash(crypto, prev), i.origin, "Home", i.kind,
            "99999999-9999-4999-8999-999999999999", Bytes.toB64(i.operatorSign.publicKey), newFp, i.now))
        rotation?.let { i.rotations += it }
    }

    private fun signedRotation(a: Assist, at: Long): ByteArray = io.silencelen.andvari.core.trust.RecoveryRotation.sign(crypto, recoverySigner,
        io.silencelen.andvari.core.trust.RotationFields(a.inner.instanceId, recoveryFp, newFp, at))

    /**
     * The card names another recovery key and no signed rotation covers it. The request's
     * screen shows the warning (its own state, not "did not check out" or "expired"), with "stop" and "keep waiting"; the
     * request is kept and nothing of the answer is opened. The rotation the old key signed, served later, lets it go on, and
     * the screens then say the key changed, and when, up to the account check. Before, the unsigned change answered
     * DID_NOT_CHECK_OUT and the signed one was never said.
     */
    @Test fun aRecoveryKeyChangeIsTheWarningWhenUnsignedAndALineWhenSigned() = runBlocking<Unit> {
        val server = Assist(FakeInstance(crypto, kind = InstanceKind.PRIVATE, recoveryFp = recoveryFp), crypto)
        val uvk = alice(server)
        val b = app(server, MemoryDeviceState(), MemoryDeviceState(), MemoryDeviceState())
        val holding = askAndVerify(b, server)
        assertEquals(null, holding.keyChange)
        val at = server.inner.now - 60_000
        // The "since" of a changed key is the time of the first card that named it.
        val cardAt = server.inner.now
        rotateTo(server, null)
        server.inner.now += 7 * 86_400_000L
        server.fulfil(server.reqs.keys.single(), uvk, newSigner)
        assertEquals(ServerResult.DONE, b.entry.refreshOperatorHelp(holding))
        val stopped = b.at<EntryScreen.OperatorHelp>()
        val warning = assertNotNull(stopped.keyChange, "the warning is the screen's own state")
        assertFalse(warning.byOldKey)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.RECOVERY_KEY_CHANGED_TITLE, warning.warningTitle?.key)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.ASSIST_RECOVERY_KEY_CHANGED_BODY, warning.warningBody)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.ASSIST_KEY_CHANGED_STOP, warning.stop)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.ASSIST_KEY_CHANGED_KEEP_WAITING, warning.keepWaiting)
        assertEquals(null, warning.line)
        assertTrue(stopped.stage != OperatorHelpStage.DID_NOT_CHECK_OUT && stopped.stage != OperatorHelpStage.EXPIRED, "never folded into an end")
        assertEquals(holding.requestCode, stopped.requestCode)
        assertFalse(b.assisted.holdsOpened(server.origin), "nothing of the answer was opened")
        assertTrue(b.assisted.keptOrigins().isNotEmpty(), "the request is kept")
        // "Keep waiting": nothing is sent; the next look stops again with the warning.
        assertEquals(ServerResult.DONE, b.entry.refreshOperatorHelp(stopped))
        assertFalse(assertNotNull(b.at<EntryScreen.OperatorHelp>().keyChange).byOldKey)

        // The rotation the old key signed is served: the request goes on, and the screens say the key changed and when.
        server.inner.rotations += signedRotation(server, at)
        assertEquals(ServerResult.DONE, b.entry.refreshOperatorHelp(b.at()))
        val check = b.at<EntryScreen.CheckAccount>()
        val change = assertNotNull(check.keyChange, "said on the account check")
        assertTrue(change.byOldKey)
        assertEquals(cardAt, change.rotatedAtMs)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.ASSIST_RECOVERY_KEY_ROTATED, change.line)
        assertEquals(null, change.warningTitle)
        b.entry.acceptRecoveredAccount(check)
        assertTrue(assertNotNull(b.at<EntryScreen.CheckAccount>().keyChange).byOldKey, "kept on the second step")
        // Back from the check: the request's screen says the signed change beside its stage.
        b.entry.back()
        val waiting = b.at<EntryScreen.OperatorHelp>()
        assertTrue(assertNotNull(waiting.keyChange).byOldKey, "the warning of the earlier look is gone")

        // "Stop this request" is the request's own cancel.
        b.entry.abandonOperatorHelp(waiting)
        assertTrue(b.assisted.keptOrigins().isEmpty())
    }

    /**
     * A request the server no longer knows (404 at the code, the poll or the commit) is said on its
     * own screen and KEPT until its lifetime ends, never shown as expired nor as "too late". When the server knows it
     * again, it goes on. Before, the poll's 404 showed EXPIRED and the commit's answered TOO_LATE and went to the first screen.
     */
    @Test fun aRequestTheServerNoLongerKnowsIsSaidAndKept() = runBlocking<Unit> {
        val server = Assist(FakeInstance(crypto, kind = InstanceKind.PRIVATE, recoveryFp = recoveryFp), crypto)
        val uvk = alice(server)
        val b = app(server, MemoryDeviceState(), MemoryDeviceState(), MemoryDeviceState())
        val holding = askAndVerify(b, server)
        server.forgotten = true
        assertEquals(ServerResult.DONE, b.entry.refreshOperatorHelp(holding))
        val unknown = b.at<EntryScreen.OperatorHelp>()
        assertEquals(io.silencelen.andvari.core.app.CopyKey.ASSIST_REQUEST_UNKNOWN, unknown.requestUnknown)
        assertEquals(OperatorHelpStage.HOLDING, unknown.stage, "the stage last known, never EXPIRED")
        assertEquals(holding.requestCode, unknown.requestCode)
        assertTrue(b.assisted.keptOrigins().isNotEmpty(), "kept")

        // Known again: it goes on to the answer.
        server.forgotten = false
        server.inner.now += 7 * 86_400_000L
        server.fulfil(server.reqs.keys.single(), uvk, recoverySigner)
        assertEquals(ServerResult.DONE, b.entry.refreshOperatorHelp(unknown))
        b.accept(b.at<EntryScreen.CheckAccount>())
        // Unknown at the commit: what was opened goes, the request is kept, and the journey is back on its screen.
        server.forgotten = true
        val r = b.entry.chooseReplacementPassword(b.at(), newPw)
        assertEquals(ReplacePasswordResult.REQUEST_UNKNOWN, r)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.ASSIST_REQUEST_UNKNOWN, r.sentence)
        val again = b.at<EntryScreen.OperatorHelp>()
        assertEquals(io.silencelen.andvari.core.app.CopyKey.ASSIST_REQUEST_UNKNOWN, again.requestUnknown)
        assertEquals(holding.requestCode, again.requestCode)
        assertFalse(b.assisted.holdsOpened(server.origin))
        assertTrue(b.assisted.keptOrigins().isNotEmpty())
        // Back from the request's screen goes to what was under it, not to the stale password screen.
        b.entry.back()
        assertFalse(b.snapshot.entry is EntryScreen.ReplacePassword || b.snapshot.entry is EntryScreen.CheckAccount)
    }

    /** At the code's step: the code's 404 is the same state, with a result of its own. */
    @Test fun aCodeTheServerAnswersAsAnUnknownRequestIsSaidAndKept() = runBlocking<Unit> {
        val server = Assist(FakeInstance(crypto, kind = InstanceKind.PRIVATE, recoveryFp = recoveryFp), crypto)
        alice(server)
        val b = app(server, MemoryDeviceState(), MemoryDeviceState(), MemoryDeviceState())
        b.entry.openSignIn(b.at())
        b.entry.openForgot(b.at())
        b.entry.openAskOperator(b.at())
        assertEquals(ServerResult.DONE, b.entry.chooseOwnServer(b.at(), server.origin))
        assertEquals(ServerResult.DONE, b.entry.confirmTrustGate(b.at<EntryScreen.TrustGate>()))
        assertEquals(AskOperatorResult.DONE, b.entry.requestOperatorHelp(b.at(), "alice@example.com"))
        server.forgotten = true
        val r = b.entry.verifyOperatorHelp(b.at(), server.code)
        assertEquals(CodeResult.REQUEST_UNKNOWN, r)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.ASSIST_REQUEST_UNKNOWN, r.sentence)
        val unknown = b.at<EntryScreen.OperatorHelp>()
        assertEquals(io.silencelen.andvari.core.app.CopyKey.ASSIST_REQUEST_UNKNOWN, unknown.requestUnknown)
        assertEquals(OperatorHelpStage.CODE_NEEDED, unknown.stage)
        assertTrue(b.assisted.keptOrigins().isNotEmpty())
    }

    /**
     * The right code for a request the server cancelled (its owner changed the password or the recovery setting, or the
     * account was recovered): a result of its own with its sentence, the request forgotten, and the first screen again.
     * Before, it answered FAILED and the code screen stayed for a request that no longer exists.
     */
    @Test fun aCodeForARequestTheServerCancelledIsSaidAndTheRequestIsForgotten() = runBlocking<Unit> {
        val server = Assist(FakeInstance(crypto, kind = InstanceKind.PRIVATE, recoveryFp = recoveryFp), crypto)
        alice(server)
        val b = app(server, MemoryDeviceState(), MemoryDeviceState(), MemoryDeviceState())
        b.entry.openSignIn(b.at())
        b.entry.openForgot(b.at())
        b.entry.openAskOperator(b.at())
        assertEquals(ServerResult.DONE, b.entry.chooseOwnServer(b.at(), server.origin))
        assertEquals(ServerResult.DONE, b.entry.confirmTrustGate(b.at<EntryScreen.TrustGate>()))
        assertEquals(AskOperatorResult.DONE, b.entry.requestOperatorHelp(b.at(), "alice@example.com"))
        server.cancelled = true
        val r = b.entry.verifyOperatorHelp(b.at(), server.code)
        assertEquals(CodeResult.REQUEST_CANCELLED, r)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.ASSIST_REQUEST_CANCELLED, r.sentence)
        b.at<EntryScreen.FirstRun>()
        assertTrue(b.assisted.keptOrigins().isEmpty(), "the request is forgotten on this device")
    }

    /** The fake's switch answers the same way. */
    @Test fun theFakesCancelledRequestIsSaidAtTheCodeStep() = runBlocking<Unit> {
        val app = io.silencelen.andvari.core.app.fake.FakeScenes.at(io.silencelen.andvari.core.app.fake.FakeScene.OPERATOR_HELP_CODE_NEEDED)
        assertTrue(app.script.serverCancelsRequest())
        val r = app.entry.verifyOperatorHelp(assertIs<EntryScreen.OperatorHelp>(app.snapshot.entry), app.script.emailCode)
        assertEquals(CodeResult.REQUEST_CANCELLED, r)
        assertIs<EntryScreen.FirstRun>(app.snapshot.entry)
        assertEquals(null, app.helpRequest)
    }

    /**
     * Whoever runs the server ends a request after its mailed code (the server's command after a restore refuses every
     * request in progress): the next look says VETOED, and the screen carries the shared line that is true of every cause
     * the device cannot tell apart, in place of the stage's own. The stand-in plays the same. Before, the screen had no
     * line of the shared code's for it, and each app said only the account's side.
     */
    @Test fun aRequestEndedByWhoeverRunsTheServerAfterItsCodeCarriesTheSharedEndedLine() = runBlocking<Unit> {
        val server = Assist(FakeInstance(crypto, kind = InstanceKind.PRIVATE, recoveryFp = recoveryFp), crypto)
        alice(server)
        val b = app(server, MemoryDeviceState(), MemoryDeviceState(), MemoryDeviceState())
        val holding = askAndVerify(b, server)
        assertNull(holding.endedLine, "a request on its way has no ended line")
        server.reqs.values.single().state = "vetoed"
        assertEquals(ServerResult.DONE, b.entry.refreshOperatorHelp(holding))
        val ended = b.at<EntryScreen.OperatorHelp>()
        assertEquals(OperatorHelpStage.VETOED, ended.stage)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.ASSIST_REQUEST_ENDED, ended.endedLine)

        val fake = io.silencelen.andvari.core.app.fake.FakeScenes.at(io.silencelen.andvari.core.app.fake.FakeScene.OPERATOR_HELP_HOLDING)
        assertNull(assertIs<EntryScreen.OperatorHelp>(fake.snapshot.entry).endedLine)
        assertTrue(fake.script.serverEndsRequest())
        assertEquals(ServerResult.DONE, fake.entry.refreshOperatorHelp(assertIs<EntryScreen.OperatorHelp>(fake.snapshot.entry)))
        val fakeEnded = assertIs<EntryScreen.OperatorHelp>(fake.snapshot.entry)
        assertEquals(OperatorHelpStage.VETOED, fakeEnded.stage)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.ASSIST_REQUEST_ENDED, fakeEnded.endedLine)
        // The account's own devices' refusal is said with the same line: the device is told the same state.
        val byDevice = io.silencelen.andvari.core.app.fake.FakeScenes.at(io.silencelen.andvari.core.app.fake.FakeScene.OPERATOR_HELP_VETOED)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.ASSIST_REQUEST_ENDED, assertIs<EntryScreen.OperatorHelp>(byDevice.snapshot.entry).endedLine)
    }

    /**
     * Whoever runs the server ends a request whose answer this device had already opened (the answer is dropped at the
     * server): setting the new master password is refused, nothing is committed, and the result is the operator route's
     * own, with the shared line that names that cause too, never the kit's "too late". The journey is at the first
     * screen. The stand-in plays the same. Before, it answered TOO_LATE, whose only words were each app's own.
     */
    @Test fun anAnsweredRequestEndedByWhoeverRunsTheServerIsRefusedAtItsCommitWithTheSharedLine() = runBlocking<Unit> {
        val server = Assist(FakeInstance(crypto, kind = InstanceKind.PRIVATE, recoveryFp = recoveryFp), crypto)
        val uvk = alice(server)
        val b = app(server, MemoryDeviceState(), MemoryDeviceState(), MemoryDeviceState())
        val holding = askAndVerify(b, server)
        server.inner.now += 7 * 86_400_000L
        server.fulfil(server.reqs.keys.single(), uvk, recoverySigner)
        assertEquals(ServerResult.DONE, b.entry.refreshOperatorHelp(holding))
        b.accept(b.at<EntryScreen.CheckAccount>())
        val choose = b.at<EntryScreen.ReplacePassword>()
        val req = server.reqs.values.single()
        req.state = "vetoed"
        req.sealed = null
        val r = b.entry.chooseReplacementPassword(choose, newPw)
        assertEquals(ReplacePasswordResult.REQUEST_ENDED, r)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.ASSIST_ANSWERED_REQUEST_ENDED, r.sentence)
        assertNull(r.trouble)
        b.at<EntryScreen.FirstRun>()
        assertEquals(1, server.reqs.size, "nothing was committed: the server still holds the request it refused")

        val fake = io.silencelen.andvari.core.app.fake.FakeScenes.at(io.silencelen.andvari.core.app.fake.FakeScene.REPLACE_PASSWORD_AFTER_HELP)
        val fakeChoose = assertIs<EntryScreen.ReplacePassword>(fake.snapshot.entry)
        assertEquals(RecoveryRoute.OPERATOR_HELP, fakeChoose.after)
        assertTrue(fake.script.serverEndsRequest())
        val fr = fake.entry.chooseReplacementPassword(fakeChoose, newPw)
        assertEquals(ReplacePasswordResult.REQUEST_ENDED, fr)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.ASSIST_ANSWERED_REQUEST_ENDED, fr.sentence)
        assertIs<EntryScreen.FirstRun>(fake.snapshot.entry)
    }

    /**
     * Whoever runs the server ends a request before its mailed code was typed: the right code is answered as a cancelled
     * request, with the shared line whose must-say now names that cause too. The stand-in's switch for it plays the same.
     */
    @Test fun aRequestEndedByWhoeverRunsTheServerBeforeItsCodeIsSaidAsCancelledOnTheStandIn() = runBlocking<Unit> {
        val app = io.silencelen.andvari.core.app.fake.FakeScenes.at(io.silencelen.andvari.core.app.fake.FakeScene.OPERATOR_HELP_CODE_NEEDED)
        assertTrue(app.script.serverEndsRequest())
        val r = app.entry.verifyOperatorHelp(assertIs<EntryScreen.OperatorHelp>(app.snapshot.entry), app.script.emailCode)
        assertEquals(CodeResult.REQUEST_CANCELLED, r)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.ASSIST_REQUEST_CANCELLED, r.sentence)
        assertIs<EntryScreen.FirstRun>(app.snapshot.entry)
        assertEquals(null, app.helpRequest)
    }

    /**
     * Leaving the account check (back, or "not now") without giving the request up: what was opened of the answer goes
     * (the engine's setAside), the request is kept, and the next look opens and checks the answer again. Before, back left
     * the delivered key and commit value in memory behind the request's screen.
     */
    @Test fun leavingTheAccountCheckDropsWhatWasOpenedAndKeepsTheRequest() = runBlocking<Unit> {
        val server = Assist(FakeInstance(crypto, kind = InstanceKind.PRIVATE, recoveryFp = recoveryFp), crypto)
        val uvk = alice(server)
        val b = app(server, MemoryDeviceState(), MemoryDeviceState(), MemoryDeviceState())
        val holding = askAndVerify(b, server)
        server.inner.now += 7 * 86_400_000L
        server.fulfil(server.reqs.keys.single(), uvk, recoverySigner)
        assertEquals(ServerResult.DONE, b.entry.refreshOperatorHelp(holding))
        val check = b.at<EntryScreen.CheckAccount>()
        assertTrue(b.assisted.holdsOpened(server.origin))
        assertTrue(b.entry.back())
        val help = b.at<EntryScreen.OperatorHelp>()
        assertFalse(b.assisted.holdsOpened(server.origin), "what was opened went with the screen")
        assertTrue(b.assisted.keptOrigins().isNotEmpty())
        assertEquals(ServerResult.DONE, b.entry.refreshOperatorHelp(help))
        assertEquals(check.accountId, b.at<EntryScreen.CheckAccount>().accountId, "opened and checked again")
        // From the password screen too: back goes to the request's screen, never to a check whose answer is gone.
        b.accept(b.at())
        assertIs<EntryScreen.ReplacePassword>(b.snapshot.entry)
        assertTrue(b.entry.back())
        assertIs<EntryScreen.OperatorHelp>(b.snapshot.entry)
        assertFalse(b.assisted.holdsOpened(server.origin))
        // "Not now" on the check: the same.
        assertEquals(ServerResult.DONE, b.entry.refreshOperatorHelp(b.at()))
        b.entry.recoveredAccountNotNow(b.at())
        assertFalse(b.assisted.holdsOpened(server.origin))
        assertTrue(b.at<EntryScreen.FirstRun>().operatorHelpWaiting)
    }

    /** A delivered account that is not the person's: stop, and the request is gone for good. Nothing is sent. */
    @Test fun aRejectedAccountStopsAndDropsTheRequest() = runBlocking<Unit> {
        val server = Assist(FakeInstance(crypto, kind = InstanceKind.PRIVATE, recoveryFp = recoveryFp), crypto)
        val uvk = alice(server)
        val b = app(server, MemoryDeviceState(), MemoryDeviceState())
        askAndVerify(b, server)
        server.inner.now += 7 * 86_400_000L
        server.fulfil(server.reqs.keys.single(), uvk, recoverySigner)
        assertEquals(ServerResult.DONE, b.entry.refreshOperatorHelp(b.at()))
        b.entry.rejectRecoveredAccount(b.at<EntryScreen.CheckAccount>())
        val first = b.at<EntryScreen.FirstRun>()
        assertEquals(FirstRunNotice.RECOVERY_STOPPED, first.notice)
        assertFalse(first.operatorHelpWaiting)
        assertTrue(b.assisted.keptOrigins().isEmpty())
    }

    /** An answer signed by a key that is not the pinned card's recovery key does not check out, and nothing is applied. */
    @Test fun anAnswerNotSignedByTheRecoveryKeyDoesNotCheckOut() = runBlocking<Unit> {
        val server = Assist(FakeInstance(crypto, kind = InstanceKind.PRIVATE, recoveryFp = recoveryFp), crypto)
        val uvk = alice(server)
        val b = app(server, MemoryDeviceState(), MemoryDeviceState())
        askAndVerify(b, server)
        server.inner.now += 7 * 86_400_000L
        server.fulfil(server.reqs.keys.single(), uvk, crypto.signKeypairFromSeed(ByteArray(32) { 9 }))
        assertEquals(ServerResult.DONE, b.entry.refreshOperatorHelp(b.at()))
        assertEquals(OperatorHelpStage.DID_NOT_CHECK_OUT, b.at<EntryScreen.OperatorHelp>().stage)
    }

    /** "Forget this server" forgets the request kept for it, in the request store. */
    @Test fun forgettingTheServerForgetsItsKeptRequest() = runBlocking<Unit> {
        val server = Assist(FakeInstance(crypto, kind = InstanceKind.PRIVATE, recoveryFp = recoveryFp), crypto)
        alice(server)
        val requests = MemoryDeviceState()
        val b = app(server, MemoryDeviceState(), MemoryDeviceState(), requests)
        askAndVerify(b, server)
        assertEquals(listOf(server.origin), b.assisted.keptOrigins())
        val instance = assertNotNull(b.snapshot.instance, "the request's server is on show")
        assertEquals(PlainResult.DONE, b.instance.forgetServer(instance))
        assertTrue(b.assisted.keptOrigins().isEmpty())
        assertTrue(requests.keys().none { it.startsWith("ovh.assist|") })
    }

    /**
     * Forgetting a FORKED server reads its pin with `pinForForget`. `pinFor` answers null under a fork,
     * and then a request kept for that server under an older address (from before a followed move) stayed behind.
     */
    @Test fun forgettingAForkedServerForgetsItsRequestKeptUnderAnOlderAddressToo() = runBlocking<Unit> {
        val server = Assist(FakeInstance(crypto, kind = InstanceKind.PRIVATE, recoveryFp = recoveryFp), crypto)
        alice(server)
        val state = MemoryDeviceState()
        val requests = MemoryDeviceState()
        val b = app(server, state, MemoryDeviceState(), requests)
        askAndVerify(b, server)
        val kept = io.silencelen.andvari.core.client.recovery.AssistRequests(requests, { server.inner.now }, b.trust)
        val mine = assertNotNull(kept.get(server.origin))
        assertNotNull(mine.instanceId, "the request is bound to the server's card")
        kept.put(mine.copy(origin = "https://old.example"))
        assertNotNull(requests.get("ovh.assist|https://old.example"))
        val pins = io.silencelen.andvari.core.client.pin.PinStore(state)
        assertTrue(pins.markForked(assertNotNull(pins.get(server.origin))))
        kotlin.test.assertNull(b.trust.pinFor(server.origin), "pinFor says nothing under the fork")
        b.publish()
        assertEquals(PlainResult.DONE, b.instance.forgetServer(assertNotNull(b.snapshot.instance)))
        assertTrue(requests.keys().none { it.startsWith("ovh.assist|") }, "both requests of the forked server go: ${requests.keys()}")
    }

    /** "Ask the operator for help" from the first screen, through the server's gate when one stands, up to the address. */
    private suspend fun toAsk(b: EngineAppApi, server: Assist): EntryScreen.AskOperator {
        b.entry.openSignIn(b.at())
        b.entry.openForgot(b.at())
        b.entry.openAskOperator(b.at())
        assertEquals(ServerResult.DONE, b.entry.chooseOwnServer(b.at(), server.origin))
        (b.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, b.entry.confirmTrustGate(it)) }
        return b.at()
    }

    /**
     * Spec 01 §7 on a device that keeps the account, signed out by its server: the operator's answer delivers, for the
     * account's own id, another key with a seed sealed under it and that seed's identity served beside it. The pick-up
     * stops before the person is asked anything, and the request's screen says so with the sign-in's own sentence
     * (before, "did not check out", which says the request is over); the request is kept, nothing is committed, and the
     * kept copy is still this account's.
     */
    @Test fun anAnswerWhoseKeyIsNotTheKeptAccountsKeepsTheRequestAndSaysSo() = runBlocking<Unit> {
        val server = Assist(FakeInstance(crypto, kind = InstanceKind.PRIVATE, recoveryFp = recoveryFp), crypto)
        val a = app(server, MemoryDeviceState(), MemoryDeviceState(), MemoryDeviceState())
        alice(server, a).fill(0)
        val userId = assertNotNull(a.keeper.session).userId
        a.keeper.endedByServer(server.origin)
        a.signInAgain(assertNotNull(a.snapshot.locked))
        assertEquals(AskOperatorResult.DONE, a.entry.requestOperatorHelp(toAsk(a, server), "alice@example.com"))
        assertEquals(CodeResult.DONE, a.entry.verifyOperatorHelp(a.at(), server.code))
        val holding = a.at<EntryScreen.OperatorHelp>()
        server.inner.now += 7 * 86_400_000L
        // The server's lie, consistent in itself: another key, a seed sealed under it, that seed's identity.
        val other = crypto.randomBytes(32)
        val seed = crypto.randomBytes(32)
        val norm = "alice@example.com"
        val real = server.inner.accounts.getValue(norm)
        server.inner.accounts[norm] = FakeInstance.Account(real.userId, real.authKey, real.kdfSalt, real.kdfParams, real.wrappedUvk,
            io.silencelen.andvari.core.crypto.Envelope.sealB64(crypto, other, seed, io.silencelen.andvari.core.crypto.Ad.idkey(real.userId)),
            Bytes.toB64(crypto.boxKeypairFromSeed(seed).publicKey), real.genesis, real.personalWrap, real.memberRecovery, real.pieceId, recoveryConfirmed = true)
        server.fulfil(server.reqs.keys.single(), other, recoverySigner)
        other.fill(0)
        seed.fill(0)
        repeat(2) {
            assertEquals(ServerResult.DONE, a.entry.refreshOperatorHelp(a.snapshot.entry as? EntryScreen.OperatorHelp ?: holding))
            val help = a.at<EntryScreen.OperatorHelp>()
            assertEquals(io.silencelen.andvari.core.app.CopyKey.SIGN_IN_SERVER_KEYS_NOT_KNOWN_HERE, help.keysNotKnownHere)
            // What stands in the way is this device's own copy of the account: its removal, never "sign out of that account".
            assertEquals(io.silencelen.andvari.core.app.KeptWayOut.REMOVE_THIS_COPY, help.wayOut)
            assertEquals(OperatorHelpStage.HOLDING, help.stage, "the stage the screen showed; never \"did not check out\"")
            assertTrue(a.assisted.keptOrigins().isNotEmpty(), "the request is kept")
        }
        assertTrue(server.reqs.isNotEmpty(), "nothing was committed")
        val kept = assertNotNull(a.keeper.session, "the kept copy stays")
        assertEquals(userId, kept.userId)
        assertTrue(kept.endedByServer)
    }

    /** Another account is signed in on [b] behind the screens' back (as a race would have it): the keeper keeps it. */
    private suspend fun anotherAccountTaken(b: EngineAppApi, origin: String) {
        val o = b.onboardingFor(origin)
        o.signupStart("carol@example.com", true)
        val t = assertIs<io.silencelen.andvari.core.client.onboard.SignupVerify.Ticket>(o.signupVerify("carol@example.com", "482915"))
        assertIs<io.silencelen.andvari.core.client.onboard.Registration.Registered>(o.register(io.silencelen.andvari.core.client.onboard.RegistrationAuth.Ticket(t),
            io.silencelen.andvari.core.client.onboard.RegistrationForm("carol@example.com", "C", strong.toCharArray(), true,
                io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind.PRIVATE, "Pixel", "android")))
        assertEquals("carol@example.com", assertNotNull(b.keeper.session).emailNorm)
    }

    /**
     * The keeper, asked at the pick-up: this device keeps another account. The request is kept and its screen says so with
     * the way out, at its last stage. Before: the stage "the operator's answer did not check out", which ends the request.
     */
    @Test fun anAnswerPickedUpWhileThisDeviceKeepsAnotherAccountKeepsTheRequestAndSaysSo() = runBlocking<Unit> {
        val server = Assist(FakeInstance(crypto, kind = InstanceKind.PRIVATE, recoveryFp = recoveryFp), crypto)
        val uvk = alice(server)
        val b = app(server, MemoryDeviceState(), MemoryDeviceState(), MemoryDeviceState())
        askAndVerify(b, server)
        anotherAccountTaken(b, server.origin)
        server.inner.now += 7 * 86_400_000L
        server.fulfil(server.reqs.keys.single(), uvk, recoverySigner)
        uvk.fill(0)
        assertEquals(ServerResult.DONE, b.entry.refreshOperatorHelp(b.at()))
        val help = b.at<EntryScreen.OperatorHelp>()
        assertEquals(io.silencelen.andvari.core.app.CopyKey.ASSIST_ANOTHER_ACCOUNT_KEPT, help.anotherAccountKept)
        assertEquals(io.silencelen.andvari.core.app.KeptWayOut.SIGN_OUT_KEPT_ACCOUNT, help.wayOut, "another account: its sign-out")
        assertEquals(null, help.identityFault)
        assertEquals(OperatorHelpStage.HOLDING, help.stage, "the stage the screen showed; never \"did not check out\"")
        assertTrue(b.assisted.keptOrigins().isNotEmpty(), "the request is kept")
        assertTrue(server.reqs.isNotEmpty(), "nothing was committed")
    }

    /**
     * The keeper, asked again just before the commit: another account was taken here since the pick-up. Nothing is
     * committed, the request is kept, and the journey is back on its screen, which says why. Before: TOO_LATE, and the
     * request was dropped.
     */
    @Test fun anAccountTakenBeforeTheCommitKeepsTheRequestAndCommitsNothing() = runBlocking<Unit> {
        val server = Assist(FakeInstance(crypto, kind = InstanceKind.PRIVATE, recoveryFp = recoveryFp), crypto)
        val uvk = alice(server)
        val b = app(server, MemoryDeviceState(), MemoryDeviceState(), MemoryDeviceState())
        val holding = askAndVerify(b, server)
        server.inner.now += 7 * 86_400_000L
        server.fulfil(server.reqs.keys.single(), uvk, recoverySigner)
        uvk.fill(0)
        assertEquals(ServerResult.DONE, b.entry.refreshOperatorHelp(holding))
        b.accept(b.at())
        val choose = b.at<EntryScreen.ReplacePassword>()
        anotherAccountTaken(b, server.origin)
        val r = b.entry.chooseReplacementPassword(choose, "a brand new Master password 7")
        assertEquals(ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT_NOT_COMMITTED, r)
        val help = b.at<EntryScreen.OperatorHelp>()
        assertEquals(io.silencelen.andvari.core.app.CopyKey.ASSIST_ANOTHER_ACCOUNT_KEPT, help.anotherAccountKept)
        assertTrue(b.assisted.keptOrigins().isNotEmpty(), "the request is kept")
        assertTrue(server.reqs.isNotEmpty(), "nothing was committed")
    }

    /**
     * On the operator's help: the account under the address was deleted and made again, and this device
     * comes to keep the EARLIER account under that address while the commit is on its way. The keeper refuses the session
     * for its own reason (another account kept; signed out again, the identity fault), and the result says that the commit
     * happened: the new password is in force, the request is used up (never "the request is kept"), and the new kit is on
     * show. Before, the reason was guessed from the addresses: "the server's keys are not this account's, nothing was
     * committed, the request is kept".
     */
    @Test fun aCommitTakenWhileThisDeviceComesToKeepTheEarlierAccountSaysTheCommitHappened() = runBlocking<Unit> {
        for (thenSignedOut in listOf(false, true)) {
            val server = Assist(FakeInstance(crypto, kind = InstanceKind.PRIVATE, recoveryFp = recoveryFp), crypto)
            alice(server).fill(0)
            val earlier = server.inner.accounts.getValue("alice@example.com")
            server.inner.accounts.remove("alice@example.com")
            val uvk = alice(server)
            val b = app(server, MemoryDeviceState(), MemoryDeviceState(), MemoryDeviceState())
            val holding = askAndVerify(b, server)
            server.inner.now += 7 * 86_400_000L
            server.fulfil(server.reqs.keys.single(), uvk, recoverySigner)
            uvk.fill(0)
            assertEquals(ServerResult.DONE, b.entry.refreshOperatorHelp(holding))
            b.accept(b.at())
            val choose = b.at<EntryScreen.ReplacePassword>()
            server.holdCommit = kotlinx.coroutines.CompletableDeferred()
            var r: ReplacePasswordResult? = null
            val job = kotlinx.coroutines.CoroutineScope(Dispatchers.Unconfined).launch { r = b.entry.chooseReplacementPassword(choose, "a brand new Master password 7") }
            server.commitReached.await()
            // The earlier account is signed in on this device meanwhile (and, in the second round, signed out again).
            val now = server.inner.accounts.getValue("alice@example.com")
            server.inner.accounts["alice@example.com"] = earlier
            try {
                assertIs<io.silencelen.andvari.core.client.onboard.SignIn.SignedIn>(b.onboardingFor(server.origin).signIn("alice@example.com", strong.toCharArray(), null))
            } finally {
                server.inner.accounts["alice@example.com"] = now
            }
            if (thenSignedOut) b.keeper.signOut()
            server.holdCommit!!.complete(Unit)
            job.join()
            val expected = if (thenSignedOut) ReplacePasswordResult.IDENTITY_FAULT_COMMITTED else ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT
            assertEquals(expected, r, "signed out again: $thenSignedOut")
            assertTrue(server.reqs.isEmpty(), "the commit went through and used the request")
            assertTrue(b.assisted.keptOrigins().isEmpty(), "the request is not kept: the server used it")
            val kit = b.at<EntryScreen.Kit>().kit
            assertEquals(if (thenSignedOut) io.silencelen.andvari.core.app.CopyKey.RECOVERY_COMMITTED_IDENTITY_FAULT else io.silencelen.andvari.core.app.CopyKey.KIT_RECOVERED_NOT_KEPT, kit.notKeptLine)
            assertNotNull(b.kit.kitDocument(kit), "the new kit is on show")
        }
    }

    /**
     * A new account [email] made on [a] at [server] by a flow whose session sink takes as [a]'s keeper does, with an early
     * check that sees nothing ([blind]) or the keeper's own: the session it opened, as the keeper answered it.
     */
    private suspend fun registerOn(a: EngineAppApi, server: Assist, email: String, blind: Boolean): io.silencelen.andvari.core.client.onboard.Registration.Registered {
        val sink = if (!blind) a.keeper else object : io.silencelen.andvari.core.client.onboard.SessionSink by a.keeper {
            override fun wouldRefuse(origin: String, emailNorm: String?, userId: String?, identityPub: ByteArray?): String? = null
        }
        val o = io.silencelen.andvari.core.client.onboard.WireOnboarding(
            server.origin, a.clientFor(server.origin), a.trust, a.knownDevices, sink, crypto, a.engine.state, "android", "Pixel", { server.inner.now },
            work = Dispatchers.Unconfined,
        )
        o.signupStart(email, true)
        val t = assertIs<io.silencelen.andvari.core.client.onboard.SignupVerify.Ticket>(o.signupVerify(email, "482915"))
        return assertIs(o.register(io.silencelen.andvari.core.client.onboard.RegistrationAuth.Ticket(t),
            io.silencelen.andvari.core.client.onboard.RegistrationForm(email, "X", strong.toCharArray(), true, io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind.PRIVATE, "Pixel", "android")))
    }

    /**
     * On the operator's help: while the commit waits at the server, another flow's session is refused on
     * this device (carol is taken, dave is refused because carol is kept, carol is signed out), and this call's own
     * session is then taken. The recovery is done, its session kept and its new kit on show. Before: STALE, with the new
     * kit wiped unseen while its session stayed kept here.
     */
    @Test fun anotherSessionRefusedWhileTheCommitRunsLeavesThisCallsSessionAndKit() = runBlocking<Unit> {
        val server = Assist(FakeInstance(crypto, kind = InstanceKind.PRIVATE, recoveryFp = recoveryFp), crypto)
        val uvk = alice(server)
        val b = app(server, MemoryDeviceState(), MemoryDeviceState(), MemoryDeviceState())
        val holding = askAndVerify(b, server)
        server.inner.now += 7 * 86_400_000L
        server.fulfil(server.reqs.keys.single(), uvk, recoverySigner)
        uvk.fill(0)
        assertEquals(ServerResult.DONE, b.entry.refreshOperatorHelp(holding))
        b.accept(b.at())
        val choose = b.at<EntryScreen.ReplacePassword>()
        server.holdCommit = kotlinx.coroutines.CompletableDeferred()
        var r: ReplacePasswordResult? = null
        val job = kotlinx.coroutines.CoroutineScope(Dispatchers.Unconfined).launch { r = b.entry.chooseReplacementPassword(choose, "a brand new Master password 7") }
        server.commitReached.await()
        val carol = registerOn(b, server, "carol@example.com", blind = false)
        assertNull(carol.notKept, "carol is taken")
        carol.kit.wipe()
        val refusals = b.keeper.refusals
        val dave = registerOn(b, server, "dave@example.com", blind = true)
        assertNotNull(dave.notKept, "dave's session is refused: carol is kept")
        dave.kit.wipe()
        assertEquals(refusals + 1, b.keeper.refusals)
        b.keeper.signOut()
        server.holdCommit!!.complete(Unit)
        job.join()
        assertEquals(ReplacePasswordResult.DONE, r)
        assertEquals("alice@example.com", assertNotNull(b.keeper.session).emailNorm, "this call's session is kept")
        val kit = b.at<EntryScreen.Kit>().kit
        assertNull(kit.notKeptLine)
        assertNotNull(b.kit.kitDocument(kit), "the new kit is on show")
    }

    /**
     * On the operator's help: the server takes the commit, and its answer cannot be
     * opened on this device (a fault while opening, after the commit). With or without another flow's session refused on
     * this device while the commit waits, the answer is said as a commit that happened and could not be opened, at the
     * first screen, and the request is not said to be kept. Before (with the refusal meanwhile): STALE, the journey left on
     * the password step although the commit was made.
     */
    @Test fun aFaultWhileOpeningAfterTheCommitIsSaidAsThatAlsoWhenAnotherSessionWasRefusedMeanwhile() = runBlocking<Unit> {
        for (race in listOf(false, true)) {
            val server = Assist(FakeInstance(crypto, kind = InstanceKind.PRIVATE, recoveryFp = recoveryFp), crypto)
            val uvk = alice(server)
            val b = app(server, MemoryDeviceState(), MemoryDeviceState(), MemoryDeviceState())
            val holding = askAndVerify(b, server)
            server.inner.now += 7 * 86_400_000L
            server.fulfil(server.reqs.keys.single(), uvk, recoverySigner)
            uvk.fill(0)
            assertEquals(ServerResult.DONE, b.entry.refreshOperatorHelp(holding))
            b.accept(b.at())
            val choose = b.at<EntryScreen.ReplacePassword>()
            server.seedSwap = true
            server.holdCommit = kotlinx.coroutines.CompletableDeferred()
            var r: ReplacePasswordResult? = null
            val job = kotlinx.coroutines.CoroutineScope(Dispatchers.Unconfined).launch { r = b.entry.chooseReplacementPassword(choose, "a brand new Master password 7") }
            server.commitReached.await()
            if (race) {
                registerOn(b, server, "carol@example.com", blind = false).kit.wipe()
                val refusals = b.keeper.refusals
                registerOn(b, server, "dave@example.com", blind = true).kit.wipe()
                assertEquals(refusals + 1, b.keeper.refusals, "dave's session is refused: carol is kept")
                b.keeper.signOut()
            }
            server.holdCommit!!.complete(Unit)
            job.join()
            assertEquals(ReplacePasswordResult.COMMITTED_NOT_OPENED, r, "race=$race")
            assertEquals(io.silencelen.andvari.core.app.CopyKey.RECOVERY_COMMITTED_NOT_OPENED, r!!.sentence)
            assertTrue(server.reqs.isEmpty(), "the server used the request up with the commit")
            b.at<EntryScreen.FirstRun>()
            assertNull(b.keeper.session, "nothing of the account is kept here: race=$race")
        }
    }

    /**
     * The engine's reason `not_the_kept_account`: this device keeps alice (signed out by her server), and the operator's
     * answer names another account under her address (hers was deleted and made again). Refused at the pick-up, before
     * anything is shown to check: the request stays, nothing is committed, and the screen says that the answer names an
     * account that is not the one kept here, with no sign-out offered. Before: "the answer did not check out".
     */
    @Test fun anAnswerNamingAnotherAccountThanTheKeptOneIsSaidAsThatAndKeepsTheRequest() = runBlocking<Unit> {
        val server = Assist(FakeInstance(crypto, kind = InstanceKind.PRIVATE, recoveryFp = recoveryFp), crypto)
        val b = app(server, MemoryDeviceState(), MemoryDeviceState(), MemoryDeviceState())
        alice(server, b).fill(0)
        b.keeper.endedByServer(server.origin)
        b.signInAgain(assertNotNull(b.snapshot.locked))
        server.inner.accounts.remove("alice@example.com")
        val uvk = alice(server)
        b.entry.openSignIn(b.at())
        b.entry.openForgot(b.at())
        b.entry.openAskOperator(b.at())
        assertEquals(ServerResult.DONE, b.entry.chooseOwnServer(b.at(), server.origin))
        (b.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, b.entry.confirmTrustGate(it)) }
        assertEquals(AskOperatorResult.DONE, b.entry.requestOperatorHelp(b.at(), "alice@example.com"))
        assertEquals(CodeResult.DONE, b.entry.verifyOperatorHelp(b.at(), server.code))
        server.inner.now += 7 * 86_400_000L
        server.fulfil(server.reqs.keys.single(), uvk, recoverySigner)
        uvk.fill(0)
        assertEquals(ServerResult.DONE, b.entry.refreshOperatorHelp(b.at()))
        val help = b.at<EntryScreen.OperatorHelp>()
        assertEquals(io.silencelen.andvari.core.app.CopyKey.ASSIST_NOT_THE_KEPT_ACCOUNT, help.notTheKeptAccount)
        assertEquals(null, help.anotherAccountKept, "never the sign-out's way out")
        assertEquals(OperatorHelpStage.HOLDING, help.stage, "the stage the screen showed; never \"did not check out\"")
        assertTrue(b.assisted.keptOrigins().isNotEmpty(), "the request is kept")
        assertTrue(server.reqs.isNotEmpty(), "nothing was committed")
    }

    /**
     * The mailbox value (decided on 2026-11-17): the field opens behind its quiet line; a text that is not a value's form
     * is said as that before anything is sent; a value goes with the request in its sent form; and what the screen says
     * afterwards is the same as without one.
     */
    @Test fun theMailboxValueGoesWithTheRequestAndChangesNothingTheScreenSays() = runBlocking<Unit> {
        val server = Assist(FakeInstance(crypto, kind = InstanceKind.PRIVATE, recoveryFp = recoveryFp), crypto)
        alice(server).fill(0)
        val b = app(server, MemoryDeviceState(), MemoryDeviceState(), MemoryDeviceState())
        val ask = toAsk(b, server)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.ASSIST_MAILBOX_VALUE_LINE, ask.mailboxValueLine)
        kotlin.test.assertNull(ask.mailboxValueField, "hidden until its line is opened")
        b.entry.openMailboxValue(ask)
        val open = b.at<EntryScreen.AskOperator>()
        assertEquals(io.silencelen.andvari.core.app.CopyKey.ASSIST_MAILBOX_VALUE_FIELD, open.mailboxValueField)
        for (bad in listOf("ABCD", "ABCD EFGH JKMN PQRO", "ABCDEFGHJKMNPQRSTU")) {
            val r = b.entry.requestOperatorHelpWithValue(open, "alice@example.com", bad)
            assertEquals(AskOperatorResult.NOT_A_MAILBOX_VALUE, r, bad)
            assertEquals(io.silencelen.andvari.core.app.CopyKey.ASSIST_NOT_A_MAILBOX_VALUE, r.sentence)
            assertTrue(b.snapshot.entry === open, "the screen stays with its field")
        }
        assertTrue(server.created.isEmpty(), "nothing was sent")
        assertEquals(AskOperatorResult.DONE, b.entry.requestOperatorHelpWithValue(open, "alice@example.com", "abcd-efgh jkmn pqrs"))
        assertEquals("ABCDEFGHJKMNPQRS", server.created.single().mailboxValue)
        val with = b.at<EntryScreen.OperatorHelp>()

        val c = app(server, MemoryDeviceState(), MemoryDeviceState(), MemoryDeviceState())
        assertEquals(AskOperatorResult.DONE, c.entry.requestOperatorHelpWithValue(toAsk(c, server), "alice@example.com", ""))
        kotlin.test.assertNull(server.created.last().mailboxValue, "blank is none")
        val without = c.at<EntryScreen.OperatorHelp>()
        assertEquals(without.stage, with.stage)
        assertEquals(without.email, with.email)
        assertEquals(without.requestCode.size, with.requestCode.size)
        assertEquals(without.holdEndsAtMs, with.holdEndsAtMs)
        assertEquals(without.answerReplaced, with.answerReplaced)
        assertEquals(without.keyChange, with.keyChange)
        assertEquals(without.requestUnknown, with.requestUnknown)
        assertEquals(without.keysNotKnownHere, with.keysNotKnownHere)
    }

    // ---- "Forget the earlier account on this device" only for ANOTHER account (decided on 2026-11-19) ----

    private fun bindingKey(origin: String) = io.silencelen.andvari.core.client.session.SessionKeeper.EMAIL_BINDING_PREFIX + origin + "|alice@example.com"

    /** An identity public key of a key pair of its own, as base64: a key no account here has. */
    private fun anotherKey(): String = Bytes.toB64(crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey)

    /**
     * The operator's answer for account U under another key, on a device that knows U under the address by the address's
     * record alone: the keeper's identity refusal, said on the request's screen, with no offer (before: offered, and two
     * taps removed the record that stops the substitution). An answer for a remade account (another id): offered as before.
     */
    @Test fun anAnswerOffersTheForgettingOnlyForAnotherAccount() = runBlocking<Unit> {
        for (another in listOf(false, true)) {
            val server = Assist(FakeInstance(crypto, kind = InstanceKind.PRIVATE, recoveryFp = recoveryFp), crypto)
            val a = app(server, MemoryDeviceState(), MemoryDeviceState(), MemoryDeviceState())
            alice(server, a).fill(0)
            val u = assertNotNull(a.keeper.session).userId
            assertEquals(PlainResult.DONE, a.signOut())
            val deliver: ByteArray
            if (another) {
                // Deleted and made again on another device: another account id.
                server.inner.accounts.remove("alice@example.com")
                deliver = alice(server)
            } else {
                // The keeper's own comparison: the address's record alone names U (no record of U's key here).
                a.engine.state.set("ovh.identity|$u", null)
                // U under another key, consistent in itself: a seed sealed under another account key, that seed's identity.
                deliver = crypto.randomBytes(32)
                val seed = crypto.randomBytes(32)
                val real = server.inner.accounts.getValue("alice@example.com")
                server.inner.accounts["alice@example.com"] = FakeInstance.Account(real.userId, real.authKey, real.kdfSalt, real.kdfParams, real.wrappedUvk,
                    io.silencelen.andvari.core.crypto.Envelope.sealB64(crypto, deliver, seed, io.silencelen.andvari.core.crypto.Ad.idkey(real.userId)),
                    Bytes.toB64(crypto.boxKeypairFromSeed(seed).publicKey), real.genesis, real.personalWrap, real.memberRecovery, real.pieceId, recoveryConfirmed = true)
                seed.fill(0)
            }
            assertEquals(AskOperatorResult.DONE, a.entry.requestOperatorHelp(toAsk(a, server), "alice@example.com"))
            assertEquals(CodeResult.DONE, a.entry.verifyOperatorHelp(a.at(), server.code))
            server.inner.now += 7 * 86_400_000L
            server.fulfil(server.reqs.keys.single(), deliver, recoverySigner)
            deliver.fill(0)
            assertEquals(ServerResult.DONE, a.entry.refreshOperatorHelp(a.at()))
            val help = a.at<EntryScreen.OperatorHelp>()
            assertEquals(io.silencelen.andvari.core.app.CopyKey.IDENTITY_FAULT_ADDRESS_KNOWN, help.identityFault, "another account: $another")
            assertTrue(a.assisted.keptOrigins().isNotEmpty(), "the request is kept")
            if (another) {
                assertEquals(u, assertNotNull(a.snapshot.earlierAccount, "another account: offered as before").earlierUserId)
            } else {
                assertNull(a.snapshot.earlierAccount, "the same account under another key: nothing is offered")
            }
        }
    }

    /**
     * The operator's answer for account U under another key, on a device that keeps U's key on record (its usual state after
     * a sign-out): the answer's own check against that record refuses it, which is the identity fault, said in its own line
     * on the request's screen with the request kept, as at the keeper's identity refusal; no offer. Before: the request ended
     * as "the operator's answer did not pass andvari's checks".
     */
    @Test fun anAnswerForTheKeptAccountUnderAnotherKeyIsTheIdentityFaultWithTheRequestKept() = runBlocking<Unit> {
        val server = Assist(FakeInstance(crypto, kind = InstanceKind.PRIVATE, recoveryFp = recoveryFp), crypto)
        val a = app(server, MemoryDeviceState(), MemoryDeviceState(), MemoryDeviceState())
        alice(server, a).fill(0)
        val u = assertNotNull(a.keeper.session).userId
        assertEquals(PlainResult.DONE, a.signOut())
        assertNotNull(a.engine.state.get("ovh.identity|$u"), "the record of U's key is kept")
        // U under another key, consistent in itself: a seed sealed under another account key, that seed's identity.
        val deliver = crypto.randomBytes(32)
        val seed = crypto.randomBytes(32)
        val real = server.inner.accounts.getValue("alice@example.com")
        server.inner.accounts["alice@example.com"] = FakeInstance.Account(real.userId, real.authKey, real.kdfSalt, real.kdfParams, real.wrappedUvk,
            io.silencelen.andvari.core.crypto.Envelope.sealB64(crypto, deliver, seed, io.silencelen.andvari.core.crypto.Ad.idkey(real.userId)),
            Bytes.toB64(crypto.boxKeypairFromSeed(seed).publicKey), real.genesis, real.personalWrap, real.memberRecovery, real.pieceId, recoveryConfirmed = true)
        seed.fill(0)
        assertEquals(AskOperatorResult.DONE, a.entry.requestOperatorHelp(toAsk(a, server), "alice@example.com"))
        assertEquals(CodeResult.DONE, a.entry.verifyOperatorHelp(a.at(), server.code))
        server.inner.now += 7 * 86_400_000L
        server.fulfil(server.reqs.keys.single(), deliver, recoverySigner)
        deliver.fill(0)
        assertEquals(ServerResult.DONE, a.entry.refreshOperatorHelp(a.at()))
        val help = a.at<EntryScreen.OperatorHelp>()
        println("the operator's answer for U under another key: stage=${help.stage} identityFault=${help.identityFault}")
        kotlin.test.assertNotEquals(OperatorHelpStage.DID_NOT_CHECK_OUT, help.stage)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.IDENTITY_FAULT_ADDRESS_KNOWN, help.identityFault)
        assertTrue(a.assisted.keptOrigins().isNotEmpty(), "the request is kept")
        assertNull(a.snapshot.earlierAccount, "nothing is offered")
        assertNull(a.keeper.session, "nothing was taken")
    }

    /**
     * The keeper, asked again just before the operator's commit: the address came to be tied here to the answer's own account
     * under another key meanwhile. The identity fault, nothing committed, the request kept, and no offer (before: offered).
     * Tied to another account instead: offered as before.
     */
    @Test fun aCommitOffersTheForgettingOnlyForAnotherAccount() = runBlocking<Unit> {
        for (another in listOf(false, true)) {
            val server = Assist(FakeInstance(crypto, kind = InstanceKind.PRIVATE, recoveryFp = recoveryFp), crypto)
            val uvk = alice(server)
            val u = server.inner.accounts.getValue("alice@example.com").userId
            val b = app(server, MemoryDeviceState(), MemoryDeviceState(), MemoryDeviceState())
            val holding = askAndVerify(b, server)
            server.inner.now += 7 * 86_400_000L
            server.fulfil(server.reqs.keys.single(), uvk, recoverySigner)
            uvk.fill(0)
            assertEquals(ServerResult.DONE, b.entry.refreshOperatorHelp(holding))
            b.accept(b.at())
            val choose = b.at<EntryScreen.ReplacePassword>()
            val earlier = if (another) "00000000-0000-4000-8000-0000000000aa" else u
            // As a take writes it: that account with an identity key that is not U's.
            b.engine.state.set(bindingKey(server.origin), "$earlier|${anotherKey()}")
            assertEquals(ReplacePasswordResult.IDENTITY_FAULT, b.entry.chooseReplacementPassword(choose, "a brand new Master password 7"), "another account: $another")
            assertTrue(server.reqs.isNotEmpty(), "nothing was committed")
            assertTrue(b.assisted.keptOrigins().isNotEmpty(), "the request is kept")
            if (another) {
                assertEquals(earlier, assertNotNull(b.snapshot.earlierAccount, "another account: offered as before").earlierUserId)
            } else {
                assertNull(b.snapshot.earlierAccount, "the same account under another key: nothing is offered")
            }
        }
    }
}
