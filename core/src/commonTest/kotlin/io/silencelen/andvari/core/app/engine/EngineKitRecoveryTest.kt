package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.KitDocument
import io.silencelen.andvari.core.app.KitReason
import io.silencelen.andvari.core.app.KitRecoverResult
import io.silencelen.andvari.core.app.KitScanResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.RecoveryRoute
import io.silencelen.andvari.core.app.ReplacePasswordResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Kit recovery (§10) on the engine: the fake's flow, against the onboarding tests' [FakeInstance]. */
class EngineKitRecoveryTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val replacement = "a brand new Master password 7"

    private class Env(val server: FakeInstance, val transport: BearerTransport, val app: EngineAppApi)

    private fun env(platform: AppPlatform = AppPlatform.ANDROID): Env {
        val server = FakeInstance(crypto)
        val transport = BearerTransport(mapOf(server.origin to server))
        val engine = AppEngine(platform, "Pixel", transport, MemoryDeviceState(), MemoryDeviceState(), crypto, { server.now }, baked = null, storeBuild = false,
            stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined)
        val app = if (platform == AppPlatform.LINUX) EngineDesktopAppApi(engine) else EngineAppApi(engine)
        app.start()
        return Env(server, transport, app)
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    /** Register, keep the kit's document, sign out. */
    private suspend fun registeredThenSignedOut(a: EngineAppApi): KitDocument {
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(a.at()))
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), "alice@example.com", true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "Alice", strong, true)))
        val doc = confirmKit(a)
        assertEquals(PlainResult.DONE, a.signOut())
        return doc
    }

    private suspend fun confirmKit(a: EngineAppApi): KitDocument {
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        return doc
    }

    private fun kitEntry(a: EngineAppApi): EntryScreen.KitEntry {
        a.entry.openSignIn(a.at())
        a.entry.openForgot(a.at())
        a.entry.openKitEntry(a.at())
        return a.at()
    }

    @Test fun aScannedKitSetsANewPasswordShowsTheNewKitAndOpensTheVault() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        val doc = registeredThenSignedOut(a)
        assertEquals(KitScanResult.NOT_A_KIT, a.entry.submitKit(kitEntry(a), "https://h.example/l#nothing", PayloadSource.SCANNED))
        val sent = e.server.calls.size
        assertEquals(KitScanResult.DONE, a.entry.submitKit(a.at(), doc.qrPayload, PayloadSource.SCANNED))
        val recover = a.at<EntryScreen.KitRecover>()
        assertEquals("alice@example.com", recover.email)
        assertEquals("https://h.example", recover.instance.origin)
        assertTrue(e.server.calls.drop(sent).none { it == WireRoute.RECOVERY_SELF_VERIFY }, "nothing is sent before the person confirms")
        assertEquals(KitRecoverResult.DONE, a.entry.confirmKitRecovery(recover))
        val choose = a.at<EntryScreen.ReplacePassword>()
        assertEquals(RecoveryRoute.KIT, choose.after)
        assertEquals(ReplacePasswordResult.WEAK_PASSWORD, a.entry.chooseReplacementPassword(choose, "short"))
        assertEquals(ReplacePasswordResult.DONE, a.entry.chooseReplacementPassword(choose, replacement))
        assertEquals(KitReason.AFTER_RECOVERY, a.at<EntryScreen.Kit>().kit.reason)
        assertEquals(AppPhase.ENTRY, a.snapshot.phase, "the vault opens only once the new kit is saved")
        val fresh = confirmKit(a)
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        assertTrue(fresh.qrPayload != doc.qrPayload, "the commit replaced the kit")
        // The new password is the one in force.
        a.lock()
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, a.unlock(assertNotNull(a.snapshot.locked), replacement))
    }

    @Test fun aKitTheServerRefusesEndsTheRecoveryAndGoesBackToTheScanner() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        val doc = registeredThenSignedOut(a)
        // Another kit has replaced this one since: the server's uniform 401.
        e.server.override[WireRoute.RECOVERY_SELF_VERIFY] = io.silencelen.andvari.core.client.net.WireResult.Refused(401,
            io.silencelen.andvari.core.model.wire.WireError("invalid_credentials", "x"))
        assertEquals(KitScanResult.DONE, a.entry.submitKit(kitEntry(a), doc.qrPayload, PayloadSource.SCANNED))
        val recover = a.at<EntryScreen.KitRecover>()
        assertEquals(KitRecoverResult.KIT_NOT_ACCEPTED, a.entry.confirmKitRecovery(recover))
        a.at<EntryScreen.KitEntry>()
        assertEquals(KitRecoverResult.STALE, a.entry.confirmKitRecovery(recover), "a kit is proved once")
    }

    @Test fun aTypedKitIsRefusedBeforeAnythingIsSentWhenItIsMalformed() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        registeredThenSignedOut(a)
        val entry = kitEntry(a)
        val sent = e.server.calls.size
        assertEquals(KitScanResult.INVALID_EMAIL, a.entry.submitTypedKit(entry, "not an address", "h.example", "aaaa"))
        assertEquals(KitScanResult.NOT_A_KIT, a.entry.submitTypedKit(entry, "alice@example.com", "h.example", "aaaa bbbb"))
        assertEquals(sent, e.server.calls.size)
    }

    @Test fun aTypedKitRecoversThroughTheSameSteps() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        val doc = registeredThenSignedOut(a)
        assertEquals(KitScanResult.DONE, a.entry.submitTypedKit(kitEntry(a), "alice@example.com", "h.example", doc.groups.joinToString(" ")))
        // A typed kit vouches for no server: a Trust Gate stands first unless this device's pin serves the recovery.
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { gate ->
            assertTrue(gate.prompt.typedKit)
            assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(gate))
        }
        val recover = a.at<EntryScreen.KitRecover>()
        assertEquals(KitRecoverResult.DONE, a.entry.confirmKitRecovery(recover))
        assertEquals(ReplacePasswordResult.DONE, a.entry.chooseReplacementPassword(a.at(), replacement))
        confirmKit(a)
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    @Test fun leavingTheRecoveryDropsItAndAPhoneRefusesTheOperatorAccountAtTheCommit() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        val doc = registeredThenSignedOut(a)
        assertEquals(KitScanResult.DONE, a.entry.submitKit(kitEntry(a), doc.qrPayload, PayloadSource.SCANNED))
        val left = a.at<EntryScreen.KitRecover>()
        a.entry.back()
        assertEquals(KitRecoverResult.STALE, a.entry.confirmKitRecovery(left))

        // The account is its server's operator account: on a phone the commit's session is ended at once.
        e.server.operatorUserId = e.server.account("alice@example.com").userId
        assertEquals(KitScanResult.DONE, a.entry.submitKit(a.at(), doc.qrPayload, PayloadSource.SCANNED))
        assertEquals(KitRecoverResult.DONE, a.entry.confirmKitRecovery(a.at()))
        assertEquals(ReplacePasswordResult.OPERATOR_NEEDS_COMPUTER, a.entry.chooseReplacementPassword(a.at(), replacement))
        a.at<EntryScreen.FirstRun>()
        assertEquals(null, a.keeper.session, "nothing of the account is kept")
        assertTrue(e.transport.bearersFor(WireRoute.LOGOUT).isNotEmpty(), "the commit's session was ended at the server")
    }

    /** Holds RECOVERY_SELF_VERIFY on [gate]; everything else goes to [inner] at once. */
    private class HeldVerify(val inner: FakeInstance) : io.silencelen.andvari.core.client.net.WireClient by inner {
        val gate = kotlinx.coroutines.CompletableDeferred<Unit>()
        val reached = kotlinx.coroutines.CompletableDeferred<Unit>()
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): io.silencelen.andvari.core.client.net.WireResult<T> {
            if (route == WireRoute.RECOVERY_SELF_VERIFY) {
                reached.complete(Unit)
                gate.await()
            }
            return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
        }
    }

    /** Holds [route] on [gate]; everything else goes to [inner] at once. */
    private class HeldRoute(val inner: FakeInstance, val route: WireRoute) : io.silencelen.andvari.core.client.net.WireClient by inner {
        val gate = kotlinx.coroutines.CompletableDeferred<Unit>()
        val reached = kotlinx.coroutines.CompletableDeferred<Unit>()
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): io.silencelen.andvari.core.client.net.WireResult<T> {
            if (route == this.route) {
                reached.complete(Unit)
                gate.await()
            }
            return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
        }
    }

    /**
     * A kit recovery left while its commit is on its way, and the server took it. The new kit
     * was never shown and the scanned one is dead, so the account holds no kit the person saved; the server's
     * `recoveryConfirmed` (spec 03 §12, spec 04 §6: cleared by every commit, set only by a confirm) says so. The intent
     * answers STALE, nothing of the commit's session is kept, and the next sign-in with the new password goes to a new
     * kit before the vault opens.
     */
    @Test fun aKitRecoveryLeftWhileItsCommitIsOnItsWayLeavesNoKitAndTheNextSignInMakesOne() = runBlocking<Unit> {
        val first = env()
        val doc = registeredThenSignedOut(first.app)
        val held = HeldRoute(first.server, WireRoute.RECOVERY_SELF_COMMIT)
        val transport = BearerTransport(mapOf(first.server.origin to held))
        val b = EngineAppApi(AppEngine(AppPlatform.ANDROID, "Pixel", transport, MemoryDeviceState(), MemoryDeviceState(), crypto, { first.server.now },
            baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined)).also { it.start() }
        b.entry.openSignIn(b.at())
        b.entry.openForgot(b.at())
        b.entry.openKitEntry(b.at())
        assertEquals(KitScanResult.DONE, b.entry.submitKit(b.at(), doc.qrPayload, PayloadSource.SCANNED))
        (b.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, b.entry.confirmTrustGate(it)) }
        assertEquals(KitRecoverResult.DONE, b.entry.confirmKitRecovery(b.at()))
        val choose = b.at<EntryScreen.ReplacePassword>()
        var result: ReplacePasswordResult? = null
        val job = launch { result = b.entry.chooseReplacementPassword(choose, replacement) }
        held.reached.await()
        b.entry.back()
        held.gate.complete(Unit)
        job.join()
        assertEquals(ReplacePasswordResult.STALE, result)
        val account = first.server.account("alice@example.com")
        assertTrue(!account.recoveryConfirmed, "the server took the commit: the account holds no confirmed kit")
        assertEquals(null, b.keeper.session, "nothing of the commit's session is kept")
        assertEquals(AppPhase.ENTRY, b.snapshot.phase)

        repeat(6) { if (b.snapshot.entry !is EntryScreen.FirstRun) b.entry.back() }
        b.entry.openSignIn(b.at())
        b.entry.openPasswordSignIn(b.at())
        assertEquals(ServerResult.DONE, b.entry.chooseOwnServer(b.at(), first.server.origin))
        (b.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, b.entry.confirmTrustGate(it)) }
        assertEquals(SignInAnswer.DONE, b.entry.submitSignIn(b.at(), "alice@example.com", replacement))
        val kit = b.at<EntryScreen.Kit>()
        assertEquals(KitReason.NEVER_SAVED, kit.kit.reason, "the next sign-in goes to a new kit")
        assertEquals(AppPhase.ENTRY, b.snapshot.phase, "the vault stays shut until it is saved")
        confirmKit(b)
        assertEquals(AppPhase.UNLOCKED, b.snapshot.phase)
        assertTrue(account.recoveryConfirmed)
    }

    /**
     * Engine-17 item 3 (`KitRecovery.cancel` on EVERY stop after a step with a handle): a host's own stop while the
     * kit's proof is in flight (the intent's coroutine cancelled; the screen stays) drops the kit pin the scan made on
     * this device. Before, the step was already off the flow and nothing cancelled it: the pin of an abandoned recovery
     * stayed behind, with the kit's secret in memory.
     */
    @Test fun aRecoveryStoppedWhileTheKitIsBeingProvedDropsThePinTheScanMade() = runBlocking<Unit> {
        val first = env()
        val doc = registeredThenSignedOut(first.app)
        val held = HeldVerify(first.server)
        val transport = BearerTransport(mapOf(first.server.origin to held))
        val b = EngineAppApi(AppEngine(AppPlatform.ANDROID, "Pixel", transport, MemoryDeviceState(), MemoryDeviceState(), crypto, { first.server.now },
            baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined)).also { it.start() }
        b.entry.openSignIn(b.at())
        b.entry.openForgot(b.at())
        b.entry.openKitEntry(b.at())
        assertEquals(KitScanResult.DONE, b.entry.submitKit(b.at(), doc.qrPayload, PayloadSource.SCANNED))
        (b.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, b.entry.confirmTrustGate(it)) }
        val recover = b.at<EntryScreen.KitRecover>()
        assertNotNull(b.trust.pinFor(first.server.origin), "the scan pinned the kit's server on this fresh device")
        val job = launch { b.entry.confirmKitRecovery(recover) }
        held.reached.await()
        job.cancel()
        job.join()
        held.gate.complete(Unit)
        assertEquals(null, b.trust.pinFor(first.server.origin), "the pin the abandoned recovery made is gone")
    }

    /**
     * Spec 01 §7 on a device that keeps the account, signed out by its server: the server holds a kit of another key for
     * the account's id. The kit's key does not open the copy's sealed identity seed, so the recovery stops with the
     * sign-in's own answer and sentence (before, a general failure with no sentence), nothing is committed, and the kept
     * copy is still this account's, as its server left it.
     */
    /**
     * The server serves, with the kit's honest key, an identity key the account's seed does not derive: the kit's checks
     * stop as `identity_mismatch`. It is the security fault, said as one. Before, it fell to a general failure.
     */
    @Test fun aKitWhoseServedIdentityDoesNotMatchItsSeedIsAnIdentityFault() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        val doc = registeredThenSignedOut(a)
        e.server.account("alice@example.com").identityPub = io.silencelen.andvari.core.crypto.Bytes.toB64(crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey)
        assertEquals(KitScanResult.DONE, a.entry.submitKit(kitEntry(a), doc.qrPayload, PayloadSource.SCANNED))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        assertEquals(KitRecoverResult.IDENTITY_FAULT, a.entry.confirmKitRecovery(a.at()))
        assertTrue(WireRoute.RECOVERY_SELF_COMMIT !in e.server.calls, "nothing was committed")
    }

    @Test fun aKitWhoseKeyIsNotTheKeptAccountsHasTheSignInsAnswerAndCommitsNothing() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(a.at()))
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), "alice@example.com", true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "Alice", strong, true)))
        confirmKit(a)
        val userId = assertNotNull(a.keeper.session).userId
        // The server now holds, for this account's id, a kit of another key.
        val other = crypto.randomBytes(32)
        val piece = io.silencelen.andvari.core.crypto.MemberRecovery.generate(crypto, userId, other)
        val kit = try {
            e.server.account("alice@example.com").memberRecovery = io.silencelen.andvari.core.model.wire.MemberRecoveryBlock(piece.recoveryWrappedUvk, piece.recoveryAuthKey)
            io.silencelen.andvari.core.trust.RecoveryKit.displayForm(piece.recoverySecret)
        } finally {
            piece.recoverySecret.fill(0)
            other.fill(0)
        }
        a.keeper.endedByServer(e.server.origin)
        a.signInAgain(assertNotNull(a.snapshot.locked))
        assertEquals(KitScanResult.DONE, a.entry.submitTypedKit(kitEntry(a), "alice@example.com", "h.example", kit))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        val r = a.entry.confirmKitRecovery(a.at())
        assertEquals(KitRecoverResult.SERVER_KEYS_NOT_KNOWN_HERE, r, "never a general failure")
        assertEquals(io.silencelen.andvari.core.app.CopyKey.SIGN_IN_SERVER_KEYS_NOT_KNOWN_HERE, r.sentence)
        a.at<EntryScreen.KitEntry>()
        assertTrue(WireRoute.RECOVERY_SELF_COMMIT !in e.server.calls, "nothing was committed")
        val kept = assertNotNull(a.keeper.session, "the kept copy stays")
        assertEquals(userId, kept.userId)
        assertTrue(kept.endedByServer)
    }
}
