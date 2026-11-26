package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.KitReason
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.RecoveryChangeResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.WhoCanRecover
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Recovery in Settings (§4.5, §7.7, §10) on the engine: who can recover, operator recovery on and off, a new kit, and §4.5's prompt. */
class EngineRecoveryTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val recovery = crypto.boxKeypairFromSeed(ByteArray(32) { 2 })
    private val fp = Escrow.fingerprint(crypto, recovery.publicKey)

    private fun server(withKey: Boolean = true): FakeInstance =
        (if (withKey) FakeInstance(crypto, recoveryFp = fp) else FakeInstance(crypto)).also { if (withKey) it.recoveryPub = recovery.publicKey }

    private fun app(server: FakeInstance, front: io.silencelen.andvari.core.client.net.WireClient = server): EngineAppApi = EngineAppApi(
        AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.origin to front)), MemoryDeviceState(), MemoryDeviceState(), crypto,
            { server.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
    ).also {
        it.linksFlow.answersPollMs = Long.MAX_VALUE
        it.start()
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    private suspend fun open(a: EngineAppApi) {
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(a.at()))
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), "alice@example.com", true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "Alice", strong, true)))
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    private fun recoveryScreen(a: EngineAppApi) = assertNotNull(a.snapshot.account!!.recovery)

    @Test fun operatorRecoveryIsTurnedOnOnlyBehindTheWarningItsBoxAndThePasswordAndTurnedOff() = runBlocking<Unit> {
        val s = server()
        val a = app(s)
        open(a)
        assertNull(a.snapshot.account!!.recovery, "closed until opened")
        assertEquals(PlainResult.DONE, a.recovery.openRecovery())
        val screen = recoveryScreen(a)
        assertEquals(WhoCanRecover.ONLY_ME, screen.whoCanRecover)
        val question = assertNotNull(screen.question, "the pinned card names a recovery key")
        assertEquals("Home", question.instance.name)
        assertNull(screen.warning)

        a.recovery.reviewOperatorRecovery(screen)
        val warning = assertNotNull(recoveryScreen(a).warning)
        val puts = s.calls.count { it == WireRoute.ACCOUNT_RECOVERY_PUT }
        assertEquals(RecoveryChangeResult.NOT_TICKED, a.recovery.turnOnOperatorRecovery(warning, false, strong))
        assertEquals(puts, s.calls.count { it == WireRoute.ACCOUNT_RECOVERY_PUT }, "nothing was sent without the box")
        assertEquals(RecoveryChangeResult.WRONG_PASSWORD, a.recovery.turnOnOperatorRecovery(warning, true, "not the password at all"))
        assertEquals("private", s.accounts.values.single().posture)
        assertEquals(RecoveryChangeResult.DONE, a.recovery.turnOnOperatorRecovery(recoveryScreen(a).warning!!, true, strong))
        assertEquals("operator", s.accounts.values.single().posture)
        assertEquals(fp, s.accounts.values.single().escrowFp, "the escrow is sealed to the card's key")
        val on = recoveryScreen(a)
        assertEquals(WhoCanRecover.ME_OR_OPERATOR, on.whoCanRecover, "as the account's own record says now")
        assertNull(on.warning)
        assertEquals(RecoveryChangeResult.STALE, a.recovery.turnOnOperatorRecovery(warning, true, strong), "a warning no longer on show")

        assertEquals(RecoveryChangeResult.DONE, a.recovery.turnOffOperatorRecovery(on, strong))
        assertEquals("private", s.accounts.values.single().posture)
        assertEquals(WhoCanRecover.ONLY_ME, recoveryScreen(a).whoCanRecover)
        a.recovery.closeRecovery()
        assertNull(a.snapshot.account!!.recovery)
    }

    @Test fun aCardWithoutARecoveryKeyOffersNoQuestion() = runBlocking<Unit> {
        val a = app(server(withKey = false))
        open(a)
        assertEquals(PlainResult.DONE, a.recovery.openRecovery())
        val screen = recoveryScreen(a)
        assertNull(screen.question)
        assertEquals(WhoCanRecover.ONLY_ME, screen.whoCanRecover)
        a.recovery.reviewOperatorRecovery(screen)
        assertNull(recoveryScreen(a).warning, "no warning without a question")
    }

    @Test fun aNewKitIsMadeBehindThePasswordAndShownOnTheKitScreen() = runBlocking<Unit> {
        val s = server()
        val a = app(s)
        open(a)
        assertEquals(RecoveryChangeResult.WRONG_PASSWORD, a.recovery.makeKit("not the password at all"))
        val before = s.accounts.values.single().pieceId
        assertEquals(RecoveryChangeResult.DONE, a.recovery.makeKit(strong))
        val kit = assertNotNull(a.snapshot.account!!.kit)
        assertEquals(KitReason.MADE_IN_SETTINGS, kit.reason)
        assertTrue(s.accounts.values.single().pieceId != before, "the old kit stopped working")
    }

    /**
     * §4.5 (T2-R-e): another device of the account, signed in with the password, finds the record saying `operator` and
     * no mirror of its own: it seals nothing and asks "Keep that?". "Not now" puts it off until the next unlock; turning
     * it off is the person's answer, behind the password.
     */
    @Test fun anotherDeviceAsksKeepThatAndSealsNothingByItself() = runBlocking<Unit> {
        val s = server()
        val a = app(s)
        open(a)
        assertEquals(PlainResult.DONE, a.recovery.openRecovery())
        a.recovery.reviewOperatorRecovery(recoveryScreen(a))
        assertEquals(RecoveryChangeResult.DONE, a.recovery.turnOnOperatorRecovery(recoveryScreen(a).warning!!, true, strong))
        assertTrue(a.snapshot.account!!.prompts.none { it is AccountPrompt.KeepOperatorRecovery }, "the device that chose it does not ask")

        val b = app(s)
        b.entry.openSignIn(b.at())
        b.entry.openPasswordSignIn(b.at())
        assertEquals(ServerResult.DONE, b.entry.chooseOwnServer(b.at(), s.origin))
        assertEquals(ServerResult.DONE, b.entry.confirmTrustGate(b.at<EntryScreen.TrustGate>()))
        val escrowPuts = s.calls.count { it == WireRoute.ESCROW_SELF }
        assertEquals(SignInAnswer.DONE, b.entry.submitSignIn(b.at(), "alice@example.com", strong))
        assertEquals(AppPhase.UNLOCKED, b.snapshot.phase)
        val asked = assertIs<AccountPrompt.KeepOperatorRecovery>(b.snapshot.account!!.prompts.single { it is AccountPrompt.KeepOperatorRecovery })
        assertEquals(escrowPuts, s.calls.count { it == WireRoute.ESCROW_SELF }, "nothing sealed by itself")

        b.recovery.keepOperatorRecoveryNotNow(asked)
        assertTrue(b.snapshot.account!!.prompts.none { it is AccountPrompt.KeepOperatorRecovery })
        b.lock()
        assertEquals(VaultUnlockResult.DONE, b.unlock(b.snapshot.locked!!, strong))
        val again = assertIs<AccountPrompt.KeepOperatorRecovery>(b.snapshot.account!!.prompts.single { it is AccountPrompt.KeepOperatorRecovery })
        assertEquals(RecoveryChangeResult.WRONG_PASSWORD, b.recovery.answerKeepOperatorRecovery(again, false, "not the password at all"))
        assertEquals(RecoveryChangeResult.DONE, b.recovery.answerKeepOperatorRecovery(again, false, strong))
        assertEquals("private", s.accounts.values.single().posture)
        assertTrue(b.snapshot.account!!.prompts.none { it is AccountPrompt.KeepOperatorRecovery })
        assertEquals(RecoveryChangeResult.STALE, b.recovery.answerKeepOperatorRecovery(again, true, strong))
    }

    /**
     * A server that no longer stores the form of recovery copy this app sealed refuses it as `escrow_wrong_form`: Settings
     * answers a result of its own with its sentence, and nothing changed. Before, it was a bare FAILED.
     */
    @Test fun aRecoveryCopyOfAFormTheServerNoLongerStoresIsSaidAsSuch() = runBlocking<Unit> {
        val s = server()
        var refuse = false
        val front = object : io.silencelen.andvari.core.client.net.WireClient by s {
            override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): io.silencelen.andvari.core.client.net.WireResult<T> {
                if (refuse && route == WireRoute.ACCOUNT_RECOVERY_PUT) {
                    return io.silencelen.andvari.core.client.net.WireResult.Refused(400, io.silencelen.andvari.core.model.wire.WireError(io.silencelen.andvari.core.model.wire.WireErrors.ESCROW_WRONG_FORM, "m"))
                }
                return s.call(route, pathParams, query, bodyJson, authenticated, decode)
            }
        }
        val a = app(s, front)
        open(a)
        assertEquals(PlainResult.DONE, a.recovery.openRecovery())
        a.recovery.reviewOperatorRecovery(recoveryScreen(a))
        refuse = true
        val r = a.recovery.turnOnOperatorRecovery(assertNotNull(recoveryScreen(a).warning), true, strong)
        assertEquals(RecoveryChangeResult.ESCROW_WRONG_FORM, r)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.ESCROW_WRONG_FORM, r.sentence)
        assertEquals("private", s.accounts.values.single().posture, "nothing changed")
    }

    /** The server, with the account-state read held until [gate] completes while [holds] says so (the posture read waits on it). */
    private class Held(val inner: FakeInstance) : io.silencelen.andvari.core.client.net.WireClient by inner {
        val gate = kotlinx.coroutines.CompletableDeferred<Unit>()
        var holds: () -> Boolean = { false }
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): io.silencelen.andvari.core.client.net.WireResult<T> {
            if (route == WireRoute.ACCOUNT_STATE_GET && holds()) gate.await()
            return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
        }
    }

    /**
     * The posture read at an opening survives a recomposition: "update required" composes the vault again while the read
     * waits, which cancelled it with the old vault's scope, and "Keep that?" never came in that session.
     */
    @Test fun thePostureReadAtAnOpeningSurvivesAVaultComposedAgain() = runBlocking<Unit> { kotlinx.coroutines.withTimeout(60_000) {
        val s = server()
        val a = app(s)
        open(a)
        assertEquals(PlainResult.DONE, a.recovery.openRecovery())
        a.recovery.reviewOperatorRecovery(recoveryScreen(a))
        assertEquals(RecoveryChangeResult.DONE, a.recovery.turnOnOperatorRecovery(recoveryScreen(a).warning!!, true, strong))

        val held = Held(s)
        val b = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(s.origin to held)), MemoryDeviceState(), MemoryDeviceState(), crypto,
                { s.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
        ).also {
            it.linksFlow.answersPollMs = Long.MAX_VALUE
            it.start()
        }
        b.entry.openSignIn(b.at())
        b.entry.openPasswordSignIn(b.at())
        assertEquals(ServerResult.DONE, b.entry.chooseOwnServer(b.at(), s.origin))
        assertEquals(ServerResult.DONE, b.entry.confirmTrustGate(b.at<EntryScreen.TrustGate>()))
        // Only the reads of the open vault wait.
        held.holds = { b.phase == AppPhase.UNLOCKED && !held.gate.isCompleted }
        assertEquals(SignInAnswer.DONE, b.entry.submitSignIn(b.at(), "alice@example.com", strong))
        assertEquals(AppPhase.UNLOCKED, b.snapshot.phase)
        val first = assertNotNull(b.vault)

        // "Update required" while the read waits: the vault is composed again at once.
        s.override[WireRoute.SYNC] = io.silencelen.andvari.core.client.net.WireResult.Refused(426,
            io.silencelen.andvari.core.model.wire.WireError(io.silencelen.andvari.core.model.wire.WireErrors.UPGRADE_REQUIRED, "m"))
        b.keeper.clientFor(s.origin).call(WireRoute.SYNC, authenticated = true) { it }
        assertTrue(assertNotNull(b.vault) !== first, "composed again")
        held.gate.complete(Unit)
        assertNotNull(b.snapshot.account!!.prompts.singleOrNull { it is AccountPrompt.KeepOperatorRecovery }, "asked in this session: ${b.snapshot.account!!.prompts}")
    } }

    /**
     * §8.5: on a device signed in with only the password, the people list names the
     * operator when the account's recovery record says operator. When this opening could not read that record, the clause
     * is shown as unknown, never dropped as if the record said "private".
     */
    @Test fun thePeopleListsOperatorClauseIsUnknownWhenTheRecoveryRecordCouldNotBeRead() = runBlocking<Unit> {
        val s = server()
        val a = app(s)
        open(a)
        assertEquals(PlainResult.DONE, a.recovery.openRecovery())
        a.recovery.reviewOperatorRecovery(recoveryScreen(a))
        assertEquals(RecoveryChangeResult.DONE, a.recovery.turnOnOperatorRecovery(recoveryScreen(a).warning!!, true, strong))
        a.vault!!.store.update { doc ->
            doc.copy(contacts = doc.contacts + ("22222222-2222-4222-8222-222222222222" to io.silencelen.andvari.core.client.state.ContactRecord(
                "22222222-2222-4222-8222-222222222222", io.silencelen.andvari.core.crypto.Bytes.toB64(crypto.randomBytes(32)),
                io.silencelen.andvari.core.trust.TrustGrammar.encodeName("Carol")!!, verifiedAt = s.now, compared = true,
                madeOn = "44444444-4444-4444-8444-444444444444")))
        }

        // Another device signs in with only the password.
        val b = app(s)
        b.entry.openSignIn(b.at())
        b.entry.openPasswordSignIn(b.at())
        assertEquals(ServerResult.DONE, b.entry.chooseOwnServer(b.at(), s.origin))
        (b.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, b.entry.confirmTrustGate(it)) }
        assertEquals(SignInAnswer.DONE, b.entry.submitSignIn(b.at(), "alice@example.com", strong))
        assertEquals(AppPhase.UNLOCKED, b.snapshot.phase)
        val known = b.snapshot.account!!.prompts.filterIsInstance<AccountPrompt.PeopleList>().single()
        assertTrue(known.operatorClauseKnown)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.PEOPLE_BODY_OPERATOR, known.body)

        // The next opening cannot read the record: the clause is unknown, and said so.
        b.lock()
        s.override[WireRoute.ACCOUNT_STATE_GET] = io.silencelen.andvari.core.client.net.WireResult.Refused(503, io.silencelen.andvari.core.model.wire.WireError("unavailable", "x"))
        assertEquals(VaultUnlockResult.DONE, b.unlock(b.snapshot.locked!!, strong))
        val unknown = b.snapshot.account!!.prompts.filterIsInstance<AccountPrompt.PeopleList>().single()
        assertTrue(!unknown.operatorClauseKnown)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.PEOPLE_BODY_OPERATOR_UNKNOWN, unknown.body, "never the body without the operator")
    }

    /**
     * Recovery: a lock while turning on operator recovery waits on the account
     * state. The escrow was sealed before that wait, and the guard refuses its send: STALE (it used to throw the guard's
     * KeysGoneException at the screen), nothing sent after the lock, the posture unchanged, and after the next unlock the
     * change is made as usual.
     */
    @Test fun aRecoveryChangeALockOvertakesAnswersStaleSendsNothingAfterTheLockAndTheAppStaysUsable() = runBlocking<Unit> {
        val s = server()
        val p = LockProbe(s)
        val a = app(s, p)
        open(a)
        assertEquals(PlainResult.DONE, a.recovery.openRecovery())
        a.recovery.reviewOperatorRecovery(recoveryScreen(a))
        val warning = assertNotNull(recoveryScreen(a).warning)
        var result: RecoveryChangeResult? = null
        with(p) { lockDuring(WireRoute.ACCOUNT_STATE_GET, { a.lock() }) { result = a.recovery.turnOnOperatorRecovery(warning, true, strong) } }
        assertEquals(emptyList(), p.crashes.map { it.toString() }, "the intent answers, it does not crash")
        assertEquals(RecoveryChangeResult.STALE, result)
        assertEquals(emptyList(), p.sentAfterLock(), "nothing is sent after the lock")
        assertEquals("private", s.accounts.values.single().posture)
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        assertEquals(PlainResult.DONE, a.recovery.openRecovery())
        a.recovery.reviewOperatorRecovery(recoveryScreen(a))
        assertEquals(RecoveryChangeResult.DONE, a.recovery.turnOnOperatorRecovery(recoveryScreen(a).warning!!, true, strong))
        assertEquals("operator", s.accounts.values.single().posture)
    }

    /** One action behind a re-authentication: [prepare] puts its screen on show (requests allowed), [act] answers for a wrong password. */
    private class Reauthed(val name: String, val prepare: suspend () -> Unit, val act: suspend (password: String) -> Any, val wrong: Any)

    /**
     * Spec 01 §7, "a wrong password sends nothing": EVERY action that asks for the master
     * password again proves it on this device first, so a wrong one sends NO request at all, of any route, before or
     * after the proof. Counted at the transport, so a read, a prelogin or a preview counts as much as the action itself.
     * The password change and the deletion are in `EngineSettingsTest`, two-step sign-in in `EngineTwoStepTest` (its
     * server wrapper serves the TOTP routes); here are the rest, then the right password still goes through.
     */
    @Test fun aWrongPasswordSendsNoRequestAtAllForEveryActionBehindAReauthentication() = runBlocking<Unit> {
        val s = server()
        val transport = BearerTransport(mapOf(s.origin to s))
        val a = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", transport, MemoryDeviceState(), MemoryDeviceState(), crypto,
                { s.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
        ).also {
            it.linksFlow.answersPollMs = Long.MAX_VALUE
            it.start()
        }
        open(a)
        val other = "22222222-2222-4222-8222-222222222222"
        val wrong = "not the password at all 3"
        val actions = listOf(
            Reauthed("a new kit (kit rotation)", { a.recovery.openRecovery() }, { pw -> a.recovery.makeKit(pw) }, RecoveryChangeResult.WRONG_PASSWORD),
            Reauthed("operator recovery on", {
                a.recovery.openRecovery()
                a.recovery.reviewOperatorRecovery(recoveryScreen(a))
            }, { pw -> a.recovery.turnOnOperatorRecovery(recoveryScreen(a).warning!!, true, pw) }, RecoveryChangeResult.WRONG_PASSWORD),
            Reauthed("operator recovery off", {
                a.recovery.openRecovery()
                a.recovery.reviewOperatorRecovery(recoveryScreen(a))
                assertEquals(RecoveryChangeResult.DONE, a.recovery.turnOnOperatorRecovery(recoveryScreen(a).warning!!, true, strong))
            }, { pw -> a.recovery.turnOffOperatorRecovery(recoveryScreen(a), pw) }, RecoveryChangeResult.WRONG_PASSWORD),
            Reauthed("revoking a device", {
                s.accounts.values.single().devices[other] = "secret"
                assertEquals(PlainResult.DONE, a.devices.openDevices())
            }, { pw -> a.devices.revokeDevice(a.snapshot.account!!.devices!!.devices.single { it.deviceId == other }, pw) },
                io.silencelen.andvari.core.app.ProofResult.WRONG_PASSWORD),
            Reauthed("new devices must be linked", { assertEquals(PlainResult.DONE, a.devices.openDevices()) },
                { pw -> a.devices.setRequireLink(true, pw) }, io.silencelen.andvari.core.app.ProofResult.WRONG_PASSWORD),
        )
        for (action in actions) {
            action.prepare()
            val before = transport.sent.size
            assertEquals(action.wrong, action.act(wrong), action.name)
            assertEquals(emptyList(), transport.sent.drop(before).map { it.route }, "${action.name}: a wrong password sends no request at all")
        }
        // The right password still goes through (the device's own proof does not refuse it).
        assertEquals(RecoveryChangeResult.DONE, a.recovery.turnOffOperatorRecovery(recoveryScreen(a), strong))
        assertEquals(io.silencelen.andvari.core.app.ProofResult.DONE, a.devices.revokeDevice(a.snapshot.account!!.devices!!.devices.single { it.deviceId == other }, strong))
    }
}
