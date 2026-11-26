package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.QuickEnrolResult
import io.silencelen.andvari.core.app.QuickUnlockResult
import io.silencelen.andvari.core.app.QuickUnlockState
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.TwoStepResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.client.ClientPolicyClamps
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.originStopped
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.client.session.TestClocks
import io.silencelen.andvari.core.client.session.TestKeyWrap
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The account settings the screens wait for, on the engine: quick unlock, the client policy, the operator key's short form. */
class EngineSettingsTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    private class Env(val server: FakeInstance, val transport: BearerTransport, val state: MemoryDeviceState, val wrap: TestKeyWrap, val app: EngineAppApi)

    private fun env(withQuickUnlock: Boolean = true, alsoAt: List<String> = emptyList()): Env {
        val server = FakeInstance(crypto)
        val transport = BearerTransport(mapOf(server.origin to server) + alsoAt.associateWith { server })
        val state = MemoryDeviceState()
        val wrap = TestKeyWrap()
        val app = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", transport, state, MemoryDeviceState(), crypto, { server.now }, baked = null, storeBuild = false,
                stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
                keyWrap = if (withQuickUnlock) wrap else null, clocks = if (withQuickUnlock) TestClocks(wall = server.now) else null),
        ).also { it.start() }
        return Env(server, transport, state, wrap, app)
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    /** Typed address, Trust Gate, sign-up, kit: the vault is open. Returns the operator key's short form the gate showed. */
    private suspend fun open(a: EngineAppApi): String {
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        val gate = a.at<EntryScreen.TrustGate>()
        val shown = gate.prompt.operatorKeyShort
        assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(gate))
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
        return shown
    }

    @Test fun quickUnlockIsOfferedTurnedOnAndOpensTheLockedVaultSendingNothing() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        open(a)
        val setting = a.snapshot.account!!.quickUnlock
        assertEquals(QuickUnlockState.OFF, setting.state)
        assertTrue(setting.offerNow)
        assertEquals(QuickEnrolResult.DONE, a.settings.turnOnQuickUnlock(setting))
        val on = a.snapshot.account!!.quickUnlock
        assertEquals(QuickUnlockState.ON, on.state)
        assertFalse(on.offerNow)
        assertEquals(QuickEnrolResult.STALE, a.settings.turnOnQuickUnlock(setting), "only the setting on show")
        a.lock()
        val locked = assertNotNull(a.snapshot.locked)
        assertTrue(locked.quickUnlock)
        val sent = e.transport.sent.size
        assertEquals(QuickUnlockResult.DONE, a.quickUnlock(locked))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        // Opening the vault reads the policy again and syncs the vault's content with the kept session; there is no
        // password proof, no sign-in and no token refresh.
        val authRoutes = io.silencelen.andvari.core.model.wire.WireRoute.entries.filter { it.path.contains("/auth/") || it.name == "PASSWORD_CHANGE" }.toSet()
        val afterUnlock = e.transport.sent.drop(sent)
        assertTrue(afterUnlock.any { it.route == io.silencelen.andvari.core.model.wire.WireRoute.CLIENT_POLICY && it.bearer == null })
        assertTrue(afterUnlock.none { it.route in authRoutes }, "sent: ${afterUnlock.map { it.route }}")
        assertEquals(QuickUnlockResult.STALE, a.quickUnlock(locked))

        // Turned off, the lock screen has the password only.
        a.settings.turnOffQuickUnlock(a.snapshot.account!!.quickUnlock)
        assertEquals(QuickUnlockState.OFF, a.snapshot.account!!.quickUnlock.state)
        a.lock()
        assertFalse(a.snapshot.locked!!.quickUnlock)
        assertEquals(QuickUnlockResult.USE_PASSWORD, a.quickUnlock(a.snapshot.locked!!))
    }

    @Test fun underAForkItOpensReadOnlyAndUnderADamagedPinItIsRefused() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        open(a)
        assertEquals(QuickEnrolResult.DONE, a.settings.turnOnQuickUnlock(a.snapshot.account!!.quickUnlock))
        a.lock()
        val store = PinStore(e.state)
        store.markForked(store.get(e.server.origin)!!)
        val sent = e.transport.sent.size
        assertEquals(QuickUnlockResult.DONE, a.quickUnlock(a.snapshot.locked!!))
        assertTrue(a.snapshot.account!!.serverStopped)
        assertEquals(sent, e.transport.sent.size, "nothing at all is dialed at a forked server")
        assertFalse(a.snapshot.account!!.quickUnlock.offerNow)
        a.lock()
        e.state.set(PinStore.KEY_PREFIX + e.server.origin, "not a pin record")
        val prompts = e.wrap.prompts
        assertEquals(QuickUnlockResult.SERVER_BLOCKED, a.quickUnlock(a.snapshot.locked!!))
        assertEquals(prompts, e.wrap.prompts, "no prompt under a damaged pin")
        assertEquals(VaultUnlockResult.SERVER_BLOCKED, a.unlock(a.snapshot.locked!!, strong))
    }

    /** Design §4.4: a pin damaged while the vault is open stops the server as a fork does, and nothing is dialed. */
    @Test fun aPinDamagedWhileOpenStopsTheServerAndItsDialing() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        open(a)
        assertTrue(a.mayDial(e.server.origin))
        assertFalse(a.snapshot.account!!.serverStopped)
        e.state.set(PinStore.KEY_PREFIX + e.server.origin, "not a pin record")
        a.publish()
        assertTrue(a.snapshot.account!!.serverStopped)
        assertFalse(a.snapshot.account!!.quickUnlock.offerNow)
        assertFalse(a.mayDial(e.server.origin))
    }

    /**
     * The newest verified card names this account as operator (a handover): a phone stops using it and keeps it locked
     * (§12.2 rule 7 as the owner decided on 2026-11-16).
     */
    private fun makeOperatorInPin(e: Env, userId: String) {
        val store = PinStore(e.state)
        store.put(store.get(e.server.origin)!!.copy(operator = userId))
    }

    private fun assertSignedOutAsOperator(e: Env) {
        val a = e.app
        assertEquals(AppPhase.ENTRY, a.snapshot.phase)
        val first = a.at<EntryScreen.FirstRun>()
        assertEquals(io.silencelen.andvari.core.app.FirstRunNotice.OPERATOR_NEEDS_COMPUTER, first.notice)
        kotlin.test.assertNotNull(first.heldAsOperator, "the account is on the first screen, held")
        assertNull(a.snapshot.account)
        assertTrue(kotlin.test.assertNotNull(a.keeper.session, "the copy is kept, locked").heldAsOperator)
        assertNull(a.keeper.established)
        assertEquals(0, e.transport.bearersFor(io.silencelen.andvari.core.model.wire.WireRoute.LOGOUT).size, "nothing is sent with it, not even a logout")
    }

    @Test fun aCardNamingTheAccountAsOperatorSignsAPhoneOutAtThePasswordUnlock() = runBlocking<Unit> {
        val e = env(withQuickUnlock = false)
        val a = e.app
        open(a)
        a.lock()
        makeOperatorInPin(e, a.keeper.session!!.userId)
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        assertSignedOutAsOperator(e)
    }

    @Test fun aCardNamingTheAccountAsOperatorSignsAPhoneOutAtAQuickUnlock() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        open(a)
        assertEquals(QuickEnrolResult.DONE, a.settings.turnOnQuickUnlock(a.snapshot.account!!.quickUnlock))
        a.lock()
        makeOperatorInPin(e, a.keeper.session!!.userId)
        assertEquals(QuickUnlockResult.DONE, a.quickUnlock(a.snapshot.locked!!))
        assertSignedOutAsOperator(e)
    }

    @Test fun aCardNamingAnotherAccountAsOperatorChangesNothing() = runBlocking<Unit> {
        val e = env(withQuickUnlock = false)
        val a = e.app
        open(a)
        a.lock()
        makeOperatorInPin(e, "0b0b0b0b-0000-4000-8000-000000000001")
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    /** The operator signs the next card of [s]'s chain, at [origin] and of [kind]. */
    private fun nextCard(s: FakeInstance, origin: String, kind: io.silencelen.andvari.core.trust.InstanceKind = s.kind) {
        s.cards += io.silencelen.andvari.core.trust.InstanceCard.sign(
            crypto, s.operatorSign,
            io.silencelen.andvari.core.trust.CardFields(
                s.instanceId, s.cards.size.toLong(), io.silencelen.andvari.core.trust.SignedFrame.hash(crypto, s.cards.last()), origin, "Home", kind,
                "99999999-9999-4999-8999-999999999999", io.silencelen.andvari.core.crypto.Bytes.toB64(s.operatorSign.publicKey), s.recoveryFp,
                s.now - 10_000 + s.cards.size * 1_000L,
            ),
        )
    }

    /** §4.4: a move onto an address this device already pins is refused; forgetting that server lets it be followed. */
    @Test fun aMoveOntoAnAddressAlreadyPinnedIsFollowedOnceThatServerIsForgotten() = runBlocking<Unit> {
        val moved = "https://moved.example"
        val e = env(alsoAt = listOf(moved))
        val a = e.app
        open(a)
        val store = PinStore(e.state)
        store.put(store.get(e.server.origin)!!.copy(origin = moved, instanceId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"))
        nextCard(e.server, moved)
        (a.instance as EngineInstance).refresh()
        val first = assertIs<io.silencelen.andvari.core.app.InstanceCardState.Moved>(a.snapshot.instance!!.card)
        assertEquals(io.silencelen.andvari.core.app.MoveResult.ALREADY_PINNED_THERE, a.instance.followMove(first))
        assertNotNull(store.get(moved), "the other server's pin is untouched")
        val pinned = assertIs<io.silencelen.andvari.core.app.InstanceCardState.Moved>(a.snapshot.instance!!.card)
        assertTrue(pinned.alreadyPinnedThere)
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.instance.forgetServerAtNewAddress(pinned))
        assertNull(store.get(moved))
        val again = assertIs<io.silencelen.andvari.core.app.InstanceCardState.Moved>(a.snapshot.instance!!.card)
        assertFalse(again.alreadyPinnedThere)
        assertEquals(io.silencelen.andvari.core.app.MoveResult.DONE, a.instance.followMove(again))
        assertEquals(moved, a.keeper.session!!.origin)
    }

    /** A move refused for a pin at the new address is judged again from the chain when it is tried again. */
    @Test fun aRefusedMoveIsJudgedAgainFromTheChainWhenTriedAgain() = runBlocking<Unit> {
        val moved = "https://moved.example"
        val e = env(alsoAt = listOf(moved))
        val a = e.app
        open(a)
        val store = PinStore(e.state)
        store.put(store.get(e.server.origin)!!.copy(origin = moved, instanceId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"))
        nextCard(e.server, moved)
        (a.instance as EngineInstance).refresh()
        val first = assertIs<io.silencelen.andvari.core.app.InstanceCardState.Moved>(a.snapshot.instance!!.card)
        assertEquals(io.silencelen.andvari.core.app.MoveResult.ALREADY_PINNED_THERE, a.instance.followMove(first))
        // The other pin goes some other way (say, forgotten from its own screen): the shown card is tried again.
        store.remove(moved)
        val shown = assertIs<io.silencelen.andvari.core.app.InstanceCardState.Moved>(a.snapshot.instance!!.card)
        assertEquals(io.silencelen.andvari.core.app.MoveResult.DONE, a.instance.followMove(shown))
        assertEquals(moved, a.keeper.session!!.origin)
    }

    /** "Not now" on a kind change: nothing is sent or stored, the old kind stays, and the gate is put off. */
    @Test fun aKindChangePutOffKeepsTheOldKind() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        open(a)
        nextCard(e.server, e.server.origin, io.silencelen.andvari.core.trust.InstanceKind.PUBLIC)
        (a.instance as EngineInstance).refresh()
        val changed = assertIs<io.silencelen.andvari.core.app.InstanceCardState.KindChanged>(a.snapshot.instance!!.card)
        assertFalse(changed.putOff)
        val sent = e.transport.sent.size
        a.instance.kindChangeNotNow(changed)
        assertTrue(assertIs<io.silencelen.andvari.core.app.InstanceCardState.KindChanged>(a.snapshot.instance!!.card).putOff)
        assertEquals("private", PinStore(e.state).get(e.server.origin)!!.kind, "the old kind stays in force")
        assertEquals(sent, e.transport.sent.size, "nothing is sent")
    }

    /** §4.4: a followed move takes the session's namespace, and its tokens, to the new address and nowhere else. */
    @Test fun aFollowedMoveTakesTheSessionToTheNewAddress() = runBlocking<Unit> {
        val moved = "https://moved.example"
        val e = env(alsoAt = listOf(moved))
        val a = e.app
        open(a)
        val s = e.server
        val home = s.origin
        nextCard(s, moved)
        assertIs<io.silencelen.andvari.core.client.pin.CardStatus.Moved>((a.instance as EngineInstance).refresh())
        val card = assertIs<io.silencelen.andvari.core.app.InstanceCardState.Moved>(a.snapshot.instance!!.card)
        assertEquals(io.silencelen.andvari.core.app.MoveResult.DONE, a.instance.followMove(card))
        assertEquals(moved, a.keeper.session!!.origin)
        assertEquals(moved, a.keeper.established!!.origin)
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        assertNotNull(a.snapshot.account!!.kitAfterMove, "a kit made before the move names the old address")
        // The bell's socket comes from the transport's dialer, asked anew for the new address (spec 03 §6).
        assertEquals(home, e.transport.bellsAsked.first())
        assertEquals(moved, e.transport.bellsAsked.last(), "the vault composed at the new address asked for its own socket")
        val route = io.silencelen.andvari.core.model.wire.WireRoute.ACCOUNT_STATE_GET
        a.keeper.clientFor(moved).call(route, authenticated = true) { it }
        assertEquals(moved, e.transport.sent.last().origin)
        assertNotNull(e.transport.sent.last().bearer, "the session's bearer goes to the new address")
        // The old address holds no pin any more, so nothing that carries a credential is sent there at all (design §4.4).
        val sentBefore = e.transport.sent.size
        assertTrue(a.keeper.clientFor(home).call(route, authenticated = true) { it }.originStopped, "the old address is stopped")
        assertEquals(sentBefore, e.transport.sent.size, "and nothing went to it")
    }

    @Test fun withoutAPlatformKeyThereIsNoQuickUnlock() = runBlocking<Unit> {
        val e = env(withQuickUnlock = false)
        val a = e.app
        open(a)
        val setting = a.snapshot.account!!.quickUnlock
        assertEquals(QuickUnlockState.UNAVAILABLE, setting.state)
        assertFalse(setting.offerNow)
        assertEquals(QuickEnrolResult.NOT_AVAILABLE, a.settings.turnOnQuickUnlock(setting))
        a.lock()
        assertFalse(a.snapshot.locked!!.quickUnlock)
        assertEquals(QuickUnlockResult.USE_PASSWORD, a.quickUnlock(a.snapshot.locked!!))
    }

    /**
     * Before this device ever read the server's policy the times are the defaults (lock
     * after 5 minutes, clear the clipboard after 30 seconds), not the ceilings; a policy kept from an earlier session is
     * used until a new one is read.
     */
    @Test fun beforeThePolicyIsReadTheTimesAreTheDefaultsAndAKeptPolicyIsUsedUntilANewOneIsRead() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val route = io.silencelen.andvari.core.model.wire.WireRoute.CLIENT_POLICY
        val served = assertIs<io.silencelen.andvari.core.client.net.WireResult.Ok<String>>(server.call(route, emptyMap(), null, null, false) { it }).value
        val longer = served.replace("\"autoLockSeconds\":300", "\"autoLockSeconds\":600").replace("\"clipboardClearSeconds\":30", "\"clipboardClearSeconds\":60")
        assertTrue(longer != served, "the served policy names 300 and 30: $served")
        server.override[route] = io.silencelen.andvari.core.client.net.WireResult.Ok(longer, 200)
        val transport = BearerTransport(mapOf(server.origin to server))
        val state = MemoryDeviceState()
        val secure = MemoryDeviceState()
        fun process() = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", transport, state, secure, crypto, { server.now }, baked = null, storeBuild = false,
                stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
        ).also { it.start() }
        val a = process()
        open(a)
        assertEquals(600, a.snapshot.account!!.policy.autoLockSeconds)
        assertEquals(60, a.snapshot.account!!.policy.clipboardClearSeconds)
        a.lock()

        // A new process, the server not answering: the kept policy is used.
        server.override[route] = io.silencelen.andvari.core.client.net.WireResult.NoAnswer(io.silencelen.andvari.core.client.net.NoAnswerKind.TRANSPORT)
        val b = process()
        assertEquals(VaultUnlockResult.DONE, b.unlock(b.snapshot.locked!!, strong))
        val kept = b.snapshot.account!!.policy
        assertTrue(kept.known)
        assertEquals(600, kept.autoLockSeconds)
        assertEquals(60, kept.clipboardClearSeconds)
        b.lock()

        // No policy ever read on this device (its record gone), still no answer: the defaults, not the ceilings.
        state.set(io.silencelen.andvari.core.client.session.KeptPolicies.KEY_PREFIX + server.origin, null)
        val c = process()
        assertEquals(VaultUnlockResult.DONE, c.unlock(c.snapshot.locked!!, strong))
        val unknown = c.snapshot.account!!.policy
        assertFalse(unknown.known)
        assertEquals(300, unknown.autoLockSeconds)
        assertEquals(30, unknown.clipboardClearSeconds)
        assertFalse(unknown.offlineCacheAllowed, "keys at rest still count as forbidden")
    }

    /**
     * "Update required" is a state of the session's server a screen reads. It closes nothing,
     * survives a request that got no answer or an answer on a route the server does not check the version on, and
     * clears at the next answer on a version-checked route that is not one. While it stands the open vault is read-only
     * from its copy (the Android app needs it so), and it is writable again once it clears.
     */
    @Test fun updateRequiredIsAStateOfTheSessionsServerThatClosesNothingAndClearsByItself() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        open(a)
        assertFalse(a.snapshot.instance!!.updateRequired)
        val route = WireRoute.SYNC
        assertTrue(route.versionChecked)
        val origin = e.server.origin
        suspend fun ask(r: WireRoute = route) = a.keeper.clientFor(origin).call(r, authenticated = true) { it }
        val tooOld = io.silencelen.andvari.core.client.net.WireResult.Refused(426,
            io.silencelen.andvari.core.model.wire.WireError(io.silencelen.andvari.core.model.wire.WireErrors.UPGRADE_REQUIRED, "m"))
        e.server.override[route] = tooOld
        val before = assertNotNull(a.vault)
        assertFalse(before.haltedForUpdate)
        ask()
        val shown = a.snapshot.instance!!
        assertTrue(shown.updateRequired)
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase, "the vault stays open")
        assertNotNull(a.content, "and its copy too")
        assertTrue(assertNotNull(a.vault).haltedForUpdate, "composed again, read-only")
        assertTrue(a.content!!.state.serverStopped, "nothing can be saved while it stands")
        // No answer says nothing, and neither does a route the server answers whatever the build (the client policy).
        e.server.override[route] = io.silencelen.andvari.core.client.net.WireResult.NoAnswer(io.silencelen.andvari.core.client.net.NoAnswerKind.TRANSPORT)
        ask()
        assertTrue(a.snapshot.instance!!.updateRequired)
        assertFalse(WireRoute.CLIENT_POLICY.versionChecked)
        assertIs<io.silencelen.andvari.core.client.net.WireResult.Ok<String>>(a.keeper.clientFor(origin).call(WireRoute.CLIENT_POLICY, authenticated = false) { it })
        assertTrue(a.snapshot.instance!!.updateRequired, "the policy read says nothing about it")
        // A lock keeps it: it is the server's state, not the vault's. The unlock composes as usual; its first sync,
        // refused again, makes the copy read-only again.
        e.server.override[route] = tooOld
        a.lock()
        assertTrue(a.snapshot.instance!!.updateRequired)
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        assertTrue(assertNotNull(a.vault).haltedForUpdate, "read-only again after the unlock's first sync")
        // A later answer on a version-checked route that is not "update required" clears it, and the copy is writable.
        e.server.override[route] = io.silencelen.andvari.core.client.net.WireResult.NoAnswer(io.silencelen.andvari.core.client.net.NoAnswerKind.TRANSPORT)
        assertTrue(WireRoute.LINK_ACK.versionChecked)
        e.server.override[WireRoute.LINK_ACK] = io.silencelen.andvari.core.client.net.WireResult.Ok("{}", 200)
        ask(WireRoute.LINK_ACK)
        assertFalse(a.snapshot.instance!!.updateRequired)
        assertFalse(assertNotNull(a.vault).haltedForUpdate)
        assertFalse(a.content!!.state.serverStopped)
        // Signed out, no server carries it, whatever that server last answered.
        e.server.override[route] = io.silencelen.andvari.core.client.net.WireResult.Refused(426,
            io.silencelen.andvari.core.model.wire.WireError(io.silencelen.andvari.core.model.wire.WireErrors.UPGRADE_REQUIRED, "m"))
        ask()
        assertTrue(a.snapshot.instance!!.updateRequired)
        a.signOut()
        assertTrue(a.snapshot.instance?.updateRequired != true)
    }

    @Test fun thePolicyIsOnTheSnapshotClampedAndKeepsItsIdentity() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        open(a)
        val policy = a.snapshot.account!!.policy
        assertTrue(policy.known)
        assertEquals(300, policy.autoLockSeconds)
        assertEquals(30, policy.clipboardClearSeconds)
        assertTrue(policy.offlineCacheAllowed)
        assertEquals(1L, policy.attachmentMaxBytes)
        a.lock()
        a.unlock(a.snapshot.locked!!, strong)
        assertTrue(policy === a.snapshot.account!!.policy, "an unchanged policy is the same object")
        assertTrue(ClientPolicyClamps.AUTO_LOCK_MAX_SECONDS >= policy.autoLockSeconds)
    }

    @Test fun instanceDetailsShowTheOperatorKeyAsTheTrustGateDid() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        val shown = open(a)
        assertTrue(shown.isNotEmpty())
        assertEquals(shown, a.snapshot.instance!!.details.operatorKeyShort, "one key, one short form")
    }

    /** Two-step sign-in is bound ([EngineTwoStepTest]); a server that does not answer its route leaves the screen shut. */
    @Test fun twoStepAtAServerThatDoesNotAnswerStaysShut() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        open(a)
        assertNull(a.snapshot.account!!.twoStep)
        assertNull(a.snapshot.account!!.kitAfterMove)
        assertEquals(io.silencelen.andvari.core.app.PlainResult.UNREACHABLE, a.settings.openTwoStep())
        assertNull(a.snapshot.account!!.twoStep)
        a.lock()
        assertEquals(io.silencelen.andvari.core.app.PlainResult.STALE, a.settings.openTwoStep())
        assertEquals(TwoStepResult.STALE, a.settings.turnOffTwoStep(io.silencelen.andvari.core.app.TwoStepScreen(false, null), "123456"))
    }

    /**
     * Change master password on the engine: behind the current password, sent to the session's own server only, with
     * no new kit due (the account's key is unchanged). This device's copy then opens with the new password, not the old.
     */
    @Test fun theMasterPasswordIsChangedBehindTheCurrentOneAndThisDevicesCopyFollows() = runBlocking<Unit> {
        val e = env(withQuickUnlock = false)
        val a = e.app
        open(a)
        val account = e.server.accounts.values.single()
        val before = account.wrappedUvk
        val newer = "a whole New master password 7 here"
        assertEquals(io.silencelen.andvari.core.app.PasswordChangeResult.WRONG_PASSWORD, a.settings.changeMasterPassword("not the password at all", newer))
        val puts = e.server.calls.count { it == WireRoute.PASSWORD_CHANGE }
        assertEquals(io.silencelen.andvari.core.app.PasswordChangeResult.WEAK_PASSWORD, a.settings.changeMasterPassword(strong, "short"))
        assertEquals(puts, e.server.calls.count { it == WireRoute.PASSWORD_CHANGE }, "a weak password is refused here")
        assertEquals(before, account.wrappedUvk)

        assertEquals(io.silencelen.andvari.core.app.PasswordChangeResult.DONE, a.settings.changeMasterPassword(strong, newer))
        assertTrue(account.wrappedUvk != before, "the server holds the new wrap")
        assertNull(a.snapshot.account!!.kit, "no new kit is due")
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        a.lock()
        assertEquals(VaultUnlockResult.WRONG_PASSWORD, a.unlock(a.snapshot.locked!!, strong), "the old password no longer opens this device's copy")
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, newer))
        // And the server takes the new one: the next change re-authenticates with it.
        assertEquals(io.silencelen.andvari.core.app.PasswordChangeResult.DONE, a.settings.changeMasterPassword(newer, strong))
        a.lock()
        assertEquals(io.silencelen.andvari.core.app.PasswordChangeResult.STALE, a.settings.changeMasterPassword(strong, newer), "locked")
    }

    /**
     * After a change from this device, the device keeps the very wrap the server took (its
     * salt, its cost), not a second one of its own, so the copy cannot fail to follow the new password and every later
     * re-authentication proves the password against the wrap the server holds too.
     */
    @Test fun aChangeKeepsTheWrapTheServerTookAsThisDevicesOwn() = runBlocking<Unit> {
        val e = env(withQuickUnlock = false)
        val a = e.app
        open(a)
        val account = e.server.accounts.values.single()
        val before = account.wrappedUvk
        val newer = "a whole New master password 7 here"
        // The wrap was made before the request went, so no KDF runs after the answer and the
        // copy here always follows.
        assertEquals(io.silencelen.andvari.core.app.PasswordChangeResult.DONE, a.settings.changeMasterPassword(strong, newer))
        assertTrue(account.wrappedUvk != before, "the server holds the new password")
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        a.lock()
        assertTrue(!a.snapshot.locked!!.previousPasswordOpensCopy, "the copy here follows: no line on the lock screen")
        assertEquals(VaultUnlockResult.WRONG_PASSWORD, a.unlock(a.snapshot.locked!!, strong))
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, newer), "the new one opens it")
        val kept = assertNotNull(a.keeper.established).accountKeys
        assertEquals(account.wrappedUvk, kept.wrappedUvk, "this device's wrap is the server's")
        assertEquals(account.kdfSalt, kept.kdfSalt)
    }

    /**
     * Spec 01 §7: a re-authentication proves the password on
     * this device first. A wrong password reaches no server: no prelogin, no request, no signed leave.
     */
    @Test fun aWrongPasswordBehindAReauthenticationReachesNoServer() = runBlocking<Unit> {
        val e = env(withQuickUnlock = false)
        val a = e.app
        open(a)
        val wrong = "not the password at all 3"
        val reauthRoutes = setOf(WireRoute.PRELOGIN, WireRoute.PASSWORD_CHANGE, WireRoute.ACCOUNT_DELETE, WireRoute.REQUIRE_LINK)

        // The master password change.
        e.server.calls.clear()
        assertEquals(io.silencelen.andvari.core.app.PasswordChangeResult.WRONG_PASSWORD, a.settings.changeMasterPassword(wrong, "a whole New master password 7 here"))
        assertTrue(e.server.calls.none { it in reauthRoutes }, "sent: ${e.server.calls}")

        // "New devices must be linked".
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.devices.openDevices())
        e.server.calls.clear()
        assertEquals(io.silencelen.andvari.core.app.ProofResult.WRONG_PASSWORD, a.devices.setRequireLink(true, wrong))
        assertTrue(e.server.calls.none { it in reauthRoutes }, "sent: ${e.server.calls}")

        // The account's deletion, with its signed leaves: nothing is fetched for it, signed or sent.
        e.server.override[WireRoute.ACCOUNT_DELETE_PREVIEW] = io.silencelen.andvari.core.client.net.WireResult.Ok(
            """{"blockers":[],"deletedVaults":[],"leftVaults":[],"memberships":[],"totpRequired":false}""", 200)
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.settings.openDeletion())
        e.server.calls.clear()
        val screen = assertNotNull(a.snapshot.account!!.deletion)
        assertEquals(io.silencelen.andvari.core.app.DeletionResult.WRONG_PASSWORD, a.settings.deleteAccount(screen, "alice@example.com", wrong, null))
        assertTrue(e.server.calls.none { it in reauthRoutes || it == WireRoute.ACCOUNT_DELETE_PREVIEW }, "sent: ${e.server.calls}")

        // The right password still goes through, derived under the session's own salt.
        assertEquals(io.silencelen.andvari.core.app.PasswordChangeResult.DONE, a.settings.changeMasterPassword(strong, "a whole New master password 7 here"))
        assertTrue(e.server.calls.none { it == WireRoute.PRELOGIN }, "no prelogin: the device's own salt and cost")
    }
}
