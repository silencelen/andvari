package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.client.pin.TrustGateWording
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * Every state IF-3 declares is reachable through the fake, and the fake's plumbing (injected outcomes, holds, the
 * clock, observation) does what the apps' screens rely on.
 *
 * The `when`s below have no `else`: a new screen, prompt or card state does not compile until it has a tag here, and
 * then fails until a scene reaches it.
 */
class AppApiReachabilityTest {
    private enum class Screen {
        FIRST_RUN, INVITE_ENTRY, OWN_SERVER, TRUST_GATE, SERVER, JOIN_INVITE, NOT_TAKING_ACCOUNTS, SIGN_UP_EMAIL, SIGN_UP_CODE,
        CREATE_ACCOUNT, RECOVERY_WARNING, KIT, SERVER_SETUP, SIGN_IN_CHOICE, SIGN_IN_SERVER, SIGN_IN, LINK_REQUIRED,
        LINK_DEVICE_ENTRY, LINK_DEVICE_WAITING, LINK_DEVICE_CODE, LINK_DEVICE_PASSWORD, LINK_DEVICE_ENDED, FORGOT, KIT_ENTRY,
        KIT_RECOVER, REPLACE_PASSWORD, ASK_OPERATOR, OPERATOR_HELP, CHECK_ACCOUNT, SERVER_CHANGED, ADDRESS_MISMATCH,
    }

    private fun tag(s: EntryScreen): Screen = when (s) {
        is EntryScreen.FirstRun -> Screen.FIRST_RUN
        is EntryScreen.InviteEntry -> Screen.INVITE_ENTRY
        is EntryScreen.OwnServer -> Screen.OWN_SERVER
        is EntryScreen.TrustGate -> Screen.TRUST_GATE
        is EntryScreen.Server -> Screen.SERVER
        is EntryScreen.JoinInvite -> Screen.JOIN_INVITE
        is EntryScreen.NotTakingAccounts -> Screen.NOT_TAKING_ACCOUNTS
        is EntryScreen.SignUpEmail -> Screen.SIGN_UP_EMAIL
        is EntryScreen.SignUpCode -> Screen.SIGN_UP_CODE
        is EntryScreen.CreateAccount -> Screen.CREATE_ACCOUNT
        is EntryScreen.RecoveryWarning -> Screen.RECOVERY_WARNING
        is EntryScreen.Kit -> Screen.KIT
        is EntryScreen.ServerSetup -> Screen.SERVER_SETUP
        is EntryScreen.SignInChoice -> Screen.SIGN_IN_CHOICE
        is EntryScreen.SignInServer -> Screen.SIGN_IN_SERVER
        is EntryScreen.SignIn -> Screen.SIGN_IN
        is EntryScreen.LinkRequired -> Screen.LINK_REQUIRED
        is EntryScreen.LinkDeviceEntry -> Screen.LINK_DEVICE_ENTRY
        is EntryScreen.LinkDeviceWaiting -> Screen.LINK_DEVICE_WAITING
        is EntryScreen.LinkDeviceCode -> Screen.LINK_DEVICE_CODE
        is EntryScreen.LinkDevicePassword -> Screen.LINK_DEVICE_PASSWORD
        is EntryScreen.LinkDeviceEnded -> Screen.LINK_DEVICE_ENDED
        is EntryScreen.Forgot -> Screen.FORGOT
        is EntryScreen.KitEntry -> Screen.KIT_ENTRY
        is EntryScreen.KitRecover -> Screen.KIT_RECOVER
        is EntryScreen.ReplacePassword -> Screen.REPLACE_PASSWORD
        is EntryScreen.AskOperator -> Screen.ASK_OPERATOR
        is EntryScreen.OperatorHelp -> Screen.OPERATOR_HELP
        is EntryScreen.CheckAccount -> Screen.CHECK_ACCOUNT
        is EntryScreen.ServerChanged -> Screen.SERVER_CHANGED
        is EntryScreen.AddressMismatch -> Screen.ADDRESS_MISMATCH
    }

    private enum class Prompt {
        INCOMING_VAULT, KEY_CHANGED, NEW_PERSON, PEOPLE_LIST, RECOVERY_REQUEST, RECOVERY_KEY_CHANGED, KEEP_OPERATOR_RECOVERY,
        CONNECTION_NOT_MADE, FINISH_SERVER_SETUP,
    }

    private fun tag(p: AccountPrompt): Prompt = when (p) {
        is AccountPrompt.IncomingVault -> Prompt.INCOMING_VAULT
        is AccountPrompt.KeyChanged -> Prompt.KEY_CHANGED
        is AccountPrompt.NewPerson -> Prompt.NEW_PERSON
        is AccountPrompt.PeopleList -> Prompt.PEOPLE_LIST
        is AccountPrompt.RecoveryRequest -> Prompt.RECOVERY_REQUEST
        is AccountPrompt.RecoveryKeyChanged -> Prompt.RECOVERY_KEY_CHANGED
        is AccountPrompt.KeepOperatorRecovery -> Prompt.KEEP_OPERATOR_RECOVERY
        is AccountPrompt.ConnectionNotMade -> Prompt.CONNECTION_NOT_MADE
        is AccountPrompt.FinishServerSetup -> Prompt.FINISH_SERVER_SETUP
    }

    private enum class Card { OK, STOPPED, DAMAGED, WITHHELD, NOT_VERIFIED, MOVED, KIND_CHANGED, UPDATE_ANDVARI }

    private fun tag(c: InstanceCardState): Card = when (c) {
        is InstanceCardState.Ok -> Card.OK
        is InstanceCardState.Stopped -> Card.STOPPED
        is InstanceCardState.Damaged -> Card.DAMAGED
        is InstanceCardState.Withheld -> Card.WITHHELD
        is InstanceCardState.NotVerified -> Card.NOT_VERIFIED
        is InstanceCardState.Moved -> Card.MOVED
        is InstanceCardState.KindChanged -> Card.KIND_CHANGED
        is InstanceCardState.UpdateAndvari -> Card.UPDATE_ANDVARI
    }

    private enum class Compare { WAITING, READY, LINK_FAILED, MATCHED }

    private fun tag(c: CompareScreen): Compare = when (c) {
        is CompareScreen.Waiting -> Compare.WAITING
        is CompareScreen.Ready -> Compare.READY
        is CompareScreen.LinkFailed -> Compare.LINK_FAILED
        is CompareScreen.Matched -> Compare.MATCHED
    }

    private enum class Host { SHOWN, CLAIMED, TYPE_DIGITS, APPROVABLE, APPROVED, ENDED }

    private fun tag(h: DeviceLinkHost): Host = when (h) {
        is DeviceLinkHost.Shown -> Host.SHOWN
        is DeviceLinkHost.Claimed -> Host.CLAIMED
        is DeviceLinkHost.TypeDigits -> Host.TYPE_DIGITS
        is DeviceLinkHost.Approvable -> Host.APPROVABLE
        is DeviceLinkHost.Approved -> Host.APPROVED
        is DeviceLinkHost.Ended -> Host.ENDED
    }

    private enum class Opened { CONNECT, KEY_CHANGED, OTHER_INSTANCE, TRUST_GATE, SERVER_CHANGED, CONNECTED }

    private fun tag(o: OpenedInvite): Opened = when (o) {
        is OpenedInvite.Connect -> Opened.CONNECT
        is OpenedInvite.KeyChanged -> Opened.KEY_CHANGED
        is OpenedInvite.OtherInstance -> Opened.OTHER_INSTANCE
        is OpenedInvite.TrustGate -> Opened.TRUST_GATE
        is OpenedInvite.ServerChanged -> Opened.SERVER_CHANGED
        is OpenedInvite.Connected -> Opened.CONNECTED
    }

    private enum class Name { CONTACT, UNVERIFIED, YOU }

    private fun tag(n: PersonName): Name = when (n) {
        is PersonName.Contact -> Name.CONTACT
        is PersonName.Unverified -> Name.UNVERIFIED
        is PersonName.You -> Name.YOU
    }

    private fun every(): List<Pair<FakeScene, FakeAppApi>> =
        FakeScene.entries.map { it to if (FakeScenes.desktopOnly(it)) FakeScenes.desktopAt(it) else FakeScenes.at(it) }

    @Test
    fun everySceneStartsAndEverySealedStateIsReachedByOne() {
        val screens = HashSet<Screen>()
        val prompts = HashSet<Prompt>()
        val cards = HashSet<Card>()
        val compares = HashSet<Compare>()
        val hosts = HashSet<Host>()
        val opened = HashSet<Opened>()
        val names = HashSet<Name>()
        val logs = HashSet<VaultLogState>()
        val wordings = HashSet<TrustGateWording>()
        val kitSteps = HashSet<KitStep>()
        val phases = hashSetOf(FakeAppApi().snapshot.phase)
        val notices = HashSet<FirstRunNotice>()
        val mismatches = HashSet<AddressMismatchFor>()
        var kitGate = false
        var typedKitGate = false
        var oldData = false
        var lockedSeen = false
        for ((scene, app) in every()) {
            val s = app.snapshot
            assertNotEquals(AppPhase.STARTING, s.phase, scene.name)
            phases += s.phase
            // Each phase has its own part of the snapshot, and no other.
            assertEquals(s.phase == AppPhase.ENTRY, s.entry != null, scene.name)
            assertEquals(s.phase == AppPhase.LOCKED, s.locked != null, scene.name)
            assertEquals(s.phase == AppPhase.UNLOCKED, s.account != null, scene.name)
            lockedSeen = lockedSeen || s.locked != null
            oldData = oldData || s.oldData != null
            s.entry?.let { screens += tag(it) }
            (s.entry as? EntryScreen.FirstRun)?.notice?.let { notices += it }
            (s.entry as? EntryScreen.AddressMismatch)?.let { mismatches += it.opening }
            (s.entry as? EntryScreen.TrustGate)?.prompt?.let {
                wordings += it.wording
                kitGate = kitGate || it.kitIdentityChanged
                typedKitGate = typedKitGate || it.typedKit
                assertTrue(it.lines.isNotEmpty() && it.operatorKeyShort.length == 32, scene.name)
            }
            (s.account?.opened as? OpenedInvite.TrustGate)?.gate?.let { wordings += it.wording }
            (s.entry as? EntryScreen.Kit)?.kit?.let { kitSteps += it.step }
            s.instance?.card?.let {
                cards += tag(it)
                if (it is InstanceCardState.KindChanged) wordings += it.gate.wording
            }
            val a = s.account ?: continue
            a.prompts.forEach { prompts += tag(it) }
            a.vaults.forEach { logs += it.log }
            a.comparing?.let { compares += tag(it) }
            a.deviceLink?.let { hosts += tag(it) }
            a.opened?.let { opened += tag(it) }
            a.members?.members?.forEach { names += tag(it.who) }
            a.kit?.let { kitSteps += it.step }
        }
        assertEquals(Screen.entries.toSet(), screens)
        assertEquals(Prompt.entries.toSet(), prompts)
        assertEquals(Card.entries.toSet(), cards)
        assertEquals(Compare.entries.toSet(), compares)
        assertEquals(Host.entries.toSet(), hosts)
        assertEquals(Opened.entries.toSet(), opened)
        assertEquals(Name.entries.toSet(), names)
        assertEquals(VaultLogState.entries.toSet(), logs)
        assertEquals(TrustGateWording.entries.toSet(), wordings)
        assertEquals(KitStep.entries.toSet(), kitSteps)
        assertEquals(AppPhase.entries.toSet(), phases)
        assertTrue(kitGate, "the kit wording of the gate")
        assertTrue(typedKitGate, "the gate of a kit typed by hand")
        assertTrue(lockedSeen && oldData, "the lock screen, and old data that could not be removed")
        // The server-ended session has no scene of its own: it is walked in the entry tests.
        assertEquals(setOf(FirstRunNotice.RECOVERY_STOPPED), notices)
        assertEquals(setOf(AddressMismatchFor.TYPED_ADDRESS, AddressMismatchFor.KIT), mismatches)
    }

    @Test
    fun aDesktopOnlySceneOnAPhoneStaysAtTheFirstScreen() {
        val phone = FakeScenes.at(FakeScene.OPERATOR_CONSOLE)
        phone.on<EntryScreen.FirstRun>()
        // The operator views are not there to reach: only the desktop type has them.
        assertFalse((phone as AppApi) is DesktopAppApi)
        assertTrue((FakeScenes.desktopAt(FakeScene.FIRST_RUN) as AppApi) is DesktopAppApi)
    }

    /** One intent per result type: whatever outcome a test injects comes back, once, and nothing else happens. */
    @Test
    fun everyOutcomeOfEveryResultTypeCanBeInjected() {
        fun <R> each(values: List<R>, scene: FakeScene, staysPut: Boolean = true, call: suspend (FakeAppApi, R) -> R) where R : Enum<R>, R : IntentResult {
            for (value in values) {
                val app = if (FakeScenes.desktopOnly(scene)) FakeScenes.desktopAt(scene) else FakeScenes.at(scene)
                val before = app.snapshot
                app.script.forceNext(value)
                assertSame(value, await { call(app, value) }, "$value")
                if (!value.done && staysPut) assertSame(before.entry, app.snapshot.entry, "$value changed the screen")
            }
        }
        each(VaultUnlockResult.entries, FakeScene.LOCKED) { app, _ -> app.unlock(assertNotNull(app.snapshot.locked), PW) }
        each(InviteResult.entries, FakeScene.INVITE_ENTRY) { app, _ -> app.entry.submitInvite(app.on(), "x", PayloadSource.PASTED) }
        each(ServerResult.entries, FakeScene.OWN_SERVER) { app, _ -> app.entry.submitServerAddress(app.on(), "x") }
        each(SignUpStartResult.entries, FakeScene.SIGN_UP_EMAIL) { app, _ -> app.entry.startSignUp(app.on(), ADA, true) }
        each(CodeResult.entries, FakeScene.SIGN_UP_CODE) { app, _ -> app.entry.verifySignUpCode(app.on(), "1") }
        each(CreateAccountResult.entries, FakeScene.CREATE_ACCOUNT) { app, _ -> app.entry.createAccount(app.on(), NewAccountInput("", "A", PW, true)) }
        each(SignInAnswer.entries, FakeScene.SIGN_IN) { app, _ -> app.entry.submitSignIn(app.on(), ADA, PW) }
        each(SignInAnswer.entries, FakeScene.SIGN_IN_CODE_NEEDED) { app, _ -> app.entry.submitSignInCode(app.on(), "1") }
        each(DeviceLinkScanResult.entries, FakeScene.LINK_DEVICE_ENTRY) { app, _ -> app.entry.submitDeviceLink(app.on(), "x", PayloadSource.SCANNED) }
        each(LinkPasswordResult.entries, FakeScene.LINK_DEVICE_PASSWORD) { app, _ -> app.entry.submitLinkPassword(app.on(), PW) }
        each(KitScanResult.entries, FakeScene.KIT_ENTRY) { app, _ -> app.entry.submitKit(app.on(), "x", PayloadSource.SCANNED) }
        // A kit is proved once: any answer but "done" (or "stale") sends the journey back to where the kit is handed in.
        each(KitRecoverResult.entries, FakeScene.KIT_RECOVER, staysPut = false) { app, value ->
            app.entry.confirmKitRecovery(app.on()).also {
                if (!value.done && value != KitRecoverResult.STALE) app.on<EntryScreen.KitEntry>() else if (!value.done) app.on<EntryScreen.KitRecover>()
            }
        }
        each(ReplacePasswordResult.entries, FakeScene.REPLACE_PASSWORD) { app, _ -> app.entry.chooseReplacementPassword(app.on(), PW) }
        each(AskOperatorResult.entries, FakeScene.ASK_OPERATOR) { app, _ -> app.entry.requestOperatorHelp(app.on(), ADA) }
        each(KitConfirmResult.entries, FakeScene.KIT_CONFIRM) { app, _ -> app.kit.confirmKit(app.kitOnShow(), listOf("a", "b", "c")) }
        each(PlainResult.entries, FakeScene.VAULTS) { app, _ -> app.contacts.openContacts() }
        each(MoveResult.entries, FakeScene.CARD_MOVED) { app, _ -> app.instance.followMove(app.snapshot.instance?.card as InstanceCardState.Moved) }
        each(ComparisonResult.entries, FakeScene.COMPARE_READY) { app, _ -> app.contacts.submitComparison(app.account.comparing as CompareScreen.Ready, "1") }
        each(LinkCreateResult.entries, FakeScene.VAULTS) { app, _ -> app.links.createConnectLink(emptyList(), 15) }
        each(ConnectResult.entries, FakeScene.OPENED_CONNECT) { app, _ -> app.links.connect(app.account.opened as OpenedInvite.Connect) }
        each(VaultActionResult.entries, FakeScene.VAULTS) { app, _ -> app.vaults.createVault("x") }
        each(ProofResult.entries, FakeScene.VAULTS) { app, _ -> app.devices.setRequireLink(true, PW) }
        each(DigitsResult.entries, FakeScene.HOST_LINK_TYPE_DIGITS) { app, _ -> app.devices.submitDeviceDigits(app.account.deviceLink as DeviceLinkHost.TypeDigits, "1") }
        each(RecoveryChangeResult.entries, FakeScene.VAULTS) { app, _ -> app.recovery.makeKit(PW) }
        each(PasswordChangeResult.entries, FakeScene.VAULTS) { app, _ -> app.settings.changeMasterPassword(PW, "another master password") }
        each(DeletionResult.entries, FakeScene.DELETION) { app, _ -> app.settings.deleteAccount(assertNotNull(app.account.deletion), ADA, PW, null) }
        each(OperatorResult.entries, FakeScene.OPERATOR_CONSOLE) { app, _ -> (app as FakeDesktopAppApi).operatorApi.refreshConsole() }
    }

    /** Every result type has exactly one "done", and an entry for each trouble any intent can have. */
    @Test
    fun everyResultTypeCarriesEveryTrouble() {
        val all: List<List<IntentResult>> = listOf(
            InviteResult.entries, ServerResult.entries, SignUpStartResult.entries, CodeResult.entries, CreateAccountResult.entries,
            SignInAnswer.entries, DeviceLinkScanResult.entries, LinkPasswordResult.entries, KitScanResult.entries, KitRecoverResult.entries,
            ReplacePasswordResult.entries, AskOperatorResult.entries, KitConfirmResult.entries, PlainResult.entries, ComparisonResult.entries,
            LinkCreateResult.entries, ConnectResult.entries, VaultActionResult.entries, ProofResult.entries, DigitsResult.entries,
            RecoveryChangeResult.entries, PasswordChangeResult.entries, DeletionResult.entries, OperatorResult.entries,
            MoveResult.entries, VaultUnlockResult.entries,
        )
        for (type in all) {
            assertEquals(1, type.count { it.done }, "$type")
            assertNull(type.first { it.done }.trouble)
            for (trouble in Trouble.entries) assertEquals(1, type.count { it.trouble == trouble }, "$trouble in $type")
            // A sentence, where there is one, is a whole one: a result names nothing.
            for (result in type) result.sentence?.let { assertFalse(it.english.contains('{'), "$result") }
        }
    }

    @Test
    fun aTroubleCanBeInjectedIntoAnyIntentAndARateLimitSaysHowLongToWait() {
        val app = FakeScenes.at(FakeScene.SIGN_IN)
        val screen = app.on<EntryScreen.SignIn>()
        app.script.failNext(Trouble.UNREACHABLE)
        assertEquals(SignInAnswer.UNREACHABLE, await { app.entry.submitSignIn(screen, ADA, PW) })
        assertSame(screen, app.snapshot.entry)
        assertEquals(0, app.retryAfterSeconds())

        app.script.rateLimitNext(42)
        assertEquals(SignInAnswer.RATE_LIMITED, await { app.entry.submitSignIn(screen, ADA, PW) })
        assertEquals(Trouble.RATE_LIMITED, SignInAnswer.RATE_LIMITED.trouble)
        assertEquals(42, app.retryAfterSeconds())
        // The wait is counted on the fake's own clock, not on anything the person can set.
        app.script.advance(10_500)
        assertEquals(32, app.retryAfterSeconds())
        app.script.advance(60_000)
        assertEquals(0, app.retryAfterSeconds())
    }

    @Test
    fun aHeldIntentShowsBusyUntilItIsReleased(): Unit = runBlocking {
        val app = FakeScenes.at(FakeScene.VAULTS)
        app.script.holdNext()
        val job = async { app.vaults.createVault("Trips") }
        yield()
        assertTrue(app.snapshot.busy)
        assertTrue(app.script.holding)
        assertNull(app.account.vaults.firstOrNull { it.name == "Trips" })
        app.script.releaseHold()
        assertEquals(VaultActionResult.DONE, job.await())
        assertFalse(app.snapshot.busy)
        assertNotNull(app.account.vaults.firstOrNull { it.name == "Trips" })
    }

    @Test
    fun observersGetTheCurrentSnapshotThenEveryChangeUntilTheyClose() {
        val app = FakeAppApi()
        val seen = ArrayList<AppPhase>()
        val subscription = app.observe { seen += it.phase }
        assertEquals(listOf(AppPhase.STARTING), seen)
        app.start()
        assertEquals(AppPhase.ENTRY, seen.last())
        assertSame(app.snapshot, app.snapshots.value)
        val count = seen.size
        subscription.close()
        app.entry.openSignIn(app.on())
        assertEquals(count, seen.size)
    }

    @Test
    fun unchangedPartsOfASnapshotKeepTheirIdentitySoAnIntentStillTakesThem() {
        val app = FakeScenes.at(FakeScene.PROMPTS)
        val incoming = app.prompt<AccountPrompt.IncomingVault>()
        // Something unrelated changes and a new snapshot is published.
        assertEquals(PlainResult.DONE, await { app.devices.openDevices() })
        assertSame(incoming, app.prompt<AccountPrompt.IncomingVault>())
        assertEquals(VaultActionResult.DONE, await { app.vaults.acceptIncoming(incoming) })
        // Answered: it is gone, and it cannot be answered twice.
        assertFalse(app.hasPrompt<AccountPrompt.IncomingVault>())
        assertEquals(VaultActionResult.STALE, await { app.vaults.acceptIncoming(incoming) })
    }

    @Test
    fun theSameCallsGiveTheSameIdsCodesAndKits() {
        fun walk(): List<String> {
            val app = FakeScenes.at(FakeScene.KIT_REVEAL)
            val kit = assertNotNull(app.kit.kitDocument(app.kitOnShow()))
            val linked = FakeScenes.at(FakeScene.LINK_DEVICE_CODE)
            return kit.groups + kit.accountId + kit.qrPayload + linked.on<EntryScreen.LinkDeviceCode>().code
        }
        assertEquals(walk(), walk())
    }
}
