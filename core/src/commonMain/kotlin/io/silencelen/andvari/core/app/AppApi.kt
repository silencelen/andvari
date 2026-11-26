package io.silencelen.andvari.core.app

import kotlinx.coroutines.flow.StateFlow

/**
 * IF-3, the app API of the onboarding and trust design (docs/design/2026-11-15-onboarding-trust.md §18.1): what the
 * Android, iOS and desktop apps build their screens against. The engine-backed controller implements it;
 * [io.silencelen.andvari.core.app.fake.FakeAppApi] implements all of it in memory, for previews and UI tests.
 *
 * ## Shape
 *
 * - **State is one immutable [AppSnapshot]**, read with [snapshot], collected with [snapshots] (Compose), or observed
 *   with [observe] (SwiftUI). A snapshot never carries a secret: a kit's secret and a link to share are read through
 *   explicit calls, and a code exists only in the one state that may show it.
 * - **Intents are functions.** A `suspend` intent talks to the server or does real work; it returns an
 *   [IntentResult] that says what to show in place, and the screen that follows is in the next snapshot. No intent
 *   throws, except a `suspend` intent's `CancellationException`.
 * - **Every state is made by core alone** (internal constructors). A UI gets one from a snapshot and hands it back to
 *   the intent it belongs to; it cannot build one.
 * - **A state that did not change is the same object in the next snapshot.** Every object a UI can hand back to an
 *   intent (an entry screen, the lock screen, a prompt, a row, a card state, an instance, a warning, a kit or a
 *   comparison screen) keeps its identity from snapshot to snapshot until something it shows changes, and an intent
 *   takes it only while it is the very object on show (anything else answers [Trouble.STALE]). So a snapshot
 *   published for another reason (an intent started, a list elsewhere changed) never invalidates what a UI holds,
 *   and a UI may compare by identity to see what changed.
 *
 * ## The rules the types enforce
 *
 * An intent that does something security-relevant takes the state it acts on as its first parameter, and that state
 * exists only once the step before it has happened. So a UI cannot call the intent early, whatever it does:
 *
 * 1. **The password rule (§4.4, T2-B1).** A master password, a one-time code, a kit and a new master password are
 *    taken, signed out, only by [EntryApi.submitSignIn], [EntryApi.submitLinkPassword], [EntryApi.confirmKitRecovery],
 *    [EntryApi.chooseReplacementPassword] and [EntryApi.createAccount]. Each needs a screen ([EntryScreen.SignIn],
 *    [EntryScreen.LinkDevicePassword], [EntryScreen.KitRecover], [EntryScreen.ReplacePassword],
 *    [EntryScreen.CreateAccount]) that core publishes only after the password gate answered `proceed` for that
 *    purpose, origin and account; a `trust_gate` answer publishes [EntryScreen.TrustGate] first. Where the account
 *    is typed on the screen itself ([EntryScreen.SignIn]), the screen needs a pin that can serve some account and
 *    the intent asks the gate again with the typed address before it sends anything. Signed in, a password goes
 *    with a re-authenticated intent to the session's own origin, which is the rule's first case.
 * 2. **Three scanners, three jobs (§12.1, FS-B1).** An invite is taken by [EntryApi.submitInvite],
 *    [LinksApi.openInvite] and [AppApi.openAppLink]; a device link only by [EntryApi.submitDeviceLink], which needs
 *    [EntryScreen.LinkDeviceEntry]; a kit only by [EntryApi.submitKit], which needs [EntryScreen.KitEntry]. Each
 *    refuses the other two kinds and starts nothing. No intent takes a payload together with a word about which
 *    screen it came from: the screen is the function that was called.
 * 3. **Codes are typed, never confirmed (§6.11, §8.2).** A link's comparison code exists only in
 *    [CompareScreen.Ready], after the reveal checked against the commitment. The new device's digits exist only in
 *    [EntryScreen.LinkDeviceCode], after its own commitment and the other side's nonce. The existing device never
 *    shows a code: [DevicesApi.submitDeviceDigits] takes what the person typed, and only in
 *    [DeviceLinkHost.TypeDigits], after the new device's reveal checked out. Nothing says "they match".
 * 4. **Consent is bound to what was shown.** Operator recovery is turned on only through an
 *    [OperatorRecoveryWarning]; an incoming vault is accepted only through the [AccountPrompt.IncomingVault] that
 *    names the `add` it answers (FS-R6); a vault is shared with an uncompared contact only through an
 *    [UncomparedShareWarning]; a recovery kit's secret is readable only while its screen is on the reveal step.
 * 5. **Operator views are not on phones (§9.1).** They are reached only through [DesktopAppApi]; [AppApi], which
 *    the phone apps and the iOS bridge get, has no way to them, and a setup link opened there is refused.
 * 6. **Names say whose word they are.** An instance is named only by an [InstanceLabel], which is its pinned card's
 *    name and origin; a person by a [PersonName], which is a contact's own label or, marked as such, only the
 *    server's. No state carries a display string the server supplied, and recovery copy uses the card alone (§7.7).
 * 7. **A screen acts on the server it names.** Signed out, every screen that belongs to a server carries its own
 *    flow, and its intents read nothing else ([EntryScreen]); [AppSnapshot.instance] is the server of the screen on
 *    show, and [InstanceApi.forgetServer] takes the instance it forgets. Core keeps no "current server" that a
 *    screen could be out of step with.
 *
 * ## The engine underneath
 *
 * The client engine (`core.client.pin`, `onboard`, `link`, `devicelink`, `log`, `recovery`, `deletion`, `state`) has
 * the same shape one layer down: its steps that send something have internal constructors too. IF-3 does not expose
 * those types to a UI, with two exceptions that are plain value sets ([io.silencelen.andvari.core.client.pin.TrustGateWording]
 * and the operator console's wire rows). Everything else is mapped one to one, and each IF-3 state names the engine
 * state it shows, so a change on either side shows up in the other's comment.
 *
 * ## Threads
 *
 * Call everything from one thread, the main thread in an app. Listeners are called on it.
 *
 * ## Swift
 *
 * The iOS app reaches this API through the Kotlin/Native Objective-C export: `IosSessionController.appApi()` for the
 * engine-backed one, `AndvariBridge.fakeApp(scene)` for the fake. The surface is kept to what the export carries
 * over unchanged, and `AppApiSurfaceTest` (JVM) holds it there. No member, enum case or parameter is named into an
 * Objective-C method family (`new…`, `copy…`, `init…`, `alloc…`) or onto a reserved word, so no name gains a `do`
 * prefix or a `_`. No intent has a default argument, an overload or a type parameter. No type shares its simple
 * name with another type of the module. What a phone app sees has no nullable number (0 or an empty string says
 * "none"). A sealed class arrives as a class with subclasses (`as?`), an enum as a class with one static member per
 * case (`==`), a `suspend` intent as an `async throws` function that throws only on cancellation, and [snapshots]
 * is for Kotlin callers only ([observe] is the Swift way in).
 *
 * ## Traceability: IF-3 contents (§18.1) to this API
 *
 * | IF-3 bullet | Carried by |
 * |---|---|
 * | First run | [EntryScreen.FirstRun], [SignupStatus], [JoinMode], [FirstRunNotice]; [EntryApi.openInviteEntry], [EntryApi.createAccountOnAndvari], [EntryApi.openOwnServer], [EntryApi.openSignIn]; [EntryScreen.OwnServer], [EntryScreen.Server] for a typed server |
 * | The lock screen | [AppPhase.LOCKED], [LockedScreen], [AppApi.unlock], [VaultUnlockResult], [AppApi.lock], [AppApi.signOut] (with [AppApi.signOutCheck], [SignOutCheck], [AppApi.signOutConfirmed], [AppApi.sendBeforeSignOut]); quick unlock: [LockedScreen.quickUnlock], [AppApi.quickUnlock], [QuickUnlockResult] |
 * | Settings | quick unlock: [AccountSnapshot.quickUnlock], [QuickUnlockSetting], [AccountSettingsApi.turnOnQuickUnlock]; two-step sign-in: [AccountSnapshot.twoStep], [TwoStepScreen], [AccountSettingsApi.openTwoStep], [TwoStepResult]; the client policy: [AccountSnapshot.policy], [ServerPolicy]; a new kit after a move: [AccountSnapshot.kitAfterMove], [KitAfterMovePrompt] |
 * | Sign-in and the password rule | [EntryScreen.SignInChoice], [EntryScreen.SignInServer], [EntryScreen.SignIn], [MasterPasswordPrompt]; [EntryScreen.TrustGate], [TrustGatePrompt] (the engine's `TrustGateWording`: typed-address, device-link, link-offer sign-in, `kind` change); [EntryApi.choosePublicInstance], [EntryApi.chooseOwnServer], [EntryApi.confirmTrustGate], [EntryApi.submitSignIn], [SignInAnswer] |
 * | Sign-up | [EntryScreen.SignUpEmail] (age confirmation, proof-of-work progress), [EntryScreen.SignUpCode]; [EntryApi.startSignUp], [EntryApi.verifySignUpCode], [EntryApi.resendSignUpCode]; [SignUpStartResult] (`MAIL_UNAVAILABLE`), [CodeResult]; the ticket stays inside core |
 * | Registration through each link kind | [EntryScreen.CreateAccount], [RegistrationVia], [NewAccountInput], [EntryApi.createAccount], [CreateAccountResult]; [EntryScreen.ServerSetup], [OperatorApi.finishServerSetup] (desktop and CLI); [InviteResult.SETUP_NEEDS_COMPUTER] (phones) |
 * | Links | [LinksApi], [LinksScreen], [OwnLinkRow], [AnsweredLinkRow], [ShareChoice], [PendingShareRow], [LinkLifetimes]; [OpenedInvite] (with its Trust Gate for an enrol link, and the contact a connect made), [EntryScreen.JoinInvite], [EntryScreen.NotTakingAccounts] (the dead ends of §6.7); [InviteResult], [ConnectResult], [LinkCreateResult]; [AccountPrompt.ConnectionNotMade] |
 * | Contacts | [ContactsApi], [ContactsScreen], [ContactRow]; [AccountPrompt.PeopleList] (the one-tap list), [ContactsApi.reviewPeople], [ContactsApi.confirmOnThisDevice], [ContactsApi.dontUseOnThisDevice]; [CompareScreen], [ContactsApi.submitComparison], [ComparisonResult] |
 * | Vault log actions | [SharedVaultsApi]: `createVault`, `addMember`, `changeRole`, `removeMember`, `leaveVault`, `offerOwnership`, `cancelOffer`, `acceptOwnership`, `deleteVault`, `restoreVault`; [VaultActionResult] |
 * | Per-vault log states | [SharedVaultRow.log], [VaultLogState]; [SharedVaultsApi.saveItemsElsewhere], [SharedVaultsApi.removeFromThisDevice] |
 * | Card states | [InstanceSnapshot.card], [InstanceCardState] (ok, fork stop, damaged pin, withheld, not verified, move, `kind` change, "Update andvari"); [InstanceApi.followMove] with [MoveResult], [InstanceApi.forgetServerAtNewAddress], [InstanceApi.acceptKindChange], [InstanceApi.kindChangeNotNow], [InstanceApi.forgetServer]; [EntryScreen.ServerChanged] for a pinned server a flow cannot open; a first pin that is refused: [ServerResult.CARD_NOT_ACCEPTED], and a card made for another address: [ServerResult.OTHER_ADDRESS], [EntryScreen.AddressMismatch] |
 * | Account deletion with leaves | [AccountSettingsApi.openDeletion], [DeletionScreen], [DeletionPlan], [AccountSettingsApi.deleteAccount], [DeletionResult] |
 * | Recovery | [RecoveryApi], [RecoveryScreen], [RecoveryQuestion], [OperatorRecoveryWarning]; [KitApi], [KitScreen], [KitDocument]; [EntryScreen.KitEntry] ([EntryApi.submitKit] scanned, [EntryApi.submitTypedKit] typed by hand), [EntryScreen.KitRecover], [EntryScreen.ReplacePassword], [EntryScreen.Kit] |
 * | Assisted recovery | [EntryScreen.AskOperator], [EntryScreen.OperatorHelp], [OperatorHelpStage]; [EntryScreen.CheckAccount] (the delivered account's ID, §9.3 step 4), [EntryApi.acceptRecoveredAccount]; [EntryScreen.ReplacePassword]; [RecoveryRequestRow], [RecoveryApi.cancelRecoveryRequest] |
 * | Devices | [EntryScreen.LinkDeviceEntry], [EntryScreen.LinkDeviceWaiting], [EntryScreen.LinkDeviceCode], [EntryScreen.LinkDevicePassword], [EntryScreen.LinkDeviceEnded] (the new device); [DeviceLinkHost] (the existing device); [DevicesScreen], [DeviceRow], [DevicesApi.revokeDevice] |
 * | Change master password | [AccountSettingsApi.changeMasterPassword], [PasswordChangeResult] |
 * | Known devices and requireLink | [DevicesApi.setRequireLink], [DevicesScreen.requireLink], [EntryScreen.LinkRequired]; the `deviceSecret` never leaves core |
 * | Quota and over-quota states | [SharedVaultRow.ownerOutOfSpace], [VaultActionResult.OUT_OF_SPACE], [LinkCreateResult.TOO_MANY_OPEN_LINKS], [MoveEverythingScreen.shortOfSpace]; the operator's override, [OperatorApi.setAccountQuota] |
 * | Incoming vaults | [AccountPrompt.IncomingVault], [SharedVaultsApi.acceptIncoming], [SharedVaultsApi.declineIncoming]; [VaultLogState.CONNECT_FIRST], [VaultLogState.CONFIRM_FIRST] |
 * | Contact prompts | [AccountPrompt.KeyChanged], [OpenedInvite.KeyChanged]; [AccountPrompt.NewPerson] |
 * | Recovery prompts | [AccountPrompt.RecoveryRequest], [AccountPrompt.RecoveryKeyChanged], [AccountPrompt.KeepOperatorRecovery] |
 * | Vault actions | [MoveEverythingScreen], [SharedVaultsApi.moveEverything]; [MemberRow.deletedByOperator], [SharedVaultsApi.removeMember] |
 * | Instance switching | [OpenedInvite.OtherInstance], [LinksApi.switchInstance] |
 * | The first-launch wipe | [AppPhase.STARTING], [AppApi.start], [PreCutoverStores], [PreCutoverStore]; a store that could not be removed: [OldDataLeft], [AppApi.retryOldDataRemoval], [AppApi.acknowledgeOldData] |
 * | Operator views | [DesktopAppApi], [OperatorApi], [OperatorConsole]; [AccountPrompt.FinishServerSetup] |
 *
 * ## Gaps
 *
 * Where the design does not say, with one reading, what a screen shows, the API carries the state and no wording.
 * Each such place says `GAP` in its comment.
 */
/**
 * An unlock that must be fast (the Android autofill overlay), on an app API that has one (the engine's: ask with
 * `as? FastUnlock`, and use [AppApi.unlock] where there is none). It is [AppApi.unlock] with the quiet re-key that
 * follows a full-password unlock, when the server's policy asks for a higher KDF cost (spec 01 §7), put off to the next
 * full-password unlock. [AppApi.unlock] performs it inline, after the vault opened.
 */
interface FastUnlock {
    suspend fun unlockPuttingOffReKey(screen: LockedScreen, password: String): VaultUnlockResult
}

/**
 * The unlock of a surface that only fills and cannot show a recovery kit (Android's autofill window; on an app API that
 * has one: ask with `as? UnlockForFilling`, and fall back to [FastUnlock] or [AppApi.unlock] where there is none). It is
 * [FastUnlock.unlockPuttingOffReKey], except for an account whose kit was never confirmed: [AppApi.unlock] makes a
 * fresh kit there before the vault opens (the server replaces the account's kit), which no window of the filling
 * surface would show. This one makes no kit: the vault opens for filling, nothing is sent about the kit, and the kit is
 * left to the app's next opening ([AccountSnapshot.kitDueAtOpening]): quick unlock stays off until a kit is confirmed,
 * so the app's next unlock is with the master password and shows the fresh kit then.
 */
interface UnlockForFilling {
    suspend fun unlockForFilling(screen: LockedScreen, password: String): VaultUnlockResult
}

interface AppApi {
    /** The current snapshot. */
    val snapshot: AppSnapshot

    /** The snapshots as a flow, for Kotlin callers: `collectAsState()` in Compose. Swift uses [observe]. */
    val snapshots: StateFlow<AppSnapshot>

    /** Call [listener] with the current snapshot, then with every later one, until the subscription is closed. */
    fun observe(listener: (AppSnapshot) -> Unit): Subscription

    /**
     * Start: run the first-launch wipe (§12.4) for every old store that is not known to be gone, then leave
     * [AppPhase.STARTING] for the first screen, or for a stored session's lock screen. A store that cannot be
     * deleted does not stop the start ([AppSnapshot.oldData]). Nothing else in this API does anything before it.
     */
    fun start()

    /** Stop: running work is cancelled and every listener is dropped. */
    fun close()

    /**
     * Unlock the stored session with its master password ([AppPhase.LOCKED]). The password opens the account's keys
     * on this device and is not sent anywhere. On [VaultUnlockResult.DONE] the vault is open, or, when the account never
     * saved a recovery kit, the journey shows a fresh one first ([EntryScreen.Kit], [KitReason.NEVER_SAVED]) and
     * the vault opens once it is confirmed.
     */
    suspend fun unlock(screen: LockedScreen, password: String): VaultUnlockResult

    /**
     * Unlock with the platform's biometric ([LockedScreen.quickUnlock]): the account's key, sealed under a key only
     * the biometric releases, opens the stored account on this device. Nothing derived from the password is used or
     * sent; it works offline. A damaged pin refuses it before any prompt; under a fork it opens the device's own copy
     * read-only, as [unlock] does. Turned on and off in Settings ([AccountSettingsApi.turnOnQuickUnlock]).
     */
    suspend fun quickUnlock(screen: LockedScreen): QuickUnlockResult

    /**
     * Lock: the account's keys are dropped from memory and every open screen of the account closes; the session
     * stays ([AppPhase.LOCKED]).
     *
     * It acts whenever the account's keys are open, whatever the phase: on a kit step of the journey (after sign-up, a
     * sign-in or unlock whose kit was never saved, a kit recovery or a device link) the kit on show is wiped as well and
     * the app goes to the lock screen; the next unlock makes a fresh kit. [signOut] works there too. In the journey
     * with no keys open, a password kept for a code step is wiped.
     *
     * **Idle auto-lock is the app's to run.** This API has no foreground, background or activity hooks and keeps no
     * idle clock: the app's own lifecycle code calls [lock] when its auto-lock window runs out or when it goes to
     * the background, as its platform does today. It must measure that window on a clock that keeps counting while
     * the device sleeps and that the person cannot set (the engine's `Clocks.monotonicMs`).
     */
    fun lock()

    /**
     * On the lock screen of a session the server ended ([LockedScreen.signedOutByServer]): open the journey at the
     * first screen, with its notice, to sign in again. Signing in to the same account at the same server takes this
     * device's copy back and sends what waited; another account is refused until this one is signed out. Nothing
     * happens on any other screen.
     */
    fun signInAgain(screen: LockedScreen)

    /** The person dismissed [AppSnapshot.kitWiped] ([notice], the one on show): it is not said again. Additive. */
    fun dismissKitWiped(notice: KitWipedNotice)

    /** The person dismissed [AppSnapshot.rememberedNewAccount] ([notice], the one on show): it is not said again. Additive. */
    fun dismissNewAccountRemembered(notice: NewAccountRememberedNotice)

    /** The person dismissed [AppSnapshot.policyWipe] ([notice], the one on show): it is not said again. Additive. */
    fun dismissPolicyWipe(notice: PolicyWipeNotice)

    /**
     * A wipe of the copy of [userId] at [origin] (its canonical address) is owed for its server's policy and not made yet:
     * the shared code sends what waits once, counts and removes the copy itself, so the app deletes nothing of it on its
     * own. Changes nothing. False where nothing is owed (also once the wipe is made, or the policy allows the copy again).
     * Additive.
     */
    fun policyWipeOwed(origin: String, userId: String): Boolean

    /**
     * The app came back to the foreground (the one lifecycle event this API takes, besides [lock]): while the vault is
     * open, the logins an extension captured meanwhile are read from the save queue
     * ([io.silencelen.andvari.core.app.content.VaultContent.readSaveQueue]); what may be saved by itself is saved, the
     * rest is listed in the content's `pendingSaves`. Nothing happens while locked: the queue is read at the unlock.
     */
    fun returnedToForeground()

    /**
     * Nothing of the app is on show from now until [returnedToForeground] (the app went to the background, or away to
     * another app's screen such as the system's print screen). Nothing is locked, sent or read here: it tells the shared
     * code that a kit which comes on show meanwhile is not seen, so that a notice of its wipe never calls it the kit that
     * was on the screen ([KitWipedNotice.unseen]). Additive.
     */
    fun wentAway()

    /**
     * The platform says a network is back (Android's network callback, the desktop's own check): live updates alone are
     * told. The bell's ladder goes to zero and a bell waiting to dial again dials now. Nothing else is read or sent: the
     * save queue is not read and nothing syncs (the bell's own first answer does that once it connects). It is valid
     * whenever a vault is open, the app in the background too; while locked, on the journey or after a sign-out it
     * does nothing. Additive (the network-return seam the Android app needs).
     */
    fun networkReturned()

    /**
     * Sign out on this device, locked or unlocked: the server is told to end the session (best effort), and the
     * session is gone from this device whatever it answered. The server's pin, and what this device knows of the
     * account's contacts, stay; [InstanceApi.forgetServer] removes those. The app is back at the first screen.
     * In the journey it signs out the account its server signed out ([AppSnapshot.keptSignedOut]), deleting its copy.
     *
     * A sign-out deletes this device's copy, and with it every change made here that the server does not have (rule
     * of 2026-11-17): when [signOutCheck] says the act needs a second confirmation ([SignOutCheck.needsConfirmation]:
     * changes wait, or this device cannot tell), this answers [PlainResult.UNSENT_NOT_CONFIRMED] and nothing is
     * deleted; the screen shows [SignOutCheck.line] and the person confirms with [signOutConfirmed].
     */
    suspend fun signOut(): PlainResult

    /**
     * Before "Sign out", and before [LinksApi.switchInstance] (which signs out): how many changes made on this device
     * have not been sent, as the confirmation must say. Read it when the confirmation opens; it is the same object for
     * as long as what it says holds. Null where [signOut] would answer STALE. Additive.
     */
    fun signOutCheck(): SignOutCheck?

    /**
     * How many changes made on this device wait to be sent and are held in memory only (a device that keeps nothing at
     * rest: a desktop without "Keep me signed in", or any device under a policy that forbids the copy). A lock keeps
     * them, sealed, and they are sent after the next unlock; ending the app loses them. Before the app ends by the
     * person's own act (quitting it), when this is above 0, ask first with the number, as a sign-out does. 0 when none.
     * It counts everything that waits in memory: the queue, and the saves and moves kept to be finished. Null when that
     * cannot be told now (locked, with such kept records in memory, which stay sealed until the next unlock): then ask
     * too, without a number.
     */
    fun waitingInMemory(): Int?

    /**
     * Sign out after the person's second confirmation of [check], which the screen showed with its line: as [signOut],
     * on this device's copy whatever waits in it. [PlainResult.UNSENT_NOT_CONFIRMED] when [check] is no longer what
     * [signOutCheck] says (more changes were made, the vault locked, another account): show the new check. Additive.
     */
    suspend fun signOutConfirmed(check: SignOutCheck): PlainResult

    /**
     * "Try sending them first" ([SignOutCheck.canSendFirst]): a sync of what waits, then the count again. DONE when
     * nothing waits any more (the act then needs no second confirmation); [SendFirstResult.NOT_ALL_SENT] when some
     * still wait, and [signOutCheck] says how many. Nothing is deleted either way. Additive.
     */
    suspend fun sendBeforeSignOut(check: SignOutCheck): SendFirstResult

    /**
     * Where a deletion of the kept account got no answer and its outcome is still not known (on its deletion screen, its
     * lock screen, or the first screen's notice): the offer to forget that account on this device, the same object for as
     * long as it holds. Null where none is offered. Additive.
     */
    fun forgetAfterUnknownDeletionCheck(): ForgetUnknownDeletion?

    /**
     * The person confirmed [check] ([ForgetUnknownDeletion.confirmLine] was on show): the account is forgotten on this
     * device (its session, keys, identity record and copy; the server's pin stays), the end of its session is sent to its
     * server, and the app is at the first screen. STALE when [check] is no longer what
     * [forgetAfterUnknownDeletionCheck] says. Never called without the person's own confirmation. Additive.
     */
    suspend fun forgetAfterUnknownDeletion(check: ForgetUnknownDeletion): PlainResult

    /**
     * "Try again": delete the old stores [notice] lists once more (§12.4). True when none is left;
     * [AppSnapshot.oldData] says what still is.
     */
    fun retryOldDataRemoval(notice: OldDataLeft): Boolean

    /** The person has been told about the old stores that are still there: [OldDataLeft.tellNow] is false from here on. */
    fun acknowledgeOldData(notice: OldDataLeft)

    /** Put [AccountSnapshot.signInNotice] away. Additive. */
    fun dismissSignInNotice()

    /**
     * How long the server last asked this app to wait, in seconds from now, counted on a clock the person cannot set;
     * 0 when no wait is in force. Read it when an intent answered [Trouble.RATE_LIMITED] (`429` with `Retry-After`,
     * which every route can answer, §7.8).
     */
    fun retryAfterSeconds(): Int

    /**
     * A link the system handed to the app: a tapped invite (§12.1; the apps register `/l` only). It is opened as an
     * invite scanned on "Scan an invite" would be, signed in or not. A device link or a kit that arrives this way
     * starts nothing ([InviteResult.DEVICE_LINK_NOT_HERE], [InviteResult.KIT_NOT_AN_INVITE]).
     *
     * Signed out, **it starts a journey of its own**, at the invite's server: the screens it shows act there, and
     * [EntryApi.back] returns to the screen that was up, which still acts on the server it named. A link that
     * arrives while the app is starting or locked, while a kit must be saved, while a server's setup is being
     * finished or while a device link is claimed starts nothing ([InviteResult.STALE]). **Core holds no link across
     * a lock**: the app keeps the URL it was handed and calls this again once [AppSnapshot.phase] is
     * [AppPhase.UNLOCKED], or [AppPhase.ENTRY] on a screen that can be left; a link is acted on only when a person
     * can see what it opens.
     */
    suspend fun openAppLink(url: String): InviteResult

    /** Signed out: first run, sign-up, registration, sign-in, linking this device, recovery. */
    val entry: EntryApi

    /** The recovery kit's reveal and confirm steps, wherever a kit is shown. */
    val kit: KitApi

    /** The server on show ([AppSnapshot.instance]): what its card asks for, and forgetting it. */
    val instance: InstanceApi

    val contacts: ContactsApi
    val links: LinksApi
    val vaults: SharedVaultsApi
    val devices: DevicesApi
    val recovery: RecoveryApi

    /** Changing the master password and deleting the account. */
    val settings: AccountSettingsApi

    /**
     * The vault's content: items, search, reveal, saves, trash, attachments, import, export, health
     * ([io.silencelen.andvari.core.app.content.VaultContent]). Non-null only while [AppSnapshot.phase] is
     * [AppPhase.UNLOCKED], and **a new instance for every unlock**: a lock, a sign-out or the end of the session closes
     * it, and an instance kept past that answers every intent with `NotDone`. Read it again after each unlock (when
     * [AppSnapshot.phase] changes), never keep one across a lock. [AccountSnapshot.contentRevision] moves with its state.
     */
    val content: io.silencelen.andvari.core.app.content.VaultContent?
}

/**
 * [AppApi] plus the operator views, for the desktop app and `andvari-cli` only (§9.1, N9). The phone apps and the
 * iOS bridge are handed an [AppApi], so they have no way to an [OperatorApi] and no code path that takes a setup
 * link: that is the rule "never the web or the phone apps", made by the types.
 */
interface DesktopAppApi : AppApi {
    val operatorApi: OperatorApi

    /** "Restore a backup", over the vault open now (the desktop's alone). */
    val restores: BackupRestoreApi
}

/** Where the app is, at the top. */
enum class AppPhase {
    /** Before [AppApi.start] finished: the first-launch wipe runs here (§12.4). Nothing is on screen yet. */
    STARTING,

    /**
     * The signed-out journey: [AppSnapshot.entry] is the screen to show. It lasts until the vault opens, so it
     * includes the recovery kit a new session must save first ([EntryScreen.Kit]).
     */
    ENTRY,

    /** A session is stored and locked: [AppSnapshot.locked] is the lock screen, and [AppApi.unlock] opens it. */
    LOCKED,

    /** Signed in and unlocked: [AppSnapshot.account] is set. */
    UNLOCKED,
}

/**
 * One immutable snapshot of everything IF-3 shows. It carries no secret: no password, no kit, no link, no token.
 */
class AppSnapshot internal constructor(
    val phase: AppPhase,
    /** [AppPhase.ENTRY]: the screen of the signed-out journey. Null in every other phase. */
    val entry: EntryScreen?,
    /** [AppPhase.LOCKED]: the lock screen. Null in every other phase. */
    val locked: LockedScreen?,
    /** [AppPhase.UNLOCKED]: the account. Null in every other phase. */
    val account: AccountSnapshot?,
    /**
     * The server on show. With a session, locked or unlocked: the session's server. Signed out: the server the
     * screen on show belongs to, once this device holds a pin for it (or a blocked record of it); null on a screen
     * that names no server, and while a Trust Gate still stands before the first pin. It is never a server other
     * than the one the screen's own intents act on.
     */
    val instance: InstanceSnapshot?,
    /** §12.4: old local stores the first launch could not delete; null when none is left, which is the usual case. */
    val oldData: OldDataLeft?,
    /** An intent is running: disable what would start another. */
    val busy: Boolean,
    /**
     * [AppPhase.ENTRY] only: the account this device keeps although its server signed it out ([LockedScreen.signedOutByServer],
     * reached through [AppApi.signInAgain]), with its server. A sign-in to that account takes its copy back; any other
     * account is refused (`ANOTHER_ACCOUNT_KEPT`) until it is signed out, which [AppApi.signOut] does here too, behind
     * the screen's usual sign-out warning. Null when no such account is kept, and in every other phase.
     */
    val keptSignedOut: MasterPasswordPrompt? = null,
    /**
     * With [keptSignedOut]: that account's session ended because this device could not confirm it with its server in time,
     * not because its server signed it out ([LockedScreen.sessionNotConfirmed]). Everything else about [keptSignedOut] holds.
     * Additive.
     */
    val keptSignedOutNotConfirmed: Boolean = false,
    /** With [keptSignedOutNotConfirmed]: its line, [CopyKey.SESSION_NOT_CONFIRMED], in place of "signed out by its server". Null otherwise. */
    val keptSignedOutLine: CopyKey? = null,
    /**
     * With [keptSignedOutNotConfirmed]: the line for that end in the one place where the person is told to sign the kept
     * account OUT first (beside a refusal `ANOTHER_ACCOUNT_KEPT` and its way out):
     * [CopyKey.SESSION_NOT_CONFIRMED_SIGN_OUT_FIRST], which does not tell them to sign in again. [keptSignedOutLine] stays
     * the line everywhere else. Null otherwise. Additive.
     */
    val keptSignedOutSignOutFirstLine: CopyKey? = null,
    /**
     * How many unexpected faults the app interface's own background work has contained since this process started
     * (the opening's sync, a ring's sync, the save queue, the end of a session): each was stopped where it happened,
     * nothing of it was kept or shown (no exception text), and the app went on. When it grows, show
     * [containedFaultLine] once, as a notice above the screen. A platform that hands its own handler in with
     * `AppEngine.main` keeps it, and this stays 0. Additive.
     */
    val containedFaults: Int = 0,
    /**
     * A recovery kit of a committed change, shown with this device's refusal of the account's session
     * ([KitScreen.notKeptLine]), was wiped: a lock came (by hand, or by the kit screen's idle limit
     * [KitScreen.idleLockAfterMs]), or the app was closed with it on show. Show [KitWipedNotice.line] once, as a notice
     * above whatever screen is on show (the lock screen, the first screen, or an account opened meanwhile), with a dismiss
     * ([AppApi.dismissKitWiped]). Null otherwise; it goes only when dismissed (an opening, a quick unlock included, and a
     * start do not take it). Additive.
     */
    val kitWiped: KitWipedNotice? = null,
    /**
     * The refusal of the screen on show ([entry]) was because this device knows the address under an earlier account, and
     * it offers "Forget the earlier account on this device" (decided on 2026-11-17; [EarlierAccountKnown] says how it is
     * shown and taken). Null otherwise, and as soon as another screen is on show. Additive.
     */
    val earlierAccount: EarlierAccountKnown? = null,
    /**
     * After the person forgot an earlier account under an address, the next account under it was taken on this device: show
     * [NewAccountRememberedNotice.line] once, as a notice above whatever screen is on show, with a dismiss
     * ([AppApi.dismissNewAccountRemembered]). Null otherwise. Additive.
     */
    val rememberedNewAccount: NewAccountRememberedNotice? = null,
    /**
     * The server's policy forbids a copy of the vault on devices, and this device's copy is gone after one try to send
     * what waited in it: show [PolicyWipeNotice.lines] as a notice above whatever
     * screen is on show, in every phase, until the person dismisses it ([AppApi.dismissPolicyWipe]). Null otherwise.
     * Additive.
     */
    val policyWipe: PolicyWipeNotice? = null,
    /**
     * The server's policy as kept on this device cannot be read: the account's copy stays closed (no content is handed
     * out, nothing is deleted) until the policy has been read from the server again. Show this line where the vault
     * would be. Null otherwise. Additive.
     */
    val closedForPolicy: CopyLine? = null,
    /**
     * The removal of this device's copy, under a server policy that forbids keeping one, is still owed for the account
     * whose session this device keeps (locked, unlocked, or kept after its server ended it): true from the moment such a
     * policy is recorded until the copy is gone and its count is taken; false otherwise, and where no session is kept.
     * It is read from the device's own record of what is owed, so it reads the same after a lock and a restart. Another
     * account's copy on the device never makes it true. Beside [policyWipe] and [closedForPolicy], the policy's other
     * states. Additive.
     */
    val policyWipeOwed: Boolean = false,
) {
    /** The notice for [containedFaults]. */
    val containedFaultLine: CopyKey get() = CopyKey.CONTAINED_FAULT
}

/**
 * [AppSnapshot.kitWiped]: the recovery kit that was on the screen is gone; the change itself stands (after a recovery the
 * new master password is in force; after a registration the account was made); the next sign-in to that account shows a
 * new kit. Where this device cannot take the account now ([whyHere] is not null), the line never says "on any device":
 * draw [whyHere] with it, which says what stands in the way here.
 */
class KitWipedNotice internal constructor(
    /** The account the kit was for. */
    val email: String,
    /**
     * [CopyKey.KIT_WIPED_AFTER_RECOVERY] or [CopyKey.KIT_WIPED_AFTER_REGISTRATION] where nothing stands in the way here;
     * otherwise [CopyKey.KIT_WIPED_AFTER_RECOVERY_NOT_HERE] or [CopyKey.KIT_WIPED_AFTER_REGISTRATION_NOT_HERE].
     */
    val line: CopyKey,
    /**
     * Why this device cannot take the account now, while what stood in the way still stood when the kit was wiped (another
     * account kept here, a fault of the account's identity, its server's operator account held, its keys, a damaged copy):
     * one of the `KIT_NOT_HERE_WHY_*` lines, never the kit's own line (which tells the person to save the kit); null
     * otherwise. Additive.
     */
    val whyHere: CopyKey? = null,
    /**
     * With [whyHere]: the way out of what stands in the way here ([KeptStops.wayOut]'s act for the same cause), for the
     * screen under the notice to offer, with its usual counts and confirmations, without a sign-in tried first: the
     * kept account's sign-out ([AppApi.signOut], callable in the journey while [AppSnapshot.keptSignedOut] is set and on
     * the lock screen), the held operator account's removal ([EntryScreen.FirstRun.heldAsOperator],
     * [EntryApi.removeHeldOperatorAccount]), or the removal of this
     * device's copy ([AppApi.signOut] of it). The notice itself carries no button but Close. Null where none applies (the
     * identity fault, no reason known). Additive.
     */
    val wayOut: KeptWayOut? = null,
    /**
     * The kit was made while nothing of the app was on show ([AppApi.wentAway]) and wiped before the app came back, so
     * it was never seen: [line] is one of the `KIT_WIPED_UNSEEN_*` lines, which never say "the kit that was on the
     * screen" and never ask the person to save a kit that is gone. Additive.
     */
    val unseen: Boolean = false,
    /**
     * The kept session that [whyHere] named when the kit was wiped (another account kept here, its server's operator
     * account held, or this device's copy of the account whose keys or record stand in the way): that session's
     * [MasterPasswordPrompt.keptMark] then. A way out under the notice is offered only while
     * [AppSnapshot.keptSignedOut] (or the lock screen's prompt) has this same mark. Null where [whyHere] names no kept
     * session. Additive.
     */
    val namedKept: String? = null,
) {
    internal companion object {
        /** [kitLine]: the kit's own refusal line ([KitScreen.notKeptLine]) while it still stands; null otherwise. */
        fun of(recovery: Boolean, email: String, kitLine: CopyKey? = null, unseen: Boolean = false, namedKept: String? = null): KitWipedNotice {
            val why = kitLine?.let { KeptStops.whyFromKitLine(it) ?: CopyKey.KIT_NOT_HERE_WHY_NOT_OPENED }
            return KitWipedNotice(
                email,
                when {
                    unseen && why == null && recovery -> CopyKey.KIT_WIPED_UNSEEN_AFTER_RECOVERY
                    unseen && why == null -> CopyKey.KIT_WIPED_UNSEEN_AFTER_REGISTRATION
                    unseen && recovery -> CopyKey.KIT_WIPED_UNSEEN_AFTER_RECOVERY_NOT_HERE
                    unseen -> CopyKey.KIT_WIPED_UNSEEN_AFTER_REGISTRATION_NOT_HERE
                    why == null && recovery -> CopyKey.KIT_WIPED_AFTER_RECOVERY
                    why == null -> CopyKey.KIT_WIPED_AFTER_REGISTRATION
                    recovery -> CopyKey.KIT_WIPED_AFTER_RECOVERY_NOT_HERE
                    else -> CopyKey.KIT_WIPED_AFTER_REGISTRATION_NOT_HERE
                },
                why,
                kitLine?.let { KeptStops.wayOutFromKitLine(it) },
                unseen,
                namedKept?.takeIf { why != null && why in NAMES_KEPT },
            )
        }

        /** The reasons that name a session kept here; the identity fault and "not opened" name none. */
        private val NAMES_KEPT = setOf(
            CopyKey.KIT_NOT_HERE_WHY_ANOTHER_KEPT, CopyKey.KIT_NOT_HERE_WHY_OPERATOR_HELD,
            CopyKey.KIT_NOT_HERE_WHY_SERVER_KEYS, CopyKey.KIT_NOT_HERE_WHY_COPY_DAMAGED,
        )
    }
}

/**
 * The lock screen of a stored session ([AppPhase.LOCKED]). It asks for an existing account's master password, so it
 * names the account, the instance and its origin ([prompt], §4.4).
 *
 * **A fork stops traffic, not reading** (§4.4). When [AppSnapshot.instance]'s card is [InstanceCardState.Stopped],
 * the password still opens what this device already holds, read-only ([AccountSnapshot.serverStopped]). Only a
 * damaged pin record ([InstanceCardState.Damaged]) blocks the unlock as well ([VaultUnlockResult.SERVER_BLOCKED]); the
 * ways on are then [AppApi.signOut] and [InstanceApi.forgetServer].
 */
class LockedScreen internal constructor(
    /** The account the stored session belongs to, and its server. */
    val prompt: MasterPasswordPrompt,
    /**
     * Quick unlock can be tried now ([AppApi.quickUnlock]): it is on for this account, a strong biometric is usable,
     * the server's policy permits it, and the periodic full password is not due. Offer the biometric button only
     * when true; the password field is always there.
     */
    val quickUnlock: Boolean,
    /**
     * The server ended this session (a refused refresh, a revoked session; design §4.4): the account is signed out by
     * the server, and this device's copy stays. The password opens it read-only ([AccountSnapshot.serverStopped]):
     * nothing is sent and nothing is written. Offer "Sign in again" ([AppApi.signInAgain]), which takes the copy back
     * for the same account here and sends what waited, and "Sign out", which deletes the copy.
     */
    val signedOutByServer: Boolean = false,
    /**
     * The master password was changed from this device but its copy could not follow
     * ([PasswordChangeResult.CHANGED_PREVIOUS_OPENS_HERE]): on this device the PREVIOUS master password opens it. Say so
     * above the password field, so the new password's failure here is not a mystery.
     */
    val previousPasswordOpensCopy: Boolean = false,
    /**
     * This account's deletion was sent and no answer came ([DeletionResult.OUTCOME_UNKNOWN]), and nothing the server
     * answered since has said whether it was deleted. Kept across locks, restarts and
     * a session the server ends (the likely sign that it was). Say "We cannot tell yet whether your account was
     * deleted" with the lock screen; it clears at the next answer from the server for this account, or when the account
     * is signed out or forgotten here. GAP: no approved wording yet.
     */
    val deletionOutcomeUnknown: Boolean = false,
    /**
     * With [signedOutByServer]: the server did not end this session; this device could not confirm it with its server in
     * time, sent nothing again (so no other session was ended), and the person signs in again. Everything else is as for
     * [signedOutByServer] ("Sign in again", "Sign out"), but the screen says [endLine] in place of "signed out by its
     * server", never that. Additive.
     */
    val sessionNotConfirmed: Boolean = false,
    /**
     * The server's policy forbids keeping data on this device, so this device keeps no key that opens the account: an
     * unlock asks the server each time ([VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE] while it does not answer; nothing
     * is removed then). Show this line with the lock screen while it is not null; quick unlock is not offered meanwhile.
     * Where the session has ended too, [endLine] says that end.
     */
    val keysAtServerLine: CopyLine? = null,
) {
    /**
     * The line for the session's end, drawn in place of the app's own "signed out by its server" where it is not null:
     * [CopyKey.SESSION_NOT_CONFIRMED] where [sessionNotConfirmed]; [CopyKey.SIGNED_OUT_KEYS_AT_SERVER] where the server
     * ended this session ([signedOutByServer]) while the account's keys are kept at the server ([keysAtServerLine]): no
     * password opens anything here then, so the line claims no copy; null otherwise.
     */
    val endLine: CopyKey? get() = when {
        sessionNotConfirmed -> CopyKey.SESSION_NOT_CONFIRMED
        signedOutByServer && keysAtServerLine != null -> CopyKey.SIGNED_OUT_KEYS_AT_SERVER
        else -> null
    }

    /**
     * Drawn in place of [endLine] while a way out that signs this kept account OUT stands on the same screen
     * ([AppSnapshot.kitWiped] with [KitWipedNotice.wayOut] [KeptWayOut.SIGN_OUT_KEPT_ACCOUNT]); neither tells the person to
     * sign in again: [CopyKey.SESSION_NOT_CONFIRMED_SIGN_OUT_FIRST] where [sessionNotConfirmed],
     * [CopyKey.SIGNED_OUT_KEYS_AT_SERVER_SIGN_OUT_FIRST] where [endLine] is [CopyKey.SIGNED_OUT_KEYS_AT_SERVER]; null
     * otherwise. Additive.
     */
    val endLineBesideSignOut: CopyKey? get() = when (endLine) {
        CopyKey.SESSION_NOT_CONFIRMED -> CopyKey.SESSION_NOT_CONFIRMED_SIGN_OUT_FIRST
        CopyKey.SIGNED_OUT_KEYS_AT_SERVER -> CopyKey.SIGNED_OUT_KEYS_AT_SERVER_SIGN_OUT_FIRST
        else -> null
    }
}

/**
 * What a quick unlock came to ([AppApi.quickUnlock]). It sends nothing and works offline. Every outcome but [DONE]
 * leaves the lock screen up with its password field.
 */
enum class QuickUnlockResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    /** Unlocked, as [VaultUnlockResult.DONE]; under a fork, read-only ([AccountSnapshot.serverStopped]). */
    DONE,

    /** The person cancelled the prompt, or chose the password: say nothing. */
    CANCELLED,

    /**
     * The master password is needed now: the biometric locked out or failed, the periodic full password is due, the
     * server's policy no longer permits it, or the account has a kit to save first. Quick unlock stays on.
     */
    USE_PASSWORD,

    /** The device's key for it is gone (its biometrics changed, or it no longer opens): quick unlock is off, and Settings offers it again. */
    TURNED_OFF,

    /** As [VaultUnlockResult.SERVER_BLOCKED]: the pin record is damaged or gone; no prompt was shown. */
    SERVER_BLOCKED,

    /** As [VaultUnlockResult.IDENTITY_FAULT]. Quick unlock is off. */
    IDENTITY_FAULT,
    STALE(Trouble.STALE),
    UNREACHABLE(Trouble.UNREACHABLE),
    RATE_LIMITED(Trouble.RATE_LIMITED),
    UPDATE_REQUIRED(Trouble.UPDATE_REQUIRED),
    FAILED(Trouble.FAILED),
    ;

    override val done: Boolean get() = this == DONE
}

/** What an unlock came to ([AppApi.unlock]). Nothing is sent by it, so the server-side troubles do not occur. */
enum class VaultUnlockResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    /** Unlocked. The vault is open, or the journey is at the kit the account never saved. */
    DONE,

    /** The password does not open the stored account. Nothing was sent, and nothing counts the tries. */
    WRONG_PASSWORD,

    /**
     * This device's pin record for the server is damaged, or gone: the account is not opened against it
     * ([InstanceCardState.Damaged]). A fork does not answer this: under a fork the unlock works, and the vault is
     * read-only ([AccountSnapshot.serverStopped]).
     */
    SERVER_BLOCKED,

    /** §5.2: the stored keys do not match the account's genesis record or this device's record of it. Nothing was opened. */
    IDENTITY_FAULT,
    STALE(Trouble.STALE),
    UNREACHABLE(Trouble.UNREACHABLE),
    RATE_LIMITED(Trouble.RATE_LIMITED),
    UPDATE_REQUIRED(Trouble.UPDATE_REQUIRED),
    FAILED(Trouble.FAILED),

    // The three below carry no trouble: each is this intent's own reason, said by its sentence.

    /**
     * The account's keys are kept at the server only ([LockedScreen.keysAtServerLine]) and the server did not answer the
     * read of them: nothing was opened and nothing was removed, and the password was not checked (only the server can
     * check it then); the lock screen stays. Said with its own sentence; a right and a wrong password read the same here.
     * Additive: it is what [UNREACHABLE] was for such an account. Its reason is this intent's own (every result type
     * carries each [Trouble] once), so its trouble is null and its sentence says it.
     */
    KEYS_AT_SERVER_UNREACHABLE(sentence = CopyKey.UNLOCK_KEYS_AT_SERVER_UNREACHABLE),

    /**
     * The account's keys are kept at the server only and this session has ended (the server ended it, or this device could
     * not confirm it in time), also where that end was learned during this unlock: nothing was opened and nothing was
     * removed; nothing opens here until the person signs in again ([LockedScreen.endLine] says the end). Additive: it is
     * what [FAILED] and, at the unlock that learned the end, [STALE] were for such an account.
     */
    KEYS_AT_SERVER_ENDED(sentence = CopyKey.UNLOCK_KEYS_AT_SERVER_ENDED),

    /**
     * The account's keys are kept at the server only and the server refused to hand them over (a refusal that is neither
     * a wait, [RATE_LIMITED], nor the session's end): nothing was opened and nothing was removed. Additive. Handed by the
     * engine once its session keeper tells a refusal from silence; until then such a refusal reads as
     * [KEYS_AT_SERVER_UNREACHABLE]. The stand-in plays it with `forceNext`.
     */
    KEYS_AT_SERVER_REFUSED(sentence = CopyKey.UNLOCK_KEYS_AT_SERVER_REFUSED),
    ;

    override val done: Boolean get() = this == DONE
}

/**
 * §12.4: pre-cut-over stores this install could not delete at its first launch. New builds never open them, so the
 * app carries on; it tries again at every start, and tells the person once.
 *
 * GAP (§12.4): the design does not say what the app does when a store cannot be deleted; it gives no wording.
 */
class OldDataLeft internal constructor(
    /** The stores that are still there. */
    val stores: List<PreCutoverStore>,
    /**
     * The person has not been told: show the notice now, then call [AppApi.acknowledgeOldData]. False afterwards:
     * a line in Settings, with [AppApi.retryOldDataRemoval], until the stores are gone.
     */
    val tellNow: Boolean,
)

/** A reason any intent can have for doing nothing. None is particular to one flow, so one piece of UI can say them all. */
enum class Trouble {
    /** The screen, prompt or row handed in is no longer the one this app shows (or the app is not signed in): nothing was done. */
    STALE,

    /** The server did not answer. */
    UNREACHABLE,

    /** The server asked to wait (`429 rate_limited`): [AppApi.retryAfterSeconds] says how long. */
    RATE_LIMITED,

    /** This build is too old for the server (`426 upgrade_required`): only an update helps. */
    UPDATE_REQUIRED,

    /** Anything else. Nothing the server sent is shown for it. */
    FAILED,
}

/**
 * What every intent's result can say. Each intent has its own enum of outcomes, so a `when` over it is exhaustive;
 * all of them implement this, so the outcomes that are not particular to a flow are handled once.
 */
interface IntentResult {
    /** The intent did what it was called for. The snapshot shows where that led. */
    val done: Boolean

    /** The reason is one any intent can have; null when [done], or when the reason is this intent's own. */
    val trouble: Trouble?

    /** The design's sentence for this outcome, when it gives one that names nothing. */
    val sentence: CopyKey?
}

/** The result of an intent that has no refusal of its own: it was done, or one of the troubles any intent can have. */
enum class PlainResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    DONE,
    STALE(Trouble.STALE),
    UNREACHABLE(Trouble.UNREACHABLE),
    RATE_LIMITED(Trouble.RATE_LIMITED),
    UPDATE_REQUIRED(Trouble.UPDATE_REQUIRED),
    FAILED(Trouble.FAILED),

    /**
     * [AppApi.signOut] without the person's second confirmation while changes made on this device were not sent, or
     * while this device cannot tell: nothing was deleted and nothing was sent. Show [AppApi.signOutCheck]'s line and
     * confirm with [AppApi.signOutConfirmed]. Additive.
     */
    UNSENT_NOT_CONFIRMED(sentence = CopyKey.UNSENT_NOT_CONFIRMED),
    ;

    override val done: Boolean get() = this == DONE
}

/**
 * What signing out would delete that the server does not hold (design §4.4: a sign-out deletes this device's copy;
 * rule of 2026-11-17: never over changes that were not sent without the person having been told). It carries the
 * person's confirmation, so it is made only by the app interface.
 */
class SignOutCheck internal constructor(
    /**
     * The changes made on this device and not sent yet, counted now as the account held as an operator counts them
     * ([HeldOperatorAccount.unsentChanges]: the item changes waiting, those the server refused and that wait for a
     * decision, and the vaults in the holding area). Null while the vault is locked: this device cannot tell.
     */
    val unsentChanges: Int?,
    /** "Try sending them first" can be offered ([AppApi.sendBeforeSignOut]): the vault is open, its session live, and some wait. */
    val canSendFirst: Boolean,
    internal val origin: String,
    internal val userId: String,
) {
    /** The act needs the person's second confirmation of this check: changes would be lost, or this device cannot tell. */
    val needsConfirmation: Boolean get() = unsentChanges != 0

    /** The line of that confirmation; null when nothing waits. */
    val line: CopyLine?
        get() = when (unsentChanges) {
            null -> CopyLine.of(CopyKey.SIGN_OUT_UNSENT_UNKNOWN)
            0 -> null
            else -> CopyLine.of(CopyKey.SIGN_OUT_UNSENT_LOST, unsentChanges.toString())
        }

    /** The button for [AppApi.sendBeforeSignOut], where [canSendFirst]. */
    val sendFirstLabel: CopyLine? get() = if (canSendFirst) CopyLine.of(CopyKey.SIGN_OUT_SEND_FIRST) else null
}

/** [AppApi.sendBeforeSignOut]. */
enum class SendFirstResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    /** Everything was sent: nothing made on this device is lost by a sign-out now. */
    DONE,

    /** Some changes are still not sent (no answer, or the server refused them): [AppApi.signOutCheck] says how many. */
    NOT_ALL_SENT(sentence = CopyKey.SIGN_OUT_SEND_FIRST_FAILED),

    /** The check is not the one on show, or nothing can be sent now (locked, or the session ended): nothing was done. */
    STALE(Trouble.STALE),
    ;

    override val done: Boolean get() = this == DONE
}

/** How a scanned or pasted payload reached the screen it was handed to. Typing counts as pasting. */
enum class PayloadSource { SCANNED, PASTED }

/**
 * The pinned card's `kind` (§4.1), typed: which copy and which recovery rules apply (§7.7). It grants nothing. It
 * maps one to one to the wire's `InstanceKind` values (`public`, `private`), and it is read only from a pinned card.
 */
enum class ServerKind {
    /** `public`: strangers sign up. Under variant R no operator recovery is ever offered here, whatever its card says. */
    PUBLIC_SERVER,

    /** `private`: a family's own server, where people know the person who runs it. */
    PRIVATE_SERVER,
}

/**
 * An instance as copy names it: the **pinned card's** name and origin, both signed by the operator's key (§4.4).
 * Wherever the name is shown the origin is shown beside it (T-R8). Recovery copy uses these two values and nothing
 * the server reports about an account, such as an operator's display name (§7.7, T2-R-f). Only core makes one, so a
 * value of this type on a screen is the card's word, never a served string.
 */
class InstanceLabel internal constructor(
    /** The card's `name`: plain text. Empty only beside [InstanceCardState.Damaged], where no card can be read. */
    val name: String,
    /** The card's origin, as the origin grammar spells it (§2.2). */
    val origin: String,
    val kind: ServerKind,
    /** Nobody but the server vouches for [name] (a typed-address pin): mark it [CopyKey.AS_THE_SERVER_NAMES_ITSELF] (§4.5). */
    val selfNamed: Boolean,
)

/** Who a row or a sentence names, and whose word the name is. */
sealed class PersonName {
    /**
     * A contact of this account whose pinned key is the key in hand (§6.9 "Labels follow keys"): [label] is the name
     * they chose in the link this account connected with them through.
     */
    class Contact internal constructor(val label: String) : PersonName()

    /**
     * Only the server's word. Show [CopyKey.MEMBER_UNVERIFIED] (or "as the server reports it") with it, never the
     * bare name (T-R5). [serverName] is null when the server gave none.
     */
    class Unverified internal constructor(val serverName: String?) : PersonName()

    /** This account. */
    class You internal constructor() : PersonName()
}

/** A device's platform, as §2.3 lists them ([wireName]). A device reports its own; no screen treats it as verified. */
enum class AppPlatform(val wireName: String) {
    ANDROID("android"),
    IOS("ios"),
    WINDOWS("windows"),
    MACOS("macos"),
    LINUX("linux"),
    WEB("web"),
    CLI("cli"),
    BROWSER_EXTENSION("extension"),

    /** A value this build does not know. */
    UNKNOWN("unknown"),
}

/**
 * The local stores a pre-cut-over build left behind, which the first launch of a new-format build deletes before
 * anything else runs (§12.4, R9). The extension's own records are the extension's to delete.
 */
enum class PreCutoverStore {
    OFFLINE_CACHE,

    /** Saved sessions, and the Keychain or Keystore items that held their tokens. */
    SAVED_SESSIONS,

    /** Device-local trust records. */
    TRUST_RECORDS,
    PERSONAL_WRAP_CACHE,
    QUICK_UNLOCK_KEYS,

    /** iOS: the App Group's AutoFill snapshot and save queue. */
    APP_GROUP_SNAPSHOT_AND_SAVE_QUEUE,
}

/**
 * The platform's side of the first-launch wipe (§12.4): each app deletes its own old stores. [AppApi.start] calls
 * [wipe] for every [PreCutoverStore] that is not yet known to be gone, keyed by a format marker per store, and only
 * then shows the first screen. New builds read none of these stores, so a store that could not be deleted is never
 * opened either way: the marker of such a store stays unset, the next start tries again, and [AppSnapshot.oldData]
 * says so meanwhile.
 */
interface PreCutoverStores {
    /**
     * Delete [store] if this platform has one. True: it is gone, or there was none. False: it is still there.
     * Never throws.
     */
    fun wipe(store: PreCutoverStore): Boolean
}
