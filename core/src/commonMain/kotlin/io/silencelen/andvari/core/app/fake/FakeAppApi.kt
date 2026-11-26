package io.silencelen.andvari.core.app.fake

import io.silencelen.andvari.core.app.AccountSettingsApi
import io.silencelen.andvari.core.app.ContactsApi
import io.silencelen.andvari.core.app.DevicesApi
import io.silencelen.andvari.core.app.EntryApi
import io.silencelen.andvari.core.app.InstanceApi
import io.silencelen.andvari.core.app.KitApi
import io.silencelen.andvari.core.app.LinksApi
import io.silencelen.andvari.core.app.OperatorApi
import io.silencelen.andvari.core.app.RecoveryApi
import io.silencelen.andvari.core.app.SharedVaultsApi
import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AccountSnapshot
import io.silencelen.andvari.core.app.AnsweredLinkRow
import io.silencelen.andvari.core.app.AppApi
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CompareScreen
import io.silencelen.andvari.core.app.ContactRow
import io.silencelen.andvari.core.app.ContactsScreen
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CopyLine
import io.silencelen.andvari.core.app.DeletionBlockerKind
import io.silencelen.andvari.core.app.DeletionBlockerRow
import io.silencelen.andvari.core.app.DeletionPlan
import io.silencelen.andvari.core.app.DeletionScreen
import io.silencelen.andvari.core.app.DesktopAppApi
import io.silencelen.andvari.core.app.DeviceLinkHost
import io.silencelen.andvari.core.app.DeviceRow
import io.silencelen.andvari.core.app.DevicesScreen
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.FirstRunNotice
import io.silencelen.andvari.core.app.HowDeviceJoined
import io.silencelen.andvari.core.app.InstanceCardState
import io.silencelen.andvari.core.app.InstanceDetails
import io.silencelen.andvari.core.app.InstanceLabel
import io.silencelen.andvari.core.app.InstanceSnapshot
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.InviteResult
import io.silencelen.andvari.core.app.JoinMode
import io.silencelen.andvari.core.app.KitReason
import io.silencelen.andvari.core.app.KitScreen
import io.silencelen.andvari.core.app.LinksScreen
import io.silencelen.andvari.core.app.LiveUpdates
import io.silencelen.andvari.core.app.LiveUpdatesTrouble
import io.silencelen.andvari.core.app.LockedScreen
import io.silencelen.andvari.core.app.MasterPasswordPrompt
import io.silencelen.andvari.core.app.MemberRow
import io.silencelen.andvari.core.app.MembersScreen
import io.silencelen.andvari.core.app.MoveEverythingScreen
import io.silencelen.andvari.core.app.MoveMemberRow
import io.silencelen.andvari.core.app.OldDataLeft
import io.silencelen.andvari.core.app.OpenedInvite
import io.silencelen.andvari.core.app.OperatorHelpStage
import io.silencelen.andvari.core.app.OperatorRecoveryWarning
import io.silencelen.andvari.core.app.OwnLinkRow
import io.silencelen.andvari.core.app.OwnershipOfferRow
import io.silencelen.andvari.core.app.PendingShareRow
import io.silencelen.andvari.core.app.PersonName
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.PreCutoverStore
import io.silencelen.andvari.core.app.PreCutoverStores
import io.silencelen.andvari.core.app.RecoveryQuestion
import io.silencelen.andvari.core.app.RecoveryRequestRow
import io.silencelen.andvari.core.app.RecoveryScreen
import io.silencelen.andvari.core.app.RoleInVault
import io.silencelen.andvari.core.app.ServerKind
import io.silencelen.andvari.core.app.ShareChoice
import io.silencelen.andvari.core.app.SharedVaultRow
import io.silencelen.andvari.core.app.SignupStatus
import io.silencelen.andvari.core.app.Subscription
import io.silencelen.andvari.core.app.content.FakeVaultContent
import io.silencelen.andvari.core.app.Trouble
import io.silencelen.andvari.core.app.TrustGatePrompt
import io.silencelen.andvari.core.app.UncomparedShareWarning
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.KitAfterMovePrompt
import io.silencelen.andvari.core.app.QuickUnlockResult
import io.silencelen.andvari.core.app.QuickUnlockSetting
import io.silencelen.andvari.core.app.QuickUnlockState
import io.silencelen.andvari.core.app.ServerPolicy
import io.silencelen.andvari.core.app.TwoStepEnrolment
import io.silencelen.andvari.core.app.TwoStepScreen
import io.silencelen.andvari.core.client.session.QuickUnlockRules
import io.silencelen.andvari.core.app.VaultLogState
import io.silencelen.andvari.core.app.WhoCanRecover
import io.silencelen.andvari.core.client.pin.GateDecision
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.client.pin.GateInput
import io.silencelen.andvari.core.client.pin.GatePayload
import io.silencelen.andvari.core.client.pin.GatePin
import io.silencelen.andvari.core.client.pin.GatePurpose
import io.silencelen.andvari.core.client.pin.GateSession
import io.silencelen.andvari.core.client.pin.PasswordGate
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.client.pin.TrustGateWording
import io.silencelen.andvari.core.trust.MemberRole
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

/**
 * IF-3 in memory: the whole [AppApi] against a scripted world, for previews and UI tests. It has no network and no
 * cryptography, and it is deterministic: the same calls give the same snapshots, ids, codes and kits.
 *
 * **It is not a security boundary and must never be built into a path a person can reach in a release.** It accepts
 * the passwords the script gave its accounts, and "verifies" nothing. What it does keep is the *order* IF-3
 * promises: every screen and prompt is published only after the steps the design puts before it, so a UI built
 * against it meets the same order with the real engine. Its password gate is the engine's own pure function
 * ([PasswordGate.decide]), so which screen comes before which is decided by the same rule as in the product.
 *
 * Where the engine and this fake disagree about a flow, the engine is right and this file is wrong.
 *
 * - [script] sets the world up, plays the other party, and injects outcomes: [FakeScript.forceNext],
 *   [FakeScript.failNext], [FakeScript.holdNext], [FakeScript.advance].
 * - [FakeScenes] puts a fresh fake on any screen in one call.
 *
 * Call it from one thread. Listeners are called on the calling thread, synchronously.
 *
 * **Never in a release build.** iOS: `AndvariBridge.fakeApp` answers nil outside a debug binary.
 * Android and desktop: only `app-android/src/debug`, `src/test`, `src/androidTest` and `app-desktop/src/test` may name
 * this package; a release build compiles `src/main` alone, and `AppApiSurfaceTest` fails when a file there names it.
 *
 * @param platform the platform this app runs on. A phone refuses setup links; [FakeDesktopAppApi] takes them.
 * @param stores what the first-launch wipe deletes; [wiped] records the calls either way.
 * @param contentCrypto the provider each unlock's [FakeVaultContent] runs over (an app's JVM tests hand one of their
 *   own, since the platform's needs its native library); null uses the platform's.
 */
open class FakeAppApi(
    val platform: AppPlatform,
    private val stores: PreCutoverStores?,
    private val contentCrypto: io.silencelen.andvari.core.crypto.CryptoProvider? = null,
) : AppApi, io.silencelen.andvari.core.app.UnlockForFilling {
    constructor() : this(AppPlatform.IOS, null)

    /** The stores the first-launch wipe asked to delete, in order, over every start and retry (§12.4). Empty when this install had run it before. */
    val wiped: MutableList<PreCutoverStore> = ArrayList()

    // ---- the world and this device ----

    internal val servers = LinkedHashMap<String, FakeServer>()
    internal val invites = HashMap<String, FakeInvite>()
    internal val deviceLinks = HashMap<String, FakeDeviceLink>()
    internal val kits = HashMap<String, FakeKit>()
    internal var nowMs: Long = 1_800_000_000_000L
    internal var serial: Int = 1
    internal val deviceId: String = "this-device"
    internal val deviceName: String = when (platform) {
        AppPlatform.ANDROID -> "Pixel"
        AppPlatform.IOS -> "iPhone"
        else -> "Desktop"
    }

    /** The pins this device holds, by origin (§4.4). */
    internal val pins = HashMap<String, MutableList<GatePin>>()

    /** Origins whose pin saw a fork: durable, and cleared only by "Forget this server" (§4.4). */
    internal val forked = HashSet<String>()

    /** Origins whose pin record does not decode: blocked like a fork, never read as "no pin". */
    internal val damaged = HashSet<String>()

    /**
     * Moves followed whose platform data did not move ([FakeScript.namespaceMoveFails]), new origin to old: the server
     * is at the new origin, and nothing is sent or read there until [InstanceApi.finishMove].
     */
    internal val moving = HashMap<String, String>()

    /** The durable block on [s], if any: a fork, a damaged pin record, or a move whose data did not move. */
    internal fun blockOn(s: FakeServer): FakeCard? = when (s.origin) {
        in damaged -> FakeCard.DAMAGED
        in forked -> FakeCard.STOPPED
        in moving -> FakeCard.MOVING
        else -> null
    }

    /** Origins whose card 0 this device signed (a setup pin): "Instance details" shows its hash. */
    internal val signedCard0 = HashSet<String>()

    /** Origins whose `kind`-change gate the person put off until the next unlock. */
    internal val kindPutOff = HashSet<String>()

    internal var phase: AppPhase = AppPhase.STARTING
    internal var entryScreen: EntryScreen? = null
    internal var session: FakeSession? = null

    /**
     * This opening of the signed-in account, as the engine's: a new one at every sign-in and after every lock. A waiting
     * change a screen was handed carries it ([io.silencelen.andvari.core.app.WaitingChange]).
     */
    internal var opening: Any = Any()
    internal var formatMarker: Boolean = false
    internal var storedSession: Pair<FakeServer, FakeAccount>? = null

    /** The server of this device's session, open or locked; null when signed out. */
    internal val sessionServer: FakeServer? get() = session?.server ?: storedSession?.first

    /**
     * As the engine's: a move's notes per account (`<origin>|<userId>`), kept on this device until dismissed, across a lock
     * and a restart; vault ids, a member's id and numbers only, names read when shown.
     */
    internal val moveNotesKept = HashMap<String, MutableList<FakeMoveNote>>()

    /** A request for the operator's help this device holds across restarts. */
    internal var helpRequest: FakeHelpRequest? = null

    /** The contacts that count on this device, by account: they outlive a sign-out (§6.9). */
    internal val confirmedContacts = HashMap<String, HashSet<String>>()

    /** The contacts the person chose not to use on this device, by account: no prompt asks about them again. */
    internal val notUsedContacts = HashMap<String, HashSet<String>>()

    /** The accounts whose list of people (§8.5) the person put off on this device. */
    internal val peoplePutOff = HashSet<String>()

    /** The accounts whose recovery choice was made on this device (§4.5, T2-R-e). */
    internal val ownMirrors = HashSet<String>()

    /** Origins this device followed a move to: a new kit is asked for there until one is made (§4.4, R36). */
    internal val newKitDue = HashSet<String>()

    /** Origins whose new-kit prompt was put off until the next unlock. */
    internal val newKitPutOff = HashSet<String>()

    /** The quick-unlock offer (design 2026-08-23 §7.1): put off, password unlocks since, re-offers made. */
    internal var quickOffer = QuickUnlockRules.ReofferInputs(dismissed = false, unlocks = 0, reoffers = 0)

    /** §12.4: the old stores a wipe could not delete, and whether the person was told. */
    private val storesGone = HashSet<PreCutoverStore>()
    private val oldLeft = ArrayList<PreCutoverStore>()
    private var oldTold = false

    /** The stage directions: the world, the other party, the clock, and injected outcomes. */
    val script: FakeScript = FakeScript(this)

    /** The public instance this build bakes (§0.3), or null in a build without one. */
    internal val baked: FakeServer? get() = if (script.noBakedInstance) null else script.publicInstance

    /** This build takes setup links and has the operator views. */
    internal val takesSetupLinks: Boolean get() = this is DesktopAppApi

    // ---- injected outcomes ----

    internal var forced: IntentResult? = null
    internal var forcedTrouble: Trouble? = null
    internal var retryAfterUntilMs: Long = 0L
    internal var retryAfterNext: Int = 0
    internal var holdArmed: Boolean = false
    private var held: CancellableContinuation<Unit>? = null
    private var busy: Int = 0

    // ---- the parts ----

    private val entryPart = FakeEntry(this)
    private val kitPart = FakeKitFlow(this)
    internal val people = FakePeople(this)
    internal val shared = FakeSharedVaults(this)
    private val own = FakeOwnAccount(this)

    override val entry: EntryApi get() = entryPart
    override val kit: KitApi get() = kitPart
    override val instance: InstanceApi get() = own
    override val contacts: ContactsApi get() = people
    override val links: LinksApi get() = people
    override val vaults: SharedVaultsApi get() = shared
    override val devices: DevicesApi get() = own
    override val recovery: RecoveryApi get() = own
    override val settings: AccountSettingsApi get() = own

    internal val entryFlow: FakeEntry get() = entryPart
    internal val kitFlow: FakeKitFlow get() = kitPart
    internal val ownPart: FakeOwnAccount get() = own

    /** Called after every publish: the operator console of a desktop fake follows the world through it. */
    internal var afterPublish: (() -> Unit)? = null

    // ---- state ----

    private val flow = MutableStateFlow(AppSnapshot(AppPhase.STARTING, null, null, null, null, null, false))
    private val listeners = ArrayList<(AppSnapshot) -> Unit>()
    private var closed = false

    override val snapshot: AppSnapshot get() = flow.value
    override val snapshots: StateFlow<AppSnapshot> get() = flow

    override fun observe(listener: (AppSnapshot) -> Unit): Subscription {
        listeners += listener
        listener(flow.value)
        return object : Subscription {
            override fun close() {
                listeners -= listener
            }
        }
    }

    override fun start() {
        if (phase != AppPhase.STARTING || closed) return
        // §12.4: before anything else, every old store that is not known to be gone.
        if (!formatMarker) wipeOldStores()
        if (storedSession != null) {
            phase = AppPhase.LOCKED
        } else {
            phase = AppPhase.ENTRY
            entryPart.reset(null)
        }
        publish()
    }

    /** One pass of the wipe: each store that is still there is tried; the format marker is set once none is left. */
    private fun wipeOldStores() {
        oldLeft.clear()
        for (store in PreCutoverStore.entries) {
            if (store in storesGone) continue
            wiped += store
            val gone = stores?.wipe(store) ?: (store !in script.oldStoresThatStay)
            if (gone) storesGone += store else oldLeft += store
        }
        formatMarker = oldLeft.isEmpty()
    }

    override fun retryOldDataRemoval(notice: OldDataLeft): Boolean {
        if (closed || snapshot.oldData !== notice) return false
        wipeOldStores()
        publish()
        return oldLeft.isEmpty()
    }

    override fun acknowledgeOldData(notice: OldDataLeft) {
        if (closed || snapshot.oldData !== notice) return
        oldTold = true
        publish()
    }

    /** As the engine's: the line after a sign-in, until dismissed or a lock. */
    internal var signInNotice: io.silencelen.andvari.core.app.CopyLine? = null

    override fun dismissSignInNotice() {
        if (signInNotice == null) return
        signInNotice = null
        publish()
    }

    /** [FakeScript.restart]: the process ends and starts again; only what the device keeps stays. */
    internal fun restart() {
        if (closed) return
        held?.cancel()
        held = null
        lock()
        session = null
        entryScreen = null
        signInNotice = null
        checkShown = null
        forgetShown = null
        openedWithoutKit = false
        away = false
        moveNotesKept.values.forEach { notes -> notes.forEach { it.shown = null } }
        rememberedShown = null
        kept.clear()
        phase = AppPhase.STARTING
        start()
    }

    override fun close() {
        closed = true
        held?.cancel()
        held = null
        listeners.clear()
        dropContent()
    }

    // ---- the vault's content: a FakeVaultContent per unlock ----

    private var contentNow: FakeVaultContent? = null
    private var contentFor: FakeSession? = null
    private var contentSub: Subscription? = null

    /** [contentNow] was composed while "update required" stood for the session's server. */
    private var contentHalted = false

    override val content: io.silencelen.andvari.core.app.content.VaultContent?
        get() = if (phase == AppPhase.UNLOCKED) contentNow else null

    /**
     * The fake content of this unlock, typed for scripting it (`seedLogin`, `failNextWith`, `stopServer`, ...): the
     * same object as [content]. Null while locked or signed out; a new object after every unlock, holding what the same
     * session's content held before the lock (a sign-out or another account starts empty).
     */
    val fakeContent: FakeVaultContent? get() = if (phase == AppPhase.UNLOCKED) contentNow else null

    /** Keep the content in step with the phase: made at an unlock, closed and dropped when the vault is not open. */
    private fun syncContent() {
        val s = session.takeIf { phase == AppPhase.UNLOCKED && !closed }
        if (contentNow != null && (s == null || contentFor !== s)) dropContent()
        // "Update required" of the session's server began or ended: the engine composes the open vault again, read-only
        // while it stands (EngineAppApi.updateRequiredChanged). The fake stops the content it has when it begins (its
        // items stay readable, as the engine's copy does; the object stays the same, where the engine's is new), and
        // composes a new, writable one when it ends (a new object, as on the engine; the fake's new content is empty).
        val haltNow = s != null && s.server.origin in updateRequiredAt
        if (contentNow != null && haltNow != contentHalted) {
            if (haltNow) {
                // Marked first: stopping publishes the content, which publishes this snapshot again.
                contentHalted = true
                contentNow?.stopServer()
            } else {
                dropContent()
                lockedContent = null
            }
        }
        if (s != null && contentNow == null) {
            // The same account at the same server unlocked again (the same session, or a sign-in again after the server
            // ended it): its content survives, as the engine's device copy does, with what waited still waiting. Signed in
            // again, the copy the server's end left read-only opens writable and sends what waited.
            val f = lockedFor
            val same = f != null && (f === s || (f.server.origin == s.server.origin && f.account === s.account))
            val again = lockedContent?.takeIf { same && (!it.state.serverStopped || lockedEnded) }?.let {
                if (lockedEnded && !signedOutByServer) it.signedInAgain() else it.reopened()
            }
            if (again != null && !signedOutByServer) lockedEnded = false
            lockedContent = null
            lockedFor = null
            val c = again ?: contentCrypto?.let { FakeVaultContent(it) } ?: FakeVaultContent()
            // Under a fork the copy opens read-only, as the engine's does (design §4.4); so under "update required".
            if (blockOn(s.server) == FakeCard.STOPPED || haltNow) c.stopServer()
            contentHalted = haltNow
            contentNow = c
            contentFor = s
            var first = true
            contentSub = c.observe { if (first) first = false else if (contentNow === c) publish() }
        }
    }

    /** The last content of [lockedFor], closed by a lock: the next unlock of the same session reopens it ([FakeVaultContent.reopened]). */
    private var lockedContent: FakeVaultContent? = null
    private var lockedFor: FakeSession? = null

    /** [lockedContent] was left read-only by the server's end ([FakeVaultContent.endedByServer]) until a sign-in again. */
    private var lockedEnded = false

    private fun dropContent() {
        contentSub?.close()
        contentSub = null
        lockedContent = contentNow
        lockedFor = contentFor
        contentNow?.close()
        contentNow = null
        contentFor = null
    }

    override fun retryAfterSeconds(): Int = if (retryAfterUntilMs <= nowMs) 0 else ((retryAfterUntilMs - nowMs + 999) / 1000).toInt()

    override suspend fun openAppLink(url: String): InviteResult = when (phase) {
        AppPhase.ENTRY -> entryPart.openAppLink(url)
        AppPhase.UNLOCKED -> people.openAppLink(url)
        else -> InviteResult.STALE
    }

    // ---- the lock screen ----

    override suspend fun unlock(screen: LockedScreen, password: String): VaultUnlockResult = unlockAs(screen, password, forFilling = false)

    /** As the engine: no kit is made for a surface that only fills; the vault opens and the kit waits for the app. */
    override suspend fun unlockForFilling(screen: LockedScreen, password: String): VaultUnlockResult = unlockAs(screen, password, forFilling = true)

    /** [AccountSnapshot.kitDueAtOpening]: opened by [unlockForFilling] while the account's kit is not confirmed; a lock ends it. */
    private var openedWithoutKit = false

    private suspend fun unlockAs(screen: LockedScreen, password: String, forFilling: Boolean): VaultUnlockResult {
        if (phase != AppPhase.LOCKED || snapshot.locked !== screen) return VaultUnlockResult.STALE
        pause()
        injected<VaultUnlockResult>()?.let { return it }
        if (phase != AppPhase.LOCKED || snapshot.locked !== screen) return VaultUnlockResult.STALE
        val (server, account) = storedSession ?: return VaultUnlockResult.STALE
        // The account is opened against this device's pin (§4.4): a damaged record, or none at all, blocks it. A fork
        // does not: it stops traffic, not reading, so what this device already holds opens read-only.
        if (blockOn(server).let { it == FakeCard.DAMAGED || it == FakeCard.MOVING } || !pinnedOrBlocked(server.origin)) return VaultUnlockResult.SERVER_BLOCKED
        // Under a policy that forbids keeping data here no key is kept on the device: the unlock asks the server.
        // As the engine: an ended session is said as that end, and silence with its own sentence.
        if (!server.offlineCacheAllowed && signedOutByServer) return VaultUnlockResult.KEYS_AT_SERVER_ENDED
        if (!server.offlineCacheAllowed && !server.reachable) return VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE
        // Nothing is sent, so nothing counts the tries and no server can be asked.
        if (password != (previousPasswordHere ?: account.password)) return VaultUnlockResult.WRONG_PASSWORD
        if (script.identityFault) {
            script.identityFault = false
            return VaultUnlockResult.IDENTITY_FAULT
        }
        // The master password was typed: the 30-day clock of quick unlock starts again, and the put-off offer counts it.
        script.passwordDue = false
        if (!script.quickUnlock) {
            val d = QuickUnlockRules.reofferDecision(quickOffer)
            quickOffer = QuickUnlockRules.ReofferInputs(quickOffer.dismissed && !d.reoffer, d.unlocks, d.reoffers)
        }
        return opened(server, account, forFilling)
    }

    /** The stored account opens: the password or the biometric opened its keys on this device. */
    private fun opened(server: FakeServer, account: FakeAccount, forFilling: Boolean = false): VaultUnlockResult {
        // An unlock keeps the server's sign-out: the copy opens read-only, as the engine's does.
        val byServer = signedOutByServer
        val s = session ?: beginSession(server, account, HowDeviceJoined.PASSWORD, "", allContactsCurrent = false)
        signedOutByServer = byServer
        // As the engine's key read at an opening: the server answered for the account, so it was not deleted.
        if (!byServer && server.accounts[account.email] === account) script.deletionOutcomeUnknown = false
        // What was put off "until the next unlock" returns now.
        s.keepOperatorNotNow = false
        s.keyChangedLater = false
        kindPutOff -= server.origin
        newKitPutOff -= server.origin
        val kitLeft = forFilling && !account.kitSaved && blockOn(server) == null && !byServer
        if (account.kitSaved || blockOn(server) != null || byServer || kitLeft) {
            // Under a fork nothing is sent, so no kit can be made either: the copy on this device opens as it is. A surface
            // that only fills makes no kit: the vault opens for filling, and the kit waits for the app's next opening.
            openedWithoutKit = kitLeft
            openVault()
        } else {
            openedWithoutKit = false
            // The vault stays shut until a kit is saved (§10): a fresh one, made with the password just given.
            phase = AppPhase.ENTRY
            kitPart.make(account, KitReason.NEVER_SAVED, inEntry = true) { openVault() }
        }
        return VaultUnlockResult.DONE
    }

    /**
     * Quick unlock can be tried for [account] on [server]: it is on, the device has a biometric, the server's policy
     * permits keys at rest, the periodic password is not due, and no kit waits to be made (unless the server is
     * stopped, where none can be made).
     */
    internal fun quickUsable(server: FakeServer, account: FakeAccount): Boolean =
        script.quickUnlock && script.biometricAvailable && server.offlineCacheAllowed && !script.passwordDue &&
            (account.kitSaved || blockOn(server) != null)

    override suspend fun quickUnlock(screen: LockedScreen): QuickUnlockResult {
        if (phase != AppPhase.LOCKED || snapshot.locked !== screen) return QuickUnlockResult.STALE
        pause()
        injected<QuickUnlockResult>()?.let { return it }
        if (phase != AppPhase.LOCKED || snapshot.locked !== screen) return QuickUnlockResult.STALE
        val (server, account) = storedSession ?: return QuickUnlockResult.STALE
        // As the password unlock: a damaged record, or none, blocks it, and before any prompt.
        if (blockOn(server).let { it == FakeCard.DAMAGED || it == FakeCard.MOVING } || !pinnedOrBlocked(server.origin)) return QuickUnlockResult.SERVER_BLOCKED
        if (!quickUsable(server, account)) return QuickUnlockResult.USE_PASSWORD
        when {
            script.biometricsChanged -> {
                script.biometricsChanged = false
                script.quickUnlock = false
                publish()
                return QuickUnlockResult.TURNED_OFF
            }
            script.biometricsCancelled -> {
                script.biometricsCancelled = false
                return QuickUnlockResult.CANCELLED
            }
            script.biometricsRefused -> {
                script.biometricsRefused = false
                return QuickUnlockResult.USE_PASSWORD
            }
        }
        if (script.identityFault) {
            script.identityFault = false
            script.quickUnlock = false
            publish()
            return QuickUnlockResult.IDENTITY_FAULT
        }
        // Nothing is sent, and no password is involved: the account's key opens what this device holds.
        opened(server, account)
        return QuickUnlockResult.DONE
    }

    /** The fake's content keeps no save queue: nothing to read. */
    /** As the engine: nothing of the app is on show from [wentAway] to [returnedToForeground]. */
    internal var away = false
        private set

    override fun wentAway() {
        away = true
    }

    override fun returnedToForeground() {
        if (!away) return
        away = false
        kitFlow.seenNow()
    }

    /** How many times [networkReturned] reached an open vault (the fake has no bell): a screen test can see the call landed. */
    var networkReturns: Int = 0
        private set

    override fun networkReturned() {
        if (phase == AppPhase.UNLOCKED && !closed) networkReturns++
    }

    override fun lock() {
        if (closed) return
        signInNotice = null
        // As the engine: a kit on show in the journey holds the account's keys; a lock wipes it and goes to the lock
        // screen, and the next unlock makes a fresh kit.
        if (phase == AppPhase.ENTRY) {
            // As the engine: a lock between the forgetting's two steps takes the confirmation back.
            entryPart.lockedDuringEntry()
            // As the engine: a kit of a committed change shown with a refusal is wiped on every road, and the screen the
            // person comes back to says so until it is dismissed ([dismissKitWiped]).
            val wiped = kitPart.wipeNotKeptAtLock(anotherKept = storedSession != null)
            if (wiped != null) kitWiped = wiped
            val s = session
            if (s != null && s.kit?.inEntry == true && storedSession != null) {
                s.kit = null
                phase = AppPhase.LOCKED
                publish()
            } else if (wiped != null) {
                // As the engine: the first screen it comes back to keeps its mark of a kept session not confirmed, so that
                // line and the notice of the wiped kit stand side by side.
                if (entryScreen == null) entryPart.reset(null, notConfirmed = entryPart.notConfirmedShown())
                publish()
            }
            return
        }
        if (phase != AppPhase.UNLOCKED) return
        val s = session ?: return
        openedWithoutKit = false
        // The account's keys go, and with them every screen that showed what they open.
        s.contactsOpen = false
        s.comparing = null
        s.linksOpen = false
        s.opened = null
        s.notUsed = null
        s.membersOf = null
        s.warning = null
        if (s.moving?.running != true) s.moving = null
        s.devicesOpen = false
        s.recoveryOpen = false
        s.reviewing = false
        if (s.kit?.inEntry == false) s.kit = null
        s.deletionOpen = false
        s.deletionPlanned = false
        s.deletionRetrying = false
        // A two-step key being set up stays for the trip to the authenticator: the next unlock shows its confirm step.
        s.twoStepOpen = false
        opening = Any()
        phase = AppPhase.LOCKED
        publish()
    }

    /** Where a sign-out acts, as in the engine: locked, unlocked, a kit on show, or the journey after "Sign in again". */
    private fun signOutPossible(): Boolean {
        val atKit = phase == AppPhase.ENTRY && (session?.kit?.inEntry == true || (signedOutByServer && storedSession != null))
        return phase == AppPhase.LOCKED || phase == AppPhase.UNLOCKED || atKit
    }

    private var checkShown: io.silencelen.andvari.core.app.SignOutCheck? = null

    /**
     * As the script sets it ([FakeScript.waitingInMemory]) while the fake keeps its copy as a durable cache would; after
     * the policy's wipe ([copyInMemory]) the changes waiting in the copy in memory are counted, as the engine's.
     */
    override fun waitingInMemory(): Int? {
        if (!copyInMemory) return script.waitingInMemory
        val c = (if (phase == AppPhase.UNLOCKED) contentNow else lockedContent) ?: return 0
        return c.state.queued + c.state.held.sumOf { c.waitingChanges(it.vaultId).size }
    }

    /** The policy's wipe took the kept account's copy ([FakeScript.policyCopyRemoved]): it goes on in memory. */
    internal var copyInMemory = false

    override fun policyWipeOwed(origin: String, userId: String): Boolean = script.policyWipeOwed

    /**
     * As the engine: counted from the open content (its changes waiting); an account whose content was never made on
     * this device has none; otherwise (locked, a copy kept from before) this device cannot tell.
     */
    override fun signOutCheck(): io.silencelen.andvari.core.app.SignOutCheck? {
        if (!signOutPossible()) return null
        val (server, account) = storedSession ?: return null
        val open = contentNow.takeIf { phase == AppPhase.UNLOCKED }
        val count = unsentHere()
        val canSend = open != null && count != null && count > 0 && !open.state.serverStopped && !signedOutByServer
        val shown = checkShown
        if (shown != null && shown.origin == server.origin && shown.userId == account.userId && shown.unsentChanges == count && shown.canSendFirst == canSend) {
            return shown
        }
        return io.silencelen.andvari.core.app.SignOutCheck(count, canSend, server.origin, account.userId).also { checkShown = it }
    }

    /**
     * The kept account's changes not sent, as the engine counts them for a sign-out and for a forgetting: from the open
     * content (the changes parked with held vaults too); none where its content was never made here; null (cannot tell)
     * for a copy kept closed.
     */
    private fun unsentHere(): Int? {
        val open = contentNow.takeIf { phase == AppPhase.UNLOCKED }
        return when {
            open != null -> open.state.queued + open.state.held.sumOf { open.waitingChanges(it.vaultId).size }
            lockedContent != null -> null
            else -> 0
        }
    }

    override suspend fun signOutConfirmed(check: io.silencelen.andvari.core.app.SignOutCheck): PlainResult {
        val now = signOutCheck() ?: return PlainResult.STALE
        if (now.needsConfirmation && now !== check) return PlainResult.UNSENT_NOT_CONFIRMED
        return signOutNow()
    }

    override suspend fun sendBeforeSignOut(check: io.silencelen.andvari.core.app.SignOutCheck): io.silencelen.andvari.core.app.SendFirstResult {
        val now = signOutCheck() ?: return io.silencelen.andvari.core.app.SendFirstResult.STALE
        if (now.origin != check.origin || now.userId != check.userId) return io.silencelen.andvari.core.app.SendFirstResult.STALE
        if (now.unsentChanges == 0) return io.silencelen.andvari.core.app.SendFirstResult.DONE
        if (!now.canSendFirst) return io.silencelen.andvari.core.app.SendFirstResult.STALE
        contentNow?.refresh()
        val after = signOutCheck() ?: return io.silencelen.andvari.core.app.SendFirstResult.STALE
        return when (after.unsentChanges) {
            0 -> io.silencelen.andvari.core.app.SendFirstResult.DONE
            null -> io.silencelen.andvari.core.app.SendFirstResult.STALE
            else -> io.silencelen.andvari.core.app.SendFirstResult.NOT_ALL_SENT
        }
    }

    private var forgetShown: io.silencelen.andvari.core.app.ForgetUnknownDeletion? = null

    /**
     * As the engine: offered wherever the kept account's deletion has an outcome not known, in any phase but the start,
     * with the changes not sent counted as a sign-out counts them (none open: "cannot tell"); a new object wherever what
     * it says changed, so one shown before a lock no longer holds after it.
     */
    override fun forgetAfterUnknownDeletionCheck(): io.silencelen.andvari.core.app.ForgetUnknownDeletion? {
        val (server, account) = storedSession?.takeIf { script.deletionOutcomeUnknown && phase != AppPhase.STARTING } ?: return null.also { forgetShown = null }
        val unsent = unsentHere()
        val shown = forgetShown
        if (shown != null && shown.origin == server.origin && shown.userId == account.userId && shown.unsentChanges == unsent) return shown
        return io.silencelen.andvari.core.app.ForgetUnknownDeletion(account.email, label(server), server.origin, account.userId, unsent).also { forgetShown = it }
    }

    /** As the engine: exactly that account goes from this device, its copy with it; the server's pin stays. */
    override suspend fun forgetAfterUnknownDeletion(check: io.silencelen.andvari.core.app.ForgetUnknownDeletion): PlainResult {
        if (forgetAfterUnknownDeletionCheck() !== check) return PlainResult.STALE
        val (_, account) = storedSession ?: return PlainResult.STALE
        forgetShown = null
        // The end of that session at its server, best effort.
        account.devices.firstOrNull { it.deviceId == deviceId }?.live = false
        confirmedContacts.remove(account.userId)
        notUsedContacts.remove(account.userId)
        peoplePutOff -= account.userId
        ownMirrors -= account.userId
        endSession(null)
        // As the engine: the copy (closed by the end above) goes with it, and with it every change not sent, as the
        // confirmation said.
        lockedContent = null
        lockedFor = null
        return PlainResult.DONE
    }

    override suspend fun signOut(): PlainResult {
        val check = signOutCheck() ?: return PlainResult.STALE
        if (check.needsConfirmation) return PlainResult.UNSENT_NOT_CONFIRMED
        return signOutNow()
    }

    /** The sign-out itself, once the rule above is met (also the switch to another server's invitation). */
    internal suspend fun signOutNow(): PlainResult {
        if (!signOutPossible()) return PlainResult.STALE
        pause()
        injected<PlainResult>()?.let { return it }
        val stored = storedSession ?: return PlainResult.STALE
        if (!signOutPossible()) return PlainResult.STALE
        checkShown = null
        // The server is told, best effort; the session is gone from this device whatever it answered.
        stored.second.devices.firstOrNull { it.deviceId == deviceId }?.live = false
        endSession(null)
        return PlainResult.DONE
    }

    // ---- shared machinery ----

    /** Publish a new snapshot built from the model. Parts of it that did not change keep their identity. */
    internal fun publish() {
        if (closed) return
        syncContent()
        usedSlots.clear()
        if (phase == AppPhase.ENTRY) entryPart.refresh()
        val shown = if (phase == AppPhase.ENTRY) entryScreen else null
        val s = AppSnapshot(
            phase = phase,
            entry = shown,
            locked = if (phase == AppPhase.LOCKED) lockedScreen() else null,
            account = session?.takeIf { phase == AppPhase.UNLOCKED }?.let(::accountSnapshot),
            // The server of the screen on show, signed out; the session's otherwise. Never anything else.
            instance = when {
                phase == AppPhase.ENTRY -> (shown?.flow as? FakeFlow)?.server?.let(::instanceSnapshot)
                phase == AppPhase.STARTING -> null
                else -> sessionServer?.let(::instanceSnapshot)
            },
            oldData = if (oldLeft.isEmpty()) null else keep("old", "$oldLeft:$oldTold") { OldDataLeft(oldLeft.toList(), tellNow = !oldTold) },
            busy = busy > 0,
            keptSignedOut = if (phase == AppPhase.ENTRY && signedOutByServer) lockedScreen()?.prompt else null,
            keptSignedOutNotConfirmed = phase == AppPhase.ENTRY && signedOutByServer && sessionNotConfirmed,
            keptSignedOutLine = if (phase == AppPhase.ENTRY && signedOutByServer && sessionNotConfirmed) io.silencelen.andvari.core.app.CopyKey.SESSION_NOT_CONFIRMED else null,
            keptSignedOutSignOutFirstLine = if (phase == AppPhase.ENTRY && signedOutByServer && sessionNotConfirmed) {
                io.silencelen.andvari.core.app.CopyKey.SESSION_NOT_CONFIRMED_SIGN_OUT_FIRST
            } else null,
            containedFaults = script.containedFaults,
            earlierAccount = if (phase == AppPhase.ENTRY) entryPart.earlierOnShow() else null,
            rememberedNewAccount = rememberedNotice(),
            kitWiped = kitWiped,
            policyWipe = policyWipeOnShow(),
            // As the engine: owed for the kept account's own copy only, from the policy's record until the copy is gone.
            policyWipeOwed = policyWipeOwedFor != null && policyWipeOwedFor == (session?.account ?: storedSession?.second)?.userId,
        )
        kept.keys.retainAll { it in usedSlots }
        flow.value = s
        for (l in listeners.toList()) l(s)
        afterPublish?.invoke()
    }

    /**
     * The start of every `suspend` intent's work: where a test's hold stops it ([FakeScript.holdNext]), with
     * [AppSnapshot.busy] set until [FakeScript.releaseHold].
     */
    internal suspend fun pause() {
        if (!holdArmed) return
        holdArmed = false
        busy++
        publish()
        try {
            suspendCancellableCoroutine<Unit> { held = it }
        } finally {
            held = null
            busy--
            publish()
        }
    }

    /**
     * The checks every `suspend` intent of the signed-in account starts with, then [body]: signed in and unlocked, a
     * test's hold, an injected outcome, and a server that answers and is not stopped.
     */
    internal suspend inline fun <reified R> act(body: (FakeSession) -> R): R where R : Enum<R>, R : IntentResult {
        if (session == null || phase != AppPhase.UNLOCKED) return troubled(Trouble.STALE)
        pause()
        injected<R>()?.let { return it }
        val s = session
        if (s == null || phase != AppPhase.UNLOCKED) return troubled(Trouble.STALE)
        // As the engine: while the copy is being removed for the policy, a shared vault's change is refused with its line.
        if (R::class == io.silencelen.andvari.core.app.VaultActionResult::class && fakeContent?.state?.removingLine != null) {
            return io.silencelen.andvari.core.app.VaultActionResult.REMOVING_COPY as R
        }
        val trouble = sessionTrouble()
        // The session's server's "update required" changed with this answer: the instance on show says so now.
        if (updateChanged) {
            updateChanged = false
            publish()
        }
        trouble?.let { return troubled(it) }
        return body(s)
    }

    internal fun releaseHold() {
        val h = held
        held = null
        h?.resume(Unit)
    }

    internal val holding: Boolean get() = held != null

    /** The outcome a test injected for this intent's result type, if any; it is used once. */
    internal inline fun <reified R> injected(): R? where R : Enum<R>, R : IntentResult {
        val f = forced
        if (f is R) {
            forced = null
            noteRateLimit(f.trouble)
            return f
        }
        val t = forcedTrouble ?: return null
        forcedTrouble = null
        noteRateLimit(t)
        return troubled<R>(t)
    }

    /** As the engine: the wait in force now, kept with an end it stopped (the fake's server always names one). */
    internal fun namedWait(): io.silencelen.andvari.core.app.NamedWait? =
        if (retryAfterUntilMs > nowMs) io.silencelen.andvari.core.app.NamedWait(retryAfterUntilMs) { nowMs } else null

    internal fun noteRateLimit(t: Trouble?) {
        if (t == Trouble.RATE_LIMITED) {
            retryAfterUntilMs = nowMs + (if (retryAfterNext > 0) retryAfterNext else 30) * 1000L
            retryAfterNext = 0
        }
    }

    /** The trouble a server gives before anything else: no answer, or a build too old. */
    internal fun reach(s: FakeServer): Trouble? {
        if (!s.reachable) return Trouble.UNREACHABLE
        // The server answered: "update required" or not, which the instance on show carries.
        answeredUpdate(s, s.tooNewForThisBuild)
        return if (s.tooNewForThisBuild) Trouble.UPDATE_REQUIRED else null
    }

    /** The servers whose latest answer was "update required", as the engine's keeper keeps them (a screen's state only). */
    private val updateRequiredAt = HashSet<String>()

    /** Set when [updateRequiredAt] changed; [act] publishes it (an intent of the session reached its server). */
    @PublishedApi internal var updateChanged = false

    private fun answeredUpdate(s: FakeServer, needed: Boolean) {
        val changed = if (needed) updateRequiredAt.add(s.origin) else updateRequiredAt.remove(s.origin)
        if (changed) updateChanged = true
    }

    /** The trouble for an intent of the signed-in account: the server's, or a stopped instance (§4.4 fork: no writes). */
    internal fun sessionTrouble(): Trouble? {
        val s = session ?: return Trouble.STALE
        if (phase != AppPhase.UNLOCKED) return Trouble.STALE
        if (blockOn(s.server) != null) return Trouble.FAILED
        return reach(s.server)
    }

    internal fun label(s: FakeServer): InstanceLabel {
        val roots = pins[s.origin].orEmpty().map { it.root }
        val vouched = roots.any { it == PinRoot.BAKED || it == PinRoot.LINK_OFFER || it == PinRoot.KIT || it == PinRoot.SETUP }
        return keep("label:${s.origin}", "${s.name}:${s.kind}:$vouched") { InstanceLabel(s.name, s.origin, s.kind, selfNamed = !vouched) }
    }

    internal fun signup(s: FakeServer): SignupStatus = SignupStatus(
        mode = if (s.reachable) s.mode else JoinMode.NOT_KNOWN,
        full = s.full,
        ageConfirmRequired = s.ageConfirmRequired,
        proofOfWork = s.powBits > 0,
    )

    internal fun pin(s: FakeServer, root: PinRoot, account: String?) {
        val list = pins.getOrPut(s.origin) { ArrayList() }
        if (list.none { it.root == root && it.account == account }) list += GatePin(s.origin, root, account)
    }

    /**
     * The engine's own password gate (§4.4), asked as the real controller asks it. The entry is the one IF-3's
     * shape allows for the purpose: a device link is only ever started from "Link from your other device" and a
     * kit recovery from "Scan your recovery kit", so the gate's `refuse_entry` for a wrong screen cannot be
     * reached through this API.
     */
    internal fun gate(purpose: GatePurpose, s: FakeServer, account: String?): GateDecision = PasswordGate.decide(
        GateInput(
            purpose = purpose,
            entry = when (purpose) {
                GatePurpose.DEVICE_LINK -> GateEntry.LINK_DEVICE_SCREEN
                GatePurpose.KIT_RECOVERY -> GateEntry.KIT_RECOVERY_SCREEN
                GatePurpose.REAUTH -> null
                else -> GateEntry.SERVER_CHOICE
            },
            payload = when (purpose) {
                GatePurpose.DEVICE_LINK -> GatePayload.D
                GatePurpose.KIT_RECOVERY -> GatePayload.KIT
                else -> null
            },
            origin = s.origin,
            account = account,
            pins = pins.values.flatten().map { if (it.origin in forked || it.origin in damaged) it.copy(blocked = true) else it },
            session = session?.let { GateSession(it.server.origin, it.account.email) },
        ),
    )

    /**
     * What a Trust Gate for [s] shows. "Switch to a different server?" when this device already uses another one:
     * it holds a session or a pin for another origin (§12.3 "when one is set"). That is a fact of the pin store,
     * not of where the journey happens to be.
     */
    internal fun gatePrompt(s: FakeServer, wording: TrustGateWording, kitChanged: Boolean, typedKit: Boolean): TrustGatePrompt = TrustGatePrompt(
        wording = wording,
        origin = s.origin,
        name = s.name,
        operatorKeyShort = s.operatorKeyShort,
        switching = wording != TrustGateWording.KIND_CHANGE && ((sessionServer != null && sessionServer !== s) || pins.keys.any { it != s.origin }),
        punycodeCaution = s.origin.contains("xn--"),
        httpCaution = s.origin.startsWith("http://"),
        kitIdentityChanged = kitChanged,
        typedKit = typedKit,
        claimedKind = if (wording == TrustGateWording.KIND_CHANGE) {
            if (s.kind == ServerKind.PUBLIC_SERVER) ServerKind.PRIVATE_SERVER else ServerKind.PUBLIC_SERVER
        } else {
            null
        },
    )

    /** A session of [account] on this device begins. The vault opens only when [openVault] is called. */
    internal fun beginSession(s: FakeServer, account: FakeAccount, how: HowDeviceJoined, linkedFrom: String, allContactsCurrent: Boolean): FakeSession {
        opening = Any()
        val known = account.devices.firstOrNull { it.deviceId == deviceId }
        val device = known ?: FakeDevice(deviceId, deviceName, platform, how).also {
            it.addedAtMs = nowMs
            it.linkedFrom = linkedFrom
            account.devices += it
        }
        device.live = true
        device.lastSeenAtMs = nowMs
        account.knownDevices += deviceId
        val made = FakeSession(
            s, account,
            passwordOnly = how == HowDeviceJoined.PASSWORD && known == null,
            currentContacts = confirmedContacts.getOrPut(account.userId) { HashSet() },
        )
        if (allContactsCurrent) account.contacts.forEach { made.currentContacts += it.userId }
        made.peopleListDue = made.passwordOnly && account.contacts.any { it.userId !in made.currentContacts }
        // §4.5: a device has its own mirror of the recovery record only when the choice was made on it.
        if (how == HowDeviceJoined.REGISTERED) ownMirrors += account.userId
        // The copy the policy's wipe left in memory was another account's (or one signed out since): this one's is kept as usual.
        if (storedSession?.second?.userId != account.userId) copyInMemory = false
        session = made
        storedSession = s to account
        takeCount++
        // A session made here (a sign-in again included) is the server's again; an unlock keeps the mark (see unlock).
        signedOutByServer = false
        sessionNotConfirmed = false
        return made
    }

    /**
     * As the engine (design §4.4): the server ended the session, and the account stays on this device as signed out by
     * the server, its copy kept and opened read-only with the password, until the person signs in again or out.
     */
    internal var signedOutByServer = false

    /**
     * As the engine: another account than the one at [server] under [norm] is kept on this device, so a session to it
     * would be refused and nothing is sent. A null [norm] tells nothing apart at the same server.
     */
    internal fun keptOther(server: FakeServer, norm: String?): Boolean {
        val (s, a) = storedSession ?: return false
        if (s.origin != server.origin) return true
        return norm != null && norm != FakeText.emailNorm(a.email)
    }

    /** As the engine's end where no try of a refresh is left: kept like a server's end, said as its own. */
    internal fun endedUnconfirmed() {
        if (storedSession == null) return
        endedByServer()
        sessionNotConfirmed = true
        publish()
    }

    /** How many sessions this fake took: a new take is a new kept copy ([MasterPasswordPrompt.keptMark]). */
    private var takeCount = 0

    /** As the engine: the opaque mark of the kept copy, the same while it is kept, another after each take. */
    internal fun keptMark(): String = storedSession?.let { "${it.first.origin}|${it.second.userId}|$takeCount" }.orEmpty()

    /** [LockedScreen.sessionNotConfirmed]: the kept session's end was this device's own (it could not confirm it in time). */
    private var sessionNotConfirmed = false

    internal fun endedByServer() {
        if (storedSession == null) return endSession(FirstRunNotice.SIGNED_OUT_BY_SERVER)
        // As the engine: the copy stays with every change still waiting, read-only until the sign-in again.
        contentNow?.let {
            it.endedByServer()
            lockedEnded = true
        }
        session = null
        openedWithoutKit = false
        script.quickUnlock = false
        signedOutByServer = true
        phase = AppPhase.LOCKED
        entryScreen = null
        publish()
    }

    /** [AppSnapshot.kitWiped]: set by a lock that wiped a kit shown with a refusal; only [dismissKitWiped] takes it. */
    private var kitWiped: io.silencelen.andvari.core.app.KitWipedNotice? = null

    /** As the engine: the notice that a kit is gone goes only with this dismissal of that very notice. */
    override fun dismissKitWiped(notice: io.silencelen.andvari.core.app.KitWipedNotice) {
        if (notice !== kitWiped) return
        kitWiped = null
        publish()
    }

    /** After a forgetting: the address, for the one notice when the next account under it is signed in here. */
    private var remembering: Pair<String, String>? = null
    private var rememberedShown: io.silencelen.andvari.core.app.NewAccountRememberedNotice? = null

    /** As the engine: matched by the server and the address. */
    internal fun rememberAfterForgetting(origin: String, email: String) {
        remembering = origin to email
    }

    /** As the engine's mark at rest: the notice raised for this server and address, kept until it is dismissed. */
    private var rememberedAt: Pair<String, String>? = null

    private fun rememberedNotice(): io.silencelen.andvari.core.app.NewAccountRememberedNotice? {
        val s = session
        remembering?.let { (origin, email) ->
            if (s != null && s.server.origin == origin && s.account.email.equals(email, ignoreCase = true)) {
                remembering = null
                rememberedAt = origin to email
                rememberedShown = io.silencelen.andvari.core.app.NewAccountRememberedNotice(email)
            }
        }
        // After a restart: raised again from the mark while that account is kept.
        val at = rememberedAt
        val kept = storedSession
        if (rememberedShown == null && at != null && kept != null && kept.first.origin == at.first && kept.second.email.equals(at.second, ignoreCase = true)) {
            rememberedShown = io.silencelen.andvari.core.app.NewAccountRememberedNotice(at.second)
        }
        return rememberedShown
    }

    /** As the engine: the mark and its notice go with [origin]'s forgetting, or with the deletion of [email]'s account there. */
    internal fun forgetRemembered(origin: String, email: String? = null) {
        fun matches(p: Pair<String, String>?) = p != null && p.first == origin && (email == null || p.second.equals(email, ignoreCase = true))
        if (matches(remembering)) remembering = null
        if (matches(rememberedAt)) {
            rememberedAt = null
            rememberedShown = null
        }
    }

    override fun dismissNewAccountRemembered(notice: io.silencelen.andvari.core.app.NewAccountRememberedNotice) {
        if (rememberedShown !== notice) return
        rememberedShown = null
        rememberedAt = null
        publish()
    }

    /** [AppSnapshot.policyWipe] as the script played it ([FakeScript.policyCopyRemoved]). */
    internal var policyWipe: io.silencelen.andvari.core.app.PolicyWipeNotice? = null

    /** The account whose copy's removal a forbidding policy made owed ([FakeScript.policyForbidsCopy]); survives a restart. */
    internal var policyWipeOwedFor: String? = null

    /** The account whose notice [policyWipe] is; null: anyone's. */
    internal var policyWipeOwner: String? = null

    /** As the engine: inside a kept session only that account's own notice; any notice where none is kept. */
    private fun policyWipeOnShow(): io.silencelen.andvari.core.app.PolicyWipeNotice? {
        val kept = (session?.account ?: storedSession?.second)?.userId
        return policyWipe?.takeIf { kept == null || policyWipeOwner == null || policyWipeOwner == kept }
    }

    override fun dismissPolicyWipe(notice: io.silencelen.andvari.core.app.PolicyWipeNotice) {
        if (closed || policyWipe !== notice || policyWipeOnShow() !== notice) return
        policyWipe = null
        publish()
    }

    override fun signInAgain(screen: LockedScreen) {
        if (phase != AppPhase.LOCKED || snapshot.locked !== screen || !signedOutByServer) return
        phase = AppPhase.ENTRY
        val kept = storedSession
        val unknown = if (!script.deletionOutcomeUnknown || kept == null) null
        else io.silencelen.andvari.core.app.DeletionOutcomeUnknownNotice(kept.second.email, label(kept.first))
        if (sessionNotConfirmed) entryPart.reset(null, unknown = unknown, notConfirmed = true)
        else entryPart.reset(FirstRunNotice.SIGNED_OUT_BY_SERVER, unknown = unknown)
        publish()
    }

    /** The vault opens. */
    internal fun openVault() {
        val s = session ?: return
        if (s.twoStepPending != null) s.twoStepOpen = true
        phase = AppPhase.UNLOCKED
        entryScreen = null
        publish()
    }

    /** The session ends on this device; the journey starts again, at a first screen that says [notice] when given. */
    internal fun endSession(notice: FirstRunNotice?, deleted: io.silencelen.andvari.core.app.AccountDeletedNotice? = null) {
        // As the engine: the account's move notes go with its session, kept or not.
        listOfNotNull(storedSession, session?.let { it.server to it.account }).forEach { (server, account) ->
            moveNotesKept.remove(server.origin + "|" + account.userId)
        }
        session = null
        // As the engine: every end of a session ends an opening for filling without its kit.
        openedWithoutKit = false
        storedSession = null
        signedOutByServer = false
        sessionNotConfirmed = false
        previousPasswordHere = null
        script.deletionOutcomeUnknown = false
        // Quick unlock goes with the session: its sealed key was the account's.
        script.quickUnlock = false
        quickOffer = QuickUnlockRules.ReofferInputs(dismissed = false, unlocks = 0, reoffers = 0)
        kept.clear()
        phase = AppPhase.ENTRY
        entryPart.reset(notice, deleted)
        publish()
    }

    /** Everything this device holds about [server]'s namespace goes: its pin with any block, and what it kept of its accounts. */
    internal fun dropNamespace(server: FakeServer) {
        pins.remove(server.origin)
        forked -= server.origin
        damaged -= server.origin
        moving -= server.origin
        signedCard0 -= server.origin
        kindPutOff -= server.origin
        newKitDue -= server.origin
        newKitPutOff -= server.origin
        moveNotesKept.keys.removeAll { it.startsWith(server.origin + "|") }
        forgetRemembered(server.origin)
        server.accounts.values.forEach {
            confirmedContacts.remove(it.userId)
            notUsedContacts.remove(it.userId)
            peoplePutOff -= it.userId
            ownMirrors -= it.userId
            // As the engine: the mark that a kit was shown here is a record of that server.
            it.kitShownUnconfirmed = false
        }
        if (helpRequest?.server === server) helpRequest = null
    }

    // ---- snapshots ----

    private class Kept(val signature: String, val parts: List<Any?>, val value: Any)

    private val kept = HashMap<String, Kept>()
    private val usedSlots = HashSet<String>()

    /** The object in [slot] as long as its content, [signature], is the same; a new one otherwise. */
    private fun <T : Any> keep(slot: String, signature: String, build: () -> T): T = keepOf(slot, emptyList(), signature, build)

    /**
     * As [keep], for an object made of other kept objects: it stays while [parts] are the very same objects, in the
     * same order, and [signature] is the same.
     */
    @Suppress("UNCHECKED_CAST")
    private fun <T : Any> keepOf(slot: String, parts: List<Any?>, signature: String, build: () -> T): T {
        usedSlots += slot
        val old = kept[slot]
        if (old != null && old.signature == signature && old.parts.size == parts.size && parts.indices.all { old.parts[it] === parts[it] }) {
            return old.value as T
        }
        val made = build()
        kept[slot] = Kept(signature, parts, made)
        return made
    }

    /** What the last check of [s]'s chain found on this device: its durable block first, then what the server serves. */
    internal fun cardOf(s: FakeServer): FakeCard {
        blockOn(s)?.let { return it }
        val bakedHere = script.storeBuild && s === baked
        return when {
            s.kindChangedUnderPin -> if (bakedHere) FakeCard.UPDATE_CHANGED else FakeCard.KIND_CHANGED
            s.movedUnderPinTo != null -> if (bakedHere) FakeCard.UPDATE_MOVED else FakeCard.MOVED
            s.servesOlderChain -> FakeCard.WITHHELD
            s.newerCardDoesNotVerify -> FakeCard.NOT_VERIFIED
            else -> FakeCard.OK
        }
    }

    /** This device holds a pin for [origin], in force or blocked: a move there would replace it. */
    internal fun pinnedOrBlocked(origin: String): Boolean = pins.containsKey(origin) || origin in forked || origin in damaged

    /** [s] as a screen shows it; null while this device holds no pin for it, in force or blocked. The same object while nothing it shows changed. */
    internal fun instanceSnapshot(s: FakeServer): InstanceSnapshot? {
        if (!pinnedOrBlocked(s.origin)) return null
        val o = s.origin
        // A damaged record has no card to read a name from: the origin alone.
        val l = if (blockOn(s) == FakeCard.DAMAGED) keep("label:$o", "damaged") { InstanceLabel("", o, s.kind, selfNamed = true) } else label(s)
        val state: InstanceCardState = when (cardOf(s)) {
            FakeCard.DAMAGED -> keep("card:$o", "damaged") { InstanceCardState.Damaged() }
            FakeCard.OK -> keep("card:$o", "ok") { InstanceCardState.Ok() }
            FakeCard.STOPPED -> keep("card:$o", "stopped") { InstanceCardState.Stopped() }
            FakeCard.WITHHELD -> keep("card:$o", "withheld") { InstanceCardState.Withheld() }
            FakeCard.NOT_VERIFIED, FakeCard.MOVING -> keep("card:$o", "not-verified") { InstanceCardState.NotVerified() }
            FakeCard.MOVED -> {
                val to = s.movedUnderPinTo.orEmpty()
                val taken = pinnedOrBlocked(to)
                keepOf("card:$o", listOf(l), "moved:$to:$taken") { InstanceCardState.Moved(l, to, alreadyPinnedThere = taken) }
            }
            FakeCard.KIND_CHANGED -> {
                val putOff = o in kindPutOff
                keep("card:$o", "kind:${s.name}:${s.kind}:$putOff") { InstanceCardState.KindChanged(gatePrompt(s, TrustGateWording.KIND_CHANGE, false, false), putOff) }
            }
            FakeCard.UPDATE_MOVED -> keep("card:$o", "update-moved") { InstanceCardState.UpdateAndvari(CopyKey.CARD_MOVED_UPDATE) }
            FakeCard.UPDATE_CHANGED -> keep("card:$o", "update-changed") { InstanceCardState.UpdateAndvari(CopyKey.CARD_CHANGED_UPDATE) }
        }
        val d = details(s)
        val from = moving[o]
        val unfinished = from?.let { keep("unfinished:$o", it) { io.silencelen.andvari.core.app.UnfinishedMove(it) } }
        // Only the session's own server carries "update required", as on the engine.
        val update = sessionServer?.origin == o && o in updateRequiredAt
        return keepOf("instance:$o", listOf(l, state, d, unfinished), "$update") { InstanceSnapshot(l, state, d, unfinished, update) }
    }

    internal fun details(s: FakeServer): InstanceDetails {
        val hash = FakeText.hex32("card0:${s.origin}") + FakeText.hex32("card0b:${s.origin}")
        val card0 = if (s.origin in signedCard0) hash else ""
        // Every pin shows the first card's hash it holds, as the engine does.
        val pinned0 = if (pins.containsKey(s.origin)) hash else ""
        return keep("details:${s.origin}", "${s.operatorKeyShort}:$card0:$pinned0") {
            InstanceDetails(operatorKeyShort = s.operatorKeyShort, cardSeq = 0L, card0Hash = card0, pinnedCard0Hash = pinned0)
        }
    }

    private fun lockedScreen(): LockedScreen? {
        val (server, account) = storedSession ?: return null
        val l = if (blockOn(server) == FakeCard.DAMAGED) keep("label:${server.origin}", "damaged") { InstanceLabel("", server.origin, server.kind, selfNamed = true) } else label(server)
        val quick = quickUsable(server, account) && !signedOutByServer
        val byServer = signedOutByServer
        val previous = previousPasswordHere != null
        val unknown = script.deletionOutcomeUnknown
        val atServer = !server.offlineCacheAllowed
        val notConfirmed = byServer && sessionNotConfirmed
        val mark = keptMark()
        return keepOf("locked", listOf(l), "${account.email}:$quick:$byServer:$previous:$unknown:$notConfirmed:$mark:$atServer") {
            LockedScreen(MasterPasswordPrompt(account.email, l, mark), quick, byServer, previous, unknown, notConfirmed, if (atServer) CopyLine.of(CopyKey.UNLOCK_KEYS_AT_SERVER) else null)
        }
    }

    /** The password this device's copy still opens with after a change it could not follow (a script's choice); null when it followed. */
    internal var previousPasswordHere: String? = null

    internal fun currentPrompts(): List<AccountPrompt> = snapshot.account?.prompts.orEmpty()

    /** The name the person gave the device that made [c], when the account's device list names it; empty otherwise. */
    private fun madeOn(a: FakeAccount, c: FakeContact): String {
        val id = c.madeOnDeviceId ?: return ""
        if (id == deviceId) return deviceName
        return a.devices.firstOrNull { it.deviceId == id }?.name.orEmpty()
    }

    private fun accountSnapshot(s: FakeSession): AccountSnapshot {
        val a = s.account
        val l = label(s.server)
        // A vault that waited for its sender to be confirmed here asks now that they are (§3.6).
        for (v in a.vaults) {
            val sender = v.sharedByContact
            if (v.log == VaultLogState.CONFIRM_FIRST && sender != null && sender.userId in s.currentContacts) {
                v.log = VaultLogState.VERIFIED
                v.incomingFrom = sender.label
                v.incomingAddSeq = v.seq++
            }
        }
        val rows = a.contacts.sortedBy { it.label }.map { contactRow(s, it) }

        val prompts = ArrayList<AccountPrompt>()
        val live = a.helpRequests.filter { (it.stage == OperatorHelpStage.HOLDING || it.stage == OperatorHelpStage.AWAITING_OPERATOR) && it.requestId !in a.helpRequestsMine }
        // As the engine: rows the server sent that cannot be read are dropped and counted, and the
        // alert is raised for them, saying the details cannot be shown.
        val unreadableAlert = (a.unreadableHelpRows > 0 || a.helpListUnread) && !a.unreadableHelpDismissed
        if (live.isNotEmpty() || unreadableAlert) {
            prompts += keep("p:requests", live.joinToString { "${it.requestId}:${it.stage}:${it.fulfilled}" } + ":$unreadableAlert") {
                AccountPrompt.RecoveryRequest(live.map(::requestRow), unreadable = unreadableAlert)
            }
        }
        // §6.7 Resume: offered at every unlock of the operator account, where a card can be signed (desktop only).
        if (takesSetupLinks && a.isOperator && !s.server.hasCard) {
            prompts += keep("p:setup", s.server.origin) { AccountPrompt.FinishServerSetup(s.server.origin) }
        }
        val optedIn = a.whoCanRecover == WhoCanRecover.ME_OR_OPERATOR && s.server.offersOperatorRecovery
        if (optedIn && a.recoveryKeyChangedUnsigned && !s.keyChangedLater) {
            prompts += keep("p:keychanged", l.name + l.origin) { AccountPrompt.RecoveryKeyChanged(l) }
        } else if (optedIn && a.userId !in ownMirrors && !s.keepOperatorNotNow && !a.recoveryKeyChangedUnsigned) {
            prompts += keep("p:keepop", l.name + l.origin) { AccountPrompt.KeepOperatorRecovery(l) }
        }
        s.connectionNotMade?.let { n ->
            val retry = n.why == io.silencelen.andvari.core.app.ConnectResult.UNREACHABLE || n.why == io.silencelen.andvari.core.app.ConnectResult.NAME_NEEDED
            prompts += keep("p:notconnected", "${n.invite.payload}:${n.why}") { AccountPrompt.ConnectionNotMade(n.invite.from.orEmpty(), n.why, retry) }
        }
        for (c in a.contacts.filter { it.keyChangeWaiting }) {
            prompts += keep("p:key:${c.userId}", c.label) { AccountPrompt.KeyChanged(c.userId, c.label) }
        }
        val notCurrent = a.contacts.filter { it.userId !in s.currentContacts }
        val putOff = a.userId in peoplePutOff
        if (s.peopleListDue) {
            // One list, once (§8.5). Put off, it waits for the person to ask, or for someone on it to share a vault.
            if (!putOff && notCurrent.isNotEmpty()) {
                val operatorClause = a.whoCanRecover == WhoCanRecover.ME_OR_OPERATOR
                val listed = notCurrent.sortedBy { it.label }.map { contactRow(s, it) }
                prompts += keepOf("p:people", listed, "$operatorClause") { AccountPrompt.PeopleList(listed, operatorClause) }
            }
        } else {
            // One tap each (§6.9), except for the people this device was told not to use.
            val notUsed = notUsedContacts[a.userId].orEmpty()
            for (c in notCurrent.filter { it.userId !in notUsed }) {
                val from = madeOn(a, c)
                prompts += keep("p:new:${c.userId}", c.label + ":" + from) { AccountPrompt.NewPerson(c.userId, c.label, from) }
            }
        }
        for (v in a.vaults.filter { it.incomingFrom != null && it.vaultId !in s.hidden }) {
            prompts += keep("p:incoming:${v.vaultId}:${v.incomingAddSeq}", v.incomingFrom + v.name) {
                AccountPrompt.IncomingVault(v.vaultId, v.incomingFrom.orEmpty(), v.name, v.incomingAddSeq)
            }
        }

        val vaultRows = a.vaults.filter { it.incomingFrom == null && it.vaultId !in s.hidden }
            .sortedBy { it.name }.map { vaultRow(s, it) }

        val notReviewed = s.peopleListDue && putOff && notCurrent.isNotEmpty()
        val contactsScreen = if (s.contactsOpen) keepOf("contacts", rows, "$notReviewed") { ContactsScreen(rows, notReviewed) } else null
        val comparing = s.comparing?.let { id -> a.contacts.firstOrNull { it.userId == id } }?.let { c ->
            when {
                c.linkFailed -> keep("compare", "failed:${c.userId}") { CompareScreen.LinkFailed(c.userId, c.label) }
                c.compared && !c.keyChangeWaiting -> keep("compare", "matched:${c.userId}") { CompareScreen.Matched(c.userId, c.label) }
                c.codesReady -> keep("compare", "ready:${c.userId}:${c.code}:${c.keyChangeWaiting}") { CompareScreen.Ready(c.userId, c.label, c.code, c.keyChangeWaiting) }
                else -> keep("compare", "waiting:${c.userId}") { CompareScreen.Waiting(c.userId, c.label) }
            }
        }
        val linksScreen = if (s.linksOpen) {
            val linkRows = s.ownLinks.filter { it.open && it.expiresAtMs > nowMs }.map { ownLinkRow(it) }
            // An answered link stays listed with its contact until the two have compared codes.
            s.answered.removeAll { it.contact.compared && !it.contact.keyChangeWaiting || it.contact !in a.contacts }
            val answeredRows = s.answered.map { n ->
                val row = contactRow(s, n.contact)
                keepOf("answered:${n.linkId}", listOf(row), "${n.keyChanged}") { AnsweredLinkRow(n.linkId, row, n.keyChanged) }
            }
            val waiting = a.contacts.flatMap { c -> c.waitingShares.map { c to it } }.mapNotNull { (c, share) ->
                val v = a.vaults.firstOrNull { it.vaultId == share.vaultId } ?: return@mapNotNull null
                keep("share:${c.userId}:${v.vaultId}", c.label + v.name + share.role) { PendingShareRow(v.vaultId, v.name, share.role, c.userId, c.label) }
            }
            val mayInvite = a.isOperator || (s.server.kind == ServerKind.PRIVATE_SERVER && s.server.membersMayInvite)
            keepOf("links", linkRows + answeredRows + waiting, "${linkRows.size}:${answeredRows.size}:$mayInvite") {
                LinksScreen(linkRows, answeredRows, waiting, mayInvite)
            }
        } else {
            null
        }
        val opened = s.opened?.let { o ->
            when (o.kind) {
                FakeOpenedKind.CONNECT -> keep("opened", "connect:${o.invite.payload}") { OpenedInvite.Connect(label(o.invite.server), o.invite.from.orEmpty()) }
                FakeOpenedKind.KEY_CHANGED -> keep("opened", "key:${o.invite.payload}") { OpenedInvite.KeyChanged(o.invite.newKeyOf?.label.orEmpty()) }
                FakeOpenedKind.OTHER_INSTANCE -> {
                    val theirs = label(o.invite.server)
                    keepOf("opened", listOf(theirs, l), "other:${o.invite.payload}:${s.requireLinkSetHere}") { OpenedInvite.OtherInstance(theirs, l, s.requireLinkSetHere) }
                }
                FakeOpenedKind.TRUST_GATE -> keepOf("opened", listOf(l), "gate:${o.invite.payload}") {
                    OpenedInvite.TrustGate(gatePrompt(o.invite.server, TrustGateWording.ENROL_LINK, false, false), l)
                }
                FakeOpenedKind.SERVER_CHANGED -> instanceSnapshot(o.invite.server)?.let { theirs ->
                    keepOf("opened", listOf(theirs), "server:${o.invite.payload}") { OpenedInvite.ServerChanged(theirs) }
                }
                FakeOpenedKind.CONNECTED -> o.contact?.let { c ->
                    val row = contactRow(s, c)
                    keepOf("opened", listOf(row), "connected:${o.invite.payload}") { OpenedInvite.Connected(row) }
                }
            }
        }
        val members = s.membersOf?.let { id -> a.vaults.firstOrNull { it.vaultId == id } }?.let { v ->
            val row = vaultRow(s, v)
            val memberRows = v.members.sortedBy { if (it.userId == a.userId) "" else it.serverName }.map { m ->
                val current = m.contact?.takeIf { it.userId in s.currentContacts }
                val sig = "${m.role}:${m.deletedByOperator}:${current?.label}:${m.serverName}"
                keep("member:${v.vaultId}:${m.userId}", sig) {
                    MemberRow(v.vaultId, m.userId, nameOf(s, m), m.role, m.deletedByOperator)
                }
            }
            val manage = v.role == RoleInVault.OWNER && row.writable
            keepOf("members", listOf(row) + memberRows, "${v.historyHint}:$manage") {
                MembersScreen(row, memberRows, mayBeIncomplete = v.historyHint, canManage = manage)
            }
        }
        val warning = s.warning?.let { w ->
            keep("warning", "${w.vault.vaultId}:${w.contact.userId}:${w.role}") {
                UncomparedShareWarning(w.vault.vaultId, w.vault.name, w.contact.userId, w.contact.label, w.role)
            }
        }
        val moving = s.moving?.let { m ->
            val row = vaultRow(s, m.vault)
            val sig = m.vault.members.filter { it.userId != a.userId }.joinToString { member ->
                val current = member.contact?.takeIf { it.userId in s.currentContacts }
                "${member.userId}:${member.role}:${member.userId in m.ticked}:${current?.label}:${member.serverName}"
            } + ":${m.running}:${m.copied}:${m.short}:${m.removing}:${m.stop}:${m.finished}:${m.vault.unreadable}"
            keepOf("moving", listOf(row), sig) {
                fun rowOf(member: FakeMember): MoveMemberRow {
                    val current = member.contact?.takeIf { it.userId in s.currentContacts }
                    return MoveMemberRow(
                        userId = member.userId,
                        who = nameOf(s, member),
                        role = if (member.role == RoleInVault.READER) MemberRole.READER else MemberRole.WRITER,
                        // A vault in good standing adds every remaining member it can; a frozen or failed one the ticked only.
                        ticked = current != null && (if (m.sourceStays) member.userId in m.ticked else member.userId != m.removing),
                        canBeAdded = current != null,
                    )
                }
                val memberRows = m.vault.members.filter { it.userId != a.userId && it.userId != m.removing && it.role != RoleInVault.OWNER }.map(::rowOf)
                val kept = when {
                    m.sourceStays -> io.silencelen.andvari.core.app.MoveKept.SOURCE_STAYS
                    memberRows.any { !it.canBeAdded } -> io.silencelen.andvari.core.app.MoveKept.MEMBER_CANNOT_BE_ADDED
                    m.vault.unreadable > 0 -> io.silencelen.andvari.core.app.MoveKept.UNREADABLE_ITEMS
                    else -> null
                }
                MoveEverythingScreen(
                    row, sourceStays = m.sourceStays, members = memberRows, shortOfSpace = m.short, running = m.running, copied = m.copied,
                    total = m.vault.itemCount, removing = m.removing?.let { r -> m.vault.members.firstOrNull { it.userId == r } }?.let(::rowOf),
                    ticksOffered = m.sourceStays, unreadable = m.vault.unreadable, oldVaultKept = kept,
                    whatMoves = io.silencelen.andvari.core.app.CopyKey.MOVE_ONLY_LIVE_ITEMS, stopped = m.stop, finished = m.finished,
                    space = m.space,
                )
            }
        }
        val devicesScreen = if (s.devicesOpen) {
            val set = s.requireLinkSetHere
            val sig = a.devices.joinToString { "${it.deviceId}:${it.live}:${it.name}:${it.lastSeenAtMs}" } + set
            keep("devices", sig) {
                val deviceRows = a.devices.sortedBy { if (it.deviceId == deviceId) 0 else 1 }.map { d ->
                    DeviceRow(d.deviceId, d.platform, d.name, d.clientVersion, d.addedAtMs, d.lastSeenAtMs, d.live, d.how, d.linkedFrom, current = d.deviceId == deviceId)
                }
                // As on the engine: the server serves no read of "New devices must be linked", so only what this
                // device set in this session is known.
                DevicesScreen(deviceRows, set ?: false, requireLinkKnown = set != null)
            }
        } else {
            null
        }
        val hostLink: DeviceLinkHost? = s.hostLink?.let { h ->
            when (h.step) {
                FakeHostStep.SHOWN -> keepOf("host", listOf(l), "shown") { DeviceLinkHost.Shown(l) }
                FakeHostStep.CLAIMED -> keep("host", "claimed:${h.name}") { DeviceLinkHost.Claimed(h.name, h.platform) }
                FakeHostStep.TYPE_DIGITS -> keep("host", "digits:${h.name}") { DeviceLinkHost.TypeDigits(h.name, h.platform) }
                FakeHostStep.APPROVABLE -> quickUsable(s.server, s.account).let { offered ->
                    keep("host", "approvable:${h.name}:$offered") { DeviceLinkHost.Approvable(h.name, h.platform, offered) }
                }
                FakeHostStep.APPROVED -> keep("host", "approved:${h.name}") { DeviceLinkHost.Approved(h.name) }
                FakeHostStep.ENDED -> keep("host", "ended:${h.end}:${h.endLine}") { DeviceLinkHost.Ended(h.end, h.endLine, h.endWait) }
            }
        }
        val recoveryScreen = if (s.recoveryOpen) {
            val offered = s.server.offersOperatorRecovery && !a.isOperator
            val unsigned = s.server.unsignedRecoveryKeyChange
            // As the engine: a request the person marked "This was me" leaves the alert, and Settings still lists it.
            val listed = a.helpRequests.filter { it.stage == OperatorHelpStage.HOLDING || it.stage == OperatorHelpStage.AWAITING_OPERATOR }
            val requestRows = if (a.helpListUnread) emptyList() else listed.map(::requestRow)
            val sig = "${a.whoCanRecover}:$offered:$unsigned:${s.reviewing}:${a.unreadableHelpRows}:${a.helpListUnread}"
            keepOf("recovery", listOf<Any?>(l) + requestRows, sig) {
                RecoveryScreen(
                    whoCanRecover = a.whoCanRecover,
                    question = if (offered) RecoveryQuestion(l, unsigned) else null,
                    warning = if (s.reviewing && offered) OperatorRecoveryWarning(l, unsigned) else null,
                    requests = requestRows,
                    unreadableRequests = if (a.helpListUnread) 0 else a.unreadableHelpRows,
                    requestsNotRead = a.helpListUnread,
                )
            }
        } else {
            null
        }
        val kitScreen = s.kit?.takeIf { !it.inEntry }?.let { kitScreen(it) }
        val deletion = if (s.deletionOpen) {
            val sig = "${s.deletionPlanned}:${s.deletionRetrying}:${s.deletionUnknown}:" + a.vaults.joinToString { "${it.vaultId}:${it.role}:${it.members.size}:${it.purgeAtMs}" } + a.twoStepCode + a.isOperator
            keep("deletion", sig) { DeletionScreen(a.email, if (s.deletionPlanned) deletionPlan(a) else null, s.deletionRetrying, s.deletionUnknown) }
        } else {
            null
        }

        return AccountSnapshot(
            email = a.email,
            accountId = a.accountId,
            operatorAccount = a.isOperator,
            serverStopped = blockOn(s.server) == FakeCard.STOPPED || signedOutByServer,
            signedOutByServer = signedOutByServer,
            sessionNotConfirmed = signedOutByServer && sessionNotConfirmed,
            endLine = if (signedOutByServer && sessionNotConfirmed) io.silencelen.andvari.core.app.CopyKey.SESSION_NOT_CONFIRMED_COPY_OPEN else null,
            prompts = prompts,
            vaults = vaultRows,
            contacts = contactsScreen,
            comparing = comparing,
            links = linksScreen,
            opened = opened,
            members = members,
            shareWarning = warning,
            moving = moving,
            devices = devicesScreen,
            deviceLink = hostLink,
            recovery = recoveryScreen,
            kit = kitScreen,
            deletion = deletion,
            quickUnlock = quickSetting(s),
            policy = policyOf(s.server),
            twoStep = if (s.twoStepOpen) {
                val pending = s.twoStepPending != null
                val enrolment = if (pending) keep("twostep-enrol", s.twoStepPending.orEmpty()) { TwoStepEnrolment() } else null
                keepOf("twostep", listOf(enrolment), "${a.twoStepCode != null}") { TwoStepScreen(a.twoStepCode != null, enrolment) }
            } else {
                null
            },
            kitAfterMove = if (s.server.origin in newKitDue && s.server.origin !in newKitPutOff && blockOn(s.server) == null) {
                keepOf("newkit", listOf(l), "") { KitAfterMovePrompt(l) }
            } else {
                null
            },
            contentRevision = contentNow?.state?.revision ?: 0L,
            inviteNotUsed = s.notUsed,
            // As the engine: none for a stopped server, a copy the server signed out or a server that wants a newer build;
            // otherwise connected exactly while the server answers and its live updates connect.
            liveUpdates = when {
                blockOn(s.server) != null || signedOutByServer || s.server.tooNewForThisBuild -> LiveUpdates.NOT_RUNNING
                s.server.reachable && s.server.liveUpdatesConnect -> LiveUpdates(running = true, connected = true, trouble = null)
                else -> LiveUpdates(running = true, connected = false, trouble = LiveUpdatesTrouble.NOT_OPENED)
            },
            unfinishedMoves = vaultRows.mapNotNull { row ->
                val line = row.unfinishedMove ?: return@mapNotNull null
                if (row.vaultId in s.movesPutOff || s.moving?.vault?.vaultId == row.vaultId) return@mapNotNull null
                keepOf("unfinished:${row.vaultId}", listOf(row), "") { io.silencelen.andvari.core.app.UnfinishedVaultMove(row, line.key == CopyKey.MOVE_DELETE_WAITING, line) }
            },
            signInNotice = signInNotice,
            kitDueAtOpening = openedWithoutKit && !s.account.kitSaved,
            movesStoredOutside = s.account.vaults.filter { it.storedOutsideInto != null }.sortedBy { it.vaultId }.map { v ->
                val into = v.storedOutsideInto.orEmpty()
                val late = v.lateAdded + v.lateChanged
                keep("stored:${v.vaultId}", "${v.name}|$into|${v.lateAdded}|${v.lateChanged}|${v.lateCopied}|${v.deletionsKept}") {
                    io.silencelen.andvari.core.app.MoveStoredNotice(
                        v.vaultId, v.name, s.account.vaults.firstOrNull { it.name == into }?.vaultId, into, v.lateAdded, v.lateChanged, late > 0,
                        if (late > 0) io.silencelen.andvari.core.app.CopyLine.of(CopyKey.MOVE_STORED_OUTSIDE, v.name, into, v.lateAdded.toString(), v.lateChanged.toString())
                        else io.silencelen.andvari.core.app.CopyLine.of(CopyKey.MOVE_STORED_OUTSIDE_NOTHING_LATE, v.name, into),
                        v.lateCopied?.let { io.silencelen.andvari.core.app.CopyLine.of(CopyKey.MOVE_STORED_COPIED, it.toString(), into) },
                        // As the engine: no deletion is carried for now; each one waiting is kept, counted and said.
                        deletionsKept = v.deletionsKept,
                        keptLine = if (v.deletionsKept > 0) io.silencelen.andvari.core.app.CopyLine.of(CopyKey.MOVE_STORED_DELETIONS_KEPT, v.deletionsKept.toString(), into) else null,
                    )
                }
            },
            moveNotes = shared.moveNotes(s),
            waitingNotices = shared.waitingNotices(s),
        )
    }

    private fun quickSetting(s: FakeSession): QuickUnlockSetting {
        val state = when {
            !script.biometricAvailable -> QuickUnlockState.UNAVAILABLE
            script.quickUnlock -> QuickUnlockState.ON
            !s.server.offlineCacheAllowed -> QuickUnlockState.NOT_ALLOWED
            else -> QuickUnlockState.OFF
        }
        val offer = state == QuickUnlockState.OFF && !quickOffer.dismissed && blockOn(s.server) == null
        return keep("quick", "$state:$offer") { QuickUnlockSetting(state, offer) }
    }

    /** [s]'s policy as the engine applies it: clamped to the client's bounds. */
    private fun policyOf(s: FakeServer): ServerPolicy {
        val autoLock = io.silencelen.andvari.core.client.session.clampAutoLockSeconds(s.autoLockSeconds)
        val clipboard = s.clipboardClearSeconds.coerceIn(1, io.silencelen.andvari.core.client.ClientPolicyClamps.CLIPBOARD_CLEAR_MAX_SECONDS)
        val kept = !s.offlineCacheAllowed && platform == AppPlatform.ANDROID
        return keep("policy:${s.origin}", "$autoLock:$clipboard:${s.offlineCacheAllowed}:${s.attachmentMaxBytes}:${s.itemAttachmentsMaxBytes}:$kept") {
            ServerPolicy(true, autoLock, clipboard, s.offlineCacheAllowed, s.attachmentMaxBytes, s.itemAttachmentsMaxBytes,
                if (kept) CopyLine.of(CopyKey.POLICY_CAPTURES_KEPT_SEALED) else null)
        }
    }

    /** Who a member of a verified log is, and whose word that is: this account, a contact current here, or only the server's name. */
    internal fun nameOf(s: FakeSession, m: FakeMember): PersonName {
        val current = m.contact?.takeIf { it.userId in s.currentContacts }
        return when {
            m.userId == s.account.userId -> PersonName.You()
            current != null -> PersonName.Contact(current.label)
            else -> PersonName.Unverified(m.serverName.ifEmpty { null })
        }
    }

    internal fun contactRow(s: FakeSession, c: FakeContact): ContactRow {
        val current = c.userId in s.currentContacts
        val from = madeOn(s.account, c)
        return keep("contact:${c.userId}", "${c.label}:${c.compared}:$current:${c.codesReady}:${c.linkFailed}:${c.revealWaiting}:$from") {
            ContactRow(c.userId, c.label, c.connectedAtMs, c.compared, current, from, c.codesReady && !c.linkFailed,
                canCompare = !c.linkFailed && (c.codesReady || c.revealWaiting))
        }
    }

    private fun requestRow(r: FakeHelpRequest): RecoveryRequestRow =
        keep("request:${r.requestId}", "${r.stage}:${r.holdEndsAtMs}:${r.fulfilled}") {
            // A request the operator answered (`ready`) is listed as answered: whoever made it can set a password now.
            RecoveryRequestRow(r.requestId, r.stage, r.createdAtMs, r.verifiedAtMs, r.holdEndsAtMs, r.platform, answered = r.fulfilled)
        }

    internal fun ownLinkRow(link: FakeOwnLink): OwnLinkRow = keep("link:${link.linkId}", link.shares.joinToString { it.vaultId + it.role }) {
        OwnLinkRow(link.linkId, link.kind, link.shares.map { ShareChoice(it.vaultId, it.role) })
    }

    internal fun vaultRow(s: FakeSession, v: FakeVault): SharedVaultRow {
        val a = s.account
        // Before a log verified, nothing is known of the vault but who the server says sent it.
        val unverified = v.log == VaultLogState.CONNECT_FIRST || v.log == VaultLogState.CONFIRM_FIRST || v.log == VaultLogState.NOT_CHECKED_YET
        val closed = unverified || v.log == VaultLogState.KEY_REFUSED || v.log == VaultLogState.KEY_MISSING
        // Nothing is written to a vault whose history does not check out, nor to any vault of a stopped server.
        val stopped = blockOn(s.server) != null
        val readOnly = v.log != VaultLogState.VERIFIED || stopped
        val offer = v.offer?.takeIf { it.expiresAtMs > nowMs }
        val ownerMember = if (unverified) null else v.members.firstOrNull { it.role == RoleInVault.OWNER }
        val ownerCurrent = ownerMember?.contact?.takeIf { it.userId in s.currentContacts }
        val toConfirm = if (v.log == VaultLogState.CONFIRM_FIRST) v.sharedByContact?.takeIf { it in a.contacts }?.let { contactRow(s, it) } else null
        val waiting = v.log == VaultLogState.CONNECT_FIRST || v.log == VaultLogState.CONFIRM_FIRST
        val sig = "${v.name}:${v.role}:${v.log}:${v.historyHint}:${v.ownerOutOfSpace}:${v.purgeAtMs}:${v.heldUntilMs}:${v.removedByOwner}:" +
            "${offer?.toUserId}:${offer?.expiresAtMs}:${v.sharedByServerName}:${v.changeWaiting}:${ownerMember?.userId}:${ownerCurrent?.label}:${ownerMember?.serverName}:$stopped:" +
            "${v.moveUnfinishedInto}:${v.moveDeleteWaiting}:${script.servesGraceDay}:" +
            v.waiting?.let { w -> "${w.kind}:${w.memberId}:${w.role}:${w.known}:${w.firstOut}:${w.looked}:${nowMs - w.sinceMs < FakeScript.DAY}" } +
            ":${s.moving?.running}:${s.movesStopped[v.vaultId]?.copied}"
        return keepOf("vault:${v.vaultId}", listOf(toConfirm), sig) {
            SharedVaultRow(
                vaultId = v.vaultId,
                name = if (closed) null else v.name,
                role = if (closed || v.log == VaultLogState.REMOVED) null else v.role,
                log = v.log,
                owner = ownerMember?.let { nameOf(s, it) },
                sharedBy = if (waiting) PersonName.Unverified(v.sharedByServerName) else null,
                senderToConfirm = toConfirm,
                historyHint = v.historyHint,
                ownerOutOfSpace = v.ownerOutOfSpace,
                // As the engine: a day only where the server served one; deleted either way.
                purgeAtMs = if (script.servesGraceDay) v.purgeAtMs else 0L,
                deleted = v.purgeAtMs > 0L,
                heldUntilMs = v.heldUntilMs,
                removedByOwner = v.removedByOwner,
                offer = offer?.let { o ->
                    val member = v.members.firstOrNull { it.userId == o.toUserId }
                    val contact = member?.contact
                    val who: PersonName = when {
                        o.toUserId == a.userId -> PersonName.You()
                        contact != null -> PersonName.Contact(contact.label)
                        else -> PersonName.Unverified(member?.serverName)
                    }
                    OwnershipOfferRow(who, toMe = o.toUserId == a.userId, expiresAtMs = o.expiresAtMs)
                },
                changeWaiting = v.changeWaiting,
                writable = !readOnly && v.purgeAtMs == 0L && v.role != RoleInVault.READER && !v.moveDeleteWaiting,
                readOnlyLine = if (v.moveDeleteWaiting && !readOnly && v.purgeAtMs == 0L && v.role != RoleInVault.READER) {
                    io.silencelen.andvari.core.app.CopyLine.of(CopyKey.MOVE_WAITING_READ_ONLY, v.name, v.moveUnfinishedInto.orEmpty())
                } else null,
                canSaveElsewhere = !closed,
                canRemoveFromDevice = v.log == VaultLogState.FAILED || v.log == VaultLogState.WITHHELD || v.log == VaultLogState.FROZEN ||
                    v.log == VaultLogState.PURGED || v.log == VaultLogState.REMOVED,
                unfinishedMove = v.moveUnfinishedInto?.let { into ->
                    io.silencelen.andvari.core.app.CopyLine.of(if (v.moveDeleteWaiting) CopyKey.MOVE_DELETE_WAITING else CopyKey.MOVE_UNFINISHED, v.name, into)
                },
                // As the engine: the owner's, on a verified, frozen or failed history, not deleted, its items copyable.
                canMoveEverything = !closed && v.role == RoleInVault.OWNER && v.purgeAtMs == 0L &&
                    (v.log == VaultLogState.VERIFIED || v.log == VaultLogState.FROZEN || v.log == VaultLogState.FAILED),
                waiting = shared.waitingRow(s, v),
                frozenMoveClose = shared.frozenMoveLine(s, v),
            )
        }
    }

    internal fun kitScreen(k: FakeKitState): KitScreen {
        val l = label(k.account.server)
        // As the engine: every kit has its idle limit from the server's policy (at most five minutes with a refusal), and a
        // kit that replaces one shown here and never confirmed says so on its reveal.
        val (limit, warnBefore, warning) = KitScreen.idleLimits(
            io.silencelen.andvari.core.client.session.clampAutoLockSeconds(k.account.server.autoLockSeconds), k.notKeptLine != null,
        )
        val void = if (k.replacesShown && k.step == io.silencelen.andvari.core.app.KitStep.REVEAL) CopyKey.KIT_EARLIER_NOT_CONFIRMED_VOID else null
        return keepOf("kit", listOf(l), "${k.reason}:${k.step}:${k.groups}:${k.tries}:${k.account.kitSerial}:${k.account.email}:${k.notKeptLine}:$limit:$void") {
            KitScreen(k.reason, k.step, k.account.email, l, if (k.step == io.silencelen.andvari.core.app.KitStep.CONFIRM) k.groups else emptyList(), k.tries, k.notKeptLine,
                limit, warnBefore, warning, void)
        }
    }

    private fun deletionPlan(a: FakeAccount): DeletionPlan {
        val owned = a.vaults.filter { it.role == RoleInVault.OWNER && it.incomingFrom == null }
        val blockers = ArrayList<DeletionBlockerRow>()
        for (v in owned) {
            val others = v.members.count { it.userId != a.userId && !it.deletedByOperator }
            if (others > 0 && v.purgeAtMs == 0L) blockers += DeletionBlockerRow(DeletionBlockerKind.SHARED_VAULT_WITH_OTHERS, v.name, others)
        }
        if (a.isOperator) blockers += DeletionBlockerRow(DeletionBlockerKind.OPERATOR_ACCOUNT, null, 0)
        if (script.unknownDeletionBlocker) blockers += DeletionBlockerRow(DeletionBlockerKind.NOT_KNOWN, null, 0)
        return DeletionPlan(
            deletedVaults = listOf("Personal") + owned.filter { v -> v.members.none { it.userId != a.userId } || v.purgeAtMs > 0L }.map { it.name },
            leftVaults = a.vaults.filter { it.role != RoleInVault.OWNER && it.role != null }.map { it.name },
            blockers = blockers,
            codeNeeded = a.twoStepCode != null,
        )
    }
}

/**
 * The fake of a desktop app (or `andvari-cli`): everything [FakeAppApi] is, plus the operator views and setup
 * links. Only this class has them, as only [DesktopAppApi] does.
 */
class FakeDesktopAppApi(
    stores: PreCutoverStores?,
    contentCrypto: io.silencelen.andvari.core.crypto.CryptoProvider? = null,
) : FakeAppApi(AppPlatform.LINUX, stores, contentCrypto), DesktopAppApi {
    constructor() : this(null)

    private val console = FakeOperator(this)
    override val operatorApi: OperatorApi get() = console

    /**
     * The fake has no item engine to restore into: no file opens here and no vault is open for a restore. The restore
     * runs over [io.silencelen.andvari.core.app.engine.EngineDesktopAppApi].
     */
    override val restores: io.silencelen.andvari.core.app.BackupRestoreApi = object : io.silencelen.andvari.core.app.BackupRestoreApi {
        override suspend fun open(passphrase: CharArray, bytes: ByteArray): io.silencelen.andvari.core.client.restore.RestoreOpening {
            passphrase.fill('\u0000')
            return io.silencelen.andvari.core.client.restore.RestoreOpening.NotOpened(io.silencelen.andvari.core.client.Backup.ERR_UNKNOWN_FORMAT)
        }

        override suspend fun preview(file: io.silencelen.andvari.core.client.restore.RestoreFile): io.silencelen.andvari.core.client.restore.RestorePreview? = null

        override fun recordInMemoryOnly(): Boolean? = null

        override fun unfinishedRestore(): Boolean = false

        override suspend fun restore(
            file: io.silencelen.andvari.core.client.restore.RestoreFile,
            choice: io.silencelen.andvari.core.client.restore.RestoreChoice,
            events: (io.silencelen.andvari.core.client.restore.RestoreEvent) -> Unit,
        ): io.silencelen.andvari.core.client.restore.RestoreResult? = null

        override suspend fun restoreAgain(
            file: io.silencelen.andvari.core.client.restore.RestoreFile,
            vaults: Set<String>,
            events: (io.silencelen.andvari.core.client.restore.RestoreEvent) -> Unit,
        ): io.silencelen.andvari.core.client.restore.RestoreResult? = null
    }
}

/** What the last check of the card chain found, in the fake. */
internal enum class FakeCard { OK, STOPPED, DAMAGED, WITHHELD, NOT_VERIFIED, MOVED, KIND_CHANGED, UPDATE_MOVED, UPDATE_CHANGED, MOVING }

/** The entry of an [R] for [t]: every result type has one for every [Trouble]. */
internal inline fun <reified R> troubled(t: Trouble): R where R : Enum<R>, R : IntentResult =
    enumValues<R>().first { it.trouble == t }
