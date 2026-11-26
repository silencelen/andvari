package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AccountSettingsApi
import io.silencelen.andvari.core.app.AccountSnapshot
import io.silencelen.andvari.core.app.AppApi
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.ContactsApi
import io.silencelen.andvari.core.app.DevicesApi
import io.silencelen.andvari.core.app.EntryApi
import io.silencelen.andvari.core.app.FirstRunNotice
import io.silencelen.andvari.core.app.InstanceApi
import io.silencelen.andvari.core.app.InstanceLabel
import io.silencelen.andvari.core.app.InstanceSnapshot
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.InviteResult
import io.silencelen.andvari.core.app.KitApi
import io.silencelen.andvari.core.app.KitReason
import io.silencelen.andvari.core.app.LinksApi
import io.silencelen.andvari.core.app.LockedScreen
import io.silencelen.andvari.core.app.MasterPasswordPrompt
import io.silencelen.andvari.core.app.OldDataLeft
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.PreCutoverStore
import io.silencelen.andvari.core.app.PreCutoverStores
import io.silencelen.andvari.core.app.RecoveryApi
import io.silencelen.andvari.core.app.ServerKind
import io.silencelen.andvari.core.app.SharedVaultsApi
import io.silencelen.andvari.core.app.Subscription
import io.silencelen.andvari.core.app.Trouble
import io.silencelen.andvari.core.app.TrustGatePrompt
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.client.pin.BakedInstance
import io.silencelen.andvari.core.client.pin.CardPin
import io.silencelen.andvari.core.client.pin.CardStatus
import io.silencelen.andvari.core.client.pin.CardTrust
import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.client.pin.OriginAccess
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.client.pin.TrustCardChainVerifier
import io.silencelen.andvari.core.client.pin.TrustGateWording
import io.silencelen.andvari.core.app.KitAfterMovePrompt
import io.silencelen.andvari.core.app.QuickEnrolResult
import io.silencelen.andvari.core.app.QuickUnlockResult
import io.silencelen.andvari.core.app.QuickUnlockSetting
import io.silencelen.andvari.core.app.QuickUnlockState
import io.silencelen.andvari.core.app.ServerPolicy
import io.silencelen.andvari.core.client.session.Clocks
import io.silencelen.andvari.core.client.session.KeptPolicies
import io.silencelen.andvari.core.client.session.KeptPolicy
import io.silencelen.andvari.core.client.session.KeptUnlock
import io.silencelen.andvari.core.client.session.PlatformKeyWrap
import io.silencelen.andvari.core.client.session.QuickEnrolOutcome
import io.silencelen.andvari.core.client.session.QuickUnlockKeeper
import io.silencelen.andvari.core.client.session.QuickUnlockOutcome
import io.silencelen.andvari.core.client.session.SessionEndReason
import io.silencelen.andvari.core.client.items.CopyDeletion
import io.silencelen.andvari.core.client.items.ItemCacheNames
import io.silencelen.andvari.core.client.session.SessionKeeper
import io.silencelen.andvari.core.client.session.WireTransport
import kotlinx.coroutines.launch
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Fingerprint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.withContext
import kotlin.coroutines.CoroutineContext

/**
 * What the engine-backed app API is built from: the platform's stores, HTTP stack and build constants.
 *
 * - [state] is device state (pins, known devices, identity records, the format markers): it outlives sign-out.
 * - [secure] is the session-grade store (Keychain, Keystore-backed): the session's tokens and nothing else of
 *   the platform's. Assisted recovery keeps its request key there too.
 * - [baked] is the store build's public instance (§0.3), or null in a build without one.
 * - [main] runs the API's own background work (the public instance's sign-up status): the main thread in an app.
 * - [work] runs the proof of work and the key derivation of an unlock.
 * - [keyWrap] is the platform's biometric-gated key for quick unlock, and [clocks] the clocks its freshness rule needs
 *   (a monotonic clock that counts through sleep, and the boot identity). Quick unlock exists only when both are
 *   given; without them [io.silencelen.andvari.core.app.QuickUnlockState.UNAVAILABLE] is all it shows.
 * - [transport] is the platform's HTTP stack: in an app, [dialingTransport] over [state] and the app's one
 *   `HttpClient`. Every client the API opens through it goes behind the engine's guard over the pin store in [state]
 *   ([SessionKeeper.guard], design §4.4), whatever the transport is; a host that opens a WebSocket asks
 *   [EngineAppApi.mayDial] first.
 */
class AppEngine(
    val platform: AppPlatform,
    val deviceName: String,
    val transport: WireTransport,
    val state: DeviceState,
    val secure: DeviceState,
    val crypto: CryptoProvider,
    val clock: () -> Long,
    val baked: BakedInstance?,
    val storeBuild: Boolean,
    val stores: PreCutoverStores?,
    val main: CoroutineContext,
    val work: CoroutineContext = Dispatchers.Default,
    val keyWrap: PlatformKeyWrap? = null,
    val clocks: Clocks? = null,
    /**
     * Where the item engine's offline caches live ([SqliteVaultCacheFiles] in the app's private files). Null keeps
     * every cache in memory. A cache is a file only while the server's client policy allows an offline cache.
     */
    val cacheFiles: VaultCacheFiles? = null,
    /**
     * A platform that keeps its device data in a directory per (origin, user) (Android, the iPhone) moves that directory
     * when the person follows a signed move (design §4.4): `onMoved(from, to)` returns true only once the directory is
     * at `to`, and treats "already at `to`, nothing left at `from`" as success (it is called again after a crash).
     * Until it succeeds the new address stays closed: nothing is sent there and no session opens there, and the
     * instance on show carries [io.silencelen.andvari.core.app.InstanceSnapshot.unfinishedMove]. Null on a platform
     * with one namespace (desktop, the command line).
     */
    val namespaceMover: io.silencelen.andvari.core.client.pin.NamespaceMover? = null,
    /**
     * Where the vault's content keeps, across locks and restarts, what a lock cut short (an unfinished move or copy, a
     * save with new files, the saves applied from the queue) and where the extensions' save queue lies: the content's
     * own [io.silencelen.andvari.core.app.content.ContentStores] over app-private files, made ONCE per process. Its
     * files are used only while the server's client policy allows an offline cache; otherwise, and with null, the
     * records are kept in memory for the process. Emptied when the person's own act ends the account on this device
     * (sign-out, a forgotten server, a policy that forbids an offline copy); never at a lock.
     */
    val contentStores: io.silencelen.andvari.core.app.content.ContentStores? = null,
    /**
     * The platform's own consent to keep a copy at rest, read at every composition of the vault (the desktop's "keep me
     * signed in on this computer"; true where the platform asks nothing). A copy is a file only while both this and the
     * server's policy allow it. When it turns to false while a vault is open, the platform calls
     * [EngineAppApi.atRestConsentChanged] BEFORE it deletes its files, so what is queued to send is carried.
     */
    val keepsAtRest: () -> Boolean = { true },
    /**
     * Where a request for an operator's help is kept (design §9.3 step 1, N11: `rSec` and `pollSecret` must outlive the
     * 7-day hold on an install that has no account): a store protected like a session (Keychain, Keystore) that the
     * platform keeps WHATEVER "keep me signed in" says. Null uses [secure], which is right where [secure] is always kept
     * (Android, the iPhone); a platform whose [secure] lives only for the process without the opt-in (the desktop)
     * passes its always-kept protected store here.
     */
    val requestStore: DeviceState? = null,
)

/**
 * The app's [AppEngine.transport]: the engine's one [io.silencelen.andvari.core.client.net.Dialer] over the pin store
 * in [state] (the device state given to [AppEngine]) and the app's [http] client, so every client is guarded at the
 * place that opens connections (design §4.4). The event bell's socket comes from the same dialer.
 */
fun dialingTransport(state: DeviceState, http: io.ktor.client.HttpClient, platform: AppPlatform): WireTransport =
    dialingTransport(io.silencelen.andvari.core.client.net.Dialer(PinStore(state), http, platform.wireName))

/**
 * [AppEngine.transport] over a [dialer] the platform built over the device's pin store: every client from
 * [io.silencelen.andvari.core.client.net.Dialer.open], and the event bell's socket from
 * [io.silencelen.andvari.core.client.net.Dialer.bellSocket] (spec 03 §6), one per opening of the vault. A transport made
 * as `WireTransport(dialer::open)` has no bell.
 */
fun dialingTransport(dialer: io.silencelen.andvari.core.client.net.Dialer): WireTransport = object : WireTransport {
    override fun open(origin: String, tokens: io.silencelen.andvari.core.client.net.TokenSource?) = dialer.open(origin, tokens)
    override fun bellSocket(origin: String) = dialer.bellSocket(origin)
}

/**
 * IF-3 over the client engine: [AppApi] for the phone apps and the iOS bridge. The fake
 * ([io.silencelen.andvari.core.app.fake.FakeAppApi]) stays for previews and UI tests; the flows of both are tested
 * alike.
 *
 * It sits beside the old [io.silencelen.andvari.core.app.SessionController] and shares nothing with it: its own
 * stores' keys (`ovh.*`), its own session ([SessionKeeper]), its own routes.
 *
 * **There is no "current server" here.** Signed out, every screen that belongs to a server carries its own
 * [EngineFlow], and the instance a snapshot shows is the one of the screen on show; with a session it is the
 * session's. What the last check of a chain found is kept per origin ([cardStatuses]).
 */
open class EngineAppApi(internal val engine: AppEngine) : AppApi, io.silencelen.andvari.core.app.FastUnlock, io.silencelen.andvari.core.app.UnlockForFilling {
    internal val crypto: CryptoProvider get() = engine.crypto
    internal val takesSetupLinks: Boolean get() = this is io.silencelen.andvari.core.app.DesktopAppApi

    // ---- the engine, made in start() ----

    internal lateinit var keeper: SessionKeeper
        private set
    internal lateinit var trust: CardTrust
        private set
    internal lateinit var knownDevices: KnownDevices
        private set
    internal lateinit var policies: KeptPolicies
        private set

    /** Kit recovery (§10): its session goes to the keeper, which opens it through every check of §5.2. */
    internal lateinit var kitRecovery: io.silencelen.andvari.core.client.recovery.WireKitRecovery
        private set

    /** The keeper as the recoveries' sink, counting the sessions a commit's answer opened and this device did not take. */
    internal lateinit var commitWatch: CommitWatch
        private set

    /** Assisted recovery (§9.3) over [requestStore]. */
    internal lateinit var assisted: io.silencelen.andvari.core.client.recovery.WireAssistedRecovery
        private set

    /** Where requests for an operator's help are kept ([AppEngine.requestStore]). */
    internal val requestStore: io.silencelen.andvari.core.client.DeviceState get() = engine.requestStore ?: engine.secure

    /** The address a kept request was made for, read from the kept record itself (the engine's steps do not carry it). */
    internal fun keptRequestEmail(origin: String): String? =
        io.silencelen.andvari.core.client.recovery.AssistRequests(requestStore, engine.clock, DelegatingTrust { trust }).get(origin)?.email

    /**
     * Device links (§8.2). The new device's side is bound (its session goes to the keeper, which opens it through every
     * check of §5.2); the existing device's side needs the account's [io.silencelen.andvari.core.client.link.LinkAccount]
     * and is bound with the devices slice.
     */
    internal lateinit var deviceLinks: io.silencelen.andvari.core.client.devicelink.WireDeviceLinks
        private set

    /**
     * Invites opened signed out (§6.7, §6.8 recipient side) and the registrations they authorise: a link flow with no
     * account. It is also each onboarding's [io.silencelen.andvari.core.client.onboard.LinkRegistrations].
     */
    internal lateinit var entryLinks: io.silencelen.andvari.core.client.link.WireLinkFlows
        private set

    /**
     * A connect link opened signed out whose person then made an account or signed in (§6.7): the step
     * [io.silencelen.andvari.core.client.link.LinkFlows.settle] returned. Its flow holds only the answer key (the link's
     * secret is gone) and keeps the pin the account stands on whatever ends it; the connection is answered once the
     * account is open, and dismissing it ends the flow with the pin kept.
     */
    internal var connectAfterEntry: io.silencelen.andvari.core.client.link.RecipientStep.Confirm? = null

    /** How often a device link waiting on the other device is polled. Tests set it out of reach and poll by hand. */
    internal var linkPollMs: Long = 2_000L

    /**
     * How long an entry call that waits on a server (sign-in, registration, a device link's pickup, a kit recovery's
     * commit) may take, the key derivation included, before it answers UNREACHABLE. Core sets
     * no other limit; a hostile server could otherwise answer whenever it chooses.
     */
    internal var entryCallMs: Long = 90_000L

    /** Quick unlock, when the platform gave a key and clocks ([AppEngine.keyWrap], [AppEngine.clocks]). */
    internal var quick: QuickUnlockKeeper? = null
        private set
    private val onboardings = HashMap<String, WireOnboarding>()

    internal fun clientFor(origin: String): WireClient = keeper.clientFor(origin)

    /**
     * "Finish setting up this server" (§6.7 Resume) for the established session at [origin], over this device's pins and
     * the one re-authentication path; null when no session is established there.
     */
    internal fun setupResume(origin: String): io.silencelen.andvari.core.client.onboard.SetupResume? {
        if (!this::keeper.isInitialized) return null
        val est = keeper.established?.takeIf { it.origin == origin } ?: return null
        val session = keeper.reauthSession()?.takeIf { it.origin == origin } ?: return null
        // The password gate's REAUTH rule wants a pin in force beside the session (§4.4). Until card 0 is pinned, the
        // setup root's kept offer stands for that pin, exactly as the origin guard already lets this session's credentials
        // go there (`OriginGuard.mayDial`): for this one re-authentication only, and only at the session's own
        // origin while its offer is kept and nothing is pinned or blocked there. Every other gate decision is unchanged.
        val reauth = io.silencelen.andvari.core.client.account.Reauth(session) {
            val pins = trust.gatePins()
            val setupStands = pins.none { it.origin == origin } && trust.pinState(origin) == PinState.None && keeper.mayDial(origin)
            if (setupStands) pins + io.silencelen.andvari.core.client.pin.GatePin(origin, io.silencelen.andvari.core.client.pin.PinRoot.SETUP, session.emailNorm) else pins
        }
        return io.silencelen.andvari.core.client.onboard.SetupResume(est, clientFor(origin), crypto, engine.state, trust, reauth, engine.clock)
    }

    /** The one "Finish setting up this server" prompt while it stands, kept so that a screen sees the same object. */
    private var setupPromptShown: io.silencelen.andvari.core.app.AccountPrompt.FinishServerSetup? = null

    /**
     * §6.7 Resume (R10) at every unlock of the operator account in a desktop app: its server has no card pinned here,
     * because the setup stopped between the registration and card 0. A phone shows nothing (§9.5).
     */
    private fun setupPrompt(open: io.silencelen.andvari.core.client.onboard.EstablishedSession): io.silencelen.andvari.core.app.AccountPrompt.FinishServerSetup? {
        if (!takesSetupLinks || open.role != "operator" || trust.pinState(open.origin) != PinState.None) {
            setupPromptShown = null
            return null
        }
        return setupPromptShown?.takeIf { it.origin == open.origin }
            ?: io.silencelen.andvari.core.app.AccountPrompt.FinishServerSetup(open.origin).also { setupPromptShown = it }
    }

    /**
     * True when a request to [origin] may be sent now (the engine's guard, design §4.4). A host asks this before it
     * opens a WebSocket to [origin]; false before [start].
     */
    fun mayDial(origin: String): Boolean = this::keeper.isInitialized && keeper.mayDial(origin)

    /**
     * The server refused a proof of the master password ([io.silencelen.andvari.core.client.account.Reauthed.PROOF_REFUSED];
     * a wrong password typed here is caught on this device first and never sent). It is never a wrong password (decided on
     * 2026-11-17): while the session's mark says the account's keys on the server are not the ones this device knows, it
     * is [keys], said as such; otherwise it is [refused], the server's refusal of a proof made here.
     */
    internal fun <R> proofRefused(keys: R, refused: R): R =
        if (this::keeper.isInitialized && keeper.session?.serverKeysNotKnownHere == true) keys else refused

    /** The onboarding of [origin]; its client carries the kept session once one is established there. */
    internal fun onboardingFor(origin: String): WireOnboarding = onboardings.getOrPut(origin) {
        WireOnboarding(
            origin, clientFor(origin), trust, knownDevices, keeper, crypto, engine.state, engine.platform.wireName, engine.deviceName, engine.clock,
            links = entryLinks, knownIdentity = keeper::knownIdentity, work = engine.work,
        )
    }

    // ---- where the app is ----

    internal var phase: AppPhase = AppPhase.STARTING
    internal var busy: Int = 0
    private var closed = false

    /**
     * What the last check of each origin's chain found, where it found something to say (§4.4). `Unreachable` is
     * never recorded: the state before it stays. A server's entry goes when the server is forgotten or followed.
     */
    internal val cardStatuses = HashMap<String, CardStatus>()

    /** The account's email as the person typed it, for screens; the session holds its normal form. */
    internal var accountEmail: String? = null

    internal var retryAfterUntilMs: Long = 0L
    /**
     * The app interface's own scope. An exception that escapes work started here is contained by the scope itself
     * (counted in [AppSnapshot.containedFaults], nothing of it kept), so no platform depends on handing a handler in
     * through `main`; a platform that does hand one in keeps its own.
     */
    internal val scope: CoroutineScope = CoroutineScope(
        SupervisorJob() + engine.main + (engine.main[kotlinx.coroutines.CoroutineExceptionHandler] ?: kotlinx.coroutines.CoroutineExceptionHandler { _, _ -> faultContained() }),
    )

    /** Faults [scope] contained; see [AppSnapshot.containedFaults]. */
    private var containedFaults = 0

    private fun faultContained() {
        containedFaults++
        // The publish itself must not throw out of the handler: a fault while publishing is only counted.
        try {
            publish()
        } catch (_: Throwable) {
        }
    }

    private val entryPart = EngineEntry(this)
    private val kitPart = EngineKit(this)
    private val instanceFlow = EngineInstance(this)
    private val unbound = Unbound(this)
    private val twoStepPart = EngineTwoStep(this)
    private val linksPart = EngineLinks(this, unbound)
    private val contactsPart = EngineContacts(this)
    private val vaultsPart = EngineSharedVaults(this)
    private val devicesPart = EngineDevices(this)
    private val recoveryPart = EngineRecovery(this)
    internal val accountSettingsPart = EngineAccountSettings(this)

    /** The operator views (§9.2): handed out by [EngineDesktopAppApi] only; a phone's API has no way to them. */
    internal val operatorPart = EngineOperator(this)

    internal val twoStepFlow: EngineTwoStep get() = twoStepPart
    internal val devicesFlow: EngineDevices get() = devicesPart
    internal val recoveryFlow: EngineRecovery get() = recoveryPart
    internal val linksFlow: EngineLinks get() = linksPart
    internal val vaultsFlow: EngineSharedVaults get() = vaultsPart
    internal val contactsFlow: EngineContacts get() = contactsPart

    /** The name of the open invitation to [vaultId] on this device ([EngineSharedVaults.openInvitationName]). */
    internal fun openInvitationName(vaultId: String): String? = vaultsPart.openInvitationName(vaultId)

    /**
     * The session ended or moved: what the account's own flows held goes (a two-step key, a connect still to answer, whose
     * settled flow ends: its answer key goes, the pin it made stays).
     */
    private fun endAccountFlows() {
        twoStepPart.ended()
        linksPart.ended()
        contactsPart.ended()
        vaultsPart.ended()
        devicesPart.ended()
        recoveryPart.ended()
        accountSettingsPart.ended()
        operatorPart.locked()
        val held = connectAfterEntry
        connectAfterEntry = null
        if (held != null) entryLinks.dismiss(held)
    }
    internal val entryFlow: EngineEntry get() = entryPart
    internal val instancePart: EngineInstance get() = instanceFlow
    internal val kitFlow: EngineKit get() = kitPart

    override val entry: EntryApi get() = entryPart
    override val kit: KitApi get() = kitPart
    override val instance: InstanceApi get() = instanceFlow
    override val contacts: ContactsApi get() = contactsPart
    override val links: LinksApi get() = linksPart
    override val vaults: SharedVaultsApi get() = vaultsPart
    override val devices: DevicesApi get() = devicesPart
    override val recovery: RecoveryApi get() = recoveryPart
    override val settings: AccountSettingsApi get() = unbound

    // ---- the vault's content (one composition per unlock) ----

    /** What this unlock opened over the account; null while locked or signed out. */
    internal var vault: EngineVault? = null
        private set

    /** The kept session as last published: its cache file is deleted when the session ends without the app asking. */
    private var lastKept: io.silencelen.andvari.core.client.session.KeptSession? = null

    override val content: io.silencelen.andvari.core.app.content.VaultContent?
        get() = if (phase == AppPhase.UNLOCKED) vault?.takeIf { !it.closed }?.content else null

    /** The vault opened: compose the account's engines on the open session, unless this session's are open already. */
    private fun openVault(carry: QueuedCarry? = null, haltForUpdate: Boolean = false) {
        val open = keeper.established ?: return
        val now = vault
        if (now != null && !now.closed && now.origin == open.origin && now.userId == open.userId) return
        now?.close()
        // A kept policy that cannot be read is not a forbidding one: the copy stays closed, untouched, until the policy is
        // read from the server ([AppSnapshot.closedForPolicy]; the opening's read composes it then).
        if (policies.unreadable(open.origin)) {
            vault = null
            return
        }
        // Another account opens here: what a lock kept of any other account's uses goes.
        dropOtherKeptUses(open.origin to open.userId)
        // What a lock kept of a copy in memory only goes into this composition of the same account (and only that one).
        val across = waitingAcrossLock?.takeIf { it.origin == open.origin && it.userId == open.userId }
        val mine = carry?.takeIf { it.origin == open.origin && it.userId == open.userId }
        val v = EngineVault.compose(this, open, mine ?: across, haltForUpdate)
        // A composition at rest keeps its file's queue by itself: what the lock kept in memory is added to it.
        if (across != null && mine == null && v.keptAtRest) v.takeCarry(across)
        if (across != null) waitingAcrossLock = null
        vault = v
        // Before anything runs in it: an old vault whose move deletion is signed and waiting is closed for writing.
        vaultsPart.composed(v)
        v.follow {
            publish()
            vaultsPart.contentChanged()
            contactsPart.contentChanged()
            recoveryPart.contentChanged()
        }
        composing = true
        try {
            v.start()
        } finally {
            composing = false
        }
        // An "update required" its first sync met while it started: the vault is composed again now, not inside start.
        if (updateCheckDue) {
            updateCheckDue = false
            updateRequiredChanged()
        }
    }

    /** [openVault] is starting a vault; [updateRequiredChanged] waits until it returns ([updateCheckDue]). */
    private var composing = false
    private var updateCheckDue = false

    /**
     * The vault closes. With [deleteFor] and a [why] the account is gone from this device by the person's own act
     * (design §4.4, "A session the server ends does not delete the device's copy"): the cache file and the kept records
     * of that account go too (sign-out, a forgotten server, account deletion, an operator account refused on a phone).
     * A lock, and a session the server ended, pass no reason: the copy stays.
     */
    internal fun endVault(deleteFor: io.silencelen.andvari.core.client.session.KeptSession?, why: CopyDeletion? = null, keepUses: Boolean = false) {
        vault?.close(keepUses)
        vault = null
        // Every end of a session closes the vault here: a vault opened for filling without its kit is no longer open.
        openedWithoutKit = false
        if (deleteFor != null && why != null) {
            lastKept = null
            dropHeld(deleteFor.origin, deleteFor.userId, why)
        }
    }

    // ---- what the content keeps across locks, and the cache files, per account ----

    /**
     * The content's kept records of every account (spec 02 §8): the platform's [AppEngine.contentStores], made once per
     * process, or the API's own in memory. At every unlock it hands the content its stores under the policy as last
     * read ([io.silencelen.andvari.core.app.content.ContentStores.keeping]): files while the policy allows an offline
     * copy, memory otherwise (and then what was on disk for the account goes).
     */
    internal val stores: io.silencelen.andvari.core.app.content.ContentStores by lazy {
        engine.contentStores ?: io.silencelen.andvari.core.app.content.ContentStores(crypto, null)
    }

    /**
     * The accounts, as (origin, user id), whose cache file or kept records may be on this device: written when a vault is
     * composed, so a stop between the end of a session and the deletion of its data is finished at the next start.
     */
    /**
     * The account's changes made here and not sent, for the forgetting after a deletion whose outcome is not known: as a
     * sign-out counts them ([signOutCheck]), plus its signed changes to shared vaults waiting to be sent. Null: this device
     * cannot tell (its copy held and not open, or not readable now). [byIdToo]: false where the forgetting keeps what is
     * kept by the account's id (another server ties it): its signed changes waiting are then not counted, as they stay.
     */
    internal fun unsentForForgetting(origin: String, userId: String, byIdToo: Boolean = true): Int? {
        val v = vault?.takeIf { !it.closed && it.origin == origin && it.userId == userId }
        val items: Int? = when {
            v != null -> runCatching { unsentOf(v.queued()) }.getOrNull()?.let { n -> v.content.keptSavesWaiting()?.let { n + it } }
            (origin to userId) !in held() -> 0
            else -> null
        }
        return items?.let { it + if (byIdToo) signedUnsentLogRecords(userId).size else 0 }
    }

    /**
     * The records of [userId]'s signed changes to shared vaults that wait to be sent, one per vault: those the engine's
     * index names and those of the same form it does not name (a store written part-way). Where the store lists its keys,
     * only records that exist (an index entry with no record holds nothing to send). The forgetting counts exactly these
     * and removes exactly these ([dropSignedUnsentLogChanges]).
     */
    private fun signedUnsentLogRecords(userId: String): Set<String> {
        val st = engine.state
        val out = LinkedHashSet<String>()
        runCatching { st.get("ovh.log|$userId|pending-index") }.getOrNull()?.split(',')?.filter { it.isNotEmpty() }?.forEach {
            out += io.silencelen.andvari.core.client.log.StoredVaultLogs.recordKey(userId, it, "pending")
        }
        val listed = runCatching { st.keys() }.getOrNull() ?: return out
        out.retainAll(listed)
        listed.filterTo(out) { it.startsWith("ovh.log|$userId|") && it.endsWith("|pending") }
        return out
    }

    /**
     * The forgetting after a deletion whose outcome is not known: [userId]'s signed changes to shared vaults that were never
     * sent (or whose sending is not known) go, with their index; nothing else the engine keeps for the account.
     */
    internal fun dropSignedUnsentLogChanges(userId: String) {
        val st = engine.state
        for (k in signedUnsentLogRecords(userId)) runCatching { st.set(k, null) }
        runCatching { st.set("ovh.log|$userId|pending-index", null) }
    }

    /** The user ids whose copy or kept records this device holds at [origin] ([HELD_KEY]). */
    internal fun heldAt(origin: String): List<String> = held().filter { it.first == origin }.map { it.second }

    /**
     * This device keeps something of an account at [origin] other than [userId] (whose address is [emailNorm]): a copy held,
     * a device row or an address's record of another address, or a record kept per origin under another user id (its
     * trust records among them, and the record of another account's identity key that a forgetting kept: forgetting the
     * server would take that key, and the earlier account would then be taken under another key). A store that cannot
     * list its keys counts as keeping something (the safer reading: the server stays known).
     */
    internal fun othersKnownAt(origin: String, userId: String, emailNorm: String): Boolean {
        if (heldAt(origin).any { it != userId }) return true
        val keys = runCatching { engine.state.keys() }.getOrNull() ?: return true
        val byAddress = listOf("ovh.dev|", io.silencelen.andvari.core.client.session.SessionKeeper.EMAIL_BINDING_PREFIX)
        val byAccount = PinStore.originKeyed().filter { FORGOTTEN_PER_ORIGIN[it] != false }
        val earlierKey = io.silencelen.andvari.core.client.session.SessionKeeper.EARLIER_IDENTITY_PREFIX + origin + "|"
        return keys.any { k ->
            (k.startsWith(earlierKey) && k.removePrefix(earlierKey) != userId) ||
                byAddress.any { p -> k.startsWith("$p$origin|") && k.removePrefix("$p$origin|") != emailNorm } ||
                byAccount.any { p -> k.startsWith("$p$origin|") && k.removePrefix("$p$origin|").substringBefore('|').let { it.isNotEmpty() && it != userId } }
        }
    }

    /**
     * A confirmed deletion of [userId] at [origin] while this device keeps something of another account there: exactly the deleted
     * account's records go (as at the forgetting of an earlier account: its data, every record kept under its id, its
     * per-origin records, the mark of a kit shown for its address, a kit's notice for its address), and the server stays
     * known with everything of the other accounts. [tied]: whether something at another server ties the account, as read
     * before anything of the deletion was removed ([PinStore.tiedElsewhere]).
     */
    internal fun dropDeletedAccountOnly(origin: String, emailNorm: String, userId: String, tied: Boolean) {
        // The copy went already, once, as the deletion's own ([sessionGone]): not a second time as a forgetting.
        dropForgotten(origin, emailNorm, userId, emptyList(), deletion = true, tied = tied)
        kitMarksForgotten(origin, emailNorm)
        // The device's own row at that server for the deleted account's address: the account it served is gone.
        runCatching { engine.state.set("ovh.dev|$origin|$emailNorm", null) }
        // So is the notice that this device remembers it.
        remembering.remove("$origin|$emailNorm")
    }

    /** The copies held; a line that is not `origin|userId` with an account's id is dropped, and the next rewrite clears it. */
    private fun held(): List<Pair<String, String>> = engine.state.get(HELD_KEY).orEmpty().split('\n').mapNotNull(::heldLine)

    private fun setHeld(list: List<Pair<String, String>>) {
        engine.state.set(HELD_KEY, list.distinct().joinToString("\n") { "${it.first}|${it.second}" }.ifEmpty { null })
    }

    /** The vault of [userId] at [origin] is about to keep data on this device. */
    internal fun noteHeld(origin: String, userId: String) {
        val now = held()
        if ((origin to userId) !in now) setHeld(now + (origin to userId))
    }

    /**
     * The account [userId] is gone from this device by the person's own act: its cache file and its kept records go, at
     * [origin] and at every address it was held at before a followed move. An end at [origin] (a sign-out, a deletion it
     * confirmed) is that server's alone: a copy of the same account id held at another server this device still knows
     * (one that serves the same accounts, or one whose move was not followed) is that server's, and stays, with whatever
     * waits in it unsent ([heldAtOriginOnly]).
     */
    private fun dropHeld(origin: String, userId: String, why: CopyDeletion) {
        val all = held()
        val gone = all.filter { it.second == userId && heldAtOriginOnly(origin, it.first) }
        for ((o, u) in (gone + (origin to userId)).distinct()) dropData(o, u, why)
        setHeld(all - gone.toSet())
    }

    /**
     * Whether [heldAt], an address an account was held at, is [origin]'s own for an end at [origin]: [origin]
     * itself, or a former address of it (a followed move leaves no pin there). Another server this device still knows is not.
     */
    private fun heldAtOriginOnly(origin: String, heldAt: String): Boolean = heldAt == origin || trust.pinState(heldAt) == PinState.None

    /** Every account held at [origin] goes: the person forgot that server (its records there go with its pin). */
    internal fun dropHeldAt(origin: String): List<String> {
        val all = held()
        val there = all.filter { it.first == origin }
        for ((o, u) in there) dropData(o, u, CopyDeletion.FORGOT_SERVER)
        // Nothing of the server stays: the notice of a policy's wipe there neither, whoever's it was.
        policyWipe.forgetNoticesAt(origin)
        setHeld(all - there.toSet())
        return there.map { it.second }
    }

    /**
     * An account's data goes only when its end was the person's own completed act (a
     * sign-out, "Forget this server", the account's deletion), which the keeper records durably before the session's
     * record goes ([SessionKeeper.endedByOwnAct]). What such an end left behind (a stop before its data was deleted)
     * goes here; an account that is only not kept (no such record: a store the platform lost, a call the person left)
     * keeps its data, and the person's own sign-out or "Forget this server" deletes it. Run at every start and after
     * every own act. Each end takes what its server's end takes ([dropHeld]: there and at its former addresses), with its
     * reason; an end an earlier build recorded without one is settled as a sign-out, as those builds settled every end.
     */
    private fun settleOwnEnds() {
        val kept = keeper.session
        val heldNow = held()
        for (e in keeper.ownEnds()) {
            val (o, u) = e.origin to e.userId
            val why = when (e.why) {
                io.silencelen.andvari.core.client.session.SessionKeeper.OWN_END_DELETED -> CopyDeletion.ACCOUNT_DELETED
                io.silencelen.andvari.core.client.session.SessionKeeper.OWN_END_FORGOTTEN -> CopyDeletion.FORGOT_SERVER
                else -> CopyDeletion.SIGNED_OUT
            }
            // The kept session spares the end's copies only where it is that account at that server (or a former address
            // of it): the same id kept at another server is that server's, and the end at [o] still takes what [o] held.
            val keptThere = kept != null && kept.userId == u && heldAtOriginOnly(o, kept.origin)
            if (!keptThere && heldNow.any { it.second == u && heldAtOriginOnly(o, it.first) }) dropHeld(o, u, why)
            // The account's own end settles "the deletion's outcome is not known yet" too (design point 4).
            accountSettingsPart.setDeletionOutcomeUnknown(o, u, false)
            keeper.ownEndSettled(o, u)
        }
    }

    /**
     * The record of [keptMark] at [origin] goes where it is [userId]'s and this device keeps no session of that account
     * there (a deletion's end, finished at a start after a stop: this process never held that mark in memory).
     */
    internal fun keptMarkGone(origin: String, userId: String) {
        if (keeper.session?.let { it.origin == origin && it.userId == userId } == true) return
        val key = KEPT_MARK_PREFIX + origin
        if (engine.state.get(key)?.startsWith("$userId|") == true) engine.state.set(key, null)
    }

    /** [settleOwnEnds], for a deletion finished at a start ([EngineAccountSettings.settleDeletions]). */
    internal fun settleOwnEndsNow() = settleOwnEnds()

    /** Every wipe of a copy takes the one lock the policy's run holds ([EnginePolicyWipe]): it waits for a run under way. */
    private fun dropData(origin: String, userId: String, why: CopyDeletion) {
        // A wipe that waits behind a run is recorded durably first: the held list lets go of the account at once, and a
        // stop before the run ends would otherwise forget it. The next start makes it ([ownWipesAtStart]).
        val waits = policyWipe.lock.held
        if (waits) policyWipe.ownWipeWaits(origin, userId, why)
        policyWipe.lock.now {
            dropDataLocked(origin, userId, why)
            policyWipe.ownWipeMade(origin, userId)
            // Made after the run's own redraw: what it took (a notice among it) leaves the screens now.
            if (waits) publish()
        }
    }

    /**
     * Where the engine's diagnostics go ([CoreLog]): the host sets it before [start]. Silent by default. The sweep of
     * accounts this device no longer knows says here when it removed nothing or stopped.
     */
    var diagnostics: io.silencelen.andvari.core.client.CoreLog = io.silencelen.andvari.core.client.CoreLog.Silent

    /**
     * The sweep ([AccountSweep]): at every start after the settling of own ends and of forgettings, and at the end of a
     * deletion the server confirmed, of "Forget this server" and of the forgetting of an earlier account.
     */
    internal fun sweepAccounts(): AccountSweep.Outcome =
        AccountSweep.run(engine.state, engine.secure, if (keeperReady) keeper.session?.userId else null, diagnostics)

    /**
     * Whether what is kept by [userId]'s id stays at the end of that account at [origin] under the address [emailNorm] (a
     * deletion there, the forgetting of it as an earlier account there): something at another server ties it
     * ([PinStore.tiedElsewhere]), or the sweep's own rule knows it apart from what this end removes ([knownApartFrom]). Read
     * before anything of the end is removed. So the tie never removes a record that the sweep would keep.
     */
    internal fun keptElsewhere(userId: String, origin: String, emailNorm: String): Boolean =
        PinStore.tiedElsewhere(engine.state, userId, origin) || userId in knownApartFrom(origin, emailNorm)

    /**
     * The accounts the sweep's rule knows apart from what an end at [origin] removes ([AccountSweep.knownApartFrom]): for an
     * account's end, under the address [emailNorm], with the copies it held at [origin] and its former addresses; for
     * "Forget this server" ([emailNorm] null), every address record there and the copies held at [origin] itself.
     */
    internal fun knownApartFrom(origin: String, emailNorm: String?): Set<String> = AccountSweep.knownApartFrom(
        engine.state, engine.secure, if (keeperReady) keeper.session?.let { it.origin to it.userId } else null, origin, emailNorm,
    ) { heldAt -> if (emailNorm == null) heldAt == origin else heldAtOriginOnly(origin, heldAt) }

    /** What a stop left of the person's own wipes that waited behind a policy's run is made now. */
    private fun ownWipesAtStart() {
        for ((o, u, why) in policyWipe.ownWipesLeft()) dropData(o, u, why)
    }

    /** [dropData] under the lock; true when the cache file is gone (or there are no cache files). */
    private fun dropDataLocked(origin: String, userId: String, why: CopyDeletion): Boolean {
        val files = engine.cacheFiles
        val gone = if (files != null) runCatching { files.delete(EngineVault.cacheName(this, origin, userId)) }.getOrDefault(false) else true
        // The person's own end takes the copy, and with it any wipe still owed for it.
        if (why != CopyDeletion.POLICY_FORBIDS_OFFLINE_COPY) policyWipe.forget(origin, userId)
        // After an account's deletion, or forgetting it with its server, nothing of it stays: its notice neither. A
        // sign-out keeps it (the person reads it at the next sign-in or on the first screen).
        if (why == CopyDeletion.ACCOUNT_DELETED || why == CopyDeletion.FORGOT_SERVER) policyWipe.forgetNotice(origin, userId)
        // What a lock kept in memory of that account goes with the person's own end (the policy's wipe is of the copy at
        // rest only: what waits in memory is not part of it, and is sent after the next unlock).
        if (why != CopyDeletion.POLICY_FORBIDS_OFFLINE_COPY && waitingAcrossLock?.let { it.origin == origin && it.userId == userId } == true) waitingAcrossLock = null
        stores.drop(origin, userId, why)
        // Uses a lock kept for the account go with its data: behavioural records never outlive the person's own end.
        dropKeptUses(origin, userId)
        // An unfinished "Move everything" is the account's too: its record goes with the account's data.
        EngineSharedVaults.dropMoves(engine.state, origin, userId)
        // So does the record of the person's own departures still waiting for an answer.
        EngineSharedVaults.dropOwnDepartures(engine.state, origin, userId)
        return gone
    }

    // ---- the policy that forbids the offline copy (EnginePolicyWipe) ----

    /** The policy's run, its marks and its notice. */
    internal val policyWipe = EnginePolicyWipe(this)

    /** The copies, as (origin, user id), that may be on this device. */
    internal fun heldCopies(): List<Pair<String, String>> = held()

    /** [keeper] is made (after [start]'s first steps). */
    internal val keeperReady: Boolean get() = this::keeper.isInitialized

    /** The kept session is [userId]'s at [origin] and the server has not ended it: a request of the run may go. */
    internal fun sessionOf(origin: String, userId: String): Boolean =
        keeper.session?.let { it.origin == origin && it.userId == userId && !it.endedByServer } == true

    /** Nothing is sent to [origin] (forked, damaged, moving, or the session there ended by its server). */
    internal fun serverStoppedFor(origin: String): Boolean = serverStopped(origin)

    /** The policy's wipe, under the lock the run holds: the copy goes; true once its cache file is gone. */
    internal fun dropCopyLocked(origin: String, userId: String): Boolean = dropDataLocked(origin, userId, CopyDeletion.POLICY_FORBIDS_OFFLINE_COPY)

    /** A record of saves kept to be finished is there for the account (on disk or in memory), found without opening it. */
    internal fun mayHoldKeptRecords(origin: String, userId: String): Boolean = stores.mayHoldKeptSaves(origin, userId)

    /** The vault over a copy about to be wiped closes (as at a lock, nothing kept for later). */
    internal fun closeVaultForWipe() {
        vault?.close()
        vault = null
    }

    /** After the policy's wipe, while the account is open: composed again, in memory, from the server. */
    internal fun reopenAfterWipe() {
        openVault()
        if (phase == AppPhase.UNLOCKED && keeper.session?.endedByServer != true) {
            recoveryPart.recomposed()
            devicesPart.recomposed()
            contactsPart.recomposed()
        }
    }

    override fun dismissPolicyWipe(notice: io.silencelen.andvari.core.app.PolicyWipeNotice) {
        if (closed) return
        policyWipe.dismiss(notice)
    }

    override fun policyWipeOwed(origin: String, userId: String): Boolean = policyWipe.owed(origin, userId) || policyWipe.counted(origin, userId)

    /** The uses a lock kept for [userId] at [origin] go (and the record under its old, id-only key). */
    private fun dropKeptUses(origin: String, userId: String) {
        engine.state.set(EngineVault.keptUsesKey(origin, userId), null)
        engine.state.set(EngineVault.legacyKeptUsesKey(userId), null)
    }

    /**
     * Kept uses stay only while keeping is allowed. [except] (the account opening now) keeps
     * its own; every other account held on this device loses its record (another account is in use here now), and with
     * [except] null every account does (the platform's consent to keep anything at rest turned off).
     */
    private fun dropOtherKeptUses(except: Pair<String, String>?) {
        for ((o, u) in held()) if ((o to u) != except) {
            engine.state.set(EngineVault.keptUsesKey(o, u), null)
            if (except == null || u != except.second) engine.state.set(EngineVault.legacyKeptUsesKey(u), null)
        }
    }

    /**
     * A followed move from [from] to [to] (design §4.4): the account's copy goes with it, never deleted (it holds
     * changes not yet sent). The cache file and the kept records are carried to the new names; what cannot be carried
     * now stays under the old names (still listed as held, so the person's own end deletes it), and the new address
     * starts from the server.
     */
    private fun carryData(from: String, to: String, userId: String) {
        if (from == to) return
        val files = engine.cacheFiles
        val filesCarried = if (files != null) {
            ItemCacheNames.carry(crypto, from, to, userId) { a, b -> files.rename(a, b) }
        } else {
            true
        }
        val keptCarried = stores.carry(from, to, userId)
        // The uses a lock kept go with the account to its new address (the record is sealed to the account, not the address).
        engine.state.get(EngineVault.keptUsesKey(from, userId))?.let {
            engine.state.set(EngineVault.keptUsesKey(to, userId), it)
            engine.state.set(EngineVault.keptUsesKey(from, userId), null)
        }
        // A wipe the server's policy calls for follows the copy: the mark names the same account's copy at the new address
        // (and stays at the old one too while part of the copy is still there).
        policyWipe.moved(from, to, userId, partly = !(filesCarried && keptCarried))
        noteHeld(to, userId)
    }

    /**
     * The session followed a move from [from] (design §4.4): the account's copy is carried to the new address's names,
     * and an open vault is composed again at the new one.
     */
    internal fun vaultMoved(from: String) {
        // A key being set up for two-step sign-in belongs to the address it was made at.
        endAccountFlows()
        val old = lastKept
        vault?.close()
        vault = null
        keeper.session?.let { s -> if (old != null && old.origin == from) carryData(from, s.origin, old.userId) }
        keeper.session?.let { carryName(from, it.origin, it.userId) }
        lastKept = keeper.session
        if (phase == AppPhase.UNLOCKED) openVault()
    }

    /**
     * A followed move from [from] whose platform data did not move (design §4.4, `OriginAccess.MOVING`); the session is
     * at the new address already ([SessionKeeper.moved]). Nothing may be read there yet: an open vault closes and its
     * keys go, as at a lock, and the account's flows go as at a finished move. The copy is carried, as at a finished
     * move. The vault opens again only after [EngineInstance.finish] succeeded.
     */
    internal fun moveHeld(from: String) {
        endAccountFlows()
        val old = lastKept
        vault?.close()
        vault = null
        keeper.session?.let { s -> if (old != null && old.origin == from) carryData(from, s.origin, old.userId) }
        keeper.session?.let { carryName(from, it.origin, it.userId) }
        lastKept = keeper.session
        if (phase == AppPhase.UNLOCKED) {
            kitPart.drop()
            keeper.lock()
            phase = AppPhase.LOCKED
        }
    }

    /**
     * At a start: the moves followed before but left unfinished (the platform's data did not move, or the app stopped
     * between the two), as (new origin, old origin). A kept session still at the old address goes to the new one now,
     * so its tokens are never sent to the old address; it stays locked until the move is finished.
     */
    private fun carryUnfinishedMoves(): List<Pair<String, String>> {
        val left = trust.pins().mapNotNull { p -> trust.unfinishedMove(p.origin)?.let { p.origin to it } }
        for ((to, from) in left) {
            val s = keeper.session
            if (s != null && s.origin == from) {
                keeper.moved(from, to)
                carryData(from, to, s.userId)
                carryName(from, to, s.userId)
            }
            policies.forget(from)
        }
        return left
    }

    // ---- snapshots ----

    private val flow = MutableStateFlow(AppSnapshot(AppPhase.STARTING, null, null, null, null, null, false))
    private val listeners = ArrayList<(AppSnapshot) -> Unit>()

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

    /**
     * The origin on show: the session's, or, signed out, the one the screen on show belongs to. It is derived, never
     * set: nothing can leave it pointing at another server than the one the screen's intents act on.
     */
    internal fun originOnShow(): String? = when (phase) {
        AppPhase.STARTING -> null
        AppPhase.ENTRY -> entryPart.shown?.flow?.origin
        AppPhase.LOCKED, AppPhase.UNLOCKED -> keeper.session?.origin
    }

    internal fun publish() {
        if (closed) return
        if (this::keeper.isInitialized) keeper.session?.let { lastKept = it }
        // A take is marked as soon as it is published, so the mark at rest follows the copy kept.
        keptMark()
        val s = AppSnapshot(
            phase = phase,
            entry = if (phase == AppPhase.ENTRY) entryPart.shown else null,
            locked = if (phase == AppPhase.LOCKED) lockedScreen() else null,
            account = if (phase == AppPhase.UNLOCKED) accountSnapshot() else null,
            instance = originOnShow()?.let(instanceFlow::snapshot),
            oldData = oldData(),
            busy = busy > 0,
            keptSignedOut = if (phase == AppPhase.ENTRY && this::keeper.isInitialized && keeper.session?.endedByServer == true) lockedScreen()?.prompt else null,
            keptSignedOutNotConfirmed = keptNotConfirmed(),
            keptSignedOutLine = if (keptNotConfirmed()) io.silencelen.andvari.core.app.CopyKey.SESSION_NOT_CONFIRMED else null,
            keptSignedOutSignOutFirstLine = if (keptNotConfirmed()) io.silencelen.andvari.core.app.CopyKey.SESSION_NOT_CONFIRMED_SIGN_OUT_FIRST else null,
            containedFaults = containedFaults,
            kitWiped = kitWiped,
            earlierAccount = if (phase == AppPhase.ENTRY) entryPart.earlierOnShow() else null,
            rememberedNewAccount = rememberedNotice(),
            policyWipe = if (this::trust.isInitialized) policyWipe.notice() else null,
            closedForPolicy = if (this::keeper.isInitialized) policyWipe.closedLine() else null,
            policyWipeOwed = this::keeper.isInitialized && keeper.session?.let { policyWipe.marked(it.origin, it.userId) } == true,
        )
        flow.value = s
        for (l in listeners.toList()) l(s)
    }

    /** Run [body] with [AppSnapshot.busy] set. */
    internal suspend inline fun <R> working(body: () -> R): R {
        busy++
        publish()
        try {
            return body()
        } finally {
            busy--
            publish()
        }
    }

    /**
     * [body], for an intent (or background work) of the account open when it starts, answering [stale] when that
     * account's keys were wiped under it. A lock or an end that overtakes the work makes the account's guard (or the key
     * floor) refuse with [io.silencelen.andvari.core.crypto.KeysGoneException] before anything more is sealed, signed,
     * derived or sent. That is the intent's own "locked" outcome, never a crash: on a phone an uncaught
     * exception ends the app. The same refusal while the account it started under still holds its keys is a fault, and
     * is thrown, never swallowed.
     */
    internal suspend fun <R> unlessLocked(stale: R, body: suspend () -> R): R {
        val held = if (this::keeper.isInitialized) keeper.established?.account else null
        return try {
            body()
        } catch (e: io.silencelen.andvari.core.crypto.KeysGoneException) {
            if (held != null && !held.isWiped) throw e
            stale
        }
    }

    // ---- start, close ----

    override fun start() {
        if (phase != AppPhase.STARTING || closed) return
        // §12.4: before anything else reads a store, every old store that is not known to be gone.
        if (engine.state.get(FORMAT_KEY) != FORMAT) wipeOldStores()
        // The per-origin records this binding keeps go with a followed move and with "Forget this server"
        // (PinStore.carryWithMoves). `ovh.newkit|` is not: the move itself writes it at the new address.
        PinStore.carryWithMoves(NAME_KEY)
        PinStore.carryWithMoves(EngineRecovery.MINE_KEY)
        PinStore.carryWithMoves(EngineSharedVaults.MOVE_PREFIX)
        PinStore.carryWithMoves(EngineAccountSettings.OUTCOME_UNKNOWN_KEY)
        PinStore.carryWithMoves(io.silencelen.andvari.core.client.session.KeptPolicies.KEY_PREFIX)
        PinStore.carryWithMoves(EngineKit.SHOWN_KEY)
        PinStore.carryWithMoves(KIT_ON_SHOW_PREFIX)
        PinStore.carryWithMoves(KIT_NAMED_KEPT_PREFIX)
        PinStore.carryWithMoves(KEPT_MARK_PREFIX)
        PinStore.carryWithMoves(EngineSharedVaults.NOTES_PREFIX)
        PinStore.carryWithMoves(REMEMBERED_PREFIX)
        val keeper = SessionKeeper(engine.transport, engine.secure, engine.state, DelegatingTrust { trust }, crypto)
        this.keeper = keeper
        // "Update required" is a state the instance on show carries; it changes nothing else.
        keeper.onUpdateRequiredChanged = {
            scope.launch {
                updateRequiredChanged()
                publish()
            }
        }
        trust = CardTrust(
            PinStore(engine.state), TrustCardChainVerifier(crypto), { clientFor(it) }, crypto, engine.baked, engine.storeBuild,
            // The session's own move is part of the move journal: the trust always has a mover,
            // which first takes the kept session to the new address (idempotent: nothing happens unless it is still at the
            // old one), then runs the platform's. A stop anywhere in between is finished by finishMove at the next start.
            onMoved = io.silencelen.andvari.core.client.pin.NamespaceMover { from, to ->
                keeper.moved(from, to)
                engine.namespaceMover?.onMoved(from, to) ?: true
            },
        )
        // Design §4.1 (VR-11): while an account is signed in, a card naming it as the operator under another key is
        // refused on its own device. The key is public, so it stays set while locked.
        keeper.onAccountOpened = { trust.signedIn(it) }
        keeper.onSessionEnded = { trust.signedOut() }
        // A take ends, before it writes anything, the deletions begun at its server that it would otherwise lose to.
        keeper.beforeTake = { origin, emailNorm, userId -> accountSettingsPart.takeEndsDeletions(origin, emailNorm, userId) }
        knownDevices = KnownDevices(engine.state, crypto)
        policies = KeptPolicies(engine.state)
        // Every road that records a policy owes the wipe a forbidding one calls for (EnginePolicyWipe). The re-key's read
        // records on a worker thread: the marks are written there at once, under their own lock, so a process that ends
        // after the record keeps them; only the start of the run hops to the app's main thread.
        policies.onRecorded = { origin, kept, couldHoldCopy -> policyWipe.recorded(origin, kept, couldHoldCopy) }
        commitWatch = CommitWatch(keeper)
        kitRecovery = io.silencelen.andvari.core.client.recovery.WireKitRecovery(
            { clientFor(it) }, DelegatingTrust { trust }, knownDevices, commitWatch, crypto, engine.platform.wireName, engine.deviceName,
            knownIdentity = keeper::knownIdentity,
        )
        assisted = io.silencelen.andvari.core.client.recovery.WireAssistedRecovery(
            { clientFor(it) }, DelegatingTrust { trust }, knownDevices, commitWatch, crypto, requestStore, engine.platform.wireName, engine.deviceName,
            engine.clock, knownIdentity = keeper::knownIdentity,
        )
        // A recovery the person left after its new password was sent: what its answer came to is published once by the
        // engine, and the first screen says it.
        kitRecovery.onLateOutcome = { scope.launch { kitRecovery.takeLateOutcome()?.let(entryPart::lateOutcome) } }
        assisted.onLateOutcome = { scope.launch { assisted.takeLateOutcome()?.let(entryPart::lateOutcome) } }
        // A policy that forbids key material at rest takes the account's wrapped keys and the quick-unlock key off this
        // device the moment it is recorded, whichever read recorded it (as on the released line).
        policies.onKept = { keeper.policyRecorded(it) }
        entryLinks =io.silencelen.andvari.core.client.link.WireLinkFlows(
            { clientFor(it) }, DelegatingTrust { trust }, engine.state, crypto, engine.clock, { vault?.takeIf { !it.closed }?.link }, setupAllowed = takesSetupLinks,
            // The vaults attached to a link are shared through the open vault's log (design §6.10), after the codes
            // matched or by a release behind the warning.
            shares = io.silencelen.andvari.core.client.link.LinkShareRelease { contact, share, uncompared -> linksPart.releaseThroughLog(contact, share, uncompared) },
        )
        deviceLinks = io.silencelen.andvari.core.client.devicelink.WireDeviceLinks(
            { clientFor(it) }, DelegatingTrust { trust }, engine.state, crypto, engine.clock,
            // The existing device's side: the open account, while its session is the server's (§8.2).
            { vault?.takeIf { !it.closed && !it.signedOutByServer && phase == AppPhase.UNLOCKED }?.link }, knownDevices, keeper,
            { origin, token -> keeper.discard(origin, token) }, engine.deviceName, engine.platform.wireName,
            // A pickup this device refuses ends that one session by its refresh token; the logout would end every session
            // of this device at that server, a kept one's too.
            endOne = { origin, refresh -> keeper.notTaken(origin, "", refresh) },
        )
        val wrap = engine.keyWrap
        val clocks = engine.clocks
        if (wrap != null && clocks != null) quick = QuickUnlockKeeper(keeper, wrap, engine.secure, engine.state, DelegatingTrust { trust }, policies, clocks, crypto)
        keeper.onEnded = { reason -> sessionEnded(reason) }
        val unfinished = carryUnfinishedMoves()
        kitWipedAtStart()
        // What an end the person made left behind (a stop before its data was deleted) goes; nothing else does.
        // A wipe of the person's own act that waited behind a policy's run when the app stopped is made now.
        ownWipesAtStart()
        settleOwnEnds()
        settleForgettings()
        // A deletion the server confirmed and a stop cut part-way is finished by its own steps.
        accountSettingsPart.settleDeletions()
        // A mark of a deletion of unknown outcome that names no account holds nothing of one: it goes, so that it does not
        // hold the sweep back for good.
        accountSettingsPart.dropOutcomeMarksNamingNoAccount()
        // Then what is kept by the id of an account this device no longer knows anywhere goes ([AccountSweep]).
        sweepAccounts()
        // A policy's wipe that was counted and could not be made is tried again, while the kept policy still forbids.
        policyWipe.atStart()
        val kept = keeper.session
        if (kept != null && kept.heldAsOperator) {
            // Held as its server's operator, across a restart: the first screen says so until the person removes it.
            phase = AppPhase.ENTRY
            entryPart.reset(FirstRunNotice.OPERATOR_NEEDS_COMPUTER)
        } else if (kept != null) {
            accountEmail = kept.emailNorm
            phase = AppPhase.LOCKED
        } else {
            phase = AppPhase.ENTRY
            entryPart.reset(null)
        }
        publish()
        if (phase == AppPhase.ENTRY) entryPart.refreshPublicSignup()
        // Each unfinished move is tried once by itself before anything can open there; failing, its card offers it again.
        if (unfinished.isNotEmpty()) scope.launch {
            for ((to, from) in unfinished) instanceFlow.finish(to, from)
        }
    }

    override fun close() {
        closed = true
        scope.cancel()
        listeners.clear()
        kitPart.drop()
        entryPart.drop()
        endAccountFlows()
        endVault(null)
        if (this::keeper.isInitialized) keeper.lock()
    }

    override fun retryAfterSeconds(): Int {
        val now = engine.clock()
        return if (retryAfterUntilMs <= now) 0 else ((retryAfterUntilMs - now + 999) / 1000).toInt()
    }

    internal fun noteRetryAfter(seconds: Long?) {
        if (seconds != null && seconds > 0) retryAfterUntilMs = engine.clock() + seconds * 1000
    }

    /** The wait [seconds] a server named, kept with the end it stopped, on the clock of [retryAfterSeconds]; null where it named none. */
    internal fun namedWait(seconds: Long?): io.silencelen.andvari.core.app.NamedWait? =
        if (seconds != null && seconds > 0) io.silencelen.andvari.core.app.NamedWait(engine.clock() + seconds * 1000, engine.clock) else null

    override suspend fun openAppLink(url: String): InviteResult = when (phase) {
        AppPhase.ENTRY -> entryPart.openAppLink(url)
        AppPhase.UNLOCKED -> linksPart.openAppLink(url)
        else -> InviteResult.STALE
    }

    // ---- §12.4: the first-launch wipe ----

    /** The old stores a wipe has not removed yet; null when the format marker says the wipe is complete. */
    private fun storesLeft(): List<PreCutoverStore> {
        if (engine.state.get(FORMAT_KEY) == FORMAT) return emptyList()
        val left = engine.state.get(FORMAT_LEFT_KEY) ?: return emptyList()
        return PreCutoverStore.entries.filter { it.name in left.split(',') }
    }

    /**
     * One pass over the old stores: on a first launch all of them, afterwards the ones a pass left behind. The
     * format marker is set only once none is left, so a store that could not be deleted is tried again at every
     * start. New builds read none of these stores either way.
     */
    private fun wipeOldStores() {
        val first = engine.state.get(FORMAT_LEFT_KEY) == null
        val pending = if (first) PreCutoverStore.entries.toList() else storesLeft()
        val left = ArrayList<PreCutoverStore>()
        for (store in pending) {
            val gone = try {
                engine.stores?.wipe(store) ?: true
            } catch (e: Throwable) {
                false
            }
            if (!gone) left += store
        }
        if (left.isEmpty()) {
            engine.state.set(FORMAT_KEY, FORMAT)
            engine.state.set(FORMAT_LEFT_KEY, null)
            engine.state.set(FORMAT_TOLD_KEY, null)
        } else {
            engine.state.set(FORMAT_LEFT_KEY, left.joinToString(",") { it.name })
        }
    }

    private var oldDataShown: OldDataLeft? = null

    private fun oldData(): OldDataLeft? {
        val left = storesLeft()
        if (left.isEmpty()) {
            oldDataShown = null
            return null
        }
        val tell = engine.state.get(FORMAT_TOLD_KEY) == null
        val shown = oldDataShown
        if (shown != null && shown.stores == left && shown.tellNow == tell) return shown
        return OldDataLeft(left, tell).also { oldDataShown = it }
    }

    override fun retryOldDataRemoval(notice: OldDataLeft): Boolean {
        if (closed || snapshot.oldData !== notice) return false
        wipeOldStores()
        publish()
        return storesLeft().isEmpty()
    }

    override fun acknowledgeOldData(notice: OldDataLeft) {
        if (closed || snapshot.oldData !== notice) return
        engine.state.set(FORMAT_TOLD_KEY, "1")
        publish()
    }

    /** The line after a sign-in ([AccountSnapshot.signInNotice]); set by the sign-in, gone at a dismiss or a lock. */
    internal var signInNotice: io.silencelen.andvari.core.app.CopyLine? = null

    override fun dismissSignInNotice() {
        if (signInNotice == null) return
        signInNotice = null
        publish()
    }

    // ---- the session ----

    private var lockedShown: LockedScreen? = null

    /** [AppSnapshot.keptSignedOutNotConfirmed]: the kept account shown as signed out ended here because it could not be confirmed. */
    private fun keptNotConfirmed(): Boolean =
        phase == AppPhase.ENTRY && this::keeper.isInitialized && keeper.session?.let { it.endedByServer && it.endedUnconfirmed } == true

    private fun lockedScreen(): LockedScreen? {
        val kept = keeper.session ?: return null
        val email = accountEmail ?: kept.emailNorm
        val label = labelFor(kept.origin) ?: InstanceLabel("", kept.origin, ServerKind.PRIVATE_SERVER, selfNamed = true)
        val quickNow = quickUsableNow()
        val byServer = kept.endedByServer
        val shown = lockedShown
        val previous = kept.previousPasswordOpensCopy
        val deletionUnknown = accountSettingsPart.deletionOutcomeUnknown(kept.origin, kept.userId)
        val atServer = kept.keysAtServer
        // The keeper's own word for an end this device made because it could not confirm the session in time.
        val notConfirmed = byServer && kept.endedUnconfirmed
        val mark = keptMark()
        if (shown != null && shown.prompt.email == email && sameLabel(shown.prompt.instance, label) && shown.quickUnlock == quickNow &&
            shown.signedOutByServer == byServer && shown.previousPasswordOpensCopy == previous && shown.deletionOutcomeUnknown == deletionUnknown &&
            shown.sessionNotConfirmed == notConfirmed && shown.prompt.keptMark == mark &&
            (shown.keysAtServerLine != null) == atServer
        ) return shown
        val line = if (atServer) io.silencelen.andvari.core.app.CopyLine.of(io.silencelen.andvari.core.app.CopyKey.UNLOCK_KEYS_AT_SERVER) else null
        return LockedScreen(MasterPasswordPrompt(email, label, mark), quickNow, byServer, previous, deletionUnknown, notConfirmed, line).also { lockedShown = it }
    }

    /**
     * Quick unlock can be tried on the lock screen: usable for the kept session, and no kit waits to be made (that needs
     * the password), unless the server is stopped, where no kit can be made either.
     */
    private fun quickUsableNow(): Boolean {
        val q = quick ?: return false
        val kept = keeper.session ?: return false
        if (!kept.recoveryConfirmed && trust.access(kept.origin) == OriginAccess.OPEN) return false
        return q.status().usable
    }

    override suspend fun quickUnlock(screen: LockedScreen): QuickUnlockResult {
        if (phase != AppPhase.LOCKED || snapshot.locked !== screen) return QuickUnlockResult.STALE
        val q = quick ?: return QuickUnlockResult.USE_PASSWORD
        if (!quickUsableNow()) {
            // A damaged pin is said as such before anything else; otherwise the password is the way in now. A move whose
            // platform data has not moved reads as blocked too: the password opens nothing there either.
            val blocked = keeper.session?.origin.let { o ->
                o == null || trust.access(o).let { it == OriginAccess.BLOCKED || it == OriginAccess.MOVING } || trust.pinState(o) == PinState.None
            }
            publish()
            return if (blocked) QuickUnlockResult.SERVER_BLOCKED else QuickUnlockResult.USE_PASSWORD
        }
        val answer = working { q.unlock() }
        if (phase != AppPhase.LOCKED) return QuickUnlockResult.STALE
        return when (answer) {
            QuickUnlockOutcome.UNLOCKED -> {
                opened()
                QuickUnlockResult.DONE
            }
            QuickUnlockOutcome.CANCELLED -> QuickUnlockResult.CANCELLED
            QuickUnlockOutcome.USE_PASSWORD -> QuickUnlockResult.USE_PASSWORD
            QuickUnlockOutcome.TURNED_OFF -> {
                publish()
                QuickUnlockResult.TURNED_OFF
            }
            QuickUnlockOutcome.BLOCKED -> {
                publish()
                QuickUnlockResult.SERVER_BLOCKED
            }
            QuickUnlockOutcome.IDENTITY_FAULT -> {
                publish()
                QuickUnlockResult.IDENTITY_FAULT
            }
            QuickUnlockOutcome.NO_SESSION -> QuickUnlockResult.STALE
        }
    }

    // ---- quick unlock in Settings ----

    private var quickShown: QuickUnlockSetting? = null

    private fun quickSetting(): QuickUnlockSetting {
        val st = quick?.status()
        val state = when {
            st == null || !st.available -> QuickUnlockState.UNAVAILABLE
            st.enrolled -> QuickUnlockState.ON
            !st.allowed -> QuickUnlockState.NOT_ALLOWED
            else -> QuickUnlockState.OFF
        }
        val offer = st?.offerNow == true && state == QuickUnlockState.OFF && !accountStopped()
        val shown = quickShown
        if (shown != null && shown.state == state && shown.offerNow == offer) return shown
        return QuickUnlockSetting(state, offer).also { quickShown = it }
    }

    /**
     * The session's server is stopped on this device (design §4.4): forked, or its pin went damaged while the vault was
     * open. Either way nothing is sent there, so nothing that needs the server is offered.
     */
    private fun accountStopped(): Boolean = keeper.established?.let { serverStopped(it.origin) } == true

    /**
     * Forked, damaged, or [OriginAccess.MOVING] (a move whose platform data has not moved), or the session there was
     * ended by the server (design §4.4): nothing is sent there, and the copy opens read-only.
     */
    private fun serverStopped(origin: String): Boolean =
        trust.access(origin) != OriginAccess.OPEN || keeper.session?.let { it.origin == origin && it.endedByServer } == true

    internal suspend fun turnOnQuickUnlock(setting: QuickUnlockSetting): QuickEnrolResult {
        if (phase != AppPhase.UNLOCKED || snapshot.account?.quickUnlock !== setting) return QuickEnrolResult.STALE
        val q = quick ?: return QuickEnrolResult.NOT_AVAILABLE
        if (setting.state != QuickUnlockState.OFF) return QuickEnrolResult.NOT_AVAILABLE
        val answer = unlessLocked(QuickEnrolOutcome.NOT_OPEN) { working { q.enrol() } }
        return when (answer) {
            QuickEnrolOutcome.ENROLLED -> QuickEnrolResult.DONE
            QuickEnrolOutcome.CANCELLED -> QuickEnrolResult.CANCELLED
            QuickEnrolOutcome.NOT_AVAILABLE -> QuickEnrolResult.NOT_AVAILABLE
            QuickEnrolOutcome.NOT_OPEN -> QuickEnrolResult.STALE
            QuickEnrolOutcome.FAILED -> QuickEnrolResult.FAILED
        }
    }

    internal fun turnOffQuickUnlock(setting: QuickUnlockSetting) {
        if (phase != AppPhase.UNLOCKED || snapshot.account?.quickUnlock !== setting) return
        quick?.turnOff()
        publish()
    }

    internal fun quickUnlockNotNow(setting: QuickUnlockSetting) {
        if (phase != AppPhase.UNLOCKED || snapshot.account?.quickUnlock !== setting) return
        quick?.notNow()
        publish()
    }

    // ---- the client policy (G7) ----

    private var policyShown: ServerPolicy? = null

    private fun serverPolicy(origin: String): ServerPolicy {
        val p: KeptPolicy? = policies.get(origin)
        val shown = policyShown
        val known = p != null
        // Never read on this device: the defaults, not the ceilings. A policy kept
        // from an earlier session stays in use until a new one is read.
        val autoLock = p?.autoLockSeconds ?: ServerPolicy.DEFAULT_AUTO_LOCK_SECONDS
        val clipboard = p?.clipboardClearSeconds ?: ServerPolicy.DEFAULT_CLIPBOARD_CLEAR_SECONDS
        val cache = p?.offlineCacheAllowed ?: false
        val file = p?.attachmentMaxBytes ?: 0L
        val item = p?.itemAttachmentsMaxBytes ?: 0L
        // Android's autofill catches logins; under a forbidding policy they are kept sealed until answered, and Settings says so.
        val kept = known && !cache && engine.platform == AppPlatform.ANDROID
        if (shown != null && shown.known == known && shown.autoLockSeconds == autoLock && shown.clipboardClearSeconds == clipboard &&
            shown.offlineCacheAllowed == cache && shown.attachmentMaxBytes == file && shown.itemAttachmentsMaxBytes == item &&
            (shown.capturesKeptLine != null) == kept
        ) return shown
        val line = if (kept) io.silencelen.andvari.core.app.CopyLine.of(io.silencelen.andvari.core.app.CopyKey.POLICY_CAPTURES_KEPT_SEALED) else null
        return ServerPolicy(known, autoLock, clipboard, cache, file, item, line).also { policyShown = it }
    }

    /** Read the session's server's policy again (at every opening of the vault). Nothing is dialed at a stopped server. */
    private fun refreshPolicy(origin: String) {
        scope.launch {
            val p = policies.fetch(clientFor(origin), engine.clock()) ?: return@launch
            quick?.policySeen(origin, p)
            // A policy that forbids the copy owes its wipe from the moment it is recorded (EnginePolicyWipe.recorded, the
            // road every read takes): the policy's run sends what waits once, counts, and removes the copy. A copy kept
            // closed for a policy that could not be read is composed now.
            if (phase == AppPhase.UNLOCKED && vault == null && keeper.session?.origin == origin) {
                openVault()
                policyWipe.startIfOwed()
            }
            publish()
        }
    }

    /**
     * The account's keys as the server holds them, read at every opening of the vault. No answer changes nothing.
     * - A kit made on another device and not confirmed there leaves the account with no
     *   working kit: the kept "kit confirmed" goes false here, and the next unlock makes a fresh kit before the vault
     *   opens. Only ever lowers it ([SessionKeeper.recoveryUnconfirmed]).
     * - A password change whose answer never came is settled by the wrap the server holds
     *   ([SessionKeeper.settleWrap]).
     */
    private fun refreshAccountKeys(origin: String, userId: String) {
        scope.launch { readAccountKeys(origin, userId) }
    }

    /** [refreshAccountKeys]'s read, waited for (a second password change settles the first with it). */
    internal suspend fun readAccountKeys(origin: String, userId: String) {
        val r = clientFor(origin).call(io.silencelen.andvari.core.model.wire.WireRoute.ACCOUNT_KEYS) {
            io.silencelen.andvari.core.model.wire.WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.AccountKeys.serializer(), it)
        }
        if (r !is io.silencelen.andvari.core.client.net.WireResult.Ok) return
        val kept = keeper.session ?: return
        if (kept.origin != origin || kept.userId != userId) return
        keeper.settleWrap(userId, r.value)
        if (!r.value.recoveryConfirmed) keeper.recoveryUnconfirmed(userId)
        // The server answered for this account: it was not deleted (design point 4).
        accountSettingsPart.setDeletionOutcomeUnknown(origin, userId, false)
        publish()
    }

    /**
     * The open vault [v] is composed again: under the policy and consent as they are now, read-only while
     * [haltForUpdate]. What its cache holds to send (the queue, the denied changes awaiting their fate, the held vaults)
     * is carried into the new cache when that one is in memory; a cache file keeps it by itself. A file the new
     * composition may not keep is deleted only after the carry.
     */
    private fun recompose(v: EngineVault, haltForUpdate: Boolean) {
        val carry = v.queued()
        v.close()
        vault = null
        openVault(carry, haltForUpdate)
        // The old vault's scope took this opening's posture read with it: when still due, it is made on the new one.
        if (phase == AppPhase.UNLOCKED && keeper.session?.endedByServer != true) recoveryPart.recomposed()
        // So did the device names' read for "made on" lines.
        if (phase == AppPhase.UNLOCKED && keeper.session?.endedByServer != true) devicesPart.recomposed()
        // And this opening's read of the account's state, when it had not answered.
        if (phase == AppPhase.UNLOCKED && keeper.session?.endedByServer != true) contactsPart.recomposed()
    }

    /**
     * This opening's read of the account's state ([EngineContacts.opened]) merged something new into this device's copy:
     * the snapshot shows it (§8.5's list, a contact to confirm, a vault row's state), and the vaults this device holds no
     * key for are looked at again, since an `accepted` record of another device may have come with it (§3.6).
     */
    internal fun accountStateMerged(v: EngineVault) {
        if (v.closed || vault !== v) return
        publish()
        v.launch { vaultsPart.refresh() }
    }

    /**
     * "Update required" of the session's server changed: while it stands the open vault is
     * read-only from its copy, the same standing as a session the server ended; once it clears the vault is composed
     * again as before. Nothing closes, locks or ends. An opening of the vault (an unlock) composes as usual, and its
     * first sync says again whether it stands; so a state that cleared while nothing could ask is cleared there.
     */
    private fun updateRequiredChanged() {
        if (composing) {
            updateCheckDue = true
            return
        }
        val v = vault ?: return
        if (v.closed || v.signedOutByServer || phase != AppPhase.UNLOCKED) return
        val stands = v.origin in keeper.updateRequired.value
        if (stands != v.haltedForUpdate) recompose(v, stands)
    }

    /**
     * The platform's own consent to keep a copy at rest ([AppEngine.keepsAtRest]) changed. When it now forbids one while
     * the vault is open with its copy at rest, the vault is composed again at once on a cache in memory, carrying what
     * is queued to send; when this returns, the cache file is deleted through [AppEngine.cacheFiles] and nothing of the
     * open vault holds it, so the platform may delete its files next. Call it AFTER the consent reads as changed and
     * BEFORE deleting anything. A consent that now allows a copy changes nothing until the next opening of the vault.
     * Signed out by the server, the copy is read-only and nothing is queued: it is composed again all the same.
     */
    fun atRestConsentChanged() {
        // Uses a lock kept go at once when nothing may be kept any more, locked or not.
        if (!engine.keepsAtRest()) dropOtherKeptUses(null)
        val v = vault ?: return
        if (v.closed || !v.keptAtRest || engine.keepsAtRest() || phase != AppPhase.UNLOCKED) return
        recompose(v, v.haltedForUpdate)
        publish()
    }

    // ---- a new kit after a followed move (§4.4, R36) ----

    private var newKitShown: KitAfterMovePrompt? = null

    /** Origins whose kit-after-move prompt was put off until the next unlock. */
    private val newKitPutOff = HashSet<String>()

    // ---- the account's name (sent in its links' offers and answers, §6.7) ----

    /** The name the account [userId] at [origin] chose at its registration on this device; empty when it was made elsewhere. */
    internal fun displayName(origin: String, userId: String): String = engine.state.get("$NAME_KEY$origin|$userId").orEmpty()

    internal fun rememberName(origin: String, userId: String, name: String) {
        engine.state.set("$NAME_KEY$origin|$userId", name.takeIf { it.isNotEmpty() })
    }

    /** The session went from [from] to [to] with a followed move: the name kept for it goes with it. */
    private fun carryName(from: String, to: String, userId: String) {
        val name = displayName(from, userId)
        if (name.isEmpty() || from == to) return
        rememberName(to, userId, name)
        rememberName(from, userId, "")
    }

    /** The person followed a move to [origin]: the next account there is asked for a new kit, until one is made. */
    internal fun newKitDue(origin: String) {
        engine.state.set(NEW_KIT_KEY + origin, "1")
    }

    /** A kit was made for the account at [origin], or the server was forgotten: nothing is due there any more. */
    internal fun newKitDone(origin: String) {
        engine.state.set(NEW_KIT_KEY + origin, null)
        newKitPutOff -= origin
    }

    private fun newKitPrompt(origin: String): KitAfterMovePrompt? {
        if (engine.state.get(NEW_KIT_KEY + origin) == null || origin in newKitPutOff || accountStopped()) return null
        val label = labelFor(origin) ?: return null
        val shown = newKitShown
        if (shown != null && sameLabel(shown.instance, label)) return shown
        return KitAfterMovePrompt(label).also { newKitShown = it }
    }

    internal fun kitAfterMoveLater(prompt: KitAfterMovePrompt) {
        if (phase != AppPhase.UNLOCKED || snapshot.account?.kitAfterMove !== prompt) return
        newKitPutOff += prompt.instance.origin
        publish()
    }

    override suspend fun unlock(screen: LockedScreen, password: String): VaultUnlockResult = unlockWith(screen, password, putOffReKey = false)

    override suspend fun unlockPuttingOffReKey(screen: LockedScreen, password: String): VaultUnlockResult = unlockWith(screen, password, putOffReKey = true)

    override suspend fun unlockForFilling(screen: LockedScreen, password: String): VaultUnlockResult =
        unlockWith(screen, password, putOffReKey = true, forFilling = true)

    /**
     * The vault was opened by [unlockForFilling] without the kit the account owes ([AccountSnapshot.kitDueAtOpening]);
     * every end of the session ends it ([endVault]: a lock, a sign-out, the server's end, a forgotten server, a deletion),
     * so the next opening of the account makes the kit or opens as it is.
     */
    internal var openedWithoutKit = false
        private set

    private suspend fun unlockWith(screen: LockedScreen, password: String, putOffReKey: Boolean, forFilling: Boolean = false): VaultUnlockResult {
        if (phase != AppPhase.LOCKED || snapshot.locked !== screen) return VaultUnlockResult.STALE
        val chars = password.toCharArray()
        // A kit that was never saved is made afresh once the account is open, and that needs the password again.
        val forKit = chars.copyOf()
        // An account whose keys are kept at the server: this unlock asks the server, and may learn there that the session ended.
        val atServer = keeper.session?.takeIf { it.keysAtServer }
        val answer = try {
            working { withContext(engine.work) { keeper.unlockAsking(chars) } }
        } catch (e: Throwable) {
            // A cancel or a throw wipes the copy too.
            forKit.fill('\u0000')
            chars.fill('\u0000')
            throw e
        }
        if (phase != AppPhase.LOCKED) {
            forKit.fill('\u0000')
            return VaultUnlockResult.STALE
        }
        return when (answer) {
            KeptUnlock.Unlocked -> {
                // §12.2 rule 7, before the kit step as before the vault: the password was right, and the snapshot is
                // now the first screen with its notice.
                if (refuseHeldOperator()) {
                    forKit.fill('\u0000')
                    return VaultUnlockResult.DONE
                }
                val kept = keeper.session
                val label = kept?.let { labelFor(it.origin) }
                // Under a fork nothing is sent, so no kit can be made either: the copy on this device opens as it is.
                val stopped = kept != null && serverStopped(kept.origin)
                // A surface that only fills cannot show a kit: it makes none (the server's kit stays as it is), opens the
                // vault for filling, and leaves the kit to the app's next opening.
                val kitLeft = forFilling && kept != null && label != null && !kept.recoveryConfirmed && !stopped
                if (kept == null || label == null || kept.recoveryConfirmed || stopped || kitLeft) {
                    // Spec 01 §7: the quiet re-key, once the vault is open, inside this opening, with the password it verified.
                    try {
                        openedWithoutKit = kitLeft
                        opened()
                        withContext(engine.work) { keeper.reKeyAfterOpening(forKit, putOffReKey) { policies.fetch(it, engine.clock())?.kdfParams } }
                    } finally {
                        forKit.fill('\u0000')
                    }
                } else {
                    // The vault stays shut until a kit is saved (§10).
                    instanceFlow.unlocked(kept.origin)
                    phase = AppPhase.ENTRY
                    entryPart.leave()
                    openedWithoutKit = false
                    kitPart.make(forKit, KitReason.NEVER_SAVED, accountEmail ?: kept.emailNorm, label, kept.origin, inEntry = true) { opened() }
                }
                VaultUnlockResult.DONE
            }
            KeptUnlock.WrongPassword -> {
                forKit.fill('\u0000')
                VaultUnlockResult.WRONG_PASSWORD
            }
            KeptUnlock.Blocked -> {
                forKit.fill('\u0000')
                publish()
                VaultUnlockResult.SERVER_BLOCKED
            }
            is KeptUnlock.IdentityFault -> {
                forKit.fill('\u0000')
                VaultUnlockResult.IDENTITY_FAULT
            }
            KeptUnlock.KdfRefused, KeptUnlock.NoSession -> {
                forKit.fill('\u0000')
                VaultUnlockResult.FAILED
            }
            // Held as its server's operator (the owner's decision of 2026-11-16): nothing derived or opened; the snapshot
            // is the first screen that says so, as for the refusal above.
            KeptUnlock.HeldAsOperator -> {
                forKit.fill('\u0000')
                refuseHeldOperator()
                VaultUnlockResult.DONE
            }
            // Another unlock ran, or a lock came while this one ran: nothing opened.
            KeptUnlock.Stale -> {
                forKit.fill('\u0000')
                // Where the read of the keys at the server learned that the session ended, that end is what came of it,
                // not an older state: said as the end (the keeper answers it as Stale where its check of the state's
                // generation comes first). Nothing opened or removed.
                val now = keeper.session
                if (atServer != null && now != null && now.endedByServer && now.keysAtServer && now.userId == atServer.userId && now.origin == atServer.origin) {
                    publish()
                    VaultUnlockResult.KEYS_AT_SERVER_ENDED
                } else {
                    VaultUnlockResult.STALE
                }
            }
            // The account's keys are kept at the server only, and it did not hand them over: nothing opened or removed;
            // the lock screen says why ([LockedScreen.keysAtServerLine], and [LockedScreen.endLine] for an end).
            is KeptUnlock.KeysAtServer -> {
                forKit.fill('\u0000')
                publish()
                keysAtServerAnswer(answer.signInNeeded, refusedStatus = null, retryAfterSeconds = null)
            }
        }
    }

    /**
     * What an unlock of an account whose keys are kept at the server says where the server did not hand them over:
     * [signInNeeded] (the session ended) is [VaultUnlockResult.KEYS_AT_SERVER_ENDED]; a refusal of the read is said as what it
     * is, a wait ([VaultUnlockResult.RATE_LIMITED], with [retryAfterSeconds] noted), an update ([VaultUnlockResult.UPDATE_REQUIRED])
     * or a refusal ([VaultUnlockResult.KEYS_AT_SERVER_REFUSED]), never as silence; no answer at all (or a server error) is
     * [VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE]. The session keeper hands no refusal yet ([refusedStatus] is then null).
     */
    internal fun keysAtServerAnswer(signInNeeded: Boolean, refusedStatus: Int?, retryAfterSeconds: Long?): VaultUnlockResult = when {
        signInNeeded -> VaultUnlockResult.KEYS_AT_SERVER_ENDED
        refusedStatus == null || refusedStatus >= 500 -> VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE
        refusedStatus == 429 -> {
            noteRetryAfter(retryAfterSeconds)
            VaultUnlockResult.RATE_LIMITED
        }
        refusedStatus == 426 -> VaultUnlockResult.UPDATE_REQUIRED
        else -> VaultUnlockResult.KEYS_AT_SERVER_REFUSED
    }

    /**
     * Lock: the account's keys are wiped, the session stays. Any open flow of the account is dropped. While a kit is on
     * show (keys open in the journey) the kit is wiped too and the app goes to the lock screen;
     * the next unlock makes a fresh kit. In the journey with no keys open, a password kept at a code step goes. A kit of a
     * committed change shown with the keeper's refusal is wiped by a lock on every road too (by hand or by the kit
     * screen's idle limit, [io.silencelen.andvari.core.app.KitScreen.idleLockAfterMs]), and never unsaid: the screen the
     * person comes back to says so once ([AppSnapshot.kitWiped]); the next sign-in shows a new kit.
     *
     * **The session's tokens** (spec 03 §2, `end-session`): every lock keeps the pair, also where nothing may be kept
     * at rest (the platform's consent off, a policy without an offline copy), because the kept session is what the
     * password unlocks from. So a lock sends nothing: no `end-session`, no logout. A host that drops its pair at a lock
     * (the web tab) is the one that ends that session with `client.endSession(newestRefreshToken)`; the app never does.
     */
    override fun lock() {
        if (closed) return
        signInNotice = null
        if (phase == AppPhase.ENTRY) {
            // A kit of a committed change shown with the keeper's refusal is a secret on the screen of a device nobody may be
            // watching: the lock wipes it on every road, and the screen the person comes back to says so once ([kitWiped]).
            val wiped = kitWipedAtLock()
            if (this::keeper.isInitialized && keeper.established != null && keeper.session != null) {
                kitPart.drop()
                entryPart.drop()
                keeper.lock()
                phase = AppPhase.LOCKED
                publish()
            } else {
                entryPart.locked()
                if (wiped) {
                    entryPart.afterKitWiped()
                    publish()
                }
            }
            return
        }
        if (phase != AppPhase.UNLOCKED) return
        kitPart.drop()
        // A vault opened for filling without its kit: the next unlock is with the password and makes the kit.
        openedWithoutKit = false
        // A two-step key being set up stays for the trip to the authenticator, while it is in time.
        twoStepPart.locked()
        // The account's screens close with the keys (a connect still owed stays held for the next unlock).
        contactsPart.ended()
        linksPart.ended()
        vaultsPart.ended()
        devicesPart.locked()
        recoveryPart.locked()
        operatorPart.locked()
        accountSettingsPart.ended()
        // The content closes and its engines go with the keys; the cache file stays. The deferred vault records are
        // not written here: that needs the keys, which go now (they are written at the next unlock or sync). The uses not
        // yet flushed are sealed now, before the wipe, and kept for the next opening's sync (EngineVault.keepUsesAtLock).
        // A lock never drops changes that wait to be sent: where the copy is in memory only (nothing may be kept at rest),
        // what waits is kept, sealed as it is, for the next opening of the same account, which sends it.
        keepWaitingAtLock()
        endVault(null, keepUses = true)
        keeper.lock()
        phase = AppPhase.LOCKED
        publish()
    }

    /** Changes that wait in a copy held in memory only, kept across a lock for the next opening of the same account. */
    private var waitingAcrossLock: QueuedCarry? = null

    private fun keepWaitingAtLock() {
        val v = vault?.takeIf { !it.closed && !it.keptAtRest && !it.wipeOwed && !it.signedOutByServer } ?: return
        val q = runCatching { v.queued() }.getOrNull() ?: return
        waitingAcrossLock = q.takeIf { unsentOf(it) > 0 }
    }

    override fun waitingInMemory(): Int? {
        if (closed) return 0
        var n = waitingAcrossLock?.let { unsentOf(it) } ?: 0
        val v = vault?.takeIf { !it.closed }
        if (v != null) {
            // The open copy: its queue when it is in memory, and the saves and moves its content keeps to be finished
            // when those are held in memory. A part that cannot be read now is "cannot be told", never 0.
            if (!v.keptAtRest) n += runCatching { unsentOf(v.queued()) }.getOrNull() ?: return null
            // With the platform's consent switched off, its own records hold them in memory too.
            if (stores.inMemory(v.origin, v.userId) || !engine.keepsAtRest()) n += (v.content.keptSavesWaiting() ?: return null) + (v.content.movesWaiting() ?: return null)
        } else {
            // Locked: what this process holds in memory of the account's kept saves and moves is sealed and cannot be
            // counted now; if there is any, the number cannot be told.
            val s = if (keeperReady) keeper.session else null
            if (s != null && (stores.holdsKeptInMemory(s.origin, s.userId) || (!engine.keepsAtRest() && mayHoldKeptRecords(s.origin, s.userId)))) return null
        }
        return n
    }

    /** Nothing of the app is on show ([wentAway] until [returnedToForeground]): a kit published meanwhile is not seen. */
    internal var away = false
        private set

    override fun wentAway() {
        away = true
    }

    override fun returnedToForeground() {
        if (away) {
            away = false
            // A kit on show now is drawn at this return: it is seen, and so is the mark at rest that a close would read.
            kitPart.seenNow()
            shownMark?.takeIf { it.unseen }?.let { markNotKeptKit(it.seen()) }
        }
        if (phase != AppPhase.UNLOCKED || closed) return
        val v = vault?.takeIf { !it.closed } ?: return
        // The bell's ladder goes to zero and a waiting bell dials now (spec 03 §6).
        v.resetBell()
        v.launch { v.content.readSaveQueue() }
    }

    override fun networkReturned() {
        if (phase != AppPhase.UNLOCKED || closed) return
        // The bell alone (spec 03 §6's ladder to zero): no save-queue read, no sync, nothing sealed.
        vault?.takeIf { !it.closed }?.resetBell()
    }

    /**
     * The event bell said the session is over (a `revoked` frame, or a `401`/`403` at its ticket after the one refresh):
     * the server ended it, as a refused refresh does. Only while the bell's session is still the kept one.
     */
    internal fun bellRevoked(origin: String, userId: String) {
        val s = keeper.session ?: return
        if (s.origin != origin || s.userId != userId) return
        keeper.endedByServer(origin)
    }

    /** Where a sign-out acts: locked, unlocked, a kit on show, or the journey after "Sign in again". */
    private fun signOutPossible(): Boolean {
        // A kit on show holds a session too: sign-out works there as well.
        val atKit = phase == AppPhase.ENTRY && this::keeper.isInitialized && keeper.established != null
        // In the journey after "Sign in again": the account its server signed out, so that another can sign in.
        val keptByServer = phase == AppPhase.ENTRY && this::keeper.isInitialized && keeper.session?.endedByServer == true
        return phase == AppPhase.LOCKED || phase == AppPhase.UNLOCKED || atKit || keptByServer
    }

    /**
     * What an opening's cache holds that the server does not have, as one count: the item changes waiting to be sent,
     * those the server refused that wait for a decision, and the changes parked with a vault kept in the holding area
     * (each change counts; a held vault with none adds nothing). A sign-out of this device loses all of them.
     */
    private fun unsentOf(q: QueuedCarry): Int =
        // Each change parked with a held vault counts, not the held vault: a held vault with none adds nothing.
        (q.pending + q.staged + q.held.flatMap { it.parked }).distinctBy { it.mutationId }.size

    /** The check last handed out: the same object while what it says holds, so a confirmation of it stays valid. */
    private var checkShown: io.silencelen.andvari.core.app.SignOutCheck? = null

    /**
     * The rule of 2026-11-17: a sign-out never deletes changes that were not sent without the person having been told.
     * Counted while this account's vault is open, as [holdAsOperator] counts them ([unsentOf]); an account of which
     * this device holds no cache and no kept records ([held]) has none; otherwise (locked) this device cannot tell.
     */
    override fun signOutCheck(): io.silencelen.andvari.core.app.SignOutCheck? {
        if (!signOutPossible()) return null
        val kept = keeper.session ?: return null
        val v = vault?.takeIf { !it.closed && it.origin == kept.origin && it.userId == kept.userId }
        val count: Int? = when {
            // A cache that cannot be read now cannot be counted: said as "cannot tell", never as none.
            // Saves with files kept to finish (a lock cut them short, or their upload failed) are unsent too: a sign-out
            // deletes them. The content's null is "cannot tell".
            v != null -> runCatching { unsentOf(v.queued()) }.getOrNull()?.let { n -> v.content.keptSavesWaiting()?.let { n + it } }
            (kept.origin to kept.userId) !in held() -> 0
            else -> null
        }
        val canSend = v != null && count != null && count > 0 && phase == AppPhase.UNLOCKED &&
            !v.signedOutByServer && !v.haltedForUpdate && kept.endedByServer != true
        val shown = checkShown
        if (shown != null && shown.origin == kept.origin && shown.userId == kept.userId && shown.unsentChanges == count && shown.canSendFirst == canSend) {
            return shown
        }
        return io.silencelen.andvari.core.app.SignOutCheck(count, canSend, kept.origin, kept.userId).also { checkShown = it }
    }

    override suspend fun signOut(): PlainResult {
        val check = signOutCheck() ?: return PlainResult.STALE
        if (check.needsConfirmation) return PlainResult.UNSENT_NOT_CONFIRMED
        return signOutNow()
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
        val v = vault ?: return io.silencelen.andvari.core.app.SendFirstResult.STALE
        // The content's own sync: it sends what waits, then reads; its line ("Synced.", or why not) is the content's.
        unlessLocked(null) { working { v.content.refresh() } }
        val after = signOutCheck() ?: return io.silencelen.andvari.core.app.SendFirstResult.STALE
        if (after.origin != check.origin || after.userId != check.userId) return io.silencelen.andvari.core.app.SendFirstResult.STALE
        return when (after.unsentChanges) {
            0 -> io.silencelen.andvari.core.app.SendFirstResult.DONE
            null -> io.silencelen.andvari.core.app.SendFirstResult.STALE
            else -> io.silencelen.andvari.core.app.SendFirstResult.NOT_ALL_SENT
        }
    }

    override fun forgetAfterUnknownDeletionCheck(): io.silencelen.andvari.core.app.ForgetUnknownDeletion? =
        if (closed) null else accountSettingsPart.forgetUnknownCheck()

    override suspend fun forgetAfterUnknownDeletion(check: io.silencelen.andvari.core.app.ForgetUnknownDeletion): PlainResult =
        if (closed) PlainResult.STALE else accountSettingsPart.forgetAfterUnknownDeletion(check)

    /** The sign-out itself, once the rule above is met (also the switch to another server's invitation). */
    internal suspend fun signOutNow(): PlainResult {
        if (!signOutPossible()) return PlainResult.STALE
        // A run of the policy's wipe under way is waited for: the sign-out never removes a copy the run is counting.
        if (policyWipe.lock.held) {
            policyWipe.lock.idle()
            if (!signOutPossible()) return PlainResult.STALE
        }
        val kept = keeper.session ?: return PlainResult.STALE
        checkShown = null
        working {
            dropKitButCommitted()
            endAccountFlows()
            // The person's own act: the device's copy goes (design §4.4).
            endVault(kept, CopyDeletion.SIGNED_OUT)
            // Best effort: the session is forgotten on this device whatever the server answered.
            keeper.signOut()
            settleOwnEnds()
        }
        accountEmail = null
        phase = AppPhase.ENTRY
        entryPart.reset(null)
        publish()
        entryPart.refreshPublicSignup()
        return PlainResult.DONE
    }

    /** The vault opens: the session is established and its kit is saved. */
    internal fun opened() {
        if (refuseHeldOperator()) return
        keeper.session?.let { instanceFlow.unlocked(it.origin) }
        // The notice of a kit a lock wiped is NOT taken by an opening (a quick unlock the app starts by itself could take it
        // unread): only the person's dismiss takes it, with its mark at rest ([dismissKitWiped]).
        // What was put off "until the next unlock" returns now.
        newKitPutOff.clear()
        phase = AppPhase.UNLOCKED
        entryPart.leave()
        openVault()
        // The opening can end the session at once (the bell's `revoked`): nothing more opens then.
        if (phase != AppPhase.UNLOCKED) return
        // Back from a trip away in the middle of a two-step setup: its screen opens again on the confirm step.
        twoStepPart.resume()
        publish()
        // A copy whose wipe the server's policy calls for: the one attempt, then the wipe (an ended session sends nothing).
        policyWipe.startIfOwed()
        // The account's device names, for "made on" lines, when a contact names its device.
        if (keeper.session?.endedByServer != true) devicesPart.readNamesIfNeeded()
        // The recovery posture, once per opening: §4.5's silent re-seal or its question, and §8.5's operator clause.
        if (keeper.session?.endedByServer != true) recoveryPart.opened()
        // Signed out by the server: the copy opens read-only, and nothing is sent.
        if (keeper.session?.endedByServer == true) return
        // A connect link the person came in through is answered now that the account is open (§6.7).
        linksPart.vaultOpened()
        // What the account's other devices decided: its state, read once per opening, in the background.
        contactsPart.opened()
        keeper.session?.let {
            refreshPolicy(it.origin)
            refreshAccountKeys(it.origin, it.userId)
        }
    }

    /**
     * Design §12.2 rule 7: a phone must not hold the operator account. The pinned card is the newest card this device
     * verified; when it names the kept session's account as `operator` (a handover made it the operator), or the
     * session itself has the operator role, a phone ends the session at once, wipes its keys, keeps nothing of the
     * account and says so ([FirstRunNotice.OPERATOR_NEEDS_COMPUTER]). It needs no signal from the server, so it covers
     * a quick unlock, which carries no role. The logout is sent afterwards, best effort, through the guard. True when
     * the session was refused.
     *
     * Until the engine's own query for it lands, the comparison is the pin's `operator` against the session's userId.
     */
    internal fun refuseHeldOperator(): Boolean {
        if (takesSetupLinks) return false
        val kept = keeper.session ?: return false
        // Only a card this device verified decides it (the pinned card, or a forked pin's last verified one): the
        // session's role is the server's word, so it puts nothing in this state. Once held, the account stays held until
        // the person removes it, whatever a later card says (the design is silent; the owner is asked).
        if (!kept.heldAsOperator && trust.cardNamesOperator(kept.origin, kept.userId) != true) return false
        holdAsOperator(kept)
        return true
    }

    /**
     * The owner's decision of 2026-11-16 ("stop using it at once, keep the copy locked, let the person remove it"),
     * replacing the silent sign-out and deletion: the open vault and every flow of the account stop now (no sync, no
     * queued save, no bell, no refresh), the keeper wipes the keys and the quick-unlock record and keeps no token
     * ([SessionKeeper.holdAsOperator]), nothing at all is sent (not even a logout), and nothing is deleted: the cache
     * file, the kept records and the wrapped key stay. The first screen says so ([EntryScreen.FirstRun.heldAsOperator])
     * until the person removes the account ([io.silencelen.andvari.core.app.EntryApi.removeHeldOperatorAccount]).
     */
    private fun holdAsOperator(kept: io.silencelen.andvari.core.client.session.KeptSession) {
        // What this device has not sent, counted while the vault is still open (afterwards it cannot be counted
        // without opening the vault); unknown when no vault was open.
        val v = vault?.takeIf { !it.closed && it.origin == kept.origin && it.userId == kept.userId }
        if (v != null) {
            val q = runCatching { v.queued() }.getOrNull()
            engine.state.set(HELD_UNSENT_KEY + kept.origin + "|" + kept.userId, q?.let { unsentOf(it).toString() })
        }
        endAccountFlows()
        // The vault closes as at a lock, its copy kept; uses recorded since the last flush are not kept (nothing more of
        // this account is written for later sending).
        endVault(null)
        keeper.holdAsOperator()
        quickShown = null
        dropKitButCommitted()
        accountEmail = null
        phase = AppPhase.ENTRY
        entryPart.reset(FirstRunNotice.OPERATOR_NEEDS_COMPUTER)
        publish()
    }

    /**
     * A session the server's own answer calls the operator's (its `role`: the server's word, not a card this device
     * verified), on a phone, at a sign-in or a recovery: it is ended here and its logout sent, but NOT as the person's
     * own act, so nothing of the account's data on this device is deleted because of it (before, the sign-out counted
     * as the person's own and the next start deleted the copy). A verified card is what holds an account as the
     * operator ([refuseHeldOperator]).
     */
    internal suspend fun endServerSaidOperator() {
        keeper.endNow(ownAct = false)?.invoke()
    }

    /** The account held as its server's operator on this device, as the first screen shows it; null when none is. */
    internal fun heldAsOperator(): io.silencelen.andvari.core.app.HeldOperatorAccount? {
        val kept = keeper.session?.takeIf { it.heldAsOperator } ?: return null
        val unsent = engine.state.get(HELD_UNSENT_KEY + kept.origin + "|" + kept.userId)?.toIntOrNull()
        // No card readable (a damaged pin): the address alone, marked as nobody's word but the address.
        val label = labelFor(kept.origin)
            ?: io.silencelen.andvari.core.app.InstanceLabel(kept.origin, kept.origin, io.silencelen.andvari.core.app.ServerKind.PRIVATE_SERVER, selfNamed = true)
        val shown = heldShown
        if (shown != null && shown.email == kept.emailNorm && sameLabel(shown.instance, label) && shown.unsentChanges == unsent) return shown
        return io.silencelen.andvari.core.app.HeldOperatorAccount(kept.emailNorm, label, unsent).also { heldShown = it }
    }

    private var heldShown: io.silencelen.andvari.core.app.HeldOperatorAccount? = null

    /**
     * The kit on show goes, except a kit of a committed change shown in the journey with the keeper's refusal
     * ([EngineKit.notKeptOnShow]): that is the account's only kit, and what happens to another account kept here (its end
     * by its server, its sign-out, its removal) never takes it away unsaid. It stays on show above whatever the journey
     * shows next. True when it stayed.
     */
    private fun dropKitButCommitted(): Boolean {
        if (phase == AppPhase.ENTRY && kitPart.notKeptOnShow) {
            // What stood in the way here may be gone now (the other account signed out, the held one removed): the mark at
            // rest says what a start after a close would say.
            shownMark?.let { markNotKeptKit(it) }
            return true
        }
        kitPart.drop()
        return false
    }

    /** [AppSnapshot.kitWiped]: said in every phase until the person dismisses it ([dismissKitWiped]); nothing else takes it. */
    private var kitWiped: io.silencelen.andvari.core.app.KitWipedNotice? = null

    /** The mark of the kit of a committed change on show now ([markNotKeptKit]), or null. */
    private var shownMark: KitMark? = null

    /** The mark of the notice not dismissed yet ([kitWiped]), or null. */
    private var noticeMark: KitMark? = null

    /**
     * The lock's part for a kit of a committed change on show in the journey: it is wiped (its secret leaves memory), and
     * the notice that says so is set; its mark stays at rest, as the notice's, until the person dismisses it. True when
     * there was one.
     */
    private fun kitWipedAtLock(): Boolean {
        val road = kitPart.notKeptRoad() ?: return false
        val known = (shownMark ?: KitMark(road.first, road.second, null, false, origin = kitPart.notKeptOrigin())).now()
        // A kit made while the app was away and wiped before it came back was never seen: the notice says so as itself.
        val seenOrNot = if (kitPart.shownSeen) known.seen() else known.unseenNow()
        // The kept session its reason names now, for the way out under the notice ([KitWipedNotice.namedKept]).
        val mark = seenOrNot.naming(keptMark().ifEmpty { null })
        kitPart.drop()
        shownMark = null
        noticeMark = mark
        keepKitMark()
        kitWiped = io.silencelen.andvari.core.app.KitWipedNotice.of(mark.recovery, mark.email, mark.whyHere, mark.unseen, mark.namedKept)
        return true
    }

    /** [MasterPasswordPrompt.keptMark]'s current value and whose it is (`<origin>|<userId>|`); see [keptMark]. */
    private var keptMarkNow = ""
    private var keptMarkOwner = ""
    private var keptMarkTakes = -1L

    /**
     * The opaque mark of the session kept now ([MasterPasswordPrompt.keptMark]); empty when none is kept. A random mark
     * made at each take this process sees ([SessionKeeper.takes] moved, or another account or origin kept), kept at rest
     * with its owner, so that the copy loaded at a start keeps the mark it had. Read at every publish, so a take is marked
     * as soon as it is published.
     */
    internal fun keptMark(): String {
        if (!this::keeper.isInitialized) return ""
        val kept = keeper.session
        val takes = keeper.takes
        if (kept == null) {
            if (keptMarkNow.isNotEmpty()) runCatching { engine.state.set(KEPT_MARK_PREFIX + keptMarkOwner.substringBefore('|'), null) }
            keptMarkNow = ""
            keptMarkOwner = ""
            keptMarkTakes = takes
            return ""
        }
        val owner = kept.origin + "|" + kept.userId + "|"
        if (takes == keptMarkTakes && owner == keptMarkOwner && keptMarkNow.isNotEmpty()) return keptMarkNow
        // Kept under its server ([KEPT_MARK_PREFIX]), so that the server's forgetting takes it and a followed move carries
        // it; the value names the account only (`<userId>|<mark>`), never the server, so it reads the same after a move.
        // One in the form from before goes.
        runCatching { engine.state.get(KEPT_MARK_KEY) }.getOrNull()?.let { runCatching { engine.state.set(KEPT_MARK_KEY, null) } }
        val stored = runCatching { engine.state.get(KEPT_MARK_PREFIX + kept.origin) }.getOrNull()
        val mine = kept.userId + "|"
        // A copy loaded at the start (no take yet in this process): the mark it had before.
        val loaded = takes == 0L && stored != null && stored.startsWith(mine) && stored.length > mine.length
        keptMarkNow = if (loaded) stored!!.removePrefix(mine) else Bytes.toB64(crypto.randomBytes(12))
        if (keptMarkOwner.isNotEmpty() && keptMarkOwner.substringBefore('|') != kept.origin) {
            runCatching { engine.state.set(KEPT_MARK_PREFIX + keptMarkOwner.substringBefore('|'), null) }
        }
        keptMarkOwner = owner
        keptMarkTakes = takes
        if (!loaded) runCatching { engine.state.set(KEPT_MARK_PREFIX + kept.origin, mine + keptMarkNow) }
        return keptMarkNow
    }

    /**
     * The kept session went from [from] to [to] with a followed move: the marks in memory follow it (the records at rest
     * are carried by the move), so that a kit's notice still names the session kept and its way out stays, and the next
     * write of a mark is under [to], with nothing left under [from].
     */
    internal fun kitMarksMoved(from: String, to: String) {
        if (from == to) return
        fun moved(m: KitMark?): KitMark? =
            if (m?.origin != from) m else KitMark(m.recovery, m.email, m.whyHere, m.whileAnotherKept, m.unseen, m.namedKept, to)
        shownMark = moved(shownMark)
        noticeMark = moved(noticeMark)
        if (keptMarkOwner.startsWith("$from|")) {
            keptMarkOwner = to + keptMarkOwner.removePrefix(from)
            keptMarkTakes = if (this::keeper.isInitialized) keeper.takes else keptMarkTakes
            runCatching { engine.state.set(KEPT_MARK_PREFIX + from, null) }
            if (keptMarkNow.isNotEmpty()) runCatching { engine.state.set(KEPT_MARK_PREFIX + to, keptMarkOwner.removePrefix("$to|") + keptMarkNow) }
        }
        // Written under [to]; [kitMarkOrigin] still names [from], so whatever stands there goes.
        if ((shownMark ?: noticeMark)?.origin == to) keepKitMark()
    }

    /**
     * What is kept at rest of a kit of a committed change shown with the keeper's refusal: only that one was on show for
     * [email] ([recovery]: after a recovery; else after a registration), and [whyHere], the refusal's own line, while it
     * stands; never anything of the kit. [whileAnotherKept]: what stands in the way here is another account kept here (or
     * its server's operator account held), and goes once none is kept; any other reason (the account's identity, its keys)
     * stands on this device.
     */
    internal class KitMark(
        val recovery: Boolean, val email: String, val whyHere: io.silencelen.andvari.core.app.CopyKey?, val whileAnotherKept: Boolean,
        /** The kit was made while the app was away and has not been on show since ([away]). */
        val unseen: Boolean = false,
        /** The [keptMark] of the session kept when the mark was made ([KitWipedNotice.namedKept]); kept at rest beside it. */
        val namedKept: String? = null,
        /** The server of the kit's account: the mark is kept under it, so that the server's forgetting takes it. Null: not known (a mark from before). */
        val origin: String? = null,
    ) {
        fun text(): String = (if (unseen) UNSEEN else "") + (if (recovery) "recovery|" else "registration|") + (whyHere?.let { "${it.name}|" } ?: "") + email

        fun seen(): KitMark = if (!unseen) this else KitMark(recovery, email, whyHere, whileAnotherKept, false, namedKept, origin)

        fun unseenNow(): KitMark = if (unseen) this else KitMark(recovery, email, whyHere, whileAnotherKept, true, namedKept, origin)

        fun naming(kept: String?): KitMark = KitMark(recovery, email, whyHere, whileAnotherKept, unseen, kept, origin)

        companion object {
            /** The prefix of a mark whose kit was never seen; a mark written before it reads as seen, as it was said then. */
            private const val UNSEEN = "unseen:"

            fun parse(stored: String, namedKept: String? = null, origin: String? = null): KitMark {
                val unseen = stored.startsWith(UNSEEN)
                val text = stored.removePrefix(UNSEEN)
                val road = text.substringBefore('|')
                val rest = text.substringAfter('|')
                val why = io.silencelen.andvari.core.app.CopyKey.entries.firstOrNull { it.name == rest.substringBefore('|') }?.takeIf { '|' in rest }
                return KitMark(road == "recovery", if (why != null) rest.substringAfter('|') else rest, why, false, unseen, namedKept, origin)
            }
        }
    }

    /** [this], with [KitMark.whyHere] dropped where what stood in the way here is gone now. */
    private fun KitMark.now(): KitMark =
        if (whyHere != null && whileAnotherKept && keeper.session == null) KitMark(recovery, email, null, false, unseen, origin = origin) else this

    /**
     * The mark at rest that a kit of a committed change is on show ([mark]), or that none is any more (null: it was
     * confirmed): a start after the app was closed with it on show says that it is gone. A notice not yet dismissed keeps
     * its own mark meanwhile.
     */
    internal fun markNotKeptKit(mark: KitMark?) {
        // A kit on show that was published only while the app was away is marked unseen, so that a close says so too.
        // It names the session kept now, which a start after a close then names too.
        shownMark = mark?.now()?.let { if (!kitPart.shownSeen) it.unseenNow() else it }?.naming(keptMark().ifEmpty { null })
        keepKitMark()
    }

    /** The origin the kit marks were last written under (one mark stands at a time). */
    private var kitMarkOrigin: String? = null

    /**
     * The mark at rest, under its server ([KIT_ON_SHOW_PREFIX]): the one on show, else the notice's. A mark written under
     * another server before, or in the form from before the marks named their server, goes.
     */
    private fun keepKitMark() {
        val mark = shownMark ?: noticeMark
        val st = engine.state
        val origin = mark?.origin
        kitMarkOrigin?.takeIf { it != origin }?.let { old ->
            runCatching { st.set(KIT_ON_SHOW_PREFIX + old, null) }
            runCatching { st.set(KIT_NAMED_KEPT_PREFIX + old, null) }
        }
        runCatching { st.set(KIT_ON_SHOW_KEY, null) }
        runCatching { st.set(KIT_NAMED_KEPT_KEY, null) }
        if (mark != null && origin != null) {
            runCatching { st.set(KIT_ON_SHOW_PREFIX + origin, mark.text()) }
            runCatching { st.set(KIT_NAMED_KEPT_PREFIX + origin, mark.namedKept) }
        }
        kitMarkOrigin = origin
    }

    /**
     * At a start: a mark left by a kit of a committed change that was on show when the app was closed, or by a notice not
     * dismissed, as the notice. The mark stays until the dismiss. A mark in the form from before the marks named their
     * server is read as of no known server: any server's forgetting takes it.
     */
    private fun kitWipedAtStart() {
        val st = engine.state
        val keyed = runCatching { st.keys() }.getOrNull().orEmpty().firstOrNull { it.startsWith(KIT_ON_SHOW_PREFIX) }
        val origin = keyed?.removePrefix(KIT_ON_SHOW_PREFIX)
        val text = keyed?.let { runCatching { st.get(it) }.getOrNull() } ?: runCatching { st.get(KIT_ON_SHOW_KEY) }.getOrNull() ?: return
        val named = runCatching { st.get(if (origin != null) KIT_NAMED_KEPT_PREFIX + origin else KIT_NAMED_KEPT_KEY) }.getOrNull()
        val mark = KitMark.parse(text, named, origin)
        noticeMark = mark
        kitMarkOrigin = origin
        kitWiped = io.silencelen.andvari.core.app.KitWipedNotice.of(mark.recovery, mark.email, mark.whyHere, mark.unseen, mark.namedKept)
    }

    /**
     * [origin] is forgotten on this device ("Forget this server", a confirmed deletion there): a kit's notice or mark of an
     * account there goes with it, at rest and in memory, and so does one of no known server. The engine's wipe of the
     * origin takes the records at rest too; this takes what the layer holds in memory.
     */
    internal fun kitMarksForgotten(origin: String, emailNorm: String? = null) {
        // [emailNorm]: only the account of that address goes (a confirmed deletion while another account is held there).
        fun goes(m: KitMark) = (m.origin == null || m.origin == origin) &&
            (emailNorm == null || io.silencelen.andvari.core.trust.TrustGrammar.emailNorm(m.email) == emailNorm)
        val shown = shownMark
        if (shown != null && goes(shown)) shownMark = null
        val notice = noticeMark
        if (notice != null && goes(notice)) {
            noticeMark = null
            kitWiped = null
        }
        keepKitMark()
        if (emailNorm != null) return
        runCatching { engine.state.set(KEPT_MARK_PREFIX + origin, null) }
        if (keptMarkOwner.startsWith("$origin|")) {
            keptMarkNow = ""
            keptMarkOwner = ""
        }
    }

    // ---- "Forget the earlier account on this device" (decided on 2026-11-17) ----

    /**
     * The offer of the forgetting for [email] at [origin], on the screen [on]; null where none is made: the address is not
     * one, this device ties no account to it there (the refusal was not about an earlier account), or the account it ties
     * to it is one this device keeps open, under another address, at another origin (a followed move) or as its server's
     * operator. What the forgetting removes that was never sent is counted as [unsentForForgetting] counts it: the account's
     * signed changes to shared vaults waiting here, with or without a copy (no copy held: those alone), and a copy held here
     * and not open: this device cannot tell.
     *
     * The binding is the keeper's own answer ([SessionKeeper.addressBinding], facts only): the offer is made only where
     * the account stands as the keeper's forgetting would remove it (not kept here, or kept here locked).
     */
    internal fun earlierOffer(origin: String, email: String, on: Any, confirming: Boolean, served: String): io.silencelen.andvari.core.app.EarlierAccountKnown? {
        val norm = io.silencelen.andvari.core.trust.TrustGrammar.emailNorm(email) ?: return null
        // A session record the secure store cannot read now may be that account's: no offer, as where the kept session is.
        if (keeper.sessionRecordUnreadable()) return null
        val binding = keeper.addressBinding(origin, norm) ?: return null
        if (binding.here != io.silencelen.andvari.core.client.session.BoundAccountHere.NOT_KEPT &&
            binding.here != io.silencelen.andvari.core.client.session.BoundAccountHere.KEPT_LOCKED
        ) return null
        val bound = binding.userId.takeIf { it.isNotEmpty() } ?: return null
        // Only for ANOTHER account than the one the server served (decided on 2026-11-19): the same account under another
        // key is the identity fault, and nothing is forgotten for it.
        if (bound == served) return null
        val kept = keeper.session
        val copy = kept != null && kept.userId == bound
        if (copy && (kept!!.origin != origin || kept.emailNorm != norm || kept.heldAsOperator || keeper.established != null)) return null
        // A copy of that account this device holds at this server (or at a former address of it) goes with the forgetting
        // ([dropForgotten]) whether or not the keeper still reads it as its session (a session record that could not be
        // read, a secure store the platform lost): the confirmation says so, and what it holds that was not sent cannot be
        // told. A copy held at another server this device knows stays, and is not named.
        val heldCopy = held().any { it.second == bound && heldAtOriginOnly(origin, it.first) }
        // The forgetting also removes that account's signed changes to shared vaults that were never sent (a sign-out keeps
        // them), kept by its id: only where nothing at another server ties the account ([dropForgotten]). They are counted
        // as the forgetting after a deletion of unknown outcome counts them, by the same records; where a copy is held here
        // and not open, nothing can be told.
        val tied = keptElsewhere(bound, origin, norm)
        val unsent: Int? = if (heldCopy) null else unsentForForgetting(origin, bound, byIdToo = !tied)
        val label = labelFor(origin)
            ?: io.silencelen.andvari.core.app.InstanceLabel(origin, origin, io.silencelen.andvari.core.app.ServerKind.PRIVATE_SERVER, selfNamed = true)
        return io.silencelen.andvari.core.app.EarlierAccountKnown(email.trim(), label, copy || heldCopy, unsent, confirming, origin, norm, bound, on, served)
    }

    /**
     * The person's second confirmation of the forgetting for [emailNorm] at [origin]: the keeper's call, which sends nothing,
     * and after "forgotten" everything this layer holds of that account goes, whatever the keeper reported about a copy
     * ([dropForgotten]). [email] is kept for the one notice at the next take under the address. [earlierUserId]: the account
     * the confirmation named; the keeper forgets that one or none ([SessionKeeper.forgetEarlierAccount]).
     */
    internal suspend fun forgetEarlier(origin: String, emailNorm: String, email: String, earlierUserId: String): io.silencelen.andvari.core.client.session.ForgetEarlier = working {
        // A session record the secure store holds and cannot read now may be that very account's: nothing is forgotten, and
        // no mark is written or taken (as where the kept session names the account).
        if (keeper.sessionRecordUnreadable()) return@working io.silencelen.andvari.core.client.session.ForgetEarlier.OpenForThatAccount
        // A forgetting begun before and not finished (the keeper forgot, the deletion stopped part-way): finished now, and
        // answered as what it is. Never "nothing to forget": the keeper's record of the address is already gone.
        forgettingMarks().firstOrNull { it.origin == origin && it.emailNorm == emailNorm }?.let { m ->
            if (boundUser(origin, emailNorm) != m.userId && keeper.session?.userId != m.userId) {
                val tied = m.tied ?: keptElsewhere(m.userId, origin, emailNorm)
                keeper.finishForgetting(origin, m.userId, knownElsewhere = tied)
                dropForgotten(origin, emailNorm, m.userId, m.at, tied = tied)
                setForgettingMarks(forgettingMarks().filterNot { it.origin == origin && it.emailNorm == emailNorm })
                if (m.userId == earlierUserId) {
                    remembering["$origin|$emailNorm"] = email
                    sweepAccounts()
                    return@working io.silencelen.andvari.core.client.session.ForgetEarlier.Forgotten(m.userId, copyRemoved = false)
                }
                // The confirmation named another account, taken under the address since the cut: the earlier forgetting is
                // finished without a word, and the account the person confirmed is forgotten below.
            }
        }
        // A lasting mark before the keeper's call, taken away only once the deletion is complete ([settleForgettings] at a
        // start, or the next tap, finishes one left standing).
        val bound = boundUser(origin, emailNorm)
        // Only what that server held, there and at its former addresses: a copy of the same account id at another server
        // this device knows is that server's ([heldAtOriginOnly]).
        val at = (held().filter { it.second == bound && heldAtOriginOnly(origin, it.first) }.map { it.first } + origin).distinct()
        // The tie is read before the keeper removes the address's record here, which a tie can run through; with it, whether
        // the sweep's own rule knows the account apart from what this forgetting removes ([keptElsewhere]).
        val tied = bound != null && keptElsewhere(bound, origin, emailNorm)
        val others = forgettingMarks().filterNot { it.origin == origin && it.emailNorm == emailNorm }
        // The mark keeps that reading: a finish after a cut reads the tie again only for a mark an earlier build wrote.
        if (bound != null) setForgettingMarks(others + ForgettingMark(origin, emailNorm, bound, at, tied))
        val r = keeper.forgetEarlierAccount(origin, emailNorm, earlierUserId, knownElsewhere = tied)
        if (r is io.silencelen.andvari.core.client.session.ForgetEarlier.Forgotten) {
            val tiedForgotten = if (r.forgottenUserId == bound) tied else keptElsewhere(r.forgottenUserId, origin, emailNorm)
            if (r.forgottenUserId != bound) setForgettingMarks(others + ForgettingMark(origin, emailNorm, r.forgottenUserId, at, tiedForgotten))
            dropForgotten(origin, emailNorm, r.forgottenUserId, at, tied = tiedForgotten)
            remembering["$origin|$emailNorm"] = email
        }
        // Forgotten and deleted, or nothing forgotten: the mark goes.
        setForgettingMarks(forgettingMarks().filterNot { it.origin == origin && it.emailNorm == emailNorm })
        if (r is io.silencelen.andvari.core.client.session.ForgetEarlier.Forgotten) sweepAccounts()
        r
    }

    /** The user id the keeper ties to [emailNorm] at [origin] ([earlierOffer]'s read of the keeper's record); null for none. */
    private fun boundUser(origin: String, emailNorm: String): String? =
        keeper.addressBinding(origin, emailNorm)?.userId?.takeIf { it.isNotEmpty() }

    /**
     * A forgetting begun: the address at [origin], the account [userId] the keeper ties to it, the origins it was held at,
     * and whether something at another server tied the account ([tied], read before anything was removed; null for a mark
     * an earlier build wrote without it). Written as `[origin, address, userId, "tie:yes"|"tie:no", held origins…]`: an
     * origin never starts with `tie:`.
     */
    internal class ForgettingMark(val origin: String, val emailNorm: String, val userId: String, val at: List<String>, val tied: Boolean?)

    /**
     * The forgettings begun and not finished ([FORGETTING_KEY]): the entries that read ([forgettingEntries]); a text that is
     * not the marks' form is read as none.
     */
    private fun forgettingMarks(): List<ForgettingMark> =
        engine.state.get(FORGETTING_KEY)?.let { forgettingEntries(it) }.orEmpty().filterNotNull()

    private fun setForgettingMarks(marks: List<ForgettingMark>) {
        engine.state.set(FORGETTING_KEY, marks.takeIf { it.isNotEmpty() }?.let { m ->
            kotlinx.serialization.json.JsonArray(m.map { k ->
                val tie = k.tied?.let { listOf(TIE_MARK + if (it) "yes" else "no") }.orEmpty()
                kotlinx.serialization.json.JsonArray((listOf(k.origin, k.emailNorm, k.userId) + tie + k.at).map { kotlinx.serialization.json.JsonPrimitive(it) })
            }).toString()
        })
    }

    /**
     * At a start, before anything is shown: a forgetting the app stopped in (between the keeper's call and the end of the
     * deletion, or a store that failed part-way) is finished. Where the keeper still ties the address to that account, or
     * keeps it, the keeper did not forget it: nothing is deleted, and the mark goes.
     */
    private fun settleForgettings() {
        // A record whose text is not the marks' form, or that holds an entry that is not one, names no forgetting this
        // device can finish, and would hold the sweep back for good: it is written again from the entries that read.
        val text = engine.state.get(FORGETTING_KEY)
        if (text != null && forgettingEntries(text)?.none { it == null } != true) setForgettingMarks(forgettingMarks())
        // While the secure store holds a session record it cannot read now, that record may be the account of a mark:
        // nothing is finished, and the marks stay (the sweep reads them as in flight).
        if (keeper.sessionRecordUnreadable()) return
        val marks = forgettingMarks()
        if (marks.isEmpty()) return
        for (m in marks) {
            if (boundUser(m.origin, m.emailNorm) != m.userId && keeper.session?.userId != m.userId) {
                // A cut after the address's record went can leave the keeper's identity record of that account: it goes now.
                val tied = m.tied ?: keptElsewhere(m.userId, m.origin, m.emailNorm)
                keeper.finishForgetting(m.origin, m.userId, knownElsewhere = tied)
                dropForgotten(m.origin, m.emailNorm, m.userId, m.at, tied = tied)
            }
            setForgettingMarks(forgettingMarks().filterNot { it.origin == m.origin && it.emailNorm == m.emailNorm })
        }
    }

    /**
     * After a forgetting, nothing of [userId] is left on this device for a server that later serves the same user id to find:
     * its cache files and the content's kept records at every address it was held at (as at a sign-out), and the records kept
     * by user id that the keeper leaves to this layer (the account's state copy and marks, its vault logs, its recovery mirror
     * and escrow mark, the item engine's records), the name it went by, the count kept for an operator's account, the
     * deletion's unknown outcome; all without condition. The identity record and the address's record are the keeper's.
     * Also every record kept per origin under the account's user id (`<prefix><origin>|<userId>` or `…|<userId>|…`) at
     * each of those origins, for every registered per-origin prefix ([PinStore.originKeyed]) that [FORGOTTEN_PER_ORIGIN]
     * does not name as keyed by the origin alone or by an address: the contacts it confirmed and its one-tap mark, its
     * link and code records, a link bundle's vault checkpoints, its quick-unlock offer, its recovery requests. [at0]: the
     * origins it was held at when the forgetting began (a deletion finished later no longer finds them in the held list).
     * Run again over what is left, it deletes the rest: a deletion stopped part-way is finished by running it again.
     *
     * Both a forgetting of an earlier account and a deletion that [origin] confirmed ([deletion], [dropDeletedAccountOnly])
     * are that server's word alone, and read one tie. What is kept for the account at another server this device still
     * knows stays (its copy with whatever waits in it unsent, its held entry, its name, its per-server records:
     * [heldAtOriginOnly]), and what is kept by the account's id alone goes only where nothing at another server ties the
     * account ([tied], as read before anything of the account was removed: [PinStore.tiedElsewhere]; a store that cannot
     * list its keys counts as a tie). Where nothing ties it elsewhere, nothing of it is left. A deletion's copies went
     * already, each once with its own reason.
     */
    private fun dropForgotten(origin: String, emailNorm: String, userId: String, at0: List<String>, deletion: Boolean = false, tied: Boolean) {
        val at = ((at0 + held().filter { it.second == userId }.map { it.first }).filter { heldAtOriginOnly(origin, it) } + origin).distinct()
        val byIdToo = !tied
        if (lastKept?.userId == userId) lastKept = null
        checkShown = null
        if (!deletion) for (o in at) dropData(o, userId, io.silencelen.andvari.core.client.items.CopyDeletion.FORGOT_SERVER)
        setHeld(held().filter { it.second != userId || it.first !in at })
        val st = engine.state
        // The mark that a kit for the address was shown here and never confirmed: that kit was the earlier account's.
        st.set(EngineKit.shownKey(origin, emailNorm), null)
        for (o in at) {
            st.set(HELD_UNSENT_KEY + o + "|" + userId, null)
            st.set("$NAME_KEY$o|$userId", null)
            accountSettingsPart.setDeletionOutcomeUnknown(o, userId, false)
        }
        // The vault-log engine's own records of the account, by its own call (held changes, memories, findings, verified
        // states). False: a store that cannot list its keys kept some; they go with "Forget this server".
        if (byIdToo) io.silencelen.andvari.core.client.log.StoredVaultLogs.forgetAccount(st, userId)
        // A prefix a host registered that this list does not name is treated as the account's: a record under it whose
        // second part is this user id is the account's own.
        val perOrigin = PinStore.originKeyed().filter { FORGOTTEN_PER_ORIGIN[it] != false }
        val listed = runCatching { st.keys() }.getOrNull()
        if (listed != null) {
            for (k in listed) {
                val byId = byIdToo && FORGOTTEN_KEYED.any { p -> k == p + userId || k.startsWith("$p$userId|") }
                if (byId || perOrigin.any { p -> at.any { o -> k == "$p$o|$userId" || k.startsWith("$p$o|$userId|") } }) st.set(k, null)
            }
        } else {
            // A store that cannot list its keys: the records whose names are known in full.
            if (byIdToo) for (k in listOf("ovh.acct|$userId|sealed", "ovh.acct|$userId|hw", "ovh.acct|$userId|cas", "ovh.acct|$userId|seen",
                    "ovh.acct|$userId|checkpoint", "ovh.rmirror|$userId", "ovh.escrowfp|$userId", "ovh.items|$userId|lost")) st.set(k, null)
            for (p in perOrigin) for (o in at) st.set("$p$o|$userId", null)
        }
        // A copy the keeper removed was noted as the person's own end: settled now.
        settleOwnEnds()
    }

    /** After a forgetting, by "origin|address": the address as typed, for the one notice at the next take there. */
    private val remembering = RememberedMarks()

    /**
     * The marks of [remembering], kept at rest ([REMEMBERED_PREFIX]`<origin>|<address>`, the address as typed) with the
     * server's records: they go with the server's forgetting and with a deletion of the account under that address, and
     * are carried when the server's address moves. A mark stays until the person dismisses its notice.
     */
    private inner class RememberedMarks {
        operator fun set(originAndAddress: String, email: String) {
            runCatching { engine.state.set(REMEMBERED_PREFIX + originAndAddress, email) }
        }

        operator fun get(originAndAddress: String): String? = runCatching { engine.state.get(REMEMBERED_PREFIX + originAndAddress) }.getOrNull()

        fun remove(originAndAddress: String) {
            runCatching { engine.state.set(REMEMBERED_PREFIX + originAndAddress, null) }
        }
    }

    private var rememberedShown: io.silencelen.andvari.core.app.NewAccountRememberedNotice? = null

    /** The mark [rememberedShown] was raised from (`<origin>|<address>`). */
    private var rememberedFrom: String? = null

    /**
     * [io.silencelen.andvari.core.app.AppSnapshot.rememberedNewAccount]: raised once the keeper keeps a session under a
     * forgotten address, and raised again from its mark at rest (after a restart) while that session is kept, until the
     * person dismisses it.
     */
    private fun rememberedNotice(): io.silencelen.andvari.core.app.NewAccountRememberedNotice? {
        if (this::keeper.isInitialized) {
            val s = keeper.session
            val at = s?.let { "${it.origin}|${it.emailNorm}" }
            val email = at?.let { remembering[it] }
            if (at != null && email != null && (rememberedFrom != at || rememberedShown?.email != email)) {
                rememberedShown = io.silencelen.andvari.core.app.NewAccountRememberedNotice(email)
                rememberedFrom = at
            }
        }
        // A notice whose mark went (its server forgotten, its account deleted) goes with it.
        if (rememberedFrom?.let { remembering[it] } == null) {
            rememberedShown = null
            rememberedFrom = null
        }
        return rememberedShown
    }

    override fun dismissNewAccountRemembered(notice: io.silencelen.andvari.core.app.NewAccountRememberedNotice) {
        if (rememberedShown !== notice) return
        rememberedFrom?.let { remembering.remove(it) }
        rememberedShown = null
        rememberedFrom = null
        publish()
    }

    override fun dismissKitWiped(notice: io.silencelen.andvari.core.app.KitWipedNotice) {
        if (kitWiped !== notice) return
        kitWiped = null
        noticeMark = null
        keepKitMark()
        publish()
    }

    /**
     * The person removes the account held as the operator ([holdAsOperator]), after the app's confirmation that showed
     * [io.silencelen.andvari.core.app.HeldOperatorAccount.removeLine]: this device's copy of it goes (the cache file, the
     * kept records, the wrapped key), as at a sign-out, and nothing is sent. STALE for an [account] no longer on show.
     */
    internal fun removeHeldOperatorAccount(account: io.silencelen.andvari.core.app.HeldOperatorAccount): PlainResult {
        val kept = keeper.session?.takeIf { it.heldAsOperator } ?: return PlainResult.STALE
        if (heldAsOperator() !== account) return PlainResult.STALE
        if (!keeper.removeHeldOperator()) return PlainResult.STALE
        dropHeld(kept.origin, kept.userId, CopyDeletion.SIGNED_OUT)
        engine.state.set(HELD_UNSENT_KEY + kept.origin + "|" + kept.userId, null)
        settleOwnEnds()
        heldShown = null
        phase = AppPhase.ENTRY
        entryPart.reset(null)
        publish()
        entryPart.refreshPublicSignup()
        return PlainResult.DONE
    }

    /**
     * The server ended the session (a refused refresh, a revoked session, the bell's `revoked`; design §4.4, "A session
     * the server ends does not delete the device's copy"): the account stays on this device as signed out by the server
     * ([LockedScreen.signedOutByServer]). Its keys are wiped and the vault closes as at a lock; the copy stays, opens
     * read-only with the master password, and is adopted again when the person signs in to the same account here.
     */
    private fun sessionEnded(reason: SessionEndReason) {
        val keepKit = dropKitButCommitted()
        endAccountFlows()
        val kept = keeper.session
        if (kept != null && kept.endedByServer) {
            endVault(null)
            if (keepKit) {
                // The kit of a committed change stays on show; after it, the first screen offers the account its server
                // signed out ([AppSnapshot.keptSignedOut]).
                publish()
                return
            }
            entryPart.drop()
            phase = AppPhase.LOCKED
            publish()
            return
        }
        endVault(lastKept.takeIf { keeper.session == null }, CopyDeletion.forSessionEnd(reason))
        accountEmail = null
        phase = AppPhase.ENTRY
        entryPart.reset(if (reason == SessionEndReason.REFRESH_REFUSED) FirstRunNotice.SIGNED_OUT_BY_SERVER else null)
        publish()
    }

    /**
     * Signed out by the server, on its lock screen: the person signs in again. The journey opens at the first screen with
     * its notice; a sign-in to the same account at this server takes the copy back and sends what waited. Another
     * account is refused until this one is signed out (its copy is only deleted by the person: [signOut]).
     */
    override fun signInAgain(screen: LockedScreen) {
        val kept = keeper.session
        if (phase != AppPhase.LOCKED || snapshot.locked !== screen || kept?.endedByServer != true) return
        phase = AppPhase.ENTRY
        // A deletion whose outcome is unknown is said on the first screen too (l2b-20 item 1 b): the server's end of the
        // session is the likely sign that it landed, and only the next answer for the account settles it.
        val unknown = if (!accountSettingsPart.deletionOutcomeUnknown(kept.origin, kept.userId)) null else labelFor(kept.origin)?.let {
            io.silencelen.andvari.core.app.DeletionOutcomeUnknownNotice(accountEmail ?: kept.emailNorm, it)
        }
        // An end this device made because it could not confirm the session is said as itself, never as the server's.
        if (kept.endedUnconfirmed) entryPart.reset(null, unknown = unknown, notConfirmed = true)
        else entryPart.reset(FirstRunNotice.SIGNED_OUT_BY_SERVER, unknown = unknown)
        publish()
        entryPart.refreshPublicSignup()
    }

    /** The session's server was forgotten, or its account deleted: the session goes, and the journey starts again. */
    internal fun sessionGone(why: CopyDeletion = CopyDeletion.FORGOT_SERVER, deleted: io.silencelen.andvari.core.app.AccountDeletedNotice? = null) {
        dropKitButCommitted()
        endAccountFlows()
        endVault(lastKept.takeIf { keeper.session == null }, why)
        settleOwnEnds()
        accountEmail = null
        phase = AppPhase.ENTRY
        entryPart.reset(null, deleted)
        publish()
    }

    // ---- the instance ----

    /** The pinned card as [InstanceLabel]: its name and origin; self-named when only the server vouches for the name. */
    internal fun label(pin: CardPin): InstanceLabel = InstanceLabel(
        pin.name, pin.origin, kindOf(pin.kind), selfNamed = pin.root == PinRoot.TRUST_GATE || pin.root == PinRoot.ENROL,
    )

    internal fun labelFor(origin: String): InstanceLabel? = when (val s = trust.pinState(origin)) {
        is PinState.Pinned -> label(s.pin)
        is PinState.Forked -> label(s.pin)
        PinState.Damaged -> InstanceLabel("", origin, ServerKind.PRIVATE_SERVER, selfNamed = true)
        PinState.None -> null
    }

    internal fun sameLabel(a: InstanceLabel?, b: InstanceLabel): Boolean =
        a != null && a.name == b.name && a.origin == b.origin && a.kind == b.kind && a.selfNamed == b.selfNamed

    internal fun kindOf(kind: String): ServerKind = if (kind == "public") ServerKind.PUBLIC_SERVER else ServerKind.PRIVATE_SERVER

    /**
     * The operator key's short form, as the Trust Gate and the browser extension show it: the engine's own
     * ([CardTrust.operatorShortFp], over the key's X25519 image, design §4.1). Empty when the key has none.
     */
    internal fun operatorKeyShort(signKeyB64: String): String = trust.operatorShortFp(signKeyB64).orEmpty()

    /**
     * What a Trust Gate shows. "Switch to a different server?" when this device already uses another one: it holds a
     * session or a pin for another origin (§12.3 "when one is set"), which is a fact of its stores, not of where the
     * journey happens to be.
     */
    internal fun gatePrompt(gate: FirstPin.NeedsTrustGate, kitChanged: Boolean, typedKit: Boolean): TrustGatePrompt = TrustGatePrompt(
        wording = gate.wording,
        origin = gate.origin,
        name = gate.name,
        operatorKeyShort = gate.operatorShortFp,
        switching = keeper.session?.let { it.origin != gate.origin } == true || trust.gatePins().any { it.origin != gate.origin },
        punycodeCaution = gate.origin.contains("xn--"),
        httpCaution = gate.origin.startsWith("http://"),
        kitIdentityChanged = kitChanged,
        typedKit = typedKit,
        claimedKind = null,
    )

    // ---- the account ----

    /** [AccountSnapshot.sessionNotConfirmed]: the copy [open] is open after its session ended here, unconfirmed in time. */
    private fun copyNotConfirmed(open: io.silencelen.andvari.core.client.onboard.EstablishedSession): Boolean =
        keeper.session?.let { it.origin == open.origin && it.userId == open.userId && it.endedByServer && it.endedUnconfirmed } == true

    private fun accountSnapshot(): AccountSnapshot? {
        val open = keeper.established ?: return null
        val vaultRows = vaultsPart.rows()
        return AccountSnapshot(
            unfinishedMoves = vaultsPart.unfinishedMoves(vaultRows),
            movesStoredOutside = vaultsPart.movesStoredOutside(),
            moveNotes = vaultsPart.moveNotes(),
            waitingNotices = vaultsPart.waitingNotices(vaultRows),
            signInNotice = signInNotice,
            kitDueAtOpening = openedWithoutKit && keeper.session?.let { it.userId == open.userId && !it.recoveryConfirmed } == true,
            email = accountEmail ?: open.emailNorm,
            accountId = open.account.accountId(crypto),
            operatorAccount = open.role == "operator",
            serverStopped = serverStopped(open.origin),
            signedOutByServer = keeper.session?.let { it.origin == open.origin && it.userId == open.userId && it.endedByServer } == true,
            sessionNotConfirmed = copyNotConfirmed(open),
            endLine = if (copyNotConfirmed(open)) io.silencelen.andvari.core.app.CopyKey.SESSION_NOT_CONFIRMED_COPY_OPEN else null,
            prompts = listOfNotNull<io.silencelen.andvari.core.app.AccountPrompt>(linksPart.notMade, setupPrompt(open)) + recoveryPart.prompts() + vaultsPart.prompts() +
                contactsPart.prompts() + linksPart.keyChangePrompts(),
            vaults = vaultRows,
            contacts = contactsPart.screen(),
            comparing = contactsPart.compare(),
            links = linksPart.screen(),
            opened = linksPart.openedInvite(),
            members = vaultsPart.members(),
            shareWarning = vaultsPart.shareWarning(),
            moving = vaultsPart.moving(),
            devices = devicesPart.screen(),
            deviceLink = devicesPart.hostScreen(),
            recovery = recoveryPart.screen(),
            kit = kitPart.accountKit(),
            deletion = accountSettingsPart.deletionScreen(),
            quickUnlock = quickSetting(),
            policy = serverPolicy(open.origin),
            twoStep = twoStepPart.screen(),
            kitAfterMove = newKitPrompt(open.origin),
            contentRevision = vault?.takeIf { !it.closed }?.content?.state?.revision ?: 0L,
            inviteNotUsed = linksPart.inviteNotUsed(),
            liveUpdates = vault?.liveUpdates() ?: io.silencelen.andvari.core.app.LiveUpdates.NOT_RUNNING,
        )
    }

    internal companion object {
        const val FORMAT_KEY = "ovh.format"

        /** The old stores a wipe left behind, by name; absent before the first pass and once none is left. */
        const val FORMAT_LEFT_KEY = "ovh.format.left"

        /** Set once the person was told about the stores that are left. */
        const val FORMAT_TOLD_KEY = "ovh.format.told"

        /** The local format of the overhaul's builds (§12.4): a build that finds another marker wipes the old stores. */
        const val FORMAT = "2"

        /** Set per origin when the person followed a move there, until a kit is made there (§4.4, R36). */
        const val NEW_KIT_KEY = "ovh.newkit|"

        /** The account's chosen name, per origin and user id, kept from its registration on this device. */
        const val NAME_KEY = "ovh.name|"

        /** How many changes this device had not sent when its account was held as the operator, per `origin|userId`. */
        const val HELD_UNSENT_KEY = "ovh.heldop.unsent|"

        /**
         * The engine's records kept by user id (`<prefix><userId>` or `<prefix><userId>|…`) that a forgetting leaves to this
         * layer: the account's state copy and marks, its recovery mirror, its escrow mark, the item engine's. Its vault logs
         * go by the vault-log engine's own call (`StoredVaultLogs.forgetAccount`).
         */
        val FORGOTTEN_KEYED = listOf("ovh.acct|", "ovh.rmirror|", "ovh.escrowfp|", "ovh.items|")

        /**
         * How a forgetting treats each per-origin prefix the engine and this layer register ([PinStore.originKeyed]): true,
         * kept `<prefix><origin>|<userId>` or `<prefix><origin>|<userId>|…`, the account's own (deleted with it); false, kept
         * by the origin alone or by an address (`ovh.dev|<origin>|<address>`: the device's own row), which stays. Every
         * registered prefix is named here (`EngineForgetEarlierFixTest` fails for one that is not), so a kind added later
         * is decided, not left behind.
         */
        internal val FORGOTTEN_PER_ORIGIN: Map<String, Boolean> = mapOf(
            "ovh.links|" to true, "ovh.links.dropped|" to true, "ovh.codes|" to true, "ovh.current|" to true, "ovh.onetap|" to true,
            "ovh.bundlevaults|" to true, "ovh.notused|" to true, "ovh.quick.offer|" to true,
            "ovh.setup|" to false, "ovh.assist|" to false, "ovh.dev|" to false,
            NAME_KEY to true, EngineRecovery.MINE_KEY to true, EngineSharedVaults.MOVE_PREFIX to true, EngineAccountSettings.OUTCOME_UNKNOWN_KEY to true,
            KeptPolicies.KEY_PREFIX to false,
            // Kept by address (`<origin>|<address>`): the forgetting deletes the one of its own address by name.
            EngineKit.SHOWN_KEY to false,
            // The record of the earlier account's key that the forgetting itself keeps (the keeper's; it goes with the server).
            SessionKeeper.EARLIER_IDENTITY_PREFIX to false,
            // Kept by the origin alone: a server's forgetting takes them.
            KIT_ON_SHOW_PREFIX to false, KIT_NAMED_KEPT_PREFIX to false, KEPT_MARK_PREFIX to false,
            // The account's move notes not yet dismissed (`<origin>|<userId>`).
            EngineSharedVaults.NOTES_PREFIX to true,
            // Kept by address (`<origin>|<address>`), for the account taken after a forgetting: a forgetting leaves it.
            REMEMBERED_PREFIX to false,
        )

        /** `<prefix><origin>|<address>`: the notice that this device now remembers the account taken after a forgetting. */
        const val REMEMBERED_PREFIX = "ovh.app.remembered|"

        /**
         * The forgettings begun and not yet finished: a JSON list of `[origin, address, userId, tie, held origins…]`, the tie
         * ([TIE_MARK]) missing in a mark an earlier build wrote.
         */
        const val FORGETTING_KEY = "ovh.app.forgetting"

        /** The start of a forgetting mark's tie: `tie:yes` or `tie:no`, as read before anything was removed. */
        private const val TIE_MARK = "tie:"

        /**
         * Written before the marks named their server: read once at a start (as a mark of no known server, which any
         * server's forgetting takes) and never written again.
         */
        const val KIT_ON_SHOW_KEY = "ovh.kit.notkept.onshow"

        /** With [KIT_ON_SHOW_KEY], as written before the marks named their server. */
        const val KIT_NAMED_KEPT_KEY = "ovh.kit.notkept.namedkept"

        /** As written before the mark named its server; cleared at the start. */
        const val KEPT_MARK_KEY = "ovh.app.keptmark"

        /**
         * `<prefix><origin>`: that a kit of a committed change at that server is on show, or its notice not dismissed
         * (`recovery|address` or `registration|address`); nothing of the kit. A record of its server: "Forget this server"
         * and a confirmed deletion there take it.
         */
        const val KIT_ON_SHOW_PREFIX = "ovh.kit.notkept.onshow|"

        /** `<prefix><origin>`, with [KIT_ON_SHOW_PREFIX]: the mark of the kept session its reason named ([KitWipedNotice.namedKept]). */
        const val KIT_NAMED_KEPT_PREFIX = "ovh.kit.notkept.namedkept|"

        /**
         * `<prefix><origin>`: the kept session's [MasterPasswordPrompt.keptMark], as `<origin>|<userId>|<mark>`, an opaque
         * random mark per take. A record of its server, as [KIT_ON_SHOW_PREFIX].
         */
        const val KEPT_MARK_PREFIX = "ovh.app.keptmark|"

        /** The accounts whose cache file or kept records may be on this device, one `origin|userId` per line. */
        const val HELD_KEY = "ovh.content.held"

        /**
         * A line of [HELD_KEY] as (origin, user id); null for a line that is not `origin|userId` with an account's id. The
         * engine reads only the lines this reads, and the sweep reads none while one does not ([AccountSweep]).
         */
        internal fun heldLine(line: String): Pair<String, String>? {
            val i = line.lastIndexOf('|')
            if (i <= 0) return null
            val id = line.substring(i + 1)
            return if (io.silencelen.andvari.core.trust.TrustGrammar.isUuid(id)) line.substring(0, i) to id else null
        }

        /**
         * The entries of [FORGETTING_KEY]'s [text]: null where the text is not a JSON list; an entry null where it is not a
         * list of strings, at least three, whose third is an account's id. The forgettings read only the entries that read
         * (and the settling at a start rewrites the record without the others); the sweep reads none while one does not.
         */
        internal fun forgettingEntries(text: String): List<ForgettingMark?>? {
            val all = runCatching { io.silencelen.andvari.core.model.wire.WireJson.json.parseToJsonElement(text) }.getOrNull() as? kotlinx.serialization.json.JsonArray
                ?: return null
            return all.map entry@{ e ->
                val f = (e as? kotlinx.serialization.json.JsonArray)?.map { (it as? kotlinx.serialization.json.JsonPrimitive)?.takeIf { p -> p.isString }?.content ?: return@entry null }
                if (f == null || f.size < 3 || !io.silencelen.andvari.core.trust.TrustGrammar.isUuid(f[2])) null else {
                    val tie = f.getOrNull(3)?.takeIf { it.startsWith(TIE_MARK) }
                    ForgettingMark(f[0], f[1], f[2], f.drop(if (tie != null) 4 else 3),
                        when (tie) { TIE_MARK + "yes" -> true; TIE_MARK + "no" -> false; null -> null; else -> true })
                }
            }
        }
    }
}

/** [DesktopAppApi] over the engine. The operator views are bound in a later slice. */
class EngineDesktopAppApi(engine: AppEngine) : EngineAppApi(engine), io.silencelen.andvari.core.app.DesktopAppApi {
    override val operatorApi: io.silencelen.andvari.core.app.OperatorApi get() = operatorPart

    override val restores: io.silencelen.andvari.core.app.BackupRestoreApi = object : io.silencelen.andvari.core.app.BackupRestoreApi {
        override suspend fun open(passphrase: CharArray, bytes: ByteArray): io.silencelen.andvari.core.client.restore.RestoreOpening =
            try {
                val text = passphrase.concatToString()
                kotlinx.coroutines.withContext(engine.work) { io.silencelen.andvari.core.client.restore.BackupRestore.open(engine.crypto, text, bytes) }
            } finally {
                passphrase.fill('\u0000')
            }

        override suspend fun preview(file: io.silencelen.andvari.core.client.restore.RestoreFile) =
            restoreHost()?.let { io.silencelen.andvari.core.client.restore.BackupRestore(it).preview(file) }

        override suspend fun restore(
            file: io.silencelen.andvari.core.client.restore.RestoreFile,
            choice: io.silencelen.andvari.core.client.restore.RestoreChoice,
            events: (io.silencelen.andvari.core.client.restore.RestoreEvent) -> Unit,
        ) = restoreHost()?.let { io.silencelen.andvari.core.client.restore.BackupRestore(it).restore(file, choice, events) }

        override suspend fun restoreAgain(
            file: io.silencelen.andvari.core.client.restore.RestoreFile,
            vaults: Set<String>,
            events: (io.silencelen.andvari.core.client.restore.RestoreEvent) -> Unit,
        ) = restoreHost()?.let { io.silencelen.andvari.core.client.restore.BackupRestore(it).restore(file, vaults, events) }

        // As the record's place is chosen at each write (ContentStores.restoreRecords): a file only while the policy as last
        // read allows an offline copy and the platform keeps data at rest. Asked anew at each call.
        override fun recordInMemoryOnly(): Boolean? {
            val v = vault?.takeIf { !it.closed && phase == AppPhase.UNLOCKED && !it.items.halted && !it.wipeOwed } ?: return null
            return !stores.restoreRecordsAtRest(policies.get(v.origin)?.offlineCacheAllowed == true) || !engine.keepsAtRest()
        }

        // The account a sign-out would end (its check), and its restore records as this device holds them.
        override fun unfinishedRestore(): Boolean {
            val c = signOutCheck() ?: return false
            val texts = stores.restoreRecordTexts(c.origin, c.userId) ?: return true
            return texts.any(io.silencelen.andvari.core.client.restore.BackupRestore.Companion::unfinished)
        }
    }

    /**
     * The shared restore's host over the vault open now: its item and log engines, the session's account, and the
     * account's restore records among its kept records ([io.silencelen.andvari.core.app.content.ContentStores.restoreRecords]).
     * Null while no vault is open, and over a copy that is read-only (signed out by the server, an update required, a
     * policy's wipe owed): a restore writes.
     */
    private fun restoreHost(): io.silencelen.andvari.core.client.restore.RestoreHost? {
        val v = vault?.takeIf { !it.closed && phase == AppPhase.UNLOCKED && !it.items.halted && !it.wipeOwed } ?: return null
        val open = keeper.established?.takeIf { it.origin == v.origin && it.userId == v.userId } ?: return null
        // The policy as last read, asked at every write of the run: one that forbids a copy and arrives meanwhile sends the
        // record's next write to memory.
        val records = stores.restoreRecords(v.origin, v.userId) { policies.get(v.origin)?.offlineCacheAllowed == true }
        return object : io.silencelen.andvari.core.client.restore.RestoreHost {
            override val crypto get() = engine.crypto
            override val origin get() = v.origin
            override val userId get() = v.userId
            override val account get() = open.account
            override val items get() = v.items
            override val logs get() = v.logs
            override val records = records

            override suspend fun sync() {
                v.content.syncQuietly()
            }

            override fun now(): Long = engine.clock()
        }
    }
}

/** An [io.silencelen.andvari.core.client.pin.InstanceTrust] made after the keeper that needs it. */
/**
 * The device's trust, read when asked (the keeper is built before the trust it reads). It forwards EVERY member of
 * [io.silencelen.andvari.core.client.pin.InstanceTrust], the defaulted ones too: a default here would answer for the
 * device (`isBakedOrigin` false at the baked origin). `DelegatingTrustTest` fails when a member is not forwarded.
 */
internal class DelegatingTrust(private val get: () -> io.silencelen.andvari.core.client.pin.InstanceTrust) : io.silencelen.andvari.core.client.pin.InstanceTrust {
    override fun pinState(origin: String) = get().pinState(origin)
    override fun access(origin: String) = get().access(origin)
    override fun isBakedOrigin(origin: String) = get().isBakedOrigin(origin)
    override suspend fun setupVerdictAtBaked(origin: String) = get().setupVerdictAtBaked(origin)
    override fun pinFor(origin: String) = get().pinFor(origin)
    override fun pins() = get().pins()
    override fun gatePins() = get().gatePins()
    override suspend fun pinBaked(origin: String) = get().pinBaked(origin)
    override suspend fun pinFromKit(origin: String, card0Hash: String, kitEmailNorm: String) = get().pinFromKit(origin, card0Hash, kitEmailNorm)
    override suspend fun pinFromLinkOffer(origin: String, instanceId: String, cardHash: String) = get().pinFromLinkOffer(origin, instanceId, cardHash)
    override suspend fun beginTrustGate(origin: String, wording: TrustGateWording) = get().beginTrustGate(origin, wording)
    override suspend fun confirmTrustGate(ticket: io.silencelen.andvari.core.client.pin.TrustGateTicket) = get().confirmTrustGate(ticket)
    override suspend fun pinFromOwnCard0(origin: String, card0Frame: String, operatorUserId: String, operatorEmailNorm: String, ownSignPub: ByteArray) =
        get().pinFromOwnCard0(origin, card0Frame, operatorUserId, operatorEmailNorm, ownSignPub)
    override suspend fun refresh(origin: String) = get().refresh(origin)
    override suspend fun followMove(status: CardStatus.Moved) = get().followMove(status)
    override suspend fun acceptKindChange(status: CardStatus.KindChanged) = get().acceptKindChange(status)
    override fun forget(origin: String) = get().forget(origin)
    override fun dropPinMade(handle: io.silencelen.andvari.core.client.pin.PinHandle) = get().dropPinMade(handle)
}

/** The first enum value of [R] whose trouble is [t]: every intent result has one per [Trouble]. */
internal inline fun <reified R> troubleOf(t: Trouble): R where R : Enum<R>, R : IntentResult =
    enumValues<R>().first { it.trouble == t }
