package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.client.ApiException
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.Contact
import io.silencelen.andvari.core.client.ContactPin
import io.silencelen.andvari.core.client.IdentityQr
import io.silencelen.andvari.core.client.LegacyPinReverifyRequiredException
import io.silencelen.andvari.core.client.MemberIdentityMismatchException
import io.silencelen.andvari.core.client.MemberNotVerifiedException
import io.silencelen.andvari.core.client.OwnershipClaim
import io.silencelen.andvari.core.client.OwnershipNotConfirmedException
import io.silencelen.andvari.core.client.OwnershipTransferAckRequiredException
import io.silencelen.andvari.core.client.ReauthFailedException
import io.silencelen.andvari.core.client.ReauthStaleSessionException
import io.silencelen.andvari.core.client.VaultKeyNotVerifiedException
import io.silencelen.andvari.core.client.PendingInvitation
import io.silencelen.andvari.core.client.CardData
import io.silencelen.andvari.core.client.ClientPolicyClamps
import io.silencelen.andvari.core.client.Duplicates
import io.silencelen.andvari.core.client.Staleness
import io.silencelen.andvari.core.client.UsageLedger
import io.silencelen.andvari.core.client.VaultHealth
import io.silencelen.andvari.core.client.CoHolder
import io.silencelen.andvari.core.client.CsvImport
import io.silencelen.andvari.core.client.CardDisplay
import io.silencelen.andvari.core.client.DecryptedItemVersion
import io.silencelen.andvari.core.client.DeletedItemView
import io.silencelen.andvari.core.client.DeletedVaultInfo
import io.silencelen.andvari.core.client.HeldVaultCopy
import io.silencelen.andvari.core.client.ExportCsv
import io.silencelen.andvari.core.client.ExportPlanner
import io.silencelen.andvari.core.client.HouseholdCopy
import io.silencelen.andvari.core.client.LifecycleNoticeCopy
import io.silencelen.andvari.core.client.VaultInfo
import io.silencelen.andvari.core.client.ItemChangedVaultsException
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.KdfPolicyViolationException
import io.silencelen.andvari.core.client.KdfReKeyCore
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.AccountStateSync
import io.silencelen.andvari.core.client.NoPersonalVaultException
import io.silencelen.andvari.core.client.OriginCanon
import io.silencelen.andvari.core.client.OriginProbeFence
import io.silencelen.andvari.core.client.Strength
import io.silencelen.andvari.core.client.SaveOutcome
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.client.UpgradeRequiredException
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.autofill.CardNormalize
import io.silencelen.andvari.core.client.autofill.SavedUri
import io.silencelen.andvari.core.client.autofill.UriMatch
import io.silencelen.andvari.core.client.session.BoundedOps
import io.silencelen.andvari.core.client.session.recoveryLockout
import io.silencelen.andvari.core.client.session.requireCurrentPolicy
import io.silencelen.andvari.core.client.session.runBounded
import io.silencelen.andvari.core.client.session.BiometricHost
import io.silencelen.andvari.core.client.session.CaptureConfirm
import io.silencelen.andvari.core.client.session.CaptureSetup
import io.silencelen.andvari.core.client.session.Clocks
import io.silencelen.andvari.core.client.session.EnrollOutcome
import io.silencelen.andvari.core.client.session.EnrollRequest
import io.silencelen.andvari.core.client.session.FirstSync
import io.silencelen.andvari.core.client.session.HttpClients
import io.silencelen.andvari.core.client.session.InviteFieldParse
import io.silencelen.andvari.core.client.session.NamespaceStorage
import io.silencelen.andvari.core.client.session.OfflineArtifacts
import io.silencelen.andvari.core.client.session.PolicyCoordinator
import io.silencelen.andvari.core.client.session.PolicyProbe
import io.silencelen.andvari.core.client.session.QuickEnrollResult
import io.silencelen.andvari.core.client.session.QuickGate
import io.silencelen.andvari.core.client.session.QuickUnlockKeys
import io.silencelen.andvari.core.client.session.RecoveryCapture
import io.silencelen.andvari.core.client.session.ServerAddress
import io.silencelen.andvari.core.client.session.ServerSwitch
import io.silencelen.andvari.core.client.session.SessionBinder
import io.silencelen.andvari.core.client.session.SessionClients
import io.silencelen.andvari.core.client.session.SessionEntry
import io.silencelen.andvari.core.client.session.SessionPersistence
import io.silencelen.andvari.core.client.session.StoredSession
import io.silencelen.andvari.core.client.session.SignInResult
import io.silencelen.andvari.core.client.session.SwitchResult
import io.silencelen.andvari.core.client.session.UnlockLadder
import io.silencelen.andvari.core.client.session.UnlockOptions
import io.silencelen.andvari.core.client.session.UnlockResult
import io.silencelen.andvari.core.client.session.VaultSession
import io.silencelen.andvari.core.client.session.effectiveSignupMode
import io.silencelen.andvari.core.client.session.enrollOriginMoved
import io.silencelen.andvari.core.client.session.parseInviteField
import io.silencelen.andvari.core.client.session.sessionElsewhere
import io.silencelen.andvari.core.client.session.signInOriginMoved
import io.silencelen.andvari.core.crypto.Attachments
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Fingerprint
import io.silencelen.andvari.core.model.AccountDeleteBlocker
import io.silencelen.andvari.core.model.AccountDeletePreview
import io.silencelen.andvari.core.crypto.Hibp
import io.silencelen.andvari.core.crypto.GeneratorOptions
import io.silencelen.andvari.core.crypto.SharedGrant
import io.silencelen.andvari.core.crypto.MemberRecovery
import io.silencelen.andvari.core.crypto.PasswordGenerator
import io.silencelen.andvari.core.crypto.Totp
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.CryptoUnavailableException
import io.silencelen.andvari.core.model.RecoveryVerifyResponse
import io.silencelen.andvari.core.model.ClientPolicy
import io.silencelen.andvari.core.model.UserLookupResponse
import io.silencelen.andvari.core.model.VaultMemberSummary
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.datetime.toLocalDateTime
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.cancellation.CancellationException

/**
 * The session controller a native UI drives (design 2026-11-09, "Session layer"): it composes the shared
 * flows (server switch, unlock ladder, sign-in and enroll, recovery capture) and the vault reads and writes,
 * with the rules Android's view model follows: lock on leaving the foreground, the idle check on return, a
 * definitive rejection reported once, no default server, the offline cache allowed until a policy forbids it.
 *
 * The UI observes one immutable [AppState] and calls actions. No exported function throws, except a suspend
 * action's [CancellationException]: every other outcome is a result. Keys stay here; secrets leave only
 * through the explicit reads ([revealSecret], [oneTimeCode], [recoveryPhrase]).
 *
 * Threading: actions run on [uiContext] (the main thread on iOS), and so does everything that changes this
 * controller's state; the KDF and the other CPU-bound steps move off it inside the shared flows.
 *
 * @param uiContext where state is published and actions run.
 * @param biometricHost what the platform's biometric prompt needs, with the reason it shows.
 * @param tickMs the idle check's period while started; 0 runs no ticker (tests drive [tick]).
 * @param serverShare where the confirmed server is published for the app's own extensions.
 * @param fillSnapshots where the AutoFill extension's encrypted snapshot is kept; nothing is written by default.
 * @param saveQueue where the extensions queue captured logins for this app to import; none by default.
 * @param appliedSaveLog where the list of automatic saves is kept across a lock: app-private, never shared.
 * @param moveMemoLog where a move or copy that did not finish is kept across a lock, sealed to the account:
 *  app-private, never shared ([VaultMoves]).
 * @param pendingSaveLog where a save with new files is kept until it is done, sealed to the account ([PendingSave]).
 * @param pendingBlobs where that save's files are kept meanwhile, each encrypted under its own key: app-private.
 */
open class SessionController(
    private val store: SessionPersistence,
    private val namespaces: NamespaceStorage,
    http: HttpClients,
    private val quickKeys: QuickUnlockKeys,
    private val clocks: Clocks,
    cleartextExemptHosts: Set<String>,
    private val uiContext: CoroutineContext,
    private val biometricHost: (reason: String?) -> BiometricHost,
    private val tickMs: Long,
    private val serverShare: ServerShare = ServerShare {},
    private val fillSnapshots: FillSnapshotStore = FillSnapshotStore.None,
    private val saveQueue: SaveQueueStore = SaveQueueStore.None,
    private val appliedSaveLog: FillSnapshotStore = InMemoryFillSnapshots(),
    private val moveMemoLog: FillSnapshotStore = InMemoryFillSnapshots(),
    pendingSaveLog: FillSnapshotStore = InMemoryFillSnapshots(),
    pendingBlobs: BlobStore = InMemoryBlobs(),
) {
    private val scope = CoroutineScope(SupervisorJob() + uiContext)
    private val session = VaultSession(clocks)
    private val crypto by lazy { createCryptoProvider() }

    private val coordinator = PolicyCoordinator(
        store,
        object : OfflineArtifacts {
            override fun deleteVaultCache(originKey: String, userId: String) {
                namespaces.deleteVaultCache(originKey, userId)
                dropFillSnapshot() // the extension's copy of the same rows goes with the cache, on every purge
            }
            override fun wipeQuickUnlock(originKey: String, userId: String) = quickKeys.wipe(originKey, userId)
        },
        session,
        clocks,
        OriginProbeFence(),
    ) { scope.launch { checkIdleLock() } } // the rejection is recorded on the session; land it now
    private val clients = SessionClients(http, store, coordinator)
    private val serverSwitch = ServerSwitch(store, session, coordinator, clients, cleartextExemptHosts)
    private val binder = SessionBinder(store, session, coordinator, namespaces, clocks)
    private val ladder = UnlockLadder(store, session, coordinator, clients, binder, quickKeys, clocks)
    private val entry = SessionEntry(store, session, coordinator, clients, binder)
    private val capture = RecoveryCapture(session)

    private val stateFlow = MutableStateFlow(AppState.initial)

    /** The current snapshot. */
    val state: AppState get() = stateFlow.value

    private fun update(change: (AppState) -> AppState) = stateFlow.update(change)

    // Secrets between two steps, never in [AppState] (§F.7: never persisted, never logged, zeroed on every exit).
    private var pendingRecoverySecret: ByteArray? = null
    private var pendingRecoveryPieceId: String? = null

    /** §F.9: the login authKey, password-equivalent, held only while the capture gate is unresolved. */
    private var pendingCaptureAuthKey: String? = null

    /** The origin the Trust Gate is up for. */
    private var gateTarget: String? = null

    private var started = false
    private var ticker: Job? = null
    private var sinceSyncMs = 0L

    /** H08: a lock on leaving the foreground that waited for a running action, and when the app left. */
    private var backgroundLockPending = false
    private var backgroundAtMono = 0L

    /** The personal-vault question, as Android asks it ([PersonalVaultFlow]). */
    private val personal = PersonalVaultFlow(
        publish = { view -> update { it.copy(personalVault = view) } },
        changed = {
            // A personal vault is in force now: the list, the snapshot, and what only waited for one.
            update { it.copy(items = summaries(it.query)) }
            writeFillSnapshot()
            refreshSaveQueue()
        },
        isLive = { session.get() === it },
    )

    /** The extensions' save queue: what was captured, what was saved by itself, and its undo ([SaveImporter]). */
    private val saves = SaveImporter(
        saveQueue, appliedSaveLog, clocks, { crypto },
        publish = { pending, applied, unreadable ->
            update { it.copy(pendingSaves = pending, appliedSaves = applied, notice = if (unreadable) SAVES_UNREADABLE else it.notice) }
        },
        wrote = {
            update { it.copy(items = summaries(it.query)) }
            writeFillSnapshot()
        },
        dropped = { droppedEarlier(it) },
    )

    /** Saves with new files, kept until they are done: on disk while the origin's policy allows an offline cache, else in memory. */
    private val pendingSaves = PendingSaves(pendingSaveLog, pendingBlobs) {
        store.baseUrl?.let { coordinator.cacheAllowed(OriginCanon.originKey(it)) } == true
    }

    /** The policy probe a landing started ([refreshPolicyIfStale]), while it runs. */
    private var policyRefresh: Job? = null

    /** Call [listener] with the current state, then with every change, on the UI context, until the subscription is closed. */
    fun observe(listener: (AppState) -> Unit): Subscription {
        val job = scope.launch { stateFlow.collect { listener(it) } }
        return object : Subscription {
            override fun close() {
                job.cancel()
            }
        }
    }

    // ---- lifecycle ----

    /** Read the stored session, probe the server, and run the idle check while in the foreground. Call once. */
    fun start() {
        scope.launch { startAndLand() }
    }

    /** [start]'s work, awaited (tests). */
    internal suspend fun startAndLand() {
        if (started) return
        started = true
        store.baseUrl?.let { session.setAutoLockSeconds(store.origin(OriginCanon.originKey(it)).autoLockSeconds) }
        if (tickMs > 0) {
            ticker = scope.launch {
                while (true) {
                    delay(tickMs)
                    tick()
                }
            }
        }
        landOnStoredState(probe = true)
    }

    /** One idle check, and the 5-minute quiet sync while unlocked (spec 03 §6). The ticker calls it every [tickMs]. */
    internal fun tick() {
        if (state.screen == AppScreen.RECOVER && state.recoverVerified && !state.busy && clocks.monotonicMs() - recoverVerifiedAtMono >= RecoverCopy.IDLE_MS) recoverTimedOut()
        checkBackgroundGrace()
        expireTwoStepKey()
        checkIdleLock()
        if (tickMs > 0) {
            sinceSyncMs += tickMs
            if (sinceSyncMs >= SYNC_EVERY_MS) backgroundSync()
        }
    }

    /** The app came to the foreground: the idle check first, then a quiet sync. */
    fun onForeground() {
        // A lock that waited for running work lands now if its time ran out while the app was away (round-9 review 6:
        // a suspended app runs no ticker); otherwise the person is back, and it is void.
        checkBackgroundGrace()
        backgroundLockPending = false
        checkIdleLock()
        backgroundSync()
        refreshPolicyIfStale()
        refreshSaveQueue() // a login captured while the app was open in the background
    }

    /**
     * The app left the foreground: the vault locks (a suspended app cannot run the idle timer). True when the lock waits
     * for running work, an upload most of all (H08; owner decision 2026-11-12): it lands when the work ends, or
     * [AttachmentRules.BACKGROUND_GRACE_MS] after the app left, whichever is first. The host keeps the app running
     * meanwhile (on iOS a background task) and calls [backgroundTimeEnded] if the system's time runs out first. The
     * screen is covered at once.
     */
    fun onBackground(): Boolean {
        // Recovery does not survive a trip to the background, at either step: the second holds the raw recovery secret,
        // the first a typed phrase (and maybe a verify in flight, which the fence then stops).
        if (state.screen == AppScreen.RECOVER) recoverTimedOut()
        if (session.get() == null) return false
        // H08: never close the engine under a running action; the lock lands when it ends.
        if (state.busy || state.upload != null) {
            if (!backgroundLockPending) backgroundAtMono = clocks.monotonicMs()
            backgroundLockPending = true
            return true
        }
        lock(REASON_BACKGROUND)
        return false
    }

    /** The time the system gave the app in the background ran out: a lock that waited for running work lands now. */
    fun backgroundTimeEnded() {
        if (!backgroundLockPending) return
        backgroundLockPending = false
        if (session.get() != null) lock(REASON_BACKGROUND)
    }

    /** A lock that waited for running work lands once the app has been away its grace, the work done or not. */
    private fun checkBackgroundGrace() {
        if (backgroundLockPending && clocks.monotonicMs() - backgroundAtMono !in 0 until AttachmentRules.BACKGROUND_GRACE_MS) backgroundTimeEnded()
    }

    /** The person interacted with the app: the idle window starts again. */
    fun userActivity() = session.touch()

    /** Stop this controller: its work is cancelled and the vault locks. */
    fun close() {
        scope.cancel()
        session.lock()
        zeroSecrets()
    }

    // ---- server ----

    /** What [input] typed into the server field means; a real change raises the Trust Gate. */
    fun chooseServer(input: String): ServerChoice = guarded({ ServerChoice.Invalid(HouseholdCopy.forError(it)) }) {
        when (val a = serverSwitch.prepare(input)) {
            ServerAddress.Invalid -> ServerChoice.Invalid(INVALID_SERVER)
            is ServerAddress.Current -> {
                serverSwitch.moveTo(a.origin) // a re-spelling of the same server: the session stays
                publishServer()
                update { it.copy(server = store.baseUrl, screen = landingScreen(), trustGate = null) }
                ServerChoice.Applied(a.origin)
            }
            is ServerAddress.NeedsGate -> {
                gateTarget = a.origin
                val view = TrustGateView(a.origin, a.render.punycodeCaution, a.render.httpCaution, a.render.cleartextBlocked)
                update { it.copy(screen = AppScreen.TRUST_GATE, trustGate = view, error = null) }
                ServerChoice.NeedsGate(view)
            }
        }
    }

    /** The Trust Gate's Connect: the server is probed first, and nothing changes unless it answers. */
    @Throws(CancellationException::class)
    suspend fun confirmTrustGate(): ActionResult = action {
        val target = gateTarget ?: return@action ActionResult.NotDone(null)
        if (state.trustGate?.cleartextBlocked == true) return@action ActionResult.Failed(CLEARTEXT_BLOCKED)
        busy()
        when (val r = serverSwitch.connect(target)) {
            is SwitchResult.Switched -> {
                gateTarget = null
                if (r.droppedSession) {
                    forgetSessionViews()
                    zeroSecrets() // the old server's session and its in-flight secrets end here
                    dropFillSnapshot()
                }
                update { cleared(it, null).copy(trustGate = null, server = store.baseUrl, policy = null, serverUnreachable = false) }
                landOnStoredState(probe = true)
                ActionResult.Ok
            }
            is SwitchResult.Unreachable -> {
                idle()
                ActionResult.Failed(HouseholdCopy.forError(r.cause))
            }
        }
    }

    /** The Trust Gate's Cancel: nothing changes. */
    fun cancelTrustGate() {
        gateTarget = null
        update { it.copy(trustGate = null, screen = landingScreen()) }
    }

    /** Signed out: open the server field to choose another server. */
    fun changeServer() {
        if (session.get() != null) return // only a signed-out or locked app changes server
        update { it.copy(screen = AppScreen.CHOOSE_SERVER, error = null) }
    }

    /** Back out of the server field without choosing: the screen the stored state says. Nothing where no server is chosen yet. */
    fun cancelChangeServer() {
        if (state.screen != AppScreen.CHOOSE_SERVER || store.baseUrl == null) return
        update { it.copy(screen = landingScreen(), error = null) }
    }

    // ---- identity ----

    /**
     * This account's identity code, for someone else to check against what their screen shows for this person: the
     * short form (32 hex, grouped by the UI) and the full fingerprint. Derived from the key this device holds, never a
     * server value. Null while locked.
     */
    fun identityCode(): String? = guarded({ null }) { session.get()?.account?.identityFingerprintShort() }

    fun identityCodeFull(): String? = guarded({ null }) { session.get()?.account?.identityFingerprintFull() }

    // ---- forgot the master password (spec 04 member recovery; Android's Recover wizard) ----

    /** §F.7: the parsed recovery secret and the server's verify answer, held only between the two steps. */
    private var recoverSecret: ByteArray? = null
    private var recoverVerify: RecoveryVerifyResponse? = null
    private var recoverEmail: String? = null

    /** Bumped whenever the wizard is opened or left: a step that finishes for an earlier one owns nothing. */
    private var recoverEpoch = 0
    private var recoverVerifiedAtMono = 0L

    private fun zeroRecover() {
        recoverSecret?.fill(0)
        recoverSecret = null
        recoverVerify = null
        recoverEmail = null
        recoverEpoch++
    }

    /** Open the wizard from the sign-in or the unlock screen. A fresh entry never inherits an earlier attempt's material. */
    fun openRecover() {
        if (state.busy || session.get() != null) return
        if (state.screen != AppScreen.WELCOME && state.screen != AppScreen.UNLOCK) return
        zeroRecover()
        update { it.copy(screen = AppScreen.RECOVER, recoverVerified = false, error = null, notice = null) }
    }

    /** Leave the wizard (either step): the held material is zeroed, and a step still in flight lands nowhere. */
    fun cancelRecover() {
        if (state.screen != AppScreen.RECOVER) return
        zeroRecover()
        update { it.copy(screen = landingScreen(), recoverVerified = false, error = null, busy = false) }
    }

    /** The new-password step sat idle, or the app left the foreground, while the raw recovery secret was held. */
    private fun recoverTimedOut() {
        zeroRecover()
        update { it.copy(screen = landingScreen(), recoverVerified = false, error = null, busy = false, notice = RecoverCopy.TIMEOUT) }
    }

    /**
     * Step 1: the email and the recovery phrase. The phrase never leaves the device: a key derived from it proves
     * possession, and the server's answer is uniform whichever of the two was wrong.
     */
    @Throws(CancellationException::class)
    suspend fun recoverVerify(email: String, phrase: String): ActionResult = action {
        if (state.screen != AppScreen.RECOVER) return@action ActionResult.NotDone(null)
        recoveryLockout(store.pendingServer)?.let { return@action ActionResult.Failed(it) }
        val origin = store.baseUrl ?: return@action ActionResult.NotDone(null)
        val secret = MemberRecovery.parseSecret(phrase) ?: return@action ActionResult.Failed(RecoverCopy.NOT_A_PHRASE)
        busy()
        val mine = recoverEpoch
        val api = clients.probe(origin)
        try {
            val authKey = withContext(Dispatchers.Default) { MemberRecovery.deriveAuthKey(crypto, secret) }
            // §F.7 cancel fence, after every await: once this wizard is gone, the step zeroes what it holds and stops.
            if (recoverEpoch != mine) {
                secret.fill(0)
                return@action ActionResult.NotDone(null)
            }
            val answer = runBounded(BoundedOps.RECOVERY_CALL_MS) { api.recoverySelfVerify(email.trim(), authKey) }
            if (recoverEpoch != mine) {
                secret.fill(0)
                return@action ActionResult.NotDone(null)
            }
            recoverSecret?.fill(0) // an earlier attempt's bytes die before the fresh stash
            recoverSecret = secret
            recoverVerify = answer
            recoverEmail = email.trim()
            recoverVerifiedAtMono = clocks.monotonicMs()
            update { it.copy(busy = false, recoverVerified = true, error = null) }
            ActionResult.Ok
        } catch (t: Throwable) {
            secret.fill(0) // a refused phrase's bytes don't linger
            if (t is CancellationException) throw t
            if (recoverEpoch != mine) return@action ActionResult.NotDone(null)
            idleFailed(recoverVerifyError(t))
        } finally {
            api.close()
        }
    }

    /**
     * Step 2: the new master password. The same UVK is opened from the phrase, the account's identity key is checked
     * against it before anything is sent (a substituted key stops here), and the reset is committed under the server
     * policy's KDF parameters. Success ends every session of the account, this device's included.
     */
    @Throws(CancellationException::class)
    suspend fun recoverCommit(newPassword: String): ActionResult = action {
        if (state.screen != AppScreen.RECOVER) return@action ActionResult.NotDone(null)
        recoveryLockout(store.pendingServer)?.let { return@action ActionResult.Failed(it) }
        val secret = recoverSecret
        val verify = recoverVerify
        val origin = store.baseUrl
        if (secret == null || verify == null || origin == null) {
            update { it.copy(recoverVerified = false) }
            return@action ActionResult.Failed(RecoverCopy.EXPIRED)
        }
        // The one irreversible outcome of this screen is a weak master password: checked here, whatever the UI did.
        if (!Strength.meetsMasterPasswordFloor(newPassword)) return@action ActionResult.Failed(RecoverCopy.WEAK_PASSWORD)
        busy()
        val mine = recoverEpoch
        val originKey = OriginCanon.originKey(origin)
        val tag = coordinator.tag(originKey) // A12: tagged before any await
        val recoveredEmail = recoverEmail // captured before any await: a commit that lands revokes this account's sessions
        val api = clients.probe(origin)
        try {
            // The KDF parameters are the server's fenced policy, never a guess; fetched now if this visit has none.
            val policy = coordinator.livePolicy ?: coordinator.boundedPolicy(api).let { requireCurrentPolicy(it, coordinator.applyPolicy(it, tag)) }
            if (recoverEpoch != mine) return@action ActionResult.NotDone(null)
            val commit = withContext(Dispatchers.Default) { Account.recover(secret, verify, newPassword, policy.kdfParams) }
            // Cancelled during the derivation (the secret may have been zeroed mid-read): never post it.
            if (recoverEpoch != mine) return@action ActionResult.NotDone(null)
            runBounded(BoundedOps.RECOVERY_CALL_MS) { api.recoverySelfCommit(commit) }
            // Past the point of no return: every session of the recovered account is revoked, this device's too.
            val cancelled = recoverEpoch != mine
            if (!cancelled) zeroRecover()
            val stored = store.load()
            if (stored != null && recoveredEmail != null && stored.email.equals(recoveredEmail, ignoreCase = true)) {
                coordinator.purgeRevoked(originKey, stored.userId)
                dropFillSnapshot() // the extensions' copy goes with the session
            }
            if (cancelled) {
                // The wizard was left (the app went to the background) while the reset was on its way, and it landed:
                // say that, not that it timed out. A wizard opened again since keeps its screen.
                update {
                    it.copy(
                        busy = false, screen = if (it.screen == AppScreen.RECOVER) it.screen else landingScreen(), lockReason = null,
                        accountEmail = store.load()?.email, mustChangePassword = store.mustChangePassword, notice = RecoverCopy.DONE,
                    )
                }
                refreshQuick()
                return@action ActionResult.NotDone(null)
            }
            update {
                it.copy(
                    busy = false, screen = landingScreen(), recoverVerified = false, lockReason = null, accountEmail = store.load()?.email,
                    mustChangePassword = store.mustChangePassword, notice = RecoverCopy.DONE,
                )
            }
            refreshQuick()
            ActionResult.Ok
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            // The held material survives a failed commit: a transient failure retries without the first step.
            if (recoverEpoch != mine) return@action ActionResult.NotDone(null)
            idleFailed(recoverResetError(t))
        } finally {
            api.close()
        }
    }

    private fun recoverVerifyError(t: Throwable): String = when {
        t is CryptoUnavailableException -> HouseholdCopy.CRYPTO_UNAVAILABLE
        t is KdfPolicyViolationException -> HouseholdCopy.WEAK_KDF_ACTION
        t is ApiException -> when {
            t.status == 401 -> "We couldn't verify that email and recovery phrase."
            t.code == "recovery_public_disabled" -> "Account recovery isn't available from this public address — connect from inside (VPN/LAN) and try again."
            else -> HouseholdCopy.SERVER_PROBLEM
        }
        t is kotlinx.io.IOException -> HouseholdCopy.UNREACHABLE
        else -> "Recovery failed. Please try again."
    }

    private fun recoverResetError(t: Throwable): String = when {
        t is CryptoUnavailableException -> HouseholdCopy.CRYPTO_UNAVAILABLE
        t is KdfPolicyViolationException -> HouseholdCopy.WEAK_KDF_ACTION
        t is CryptoException && t.message?.contains("identity key mismatch") == true -> HouseholdCopy.IDENTITY_MISMATCH
        t is ApiException -> when {
            t.code == "invalid_ticket" || t.status == 401 -> RecoverCopy.EXPIRED
            t.code == "recovery_account_not_active" -> "This account is disabled — self-recovery isn't available. Ask your admin to recover it."
            else -> HouseholdCopy.SERVER_PROBLEM
        }
        t is kotlinx.io.IOException -> HouseholdCopy.UNREACHABLE
        else -> "Recovery failed. Please try again."
    }

    /** Probe the server's policy again (after [AppState.serverUnreachable]). */
    @Throws(CancellationException::class)
    suspend fun retryServer(): ActionResult = action {
        busy()
        probePolicy()
        idle()
        if (state.serverUnreachable) ActionResult.Failed(HouseholdCopy.forError(kotlinx.io.IOException("unreachable"))) else ActionResult.Ok
    }

    // ---- sign-in and enroll ----

    /** Sign in at [AppState.server]. [totp] is the authenticator's code, after [ActionResult.NeedsCode]. */
    @Throws(CancellationException::class)
    suspend fun signIn(email: String, password: String, totp: String?): ActionResult = action {
        busy()
        when (val r = entry.signIn(email.trim(), password, totp?.trim()?.ifEmpty { null }, firstSync = { syncNow(it) })) {
            is SignInResult.SignedIn -> {
                update { it.copy(totpRequired = false, mustChangePassword = r.mustChangePassword, accountEmail = email.trim()) }
                val proof = r.captureProof
                // F61: the KDF re-key, never under a pending capture gate (it would strand the gate's reauth proof).
                if (proof == null) reKey(r.unlocked, password, r.keys)
                if (proof != null) startRecoveryCapture(proof) else toVault()
                showFirstSync(r.firstSync)
                ActionResult.Ok
            }
            is SignInResult.TotpRequired -> {
                update { it.copy(busy = false, totpRequired = true) }
                ActionResult.NeedsCode(r.codeWasWrong)
            }
            is SignInResult.PendingSwitch -> idleFailed(SWITCH_PENDING)
            is SignInResult.OriginMoved -> idleFailed(signInOriginMoved(r.origin))
            SignInResult.EndedBeforeLanding -> sessionEndedBeforeLanding()
            is SignInResult.Failed -> failure(r.cause) { HouseholdCopy.forSignInError(it, totpTried = totp != null) }
        }
    }

    /** Enroll at [AppState.server] with an invite; lands on the shown-once recovery phrase. */
    @Throws(CancellationException::class)
    suspend fun enroll(form: EnrollForm): ActionResult = action {
        val origin = store.baseUrl ?: return@action ActionResult.Failed(CHOOSE_SERVER_FIRST)
        // An enroll link for another server goes through the manual Trust Gate first (v1 has no invite-driven switch).
        val parsed = parseInviteField(form.invite, origin)
        if (parsed is InviteFieldParse.Link && parsed.gate) return@action ActionResult.OtherServer(parsed.origin)
        val email = form.email.trim().ifEmpty { (parsed as? InviteFieldParse.Link)?.email.orEmpty() }
        val waived = !form.hasRecoverySheet
        busy()
        val request = EnrollRequest(parsed.token, email, form.name.trim(), form.password, waived, form.sheetCode.trim(), coordinator.livePolicy)
        when (val r = entry.enroll(request, firstSync = { syncNow(it) })) {
            is EnrollOutcome.Enrolled -> {
                pendingRecoverySecret = r.recoverySecret
                pendingRecoveryPieceId = r.pieceId
                update {
                    it.copy(
                        screen = AppScreen.RECOVERY_REVEAL, recoveryWaived = waived, busy = false, error = null,
                        mustChangePassword = r.mustChangePassword, accountEmail = email, lockReason = null,
                    )
                }
                showFirstSync(r.firstSync)
                ActionResult.Ok
            }
            EnrollOutcome.WeakPassword -> idleFailed(WEAK_MASTER_PASSWORD)
            EnrollOutcome.AnchorMismatch -> idleFailed(SHEET_MISMATCH)
            is EnrollOutcome.OriginMoved -> idleFailed(enrollOriginMoved(r.origin))
            EnrollOutcome.EndedBeforeLanding -> sessionEndedBeforeLanding()
            is EnrollOutcome.Failed -> failure(r.cause, HouseholdCopy::forEnrollError)
        }
    }

    // ---- the recovery phrase ----

    /** RECOVERY_REVEAL: the phrase to show, grouped for reading; null on any other screen. */
    fun recoveryPhrase(): String? =
        if (state.screen == AppScreen.RECOVERY_REVEAL) pendingRecoverySecret?.let { runCatching { MemberRecovery.displayForm(it) }.getOrNull() } else null

    /** RECOVERY_REVEAL: the phrase typed back. A match confirms it and opens the vault; a mismatch is [ActionResult.Mismatch]. */
    @Throws(CancellationException::class)
    suspend fun confirmRecoveryPhrase(typedBack: String): ActionResult = action {
        val secret = pendingRecoverySecret ?: return@action ActionResult.NotDone(null)
        if (!MemberRecovery.confirmMatches(secret, typedBack)) return@action ActionResult.Mismatch
        if (pendingCaptureAuthKey != null) {
            // §F.9 capture-gate path: the piece-bound confirm is awaited, so the vault never opens on a phrase the
            // server no longer holds.
            val live = session.get() ?: return@action ActionResult.NotDone(null)
            busy()
            when (capture.confirm(live, pendingRecoveryPieceId)) {
                CaptureConfirm.SessionEnded -> {
                    idle()
                    ActionResult.NotDone(null)
                }
                CaptureConfirm.Stale -> {
                    // The phrase just typed is dead (another device's setup replaced it): a fresh one follows.
                    zeroPendingRecovery()
                    update { it.copy(busy = false, screen = AppScreen.RECOVERY_CAPTURE, recoveryReplacedNotice = true) }
                    runRecoveryCapture()
                    ActionResult.NotDone(RECOVERY_PHRASE_REPLACED)
                }
                CaptureConfirm.Confirmed, CaptureConfirm.Failed -> {
                    zeroPendingRecovery()
                    pendingCaptureAuthKey = null // the gate is resolved: the reauth proof dies here
                    toVault()
                    ActionResult.Ok
                }
            }
        } else {
            // Enroll path: the confirm tells the server this phrase was saved; the vault opens without waiting on it.
            val api = session.get()?.api
            val pieceId = pendingRecoveryPieceId
            zeroPendingRecovery()
            toVault()
            if (api != null) {
                scope.launch {
                    if (capture.confirmEnrolled(api, pieceId) == CaptureConfirm.Stale) update { it.copy(notice = RECOVERY_PHRASE_REPLACED) }
                }
            }
            ActionResult.Ok
        }
    }

    /** RECOVERY_CAPTURE: commit a fresh recovery piece again, after [AppState.recoveryCaptureError]. */
    @Throws(CancellationException::class)
    suspend fun retryRecoveryCapture(): ActionResult = action {
        if (state.screen != AppScreen.RECOVERY_CAPTURE || state.busy) return@action ActionResult.NotDone(null)
        runRecoveryCaptureNow()
    }

    // ---- unlock ----

    /** UNLOCK with the master password. */
    @Throws(CancellationException::class)
    suspend fun unlock(password: String): ActionResult = action {
        val stored = store.load() ?: return@action noSession()
        busy()
        when (val r = ladder.unlockWithPassword(stored, password, UnlockOptions(firstSync = { syncNow(it) }))) {
            is UnlockResult.Unlocked -> {
                update { it.copy(mustChangePassword = store.mustChangePassword) }
                // §F.9: only FRESH keys gate; an offline unlock skips it and the next online one re-gates.
                val gate = r.online && r.keys.recoveryConfirmed != true
                if (r.online && !gate) reKey(r.unlocked, password, r.keys)
                if (gate) {
                    // The gate's proof through the one fenced in-session derivation (A9 M-1), off the UI thread.
                    val authKey = withContext(Dispatchers.Default) { r.unlocked.account.reauthAuthKey(password, r.keys) }
                    startRecoveryCapture(authKey)
                } else {
                    toVault()
                }
                showFirstSync(r.firstSync)
                ActionResult.Ok
            }
            else -> unlockOutcome(r, HouseholdCopy::forUnlockError)
        }
    }

    /** UNLOCK with Face ID or Touch ID; [reason] is what the prompt says (null: a default). */
    @Throws(CancellationException::class)
    suspend fun unlockWithBiometrics(reason: String?): ActionResult = action {
        val stored = store.load() ?: return@action noSession()
        busy()
        val options = UnlockOptions(firstSync = { syncNow(it) })
        when (val r = ladder.unlockWithQuick(stored, biometricHost(reason ?: UNLOCK_PROMPT), options)) {
            is UnlockResult.Unlocked -> {
                update { it.copy(mustChangePassword = store.mustChangePassword) }
                toVault()
                showFirstSync(r.firstSync)
                ActionResult.Ok
            }
            is UnlockResult.QuickUnavailable -> {
                idle()
                refreshQuick()
                ActionResult.NotDone(null)
            }
            is UnlockResult.QuickFallback -> {
                idle()
                ActionResult.NotDone(r.reason)
            }
            is UnlockResult.QuickWiped -> {
                idle()
                refreshQuick()
                ActionResult.NotDone(r.reason)
            }
            else -> unlockOutcome(r, HouseholdCopy::forError)
        }
    }

    /** Turn quick unlock on for this account on this device; the biometric prompt confirms it. */
    @Throws(CancellationException::class)
    suspend fun enableQuickUnlock(reason: String?): ActionResult = action {
        busy()
        val r = ladder.enableQuick(biometricHost(reason ?: ENABLE_PROMPT))
        idle()
        refreshQuick()
        when (r) {
            QuickEnrollResult.Enabled -> ActionResult.Ok
            QuickEnrollResult.Cancelled -> ActionResult.NotDone(null)
            QuickEnrollResult.NoSession -> ActionResult.NotDone(null)
            QuickEnrollResult.MustChangePassword -> ActionResult.Failed(CHANGE_PASSWORD_FIRST)
            QuickEnrollResult.NeedsPasswordUnlock -> ActionResult.Failed(UNLOCK_WITH_PASSWORD_FIRST)
            is QuickEnrollResult.Unavailable -> ActionResult.Failed(runCatching { quickReason(r.gate) }.getOrNull() ?: QUICK_UNAVAILABLE)
            is QuickEnrollResult.Failed -> ActionResult.Failed(r.reason ?: QUICK_NOT_ENABLED)
        }
    }

    /** Turn quick unlock off: the wrapped key and its hardware key are destroyed. Never gated. */
    fun disableQuickUnlock() {
        val userId = store.load()?.userId ?: session.get()?.account?.userId ?: return
        val originKey = store.baseUrl?.let(OriginCanon::originKey) ?: return
        quickKeys.wipe(originKey, userId)
        refreshQuick()
    }

    // ---- the vault ----

    /** Filter the vault list ([AppState.items]) by [query]. */
    fun setQuery(query: String) {
        update { it.copy(query = query, items = summaries(query)) }
    }

    /** An item's detail, without its secrets; null if the vault is locked or the item is gone. */
    fun itemDetail(itemId: String): ItemDetail? = guarded({ null }) {
        val live = session.get() ?: return@guarded null
        val item = live.engine.item(itemId) ?: return@guarded null
        val doc = item.doc
        val role = live.account.roleFor(item.vaultId)
        ItemDetail(
            itemId = item.itemId, vaultId = item.vaultId, type = doc.type, name = doc.name,
            username = doc.login?.username?.ifEmpty { null }, uris = doc.login?.uris.orEmpty(),
            hasPassword = !doc.login?.password.isNullOrEmpty(), hasNotes = !doc.notes.isNullOrEmpty(),
            hasTotp = !doc.login?.totp.isNullOrEmpty(), favorite = doc.favorite, updatedAt = item.updatedAt,
            editable = doc.type in EDITABLE_TYPES && role != "reader" && live.account.canSealUnder(item.vaultId),
            previousPasswords = doc.login?.passwordHistory?.size ?: 0,
            card = doc.card?.takeIf { doc.type == "card" }?.let { c ->
                CardDetail(
                    summary = CardDisplay.subtitle(doc), cardholder = c.cardholderName?.ifEmpty { null },
                    expiry = listOfNotNull(c.expMonth?.ifEmpty { null }, c.expYear?.ifEmpty { null }).joinToString("/").ifEmpty { null },
                    postalCode = c.postalCode?.ifEmpty { null }, hasNumber = !c.number.isNullOrEmpty(), hasCode = !c.securityCode.isNullOrEmpty(),
                    expMonth = c.expMonth?.ifEmpty { null }, expYear = c.expYear?.ifEmpty { null },
                )
            },
            attachments = doc.attachments.map(::attachmentView),
        )
    }

    /** One secret field of an item, for an explicit reveal or copy; null if locked, gone or empty. */
    fun revealSecret(itemId: String, field: SecretField): String? = guarded({ null }) {
        val doc = session.get()?.engine?.item(itemId)?.doc ?: return@guarded null
        session.touch()
        when (field) {
            SecretField.PASSWORD -> doc.login?.password
            SecretField.NOTES -> doc.notes
            SecretField.TOTP_SECRET -> doc.login?.totp
            SecretField.CARD_NUMBER -> doc.card?.number
            SecretField.CARD_CODE -> doc.card?.securityCode
        }?.ifEmpty { null }
    }

    /**
     * When each earlier password of a login was retired (unix milliseconds), newest first: the index is what
     * [previousPassword] takes. The passwords themselves are read one at a time, on request.
     */
    fun passwordHistory(itemId: String): List<Long> = guarded({ emptyList() }) {
        session.get()?.engine?.item(itemId)?.doc?.login?.passwordHistory.orEmpty().map { it.retiredAt }.reversed()
    }

    /** One earlier password of a login, by its place in [passwordHistory] (0 is the most recent); null when there is none. */
    fun previousPassword(itemId: String, index: Int): String? = guarded({ null }) {
        val history = session.get()?.engine?.item(itemId)?.doc?.login?.passwordHistory.orEmpty()
        session.touch()
        history.reversed().getOrNull(index)?.password
    }

    /** The item's current one-time code; null if it has none, or the vault is locked. */
    fun oneTimeCode(itemId: String): OneTimeCode? = guarded({ null }) {
        val uri = session.get()?.engine?.item(itemId)?.doc?.login?.totp?.ifEmpty { null } ?: return@guarded null
        val config = Totp.parseUri(Totp.normalize(uri))
        val nowSeconds = clocks.wallMs() / 1000
        val period = config.periodSeconds
        OneTimeCode(Totp.code(crypto, config, nowSeconds), (period - (nowSeconds % period)).toInt(), period)
    }

    /**
     * Add a login ([itemId] null) or save an edit of one. A new login goes to [vaultId] when named (one of [vaultsForNewItems]),
     * else to the personal vault; an edit stays in its vault whatever [vaultId] says.
     */
    @Throws(CancellationException::class)
    suspend fun saveLogin(itemId: String?, input: LoginInput, vaultId: String? = null): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        if (input.name.isBlank()) return@action ActionResult.Failed(NAME_REQUIRED)
        val totp = if (input.totp.isBlank()) "" else Totp.normalize(input.totp)
        if (totp.isNotEmpty() && runCatching { Totp.parseUri(totp) }.isFailure) return@action ActionResult.Failed(TOTP_INVALID)
        val existing = itemId?.let { live.engine.item(it) ?: return@action ActionResult.Failed(ITEM_GONE) }
        // A9 review LOW-2: a new item never goes to a guessed vault.
        if (existing == null) newHomeRefusal(live, vaultId)?.let { return@action it }
        // A copy of the existing document, never a rebuild: favorites, the password history, attachments and fields
        // this client does not know survive the edit (spec 02 §3).
        val base = existing?.doc ?: ItemDoc(type = "login", name = "")
        val doc = base.copy(
            name = input.name.trim(),
            notes = input.notes.ifBlank { null },
            favorite = input.favorite,
            login = (base.login ?: LoginData()).copy(
                username = input.username,
                password = input.password,
                uris = input.uris.map { it.trim() }.filter { it.isNotEmpty() },
                totp = totp.ifEmpty { null },
            ),
        )
        if (savingFiles(itemId)) return@action ActionResult.NotDone(null) // this editor's save runs already
        busy()
        // INV-EDIT: an edit is sealed under the vault its item lives in; a new login goes to the personal vault.
        // Alone with respect to the save queue: an automatic save never writes over this edit from an older read.
        val outcome = saveWithFiles(live, itemId, doc, existing?.vaultId ?: vaultId)
        if (outcome == null || session.get() !== live) return@action notDone(live) // locked meanwhile, or this editor's save runs already
        update { it.copy(busy = false, items = summaries(it.query), notice = if (outcome == SaveOutcome.QUEUED) HouseholdCopy.SAVE_OFFLINE else it.notice) }
        writeFillSnapshot()
        ActionResult.Ok
    }

    /**
     * Add a card ([itemId] null) to the personal vault, or save an edit of one. The fields are normalized once, here,
     * as the other clients do: the number and the code keep their digits only, the expiry is read as a month and a
     * four-digit year (a whole "07/31" typed into the month is split), and the brand is always worked out from the
     * number. An expiry that cannot be read is refused, never guessed.
     */
    @Throws(CancellationException::class)
    suspend fun saveCard(itemId: String?, input: CardInput, vaultId: String? = null): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        if (input.name.isBlank()) return@action ActionResult.Failed(CARD_NAME_REQUIRED)
        val combined = if (input.expMonth.isNotBlank() && CardNormalize.padMonth(input.expMonth) == null && input.expYear.isBlank()) CardNormalize.parseExpiry(input.expMonth) else null
        val month = combined?.expMonth ?: CardNormalize.padMonth(input.expMonth)
        val year = combined?.expYear ?: CardNormalize.yearTo4(input.expYear)
        if ((input.expMonth.isNotBlank() && month == null) || (input.expYear.isNotBlank() && year == null)) return@action ActionResult.Failed(CARD_EXPIRY_INVALID)
        val existing = itemId?.let { live.engine.item(it) ?: return@action ActionResult.Failed(ITEM_GONE) }
        if (existing != null && existing.doc.type != "card") return@action ActionResult.Failed(ITEM_GONE)
        // No card number is longer than 19 digits (ISO/IEC 7812). A number already stored is kept as it is, whatever
        // its length, so editing an odd card's name never fails on a number the person did not touch.
        val digits = CardNormalize.digitsOnly(input.number)
        if (digits.length > CARD_NUMBER_MAX_DIGITS && digits != existing?.doc?.card?.number) return@action ActionResult.Failed(CARD_NUMBER_TOO_LONG)
        if (existing == null) newHomeRefusal(live, vaultId)?.let { return@action it }
        // A copy of the existing document and of its card, never a rebuild: fields this client does not know survive.
        val base = existing?.doc ?: ItemDoc(type = "card", name = "", card = CardData())
        val doc = base.copy(
            name = input.name.trim(),
            notes = input.notes.ifBlank { null },
            favorite = input.favorite,
            card = (base.card ?: CardData()).copy(
                cardholderName = input.cardholder.trim().ifBlank { null },
                number = digits.ifBlank { null },
                expMonth = month,
                expYear = year,
                securityCode = CardNormalize.digitsOnly(input.securityCode).ifBlank { null },
                postalCode = input.postalCode.trim().ifBlank { null },
                brand = CardNormalize.brand(input.number),
            ),
        )
        if (savingFiles(itemId)) return@action ActionResult.NotDone(null) // this editor's save runs already
        busy()
        val outcome = saveWithFiles(live, itemId, doc, existing?.vaultId ?: vaultId)
        if (outcome == null || session.get() !== live) return@action notDone(live) // locked meanwhile, or this editor's save runs already
        update { it.copy(busy = false, items = summaries(it.query), notice = if (outcome == SaveOutcome.QUEUED) HouseholdCopy.SAVE_OFFLINE else it.notice) }
        writeFillSnapshot()
        ActionResult.Ok
    }

    /**
     * A line to show under a card number while it is typed, or null: a number that cannot be saved, or one that does
     * not pass the usual check (a warning only, since an odd but real card must still be savable).
     */
    fun cardNumberWarning(number: String): String? {
        val digits = CardNormalize.digitsOnly(number)
        return when {
            digits.length > CARD_NUMBER_MAX_DIGITS -> CARD_NUMBER_TOO_LONG
            digits.length >= 12 && !CardNormalize.luhnValid(digits) -> CARD_NUMBER_UNUSUAL
            else -> null
        }
    }

    /**
     * Add a secure note ([itemId] null) to the personal vault, or save an edit of one. The text is kept as typed; an
     * empty note is allowed (the name is what is required). The text is a secret like a password: it is read through
     * [revealSecret] with [SecretField.NOTES], never carried in the state.
     */
    @Throws(CancellationException::class)
    suspend fun saveNote(itemId: String?, input: NoteInput, vaultId: String? = null): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        if (input.name.isBlank()) return@action ActionResult.Failed(NOTE_NAME_REQUIRED)
        val existing = itemId?.let { live.engine.item(it) ?: return@action ActionResult.Failed(ITEM_GONE) }
        if (existing != null && existing.doc.type != "note") return@action ActionResult.Failed(ITEM_GONE)
        if (existing == null) newHomeRefusal(live, vaultId)?.let { return@action it }
        // A copy of the existing document, never a rebuild: attachments and fields this client does not know survive.
        val base = existing?.doc ?: ItemDoc(type = "note", name = "")
        val doc = base.copy(name = input.name.trim(), notes = input.text.ifBlank { null }, favorite = input.favorite)
        if (savingFiles(itemId)) return@action ActionResult.NotDone(null) // this editor's save runs already
        busy()
        val outcome = saveWithFiles(live, itemId, doc, existing?.vaultId ?: vaultId)
        if (outcome == null || session.get() !== live) return@action notDone(live) // locked meanwhile, or this editor's save runs already
        update { it.copy(busy = false, items = summaries(it.query), notice = if (outcome == SaveOutcome.QUEUED) HouseholdCopy.SAVE_OFFLINE else it.notice) }
        writeFillSnapshot()
        ActionResult.Ok
    }

    // ---- screens that read from the server as they open ----

    /**
     * One per screen that reads from the server as it opens (the trash, an item's history, the shared vaults, two-step
     * sign-in): every open and every close moves it on, so a read that finishes after its screen was closed, or opened
     * again, assigns nothing (round-6 review L8). What it read is dropped there.
     */
    private class ScreenToken {
        private var value = 0L

        fun open(): Long = ++value

        fun close() {
            value++
        }

        fun now(): Long = value

        fun still(token: Long): Boolean = value == token
    }

    private val trashScreen = ScreenToken()
    private val historyScreen = ScreenToken()
    private val sharingScreen = ScreenToken()
    private val twoStepScreen = ScreenToken()

    /** A read whose screen closed (or opened again) meanwhile: nothing is assigned, and the controller is idle again. */
    private fun screenGone(): ActionResult {
        update { it.copy(busy = false) }
        return ActionResult.NotDone(null)
    }

    /** An action that ends without doing its work: idle again, unless the vault locked meanwhile (the lock reset the state). */
    private fun notDone(live: VaultSession.Unlocked): ActionResult {
        if (session.get() === live) idle()
        return ActionResult.NotDone(null)
    }

    // ---- trash (spec 03 §11: a deleted item is kept 30 days) ----

    /** The trash as last read, each deleted item with its last readable version. Held only while the trash is open. */
    private var trashRead: Map<String, DeletedItemView> = emptyMap()

    /** Whether this account may write [vaultId]: not a reader of it, and holding its key. */
    private fun canWrite(live: VaultSession.Unlocked, vaultId: String): Boolean =
        live.account.roleFor(vaultId) != "reader" && live.account.canSealUnder(vaultId)

    /** A line about [doc] that tells it apart and is never a secret: a login's username, a card's brand and last four. */
    private fun safeDetail(doc: ItemDoc): String? = when (doc.type) {
        "login" -> doc.login?.username?.ifEmpty { null }
        "card" -> CardDisplay.subtitle(doc).ifEmpty { null }
        else -> null
    }

    private fun vaultName(live: VaultSession.Unlocked, vaultId: String): String? =
        runCatching { live.engine.vaultInfos().firstOrNull { it.vaultId == vaultId }?.name }.getOrNull()

    private fun trashViews(live: VaultSession.Unlocked): List<TrashItemView> = trashRead.values.sortedByDescending { it.deletedAt }.map { d ->
        val doc = d.doc
        TrashItemView(
            itemId = d.itemId, name = doc?.name, type = doc?.type, detail = doc?.let(::safeDetail), vault = vaultName(live, d.vaultId),
            deletedAtMs = d.deletedAt, canRestore = doc != null && canWrite(live, d.vaultId), canPurge = live.account.roleFor(d.vaultId) != "reader",
        )
    }

    /** Read the server's trash ([AppState.trash]). Each item is named from its last readable version. */
    @Throws(CancellationException::class)
    suspend fun openTrash(): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val token = trashScreen.open()
        busy()
        val deleted = runBounded(BoundedOps.FLAT_MS) { live.engine.deletedItems() }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        if (!trashScreen.still(token)) return@action screenGone()
        trashRead = deleted.associateBy { it.itemId }
        update { it.copy(busy = false, trash = trashViews(live)) }
        ActionResult.Ok
    }

    /** The trash screen closed: what was read goes. */
    fun closeTrash() {
        trashScreen.close()
        trashRead = emptyMap()
        update { it.copy(trash = null) }
    }

    /** Bring a deleted item back to its vault, on every device. Its attachments do not come back. */
    @Throws(CancellationException::class)
    suspend fun restoreFromTrash(itemId: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val deleted = trashRead[itemId] ?: return@action ActionResult.Failed(ItemCopy.TRASH_GONE)
        val doc = deleted.doc ?: return@action ActionResult.Failed(ItemCopy.TRASH_UNREADABLE)
        if (!canWrite(live, deleted.vaultId)) return@action ActionResult.Failed(ItemCopy.READ_ONLY)
        busy()
        runBounded(BoundedOps.FLAT_MS) { live.engine.restoreDeleted(itemId, deleted.vaultId, doc) }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        trashRead = trashRead - itemId
        update { it.copy(busy = false, items = summaries(it.query), vaultNotices = vaultNotices(live), trash = it.trash?.let { trashViews(live) }, notice = ItemCopy.TRASH_RESTORED) }
        writeFillSnapshot()
        ActionResult.Ok
    }

    /** Delete an item for good: it and its history are removed from every device now. */
    @Throws(CancellationException::class)
    suspend fun purgeFromTrash(itemId: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val deleted = trashRead[itemId] ?: return@action ActionResult.Failed(ItemCopy.TRASH_GONE)
        if (live.account.roleFor(deleted.vaultId) == "reader") return@action ActionResult.Failed(ItemCopy.READ_ONLY)
        busy()
        runBounded(BoundedOps.FLAT_MS) { live.engine.purgeDeleted(itemId) }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        trashRead = trashRead - itemId
        update { it.copy(busy = false, trash = it.trash?.let { trashViews(live) }, notice = ItemCopy.TRASH_PURGED) }
        ActionResult.Ok
    }

    // ---- item history (the server keeps an item's last 10 saves) ----

    /** The open history: whose, and its versions decrypted. Held only while it is open. */
    private var historyRead: Pair<String, List<DecryptedItemVersion>>? = null

    private fun historyView(live: VaultSession.Unlocked, itemId: String, versions: List<DecryptedItemVersion>): ItemHistoryView {
        val vaultId = live.engine.item(itemId)?.vaultId
        return ItemHistoryView(
            itemId = itemId,
            versions = versions.map { v -> ItemVersionView(v.rev, v.archivedAt, v.doc.name, safeDetail(v.doc), !v.doc.login?.password.isNullOrEmpty()) },
            canRestore = vaultId != null && canWrite(live, vaultId),
        )
    }

    /** Read [itemId]'s earlier versions ([AppState.history]), newest first. */
    @Throws(CancellationException::class)
    suspend fun openItemHistory(itemId: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val item = live.engine.item(itemId) ?: return@action ActionResult.Failed(ITEM_GONE)
        val token = historyScreen.open()
        busy()
        val versions = runBounded(BoundedOps.FLAT_MS) { live.engine.itemVersions(itemId, item.vaultId) }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        if (!historyScreen.still(token)) return@action screenGone()
        historyRead = itemId to versions
        update { it.copy(busy = false, history = historyView(live, itemId, versions)) }
        ActionResult.Ok
    }

    /** The history closed: the versions read go. */
    fun closeItemHistory() {
        historyScreen.close()
        historyRead = null
        update { it.copy(history = null) }
    }

    /** One earlier version's password, for an explicit Show; null when it has none or the history is not open. */
    fun historyPassword(itemId: String, rev: Long): String? = guarded({ null }) {
        historyRead?.takeIf { it.first == itemId }?.second?.firstOrNull { it.rev == rev }?.doc?.login?.password?.ifEmpty { null }
    }

    /**
     * Put an earlier version back: an ordinary save of it over the item (the version it replaces is kept in the history
     * by the server), without the attachments the item no longer has.
     */
    @Throws(CancellationException::class)
    suspend fun restoreItemVersion(itemId: String, rev: Long): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val version = historyRead?.takeIf { it.first == itemId }?.second?.firstOrNull { it.rev == rev } ?: return@action ActionResult.Failed(ItemCopy.HISTORY_GONE)
        val item = live.engine.item(itemId) ?: return@action ActionResult.Failed(ITEM_GONE)
        if (!canWrite(live, item.vaultId)) return@action ActionResult.Failed(ItemCopy.READ_ONLY)
        // An item's kind never changes: a version of another kind is not this item's.
        if (version.doc.type != item.doc.type) return@action ActionResult.Failed(ItemCopy.HISTORY_GONE)
        val doc = live.engine.versionDocForRestore(itemId, version.doc)
        val token = historyScreen.now()
        busy()
        val outcome = saves.exclusive { live.engine.save(itemId, doc, item.vaultId) }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        update { it.copy(busy = false, items = summaries(it.query), notice = if (outcome == SaveOutcome.QUEUED) HouseholdCopy.SAVE_OFFLINE else ItemCopy.VERSION_RESTORED) }
        writeFillSnapshot()
        // The history again, best effort: the version just replaced is in it once the server has the restore.
        val fresh = runCatching { runBounded(BoundedOps.FLAT_MS) { live.engine.itemVersions(itemId, item.vaultId) } }
            .onFailure { if (it is CancellationException) throw it }.getOrNull()
        if (fresh != null && session.get() === live && historyScreen.still(token) && historyRead?.first == itemId) {
            historyRead = itemId to fresh
            update { it.copy(history = historyView(live, itemId, fresh)) }
        }
        ActionResult.Ok
    }

    // ---- attachments (spec 02 §6; owner decision 2026-11-12) ----

    /**
     * The files of the item an editor has open: the kept files it takes off, and the files it adds, each encrypted under a
     * key of its own and set aside as it is added (its plaintext zeroed then). A new item's id is minted when its editor
     * opens, so every try of its save uses it (F71). It lives while the editor is open.
     */
    private class Draft(val itemId: String?, val newItemId: String) {
        val removed = LinkedHashSet<String>()
        val added = ArrayList<AttachmentRef>()

        /** The save this editor kept and has not finished ([PendingSave.id]), and the new files it names. */
        var keptId: String? = null
        val keptFiles = HashSet<String>()

        /** A save of it is running: its files cannot change, and closing the editor does not take the save back. */
        var saving = false
    }

    private var draft: Draft? = null

    /** The resumption of kept saves after an unlock, while it runs: one at a time. */
    private var resuming: Job? = null

    /** What one file, and an item's files together, may come to here: the server's policy, held to this app's ([AttachmentRules]). */
    fun attachmentLimits(): AttachmentLimitsView =
        AttachmentRules.limits(state.policy?.attachmentMaxBytes, state.policy?.itemAttachmentsMaxBytes)

    private fun keptFiles(live: VaultSession.Unlocked, d: Draft): List<AttachmentRef> =
        d.itemId?.let { live.engine.item(it)?.doc?.attachments }.orEmpty().filter { it.id !in d.removed }

    private fun draftView(live: VaultSession.Unlocked, d: Draft): AttachmentDraftView {
        val kept = keptFiles(live, d)
        return AttachmentDraftView(
            kept = kept.map(::attachmentView),
            added = d.added.map(::attachmentView),
            totalBytes = kept.sumOf { it.size } + d.added.sumOf { it.size },
            limits = attachmentLimits(),
        )
    }

    /** An editor opened ([itemId] null: a new item): its files are listed, and files can be added and taken off. */
    fun openAttachmentDraft(itemId: String?) {
        val live = session.get() ?: return
        discardDraft(live)
        val d = Draft(itemId, itemId ?: live.account.newItemId())
        draft = d
        update { it.copy(attachmentDraft = draftView(live, d)) }
    }

    /** The editor closed: the files it added go, and a save of it that did not finish is not tried again. */
    fun closeAttachmentDraft() {
        session.get()?.let(::discardDraft)
        draft = null
        update { it.copy(attachmentDraft = null) }
    }

    private fun discardDraft(live: VaultSession.Unlocked) {
        val d = draft ?: return
        draft = null
        if (d.saving) return // the save runs on, and lets its files go when it is done
        d.keptId?.let { runCatching { pendingSaves.forget(live.account, it) } }
        d.added.filter { it.id !in d.keptFiles }.forEach { runCatching { pendingSaves.dropBlob(it.id) } }
    }

    /** A lock: the editor is gone. What its last save kept stays, to be finished after the next unlock; the rest goes. */
    private fun lockDraft() {
        val d = draft ?: return
        draft = null
        d.added.filter { it.id !in d.keptFiles }.forEach { runCatching { pendingSaves.dropBlob(it.id) } }
    }

    /**
     * Add a file to the open editor's item. [name] is what it is called (a path is cut to its last part). The file is
     * held to [attachmentLimits] (the app checks its size against them before it reads it, too), encrypted off the main
     * thread under a key of its own and set aside, and [bytes] zeroed: it goes up with the item's next save.
     */
    @Throws(CancellationException::class)
    suspend fun addAttachment(name: String, bytes: ByteArray): ActionResult = action {
        try {
            val live = session.get() ?: return@action ActionResult.NotDone(null)
            val d = draft?.takeIf { !it.saving } ?: return@action ActionResult.NotDone(null)
            val held = keptFiles(live, d).sumOf { it.size } + d.added.sumOf { it.size }
            AttachmentRules.refusal(bytes.size.toLong(), held, attachmentLimits())?.let { return@action ActionResult.Failed(it) }
            busy()
            val key = live.account.newFileKey()
            val crypto = live.account.cryptoProvider()
            val sealed = try {
                withContext(Dispatchers.Default) { Attachments.encrypt(crypto, key, bytes).let { it.header + it.ciphertext } }
            } catch (t: Throwable) {
                key.fill(0)
                throw t
            }
            val ref = AttachmentRef(id = live.account.newItemId(), name = fileName(name), size = bytes.size.toLong(), fileKey = Bytes.toB64(key))
            key.fill(0)
            if (session.get() !== live || draft !== d || d.saving) {
                sealed.fill(0)
                return@action notDone(live) // locked, or the editor closed, meanwhile
            }
            val setAside = try {
                pendingSaves.putBlob(ref.id, sealed)
            } finally {
                sealed.fill(0)
            }
            if (!setAside) return@action idleFailed(AttachmentCopy.FILE_NOT_SET_ASIDE)
            d.added += ref
            update { it.copy(busy = false, attachmentDraft = draftView(live, d)) }
            ActionResult.Ok
        } finally {
            bytes.fill(0)
        }
    }

    /** Take a file off the open editor's item: an added one goes now; a kept one leaves the item at its next save. */
    fun removeAttachment(attachmentId: String) {
        val live = session.get() ?: return
        val d = draft?.takeIf { !it.saving } ?: return
        val added = d.added.firstOrNull { it.id == attachmentId }
        if (added != null) {
            d.added.remove(added)
            if (attachmentId !in d.keptFiles) runCatching { pendingSaves.dropBlob(attachmentId) }
        } else if (keptFiles(live, d).any { it.id == attachmentId }) {
            d.removed += attachmentId
        }
        update { it.copy(attachmentDraft = draftView(live, d)) }
    }

    /** What a file is called here: its name made safe to show and to offer to Files ([AttachmentRules.safeFileName]). */
    private fun fileName(raw: String): String = AttachmentRules.safeFileName(raw)

    /** A file as the app lists it: never its name as stored, which whoever added the file chose (round-9 review 1). */
    private fun attachmentView(ref: AttachmentRef): AttachmentView = AttachmentView(ref.id, fileName(ref.name), ref.size)

    /**
     * One file of an item, decrypted, for a preview or to save to Files: the caller keeps it in memory and writes no
     * copy of it. Refused past what this app opens ([AttachmentRules.MAX_FILE_BYTES]); the download is bounded by the
     * file's size. No bytes and no error: the vault locked meanwhile.
     */
    @Throws(CancellationException::class)
    suspend fun readAttachment(itemId: String, attachmentId: String): AttachmentContent = withContext(uiContext) {
        val live = session.get() ?: return@withContext AttachmentContent("", null, null)
        val ref = live.engine.item(itemId)?.doc?.attachments?.firstOrNull { it.id == attachmentId }
            ?: return@withContext AttachmentContent("", null, AttachmentCopy.FILE_GONE)
        val name = fileName(ref.name)
        if (ref.size > AttachmentRules.MAX_FILE_BYTES) return@withContext AttachmentContent(name, null, AttachmentCopy.FILE_TOO_LARGE_TO_OPEN)
        session.touch()
        try {
            val bytes = runBounded(BoundedOps.attachmentMs(ref.size)) { live.engine.downloadAttachment(ref) }
            if (session.get() !== live) {
                bytes.fill(0)
                AttachmentContent(name, null, null)
            } else {
                AttachmentContent(name, bytes, null)
            }
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            AttachmentContent(name, null, HouseholdCopy.forError(t))
        }
    }

    /**
     * Save [doc] with the open editor's changes to its files (spec 02 §6, files first): files taken off leave the item,
     * and new ones go up before the item that names them. A save with new files is kept ([PendingSave]) before anything
     * is sent, so one a lock cuts short is finished after the next unlock under the same ids, never made twice, and a
     * second Save of the same editor replaces it. Null: the vault locked before the save was done, or a save of the same
     * editor runs already.
     */
    private suspend fun saveWithFiles(live: VaultSession.Unlocked, itemId: String?, doc: ItemDoc, vaultId: String?): SaveOutcome? {
        val d = draft?.takeIf { it.itemId == itemId } ?: return saves.exclusive { live.engine.save(itemId, doc, vaultId) }
        if (d.saving) return null
        val withFiles = doc.copy(attachments = doc.attachments.filter { it.id !in d.removed } + d.added)
        val newItemId = if (itemId == null) d.newItemId else null
        if (d.added.isEmpty()) {
            val outcome = saves.exclusive { live.engine.saveWithUploads(itemId, withFiles, emptyList(), vaultId, newItemId = newItemId) }
            if (draft === d) draft = null
            return outcome
        }
        val home = vaultId ?: live.account.personalVaultId.ifEmpty { throw NoPersonalVaultException() }
        val p = PendingSave(
            id = d.keptId ?: live.account.newItemId(), itemId = itemId, newItemId = d.newItemId, vaultId = home,
            baseRev = itemId?.let { live.engine.item(it)?.rev } ?: 0L, doc = withFiles, newFiles = d.added.map { it.id },
            removedFiles = d.removed.toList(),
        )
        if (!pendingSaves.keep(live.account, p)) throw IllegalStateException(AttachmentCopy.FILE_NOT_SET_ASIDE)
        // Files an earlier try of this editor's save named and this one does not: set aside for nothing now.
        d.keptFiles.filter { it !in p.newFiles }.forEach { runCatching { pendingSaves.dropBlob(it) } }
        d.keptId = p.id
        d.keptFiles.clear()
        d.keptFiles += p.newFiles
        d.saving = true
        try {
            val finished = finishPendingSave(live, p, resumed = false) ?: return null
            if (draft === d) draft = null
            return finished.outcome
        } finally {
            d.saving = false
        }
    }

    /** A save of the editor open on [itemId] runs. */
    private fun savingFiles(itemId: String?): Boolean = draft?.let { it.itemId == itemId && it.saving } == true

    /** The server has the item as [p] saves it: every new file of it is in the item (a lock came after the save, before it was let go). */
    private fun landed(live: VaultSession.Unlocked, p: PendingSave): Boolean =
        live.engine.item(p.newItemId)?.doc?.attachments?.map { it.id }?.containsAll(p.newFiles) == true

    /**
     * How a kept save was finished: the save's outcome, whether only its new files went onto the item as it is now, and
     * whether files it took off are still in the item because of that.
     */
    private class Finished(val outcome: SaveOutcome, val filesOnly: Boolean, val removalsNotKept: Boolean = false)

    /**
     * Send a kept save's new files, then the item that names them; the save is let go once the server has the item.
     * Null: the vault locked first, and the save stays kept.
     *
     * The editor's own save ([resumed] false) goes from the revision it was edited from, so someone else's change made
     * meanwhile is kept as a conflict copy, never overwritten; edits of this device still waiting to be sent are in the
     * document it was built from, so they are folded into it. A save finished later ([resumed]) is older than what may
     * have happened since (round-9 review 3), and is judged against the item as the server has it after a pull
     * ([resumePendingSaves], round-10 review 5): when the item's revision moved, or an edit of it waits to be sent, only
     * its new files are added to the item as it is now. Nothing else of the older save is applied, the files it took off
     * included (they stay, and the notice says so).
     */
    private suspend fun finishPendingSave(live: VaultSession.Unlocked, p: PendingSave, resumed: Boolean): Finished? {
        val refs = p.doc.attachments.associateBy { it.id }
        try {
            if (!landed(live, p)) {
                update { it.copy(upload = UploadView(0, p.newFiles.size)) }
                for ((i, id) in p.newFiles.withIndex()) {
                    val ref = refs[id] ?: throw IllegalStateException(AttachmentCopy.FILE_NOT_SET_ASIDE)
                    val sealed = pendingSaves.blob(id) ?: throw IllegalStateException(AttachmentCopy.FILE_NOT_SET_ASIDE)
                    try {
                        runBounded(BoundedOps.attachmentMs(ref.size)) { live.engine.uploadEncryptedAttachment(id, p.newItemId, p.vaultId, sealed) }
                    } finally {
                        sealed.fill(0)
                    }
                    if (session.get() !== live) return null
                    update { it.copy(upload = UploadView(i + 1, p.newFiles.size)) }
                }
            }
            return saves.exclusive {
                if (session.get() !== live) return@exclusive null
                if (landed(live, p)) return@exclusive Finished(SaveOutcome.APPLIED, filesOnly = false).also { pendingSaves.forget(live.account, p.id) }
                val current = p.itemId?.let { live.engine.item(it) }
                val waiting = p.itemId != null && live.engine.hasPendingSync(p.itemId)
                val finished = if (resumed && current != null && (current.rev != p.baseRev || waiting)) {
                    val added = p.doc.attachments.filter { it.id in p.newFiles }
                    val files = current.doc.attachments.filter { it.id !in p.newFiles } + added
                    val removalsNotKept = current.doc.attachments.any { it.id in p.removedFiles }
                    Finished(live.engine.saveWithUploads(p.itemId, current.doc.copy(attachments = files), emptyList(), p.vaultId), filesOnly = true, removalsNotKept = removalsNotKept)
                } else {
                    val outcome = live.engine.saveWithUploads(
                        p.itemId, p.doc, emptyList(), p.vaultId,
                        newItemId = if (p.itemId == null) p.newItemId else null,
                        baseItemRev = if (p.itemId != null && !waiting) p.baseRev else null,
                    )
                    Finished(outcome, filesOnly = false)
                }
                pendingSaves.forget(live.account, p.id)
                finished
            }
        } finally {
            if (session.get() === live) update { it.copy(upload = null) }
        }
    }

    /**
     * After an unlock: the saves with files a lock cut short (or that could not reach the server) are finished, under the
     * ids they were given. One the server refuses for good is let go and said; one that still cannot get through stays
     * for the next unlock. Files set aside for an editor the app was closed in go.
     */
    private fun resumePendingSaves() {
        val live = session.get() ?: return
        if (resuming?.isActive == true) return
        // What a policy probe took off the disk while locked is opened now, and what an earlier version left is counted:
        // either is said (round-10 reviews 2 and 3).
        runCatching { pendingSaves.unlocked(live.account) }.getOrNull()?.let { found ->
            if (found.movedToMemory > 0) update { it.copy(notice = AttachmentCopy.KEPT_IN_MEMORY) }
            droppedEarlier(found.unreadable)
        }
        val kept = runCatching {
            pendingSaves.sweep(live.account, draft?.added?.mapTo(HashSet()) { it.id }.orEmpty())
            pendingSaves.load(live.account)
        }.getOrDefault(emptyList())
        if (kept.isEmpty()) return
        resuming = scope.launch {
            var done = 0
            val filesOnly = mutableListOf<Pair<String, Boolean>>()
            try {
                // Pull first, then decide (round-10 review 5): whether a kept save landed, or its item changed since, is
                // judged against the server's copy, not a cache an offline unlock left as it was. No pull, nothing is
                // decided: the saves stay kept for the next unlock.
                try {
                    runBounded(BoundedOps.FLAT_MS) { syncNow(live.engine) }
                } catch (t: Throwable) {
                    if (t is CancellationException) throw t
                    if (session.get() === live) update { it.copy(notice = AttachmentCopy.savedLater(kept.first().doc.name.ifBlank { "An item" })) }
                    return@launch
                }
                for (p in kept) {
                    if (session.get() !== live) return@launch
                    if (draft?.keptId == p.id) continue // its editor is open: its own Save finishes it
                    try {
                        val finished = finishPendingSave(live, p, resumed = true) ?: return@launch
                        if (finished.filesOnly) filesOnly += p.doc.name.ifBlank { "An item" } to finished.removalsNotKept
                        done++
                    } catch (t: Throwable) {
                        if (t is CancellationException) throw t
                        if (session.get() !== live) return@launch
                        val name = p.doc.name.ifBlank { "An item" }
                        if (givenUp(t)) {
                            runCatching { pendingSaves.forget(live.account, p.id) }
                            update { it.copy(notice = AttachmentCopy.savedWithoutFiles(name, HouseholdCopy.forError(t))) }
                        } else {
                            update { it.copy(notice = AttachmentCopy.savedLater(name)) }
                        }
                    }
                }
            } finally {
                afterAction() // a lock that waited for this upload lands now
            }
            if (done > 0 && session.get() === live) {
                val said = when {
                    filesOnly.isNotEmpty() -> AttachmentCopy.filesOnly(filesOnly.first().first, filesOnly.first().second)
                    done == 1 -> AttachmentCopy.KEPT_SAVE_DONE
                    else -> "$done ${AttachmentCopy.KEPT_SAVES_DONE}"
                }
                update { it.copy(items = summaries(it.query), notice = said) }
                writeFillSnapshot()
            }
        }
    }

    /** What an earlier version kept on this device and this one could not carry over, counted since the unlock: one notice. */
    private var earlierDropped = 0

    /** [count] more things an earlier version kept could not be carried over (round-10 review 3): the notice says how many. */
    private fun droppedEarlier(count: Int) {
        if (count <= 0) return
        earlierDropped += count
        update { it.copy(notice = AttachmentCopy.earlierRecords(earlierDropped)) }
    }

    /** A kept save the server refuses for good: an item gone or moved, a vault this account may no longer write, too large. */
    private fun givenUp(t: Throwable): Boolean = when (t) {
        is ItemChangedVaultsException -> true
        is ApiException -> t.status in 400..499 && t.status != 401 && t.status != 408 && t.status != 429
        is IllegalStateException -> t.message == AttachmentCopy.FILE_NOT_SET_ASIDE
        else -> false
    }

    // ---- shared vaults: create, rename, delete and restore, leave (spec 03 §10, §11) ----

    /** The restorable deleted vaults as last listed, by vault: their deleteIds stay here, never in the state. */
    private var deletedVaults: Map<String, DeletedVaultInfo> = emptyMap()

    /** The vault whose items are being copied into the personal vault, while that runs: its deletion waits for it. */
    private var copyingVault: String? = null

    private fun sharingVaults(live: VaultSession.Unlocked): List<SharingVaultView> {
        val items = live.engine.items()
        val reviewing = runCatching { live.engine.legacyReviewVaults() }.getOrDefault(emptyList()).mapTo(HashSet()) { it.vaultId }
        return runCatching { live.engine.vaultInfos() }.getOrDefault(emptyList()).map { v ->
            val own = items.filter { it.vaultId == v.vaultId }
            val personal = v.type == "personal"
            SharingVaultView(
                vaultId = v.vaultId, name = v.name, personal = personal, role = if (personal) null else (v.role ?: "reader"),
                ownershipConfirmed = !personal && v.role == "owner" && runCatching { live.engine.ownsVault(v.vaultId) }.getOrDefault(false),
                itemCount = own.size, attachmentCount = own.sumOf { it.doc.attachments.size },
                awaitingReview = !personal && v.vaultId in reviewing,
            )
        }
    }

    private fun removedVaults(live: VaultSession.Unlocked): List<RemovedVaultView> =
        // A vault this account can still restore is listed once, under Recently deleted, not again here.
        runCatching { live.engine.heldVaultInfos() }.getOrDefault(emptyList()).filter { it.vaultId !in deletedVaults }.map { h ->
            // Sharing review 2026-11 (item 6): by how the removal's proof checked here, the same words on every client.
            val (line, warning) = HeldVaultCopy.sentence(h)
            RemovedVaultView(h.vaultId, h.name, line, warning)
        }

    private fun sharingView(live: VaultSession.Unlocked, copied: String? = state.sharing?.copied): SharingView = SharingView(
        vaults = sharingVaults(live),
        deleted = deletedVaults.values.sortedByDescending { it.deletedAt }.map { DeletedVaultView(it.vaultId, it.name, it.deletedAt, it.purgeAt) },
        removed = removedVaults(live),
        copying = state.sharing?.copying,
        copied = copied,
    )

    /** The vault list after a change: the items and the sharing screen both follow. */
    private fun publishSharing(live: VaultSession.Unlocked, notice: String? = null) {
        val invitations = invitationViews(live)
        val offers = ownershipOfferViews(live)
        val reviews = legacyReviewViews(live)
        update {
            it.copy(
                busy = false, items = summaries(it.query), vaultNotices = vaultNotices(live), invitations = invitations, ownershipOffers = offers,
                legacyReviews = reviews, sharing = it.sharing?.let { sharingView(live) }, notice = notice ?: it.notice,
            )
        }
        writeFillSnapshot()
    }

    /** Open the shared vaults screen ([AppState.sharing]): the vaults held, and the deleted ones this account can restore. */
    @Throws(CancellationException::class)
    suspend fun openSharing(): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val token = sharingScreen.open()
        update { it.copy(sharing = sharingView(live, copied = null)) }
        busy()
        val listed = try {
            runBounded(BoundedOps.FLAT_MS) { live.engine.listDeleted() }
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            // The vaults held are shown whatever happens; what is restorable needs the server.
            return@action failure(t, HouseholdCopy::forError)
        }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        if (!sharingScreen.still(token)) return@action screenGone()
        deletedVaults = listed.associateBy { it.vaultId }
        update { it.copy(busy = false, sharing = sharingView(live)) }
        ActionResult.Ok
    }

    fun closeSharing() {
        sharingScreen.close()
        deletedVaults = emptyMap()
        update { it.copy(sharing = null) }
    }

    /** Create a shared vault this account owns. Nobody else is in it until a member is added. */
    @Throws(CancellationException::class)
    suspend fun createSharedVault(name: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val trimmed = name.trim()
        if (trimmed.isEmpty()) return@action ActionResult.Failed(SharingCopy.NAME_REQUIRED)
        busy()
        runBounded(BoundedOps.FLAT_MS) { live.engine.createSharedVault(trimmed) }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        publishSharing(live, notice = "“$trimmed” is ready. It is shared with nobody until you add someone.")
        ActionResult.Ok
    }

    /** Rename a shared vault this account owns. The name is encrypted and syncs to every member. */
    @Throws(CancellationException::class)
    suspend fun renameSharedVault(vaultId: String, name: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val trimmed = name.trim()
        if (trimmed.isEmpty()) return@action ActionResult.Failed(SharingCopy.NAME_REQUIRED)
        if (!ownedShared(live, vaultId)) return@action ActionResult.Failed(SharingCopy.OWNER_ONLY)
        busy()
        runBounded(BoundedOps.FLAT_MS) { live.engine.renameVault(vaultId, trimmed) }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        publishSharing(live)
        ActionResult.Ok
    }

    /** Whether [vaultId] is a shared vault the server says this account owns. */
    private fun ownedShared(live: VaultSession.Unlocked, vaultId: String): Boolean =
        runCatching { live.engine.vaultInfos() }.getOrDefault(emptyList()).any { it.vaultId == vaultId && it.type == "shared" && it.role == "owner" }

    /**
     * Copy every item of [vaultId] into the personal vault before it is deleted (copies only: nothing in [vaultId]
     * changes). Retrying after a failure converges instead of duplicating.
     */
    // Not "copy…": Kotlin/Native exports a name that starts with "copy" as doCopy… (Objective-C's method families).
    @Throws(CancellationException::class)
    suspend fun saveVaultItemsToPersonal(vaultId: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        if (copyingVault != null) return@action ActionResult.NotDone(null) // one copy at a time
        if (live.account.personalVaultId.isEmpty()) return@action ActionResult.Failed(HouseholdCopy.NO_PERSONAL_VAULT)
        val engine = live.engine
        val inVault = engine.items().filter { it.vaultId == vaultId }
        val bytes = inVault.sumOf { i -> i.doc.attachments.sumOf { it.size } }
        copyingVault = vaultId
        busy()
        update { it.copy(sharing = it.sharing?.copy(copying = CopyProgressView(vaultId, 0, inVault.size), copied = null)) }
        try {
            val copied = runBounded(BoundedOps.rescueCopyMs(bytes, inVault.size)) {
                engine.copyAllToPersonal(vaultId) { done, total -> update { it.copy(sharing = it.sharing?.copy(copying = CopyProgressView(vaultId, done, total))) } }
            }
            if (session.get() !== live) return@action ActionResult.NotDone(null)
            update { it.copy(sharing = it.sharing?.copy(copying = null)) }
            publishSharing(live)
            update {
                it.copy(sharing = it.sharing?.copy(copied = "Copied $copied ${if (copied == 1) "item" else "items"} to your personal vault. Deleting the shared vault won't remove those copies."))
            }
            ActionResult.Ok
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            update { it.copy(sharing = it.sharing?.copy(copying = null)) }
            failure(t, HouseholdCopy::forError)
        } finally {
            if (copyingVault == vaultId) copyingVault = null
        }
    }

    /**
     * Delete a shared vault this account owns, once [typedName] is its name: it leaves everyone's andvari now, and the
     * server keeps it for 7 days, during which Recently deleted brings it back. Refused while its items are being copied
     * into the personal vault.
     */
    @Throws(CancellationException::class)
    suspend fun deleteSharedVault(vaultId: String, typedName: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        if (copyingVault != null) return@action ActionResult.Failed(SharingCopy.COPY_RUNNING)
        val vault = runCatching { live.engine.vaultInfos() }.getOrDefault(emptyList()).firstOrNull { it.vaultId == vaultId }
            ?: return@action ActionResult.Failed(SharingCopy.VAULT_GONE)
        if (vault.type != "shared" || vault.role != "owner") return@action ActionResult.Failed(SharingCopy.OWNER_ONLY)
        if (typedName != vault.name) return@action ActionResult.Failed(SharingCopy.TYPE_THE_NAME)
        busy()
        val purgeAt = runBounded(BoundedOps.FLAT_MS) { live.engine.deleteSharedVault(vaultId) }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        // What is restorable now includes this vault: the list is read again, best effort.
        runCatching { runBounded(BoundedOps.FLAT_MS) { live.engine.listDeleted() } }.onFailure { if (it is CancellationException) throw it }
            .getOrNull()?.let { listed -> deletedVaults = listed.associateBy { it.vaultId } }
        publishSharing(
            live,
            notice = "“${vault.name}” is deleted. Members lost access now. You can restore it until ${LifecycleNoticeCopy.englishDay(purgeAt)} from Recently deleted.",
        )
        ActionResult.Ok
    }

    /** Bring a deleted shared vault back, for every member, with everything that was in it. */
    @Throws(CancellationException::class)
    suspend fun restoreDeletedVault(vaultId: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val deleted = deletedVaults[vaultId] ?: return@action ActionResult.Failed(SharingCopy.VAULT_GONE)
        busy()
        runBounded(BoundedOps.FLAT_MS) { live.engine.restoreSharedVault(vaultId, deleted.deleteId) }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        deletedVaults = deletedVaults - vaultId
        publishSharing(live, notice = "“${deleted.name}” is back, for every member.")
        ActionResult.Ok
    }

    /**
     * Leave a shared vault this account is a member of: access ends on all of its devices, unsynced edits there are
     * discarded, and only the owner can add it back. An owner cannot leave: it transfers or deletes the vault instead.
     */
    @Throws(CancellationException::class)
    suspend fun leaveSharedVault(vaultId: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val vault = runCatching { live.engine.vaultInfos() }.getOrDefault(emptyList()).firstOrNull { it.vaultId == vaultId }
            ?: return@action ActionResult.Failed(SharingCopy.VAULT_GONE)
        if (vault.type != "shared") return@action ActionResult.Failed(SharingCopy.VAULT_GONE)
        // Sharing review 2026-11 (item 8): the server's owner label never keeps this account in a vault awaiting review, one
        // whose key nothing verified; leaving it is the safe way out. The server refuses an owner that really is one.
        val awaitingReview = runCatching { live.engine.legacyReviewVaults() }.getOrDefault(emptyList()).any { it.vaultId == vaultId }
        if (vault.role == "owner" && !awaitingReview) return@action ActionResult.Failed(SharingCopy.OWNER_CANNOT_LEAVE)
        busy()
        runBounded(BoundedOps.FLAT_MS) { live.engine.leaveSharedVault(vaultId) }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        publishSharing(live, notice = "You left “${vault.name}”.")
        ActionResult.Ok
    }

    // ---- the members of a shared vault (spec 03 §10; root cause A §1.5, §1.6, §7.2) ----
    //
    // Who the server lists, what it calls them and the key it serves for each are its word. This device trusts a key
    // only after the person compared codes for it here ([verifyWithCode], [verifyWithQr]). An add seals the vault's key
    // to the key verified, never to one fresh from the server; core's [SyncEngine.addVaultMember] holds that rule and
    // refuses an add the pins contradict, whatever a screen showed.

    /** The members the server listed for the open members screen. Held only while it is open. */
    private var membersRead: List<VaultMemberSummary>? = null

    /** The account a look-up answered with for the address typed to add someone. Held only while the members screen is open. */
    private class NewMember(val vaultId: String, val email: String, val served: UserLookupResponse)

    private var newMember: NewMember? = null

    /** Whom an open comparison of codes is with, as the server served them, and what a match records or opens. */
    private class VerifyTarget(val served: UserLookupResponse, val email: String?, val invitation: PendingInvitation?)

    private var verifyTarget: VerifyTarget? = null

    private val membersScreen = ScreenToken()

    /** What the server called each invitation's sender (by grant id). Each is asked for once a session, in the background. */
    private val invitationSenders = HashMap<String, String>()
    private val invitationAsks = HashSet<String>()

    /** vaultId → what the server calls the owner offering this account that vault; each asked for once. */
    private val offerOwners = HashMap<String, String>()
    private val offerOwnerAsks = HashSet<String>()

    /** vaultId → what the server calls the owner of a vault awaiting review; each asked for once a session. */
    private val reviewOwners = HashMap<String, String>()
    private val reviewOwnerAsks = HashSet<String>()

    /** The "You own <vault>?" the engine described, while it is open: only that one can be confirmed. */
    private var claim: OwnershipClaim? = null

    /** The members screen for [vaultId] as this device sees it now; null when the vault is no longer a shared one held here. */
    private fun membersView(live: VaultSession.Unlocked, vaultId: String): MembersView? {
        val vault = vaultList(live).firstOrNull { it.vaultId == vaultId && it.type == "shared" } ?: return null
        val owner = vault.role == "owner"
        val rows = membersRead?.map { m ->
            val you = m.userId == live.account.userId
            val check = if (you) null else memberCheck(live, m.userId, m.identityPub)
            MemberView(
                userId = m.userId, name = m.displayName, email = m.email, role = m.role, disabled = (m.status ?: "active") != "active", you = you,
                check = check, verifiedName = if (check == MemberCheck.VERIFIED) verifiedNameOf(live, m.userId) else null,
            )
        }
        val pending = if (owner) runCatching { live.engine.pendingTransferFor(vaultId) }.getOrNull() else null
        return MembersView(
            vaultId = vaultId, vaultName = vault.name, owner = owner,
            canAdd = owner && runCatching { live.engine.ownsVault(vaultId) }.getOrDefault(false),
            members = rows, adding = newMember?.takeIf { it.vaultId == vaultId }?.let { newMemberView(live, it) },
            offer = pending?.takeIf { it.toUserId != live.account.userId && it.expiresAt > clocks.wallMs() }?.let { p ->
                // Sharing review 2026-11 (item 5): "You asked" only for this account's own offer, whose proof checks.
                val target = rows?.firstOrNull { it.userId == p.toUserId }
                OwnerOfferView(
                    p.toUserId, target?.verifiedName ?: target?.name ?: MembersCopy.A_MEMBER, p.expiresAt,
                    mine = runCatching { live.engine.pendingTransferIsOwn(vaultId) }.getOrDefault(false),
                )
            },
            legacy = if (owner) legacyGrantViews(live, vaultId) else emptyList(),
        )
    }

    /**
     * The members last listed as still on the older kind of sharing ([loadLegacyGrants]), each with what this device
     * knows of them NOW: a comparison of codes made since shows at once. Someone no longer listed as a member is left out.
     */
    private fun legacyGrantViews(live: VaultSession.Unlocked, vaultId: String): List<LegacyGrantView> {
        if (!runCatching { live.engine.ownsVault(vaultId) }.getOrDefault(false)) return emptyList()
        val listed = membersRead?.mapTo(HashSet()) { it.userId }
        return live.engine.legacyGrantRows(vaultId).filter { listed == null || it.userId in listed }.map { r ->
            val check = memberCheck(live, r.userId, r.identityPub)
            LegacyGrantView(
                userId = r.userId, name = r.displayName, email = r.email, check = check,
                verifiedLabel = if (check == MemberCheck.VERIFIED) live.engine.accountState.currentPin(r.userId)?.label else null,
                sharedAtMs = r.previouslySharedAt,
            )
        }
    }

    /**
     * Ask the server which members are still on the older kind of sharing (the owner's list, §8.2 step 4). Best effort:
     * loading it signs nothing, and a list that cannot be read only means nothing is offered for re-sharing yet.
     */
    private suspend fun loadLegacyGrants(live: VaultSession.Unlocked, vaultId: String, token: Long) {
        try {
            runBounded(BoundedOps.FLAT_MS) { live.engine.loadLegacyGrants(vaultId) }
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            return
        }
        if (session.get() !== live || !membersScreen.still(token)) return
        update { it.copy(members = it.members?.takeIf { m -> m.vaultId == vaultId }?.let { membersView(live, vaultId) } ?: it.members) }
    }

    private fun memberCheck(live: VaultSession.Unlocked, userId: String, identityPub: String): MemberCheck =
        when (runCatching { live.engine.memberPinState(userId, identityPub) }.getOrDefault(SyncEngine.MemberPinState.NEEDS_VERIFICATION)) {
            SyncEngine.MemberPinState.PINNED -> MemberCheck.VERIFIED
            SyncEngine.MemberPinState.KEY_CHANGED -> MemberCheck.KEY_CHANGED
            SyncEngine.MemberPinState.NEEDS_VERIFICATION -> MemberCheck.NOT_VERIFIED
        }

    /** What this device recorded when it verified [userId]: the address typed then, else the name shown then. */
    private fun verifiedNameOf(live: VaultSession.Unlocked, userId: String): String? =
        live.engine.accountState.currentPin(userId)?.let { it.email ?: it.label }

    /**
     * Where adding [n] stands, by this account's pins (A11): the server's name for them is shown as its word, and a
     * confirmation names who was verified for the address typed, never the look-up's answer.
     */
    private fun newMemberView(live: VaultSession.Unlocked, n: NewMember): NewMemberView {
        val engine = live.engine
        val identity = engine.addMemberIdentity(n.email, n.served.userId)
        val pinState = engine.memberPinState(n.served)
        val (step, reason) = when {
            identity is ContactPin.AddIdentity.Mismatch -> NewMemberStep.REFUSED to MembersCopy.mismatch(n.email, identity.pin, identity.claimedBy)
            pinState == SyncEngine.MemberPinState.KEY_CHANGED ->
                NewMemberStep.VERIFY_AGAIN to MembersCopy.keyChanged(n.email, engine.accountState.currentPin(n.served.userId)?.label)
            pinState == SyncEngine.MemberPinState.NEEDS_VERIFICATION -> NewMemberStep.VERIFY to null
            identity is ContactPin.AddIdentity.Legacy -> NewMemberStep.VERIFY_AGAIN to MembersCopy.legacy(n.email, identity.pin.label)
            identity is ContactPin.AddIdentity.Match -> NewMemberStep.READY to null
            else -> NewMemberStep.VERIFY to null
        }
        val verified = (identity as? ContactPin.AddIdentity.Match)?.pin?.takeIf { step == NewMemberStep.READY }?.let { pin ->
            VerifiedPersonView(pin.email ?: ContactPin.normalizeEmail(n.email), pin.verifiedAt, pin.label, codeOf(live, pin.identityPub))
        }
        return NewMemberView(n.email, n.served.displayName, step, verified, reason)
    }

    /** The 32-hex identity code of a key (base64url); empty when the key does not decode. */
    private fun codeOf(live: VaultSession.Unlocked, identityPub: String): String =
        runCatching { SharedGrant.shortFingerprint(live.account.cryptoProvider(), Bytes.fromB64(identityPub)) }.getOrDefault("")

    /** Open a shared vault's members ([AppState.members]): who the server lists, and whether this device verified each. */
    @Throws(CancellationException::class)
    suspend fun openMembers(vaultId: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val token = membersScreen.open()
        membersRead = null
        newMember = null
        dropMemberVerification()
        val view = membersView(live, vaultId)
        update { it.copy(members = view) }
        if (view == null) return@action ActionResult.Failed(SharingCopy.VAULT_GONE)
        busy()
        val listed = try {
            runBounded(BoundedOps.FLAT_MS) { live.api.vaultMembers(vaultId) }
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            if (session.get() !== live) return@action ActionResult.NotDone(null)
            if (!membersScreen.still(token)) return@action screenGone()
            return@action failure(t, HouseholdCopy::forError)
        }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        if (!membersScreen.still(token)) return@action screenGone()
        membersRead = listed
        update { it.copy(busy = false, members = membersView(live, vaultId)) }
        if (state.members?.canAdd == true) loadLegacyGrants(live, vaultId, token)
        ActionResult.Ok
    }

    fun closeMembers() {
        membersScreen.close()
        membersRead = null
        newMember = null
        dropMemberVerification()
        update { it.copy(members = null) }
    }

    /** A comparison opened from the members screen goes with it; an invitation's stays. */
    private fun dropMemberVerification() {
        val target = verifyTarget ?: return
        if (target.invitation != null) return
        verifyTarget = null
        update { it.copy(verifying = null) }
    }

    /**
     * The list read again after a change, best effort: the change is done whatever this read comes to. When it cannot
     * be read, [fallback] applies the change to the list as last read.
     */
    private suspend fun rereadMembers(live: VaultSession.Unlocked, vaultId: String, token: Long, fallback: (List<VaultMemberSummary>) -> List<VaultMemberSummary>) {
        val listed = try {
            runBounded(BoundedOps.FLAT_MS) { live.api.vaultMembers(vaultId) }
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            null
        }
        if (session.get() !== live || !membersScreen.still(token)) return
        membersRead = listed ?: membersRead?.let(fallback)
    }

    /**
     * Look up the account for an address typed to add someone (owner). The server's answer is untrusted: adding waits
     * for this device's verification of that account for this address ([verifyNewMember]), or uses the one it holds.
     */
    @Throws(CancellationException::class)
    suspend fun findNewMember(email: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val open = state.members ?: return@action ActionResult.NotDone(null)
        val typed = email.trim()
        if (typed.isEmpty()) return@action ActionResult.Failed(MembersCopy.EMAIL_REQUIRED)
        if (!open.owner) return@action ActionResult.Failed(SharingCopy.OWNER_ONLY)
        if (!open.canAdd) return@action ActionResult.Failed(MembersCopy.OWNERSHIP_UNCONFIRMED)
        val token = membersScreen.now()
        newMember = null
        dropMemberVerification()
        update { it.copy(members = it.members?.copy(adding = null)) }
        busy()
        val served = try {
            runBounded(BoundedOps.FLAT_MS) { live.engine.lookupMember(typed) }
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            return@action failure(t, MembersCopy::forLookup)
        }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        if (!membersScreen.still(token)) return@action screenGone()
        if (served.userId == live.account.userId) return@action idleFailed(MembersCopy.THATS_YOU)
        if (membersRead.orEmpty().any { it.userId == served.userId }) return@action idleFailed(MembersCopy.ALREADY_MEMBER)
        newMember = NewMember(open.vaultId, typed, served)
        update { it.copy(busy = false, members = membersView(live, open.vaultId)) }
        ActionResult.Ok
    }

    /** Forget the person being added (the address was changed, or adding was put away). */
    fun cancelNewMember() {
        newMember = null
        dropMemberVerification()
        update { it.copy(members = it.members?.copy(adding = null)) }
    }

    /**
     * Add the person looked up (owner) as [role], "writer" or "reader". The vault's key is sealed, with a signed grant, to
     * the key this device verified for the address typed (core [SyncEngine.addVaultMember], which refuses an add the
     * pins do not support). Their devices open the vault once they have verified this account too.
     */
    @Throws(CancellationException::class)
    suspend fun addNewMember(role: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val n = newMember ?: return@action ActionResult.Failed(MembersCopy.LOOK_UP_AGAIN)
        if (role !in MEMBER_ROLES) return@action ActionResult.Failed(MembersCopy.BAD_ROLE)
        val view = newMemberView(live, n)
        if (view.step != NewMemberStep.READY) return@action ActionResult.Failed(view.reason ?: MembersCopy.VERIFY_FIRST)
        val who = view.verified?.email ?: n.email
        val token = membersScreen.now()
        busy()
        try {
            runBounded(BoundedOps.FLAT_MS) { live.engine.addVaultMember(n.vaultId, n.served.userId, role, n.email) }
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            return@action failure(t, MembersCopy::forAdd)
        }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        if (newMember === n) newMember = null
        rereadMembers(live, n.vaultId, token) { rows -> rows + VaultMemberSummary(n.served.userId, who, n.served.displayName, role, n.served.identityPub, clocks.wallMs()) }
        val after = membersView(live, n.vaultId)
        update { it.copy(busy = false, members = if (membersScreen.still(token)) after else it.members, notice = MembersCopy.added(who, after?.vaultName, role)) }
        ActionResult.Ok
    }

    /** Make a member a writer or a reader (owner). Their devices follow at their next sync. */
    @Throws(CancellationException::class)
    suspend fun setMemberRole(userId: String, role: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val open = state.members ?: return@action ActionResult.NotDone(null)
        if (!open.owner) return@action ActionResult.Failed(SharingCopy.OWNER_ONLY)
        if (role !in MEMBER_ROLES) return@action ActionResult.Failed(MembersCopy.BAD_ROLE)
        val member = membersRead?.firstOrNull { it.userId == userId } ?: return@action ActionResult.Failed(MembersCopy.MEMBER_GONE)
        if (member.role == "owner" || member.userId == live.account.userId) return@action ActionResult.Failed(MembersCopy.OWNER_STAYS)
        if (member.role == role) return@action ActionResult.Ok
        val token = membersScreen.now()
        busy()
        runBounded(BoundedOps.FLAT_MS) { live.api.setVaultMemberRole(open.vaultId, userId, role) }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        rereadMembers(live, open.vaultId, token) { rows -> rows.map { if (it.userId == userId) it.copy(role = role) else it } }
        update { it.copy(busy = false, members = if (membersScreen.still(token)) membersView(live, open.vaultId) else it.members, notice = MembersCopy.roleChanged(member.displayName, role)) }
        ActionResult.Ok
    }

    /**
     * Remove a member (owner), with the removal proof their devices check (core [SyncEngine.removeVaultMember]). They keep
     * whatever they already saw: the vault's key is not changed.
     */
    @Throws(CancellationException::class)
    suspend fun removeMember(userId: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val open = state.members ?: return@action ActionResult.NotDone(null)
        if (!open.owner) return@action ActionResult.Failed(SharingCopy.OWNER_ONLY)
        val member = membersRead?.firstOrNull { it.userId == userId } ?: return@action ActionResult.Failed(MembersCopy.MEMBER_GONE)
        if (member.role == "owner" || member.userId == live.account.userId) return@action ActionResult.Failed(MembersCopy.OWNER_STAYS)
        val token = membersScreen.now()
        busy()
        runBounded(BoundedOps.FLAT_MS) { live.engine.removeVaultMember(open.vaultId, userId) }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        rereadMembers(live, open.vaultId, token) { rows -> rows.filterNot { it.userId == userId } }
        val invitations = invitationViews(live)
        update {
            it.copy(
                busy = false, items = summaries(it.query), vaultNotices = vaultNotices(live), invitations = invitations,
                members = if (membersScreen.still(token)) membersView(live, open.vaultId) else it.members,
                notice = MembersCopy.removed(member.displayName, open.vaultName),
            )
        }
        ActionResult.Ok
    }

    // ---- handing a vault over (spec 03 §11: TRANSFER) ----

    /**
     * Offer to make a member the owner (owner). Nothing changes until they accept in their app, within 14 days; until
     * then the owner can cancel. Only to someone verified on this device (sharing review 2026-11, item 4), named as they
     * were recorded then. The offer's proof is made with the vault's key, which every member holds, so it tells their
     * devices only that some member made it; this account's devices know it as their own by their record of the offers
     * it made ([SyncEngine.offerTransfer]). Afterwards they manage the vault and this account stays in it as a writer.
     */
    @Throws(CancellationException::class)
    suspend fun offerOwnership(userId: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val open = state.members ?: return@action ActionResult.NotDone(null)
        if (!open.owner) return@action ActionResult.Failed(SharingCopy.OWNER_ONLY)
        if (!open.canAdd) return@action ActionResult.Failed(MembersCopy.OWNERSHIP_UNCONFIRMED_TRANSFER)
        if (open.offer != null) return@action ActionResult.Failed(MembersCopy.OFFER_PENDING)
        val member = membersRead?.firstOrNull { it.userId == userId } ?: return@action ActionResult.Failed(MembersCopy.MEMBER_GONE)
        if (member.role == "owner" || member.userId == live.account.userId) return@action ActionResult.Failed(MembersCopy.OWNER_ALREADY)
        if ((member.status ?: "active") != "active") return@action ActionResult.Failed(MembersCopy.DISABLED_CANNOT_OWN)
        if (memberCheck(live, member.userId, member.identityPub) != MemberCheck.VERIFIED) return@action ActionResult.Failed(MembersCopy.VERIFY_BEFORE_HANDOVER)
        val name = verifiedNameOf(live, member.userId) ?: member.displayName
        val token = membersScreen.now()
        busy()
        try {
            runBounded(BoundedOps.FLAT_MS) { live.engine.offerTransfer(open.vaultId, userId) }
        } catch (e: MemberNotVerifiedException) {
            if (session.get() !== live) return@action ActionResult.NotDone(null)
            return@action idleFailed(MembersCopy.VERIFY_BEFORE_HANDOVER)
        }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        rereadMembers(live, open.vaultId, token) { it }
        update { it.copy(busy = false, members = if (membersScreen.still(token)) membersView(live, open.vaultId) else it.members, notice = MembersCopy.offered(name, open.vaultName)) }
        ActionResult.Ok
    }

    /** Take back the offer to hand the open vault over (owner), before it was accepted. */
    @Throws(CancellationException::class)
    suspend fun cancelOwnershipOffer(): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val open = state.members ?: return@action ActionResult.NotDone(null)
        if (!open.owner) return@action ActionResult.Failed(SharingCopy.OWNER_ONLY)
        if (open.offer == null) return@action ActionResult.Ok
        val token = membersScreen.now()
        busy()
        runBounded(BoundedOps.FLAT_MS) { live.engine.cancelTransfer(open.vaultId) }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        update { it.copy(busy = false, members = if (membersScreen.still(token)) membersView(live, open.vaultId) else it.members, notice = MembersCopy.OFFER_CANCELLED) }
        ActionResult.Ok
    }

    /**
     * Become the owner of a vault an offer was made for ([AppState.ownershipOffers]). The engine checks the offer under
     * the vault's key again before it acts, and seals the vault's key to this account as its owner.
     */
    @Throws(CancellationException::class)
    suspend fun acceptOwnership(vaultId: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val offer = state.ownershipOffers.firstOrNull { it.vaultId == vaultId } ?: return@action ActionResult.Failed(MembersCopy.OFFER_GONE)
        busy()
        // Sharing review 2026-11 (item 2): the offer shown, and no other.
        runBounded(BoundedOps.FLAT_MS) { live.engine.acceptTransfer(vaultId, offer.offerId) }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        publishSharing(live, MembersCopy.ownershipAccepted(offer.vaultName))
        ActionResult.Ok
    }

    /** Say no to an offer to become a vault's owner: the vault stays as it is, and its owner keeps it. */
    @Throws(CancellationException::class)
    suspend fun declineOwnership(vaultId: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val offer = state.ownershipOffers.firstOrNull { it.vaultId == vaultId } ?: return@action ActionResult.Ok
        busy()
        runBounded(BoundedOps.FLAT_MS) { live.engine.cancelTransfer(vaultId) }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        publishSharing(live, MembersCopy.ownershipDeclined(offer.vaultName))
        ActionResult.Ok
    }

    /** The verified offers to make this account a vault's owner. Each owner's name is asked for once, in the background. */
    private fun ownershipOfferViews(live: VaultSession.Unlocked): List<OwnershipOfferView> {
        val now = clocks.wallMs()
        val offers = runCatching { live.engine.incomingTransfers() }.getOrDefault(emptyList()).filter { it.expiresAt > now }
        for (o in offers) if (o.vaultId !in offerOwners && offerOwnerAsks.add(o.vaultId)) askOfferOwner(live, o.vaultId)
        return offers.sortedBy { it.vaultName }.map { OwnershipOfferView(it.vaultId, it.vaultName, it.offerId, offerOwners[it.vaultId], it.expiresAt) }
    }

    private fun askOfferOwner(live: VaultSession.Unlocked, vaultId: String) {
        scope.launch {
            val owner = try {
                runBounded(BoundedOps.FLAT_MS) { live.api.vaultMembers(vaultId) }.firstOrNull { it.role == "owner" }
            } catch (t: Throwable) {
                if (t is CancellationException) throw t
                return@launch // unnamed: the offer still verified under the vault's key
            } ?: return@launch
            if (session.get() !== live) return@launch
            offerOwners[vaultId] = owner.displayName
            update { s -> s.copy(ownershipOffers = s.ownershipOffers.map { if (it.vaultId == vaultId) it.copy(from = owner.displayName) else it }) }
        }
    }

    // ---- "You own <vault>?" and sharing again under the signed kind (root cause A §8.2 step 4, A6b) ----
    //
    // The server's word that this account owns a vault never lets this device sign or seal anything for it. A vault made
    // before andvari kept its own record of ownership needs the person to say so once, with their master password; then
    // the members the server lists as still on the older kind of sharing can be shared with again, one confirmed person
    // at a time, sealed to the key this device verified for them.

    /**
     * Step 1 of "You own <vault>?": load what the server reports of [vaultId] (who it lists as the owner, its last
     * handover, who else holds it) to show before the master password is asked for. Records nothing.
     */
    @Throws(CancellationException::class)
    suspend fun describeOwnership(vaultId: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val vault = vaultList(live).firstOrNull { it.vaultId == vaultId && it.type == "shared" } ?: return@action ActionResult.Failed(SharingCopy.VAULT_GONE)
        if (vault.role != "owner") return@action ActionResult.Failed(SharingCopy.OWNER_ONLY)
        if (live.engine.ownsVault(vaultId)) return@action ActionResult.Ok
        claim = null
        update { it.copy(ownershipClaim = null) }
        busy()
        val described = try {
            runBounded(BoundedOps.FLAT_MS) { live.engine.describeOwnership(vaultId) }
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            if (session.get() !== live) return@action ActionResult.NotDone(null)
            return@action failure(t, MembersCopy::forClaim)
        }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        claim = described
        update { it.copy(busy = false, ownershipClaim = claimView(described, vault.name)) }
        ActionResult.Ok
    }

    private fun claimView(c: OwnershipClaim, fallbackName: String): OwnershipClaimView {
        val who = { h: CoHolder -> if (h.displayName.isNotEmpty()) "${h.displayName} (${h.email})" else MembersCopy.SOMEONE_UNNAMED }
        val history = c.lastTransferTo?.let { "Last handed over to ${who(it)}, handover #${c.lastTransferSeq}" }
            ?: "Created by ${c.reportedOwner?.let(who) ?: "an owner the server didn't name"}; never handed over"
        val others = if (c.coHolders.isEmpty()) "no one else" else c.coHolders.joinToString("; ") { "${who(it)}, ${it.role}" }
        return OwnershipClaimView(
            vaultId = c.vaultId, vaultName = c.vaultName ?: fallbackName,
            lines = listOf("$history (as the server reports it).", "Also in this vault: $others (as the server reports it)."),
            receivedAsMember = c.receivedAsMember,
        )
    }

    /** Close "You own <vault>?" without confirming. */
    fun cancelOwnershipClaim() {
        guarded({}) {
            claim = null
            session.get()?.engine?.cancelOwnershipClaim()
            update { it.copy(ownershipClaim = null) }
        }
    }

    /**
     * Step 2: the person confirmed that they own the vault, with their master password (checked on this device, against
     * the key this session holds) and, for a vault this device first received as a member, [handedOver]: that its owner
     * handed it to them. Records the vault as this account's own; adding members and handing it over work from then on.
     */
    @Throws(CancellationException::class)
    suspend fun confirmOwnership(password: String, handedOver: Boolean): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val described = claim ?: return@action ActionResult.NotDone(null)
        val name = state.ownershipClaim?.vaultName
        if (password.isEmpty()) return@action ActionResult.Failed(MembersCopy.PASSWORD_REQUIRED)
        if (described.receivedAsMember && !handedOver) return@action ActionResult.Failed(MembersCopy.HANDED_OVER_REQUIRED)
        busy()
        try {
            runBounded(BoundedOps.FLAT_MS) { live.engine.confirmOwnership(described, password, handedOver) }
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            if (session.get() !== live) return@action ActionResult.NotDone(null)
            return@action failure(t, MembersCopy::forOwnershipConfirm)
        }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        claim = null
        update { it.copy(ownershipClaim = null, members = it.members?.let { m -> membersView(live, m.vaultId) ?: m }) }
        publishSharing(live, MembersCopy.ownershipConfirmed(name))
        val open = state.members
        if (open != null && open.vaultId == described.vaultId && open.canAdd) loadLegacyGrants(live, open.vaultId, membersScreen.now())
        ActionResult.Ok
    }

    /**
     * Share the open vault again with [userId], whom the server lists as still on the older kind of sharing: signed by
     * this account and sealed to the key this device verified for them (core refuses anyone not verified here, or whose
     * key the server has since changed). Only someone the list offered, in a vault this account's own record says it owns.
     */
    @Throws(CancellationException::class)
    suspend fun reshareWithMember(userId: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val open = state.members ?: return@action ActionResult.NotDone(null)
        if (!open.canAdd) return@action ActionResult.Failed(MembersCopy.OWNERSHIP_UNCONFIRMED)
        val row = live.engine.legacyGrantRows(open.vaultId).firstOrNull { it.userId == userId } ?: return@action ActionResult.Failed(MembersCopy.MEMBER_GONE)
        val shown = open.legacy.firstOrNull { it.userId == userId }
        if (shown?.check != MemberCheck.VERIFIED) return@action ActionResult.Failed(MembersCopy.VERIFY_FIRST)
        val token = membersScreen.now()
        busy()
        try {
            runBounded(BoundedOps.FLAT_MS) { live.engine.confirmReissue(row) }
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            if (session.get() !== live) return@action ActionResult.NotDone(null)
            return@action failure(t, MembersCopy::forReshare)
        }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        val notice = MembersCopy.reshared(open.vaultName, shown.verifiedLabel ?: shown.name)
        if (membersScreen.still(token)) update { it.copy(busy = false, members = membersView(live, open.vaultId), notice = notice) } else update { it.copy(busy = false, notice = notice) }
        ActionResult.Ok
    }

    // ---- comparing identity codes (root cause A §7.2) ----

    /** Compare codes with a member listed on the open members screen (not verified here, or their key changed). */
    fun verifyListedMember(userId: String): ActionResult = guarded({ ActionResult.Failed(HouseholdCopy.forError(it)) }) {
        val live = session.get() ?: return@guarded ActionResult.NotDone(null)
        val member = membersRead?.firstOrNull { it.userId == userId } ?: return@guarded ActionResult.Failed(MembersCopy.MEMBER_GONE)
        if (member.userId == live.account.userId) return@guarded ActionResult.Failed(MembersCopy.THATS_YOU)
        openVerification(live, VerifyTarget(UserLookupResponse(member.userId, member.displayName, member.identityPub), email = null, invitation = null))
    }

    /** Compare codes with the person being added; the address typed to find them is recorded with the verification. */
    fun verifyNewMember(): ActionResult = guarded({ ActionResult.Failed(HouseholdCopy.forError(it)) }) {
        val live = session.get() ?: return@guarded ActionResult.NotDone(null)
        val n = newMember ?: return@guarded ActionResult.Failed(MembersCopy.LOOK_UP_AGAIN)
        val view = newMemberView(live, n)
        when (view.step) {
            NewMemberStep.READY -> ActionResult.NotDone(null)
            NewMemberStep.REFUSED -> ActionResult.Failed(view.reason ?: MembersCopy.MISMATCH_ADD)
            else -> openVerification(live, VerifyTarget(n.served, n.email, invitation = null))
        }
    }

    /** Compare codes with whoever sent an invitation. The server says who that is; the codes check it. */
    @Throws(CancellationException::class)
    suspend fun verifyInvitation(id: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val invitation = live.engine.pendingInvitations().firstOrNull { it.grantIdB64 == id } ?: return@action ActionResult.Failed(MembersCopy.INVITATION_GONE)
        busy()
        val sender = runBounded(BoundedOps.FLAT_MS) { live.engine.invitationSender(invitation) }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        if (sender.userId != invitation.fromUserId) return@action idleFailed(MembersCopy.SENDER_UNKNOWN)
        invitationSenders[id] = sender.displayName
        val invitations = invitationViews(live)
        update { it.copy(busy = false, invitations = invitations) }
        openVerification(live, VerifyTarget(sender, email = null, invitation = invitation))
    }

    private fun openVerification(live: VaultSession.Unlocked, target: VerifyTarget): ActionResult {
        val view = VerifyView(
            serverName = target.served.displayName, email = target.email?.let(ContactPin::normalizeEmail), invitation = target.invitation != null,
            myCode = live.account.identityFingerprintShort(), myQr = live.engine.identityQrPayload(),
        )
        verifyTarget = target
        update { it.copy(verifying = view) }
        return ActionResult.Ok
    }

    /** Put the comparison away. Nothing was recorded. */
    fun cancelVerifying() {
        verifyTarget = null
        update { it.copy(verifying = null) }
    }

    /**
     * They read their code from THEIR screen and it was typed here: 32 hex, spaces and case aside. It is compared with the
     * key the server serves for them, and only a match records them as verified (for an invitation, it also opens the
     * vault it shares). A mismatch records nothing.
     */
    @Throws(CancellationException::class)
    suspend fun verifyWithCode(code: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val target = verifyTarget ?: return@action ActionResult.NotDone(null)
        if (code.lowercase().count { it in HEX_DIGITS } != Fingerprint.SHORT_HEX_LEN) return@action ActionResult.Failed(MembersCopy.CODE_LENGTH)
        busy()
        val matched = try {
            runBounded(BoundedOps.FLAT_MS) {
                val invitation = target.invitation
                if (invitation != null) live.engine.acceptInvitation(invitation, code) else live.engine.verifyMemberTyped(target.served, code, target.email) != null
            }
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            return@action failure(t, MembersCopy::forVerifySave)
        }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        if (!matched) {
            val invitations = invitationViews(live)
            update { it.copy(invitations = invitations) }
            return@action idleFailed(if (target.invitation != null) MembersCopy.INVITATION_MISMATCH else MembersCopy.CODE_MISMATCH)
        }
        verified(live, target)
    }

    /**
     * Their identity QR code was scanned: [payload] exactly as read. It must name the account being verified and match the
     * key the server serves for it at full length; only then are they recorded as verified.
     */
    @Throws(CancellationException::class)
    suspend fun verifyWithQr(payload: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val target = verifyTarget ?: return@action ActionResult.NotDone(null)
        val parsed = IdentityQr.parse(payload) ?: return@action ActionResult.Failed(MembersCopy.QR_NOT_IDENTITY)
        if (parsed.userId != target.served.userId) return@action ActionResult.Failed(MembersCopy.QR_OTHER_ACCOUNT)
        busy()
        val matched = try {
            runBounded(BoundedOps.FLAT_MS) {
                val invitation = target.invitation
                if (invitation != null) live.engine.acceptInvitationQr(invitation, payload) else live.engine.verifyMemberQr(target.served, payload, target.email) != null
            }
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            return@action failure(t, MembersCopy::forVerifySave)
        }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        if (!matched) {
            val invitations = invitationViews(live)
            update { it.copy(invitations = invitations) }
            return@action idleFailed(if (target.invitation != null) MembersCopy.INVITATION_QR_MISMATCH else MembersCopy.QR_MISMATCH)
        }
        verified(live, target)
    }

    /** A match: the comparison closes, and what it changed shows (the members, the person being added, or the vault an invitation shares). */
    private fun verified(live: VaultSession.Unlocked, target: VerifyTarget): ActionResult {
        val current = verifyTarget === target
        if (current) verifyTarget = null
        val invitation = target.invitation
        if (invitation == null) {
            update { s ->
                s.copy(
                    busy = false, verifying = if (current) null else s.verifying, members = s.members?.let { m -> membersView(live, m.vaultId) ?: m },
                    household = s.household?.let { householdView(live) }, notice = MembersCopy.verified(target.served.displayName),
                )
            }
            return ActionResult.Ok
        }
        val vault = vaultList(live).firstOrNull { it.vaultId == invitation.vaultId }?.name
        val invitations = invitationViews(live)
        val reviews = legacyReviewViews(live)
        update { s ->
            s.copy(
                busy = false, verifying = if (current) null else s.verifying, items = summaries(s.query), vaultNotices = vaultNotices(live), invitations = invitations,
                legacyReviews = reviews, sharing = s.sharing?.let { sharingView(live) }, notice = MembersCopy.invitationAccepted(target.served.displayName, vault),
            )
        }
        writeFillSnapshot()
        backgroundSync() // what the vault holds comes in with the next sync; the person need not wait for it
        return ActionResult.Ok
    }

    // ---- the people this account verified (root cause A §7.2; Android's "Household members you've verified") ----

    private val householdScreen = ScreenToken()

    /**
     * Open the list of the people this account verified ([AppState.household]): the account's own record, read again from
     * the server (sealed so only this account can read it) and merged with this device's copy.
     */
    @Throws(CancellationException::class)
    suspend fun openHousehold(): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val token = householdScreen.open()
        update { it.copy(household = householdView(live)) }
        busy()
        try {
            runBounded(BoundedOps.FLAT_MS) { live.engine.accountState.refresh() }
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            if (session.get() !== live) return@action ActionResult.NotDone(null)
            if (!householdScreen.still(token)) return@action screenGone()
            return@action failure(t, HouseholdCopy::forError) // this device's copy stays listed
        }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        if (!householdScreen.still(token)) return@action screenGone()
        update { it.copy(busy = false, household = householdView(live)) }
        ActionResult.Ok
    }

    fun closeHousehold() {
        householdScreen.close()
        update { it.copy(household = null) }
    }

    private fun householdView(live: VaultSession.Unlocked): HouseholdView {
        val record = live.engine.accountState
        val warning = when (record.anomaly) {
            AccountStateSync.Anomaly.ROLLBACK -> MembersCopy.RECORD_ROLLED_BACK
            AccountStateSync.Anomaly.UNREADABLE -> MembersCopy.RECORD_UNREADABLE
            null -> null
        }
        val contacts = record.contacts().filter { it.userId != live.account.userId }.sortedWith(compareBy({ (it.email ?: it.label).lowercase() }, { it.userId })).map {
            ContactView(it.userId, it.email, it.label, it.method, it.verifiedAt, confirmedHere = record.isCurrent(it))
        }
        return HouseholdView(contacts, warning)
    }

    /** Look up the account for an address typed to verify someone; the codes are compared next ([AppState.verifying]). */
    @Throws(CancellationException::class)
    suspend fun findHouseholdMember(email: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val typed = email.trim()
        if (typed.isEmpty()) return@action ActionResult.Failed(MembersCopy.EMAIL_REQUIRED)
        busy()
        val served = try {
            runBounded(BoundedOps.FLAT_MS) { live.engine.lookupMember(typed) }
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            if (session.get() !== live) return@action ActionResult.NotDone(null)
            return@action failure(t, MembersCopy::forLookup)
        }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        if (served.userId == live.account.userId) return@action idleFailed(MembersCopy.THATS_YOU)
        update { it.copy(busy = false) }
        openVerification(live, VerifyTarget(served, typed, invitation = null))
    }

    /**
     * Take someone off the people this account verified, on all its devices: shared vaults from them are invitations
     * again, and adding them to a vault asks for the codes again. Vaults already shared stay as they are.
     */
    @Throws(CancellationException::class)
    suspend fun removeContact(userId: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val contact = live.engine.accountState.contacts().firstOrNull { it.userId == userId } ?: return@action ActionResult.Failed(MembersCopy.CONTACT_GONE)
        busy()
        runBounded(BoundedOps.FLAT_MS) { live.engine.unpinMember(userId) }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        update {
            it.copy(
                busy = false, household = it.household?.let { householdView(live) }, members = it.members?.let { m -> membersView(live, m.vaultId) ?: m },
                notice = MembersCopy.contactRemoved(contact.email ?: contact.label),
            )
        }
        ActionResult.Ok
    }

    // ---- invitations (root cause A §1.6) ----

    /** The invitations the vault screen lists. Each sender's name is asked for once, in the background. */
    private fun invitationViews(live: VaultSession.Unlocked): List<InvitationView> {
        val pending = runCatching { live.engine.pendingInvitations() }.getOrDefault(emptyList())
        for (invitation in pending) if (invitation.grantIdB64 !in invitationSenders && invitationAsks.add(invitation.grantIdB64)) askSender(live, invitation)
        return pending.map { InvitationView(it.grantIdB64, invitationSenders[it.grantIdB64]) }
    }

    private fun askSender(live: VaultSession.Unlocked, invitation: PendingInvitation) {
        scope.launch {
            val sender = try {
                runBounded(BoundedOps.FLAT_MS) { live.engine.invitationSender(invitation) }
            } catch (t: Throwable) {
                if (t is CancellationException) throw t
                return@launch // unnamed: the person can still verify them
            }
            if (session.get() !== live || sender.userId != invitation.fromUserId) return@launch
            invitationSenders[invitation.grantIdB64] = sender.displayName
            update { s -> s.copy(invitations = s.invitations.map { if (it.id == invitation.grantIdB64) it.copy(from = sender.displayName) else it }) }
        }
    }

    /** Hide an invitation on this device. A new one from the same person asks again. */
    fun declineInvitation(id: String) {
        guarded({}) {
            val live = session.get() ?: return@guarded
            val invitation = live.engine.pendingInvitations().firstOrNull { it.grantIdB64 == id } ?: return@guarded
            live.engine.declineInvitation(invitation)
            if (verifyTarget?.invitation?.grantIdB64 == id) cancelVerifying()
            val invitations = invitationViews(live)
            update { it.copy(invitations = invitations) }
        }
    }

    // ---- shared vaults awaiting review (root cause A §8.2) ----

    /** The vaults readable only through an older kind of sharing nobody vouched for. Each owner's name is asked for once, in the background. */
    private fun legacyReviewViews(live: VaultSession.Unlocked): List<LegacyReviewView> {
        val vaults = runCatching { live.engine.legacyReviewVaults() }.getOrDefault(emptyList())
        for (v in vaults) if (v.vaultId !in reviewOwners && reviewOwnerAsks.add(v.vaultId)) askReviewOwner(live, v.vaultId)
        return vaults.sortedWith(compareBy({ it.name == null }, { it.name?.lowercase() }, { it.vaultId }))
            .map { LegacyReviewView(it.vaultId, it.name, it.itemCount, reviewOwners[it.vaultId]) }
    }

    private fun askReviewOwner(live: VaultSession.Unlocked, vaultId: String) {
        scope.launch {
            val owner = try {
                runBounded(BoundedOps.FLAT_MS) { listOfNotNull(live.engine.reportedOwner(vaultId)) }.firstOrNull()
            } catch (t: Throwable) {
                if (t is CancellationException) throw t
                return@launch // unnamed: the person can still accept or leave it
            } ?: return@launch
            if (session.get() !== live) return@launch
            reviewOwners[vaultId] = owner.displayName
            update { s -> s.copy(legacyReviews = s.legacyReviews.map { if (it.vaultId == vaultId) it.copy(owner = owner.displayName) else it }) }
        }
    }

    /**
     * "Accept" on a vault awaiting review (trust on first use, said plainly): this device vouches for the key the server
     * delivered, the vault stops being read only, and this account's own wrap of its key is stored with the server.
     */
    @Throws(CancellationException::class)
    suspend fun acceptLegacyVault(vaultId: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val review = legacyReviewViews(live).firstOrNull { it.vaultId == vaultId } ?: return@action ActionResult.Failed(MembersCopy.REVIEW_GONE)
        busy()
        try {
            runBounded(BoundedOps.FLAT_MS) { live.engine.acceptLegacyVault(vaultId) }
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            if (session.get() !== live) return@action ActionResult.NotDone(null)
            return@action failure(t, MembersCopy::forAccept)
        }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        publishSharing(live, MembersCopy.reviewAccepted(review.name))
        ActionResult.Ok
    }

    /** This account's identity QR code payload (`andvari-id:1:…`), over the key this device holds; null while locked. */
    fun identityQr(): String? = guarded({ null }) { session.get()?.engine?.identityQrPayload() }

    // ---- two-step sign-in (spec 03 §2: a TOTP factor the server checks at sign-in) ----

    /**
     * The key being set up (round-6 review L4), with when it was minted and whose it is (this server and account). It
     * is held while the two-step screen is open and through a trip away from the app (to add it to an authenticator,
     * which may lock the app), for at most [TWO_STEP_PENDING_MS] from when the server minted it: a lock keeps it, and
     * after the next unlock the screen comes back on its confirm step ([resumeTwoStep]). A sign-out, a server switch, an
     * ended session, its time running out (at once, locked or not: [expireTwoStepKey]), a confirm, or closing the screen
     * while unlocked drop it. Only the key and its
     * link are kept, never the password. It never enters the state.
     */
    private class PendingTwoStep(val setup: TwoStepSetup, val mintedAtMs: Long, val owner: String)

    private var twoStepPending: PendingTwoStep? = null

    /** This server and account, as a pending key records whose it is. */
    private fun ownerOf(live: VaultSession.Unlocked): String = (store.baseUrl?.let(OriginCanon::originKey) ?: "") + "/" + live.account.userId

    /** Whether a key being set up is held (tests: what a lock or a revocation keeps). */
    internal fun holdsTwoStepKey(): Boolean = twoStepPending != null

    /** The pending key while it is [live]'s and in time; one past its time, or another account's, is dropped here. */
    private fun pendingTwoStep(live: VaultSession.Unlocked): TwoStepSetup? {
        val pending = twoStepPending ?: return null
        val age = clocks.monotonicMs() - pending.mintedAtMs
        if (age !in 0 until TWO_STEP_PENDING_MS || pending.owner != ownerOf(live)) {
            twoStepPending = null
            return null
        }
        return pending.setup
    }

    /**
     * A key being set up goes when its time is up, locked or not (round-8 review L): the ticker looks every second, so it
     * is not kept in memory past [TWO_STEP_PENDING_MS] while the app runs. A screen setting it up goes back to its start.
     */
    private fun expireTwoStepKey() {
        val pending = twoStepPending ?: return
        if (clocks.monotonicMs() - pending.mintedAtMs in 0 until TWO_STEP_PENDING_MS) return
        twoStepPending = null
        if (state.twoStep?.settingUp == true) update { it.copy(twoStep = it.twoStep?.copy(settingUp = false, resumed = false)) }
    }

    /** Back from a trip away in the middle of a setup: the two-step screen opens again on its confirm step. */
    private fun resumeTwoStep() {
        val live = session.get() ?: return
        if (pendingTwoStep(live) == null) return
        update { it.copy(twoStep = TwoStepView(enrolled = false, settingUp = true, resumed = true)) }
    }

    /** Read whether two-step sign-in is on ([AppState.twoStep]). */
    @Throws(CancellationException::class)
    suspend fun loadTwoStep(): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val token = twoStepScreen.open()
        busy()
        val status = try {
            runBounded(BoundedOps.FLAT_MS) { live.api.totpStatus() }
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            return@action failure(t, HouseholdCopy::forTotpError)
        }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        if (!twoStepScreen.still(token)) return@action screenGone()
        update { it.copy(busy = false, twoStep = TwoStepView(status.enrolled, settingUp = pendingTwoStep(live) != null)) }
        ActionResult.Ok
    }

    /**
     * Start setting up two-step sign-in. The master password is the proof the server asks for (one key derivation,
     * off the main thread); the new key is held here ([twoStepSetup]) until a code from it confirms it.
     */
    @Throws(CancellationException::class)
    suspend fun beginTwoStep(password: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        if (password.isEmpty()) return@action ActionResult.NotDone(null)
        val token = twoStepScreen.now()
        busy()
        val setup = try {
            runBounded(BoundedOps.FLAT_MS) { withContext(Dispatchers.Default) { live.api.totpSetupWithPassword(password, live.account) } }
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            return@action failure(t, HouseholdCopy::forTotpError)
        }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        // The screen closed meanwhile: the new key is not held (the server drops it unconfirmed).
        if (!twoStepScreen.still(token)) return@action screenGone()
        val link = authenticatorLink(setup.secretBase32, setup.otpauthUri, store.baseUrl?.let(::hostOf) ?: "")
        twoStepPending = PendingTwoStep(TwoStepSetup(setup.secretBase32, link), clocks.monotonicMs(), ownerOf(live))
        update { it.copy(busy = false, twoStep = TwoStepView(enrolled = it.twoStep?.enrolled ?: false, settingUp = true)) }
        ActionResult.Ok
    }

    /** The key being set up, to show (as a QR code and as text) while unlocked; null when none is. */
    fun twoStepSetup(): TwoStepSetup? = guarded({ null }) { session.get()?.let(::pendingTwoStep) }

    /** Confirm the key being set up with a code it shows now: two-step sign-in is on from here. */
    @Throws(CancellationException::class)
    suspend fun confirmTwoStep(code: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        if (pendingTwoStep(live) == null) return@action ActionResult.NotDone(null)
        val token = twoStepScreen.now()
        busy()
        val status = try {
            runBounded(BoundedOps.FLAT_MS) { live.api.totpConfirm(code.trim()) }
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            return@action failure(t, HouseholdCopy::forTotpError) // the key stays up for another try
        }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        twoStepPending = null
        // Confirmed on the server either way; the screen is only redrawn while it is open.
        val open = twoStepScreen.still(token)
        update { it.copy(busy = false, twoStep = if (open) TwoStepView(status.enrolled, settingUp = false) else it.twoStep, notice = if (status.enrolled) ItemCopy.TWO_STEP_ON else it.notice) }
        ActionResult.Ok
    }

    /** Turn two-step sign-in off, with a current code from the authenticator. */
    @Throws(CancellationException::class)
    suspend fun disableTwoStep(code: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val token = twoStepScreen.now()
        busy()
        val status = try {
            runBounded(BoundedOps.FLAT_MS) { live.api.totpDisable(code.trim()) }
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            return@action failure(t, HouseholdCopy::forTotpError)
        }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        val open = twoStepScreen.still(token)
        update { it.copy(busy = false, twoStep = if (open) TwoStepView(status.enrolled, settingUp = false) else it.twoStep, notice = if (!status.enrolled) ItemCopy.TWO_STEP_OFF else it.notice) }
        ActionResult.Ok
    }

    /**
     * The two-step screen closed. Closed by the person (unlocked), a key not yet confirmed is forgotten (the server drops
     * it unconfirmed). Closed because the app locked, the key stays for the trip ([twoStepPending]).
     */
    fun closeTwoStep() {
        twoStepScreen.close()
        if (session.get() != null) twoStepPending = null
        update { it.copy(twoStep = null) }
    }

    // ---- lifecycle notices (spec 03 §11) ----

    /** What the last syncs said about shared vaults, as the vault screen shows it. */
    private fun vaultNotices(live: VaultSession.Unlocked): List<VaultNoticeView> =
        runCatching { live.engine.notices() }.getOrDefault(emptyList()).map { n ->
            val (text, warning) = LifecycleNoticeCopy.body(n)
            VaultNoticeView(n.id, text, warning)
        }

    /** The person has read one notice: it goes until something new happens. */
    fun dismissVaultNotice(id: String) {
        val live = session.get() ?: return
        runCatching { live.engine.dismissNotice(id) }
        update { it.copy(vaultNotices = vaultNotices(live)) }
    }

    // ---- vaults: where a new item goes, and moving or copying one (design §8, F18/F19) ----

    private fun vaultList(live: VaultSession.Unlocked): List<VaultInfo> = runCatching { live.engine.vaultInfos() }.getOrDefault(emptyList())

    /**
     * The vaults this account can put an item in: its personal vault first, then the shared vaults it owns or writes, by
     * name, each one it holds the key of. The one rule Android's view model uses too ([VaultMoves.writableVaults]).
     */
    private fun writableVaults(live: VaultSession.Unlocked): List<VaultInfo> = VaultMoves.writableVaults(vaultList(live), live.account::canSealUnder)

    private fun choiceOf(v: VaultInfo) = VaultChoiceView(v.vaultId, v.name, personal = v.type == "personal")

    /**
     * Where a new item may go: the personal vault first (the default the editors start on), then the shared vaults this
     * account can write. A shared vault is only ever the person's own choice: nothing here or in a save picks one.
     */
    fun vaultsForNewItems(): List<VaultChoiceView> = guarded({ emptyList() }) {
        session.get()?.let { live -> writableVaults(live).map(::choiceOf) }.orEmpty()
    }

    /** Why a new item cannot go to [vaultId] (null: the personal vault), or null when it can. */
    private fun newHomeRefusal(live: VaultSession.Unlocked, vaultId: String?): ActionResult? = when {
        vaultId != null -> if (writableVaults(live).any { it.vaultId == vaultId }) null else ActionResult.Failed(ItemCopy.VAULT_NOT_WRITABLE)
        // A9 review LOW-2: a new item never goes to a guessed vault.
        live.account.personalVaultId.isEmpty() -> ActionResult.Failed(HouseholdCopy.NO_PERSONAL_VAULT)
        else -> null
    }

    /**
     * The vaults [itemId] can be copied to, and moved to when [canMoveOut]: the writable ones but its own
     * ([VaultMoves.targets]). An item in a vault this account only reads can still be copied out.
     */
    fun moveTargets(itemId: String): List<VaultChoiceView> = guarded({ emptyList() }) {
        val live = session.get() ?: return@guarded emptyList()
        val item = live.engine.item(itemId) ?: return@guarded emptyList()
        VaultMoves.targets(item.vaultId, vaultList(live), live.account::canSealUnder).map(::choiceOf)
    }

    /** Whether [itemId] can be moved out of its vault (a move deletes it there), not only copied ([VaultMoves.canTakeOut]). */
    fun canMoveOut(itemId: String): Boolean = guarded({ false }) {
        val live = session.get() ?: return@guarded false
        val item = live.engine.item(itemId) ?: return@guarded false
        VaultMoves.canTakeOut(item.vaultId, vaultList(live))
    }

    /**
     * Moves and copies that did not finish, by item, target and kind ([VaultMoves]): kept until done or cancelled, so
     * that Try again replays the same ids, and across a lock sealed to the account in app-private storage (they name
     * new attachment keys, so never in memory while locked).
     */
    private val moves = VaultMoves(VaultMoves.Store.Sealed(moveMemoLog, ::droppedEarlier) { session.get()?.account })

    /** The person cancelled moving or copying [itemId]: what an unfinished try kept goes. A lock is not a cancel. */
    fun cancelMove(itemId: String) {
        if (session.get() == null) return
        guarded({}) { moves.cancelled(itemId) }
    }

    /**
     * Move (copy, then delete the original) or copy [itemId] into [targetVaultId], one of [moveTargets]. Attachments are
     * copied too. A target that refuses the copy, or an item that changed meanwhile, stops it with the original
     * untouched.
     */
    @Throws(CancellationException::class)
    suspend fun moveOrCopyItem(itemId: String, targetVaultId: String, move: Boolean): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val current = live.engine.item(itemId) ?: return@action ActionResult.Failed(ITEM_GONE)
        val vaults = vaultList(live)
        if (move && !VaultMoves.canTakeOut(current.vaultId, vaults)) return@action ActionResult.Failed(ItemCopy.READ_ONLY)
        if (VaultMoves.targets(current.vaultId, vaults, live.account::canSealUnder).none { it.vaultId == targetVaultId }) {
            return@action ActionResult.Failed(ItemCopy.VAULT_NOT_WRITABLE)
        }
        val target = vaultName(live, targetVaultId) ?: "the other vault"
        val source = vaultName(live, current.vaultId) ?: "its vault"
        val name = current.doc.name.ifBlank { "This item" }
        val gesture = when (val prepared = try {
            moves.prepare(live.engine, current, targetVaultId, move) { runBounded(BoundedOps.FLAT_MS) { live.engine.sync() } }
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            // A kept try could not be checked against the target (offline): nothing is replayed unchecked.
            return@action idleFailed(ItemCopy.MOVE_RETRY)
        }) {
            is VaultMoves.Prepared.AlreadyCopied -> return@action ActionResult.Failed(VaultMoves.alreadyCopiedLine(name, target, prepared.changedSince))
            is VaultMoves.Prepared.Run -> prepared.gesture
        }
        busy()
        try {
            // Audit H10: the gesture re-uploads the item's attachments, so its bound scales with their bytes.
            saves.exclusive { runBounded(BoundedOps.attachmentMs(current.doc.attachments.sumOf { it.size })) { live.engine.runGesture(gesture) } }
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            val failed = moves.failed(itemId, targetVaultId, move, t)
            if (session.get() !== live) return@action ActionResult.NotDone(null)
            return@action when (failed) {
                VaultMoves.Failure.COPY_DENIED -> idleFailed(ItemCopy.MOVE_DENIED)
                VaultMoves.Failure.CHANGED_AFTER_COPY, VaultMoves.Failure.ORIGINAL_KEPT -> {
                    // The copy is there: the list shows it, and the message says where both are.
                    update { it.copy(items = summaries(it.query)) }
                    writeFillSnapshot()
                    idleFailed(VaultMoves.bothVaultsLine(failed, name, target, source) ?: ItemCopy.MOVE_CHANGED)
                }
                VaultMoves.Failure.FORBIDDEN -> failure(t, HouseholdCopy::forError)
                // Transient: the gesture is kept, so Try again replays the same ids.
                VaultMoves.Failure.TRANSIENT -> idleFailed(ItemCopy.MOVE_RETRY)
            }
        }
        moves.finished(itemId, targetVaultId, move)
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        update { it.copy(busy = false, items = summaries(it.query), vaultNotices = vaultNotices(live), notice = if (move) "Moved to “$target”." else "Copied to “$target”.") }
        writeFillSnapshot()
        ActionResult.Ok
    }

    /** Delete an item (it goes to the server's trash). */
    @Throws(CancellationException::class)
    suspend fun deleteItem(itemId: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        busy()
        val outcome = saves.exclusive {
            live.engine.remove(itemId).also { if (session.get() === live) runCatching { saves.itemDeletedLocked(live, itemId) } }
        }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        update { it.copy(busy = false, items = summaries(it.query), notice = if (outcome == SaveOutcome.QUEUED) HouseholdCopy.SAVE_OFFLINE else it.notice) }
        writeFillSnapshot()
        ActionResult.Ok
    }

    // ---- vault health (design 2026-08-23; the Android app's health screen) ----
    //
    // Every ranking, cluster, survivor and refusal is core's (VaultHealth, Duplicates, Staleness); this carries them to the
    // screen and writes only what they plan, each write an ordinary save or delete of the item in its own vault. A breach
    // check sends the server the first 5 hex characters of each distinct password's SHA-1 and nothing more: the server
    // fetches that range of the breach list for this device and the match is made here. The verdicts stay in memory, by
    // item, for the session. andvari never tries a password anywhere: a person signs in and says what happened.

    /** What the health screen holds while it is open. */
    private var health: HealthSession? = null

    /** The last breach check of this session; a lock forgets it. */
    private var breaches: BreachVerdicts? = null

    /** Open vault health ([AppState.health]). The usage record (when each login was last used) is read in the background. */
    fun openHealth() {
        guarded({}) {
            val live = session.get() ?: return@guarded
            val h = HealthSession()
            health = h
            publishHealth(live)
            readUsage(live, h)
        }
    }

    fun closeHealth() {
        health = null
        update { it.copy(health = null) }
    }

    /** The screen again from the vault as it is now (an item opened from it may have changed). */
    fun refreshHealth() {
        guarded({}) { session.get()?.let(::publishHealth) }
    }

    /** List the logins snoozed for now too. The counts at the top never change with it. */
    fun setHealthShowSnoozed(show: Boolean) {
        guarded({}) {
            val live = session.get() ?: return@guarded
            health?.showSnoozed = show
            publishHealth(live)
        }
    }

    fun dismissHealthMessage() {
        guarded({}) {
            val live = session.get() ?: return@guarded
            health?.message = null
            publishHealth(live)
        }
    }

    private fun publishHealth(live: VaultSession.Unlocked) {
        val view = healthNow(live) ?: return
        update { it.copy(health = view) }
    }

    /** The open health screen as the vault is now; null when it is closed. A run whose login is gone ends. */
    private fun healthNow(live: VaultSession.Unlocked): HealthView? {
        val h = health ?: return null
        val names = vaultList(live).associate { it.vaultId to it.name }
        fun build() = healthView(
            h, live.engine.items(), runCatching { live.engine.pendingSyncItemIds() }.getOrDefault(emptySet()), breaches,
            { live.account.roleFor(it) }, { names[it] ?: "Shared" }, clocks.wallMs(),
        )
        val view = build()
        if (!h.running || view.run != null) return view
        h.queue = emptyList()
        h.index = 0
        return build()
    }

    /** The usage record, for "last used" (other devices record uses). A ranking hint: nothing is said when it can't be read. */
    private fun readUsage(live: VaultSession.Unlocked, h: HealthSession) {
        scope.launch {
            val read = try {
                val sealed = runBounded(BoundedOps.FLAT_MS) { live.api.usage() }.sealedUsage
                if (sealed == null) emptyMap() else UsageLedger.parse(live.account.openUsage(sealed).decodeToString())
            } catch (t: Throwable) {
                if (t is CancellationException) throw t
                return@launch
            }
            if (session.get() !== live || health !== h) return@launch
            h.usage = read
            publishHealth(live)
        }
    }

    /**
     * Check every login's password against known breaches (spec 03 §8, k-anonymity). Each distinct password is hashed
     * here, and only the first 5 hex characters of its SHA-1 go to the server, which fetches that range for this device;
     * the match is made here. A range that can't be fetched leaves its logins without a verdict, never "none", and a check
     * in which no range came back keeps the last verdicts. Closing the screen or locking stops it, keeping nothing.
     */
    @Throws(CancellationException::class)
    suspend fun checkBreaches(): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val h = health ?: return@action ActionResult.NotDone(null)
        if (h.scan != null) return@action ActionResult.NotDone(null)
        val items = live.engine.items()
        val rows = VaultHealth.healthRows(items)
        if (rows.isEmpty()) return@action ActionResult.Ok
        // The revision each verdict is about, taken with the passwords: a sync during the check must not pair the two.
        val revs = items.associate { it.itemId to it.rev }
        val crypto = live.account.cryptoProvider()
        val hashes = withContext(Dispatchers.Default) { rows.map { it.password }.distinct().associateWith { Hibp.sha1UpperHex(crypto, it) } }
        val byPrefix = hashes.entries.groupBy({ Hibp.prefix(it.value) }, { it.key })
        h.message = null
        h.scan = ScanProgressView(0, byPrefix.size)
        publishHealth(live)
        val counts = HashMap<String, Long>()
        var failed = 0
        var done = 0
        for ((prefix, passwords) in byPrefix) {
            val range = try {
                runBounded(BoundedOps.FLAT_MS) { live.api.hibpRange(prefix) }
            } catch (t: Throwable) {
                if (t is CancellationException) throw t
                null
            }
            if (session.get() !== live || health !== h) return@action ActionResult.NotDone(null)
            if (range == null) failed++ else for (pw in passwords) counts[pw] = Hibp.countInRange(range, hashes.getValue(pw))
            done++
            h.scan = ScanProgressView(done, byPrefix.size)
            publishHealth(live)
        }
        h.scan = null
        if (failed == byPrefix.size) {
            h.message = HealthCopy.SCAN_FAILED
        } else {
            val byItem = rows.mapNotNull { r -> counts[r.password]?.let { r.itemId to it } }.toMap()
            breaches = BreachVerdicts(byItem, byItem.keys.mapNotNull { id -> revs[id]?.let { id to it } }.toMap(), incomplete = failed > 0)
            h.message = if (failed > 0) HealthCopy.SCAN_INCOMPLETE else HealthCopy.scanDone(rows.count { (byItem[it.itemId] ?: 0L) > 0L })
        }
        publishHealth(live)
        ActionResult.Ok
    }

    /** One health action: a refusal or failure is said on the health screen, where it was asked for. */
    private suspend fun healthAction(block: suspend (VaultSession.Unlocked, HealthSession) -> ActionResult): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val h = health ?: return@action ActionResult.NotDone(null)
        val result = try {
            block(live, h)
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            failure(t, HouseholdCopy::forSaveError)
        }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        if (health === h && result is ActionResult.Failed) h.message = result.message
        update { it.copy(busy = false, items = summaries(it.query), health = healthNow(live) ?: it.health) }
        writeFillSnapshot()
        result
    }

    private fun clusterOf(live: VaultSession.Unlocked, signature: String): Duplicates.DuplicateCluster? =
        Duplicates.duplicateClusters(live.engine.items()) { live.account.roleFor(it) }.firstOrNull { it.signature == signature }

    private suspend fun saveIn(live: VaultSession.Unlocked, itemId: String, doc: ItemDoc) {
        // INV-EDIT: in the vault the item is in now; core refuses a save that would move it.
        val vaultId = live.engine.item(itemId)?.vaultId
        saves.exclusive { live.engine.save(itemId, doc, vaultId) }
    }

    private suspend fun trash(live: VaultSession.Unlocked, itemId: String) {
        saves.exclusive { live.engine.remove(itemId).also { if (session.get() === live) runCatching { saves.itemDeletedLocked(live, itemId) } } }
    }

    /**
     * Save the survivor core composed, then move the other copies to the trash. The survivor goes first, so nothing is
     * removed before what it carries has landed; a failure after it is a partial state, and [partial] says so.
     */
    private suspend fun runMerge(live: VaultSession.Unlocked, h: HealthSession, plan: Duplicates.MergePlan, success: (Int) -> String, partial: String): ActionResult {
        busy()
        saveIn(live, plan.survivorId, plan.doc)
        try {
            for (id in plan.loserIds) trash(live, id)
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            return ActionResult.Failed(partial)
        }
        h.message = success(plan.loserIds.size)
        return ActionResult.Ok
    }

    /** Merge copies that have the same password (core's plan: saved sites from every copy are kept). */
    @Throws(CancellationException::class)
    suspend fun mergeDuplicates(signature: String): ActionResult = healthAction { live, h ->
        val cluster = clusterOf(live, signature)
        val plan = cluster?.merge ?: return@healthAction ActionResult.Failed(cluster?.mergeRefusal ?: HealthCopy.GROUP_CHANGED)
        runMerge(live, h, plan, HealthCopy::merged, HealthCopy.MERGE_DIDNT_FINISH)
    }

    /**
     * Keep one of copies with different passwords, the one the person found still works: the others go to the trash, and
     * their passwords into the kept login's password history first.
     */
    @Throws(CancellationException::class)
    suspend fun keepDuplicate(signature: String, keepId: String): ActionResult = healthAction { live, h ->
        val cluster = clusterOf(live, signature) ?: return@healthAction ActionResult.Failed(HealthCopy.GROUP_CHANGED)
        val plan = Duplicates.planKeep(live.engine.items(), cluster.members.map { it.itemId }, keepId, { live.account.roleFor(it) }, clocks.wallMs())
        val keep = plan.keep ?: return@healthAction ActionResult.Failed(plan.keepRefusal ?: HealthCopy.GROUP_CHANGED)
        runMerge(live, h, keep, HealthCopy::kept, HealthCopy.KEEP_DIDNT_FINISH)
    }

    /** "Not duplicates": every copy is marked with the group as it is, so it stays quiet until one of them changes. */
    @Throws(CancellationException::class)
    suspend fun markNotDuplicates(signature: String): ActionResult = acknowledgeCluster(signature, restoring = false)

    /** Put a group marked "not duplicates" back on the list. */
    @Throws(CancellationException::class)
    suspend fun restoreDuplicates(signature: String): ActionResult = acknowledgeCluster(signature, restoring = true)

    private suspend fun acknowledgeCluster(signature: String, restoring: Boolean): ActionResult = healthAction { live, h ->
        val cluster = clusterOf(live, signature) ?: return@healthAction ActionResult.Failed(HealthCopy.GROUP_CHANGED)
        val plan = Duplicates.planDismiss(live.engine.items(), cluster.members.map { it.itemId }, if (restoring) "" else cluster.signature) { live.account.roleFor(it) }
        val writes = plan.writes ?: return@healthAction ActionResult.Failed(plan.dismissRefusal ?: HealthCopy.GROUP_CHANGED)
        busy()
        var written = 0
        try {
            for (w in writes) {
                saveIn(live, w.itemId, w.doc)
                written++
            }
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            if (written == 0) throw t // nothing landed: the ordinary save failure is the honest sentence
            return@healthAction ActionResult.Failed(HealthCopy.NOT_EVERY_COPY)
        }
        h.message = if (restoring) HealthCopy.BACK_ON_THE_LIST else HealthCopy.NOT_DUPLICATES
        ActionResult.Ok
    }

    /** Check logins one at a time, from the list as it is shown: all of them, worst first, or only the never-checked. */
    fun startCheckRun(neverCheckedOnly: Boolean) {
        guarded({}) {
            val live = session.get() ?: return@guarded
            val h = health ?: return@guarded
            val rows = healthNow(live)?.staleness.orEmpty().filter { !neverCheckedOnly || it.neverChecked }
            beginRun(live, h, rows.map { it.itemId })
        }
    }

    /** Check one login. */
    fun checkLogin(itemId: String) {
        guarded({}) {
            val live = session.get() ?: return@guarded
            val h = health ?: return@guarded
            beginRun(live, h, listOf(itemId))
        }
    }

    private fun beginRun(live: VaultSession.Unlocked, h: HealthSession, queue: List<String>) {
        if (queue.isEmpty()) return
        h.queue = queue
        h.index = 0
        h.message = null
        h.offerDelete = null
        h.offerBad = null
        publishHealth(live)
    }

    /** Move on without a verdict: "I didn't check this" is not one, so nothing is written. */
    fun skipCheck() {
        guarded({}) {
            val live = session.get() ?: return@guarded
            health?.let(::advanceRun)
            publishHealth(live)
        }
    }

    fun stopCheckRun() {
        guarded({}) {
            val live = session.get() ?: return@guarded
            health?.let { it.queue = emptyList(); it.index = 0 }
            publishHealth(live)
        }
    }

    private fun advanceRun(h: HealthSession) {
        val next = h.index + 1
        if (next < h.queue.size) {
            h.index = next
            return
        }
        h.queue = emptyList()
        h.index = 0
        h.message = HealthCopy.RUN_FINISHED
    }

    /**
     * What the person found when they signed in at the site themselves: "ok", "bad", "gone", or "blocked" (couldn't
     * finish, which also snoozes the login for 30 days). Only the verdict is written, on the item. A refusal keeps the
     * run where it is; a verdict on the login the run stands on moves it on. "gone" offers the trash, "bad" a new password.
     */
    @Throws(CancellationException::class)
    suspend fun recordCheck(itemId: String, result: String): ActionResult = healthAction { live, h ->
        if (result !in HealthCopy.CHECK_RESULTS) return@healthAction ActionResult.Failed(HealthCopy.CHOOSE_RESULT)
        val snooze = if (result == "blocked") Staleness.SNOOZE_MS else null
        val plan = Staleness.planCheck(live.engine.items(), itemId, result, clocks.wallMs(), { live.account.roleFor(it) }, snooze)
        val write = plan.write ?: return@healthAction ActionResult.Failed(plan.refusal ?: HealthCopy.GROUP_CHANGED)
        busy()
        h.message = null
        saveIn(live, write.itemId, write.doc)
        h.offerDelete = if (result == "gone") itemId else null
        h.offerBad = if (result == "bad") itemId else null
        if (h.running && h.queue.getOrNull(h.index) == itemId) advanceRun(h)
        ActionResult.Ok
    }

    /** Bring a snoozed login back into the list now; its verdict stays. */
    @Throws(CancellationException::class)
    suspend fun unsnoozeLogin(itemId: String): ActionResult = healthAction { live, h ->
        val plan = Staleness.planUnsnooze(live.engine.items(), itemId) { live.account.roleFor(it) }
        val write = plan.write ?: return@healthAction plan.refusal?.let { ActionResult.Failed(it) } ?: ActionResult.Ok
        busy()
        saveIn(live, write.itemId, write.doc)
        h.message = HealthCopy.BACK_ON_THE_LIST
        ActionResult.Ok
    }

    /** The login just marked as gone, to the trash (it can be restored from there for 30 days). */
    @Throws(CancellationException::class)
    suspend fun trashGoneLogin(): ActionResult = healthAction { live, h ->
        val itemId = h.offerDelete ?: return@healthAction ActionResult.NotDone(null)
        busy()
        trash(live, itemId)
        h.offerDelete = null
        h.message = HealthCopy.TRASHED
        ActionResult.Ok
    }

    /** "Keep it": the verdict stays recorded; only the offer goes. */
    fun keepGoneLogin() {
        guarded({}) {
            val live = session.get() ?: return@guarded
            health?.offerDelete = null
            publishHealth(live)
        }
    }

    /**
     * The offer after "bad", answered. Taken ([opening]): the person is about to change that password, so the run ends
     * here rather than waiting behind them. Declined: only the offer goes. Nothing is written either way.
     */
    fun answerBadOffer(opening: Boolean) {
        guarded({}) {
            val live = session.get() ?: return@guarded
            val h = health ?: return@guarded
            h.offerBad = null
            if (opening) {
                h.offerDelete = null
                h.queue = emptyList()
                h.index = 0
            }
            publishHealth(live)
        }
    }

    // ---- importing a CSV export (spec 06; the universal importer, design 2026-07-11; the Android app's flow) ----
    //
    // The file is read, parsed and planned on this device. Nothing of it goes to the server as it is: each planned item
    // is encrypted here under the chosen vault's key and sent like any other save. The plan is made against the items
    // already in that vault (core's dedupe), and only ever sent into the vault it was made for.

    /** The import screen's file and plan, while it is open. */
    private var csv: CsvSession? = null

    /**
     * Read a CSV export and plan its import into the personal vault, against what is already there. [bytes] are zeroed
     * once read. Nothing is sent until [confirmImport].
     */
    @Throws(CancellationException::class)
    suspend fun importCsv(bytes: ByteArray): ActionResult = action {
        try {
            val live = session.get() ?: return@action ActionResult.NotDone(null)
            if (bytes.size > CsvImport.MAX_BYTES) return@action ActionResult.Failed(ImportCopy.TOO_LARGE)
            // Planned only against a vault this device holds: an empty projection would quietly switch the dedupe off.
            val personal = live.account.personalVaultId
            if (personal.isEmpty() || vaultList(live).none { it.vaultId == personal }) return@action ActionResult.Failed(ImportCopy.NO_VAULT)
            busy()
            val read = try {
                withContext(Dispatchers.Default) { CsvImport.parse(bytes) to CsvImport.rowOrdinalsByLine(bytes) }
            } catch (e: CsvImport.ImportException) {
                return@action failure(e) { ImportCopy.forCode(e.code) }
            } catch (t: Throwable) {
                if (t is CancellationException) throw t
                return@action failure(t, HouseholdCopy::forImportError)
            }
            if (session.get() !== live) return@action ActionResult.NotDone(null)
            val s = CsvSession(read.first, read.second, looksMangled(read.first))
            s.vaultId = personal
            val existing = live.engine.importProjections(personal)
            s.plan = withContext(Dispatchers.Default) { CsvImport.plan(s.parsed, existing) { live.account.newItemId() } }
            if (session.get() !== live) return@action ActionResult.NotDone(null)
            csv = s
            publishImport(live)
            idle()
            ActionResult.Ok
        } finally {
            bytes.fill(0)
        }
    }

    /** Import into [vaultId] instead: the plan is made again against that vault's items. Only before the import began. */
    @Throws(CancellationException::class)
    suspend fun setImportVault(vaultId: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val s = csv ?: return@action ActionResult.NotDone(null)
        if (s.busy || s.error != null || s.done || vaultId == s.vaultId) return@action ActionResult.NotDone(null)
        if (writableVaults(live).none { it.vaultId == vaultId }) return@action ActionResult.Failed(ImportCopy.VAULT_GONE)
        s.busy = true
        publishImport(live)
        val plan = try {
            val existing = live.engine.importProjections(vaultId)
            withContext(Dispatchers.Default) { CsvImport.plan(s.parsed, existing) { live.account.newItemId() } }
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            null
        } finally {
            s.busy = false
        }
        if (session.get() !== live || csv !== s) return@action ActionResult.NotDone(null)
        if (plan == null) {
            publishImport(live)
            return@action ActionResult.Failed(ImportCopy.NO_VAULT)
        }
        // The plan and its vault change together: a plan is never sent into another vault than the one it was made for.
        s.plan = plan
        s.vaultId = vaultId
        publishImport(live)
        ActionResult.Ok
    }

    /**
     * Encrypt and send the planned items into the chosen vault. A failure keeps the plan: Retry sends the same items,
     * under the same ids, so nothing is imported twice.
     */
    @Throws(CancellationException::class)
    suspend fun confirmImport(): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val s = csv ?: return@action ActionResult.NotDone(null)
        val plan = s.plan ?: return@action ActionResult.NotDone(null)
        if (s.busy || s.done || plan.items.isEmpty()) return@action ActionResult.NotDone(null)
        val vaultId = s.vaultId
        s.busy = true
        s.error = null
        s.retryable = true
        s.progress = ScanProgressView(0, plan.items.size)
        publishImport(live)
        val failed = try {
            runBounded(BoundedOps.importMs(plan.items.size)) {
                live.engine.importAll(plan.items, onProgress = { done, total ->
                    if (csv === s) {
                        s.progress = ScanProgressView(done, total)
                        publishImport(live)
                    }
                }, vaultId = vaultId)
            }
            null
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            t
        }
        s.busy = false
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        if (failed is UpgradeRequiredException) return@action failure(failed, HouseholdCopy::forError)
        when {
            failed != null -> {
                s.retryable = importRetryable(failed)
                s.error = if (s.retryable) ImportCopy.INTERRUPTED else HouseholdCopy.forError(failed)
            }
            // A vault deleted while importing parks the items rather than refusing them: that is not a success.
            vaultList(live).none { it.vaultId == vaultId } -> {
                s.retryable = false
                s.error = ImportCopy.PARKED
            }
            else -> {
                s.done = true
                s.progress = null
            }
        }
        update { it.copy(items = summaries(it.query)) }
        writeFillSnapshot()
        publishImport(live)
        ActionResult.Ok
    }

    /** Close the import: the parsed file and the plan go. */
    fun closeImport() {
        csv = null
        update { it.copy(csvImport = null) }
    }

    // ---- export and backup (spec 07; the Android and desktop apps' flows on core's Export and ExportPlanner) ----
    //
    // The file is made in memory when the person has chosen a folder, handed to the platform to write there once, read
    // back and compared; it is never written anywhere else, so no copy of a plaintext CSV outlives the export.

    private var exporting: ExportSession? = null

    /**
     * Open the export screen for [kind]: a sync first (spec 07: an export holds what the server has; offline, the vault as
     * of the last sync, which the screen says), then what the export would hold, by vault. Nothing is made until the
     * person has chosen a folder ([csvFile], [backupFile]).
     */
    @Throws(CancellationException::class)
    suspend fun openExport(kind: ExportKind): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        busy()
        val offline = try {
            runBounded(BoundedOps.FLAT_MS) { syncNow(live.engine) }
            false
        } catch (e: kotlinx.io.IOException) {
            true
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            if (session.get() !== live) return@action ActionResult.NotDone(null)
            return@action failure(t, HouseholdCopy::forError) // a refused sync is said, never exported over
        }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        val s = ExportSession(kind, ExportPlanner.vaultLines(live.engine, live.account), live.account.personalVaultId)
        if (offline) s.offlineNote = ExportCopy.offline(store.lastSyncAt.takeIf { it > 0 }?.let(LifecycleNoticeCopy::englishDay))
        exporting = s
        publishExport(live)
        idle()
        ActionResult.Ok
    }

    /** Put a shared vault in the export or leave it out; the personal vault is always in. */
    fun setExportVault(vaultId: String, included: Boolean) {
        val live = session.get() ?: return
        val s = exporting ?: return
        if (s.busy || vaultId == s.personalId || s.lines.none { it.vaultId == vaultId }) return
        s.included = if (included) s.included + vaultId else s.included - vaultId
        s.error = null
        s.done = null
        publishExport(live)
    }

    /** Backup: whether the files attached to its items go in (up to the 64 MiB cap; the rest are named). */
    fun setExportAttachments(include: Boolean) {
        val live = session.get() ?: return
        val s = exporting?.takeIf { it.kind == ExportKind.BACKUP && !it.busy } ?: return
        s.includeAttachments = include
        s.done = null
        publishExport(live)
    }

    fun closeExport() {
        exporting = null
        update { it.copy(exporting = null) }
    }

    /**
     * The CSV for the folder the person chose: exactly the logins the screen counted, once the tick ([acknowledged])
     * covers the formula cells it listed. The cells are worked out again from what is written: a vault that changed
     * meanwhile writes nothing, and the screen comes back with the new list. Null when nothing is to be written (the
     * screen says why). The bytes are plaintext: the caller writes them once, to that folder, and zeroes them.
     */
    fun csvFile(acknowledged: Boolean): ExportFile? {
        val live = session.get() ?: return null
        val s = exporting?.takeIf { it.kind == ExportKind.CSV && !it.busy } ?: return null
        s.done = null
        val docs = ExportPlanner.orderedItems(live.engine, s.order()).map { it.doc }
        val refusal = when {
            docs.none { it.type == "login" } -> ExportCopy.NOTHING_TO_EXPORT
            s.shownCells.isNotEmpty() && !acknowledged -> ExportCopy.FORMULA_ACK_NEEDED
            else -> null
        }
        if (refusal != null) {
            s.error = refusal
            publishExport(live)
            return null
        }
        return when (val gated = ExportCsv.gatedWrite(docs, if (acknowledged) s.shownCells else null)) {
            is ExportCsv.GatedWrite.NeedsAcknowledgement -> {
                s.error = ExportCopy.VAULT_CHANGED
                publishExport(live)
                null
            }
            is ExportCsv.GatedWrite.Ready -> {
                s.error = null
                s.made = ExportMade(gated.loginCount, 0, 0, 0, emptyList())
                ExportFile("andvari-export-${exportDate()}.csv", gated.csv.encodeToByteArray())
            }
        }
    }

    /**
     * The backup for the folder the person chose (spec 07 §2): made in memory under [passphrase], which must be typed
     * twice the same and be at least "good", then opened again under it, every file in it read back, before it is handed
     * over: what is written is a backup that opens. Files go in when chosen, up to the 64 MiB cap; one that does not
     * download twice is left out, by name. Null when nothing is to be written (the screen says why).
     */
    @Throws(CancellationException::class)
    suspend fun backupFile(passphrase: String, confirm: String): ExportFile? {
        val live = session.get() ?: return null
        val s = exporting?.takeIf { it.kind == ExportKind.BACKUP && !it.busy } ?: return null
        s.done = null
        val refusal = when {
            passphrase.isEmpty() -> ExportCopy.PASSPHRASE_REQUIRED
            passphrase != confirm -> ExportCopy.PASSPHRASES_DIFFER
            Strength.estimateStrength(passphrase) < Strength.BACKUP_FLOOR -> ExportCopy.PASSPHRASE_WEAK
            s.order().isEmpty() -> ExportCopy.NOTHING_TO_EXPORT
            else -> null
        }
        if (refusal != null) {
            s.error = refusal
            publishExport(live)
            return null
        }
        s.busy = true
        s.error = null
        publishExport(live)
        try {
            val made = withContext(Dispatchers.Default) { makeBackup(live, s, passphrase) }
            if (session.get() !== live || exporting !== s) {
                made.second.fill(0)
                return null
            }
            s.made = made.first
            return ExportFile("andvari-backup-${exportDate()}.andvari", made.second)
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            if (exporting === s) s.error = if (t is BackupVerifyException) ExportCopy.VERIFY_FAILED else HouseholdCopy.forError(t)
            return null
        } finally {
            s.busy = false
            if (session.get() === live && exporting === s) publishExport(live)
        }
    }

    /** The file was written to [folder] as [fileName] and read back the same: the screen says what it holds. */
    fun exportSaved(fileName: String, folder: String) {
        val live = session.get() ?: return
        val s = exporting ?: return
        val made = s.made ?: return
        s.made = null
        s.error = null
        s.done = when (s.kind) {
            ExportKind.CSV -> ExportCopy.csvSaved(fileName, folder, made.logins)
            ExportKind.BACKUP -> ExportCopy.backupSaved(fileName, folder, made.items, made.vaults, made.files) +
                (if (made.skipped.isEmpty()) "" else " " + ExportCopy.filesSkipped(made.skipped))
        }
        session.touch() // an export counts as use, for the idle lock
        publishExport(live)
    }

    /** Nothing was saved: the folder could not be written to, or ([written]) the file did not read back the same and the
     *  caller removed it. */
    fun exportNotSaved(written: Boolean) {
        val live = session.get() ?: return
        val s = exporting ?: return
        s.made = null
        s.error = if (written) ExportCopy.READ_BACK_FAILED else ExportCopy.WRITE_FAILED
        publishExport(live)
    }

    private fun publishExport(live: VaultSession.Unlocked) {
        val s = exporting ?: return
        val items = ExportPlanner.orderedItems(live.engine, s.order())
        val view = if (s.kind == ExportKind.CSV) {
            val docs = items.map { it.doc }
            val warnings = ExportCsv.warnings(docs)
            // What a tick acknowledges: the cells shown now (re-checked against what is written, [csvFile]).
            s.shownCells = warnings.formulaCells
            exportView(s, warnings, docs.count { it.type == "login" }, items.size, null)
        } else {
            exportView(s, null, 0, items.size, ExportPlanner.planAttachments(items))
        }
        update { it.copy(exporting = view) }
    }

    /** spec 07 §2: build in memory, then open again and read every file back; the made file and what it holds. */
    private suspend fun makeBackup(live: VaultSession.Unlocked, s: ExportSession, passphrase: String): Pair<ExportMade, ByteArray> {
        val account = live.account
        val engine = live.engine
        val crypto = account.cryptoProvider()
        val order = s.order()
        val lines = s.lines.filter { it.vaultId in order }
        val items = ExportPlanner.orderedItems(engine, order)
        val undecryptable = ExportPlanner.undecryptable(engine).filter { it.vaultId in order }
        val formatVersions = engine.envelopes().associate { it.itemId to it.formatVersion }
        val plan = if (s.includeAttachments) ExportPlanner.planAttachments(items) else io.silencelen.andvari.core.client.AttachmentPlan(emptyList(), 0L, emptyList())
        val fetched = ArrayList<Pair<io.silencelen.andvari.core.client.PlannedAttachment, ByteArray>>()
        val fetchFailed = ArrayList<String>()
        try {
            for (p in plan.included) {
                var bytes: ByteArray? = null
                for (attempt in 0 until 2) {
                    bytes = runCatching { runBounded(BoundedOps.attachmentMs(p.ref.size)) { engine.downloadAttachment(p.ref) } }.getOrNull()
                    if (bytes != null) break
                }
                if (bytes == null) fetchFailed.add(AttachmentRules.safeFileName(p.ref.name)) else fetched.add(p to bytes)
            }
            // Each file goes in under a fresh key of its own (spec 07 §2.4); the items keep theirs.
            val freshKeys = fetched.map { account.newFileKey() }
            val manifest = fetched.mapIndexed { i, (p, bytes) ->
                io.silencelen.andvari.core.client.BackupAttachmentEntry(
                    section = i + 1, attachmentId = p.ref.id, itemId = p.item.itemId,
                    name = p.ref.name, size = bytes.size.toLong(), fileKey = Bytes.toB64(freshKeys[i]),
                )
            }
            val payload = io.silencelen.andvari.core.client.BackupPayload(
                exportedAt = clocks.wallMs(),
                origin = store.baseUrl ?: "",
                userId = account.userId,
                identityFingerprint = account.identityFingerprintShort(),
                vaults = lines.map { io.silencelen.andvari.core.client.BackupVault(it.vaultId, it.type, it.name, it.role) },
                items = items.map { io.silencelen.andvari.core.client.BackupItem(it.itemId, it.vaultId, formatVersions[it.itemId] ?: 1, it.updatedAt, it.doc) },
                attachments = manifest,
                skipped = io.silencelen.andvari.core.client.BackupSkipped(undecryptable, plan.overCap, fetchFailed),
            )
            // The policy's KDF cost, within what a backup may ask of the device that opens it (spec 07 §2.2).
            val policyParams = coordinator.livePolicy?.kdfParams ?: io.silencelen.andvari.core.crypto.KdfParams.DEFAULT
            val kdfParams = if (policyParams.ops <= io.silencelen.andvari.core.client.Backup.MAX_KDF_OPS && policyParams.memBytes <= io.silencelen.andvari.core.client.Backup.MAX_KDF_MEM_BYTES) {
                policyParams
            } else {
                io.silencelen.andvari.core.crypto.KdfParams.DEFAULT
            }
            val chunks = ArrayList<ByteArray>()
            val sections = fetched.mapIndexed { i, (_, bytes) -> io.silencelen.andvari.core.client.Backup.AttachmentSection(freshKeys[i]) { bytes } }
            io.silencelen.andvari.core.client.Backup.build(
                crypto = crypto, passphrase = passphrase,
                fileId = account.newItemId(), kdfSalt = crypto.randomBytes(io.silencelen.andvari.core.crypto.KdfParams.SALT_BYTES),
                kdfParams = kdfParams, payload = payload, attachments = sections,
            ) { chunks.add(it.copyOf()) }
            val file = ByteArray(chunks.sumOf { it.size })
            var at = 0
            for (c in chunks) {
                c.copyInto(file, at)
                at += c.size
            }
            // Opened again under the same passphrase, every file read back (spec 07 §2.6): only a backup that opens leaves.
            val opened = try {
                io.silencelen.andvari.core.client.Backup.open(crypto, passphrase, file)
            } catch (e: Exception) {
                file.fill(0)
                throw BackupVerifyException()
            }
            if (opened.payload != payload) {
                file.fill(0)
                throw BackupVerifyException()
            }
            for (entry in opened.payload.attachments) {
                val plain = opened.readAttachment(entry)
                val ok = plain.size.toLong() == entry.size
                plain.fill(0)
                if (!ok) {
                    file.fill(0)
                    throw BackupVerifyException()
                }
            }
            return ExportMade(0, items.size, lines.size, manifest.size, plan.overCap + fetchFailed) to file
        } finally {
            fetched.forEach { it.second.fill(0) } // Backup.build zeroes what it consumed; a throw before it leaves stragglers
        }
    }

    /** Today's date for the file's name, as the other apps name it (yyyy-MM-dd, this device's time zone). */
    private fun exportDate(): String =
        kotlinx.datetime.Instant.fromEpochMilliseconds(clocks.wallMs()).toLocalDateTime(kotlinx.datetime.TimeZone.currentSystemDefault()).date.toString()

    /** A made backup did not open again as made (spec 07 §2.6): nothing is handed over. */
    private class BackupVerifyException : Exception("the backup did not open again as made")

    private fun publishImport(live: VaultSession.Unlocked) {
        val s = csv ?: return
        val names = vaultList(live).associate { it.vaultId to it.name }
        update { it.copy(csvImport = csvImportView(s, { id -> names[id] ?: "this vault" }, writableVaults(live).map(::choiceOf))) }
    }

    /** A failed import push worth a Retry: a transport blip, a rate limit or a server error converge on the same items. */
    private fun importRetryable(t: Throwable): Boolean = when {
        t is KdfPolicyViolationException -> false
        t is ApiException -> t.code == "rate_limited" || t.status == 429 || t.status >= 500
        else -> true
    }

    /** A file copied out of a web page arrives HTML-escaped: said when more than one value carries an entity. */
    private fun looksMangled(parsed: CsvImport.Parsed): Boolean {
        val entity = Regex("&(amp|lt|gt|quot|#\\d+);")
        var hits = 0
        for (r in parsed.rows) for (v in listOf(r.name, r.url, r.username, r.password, r.notes, r.totp ?: "")) {
            if (entity.containsMatchIn(v) && ++hits >= 2) return true
        }
        return false
    }

    /** Sync now. */
    @Throws(CancellationException::class)
    suspend fun refresh(): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        busy()
        try {
            syncNow(live.engine)
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            return@action failure(t, HouseholdCopy::forSyncError)
        }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        val invitations = invitationViews(live)
        val offers = ownershipOfferViews(live)
        val reviews = legacyReviewViews(live)
        update {
            it.copy(
                busy = false, items = summaries(it.query), vaultNotices = vaultNotices(live), invitations = invitations, ownershipOffers = offers,
                legacyReviews = reviews, health = healthNow(live) ?: it.health, notice = SYNCED,
            )
        }
        writeFillSnapshot()
        refreshPersonalVault() // a sync can change what the server says the personal vault is
        ActionResult.Ok
    }

    /** A new password under [settings]. */
    fun generatePassword(settings: GeneratorSettings): String = guarded({ "" }) {
        val options = GeneratorOptions(settings.length, settings.lower, settings.upper, settings.digits, settings.symbols, settings.avoidAmbiguous)
        runCatching { PasswordGenerator.generate(crypto, options) }.getOrElse {
            // Settings no password can satisfy (every class off): the standard ones, at the asked length.
            PasswordGenerator.generate(crypto, GeneratorOptions(length = settings.length.coerceIn(8, 128)))
        }
    }

    // ---- the session ----

    /** Lock now: the keys leave memory; the stored session stays for the next unlock. */
    fun lock() = lock(REASON_LOCKED)

    /** Sign out: the session is ended at the server, and this account's data on this device is deleted. */
    @Throws(CancellationException::class)
    suspend fun signOut(): ActionResult = action {
        if (state.busy) return@action ActionResult.NotDone(null)
        val stored = store.load()
        val live = session.get()
        busy()
        // The revocation is AWAITED (bounded) before the teardown: a logout racing the transport's close would leave
        // the refresh token valid for its whole lifetime.
        if (live != null) {
            runCatching { withTimeoutOrNull(LOGOUT_MS) { live.api.logout() } }
        } else if (stored != null) {
            // A locked sign-out: no live holder, but the stored refresh token is still valid at the server. Revoke it
            // at the session's OWN origin (A14, F8).
            val a = clients.forSession(stored, stored.baseUrl)
            runCatching { withTimeoutOrNull(LOGOUT_MS) { a.logout() } }
            a.close()
        }
        session.lock() // the engine releases its cache before the cache is deleted
        forgetSessionViews()
        zeroSecrets()
        dropFillSnapshot() // whatever the stored session says: nothing shared with the extensions outlives a sign-out
        stored?.userId?.let { userId ->
            // §4.2: the namespace of the origin the session lived at; other origins are never touched.
            store.baseUrl?.let(OriginCanon::originKey)?.let { originKey ->
                namespaces.deleteVaultCache(originKey, userId)
                dropFillSnapshot()
                quickKeys.wipe(originKey, userId) // a sign-out always takes the quick-unlock key and its stamp (spec 01 §8.1)
                store.origin(originKey).clearPasswordStamp(userId)
            }
        }
        store.clear()
        session.takeRejected() // a refusal heard during this sign-out is this sign-out, not a second event
        update { cleared(it, null).copy(screen = landingScreen(), accountEmail = null, mustChangePassword = false, upgradeMessage = null) }
        refreshQuick()
        ActionResult.Ok
    }

    // ---- deleting the account (spec 03 §13; the web client's Settings › Delete account) ----
    //
    // The server deletes the account in one transaction, after the typed address, a fresh master-password proof and the
    // two-step code when the account has one. What it would do is shown first (its preview): what goes, and what stands
    // in the way. Once it is done, everything this device kept for the account goes too. A request whose answer says
    // nothing (no answer, a server error) may have deleted the account: that is said, never "deleted" or "not deleted".
    // The steps are core's AccountDeletionFlow, which the Android and desktop apps take too.

    private val deletionScreen = ScreenToken()
    private val deletion = AccountDeletionFlow(DeletionCopy.IPHONE)

    /** The preview as last read, for the blockers' and vaults' names. */
    private var deletionRead: AccountDeletePreview? = null

    /** Open Settings › Delete account ([AppState.accountDeletion]): what deleting would do now, as the server says. */
    @Throws(CancellationException::class)
    suspend fun openAccountDeletion(): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val token = deletionScreen.open()
        deletionRead = null
        update { it.copy(accountDeletion = AccountDeletionView(email = store.load()?.email ?: "", preview = null)) }
        busy()
        val preview = try {
            deletion.preview(live.api)
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            if (session.get() !== live) return@action ActionResult.NotDone(null)
            if (!deletionScreen.still(token)) return@action screenGone()
            return@action failure(t, deletion.copy::forPreview)
        }
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        if (!deletionScreen.still(token)) return@action screenGone()
        deletionRead = preview
        update { it.copy(busy = false, accountDeletion = it.accountDeletion?.copy(preview = deletionPreviewView(live, preview))) }
        ActionResult.Ok
    }

    fun closeAccountDeletion() {
        deletionScreen.close()
        deletionRead = null
        update { it.copy(accountDeletion = null) }
    }

    private fun deletionPreviewView(live: VaultSession.Unlocked, p: AccountDeletePreview, blockers: List<AccountDeleteBlocker> = p.blockers): AccountDeletionPreviewView {
        val names = vaultList(live).associate { it.vaultId to it.name }
        return deletion.previewView(p, live.account.personalVaultId, names::get, blockers)
    }

    /**
     * Delete this account: [email] typed as on the screen, the master [password] (proved on this device against the key
     * this session holds, then sent as the fresh proof the server checks) and the two-step [code] when the account has
     * one. Nothing is sent when the address does not match. Once the server says it is done, this device keeps nothing
     * of the account: the session, its tokens and keys, quick unlock, the vault cache and its device state, the
     * self-identity records, the snapshot and save queue the extensions share, kept saves and their files, the saved list
     * and unfinished moves. The app then stands on the server screen.
     */
    @Throws(CancellationException::class)
    suspend fun deleteAccount(email: String, password: String, code: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        val stored = store.load() ?: return@action ActionResult.NotDone(null)
        val open = state.accountDeletion ?: return@action ActionResult.NotDone(null)
        val preview = deletionRead ?: return@action ActionResult.NotDone(null)
        deletion.refusal(email, stored.email, password, code, preview.totpRequired)?.let { return@action ActionResult.Failed(it) }
        busy()
        when (val outcome = deletion.delete(live.api, live.account, email, password, code)) {
            // Done: whatever ended the session meanwhile (the deletion revokes every session of the account), the account is
            // gone, and this device forgets it.
            DeletionOutcome.Deleted -> {
                wipeDeletedAccount(stored)
                // As on a first launch: no server chosen, nobody signed in, no policy known.
                update {
                    cleared(it, null).copy(
                        screen = landingScreen(), server = store.baseUrl, policy = null, serverUnreachable = false,
                        accountEmail = null, mustChangePassword = false, upgradeMessage = null,
                        notice = deletion.copy.deleted(stored.email),
                    )
                }
                refreshQuick()
                return@action ActionResult.Ok
            }
            is DeletionOutcome.Blocked -> {
                if (session.get() !== live) return@action ActionResult.NotDone(null)
                // The server's blockers now, in place of the preview's.
                update { s -> s.copy(busy = false, accountDeletion = s.accountDeletion?.copy(outcomeUnknown = false, preview = deletionPreviewView(live, preview, outcome.blockers))) }
                return@action ActionResult.Failed(deletion.copy.BLOCKED)
            }
            DeletionOutcome.Unknown -> {
                if (session.get() !== live) return@action ActionResult.NotDone(null)
                update { s -> s.copy(busy = false, accountDeletion = s.accountDeletion?.copy(outcomeUnknown = true)) }
                return@action ActionResult.Failed(deletion.copy.OUTCOME_UNKNOWN)
            }
            is DeletionOutcome.Refused -> {
                if (session.get() !== live) return@action ActionResult.NotDone(null)
                // The server had asked for no code, but the account has one now: the field shows, and the person types it.
                if (outcome.codeNowRequired) {
                    deletionRead = preview.copy(totpRequired = true)
                    update { s -> s.copy(accountDeletion = s.accountDeletion?.let { d -> d.copy(preview = d.preview?.copy(totpRequired = true)) }) }
                }
                return@action failure(outcome.cause) { deletion.refusedMessage(it, open.outcomeUnknown) }
            }
        }
    }

    /**
     * After an answer that said nothing ([AccountDeletionView.outcomeUnknown]): ask the server for the preview again. An
     * answer means the account is still here; a refused session says only that this session ended, which a revocation
     * does too, so the account may still exist.
     */
    @Throws(CancellationException::class)
    suspend fun checkAccountDeletion(): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        if (state.accountDeletion?.outcomeUnknown != true) return@action ActionResult.NotDone(null)
        busy()
        val check = deletion.check(live.api)
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        if (check !is DeletionCheck.StillHere) {
            idle()
            return@action ActionResult.Failed(deletion.checkMessage(check) ?: deletion.copy.OUTCOME_UNKNOWN)
        }
        deletionRead = check.preview
        update { it.copy(busy = false, notice = deletion.copy.NOT_DELETED_AFTER_CHECK, accountDeletion = it.accountDeletion?.copy(outcomeUnknown = false, preview = deletionPreviewView(live, check.preview))) }
        ActionResult.Ok
    }

    /**
     * The server deleted [stored]'s account: this device is left as a fresh install (spec 03 §13, owner decision
     * 2026-11-15), with nothing of the account and nothing of its server. What the account kept goes (the session and its
     * tokens, the snapshot and save queue the extensions share, kept saves and their files, the saved list, unfinished
     * moves, every screen's state), and so does everything kept under that server's origin, whoever's it is: every vault
     * cache and device state, every quick-unlock key, the policy mirrors, cached account keys, full-password stamps and
     * the spec 01 §5 self-identity records. The address itself goes last, so the app stands where a first launch does:
     * at the server choice, in this process and the next. Another server's namespace is never touched (§4.2).
     */
    private fun wipeDeletedAccount(stored: StoredSession) {
        session.lock() // the engine releases its cache before the cache is deleted
        forgetSessionViews() // kept saves and their files, unfinished moves, every screen's state
        zeroSecrets()
        dropFillSnapshot() // the snapshot, the save queue and its key, the saved list
        val originKey = (stored.baseUrl.takeIf { it.isNotEmpty() } ?: store.baseUrl)?.let(OriginCanon::originKey)
        if (originKey == null) {
            store.clear()
        } else {
            // Every account's namespace at that server, and the quick-unlock key of each (a sign-out wipes its own, so
            // none but this account's is expected; whatever is there goes).
            val users = (runCatching { namespaces.deleteOrigin(originKey) }.getOrDefault(emptyList()) + OriginCanon.pathSafe(stored.userId)).distinct()
            users.forEach { user -> runCatching { quickKeys.wipe(originKey, user) } }
            store.forgetServer(originKey)
        }
        // A policy probe still on its way writes nothing back, and the live policy was that server's.
        coordinator.originChanged()
        gateTarget = null
        publishServer() // the extensions' copy of the address goes with it
        session.takeRejected() // the server ended the session: that is this deletion, not a second event
    }

    /** The error has been shown. */
    fun dismissError() = update { it.copy(error = null) }

    /** The notice has been shown. */
    fun dismissNotice() = update { it.copy(notice = null) }

    // ---- internals ----

    /** Run an exported action on the UI context: every failure becomes a result; only cancellation propagates. */
    private suspend fun action(block: suspend () -> ActionResult): ActionResult = withContext(uiContext) {
        session.touch()
        try {
            block()
        } catch (c: CancellationException) {
            update { it.copy(busy = false) }
            throw c
        } catch (t: Throwable) {
            failure(t, HouseholdCopy::forError)
        } finally {
            afterAction()
        }
    }

    /** A non-suspend export: [block], or [fallback] for anything it throws (nothing crosses into Swift). */
    private inline fun <T> guarded(fallback: (Throwable) -> T, block: () -> T): T =
        try {
            block()
        } catch (t: Throwable) {
            fallback(t)
        }

    private fun busy() = update { it.copy(busy = true, error = null) }

    private fun idle() = update { it.copy(busy = false) }

    private fun idleFailed(message: String): ActionResult {
        idle()
        return ActionResult.Failed(message)
    }

    /** A failure's sentence; a 426 raises the update screen instead. */
    private fun failure(t: Throwable, copy: (Throwable) -> String): ActionResult {
        if (t is UpgradeRequiredException) {
            update { it.copy(busy = false, screen = AppScreen.UPGRADE_REQUIRED, upgradeMessage = UPGRADE_REQUIRED) }
            return ActionResult.Failed(UPGRADE_REQUIRED)
        }
        idle()
        return ActionResult.Failed(copy(t))
    }

    /** H08: a lock on leaving the foreground lands once the action it waited for ends. */
    private fun afterAction() {
        if (backgroundLockPending && !state.busy && state.upload == null) {
            backgroundLockPending = false
            if (session.get() != null) lock(REASON_BACKGROUND)
        }
    }

    private fun unlockOutcome(r: UnlockResult, copy: (Throwable) -> String): ActionResult = when (r) {
        is UnlockResult.Elsewhere -> idleFailed(sessionElsewhere(r.sessionOrigin))
        is UnlockResult.Adopted -> {
            toVault()
            ActionResult.Ok
        }
        is UnlockResult.Revoked -> {
            // F26: a definitive rejection is a session-end: the ladder purged the session; say why on sign-in. What the
            // account kept across the lock goes with it (round-7 review L4): a key being set up, an unfinished move.
            forgetSessionViews()
            update { cleared(it, REASON_SESSION_ENDED).copy(screen = landingScreen(), accountEmail = null, mustChangePassword = false) }
            refreshQuick()
            ActionResult.Failed(copy(r.cause))
        }
        is UnlockResult.Failed -> failure(r.cause, copy)
        UnlockResult.EndedBeforeLanding -> sessionEndedBeforeLanding()
        UnlockResult.SessionChanged -> {
            sessionChangedWhileWaiting()
            ActionResult.NotDone(null)
        }
        is UnlockResult.Unlocked, is UnlockResult.QuickUnavailable, is UnlockResult.QuickFallback, is UnlockResult.QuickWiped -> {
            idle()
            ActionResult.NotDone(null)
        }
    }

    /** No stored session to unlock: the sign-in surface. */
    private fun noSession(): ActionResult {
        update { it.copy(screen = landingScreen(), accountEmail = null) }
        return ActionResult.NotDone(null)
    }

    /** The screen the stored state says, with no session bound. */
    private fun landingScreen(): AppScreen = when {
        store.baseUrl == null -> AppScreen.CHOOSE_SERVER
        store.load() != null -> AppScreen.UNLOCK
        else -> AppScreen.WELCOME
    }

    private suspend fun landOnStoredState(probe: Boolean) {
        publishServer()
        val stored = store.load()
        update { it.copy(server = store.baseUrl, screen = if (session.get() != null) AppScreen.VAULT else landingScreen(), accountEmail = stored?.email) }
        if (session.get() != null) update { it.copy(items = summaries(it.query)) }
        refreshQuick()
        if (probe && store.baseUrl != null) probePolicy()
    }

    /** The tokenless policy probe of the origin the client dials; a forbidding answer purges that origin's namespace. */
    private suspend fun probePolicy() {
        when (val p = serverSwitch.probePolicy()) {
            is PolicyProbe.Applied -> {
                update { it.copy(policy = policyView(p.policy), serverUnreachable = false) }
                if (!p.policy.offlineCacheAllowed) dropFillSnapshot() else writeFillSnapshot()
            }
            is PolicyProbe.Failed -> if (p.current) update { it.copy(policy = null, serverUnreachable = true) }
            PolicyProbe.Stale, PolicyProbe.NoOrigin -> {}
        }
        refreshQuick()
    }

    private fun policyView(p: ClientPolicy) = PolicyView(
        offlineCacheAllowed = p.offlineCacheAllowed,
        autoLockSeconds = store.baseUrl?.let { store.origin(OriginCanon.originKey(it)).autoLockSeconds } ?: p.autoLockSeconds,
        recoveryFingerprintShort = p.recoveryFingerprint.take(32),
        signupMode = effectiveSignupMode(p.signupMode),
        clipboardClearSeconds = p.clipboardClearSeconds.coerceIn(1, ClientPolicyClamps.CLIPBOARD_CLEAR_MAX_SECONDS),
        attachmentMaxBytes = AttachmentRules.limits(p.attachmentMaxBytes, p.itemAttachmentsMaxBytes).perFileBytes,
        itemAttachmentsMaxBytes = AttachmentRules.limits(p.attachmentMaxBytes, p.itemAttachmentsMaxBytes).perItemBytes,
    )

    /** Gap 6: the same quick-unlock gates the ladder enforces at unlock, and why one refuses. */
    private fun refreshQuick() {
        val q = runCatching { ladder.quickStatus(store.load()?.userId ?: session.get()?.account?.userId) }.getOrNull() ?: return
        val reason = runCatching { quickReason(q.refusal) }.getOrNull()
        update { it.copy(quickUnlock = QuickUnlockView(available = q.eligible, enrolled = q.enrolled, fresh = q.fresh, refusal = q.refusal, reason = reason)) }
    }

    /** The sentence under the quick-unlock switch for [gate]; none while it is merely turned off. */
    private fun quickReason(gate: QuickGate?): String? = when (gate) {
        null, QuickGate.NOT_ENROLLED -> null
        QuickGate.POLICY -> {
            val originKey = store.baseUrl?.let(OriginCanon::originKey)
            if (originKey != null && !coordinator.cacheAllowed(originKey)) QUICK_FORBIDDEN else QUICK_POLICY_UNSEEN
        }
        QuickGate.NO_BIOMETRIC -> quickKeys.biometricProblem() ?: QUICK_NO_BIOMETRIC
        QuickGate.EXPIRED -> QUICK_EXPIRED
    }

    /**
     * A4: quick unlock needs this origin's policy seen within 7 days, and the start-up probe is the only other read
     * a locked app makes. A probe that failed at launch, or an app that stayed in memory for days (it locks on every
     * trip to the background, so its quiet sync rarely runs), left that clock stale. So every landing in the vault and
     * every return to the foreground probes again once the policy is unknown in this visit or older than an hour.
     * The probe is the tokenless, fenced one.
     */
    private fun refreshPolicyIfStale() {
        val originKey = store.baseUrl?.let(OriginCanon::originKey) ?: return
        val fetchedAt = store.origin(originKey).policyFetchedAt
        val age = clocks.wallMs() - fetchedAt
        if (coordinator.livePolicy != null && fetchedAt > 0L && age in 0 until POLICY_REFRESH_MS) return
        if (policyRefresh?.isActive == true) return
        policyRefresh = scope.launch { probePolicy() }
    }

    /** Tell the app's extensions which server it uses: the origin it dials, which only the Trust Gate (or a re-spelling) sets. */
    private fun publishServer() {
        runCatching { serverShare.publish(store.baseUrl) }
    }

    private fun summaries(query: String): List<ItemSummary> {
        val live = session.get() ?: return emptyList()
        val q = query.trim().lowercase()
        val pending = runCatching { live.engine.pendingSyncItemIds() }.getOrDefault(emptySet())
        return live.engine.items().filter { matches(it, q) }.map { summaryOf(it, it.itemId in pending) }
    }

    private fun summaryOf(item: VaultItem, pending: Boolean): ItemSummary {
        val doc = item.doc
        val first = doc.login?.uris?.firstOrNull()
        return ItemSummary(
            itemId = item.itemId, name = doc.name, type = doc.type,
            username = doc.login?.username?.ifEmpty { null },
            host = first?.let(::hostOf),
            favorite = doc.favorite, hasTotp = !doc.login?.totp.isNullOrEmpty(), pendingSync = pending,
        )
    }

    /** F79 parity with web, desktop and Android: the name, the notes, the username, every web address and a card's brand and last four. */
    private fun matches(item: VaultItem, q: String): Boolean {
        if (q.isEmpty()) return true
        val d = item.doc
        return d.name.lowercase().contains(q) ||
            (d.notes ?: "").lowercase().contains(q) ||
            (d.login?.username ?: "").lowercase().contains(q) ||
            (d.login?.uris ?: emptyList()).any { it.lowercase().contains(q) } ||
            (d.type == "card" && CardDisplay.subtitle(d).lowercase().contains(q))
    }

    /** The host of a stored web address, for display: "https://user@login.example.com:8443/x" is login.example.com. */
    private fun hostOf(uri: String): String? {
        val afterScheme = uri.substringAfter("://", uri)
        val authority = afterScheme.takeWhile { it != '/' && it != '?' && it != '#' }.substringAfterLast('@')
        val host = if (authority.startsWith("[")) authority.substringBefore(']').plus("]") else authority.substringBefore(':')
        return host.lowercase().ifEmpty { null }
    }

    private fun toVault() {
        val invitations = session.get()?.let(::invitationViews).orEmpty()
        val offers = session.get()?.let(::ownershipOfferViews).orEmpty()
        val reviews = session.get()?.let(::legacyReviewViews).orEmpty()
        update {
            it.copy(
                screen = AppScreen.VAULT, items = summaries(it.query), vaultNotices = session.get()?.let(::vaultNotices).orEmpty(), invitations = invitations, ownershipOffers = offers,
                legacyReviews = reviews,
                busy = false, error = null, totpRequired = false,
                lockReason = null, recoveryCaptureError = null, recoveryReplacedNotice = false,
            )
        }
        refreshQuick()
        refreshPolicyIfStale()
        writeFillSnapshot()
        refreshSaveQueue()
        refreshPersonalVault()
        resumeTwoStep()
        runCatching { moves.check() } // a kept move this version cannot read is said now, not at the next move
        resumePendingSaves()
    }

    // ---- the personal vault ----

    /** Show the personal-vault notice as it stands, then look up what it needs from the server. */
    private fun refreshPersonalVault() {
        val live = session.get() ?: return
        runCatching { personal.render(live) }
        if (live.account.personalStatus == Account.PersonalStatus.CONFIRMED) return
        scope.launch {
            // Off any action, so the session may have ended meanwhile: the flow checks after every await.
            if (session.get() === live) runCatching { personal.load(live) }.onFailure { if (it is CancellationException) throw it }
        }
    }

    /** Look up again who else holds the vault the server names ([PersonalVaultView.lookupFailed]). */
    @Throws(CancellationException::class)
    suspend fun retryPersonalVaultDetails(): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        personal.load(live)
        ActionResult.Ok
    }

    /** "Use <the vault the server names>" ([PersonalVaultView.useServedLabel]); offered only after its co-holders loaded. */
    fun usePersonalVaultServed(): ActionResult = guarded({ ActionResult.Failed(HouseholdCopy.forError(it)) }) {
        val live = session.get() ?: return@guarded ActionResult.NotDone(null)
        if (personal.useServed(live)) ActionResult.Ok else ActionResult.NotDone(null)
    }

    /**
     * Propose a personal vault: [vaultId] from [PersonalVaultView.choices] or [PersonalVaultView.otherChoices], or
     * null for "Keep" ([PersonalVaultView.keepLabel]). Raises the confirmation ([PersonalVaultView.proposal]); nothing
     * is written.
     */
    @Throws(CancellationException::class)
    suspend fun proposePersonalVault(vaultId: String?): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        busy()
        val raised = personal.propose(live, vaultId)
        idle()
        if (raised) ActionResult.Ok else ActionResult.NotDone(null)
    }

    /** Dismiss the confirmation without choosing. */
    fun cancelPersonalVaultProposal() {
        val live = session.get() ?: return
        runCatching { personal.cancel(live) }
    }

    /** Confirm the raised proposal; [password] is the master password where [PersonalProposalView.needsPassword]. */
    @Throws(CancellationException::class)
    suspend fun confirmPersonalVault(password: String?): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        busy()
        val done = personal.confirm(live, password)
        idle()
        if (done) ActionResult.Ok else ActionResult.NotDone(null)
    }

    /**
     * The AutoFill extension's snapshot (design 2026-11-09): the live engine's rows, still under their vault keys,
     * replaced after every landing, sync and edit. Nothing is written, and the last one is removed, when the origin's
     * policy forbids an offline cache. A row the server has not confirmed yet is not in it.
     */
    private fun writeFillSnapshot() {
        if (fillSnapshots === FillSnapshotStore.None) return
        runCatching {
            val live = session.get() ?: return
            val origin = store.baseUrl ?: return
            val originKey = OriginCanon.originKey(origin)
            val stored = store.load()
            val keys = store.origin(originKey).loadAccountKeys(live.account.userId)
            if (!coordinator.cacheAllowed(originKey) || stored == null || keys == null || stored.userId != live.account.userId) {
                fillSnapshots.delete()
                return
            }
            // Only what this app shows: the login and card items its engine opened, and the vault and grant rows of the
            // vaults they live in. The engine's trust state (held vaults, held key tags) stays in the app; a row it refused or
            // set aside is not in the snapshot, so the extension cannot open what the app would not.
            val shown = live.engine.items().filter { it.doc.type == "login" || it.doc.type == "card" }
            val ids = shown.mapTo(HashSet()) { it.itemId }
            val vaultIds = shown.mapTo(HashSet()) { it.vaultId }
            val snap = FillSnapshot(
                origin = OriginCanon.canonicalOrigin(origin), userId = stored.userId, email = stored.email, keys = keys,
                vaults = live.engine.vaultRows().filter { it.vaultId in vaultIds },
                grants = live.engine.grants().filter { it.vaultId in vaultIds },
                items = live.engine.envelopes().filter { it.itemId in ids },
                writtenAtMs = clocks.wallMs(),
            )
            // A snapshot that could not be replaced is removed: a stale one must not outlive what it mirrored.
            if (!fillSnapshots.write(snap.encode())) fillSnapshots.delete()
        }.onFailure { runCatching { fillSnapshots.delete() } }
    }

    /** Everything the extensions share for one account goes together: the snapshot, the save key, the queued saves and the list of applied ones. */
    private fun dropFillSnapshot() {
        runCatching { fillSnapshots.delete() }
        runCatching { saves.dropAll() }
        // And the saves with files kept on disk: moved into memory, with every file set aside (an open editor's too),
        // while the account is unlocked, and said (round-9 review 8); while it is locked they stay on disk until the next
        // unlock moves them (round-11 review). One in memory goes with the account.
        val live = session.get()
        if (pendingSaves.leaveDisk(live?.account) > 0) update { it.copy(notice = AttachmentCopy.KEPT_IN_MEMORY) }
    }

    /**
     * The extensions' save queue (design 2026-11-09, "Saving"; [SaveImporter] has the rules): publish the key, read
     * what was queued, and save what may be saved by itself. Runs after every landing in the vault and every return to
     * the foreground, off the action that triggered it.
     */
    private fun refreshSaveQueue() {
        if (!saves.enabled) return
        val live = session.get() ?: return
        val origin = store.baseUrl ?: return
        scope.launch {
            runCatching { saves.sync(live, origin, coordinator.cacheAllowed(OriginCanon.originKey(origin)), apply = true) { session.get() === live } }
                .onFailure { if (it is CancellationException) throw it }
        }
    }

    private fun result(r: ImportResult): ActionResult = when (r) {
        is ImportResult.Done -> {
            update { it.copy(busy = false, notice = if (r.queuedOffline) HouseholdCopy.SAVE_OFFLINE else it.notice) }
            ActionResult.Ok
        }
        ImportResult.Gone -> {
            idle()
            ActionResult.NotDone(null)
        }
        is ImportResult.Failed -> idleFailed(r.message)
    }

    /** The password of a listed capture, for the person to check before saving it; null when it is gone. */
    fun pendingSavePassword(id: String): String? = guarded({ null }) { saves.password(id) }

    /** Save one listed capture by hand ([AppState.pendingSaves]): what its row named, or nothing. */
    @Throws(CancellationException::class)
    suspend fun confirmPendingSave(id: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        busy()
        result(saves.confirm(live, id) { session.get() === live })
    }

    /** Discard one listed capture: it leaves the queue and nothing is written. */
    fun discardPendingSave(id: String) {
        if (session.get() == null) return
        val live = session.get() ?: return
        // Under the queue's own lock; it runs at once unless a save is in progress, and then right after it.
        scope.launch(start = CoroutineStart.UNDISPATCHED) { runCatching { saves.discard(live, id) }.onFailure { if (it is CancellationException) throw it } }
    }

    /** Take back one automatic save ([AppState.appliedSaves]); a login changed since is left alone. */
    @Throws(CancellationException::class)
    suspend fun undoAppliedSave(id: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        busy()
        result(saves.undo(live, id) { session.get() === live })
    }

    /** Take back every listed automatic save that has not been changed since. */
    @Throws(CancellationException::class)
    suspend fun undoAllAppliedSaves(): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        busy()
        result(saves.undoAll(live) { session.get() === live })
    }

    /** The "saved from AutoFill" list has been read: it goes, and with it the undo from here. */
    fun dismissAppliedSaves() {
        val live = session.get() ?: return
        scope.launch(start = CoroutineStart.UNDISPATCHED) { runCatching { saves.dismiss(live) }.onFailure { if (it is CancellationException) throw it } }
    }

    /**
     * What the system's AutoFill suggestions may know (iOS `ASCredentialIdentityStore`): one entry per web address of
     * each login that has a username. Empty while locked, and when the policy forbids an offline cache, so the host
     * then clears the system's copy. No password leaves through here.
     */
    fun credentialIdentities(): List<CredentialIdentity> = guarded({ emptyList() }) {
        val live = session.get() ?: return@guarded emptyList()
        val originKey = store.baseUrl?.let(OriginCanon::originKey) ?: return@guarded emptyList()
        if (!coordinator.cacheAllowed(originKey)) return@guarded emptyList()
        live.engine.items().flatMap { item ->
            val login = item.doc.login?.takeIf { item.doc.type == "login" && !it.username.isNullOrEmpty() } ?: return@flatMap emptyList()
            // Web addresses only: an app-package address (androidapp://…) names an Android app, never a domain.
            login.uris.mapNotNull { (UriMatch.parseSavedUri(it) as? SavedUri.Web)?.host }.distinct()
                .map { CredentialIdentity(item.itemId, it, login.username!!, !login.totp.isNullOrEmpty()) }
        }
    }

    private fun showFirstSync(first: FirstSync) {
        when (first) {
            FirstSync.Done -> {}
            // A notice about captured logins that were removed is not replaced by the weaker "offline" one.
            FirstSync.Offline -> update { if (it.notice == SAVES_UNREADABLE || earlierDropped > 0) it else it.copy(notice = OFFLINE) }
            FirstSync.UpgradeRequired -> update { it.copy(busy = false, screen = AppScreen.UPGRADE_REQUIRED, upgradeMessage = UPGRADE_REQUIRED) }
            is FirstSync.Failed -> update { it.copy(error = first.message) }
        }
    }

    private suspend fun syncNow(engine: SyncEngine) {
        engine.sync()
        store.lastSyncAt = clocks.wallMs()
        sinceSyncMs = 0
    }

    /** F61: the detached KDF re-key, when the policy raised the cost (fenced inside core). */
    private fun reKey(live: VaultSession.Unlocked, password: String, keys: io.silencelen.andvari.core.model.AccountKeys) {
        if (store.mustChangePassword) return
        val policy = coordinator.livePolicy ?: return
        val originKey = store.baseUrl?.let(OriginCanon::originKey) ?: return
        val userId = live.account.userId
        scope.launch(Dispatchers.Default) {
            KdfReKeyCore.maybeUpgrade(live.api, userId, password, keys, policy, live.account) { updated -> binder.persistAccountKeys(originKey, userId, updated) }
        }
    }

    // §F.9 capture gate
    private fun startRecoveryCapture(currentAuthKey: String) {
        pendingCaptureAuthKey = currentAuthKey
        update { it.copy(screen = AppScreen.RECOVERY_CAPTURE, recoveryCaptureError = null, recoveryReplacedNotice = false, busy = false, error = null) }
        runRecoveryCapture()
    }

    private fun runRecoveryCapture() {
        scope.launch { runRecoveryCaptureNow() }
    }

    private suspend fun runRecoveryCaptureNow(): ActionResult {
        val live = session.get() ?: return ActionResult.NotDone(null)
        val authKey = pendingCaptureAuthKey ?: return ActionResult.NotDone(null)
        update { it.copy(recoveryCaptureError = null, busy = true) }
        return when (val r = capture.setup(live, authKey)) {
            is CaptureSetup.Ready -> {
                pendingRecoverySecret = r.secret
                pendingRecoveryPieceId = r.pieceId
                update { it.copy(busy = false, screen = AppScreen.RECOVERY_REVEAL, recoveryWaived = false) }
                ActionResult.Ok
            }
            CaptureSetup.SessionEnded -> {
                idle()
                ActionResult.NotDone(null)
            }
            CaptureSetup.UpgradeRequired -> {
                update { it.copy(busy = false, screen = AppScreen.UPGRADE_REQUIRED, upgradeMessage = UPGRADE_REQUIRED) }
                ActionResult.Failed(UPGRADE_REQUIRED)
            }
            is CaptureSetup.Failed -> {
                val message = if (r.offline) CAPTURE_OFFLINE else CAPTURE_FAILED
                update { it.copy(busy = false, recoveryCaptureError = message) }
                ActionResult.Failed(message)
            }
        }
    }

    private fun zeroPendingRecovery() {
        pendingRecoverySecret?.fill(0)
        pendingRecoverySecret = null
        pendingRecoveryPieceId = null
    }

    private fun zeroSecrets() {
        zeroPendingRecovery()
        pendingCaptureAuthKey = null
    }

    /** The idle check (spec 01 §8), and a rejection heard by any client of the session, reported once. */
    private fun checkIdleLock() {
        val s = state
        // §F.7: a lock mid-reveal destroys the shown-once phrase, and the reason says so.
        val idleReason = if (pendingRecoverySecret != null) REASON_IDLE_RECOVERY else REASON_IDLE
        if (session.get() == null) {
            if (session.takeRejected()) {
                endRejectedSession()
                return
            }
            if (s.screen == AppScreen.VAULT || s.screen == AppScreen.RECOVERY_REVEAL || s.screen == AppScreen.RECOVERY_CAPTURE) lock(idleReason)
            return
        }
        if (s.busy || s.upload != null) return // never close the engine under a running action, or an upload
        if (session.idleExpired()) lock(idleReason)
    }

    /** Whatever a session's screens held in memory about the vault goes with it, however the session ended. */
    /**
     * What a lock forgets. [ordinaryLock]: the account stays, so a key being set up stays for the trip it came from (L4)
     * and an unfinished move stays sealed in storage (L5); otherwise (a sign-out, a server switch, an ended session)
     * both go.
     */
    private fun forgetSessionViews(ordinaryLock: Boolean = false) {
        lockDraft()
        resuming?.cancel() // a kept save being finished stays kept, for the next unlock
        if (!ordinaryLock) pendingSaves.dropAll()
        saves.locked()
        personal.reset()
        trashRead = emptyMap()
        historyRead = null
        if (ordinaryLock) moves.forget() else moves.drop()
        // A key past its time goes now, not at the next unlock (round-7 review L4): it is not kept in memory while locked.
        val pending = twoStepPending
        if (!ordinaryLock || (pending != null && clocks.monotonicMs() - pending.mintedAtMs !in 0 until TWO_STEP_PENDING_MS)) twoStepPending = null
        deletedVaults = emptyMap()
        earlierDropped = 0
        membersRead = null
        newMember = null
        verifyTarget = null
        deletionRead = null
        invitationSenders.clear()
        invitationAsks.clear()
        offerOwners.clear()
        offerOwnerAsks.clear()
        reviewOwners.clear()
        reviewOwnerAsks.clear()
        claim = null
        health = null
        breaches = null
        csv = null
        exporting = null
    }

    private fun lock(reason: String?) {
        session.lock()
        forgetSessionViews(ordinaryLock = true)
        zeroSecrets()
        backgroundLockPending = false
        val stored = store.load()
        update { cleared(it, reason).copy(screen = landingScreen(), accountEmail = stored?.email) }
        refreshQuick() // gap 6: the flags are recomputed for the screen this lands on
    }

    /** A definitive in-session rejection: the coordinator locked and purged the session; the sign-in surface, with the reason. */
    private fun endRejectedSession() {
        forgetSessionViews()
        zeroSecrets()
        update { cleared(it, REASON_SESSION_ENDED).copy(screen = landingScreen(), accountEmail = null, mustChangePassword = false) }
        refreshQuick()
    }

    /** The session an action bound ended during its first sync: land where the idle check says. */
    private fun sessionEndedBeforeLanding(): ActionResult {
        idle()
        checkIdleLock()
        return ActionResult.NotDone(null)
    }

    private fun sessionChangedWhileWaiting() {
        idle()
        if (session.takeRejected()) {
            endRejectedSession()
            return
        }
        update { it.copy(screen = landingScreen(), accountEmail = store.load()?.email) }
        refreshQuick()
    }

    /** The quiet sync (spec 03 §6): the policy first, so the auto-lock follows an admin's change, then the vault. */
    private fun backgroundSync() {
        val live = session.get() ?: return
        if (state.busy || state.syncing) return
        update { it.copy(syncing = true) }
        sinceSyncMs = 0
        val originKey = store.baseUrl?.let(OriginCanon::originKey) ?: return
        val tag = coordinator.tag(originKey)
        scope.launch {
            runCatching { live.api.clientPolicy() }.onSuccess { p ->
                // A forbidding policy is enforced on every fetch that passed the fence, this one included.
                if (coordinator.applyPolicy(p, tag)) {
                    update { it.copy(policy = policyView(p), serverUnreachable = false) }
                    if (!p.offlineCacheAllowed) coordinator.purgeForbidden(originKey, live.account.userId)
                }
            }
            try {
                syncNow(live.engine)
                if (session.get() === live) {
                    val invitations = invitationViews(live)
                    val offers = ownershipOfferViews(live)
                    val reviews = legacyReviewViews(live)
                    update {
                        it.copy(
                            syncing = false, items = summaries(it.query), vaultNotices = vaultNotices(live), invitations = invitations, ownershipOffers = offers,
                            legacyReviews = reviews, health = healthNow(live) ?: it.health,
                        )
                    }
                } else {
                    update { it.copy(syncing = false) }
                }
                writeFillSnapshot()
                refreshPersonalVault()
            } catch (t: Throwable) {
                if (t is CancellationException) throw t
                if (t is UpgradeRequiredException) {
                    update { it.copy(syncing = false, screen = AppScreen.UPGRADE_REQUIRED, upgradeMessage = UPGRADE_REQUIRED) }
                    return@launch
                }
                // Unattended: a transport failure, or a lock mid-sync, stays quiet.
                val torn = session.get() !== live
                update { it.copy(syncing = false, error = if (t is kotlinx.io.IOException || torn) it.error else HouseholdCopy.forSyncError(t)) }
            }
        }
    }

    /** What every end of a session clears from the screen. */
    private fun cleared(s: AppState, reason: String?) = s.copy(
        items = emptyList(), query = "", syncing = false, busy = false, error = null, notice = null, totpRequired = false,
        trustGate = null, recoveryWaived = false, recoveryCaptureError = null, recoveryReplacedNotice = false, lockReason = reason,
        personalVault = null, pendingSaves = emptyList(), appliedSaves = emptyList(), vaultNotices = emptyList(), sharing = null, twoStep = null, trash = null, history = null,
        attachmentDraft = null, upload = null, members = null, verifying = null, household = null, invitations = emptyList(), ownershipOffers = emptyList(),
        legacyReviews = emptyList(), ownershipClaim = null, accountDeletion = null, health = null, csvImport = null, exporting = null,
    )

    private companion object {
        const val SYNC_EVERY_MS = 5 * 60 * 1000L


        /** How long a key being set up is kept from when the server minted it (round-6 review L4). */
        const val TWO_STEP_PENDING_MS = 10 * 60 * 1000L

        /** The roles an owner gives a member. */
        val MEMBER_ROLES = setOf("writer", "reader")

        /** What a typed identity code is counted in ([Fingerprint.matchesShort] drops everything else). */
        const val HEX_DIGITS = "0123456789abcdef"
        const val POLICY_REFRESH_MS = 60 * 60 * 1000L
        const val LOGOUT_MS = 5_000L

        // The household's sentences (the Android app's, where it has them).
        const val REASON_LOCKED = "Locked."
        const val REASON_IDLE = "Locked after inactivity."
        const val REASON_BACKGROUND = "Locked when you left the app."
        const val REASON_SESSION_ENDED = "Your session ended — sign in again."
        const val REASON_IDLE_RECOVERY =
            "Locked after inactivity. Your recovery phrase was not confirmed — you'll be shown a fresh one after you unlock."
        const val UPGRADE_REQUIRED = "This andvari server needs a newer version of the app. Update andvari from the App Store, then reopen it."
        const val RECOVERY_PHRASE_REPLACED =
            "This recovery phrase was replaced — a newer one was created, possibly from another device. " +
                "A fresh phrase will be shown; discard any phrase you saved before it."
        const val CAPTURE_OFFLINE = "Can't reach the server right now — check your connection and try again."
        const val CAPTURE_FAILED = "Couldn't set up your recovery phrase just now — try again in a moment."
        const val WEAK_MASTER_PASSWORD = "Choose a stronger master password — mix length with upper/lower case, digits, or symbols."
        const val SHEET_MISMATCH = "The recovery-sheet check no longer matches this server — re-verify the printed sheet's first 32 characters."
        const val INVALID_SERVER = "Enter a server address like https://vault.example.com — no path, no user name."
        const val CLEARTEXT_BLOCKED = "This server uses plain http, which iOS does not allow. Use its https address."
        const val CHOOSE_SERVER_FIRST = "Choose your server first."
        const val SWITCH_PENDING = "Finish or cancel the server change first."
        const val OFFLINE = "Offline — showing cached data"
        const val SYNCED = "Synced."
        const val UNLOCK_PROMPT = "Unlock andvari"
        const val ENABLE_PROMPT = "Turn on quick unlock"
        const val CHANGE_PASSWORD_FIRST = "Change your master password first, then you can turn on quick unlock."
        const val UNLOCK_WITH_PASSWORD_FIRST = "Unlock with your master password first, then turn quick unlock on."
        const val SAVES_UNREADABLE = "Some logins captured for saving could not be read and were removed. Sign in on that site again to capture them."
        const val QUICK_FORBIDDEN = "Your server doesn't allow unlocking without your master password."
        const val QUICK_POLICY_UNSEEN = "andvari needs to reach your server before this can be turned on. Check your connection."
        const val QUICK_NO_BIOMETRIC = "Set up Face ID or Touch ID on this iPhone first."
        const val QUICK_EXPIRED = "Unlock with your master password once to use this again."
        const val QUICK_UNAVAILABLE = "This device has no usable Face ID or Touch ID, or your org doesn't allow it."
        const val QUICK_NOT_ENABLED = "Couldn't turn on quick unlock."
        const val CARD_NAME_REQUIRED = "Give the card a name."
        const val NOTE_NAME_REQUIRED = "Give the note a name."

        /** The kinds of item this app can edit. */
        val EDITABLE_TYPES = setOf("login", "card", "note")
        const val CARD_EXPIRY_INVALID = "That expiry date can't be read. Use a month and a year, like 07 and 2031."
        const val CARD_NUMBER_MAX_DIGITS = 19
        const val CARD_NUMBER_TOO_LONG = "A card number has at most 19 digits. Check the number."
        const val CARD_NUMBER_UNUSUAL = "This number doesn't pass the usual check for card numbers. You can still save it."
        const val NAME_REQUIRED = "Give the login a name."
        const val TOTP_INVALID = "That one-time code key isn't valid base32 or an otpauth:// link."
        const val ITEM_GONE = "This item is no longer here."
    }
}

/** The recover wizard's fixed sentences and its idle bound (Android's wording). */
internal object RecoverCopy {
    /** How long the new-password step may sit while the raw recovery secret is held. */
    const val IDLE_MS = 300_000L
    const val TIMEOUT = "Timed out for your security. Start the recovery again."
    const val NOT_A_PHRASE = "That doesn't look like a recovery phrase — check it and try again."
    const val EXPIRED = "Your recovery session expired — start again."
    const val WEAK_PASSWORD = "Choose a stronger master password — mix length with upper/lower case, digits, or symbols."
    const val DONE = "Master password reset — sign in with your new password."
}

/** What the trash and the item history say. */
internal object ItemCopy {
    const val TRASH_RESTORED = "Item restored."
    const val TRASH_PURGED = "Item deleted for good."
    const val TRASH_GONE = "That item is no longer in the trash. Open the trash again."
    const val TRASH_UNREADABLE = "No readable version of this item is left, so it can only be deleted for good."
    const val READ_ONLY = "You can only view this vault, so this can't be changed here."
    const val HISTORY_GONE = "That version is no longer listed. Open the history again."
    const val VERSION_RESTORED = "Restored that version. The one it replaced is in the history."
    const val VAULT_NOT_WRITABLE = "You can't add items to that vault."
    const val TWO_STEP_ON = "Two-step sign-in is on: a code from your authenticator is asked for at every sign-in."
    const val TWO_STEP_OFF = "Two-step sign-in is off."
    const val MOVE_DENIED = "You don't have permission to add items to that vault, so nothing was moved."
    const val MOVE_CHANGED = "This item changed while it was being moved. Review it and try again."
    const val MOVE_RETRY = "That didn't finish. Try again: it won't make a duplicate."
}

/** What the shared vaults screen says when it refuses. */
internal object SharingCopy {
    const val NAME_REQUIRED = "Give the vault a name."
    const val OWNER_ONLY = "Only the vault's owner can do that."
    const val VAULT_GONE = "That vault is no longer here."
    const val TYPE_THE_NAME = "Type the vault's name exactly to delete it."
    const val COPY_RUNNING = "Wait for the copy into your personal vault to finish first."
    const val OWNER_CANNOT_LEAVE = "You own this vault, so you can't leave it: make someone else the owner, or delete it."
}

/** What the members screen and a comparison of identity codes say (the web app's words, where it has them). */
internal object MembersCopy {
    const val EMAIL_REQUIRED = "Type their email address."
    const val THATS_YOU = "That's your own account."
    const val ALREADY_MEMBER = "They're already in this vault."
    const val NO_SUCH_USER = "No active account has that email."
    const val LOOK_UP_AGAIN = "Look them up again."
    const val BAD_ROLE = "Choose writer or reader."
    const val MEMBER_GONE = "They're no longer listed. Open the members again."
    const val OWNER_STAYS = "The owner can't be changed or removed here. To hand the vault over, make someone else its owner."
    const val A_MEMBER = "a member"
    const val OWNER_ALREADY = "They already own this vault."
    const val DISABLED_CANNOT_OWN = "Their account is disabled, so they can't take the vault over."
    const val OFFER_PENDING = "An offer to hand this vault over is already waiting. Cancel it first."
    const val OFFER_CANCELLED =
        "Offer cancelled. Should the server complete it anyway, your devices warn you and keep their record that you own the vault."
    const val VERIFY_BEFORE_HANDOVER =
        "Verify them on this device first, by comparing codes with them in person or on a call you trust: only someone you verified can be made the owner."
    const val OFFER_GONE = "That offer is no longer waiting."
    const val CONTACT_GONE = "They're no longer on your list."
    const val RECORD_ROLLED_BACK = "The server sent an older copy of the people you verified. Your newer copy was kept. If this keeps happening, tell your admin."
    const val RECORD_UNREADABLE = "The server sent a list of verified people this account did not write. It was ignored. Tell your admin."
    const val OWNERSHIP_UNCONFIRMED_TRANSFER =
        "Before you hand this vault over, confirm that you own it: this account has no record that you created it or that it was transferred to you."
    const val OWNERSHIP_UNCONFIRMED =
        "Before you add anyone, confirm that you own this vault: this account has no record that you created it or that it was transferred to you."
    const val SOMEONE_UNNAMED = "someone the server didn't name"
    const val PASSWORD_REQUIRED = "Type your master password."
    const val HANDED_OVER_REQUIRED = "This device first got this vault as a member. Confirm that its owner handed it over to you, and only if that is true."
    const val CLAIM_KEY = "This vault's key didn't come from your own account, so andvari can't record that you own it. Tell your admin."
    const val CLAIM_STALE = "That confirmation expired. Start it again."
    const val RESHARE_VERIFY_AGAIN = "Couldn't share it again: verify them again, then retry."
    const val LIST_CHANGED = "The list changed. Open the members again."
    const val REVIEW_GONE = "That vault no longer needs reviewing."
    const val ACCEPT_FAILED = "Couldn't accept it. Try again."
    const val VERIFY_FIRST = "Verify them first: compare codes with them, in person or on a call you trust."
    const val CODE_LENGTH = "Type all 32 characters of their code."
    const val CODE_MISMATCH =
        "That code doesn't match the key this server holds for them. If they read it correctly from their own screen, STOP: do not share with this account until your admin checks it."
    const val QR_NOT_IDENTITY = "That isn't an andvari identity code."
    const val QR_OTHER_ACCOUNT = "That QR code belongs to a different account than the one you are verifying."
    const val QR_MISMATCH = "Their QR code doesn't match the key this server holds for them. STOP: do not share with this account until your admin checks it."
    const val INVITATION_MISMATCH =
        "That code doesn't match, or the invitation didn't verify. If they read it correctly from their own screen, STOP and tell your admin."
    const val INVITATION_QR_MISMATCH = "Their QR code doesn't match, or the invitation didn't verify. STOP and tell your admin."
    const val INVITATION_GONE = "That invitation is no longer here."
    const val SENDER_UNKNOWN = "The server couldn't say who sent this invitation. Try again later."
    const val SAVE_FAILED = "Couldn't save the verification. Try again."
    const val MISMATCH_ADD = "The server answered that address with an account you verified as someone else. Don't add them: the server may be misbehaving. Tell your admin."
    const val LEGACY_ADD = "You verified this person before andvari recorded their email. Verify them again to add them."

    fun forLookup(t: Throwable): String = if (t is ApiException && t.code == "no_such_user") NO_SUCH_USER else HouseholdCopy.forError(t)

    /** "You own <vault>?" could not load what the server reports of the vault, or the vault's key is not this account's own. */
    fun forClaim(t: Throwable): String = if (t is VaultKeyNotVerifiedException) CLAIM_KEY else HouseholdCopy.forError(t)

    fun forOwnershipConfirm(t: Throwable): String = when (t) {
        is ReauthFailedException -> HouseholdCopy.REAUTH_FAILED
        is ReauthStaleSessionException -> HouseholdCopy.REAUTH_STALE_SESSION
        is OwnershipTransferAckRequiredException -> HANDED_OVER_REQUIRED
        is VaultKeyNotVerifiedException -> CLAIM_KEY
        is IllegalStateException -> CLAIM_STALE
        else -> HouseholdCopy.forError(t)
    }

    fun forReshare(t: Throwable): String = when (t) {
        is MemberNotVerifiedException -> RESHARE_VERIFY_AGAIN
        is OwnershipNotConfirmedException -> OWNERSHIP_UNCONFIRMED
        is IllegalStateException -> LIST_CHANGED
        else -> HouseholdCopy.forError(t)
    }

    fun forAccept(t: Throwable): String = if (t is IllegalStateException) ACCEPT_FAILED else HouseholdCopy.forError(t)

    fun ownershipConfirmed(vault: String?): String =
        "Recorded: you own " + (vault?.let { "“$it”" } ?: "this vault") + ". You can add members and hand it over."

    fun reshared(vault: String, who: String): String = "Shared “$vault” again with “$who”, signed by you."

    fun reviewAccepted(vault: String?): String = "Accepted " + (vault?.let { "“$it”" } ?: "the vault") + ". You can save into it now, as your role allows."

    fun forAdd(t: Throwable): String = when (t) {
        is MemberNotVerifiedException -> VERIFY_FIRST
        is MemberIdentityMismatchException -> MISMATCH_ADD
        is LegacyPinReverifyRequiredException -> LEGACY_ADD
        is OwnershipNotConfirmedException -> OWNERSHIP_UNCONFIRMED
        is ApiException -> if (t.code == "already_member") ALREADY_MEMBER else HouseholdCopy.forError(t)
        else -> HouseholdCopy.forError(t)
    }

    /** Recording a verification (an account-state write, or the sender's key for an invitation) did not finish. */
    fun forVerifySave(t: Throwable): String = if (t is CryptoUnavailableException) HouseholdCopy.forError(t) else SAVE_FAILED

    fun keyChanged(email: String, label: String?): String =
        "The server now holds a different identity key for the account it gives for $email than the one you verified" +
            (label?.let { " (the name shown when you verified them: “$it”)" } ?: "") +
            ". Don't add them until you have checked their code in person again, and tell your admin."

    fun legacy(email: String, label: String): String =
        "You verified this person before andvari recorded their email. Verify them again to add them. (The name shown when you verified them was “$label”; that name came from the server, so it can't confirm who $email is.)"

    fun mismatch(email: String, pin: Contact?, claimedBy: Contact?): String = buildString {
        if (pin != null) {
            append("The server answered $email with an account you verified")
            append(pin.email?.let { " at $it" } ?: " under another address")
            append(" (the name shown when you verified them: “${pin.label}”)")
            if (claimedBy != null) append(", but you verified a different person at $email (the name shown when you verified them: “${claimedBy.label}”)")
            append(". ")
        } else {
            append("You verified a different person at $email")
            if (claimedBy != null) append(" (the name shown when you verified them: “${claimedBy.label}”)")
            append(", but the server answered that address with another account. ")
        }
        append("Don't add them: the server may be misbehaving. Tell your admin.")
    }

    fun added(email: String, vault: String?, role: String): String =
        "Added $email to " + (vault?.let { "“$it”" } ?: "the vault") + " as a $role. If they haven't verified you yet, andvari asks them to compare codes with you before the vault opens for them."

    fun roleChanged(name: String, role: String): String = "$name is now a $role."

    fun removed(name: String, vault: String): String = "Removed $name from “$vault”. They keep anything they already saw: the vault's key is not changed."

    fun offered(name: String, vault: String): String =
        "Asked $name to take over “$vault”. Nothing changes until they accept in their app, within 14 days; you can cancel until then."

    fun ownershipAccepted(vault: String): String = "You own “$vault” now: you manage its members, and only you can rename, hand over or delete it."

    fun ownershipDeclined(vault: String): String = "Declined. “$vault” stays with its owner."

    fun contactRemoved(who: String): String = "Removed $who from the people you verified. Compare codes with them again before you share with them."

    fun verified(name: String): String = "Verified $name on this device."

    fun invitationAccepted(name: String, vault: String?): String = "Verified $name." + (vault?.let { " “$it” is open now." } ?: "")
}

/**
 * The link an authenticator adds a two-step key from (round-6 review L4): issuer "andvari", labelled with the server's
 * [host], never the email (the label shows in the authenticator's list). The algorithm, digits and period of the
 * server's own link are kept where they are not the standard ones; a link that does not parse gives the standard ones.
 */
internal fun authenticatorLink(secret: String, serverLink: String, host: String): String {
    fun enc(s: String) = buildString {
        for (b in s.encodeToByteArray()) {
            val c = (b.toInt() and 0xff).toChar()
            if (c.isLetterOrDigit() && c.code < 0x80 || c in "-._~") append(c) else append('%').append((b.toInt() and 0xff).toString(16).uppercase().padStart(2, '0'))
        }
    }
    val config = runCatching { Totp.parseUri(serverLink) }.getOrNull()
    return buildString {
        append("otpauth://totp/andvari:").append(enc(host.ifEmpty { "andvari" }))
        append("?secret=").append(enc(secret)).append("&issuer=andvari")
        if (config != null) {
            if (config.algorithm.name != "SHA1") append("&algorithm=").append(config.algorithm.name)
            if (config.digits != 6) append("&digits=").append(config.digits)
            if (config.periodSeconds != 30) append("&period=").append(config.periodSeconds)
        }
    }
}
