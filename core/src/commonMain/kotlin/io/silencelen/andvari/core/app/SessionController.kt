package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.client.CardDisplay
import io.silencelen.andvari.core.client.HouseholdCopy
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.KdfReKeyCore
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.OriginCanon
import io.silencelen.andvari.core.client.OriginProbeFence
import io.silencelen.andvari.core.client.SaveOutcome
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.client.UpgradeRequiredException
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.autofill.SavedUri
import io.silencelen.andvari.core.client.autofill.UriMatch
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
import io.silencelen.andvari.core.crypto.GeneratorOptions
import io.silencelen.andvari.core.crypto.MemberRecovery
import io.silencelen.andvari.core.crypto.PasswordGenerator
import io.silencelen.andvari.core.crypto.Totp
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.ClientPolicy
import kotlinx.coroutines.CoroutineScope
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

    /** H08: a lock on leaving the foreground that waited for a running action. */
    private var backgroundLockPending = false

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
    )

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
        checkIdleLock()
        if (tickMs > 0) {
            sinceSyncMs += tickMs
            if (sinceSyncMs >= SYNC_EVERY_MS) backgroundSync()
        }
    }

    /** The app came to the foreground: the idle check first, then a quiet sync. */
    fun onForeground() {
        backgroundLockPending = false // the person is back: a lock still waiting for an action is void
        checkIdleLock()
        backgroundSync()
        refreshPolicyIfStale()
        refreshSaveQueue() // a login captured while the app was open in the background
    }

    /** The app left the foreground: the vault locks (a suspended app cannot run the idle timer). */
    fun onBackground() {
        if (session.get() == null) return
        // H08: never close the engine under a running action; the lock lands when it ends.
        if (state.busy) {
            backgroundLockPending = true
            return
        }
        lock(REASON_BACKGROUND)
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
            editable = doc.type == "login" && role != "reader" && live.account.canSealUnder(item.vaultId),
            previousPasswords = doc.login?.passwordHistory?.size ?: 0,
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

    /** Add a login ([itemId] null) to the personal vault, or save an edit of one. */
    @Throws(CancellationException::class)
    suspend fun saveLogin(itemId: String?, input: LoginInput): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        if (input.name.isBlank()) return@action ActionResult.Failed(NAME_REQUIRED)
        val totp = if (input.totp.isBlank()) "" else Totp.normalize(input.totp)
        if (totp.isNotEmpty() && runCatching { Totp.parseUri(totp) }.isFailure) return@action ActionResult.Failed(TOTP_INVALID)
        val existing = itemId?.let { live.engine.item(it) ?: return@action ActionResult.Failed(ITEM_GONE) }
        // A9 review LOW-2: a new item never goes to a guessed vault.
        if (existing == null && live.account.personalVaultId.isEmpty()) return@action ActionResult.Failed(HouseholdCopy.NO_PERSONAL_VAULT)
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
        busy()
        // INV-EDIT: an edit is sealed under the vault its item lives in; a new login goes to the personal vault.
        val outcome = live.engine.save(itemId, doc, existing?.vaultId)
        if (session.get() !== live) return@action ActionResult.NotDone(null) // locked meanwhile
        update { it.copy(busy = false, items = summaries(it.query), notice = if (outcome == SaveOutcome.QUEUED) HouseholdCopy.SAVE_OFFLINE else it.notice) }
        writeFillSnapshot()
        ActionResult.Ok
    }

    /** Delete an item (it goes to the server's trash). */
    @Throws(CancellationException::class)
    suspend fun deleteItem(itemId: String): ActionResult = action {
        val live = session.get() ?: return@action ActionResult.NotDone(null)
        busy()
        val outcome = live.engine.remove(itemId)
        if (session.get() !== live) return@action ActionResult.NotDone(null)
        update { it.copy(busy = false, items = summaries(it.query), notice = if (outcome == SaveOutcome.QUEUED) HouseholdCopy.SAVE_OFFLINE else it.notice) }
        writeFillSnapshot()
        ActionResult.Ok
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
        update { it.copy(busy = false, items = summaries(it.query), notice = SYNCED) }
        writeFillSnapshot()
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
        if (backgroundLockPending && !state.busy) {
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
            // F26: a definitive rejection is a session-end: the ladder purged the session; say why on sign-in.
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
        update {
            it.copy(
                screen = AppScreen.VAULT, items = summaries(it.query), busy = false, error = null, totpRequired = false,
                lockReason = null, recoveryCaptureError = null, recoveryReplacedNotice = false,
            )
        }
        refreshQuick()
        refreshPolicyIfStale()
        writeFillSnapshot()
        refreshSaveQueue()
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
        runCatching { saves.discard(id) }
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
        runCatching { saves.dismiss() }
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
            FirstSync.Offline -> update { if (it.notice == SAVES_UNREADABLE) it else it.copy(notice = OFFLINE) }
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
        if (s.busy) return // never close the engine under a running action
        if (session.idleExpired()) lock(idleReason)
    }

    private fun lock(reason: String?) {
        session.lock()
        saves.locked()
        zeroSecrets()
        backgroundLockPending = false
        val stored = store.load()
        update { cleared(it, reason).copy(screen = landingScreen(), accountEmail = stored?.email) }
        refreshQuick() // gap 6: the flags are recomputed for the screen this lands on
    }

    /** A definitive in-session rejection: the coordinator locked and purged the session; the sign-in surface, with the reason. */
    private fun endRejectedSession() {
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
                if (session.get() === live) update { it.copy(syncing = false, items = summaries(it.query)) } else update { it.copy(syncing = false) }
                writeFillSnapshot()
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
        pendingSaves = emptyList(), appliedSaves = emptyList(),
    )

    private companion object {
        const val SYNC_EVERY_MS = 5 * 60 * 1000L
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
        const val NAME_REQUIRED = "Give the login a name."
        const val TOTP_INVALID = "That one-time code key isn't valid base32 or an otpauth:// link."
        const val ITEM_GONE = "This item is no longer here."
    }
}
