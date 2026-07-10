package io.silencelen.andvari.desktop

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.ApiException
import io.silencelen.andvari.core.client.CopyDeniedException
import io.silencelen.andvari.core.client.ItemChangedException
import io.silencelen.andvari.core.client.MoveGesture
import io.silencelen.andvari.core.client.VaultInfo
import io.silencelen.andvari.core.client.UpgradeRequiredException
import io.silencelen.andvari.core.client.AttachmentPlan
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.CsvImport
import io.silencelen.andvari.core.client.DecryptedItemVersion
import io.silencelen.andvari.core.client.DeletedItemView
import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupAttachmentEntry
import io.silencelen.andvari.core.client.BackupItem
import io.silencelen.andvari.core.client.BackupPayload
import io.silencelen.andvari.core.client.BackupPreflight
import io.silencelen.andvari.core.client.BackupResult
import io.silencelen.andvari.core.client.BackupSkipped
import io.silencelen.andvari.core.client.BackupVault
import io.silencelen.andvari.core.client.CsvPreflight
import io.silencelen.andvari.core.client.ExportCsv
import io.silencelen.andvari.core.client.ExportPlanner
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.sqliteVaultCache
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.PendingUpload
import io.silencelen.andvari.core.client.PlannedAttachment
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.client.Tokens
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.model.ClientPolicy
import io.silencelen.andvari.core.model.LoginRequest
import io.silencelen.andvari.core.model.TotpSetupResponse
import io.silencelen.andvari.core.model.TotpStatus
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption

sealed interface DesktopScreen {
    data object Loading : DesktopScreen
    data object Welcome : DesktopScreen
    data class Unlock(val email: String) : DesktopScreen
    data object Vault : DesktopScreen
    data object Settings : DesktopScreen
    data object Trash : DesktopScreen
}

/** F74: the Settings server-TOTP status fetch as an honest tri-state — Failed must STOP
 *  the spinner and offer Retry, instead of spinning forever beside its own error (the old
 *  shape used totpStatus==null for both "checking" and "check failed"). */
enum class TotpLoad { Pending, Ready, Failed }

/**
 * Plain state holder for the desktop app (no AndroidX ViewModel). Drives the shared
 * :core client (Account + AndvariApi[java engine] + SyncEngine) and exposes Compose
 * state. Mirrors the Android AndvariViewModel.
 */
class DesktopState(private val scope: CoroutineScope) {
    private val store = DesktopSessionStore()

    init {
        // One-time: bump an old LAN-default server URL to the tailnet default before any
        // state reads it (mirrors Android's MainActivity.migrateDefaultOnce).
        store.migrateDefaultOnce()
        // Inactivity auto-lock watcher (spec 01 §8, 1 s resolution) + the spec 03 §6 poll
        // (every 5 min while unlocked). Both live on the window's scope: they die with it.
        scope.launch {
            while (true) {
                delay(1_000)
                maybeIdleLock()
            }
        }
        scope.launch {
            while (true) {
                delay(POLL_INTERVAL_MS)
                backgroundSync()
            }
        }
    }

    var screen by mutableStateOf<DesktopScreen>(DesktopScreen.Loading)
        private set
    var items by mutableStateOf<List<VaultItem>>(emptyList())
        private set
    // Held envelopes newer than this build can decrypt (fail-closed) — the vault list
    // shows them as a one-line "N items need an app update" banner instead of nothing.
    var needsUpdateCount by mutableStateOf(0)
        private set
    var policy by mutableStateOf<ClientPolicy?>(null)
        private set
    var busy by mutableStateOf(false)
        private set
    var error by mutableStateOf<String?>(null)
    /** F71 review: the editor's INLINE save error. Kept apart from the global [error] —
     *  backgroundSync writes that one every 5 min / on focus, and piping it into the editor
     *  painted "sync failed" above Save mid-composition as if the user's edit had failed. */
    var saveError by mutableStateOf<String?>(null)
    /** F71 review: the NEW-item draft id, stable across save retries within one editor
     *  session (attachments committed by a failed attempt are bound to it — a fresh mint
     *  per retry trips the push's attachment_mismatch forever). One editor at a time on
     *  desktop, so one field; cleared on success and on cancel. */
    private var draftItemId: String? = null
        private set
    var notice by mutableStateOf<String?>(null)
        private set
    var baseUrl by mutableStateOf(store.baseUrl)
        private set
    var updateAvailable by mutableStateOf<String?>(null)
        private set
    // Set when the server 426s this build (minVersion pin) — the UI shows a blocking
    // "update required" screen. Advisory: the gate is a nudge for honest clients.
    var upgradeRequired by mutableStateOf<String?>(null)
        private set
    var signInTotpRequired by mutableStateOf(false)
        private set
    // F58: the sign-in SessionResponse flagged this account "must change password" — an admin
    // recovery left a TEMPORARY password live. Desktop has no change-password screen (deferred),
    // so the UI shows a prominent, non-dismissable root banner directing to the web app.
    // Deliberately survives lock(): the temp password is still what unlocks, and accountKeys()
    // (the unlock path) doesn't carry the flag — so within a run the nag can only clear via
    // sign-out or a fresh sign-in that returns false (i.e. after the change actually happened).
    var mustChangePassword by mutableStateOf(false)
        private set
    // F57: this account's escrow is sealed to a superseded org recovery key (re-ceremony) — the
    // vault screen offers a re-seal. escrowFingerprint is the CURRENT org fingerprint (re-seal
    // target + the value the user verifies against the new printed sheet).
    var escrowStale by mutableStateOf(false)
        private set
    var escrowFingerprint by mutableStateOf("")
        private set
    // Item history (feature): decrypted archived versions of the currently-viewed item, loaded on
    // demand (null = not loaded / loading). Restore a chosen version with saveItem.
    var itemVersions by mutableStateOf<List<DecryptedItemVersion>?>(null)
        private set
    // Item undelete (feature): the Trash screen's deleted items (null = not loaded / loading).
    var deletedItems by mutableStateOf<List<DeletedItemView>?>(null)
        private set
    // F19 move/copy: the running gesture's attachment progress (null unless attachments copy)
    // and an INLINE error kept separate from the global `error` bar so the Detail control can
    // show it beside a Retry button (web MoveCopyControl parity).
    var moveProgress by mutableStateOf<Pair<Int, Int>?>(null)
        private set
    var moveError by mutableStateOf<String?>(null)
        private set
    // F71: the in-flight save's per-upload attachment progress (null unless a save with
    // new attachments is running) — the editor shows it while it stays open under `busy`.
    var saveProgress by mutableStateOf<Pair<Int, Int>?>(null)
        private set
    var totpStatus by mutableStateOf<TotpStatus?>(null)
        private set
    // F74: tri-state for the status fetch above — totpStatus==null alone can't distinguish
    // "still checking" from "check failed", which left a live spinner beside a stale error.
    var totpLoad by mutableStateOf(TotpLoad.Pending)
        private set
    var totpSetupInfo by mutableStateOf<TotpSetupResponse?>(null)
        private set
    var totpError by mutableStateOf<String?>(null)
        private set
    // CSV import (spec 06 + guided importers): a preview/plan kept across a retry so an
    // interrupted import replays the SAME itemIds idempotently instead of duplicating.
    var importPlan by mutableStateOf<CsvImport.ImportPlan?>(null)
        private set
    var importFormat by mutableStateOf<CsvImport.ImportFormat?>(null)
        private set
    // The guide the user picked — instructions + the preview's mismatch hint only; header
    // detection stays authoritative (a Bitwarden file picked under "Chrome" imports fine).
    var importSource by mutableStateOf<ImportSource?>(null)
        private set
    // A10 LastPass mangle heuristic: several parsed values look HTML-entity-encoded
    // (&amp; and friends) — the preview shows a re-export hint. Never auto-decoded.
    var importMangled by mutableStateOf(false)

    /** A9: physical file line → 1-based data-row ordinal, so a row error reads
     *  "row N (file line M)" even when a multi-line quoted note shifts physical lines. */
    var importRowOrdinals by mutableStateOf<Map<Int, Int>>(emptyMap())
        private set
    var importReport by mutableStateOf<CsvImport.ImportReport?>(null)
        private set
    var importError by mutableStateOf<String?>(null)
        private set
    var importProgress by mutableStateOf<Pair<Int, Int>?>(null)
        private set
    var importBusy by mutableStateOf(false)
        private set
    var importDone by mutableStateOf(false)
        private set
    // S2: the import's DESTINATION vault. Always assigned WITH importPlan (importFromFile /
    // importSetVault) and read with it in importConfirm — the F75 dedupe fingerprints the
    // plan against this vault, so plan and commit must never name different ones. Survives
    // importDone so the summary can name the vault; cleared on dismiss.
    var importVaultId by mutableStateOf<String?>(null)
        private set
    // S2: the parsed file, retained ONLY while the preview is open — importSetVault re-plans
    // from it against another vault's projections. Plaintext (like importPlan.items, which
    // outlives it anyway); dropped in importDismiss.
    private var importParsed: CsvImport.Parsed? = null
    // Export & backup (spec 07) — preflight dialogs + post-backup summary.
    var backupPreflight by mutableStateOf<BackupPreflight?>(null)
        private set
    var backupResult by mutableStateOf<BackupResult?>(null)
        private set
    var csvPreflight by mutableStateOf<CsvPreflight?>(null)
        private set
    var lastExportAt by mutableStateOf(store.lastExportAt)
        private set

    private var api: AndvariApi? = null
    private var account: Account? = null
    // F82: raw-row reads (vault rows / envelopes — the spec 07 export enumerates from
    // them) go through the engine's read surface; no carried cache reference here.
    private var engine: SyncEngine? = null
    // F19 gestures memoized per (item|target|mode): a RETRY of a transiently-failed move/copy
    // reuses the SAME gesture (fresh ids were minted ONCE) so the server's mutation dedup
    // converges instead of duplicating. Kept ONLY across a failed attempt of the same
    // UNCHANGED item — a rev change remints (a stale gesture would rebuild attachments from a
    // stale snapshot); Cancel/mode-change discards. Mirrors Android's moveGestures.
    private val moveGestures = mutableMapOf<String, MoveGesture>()

    private fun newApi(tokens: Tokens? = null) =
        AndvariApi(store.baseUrl, HttpClient(Java), tokens, { store.updateTokens(it) }, platform = desktopPlatform())

    fun start() {
        scope.launch {
            val probe = newApi()
            runCatching { probe.clientPolicy() }.onSuccess { p ->
                applyPolicy(p) // UI state + persisted offline fallbacks (auto-lock included)
                // Policy may forbid the durable cache; purge any existing file the moment
                // we learn it (spec 02 §8), even before unlock — mirrors the Android client.
                if (!p.offlineCacheAllowed) store.load()?.let { purgeOfflineData(it.userId) }
            }
            probe.close()
            runCatching { checkForUpdate(store.baseUrl) }.onSuccess { updateAvailable = it }
            val session = store.load()
            screen = if (session != null && session.accessToken.isNotEmpty()) DesktopScreen.Unlock(session.email) else DesktopScreen.Welcome
            baseUrl = store.baseUrl
        }
    }

    fun updateServer(url: String) {
        store.baseUrl = url.trim().removeSuffix("/")
        baseUrl = store.baseUrl
    }

    fun clearError() { error = null }
    fun clearSaveError() { saveError = null }
    /** Editor closed (cancel or success): the next editor session starts a fresh draft.
     *  NOT part of [clearSaveError] — dismissing the inline error must keep the draft id,
     *  or the very next retry re-mints and re-wedges on attachment_mismatch. */
    fun endEditorSession() { saveError = null; draftItemId = null }
    fun clearNotice() { notice = null }

    fun signIn(email: String, password: String, totp: String? = null) = op {
        val a = newApi()
        val pre = a.prelogin(email)
        // Argon2id (64 MiB, twice per sign-in) is CPU-bound — never on the UI thread.
        val authKey = withContext(Dispatchers.Default) { Account.deriveAuthKey(password, pre.kdfSalt, pre.kdfParams) }
        val s = try {
            a.login(LoginRequest(email, authKey, Account.deviceInfo(deviceName(), desktopPlatform()), totp = totp))
        } catch (e: ApiException) {
            a.close()
            when (e.code) {
                // Server-TOTP is enrolled: reveal the code field and let the user retry.
                "totp_required" -> { signInTotpRequired = true; busy = false; return@op }
                "public_login_requires_totp" ->
                    throw ApiException(e.status, e.code, "this account has no server-TOTP enrolled; public access is blocked")
                else -> throw e
            }
        }
        val acct = withContext(Dispatchers.Default) { Account.unlock(s.userId, password, s.accountKeys) }
        store.save(DesktopSession(store.baseUrl, s.userId, email, s.accessToken, s.refreshToken))
        persistAccountKeys(s.accountKeys)
        bind(a, acct); syncNow(engine!!)
        escrowStale = s.accountKeys.escrowStale; escrowFingerprint = s.accountKeys.escrowFingerprint
        mustChangePassword = s.mustChangePassword // F58: a recovery temp password forces the banner
        signInTotpRequired = false
        toVault()
    }

    fun unlock(email: String, password: String) = op {
        val session = store.load() ?: error("no session")
        val a = newApi(session.tokens())
        // Offline unlock (spec 02 §8): cached keys when the network is down; wipe on a
        // definitive auth rejection.
        val keys = try {
            a.accountKeys().also { persistAccountKeys(it) }
        } catch (e: java.io.IOException) {
            store.loadAccountKeys() ?: throw e
        } catch (e: ApiException) {
            if (e.status == 401) { purgeOfflineData(session.userId); store.clear() }
            throw e
        }
        // KDF off the UI thread (argon2id 64 MiB — the unlock spinner must animate).
        val acct = withContext(Dispatchers.Default) { Account.unlock(session.userId, password, keys) }
        bind(a, acct)
        escrowStale = keys.escrowStale; escrowFingerprint = keys.escrowFingerprint
        runCatching { syncNow(engine!!) }.onFailure {
            if (it is java.io.IOException) notice = "Offline — showing cached data" else throw it
        }
        toVault()
    }

    fun enroll(invite: String, email: String, name: String, password: String) = op {
        val pol = policy ?: newApi().clientPolicy().also { policy = it }
        val a = newApi()
        val recoveryPub = Bytes.fromB64(a.recoveryPubkey())
        // Key generation + KDF are CPU-bound (argon2id) — off the UI thread.
        val (req, acct) = withContext(Dispatchers.Default) {
            Account.enroll(
                inviteToken = invite, email = email, displayName = name.ifBlank { email.substringBefore('@') },
                password = password, params = pol.kdfParams,
                recoveryPublicKey = recoveryPub, recoveryFingerprint = pol.recoveryFingerprint, deviceName = deviceName(),
            )
        }
        val s = a.register(req)
        store.save(DesktopSession(store.baseUrl, s.userId, email, s.accessToken, s.refreshToken))
        persistAccountKeys(s.accountKeys)
        bind(a, acct); syncNow(engine!!)
        escrowStale = s.accountKeys.escrowStale; escrowFingerprint = s.accountKeys.escrowFingerprint
        mustChangePassword = s.mustChangePassword // F58: never true for a fresh enroll; wired for truth
        toVault()
    }

    /**
     * F57: re-seal this account's UVK to the CURRENT org recovery key after a re-ceremony. The user
     * must have TYPED the new recovery fingerprint's short form from their PRINTED sheet (spec 04
     * §2(3)); we re-check it, then [Account.resealEscrowFor] binds the server-fetched recovery pubkey
     * to that verified fingerprint (refusing on mismatch) so a hostile server can't redirect the
     * escrow. Non-blocking: on success the banner clears; a failure surfaces as an error.
     */
    fun resealEscrow(shortFormEntry: String) = op {
        val a = api
        val acct = account
        val fp = escrowFingerprint
        if (a == null || acct == null) { busy = false; return@op }
        if (!Escrow.shortFormMatches(shortFormEntry, fp)) {
            busy = false; error = "That doesn't match this server's recovery key — check your printed recovery sheet."
            return@op
        }
        val pub = withContext(Dispatchers.Default) { a.recoveryPubkey() }
        val upload = withContext(Dispatchers.Default) { acct.resealEscrowFor(pub, fp) }
        a.escrowSelf(upload)
        busy = false; escrowStale = false; notice = "Account re-protected — your recovery is up to date."
    }

    // F18: [vaultId] is honored ONLY for a NEW item (itemId == null) — the core save guard
    // keeps an existing item in its own vault (server enforces vault_mismatch), so a restore
    // (itemId != null) leaves it null and lands the item back where it was.
    // F71: [onSaved] fires ONLY on success — the editor closes there and nowhere else, so a
    // failed save/upload keeps the typed fields + picked attachments editable with the error
    // beside them (the Android op{}+onSaved contract).
    fun saveItem(itemId: String?, doc: ItemDoc, uploads: List<PendingUpload> = emptyList(), vaultId: String? = null, onSaved: () -> Unit = {}) = op {
        saveError = null
        if (itemId == null && draftItemId == null) draftItemId = account?.newItemId()
        try {
            // Named: a trailing lambda binds to the LAST parameter (the runGesture rule).
            engine!!.saveWithUploads(
                itemId, doc, uploads, vaultId,
                onProgress = { done, total -> saveProgress = done to total },
                newItemId = if (itemId == null) draftItemId else null,
            )
        } catch (e: UpgradeRequiredException) {
            throw e // the blocking upgrade screen owns 426 — never an inline save error
        } catch (t: Throwable) {
            // Route the failure to the EDITOR's error surface and stop: the editor stays
            // open (F71) and the global bar stays quiet — op's generic catch never sees it.
            busy = false
            saveError = t.message ?: "save failed"
            return@op
        } finally {
            saveProgress = null
        }
        draftItemId = null
        refreshItems()
        onSaved()
    }

    /** Item history (feature): load + decrypt the currently-viewed item's archived versions. */
    fun loadItemVersions(itemId: String, vaultId: String) = op {
        itemVersions = null
        itemVersions = engine!!.itemVersions(itemId, vaultId)
        busy = false
    }

    fun clearItemVersions() { itemVersions = null }
    fun deleteItem(itemId: String) = op { engine!!.remove(itemId); refreshItems() }
    fun refresh() = op { syncNow(engine!!); refreshItems() }
    fun item(itemId: String): VaultItem? = engine?.item(itemId)

    /** Server-declared role for a vault (mirrors web's account.roleFor) — null when unknown. */
    fun roleFor(vaultId: String): String? = account?.roleFor(vaultId)

    /** F81: vaultId → decrypted vault name for every held vault EXCEPT the personal one — the
     *  gold shared-vault badge on rows/detail. Decrypts each vault's metaBlob, so the UI calls
     *  it once per items-change (under remember(items)), never per row recomposition. */
    fun sharedVaultNames(): Map<String, String> {
        val acct = account ?: return emptyMap()
        return engine?.vaultInfos()?.filterNot { it.vaultId == acct.personalVaultId }
            ?.associate { it.vaultId to it.name }.orEmpty()
    }

    /**
     * F18: vaults a NEW item may be created in — the personal vault plus any shared vault we can
     * WRITE to (owner/writer). vaultInfos() is personal-first, so `.first()` is the default the
     * picker starts on. Existing items never move via the editor (the core save guard fences a
     * changed vaultId), so this is a new-item / move-target list only. Each call decrypts vault
     * metadata, so the UI reads it once (under remember), never per recomposition.
     */
    fun newItemVaultChoices(): List<VaultInfo> =
        engine?.vaultInfos()?.filter { it.type == "personal" || it.role == "owner" || it.role == "writer" }.orEmpty()

    /** F19: discard an item's memoized gestures + the inline move state — on Cancel or a
     *  mode switch, so the next gesture is minted fresh (a lingering gesture would replay a
     *  stale snapshot). A transient failure deliberately does NOT call this: the memo must
     *  survive so Retry replays the SAME ids (server dedup converges, never a duplicate). */
    fun clearMoveState(itemId: String) {
        moveGestures.keys.filter { it.startsWith("$itemId|") }.forEach { moveGestures.remove(it) }
        moveError = null
        moveProgress = null
    }

    /**
     * F19 (design §8): move (copy-leg-first, THEN delete source) or copy [itemId] into
     * [targetVaultId]. All gesture logic lives in core [SyncEngine.runGesture] (copy confirmed
     * before any delete, per-gesture idempotent mutationIds) — this only picks/reuses the
     * gesture and maps failures to inline copy. Sets the global [busy] so the idle auto-lock
     * defers (never yanks the engine mid-move). onDone fires ONLY on success (the caller closes
     * the picker + leaves the detail). Mirrors Android's moveOrCopyItem.
     */
    fun moveOrCopyItem(itemId: String, targetVaultId: String, move: Boolean, onDone: () -> Unit) {
        val e = engine ?: return
        val gKey = "$itemId|$targetVaultId|$move"
        busy = true; moveError = null; moveProgress = null
        scope.launch {
            try {
                val current = e.item(itemId)
                    ?: throw ApiException(409, "vault_state_changed", "This item is no longer here — it may have been removed or its vault deleted.")
                // Reuse the memo ONLY while the source content is unchanged — a different rev
                // IS different content, so remint (a stale gesture would rebuild attachments
                // from a stale snapshot). Fresh ids are minted exactly once per gesture.
                val memo = moveGestures[gKey]
                val g = if (memo != null && memo.sourceRev == current.rev) memo
                        else e.newMoveGesture(itemId, targetVaultId, move).also { moveGestures[gKey] = it }
                // Named: a trailing lambda would bind to `finalSync: Boolean`, not onProgress.
                e.runGesture(g, onProgress = { done, total -> moveProgress = done to total })
                moveGestures.remove(gKey)
                val target = e.vaultInfos().find { it.vaultId == targetVaultId }?.name ?: "the other vault"
                refreshItems() // clears busy; a MOVE also empties the detail (source item is gone)
                moveProgress = null
                notice = if (move) "Moved to “$target”." else "Copied to “$target”."
                onDone()
            } catch (t: Throwable) {
                moveProgress = null; busy = false
                when {
                    // Copy denied / source changed / a 403 are TERMINAL — drop the gesture so a
                    // fresh attempt re-reads state (never a blind replay of a doomed gesture).
                    t is CopyDeniedException -> { moveGestures.remove(gKey); moveError = "You don't have permission to add items to that vault — nothing was moved." }
                    t is ItemChangedException -> { moveGestures.remove(gKey); moveError = "This item changed while moving — go back, review it, and try again." }
                    t is ApiException && t.status == 403 -> { moveGestures.remove(gKey); moveError = t.message ?: "Move denied — nothing was moved." }
                    // Transient — KEEP the gesture so Retry replays the same ids (no duplicate).
                    else -> moveError = "That didn't finish. Press Retry — it won't create a duplicate."
                }
            }
        }
    }

    // ---- inactivity auto-lock + poll cadence (spec 01 §8 / spec 03 §6) ----

    // Clock choice: wall clock (System.currentTimeMillis). System.nanoTime is monotonic but
    // EXCLUDES time suspended on Linux (CLOCK_MONOTONIC), so a laptop that slept past the
    // window would wake "fresh". Wall time counts sleep — lid-closed-overnight locks on the
    // first tick after wake; an NTP step only shifts the lock by the adjustment, acceptable
    // for a minutes-scale window (and a backwards user clock change can only DELAY, which
    // the manual Lock button still covers).
    private var lastInteractionMs = System.currentTimeMillis()

    /** Record user interaction (pointer/key) — called from the window-level interceptors. */
    fun touch() {
        lastInteractionMs = System.currentTimeMillis()
    }

    /**
     * Lock if the inactivity window elapsed (policy `autoLockSeconds`; persisted last-known
     * value when the live policy hasn't loaded; 0 disables). Never yanks the engine under an
     * in-flight op ([busy]/import) — the durable queue would survive it, but the op would
     * surface a spurious error; the next 1 s tick re-checks, so the lock is deferred, not
     * skipped.
     */
    private fun maybeIdleLock() {
        if (engine == null) return
        val window = policy?.autoLockSeconds ?: store.autoLockSeconds
        if (window <= 0) return
        if (busy || importBusy) return
        if (System.currentTimeMillis() - lastInteractionMs >= window * 1000L) lock()
    }

    /**
     * Quiet poll sync (spec 03 §6: focus regained + every 5 min while unlocked): refresh
     * policy first (so autoLock/clipboard windows track admin changes mid-session), then
     * push-queue + pull. Reuses [busy] as the overlap guard — read and set on the single
     * UI thread, so it can't interleave with a user-initiated op. Offline blips stay
     * silent; anything else (rev regression, denied writes) surfaces like a manual sync.
     */
    fun backgroundSync() {
        val e = engine ?: return
        if (busy || importBusy) return
        busy = true
        scope.launch {
            runCatching { api?.clientPolicy() }.getOrNull()?.let { applyPolicy(it) }
            try {
                syncNow(e)
                items = e.items()
                needsUpdateCount = e.needsUpdateCount()
                busy = false
            } catch (t: Throwable) {
                busy = false
                if (t !is java.io.IOException) error = t.message ?: "sync failed"
            }
        }
    }

    /** Window regained focus: enforce the idle window FIRST, then catch up (spec 03 §6). */
    fun onWindowFocus() {
        maybeIdleLock()
        backgroundSync()
    }

    // ---- CSV import (spec 06 + guided importers, design 2026-07-09) ----

    /**
     * Bounded read → parse → vault-aware plan, all on-device (nothing is uploaded).
     * [source] is the guide the user picked — it informs instructions and the mismatch
     * hint ONLY; header detection stays authoritative. The plan step REFUSES (A8) when
     * the personal vault's projections aren't available rather than silently planning
     * against an empty vault (every duplicate would sail in unflagged).
     */
    fun importFromFile(file: File, source: ImportSource) {
        importDismiss()
        importSource = source
        val eng = engine
        val acct = account
        // A8: the existing-items seam is core-owned and REFUSES rather than degrades —
        // locked, or a personal vault that hasn't hydrated/synced yet, must never plan
        // against an empty `existing` (that would silently disable the dedupe). Mirrors
        // the Android ViewModel's gate exactly.
        if (eng == null || acct == null || eng.vaultInfos().none { it.vaultId == acct.personalVaultId }) {
            importError = "Couldn’t check your vault for items you already have — unlock and sync first, then try the import again."
            return
        }
        // BOUNDED read (mirrors Android's readBounded): the cap is enforced while
        // streaming, so a mislabeled multi-GB pick is rejected without being buffered.
        val bytes = try {
            file.inputStream().use { readBounded(it, CsvImport.MAX_BYTES) }
        } catch (t: Throwable) {
            importError = "Couldn't read ${file.name}: ${t.message}"; return
        }
        if (bytes == null) { importError = friendlyImport("too_large", source); return }
        try {
            val parsed = CsvImport.parse(bytes)
            importFormat = parsed.format
            importMangled = looksHtmlMangled(parsed)
            importRowOrdinals = CsvImport.rowOrdinalsByLine(bytes) // A9, same reader as parse
            // Vault-aware plan (F75): `existing` = the DESTINATION vault's light projections,
            // built by the core-owned builder — never raw item lists mapped here (A8).
            // S2: default destination = personal; ONE variable feeds the projections here and
            // (as importVaultId) the eventual importAll. The picker re-plans via importSetVault.
            val dest = acct.personalVaultId
            importParsed = parsed
            importVaultId = dest
            importPlan = CsvImport.plan(parsed, eng.importProjections(dest)) { acct.newItemId() }
        } catch (e: CsvImport.ImportException) {
            importError = friendlyImport(e.code, source)
        } catch (t: Throwable) {
            importError = t.message ?: "could not read that file"
        }
    }

    /**
     * Encrypt-and-push the planned items. Reuses plan.items on every call so a mid-import
     * failure is fixed with Retry (idempotent replay of the same itemIds), NOT a re-parse.
     */
    /**
     * S2: switch the import's destination vault — RE-PLANS the parsed file against that
     * vault's projections (the F75 dedupe is per-vault; a plan fingerprinted against one
     * vault must never commit into another). Plan and importVaultId are assigned together
     * after the off-thread plan, and importConfirm reads them together — the invariant is
     * structural. importBusy covers the re-plan: Confirm disables and re-entry no-ops.
     */
    fun importSetVault(vaultId: String) {
        val acct = account ?: return
        val eng = engine ?: return
        val parsed = importParsed ?: return
        // Web importLocked parity: after an import ATTEMPT (error = partial, done = landed)
        // a re-plan would mint new ids — breaking Retry's idempotent replay and duplicating
        // the already-landed rows into the new destination. Only Retry or Dismiss remain.
        if (importBusy || importError != null || importDone || vaultId == importVaultId) return
        // Refuse-not-degrade (A8), now gating the CHOSEN vault: the picker only offers held
        // vaults, but a sync-time removal can race the click — never re-plan against a vault
        // we no longer hold (it would plan as if the vault were empty).
        if (eng.vaultInfos().none { it.vaultId == vaultId }) {
            importPlan = null
            importError = "That vault isn’t available any more — sync and try the import again."
            return
        }
        importBusy = true; importError = null
        scope.launch {
            try {
                val plan = withContext(Dispatchers.Default) {
                    CsvImport.plan(parsed, eng.importProjections(vaultId)) { acct.newItemId() }
                }
                importPlan = plan
                importVaultId = vaultId
                importProgress = null
            } catch (t: Throwable) {
                importError = t.message ?: "could not re-check that file" // plan/vault unchanged — still a matched pair
            } finally {
                importBusy = false
            }
        }
    }

    fun importConfirm() {
        if (importBusy) return // state-level: the button's enabled flag lags a frame behind a re-plan
        // S2: plan + destination read together — they were assigned together (importFromFile /
        // importSetVault), which is what keeps the F75 invariant (never re-read the picker).
        val plan = importPlan ?: return
        val dest = importVaultId
        importBusy = true; importError = null; importProgress = 0 to plan.items.size
        scope.launch {
            try {
                engine!!.importAll(plan.items, onProgress = { done, total -> importProgress = done to total }, vaultId = dest)
                // The destination can be deleted INTO GRACE mid-import: denials park (F21) and
                // importAll returns normally — success copy telling the user to delete the CSV
                // would then be a lie. A held/gone destination is not a success.
                if (dest != null && engine?.vaultInfos()?.none { it.vaultId == dest } == true) {
                    importBusy = false
                    importError = "The destination vault was removed while importing — the rows are parked and will land only if it is restored. KEEP the CSV file."
                    return@launch
                }
                importReport = plan.report
                importDone = true
                importBusy = false
                items = engine?.items() ?: emptyList()
            } catch (t: Throwable) {
                importBusy = false
                importError = "Import interrupted — press Retry to finish (no duplicates will be created)."
            }
        }
    }

    fun importDismiss() {
        importPlan = null; importFormat = null; importReport = null; importSource = null
        importError = null; importProgress = null; importBusy = false; importDone = false
        importMangled = false; importVaultId = null; importParsed = null
    }

    private fun friendlyImport(code: String, source: ImportSource?): String = when (code) {
        "too_large" -> "That file is larger than 10 MiB — far bigger than any real password export."
        "too_many_rows" -> "That file has more than 10,000 rows. Split it into smaller files and import each."
        "unrecognized_header" -> when (source) {
            // Per-source hint (design): older 1Password CSV shapes vary too wildly to read.
            ImportSource.ONEPASSWORD ->
                "This doesn’t look like a 1Password 8 CSV. Older 1Password export shapes vary — export from 1Password 8+ as CSV, or use a Bitwarden CSV as an intermediate."
            null -> "This doesn’t look like a password export this app understands."
            else -> "This doesn’t look like a ${source.label} export — or any password CSV this app understands. Re-check the export steps and try again."
        }
        else -> "That file could not be read ($code)."
    }

    /**
     * Read at most [limit] bytes from [input]; return null if the source is larger (so a
     * multi-GB pick is rejected without ever being buffered in memory). Mirrors Android's
     * readBounded and CsvImport's own size cap, so a file that fits here also passes parse().
     */
    private fun readBounded(input: java.io.InputStream, limit: Int): ByteArray? {
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(64 * 1024)
        var total = 0L
        while (true) {
            val r = input.read(buf)
            if (r < 0) break
            total += r
            if (total > limit) return null
            out.write(buf, 0, r)
        }
        return out.toByteArray()
    }

    /** A10: fires when MULTIPLE parsed values carry HTML entities — one legitimate
     *  "&amp;" in a single note shouldn't cry wolf, a file full of them should. */
    private fun looksHtmlMangled(parsed: CsvImport.Parsed): Boolean {
        var hits = 0
        for (row in parsed.rows) {
            for (v in listOf(row.name, row.url, row.username, row.password, row.notes, row.totp ?: "")) {
                if (HTML_ENTITY.containsMatchIn(v) && ++hits >= 2) return true
            }
        }
        return false
    }

    /** Seed-derived identity short code (spec 01 §5) — read out during sharing verification. */
    fun identityCode(): String? = account?.identityFingerprintShort()

    // ---- attachments ----

    /** Mint the SECRET half of a new attachment: fresh id + random per-file key (spec 02 §6). */
    fun newAttachmentRef(name: String, size: Long): AttachmentRef {
        val acct = account ?: throw IllegalStateException("vault is locked")
        return AttachmentRef(id = acct.newItemId(), name = name, size = size, fileKey = Bytes.toB64(acct.newFileKey()))
    }

    /** Download + decrypt an attachment off the UI thread and write it to [dest] via the
     *  same temp-then-atomic-move discipline as the exports ([writeVerifiedAtomically],
     *  F71): a failed write must never leave a torn file — or destroy a pre-existing
     *  one — at [dest]. */
    fun saveAttachmentTo(ref: AttachmentRef, dest: File) = op {
        withContext(Dispatchers.IO) {
            val bytes = engine!!.downloadAttachment(ref)
            try { writeVerifiedAtomically(dest, bytes) } finally { bytes.fill(0) } // attachment plaintext — wipe our copy
        }
        busy = false
        notice = "Saved ${ref.name} to ${dest.absolutePath}"
    }

    // ---- settings / server TOTP ----

    fun openSettings() {
        totpSetupInfo = null
        backupPreflight = null; backupResult = null; csvPreflight = null
        lastExportAt = store.lastExportAt
        screen = DesktopScreen.Settings
        loadTotpStatus()
    }

    /** F74: (re)fetch the server-TOTP status — Pending spins, Failed shows the error AND a
     *  Retry that re-runs exactly this, Ready renders the real enrolled/not-enrolled blocks. */
    fun loadTotpStatus() {
        totpLoad = TotpLoad.Pending; totpStatus = null; totpError = null
        scope.launch {
            runCatching { api!!.totpStatus() }
                .onSuccess { totpStatus = it; totpLoad = TotpLoad.Ready }
                .onFailure { totpError = it.message ?: "couldn't load TOTP status"; totpLoad = TotpLoad.Failed }
        }
    }

    fun closeSettings() {
        totpSetupInfo = null; totpError = null
        screen = DesktopScreen.Vault
    }

    /** Item undelete (feature): open the Trash screen and load the deleted items. */
    fun openTrash() {
        deletedItems = null
        screen = DesktopScreen.Trash
        loadDeletedItems()
    }

    fun loadDeletedItems() = op {
        deletedItems = engine!!.deletedItems()
        busy = false
    }

    /** Item undelete (feature): restore a deleted item, then refresh the trash list + the vault. */
    fun restoreDeleted(itemId: String, vaultId: String, doc: ItemDoc) = op {
        engine!!.restoreDeleted(itemId, vaultId, doc)
        deletedItems = engine!!.deletedItems()
        refreshItems()
        busy = false
    }

    /** Item undelete (F49): "Delete forever" a tombstoned item, then refresh the trash list. */
    fun purgeDeleted(itemId: String) = op {
        engine!!.purgeDeleted(itemId)
        deletedItems = engine!!.deletedItems()
        busy = false
    }

    fun closeTrash() {
        deletedItems = null
        screen = DesktopScreen.Vault
    }

    fun beginTotpSetup() = totpOp { totpSetupInfo = api!!.totpSetup() }

    fun confirmTotp(code: String) = totpOp {
        totpStatus = api!!.totpConfirm(code.trim())
        totpSetupInfo = null
    }

    fun disableTotp(code: String) = totpOp { totpStatus = api!!.totpDisable(code.trim()) }

    private fun totpOp(block: suspend () -> Unit) {
        busy = true; totpError = null
        scope.launch {
            try { block(); busy = false } catch (t: Throwable) {
                busy = false
                totpError = if (t is ApiException && t.code == "bad_totp_code") {
                    "That code isn't right — check your authenticator and try again."
                } else t.message ?: "something went wrong"
            }
        }
    }

    // ---- export & backup (spec 07) ----

    /**
     * "Back up vault…" step 1: sync first (spec 07 — clients MUST sync before
     * snapshotting; offline → proceed with a "vault as of last sync <time>" note), then
     * open the preflight dialog. Runs under [busy], which maybeIdleLock defers on — the
     * auto-lock cannot yank the engine mid-flow.
     */
    fun backupBegin() {
        val e = engine ?: return
        busy = true; error = null; notice = null
        scope.launch {
            val offline = try {
                syncNow(e); false
            } catch (t: java.io.IOException) {
                true // offline is fine — export the cached snapshot, visibly dated
            } catch (t: Throwable) {
                busy = false; error = t.message ?: "sync failed"; return@launch
            }
            val acct = account
            if (acct == null) { busy = false; return@launch }
            items = e.items()
            backupPreflight = BackupPreflight(ExportPlanner.vaultLines(e, acct), offlineNote(offline))
            busy = false
        }
    }

    fun backupDismiss() { backupPreflight = null }
    fun backupResultDismiss() { backupResult = null }

    /** Live §2.5 attachment plan for the preflight dialog's current vault selection
     *  (pure in-memory reads — cheap enough for recomposition). */
    fun attachmentPlan(selected: Set<String>): AttachmentPlan {
        val e = engine ?: return AttachmentPlan(emptyList(), 0L, emptyList())
        val order = backupPreflight?.vaults?.map { it.vaultId }?.filter { it in selected }
            ?: return AttachmentPlan(emptyList(), 0L, emptyList())
        return ExportPlanner.planAttachments(ExportPlanner.orderedItems(e, order))
    }

    /**
     * "Back up vault…" step 2: build → verify → write [dest] via temp-then-atomic-move
     * (see [writeVerifiedAtomically]), all off the UI thread (saveAttachmentTo's
     * pattern). The catch deliberately does NOT touch [dest]: failures before the move
     * happen entirely in the temp file (the helper cleans it up), so a pre-existing
     * backup at [dest] is never destroyed by a failed re-export — the old
     * `dest.delete()` here turned "one good backup" into "zero backups" whenever
     * build/fetch/verify threw before a byte was written. Success records lastExportAt
     * locally and counts as user activity (touch()).
     */
    fun backupRun(selectedVaults: Set<String>, includeAttachments: Boolean, passphrase: String, dest: File) {
        val e = engine ?: return
        val acct = account ?: return
        busy = true; error = null; backupPreflight = null
        scope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    buildAndWriteBackup(e, acct, selectedVaults, includeAttachments, passphrase, dest)
                }
                store.lastExportAt = System.currentTimeMillis()
                lastExportAt = store.lastExportAt
                touch() // export counts as user activity (spec 07 §2.6 / 01 §8)
                busy = false
                backupResult = result
            } catch (t: Throwable) {
                busy = false; error = t.message ?: "backup failed"
            }
        }
    }

    private suspend fun buildAndWriteBackup(
        e: SyncEngine,
        acct: Account,
        selectedVaults: Set<String>,
        includeAttachments: Boolean,
        passphrase: String,
        dest: File,
    ): BackupResult {
        val crypto = acct.cryptoProvider()

        // Snapshot every input up front (cheap in-memory reads): a concurrent manual lock
        // can close the engine's cache underneath a long build, and reads-then-crypto keeps
        // that window to "attachment downloads fail → named skips", never a torn payload.
        val allLines = ExportPlanner.vaultLines(e, acct)
        val lines = allLines.filter { it.vaultId in selectedVaults }
        val exportItems = ExportPlanner.orderedItems(e, lines.map { it.vaultId })
        // Enumerate undecryptable envelopes (missing VK / newer formatVersion) — but not
        // those of a VK-held vault the user explicitly deselected.
        val deselected = allLines.map { it.vaultId }.toSet() - selectedVaults
        val undecryptable = ExportPlanner.undecryptable(e).filter { it.vaultId !in deselected }
        val formatVersions = e.envelopes().associate { it.itemId to it.formatVersion }

        // §2.5: fetch each opted-in attachment plaintext one at a time through the normal
        // client path; ONE retry, then skip BY NAME — never silently, never fatal. The
        // buffers are held until Backup.build consumes (and zeroes) them; the 64 MiB
        // total-plaintext cap keeps the whole set well below any desktop heap.
        val plan = if (includeAttachments) ExportPlanner.planAttachments(exportItems) else AttachmentPlan(emptyList(), 0L, emptyList())
        val fetched = ArrayList<Pair<PlannedAttachment, ByteArray>>()
        val fetchFailed = ArrayList<String>()
        for (p in plan.included) {
            var bytes: ByteArray? = null
            for (attempt in 0 until 2) {
                bytes = runCatching { e.downloadAttachment(p.ref) }.getOrNull()
                if (bytes != null) break
            }
            if (bytes == null) fetchFailed.add(p.ref.name) else fetched.add(p to bytes)
        }

        try {
            // Manifest fileKeys are FRESH per-section keys (spec 07 §2.4); the docs keep
            // their original server-blob fileKeys verbatim inside the payload.
            val freshKeys = fetched.map { acct.newFileKey() }
            val manifest = fetched.mapIndexed { i, (p, bytes) ->
                BackupAttachmentEntry(
                    section = i + 1, attachmentId = p.ref.id, itemId = p.item.itemId,
                    name = p.ref.name, size = bytes.size.toLong(), fileKey = Bytes.toB64(freshKeys[i]),
                )
            }
            val payload = BackupPayload(
                exportedAt = System.currentTimeMillis(), // call-site clock; core takes it as data
                origin = store.baseUrl,
                userId = acct.userId,
                identityFingerprint = acct.identityFingerprintShort(),
                vaults = lines.map { BackupVault(it.vaultId, it.type, it.name, it.role) },
                items = exportItems.map { BackupItem(it.itemId, it.vaultId, formatVersions[it.itemId] ?: 1, it.updatedAt, it.doc) },
                attachments = manifest,
                skipped = BackupSkipped(undecryptable, plan.overCap, fetchFailed),
            )

            // spec 01 §1 production KDF params (live policy when known), clamped to the
            // §2.2 open() ceilings so the file we produce is always re-openable.
            val policyParams = policy?.kdfParams ?: KdfParams.DEFAULT
            val kdfParams =
                if (policyParams.ops <= Backup.MAX_KDF_OPS && policyParams.memBytes <= Backup.MAX_KDF_MEM_BYTES) policyParams
                else KdfParams.DEFAULT

            // Build to an in-memory buffer, verify, THEN write the file (spec 07 §2.6
            // write-discipline: verify before declaring success, never leave a partial
            // file). In-memory is deliberate: the §2.5 64 MiB attachment-plaintext cap +
            // items keeps the container comfortably below the heap, and it lets us verify
            // the EXACT bytes we are about to persist before the disk sees a single one.
            val out = java.io.ByteArrayOutputStream()
            val sections = fetched.mapIndexed { i, (_, bytes) -> Backup.AttachmentSection(freshKeys[i]) { bytes } }
            Backup.build(
                crypto = crypto, passphrase = passphrase,
                fileId = acct.newItemId(), kdfSalt = crypto.randomBytes(KdfParams.SALT_BYTES),
                kdfParams = kdfParams, payload = payload, attachments = sections,
            ) { out.write(it) }
            val file = out.toByteArray()

            // Verify from the produced bytes: re-open section 0 under the same passphrase
            // and decrypt every attachment section's final tag — single pass (§2.6).
            val opened = Backup.open(crypto, passphrase, file)
            if (opened.payload != payload) throw IllegalStateException("backup verification failed — the written payload does not round-trip")
            for (entry in opened.payload.attachments) {
                val plain = opened.readAttachment(entry)
                val ok = plain.size.toLong() == entry.size
                plain.fill(0)
                if (!ok) throw IllegalStateException("backup verification failed — attachment \"${entry.name}\" does not round-trip")
            }

            writeVerifiedAtomically(dest, file)
            return BackupResult(exportItems.size, lines.size, manifest.size, plan.overCap, fetchFailed)
        } finally {
            // Backup.build zeroes each plaintext it consumed; a throw before/during build
            // leaves stragglers — zero them all (idempotent).
            fetched.forEach { it.second.fill(0) }
        }
    }

    /** "Export for another password manager…" step 1: sync (same offline posture as the
     *  backup), then the warning-gated preflight — by NAME, never counts (spec 07 §1). */
    fun csvBegin() {
        val e = engine ?: return
        busy = true; error = null; notice = null
        scope.launch {
            val offline = try {
                syncNow(e); false
            } catch (t: java.io.IOException) {
                true
            } catch (t: Throwable) {
                busy = false; error = t.message ?: "sync failed"; return@launch
            }
            val acct = account
            if (acct == null) { busy = false; return@launch }
            val docs = orderedDocs(e, acct)
            items = e.items()
            csvPreflight = CsvPreflight(ExportCsv.warnings(docs), docs.count { it.type == "login" }, offlineNote(offline))
            busy = false
        }
    }

    fun csvDismiss() { csvPreflight = null }

    /** CSV step 2: write the spec 07 §1 bytes (UTF-8, no BOM) to [dest] via
     *  temp-then-atomic-move (same overwrite safety as the backup: a failure must
     *  never delete a pre-existing file at [dest] — the helper only ever cleans up
     *  its own temp, so no delete in the catch here). */
    fun csvRun(dest: File) {
        val e = engine ?: return
        val acct = account ?: return
        busy = true; error = null; csvPreflight = null
        scope.launch {
            try {
                val count = withContext(Dispatchers.IO) {
                    val docs = orderedDocs(e, acct)
                    val bytes = ExportCsv.write(docs).encodeToByteArray()
                    try { writeVerifiedAtomically(dest, bytes) } finally { bytes.fill(0) } // plaintext passwords — wipe our copy
                    docs.count { it.type == "login" }
                }
                touch()
                busy = false
                notice = "Exported $count logins to ${dest.absolutePath}. Delete the CSV once the other manager has imported it."
            } catch (t: Throwable) {
                busy = false; error = t.message ?: "export failed"
            }
        }
    }

    /**
     * Spec 07 §2.6 write discipline + overwrite safety: write [bytes] to a temp file in
     * [dest]'s OWN directory (same filesystem → rename-able), verify the ON-DISK bytes
     * (byte-equality with the in-memory buffer the callers already verified — this also
     * transfers the Backup.open verification to the persisted bytes), then move the temp
     * over [dest], atomically where the filesystem supports it. The pre-existing file at
     * [dest] is never touched until a fully verified replacement exists, so a failed
     * re-export can no longer destroy a good old backup.
     *
     * Failure handling, two distinct phases:
     * - write/verify failure → delete ONLY the temp (dest untouched);
     * - move failure (rare; e.g. dest locked on Windows after the non-atomic fallback
     *   started) → deliberately KEEP the temp: on that fallback dest may already be
     *   gone, so the temp can be the only surviving verified copy. The surfaced error
     *   names it. A hard crash mid-export can likewise leave a `.tmp` behind
     *   (deleteOnExit covers normal JVM shutdown); a stray temp never masquerades as a
     *   backup and beats a destroyed one.
     */
    private fun writeVerifiedAtomically(dest: File, bytes: ByteArray) {
        val dir = dest.absoluteFile.parentFile ?: File(System.getProperty("user.dir") ?: ".")
        val tmp = File.createTempFile("andvari-", ".tmp", dir)
        tmp.deleteOnExit() // no-op after a successful move (the path no longer exists)
        restrictToOwner(tmp) // exports can hold plaintext (CSV) — same 0600 posture as the cache
        try {
            tmp.writeBytes(bytes)
            val onDisk = tmp.readBytes()
            val ok = onDisk.contentEquals(bytes)
            onDisk.fill(0) // the CSV path passes plaintext — wipe our read-back copy
            if (!ok) throw IllegalStateException("verification failed — the on-disk bytes do not match what was written")
        } catch (t: Throwable) {
            runCatching { tmp.delete() }
            throw t
        }
        try {
            try {
                Files.move(tmp.toPath(), dest.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (e: AtomicMoveNotSupportedException) {
                Files.move(tmp.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING)
            }
        } catch (t: Throwable) {
            throw IllegalStateException("could not replace ${dest.name}: ${t.message} — the verified export was left at ${tmp.name} in the same folder", t)
        }
    }

    /** All VK-held docs in the pinned export order (vault order, then updatedAt). */
    private fun orderedDocs(e: SyncEngine, acct: Account): List<ItemDoc> {
        val order = ExportPlanner.vaultLines(e, acct).map { it.vaultId }
        return ExportPlanner.orderedItems(e, order).map { it.doc }
    }

    private fun offlineNote(offline: Boolean): String? {
        if (!offline) return null
        val at = store.lastSyncAt
        val stamp = if (at > 0) {
            java.text.DateFormat.getDateTimeInstance(java.text.DateFormat.SHORT, java.text.DateFormat.SHORT).format(java.util.Date(at))
        } else "(unknown)"
        return "Offline — this exports the vault as of last sync $stamp."
    }

    fun lock() {
        // Retain the ciphertext cache on lock (spec 05 T3); close its handle.
        engine?.close(); api?.close(); api = null; account = null; engine = null
        clearVaultClipboard() // a copied secret must not outlive the unlocked session
        clearSecondary()
        screen = DesktopScreen.Unlock(store.load()?.email ?: ""); items = emptyList(); needsUpdateCount = 0
    }

    fun signOut() {
        if (busy) return
        val session = store.load()
        val a = api
        busy = true; error = null
        scope.launch {
            // AWAIT the server-side revocation (bounded) BEFORE close(): the old
            // fire-and-forget launch raced the teardown below, which cancelled the
            // in-flight logout and left the refresh token valid for ~30 days.
            if (a != null) {
                runCatching { withTimeoutOrNull(5_000) { a.logout() } }
            } else if (session != null && session.accessToken.isNotEmpty()) {
                // LOCKED sign-out (the Unlock screen's "Sign out / use a different
                // account"): no live token-holder exists, but the persisted refresh token
                // is still valid server-side — store.clear() alone would leave it live
                // for ~30 days. Build a short-lived holder purely to revoke it.
                val temp = newApi(session.tokens())
                runCatching { withTimeoutOrNull(5_000) { temp.logout() } }
                temp.close()
            }
            // Close the engine (releases the DB handle — Windows won't delete an open file) first.
            engine?.close(); a?.close(); api = null; account = null; engine = null
            clearVaultClipboard()
            session?.userId?.let { deleteCache(it) }
            store.clear()
            clearSecondary(); signInTotpRequired = false
            mustChangePassword = false // F58: sign-out drops the account; the flag re-arrives at the next sign-in
            busy = false
            screen = DesktopScreen.Welcome; items = emptyList(); needsUpdateCount = 0
        }
    }

    private fun clearSecondary() {
        importDismiss() // the parsed CSV + plan hold every password in the file — never outlive the session
        notice = null; totpStatus = null; totpSetupInfo = null; totpError = null
        backupPreflight = null; backupResult = null; csvPreflight = null
        // F19: drop any in-flight move state + memoized gesture ids/fileKeys on lock/sign-out.
        moveError = null; moveProgress = null; moveGestures.clear()
    }

    private fun cacheFile(userId: String) = File(store.cacheDir, "vault-$userId.db")

    private fun deleteCache(userId: String) {
        for (suffix in listOf("", "-wal", "-shm")) {
            val f = File(store.cacheDir, "vault-$userId.db$suffix")
            // Windows: a straggler handle (AV/indexer) can defeat the unlink — retry at JVM exit.
            if (!f.delete() && f.exists()) f.deleteOnExit()
        }
    }

    private fun cacheAllowed(): Boolean = policy?.offlineCacheAllowed ?: store.cacheAllowed

    /** Record a freshly-fetched policy in UI state + the persisted offline fallbacks. */
    private fun applyPolicy(p: ClientPolicy) {
        policy = p
        store.cacheAllowed = p.offlineCacheAllowed
        store.autoLockSeconds = p.autoLockSeconds
    }

    /** Persist accountKeys for offline unlock ONLY when the policy permits it (spec 02 §8). */
    private fun persistAccountKeys(keys: io.silencelen.andvari.core.model.AccountKeys) {
        if (cacheAllowed()) store.saveAccountKeys(keys) else store.clearAccountKeys()
    }

    /** Enforce offlineCacheAllowed=false: drop BOTH the vault DB and the cached keys. */
    private fun purgeOfflineData(userId: String) { deleteCache(userId); store.clearAccountKeys() }

    private fun bind(a: AndvariApi, acct: Account) {
        touch() // spec 01 §8: the auto-lock timer resets on unlock
        engine?.close()
        api = a; account = acct
        val allowed = policy?.offlineCacheAllowed ?: store.cacheAllowed
        val newCache = if (allowed) {
            val db = cacheFile(acct.userId)
            sqliteVaultCache(db.absolutePath, acct.userId).also {
                // 0600 on POSIX, best-effort on Windows — same handling as session.json.
                for (suffix in listOf("", "-wal", "-shm")) restrictToOwner(File("${db.path}$suffix"))
            }
        } else {
            deleteCache(acct.userId); InMemoryVaultCache()
        }
        engine = SyncEngine(a, acct, newCache).also { it.hydrate() }
    }

    /** Sync + record the wall-clock time of the last SUCCESS — the timestamp the spec 07
     *  offline-export note shows ("vault as of last sync <time>"). */
    private suspend fun syncNow(e: SyncEngine) {
        e.sync()
        store.lastSyncAt = System.currentTimeMillis()
    }

    private fun restrictToOwner(f: File) {
        if (!f.exists()) return
        runCatching { f.setReadable(false, false); f.setReadable(true, true); f.setWritable(false, false); f.setWritable(true, true) }
    }

    private fun refreshItems() {
        items = engine?.items() ?: emptyList()
        needsUpdateCount = engine?.needsUpdateCount() ?: 0
        busy = false; error = null
    }

    private fun toVault() {
        screen = DesktopScreen.Vault
        items = engine?.items() ?: emptyList()
        needsUpdateCount = engine?.needsUpdateCount() ?: 0
        busy = false; error = null
    }

    private fun op(block: suspend () -> Unit) {
        busy = true; error = null; notice = null
        scope.launch {
            try {
                block()
            } catch (e: UpgradeRequiredException) {
                // A 426 is not a per-action error — this desktop build is too old for the
                // server's pin. Surface the blocking upgrade screen instead of a toast.
                busy = false
                upgradeRequired = "This andvari server requires a newer desktop app. Download the latest from ${store.baseUrl}/downloads."
            } catch (t: Throwable) {
                busy = false; error = t.message ?: "something went wrong"
            }
        }
    }

    private fun deviceName(): String = "${System.getProperty("os.name")} desktop"

    /** Wire platform tag from the JVM OS: "windows" or "linux" (the only jpackage targets). */
    private fun desktopPlatform(): String =
        if (System.getProperty("os.name").orEmpty().lowercase().contains("win")) "windows" else "linux"

    private companion object {
        const val POLL_INTERVAL_MS = 5L * 60 * 1000 // spec 03 §6 poll interval

        /** A10's pinned pattern — the entities a LastPass in-page export mangles values with. */
        val HTML_ENTITY = Regex("&(amp|lt|gt|quot|#\\d+);")
    }
}

/**
 * Guided-import sources (design 2026-07-09): the eight picker entries. Each carries its
 * display label, the format(s) a file from it is EXPECTED to detect as, and 2–4 numbered
 * export steps. The pick informs instructions and the preview's mismatch hint only —
 * header detection stays authoritative.
 *
 * [expectedFormats] matches on ImportFormat.name STRINGS deliberately: the three new core
 * constants land in a parallel workstream and "1password" cannot be a Kotlin identifier,
 * so this file must not hard-reference a guessed spelling (both plausible ones are listed).
 */
enum class ImportSource(val label: String, val expectedFormats: Set<String>, val steps: List<String>) {
    CHROME(
        "Chrome", setOf("CHROME"),
        listOf(
            "Open chrome://password-manager/settings (Menu ⋮ → Passwords and autofill → Google Password Manager → Settings).",
            "Under “Export passwords”, choose Download file.",
            "Save the CSV, then choose it here.",
        ),
    ),
    EDGE(
        "Edge", setOf("CHROME"),
        listOf(
            "Open edge://wallet/passwords.",
            "Click ⋯ next to “Saved passwords” and choose Export passwords.",
            "Confirm with your device sign-in and save the CSV.",
        ),
    ),
    BRAVE(
        "Brave", setOf("CHROME"),
        listOf(
            "Open brave://password-manager/settings.",
            "Under “Export passwords”, choose Download file.",
            "Save the CSV, then choose it here.",
        ),
    ),
    OPERA(
        "Opera", setOf("CHROME"),
        listOf(
            "Open opera://settings/passwords.",
            "Next to “Saved Passwords”, click ⋮ and choose Export passwords.",
            "Save the CSV, then choose it here.",
        ),
    ),
    FIREFOX(
        "Firefox", setOf("FIREFOX"),
        listOf(
            "Menu ☰ → Passwords (about:logins).",
            "Click ⋯ (top right) → Export passwords…",
            "Confirm with your device sign-in and save the CSV.",
        ),
    ),
    BITWARDEN(
        "Bitwarden", setOf("BITWARDEN"),
        listOf(
            "In the web vault or desktop app: Tools → Export vault.",
            "File format: .csv (not .json).",
            "Confirm your master password and save the file.",
        ),
    ),
    ONEPASSWORD(
        "1Password", setOf("ONEPASSWORD", "ONE_PASSWORD"),
        listOf(
            "In the 1Password 8 desktop app: File → Export → your account.",
            "Format: CSV, then confirm your account password.",
            "1Password 8 or newer only — older exports vary too much to read reliably.",
        ),
    ),
    LASTPASS(
        // A10: the instruction block pins the file-download export path.
        "LastPass", setOf("LASTPASS"),
        listOf(
            "In your LastPass vault: Advanced Options → Export.",
            "Choose the file download — if a page of text opens instead, values can arrive HTML-mangled; don’t copy-paste it.",
            "Save the CSV, then choose it here.",
        ),
    ),
}
