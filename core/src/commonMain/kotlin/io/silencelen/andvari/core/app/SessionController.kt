package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.client.session.BiometricHost
import io.silencelen.andvari.core.client.session.Clocks
import io.silencelen.andvari.core.client.session.HttpClients
import io.silencelen.andvari.core.client.session.NamespaceStorage
import io.silencelen.andvari.core.client.session.QuickUnlockKeys
import io.silencelen.andvari.core.client.session.SessionPersistence
import kotlinx.coroutines.flow.MutableStateFlow
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
 * @param uiContext where state is published and actions run (the main thread on iOS).
 * @param biometricHost what the platform's biometric prompt needs, with the reason it shows.
 * @param tickMs the idle check's period while started; 0 runs no ticker.
 */
open class SessionController(
    private val store: SessionPersistence,
    private val namespaces: NamespaceStorage,
    private val http: HttpClients,
    private val quickKeys: QuickUnlockKeys,
    private val clocks: Clocks,
    private val cleartextExemptHosts: Set<String>,
    private val uiContext: CoroutineContext,
    private val biometricHost: (reason: String?) -> BiometricHost,
    private val tickMs: Long,
) {
    private val stateFlow = MutableStateFlow(AppState.initial)

    private companion object {
        /** The API surface lands before the bodies (survey step: iOS controller). */
        val NOT_YET = ActionResult.Failed("Not available yet.")
    }

    /** The current snapshot. */
    val state: AppState get() = stateFlow.value

    /** Call [listener] with the current state, then with every change, on the UI context, until the subscription is closed. */
    fun observe(listener: (AppState) -> Unit): Subscription {
        listener(stateFlow.value)
        return object : Subscription {
            override fun close() {}
        }
    }

    // ---- lifecycle ----

    /** Read the stored session, probe the server, and run the idle check while in the foreground. Call once. */
    fun start() {}

    /** The app came to the foreground: the idle check first, then a quiet sync. */
    fun onForeground() {}

    /** The app left the foreground: the vault locks (a suspended app cannot run the idle timer). */
    fun onBackground() {}

    /** The person interacted with the app: the idle window starts again. */
    fun userActivity() {}

    /** Stop this controller: its work is cancelled and the vault locks. */
    fun close() {}

    // ---- server ----

    /** What [input] typed into the server field means; a real change raises the Trust Gate. */
    fun chooseServer(input: String): ServerChoice = ServerChoice.Invalid(NOT_YET.message)

    /** The Trust Gate's Connect: the server is probed first, and nothing changes unless it answers. */
    @Throws(CancellationException::class)
    suspend fun confirmTrustGate(): ActionResult = NOT_YET

    /** The Trust Gate's Cancel: nothing changes. */
    fun cancelTrustGate() {}

    /** Signed out: open the server field to choose another server. */
    fun changeServer() {}

    /** Probe the server's policy again (after [AppState.serverUnreachable]). */
    @Throws(CancellationException::class)
    suspend fun retryServer(): ActionResult = NOT_YET

    // ---- sign-in and enroll ----

    /** Sign in at [AppState.server]. [totp] is the authenticator's code, after [ActionResult.NeedsCode]. */
    @Throws(CancellationException::class)
    suspend fun signIn(email: String, password: String, totp: String?): ActionResult = NOT_YET

    /** Enroll at [AppState.server] with an invite; lands on the shown-once recovery phrase. */
    @Throws(CancellationException::class)
    suspend fun enroll(form: EnrollForm): ActionResult = NOT_YET

    // ---- the recovery phrase ----

    /** RECOVERY_REVEAL: the phrase to show, grouped for reading; null on any other screen. */
    fun recoveryPhrase(): String? = null

    /** RECOVERY_REVEAL: the phrase typed back. A match confirms it and opens the vault; a mismatch is [ActionResult.Mismatch]. */
    @Throws(CancellationException::class)
    suspend fun confirmRecoveryPhrase(typedBack: String): ActionResult = NOT_YET

    /** RECOVERY_CAPTURE: commit a fresh recovery piece again, after [AppState.recoveryCaptureError]. */
    @Throws(CancellationException::class)
    suspend fun retryRecoveryCapture(): ActionResult = NOT_YET

    // ---- unlock ----

    /** UNLOCK with the master password. */
    @Throws(CancellationException::class)
    suspend fun unlock(password: String): ActionResult = NOT_YET

    /** UNLOCK with Face ID or Touch ID; [reason] is what the prompt says (null: a default). */
    @Throws(CancellationException::class)
    suspend fun unlockWithBiometrics(reason: String?): ActionResult = NOT_YET

    /** Turn quick unlock on for this account on this device; the biometric prompt confirms it. */
    @Throws(CancellationException::class)
    suspend fun enableQuickUnlock(reason: String?): ActionResult = NOT_YET

    /** Turn quick unlock off: the wrapped key and its hardware key are destroyed. */
    fun disableQuickUnlock() {}

    // ---- the vault ----

    /** Filter the vault list ([AppState.items]) by [query]. */
    fun setQuery(query: String) {}

    /** An item's detail, without its secrets; null if the vault is locked or the item is gone. */
    fun itemDetail(itemId: String): ItemDetail? = null

    /** One secret field of an item, for an explicit reveal or copy; null if locked, gone or empty. */
    fun revealSecret(itemId: String, field: SecretField): String? = null

    /** The item's current one-time code; null if it has none, or the vault is locked. */
    fun oneTimeCode(itemId: String): OneTimeCode? = null

    /** Add a login ([itemId] null) to the personal vault, or save an edit of one. */
    @Throws(CancellationException::class)
    suspend fun saveLogin(itemId: String?, input: LoginInput): ActionResult = NOT_YET

    /** Delete an item (it goes to the server's trash). */
    @Throws(CancellationException::class)
    suspend fun deleteItem(itemId: String): ActionResult = NOT_YET

    /** Sync now. */
    @Throws(CancellationException::class)
    suspend fun refresh(): ActionResult = NOT_YET

    /** A new password under [settings]. */
    fun generatePassword(settings: GeneratorSettings): String = ""

    // ---- the session ----

    /** Lock now: the keys leave memory; the stored session stays for the next unlock. */
    fun lock() {}

    /** Sign out: the session is ended at the server, and this account's data on this device is deleted. */
    @Throws(CancellationException::class)
    suspend fun signOut(): ActionResult = NOT_YET

    /** The error has been shown. */
    fun dismissError() {}

    /** The notice has been shown. */
    fun dismissNotice() {}
}
