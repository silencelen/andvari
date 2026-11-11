package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.OriginCanon
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.client.autofill.FillTarget
import io.silencelen.andvari.core.client.autofill.UriMatch
import io.silencelen.andvari.core.client.session.BiometricHost
import io.silencelen.andvari.core.client.session.Clocks
import io.silencelen.andvari.core.client.session.HttpClients
import io.silencelen.andvari.core.client.session.QuickGate
import io.silencelen.andvari.core.client.session.QuickGates
import io.silencelen.andvari.core.client.session.QuickRecover
import io.silencelen.andvari.core.client.session.QuickUnlockKeys
import io.silencelen.andvari.core.client.session.SessionPersistence
import io.silencelen.andvari.core.client.session.offlineOnly
import io.silencelen.andvari.core.crypto.Totp
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlin.coroutines.cancellation.CancellationException

/** Whether a fill can start here, before any prompt. */
sealed class FillAvailability {
    /** The snapshot is there and quick unlock may run for [email]. */
    data class Ready(val email: String) : FillAvailability()

    /** Nothing can be filled from here now; [message] says what to do in the app. */
    data class OpenApp(val message: String) : FillAvailability()
}

/** How an unlock for a fill ended. */
sealed class FillUnlock {
    data object Unlocked : FillUnlock()

    /** The person dismissed the prompt. */
    data object Cancelled : FillUnlock()

    data class OpenApp(val message: String) : FillUnlock()
}

/** A login the fill sheet lists. No secret. */
data class FillLogin(
    val itemId: String,
    val name: String,
    val username: String,
    /** The first web address's host, for display. */
    val host: String?,
    /** It matches one of the hosts the fill is for. */
    val matches: Boolean,
    val hasTotp: Boolean,
)

/** The one item a fill completes with. */
data class FillCredential(val username: String, val password: String)

/**
 * The read-only vault of a process that is not the app (design 2026-11-09, "AutoFill"): the iOS credential-provider
 * extension, and the Safari extension's native handler. It never contacts the server (its client refuses every
 * request), never runs the password KDF, and never holds a token. It opens the app's [FillSnapshot] with the UVK the
 * quick-unlock prompt releases, under the same gates as the app's own quick unlock ([QuickGates]), and keeps the
 * account only until [close].
 */
class AutofillVault(
    private val store: SessionPersistence,
    private val snapshots: FillSnapshotStore,
    private val quickKeys: QuickUnlockKeys,
    private val clocks: Clocks,
    private val http: HttpClients,
) {
    private val gates = QuickGates(store, quickKeys, clocks)
    private val crypto by lazy { createCryptoProvider() }
    private var open: Open? = null

    private class Open(val account: Account, val engine: SyncEngine, val api: AndvariApi)

    /** The snapshot of the origin the app dials, or null. */
    private fun snapshot(): FillSnapshot? {
        val dialed = store.baseUrl ?: return null
        val snap = snapshots.read()?.let(FillSnapshot::decode) ?: return null
        return snap.takeIf { runCatching { OriginCanon.originKey(it.origin) == OriginCanon.originKey(dialed) }.getOrDefault(false) }
    }

    private fun refusal(gate: QuickGate, originKey: String): String = when (gate) {
        QuickGate.POLICY -> if (!store.origin(originKey).cacheAllowed) FORBIDDEN else POLICY_UNSEEN
        QuickGate.NO_BIOMETRIC -> quickKeys.biometricProblem() ?: NO_BIOMETRIC
        QuickGate.NOT_ENROLLED -> NOT_ENROLLED
        QuickGate.EXPIRED -> EXPIRED
    }

    /** Whether a fill can start, and for whom. Never throws. */
    fun availability(): FillAvailability = try {
        val snap = snapshot()
        if (snap == null) {
            FillAvailability.OpenApp(NO_SNAPSHOT)
        } else {
            val gate = gates.status(snap.userId).refusal
            if (gate == null) FillAvailability.Ready(snap.email) else FillAvailability.OpenApp(refusal(gate, OriginCanon.originKey(snap.origin)))
        }
    } catch (t: Throwable) {
        FillAvailability.OpenApp(NO_SNAPSHOT)
    }

    /**
     * The biometric prompt over [host], then the snapshot opened in memory. The gates hold here whatever a UI showed.
     * The recovered UVK is zeroed on every path where no account took it.
     */
    @Throws(CancellationException::class)
    suspend fun unlock(host: BiometricHost): FillUnlock {
        close()
        val snap = snapshot() ?: return FillUnlock.OpenApp(NO_SNAPSHOT)
        val originKey = OriginCanon.originKey(snap.origin)
        gates.status(snap.userId).refusal?.let { return FillUnlock.OpenApp(refusal(it, originKey)) }
        val uvk = when (val r = quickKeys.recover(host, originKey, snap.userId)) {
            is QuickRecover.Ok -> r.uvk
            is QuickRecover.Fallback -> return if (r.reason == null) FillUnlock.Cancelled else FillUnlock.OpenApp(USE_APP)
            is QuickRecover.Wiped -> return FillUnlock.OpenApp(NOT_ENROLLED)
        }
        var taken = false
        var account: Account? = null
        var api: AndvariApi? = null
        try {
            val pin = store.origin(originKey).identityPins().pinFor(snap.email, snap.userId)
            account = Account.unlockWithUvk(snap.userId, uvk, snap.keys, selfIdentityPub = pin).also { taken = true }
            val cache = InMemoryVaultCache()
            snap.vaults.forEach(cache::upsertVault)
            snap.grants.forEach(cache::upsertGrant)
            snap.items.forEach { cache.upsertItem(it, null) }
            api = AndvariApi(snap.origin, http.create().offlineOnly(), platform = http.wirePlatform)
            val engine = SyncEngine(api, account, cache).also { it.hydrate() }
            open = Open(account, engine, api)
            return FillUnlock.Unlocked
        } catch (t: Throwable) {
            if (!taken) uvk.fill(0)
            account?.wipe()
            api?.close()
            if (t is CancellationException) throw t
            return FillUnlock.OpenApp(USE_APP)
        }
    }

    /** The logins, those matching one of [hosts] first. Empty while locked. */
    fun logins(hosts: List<String>): List<FillLogin> {
        val live = open ?: return emptyList()
        val targets = hosts.mapNotNull { UriMatch.normalizeHost(it) }.map { FillTarget(it, "") }
        return live.engine.items()
            .filter { it.doc.type == "login" && it.doc.login != null }
            .map { item ->
                val login = item.doc.login!!
                FillLogin(
                    itemId = item.itemId,
                    name = item.doc.name,
                    username = login.username.orEmpty(),
                    host = login.uris.firstOrNull()?.let { UriMatch.normalizeHostUnicode(it) ?: UriMatch.normalizeHost(it) },
                    matches = targets.any { UriMatch.matchLogins(login.uris, it) },
                    hasTotp = !login.totp.isNullOrEmpty(),
                )
            }
            .sortedWith(compareByDescending<FillLogin> { it.matches }.thenBy { it.name.lowercase() })
    }

    /** The username and password of [itemId]; null while locked or when it is not a login. */
    fun credential(itemId: String): FillCredential? {
        val login = open?.engine?.item(itemId)?.doc?.login ?: return null
        return FillCredential(login.username.orEmpty(), login.password.orEmpty())
    }

    /** The current one-time code of [itemId]; null while locked or when it has none. */
    fun oneTimeCode(itemId: String): String? = runCatching {
        val uri = open?.engine?.item(itemId)?.doc?.login?.totp?.ifEmpty { null } ?: return null
        Totp.code(crypto, Totp.parseUri(Totp.normalize(uri)), clocks.wallMs() / 1000)
    }.getOrNull()

    /** End the fill: the account's keys are zeroed. Idempotent. */
    fun close() {
        val live = open ?: return
        open = null
        runCatching { live.account.wipe() }
        runCatching { live.engine.close() }
        runCatching { live.api.close() }
    }

    companion object {
        const val NO_SNAPSHOT = "Open andvari and unlock it once, then try again."
        const val NOT_ENROLLED = "Turn on Face ID in andvari's Settings to fill passwords from here."
        const val EXPIRED = "Open andvari and unlock with your master password, then try again."
        const val POLICY_UNSEEN = "Open andvari so it can reach your server, then try again."
        const val FORBIDDEN = "Your server doesn't allow filling from here. Open andvari to copy the password."
        const val NO_BIOMETRIC = "Set up Face ID or Touch ID on this iPhone first."
        const val USE_APP = "Couldn't unlock here. Open andvari to copy the password."
    }
}
