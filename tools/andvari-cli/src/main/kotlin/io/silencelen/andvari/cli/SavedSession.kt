package io.silencelen.andvari.cli

import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.net.TokenSource
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.net.originStopped
import io.silencelen.andvari.core.client.onboard.AccountOpen
import io.silencelen.andvari.core.client.onboard.EstablishedSession
import io.silencelen.andvari.core.client.onboard.PasswordOpen
import io.silencelen.andvari.core.client.onboard.SessionHow
import io.silencelen.andvari.core.client.pin.ServerForgotten
import io.silencelen.andvari.core.model.wire.AccountKeys
import io.silencelen.andvari.core.model.wire.RefreshRequest
import io.silencelen.andvari.core.model.wire.TokenPair
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.serialization.Serializable

/**
 * A session kept between invocations in this device's SECURE store (owner-only): the token pair and the ids, never a
 * key. Reopening needs the master password every time: the served `wrappedUvk` opens only under the password's wrap key,
 * and the account then passes every identity check of design §5.2 again ([AccountOpen]) against the pinned card. This
 * keeps a script from signing in on every command (the login bucket is a few a minute) without keeping any key on disk.
 */
/**
 * An account this home keeps at a server: a saved session's, or the address remembered as the account there (one whose
 * session its server ended keeps only that). [userId] and [role] are null where nothing kept here records them.
 */
class KeptHere(val emailNorm: String, val userId: String?, val role: String?)

class SavedSessions(private val secure: DeviceState) {
    @Serializable
    private data class Saved(
        val origin: String, val emailNorm: String, val userId: String, val deviceId: String, val role: String,
        val totpEnrolled: Boolean, val mustEnrollTotp: Boolean, val how: String, val accessToken: String, val refreshToken: String,
        /**
         * An older record's mark that a refresh with [refreshToken] got no answer, at a time it did not keep: read as no try
         * left. Never written true any more ([refreshOutAt] replaces it).
         */
        val refreshUnanswered: Boolean = false,
        /** [HeldSession.refreshOutAt]: written before a refresh of [refreshToken] goes, cleared only by an answer in the server's own envelope. */
        val refreshOutAt: Long? = null,
        /** [HeldSession.refreshTriedAgain]. */
        val refreshTriedAgain: Boolean = false,
    ) {
        /** The time of the refresh out ([refreshOutAt]); an older record's mark with no time counts as out from the start. */
        val outAt: Long? get() = refreshOutAt ?: if (refreshUnanswered) 0L else null

        /** Whether the refresh out was tried again; an older record's mark counts as tried. */
        val triedAgain: Boolean get() = refreshTriedAgain || (refreshUnanswered && refreshOutAt == null)
    }

    private fun key(origin: String, emailNorm: String) = "cli.session|$origin|$emailNorm"

    companion object {
        /** The saved session [text] as kept at [origin] after a followed move; null when it does not decode. */
        internal fun atOrigin(text: String, origin: String): String? =
            runCatching { WireJson.json.decodeFromString(Saved.serializer(), text) }.getOrNull()
                ?.let { WireJson.json.encodeToString(Saved.serializer(), it.copy(origin = origin)) }
    }

    fun save(h: HeldSession) {
        val s = h.session
        secure.set(key(h.origin, h.emailNorm), WireJson.json.encodeToString(Saved.serializer(),
            Saved(h.origin, h.emailNorm, s.userId, s.deviceId, s.role, s.totpEnrolled, s.mustEnrollTotp, s.how.name, h.accessToken, h.refreshToken,
                refreshOutAt = h.refreshOutAt, refreshTriedAgain = h.refreshTriedAgain)))
    }

    private fun saved(origin: String, emailNorm: String): Saved? =
        secure.get(key(origin, emailNorm))?.let { runCatching { WireJson.json.decodeFromString(Saved.serializer(), it) }.getOrNull() }

    /** The saved session's (device row, refresh token) for [emailNorm] at [origin], or null: what a sign-in names ([Host.signInReplaces]). */
    fun token(origin: String, emailNorm: String): Pair<String, String>? = saved(origin, emailNorm)?.let { it.deviceId to it.refreshToken }

    fun forget(origin: String, emailNorm: String) = secure.set(key(origin, emailNorm), null)

    /**
     * Every session kept for [origin] is forgotten ("Forget this server"), the remembered one ([remembered]) too when the
     * store cannot list its keys. Answers null when all are gone, else [ServerForgotten.CANNOT_LIST] or
     * [ServerForgotten.CANNOT_DELETE].
     */
    fun forgetAll(origin: String, remembered: String?): String? {
        val prefix = "cli.session|$origin|"
        var failed: String? = null
        val keys = try { secure.keys() } catch (e: Exception) { null }
        if (keys == null) failed = ServerForgotten.CANNOT_LIST
        for (k in keys.orEmpty().filter { it.startsWith(prefix) } + listOfNotNull(remembered?.let { key(origin, it) })) {
            try { secure.set(k, null) } catch (e: Exception) { failed = failed ?: ServerForgotten.CANNOT_DELETE }
        }
        return failed
    }

    /** The user ids of the sessions kept for [origin] (those that can be read); null when the store cannot list its keys. */
    fun userIds(origin: String): List<String>? {
        val keys = try { secure.keys() } catch (e: Exception) { null } ?: return null
        return keys.filter { it.startsWith("cli.session|$origin|") }.mapNotNull { k ->
            runCatching { secure.get(k)?.let { WireJson.json.decodeFromString(Saved.serializer(), it).userId } }.getOrNull()
        }
    }

    /** The addresses of the sessions kept for [origin]; null when the store cannot list its keys. */
    fun emails(origin: String): List<String>? {
        val keys = try { secure.keys() } catch (e: Exception) { null } ?: return null
        val prefix = "cli.session|$origin|"
        return keys.filter { it.startsWith(prefix) }.map { it.removePrefix(prefix) }
    }

    /**
     * The accounts with a session kept for [origin]: each one's address, and its user id and role where the saved session
     * reads (null where it does not); null when the store cannot list its keys.
     */
    fun accounts(origin: String): List<KeptHere>? {
        val keys = try { secure.keys() } catch (e: Exception) { null } ?: return null
        val prefix = "cli.session|$origin|"
        return keys.filter { it.startsWith(prefix) }.map { k ->
            val s = runCatching { secure.get(k)?.let { WireJson.json.decodeFromString(Saved.serializer(), it) } }.getOrNull()
            KeptHere(k.removePrefix(prefix), s?.userId, s?.role)
        }
    }

    fun has(origin: String, emailNorm: String) = secure.get(key(origin, emailNorm)) != null

    /** The access token of the saved session (for signing it out), or null. */
    fun accessToken(origin: String, emailNorm: String): String? =
        secure.get(key(origin, emailNorm))?.let { runCatching { WireJson.json.decodeFromString(Saved.serializer(), it) }.getOrNull()?.accessToken }

    /** What reopening a saved session came to. */
    sealed class Reopen {
        /** The session is held on the host again. */
        data object Reopened : Reopen()

        /** No saved session, or the password does not open the served keys: the caller signs in afresh. */
        data object None : Reopen()

        /**
         * The server ended the session ([code], a refused refresh): its saved tokens are deleted, and nothing else this
         * device keeps for the account (design §4.4 "A session the server ends does not delete the device's copy").
         */
        data class Ended(val code: String) : Reopen()

        /**
         * The password opened the account, but the saved session cannot be rebuilt from what this device kept (its tokens
         * are empty, or it names another account): it is not used, the keys just opened are wiped, and the saved copy stays
         * until a sign-in replaces it. The person signs in again.
         */
        data object Unusable : Reopen()

        /**
         * A refresh of the saved session got no answer (in this run or an earlier one) and no try of it is left ([Host.refreshMay]):
         * the server may have replaced its refresh token, so it is not sent to the refresh again. The saved session stays
         * until a sign-in replaces it; that sign-in names it, and the server ends it ([Host.signInReplaces]).
         */
        data object RefreshUnanswered : Reopen()

        /**
         * The refresh of the saved session sent in this run got no answer, and one more try of it is left: a later run
         * inside [Host.REFRESH_SECOND_TRY_MS] of it sends it once more. The saved session stays, with the mark.
         */
        data object RefreshLost : Reopen()
    }

    /**
     * Reopen the saved session for ([origin], [emailNorm]) on [host] with [password] (wiped). The saved session is kept
     * when the origin is stopped here (an error naming the stop), when the server does not answer, or when it refuses
     * for any reason but ending the session (an error saying so); it is deleted only when the server ended it.
     */
    suspend fun reopen(host: Host, origin: String, emailNorm: String, password: CharArray): Reopen {
        val saved = saved(origin, emailNorm)
        if (saved == null) { password.fill('\u0000'); return Reopen.None }
        // A refresh of the saved token out with no answer, and no try of it left: nothing is sent at all.
        if (saved.outAt != null && Host.refreshMay(saved.outAt, saved.triedAgain, host.clock()) == RefreshMay.NONE) {
            password.fill('\u0000'); return Reopen.RefreshUnanswered
        }
        var access = saved.accessToken
        var refresh = saved.refreshToken
        var outAt = saved.outAt
        var triedAgain = saved.triedAgain
        var refreshRefused: WireResult.Refused? = null
        var refreshAnswered: WireResult.Refused? = null
        var refreshLost = false
        var refreshWithheld = false
        // The record as it stands now, with the tokens and the marks of this reopening (the older mark is never written again).
        fun record() = secure.set(key(origin, emailNorm), WireJson.json.encodeToString(Saved.serializer(),
            saved.copy(accessToken = access, refreshToken = refresh, refreshUnanswered = false, refreshOutAt = outAt, refreshTriedAgain = triedAgain)))
        // Both clients come from the host's dialer: under a forked or damaged pin nothing is sent, not even the refresh.
        val probe = host.open(origin, object : TokenSource {
            override fun accessToken() = access
            override suspend fun refresh(staleAccessToken: String): Boolean {
                val wasOut = outAt
                val wasTried = triedAgain
                when (Host.refreshMay(outAt, triedAgain, host.clock())) {
                    RefreshMay.NONE -> { refreshWithheld = true; return false }
                    RefreshMay.AGAIN -> triedAgain = true
                    RefreshMay.FIRST -> outAt = host.clock()
                }
                // The mark is written before the refresh goes: a run that ends while it is out leaves it.
                record()
                val body = WireJson.json.encodeToString(RefreshRequest.serializer(), RefreshRequest(refresh))
                val r = host.open(origin, null).call(WireRoute.REFRESH, bodyJson = body,
                    decode = { WireJson.json.decodeFromString(TokenPair.serializer(), it) })
                if (Host.refreshOut(r)) { refreshLost = true; return false }
                if (r is WireResult.Refused && r.code == io.silencelen.andvari.core.client.net.ORIGIN_STOPPED) {
                    // Stopped on this device: nothing was sent, so what was out before is out still.
                    outAt = wasOut; triedAgain = wasTried; record(); return false
                }
                // An answer in the server's own envelope: nothing of this token is out any more.
                outAt = null; triedAgain = false
                if (r is WireResult.Refused) { refreshRefused = r; refreshAnswered = r }
                if (r is WireResult.Ok) { access = r.value.accessToken; refresh = r.value.refreshToken }
                if (!(r is WireResult.Refused && Host.endsSession(r))) record()
                return r is WireResult.Ok
            }
        })
        val served = probe.call(WireRoute.ACCOUNT_KEYS, decode = { WireJson.json.decodeFromString(AccountKeys.serializer(), it) })
        // A stopped origin is not the server refusing the session: the saved session is kept for after "forget".
        if (served.originStopped) { password.fill('\u0000'); throw stoppedError(origin, host.access(origin)) }
        val ended = refreshRefused?.takeIf { Host.endsSession(it) }
        if (ended != null) { password.fill('\u0000'); forget(origin, emailNorm); return Reopen.Ended(ended.code) }
        if (refreshWithheld) { password.fill('\u0000'); return Reopen.RefreshUnanswered }
        if (refreshLost) { password.fill('\u0000'); return if (triedAgain) Reopen.RefreshUnanswered else Reopen.RefreshLost }
        // The server refused the refresh in its own envelope without ending the session: it is kept for the next try.
        refreshAnswered?.let { r ->
            password.fill('\u0000')
            throw CliError(fill(SESSION_KEPT_NOT_REFRESHED, origin, r.code), 1, KEY_SESSION_KEPT_NOT_REFRESHED)
        }
        val keys = when (served) {
            is WireResult.Ok -> served.value
            is WireResult.NoAnswer -> { password.fill('\u0000'); throw CliError(fill(SESSION_KEPT_NO_ANSWER, origin), 1, KEY_SESSION_KEPT_NO_ANSWER) }
            is WireResult.Refused -> {
                password.fill('\u0000')
                throw CliError("$origin refused this device's saved session (${served.code}) without ending it; the session is kept. " +
                    "Try again later, or run `andvari-cli sign-out` to end it on this device and then `sign-in`")
            }
        }
        val pin = host.trust.pinFor(origin) ?: return Reopen.None.also { password.fill('\u0000') }
        // Spec 01 §7, "KDF upgrade": the password this opening verifies re-keys the account right after it, when the policy
        // asks for a legitimate raise. The opening wipes [password], so the re-key has its own copy, wiped on every path.
        val forReKey = password.copyOf()
        try {
            // The engine derives and wipes the password's keys itself; this host never holds the wrap key.
            val account = when (val o = AccountOpen.openWithPassword(host.crypto, saved.userId, password, keys, pin.instanceId, host.knownIdentity(origin, saved.userId))) {
                is PasswordOpen.Opened -> o.account
                is PasswordOpen.WrongPassword, is PasswordOpen.Refused -> return Reopen.None
                // The record of the account's key decided: said as that ([IDENTITY_KEY_REFUSED_OPEN]); any other fault as before.
                is PasswordOpen.IdentityFault -> throw if (o.reason == AccountOpen.SELF_IDENTITY_MISMATCH && host.knownIdentity(origin, saved.userId) != null)
                    CliError(fill(IDENTITY_KEY_REFUSED_OPEN, origin, ACT_REOPEN), 1, IDENTITY_KEY_NOT_KNOWN)
                    else CliError("SECURITY: the server's keys do not open as this account (${o.reason}); nothing was used")
            }
            // The engine rebuilds the session from the kept tokens and the account the password just opened; it builds none for
            // tokens that are empty or an account that is not the one the saved session names.
            val how = runCatching { SessionHow.valueOf(saved.how) }.getOrNull()
            val es = how?.let {
                EstablishedSession.reopened(origin, emailNorm, saved.userId, saved.deviceId, saved.role, saved.totpEnrolled, saved.mustEnrollTotp,
                    it, access, refresh, keys, account)
            }
            if (es == null) {
                account.wipe()
                return Reopen.Unusable
            }
            // The wrap the password just opened, at the cost the keys named: the floor of any new wrap made in this run.
            OpenedCosts.note(es, keys.kdfParams)
            // A refresh still out (this reopening sent none) keeps its mark: the window holds for the rest of the run too.
            val h = HeldSession(es, access, refresh).also { it.refreshOutAt = outAt; it.refreshTriedAgain = triedAgain }
            host.adopt(h)
            save(h)
            host.reKeyAfterOpening(h, forReKey)
            return Reopen.Reopened
        } finally {
            forReKey.fill('\u0000')
        }
    }
}
