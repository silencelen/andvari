package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.InstanceLabel
import io.silencelen.andvari.core.app.KitApi
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.KitDocument
import io.silencelen.andvari.core.app.KitReason
import io.silencelen.andvari.core.app.KitScreen
import io.silencelen.andvari.core.app.KitStep
import io.silencelen.andvari.core.app.Trouble
import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.account.WireAccountSettings
import io.silencelen.andvari.core.client.onboard.KitConfirm
import io.silencelen.andvari.core.client.onboard.RevealedKit
import io.silencelen.andvari.core.model.wire.WireErrors

/**
 * The recovery kit's capture gate (§10) over the engine's [RevealedKit] and `confirmKit`: reveal, "Type groups …",
 * and the server's record of the confirmation. One kit is on show at a time, in the entry journey ([inEntry]) or in
 * Settings. Its secret is readable only on the reveal step and is wiped once the kit is confirmed or left.
 */
internal class EngineKit(private val app: EngineAppApi) : KitApi {
    private class Showing(
        var reason: KitReason,
        val email: String,
        val instance: InstanceLabel,
        val origin: String,
        val inEntry: Boolean,
        val onDone: () -> Unit,
    ) {
        var kit: RevealedKit? = null
        var step: KitStep = KitStep.MAKING
        var groups: List<Int> = emptyList()
        var failed: Int = 0
        var screen: KitScreen? = null
        var madeAtMs: Long = 0L

        /** Shown with a refusal: no session holds the account, so the confirm is checked here only ([KitScreen.notKeptLine]). */
        var notKept: io.silencelen.andvari.core.app.CopyKey? = null

        /** This kit was made while a kit shown here before was never confirmed at the server ([KitScreen.earlierKitVoidLine]). */
        var replacesShown = false

        /** Published at least once while the app was on show ([EngineAppApi.away] false): it may have been seen. */
        var seen = false

        fun wipe() {
            kit?.wipe()
            kit = null
        }
    }

    private var showing: Showing? = null

    /** The kit screen on show in the entry journey, or null. */
    val entryScreen: KitScreen? get() = showing?.takeIf { it.inEntry }?.screen

    /** The origin of the account whose kit is on show in the entry journey, or null. */
    val entryOrigin: String? get() = showing?.takeIf { it.inEntry }?.origin

    /** The kit screen on show in Settings, or null. */
    fun accountKit(): KitScreen? = showing?.takeIf { !it.inEntry }?.screen

    /**
     * A kit of a committed change is on show in the journey with the keeper's refusal ([showNotKept]): the account's only
     * kit. The end, the sign-out or the removal of another account kept here leaves it on show; a lock wipes it, and the
     * screen after says so ([io.silencelen.andvari.core.app.AppSnapshot.kitWiped]).
     */
    val notKeptOnShow: Boolean get() = showing?.let { it.inEntry && it.notKept != null && it.kit != null } == true

    /** For the kit of [notKeptOnShow]: (whether it came after a recovery, its account's address); null when none is on show. */
    fun notKeptRoad(): Pair<Boolean, String>? = showing?.takeIf { it.inEntry && it.notKept != null && it.kit != null }?.let {
        (it.reason != KitReason.FIRST_KIT) to it.email
    }

    /** With [notKeptRoad]: the server of the kit's account. */
    fun notKeptOrigin(): String? = showing?.takeIf { it.inEntry && it.notKept != null && it.kit != null }?.origin

    /** The kit on show was published while the app was on show (or no kit is on show). */
    val shownSeen: Boolean get() = showing?.seen != false

    /** The app is on show again: a kit on show now is seen. */
    fun seenNow() {
        showing?.seen = true
    }

    /** Show [kit], made by a registration or a recovery commit, on its reveal step. [onDone] runs once it is confirmed. */
    fun show(kit: RevealedKit, reason: KitReason, email: String, instance: InstanceLabel, origin: String, inEntry: Boolean, onDone: () -> Unit) {
        drop()
        val s = Showing(reason, email, instance, origin, inEntry, onDone)
        s.kit = kit
        s.step = KitStep.REVEAL
        s.madeAtMs = app.engine.clock()
        showing = s
        markShown(s)
        remake(s)
    }

    /**
     * Show [kit], which a commit made at the server although this device then refused the session (the engine handed it
     * up with the refusal), on its reveal step with [line]. The server holds a piece of it and the old kit is dead, so it
     * is never dropped unshown: it is wiped only once the person typed its groups ([confirmKit], checked here, as no
     * session can tell the server), or left. [onDone] runs after that confirmation.
     */
    fun showNotKept(kit: RevealedKit, reason: KitReason, line: io.silencelen.andvari.core.app.CopyKey, email: String, instance: InstanceLabel, origin: String, onDone: () -> Unit) {
        drop()
        val s = Showing(reason, email, instance, origin, inEntry = true, onDone)
        s.kit = kit
        s.notKept = line
        s.step = KitStep.REVEAL
        s.madeAtMs = app.engine.clock()
        showing = s
        markShown(s)
        remake(s)
    }

    /**
     * A sign-in found the kit never saved (§10): make a fresh one now with [password] (taken: wiped here), then show
     * it. When that fails the screen is on [KitStep.NOT_MADE] and [retryKit] asks for the password again. The vault
     * stays shut until a kit is confirmed.
     */
    suspend fun make(password: CharArray, reason: KitReason, email: String, instance: InstanceLabel, origin: String, inEntry: Boolean, onDone: () -> Unit): KitConfirmResult {
        drop()
        val s = Showing(reason, email, instance, origin, inEntry, onDone)
        showing = s
        remake(s)
        return rotate(s, password)
    }

    /** Leave the kit: its secret and any held password are wiped. */
    fun drop() {
        showing?.wipe()
        showing = null
    }

    private fun remake(s: Showing) {
        // Every kit carries its idle limit: the policy this device keeps for the kit's server (the account's own, in
        // Settings), five minutes where it keeps none; at most five minutes for a kit shown with a refusal.
        val policy = runCatching { app.policies.get(s.origin)?.autoLockSeconds }.getOrNull()
        val (limit, warnBefore, warning) = KitScreen.idleLimits(policy, s.notKept != null)
        val void = if (s.replacesShown && s.step == KitStep.REVEAL) io.silencelen.andvari.core.app.CopyKey.KIT_EARLIER_NOT_CONFIRMED_VOID else null
        s.screen = KitScreen(s.reason, s.step, s.email, s.instance, if (s.step == KitStep.CONFIRM) s.groups else emptyList(), s.failed, s.notKept,
            limit, warnBefore, warning, void)
        if (!app.away) s.seen = true
        app.publish()
    }

    /**
     * The mark at rest that a kit for [Showing.email] at [Showing.origin] is on show and not confirmed at the server: only
     * the address and the origin, never anything of the kit. It stays until a kit is confirmed there ([confirmKit]), so a
     * kit made later for the account, in this run or after a restart, says that the earlier one no longer works. A kit
     * typed back with a refusal ([confirmNotKept]) keeps it: the server holds that kit unconfirmed, and the next sign-in
     * replaces it.
     */
    private fun markShown(s: Showing) {
        runCatching { app.engine.state.set(shownKey(s), "1") }
    }

    /** A kit for this account was shown here and never confirmed at the server ([markShown]). */
    private fun shownBefore(s: Showing): Boolean = runCatching { app.engine.state.get(shownKey(s)) != null }.getOrDefault(false)

    private fun shownKey(s: Showing): String = shownKey(s.origin, s.email)

    internal companion object {
        /**
         * [markShown]'s record: `ovh.kit.shown|<origin>|<address>`. A record of that server like the others: registered at
         * the start ([io.silencelen.andvari.core.client.pin.PinStore.carryWithMoves]), so a followed move carries it and
         * "Forget this server" deletes it; the account's deletion on this device and the forgetting of an earlier account
         * under the address delete it by name ([shownKey]).
         */
        const val SHOWN_KEY = "ovh.kit.shown|"

        /** The mark's key for [email] at [origin]: the address as the keeper normalises it (lowercased where it is not one). */
        fun shownKey(origin: String, email: String): String =
            SHOWN_KEY + origin + "|" + (io.silencelen.andvari.core.trust.TrustGrammar.emailNorm(email) ?: email.trim().lowercase())
    }

    private fun on(screen: KitScreen): Showing? = showing?.takeIf { it.screen === screen }

    /** `PUT /recovery/self-setup`† with [password] (taken: the engine wipes it), and the fresh kit on its reveal. */
    private suspend fun rotate(s: Showing, password: CharArray): KitConfirmResult {
        val settings = settings(s.origin)
        if (settings == null) {
            password.fill('\u0000')
            return KitConfirmResult.STALE
        }
        val userId = app.keeper.established?.userId
        val r = try {
            app.working { settings.rotateKit(password) }
        } catch (e: io.silencelen.andvari.core.crypto.KeysGoneException) {
            // A lock before the request went: nothing was sent, the old kit stands.
            return KitConfirmResult.STALE
        }
        // The server replaced the kit: the old one is void and the new one is not confirmed until it is, whatever the
        // screen does next (a lock, a crash, the screen left).
        if (r is Reauthed.Done && userId != null) app.keeper.recoveryUnconfirmed(userId)
        if (showing !== s) {
            if (r is Reauthed.Done) r.value.wipe()
            return KitConfirmResult.STALE
        }
        return when (r) {
            is Reauthed.Done -> {
                s.kit = r.value
                s.step = KitStep.REVEAL
                s.failed = 0
                s.madeAtMs = app.engine.clock()
                // The server replaced the account's kit: one shown here before and never confirmed is void now.
                s.replacesShown = shownBefore(s)
                markShown(s)
                remake(s)
                KitConfirmResult.DONE
            }
            else -> {
                s.step = KitStep.NOT_MADE
                remake(s)
                reauthedTrouble(r)
            }
        }
    }

    private fun reauthedTrouble(r: Reauthed<*>): KitConfirmResult = when (r) {
        is Reauthed.Refused -> {
            app.noteRetryAfter(r.retryAfterSeconds)
            when (r.code) {
                WireErrors.RATE_LIMITED -> KitConfirmResult.RATE_LIMITED
                WireErrors.UPGRADE_REQUIRED -> KitConfirmResult.UPDATE_REQUIRED
                Reauthed.PROOF_REFUSED -> app.proofRefused(KitConfirmResult.KEYS_NOT_KNOWN_HERE, KitConfirmResult.PROOF_REFUSED)
                else -> KitConfirmResult.FAILED
            }
        }
        Reauthed.Unknown -> KitConfirmResult.UNREACHABLE
        Reauthed.WrongPassword -> KitConfirmResult.WRONG_PASSWORD
        else -> KitConfirmResult.FAILED
    }

    /** The engine's kit rotation for the kept session at [origin]. */
    private fun settings(origin: String): WireAccountSettings? {
        val open = app.keeper.established?.takeIf { it.origin == origin } ?: return null
        val pin = app.trust.pinFor(origin) ?: return null
        val reauth = app.keeper.reauth() ?: return null
        return WireAccountSettings(origin, open.emailNorm, pin.card0Hash, open.account, app.clientFor(origin), app.crypto, reauth,
            app.keeper.accountKdfParams() ?: io.silencelen.andvari.core.crypto.KdfParams.DEFAULT, thisDevice = open.deviceId)
    }

    override fun kitDocument(screen: KitScreen): KitDocument? {
        val s = on(screen) ?: return null
        if (s.step != KitStep.REVEAL) return null
        val kit = s.kit ?: return null
        return KitDocument(s.email, s.instance, s.madeAtMs, kit.groups, kit.qr, kit.accountId)
    }

    override fun proceedToConfirm(screen: KitScreen) {
        val s = on(screen) ?: return
        val kit = s.kit ?: return
        if (s.step != KitStep.REVEAL) return
        s.groups = app.onboardingFor(s.origin).kitChallenge(kit).sorted()
        s.step = KitStep.CONFIRM
        remake(s)
    }

    override fun showKitAgain(screen: KitScreen) {
        val s = on(screen) ?: return
        if (s.step != KitStep.CONFIRM) return
        s.step = KitStep.REVEAL
        remake(s)
    }

    override suspend fun confirmKit(screen: KitScreen, typedGroups: List<String>): KitConfirmResult {
        val s = on(screen) ?: return KitConfirmResult.STALE
        val kit = s.kit ?: return KitConfirmResult.STALE
        if (s.step != KitStep.CONFIRM || typedGroups.size != s.groups.size) return KitConfirmResult.STALE
        if (s.notKept != null) return confirmNotKept(s, kit, typedGroups)
        val typed = s.groups.zip(typedGroups).toMap()
        val r = app.working { app.onboardingFor(s.origin).confirmKit(kit, typed) }
        if (showing !== s) return KitConfirmResult.STALE
        return when (r) {
            KitConfirm.Confirmed -> {
                app.keeper.recoveryConfirmed()
                runCatching { app.engine.state.set(shownKey(s), null) }
                // A kit made now names the server's address as it is: one asked for after a move is no longer due.
                app.newKitDone(s.origin)
                s.wipe()
                showing = null
                s.onDone()
                app.publish()
                KitConfirmResult.DONE
            }
            KitConfirm.Wrong -> {
                s.failed++
                remake(s)
                KitConfirmResult.MISMATCH
            }
            KitConfirm.ShowAgain -> {
                s.failed = 0
                s.groups = emptyList()
                s.step = KitStep.REVEAL
                remake(s)
                KitConfirmResult.MISMATCH
            }
            is KitConfirm.Unrecorded -> when (r.code) {
                WireErrors.RATE_LIMITED -> KitConfirmResult.RATE_LIMITED
                WireErrors.UPGRADE_REQUIRED -> KitConfirmResult.UPDATE_REQUIRED
                // A newer kit made elsewhere: this one is void, and a fresh one needs the password (retryKit).
                "recovery_piece_stale" -> {
                    s.wipe()
                    s.reason = KitReason.REPLACED_ELSEWHERE
                    s.step = KitStep.NOT_MADE
                    s.failed = 0
                    s.groups = emptyList()
                    remake(s)
                    KitConfirmResult.REPLACED
                }
                "unreachable" -> KitConfirmResult.UNREACHABLE
                else -> KitConfirmResult.FAILED
            }
        }
    }

    /**
     * The confirm of a kit shown with a refusal ([showNotKept]): the groups are checked on this device against the kit's
     * own secret, as the engine checks them before it tells the server; no session exists to record it there (the next
     * sign-in reads the server's own record and asks for a kit again where it holds none confirmed). Three wrong entries
     * show the kit again. Only a match wipes the kit.
     */
    private fun confirmNotKept(s: Showing, kit: RevealedKit, typedGroups: List<String>): KitConfirmResult {
        if (!io.silencelen.andvari.core.trust.RecoveryKit.confirmMatches(kit.secret, s.groups, typedGroups)) {
            s.failed++
            if (s.failed >= 3) {
                s.failed = 0
                s.groups = emptyList()
                kit.challenge = null
                s.step = KitStep.REVEAL
            }
            remake(s)
            return KitConfirmResult.MISMATCH
        }
        s.wipe()
        showing = null
        s.onDone()
        app.publish()
        return KitConfirmResult.DONE
    }

    override suspend fun retryKit(screen: KitScreen, password: String): KitConfirmResult {
        val s = on(screen) ?: return KitConfirmResult.STALE
        if (s.step != KitStep.NOT_MADE) return KitConfirmResult.STALE
        s.step = KitStep.MAKING
        remake(s)
        return rotate(s, password.toCharArray())
    }
}
