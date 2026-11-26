package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.TwoStepEnrolment
import io.silencelen.andvari.core.app.TwoStepKey
import io.silencelen.andvari.core.app.TwoStepResult
import io.silencelen.andvari.core.app.TwoStepScreen
import io.silencelen.andvari.core.app.authenticatorLink
import io.silencelen.andvari.core.client.account.Fetched
import io.silencelen.andvari.core.client.account.TwoStepAnswer
import io.silencelen.andvari.core.client.account.TwoStepSecret
import io.silencelen.andvari.core.client.account.TwoStepSetup
import io.silencelen.andvari.core.client.account.WireTwoStep
import io.silencelen.andvari.core.model.wire.WireErrors
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Settings › Two-step sign-in (spec 03 rows 13 to 16) over the engine's [WireTwoStep] on the kept session.
 *
 * The key being set up ([Pending]) lives as the old controller's did (round-6 to round-8 reviews): it is held while the
 * screen is open and through a trip away from the app (to add it to an authenticator, which may lock the app), for at
 * most [PENDING_MS] from when the server minted it. A lock keeps it, and after the next unlock the screen is open again
 * on its confirm step ([resume]). A sign-out, an ended session, a forgotten or followed server, its time running out
 * (at once, locked or not), a confirm, or closing the screen while unlocked drop it. Only the key and its link are
 * kept, never the password, and the key never enters a snapshot: [twoStepKey] reads it.
 */
internal class EngineTwoStep(private val app: EngineAppApi) {
    private class Pending(val secret: TwoStepSecret, val mintedAtMs: Long, val origin: String, val userId: String) {
        val enrolment = TwoStepEnrolment()
    }

    private var open = false
    private var enabled = false
    private var pending: Pending? = null
    private var shown: TwoStepScreen? = null
    private var expiry: Job? = null

    /** Moves on at every open, close, lock and end, so an answer for a screen that went is not applied. */
    private var generation = 0

    private fun now(): Long = app.engine.clocks?.monotonicMs() ?: app.engine.clock()

    /** Whether a key being set up is held (tests: what a lock or an end keeps). */
    internal fun holdsKey(): Boolean = pending != null

    /** The two-step engine of the established session, or null when no session is established or no reauth exists. */
    private fun wire(): WireTwoStep? {
        val open = app.keeper.established ?: return null
        val reauth = app.keeper.reauth() ?: return null
        return WireTwoStep(app.clientFor(open.origin), reauth)
    }

    /** The pending key while it belongs to the established session and is in time; one past its time or another's goes. */
    private fun live(): Pending? {
        val p = pending ?: return null
        val est = app.keeper.established
        val age = now() - p.mintedAtMs
        if (age !in 0 until PENDING_MS || est == null || est.origin != p.origin || est.userId != p.userId) {
            drop()
            return null
        }
        return p
    }

    private fun drop() {
        pending = null
        expiry?.cancel()
        expiry = null
    }

    /** The screen as a snapshot carries it; null while closed. Kept the same object while nothing on it changed. */
    fun screen(): TwoStepScreen? {
        if (!open) {
            shown = null
            return null
        }
        val enrolment = live()?.enrolment
        val s = shown
        if (s != null && s.enabled == enabled && s.enrolment === enrolment) return s
        return TwoStepScreen(enabled, enrolment).also { shown = it }
    }

    private fun onShow(screen: TwoStepScreen): Boolean = app.phase == AppPhase.UNLOCKED && app.snapshot.account?.twoStep === screen

    // ---- the lifecycle the app API drives ----

    /** The app locked: the screen closes, and a key in time stays for the trip. */
    fun locked() {
        open = false
        generation++
        live()
    }

    /** The vault opened again: a key still in time puts the screen back on its confirm step. */
    fun resume() {
        if (live() == null) return
        open = true
        enabled = false
        generation++
    }

    /** The session ended, or its server was forgotten or followed: the screen and any key go. */
    fun ended() {
        open = false
        generation++
        drop()
    }

    // ---- the intents ----

    suspend fun openTwoStep(): PlainResult {
        if (app.phase != AppPhase.UNLOCKED) return PlainResult.STALE
        val w = wire() ?: return PlainResult.STALE
        val g = ++generation
        val r = app.working { w.status() }
        if (g != generation || app.phase != AppPhase.UNLOCKED) return PlainResult.STALE
        return when (r) {
            is Fetched.Ok -> {
                open = true
                enabled = r.value.enrolled
                // A key this device holds is shown only while the server still waits for its first code.
                if (r.value.enrolled || !r.value.pendingSetup) drop()
                app.publish()
                PlainResult.DONE
            }
            is Fetched.Refused -> refusedPlain(r.code)
            Fetched.Unreachable -> PlainResult.UNREACHABLE
        }
    }

    fun closeTwoStep() {
        if (app.phase != AppPhase.UNLOCKED || !open) return
        // Closed by the person: a key not yet confirmed is forgotten (the server drops it unconfirmed).
        ended()
        app.publish()
    }

    suspend fun startTwoStep(screen: TwoStepScreen, password: String): TwoStepResult {
        if (!onShow(screen)) return TwoStepResult.STALE
        if (screen.enabled) return TwoStepResult.NOT_PENDING
        val est = app.keeper.established ?: return TwoStepResult.STALE
        val w = wire() ?: return TwoStepResult.STALE
        if (password.isEmpty()) return TwoStepResult.WRONG_PASSWORD
        val g = generation
        // The engine wipes the array; the String is the caller's.
        val r = app.working { w.setup(password.toCharArray()) }
        val still = app.keeper.established
        if (g != generation || app.phase != AppPhase.UNLOCKED || still == null || still.origin != est.origin || still.userId != est.userId) {
            // The screen closed meanwhile: the new key is not held (the server drops it unconfirmed).
            return TwoStepResult.STALE
        }
        return when (r) {
            is TwoStepSetup.Ready -> {
                drop()
                val p = Pending(r.secret, now(), est.origin, est.userId)
                pending = p
                expiry = app.scope.launch {
                    delay(PENDING_MS)
                    if (pending === p) {
                        drop()
                        app.publish()
                    }
                }
                app.publish()
                TwoStepResult.DONE
            }
            TwoStepSetup.WrongPassword -> TwoStepResult.WRONG_PASSWORD
            // The server wants a current code: two-step sign-in is on already. The screen reads it again.
            TwoStepSetup.ReauthRequired -> movedOn()
            TwoStepSetup.BadCode -> TwoStepResult.WRONG_CODE
            TwoStepSetup.NoSession -> TwoStepResult.FAILED
            is TwoStepSetup.Refused -> refused(r.code, r.retryAfterSeconds)
            TwoStepSetup.Unknown -> TwoStepResult.UNREACHABLE
        }
    }

    fun twoStepKey(enrolment: TwoStepEnrolment): TwoStepKey? {
        if (app.phase != AppPhase.UNLOCKED || app.snapshot.account?.twoStep?.enrolment !== enrolment) return null
        val p = live()?.takeIf { it.enrolment === enrolment } ?: return null
        return TwoStepKey(p.secret.secretBase32, authenticatorLink(p.secret.secretBase32, p.secret.otpauthUri, hostOf(p.origin)))
    }

    suspend fun confirmTwoStep(enrolment: TwoStepEnrolment, code: String): TwoStepResult {
        if (app.phase != AppPhase.UNLOCKED || app.snapshot.account?.twoStep?.enrolment !== enrolment) return TwoStepResult.STALE
        val p = live()?.takeIf { it.enrolment === enrolment }
        if (p == null) {
            app.publish()
            return TwoStepResult.NOT_PENDING
        }
        val w = wire() ?: return TwoStepResult.STALE
        val g = generation
        val r = app.working { w.confirm(code.trim()) }
        if (r == TwoStepAnswer.Ok) {
            // On at the server whatever the screen did meanwhile; the screen is redrawn only while it is open.
            if (pending === p) drop()
            if (g == generation && open) enabled = true
            app.publish()
            return TwoStepResult.DONE
        }
        if (g != generation || app.phase != AppPhase.UNLOCKED) return TwoStepResult.STALE
        return when (r) {
            TwoStepAnswer.BadCode -> TwoStepResult.WRONG_CODE // the key stays up for the next code
            TwoStepAnswer.NoPendingSetup, TwoStepAnswer.NotEnrolled -> {
                if (pending === p) drop()
                movedOn()
            }
            TwoStepAnswer.NoSession, TwoStepAnswer.WrongPassword, TwoStepAnswer.ReauthRequired -> TwoStepResult.FAILED
            is TwoStepAnswer.Refused -> refused(r.code, r.retryAfterSeconds)
            TwoStepAnswer.Unknown -> TwoStepResult.UNREACHABLE
            TwoStepAnswer.Ok -> TwoStepResult.DONE
        }
    }

    /**
     * The code alone no longer turns two-step sign-in off (decided on 2026-11-16): nothing is sent, and the answer says the
     * master password is needed. Kept so that no app breaks.
     */
    @Suppress("UNUSED_PARAMETER")
    fun turnOffTwoStep(screen: TwoStepScreen, code: String): TwoStepResult {
        if (!onShow(screen)) return TwoStepResult.STALE
        if (!screen.enabled) return TwoStepResult.NOT_PENDING
        return TwoStepResult.PASSWORD_NEEDED
    }

    suspend fun turnOffTwoStepWithPassword(screen: TwoStepScreen, code: String, password: String): TwoStepResult {
        if (!onShow(screen)) return TwoStepResult.STALE
        if (!screen.enabled) return TwoStepResult.NOT_PENDING
        val w = wire() ?: return TwoStepResult.STALE
        if (password.isEmpty()) return TwoStepResult.WRONG_PASSWORD
        val g = generation
        // The engine wipes the array on every path; the String is the caller's.
        val r = app.working { w.disable(code.trim(), password.toCharArray()) }
        if (r == TwoStepAnswer.Ok) {
            if (g == generation && open) enabled = false
            app.publish()
            return TwoStepResult.DONE
        }
        if (g != generation || app.phase != AppPhase.UNLOCKED) return TwoStepResult.STALE
        return when (r) {
            TwoStepAnswer.BadCode -> TwoStepResult.WRONG_CODE
            TwoStepAnswer.WrongPassword -> TwoStepResult.WRONG_PASSWORD
            TwoStepAnswer.NotEnrolled, TwoStepAnswer.NoPendingSetup -> movedOn()
            // The server asked for a proof that was sent: it does not take this one. Never a wrong password.
            TwoStepAnswer.ReauthRequired, TwoStepAnswer.NoSession -> TwoStepResult.FAILED
            is TwoStepAnswer.Refused -> triesRefused(r.code, r.retryAfterSeconds)
            TwoStepAnswer.Unknown -> TwoStepResult.UNREACHABLE
            TwoStepAnswer.Ok -> TwoStepResult.DONE
        }
    }

    suspend fun replaceTwoStepKey(screen: TwoStepScreen, code: String, password: String): TwoStepResult {
        if (!onShow(screen)) return TwoStepResult.STALE
        if (!screen.enabled) return TwoStepResult.NOT_PENDING
        val est = app.keeper.established ?: return TwoStepResult.STALE
        val w = wire() ?: return TwoStepResult.STALE
        if (password.isEmpty()) return TwoStepResult.WRONG_PASSWORD
        val g = generation
        val r = app.working { w.rotate(code.trim(), password.toCharArray()) }
        val still = app.keeper.established
        if (g != generation || app.phase != AppPhase.UNLOCKED || still == null || still.origin != est.origin || still.userId != est.userId) {
            return TwoStepResult.STALE
        }
        return when (r) {
            is TwoStepSetup.Ready -> {
                hold(r.secret, est.origin, est.userId)
                TwoStepResult.DONE
            }
            TwoStepSetup.WrongPassword -> TwoStepResult.WRONG_PASSWORD
            TwoStepSetup.BadCode -> TwoStepResult.WRONG_CODE
            TwoStepSetup.ReauthRequired, TwoStepSetup.NoSession -> TwoStepResult.FAILED
            is TwoStepSetup.Refused -> triesRefused(r.code, r.retryAfterSeconds)
            TwoStepSetup.Unknown -> TwoStepResult.UNREACHABLE
        }
    }

    /** A new key the server minted: held for the confirm step, for at most [PENDING_MS]. Publishes. */
    private fun hold(secret: TwoStepSecret, origin: String, userId: String) {
        drop()
        val p = Pending(secret, now(), origin, userId)
        pending = p
        expiry = app.scope.launch {
            delay(PENDING_MS)
            if (pending === p) {
                drop()
                app.publish()
            }
        }
        app.publish()
    }

    /** As [refused], where a `429` is a back-off of the proofs' or of the codes' (or the route's bucket): too many tries. */
    private fun triesRefused(code: String, retryAfterSeconds: Long?): TwoStepResult {
        if (code != WireErrors.RATE_LIMITED) return refused(code, retryAfterSeconds)
        app.noteRetryAfter(retryAfterSeconds)
        return TwoStepResult.TOO_MANY_TRIES
    }

    /** The server's state moved on: read it again so the screen shows what it is, and say so. */
    private suspend fun movedOn(): TwoStepResult {
        val w = wire()
        val g = generation
        val r = w?.let { app.working { it.status() } }
        if (r is Fetched.Ok && g == generation && open) {
            enabled = r.value.enrolled
            if (r.value.enrolled || !r.value.pendingSetup) drop()
        }
        app.publish()
        return TwoStepResult.NOT_PENDING
    }

    private fun refused(code: String, retryAfterSeconds: Long?): TwoStepResult {
        app.noteRetryAfter(retryAfterSeconds)
        return when (code) {
            WireErrors.RATE_LIMITED -> TwoStepResult.RATE_LIMITED
            WireErrors.UPGRADE_REQUIRED -> TwoStepResult.UPDATE_REQUIRED
            io.silencelen.andvari.core.client.account.Reauthed.PROOF_REFUSED -> app.proofRefused(TwoStepResult.KEYS_NOT_KNOWN_HERE, TwoStepResult.PROOF_REFUSED)
            else -> TwoStepResult.FAILED
        }
    }

    private fun refusedPlain(code: String): PlainResult = when (code) {
        WireErrors.RATE_LIMITED -> PlainResult.RATE_LIMITED
        WireErrors.UPGRADE_REQUIRED -> PlainResult.UPDATE_REQUIRED
        else -> PlainResult.FAILED
    }

    internal companion object {
        /** How long a key being set up is held from when the server minted it (the old controller's 10 minutes). */
        const val PENDING_MS = 10 * 60 * 1000L

        /** The host of [origin], as the authenticator's label names the server. */
        fun hostOf(origin: String): String = origin.substringAfter("://").substringBefore('/').substringBefore(':')
    }
}
