package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.crypto.KeysGoneException
import io.silencelen.andvari.core.client.session.PresenceOutcome
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.DeviceLinkHost
import io.silencelen.andvari.core.app.DeviceLinkHostEnd
import io.silencelen.andvari.core.app.DeviceRow
import io.silencelen.andvari.core.app.DevicesApi
import io.silencelen.andvari.core.app.DevicesScreen
import io.silencelen.andvari.core.app.DigitsResult
import io.silencelen.andvari.core.app.HowDeviceJoined
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ProofResult
import io.silencelen.andvari.core.app.Trouble
import io.silencelen.andvari.core.client.account.Fetched
import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.account.WireAccountSettings
import io.silencelen.andvari.core.client.devicelink.DeviceLinkStop
import io.silencelen.andvari.core.client.devicelink.ExistingStep
import io.silencelen.andvari.core.model.wire.Device
import kotlinx.coroutines.launch
import io.silencelen.andvari.core.model.wire.WireErrors

/**
 * "Your devices" (design §8.6) and "New devices must be linked" (§8.7) on the engine's [WireAccountSettings]: the list
 * as the server serves it, a revoke and the switch, each behind the one re-authentication path (`PasswordGate` purpose
 * `reauth`, this session's origin and account), which wipes the password it is handed.
 *
 * The server serves no read of "New devices must be linked" (spec 03 §16.8 has only the `PUT`), so the screen says
 * what THIS device set during this session and otherwise that it is not known ([DevicesScreen.requireLinkKnown]).
 *
 * Linking a new device from this one (the existing device's side, [DeviceLinkHost], §8.2) runs the engine's
 * [io.silencelen.andvari.core.client.devicelink.DeviceLinks] for the open account: the link and its QR with the
 * server's name and origin for comparison, a poll while it waits on the new device, the digits typed here, and the
 * approval behind the local unlock (the master password opening this device's copy; nothing is sent for it).
 */
internal class EngineDevices(private val app: EngineAppApi) : DevicesApi {
    private var open = false
    private var listed: List<Device>? = null
    private var shown: DevicesScreen? = null

    /** What this device set for "New devices must be linked" this session, for the session's origin and account. */
    private var requireLinkSet: Triple<String, String, Boolean>? = null

    /** The names of the account's devices by id, from the last list read this opening (for "made on" lines). */
    private val names = HashMap<String, String>()
    private var namesAsked = false

    /** The names' read of this opening was started and has not ended (a recomposition cancels it). */
    private var namesDue = false

    /** Moves on at every open, lock and end, so an answer for a screen that went is not applied. */
    private var generation = 0

    fun locked() {
        open = false
        shown = null
        listed = null
        names.clear()
        namesAsked = false
        namesDue = false
        generation++
        hostEnded()
    }

    fun ended() {
        locked()
        requireLinkSet = null
    }

    /**
     * "New devices must be linked" for the open account as this device knows it: what this device set during this
     * session, or null (the server serves no read of it, so this device cannot tell).
     */
    fun requireLinkKnown(): Boolean? {
        val est = app.keeper.established ?: return null
        return requireLinkSet?.takeIf { it.first == est.origin && it.second == est.userId }?.third
    }

    private fun settings(): WireAccountSettings? {
        val est = app.keeper.established ?: return null
        val pin = app.trust.pinFor(est.origin) ?: return null
        val reauth = app.keeper.reauth() ?: return null
        // This session's device id: a whole list of another account (it marks another device `current`) is refused.
        return WireAccountSettings(est.origin, est.emailNorm, pin.card0Hash, est.account, app.clientFor(est.origin), app.crypto, reauth,
            app.keeper.accountKdfParams() ?: io.silencelen.andvari.core.crypto.KdfParams.DEFAULT, thisDevice = est.deviceId)
    }

    private fun unlocked() = app.phase == AppPhase.UNLOCKED && app.keeper.established != null

    // ---- the snapshot ----

    fun screen(): DevicesScreen? {
        if (!open || !unlocked()) return null
        val list = listed ?: return null
        val est = app.keeper.established ?: return null
        val set = requireLinkSet?.takeIf { it.first == est.origin && it.second == est.userId }
        val s = shown
        if (s != null && s.requireLinkKnown == (set != null) && s.requireLink == (set?.third ?: false)) return s
        val rows = list.sortedWith(compareBy({ !it.current }, { -(it.lastSeenAt ?: 0L) }, { it.deviceId })).map(::row)
        return DevicesScreen(rows, set?.third ?: false, requireLinkKnown = set != null).also { shown = it }
    }

    private fun row(d: Device): DeviceRow = DeviceRow(
        d.deviceId,
        AppPlatform.entries.firstOrNull { it.wireName == d.platform && it != AppPlatform.UNKNOWN } ?: AppPlatform.UNKNOWN,
        d.name,
        d.clientVersion.orEmpty(),
        d.createdAt,
        d.lastSeenAt ?: 0L,
        d.live,
        when (d.how) {
            "registered" -> HowDeviceJoined.REGISTERED
            "password" -> HowDeviceJoined.PASSWORD
            "linked" -> HowDeviceJoined.LINKED
            "recovered" -> HowDeviceJoined.RECOVERED
            else -> HowDeviceJoined.NOT_KNOWN
        },
        d.linkedFrom?.let { from -> listed?.firstOrNull { it.deviceId == from }?.name }.orEmpty(),
        d.current,
    )

    /** The name the account's device [deviceId] gave itself, for a "made on" line; empty while it is not known. */
    fun nameOf(deviceId: String): String = if (deviceId.isEmpty() || !unlocked()) "" else names[deviceId].orEmpty()

    /**
     * At an opening of the vault: when a contact of the account names the device that made it, the list is read once,
     * in the vault's scope, so "made on" lines can name it; a snapshot follows when it came. Nothing is read otherwise.
     */
    fun readNamesIfNeeded() {
        if (namesAsked || !unlocked()) return
        val v = app.vault ?: return
        if (v.store.local().contacts.values.none { it.madeOn.isNotEmpty() }) return
        namesAsked = true
        namesDue = true
        val g = generation
        v.launch {
            val r = settings()?.list()
            // An answer, or none to be had: the read is over for this opening. A read the old vault's scope cancelled
            // never gets here, and [recomposed] asks again.
            if (g == generation) namesDue = false
            if (r == null || g != generation || r !is Fetched.Ok) return@launch
            take(r.value)
            app.publish()
        }
    }

    /** The open vault was composed again: a read of the names it cancelled with the old vault's scope is made again. */
    fun recomposed() {
        if (!namesDue) return
        namesAsked = false
        readNamesIfNeeded()
    }

    /**
     * A device link made here completed (the approval was answered): "Your devices", when open, is read again in the
     * vault's scope, so it is fresh without the person reopening it (the screens' ask). The new device is listed once
     * the server has it; a read that gets no answer leaves the list as it was.
     */
    private fun refreshAfterLink() {
        if (!open || !unlocked()) return
        val v = app.vault ?: return
        val g = generation
        v.launch {
            val r = settings()?.list()
            if (r !is Fetched.Ok || g != generation || !open || !unlocked()) return@launch
            take(r.value)
            app.publish()
        }
    }

    private fun take(list: List<Device>) {
        listed = list
        shown = null
        names.clear()
        for (d in list) names[d.deviceId] = d.name
    }

    // ---- intents ----

    override suspend fun openDevices(): PlainResult {
        if (!unlocked()) return PlainResult.STALE
        val s = settings() ?: return PlainResult.STALE
        val g = ++generation
        val r = app.working { s.list() }
        if (g != generation || !unlocked()) return PlainResult.STALE
        return when (r) {
            is Fetched.Ok -> {
                take(r.value)
                open = true
                app.publish()
                PlainResult.DONE
            }
            is Fetched.Refused -> when (r.code) {
                WireErrors.RATE_LIMITED -> PlainResult.RATE_LIMITED
                WireErrors.UPGRADE_REQUIRED -> PlainResult.UPDATE_REQUIRED
                else -> PlainResult.FAILED
            }
            Fetched.Unreachable -> PlainResult.UNREACHABLE
        }
    }

    override fun closeDevices() {
        if (!open) return
        open = false
        shown = null
        generation++
        app.publish()
    }

    private fun onShow(): DevicesScreen? = app.snapshot.account?.devices?.takeIf { open && unlocked() }

    override suspend fun revokeDevice(device: DeviceRow, password: String): ProofResult {
        val screen = onShow() ?: return ProofResult.STALE
        if (screen.devices.none { it === device }) return ProofResult.STALE
        // This device signs out instead. A device that is not live is still offered: one that signed out or sat idle is
        // still a known device (§8.7) until a revoke clears its secret, and the list cannot tell it from a revoked one.
        if (device.current) return ProofResult.NOT_POSSIBLE
        if (password.isEmpty()) return ProofResult.WRONG_PASSWORD
        val s = settings() ?: return ProofResult.STALE
        val g = generation
        val r = app.working { s.revoke(device.deviceId, password.toCharArray()) }
        if (g != generation || !unlocked()) return ProofResult.STALE
        val result = proof(r)
        // Done or not, the list is read again so the screen shows what the server holds now.
        if (result != ProofResult.WRONG_PASSWORD) reread()
        return result
    }

    override suspend fun setRequireLink(enabled: Boolean, password: String): ProofResult {
        onShow() ?: return ProofResult.STALE
        if (password.isEmpty()) return ProofResult.WRONG_PASSWORD
        val est = app.keeper.established ?: return ProofResult.STALE
        val s = settings() ?: return ProofResult.STALE
        val g = generation
        val r = app.working { s.setRequireLink(enabled, password.toCharArray()) }
        if (g != generation || !unlocked()) return ProofResult.STALE
        if (r is Reauthed.Done) {
            requireLinkSet = Triple(est.origin, est.userId, r.value)
            shown = null
            app.publish()
        }
        return proof(r)
    }

    private suspend fun reread() {
        val s = settings() ?: return
        val g = generation
        val r = s.list()
        if (g != generation || !open || r !is Fetched.Ok) return
        take(r.value)
        app.publish()
    }

    private fun proof(r: Reauthed<*>): ProofResult = when (r) {
        is Reauthed.Done -> ProofResult.DONE
        Reauthed.WrongPassword -> ProofResult.WRONG_PASSWORD
        Reauthed.NoSession, Reauthed.PasswordTooWeak -> ProofResult.FAILED
        Reauthed.Unknown -> ProofResult.UNREACHABLE
        is Reauthed.Refused -> {
            app.noteRetryAfter(r.retryAfterSeconds)
            when (r.code) {
                WireErrors.RATE_LIMITED -> ProofResult.RATE_LIMITED
                WireErrors.UPGRADE_REQUIRED -> ProofResult.UPDATE_REQUIRED
                WireErrors.CREDENTIAL_CHANGED -> ProofResult.CHANGED_ELSEWHERE
                // The server's codes for a device that is not the account's, or is the caller (spec 03 §16.7); a
                // device id that is not a uuid is refused here before anything is sent.
                WireErrors.NO_SUCH_DEVICE, WireErrors.CANNOT_TARGET_SELF, "not_found", "bad_device_id" -> ProofResult.NOT_POSSIBLE
                Reauthed.PROOF_REFUSED -> app.proofRefused(ProofResult.KEYS_NOT_KNOWN_HERE, ProofResult.PROOF_REFUSED)
                else -> ProofResult.FAILED
            }
        }
    }

    // ---- linking a new device from this one (§8.2, the existing device's side) ----

    /** The engine's step of the link this device runs; null when none runs. */
    private var hostStep: ExistingStep? = null

    /** What the screen shows of it; kept after an approval or an end until it is dismissed. */
    private var host: DeviceLinkHost? = null

    /** The link's URL, for the QR, while its step is [ExistingStep.Shown]. */
    private var hostUrl: String? = null

    /** When the link runs out, on the monotonic clock, from the server's `ttlMs` (SR-1). */
    private var hostDeadline = 0L
    private var hostPoll: kotlinx.coroutines.Job? = null

    /** Moves on at every new link, cancel, dismissal, lock and end: an answer for a link that went is not applied. */
    private var hostGeneration = 0

    private fun nowMono(): Long = app.engine.clocks?.monotonicMs() ?: app.engine.clock()

    /** The link on show ([io.silencelen.andvari.core.app.AccountSnapshot.deviceLink]), while the vault is open. */
    fun hostScreen(): DeviceLinkHost? = host?.takeIf { unlocked() }

    private fun platformOf(wire: String): AppPlatform = AppPlatform.entries.firstOrNull { it.wireName == wire && it != AppPlatform.UNKNOWN } ?: AppPlatform.UNKNOWN

    private fun endOf(reason: DeviceLinkStop): DeviceLinkHostEnd = when (reason) {
        DeviceLinkStop.CANCELLED -> DeviceLinkHostEnd.CANCELLED
        DeviceLinkStop.CODE_MISMATCH -> DeviceLinkHostEnd.CODE_MISMATCH
        DeviceLinkStop.EXPIRED -> DeviceLinkHostEnd.EXPIRED
        else -> DeviceLinkHostEnd.DID_NOT_CHECK_OUT
    }

    /** Show [step]; the same screen object is kept while the step says the same. */
    private fun showStep(step: ExistingStep) {
        val before = host
        hostStep = step.takeIf { it !is ExistingStep.Stopped && it !is ExistingStep.Approved }
        host = when (step) {
            is ExistingStep.Shown -> (before as? DeviceLinkHost.Shown) ?: app.labelFor(step.origin)?.let { DeviceLinkHost.Shown(it) }
            is ExistingStep.ClaimFixed -> (before as? DeviceLinkHost.Claimed)?.takeIf { it.deviceName == step.name } ?: DeviceLinkHost.Claimed(step.name, platformOf(step.platform))
            is ExistingStep.TypeDigits -> (before as? DeviceLinkHost.TypeDigits)?.takeIf { it.deviceName == step.name } ?: DeviceLinkHost.TypeDigits(step.name, platformOf(step.platform))
            // Quick unlock cannot yet prove the person here without opening the account again: the password is asked.
            is ExistingStep.Approvable -> (before as? DeviceLinkHost.Approvable)?.takeIf { it.deviceName == step.name } ?: DeviceLinkHost.Approvable(step.name, platformOf(step.platform), biometricsOffered = app.quick?.status()?.usable == true)
            is ExistingStep.Approved -> DeviceLinkHost.Approved(step.name)
            is ExistingStep.Stopped -> if (step.reason == DeviceLinkStop.TOO_MANY) {
                // Refused as one of too many requests: never "a check failed" or "unreachable"; the wait it named is kept.
                app.noteRetryAfter(step.retryAfterSeconds)
                DeviceLinkHost.Ended(DeviceLinkHostEnd.DID_NOT_CHECK_OUT, io.silencelen.andvari.core.app.CopyKey.DEVICE_LINK_HOST_TOO_MANY,
                    app.namedWait(step.retryAfterSeconds))
            } else {
                DeviceLinkHost.Ended(endOf(step.reason))
            }
        }
        if (step !is ExistingStep.Shown) hostUrl = null
        if (hostStep == null) {
            hostPoll?.cancel()
            hostPoll = null
        }
    }

    /** The running link goes: its poll stops and the engine cancels it (best effort; the server deletes it). */
    private fun dropHost() {
        hostGeneration++
        hostPoll?.cancel()
        hostPoll = null
        val step = hostStep
        hostStep = null
        hostUrl = null
        if (step != null) app.scope.launch { runCatching { tokenOf(step)?.let { app.deviceLinks.cancel(it) } } }
    }

    private fun tokenOf(step: ExistingStep): io.silencelen.andvari.core.client.devicelink.DeviceLinkToken? = when (step) {
        is ExistingStep.Shown -> step.token
        is ExistingStep.ClaimFixed -> step.token
        is ExistingStep.TypeDigits -> step.token
        is ExistingStep.Approvable -> step.token
        else -> null
    }

    /** The lock and the end close the link: it needs the open account to be approved. */
    private fun hostEnded() {
        dropHost()
        host = null
    }

    /** Advance the link every [EngineAppApi.linkPollMs] while it waits on the new device. */
    private fun pollHost() {
        hostPoll?.cancel()
        val g = hostGeneration
        hostPoll = app.scope.launch {
            while (g == hostGeneration) {
                kotlinx.coroutines.delay(app.linkPollMs)
                if (!pollHostOnce(g)) break
            }
        }
    }

    /** One advance of the running link (tests drive the poll with it). True while it still waits on the new device. */
    internal suspend fun pollDeviceLinkHost(): Boolean = pollHostOnce(hostGeneration)

    private suspend fun pollHostOnce(g: Int): Boolean {
        val s = hostStep
        if (s !is ExistingStep.Shown && s !is ExistingStep.ClaimFixed) return false
        // The link's own time is the time of its first step only (shown, not yet claimed): once claimed, each step has
        // its own time at the server, counted from when it began, and the server's answer says when it ran out.
        if (s is ExistingStep.Shown && nowMono() > hostDeadline) {
            dropHost()
            host = DeviceLinkHost.Ended(DeviceLinkHostEnd.EXPIRED)
            app.publish()
            return false
        }
        val next = app.deviceLinks.advance(s)
        if (g != hostGeneration || hostStep !== s || !unlocked()) return false
        // No answer is not an end: the link waits, and the next poll asks again.
        if (next is ExistingStep.Stopped && next.reason == DeviceLinkStop.UNREACHABLE) return true
        if (next !== s) {
            showStep(next)
            app.publish()
        }
        return next is ExistingStep.Shown || next is ExistingStep.ClaimFixed
    }

    override suspend fun startDeviceLink(): PlainResult {
        if (!unlocked() || app.vault?.signedOutByServer == true) return PlainResult.STALE
        dropHost()
        host = null
        val g = hostGeneration
        val r = app.working { app.deviceLinks.create() }
        if (g != hostGeneration || !unlocked()) {
            if (r is ExistingStep.Shown) app.scope.launch { runCatching { app.deviceLinks.cancel(r.token) } }
            return PlainResult.STALE
        }
        return when (r) {
            is ExistingStep.Shown -> {
                hostUrl = r.url
                hostDeadline = nowMono() + r.ttlMs
                showStep(r)
                app.publish()
                pollHost()
                PlainResult.DONE
            }
            is ExistingStep.Stopped -> when (r.reason) {
                DeviceLinkStop.UNREACHABLE -> PlainResult.UNREACHABLE
                DeviceLinkStop.TOO_MANY -> {
                    app.noteRetryAfter(r.retryAfterSeconds)
                    PlainResult.RATE_LIMITED
                }
                else -> PlainResult.FAILED
            }
            else -> PlainResult.FAILED
        }
    }

    override fun deviceLinkToShow(screen: DeviceLinkHost.Shown): String? =
        hostUrl?.takeIf { unlocked() && host === screen && hostStep is ExistingStep.Shown }

    override fun deviceLinkTimeLeftMs(): Long = if (hostStep == null) 0L else (hostDeadline - nowMono()).coerceAtLeast(0L)

    override suspend fun submitDeviceDigits(screen: DeviceLinkHost.TypeDigits, digits: String): DigitsResult {
        val s = hostStep as? ExistingStep.TypeDigits
        if (!unlocked() || host !== screen || s == null) return DigitsResult.STALE
        val g = hostGeneration
        val next = app.working { app.deviceLinks.typeDigits(s, digits) }
        if (g != hostGeneration || !unlocked()) return DigitsResult.STALE
        showStep(next)
        app.publish()
        return when {
            next is ExistingStep.Approvable -> DigitsResult.DONE
            next is ExistingStep.Stopped && next.reason == DeviceLinkStop.CODE_MISMATCH -> DigitsResult.MISMATCH
            next is ExistingStep.Stopped && next.reason == DeviceLinkStop.UNREACHABLE -> DigitsResult.UNREACHABLE
            // The link ended there ([showStep] says so with its own line); the wait is [AppApi.retryAfterSeconds].
            next is ExistingStep.Stopped && next.reason == DeviceLinkStop.TOO_MANY -> DigitsResult.RATE_LIMITED
            else -> DigitsResult.FAILED
        }
    }

    override suspend fun approveWithPassword(screen: DeviceLinkHost.Approvable, password: String): ProofResult {
        val s = hostStep as? ExistingStep.Approvable
        if (!unlocked() || host !== screen || s == null) return ProofResult.STALE
        if (password.isEmpty()) return ProofResult.WRONG_PASSWORD
        val g = hostGeneration
        // The local unlock of §8.2 step 6: the password must open this device's copy of the open account's key.
        // Nothing is sent for it, and a wrong one leaves the link as it is.
        val proved = try {
            app.working { app.keeper.passwordOpensOpenAccount(password.toCharArray()) }
        } catch (e: KeysGoneException) {
            return ProofResult.STALE // locked meanwhile: never "wrong password"
        }
        if (g != hostGeneration || !unlocked()) return ProofResult.STALE
        if (!proved) return ProofResult.WRONG_PASSWORD
        return approveNow(s, g)
    }

    /** The person was proved on this device ([g] the link it was proved for): the link engine approves [s]. */
    private suspend fun approveNow(s: ExistingStep.Approvable, g: Int): ProofResult {
        // A lock during the approval approves nothing: it answers as overtaken, never as a crash.
        val next = try {
            app.working { app.deviceLinks.approve(s) }
        } catch (e: KeysGoneException) {
            return ProofResult.STALE
        }
        if (g != hostGeneration || !unlocked()) return ProofResult.STALE
        showStep(next)
        app.publish()
        if (next is ExistingStep.Approved) refreshAfterLink()
        return when {
            next is ExistingStep.Approved -> ProofResult.DONE
            next is ExistingStep.Stopped && next.reason == DeviceLinkStop.UNREACHABLE -> ProofResult.UNREACHABLE
            // The link's time ran out before the approval reached the server (a prompt answered late): said as that.
            next is ExistingStep.Stopped && next.reason == DeviceLinkStop.EXPIRED -> ProofResult.LINK_EXPIRED
            next is ExistingStep.Stopped && next.reason == DeviceLinkStop.TOO_MANY -> ProofResult.RATE_LIMITED
            else -> ProofResult.FAILED
        }
    }

    /**
     * §8.2 step 6, with the device's own lock (rule of 2026-11-17): the strong fingerprint or face check quick unlock
     * uses, through the session code's one call that opens the sealed quick-unlock key behind the system's prompt and
     * compares it with the open account's key; never the device's PIN or passcode. Only [PresenceOutcome.CONFIRMED]
     * approves. A cancelled prompt leaves the link as it is; where quick unlock cannot answer (not on, switched off by
     * this check, a lockout, the periodic password due) the master password is asked; a lock overtaking the prompt
     * approves nothing. Nothing is sent before the approval itself.
     */
    override suspend fun approveWithBiometrics(screen: DeviceLinkHost.Approvable, reason: String?): ProofResult {
        val s = hostStep as? ExistingStep.Approvable
        if (!unlocked() || host !== screen || s == null) return ProofResult.STALE
        val g = hostGeneration
        val outcome = try {
            app.quick?.let { q -> app.working { q.confirmPresence(reason) } } ?: PresenceOutcome.USE_PASSWORD
        } catch (e: KeysGoneException) {
            PresenceOutcome.STALE
        }
        // A record the check found unusable was wiped: Settings' quick unlock follows.
        if (outcome == PresenceOutcome.TURNED_OFF) app.publish()
        if (g != hostGeneration || !unlocked() || host !== screen || hostStep !== s) return ProofResult.STALE
        // A prompt answered late is not judged here: the server gives each step of the link its own time, counted from
        // when that step began, which this device does not know. The approval goes out, and a step that ran out is the
        // server's refusal, said as the link having expired ([approveNow]); nothing is cancelled for it.
        return when (outcome) {
            PresenceOutcome.CONFIRMED -> approveNow(s, g)
            PresenceOutcome.CANCELLED -> ProofResult.CANCELLED
            PresenceOutcome.USE_PASSWORD, PresenceOutcome.TURNED_OFF -> ProofResult.BIOMETRICS_NOT_USED
            PresenceOutcome.STALE -> ProofResult.STALE
        }
    }

    override suspend fun cancelDeviceLink(): PlainResult {
        val s = hostStep
        if (!unlocked() || s == null) return PlainResult.STALE
        hostGeneration++
        hostPoll?.cancel()
        hostPoll = null
        hostStep = null
        hostUrl = null
        app.working { tokenOf(s)?.let { app.deviceLinks.cancel(it) } }
        host = DeviceLinkHost.Ended(DeviceLinkHostEnd.CANCELLED)
        app.publish()
        return PlainResult.DONE
    }

    override fun dismissDeviceLink() {
        val h = host
        if (h !is DeviceLinkHost.Approved && h !is DeviceLinkHost.Ended) return
        hostGeneration++
        host = null
        app.publish()
    }
}
