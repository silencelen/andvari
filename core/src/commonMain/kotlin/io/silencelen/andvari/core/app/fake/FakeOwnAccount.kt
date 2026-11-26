package io.silencelen.andvari.core.app.fake

import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AccountSettingsApi
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.DeletionResult
import io.silencelen.andvari.core.app.DeletionScreen
import io.silencelen.andvari.core.app.DeviceLinkHost
import io.silencelen.andvari.core.app.DeviceLinkHostEnd
import io.silencelen.andvari.core.app.DeviceRow
import io.silencelen.andvari.core.app.DevicesApi
import io.silencelen.andvari.core.app.DigitsResult
import io.silencelen.andvari.core.app.InstanceApi
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.InstanceCardState
import io.silencelen.andvari.core.app.InstanceSnapshot
import io.silencelen.andvari.core.app.OpenedInvite
import io.silencelen.andvari.core.app.KitReason
import io.silencelen.andvari.core.app.OperatorHelpStage
import io.silencelen.andvari.core.app.OperatorRecoveryWarning
import io.silencelen.andvari.core.app.PasswordChangeResult
import io.silencelen.andvari.core.app.MoveResult
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ProofResult
import io.silencelen.andvari.core.app.RecoveryApi
import io.silencelen.andvari.core.app.RecoveryChangeResult
import io.silencelen.andvari.core.app.RecoveryRequestRow
import io.silencelen.andvari.core.app.RecoveryScreen
import io.silencelen.andvari.core.app.RoleInVault
import io.silencelen.andvari.core.app.ServerKind
import io.silencelen.andvari.core.app.VaultLogState
import io.silencelen.andvari.core.app.WhoCanRecover
import io.silencelen.andvari.core.app.KitAfterMovePrompt
import io.silencelen.andvari.core.app.QuickEnrolResult
import io.silencelen.andvari.core.app.QuickUnlockSetting
import io.silencelen.andvari.core.app.QuickUnlockState
import io.silencelen.andvari.core.app.TwoStepEnrolment
import io.silencelen.andvari.core.app.TwoStepKey
import io.silencelen.andvari.core.app.TwoStepResult
import io.silencelen.andvari.core.app.TwoStepScreen
import io.silencelen.andvari.core.client.session.QuickUnlockRules

/** The signed-in account's own settings in the fake: its server's card, its devices, its recovery, and its end. */
internal class FakeOwnAccount(private val app: FakeAppApi) : InstanceApi, DevicesApi, RecoveryApi, AccountSettingsApi {
    // ---- the instance card ----

    /**
     * The instances on show: the snapshot's own (which is also the one on [EntryScreen.ServerChanged] while that
     * screen is up), and the one an opened invite named. An intent of the instance card acts only on one of these,
     * so on the server its screen named.
     */
    private fun onShow(): List<InstanceSnapshot> =
        listOfNotNull(app.snapshot.instance, (app.snapshot.account?.opened as? OpenedInvite.ServerChanged)?.instance)

    /** The server whose card on show is the very object [card]. */
    private fun serverOf(card: InstanceCardState): FakeServer? =
        onShow().firstOrNull { it.card === card }?.let { app.servers[it.label.origin] }

    /** Whatever showed [server]'s card goes back to where its flow began, once the card is in order. The caller publishes. */
    private fun settled(server: FakeServer) {
        app.entryFlow.serverSettled(server)
        app.people.openedServerSettled(server)
    }

    override suspend fun followMove(card: InstanceCardState.Moved): MoveResult {
        if (serverOf(card) == null) return MoveResult.STALE
        app.pause()
        app.injected<MoveResult>()?.let { return it }
        val server = serverOf(card) ?: return MoveResult.STALE
        val to = server.movedUnderPinTo ?: return MoveResult.STALE
        app.reach(server)?.let { return troubled(it) }
        // A move never replaces a pin this device already holds for the new origin (§4.4 `pin_conflict`).
        if (app.pinnedOrBlocked(to)) {
            app.publish()
            return MoveResult.ALREADY_PINNED_THERE
        }
        // The move is signed by the pinned operator key, so the namespace follows with no Trust Gate. A session on
        // that server goes with it: it is the same server at its new address.
        val from = server.origin
        val pins = app.pins.remove(from)
        app.servers.remove(from)
        server.origin = to
        server.movedUnderPinTo = null
        app.servers[to] = server
        if (pins != null) app.pins[to] = pins.map { it.copy(origin = to) }.toMutableList()
        if (app.signedCard0.remove(from)) app.signedCard0 += to
        if (app.kindPutOff.remove(from)) app.kindPutOff += to
        app.newKitPutOff -= from
        app.newKitDue -= from
        // A quick-unlock key sealed for the old address goes: the first unlock at the new one takes the password.
        if (app.sessionServer === server) app.script.quickUnlock = false
        if (app.script.namespaceMoveFails) {
            // The move stands, but the data on this device did not reach the new address: nothing opens there until the
            // move is finished, and an open vault locks.
            app.moving[to] = from
            settled(server)
            if (app.phase == AppPhase.UNLOCKED && app.sessionServer === server) app.lock()
            app.publish()
            return MoveResult.NOT_FINISHED
        }
        // R36: a kit made before the move names the old address; the app asks for a new one there.
        app.newKitDue += to
        settled(server)
        app.publish()
        return MoveResult.DONE
    }

    override suspend fun finishMove(move: io.silencelen.andvari.core.app.UnfinishedMove): MoveResult {
        val origin = onShow().firstOrNull { it.unfinishedMove === move }?.label?.origin ?: return MoveResult.STALE
        app.pause()
        app.injected<MoveResult>()?.let { return it }
        if (app.moving[origin] != move.fromOrigin) return MoveResult.STALE
        if (app.script.namespaceMoveFails) return MoveResult.NOT_FINISHED
        app.moving.remove(origin)
        app.newKitDue += origin
        app.publish()
        return MoveResult.DONE
    }

    override suspend fun forgetServerAtNewAddress(card: InstanceCardState.Moved): PlainResult {
        if (serverOf(card) == null || !card.alreadyPinnedThere) return PlainResult.STALE
        app.pause()
        app.injected<PlainResult>()?.let { return it }
        if (serverOf(card) == null) return PlainResult.STALE
        // The server this device knows at the new address goes from this device: its pin, with any block, and its data.
        val there = app.servers[card.toOrigin]
        if (there != null) {
            app.dropNamespace(there)
        } else {
            app.pins.remove(card.toOrigin)
            app.forked -= card.toOrigin
            app.damaged -= card.toOrigin
        }
        app.publish()
        return PlainResult.DONE
    }

    override suspend fun acceptKindChange(card: InstanceCardState.KindChanged): PlainResult {
        if (serverOf(card) == null) return PlainResult.STALE
        app.pause()
        app.injected<PlainResult>()?.let { return it }
        val server = serverOf(card) ?: return PlainResult.STALE
        if (!server.kindChangedUnderPin) return PlainResult.STALE
        app.reach(server)?.let { return troubled(it) }
        // Until here the app kept using the old kind (T2-Rec). A card that also moved shows its move next.
        server.kind = if (server.kind == ServerKind.PUBLIC_SERVER) ServerKind.PRIVATE_SERVER else ServerKind.PUBLIC_SERVER
        server.kindChangedUnderPin = false
        app.kindPutOff -= server.origin
        settled(server)
        app.publish()
        return PlainResult.DONE
    }

    override fun kindChangeNotNow(card: InstanceCardState.KindChanged) {
        val server = serverOf(card) ?: return
        // Nothing is sent or stored: the old kind stays in force, and the gate stays shut until the next unlock.
        app.kindPutOff += server.origin
        app.publish()
    }

    override suspend fun forgetServer(instance: InstanceSnapshot): PlainResult {
        if (onShow().none { it === instance }) return PlainResult.STALE
        app.pause()
        app.injected<PlainResult>()?.let { return it }
        if (onShow().none { it === instance }) return PlainResult.STALE
        val server = app.servers[instance.label.origin] ?: return PlainResult.STALE
        // The namespace's pin, with its fork or damage mark, and its data go from this device; the server is told nothing.
        app.dropNamespace(server)
        when {
            // The server of this device's session: the session goes with its namespace.
            app.sessionServer === server -> app.endSession(null)
            // Signed out: the journey that led to it is over.
            app.phase == AppPhase.ENTRY -> {
                app.entryFlow.reset(null)
                app.publish()
            }
            // Another server, named by an opened invite: this app stays signed in where it is.
            else -> {
                app.people.openedServerSettled(server)
                app.publish()
            }
        }
        return PlainResult.DONE
    }

    // ---- devices ----

    override suspend fun openDevices(): PlainResult = app.act { s ->
        s.devicesOpen = true
        app.publish()
        PlainResult.DONE
    }

    override fun closeDevices() {
        app.session?.devicesOpen = false
        app.publish()
    }

    override suspend fun revokeDevice(device: DeviceRow, password: String): ProofResult = app.act { s ->
        if (password != s.account.password) return ProofResult.WRONG_PASSWORD
        app.script.proofRefusal(ProofResult.KEYS_NOT_KNOWN_HERE, ProofResult.PROOF_REFUSED)?.let { return it }
        val found = s.account.devices.firstOrNull { it.deviceId == device.deviceId }
        if (found == null || found.deviceId == app.deviceId) return ProofResult.NOT_POSSIBLE
        // As the server: the device stays on the list, not live, and a second revoke is done again.
        found.live = false
        // A revoked device is no longer one the account knows (FC-8).
        s.account.knownDevices -= found.deviceId
        app.publish()
        ProofResult.DONE
    }

    override suspend fun setRequireLink(enabled: Boolean, password: String): ProofResult = app.act { s ->
        if (password != s.account.password) return ProofResult.WRONG_PASSWORD
        app.script.proofRefusal(ProofResult.KEYS_NOT_KNOWN_HERE, ProofResult.PROOF_REFUSED)?.let { return it }
        s.account.requireLink = enabled
        // The server serves no read of it: the screen knows only what this device set (as on the engine).
        s.requireLinkSetHere = enabled
        app.publish()
        ProofResult.DONE
    }

    override suspend fun startDeviceLink(): PlainResult = app.act { s ->
        if (app.script.linkTooMany) {
            // As the engine: refused as one of too many requests, said as that with the wait; no link is made or shown.
            app.script.linkTooMany = false
            app.noteRateLimit(io.silencelen.andvari.core.app.Trouble.RATE_LIMITED)
            s.hostLink = null
            app.publish()
            return PlainResult.RATE_LIMITED
        }
        // An account has one live device link: making one cancels every earlier one that was not picked up (S3-C3).
        val n = app.serial++
        val payload = "${FakeText.JOIN_BASE}/d#v2.${FakeText.originToken(s.server.origin)}.d$n"
        s.hostLink = FakeHostLink(payload, app.nowMs + 5 * FakeScript.MINUTE, FakeText.digits6("device-link:$n"))
        app.publish()
        PlainResult.DONE
    }

    override fun deviceLinkToShow(screen: DeviceLinkHost.Shown): String? {
        val host = app.session?.hostLink ?: return null
        return if (app.snapshot.account?.deviceLink === screen && host.step == FakeHostStep.SHOWN) host.payload else null
    }

    override fun deviceLinkTimeLeftMs(): Long {
        val host = app.session?.hostLink ?: return 0L
        return if (host.step == FakeHostStep.ENDED) 0L else maxOf(0L, host.expiresAtMs - app.nowMs)
    }

    override suspend fun submitDeviceDigits(screen: DeviceLinkHost.TypeDigits, digits: String): DigitsResult = app.act { s ->
        val host = s.hostLink
        if (host == null || app.snapshot.account?.deviceLink !== screen || host.step != FakeHostStep.TYPE_DIGITS) return DigitsResult.STALE
        if (endedAsTooMany(host)) return DigitsResult.RATE_LIMITED
        if (digits != host.code) {
            // A mismatch cancels the link (§8.2 step 5).
            host.end(DeviceLinkHostEnd.CODE_MISMATCH)
            app.publish()
            return DigitsResult.MISMATCH
        }
        host.step = FakeHostStep.APPROVABLE
        app.publish()
        DigitsResult.DONE
    }

    override suspend fun approveWithPassword(screen: DeviceLinkHost.Approvable, password: String): ProofResult = app.act { s ->
        val host = approvable(s, screen) ?: return ProofResult.STALE
        if (password != s.account.password) return ProofResult.WRONG_PASSWORD
        app.script.proofRefusal(ProofResult.KEYS_NOT_KNOWN_HERE, ProofResult.PROOF_REFUSED)?.let { return it }
        approve(host)
    }

    override suspend fun approveWithBiometrics(screen: DeviceLinkHost.Approvable, reason: String?): ProofResult = app.act { s ->
        val host = approvable(s, screen) ?: return ProofResult.STALE
        val script = app.script
        // As the engine: only a confirmed check approves; the password is asked wherever quick unlock cannot answer.
        if (!app.quickUsable(s.server, s.account)) return ProofResult.BIOMETRICS_NOT_USED
        when {
            script.lockDuringPresence -> {
                script.lockDuringPresence = false
                app.lock()
                return ProofResult.STALE
            }
            script.biometricsChanged -> {
                script.biometricsChanged = false
                script.quickUnlock = false
                app.publish()
                return ProofResult.BIOMETRICS_NOT_USED
            }
            script.biometricsCancelled -> {
                script.biometricsCancelled = false
                return ProofResult.CANCELLED
            }
            script.biometricsRefused -> {
                script.biometricsRefused = false
                return ProofResult.BIOMETRICS_NOT_USED
            }
        }
        approve(host)
    }

    private fun approvable(s: FakeSession, screen: DeviceLinkHost.Approvable): FakeHostLink? =
        s.hostLink?.takeIf { app.snapshot.account?.deviceLink === screen && it.step == FakeHostStep.APPROVABLE }

    /**
     * As the engine where the server refuses a step of the link as one of too many requests ([FakeScript.linkTooMany]): the
     * link ends with its own line (never "a check failed"), and the wait is kept.
     */
    private fun endedAsTooMany(host: FakeHostLink): Boolean {
        if (!app.script.linkTooMany) return false
        app.script.linkTooMany = false
        app.noteRateLimit(io.silencelen.andvari.core.app.Trouble.RATE_LIMITED)
        host.end(DeviceLinkHostEnd.DID_NOT_CHECK_OUT, io.silencelen.andvari.core.app.CopyKey.DEVICE_LINK_HOST_TOO_MANY, app.namedWait())
        app.publish()
        return true
    }

    private fun approve(host: FakeHostLink): ProofResult {
        if (endedAsTooMany(host)) return ProofResult.RATE_LIMITED
        // No device and no session exists yet: the new device still has to prove the master password.
        host.step = FakeHostStep.APPROVED
        host.expiresAtMs = app.nowMs + 5 * FakeScript.MINUTE
        app.publish()
        return ProofResult.DONE
    }

    override suspend fun cancelDeviceLink(): PlainResult = app.act { s ->
        val host = s.hostLink
        if (host == null || host.step == FakeHostStep.ENDED || host.pickedUp) return PlainResult.STALE
        host.end(DeviceLinkHostEnd.CANCELLED)
        app.publish()
        PlainResult.DONE
    }

    override fun dismissDeviceLink() {
        val s = app.session ?: return
        // An approved link is done on this side; an ended one is over. Anything before that is cancelled, not dismissed.
        val step = s.hostLink?.step
        if (step != FakeHostStep.ENDED && step != FakeHostStep.APPROVED) return
        s.hostLink = null
        app.publish()
    }

    /** The other device's part in a link this device shows. */
    fun host(change: (FakeHostLink) -> Unit) {
        val host = app.session?.hostLink ?: return
        if (host.step == FakeHostStep.ENDED) return
        change(host)
        app.publish()
    }

    // ---- recovery ----

    override suspend fun openRecovery(): PlainResult = app.act { s ->
        s.recoveryOpen = true
        app.publish()
        PlainResult.DONE
    }

    override fun closeRecovery() {
        val s = app.session ?: return
        s.recoveryOpen = false
        s.reviewing = false
        app.publish()
    }

    override fun reviewOperatorRecovery(screen: RecoveryScreen) {
        val s = app.session ?: return
        if (app.snapshot.account?.recovery !== screen || screen.question == null) return
        s.reviewing = true
        app.publish()
    }

    override suspend fun turnOnOperatorRecovery(warning: OperatorRecoveryWarning, understood: Boolean, password: String): RecoveryChangeResult = app.act { s ->
        if (!s.reviewing || app.snapshot.account?.recovery?.warning !== warning) return RecoveryChangeResult.STALE
        // The checkbox is part of the consent: without it nothing is sent.
        if (!understood) return RecoveryChangeResult.NOT_TICKED
        if (password != s.account.password) return RecoveryChangeResult.WRONG_PASSWORD
        app.script.proofRefusal(RecoveryChangeResult.KEYS_NOT_KNOWN_HERE, RecoveryChangeResult.PROOF_REFUSED)?.let { return it }
        if (!s.server.offersOperatorRecovery || s.account.isOperator) return RecoveryChangeResult.OPERATOR_RECOVERY_UNAVAILABLE
        choose(s, WhoCanRecover.ME_OR_OPERATOR)
        s.reviewing = false
        app.publish()
        RecoveryChangeResult.DONE
    }

    override fun keepRecoveryPrivate(warning: OperatorRecoveryWarning) {
        val s = app.session ?: return
        if (app.snapshot.account?.recovery?.warning !== warning) return
        s.reviewing = false
        app.publish()
    }

    override suspend fun turnOffOperatorRecovery(screen: RecoveryScreen, password: String): RecoveryChangeResult = app.act { s ->
        if (app.snapshot.account?.recovery !== screen) return RecoveryChangeResult.STALE
        if (password != s.account.password) return RecoveryChangeResult.WRONG_PASSWORD
        app.script.proofRefusal(RecoveryChangeResult.KEYS_NOT_KNOWN_HERE, RecoveryChangeResult.PROOF_REFUSED)?.let { return it }
        choose(s, WhoCanRecover.ONLY_ME)
        app.publish()
        RecoveryChangeResult.DONE
    }

    /** The person's own choice, made on this device: the account's record and this device's mirror of it (§4.5). */
    private fun choose(s: FakeSession, who: WhoCanRecover) {
        s.account.whoCanRecover = who
        s.account.recoveryKeyChangedUnsigned = false
        app.ownMirrors += s.account.userId
    }

    override suspend fun makeKit(password: String): RecoveryChangeResult = app.act { s ->
        if (password != s.account.password) return RecoveryChangeResult.WRONG_PASSWORD
        app.script.proofRefusal(RecoveryChangeResult.KEYS_NOT_KNOWN_HERE, RecoveryChangeResult.PROOF_REFUSED)?.let { return it }
        // A kit made now names the server's address as it is: one asked for after a move is no longer due.
        app.newKitDue -= s.server.origin
        app.kitFlow.make(s.account, KitReason.MADE_IN_SETTINGS, inEntry = false) {}
        RecoveryChangeResult.DONE
    }

    override fun kitAfterMoveLater(prompt: KitAfterMovePrompt) {
        if (app.phase != AppPhase.UNLOCKED || app.snapshot.account?.kitAfterMove !== prompt) return
        app.newKitPutOff += prompt.instance.origin
        app.publish()
    }

    // ---- quick unlock ----

    override suspend fun turnOnQuickUnlock(setting: QuickUnlockSetting): QuickEnrolResult {
        if (app.phase != AppPhase.UNLOCKED || app.snapshot.account?.quickUnlock !== setting) return QuickEnrolResult.STALE
        app.pause()
        app.injected<QuickEnrolResult>()?.let { return it }
        if (app.phase != AppPhase.UNLOCKED || app.snapshot.account?.quickUnlock !== setting) return QuickEnrolResult.STALE
        if (setting.state != QuickUnlockState.OFF) return QuickEnrolResult.NOT_AVAILABLE
        if (app.script.biometricsCancelled) {
            app.script.biometricsCancelled = false
            return QuickEnrolResult.CANCELLED
        }
        // The account's key is sealed under the device's key; nothing is sent, and the 30-day clock is not renewed.
        app.script.quickUnlock = true
        app.publish()
        return QuickEnrolResult.DONE
    }

    override fun turnOffQuickUnlock(setting: QuickUnlockSetting) {
        if (app.phase != AppPhase.UNLOCKED || app.snapshot.account?.quickUnlock !== setting) return
        app.script.quickUnlock = false
        app.publish()
    }

    override fun quickUnlockNotNow(setting: QuickUnlockSetting) {
        if (app.phase != AppPhase.UNLOCKED || app.snapshot.account?.quickUnlock !== setting) return
        app.quickOffer = QuickUnlockRules.ReofferInputs(dismissed = true, unlocks = 0, reoffers = app.quickOffer.reoffers)
        app.publish()
    }

    // ---- two-step sign-in ----

    override suspend fun openTwoStep(): PlainResult = app.act { s ->
        s.twoStepOpen = true
        s.twoStepPending = null
        app.publish()
        PlainResult.DONE
    }

    override fun closeTwoStep() {
        val s = app.session ?: return
        if (!s.twoStepOpen) return
        s.twoStepOpen = false
        s.twoStepPending = null
        app.publish()
    }

    override suspend fun startTwoStep(screen: TwoStepScreen, password: String): TwoStepResult = app.act { s ->
        if (app.snapshot.account?.twoStep !== screen) return TwoStepResult.STALE
        if (s.account.twoStepCode != null) return TwoStepResult.NOT_PENDING
        // The password goes, as a re-authentication, to the session's own server only.
        if (password != s.account.password) return TwoStepResult.WRONG_PASSWORD
        app.script.proofRefusal(TwoStepResult.KEYS_NOT_KNOWN_HERE, TwoStepResult.PROOF_REFUSED)?.let { return it }
        s.twoStepPending = "JBSWY3DPEHPK3PXP" + app.serial++
        app.publish()
        TwoStepResult.DONE
    }

    override fun twoStepKey(enrolment: TwoStepEnrolment): TwoStepKey? {
        val s = app.session ?: return null
        if (app.phase != AppPhase.UNLOCKED || app.snapshot.account?.twoStep?.enrolment !== enrolment) return null
        val secret = s.twoStepPending ?: return null
        return TwoStepKey(secret, "otpauth://totp/andvari:${s.account.email}?secret=$secret&issuer=andvari")
    }

    override suspend fun confirmTwoStep(enrolment: TwoStepEnrolment, code: String): TwoStepResult = app.act { s ->
        if (app.snapshot.account?.twoStep?.enrolment !== enrolment) return TwoStepResult.STALE
        if (s.twoStepPending == null) return TwoStepResult.NOT_PENDING
        if (code != app.script.authenticatorCode) return TwoStepResult.WRONG_CODE
        s.account.twoStepCode = app.script.authenticatorCode
        s.twoStepPending = null
        app.publish()
        TwoStepResult.DONE
    }

    override suspend fun turnOffTwoStep(screen: TwoStepScreen, code: String): TwoStepResult = app.act { s ->
        if (app.snapshot.account?.twoStep !== screen) return TwoStepResult.STALE
        if (s.account.twoStepCode == null) {
            app.publish()
            return TwoStepResult.NOT_PENDING
        }
        // As the engine: a code alone is no longer enough (decided on 2026-11-16), and nothing is sent.
        TwoStepResult.PASSWORD_NEEDED
    }

    /**
     * As the server answers since 2026-11-16, in its order: the password first ([FakeScript.twoStepTriesLocked] is the
     * back-off of either kind), then the code.
     */
    private fun twoStepProof(s: FakeSession, code: String, password: String): TwoStepResult? {
        if (app.script.twoStepTriesLocked) return TwoStepResult.TOO_MANY_TRIES
        if (password != s.account.password) return TwoStepResult.WRONG_PASSWORD
        app.script.proofRefusal(TwoStepResult.KEYS_NOT_KNOWN_HERE, TwoStepResult.PROOF_REFUSED)?.let { return it }
        if (code != s.account.twoStepCode) return TwoStepResult.WRONG_CODE
        return null
    }

    override suspend fun turnOffTwoStepWithPassword(screen: TwoStepScreen, code: String, password: String): TwoStepResult = app.act { s ->
        if (app.snapshot.account?.twoStep !== screen) return TwoStepResult.STALE
        if (s.account.twoStepCode == null) {
            app.publish()
            return TwoStepResult.NOT_PENDING
        }
        twoStepProof(s, code, password)?.let { return it }
        s.account.twoStepCode = null
        app.publish()
        TwoStepResult.DONE
    }

    override suspend fun replaceTwoStepKey(screen: TwoStepScreen, code: String, password: String): TwoStepResult = app.act { s ->
        if (app.snapshot.account?.twoStep !== screen) return TwoStepResult.STALE
        if (s.account.twoStepCode == null) {
            app.publish()
            return TwoStepResult.NOT_PENDING
        }
        twoStepProof(s, code, password)?.let { return it }
        // The new key waits for its first code; the old one stays in force until then.
        s.twoStepPending = "JBSWY3DPEHPK3PXQ" + app.serial++
        app.publish()
        TwoStepResult.DONE
    }

    override suspend fun cancelRecoveryRequest(request: RecoveryRequestRow): PlainResult = app.act { s ->
        val found = s.account.helpRequests.firstOrNull { it.requestId == request.requestId } ?: return PlainResult.STALE
        // The veto is a statement this account's key signs; the request dies.
        found.stage = OperatorHelpStage.VETOED
        s.account.helpRequests -= found
        app.publish()
        PlainResult.DONE
    }

    override fun recoveryRequestWasMe(prompt: AccountPrompt.RecoveryRequest) {
        val s = app.session ?: return
        if (app.currentPrompts().none { it === prompt }) return
        // As the engine: the alert goes for these requests on this device; Settings still lists them.
        s.account.helpRequestsMine += prompt.requests.map { it.requestId }
        if (prompt.unreadable) s.account.unreadableHelpDismissed = true
        app.publish()
    }

    override suspend fun answerRecoveryKeyChanged(prompt: AccountPrompt.RecoveryKeyChanged, keep: Boolean, password: String): RecoveryChangeResult = app.act { s ->
        if (app.currentPrompts().none { it === prompt }) return RecoveryChangeResult.STALE
        if (password != s.account.password) return RecoveryChangeResult.WRONG_PASSWORD
        app.script.proofRefusal(RecoveryChangeResult.KEYS_NOT_KNOWN_HERE, RecoveryChangeResult.PROOF_REFUSED)?.let { return it }
        choose(s, if (keep) WhoCanRecover.ME_OR_OPERATOR else WhoCanRecover.ONLY_ME)
        app.publish()
        RecoveryChangeResult.DONE
    }

    override fun recoveryKeyChangedLater(prompt: AccountPrompt.RecoveryKeyChanged) {
        val s = app.session ?: return
        if (app.currentPrompts().none { it === prompt }) return
        // Nothing changes and nothing is sealed; the prompt returns at the next unlock.
        s.keyChangedLater = true
        app.publish()
    }

    override suspend fun answerKeepOperatorRecovery(prompt: AccountPrompt.KeepOperatorRecovery, keep: Boolean, password: String): RecoveryChangeResult = app.act { s ->
        if (app.currentPrompts().none { it === prompt }) return RecoveryChangeResult.STALE
        if (password != s.account.password) return RecoveryChangeResult.WRONG_PASSWORD
        app.script.proofRefusal(RecoveryChangeResult.KEYS_NOT_KNOWN_HERE, RecoveryChangeResult.PROOF_REFUSED)?.let { return it }
        choose(s, if (keep) WhoCanRecover.ME_OR_OPERATOR else WhoCanRecover.ONLY_ME)
        app.publish()
        RecoveryChangeResult.DONE
    }

    override fun keepOperatorRecoveryNotNow(prompt: AccountPrompt.KeepOperatorRecovery) {
        val s = app.session ?: return
        if (app.currentPrompts().none { it === prompt }) return
        s.keepOperatorNotNow = true
        app.publish()
    }

    // ---- the master password, and deleting the account ----

    override suspend fun changeMasterPassword(current: String, replacement: String): PasswordChangeResult = app.act { s ->
        if (current != s.account.password) return PasswordChangeResult.WRONG_PASSWORD
        app.script.proofRefusal(PasswordChangeResult.KEYS_NOT_KNOWN_HERE, PasswordChangeResult.PROOF_REFUSED)?.let { return it }
        if (!FakeText.strongEnough(replacement)) return PasswordChangeResult.WEAK_PASSWORD
        val previous = app.previousPasswordHere ?: s.account.password
        s.account.password = replacement
        // Every other session of the account ends; the kit and any operator recovery stay valid.
        s.account.devices.filter { it.deviceId != app.deviceId }.forEach { it.live = false }
        // This device's copy follows the new password, unless the script says it cannot: then the previous one opens it here.
        val followed = !app.script.deviceCannotFollowPassword
        app.script.deviceCannotFollowPassword = false
        app.previousPasswordHere = if (followed) null else previous
        app.publish()
        if (followed) PasswordChangeResult.DONE else PasswordChangeResult.CHANGED_PREVIOUS_OPENS_HERE
    }

    override suspend fun openDeletion(): PlainResult {
        val before = app.session
        if (before == null || app.phase != AppPhase.UNLOCKED) return PlainResult.STALE
        // The screen opens at once; its plan arrives with the server's answer.
        before.deletionOpen = true
        before.deletionPlanned = false
        before.deletionRetrying = false
        before.deletionUnknown = false
        app.publish()
        return app.act { s ->
            s.deletionPlanned = true
            app.publish()
            PlainResult.DONE
        }
    }

    override fun closeDeletion() {
        val s = app.session ?: return
        s.deletionOpen = false
        s.deletionPlanned = false
        s.deletionRetrying = false
        app.publish()
    }

    override suspend fun deleteAccount(screen: DeletionScreen, typedEmail: String, password: String, code: String?): DeletionResult = app.act { s ->
        if (app.snapshot.account?.deletion !== screen) return DeletionResult.STALE
        val account = s.account
        // The server's order: the typed address, the code (before the password, so the route is no password oracle), the password.
        if (FakeText.emailNorm(typedEmail) != account.email) return DeletionResult.EMAIL_MISMATCH
        val twoStep = account.twoStepCode
        if (twoStep != null) {
            if (code == null) return DeletionResult.CODE_NEEDED
            if (code != twoStep) return DeletionResult.WRONG_CODE
        }
        if (password != account.password) return DeletionResult.WRONG_PASSWORD
        app.script.proofRefusal(DeletionResult.KEYS_NOT_KNOWN_HERE, DeletionResult.PROOF_REFUSED)?.let { return it }
        if (screen.plan?.canProceed != true) return DeletionResult.BLOCKED
        // One leave per membership, built at the head the server served. A head dated more than a day ahead of
        // this device's clock stops everything before anything is signed (FS-R7).
        if (app.script.deletionFarFutureHead) return DeletionResult.FAR_FUTURE
        if (app.script.clockAhead) return DeletionResult.CLOCK_AHEAD
        var tries = 0
        while (app.script.deletionStaleRounds > 0) {
            // `409 account_delete_log_stale`: a vault's history moved; fetch the heads again and retry.
            app.script.deletionStaleRounds--
            s.deletionRetrying = true
            app.publish()
            if (++tries >= 3) {
                s.deletionRetrying = false
                app.publish()
                return DeletionResult.STILL_CHANGING
            }
        }
        s.deletionRetrying = false
        if (app.script.deletionAnswerLost) {
            app.script.deletionAnswerLost = false
            if (app.script.deletionHappenedAnyway) erase(account)
            s.deletionUnknown = true
            app.script.deletionOutcomeUnknown = true
            app.publish()
            return DeletionResult.OUTCOME_UNKNOWN
        }
        erase(account)
        // As the engine: the server is forgotten with the account only where this device keeps nothing of another account there.
        val forgetServer = !app.script.anotherAccountKnownAtServer
        gone(account, io.silencelen.andvari.core.app.AccountDeletedNotice(account.email, app.label(s.server), serverForgotten = forgetServer), forgetServer)
        DeletionResult.DONE
    }

    /** The server's side of a deletion: the account and the vaults only it holds go. */
    private fun erase(account: FakeAccount) {
        account.server.accounts.remove(account.email)
    }

    /**
     * This device's side: its state for the account is wiped, and, as the engine does, everything "Forget this server"
     * removes goes too (the pin among it), so the app is back at the first screen as on a fresh install for that server;
     * where [forgetServer] is false (another account is known there), only the account's own records go.
     */
    private fun gone(account: FakeAccount, deleted: io.silencelen.andvari.core.app.AccountDeletedNotice? = null, forgetServer: Boolean = true) {
        app.confirmedContacts.remove(account.userId)
        app.notUsedContacts.remove(account.userId)
        app.peoplePutOff -= account.userId
        app.ownMirrors -= account.userId
        account.kitShownUnconfirmed = false
        if (forgetServer) app.dropNamespace(account.server) else app.forgetRemembered(account.server.origin, account.email)
        app.endSession(null, deleted)
    }

    override suspend fun checkDeletion(screen: DeletionScreen): PlainResult = app.act { s ->
        if (app.snapshot.account?.deletion !== screen || !s.deletionUnknown) return PlainResult.STALE
        if (s.server.accounts[s.account.email] !== s.account) {
            // As the engine (the account-deletion design's step 7): the server answers the check with a `401`, which
            // cannot be told from another end of the session, so the account stands as signed out by the server with
            // its copy, and nothing says it was deleted.
            app.endedByServer()
            return PlainResult.STALE
        } else {
            s.deletionUnknown = false
            app.script.deletionOutcomeUnknown = false
            app.publish()
        }
        PlainResult.DONE
    }

    // ---- the clock ----

    /** Time passed: a device link's step, an ownership offer or a deleted vault's grace may have run out. */
    fun tick(s: FakeSession) {
        val host = s.hostLink
        // A link that was approved has done its part here: the pickup's own clock is the new device's.
        if (host != null && host.step != FakeHostStep.ENDED && host.step != FakeHostStep.APPROVED && host.expiresAtMs <= app.nowMs) host.end(DeviceLinkHostEnd.EXPIRED)
        for (vault in s.account.vaults) {
            if (vault.offer?.let { it.expiresAtMs <= app.nowMs } == true) vault.offer = null
            if (vault.purgeAtMs in 1..app.nowMs && vault.log == VaultLogState.VERIFIED) {
                // The grace ended. "Deleted for good" is said because the log verified through the owner's signed delete.
                vault.purgeAtMs = 0L
                vault.log = VaultLogState.PURGED
                vault.heldUntilMs = app.nowMs + 30 * FakeScript.DAY
                if (vault.role != RoleInVault.OWNER) vault.role = null
            }
        }
        for (request in s.account.helpRequests) {
            if (request.stage == OperatorHelpStage.HOLDING && app.nowMs >= request.holdEndsAtMs) request.stage = OperatorHelpStage.AWAITING_OPERATOR
        }
    }
}
