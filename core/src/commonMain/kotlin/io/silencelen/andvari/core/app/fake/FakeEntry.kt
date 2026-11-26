package io.silencelen.andvari.core.app.fake

import io.silencelen.andvari.core.app.AddressMismatchFor
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AskOperatorResult
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.ConnectResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.DeviceLinkScanResult
import io.silencelen.andvari.core.app.EntryApi
import io.silencelen.andvari.core.app.EntryFlow
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.FirstRunNotice
import io.silencelen.andvari.core.app.HowDeviceJoined
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.InviteResult
import io.silencelen.andvari.core.app.JoinMode
import io.silencelen.andvari.core.app.KitReason
import io.silencelen.andvari.core.app.KitRecoverResult
import io.silencelen.andvari.core.app.KitScanResult
import io.silencelen.andvari.core.app.LinkDeviceEnd
import io.silencelen.andvari.core.app.LinkPasswordResult
import io.silencelen.andvari.core.app.MasterPasswordPrompt
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.OperatorHelpStage
import io.silencelen.andvari.core.app.OperatorRecoveryWarning
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.RecoveryQuestion
import io.silencelen.andvari.core.app.RecoveryRoute
import io.silencelen.andvari.core.app.RegistrationVia
import io.silencelen.andvari.core.app.ReplacePasswordResult
import io.silencelen.andvari.core.app.ServerPurpose
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.ServerSetupStep
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.SignupStatus
import io.silencelen.andvari.core.app.Trouble
import io.silencelen.andvari.core.app.WhoCanRecover
import io.silencelen.andvari.core.client.pin.GateDecision
import io.silencelen.andvari.core.client.pin.GatePin
import io.silencelen.andvari.core.client.pin.GatePurpose
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.client.pin.TrustGateWording
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

/**
 * The fake's [EntryFlow]: one server, and what the steps of a flow there have gathered. A screen made in a flow holds
 * it for good, and the intents of that screen read nothing else: there is no "server the journey is on".
 */
internal class FakeFlow(val server: FakeServer) : EntryFlow() {
    override val origin: String get() = server.origin

    /** The invite this flow was opened with. */
    var invite: FakeInvite? = null

    /** What confirming this flow's Trust Gate goes on with; null when no gate stands. */
    var afterGate: (() -> ServerResult)? = null

    /** The pin this flow made where none existed: it goes again when the flow is abandoned before anything came of it (§4.4). */
    var madePin: GatePin? = null

    // sign-up
    var signUpEmail: String = ""
    var signUpAge: Boolean = false
    var codeGood: Boolean = false
    var codeExpiresAtMs: Long = 0L
    var codeTries: Int = 0
    var ticketExpiresAtMs: Long = 0L
    var working: CancellableContinuation<Unit>? = null

    /** The account whose password verified and whose two-step code is asked for now; the password is not asked again. */
    var codeFor: FakeAccount? = null

    // linking this device
    var link: FakeDeviceLink? = null
    var linkPinMade: Boolean = false
    var linkPasswordOk: Boolean = false

    // recovery
    var kit: FakeKit? = null

    /** The person passed the kit's Trust Gate: the pin is made when the kit is proved, not before (the engine's `verify`). */
    var pinAtConfirm: Boolean = false
    var recovering: FakeAccount? = null
    var request: FakeHelpRequest? = null
}

/** The engine keeper's answers, as the fake plays them. */
private const val ANOTHER_SESSION_KEPT = io.silencelen.andvari.core.client.session.Establishing.ANOTHER_SESSION_KEPT
private const val SELF_IDENTITY_MISMATCH = io.silencelen.andvari.core.client.onboard.AccountOpen.SELF_IDENTITY_MISMATCH
private const val OPERATOR_ACCOUNT_HELD = io.silencelen.andvari.core.client.session.Establishing.OPERATOR_ACCOUNT_HELD
private const val KEPT_COPY_DAMAGED = io.silencelen.andvari.core.client.session.Establishing.KEPT_COPY_DAMAGED
private const val NOT_THE_KEPT_ACCOUNT = io.silencelen.andvari.core.client.recovery.WireAssistedRecovery.NOT_THE_KEPT_ACCOUNT

/** The device link's stop for the keeper's own reason [reason]. */
private fun linkStopOf(reason: String): io.silencelen.andvari.core.client.devicelink.DeviceLinkStop = when (reason) {
    OPERATOR_ACCOUNT_HELD -> io.silencelen.andvari.core.client.devicelink.DeviceLinkStop.OPERATOR_ACCOUNT_HELD
    KEPT_COPY_DAMAGED -> io.silencelen.andvari.core.client.devicelink.DeviceLinkStop.KEPT_COPY_DAMAGED
    SELF_IDENTITY_MISMATCH -> io.silencelen.andvari.core.client.devicelink.DeviceLinkStop.IDENTITY_MISMATCH
    else -> io.silencelen.andvari.core.client.devicelink.DeviceLinkStop.ANOTHER_SESSION_KEPT
}

/** The signed-out journey of the fake. Each screen is published only by the step the design puts before it. */
internal class FakeEntry(private val app: FakeAppApi) : EntryApi {
    private val stack = ArrayList<EntryScreen>()

    /** What the first screen says once ([EntryScreen.FirstRun.notice]). */
    private var notice: FirstRunNotice? = null

    private val takesSetupLinks: Boolean get() = app.takesSetupLinks
    private val baked: FakeServer? get() = app.baked

    // ---- plumbing ----

    private fun on(screen: EntryScreen): Boolean = app.phase == AppPhase.ENTRY && app.entryScreen === screen

    private fun flowOf(screen: EntryScreen): FakeFlow? = screen.flow as? FakeFlow

    /** Forward: the screen before stays to go back to. */
    private fun go(next: EntryScreen) {
        app.entryScreen?.let { stack += it }
        app.entryScreen = next
        app.publish()
    }

    /** The same place in the journey, changed. */
    private fun swap(next: EntryScreen) {
        app.entryScreen = next
        app.publish()
    }

    /** Leave the screen on show for the one before it (the first screen when there is none). The caller publishes. */
    private fun pop() {
        val left = app.entryScreen
        app.entryScreen = if (stack.isEmpty()) firstRun() else stack.removeAt(stack.size - 1)
        leftBehind(left)
    }

    /** [left] went off screen: when no screen of its flow is left in the journey, the flow is over. */
    private fun leftBehind(left: EntryScreen?) {
        val f = left?.flow as? FakeFlow ?: return
        if (app.entryScreen?.flow === f || stack.any { it.flow === f }) return
        abandon(f)
    }

    /** A flow nothing came of ends: what it held is dropped, a link it claimed is given up, and a pin it made goes again. */
    private fun abandon(f: FakeFlow) {
        f.afterGate = null
        f.codeFor = null
        f.kit = null
        f.recovering = null
        f.link?.let { l ->
            if (l.step == FakeLinkStep.CLAIMED || l.step == FakeLinkStep.REVEALED || l.step == FakeLinkStep.APPROVED) l.step = FakeLinkStep.CANCELLED
        }
        f.link = null
        dropMadePin(f)
    }

    private fun dropMadePin(f: FakeFlow) {
        val made = f.madePin ?: return
        f.madePin = null
        val list = app.pins[made.origin] ?: return
        list.remove(made)
        if (list.isEmpty()) app.pins.remove(made.origin)
    }

    /** Pin [f]'s server through [root] as a link or a kit does: a pin made where none existed is the flow's own until something comes of it. */
    private fun pinFor(f: FakeFlow, root: PinRoot, account: String?) {
        val had = app.pins.containsKey(f.server.origin)
        app.pin(f.server, root, account)
        if (!had) f.madePin = app.pins[f.server.origin]?.firstOrNull { it.root == root && it.account == account }
    }

    /** A session came of [f]: its pin stays, and the rest of the journey is over. */
    private fun journeyDone(f: FakeFlow) {
        f.madePin = null
        val others = stack.mapNotNull { it.flow as? FakeFlow }.filter { it !== f }.distinct()
        stack.clear()
        others.forEach(::abandon)
    }

    private fun publicStatus(): SignupStatus {
        val b = baked
        return if (b == null || app.script.publicStatusNotFetched) SignupStatus(JoinMode.NOT_KNOWN, full = false, ageConfirmRequired = false, proofOfWork = false) else app.signup(b)
    }

    private fun firstRun(): EntryScreen.FirstRun =
        EntryScreen.FirstRun(publicStatus(), takesSetupLinks, app.helpRequest != null, offersPublicInstance = baked != null, notice = notice,
            accountDeleted = accountDeleted, deletionOutcomeUnknown = deletionUnknown, heldAsOperator = held(), lateRecovery = lateRecovery,
            sessionNotConfirmed = sessionNotConfirmed)

    /** As the engine: what a recovery the person left came to, said on the first screen until dismissed. */
    private var lateRecovery: io.silencelen.andvari.core.app.LateRecoveryNotice? = null

    /** [FakeScript.leftRecoveryAnswered]: the newest replaces an older one; the first screen is republished when on show. */
    internal fun lateOutcome(notice: io.silencelen.andvari.core.app.LateRecoveryNotice) {
        lateRecovery = notice
        if (app.entryScreen is EntryScreen.FirstRun) app.entryScreen = firstRun()
        for (i in stack.indices) if (stack[i] is EntryScreen.FirstRun) stack[i] = firstRun()
        app.publish()
    }

    private var heldShown: io.silencelen.andvari.core.app.HeldOperatorAccount? = null

    /** [FakeScript.heldAsOperator] as the first screen shows it (the same object while it is unchanged). */
    private fun held(): io.silencelen.andvari.core.app.HeldOperatorAccount? {
        val h = app.script.heldAsOperator ?: return null.also { heldShown = null }
        heldShown?.takeIf { it.email == h.email && it.instance.name == h.serverName && it.instance.origin == h.origin && it.unsentChanges == h.unsentChanges }
            ?.let { return it }
        return io.silencelen.andvari.core.app.HeldOperatorAccount(h.email, io.silencelen.andvari.core.app.InstanceLabel(h.serverName, h.origin, io.silencelen.andvari.core.app.ServerKind.PRIVATE_SERVER, false), h.unsentChanges)
            .also { heldShown = it }
    }

    override suspend fun removeHeldOperatorAccount(account: io.silencelen.andvari.core.app.HeldOperatorAccount): io.silencelen.andvari.core.app.PlainResult {
        if (held() !== account) return io.silencelen.andvari.core.app.PlainResult.STALE
        app.script.heldAsOperator = null
        heldShown = null
        if (app.entryScreen is EntryScreen.FirstRun) swap(firstRun())
        return io.silencelen.andvari.core.app.PlainResult.DONE
    }

    /** The account this device just deleted, said once beside [notice] (as the engine). */
    private var accountDeleted: io.silencelen.andvari.core.app.AccountDeletedNotice? = null

    /** A deletion whose outcome is unknown, said beside [notice] until dismissed (as the engine). */
    private var deletionUnknown: io.silencelen.andvari.core.app.DeletionOutcomeUnknownNotice? = null

    /** As the engine: the session this device could not confirm, said once in place of [notice] until dismissed. */
    private var sessionNotConfirmed = false

    /** The first screen's mark of a session not confirmed, while it is not dismissed: a reset after a kit's wipe keeps it. */
    fun notConfirmedShown(): Boolean = sessionNotConfirmed

    /** Back to the first screen, which says [notice], [deleted] and [unknown] when given, with nothing of an abandoned journey left. The caller publishes. */
    fun reset(
        notice: FirstRunNotice?, deleted: io.silencelen.andvari.core.app.AccountDeletedNotice? = null,
        unknown: io.silencelen.andvari.core.app.DeletionOutcomeUnknownNotice? = null,
        notConfirmed: Boolean = false,
    ) {
        val flows = (stack + listOfNotNull(app.entryScreen)).mapNotNull { it.flow as? FakeFlow }.distinct()
        stack.clear()
        this.notice = notice
        this.accountDeleted = deleted
        this.deletionUnknown = unknown
        this.sessionNotConfirmed = notConfirmed
        app.entryScreen = firstRun()
        flows.forEach(::abandon)
    }

    /** The world changed under the screen on show: the first screen and a changed server's card are shown as they are now. */
    fun refresh() {
        when (val shown = app.entryScreen) {
            is EntryScreen.FirstRun -> {
                val now = firstRun()
                val same = shown.signup.mode == now.signup.mode && shown.signup.full == now.signup.full &&
                    shown.signup.proofOfWork == now.signup.proofOfWork && shown.signup.ageConfirmRequired == now.signup.ageConfirmRequired &&
                    shown.operatorHelpWaiting == now.operatorHelpWaiting && shown.offersPublicInstance == now.offersPublicInstance && shown.notice == now.notice
                if (!same) app.entryScreen = now
            }
            is EntryScreen.ServerChanged -> {
                val f = flowOf(shown) ?: return
                val now = app.instanceSnapshot(f.server)
                if (now == null) {
                    // The server was forgotten from under the screen.
                    app.entryScreen = if (stack.isEmpty()) firstRun() else stack.removeAt(stack.size - 1)
                } else if (now !== shown.instance) {
                    app.entryScreen = EntryScreen.ServerChanged(f, now)
                }
            }
            else -> Unit
        }
    }

    /** The checks every `suspend` intent starts with, then [body]. */
    private suspend inline fun <reified R> step(screen: EntryScreen, body: () -> R): R where R : Enum<R>, R : IntentResult {
        if (!on(screen)) return troubled(Trouble.STALE)
        // As the engine: a new try on the screen takes the offer of an earlier refusal away.
        earlier = null
        app.pause()
        app.injected<R>()?.let { return it }
        if (!on(screen)) return troubled(Trouble.STALE)
        return body()
    }

    /** What stands in the way of opening a server at all. */
    private enum class Hurdle { BLOCKED, NO_CARD, OTHER_ADDRESS, NOT_ACCEPTED, CHANGED }

    /** This device's pin for [server] is blocked: a fork seen now is stored with the pin, and both kinds of block are durable (§4.4). */
    private fun blockedNow(server: FakeServer): Boolean {
        if (app.pins.containsKey(server.origin) && server.identityChanged) app.forked += server.origin
        return app.blockOn(server) != null
    }

    /**
     * What stops a flow from opening [server], in the engine's order (§2.4, §4.4), with the screen that says so on
     * show: a blocked pin; no card at all; with no pin, a card made for another address, or a chain the root does not
     * anchor; with a pin, a chain that moved, changed `kind` or ends below it, or a newer card that does not verify.
     * [mismatchFor] null: a card made for another address is answered without a screen.
     */
    private fun hurdle(server: FakeServer, mismatchFor: AddressMismatchFor?, mismatchFlow: FakeFlow?): Hurdle? {
        if (blockedNow(server)) {
            showServer(server)
            return Hurdle.BLOCKED
        }
        if (!server.hasCard) return Hurdle.NO_CARD
        if (!app.pins.containsKey(server.origin)) {
            if (server.servesAnotherServersCard) {
                if (mismatchFor != null) {
                    go(EntryScreen.AddressMismatch(mismatchFlow, server.origin, server.cardNamesOrigin, mismatchFor, publicInstance = server === baked))
                }
                return Hurdle.OTHER_ADDRESS
            }
            // The baked root anchors at card 0: a chain that starts elsewhere is not the public instance's.
            return if (server === baked && server.identityChanged) Hurdle.NOT_ACCEPTED else null
        }
        return when (app.cardOf(server)) {
            FakeCard.MOVED, FakeCard.KIND_CHANGED, FakeCard.UPDATE_MOVED, FakeCard.UPDATE_CHANGED, FakeCard.WITHHELD -> {
                showServer(server)
                Hurdle.CHANGED
            }
            FakeCard.NOT_VERIFIED -> Hurdle.NOT_ACCEPTED
            else -> null
        }
    }

    /** [EntryScreen.ServerChanged] for [server]: its card says what was found, and its intents act on that server. */
    private fun showServer(server: FakeServer) {
        val shown = app.entryScreen
        if (shown is EntryScreen.ServerChanged && flowOf(shown)?.server === server) return
        val snapshot = app.instanceSnapshot(server) ?: return
        go(EntryScreen.ServerChanged(FakeFlow(server), snapshot))
    }

    private fun serverResult(h: Hurdle): ServerResult = when (h) {
        Hurdle.BLOCKED -> ServerResult.IDENTITY_CONFLICT
        Hurdle.NO_CARD -> ServerResult.NOT_SET_UP_YET
        Hurdle.OTHER_ADDRESS -> ServerResult.OTHER_ADDRESS
        Hurdle.NOT_ACCEPTED -> ServerResult.CARD_NOT_ACCEPTED
        Hurdle.CHANGED -> ServerResult.SERVER_CHANGED
    }

    /** The changed server on show was followed or accepted ([io.silencelen.andvari.core.app.InstanceApi]): back to where the flow began, once its card is in order. */
    fun serverSettled(server: FakeServer) {
        val shown = app.entryScreen as? EntryScreen.ServerChanged ?: return
        if (flowOf(shown)?.server !== server || app.cardOf(server) != FakeCard.OK) return
        pop()
    }

    private fun raiseGate(flow: FakeFlow, wording: TrustGateWording, kitChanged: Boolean, typedKit: Boolean, then: () -> ServerResult) {
        flow.afterGate = then
        go(EntryScreen.TrustGate(flow, app.gatePrompt(flow.server, wording, kitChanged, typedKit)))
    }

    private fun question(server: FakeServer, operatorAccount: Boolean): RecoveryQuestion? =
        if (server.offersOperatorRecovery && !operatorAccount) RecoveryQuestion(app.label(server), server.unsignedRecoveryKeyChange) else null

    private fun claimed(screen: EntryScreen?): Boolean =
        screen is EntryScreen.LinkDeviceWaiting || screen is EntryScreen.LinkDeviceCode || screen is EntryScreen.LinkDevicePassword

    // ---- navigation ----

    override fun back(): Boolean {
        if (app.phase != AppPhase.ENTRY) return false
        val shown = app.entryScreen
        if (shown is EntryScreen.Kit || shown is EntryScreen.ServerSetup || stack.isEmpty()) return false
        // A claimed link is left only by startOver(), which gives it up.
        if (claimed(shown)) return false
        if (shown is EntryScreen.TrustGate) flowOf(shown)?.afterGate = null
        // The keys held for a two-step code go when their screen is left.
        if (shown is EntryScreen.SignIn) flowOf(shown)?.codeFor = null
        pop()
        refresh()
        app.publish()
        return true
    }

    override fun startOver() {
        if (app.phase != AppPhase.ENTRY) return
        if (app.entryScreen is EntryScreen.Kit || app.entryScreen is EntryScreen.ServerSetup) return
        reset(null)
        app.publish()
    }

    // ---- the first screen ----

    override fun openInviteEntry(screen: EntryScreen.FirstRun) {
        if (on(screen)) go(EntryScreen.InviteEntry())
    }

    override suspend fun createAccountOnAndvari(screen: EntryScreen.FirstRun): ServerResult = step(screen) {
        val server = baked ?: return ServerResult.FAILED
        app.reach(server)?.let { return troubled(it) }
        // The server answers now: whatever the first screen showed, this is what it says about new accounts.
        app.script.publicStatusNotFetched = false
        hurdle(server, AddressMismatchFor.TYPED_ADDRESS, null)?.let { return serverResult(it) }
        app.pin(server, PinRoot.BAKED, null)
        if (!app.signup(server).takingAccounts) {
            swap(firstRun())
            return ServerResult.NOT_TAKING_ACCOUNTS
        }
        go(signUpEmail(FakeFlow(server), null))
        ServerResult.DONE
    }

    override fun dismissNotice(screen: EntryScreen.FirstRun) {
        if (!on(screen) || (notice == null && accountDeleted == null && deletionUnknown == null && lateRecovery == null && !sessionNotConfirmed)) return
        notice = null
        accountDeleted = null
        deletionUnknown = null
        lateRecovery = null
        sessionNotConfirmed = false
        swap(firstRun())
    }

    override fun openOwnServer(screen: EntryScreen.FirstRun) {
        if (on(screen)) go(EntryScreen.OwnServer(takesSetupLinks))
    }

    override fun openSignIn(screen: EntryScreen.FirstRun) {
        if (on(screen)) go(EntryScreen.SignInChoice())
    }

    override suspend fun resumeOperatorHelp(screen: EntryScreen.FirstRun): ServerResult = step(screen) {
        val request = app.helpRequest ?: return ServerResult.STALE
        app.reach(request.server)?.let { return troubled(it) }
        val flow = FakeFlow(request.server).also { it.request = request }
        tickRequest(request)
        if (request.fulfilled && !request.answerForged && !answerHeld(request)) go(checkAccount(flow, request)) else go(helpScreen(flow, request))
        ServerResult.DONE
    }

    /** §9.3 step 4: the delivered account, for the person to check before any new password. */
    private fun checkAccount(flow: FakeFlow, request: FakeHelpRequest): EntryScreen.CheckAccount {
        val delivered = request.delivers ?: request.server.accounts[request.email]
        return EntryScreen.CheckAccount(flow, app.label(request.server), request.email, delivered?.accountId.orEmpty(), keyChange = keyChange(request, withUnsigned = false))
    }

    /** The request [screen]'s flow holds, while it is still the one this device keeps. */
    private fun requestOf(screen: EntryScreen): Pair<FakeFlow, FakeHelpRequest>? {
        val flow = flowOf(screen) ?: return null
        val request = flow.request?.takeIf { app.helpRequest === it } ?: return null
        return flow to request
    }

    override fun acceptRecoveredAccount(screen: EntryScreen.CheckAccount) {
        if (!on(screen)) return
        val (flow, request) = requestOf(screen) ?: return
        // As the engine, behind the script's switch until the apps take the second step: the
        // first "it is the same" shows the comparison's second step.
        if (app.script.checkAccountConfirmStep && !screen.confirming) {
            go(EntryScreen.CheckAccount(flow, screen.instance, screen.email, screen.accountId, confirming = true, keyChange = screen.keyChange))
            return
        }
        // Whoever the answer delivered is the account the new password is set for: that is what the check is about.
        flow.recovering = request.delivers ?: request.server.accounts[request.email]
        // The screen names the address the person asked with (the answer names it too, inside the account's signature).
        go(EntryScreen.ReplacePassword(flow, request.email, screen.instance, RecoveryRoute.OPERATOR_HELP))
    }

    override fun rejectRecoveredAccount(screen: EntryScreen.CheckAccount) {
        if (!on(screen)) return
        app.helpRequest = null
        reset(FirstRunNotice.RECOVERY_STOPPED)
        app.publish()
    }

    override fun recoveredAccountNotNow(screen: EntryScreen.CheckAccount) {
        if (!on(screen)) return
        // Nothing is dropped: the request waits on this device, and the first screen offers it again.
        reset(null)
        app.publish()
    }

    // ---- invites ----

    override suspend fun submitInvite(screen: EntryScreen.InviteEntry, payload: String, source: PayloadSource): InviteResult =
        step(screen) { openInvite(payload) }

    suspend fun openAppLink(url: String): InviteResult {
        app.pause()
        app.injected<InviteResult>()?.let { return it }
        val shown = app.entryScreen
        // A tapped link arrives on whatever screen is up; it never interrupts a kit or a setup that must finish, or a claimed link.
        if (shown is EntryScreen.Kit || shown is EntryScreen.ServerSetup || claimed(shown)) return InviteResult.STALE
        return openInvite(url)
    }

    /** The journey goes on with an invite that was opened while signed in to another instance (§6.7). */
    fun continueWith(payload: String): InviteResult = openInvite(payload)

    /**
     * §6.8, recipient side, in order. Only an invite is acted on. **Every call starts a flow of its own**, at the
     * invite's server: the screens it shows act there, and the screens that were up before keep acting where they did.
     */
    private fun openInvite(payload: String): InviteResult {
        val (shape, key) = FakeText.shape(payload)
        when (shape) {
            PayloadShape.DEVICE_LINK -> return InviteResult.DEVICE_LINK_NOT_HERE
            PayloadShape.KIT -> return InviteResult.KIT_NOT_AN_INVITE
            PayloadShape.NOTHING -> return InviteResult.NOT_AN_INVITE
            PayloadShape.INVITE -> Unit
        }
        val found = app.invites[key] ?: return InviteResult.NOT_FOUND
        val server = found.server
        app.reach(server)?.let { return troubled(it) }
        when (found.state) {
            FakeInviteState.EXPIRED -> return InviteResult.EXPIRED
            FakeInviteState.USED -> return InviteResult.ALREADY_USED
            FakeInviteState.REVOKED -> return InviteResult.NOT_FOUND
            FakeInviteState.DAMAGED -> return InviteResult.DOES_NOT_CHECK_OUT
            FakeInviteState.OPEN -> if (found.expiresAtMs <= app.nowMs) return InviteResult.EXPIRED
        }
        val flow = FakeFlow(server).also { it.invite = found }
        if (found.kind == FakeInviteKind.SETUP) {
            if (!takesSetupLinks) return InviteResult.SETUP_NEEDS_COMPUTER
            if (blockedNow(server)) {
                showServer(server)
                return InviteResult.IDENTITY_CONFLICT
            }
            // A build never signs card 0 of the instance it bakes, and a server that serves a card is set up already (§4.4).
            if (server.hasCard || server.operatorExists || server === baked) return InviteResult.SETUP_ALREADY_DONE
            // The offer is the host's own word about a server with no card yet; this device will sign card 0 and pin that.
            go(EntryScreen.CreateAccount(flow, RegistrationVia.SETUP_LINK, app.label(server), null, null, false, null, WhoCanRecover.ONLY_ME))
            return InviteResult.DONE
        }
        // A card made for another address shows both addresses (the engine's `RecipientStep.OriginMismatch`).
        when (hurdle(server, AddressMismatchFor.INVITE, flow)) {
            Hurdle.BLOCKED -> return InviteResult.IDENTITY_CONFLICT
            Hurdle.CHANGED -> return InviteResult.SERVER_CHANGED
            Hurdle.OTHER_ADDRESS -> return InviteResult.OTHER_ADDRESS
            Hurdle.NO_CARD, Hurdle.NOT_ACCEPTED -> return InviteResult.DOES_NOT_CHECK_OUT
            null -> Unit
        }
        // At the baked origin the baked root comes first, whatever the link (§4.4): the pin is a password pin.
        val linkRoot = if (server === baked) PinRoot.BAKED else PinRoot.LINK_OFFER
        when (found.kind) {
            FakeInviteKind.CONNECT -> {
                pinFor(flow, linkRoot, null)
                val status = app.signup(server)
                if (status.takingAccounts) go(EntryScreen.JoinInvite(flow, app.label(server), found.from.orEmpty()))
                else go(EntryScreen.NotTakingAccounts(flow, app.label(server), found.from.orEmpty(), status))
            }
            FakeInviteKind.REGISTER -> {
                pinFor(flow, linkRoot, null)
                go(EntryScreen.CreateAccount(flow, RegistrationVia.INVITATION_LINK, app.label(server), null, found.from, server.ageConfirmRequired, question(server, false), WhoCanRecover.ONLY_ME))
            }
            FakeInviteKind.ENROL -> {
                val form = {
                    go(EntryScreen.CreateAccount(flow, RegistrationVia.ENROLMENT_LINK, app.label(server), found.boundEmail, null, server.ageConfirmRequired, question(server, false), WhoCanRecover.ONLY_ME))
                }
                when {
                    server === baked -> {
                        // The build vouches for the public instance: no gate, and the pin's root is `baked`.
                        pinFor(flow, PinRoot.BAKED, null)
                        form()
                    }
                    // Any pin this device holds for the origin is enough to create an account there (§4.4).
                    app.pins.containsKey(server.origin) -> form()
                    // An enrol link is the host's own claim: the typed-address gate, and a pin that is not a password pin.
                    else -> raiseGate(flow, TrustGateWording.ENROL_LINK, false, false) {
                        pinFor(flow, PinRoot.ENROL, null)
                        form()
                        ServerResult.DONE
                    }
                }
            }
            FakeInviteKind.SETUP -> Unit
        }
        return InviteResult.DONE
    }

    override suspend fun joinFromInvite(screen: EntryScreen.JoinInvite): ServerResult = step(screen) {
        val flow = flowOf(screen) ?: return ServerResult.STALE
        val server = flow.server
        app.reach(server)?.let { return troubled(it) }
        val status = app.signup(server)
        if (!status.takingAccounts) {
            swap(EntryScreen.NotTakingAccounts(flow, screen.instance, screen.from, status))
            return ServerResult.NOT_TAKING_ACCOUNTS
        }
        go(signUpEmail(flow, screen.from))
        ServerResult.DONE
    }

    override suspend fun signInFromInvite(screen: EntryScreen.JoinInvite): ServerResult = step(screen) { beginSignIn(flowOf(screen)) }

    override suspend fun signInWhereInvited(screen: EntryScreen.NotTakingAccounts): ServerResult = step(screen) { beginSignIn(flowOf(screen)) }

    /**
     * Whether the screen that follows the server choice may show for [server] without the Trust Gate first: a pin of
     * this device can be a password pin there for [purpose]. A setup pin serves only the operator account it
     * enrolled, and no account is known yet, so [submitSignIn] asks the gate again with the typed address.
     */
    private fun vouchedFor(purpose: GatePurpose, server: FakeServer): Boolean =
        app.gate(purpose, server, null) == GateDecision.PROCEED ||
            (purpose == GatePurpose.SIGN_IN && app.pins[server.origin].orEmpty().any { it.root == PinRoot.SETUP })

    /**
     * The password gate for a sign-in on [flow]'s server (§4.4): the password screen when a pin can serve a sign-in
     * there, the Trust Gate first when the origin's pins are not password pins.
     */
    private fun beginSignIn(flow: FakeFlow?): ServerResult {
        flow ?: return ServerResult.STALE
        val server = flow.server
        app.reach(server)?.let { return troubled(it) }
        hurdle(server, AddressMismatchFor.TYPED_ADDRESS, null)?.let { return serverResult(it) }
        val form = { go(EntryScreen.SignIn(flow, MasterPasswordPrompt(null, app.label(server)), false)) }
        if (vouchedFor(GatePurpose.SIGN_IN, server)) {
            form()
        } else {
            val unvouched = app.pins.containsKey(server.origin)
            raiseGate(flow, if (unvouched) TrustGateWording.LINK_OFFER_SIGN_IN else TrustGateWording.TYPED_ADDRESS, false, false) {
                app.pin(server, PinRoot.TRUST_GATE, null)
                form()
                ServerResult.DONE
            }
        }
        return ServerResult.DONE
    }

    // ---- "Use your own server" ----

    override suspend fun submitServerAddress(screen: EntryScreen.OwnServer, input: String): ServerResult = step(screen) {
        if (FakeText.shape(input).first == PayloadShape.INVITE) {
            // The desktop app takes a server's setup link here; no other link, and no phone, does.
            val found = app.invites[FakeText.shape(input).second]
            if (found != null && found.kind != FakeInviteKind.SETUP) return ServerResult.NOT_AN_ADDRESS
            // A phone says where a setup link belongs, here as on "Scan an invite" (§9.5).
            if (!takesSetupLinks) return if (found != null) ServerResult.SETUP_NEEDS_COMPUTER else ServerResult.NOT_AN_ADDRESS
            return when (openInvite(input)) {
                InviteResult.DONE -> ServerResult.DONE
                InviteResult.SETUP_ALREADY_DONE -> ServerResult.SETUP_ALREADY_DONE
                InviteResult.IDENTITY_CONFLICT -> ServerResult.IDENTITY_CONFLICT
                InviteResult.UNREACHABLE -> ServerResult.UNREACHABLE
                InviteResult.UPDATE_REQUIRED -> ServerResult.UPDATE_REQUIRED
                else -> ServerResult.SETUP_LINK_NOT_USABLE
            }
        }
        typedServer(input, GatePurpose.SIGN_IN) { flow ->
            go(EntryScreen.Server(flow, app.label(flow.server), app.signup(flow.server)))
            ServerResult.DONE
        }
    }

    /** A typed address: the grammar, the card, then the Trust Gate unless this device vouched for it before. Each call starts a flow at that server. */
    private fun typedServer(input: String, purpose: GatePurpose, then: (FakeFlow) -> ServerResult): ServerResult {
        val origin = FakeText.origin(input) ?: return ServerResult.NOT_AN_ADDRESS
        val server = app.servers[origin] ?: return ServerResult.UNREACHABLE
        app.reach(server)?.let { return troubled(it) }
        hurdle(server, AddressMismatchFor.TYPED_ADDRESS, null)?.let { return serverResult(it) }
        val flow = FakeFlow(server)
        if (server === baked) app.pin(server, PinRoot.BAKED, null)
        if (vouchedFor(purpose, server)) return then(flow)
        val unvouched = app.pins.containsKey(origin)
        raiseGate(flow, if (unvouched) TrustGateWording.LINK_OFFER_SIGN_IN else TrustGateWording.TYPED_ADDRESS, false, false) {
            app.pin(server, PinRoot.TRUST_GATE, null)
            then(flow)
        }
        return ServerResult.DONE
    }

    override suspend fun createAccountHere(screen: EntryScreen.Server): ServerResult = step(screen) {
        val flow = flowOf(screen) ?: return ServerResult.STALE
        val server = flow.server
        app.reach(server)?.let { return troubled(it) }
        val status = app.signup(server)
        if (!status.takingAccounts) {
            swap(EntryScreen.Server(flow, screen.instance, status))
            return ServerResult.NOT_TAKING_ACCOUNTS
        }
        go(signUpEmail(flow, null))
        ServerResult.DONE
    }

    override suspend fun signInHere(screen: EntryScreen.Server): ServerResult = step(screen) { beginSignIn(flowOf(screen)) }

    // ---- the Trust Gate ----

    override suspend fun confirmTrustGate(screen: EntryScreen.TrustGate): ServerResult = step(screen) {
        val flow = flowOf(screen) ?: return ServerResult.STALE
        app.reach(flow.server)?.let { return troubled(it) }
        val then = flow.afterGate ?: return ServerResult.STALE
        flow.afterGate = null
        // The gate is not a place to come back to: what follows replaces it.
        app.entryScreen = if (stack.isEmpty()) firstRun() else stack.removeAt(stack.size - 1)
        val result = then()
        app.publish()
        result
    }

    override fun declineTrustGate(screen: EntryScreen.TrustGate) {
        if (!on(screen)) return
        val flow = flowOf(screen)
        flow?.afterGate = null
        flow?.link = null
        pop()
        app.publish()
    }

    // ---- sign-up ----

    private fun signUpEmail(flow: FakeFlow, connectWith: String?): EntryScreen.SignUpEmail =
        EntryScreen.SignUpEmail(flow, app.label(flow.server), flow.server.ageConfirmRequired, connectWith, provingWork = false, workPercent = 0)

    override suspend fun startSignUp(screen: EntryScreen.SignUpEmail, email: String, ageConfirmed: Boolean): SignUpStartResult = step(screen) {
        val flow = flowOf(screen) ?: return SignUpStartResult.STALE
        val server = flow.server
        // A new account is never the one kept here: refused before an address or a code is sent anywhere.
        if (app.storedSession != null) return SignUpStartResult.ANOTHER_ACCOUNT_KEPT
        val norm = FakeText.emailNorm(email) ?: return SignUpStartResult.INVALID_EMAIL
        app.reach(server)?.let { return troubled(it) }
        if (server.mode != JoinMode.ANYONE) return SignUpStartResult.SIGNUP_CLOSED
        if (server.full) return SignUpStartResult.SIGNUP_FULL
        if (norm.substringAfter('@') in server.blockedDomains) return SignUpStartResult.EMAIL_DOMAIN_NOT_ACCEPTED
        if (server.ageConfirmRequired && !ageConfirmed) return SignUpStartResult.AGE_CONFIRMATION_NEEDED
        if (server.powBits > 0 && app.script.holdProofOfWork) {
            app.script.holdProofOfWork = false
            swap(EntryScreen.SignUpEmail(flow, screen.instance, screen.ageConfirmRequired, screen.connectWith, provingWork = true, workPercent = 0))
            try {
                suspendCancellableCoroutine<Unit> { flow.working = it }
            } finally {
                flow.working = null
            }
            val shown = app.entryScreen
            if (shown !is EntryScreen.SignUpEmail || shown.flow !== flow) return SignUpStartResult.STALE
            swap(EntryScreen.SignUpEmail(flow, screen.instance, screen.ageConfirmRequired, screen.connectWith, provingWork = false, workPercent = 0))
        }
        if (server.mailStalled) return SignUpStartResult.MAIL_UNAVAILABLE
        // The answer is the same whether or not the address has an account; only a new address gets a code.
        flow.signUpEmail = norm
        flow.signUpAge = ageConfirmed
        flow.codeGood = !server.accounts.containsKey(norm)
        flow.codeExpiresAtMs = app.nowMs + 15 * FakeScript.MINUTE
        flow.codeTries = 0
        go(EntryScreen.SignUpCode(flow, screen.instance, email.trim(), screen.connectWith))
        SignUpStartResult.DONE
    }

    fun workProgress(percent: Int) {
        val shown = app.entryScreen as? EntryScreen.SignUpEmail ?: return
        val flow = flowOf(shown) ?: return
        if (!shown.provingWork) return
        swap(EntryScreen.SignUpEmail(flow, shown.instance, shown.ageConfirmRequired, shown.connectWith, provingWork = true, workPercent = percent.coerceIn(0, 100)))
    }

    fun finishWork() {
        val flow = (app.entryScreen as? EntryScreen.SignUpEmail)?.let(::flowOf) ?: return
        val w = flow.working
        flow.working = null
        w?.resume(Unit)
    }

    override suspend fun verifySignUpCode(screen: EntryScreen.SignUpCode, code: String): CodeResult = step(screen) {
        val flow = flowOf(screen) ?: return CodeResult.STALE
        val server = flow.server
        app.reach(server)?.let { return troubled(it) }
        val good = flow.codeGood && flow.codeTries < 5 && app.nowMs <= flow.codeExpiresAtMs && code == app.script.emailCode
        if (!good) {
            flow.codeTries++
            return CodeResult.WRONG_CODE
        }
        flow.codeGood = false
        flow.ticketExpiresAtMs = app.nowMs + 30 * FakeScript.MINUTE
        val via = if (flow.invite?.kind == FakeInviteKind.CONNECT) RegistrationVia.CONNECT_LINK else RegistrationVia.EMAIL_CODE
        go(EntryScreen.CreateAccount(flow, via, screen.instance, flow.signUpEmail, screen.connectWith, false, question(server, false), WhoCanRecover.ONLY_ME))
        CodeResult.DONE
    }

    override suspend fun resendSignUpCode(screen: EntryScreen.SignUpCode): SignUpStartResult = step(screen) {
        val flow = flowOf(screen) ?: return SignUpStartResult.STALE
        val server = flow.server
        app.reach(server)?.let { return troubled(it) }
        if (server.mailStalled) return SignUpStartResult.MAIL_UNAVAILABLE
        flow.codeGood = !server.accounts.containsKey(flow.signUpEmail)
        flow.codeExpiresAtMs = app.nowMs + 15 * FakeScript.MINUTE
        flow.codeTries = 0
        SignUpStartResult.DONE
    }

    // ---- registration ----

    private fun form(flow: FakeFlow, from: EntryScreen.CreateAccount, who: WhoCanRecover): EntryScreen.CreateAccount =
        EntryScreen.CreateAccount(flow, from.via, from.instance, from.fixedEmail, from.invitedBy, from.ageConfirmRequired, from.recovery, who)

    override fun reviewOperatorRecovery(screen: EntryScreen.CreateAccount) {
        val q = screen.recovery ?: return
        val flow = flowOf(screen) ?: return
        if (on(screen)) go(EntryScreen.RecoveryWarning(flow, OperatorRecoveryWarning(q.instance, q.unsignedChange)))
    }

    override fun acceptOperatorRecovery(screen: EntryScreen.RecoveryWarning, understood: Boolean): Boolean {
        if (!on(screen) || !understood) return false
        val flow = flowOf(screen) ?: return false
        val before = stack.removeAt(stack.size - 1) as EntryScreen.CreateAccount
        swap(form(flow, before, WhoCanRecover.ME_OR_OPERATOR))
        return true
    }

    override fun keepRecoveryPrivate(screen: EntryScreen.RecoveryWarning) {
        if (!on(screen)) return
        val flow = flowOf(screen) ?: return
        val before = stack.removeAt(stack.size - 1) as EntryScreen.CreateAccount
        swap(form(flow, before, WhoCanRecover.ONLY_ME))
    }

    override fun chooseOnlyMe(screen: EntryScreen.CreateAccount) {
        val flow = flowOf(screen) ?: return
        if (on(screen) && screen.whoCanRecover != WhoCanRecover.ONLY_ME) swap(form(flow, screen, WhoCanRecover.ONLY_ME))
    }

    override suspend fun createAccount(screen: EntryScreen.CreateAccount, input: NewAccountInput): CreateAccountResult = step(screen) {
        val flow = flowOf(screen) ?: return CreateAccountResult.STALE
        val server = flow.server
        // As the engine: a new account is never the one kept here, so nothing is sent.
        if (app.storedSession != null) return CreateAccountResult.ANOTHER_ACCOUNT_KEPT
        val norm = FakeText.emailNorm(screen.fixedEmail ?: input.email) ?: return CreateAccountResult.INVALID_EMAIL
        if (!FakeText.strongEnough(input.password)) return CreateAccountResult.WEAK_PASSWORD
        app.reach(server)?.let { return troubled(it) }
        val used = flow.invite
        val linkOpen = used != null && used.state == FakeInviteState.OPEN && used.expiresAtMs > app.nowMs
        when (screen.via) {
            RegistrationVia.EMAIL_CODE, RegistrationVia.CONNECT_LINK -> {
                if (server.mode != JoinMode.ANYONE) return CreateAccountResult.SIGNUP_CLOSED
                if (app.nowMs > flow.ticketExpiresAtMs) return CreateAccountResult.VERIFICATION_EXPIRED
            }
            RegistrationVia.INVITATION_LINK -> {
                if (server.mode == JoinMode.CLOSED) return CreateAccountResult.SIGNUP_CLOSED
                if (!linkOpen) return CreateAccountResult.LINK_GONE
            }
            RegistrationVia.ENROLMENT_LINK -> {
                if (!linkOpen) return CreateAccountResult.LINK_GONE
                if (used != null && used.boundEmail != null && used.boundEmail != norm) return CreateAccountResult.EMAIL_NOT_THE_LINKS
            }
            RegistrationVia.SETUP_LINK -> {
                if (server.operatorExists) return CreateAccountResult.SETUP_ALREADY_DONE
                if (!linkOpen) return CreateAccountResult.LINK_GONE
            }
        }
        val setup = screen.via == RegistrationVia.SETUP_LINK
        if (!setup && !server.hasCard) return CreateAccountResult.SERVER_NOT_SET_UP
        val ageGiven = input.ageConfirmed || (flow.signUpAge && screen.fixedEmail == flow.signUpEmail)
        if (server.ageConfirmRequired && !setup && !ageGiven) return CreateAccountResult.AGE_CONFIRMATION_NEEDED
        if (!setup && server.full) return CreateAccountResult.SIGNUP_FULL
        if (!setup && screen.via != RegistrationVia.ENROLMENT_LINK && server.dailyLimitReached) return CreateAccountResult.DAILY_LIMIT
        if (server.accounts.containsKey(norm)) return CreateAccountResult.EMAIL_TAKEN
        if (screen.whoCanRecover == WhoCanRecover.ME_OR_OPERATOR && !server.offersOperatorRecovery) return CreateAccountResult.OPERATOR_RECOVERY_UNAVAILABLE
        if (app.script.escrowWrongForm) {
            app.script.escrowWrongForm = false
            return CreateAccountResult.ESCROW_WRONG_FORM
        }
        if (app.script.earlierAccountKnown && !app.script.identityFault) {
            // As the engine's keeper: this device knows the address under an earlier account, so the account made is not
            // taken here, and the forgetting is offered (a new account is never the earlier one under another key). The
            // ticket stays for the try after it.
            raiseEarlier(server, screen.fixedEmail ?: input.email, sameAccount = false)
            return CreateAccountResult.IDENTITY_FAULT
        }

        val account = server.addAccount(norm, input.password)
        account.whoCanRecover = screen.whoCanRecover
        account.kitSaved = false
        account.nameHere = input.displayName.takeIf { io.silencelen.andvari.core.trust.TrustGrammar.encodeName(it) != null }
        if (setup) {
            account.isOperator = true
            server.operatorExists = true
        }
        flow.ticketExpiresAtMs = 0L
        if (app.script.identityFault) {
            // §5.2: the server's answer does not carry back the identity this device registered. The account may
            // exist there; nothing is opened and no session is kept here. A fault of the server's answer: as the engine, it
            // offers no forgetting.
            app.script.identityFault = false
            return CreateAccountResult.IDENTITY_FAULT
        }
        val lateRefusal = (app.script.refusedAfterCommit ?: ANOTHER_SESSION_KEPT.takeIf { app.script.anotherAccountTakenDuringCommit })?.takeIf { !setup }
        if (lateRefusal != null) {
            // As the engine: the account was made and the keeper then refused its session for its own reason (another
            // account kept here meanwhile, its server's operator account held here, ...). Its first kit is shown with the
            // refusal and kept until it is confirmed; nothing of it is kept.
            app.script.anotherAccountTakenDuringCommit = false
            app.script.refusedAfterCommit = null
            used?.state = FakeInviteState.USED
            flow.invite = null
            stack.clear()
            val result = io.silencelen.andvari.core.app.KeeperReasons.committedRegistration(lateRefusal)
            app.kitFlow.showNotKept(account, KitReason.FIRST_KIT, io.silencelen.andvari.core.app.KeeperReasons.kitLine(result),
                result in io.silencelen.andvari.core.app.KeeperReasons.WHILE_ANOTHER_KEPT) {
                reset(null)
                app.publish()
            }
            return result
        }
        journeyDone(flow)
        val session = app.beginSession(server, account, HowDeviceJoined.REGISTERED, "", allContactsCurrent = true)
        if (used != null) {
            when (used.kind) {
                // A register link pins the two accounts to each other inside the registration.
                FakeInviteKind.REGISTER -> {
                    used.state = FakeInviteState.USED
                    connectWith(session, used)
                }
                // A connect link's answer is posted right after the registration, and that may fail: the account exists either way.
                FakeInviteKind.CONNECT -> {
                    val fails = app.script.connectAnswerFails
                    app.script.connectAnswerFails = null
                    if (fails != null && fails != ConnectResult.DONE) {
                        session.connectionNotMade = FakeConnectionNotMade(used, fails)
                    } else {
                        used.state = FakeInviteState.USED
                        connectWith(session, used)
                    }
                }
                else -> used.state = FakeInviteState.USED
            }
        }
        flow.invite = null
        // Setup: card 0 is signed inside the registration and its hash goes into the kit, so the setup comes first.
        if (setup) signCard(flow) else app.kitFlow.show(account, KitReason.FIRST_KIT, inEntry = true) { app.openVault() }
        CreateAccountResult.DONE
    }

    /** The creator of [used] becomes a contact of the new account, uncompared and current on this device. */
    fun connectWith(session: FakeSession, used: FakeInvite) {
        val contact = session.account.addContact(used.from.orEmpty(), compared = false)
        contact.madeOnDeviceId = app.deviceId
        contact.connectedAtMs = app.nowMs
        contact.code = FakeText.digits6("code:${used.payload}")
        session.currentContacts += contact.userId
    }

    /** §6.7 setup link, step 3: this device signs card 0, uploads it and pins it. */
    private fun signCard(flow: FakeFlow) {
        val server = flow.server
        stack.clear()
        if (app.script.holdCardUpload) {
            swap(EntryScreen.ServerSetup(flow, app.label(server), ServerSetupStep.SIGNING, null))
            return
        }
        if (app.script.cardUploadFails) {
            app.script.cardUploadFails = false
            swap(EntryScreen.ServerSetup(flow, app.label(server), ServerSetupStep.NOT_UPLOADED, null))
            return
        }
        server.hasCard = true
        app.signedCard0 += server.origin
        app.pin(server, PinRoot.SETUP, app.session?.account?.email)
        swap(EntryScreen.ServerSetup(flow, app.label(server), ServerSetupStep.FINISHED, app.details(server)))
    }

    /** The held upload of card 0 lands. */
    fun finishCardUpload() {
        val shown = app.entryScreen as? EntryScreen.ServerSetup ?: return
        if (shown.step != ServerSetupStep.SIGNING) return
        app.script.holdCardUpload = false
        flowOf(shown)?.let(::signCard)
    }

    override suspend fun retryServerSetup(screen: EntryScreen.ServerSetup, password: String): ServerResult = step(screen) {
        val flow = flowOf(screen) ?: return ServerResult.STALE
        if (screen.step != ServerSetupStep.NOT_UPLOADED) return ServerResult.STALE
        app.reach(flow.server)?.let { return troubled(it) }
        val account = app.session?.account ?: return ServerResult.STALE
        if (password != account.password) return ServerResult.WRONG_PASSWORD
        app.script.proofRefusal(ServerResult.KEYS_NOT_KNOWN_HERE, ServerResult.PROOF_REFUSED)?.let { return it }
        signCard(flow)
        ServerResult.DONE
    }

    override fun finishServerSetup(screen: EntryScreen.ServerSetup) {
        if (!on(screen) || screen.step != ServerSetupStep.FINISHED) return
        val account = app.session?.account ?: return
        app.kitFlow.show(account, KitReason.FIRST_KIT, inEntry = true) { app.openVault() }
    }

    // ---- sign-in ----

    override fun openLinkDevice(screen: EntryScreen.SignInChoice) {
        if (on(screen)) go(EntryScreen.LinkDeviceEntry())
    }

    override fun openPasswordSignIn(screen: EntryScreen.SignInChoice) {
        if (on(screen)) go(EntryScreen.SignInServer(ServerPurpose.SIGN_IN, offersPublicInstance = baked != null))
    }

    override fun openForgot(screen: EntryScreen.SignInChoice) {
        if (on(screen)) go(EntryScreen.Forgot())
    }

    override suspend fun choosePublicInstance(screen: EntryScreen.SignInServer): ServerResult = step(screen) {
        val server = baked ?: return ServerResult.FAILED
        app.reach(server)?.let { return troubled(it) }
        hurdle(server, AddressMismatchFor.TYPED_ADDRESS, null)?.let { return serverResult(it) }
        app.pin(server, PinRoot.BAKED, null)
        chosen(screen.purpose, FakeFlow(server))
    }

    override suspend fun chooseOwnServer(screen: EntryScreen.SignInServer, address: String): ServerResult = step(screen) {
        val purpose = if (screen.purpose == ServerPurpose.SIGN_IN) GatePurpose.SIGN_IN else GatePurpose.ASSISTED_RECOVERY
        typedServer(address, purpose) { flow -> chosen(screen.purpose, flow) }
    }

    /** The server is pinned for a password: the password screen, or "Ask the operator" where the server offers it. */
    private fun chosen(purpose: ServerPurpose, flow: FakeFlow): ServerResult {
        val server = flow.server
        if (purpose == ServerPurpose.ASK_OPERATOR && !server.offersOperatorRecovery) return ServerResult.NO_OPERATOR_RECOVERY
        if (purpose == ServerPurpose.SIGN_IN) go(EntryScreen.SignIn(flow, MasterPasswordPrompt(null, app.label(server)), false))
        else go(EntryScreen.AskOperator(flow, app.label(server)))
        return ServerResult.DONE
    }

    override suspend fun submitSignInCode(screen: EntryScreen.SignIn, code: String): SignInAnswer = step(screen) {
        val flow = flowOf(screen) ?: return SignInAnswer.STALE
        val server = flow.server
        val account = flow.codeFor ?: return SignInAnswer.STALE
        if (!screen.codeNeeded) return SignInAnswer.STALE
        // As the engine: a code step is used once, whatever came of it; the next try starts at the password again, so that
        // no further code is refused as stale.
        flow.codeFor = null
        app.reach(server)?.let {
            swap(EntryScreen.SignIn(flow, screen.prompt, codeNeeded = false))
            return troubled(it)
        }
        if (blockedNow(server)) {
            swap(EntryScreen.SignIn(flow, screen.prompt, codeNeeded = false))
            app.publish()
            return SignInAnswer.FAILED
        }
        if (code != account.twoStepCode) {
            // As the engine does: a code the server did not take is said as that, never as a wrong password; the keys
            // derived from the password go, and it is asked again.
            swap(EntryScreen.SignIn(flow, screen.prompt, codeNeeded = false))
            return SignInAnswer.REFUSED_AFTER_CODE
        }
        // As the engine: whatever the session keeper answers once the code was taken, the screen is back at the password;
        // it stands before the answer is published, so that whatever the answer raises is on it.
        val next = EntryScreen.SignIn(flow, screen.prompt, codeNeeded = false)
        app.entryScreen = next
        val answer = signedIn(next, flow, account)
        if (app.entryScreen === next) app.publish()
        answer
    }

    override suspend fun submitSignIn(screen: EntryScreen.SignIn, email: String, password: String): SignInAnswer = step(screen) {
        // The server this screen was made for, and no other: whatever was opened since.
        val flow = flowOf(screen) ?: return SignInAnswer.STALE
        val server = flow.server
        // As the engine: another account is kept here, so nothing is sent.
        if (app.keptOther(server, FakeText.emailNorm(email))) return SignInAnswer.ANOTHER_ACCOUNT_KEPT
        app.reach(server)?.let { return troubled(it) }
        if (blockedNow(server)) {
            // The app stops using the instance. It is the server of the screen on show, so its card says why.
            app.publish()
            return SignInAnswer.FAILED
        }
        val norm = FakeText.emailNorm(email)
        if (app.gate(GatePurpose.SIGN_IN, server, norm) != GateDecision.PROCEED) {
            // The sign-in screen is not a place to come back to past the gate: confirming shows a fresh one.
            if (stack.isNotEmpty()) app.entryScreen = stack.removeAt(stack.size - 1)
            raiseGate(flow, TrustGateWording.LINK_OFFER_SIGN_IN, false, false) {
                app.pin(server, PinRoot.TRUST_GATE, null)
                go(EntryScreen.SignIn(flow, MasterPasswordPrompt(null, app.label(server)), false))
                ServerResult.DONE
            }
            return SignInAnswer.TRUST_GATE_FIRST
        }
        // One answer for a wrong address, a wrong password, a disabled account and a wrong code.
        val account = norm?.let { server.accounts[it] }
        flow.codeFor = null
        if (account == null || account.password != password || account.disabled) return SignInAnswer.WRONG
        if (account.twoStepCode != null) {
            flow.codeFor = account
            swap(EntryScreen.SignIn(flow, screen.prompt, codeNeeded = true))
            return SignInAnswer.CODE_NEEDED
        }
        signedIn(screen, flow, account)
    }

    /** The password and any code verified. */
    private fun signedIn(screen: EntryScreen.SignIn, flow: FakeFlow, account: FakeAccount): SignInAnswer {
        val server = flow.server
        // Only now, with the password and any code verified, does the account's link requirement speak (§8.7, FC-8).
        if (account.requireLink && app.deviceId !in account.knownDevices) {
            go(EntryScreen.LinkRequired(flow, screen.prompt.instance, account.email))
            return SignInAnswer.LINK_REQUIRED
        }
        if (app.script.identityFault) {
            app.script.identityFault = false
            raiseEarlier(server, account.email)
            return SignInAnswer.IDENTITY_FAULT
        }
        // As the engine's keeper with a reason of its own: said as what it is.
        app.script.keeperRefuses?.let { reason -> io.silencelen.andvari.core.app.KeeperReasons.signIn(reason)?.let { return it } }
        // Spec 01 §7, as the engine: the server's copy opened to another key than the one this device keeps.
        if (app.script.signInServerKeysNotKnown) {
            app.script.signInServerKeysNotKnown = false
            return SignInAnswer.SERVER_KEYS_NOT_KNOWN_HERE
        }
        // §9.1: the operator account signs in only where the operator views are. A phone ends the session it just opened.
        if (account.isOperator && !takesSetupLinks) return SignInAnswer.OPERATOR_NEEDS_COMPUTER
        val known = app.deviceId in account.knownDevices
        journeyDone(flow)
        app.beginSession(server, account, HowDeviceJoined.PASSWORD, "", allContactsCurrent = false)
        if (known) app.session?.let { it.peopleListDue = false }
        app.signInNotice = if (app.script.signInOverOtherPasswordCopy) io.silencelen.andvari.core.app.CopyLine.of(io.silencelen.andvari.core.app.CopyKey.SIGNED_IN_COPY_FOLLOWS_SERVER) else null
        app.script.signInOverOtherPasswordCopy = false
        if (account.kitSaved) app.openVault()
        else app.kitFlow.make(account, KitReason.NEVER_SAVED, inEntry = true) { app.openVault() }
        return SignInAnswer.DONE
    }

    /** To "Link from your other device", as if the person had walked there from the first screen. */
    private fun toLinkEntry() {
        val left = app.entryScreen
        val flows = stack.mapNotNull { it.flow as? FakeFlow }.distinct()
        stack.clear()
        stack += firstRun()
        stack += EntryScreen.SignInChoice()
        app.entryScreen = EntryScreen.LinkDeviceEntry()
        flows.forEach(::abandon)
        leftBehind(left)
        app.publish()
    }

    override fun linkInstead(screen: EntryScreen.LinkRequired) {
        if (on(screen)) toLinkEntry()
    }

    // ---- linking this device (§8.2, the new device) ----

    override suspend fun submitDeviceLink(screen: EntryScreen.LinkDeviceEntry, payload: String, source: PayloadSource): DeviceLinkScanResult = step(screen) {
        val (shape, key) = FakeText.shape(payload)
        if (shape != PayloadShape.DEVICE_LINK) return DeviceLinkScanResult.NOT_A_DEVICE_LINK
        val found = app.deviceLinks[key] ?: return DeviceLinkScanResult.NOT_A_DEVICE_LINK
        val server = found.server
        app.reach(server)?.let { return troubled(it) }
        when (hurdle(server, AddressMismatchFor.DEVICE_LINK, null)) {
            Hurdle.BLOCKED -> return DeviceLinkScanResult.IDENTITY_CONFLICT
            Hurdle.CHANGED -> return DeviceLinkScanResult.SERVER_CHANGED
            Hurdle.OTHER_ADDRESS -> return DeviceLinkScanResult.OTHER_ADDRESS
            Hurdle.NO_CARD, Hurdle.NOT_ACCEPTED -> return DeviceLinkScanResult.CARD_NOT_ACCEPTED
            null -> Unit
        }
        // As the engine's keeper, asked with the origin only before the claim: an account kept at another server.
        if (app.storedSession?.let { it.first.origin != server.origin } == true) {
            go(EntryScreen.LinkDeviceEnded(LinkDeviceEnd.ANOTHER_SESSION_KEPT))
            return DeviceLinkScanResult.DONE
        }
        val flow = FakeFlow(server).also { it.link = found }
        if (server === baked) app.pin(server, PinRoot.BAKED, null)
        // Step 0: a password pin for the link's origin before anything is sent to it.
        if (app.gate(GatePurpose.DEVICE_LINK, server, null) == GateDecision.PROCEED) {
            if (!claim(flow)) return DeviceLinkScanResult.RATE_LIMITED
        } else {
            raiseGate(flow, TrustGateWording.DEVICE_LINK, false, false) {
                app.pin(server, PinRoot.TRUST_GATE, null)
                flow.linkPinMade = true
                if (claim(flow)) ServerResult.DONE else ServerResult.RATE_LIMITED
            }
        }
        DeviceLinkScanResult.DONE
    }

    /**
     * Step 2: the claim, with this device's commitment. The first claim wins. False where the server refused it as one of
     * too many requests ([FakeScript.linkTooMany]): as the engine, nothing is claimed and the wait is kept.
     */
    private fun claim(flow: FakeFlow): Boolean {
        if (app.script.linkTooMany) {
            app.script.linkTooMany = false
            app.noteRateLimit(Trouble.RATE_LIMITED)
            flow.link = null
            return false
        }
        val found = flow.link ?: return true
        val ended = when {
            found.step == FakeLinkStep.CANCELLED || found.step == FakeLinkStep.PICKED_UP -> LinkDeviceEnd.CANCELLED
            found.expiresAtMs <= app.nowMs -> LinkDeviceEnd.EXPIRED
            found.claimedByOther || found.step != FakeLinkStep.OPEN -> LinkDeviceEnd.ALREADY_CLAIMED
            else -> null
        }
        if (ended != null) {
            flow.link = null
            go(EntryScreen.LinkDeviceEnded(ended))
            return true
        }
        found.step = FakeLinkStep.CLAIMED
        found.expiresAtMs = app.nowMs + 5 * FakeScript.MINUTE
        go(EntryScreen.LinkDeviceWaiting(flow, app.label(found.server)))
        return true
    }

    /** Steps 3 to 5: the other device's nonce arrives, this device reveals, and only now a code exists. */
    fun otherDeviceAnswers() {
        val shown = app.entryScreen as? EntryScreen.LinkDeviceWaiting ?: return
        val flow = flowOf(shown) ?: return
        val found = flow.link ?: return
        if (found.step != FakeLinkStep.CLAIMED) return
        found.step = FakeLinkStep.REVEALED
        found.expiresAtMs = app.nowMs + 5 * FakeScript.MINUTE
        swap(EntryScreen.LinkDeviceCode(flow, shown.instance, found.code))
    }

    /** Steps 6 and 7: the approval arrives, names the pinned origin and passes its MAC; only now the password is asked. */
    fun otherDeviceApproves() {
        val shown = app.entryScreen as? EntryScreen.LinkDeviceCode ?: return
        val flow = flowOf(shown) ?: return
        val found = flow.link ?: return
        if (found.step != FakeLinkStep.REVEALED) return
        if (app.script.linkIdentityCannotTell) {
            // As the engine's identity stop at the approval that names no address: its own end, and no offer.
            app.script.linkIdentityCannotTell = false
            endLink(LinkDeviceEnd.IDENTITY_FAULT_CANNOT_TELL)
            return
        }
        if (app.script.keeperIdentityFault) {
            // As the engine's keeper once the approval names the account: its address is known here under another account
            // or key. The link ends before any password is asked.
            app.script.keeperIdentityFault = false
            endLink(LinkDeviceEnd.IDENTITY_FAULT)
            // As the engine's link stop with the address ([io.silencelen.andvari.core.client.devicelink.NewStep.Stopped.addressKnownHere]):
            // the ended screen offers the forgetting as a sign-in does, where the script says an earlier account is known.
            raiseEarlier(flow.server, found.account.email)
            return
        }
        app.script.keeperRefuses?.let { reason ->
            // As the engine's keeper with a reason of its own: the link ends with it, before any password is asked.
            endLink(io.silencelen.andvari.core.app.KeeperReasons.linkEnd(linkStopOf(reason)) ?: LinkDeviceEnd.DID_NOT_CHECK_OUT)
            return
        }
        found.step = FakeLinkStep.APPROVED
        found.expiresAtMs = app.nowMs + 5 * FakeScript.MINUTE
        swap(EntryScreen.LinkDevicePassword(flow, MasterPasswordPrompt(found.account.email, shown.instance), false))
    }

    /** The claimed link on show ends without linking this device. */
    fun endLink(outcome: LinkDeviceEnd, wait: io.silencelen.andvari.core.app.NamedWait? = null) {
        val shown = app.entryScreen
        if (!claimed(shown) || shown == null) return
        val flow = flowOf(shown) ?: return
        val found = flow.link ?: return
        found.step = FakeLinkStep.CANCELLED
        flow.link = null
        swap(EntryScreen.LinkDeviceEnded(outcome, wait))
    }

    override suspend fun submitLinkPassword(screen: EntryScreen.LinkDevicePassword, password: String): LinkPasswordResult = step(screen) {
        val flow = flowOf(screen) ?: return LinkPasswordResult.STALE
        val found = flow.link ?: return LinkPasswordResult.STALE
        if (app.keptOther(found.server, FakeText.emailNorm(found.account.email))) return LinkPasswordResult.ANOTHER_ACCOUNT_KEPT
        app.reach(found.server)?.let { return troubled(it) }
        if (found.expiresAtMs <= app.nowMs) {
            endLink(LinkDeviceEnd.EXPIRED)
            return LinkPasswordResult.ENDED
        }
        val account = found.account
        flow.linkPasswordOk = false
        if (account.password != password) {
            // As the engine: a former password that still opens this device's copy of the account is a refused proof;
            // the link and its password screen stay.
            val opensCopy = app.storedSession?.second === account && app.previousPasswordHere == password
            return if (opensCopy) LinkPasswordResult.PROOF_REFUSED else LinkPasswordResult.WRONG
        }
        if (account.twoStepCode != null) {
            flow.linkPasswordOk = true
            swap(EntryScreen.LinkDevicePassword(flow, screen.prompt, codeNeeded = true))
            return LinkPasswordResult.CODE_NEEDED
        }
        pickUp(flow, found)
    }

    override suspend fun submitLinkCode(screen: EntryScreen.LinkDevicePassword, code: String): LinkPasswordResult = step(screen) {
        val flow = flowOf(screen) ?: return LinkPasswordResult.STALE
        val found = flow.link ?: return LinkPasswordResult.STALE
        if (!screen.codeNeeded || !flow.linkPasswordOk) return LinkPasswordResult.STALE
        app.reach(found.server)?.let { return troubled(it) }
        if (found.expiresAtMs <= app.nowMs) {
            endLink(LinkDeviceEnd.EXPIRED)
            return LinkPasswordResult.ENDED
        }
        if (code != found.account.twoStepCode) {
            // As the engine: within the link's time a code the server did not take leaves the link open; the screen is
            // back at the password, and the password and the current code are typed again (never "wrong password").
            flow.linkPasswordOk = false
            swap(EntryScreen.LinkDevicePassword(flow, screen.prompt, codeNeeded = false))
            return LinkPasswordResult.CODE_REFUSED_LINK_STAYS
        }
        flow.linkPasswordOk = false
        pickUp(flow, found)
    }

    private fun pickUp(flow: FakeFlow, found: FakeDeviceLink): LinkPasswordResult {
        val server = found.server
        val account = found.account
        if (app.script.linkTooMany) {
            // As the engine: the pickup refused as one of too many requests ends the link with its own end and the wait.
            app.script.linkTooMany = false
            app.noteRateLimit(Trouble.RATE_LIMITED)
            endLink(LinkDeviceEnd.TOO_MANY, app.namedWait())
            return LinkPasswordResult.RATE_LIMITED
        }
        // Step 8: the session arrived; the bundle must open and agree with the pin made before the claim.
        if (app.script.bundleDisagreesWithPin || app.script.bundleDoesNotOpen) {
            val wrongServer = app.script.bundleDisagreesWithPin
            app.script.bundleDisagreesWithPin = false
            app.script.bundleDoesNotOpen = false
            if (wrongServer && flow.linkPinMade) {
                // Only the pin this link made in its step 0, never one the device already had (§4.4).
                app.pins[server.origin]?.removeAll { it.root == PinRoot.TRUST_GATE }
                if (app.pins[server.origin].isNullOrEmpty()) app.pins.remove(server.origin)
            }
            endLink(if (wrongServer) LinkDeviceEnd.WRONG_SERVER else LinkDeviceEnd.DID_NOT_CHECK_OUT)
            return LinkPasswordResult.ENDED
        }
        // As the engine: the pickup's session is ended alone, nothing kept is replaced, and the end says its way out.
        if (app.script.linkKeysNotKnownHere) {
            app.script.linkKeysNotKnownHere = false
            endLink(LinkDeviceEnd.SERVER_KEYS_NOT_KNOWN_HERE)
            return LinkPasswordResult.SERVER_KEYS_NOT_KNOWN_HERE
        }
        if (app.script.linkAnotherSessionKept) {
            app.script.linkAnotherSessionKept = false
            endLink(LinkDeviceEnd.ANOTHER_SESSION_KEPT)
            return LinkPasswordResult.ANOTHER_SESSION_KEPT
        }
        found.step = FakeLinkStep.PICKED_UP
        flow.link = null
        journeyDone(flow)
        if (account.isOperator && !takesSetupLinks) {
            // §9.1: the operator account is not on phones. The session the pickup opened ends at once; nothing is kept.
            app.entryScreen = firstRun()
            app.publish()
            return LinkPasswordResult.OPERATOR_NEEDS_COMPUTER
        }
        // The bundle makes the account's contacts current here: no second ceremony (G3).
        app.beginSession(server, account, HowDeviceJoined.LINKED, found.fromDevice, allContactsCurrent = true)
        // Spec 01 §7, as after a sign-in: the copy kept here was sealed under another master password.
        app.signInNotice = if (app.script.signInOverOtherPasswordCopy) io.silencelen.andvari.core.app.CopyLine.of(io.silencelen.andvari.core.app.CopyKey.SIGNED_IN_COPY_FOLLOWS_SERVER) else null
        app.script.signInOverOtherPasswordCopy = false
        app.openVault()
        return LinkPasswordResult.DONE
    }

    override fun dismissLinkDevice(screen: EntryScreen.LinkDeviceEnded) {
        if (on(screen)) toLinkEntry()
    }

    // ---- forgot the master password ----

    override fun openKitEntry(screen: EntryScreen.Forgot) {
        if (on(screen)) go(EntryScreen.KitEntry())
    }

    override fun openAskOperator(screen: EntryScreen.Forgot) {
        // The public instance offers no operator recovery (variant R, §7.7), so it is not among the choices here.
        if (on(screen)) go(EntryScreen.SignInServer(ServerPurpose.ASK_OPERATOR, offersPublicInstance = false))
    }

    override suspend fun submitKit(screen: EntryScreen.KitEntry, payload: String, source: PayloadSource): KitScanResult = step(screen) {
        val (shape, key) = FakeText.shape(payload)
        if (shape != PayloadShape.KIT) return KitScanResult.NOT_A_KIT
        val found = app.kits[key] ?: return KitScanResult.NOT_A_KIT
        startKit(found, typed = false)
    }

    /**
     * A kit, scanned or typed, at the server it names (§10, §4.4): a flow of its own. The kit's own anchor is checked
     * first, whatever pin this device holds: a scanned kit whose card hash no longer matches goes through the Trust
     * Gate with the kit warning even where a password pin exists.
     */
    private fun startKit(found: FakeKit, typed: Boolean): KitScanResult {
        val server = found.server
        // As the engine's keeper, asked with the origin only before anything is sent: an account kept at another server.
        if (app.storedSession?.let { it.first.origin != server.origin } == true) return KitScanResult.ANOTHER_ACCOUNT_KEPT
        app.reach(server)?.let { return troubled(it) }
        val flow = FakeFlow(server).also { it.kit = found }
        when (hurdle(server, if (typed) AddressMismatchFor.TYPED_KIT else AddressMismatchFor.KIT, flow)) {
            Hurdle.BLOCKED -> return KitScanResult.IDENTITY_CONFLICT
            Hurdle.CHANGED -> return KitScanResult.SERVER_CHANGED
            Hurdle.OTHER_ADDRESS -> return KitScanResult.OTHER_ADDRESS
            Hurdle.NO_CARD, Hurdle.NOT_ACCEPTED -> return KitScanResult.CARD_NOT_ACCEPTED
            null -> Unit
        }
        if (!typed && !found.card0Matches) {
            // Made before the server's identity was reset: the kit vouches for another identity than the one served.
            raiseGate(flow, TrustGateWording.TYPED_ADDRESS, kitChanged = true, typedKit = false) {
                flow.pinAtConfirm = true
                recoverWith(flow, found)
                ServerResult.DONE
            }
            return KitScanResult.DONE
        }
        if (server === baked) pinFor(flow, PinRoot.BAKED, null)
        when {
            app.gate(GatePurpose.KIT_RECOVERY, server, found.email) == GateDecision.PROCEED -> recoverWith(flow, found)
            typed -> {
                // No card hash was typed, so the kit vouches for no server: the gate, unless a pin already serves this recovery.
                raiseGate(flow, TrustGateWording.TYPED_ADDRESS, kitChanged = false, typedKit = true) {
                    flow.pinAtConfirm = true
                    recoverWith(flow, found)
                    ServerResult.DONE
                }
            }
            else -> {
                // The kit's own card hash anchors the pin: for this account's recovery, and nothing else.
                pinFor(flow, PinRoot.KIT, found.email)
                recoverWith(flow, found)
            }
        }
        return KitScanResult.DONE
    }

    /** "Recover … on …" for [found]. Nothing has been sent, and nothing is until the person confirms. */
    private fun recoverWith(flow: FakeFlow, found: FakeKit) {
        go(EntryScreen.KitRecover(flow, found.email, app.label(found.server)))
    }

    override suspend fun submitTypedKit(screen: EntryScreen.KitEntry, email: String, serverAddress: String, groups: String): KitScanResult = step(screen) {
        val norm = FakeText.emailNorm(email) ?: return KitScanResult.INVALID_EMAIL
        val origin = FakeText.origin(serverAddress) ?: return KitScanResult.NOT_AN_ADDRESS
        // §10: spaces and line breaks are ignored, nothing else; what is left is the secret's 43 characters.
        val secret = groups.filter { it != ' ' && it != '\n' && it != '\r' }
        val kitAlphabet = secret.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' }
        if (secret.length != 43 || !kitAlphabet) return KitScanResult.NOT_A_KIT
        val server = app.servers[origin] ?: return KitScanResult.UNREACHABLE
        startKit(typedKit(server, norm, secret), typed = true)
    }

    /** A typed kit at [server]: whether the address has an account there, and whether these are its kit's groups, only the server says. */
    private fun typedKit(server: FakeServer, norm: String, secret: String): FakeKit {
        val account = server.accounts[norm]
        val right = account != null && FakeText.kitGroups(account, account.kitSerial).joinToString("") == secret
        return FakeKit("typed:${app.serial++}:$secret", server, norm, account, if (right && account != null) account.kitSerial else -1)
    }

    override suspend fun recoverAtNamedAddress(screen: EntryScreen.AddressMismatch): KitScanResult = step(screen) {
        if (!screen.canRecoverThere) return KitScanResult.STALE
        val flow = flowOf(screen) ?: return KitScanResult.STALE
        val old = flow.kit ?: return KitScanResult.STALE
        val target = app.servers[screen.cardNames] ?: return KitScanResult.UNREACHABLE
        val typed = screen.opening == AddressMismatchFor.TYPED_KIT
        // The same kit at the address the card names: every check runs again there, from the card chain on.
        val there = if (typed) {
            typedKit(target, old.email, old.payload.substringAfterLast(':'))
        } else {
            FakeKit(old.payload, target, old.email, target.accounts[old.email], old.serial).also { it.card0Matches = old.card0Matches }
        }
        // The mismatch is not a place to come back to: the recovery goes on from where the kit was handed in.
        flow.kit = null
        pop()
        startKit(there, typed)
    }

    override suspend fun confirmKitRecovery(screen: EntryScreen.KitRecover): KitRecoverResult {
        if (!on(screen)) return KitRecoverResult.STALE
        app.pause()
        if (!on(screen)) return KitRecoverResult.STALE
        val flow = flowOf(screen) ?: return KitRecoverResult.STALE
        val found = flow.kit ?: return KitRecoverResult.STALE
        // An injected refusal ends the recovery as a real one does; an injected "done" or "stale" does nothing else.
        val forced = app.injected<KitRecoverResult>()
        if (forced != null && (forced.done || forced == KitRecoverResult.STALE)) return forced
        // As the engine: another account is kept here, so nothing is sent (and the kit goes, as on every refusal).
        val result = forced
            ?: if (app.keptOther(found.server, FakeText.emailNorm(found.email))) KitRecoverResult.ANOTHER_ACCOUNT_KEPT
            else when (app.script.keeperRefuses) {
                // As the engine's keeper with a reason of its own, asked once the kit named the account: nothing is committed.
                OPERATOR_ACCOUNT_HELD -> KitRecoverResult.OPERATOR_ACCOUNT_HELD
                KEPT_COPY_DAMAGED -> KitRecoverResult.KEPT_COPY_DAMAGED
                else -> proveKit(flow, found)
            }
        if (result == KitRecoverResult.DONE) {
            go(EntryScreen.ReplacePassword(flow, found.email, screen.instance, RecoveryRoute.KIT))
        } else if (result != KitRecoverResult.STALE) {
            // A kit is proved once: whatever went wrong, its secret is gone and it has to be handed in again.
            dropKit(flow)
            // As the engine: an offer the check raised stands on the screen the journey went back to.
            earlier?.takeIf { it.on === screen }?.let { e ->
                app.entryScreen?.let { on -> earlier = offerOf(e.origin, e.instance, e.email, on, confirming = false); app.publish() }
            }
        }
        return result
    }

    private fun proveKit(flow: FakeFlow, found: FakeKit): KitRecoverResult {
        if (flow.pinAtConfirm) {
            // The gate the person passed is confirmed now, with the kit; it is the one pin a failed proof leaves behind.
            flow.pinAtConfirm = false
            app.pin(found.server, PinRoot.TRUST_GATE, null)
        }
        app.reach(found.server)?.let { return troubled(it) }
        // One answer for no such account, another account's kit, groups that are no kit, and a kit a newer one replaced.
        val account = found.account
        if (account == null || found.server.accounts[found.email] !== account || found.serial != account.kitSerial) return KitRecoverResult.KIT_NOT_ACCEPTED
        if (app.script.identityFault) {
            app.script.identityFault = false
            raiseEarlier(found.server, found.email)
            return KitRecoverResult.IDENTITY_FAULT
        }
        // Spec 01 §7, as the engine: the kit's key does not open this device's kept copy of the account. Nothing is sent.
        if (app.script.recoveredKeyNotKept) {
            app.script.recoveredKeyNotKept = false
            return KitRecoverResult.SERVER_KEYS_NOT_KNOWN_HERE
        }
        // §9.1: the pinned card names this account as the operator, and the operator account is not on phones.
        if (account.isOperator && !takesSetupLinks) return KitRecoverResult.OPERATOR_NEEDS_COMPUTER
        flow.recovering = account
        return KitRecoverResult.DONE
    }

    /** The recovery on show is over: its screens go, the pin it made goes, and the journey is back where the kit was handed in. */
    private fun dropKit(flow: FakeFlow) {
        flow.kit = null
        flow.recovering = null
        flow.pinAtConfirm = false
        dropMadePin(flow)
        while (stack.isNotEmpty() && stack.last().flow === flow) stack.removeAt(stack.size - 1)
        app.entryScreen = if (stack.isEmpty()) firstRun() else stack.removeAt(stack.size - 1)
        app.publish()
    }

    override suspend fun chooseReplacementPassword(screen: EntryScreen.ReplacePassword, password: String): ReplacePasswordResult = step(screen) {
        val flow = flowOf(screen) ?: return ReplacePasswordResult.STALE
        val account = flow.recovering ?: return ReplacePasswordResult.STALE
        if (!FakeText.strongEnough(password)) return ReplacePasswordResult.WEAK_PASSWORD
        app.reach(account.server)?.let { return troubled(it) }
        if (account.disabled) return ReplacePasswordResult.ACCOUNT_DISABLED
        val request = flow.request?.takeIf { app.helpRequest === it }
        // As the engine: an answered request that can no longer be finished (it ran out of time or was used, or whoever runs
        // the server ended it) commits nothing; what was opened goes and the journey is back at the first screen.
        if (screen.after == RecoveryRoute.OPERATOR_HELP && request?.fulfilled != true) {
            reset(null)
            app.publish()
            return ReplacePasswordResult.REQUEST_ENDED
        }
        // As the engine: the request is kept and the journey is back on its screen, which says why.
        if (screen.after == RecoveryRoute.OPERATOR_HELP && request != null && (request.answerReplaced || request.unknownToServer)) {
            val replaced = request.answerReplaced
            if (replaced) {
                // The operator must upload again: the next look finds nothing until then.
                request.fulfilled = false
                request.answerReplaced = false
            }
            flow.recovering = null
            // The account check and the password screen go; the request's screen stands in place of the one under them.
            while (stack.isNotEmpty() && stack.last().flow === flow && stack.last() !is EntryScreen.OperatorHelp) stack.removeAt(stack.size - 1)
            if (stack.isNotEmpty() && stack.last().flow === flow) stack.removeAt(stack.size - 1)
            swap(helpScreen(flow, request, replaced = replaced))
            return if (replaced) ReplacePasswordResult.ANSWER_REPLACED else ReplacePasswordResult.REQUEST_UNKNOWN
        }
        // Spec 01 §7, asked again before the commit, as the engine: nothing is committed. After the operator's help the
        // request is kept and its screen says so; after a kit the journey goes back to where the kit is handed in.
        val keyNotKept = if (screen.after == RecoveryRoute.OPERATOR_HELP) request?.keyNotKept == true else app.script.recoveredKeyNotKept
        if (keyNotKept) {
            flow.recovering = null
            if (screen.after == RecoveryRoute.OPERATOR_HELP && request != null) {
                while (stack.isNotEmpty() && stack.last().flow === flow && stack.last() !is EntryScreen.OperatorHelp) stack.removeAt(stack.size - 1)
                if (stack.isNotEmpty() && stack.last().flow === flow) stack.removeAt(stack.size - 1)
                swap(helpScreen(flow, request))
            } else {
                app.script.recoveredKeyNotKept = false
                dropKit(flow)
            }
            return ReplacePasswordResult.SERVER_KEYS_NOT_KNOWN_HERE
        }
        // As the engine's keeper, asked again just before the commit: another account is kept here now, or the address is
        // known here under another account or key. Nothing is committed.
        if (app.script.anotherAccountTakenBeforeCommit || app.script.keeperIdentityFault || app.script.keeperRefuses != null) {
            val stop = when {
                app.script.anotherAccountTakenBeforeCommit -> ANOTHER_SESSION_KEPT
                app.script.keeperIdentityFault -> SELF_IDENTITY_MISMATCH
                else -> app.script.keeperRefuses!!
            }
            if (stop == ANOTHER_SESSION_KEPT) app.script.anotherAccountTakenBeforeCommit = false
            if (stop == SELF_IDENTITY_MISMATCH) app.script.keeperIdentityFault = false
            flow.recovering = null
            if (screen.after == RecoveryRoute.OPERATOR_HELP && request != null) {
                while (stack.isNotEmpty() && stack.last().flow === flow && stack.last() !is EntryScreen.OperatorHelp) stack.removeAt(stack.size - 1)
                if (stack.isNotEmpty() && stack.last().flow === flow) stack.removeAt(stack.size - 1)
                swap(helpScreen(flow, request, keeperStop = stop))
            } else {
                dropKit(flow)
            }
            if (stop == SELF_IDENTITY_MISMATCH) raiseEarlier(flow.server, screen.email)
            return io.silencelen.andvari.core.app.KeeperReasons.beforeCommit(stop) ?: ReplacePasswordResult.FAILED
        }
        // The commit: a new password, a new kit in the same step, every session ended, two-step and link-only off.
        account.password = password
        account.kitSerial++
        account.kitSaved = false
        account.twoStepCode = null
        account.requireLink = false
        account.devices.forEach { it.live = false }
        account.knownDevices.clear()
        if (screen.after == RecoveryRoute.OPERATOR_HELP && request != null) {
            account.helpRequests -= request
            app.helpRequest = null
        }
        flow.recovering = null
        flow.kit = null
        if (app.script.recoveryCommitUnanswered) {
            // The commit landed and its answer was lost: the old kit may be dead, so the way on is a sign-in with the new password.
            app.script.recoveryCommitUnanswered = false
            flow.madePin = null
            stack.clear()
            app.entryScreen = firstRun()
            beginSignIn(FakeFlow(account.server))
            app.publish()
            return ReplacePasswordResult.MAY_HAVE_WORKED
        }
        if (app.script.recoveryCommitNotOpened) {
            // As the engine: the commit stood, its answer did not open the account here; never "stale", never the
            // password step again, whatever other session was refused meanwhile.
            app.script.recoveryCommitNotOpened = false
            app.script.anotherAccountTakenDuringCommit = false
            flow.madePin = null
            reset(null)
            app.publish()
            return ReplacePasswordResult.COMMITTED_NOT_OPENED
        }
        val lateRefusal = app.script.refusedAfterCommit ?: ANOTHER_SESSION_KEPT.takeIf { app.script.anotherAccountTakenDuringCommit }
        if (lateRefusal != null) {
            // As the engine: the commit stood at the server and the keeper then refused its session, for its own reason.
            // The new kit is the account's only one: shown with the refusal, kept until confirmed.
            app.script.anotherAccountTakenDuringCommit = false
            app.script.refusedAfterCommit = null
            flow.madePin = null
            stack.clear()
            val result = io.silencelen.andvari.core.app.KeeperReasons.committedRecovery(lateRefusal)
            app.kitFlow.showNotKept(account, KitReason.AFTER_RECOVERY, io.silencelen.andvari.core.app.KeeperReasons.kitLine(result),
                result in io.silencelen.andvari.core.app.KeeperReasons.WHILE_ANOTHER_KEPT) {
                reset(null)
                app.publish()
            }
            return result
        }
        journeyDone(flow)
        if (account.isOperator && !takesSetupLinks) {
            // §9.1: found only from the commit's session. The new password is in force; the session ends at once.
            app.entryScreen = firstRun()
            app.publish()
            return ReplacePasswordResult.OPERATOR_NEEDS_COMPUTER
        }
        app.beginSession(account.server, account, HowDeviceJoined.RECOVERED, "", allContactsCurrent = false)
        app.kitFlow.show(account, KitReason.AFTER_RECOVERY, inEntry = true) { app.openVault() }
        ReplacePasswordResult.DONE
    }

    // ---- the operator's help (§9.3) ----

    override fun openMailboxValue(screen: EntryScreen.AskOperator) {
        if (!on(screen) || screen.mailboxValueOpen) return
        val flow = flowOf(screen) ?: return
        swap(EntryScreen.AskOperator(flow, screen.instance, mailboxValueOpen = true))
    }

    override suspend fun requestOperatorHelp(screen: EntryScreen.AskOperator, email: String): AskOperatorResult = askOperator(screen, email, null)

    override suspend fun requestOperatorHelpWithValue(screen: EntryScreen.AskOperator, email: String, mailboxValue: String): AskOperatorResult =
        askOperator(screen, email, mailboxValue)

    private suspend fun askOperator(screen: EntryScreen.AskOperator, email: String, mailboxValue: String?): AskOperatorResult = step(screen) {
        val flow = flowOf(screen) ?: return AskOperatorResult.STALE
        val server = flow.server
        val norm = FakeText.emailNorm(email) ?: return AskOperatorResult.INVALID_EMAIL
        // As the engine: a text that cannot be a mailbox value is said before anything is sent; blank is none.
        val value = mailboxValue?.takeIf { it.isNotBlank() }?.let {
            io.silencelen.andvari.core.client.recovery.WireAssistedRecovery.mailboxValueOf(it) ?: return AskOperatorResult.NOT_A_MAILBOX_VALUE
        }
        app.reach(server)?.let { return troubled(it) }
        if (server.mailStalled) return AskOperatorResult.MAIL_UNAVAILABLE
        // The answer is the same for every address; a code is mailed only to an account that chose operator recovery.
        val account = server.accounts[norm]
        val request = FakeHelpRequest(
            "request-${app.serial++}", server, norm, app.nowMs,
            codeMailed = account != null && account.whoCanRecover == WhoCanRecover.ME_OR_OPERATOR, platform = app.platform,
        )
        request.mailboxValue = value
        app.helpRequest = request
        flow.request = request
        go(helpScreen(flow, request))
        AskOperatorResult.DONE
    }

    private fun helpScreen(flow: FakeFlow, request: FakeHelpRequest, replaced: Boolean = false, keeperStop: String? = null): EntryScreen.OperatorHelp {
        // As the engine's keeper at the pick-up: another account kept here, or the address bound here to another account.
        val stop = keeperStop ?: if (request.fulfilled) keeperStopAtPickUp(request) else null
        return EntryScreen.OperatorHelp(
            flow, app.label(request.server), request.email, request.stage, FakeText.requestCode(request.requestId), request.holdEndsAtMs,
            answerReplaced = if (replaced) io.silencelen.andvari.core.app.CopyKey.ASSIST_ANSWER_REPLACED else null,
            keyChange = keyChange(request, withUnsigned = true),
            requestUnknown = if (request.unknownToServer) io.silencelen.andvari.core.app.CopyKey.ASSIST_REQUEST_UNKNOWN else null,
            keysNotKnownHere = if (request.fulfilled && request.keyNotKept) io.silencelen.andvari.core.app.CopyKey.SIGN_IN_SERVER_KEYS_NOT_KNOWN_HERE else null,
            anotherAccountKept = if (stop == ANOTHER_SESSION_KEPT) io.silencelen.andvari.core.app.CopyKey.ASSIST_ANOTHER_ACCOUNT_KEPT else null,
            identityFault = if (stop == SELF_IDENTITY_MISMATCH) io.silencelen.andvari.core.app.CopyKey.IDENTITY_FAULT_ADDRESS_KNOWN else null,
            operatorAccountHeld = if (stop == OPERATOR_ACCOUNT_HELD) io.silencelen.andvari.core.app.CopyKey.OPERATOR_ACCOUNT_HELD_HERE else null,
            keptCopyDamaged = if (stop == KEPT_COPY_DAMAGED) io.silencelen.andvari.core.app.CopyKey.KEPT_COPY_DAMAGED else null,
            notTheKeptAccount = if (stop == NOT_THE_KEPT_ACCOUNT) io.silencelen.andvari.core.app.CopyKey.ASSIST_NOT_THE_KEPT_ACCOUNT else null,
        )
    }

    /** What the engine's keeper says at an answer's pick-up for [request]: null when it would take the session. */
    private fun keeperStopAtPickUp(request: FakeHelpRequest): String? = when {
        // As the engine: an answer that names another account than the one kept for the address is refused first.
        request.namesAnotherAccount -> NOT_THE_KEPT_ACCOUNT
        app.script.keeperRefuses != null -> app.script.keeperRefuses
        request.boundElsewhere -> SELF_IDENTITY_MISMATCH
        app.keptOther(request.server, request.email) -> ANOTHER_SESSION_KEPT
        else -> null
    }

    /** As the engine: an unsigned change stops the request; a signed one is said beside it. */
    private fun keyChange(request: FakeHelpRequest, withUnsigned: Boolean): io.silencelen.andvari.core.app.AssistKeyChange? = when {
        request.keyChangedUnsigned -> if (withUnsigned) io.silencelen.andvari.core.app.AssistKeyChange(app.label(request.server), byOldKey = false, rotatedAtMs = 0L) else null
        request.keyRotatedAtMs != null -> io.silencelen.andvari.core.app.AssistKeyChange(app.label(request.server), byOldKey = true, rotatedAtMs = request.keyRotatedAtMs!!)
        else -> null
    }

    /** The request's answer is stopped before anything of it is opened: an unsigned key change, or a server that forgot it. */
    private fun answerHeld(request: FakeHelpRequest): Boolean =
        request.keyChangedUnsigned || request.unknownToServer || request.keyNotKept || keeperStopAtPickUp(request) != null

    override suspend fun verifyOperatorHelp(screen: EntryScreen.OperatorHelp, code: String): CodeResult = step(screen) {
        val (flow, request) = requestOf(screen) ?: return CodeResult.STALE
        app.reach(request.server)?.let { return troubled(it) }
        tickRequest(request)
        if (request.unknownToServer) {
            swap(helpScreen(flow, request))
            return CodeResult.REQUEST_UNKNOWN
        }
        if (request.cancelledByServer && request.stage == OperatorHelpStage.CODE_NEEDED) {
            app.helpRequest = null
            reset(null)
            app.publish()
            return CodeResult.REQUEST_CANCELLED
        }
        val good = request.stage == OperatorHelpStage.CODE_NEEDED && request.codeMailed && request.wrongTries < 5 &&
            app.nowMs <= request.createdAtMs + 15 * FakeScript.MINUTE && code == app.script.emailCode
        if (!good) {
            request.wrongTries++
            return CodeResult.WRONG_CODE
        }
        request.stage = OperatorHelpStage.HOLDING
        request.verifiedAtMs = app.nowMs
        request.holdEndsAtMs = app.nowMs + 7 * FakeScript.DAY
        request.server.accounts[request.email]?.helpRequests?.add(request)
        swap(helpScreen(flow, request))
        CodeResult.DONE
    }

    override suspend fun refreshOperatorHelp(screen: EntryScreen.OperatorHelp): ServerResult = step(screen) {
        val (flow, request) = requestOf(screen) ?: return ServerResult.STALE
        app.reach(request.server)?.let { return troubled(it) }
        tickRequest(request)
        if (request.fulfilled && !answerHeld(request)) {
            // The answer must be signed by the recovery key the pinned card names, and match this request.
            if (request.answerForged) {
                request.stage = OperatorHelpStage.DID_NOT_CHECK_OUT
                swap(helpScreen(flow, request))
            } else {
                go(checkAccount(flow, request))
            }
        } else {
            swap(helpScreen(flow, request))
        }
        // As the engine: an operator's answer for an address this device knows under an earlier account offers the forgetting.
        if ((app.entryScreen as? EntryScreen.OperatorHelp)?.identityFault != null) raiseEarlier(request.server, request.email)
        ServerResult.DONE
    }

    override fun abandonOperatorHelp(screen: EntryScreen.OperatorHelp) {
        if (!on(screen)) return
        val offered = earlierOnShow()
        app.helpRequest = null
        reset(null)
        app.publish()
        // As the engine: the offer outlives the request it waited on, on the first screen.
        offered?.let { e -> app.entryScreen?.let { on -> earlier = offerOf(e.origin, e.instance, e.email, on, confirming = false); app.publish() } }
    }

    // ---- "Forget the earlier account on this device" (decided on 2026-11-17), as the engine plays it ----

    /** The offer, with the screen whose refusal raised it ([FakeScript.earlierAccountKnown]); null when none stands. */
    private var earlier: io.silencelen.andvari.core.app.EarlierAccountKnown? = null

    /** A forgetting failed part-way ([FakeScript.forgetFailsOnce]): the next tap finishes it. */
    private var forgettingBegun = false

    /** [io.silencelen.andvari.core.app.AppSnapshot.earlierAccount]. */
    internal fun earlierOnShow(): io.silencelen.andvari.core.app.EarlierAccountKnown? =
        earlier?.takeIf { app.phase == AppPhase.ENTRY && it.on === app.entryScreen }

    private fun offerOf(origin: String, label: io.silencelen.andvari.core.app.InstanceLabel, email: String, on: Any, confirming: Boolean): io.silencelen.andvari.core.app.EarlierAccountKnown {
        val copy = app.script.earlierCopyKept || app.script.earlierCopyHeld
        val norm = FakeText.emailNorm(email) ?: email.trim().lowercase()
        // As the engine: the account offered is never open here, so what it would lose unsent cannot be told where its data is
        // held here; elsewhere (no copy, or a kept copy whose data is not held) it is its signed changes to shared vaults
        // waiting here, which the forgetting removes.
        val unsent = if (copy && (app.script.earlierCopyHeld || app.script.earlierCopyUnsent != 0)) null else app.script.earlierSharedChangesUnsent
        // The earlier account back under its own key: the account offered is the one the address names now, the new one.
        val back = app.script.earlierBackUnderOwnKey
        return io.silencelen.andvari.core.app.EarlierAccountKnown(email.trim(), label, copy, unsent, confirming,
            origin, norm, if (back) "new:$norm" else "earlier:$norm", on, if (back) "earlier:$norm" else "served:$norm")
    }

    /**
     * The identity fault just said, for [email] at [server], is the keeper's for an earlier account ([FakeScript.earlierAccountKnown]):
     * offered on the screen on show, unless the server serves that very account under another key ([sameAccount], as the engine).
     */
    private fun raiseEarlier(server: FakeServer, email: String, sameAccount: Boolean = app.script.sameAccountOtherKey) {
        if (!(app.script.earlierAccountKnown || app.script.earlierBackUnderOwnKey) || sameAccount) return
        val on = app.entryScreen ?: return
        earlier = offerOf(server.origin, app.label(server), email, on, confirming = false)
        app.publish()
    }

    /**
     * As the engine: a lock between the two steps takes the confirmation back. Not where the lock goes to the lock screen
     * (a kit on show in the journey for a kept session): the engine drops the journey's screens there instead, and the offer
     * is not on show.
     */
    fun lockedDuringEntry() {
        if (app.session?.kit?.inEntry == true && app.storedSession != null) return
        val e = earlier?.takeIf { it.confirming } ?: return
        earlier = offerOf(e.origin, e.instance, e.email, e.on, confirming = false)
        app.publish()
    }

    override fun askToForgetEarlierAccount(offer: io.silencelen.andvari.core.app.EarlierAccountKnown): Boolean {
        if (earlierOnShow() !== offer || offer.confirming) return false
        if (app.script.addressTiedToServed) {
            // As the engine: the address is tied now to the account served, so no offer stands.
            earlier = null
            app.publish()
            return false
        }
        earlier = offerOf(offer.origin, offer.instance, offer.email, offer.on, confirming = true)
        app.publish()
        return true
    }

    override fun keepEarlierAccount(offer: io.silencelen.andvari.core.app.EarlierAccountKnown) {
        if (earlierOnShow() !== offer) return
        earlier = if (offer.confirming) offerOf(offer.origin, offer.instance, offer.email, offer.on, confirming = false) else null
        app.publish()
    }

    override suspend fun forgetEarlierAccount(confirmation: io.silencelen.andvari.core.app.EarlierAccountKnown): io.silencelen.andvari.core.app.ForgetEarlierResult {
        if (earlierOnShow() !== confirmation) return io.silencelen.andvari.core.app.ForgetEarlierResult.STALE
        if (!confirmation.confirming) return io.silencelen.andvari.core.app.ForgetEarlierResult.NOT_CONFIRMED
        if (app.script.addressTiedToServed) {
            // As the engine: the address is tied now to the very account the server served; nothing is forgotten, no offer stands.
            earlier = null
            app.publish()
            return io.silencelen.andvari.core.app.ForgetEarlierResult.ADDRESS_NOW_THE_SERVED_ACCOUNT
        }
        // A forgetting that failed part-way is finished by this tap, and said as forgotten (as the engine).
        val finishing = forgettingBegun
        // The copy or its count changed since the confirmation was shown ([FakeScript.earlierCopyKept] set meanwhile).
        val now = offerOf(confirmation.origin, confirmation.instance, confirmation.email, confirmation.on, confirming = true)
        if (!finishing && (confirmation.keptCopy != now.keptCopy || confirmation.unsentChanges != now.unsentChanges)) {
            earlier = now
            app.publish()
            return io.silencelen.andvari.core.app.ForgetEarlierResult.NOT_CONFIRMED
        }
        if (!finishing && app.script.forgetFailsOnce) {
            // As the engine with a store that fails after the keeper forgot: the call throws, the second step stays on show.
            app.script.forgetFailsOnce = false
            forgettingBegun = true
            app.script.earlierAccountKnown = false
            throw IllegalStateException("the device's store failed while the earlier account was being deleted")
        }
        val r = if (finishing) io.silencelen.andvari.core.app.ForgetEarlierResult.FORGOTTEN else app.script.forgetAnswer
        forgettingBegun = false
        earlier = when (r) {
            io.silencelen.andvari.core.app.ForgetEarlierResult.UNDER_WAY, io.silencelen.andvari.core.app.ForgetEarlierResult.REQUEST_KEPT ->
                offerOf(confirmation.origin, confirmation.instance, confirmation.email, confirmation.on, confirming = false)
            else -> null
        }
        // As the engine: no record ties the address to an account (nothing to forget), or the account is the one kept here
        // (open): no offer is made again for it.
        if (r == io.silencelen.andvari.core.app.ForgetEarlierResult.NOTHING_TO_FORGET || r == io.silencelen.andvari.core.app.ForgetEarlierResult.ACCOUNT_OPEN) {
            app.script.earlierAccountKnown = false
        }
        if (r == io.silencelen.andvari.core.app.ForgetEarlierResult.FORGOTTEN) {
            // The device no longer knows the earlier account, nor keeps or holds a copy of it, nor its signed changes to shared
            // vaults; the next account taken under the address at that server is said once.
            app.script.earlierAccountKnown = false
            app.script.earlierSharedChangesUnsent = 0
            app.script.earlierBackUnderOwnKey = false
            app.script.earlierCopyKept = false
            app.script.earlierCopyHeld = false
            app.rememberAfterForgetting(confirmation.origin, confirmation.email)
            // As the engine: a sign-in whose code step was refused stands at its password step again.
            (confirmation.on as? EntryScreen.SignIn)?.takeIf { it.codeNeeded && it === app.entryScreen }?.let { s ->
                flowOf(s)?.let { f ->
                    f.codeFor = null
                    app.entryScreen = EntryScreen.SignIn(f, s.prompt, codeNeeded = false)
                }
            }
        }
        app.publish()
        return r
    }

    /** Where a request stands by the clock: the code's day, the 7-day hold, the 30 days after it. */
    private fun tickRequest(request: FakeHelpRequest) {
        when (request.stage) {
            OperatorHelpStage.CODE_NEEDED -> if (app.nowMs > request.createdAtMs + FakeScript.DAY) request.stage = OperatorHelpStage.EXPIRED
            OperatorHelpStage.HOLDING -> if (app.nowMs >= request.holdEndsAtMs) request.stage = OperatorHelpStage.AWAITING_OPERATOR
            OperatorHelpStage.AWAITING_OPERATOR ->
                if (!request.fulfilled && app.nowMs > request.holdEndsAtMs + 30 * FakeScript.DAY) request.stage = OperatorHelpStage.EXPIRED
            else -> Unit
        }
        if (request.stage == OperatorHelpStage.EXPIRED || request.stage == OperatorHelpStage.VETOED) {
            request.server.accounts[request.email]?.helpRequests?.remove(request)
        }
    }

    /** Time passed: a device link's step may have run out, and a request for help may have moved on. */
    fun tick() {
        val shown = app.entryScreen
        val found = if (claimed(shown) && shown != null) flowOf(shown)?.link else null
        if (found != null && found.expiresAtMs <= app.nowMs) endLink(LinkDeviceEnd.EXPIRED)
        app.helpRequest?.let(::tickRequest)
        refresh()
    }
}
