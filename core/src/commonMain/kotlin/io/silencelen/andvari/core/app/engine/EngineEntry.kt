package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AddressMismatchFor
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AskOperatorResult
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.DeviceLinkScanResult
import io.silencelen.andvari.core.app.EntryApi
import io.silencelen.andvari.core.app.EntryFlow
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.FirstRunNotice
import io.silencelen.andvari.core.app.ForgetEarlierResult
import io.silencelen.andvari.core.client.session.ForgetEarlier
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.InviteResult
import io.silencelen.andvari.core.app.JoinMode
import io.silencelen.andvari.core.app.KitReason
import io.silencelen.andvari.core.app.KitRecoverResult
import io.silencelen.andvari.core.app.KitScanResult
import io.silencelen.andvari.core.app.InstanceLabel
import io.silencelen.andvari.core.app.RecoveryRoute
import io.silencelen.andvari.core.app.ServerKind
import io.silencelen.andvari.core.app.LinkDeviceEnd
import io.silencelen.andvari.core.client.devicelink.DeviceLinkStop
import io.silencelen.andvari.core.client.devicelink.DeviceLinkToken
import io.silencelen.andvari.core.client.devicelink.NewStep
import io.silencelen.andvari.core.client.link.LinkStop
import io.silencelen.andvari.core.client.link.RecipientStep
import io.silencelen.andvari.core.app.OperatorHelpStage
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.client.recovery.AssistedStep
import io.silencelen.andvari.core.client.recovery.KeptAssistRequests
import io.silencelen.andvari.core.client.recovery.KitRecoveryStep
import io.silencelen.andvari.core.client.recovery.WireAssistedRecovery
import io.silencelen.andvari.core.client.recovery.WireKitRecovery
import io.silencelen.andvari.core.model.wire.RecoveryRequestState
import io.silencelen.andvari.core.app.LinkPasswordResult
import io.silencelen.andvari.core.app.MasterPasswordPrompt
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.OperatorRecoveryWarning
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.RecoveryQuestion
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
import io.silencelen.andvari.core.client.account.Fetched
import io.silencelen.andvari.core.client.onboard.OperatorRecoveryOffer
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.RegistrationForm
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.onboard.SignupOffer
import io.silencelen.andvari.core.client.onboard.SignupStart
import io.silencelen.andvari.core.client.onboard.SignupVerify
import io.silencelen.andvari.core.client.pin.CardStatus
import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.pin.GateDecision
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.client.pin.GateInput
import io.silencelen.andvari.core.client.pin.GatePurpose
import io.silencelen.andvari.core.client.pin.PasswordGate
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.client.pin.TrustGateWording
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.trust.DeviceLinkUrl
import io.silencelen.andvari.core.trust.LinkUrl
import io.silencelen.andvari.core.trust.RecoveryKit
import io.silencelen.andvari.core.trust.TrustGrammar
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/**
 * The binding's [EntryFlow]: one origin, and what the steps of a flow there hold. A screen made in a flow keeps it
 * for good and its intents read nothing else, so nothing typed on a screen can reach another origin than the one the
 * screen names.
 */
internal class EngineFlow(override val origin: String) : EntryFlow() {
    /** The Trust Gate of this flow, and what confirming it goes on with; null when none stands. */
    var gate: FirstPin.NeedsTrustGate? = null
    var afterGate: (suspend () -> ServerResult)? = null

    // sign-up
    var signUpEmail: String = ""
    var signUpAge: Boolean = false

    /** The server's policy asks for a proof of work before a code is sent (§7.5). */
    var signUpPow: Boolean = false
    var ticket: SignupVerify.Ticket? = null
    var recoveryOffer: OperatorRecoveryOffer? = null

    /** A two-step sign-in waiting for its code: the engine's step, and the address it is for. */
    var pendingCode: SignIn.TotpRequired? = null
    var pendingEmail: String = ""

    /** The password of that sign-in, kept only for a kit that turns out never to have been saved, and wiped with the step. */
    var pendingPassword: CharArray? = null

    /**
     * When [pendingPassword] stops being kept: the two-step key's ten minutes from the code
     * step. A lock wipes it at once.
     */
    var pendingPasswordUntilMs: Long = 0L

    fun wipePassword() {
        pendingPassword?.fill('\u0000')
        pendingPassword = null
        pendingPasswordUntilMs = 0L
    }

    /**
     * A kit recovery's step held by this flow (`ConfirmTarget`, `OriginMismatch` or `ChoosePassword`): the engine
     * keeps the kit's secret behind it until it is used or cancelled.
     */
    var kitStep: KitRecoveryStep? = null

    /** The kit was typed by hand (its Trust Gate says so, and an address mismatch is a typed kit's). */
    var kitTyped: Boolean = false

    /**
     * A request for an operator's help (§9.3): the engine's last step and the address it was made with. Leaving the
     * screens drops only the step: the request stays kept on this device until it is abandoned, rejected or ends.
     */
    var assistStep: io.silencelen.andvari.core.client.recovery.AssistedStep? = null
    var assistEmail: String = ""

    /**
     * A setup link's flow (§6.7, §9.5, desktop only): the server's name as its setup offer gives it, shown self-named
     * until card 0 is pinned. [setupKept]: opening it kept the offer in device state (§6.7 step 2); a flow that ends
     * with no account made drops it again. [setupKit]: the new operator account's kit, held behind the server setup
     * screen until the person goes on to it, and wiped with the flow (a lock included).
     */
    var setupLabel: io.silencelen.andvari.core.app.InstanceLabel? = null
    var setupKept: Boolean = false
    var setupRegistered: Boolean = false
    var setupKit: io.silencelen.andvari.core.client.onboard.RevealedKit? = null

    /**
     * A device link linking this device (§8.2, new device): the engine's last step, and the poll that advances it
     * while it waits on the other device. The engine holds the link's keys behind the step until it ends or is
     * cancelled; a flow left behind cancels it.
     */
    var linkStep: io.silencelen.andvari.core.client.devicelink.NewStep? = null
    var linkPoll: kotlinx.coroutines.Job? = null

    /**
     * An invite opened signed out (§6.8): the link engine's step this flow waits on (its Trust Gate, or the `Confirm`
     * a registration or a sign-up goes on from). A flow left behind dismisses it, which drops a pin it made.
     */
    var invite: io.silencelen.andvari.core.client.link.RecipientStep? = null
}

/**
 * The signed-out journey (§12.1) over the engine: the server choice and the Trust Gate ([io.silencelen.andvari.core.client.pin.InstanceTrust]),
 * sign-up and registration by a verified address and sign-in ([io.silencelen.andvari.core.client.onboard.WireOnboarding]),
 * the kit before the vault opens ([EngineKit]), kit recovery, and linking this device (the device-link engine's
 * new-device side, polled in the API's scope while it waits on the other device).
 *
 * Invites opened signed out go through the link engine's recipient checks ([EngineAppApi.entryLinks]), and register
 * and enrol links register through it. Bound in a later slice, and answering [Trouble.FAILED] until then: a setup
 * link's registration (card 0 on a computer), the connection a connect link asks for once the account is open, and
 * the operator's help. Each of their scanners already refuses the other two
 * kinds of payload, so nothing is started from the wrong screen.
 */
internal class EngineEntry(private val app: EngineAppApi) : EntryApi {
    private val stack = ArrayList<EntryScreen>()
    private var screen: EntryScreen? = null
    private var kitShown: EntryScreen.Kit? = null

    /** What the first screen says once. */
    private var notice: FirstRunNotice? = null

    private var publicSignup: SignupStatus = notKnown()

    /** The screen on show: the kit's while one is on show in the journey. */
    val shown: EntryScreen?
        get() {
            val k = app.kitFlow.entryScreen ?: return screen
            val origin = app.kitFlow.entryOrigin ?: return screen
            val cached = kitShown
            if (cached != null && cached.kit === k) return cached
            // The kit's screen belongs to the server of the account it is for.
            val flow = (cached?.flow as? EngineFlow)?.takeIf { it.origin == origin } ?: EngineFlow(origin)
            return EntryScreen.Kit(flow, k).also { kitShown = it }
        }

    // ---- plumbing ----

    private fun on(s: EntryScreen): Boolean = app.phase == AppPhase.ENTRY && shown === s

    private fun flowOf(s: EntryScreen): EngineFlow? = s.flow as? EngineFlow

    private fun go(next: EntryScreen) {
        screen?.let { stack += it }
        screen = next
        app.publish()
    }

    private fun swap(next: EntryScreen) {
        screen = next
        app.publish()
    }

    /** Leave the screen on show for the one before it (the first screen when there is none). The caller publishes. */
    private fun pop() {
        val left = screen
        screen = if (stack.isEmpty()) firstRun() else stack.removeAt(stack.size - 1)
        leftBehind(left)
    }

    /** [left] went off screen: when no screen of its flow is left in the journey, what the flow held is wiped. */
    private fun leftBehind(left: EntryScreen?) {
        val f = left?.flow as? EngineFlow ?: return
        if (screen?.flow === f || stack.any { it.flow === f }) return
        abandon(f)
    }

    /** A flow nothing came of ends: its gate, its ticket and the keys of a sign-in waiting for a code are dropped. */
    private fun abandon(f: EngineFlow) {
        f.pendingCode?.let { app.onboardingFor(f.origin).cancelSignIn(it) }
        f.pendingCode = null
        f.wipePassword()
        f.gate = null
        f.afterGate = null
        // A registration's ticket left behind is left at the engine too: its hold on the address ends with it, so that a
        // forgetting of an earlier account under that address is not refused as "something is under way" afterwards.
        leaveTicket(f)
        f.recoveryOffer = null
        // A kit recovery left behind drops the kit's secret and the pin it made.
        f.kitStep?.let { app.kitRecovery.cancel(it) }
        f.kitStep = null
        // A device link left behind stops polling and is cancelled: the engine forgets its keys, and the link is deleted.
        f.linkPoll?.cancel()
        f.linkPoll = null
        f.linkStep?.let(::linkToken)?.let { t -> app.scope.launch { app.deviceLinks.cancel(t) } }
        f.linkStep = null
        // An invite nothing came of: the link engine ends its flow, wipes the link's secret and drops a pin it made.
        f.invite?.let(app.entryLinks::dismiss)
        f.invite = null
        // A request for an operator's help stays kept (it must outlive the 7-day hold); only this flow's step goes, and with it
        // whatever of the operator's answer was opened for it (the delivered key and commit value never
        // outlive the screens they were opened for; the next look opens and checks the answer again).
        f.assistStep?.let(app.assisted::setAside)
        f.assistStep = null
        // A setup's kit goes with its flow; an offer kept for a setup that made no account goes too (a registered one
        // stays for "Finish setting up this server", §6.7 Resume).
        f.setupKit?.wipe()
        f.setupKit = null
        if (f.setupKept && !f.setupRegistered) io.silencelen.andvari.core.client.onboard.SetupOffers(app.engine.state).remove(f.origin)
        f.setupKept = false
    }

    /** [f]'s registration ticket, if it holds one, is given up at the engine (its hold on the address ends) and dropped. */
    private fun leaveTicket(f: EngineFlow) {
        val t = f.ticket ?: return
        f.ticket = null
        app.onboardingFor(f.origin).leaveSignup(t)
    }

    /**
     * An account was opened on [f]'s server (a registration, or a sign-in from an invite): its invite is settled, not
     * dismissed, so its flow keeps the pin the account now stands on whatever ends it. A connect link's settled step
     * (only its answer key is kept) is held for the account to answer once it is open
     * ([EngineAppApi.connectAfterEntry]); any other link's flow ends here.
     */
    private fun inviteUsed(f: EngineFlow) {
        val step = f.invite as? RecipientStep.Confirm
        f.invite = null
        if (step != null) app.entryLinks.settle(step)?.let { app.connectAfterEntry = it }
    }

    private fun firstRun(): EntryScreen.FirstRun =
        EntryScreen.FirstRun(publicSignup, app.takesSetupLinks, operatorHelpWaiting = app.assisted.keptOrigins().isNotEmpty(),
            offersPublicInstance = app.engine.baked != null, notice = notice, accountDeleted = accountDeleted,
            deletionOutcomeUnknown = deletionUnknown, heldAsOperator = app.heldAsOperator(), lateRecovery = lateRecovery,
            sessionNotConfirmed = sessionNotConfirmed)

    /** What a recovery the person left came to, said on the first screen until dismissed (it outlives a [reset]). */
    private var lateRecovery: io.silencelen.andvari.core.app.LateRecoveryNotice? = null

    /**
     * The engine published what a recovery's commit came to after the person left it: kept for
     * the first screen, the newest replacing an older one, and the first screen republished when it is on show.
     */
    fun lateOutcome(o: io.silencelen.andvari.core.client.recovery.LateRecoveryOutcome) {
        val via = if (o.via == io.silencelen.andvari.core.client.recovery.LateRecoveryOutcome.Via.KIT) RecoveryRoute.KIT else RecoveryRoute.OPERATOR_HELP
        val result = when (o.result) {
            io.silencelen.andvari.core.client.recovery.LateRecoveryOutcome.Result.RESET -> io.silencelen.andvari.core.app.LateRecoveryResult.RESET
            io.silencelen.andvari.core.client.recovery.LateRecoveryOutcome.Result.REFUSED -> io.silencelen.andvari.core.app.LateRecoveryResult.REFUSED
            io.silencelen.andvari.core.client.recovery.LateRecoveryOutcome.Result.UNKNOWN -> io.silencelen.andvari.core.app.LateRecoveryResult.UNKNOWN
        }
        lateRecovery = io.silencelen.andvari.core.app.LateRecoveryNotice(o.email, labelOf(o.origin), via, result)
        // The first screen says it wherever it is: on show, or under the journey the person is on now.
        if (screen is EntryScreen.FirstRun) screen = firstRun()
        for (i in stack.indices) if (stack[i] is EntryScreen.FirstRun) stack[i] = firstRun()
        app.publish()
    }

    override suspend fun removeHeldOperatorAccount(account: io.silencelen.andvari.core.app.HeldOperatorAccount): io.silencelen.andvari.core.app.PlainResult =
        app.removeHeldOperatorAccount(account)

    /** The account this device just deleted, said once on the first screen beside [notice]. */
    private var accountDeleted: io.silencelen.andvari.core.app.AccountDeletedNotice? = null

    /** The account whose deletion's outcome is unknown, said on the first screen beside [notice] until dismissed. */
    private var deletionUnknown: io.silencelen.andvari.core.app.DeletionOutcomeUnknownNotice? = null

    /**
     * Back to the first screen, which says [notice] when given, [deleted] (an account this device just deleted) when
     * given, and [unknown] (a deletion whose outcome is unknown) when given; nothing of an abandoned journey is left.
     * The caller publishes.
     */
    fun reset(
        notice: FirstRunNotice?, deleted: io.silencelen.andvari.core.app.AccountDeletedNotice? = null,
        unknown: io.silencelen.andvari.core.app.DeletionOutcomeUnknownNotice? = null,
        notConfirmed: Boolean = false,
    ) {
        drop()
        this.notice = notice
        this.accountDeleted = deleted
        this.deletionUnknown = unknown
        this.sessionNotConfirmed = notConfirmed
        screen = firstRun()
    }

    /** [EntryScreen.FirstRun.sessionNotConfirmed], said once until the dismiss. */
    private var sessionNotConfirmed = false

    /** Wipe what the journey's flows hold, and forget the journey. */
    fun drop() {
        (stack + listOfNotNull(screen, kitShown)).mapNotNull { it.flow as? EngineFlow }.distinct().forEach(::abandon)
        stack.clear()
        screen = null
        kitShown = null
    }

    /**
     * The host locked during the journey: a password kept at a code step goes now. A sign-in's
     * code step goes with it (the engine's derived keys too), and the password form is shown again.
     */
    fun locked() {
        // A lock between the two steps of the forgetting takes the confirmation back: nothing is forgotten, and the offer is
        // at its first step again.
        earlier?.takeIf { it.confirming }?.let { e ->
            earlier = app.earlierOffer(e.origin, e.email, e.on, confirming = false, e.servedUserId)
            app.publish()
        }
        val s = screen
        val flow = s?.flow as? EngineFlow ?: return
        if (flow.pendingCode != null && s is EntryScreen.SignIn) {
            cancelPendingCode(flow)
            if (s.codeNeeded) swap(EntryScreen.SignIn(flow, s.prompt, codeNeeded = false))
        }
        flow.wipePassword()
    }

    /** A lock wiped the kit that was on show: with no screen under it, the journey is at its first screen. */
    fun afterKitWiped() {
        // The first screen keeps its mark of a kept session not confirmed (until it is dismissed), so that line and the
        // notice of the wiped kit stand side by side.
        if (screen == null) reset(null, notConfirmed = sessionNotConfirmed)
    }

    /** The vault opened, or a kit took the journey over: the screens before it are gone. */
    fun leave() {
        drop()
    }

    /** Fetch what the public instance says about new accounts, for the first screen (a hint; the server enforces). */
    fun refreshPublicSignup() {
        val baked = app.engine.baked ?: return
        app.scope.launch {
            val offer = app.onboardingFor(baked.origin).signupOffer()
            if (offer is Fetched.Ok) notePublicSignup(status(offer.value))
        }
    }

    /** What the public instance says now: the first screen is republished only when it says something else. */
    private fun notePublicSignup(now: SignupStatus) {
        val before = publicSignup
        if (before.mode == now.mode && before.full == now.full && before.ageConfirmRequired == now.ageConfirmRequired && before.proofOfWork == now.proofOfWork) return
        publicSignup = now
        if (screen is EntryScreen.FirstRun && app.phase == AppPhase.ENTRY) {
            screen = firstRun()
            app.publish()
        }
    }

    private suspend inline fun <reified R> step(s: EntryScreen, body: () -> R): R where R : Enum<R>, R : IntentResult {
        if (!on(s)) return troubleOf(Trouble.STALE)
        // A new try on the screen takes the offer of an earlier refusal away; a refusal of the same kind raises it again.
        earlier = null
        return app.working(body)
    }

    // ---- "Forget the earlier account on this device" (decided on 2026-11-17) ----

    /** The offer of the forgetting, with the screen whose refusal raised it; null when none stands. */
    private var earlier: io.silencelen.andvari.core.app.EarlierAccountKnown? = null

    /** [io.silencelen.andvari.core.app.AppSnapshot.earlierAccount]: the offer, while the screen it was raised on is on show. */
    internal fun earlierOnShow(): io.silencelen.andvari.core.app.EarlierAccountKnown? {
        val e = earlier ?: return null
        return e.takeIf { app.phase == AppPhase.ENTRY && it.on === shown }
    }

    /**
     * The flow of the screen on show was refused by the session keeper's own reason for an address it knows under another
     * account ([SELF_IDENTITY_MISMATCH]) for [email] at [origin], the server serving [served], ANOTHER account (by id) than
     * the one the address is tied to, as the keeper told it: the offer is raised on that screen, when the device does
     * remember an earlier account under the address that it does not keep open, elsewhere or as the operator's
     * ([EngineAppApi.earlierOffer]). [served] null (the same account under another key, or a cause that cannot be told):
     * nothing is raised. Publishes.
     */
    private fun raiseEarlier(origin: String, email: String, served: String?) {
        val on = shown ?: return
        if (served == null) return
        earlier = app.earlierOffer(origin, email, on, confirming = false, served)
        app.publish()
    }

    override fun askToForgetEarlierAccount(offer: io.silencelen.andvari.core.app.EarlierAccountKnown): Boolean {
        if (earlierOnShow() !== offer || offer.confirming) return false
        // Counted now, as a sign-out counts: the confirmation says what holds when it is shown.
        earlier = app.earlierOffer(offer.origin, offer.email, offer.on, confirming = true, offer.servedUserId)?.takeIf { it.earlierUserId == offer.earlierUserId }
        app.publish()
        return earlier != null
    }

    override fun keepEarlierAccount(offer: io.silencelen.andvari.core.app.EarlierAccountKnown) {
        if (earlierOnShow() !== offer) return
        earlier = if (offer.confirming) app.earlierOffer(offer.origin, offer.email, offer.on, confirming = false, offer.servedUserId) else null
        app.publish()
    }

    override suspend fun forgetEarlierAccount(confirmation: io.silencelen.andvari.core.app.EarlierAccountKnown): ForgetEarlierResult {
        if (earlierOnShow() !== confirmation) return ForgetEarlierResult.STALE
        if (!confirmation.confirming) return ForgetEarlierResult.NOT_CONFIRMED
        // The address is tied now to the very account the server served: nothing is forgotten for it, and no offer stands
        // (as for a confirmation that no longer holds).
        if (app.keeper.addressBinding(confirmation.origin, confirmation.emailNorm)?.userId == confirmation.servedUserId) {
            earlier = null
            app.publish()
            return ForgetEarlierResult.ADDRESS_NOW_THE_SERVED_ACCOUNT
        }
        // What the confirmation said must hold still: the same earlier account, the same copy, the same count. Otherwise the
        // confirmation is shown again with what holds now, and nothing is forgotten.
        val now = app.earlierOffer(confirmation.origin, confirmation.email, confirmation.on, confirming = true, confirmation.servedUserId)
        if (now != null && (now.earlierUserId != confirmation.earlierUserId || now.keptCopy != confirmation.keptCopy || now.unsentChanges != confirmation.unsentChanges)) {
            earlier = now
            app.publish()
            return ForgetEarlierResult.NOT_CONFIRMED
        }
        val result = when (app.forgetEarlier(confirmation.origin, confirmation.emailNorm, confirmation.email, confirmation.earlierUserId)) {
            is ForgetEarlier.Forgotten -> ForgetEarlierResult.FORGOTTEN
            // The address came to name another account before the keeper's call: the confirmation no longer holds.
            // Where that account is the very one the server serves, nothing is left to confirm: said so (no offer stands then).
            ForgetEarlier.NoLongerHolds ->
                if (app.keeper.addressBinding(confirmation.origin, confirmation.emailNorm)?.userId == confirmation.servedUserId) {
                    ForgetEarlierResult.ADDRESS_NOW_THE_SERVED_ACCOUNT
                } else {
                    ForgetEarlierResult.NOT_CONFIRMED
                }
            ForgetEarlier.NothingToForget -> ForgetEarlierResult.NOTHING_TO_FORGET
            ForgetEarlier.OpenForThatAccount -> ForgetEarlierResult.ACCOUNT_OPEN
            // A request for the operator's help kept at that server holds the address for as long as it is kept: said only
            // when the kept request is for this address (it holds no other); otherwise as any flow under way.
            ForgetEarlier.FlowUnderWay ->
                if (app.keptRequestEmail(confirmation.origin)?.let { io.silencelen.andvari.core.trust.TrustGrammar.emailNorm(it) } == confirmation.emailNorm) {
                    ForgetEarlierResult.REQUEST_KEPT
                } else {
                    ForgetEarlierResult.UNDER_WAY
                }
        }
        earlier = when (result) {
            // Refused for now: the offer stays, at its first step.
            ForgetEarlierResult.UNDER_WAY, ForgetEarlierResult.REQUEST_KEPT ->
                app.earlierOffer(confirmation.origin, confirmation.email, confirmation.on, confirming = false, confirmation.servedUserId)
            // As for a confirmation that no longer holds above: shown again with what holds now, or none.
            ForgetEarlierResult.NOT_CONFIRMED ->
                app.earlierOffer(confirmation.origin, confirmation.email, confirmation.on, confirming = true, confirmation.servedUserId)
            else -> null
        }
        // Forgotten on a sign-in's code screen: its code step was refused with the identity fault and is gone, so the sign-in
        // stands at its password step again ("try again to go on" never meets a stale code step).
        if (result == ForgetEarlierResult.FORGOTTEN) {
            (confirmation.on as? EntryScreen.SignIn)?.takeIf { it.codeNeeded && it === screen }?.let { s ->
                flowOf(s)?.let { f ->
                    cancelPendingCode(f)
                    screen = EntryScreen.SignIn(f, s.prompt, codeNeeded = false)
                }
            }
        }
        app.publish()
        return result
    }

    /** What an entry intent's engine call came to. */
    private sealed class Called<out T> {
        class Answered<T>(val value: T) : Called<T>()

        /**
         * The screen it was made for is no longer on show, or the app left the entry: whatever it established is ended.
         * [late] is the answer that came too late, for the caller to release what it holds. [refused]: the screen is
         * still on show, and the keeper refused the session it established because another account is kept here.
         */
        class Left<T>(val late: T, val refused: Boolean = false, val identity: Boolean = false) : Called<T>()

        /** The server did not answer within [EngineAppApi.entryCallMs]: whatever it established is ended. */
        data object TimedOut : Called<Nothing>()

        /**
         * The keys the call held were wiped under it, because the person left (the flow's keys go with the screen) or a
         * lock came: it stopped there, refused by the key floor or the account's guard, and sent nothing more. STALE.
         */
        data object Overtaken : Called<Nothing>()
    }

    /**
     * An entry call that may establish a session and waits on a server (sign-in, its code, registration, a device link's
     * pickup, a kit recovery's commit): with a time limit, and [screen] checked again once it answered. When the
     * person left meanwhile, or it ran out of time, the session it established (if the keeper still holds it) ends on
     * this device at once and its logout goes to its own origin through the guard; a session the keeper refused (another
     * one is kept) counts as left too. A late answer never completes. When that session had replaced a kept record of
     * the same account (signed out by its server), the record is put back as it was instead:
     * a left sign-in never costs a kept account, [io.silencelen.andvari.core.client.session.SessionKeeper.endTakenSince].
     *
     * [refusedHere]: for an answer that carries the keeper's own verdict on THIS call's session (a recovery's or a
     * registration's commit, whose `notKept` is the keeper's reason or null when it took the session), whether the keeper
     * refused it; null when the answer does not say. Where the answer says, a refusal of some other session while this
     * call ran (two flows establishing at once) neither makes this call's taken session "refused" nor its kit stale.
     * A commit's answer that carries no session of its own (a stop, also one after the commit: a fault while opening, or
     * "may have landed") holds no keeper refusal of this call's session, and says false: such an answer is never turned
     * into "stale" by a refusal elsewhere. Where the answer cannot say (null), any refusal during the call counts.
     */
    private suspend fun <T> call(screen: EntryScreen, refusedHere: (T) -> Boolean? = { null }, body: suspend () -> T): Called<T> {
        val keeper = app.keeper
        val mark = keeper.takes
        val refused = keeper.refusals
        val identityRefused = keeper.identityRefusals
        val origin = flowOf(screen)?.origin
        var overtaken = false
        val r = try {
            withTimeoutOrNull(app.entryCallMs) { Called.Answered(body()) }
        } catch (e: io.silencelen.andvari.core.crypto.KeysGoneException) {
            // The keys this call held were wiped under it, and the engine stopped before sealing, signing
            // or sending anything more:
            // - A lock (the app locked itself while the server held an answer): a registration's session was open, its
            //   recovery record or card 0 was still to be written. The session stays kept, locked; the next unlock goes
            //   on from it (an unconfirmed kit asks for a new one first).
            // - The person left: a kit recovery's commit whose recovered key went with the flow, its late answer's
            //   opening refused by the key floor. Whatever it established ends, as for any call the person left.
            // A refusal with the screen still on show and nothing locked is a fault, and is thrown.
            if (app.phase == AppPhase.LOCKED) return Called.Overtaken
            if (on(screen) && app.phase == AppPhase.ENTRY) throw e
            overtaken = true
            null
        }
        val refusedNow = r?.let { refusedHere(it.value) } ?: (keeper.refusals != refused)
        if (r != null && on(screen) && !refusedNow) return r
        // Only this call's own session: one the keeper refused was never kept, and one taken meanwhile at another
        // address (the person moved on) is not this call's.
        val mine = !refusedNow && origin != null && keeper.session?.origin == origin
        if (mine) keeper.endTakenSince(mark)?.let { logout ->
            app.scope.launch { logout() }
            app.publish()
        }
        return if (overtaken) Called.Overtaken
        else if (r == null) Called.TimedOut
        else Called.Left(r.value, refused = refusedNow && on(screen), identity = keeper.identityRefusals != identityRefused && on(screen))
    }

    /**
     * A recovery's commit the server took, whose session the keeper then refused for [reason]: the keeper's own reason, as
     * the engine hands it up with the new kit (`Recovered.notKept`), never one guessed from addresses. Every one of these
     * results says what is so after a commit: the new master password is in force and the old kit no longer works; the
     * new kit is on show with it.
     */
    private fun committedNotKept(reason: String): ReplacePasswordResult = io.silencelen.andvari.core.app.KeeperReasons.committedRecovery(reason)

    /**
     * What a recovery's commit that came back as [Called.Left] without a kit the keeper refused is said as: the trouble of
     * a call the person left (or one that ran out of time). Nothing here says another account is kept: only the keeper's
     * own reason, handed up with the kit, says why a session was refused.
     */
    /**
     * A recovery's commit the server took, whose answer this device could not open the account from (a fault while
     * opening: the engine ended that session unkept, [CommitWatch]): the new master password is in force and the old kit
     * no longer works, and no new kit could be shown. Back to the first screen; never "nothing was committed".
     */
    private fun committedNotOpened(): ReplacePasswordResult {
        reset(null)
        app.publish()
        return ReplacePasswordResult.COMMITTED_NOT_OPENED
    }

    private fun lateRecoveryAnswer(c: Called<*>): ReplacePasswordResult =
        troubleOf(if (c is Called.TimedOut) Trouble.UNREACHABLE else Trouble.STALE)

    /**
     * Show [kit], handed up with the keeper's refusal after a commit the server took (a recovery's, or a registration's),
     * on the journey's kit screen with the line that fits [result]; once the person confirmed it, the kit is wiped and
     * the journey is back at the first screen, where the kept account can be signed out. Publishes. A first screen the
     * journey was reset to meanwhile with its notice (the end or sign-out of the account kept here) stands after the kit.
     * While it is on show, a mark at rest says only that a kit was on show for [email], so that a start after the app was
     * closed can say it is gone ([EngineAppApi.markNotKeptKit]).
     */
    private fun notKeptKit(kit: io.silencelen.andvari.core.client.onboard.RevealedKit, reason: KitReason, result: IntentResult, email: String, label: InstanceLabel, origin: String) {
        val line = io.silencelen.andvari.core.app.KeeperReasons.kitLine(result)
        app.kitFlow.showNotKept(kit, reason, line, email, label, origin) {
            app.markNotKeptKit(null)
            if (screen == null) reset(null)
            app.publish()
        }
        // Written once the kit is on show (nothing runs in between), so the mark knows whether it was published unseen.
        app.markNotKeptKit(EngineAppApi.KitMark(reason != KitReason.FIRST_KIT, email, line, whileAnotherKept = result in WHILE_ANOTHER_KEPT, origin = origin))
        drop()
        app.publish()
    }

    /** A late answer's result; [kept] for a session the keeper refused because another account is kept here. */
    private inline fun <reified R> lateAnswer(c: Called<*>, kept: R): R where R : Enum<R>, R : IntentResult =
        if (c is Called.Left && c.refused) kept
        else troubleOf(if (c is Called.TimedOut) Trouble.UNREACHABLE else Trouble.STALE)

    /**
     * Another account than the one at [origin] under [email] is kept on this device (signed out by its server, design
     * §4.4): the keeper would refuse the session, so nothing is sent. An address that is not one, or none, tells
     * nothing apart at the same origin; the keeper's own refusal ([Called.Left.refused]) is then the backstop.
     */
    /**
     * With the reason the keeper would give: [OPERATOR_ACCOUNT_HELD] for an account held here as its
     * server's operator (said as that, never as "another account is kept"), [ANOTHER_SESSION_KEPT] for another account
     * kept; null when nothing kept stands in the way.
     */
    private fun keptStop(origin: String, email: String?): String? {
        val kept = app.keeper.session ?: return null
        // An account held as its server's operator (the owner's decision of 2026-11-16) is opened by nothing here, the
        // same account's sign-in, link or recovery included: nothing is sent until the person removes it.
        if (kept.heldAsOperator) return OPERATOR_ACCOUNT_HELD
        if (kept.origin != origin) return ANOTHER_SESSION_KEPT
        val norm = email?.let(TrustGrammar::emailNorm) ?: return null
        return ANOTHER_SESSION_KEPT.takeIf { norm != kept.emailNorm }
    }

    // ---- mapping the engine's answers ----

    private fun notKnown() = SignupStatus(JoinMode.NOT_KNOWN, full = false, ageConfirmRequired = false, proofOfWork = false)

    private fun status(o: SignupOffer) = SignupStatus(
        mode = when (o.mode) {
            "open" -> JoinMode.ANYONE
            "links" -> JoinMode.INVITATION_ONLY
            "closed" -> JoinMode.CLOSED
            else -> JoinMode.NOT_KNOWN
        },
        full = o.full,
        ageConfirmRequired = o.ageConfirmRequired,
        proofOfWork = o.powBits > 0,
    )

    /** The trouble a refusal code names that any intent can have, after noting a `Retry-After`. */
    private fun common(code: String, retryAfter: Long?): Trouble? = when (code) {
        WireErrors.RATE_LIMITED -> {
            app.noteRetryAfter(retryAfter)
            Trouble.RATE_LIMITED
        }
        WireErrors.UPGRADE_REQUIRED -> Trouble.UPDATE_REQUIRED
        else -> null
    }

    /** An address as typed under "Use your own server" (§2.2): the scheme defaults to https; nothing else is guessed. */
    private fun typedOrigin(input: String): String? {
        var s = input.trim()
        if (!s.contains("://")) s = "https://$s"
        s = s.trimEnd('/')
        val scheme = s.substringBefore("://").lowercase()
        val rest = s.substringAfter("://").lowercase()
        val origin = "$scheme://$rest"
        return origin.takeIf { TrustGrammar.isOrigin(it) }
    }

    private fun gateInput(purpose: GatePurpose, origin: String, account: String?) =
        GateInput(purpose, GateEntry.SERVER_CHOICE, null, origin, account, app.trust.gatePins())

    /**
     * A pin of this device may serve a password on [origin] for [purpose] before any account is known: the gate says
     * proceed, or the pin is a setup pin (it serves only its operator account, which the sign-in asks again).
     */
    private fun vouchedFor(purpose: GatePurpose, origin: String): Boolean =
        PasswordGate.decide(gateInput(purpose, origin, null)) == GateDecision.PROCEED ||
            (purpose == GatePurpose.SIGN_IN && app.trust.pinFor(origin)?.root == PinRoot.SETUP)

    private fun blocked(origin: String): Boolean {
        val s = app.trust.pinState(origin)
        return s is PinState.Forked || s == PinState.Damaged
    }

    /**
     * [EntryScreen.ServerChanged] for [origin]: its card says what was found (a block, a move, a `kind` change, an
     * older chain), and the intents of that card act on that server. False when this device holds nothing to show.
     */
    private fun showServer(origin: String): Boolean {
        val on = screen
        if (on is EntryScreen.ServerChanged && on.flow?.origin == origin) return true
        val snapshot = app.instancePart.snapshot(origin) ?: return false
        go(EntryScreen.ServerChanged(EngineFlow(origin), snapshot))
        return true
    }

    /** The changed server on show was followed or accepted: back to where its flow began, to start it again. */
    fun serverSettled(origin: String) {
        val on = screen as? EntryScreen.ServerChanged ?: return
        if (on.flow?.origin != origin || app.phase != AppPhase.ENTRY) return
        pop()
    }

    /**
     * After a wait, the screen changes only while [asked] (the screen whose intent waited) is
     * still on show. False when the person left it: nothing is shown, and the caller answers STALE.
     */
    private fun stillOn(asked: EntryScreen?): Boolean = asked != null && on(asked)

    /**
     * What a first pin came to, for a flow that goes on with [then] once the origin is pinned. It is called after the
     * wait for [fp]: when the person left [asked] meanwhile, nothing is shown (a gate raised now would cover the screen
     * the person went to) and the answer is STALE.
     */
    private suspend fun firstPin(
        asked: EntryScreen,
        flow: EngineFlow,
        fp: FirstPin,
        mismatchFor: AddressMismatchFor,
        kitChanged: Boolean,
        then: suspend () -> ServerResult,
    ): ServerResult {
        val origin = flow.origin
        if (!stillOn(asked)) return ServerResult.STALE
        return when (fp) {
            is FirstPin.Pinned -> then()
            is FirstPin.NeedsTrustGate -> {
                raiseGate(flow, fp, kitChanged, then)
                ServerResult.DONE
            }
            is FirstPin.KitAnchorMismatch -> {
                raiseGate(flow, fp.gate, true, then)
                ServerResult.DONE
            }
            is FirstPin.Refused -> when {
                fp.reason != "withheld" -> ServerResult.CARD_NOT_ACCEPTED
                // No card at all, and no pin: the server's setup is unfinished.
                app.trust.pinState(origin) == PinState.None -> ServerResult.NOT_SET_UP_YET
                else -> {
                    // Under this device's pin the chain ends below it: nothing is opened there now.
                    app.trust.pinFor(origin)?.let { app.cardStatuses[origin] = CardStatus.Withheld(it, null) }
                    if (showServer(origin)) ServerResult.SERVER_CHANGED else ServerResult.FAILED
                }
            }
            is FirstPin.OriginMismatch -> {
                go(EntryScreen.AddressMismatch(null, fp.dialedOrigin, fp.cardOrigin, mismatchFor, publicInstance = app.engine.baked?.origin == fp.dialedOrigin))
                ServerResult.OTHER_ADDRESS
            }
            is FirstPin.Blocked -> if (showServer(origin)) ServerResult.IDENTITY_CONFLICT else ServerResult.FAILED
            // The call would swap the chain a pin holds: nothing changed, and the card on offer is not that pin's.
            is FirstPin.PinConflict -> ServerResult.CARD_NOT_ACCEPTED
            is FirstPin.PinChanged -> {
                // §2.4: a moved or re-kinded chain under an existing pin is handled as a move first, for that server.
                app.cardStatuses[origin] = fp.status
                if (showServer(origin)) ServerResult.SERVER_CHANGED else ServerResult.FAILED
            }
            FirstPin.Unreachable -> ServerResult.UNREACHABLE
        }
    }

    private fun raiseGate(flow: EngineFlow, fp: FirstPin.NeedsTrustGate, kitChanged: Boolean, then: suspend () -> ServerResult) {
        flow.gate = fp
        flow.afterGate = then
        go(EntryScreen.TrustGate(flow, app.gatePrompt(fp, kitChanged, typedKit = false)))
    }

    /**
     * A typed address for [purpose]: the grammar, a blocked pin, then the Trust Gate unless a pin of this device can
     * serve a password there already. Every call starts a flow of its own at that origin.
     */
    private suspend fun typedServer(asked: EntryScreen, input: String, purpose: GatePurpose, then: suspend (EngineFlow) -> ServerResult): ServerResult {
        val origin = typedOrigin(input) ?: return ServerResult.NOT_AN_ADDRESS
        if (blocked(origin)) return if (showServer(origin)) ServerResult.IDENTITY_CONFLICT else ServerResult.FAILED
        val flow = EngineFlow(origin)
        val baked = app.engine.baked
        if (baked != null && baked.origin == origin) return firstPin(asked, flow, app.trust.pinBaked(origin), AddressMismatchFor.TYPED_ADDRESS, false) { then(flow) }
        if (vouchedFor(purpose, origin)) {
            // A pin this device holds already: its chain is judged before anything is opened under it (§2.4).
            val r = app.trust.refresh(origin)
            if (!stillOn(asked)) return ServerResult.STALE
            when (r) {
                CardStatus.Unreachable -> return ServerResult.UNREACHABLE
                is CardStatus.Ok -> app.cardStatuses[origin] = r
                is CardStatus.Refused -> {
                    app.cardStatuses[origin] = r
                    return ServerResult.CARD_NOT_ACCEPTED
                }
                is CardStatus.Fork -> return if (showServer(origin)) ServerResult.IDENTITY_CONFLICT else ServerResult.FAILED
                else -> {
                    app.cardStatuses[origin] = r
                    return if (showServer(origin)) ServerResult.SERVER_CHANGED else ServerResult.FAILED
                }
            }
            return then(flow)
        }
        val wording = if (app.trust.pinState(origin) is PinState.Pinned) TrustGateWording.LINK_OFFER_SIGN_IN else TrustGateWording.TYPED_ADDRESS
        return firstPin(asked, flow, app.trust.beginTrustGate(origin, wording), AddressMismatchFor.TYPED_ADDRESS, false) { then(flow) }
    }

    private suspend fun signupStatus(origin: String): Pair<SignupStatus, Trouble?> = when (val o = app.onboardingFor(origin).signupOffer()) {
        is Fetched.Ok -> status(o.value) to null
        is Fetched.Refused -> notKnown() to (common(o.code, null) ?: Trouble.FAILED)
        Fetched.Unreachable -> notKnown() to Trouble.UNREACHABLE
    }

    private fun claimed(s: EntryScreen?): Boolean =
        s is EntryScreen.LinkDeviceWaiting || s is EntryScreen.LinkDeviceCode || s is EntryScreen.LinkDevicePassword

    // ---- navigation ----

    override fun back(): Boolean {
        if (app.phase != AppPhase.ENTRY) return false
        val s = shown
        if (s is EntryScreen.Kit || s is EntryScreen.ServerSetup || stack.isEmpty()) return false
        // A claimed link is left only by startOver(), which gives it up.
        if (claimed(s)) return false
        if (s is EntryScreen.TrustGate) flowOf(s)?.let {
            it.gate = null
            it.afterGate = null
        }
        // The keys held for a two-step code go when their screen is left.
        if (s is EntryScreen.SignIn) flowOf(s)?.let(::cancelPendingCode)
        // Back from the account check, or from the new password after an operator's help: the answer opened for them goes
        // (the engine's setAside), the request stays kept, and the journey is back on the request's screen, whose next look
        // opens and checks the answer again.
        val f = s?.let(::flowOf)
        if (f != null && (s is EntryScreen.CheckAccount || (s is EntryScreen.ReplacePassword && s.after == RecoveryRoute.OPERATOR_HELP))) {
            f.assistStep?.let(app.assisted::setAside)
            f.assistStep = null
            while (screen?.flow === f && (screen is EntryScreen.CheckAccount || screen is EntryScreen.ReplacePassword)) pop()
            // The request's screen under them is from an earlier look: shown again as the request stands now (what that look
            // said of the key, the server or the answer is no longer current; a signed key change is said again).
            (screen as? EntryScreen.OperatorHelp)?.takeIf { it.flow === f }?.let { h ->
                screen = helpScreen(f, h.stage, h.requestCode.joinToString(" "), h.holdEndsAtMs.takeIf { it > 0 })
            }
            app.publish()
            return true
        }
        pop()
        app.publish()
        return true
    }

    override fun startOver() {
        if (app.phase != AppPhase.ENTRY) return
        val s = shown
        if (s is EntryScreen.Kit || s is EntryScreen.ServerSetup) return
        reset(null)
        app.publish()
    }

    // ---- the first screen ----

    override fun openInviteEntry(screen: EntryScreen.FirstRun) {
        if (on(screen)) go(EntryScreen.InviteEntry())
    }

    override suspend fun createAccountOnAndvari(screen: EntryScreen.FirstRun): ServerResult = step(screen) {
        val baked = app.engine.baked ?: return ServerResult.FAILED
        if (blocked(baked.origin)) return if (showServer(baked.origin)) ServerResult.IDENTITY_CONFLICT else ServerResult.FAILED
        val flow = EngineFlow(baked.origin)
        firstPin(screen, flow, app.trust.pinBaked(baked.origin), AddressMismatchFor.TYPED_ADDRESS, false) {
            // The server answers now: whatever the first screen showed, this is what it says about new accounts.
            val (status, trouble) = signupStatus(flow.origin)
            val label = app.labelFor(flow.origin)
            when {
                !stillOn(screen) -> ServerResult.STALE
                trouble != null -> troubleOf<ServerResult>(trouble)
                label == null -> ServerResult.FAILED
                !status.takingAccounts -> {
                    notePublicSignup(status)
                    ServerResult.NOT_TAKING_ACCOUNTS
                }
                else -> {
                    notePublicSignup(status)
                    flow.signUpPow = status.proofOfWork
                    go(EntryScreen.SignUpEmail(flow, label, status.ageConfirmRequired, null, provingWork = false, workPercent = 0))
                    ServerResult.DONE
                }
            }
        }
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
        if (on(screen)) go(EntryScreen.OwnServer(app.takesSetupLinks))
    }

    override fun openSignIn(screen: EntryScreen.FirstRun) {
        if (on(screen)) go(EntryScreen.SignInChoice())
    }

    override suspend fun resumeOperatorHelp(screen: EntryScreen.FirstRun): ServerResult = step(screen) {
        // One request is kept per server; the first one kept is shown (a device rarely holds two).
        val origin = app.assisted.keptOrigins().firstOrNull() ?: return ServerResult.STALE
        val email = app.keptRequestEmail(origin) ?: return ServerResult.STALE
        val r = app.assisted.resume(origin) ?: return ServerResult.STALE
        if (!on(screen)) return ServerResult.STALE
        val flow = EngineFlow(origin).also { it.assistEmail = email }
        // The request may have moved on with its server's move: the flow acts where the engine kept it.
        val shownFlow = assistOrigin(r)?.takeIf { it != origin }?.let { EngineFlow(it).also { f -> f.assistEmail = email } } ?: flow
        assistShown(shownFlow, r, replace = false)
    }

    // ---- invites (bound with the link flows) ----

    /** What a payload is, by its own grammar: the three scanners each take one kind only (§12.1). */
    private enum class Shape { INVITE, DEVICE_LINK, KIT, NONE }

    private fun shape(payload: String): Shape {
        val p = payload.trim()
        if (p.startsWith("andvari-kit:") || RecoveryKit.parseQr(p) != null) return Shape.KIT
        DeviceLinkUrl.parse(p)?.let {
            it.wipe()
            return Shape.DEVICE_LINK
        }
        LinkUrl.parse(p)?.let {
            it.wipe()
            return Shape.INVITE
        }
        return Shape.NONE
    }

    /** An invite opened from [entry], through every recipient check of §6.8 in the link engine. */
    private suspend fun openInvite(asked: EntryScreen?, payload: String, entry: GateEntry, setupOnly: Boolean = false): InviteResult {
        when (shape(payload)) {
            Shape.KIT -> return InviteResult.KIT_NOT_AN_INVITE
            Shape.DEVICE_LINK -> return InviteResult.DEVICE_LINK_NOT_HERE
            Shape.NONE -> return InviteResult.NOT_AN_INVITE
            Shape.INVITE -> Unit
        }
        val text = payload.trim()
        val parsed = LinkUrl.parse(text) ?: return InviteResult.NOT_AN_INVITE
        val origin = parsed.origin
        parsed.wipe()
        if (blocked(origin)) return if (showServer(origin)) InviteResult.IDENTITY_CONFLICT else InviteResult.FAILED
        // A kit on show holds an open account: a lock while the link is opened answers STALE.
        val step = app.unlessLocked(null) { app.entryLinks.open(text, entry) } ?: return InviteResult.STALE
        return inviteStep(asked, EngineFlow(origin), step, setupOnly)
    }

    /**
     * §6.7 setup link, step 1, on a computer (the link engine stops a phone with `SETUP_ON_PHONE` and an instance that
     * serves a card with `already_set_up`, before this): the sign-up form for the server's first operator. No pin exists
     * yet, so the server is named as its setup offer names it, marked self-named, beside its origin (T-R8). Opening it
     * keeps the offer in device state (§6.7 step 2), until card 0 is accepted or the flow ends with no account made.
     * Nothing was sent but the link's own reads.
     */
    private fun setupConfirm(flow: EngineFlow, s: RecipientStep.Confirm): InviteResult {
        val reg = (if (app.takesSetupLinks) app.entryLinks.resolve(s) else null) as? io.silencelen.andvari.core.client.onboard.LinkRegistration.Setup
        if (reg == null || reg.origin != flow.origin) {
            abandon(flow)
            return if (app.takesSetupLinks) InviteResult.EXPIRED else InviteResult.SETUP_NEEDS_COMPUTER
        }
        flow.setupKept = true
        val label = InstanceLabel(s.offer.instanceName, flow.origin, app.kindOf(reg.kind), selfNamed = true)
        flow.setupLabel = label
        go(EntryScreen.CreateAccount(flow, RegistrationVia.SETUP_LINK, label, null, null, false, null, WhoCanRecover.ONLY_ME))
        return InviteResult.DONE
    }

    /**
     * What the link engine's [s] came to for [flow]: a screen, or a refusal that leaves the screen on show. Called after
     * the wait for [s]: when the person left [asked] meanwhile, the step is dismissed (the link engine ends its flow and
     * drops a pin it made) and nothing is shown.
     */
    private suspend fun inviteStep(asked: EntryScreen?, flow: EngineFlow, s: RecipientStep, setupOnly: Boolean = false): InviteResult {
        flow.invite = null
        val origin = flow.origin
        if (!stillOn(asked)) {
            if (s !is RecipientStep.Stopped) app.entryLinks.dismiss(s)
            return InviteResult.STALE
        }
        if (setupOnly && s !is RecipientStep.Stopped && !(s is RecipientStep.Confirm && s.offer.kind == "setup")) {
            // "Use your own server" takes a server's setup link and no other link (§12.1): nothing more is sent.
            app.entryLinks.dismiss(s)
            return InviteResult.NOT_AN_INVITE
        }
        return when (s) {
            is RecipientStep.Stopped -> inviteStopped(origin, s.reason)
            is RecipientStep.OriginMismatch -> {
                // §2.4: the card the link's server serves was made for another address. Both are shown; nothing was pinned.
                go(EntryScreen.AddressMismatch(null, s.dialedOrigin, s.cardOrigin, AddressMismatchFor.INVITE, publicInstance = app.engine.baked?.origin == s.dialedOrigin))
                InviteResult.OTHER_ADDRESS
            }
            is RecipientStep.PinChanged -> {
                // §2.4: a move met while a link is opened under an existing pin is handled first; the link is opened again after.
                app.cardStatuses[origin] = s.change.status
                if (showServer(origin)) InviteResult.SERVER_CHANGED else InviteResult.FAILED
            }
            is RecipientStep.TrustGate -> {
                // An enrol link: the host's own claim, through the Trust Gate in its enrol wording.
                flow.invite = s
                raiseGate(flow, s.gate, false) {
                    val next = app.unlessLocked(null) { app.entryLinks.proceed(s) } ?: return@raiseGate ServerResult.STALE
                    // Confirming the gate shows [asked] again (the screen it covered): the answer goes there or nowhere.
                    inviteToServer(inviteStep(asked, flow, next))
                }
                InviteResult.DONE
            }
            is RecipientStep.NotTakingAccounts -> {
                val label = app.labelFor(origin) ?: return InviteResult.FAILED
                val mode = when (s.mode) {
                    "open" -> JoinMode.ANYONE
                    "links" -> JoinMode.INVITATION_ONLY
                    "closed" -> JoinMode.CLOSED
                    else -> JoinMode.NOT_KNOWN
                }
                go(EntryScreen.NotTakingAccounts(flow, label, s.offer.creatorName.orEmpty(), SignupStatus(mode, s.full, ageConfirmRequired = false, proofOfWork = false)))
                InviteResult.DONE
            }
            is RecipientStep.Confirm -> {
                flow.invite = s
                if (s.offer.kind == "setup") return setupConfirm(flow, s)
                val label = app.labelFor(origin)
                if (label == null) {
                    abandon(flow)
                    return InviteResult.FAILED
                }
                when (s.offer.kind) {
                    "connect" -> {
                        go(EntryScreen.JoinInvite(flow, label, s.offer.creatorName.orEmpty()))
                        InviteResult.DONE
                    }
                    "register", "enrol" -> {
                        val (status, trouble) = signupStatus(origin)
                        if (trouble != null) {
                            abandon(flow)
                            return troubleOf(trouble)
                        }
                        val offer = app.onboardingFor(origin).operatorRecoveryOffer()
                        if (!stillOn(asked)) {
                            abandon(flow)
                            return InviteResult.STALE
                        }
                        flow.recoveryOffer = offer
                        val question = offer?.let { RecoveryQuestion(label, it.unsignedChange) }
                        val register = s.offer.kind == "register"
                        go(EntryScreen.CreateAccount(
                            flow, if (register) RegistrationVia.INVITATION_LINK else RegistrationVia.ENROLMENT_LINK, label,
                            if (register) null else s.offer.boundEmail, if (register) s.offer.creatorName else null,
                            status.ageConfirmRequired, question, WhoCanRecover.ONLY_ME,
                        ))
                        InviteResult.DONE
                    }
                    else -> {
                        // A kind this build does not know: nothing was sent.
                        abandon(flow)
                        InviteResult.FAILED
                    }
                }
            }
            // A signed-out flow has no account: none of these is a step it can reach.
            else -> {
                app.entryLinks.dismiss(s)
                InviteResult.FAILED
            }
        }
    }

    /** A recipient stop, as the invite screen says it (§2.4 "Opening a link"). */
    private fun inviteStopped(origin: String, reason: LinkStop): InviteResult = when (reason) {
        LinkStop.BAD_LINK, LinkStop.WRONG_ENTRY -> InviteResult.NOT_AN_INVITE
        LinkStop.WRONG_SCREEN_DEVICE_LINK -> InviteResult.DEVICE_LINK_NOT_HERE
        LinkStop.WRONG_SCREEN_KIT -> InviteResult.KIT_NOT_AN_INVITE
        LinkStop.UNKNOWN -> InviteResult.NOT_FOUND
        LinkStop.EXPIRED, LinkStop.OFFER_EXPIRED -> InviteResult.EXPIRED
        LinkStop.ALREADY_USED -> InviteResult.ALREADY_USED
        LinkStop.OWN_LINK -> InviteResult.OWN_LINK
        LinkStop.ORIGIN_MISMATCH -> InviteResult.OTHER_ADDRESS
        LinkStop.FORK, LinkStop.DAMAGED -> if (showServer(origin)) InviteResult.IDENTITY_CONFLICT else InviteResult.FAILED
        LinkStop.UPDATE_REQUIRED -> InviteResult.UPDATE_REQUIRED
        LinkStop.SETUP_ON_PHONE -> InviteResult.SETUP_NEEDS_COMPUTER
        LinkStop.ALREADY_SET_UP -> InviteResult.SETUP_ALREADY_DONE
        LinkStop.UNREACHABLE -> InviteResult.UNREACHABLE
        LinkStop.STALE, LinkStop.DECLINED -> InviteResult.STALE
        else -> InviteResult.DOES_NOT_CHECK_OUT
    }

    /**
     * An invite for another server opened while signed in, after "Switch to …" signed out (§6.7): the link engine runs
     * its account checks again with no account, and the journey shows what they came to, as if the link had been opened
     * on the first screen.
     */
    internal suspend fun continueInvite(step: RecipientStep.OtherInstance): ServerResult {
        val asked = shown
        val next = app.entryLinks.proceed(step)
        return inviteToServer(inviteStep(asked, EngineFlow(step.offer.origin), next))
    }

    /** [origin] answers its public sign-up read: [ServerResult.DONE], or the trouble that stopped it. Nothing is signed. */
    internal suspend fun answers(origin: String): ServerResult = signupStatus(origin).second?.let { troubleOf<ServerResult>(it) } ?: ServerResult.DONE

    internal fun inviteToServer(r: InviteResult): ServerResult = when (r) {
        InviteResult.DONE -> ServerResult.DONE
        InviteResult.OTHER_ADDRESS -> ServerResult.OTHER_ADDRESS
        InviteResult.IDENTITY_CONFLICT -> ServerResult.IDENTITY_CONFLICT
        InviteResult.SERVER_CHANGED -> ServerResult.SERVER_CHANGED
        InviteResult.UNREACHABLE -> ServerResult.UNREACHABLE
        InviteResult.RATE_LIMITED -> ServerResult.RATE_LIMITED
        InviteResult.UPDATE_REQUIRED -> ServerResult.UPDATE_REQUIRED
        InviteResult.STALE -> ServerResult.STALE
        InviteResult.DOES_NOT_CHECK_OUT -> ServerResult.CARD_NOT_ACCEPTED
        else -> ServerResult.FAILED
    }

    suspend fun openAppLink(url: String): InviteResult {
        val s = shown
        // A tapped link never interrupts a kit or a setup that must finish, or a claimed link.
        if (s is EntryScreen.Kit || s is EntryScreen.ServerSetup || claimed(s)) return InviteResult.STALE
        return app.working { openInvite(s, url, GateEntry.APP_LINK) }
    }

    override suspend fun submitInvite(screen: EntryScreen.InviteEntry, payload: String, source: PayloadSource): InviteResult =
        step(screen) { openInvite(screen, payload, if (source == PayloadSource.SCANNED) GateEntry.SCAN_INVITE else GateEntry.PASTE_INVITE) }

    /**
     * "Create an account" from a connect link (§6.7): sign-up by a verified address at the link's server. The
     * connection itself is answered once the account is open ([EngineAppApi.connectAfterEntry]).
     */
    override suspend fun joinFromInvite(screen: EntryScreen.JoinInvite): ServerResult = step(screen) {
        val flow = flowOf(screen) ?: return ServerResult.STALE
        if (flow.invite !is RecipientStep.Confirm) return ServerResult.STALE
        val (status, trouble) = signupStatus(flow.origin)
        if (!stillOn(screen)) return ServerResult.STALE
        if (trouble != null) return troubleOf(trouble)
        if (!status.takingAccounts) {
            swap(EntryScreen.NotTakingAccounts(flow, screen.instance, screen.from, status))
            return ServerResult.NOT_TAKING_ACCOUNTS
        }
        flow.signUpPow = status.proofOfWork
        go(EntryScreen.SignUpEmail(flow, screen.instance, status.ageConfirmRequired, screen.from, provingWork = false, workPercent = 0))
        ServerResult.DONE
    }

    override suspend fun signInFromInvite(screen: EntryScreen.JoinInvite): ServerResult = step(screen) { beginSignIn(screen, flowOf(screen) ?: return ServerResult.STALE) }

    override suspend fun signInWhereInvited(screen: EntryScreen.NotTakingAccounts): ServerResult = step(screen) { beginSignIn(screen, flowOf(screen) ?: return ServerResult.STALE) }

    // ---- "Use your own server" ----

    override suspend fun submitServerAddress(screen: EntryScreen.OwnServer, input: String): ServerResult = step(screen) {
        if (shape(input) == Shape.INVITE) {
            // §12.1: the desktop app takes the server's setup link here, through every check of the link engine, and no
            // other link; a phone says where a setup link belongs.
            if (!app.takesSetupLinks) return ServerResult.SETUP_NEEDS_COMPUTER
            return when (openInvite(screen, input, GateEntry.PASTE_INVITE, setupOnly = true)) {
                InviteResult.DONE -> ServerResult.DONE
                InviteResult.NOT_AN_INVITE -> ServerResult.NOT_AN_ADDRESS
                InviteResult.SETUP_ALREADY_DONE -> ServerResult.SETUP_ALREADY_DONE
                InviteResult.SETUP_NEEDS_COMPUTER -> ServerResult.SETUP_NEEDS_COMPUTER
                InviteResult.IDENTITY_CONFLICT -> ServerResult.IDENTITY_CONFLICT
                InviteResult.OTHER_ADDRESS -> ServerResult.OTHER_ADDRESS
                InviteResult.UNREACHABLE -> ServerResult.UNREACHABLE
                InviteResult.RATE_LIMITED -> ServerResult.RATE_LIMITED
                InviteResult.UPDATE_REQUIRED -> ServerResult.UPDATE_REQUIRED
                InviteResult.STALE -> ServerResult.STALE
                else -> ServerResult.SETUP_LINK_NOT_USABLE
            }
        }
        typedServer(screen, input, GatePurpose.SIGN_IN) { flow ->
            val label = app.labelFor(flow.origin) ?: return@typedServer ServerResult.FAILED
            val (status, trouble) = signupStatus(flow.origin)
            // After a Trust Gate the address screen is on show again: the late answer goes there or nowhere.
            if (!stillOn(screen)) return@typedServer ServerResult.STALE
            if (trouble == Trouble.RATE_LIMITED || trouble == Trouble.UPDATE_REQUIRED) return@typedServer troubleOf(trouble)
            go(EntryScreen.Server(flow, label, status))
            ServerResult.DONE
        }
    }

    override suspend fun createAccountHere(screen: EntryScreen.Server): ServerResult = step(screen) {
        val flow = flowOf(screen) ?: return ServerResult.STALE
        val (status, trouble) = signupStatus(flow.origin)
        if (!stillOn(screen)) return ServerResult.STALE
        if (trouble != null) return troubleOf(trouble)
        if (!status.takingAccounts) {
            swap(EntryScreen.Server(flow, screen.instance, status))
            return ServerResult.NOT_TAKING_ACCOUNTS
        }
        flow.signUpPow = status.proofOfWork
        go(EntryScreen.SignUpEmail(flow, screen.instance, status.ageConfirmRequired, null, provingWork = false, workPercent = 0))
        ServerResult.DONE
    }

    override suspend fun signInHere(screen: EntryScreen.Server): ServerResult = step(screen) { beginSignIn(screen, flowOf(screen) ?: return ServerResult.STALE) }

    /** The password screen when a pin of this device can serve a sign-in at [flow]'s origin; the Trust Gate first otherwise. */
    private suspend fun beginSignIn(asked: EntryScreen, flow: EngineFlow): ServerResult {
        val origin = flow.origin
        if (blocked(origin)) return if (showServer(origin)) ServerResult.IDENTITY_CONFLICT else ServerResult.FAILED
        val form: suspend () -> ServerResult = {
            val label = app.labelFor(origin)
            if (label == null) {
                ServerResult.FAILED
            } else {
                go(EntryScreen.SignIn(flow, MasterPasswordPrompt(null, label), codeNeeded = false))
                ServerResult.DONE
            }
        }
        if (vouchedFor(GatePurpose.SIGN_IN, origin)) return form()
        val wording = if (app.trust.pinState(origin) is PinState.Pinned) TrustGateWording.LINK_OFFER_SIGN_IN else TrustGateWording.TYPED_ADDRESS
        return firstPin(asked, flow, app.trust.beginTrustGate(origin, wording), AddressMismatchFor.TYPED_ADDRESS, false, form)
    }

    // ---- the Trust Gate ----

    override suspend fun confirmTrustGate(screen: EntryScreen.TrustGate): ServerResult = step(screen) {
        val flow = flowOf(screen) ?: return ServerResult.STALE
        val g = flow.gate ?: return ServerResult.STALE
        val then = flow.afterGate ?: return ServerResult.STALE
        flow.gate = null
        flow.afterGate = null
        // The gate is not a place to come back to: what follows replaces it.
        val under = if (stack.isEmpty()) firstRun() else stack.removeAt(stack.size - 1)
        this.screen = under
        // A kit's gate pins at the kit's proof, inside the engine's verify, never here (a failed proof leaves no pin).
        // A device link's gate is confirmed inside the device-link engine (`afterTrustGate`), which pins and claims.
        // So is an invite's, inside the link engine (`proceed`). What follows the gate checks, after each of its own
        // waits, that [under] is still on show.
        val r = if (flow.kitStep is KitRecoveryStep.ConfirmTarget || flow.linkStep is NewStep.TrustGate || flow.invite is RecipientStep.TrustGate) {
            then()
        } else {
            val fp = app.trust.confirmTrustGate(g.confirm)
            if (!stillOn(under)) ServerResult.STALE
            else when (fp) {
                is FirstPin.Pinned -> then()
                else -> firstPin(under, flow, fp, AddressMismatchFor.TYPED_ADDRESS, false, then)
            }
        }
        app.publish()
        r
    }

    override fun declineTrustGate(screen: EntryScreen.TrustGate) {
        if (!on(screen)) return
        flowOf(screen)?.let {
            it.gate = null
            it.afterGate = null
        }
        pop()
        app.publish()
    }

    // ---- §7.2: sign-up ----

    override suspend fun startSignUp(screen: EntryScreen.SignUpEmail, email: String, ageConfirmed: Boolean): SignUpStartResult = step(screen) {
        val flow = flowOf(screen) ?: return SignUpStartResult.STALE
        // A new account is never the one kept here (signed out by its server, design
        // §4.4), so sign-up is refused at its first step, before an address or a code is sent anywhere, not at
        // "Create account" after both went.
        app.keeper.session?.let { return if (it.heldAsOperator) SignUpStartResult.OPERATOR_ACCOUNT_HELD else SignUpStartResult.ANOTHER_ACCOUNT_KEPT }
        if (TrustGrammar.emailNorm(email) == null) return SignUpStartResult.INVALID_EMAIL
        if (screen.ageConfirmRequired && !ageConfirmed) return SignUpStartResult.AGE_CONFIRMATION_NEEDED
        var proving: EntryScreen.SignUpEmail? = null
        if (flow.signUpPow) {
            val first = EntryScreen.SignUpEmail(flow, screen.instance, screen.ageConfirmRequired, screen.connectWith, provingWork = true, workPercent = 0)
            proving = first
            swap(first)
        }
        val r = app.onboardingFor(flow.origin).signupStart(email, ageConfirmed) { f ->
            // The proof of work reports from its worker: the screen changes on the API's own thread.
            app.scope.launch {
                val percent = (f * 100).toInt().coerceIn(0, 100)
                val s = this@EngineEntry.screen
                if (s === screen || (s != null && s === proving)) {
                    val next = EntryScreen.SignUpEmail(flow, screen.instance, screen.ageConfirmRequired, screen.connectWith, provingWork = f < 1f, workPercent = if (f < 1f) percent else 0)
                    proving = next
                    swap(next)
                }
            }
        }
        val current = this.screen
        if (current !== screen && current !== proving) return SignUpStartResult.STALE
        if (current !== screen) swap(screen)
        when (r) {
            SignupStart.Sent -> {
                // A sign-up started again in the same flow (back from its form): the earlier address's ticket is left.
                leaveTicket(flow)
                flow.signUpEmail = email.trim()
                flow.signUpAge = ageConfirmed
                go(EntryScreen.SignUpCode(flow, screen.instance, email.trim(), screen.connectWith))
                SignUpStartResult.DONE
            }
            is SignupStart.Refused -> signUpRefused(r.code, r.retryAfterSeconds)
            SignupStart.MailUnavailable -> SignUpStartResult.MAIL_UNAVAILABLE
            SignupStart.Unreachable -> SignUpStartResult.UNREACHABLE
        }
    }

    private fun signUpRefused(code: String, retryAfter: Long?): SignUpStartResult {
        common(code, retryAfter)?.let { return troubleOf(it) }
        return when (code) {
            WireErrors.INVALID_EMAIL -> SignUpStartResult.INVALID_EMAIL
            WireErrors.EMAIL_DOMAIN_BLOCKED -> SignUpStartResult.EMAIL_DOMAIN_NOT_ACCEPTED
            WireErrors.AGE_CONFIRM_REQUIRED -> SignUpStartResult.AGE_CONFIRMATION_NEEDED
            WireErrors.SIGNUP_CLOSED -> SignUpStartResult.SIGNUP_CLOSED
            WireErrors.SIGNUP_FULL -> SignUpStartResult.SIGNUP_FULL
            else -> SignUpStartResult.FAILED
        }
    }

    override suspend fun verifySignUpCode(screen: EntryScreen.SignUpCode, code: String): CodeResult = step(screen) {
        val flow = flowOf(screen) ?: return CodeResult.STALE
        val verified = app.onboardingFor(flow.origin).signupVerify(flow.signUpEmail, code.trim())
        // Left meanwhile: a ticket the verify handed out is left at the engine at once (no screen will use it), so its hold
        // on the address ends with the flow the person left.
        val stale = { (verified as? SignupVerify.Ticket)?.let { app.onboardingFor(flow.origin).leaveSignup(it) }; CodeResult.STALE }
        if (!stillOn(screen)) return stale()
        when (val r = verified) {
            is SignupVerify.Ticket -> {
                val offer = app.onboardingFor(flow.origin).operatorRecoveryOffer()
                if (!stillOn(screen)) return stale()
                // A code verified again (back from the form): the ticket it replaces is left, not dropped holding.
                if (flow.ticket !== r) leaveTicket(flow)
                flow.ticket = r
                flow.recoveryOffer = offer
                val question = offer?.let { RecoveryQuestion(screen.instance, it.unsignedChange) }
                go(EntryScreen.CreateAccount(flow, RegistrationVia.EMAIL_CODE, screen.instance, flow.signUpEmail, null, false, question, WhoCanRecover.ONLY_ME))
                CodeResult.DONE
            }
            SignupVerify.BadCode -> CodeResult.WRONG_CODE
            is SignupVerify.Refused -> common(r.code, r.retryAfterSeconds)?.let { troubleOf<CodeResult>(it) } ?: CodeResult.FAILED
            SignupVerify.Unreachable -> CodeResult.UNREACHABLE
        }
    }

    override suspend fun resendSignUpCode(screen: EntryScreen.SignUpCode): SignUpStartResult = step(screen) {
        val flow = flowOf(screen) ?: return SignUpStartResult.STALE
        when (val r = app.onboardingFor(flow.origin).signupStart(flow.signUpEmail, flow.signUpAge)) {
            SignupStart.Sent -> SignUpStartResult.DONE
            is SignupStart.Refused -> signUpRefused(r.code, r.retryAfterSeconds)
            SignupStart.MailUnavailable -> SignUpStartResult.MAIL_UNAVAILABLE
            SignupStart.Unreachable -> SignUpStartResult.UNREACHABLE
        }
    }

    // ---- §7.3, §7.7: registration ----

    private fun form(flow: EngineFlow, from: EntryScreen.CreateAccount, who: WhoCanRecover) =
        EntryScreen.CreateAccount(flow, from.via, from.instance, from.fixedEmail, from.invitedBy, from.ageConfirmRequired, from.recovery, who)

    override fun reviewOperatorRecovery(screen: EntryScreen.CreateAccount) {
        val q = screen.recovery ?: return
        val flow = flowOf(screen) ?: return
        if (on(screen)) go(EntryScreen.RecoveryWarning(flow, OperatorRecoveryWarning(q.instance, q.unsignedChange)))
    }

    override fun acceptOperatorRecovery(screen: EntryScreen.RecoveryWarning, understood: Boolean): Boolean {
        if (!on(screen) || !understood) return false
        val flow = flowOf(screen) ?: return false
        val before = stack.removeLastOrNull() as? EntryScreen.CreateAccount ?: return false
        swap(form(flow, before, WhoCanRecover.ME_OR_OPERATOR))
        return true
    }

    override fun keepRecoveryPrivate(screen: EntryScreen.RecoveryWarning) {
        if (!on(screen)) return
        val flow = flowOf(screen) ?: return
        val before = stack.removeLastOrNull() as? EntryScreen.CreateAccount ?: return
        swap(form(flow, before, WhoCanRecover.ONLY_ME))
    }

    override fun chooseOnlyMe(screen: EntryScreen.CreateAccount) {
        val flow = flowOf(screen) ?: return
        if (on(screen) && screen.whoCanRecover != WhoCanRecover.ONLY_ME) swap(form(flow, screen, WhoCanRecover.ONLY_ME))
    }

    override suspend fun createAccount(screen: EntryScreen.CreateAccount, input: NewAccountInput): CreateAccountResult = step(screen) {
        val flow = flowOf(screen) ?: return CreateAccountResult.STALE
        val origin = flow.origin
        val auth = when (screen.via) {
            RegistrationVia.EMAIL_CODE -> RegistrationAuth.Ticket(flow.ticket ?: return CreateAccountResult.STALE)
            // The link engine re-derives what the step authorises from its own state (LinkRegistrations.resolve).
            RegistrationVia.INVITATION_LINK -> RegistrationAuth.RegisterLink(flow.invite as? RecipientStep.Confirm ?: return CreateAccountResult.STALE)
            RegistrationVia.ENROLMENT_LINK -> RegistrationAuth.EnrolLink(flow.invite as? RecipientStep.Confirm ?: return CreateAccountResult.STALE)
            // §6.7: the server's first operator, on a computer only; card 0 is signed inside the registration.
            RegistrationVia.SETUP_LINK -> if (!app.takesSetupLinks) return CreateAccountResult.FAILED
            else RegistrationAuth.SetupLink(flow.invite as? RecipientStep.Confirm ?: return CreateAccountResult.STALE)
            else -> return CreateAccountResult.FAILED
        }
        // A new account is never the one kept here: nothing is sent, so no account is made only to be refused.
        app.keeper.session?.let { return if (it.heldAsOperator) CreateAccountResult.OPERATOR_ACCOUNT_HELD else CreateAccountResult.ANOTHER_ACCOUNT_KEPT }
        val email = screen.fixedEmail ?: input.email
        val operator = screen.whoCanRecover == WhoCanRecover.ME_OR_OPERATOR
        val form = RegistrationForm(
            email = email,
            displayName = input.displayName,
            password = input.password.toCharArray(),
            ageConfirmed = input.ageConfirmed || (flow.signUpAge && screen.fixedEmail != null),
            recovery = if (operator) RecoveryChoiceKind.OPERATOR else RecoveryChoiceKind.PRIVATE,
            deviceName = app.engine.deviceName,
            platform = app.engine.platform.wireName,
            operatorOffer = if (operator) flow.recoveryOffer else null,
            operatorUnderstood = operator,
        )
        val called = try {
            call(screen, refusedHere = {
                when (it) {
                    is Registration.Registered -> it.notKept != null
                    // The keeper's refusal before anything was committed comes back as the server-shaped code: counted as before.
                    is Registration.Refused -> null
                    else -> false
                }
            }) { app.onboardingFor(origin).register(auth, form) }
        } finally {
            form.password.fill('\u0000')
        }
        val r = (called as? Called.Answered)?.value ?: return lateRegistration(flow, origin, email, input.displayName, called)
        when (r) {
            is Registration.Registered -> {
                flow.ticket = null
                inviteUsed(flow)
                // The name the account goes by in its links' offers and answers (§6.7): the server keeps it, but serves it nowhere.
                app.rememberName(origin, r.userId, input.displayName)
                if (screen.via == RegistrationVia.SETUP_LINK) return setupRegistered(flow, email.trim(), r)
                val label = app.labelFor(origin) ?: return CreateAccountResult.FAILED
                app.accountEmail = email.trim()
                // The journey's screens are behind the kit now: there is no way back past it.
                leave()
                app.kitFlow.show(r.kit, KitReason.FIRST_KIT, email.trim(), label, origin, inEntry = true) { app.opened() }
                CreateAccountResult.DONE
            }
            Registration.PasswordTooWeak -> CreateAccountResult.WEAK_PASSWORD
            is Registration.IdentityFault -> {
                if (r.reason == SELF_IDENTITY_MISMATCH) raiseEarlier(origin, email, r.anotherAccountServed)
                CreateAccountResult.IDENTITY_FAULT
            }
            Registration.Unknown -> CreateAccountResult.MAY_EXIST
            is Registration.Refused -> registrationRefused(r.code, r.retryAfterSeconds)
        }
    }

    /**
     * A registration that came back as [Called.Left]. When the keeper refused its session with the screen still on show
     * and the account was made ([Registration.Registered] with the engine's `notKept`), its first kit is shown with the
     * refusal and kept until the person confirmed it: the account exists under the chosen password, and the result says
     * the keeper's own reason (`Registered.notKept`) with its way out. Otherwise what the call held goes, as for any call
     * the person left.
     */
    private fun lateRegistration(flow: EngineFlow, origin: String, email: String, name: String, called: Called<Registration>): CreateAccountResult {
        val late = (called as? Called.Left)?.late as? Registration.Registered
        val reason = late?.notKept
        if (late == null || reason == null || !(called as Called.Left).refused) {
            late?.kit?.wipe()
            return lateAnswer(called, CreateAccountResult.ANOTHER_ACCOUNT_KEPT)
        }
        flow.ticket = null
        // The name the account goes by in its links is the person's own word, kept as at any registration (§6.7).
        app.rememberName(origin, late.userId, name)
        // The keeper's own reason, never one guessed from which counter moved: a device that came to hold its server's
        // operator account meanwhile is not told "another account is kept".
        val result = io.silencelen.andvari.core.app.KeeperReasons.committedRegistration(reason)
        val label = app.labelFor(origin) ?: run {
            late.kit.wipe()
            return result
        }
        notKeptKit(late.kit, KitReason.FIRST_KIT, result, email.trim(), label, origin)
        return result
    }

    private fun registrationRefused(code: String, retryAfter: Long?): CreateAccountResult {
        common(code, retryAfter)?.let { return troubleOf(it) }
        return when (code) {
            // The keeper's answer before anything was committed (in a race only: the screen refuses earlier): another
            // account is kept here, so no account was made.
            ANOTHER_SESSION_KEPT -> CreateAccountResult.ANOTHER_ACCOUNT_KEPT
            OPERATOR_ACCOUNT_HELD -> CreateAccountResult.OPERATOR_ACCOUNT_HELD
            WireErrors.INVALID_EMAIL -> CreateAccountResult.INVALID_EMAIL
            WireErrors.EMAIL_TAKEN -> CreateAccountResult.EMAIL_TAKEN
            "email_mismatch" -> CreateAccountResult.EMAIL_NOT_THE_LINKS
            WireErrors.AGE_CONFIRM_REQUIRED -> CreateAccountResult.AGE_CONFIRMATION_NEEDED
            WireErrors.SIGNUP_CLOSED -> CreateAccountResult.SIGNUP_CLOSED
            WireErrors.SIGNUP_FULL -> CreateAccountResult.SIGNUP_FULL
            WireErrors.SIGNUP_DAILY_MAX -> CreateAccountResult.DAILY_LIMIT
            WireErrors.BAD_TICKET -> CreateAccountResult.VERIFICATION_EXPIRED
            WireErrors.LINK_USED, WireErrors.LINK_EXPIRED, WireErrors.LINK_UNKNOWN, "link_stale" -> CreateAccountResult.LINK_GONE
            WireErrors.SETUP_INCOMPLETE -> CreateAccountResult.SERVER_NOT_SET_UP
            WireErrors.SETUP_DONE -> CreateAccountResult.SETUP_ALREADY_DONE
            WireErrors.OPERATOR_RECOVERY_UNAVAILABLE, "stale_offer" -> CreateAccountResult.OPERATOR_RECOVERY_UNAVAILABLE
            WireErrors.ESCROW_WRONG_FORM -> CreateAccountResult.ESCROW_WRONG_FORM
            else -> CreateAccountResult.FAILED
        }
    }

    /**
     * §6.7 step 3 came to [r] inside the registration: the server setup screen, FINISHED when card 0 was accepted and
     * pinned, NOT_UPLOADED otherwise (no clean answer, another card stored, or its pin refused). The account exists and
     * its session is kept either way; the new kit waits behind this screen on [flow] and is shown by
     * [finishServerSetup], because the kit names card 0.
     */
    private fun setupRegistered(flow: EngineFlow, email: String, r: Registration.Registered): CreateAccountResult {
        app.accountEmail = email
        flow.setupRegistered = true
        // The journey's screens are behind the setup now: there is no way back past it.
        leave()
        flow.setupKit = r.kit
        swap(serverSetup(flow, if (r.cardPending) ServerSetupStep.NOT_UPLOADED else ServerSetupStep.FINISHED))
        return CreateAccountResult.DONE
    }

    /** The server setup screen for [flow] at [step]: the pinned card's name once card 0 is pinned, the offer's before. */
    private fun serverSetup(flow: EngineFlow, step: ServerSetupStep): EntryScreen.ServerSetup {
        val pin = app.trust.pinFor(flow.origin)
        val label = pin?.let { app.labelFor(flow.origin) } ?: flow.setupLabel
            ?: InstanceLabel("", flow.origin, io.silencelen.andvari.core.app.ServerKind.PRIVATE_SERVER, selfNamed = true)
        // What "Instance details" shows, with card 0's hash only from this device's own setup pin (§14.1, T-R10).
        val details = if (step != ServerSetupStep.FINISHED || pin == null) null else io.silencelen.andvari.core.app.InstanceDetails(
            app.operatorKeyShort(pin.operatorSignKey), pin.seq, if (pin.root == io.silencelen.andvari.core.client.pin.PinRoot.SETUP) pin.card0Hash else "",
        )
        return EntryScreen.ServerSetup(flow, label, step, details)
    }

    /**
     * "Try again" after NOT_UPLOADED: the engine's `SetupResume.finish` with the operator's master [password] (one fresh
     * `currentAuthKey`, the one re-authentication path), under the account's guard, so a lock that overtakes it answers
     * STALE with nothing sealed or sent after it. What a server's answer can and cannot make it do:
     * - it signs card 0 only while the instance serves no card (a served card answers SETUP_ALREADY_DONE, nothing
     *   signed, nothing pinned);
     * - it signs only for the session's own origin, and from this device's kept offer or a served `setup` block that
     *   names that origin (another address, or operator recovery on a public instance, signs nothing);
     * - it pins only the card 0 it signed itself, once the server's answer names exactly that card at `seq` 0;
     *   anything else stays NOT_UPLOADED (CARD_NOT_ACCEPTED) with nothing pinned.
     * Once finished, the kit waiting behind the screen names the card 0 actually accepted.
     */
    override suspend fun retryServerSetup(screen: EntryScreen.ServerSetup, password: String): ServerResult = step(screen) {
        val flow = flowOf(screen) ?: return ServerResult.STALE
        if (screen.step != ServerSetupStep.NOT_UPLOADED || flow.setupKit == null) return ServerResult.STALE
        val resume = app.setupResume(flow.origin) ?: return ServerResult.STALE
        val chars = password.toCharArray()
        val r = try {
            app.unlessLocked(null) { resume.finish(chars) }
        } finally {
            chars.fill('\u0000')
        } ?: return ServerResult.STALE
        if (!on(screen)) return ServerResult.STALE
        when (r) {
            is io.silencelen.andvari.core.client.account.Reauthed.Done -> {
                // The kit names card 0 (§10): the one now accepted, whose hash may differ from the one signed at first.
                val kit = flow.setupKit ?: return ServerResult.STALE
                val email = app.keeper.session?.emailNorm ?: return ServerResult.STALE
                val qr = io.silencelen.andvari.core.trust.RecoveryKit.composeQr(flow.origin, r.value, email, kit.secret) ?: return ServerResult.FAILED
                flow.setupKit = io.silencelen.andvari.core.client.onboard.RevealedKit(kit.groups, qr, kit.pieceId, kit.accountId, kit.secret.copyOf())
                kit.wipe()
                swap(serverSetup(flow, ServerSetupStep.FINISHED))
                ServerResult.DONE
            }
            io.silencelen.andvari.core.client.account.Reauthed.WrongPassword -> ServerResult.WRONG_PASSWORD
            io.silencelen.andvari.core.client.account.Reauthed.Unknown -> ServerResult.UNREACHABLE
            io.silencelen.andvari.core.client.account.Reauthed.NoSession -> ServerResult.STALE
            io.silencelen.andvari.core.client.account.Reauthed.PasswordTooWeak -> ServerResult.FAILED
            is io.silencelen.andvari.core.client.account.Reauthed.Refused -> when (r.code) {
                io.silencelen.andvari.core.client.onboard.SetupResume.SETUP_DONE -> ServerResult.SETUP_ALREADY_DONE
                io.silencelen.andvari.core.client.onboard.SetupResume.CARD_MISMATCH, io.silencelen.andvari.core.client.onboard.SetupResume.PIN_FAILED,
                "bad_card", "card_head_moved" -> ServerResult.CARD_NOT_ACCEPTED
                io.silencelen.andvari.core.client.account.Reauthed.PROOF_REFUSED -> app.proofRefused(ServerResult.KEYS_NOT_KNOWN_HERE, ServerResult.PROOF_REFUSED)
                else -> common(r.code, r.retryAfterSeconds)?.let { troubleOf<ServerResult>(it) } ?: ServerResult.FAILED
            }
        }
    }

    override fun finishServerSetup(screen: EntryScreen.ServerSetup) {
        if (!on(screen) || screen.step != ServerSetupStep.FINISHED) return
        val flow = flowOf(screen) ?: return
        val kit = flow.setupKit ?: return
        flow.setupKit = null
        val label = app.labelFor(flow.origin) ?: screen.instance
        leave()
        app.kitFlow.show(kit, KitReason.FIRST_KIT, app.accountEmail ?: app.keeper.session?.emailNorm.orEmpty(), label, flow.origin, inEntry = true) { app.opened() }
        app.publish()
    }

    // ---- sign-in ----

    override fun openLinkDevice(screen: EntryScreen.SignInChoice) {
        if (on(screen)) go(EntryScreen.LinkDeviceEntry())
    }

    override fun openPasswordSignIn(screen: EntryScreen.SignInChoice) {
        if (on(screen)) go(EntryScreen.SignInServer(ServerPurpose.SIGN_IN, offersPublicInstance = app.engine.baked != null))
    }

    override fun openForgot(screen: EntryScreen.SignInChoice) {
        if (on(screen)) go(EntryScreen.Forgot())
    }

    override suspend fun choosePublicInstance(screen: EntryScreen.SignInServer): ServerResult = step(screen) {
        val baked = app.engine.baked ?: return ServerResult.FAILED
        if (blocked(baked.origin)) return if (showServer(baked.origin)) ServerResult.IDENTITY_CONFLICT else ServerResult.FAILED
        val flow = EngineFlow(baked.origin)
        firstPin(screen, flow, app.trust.pinBaked(baked.origin), AddressMismatchFor.TYPED_ADDRESS, false) { chosen(screen, screen.purpose, flow) }
    }

    override suspend fun chooseOwnServer(screen: EntryScreen.SignInServer, address: String): ServerResult = step(screen) {
        val purpose = if (screen.purpose == ServerPurpose.SIGN_IN) GatePurpose.SIGN_IN else GatePurpose.ASSISTED_RECOVERY
        typedServer(screen, address, purpose) { flow -> chosen(screen, screen.purpose, flow) }
    }

    private suspend fun chosen(asked: EntryScreen, purpose: ServerPurpose, flow: EngineFlow): ServerResult {
        if (purpose == ServerPurpose.ASK_OPERATOR) {
            // §9.3 step 1: the server is pinned; "Ask the operator for help" for an address typed next. Nothing is sent yet.
            val label = app.labelFor(flow.origin) ?: return ServerResult.FAILED
            go(EntryScreen.AskOperator(flow, label))
            app.publish()
            return ServerResult.DONE
        }
        return beginSignIn(asked, flow)
    }

    /** The keys of a sign-in that waits for its code are dropped, with the password kept beside them. */
    private fun cancelPendingCode(flow: EngineFlow) {
        flow.wipePassword()
        val p = flow.pendingCode ?: return
        flow.pendingCode = null
        app.onboardingFor(flow.origin).cancelSignIn(p)
    }

    override suspend fun submitSignInCode(screen: EntryScreen.SignIn, code: String): SignInAnswer = step(screen) {
        val flow = flowOf(screen) ?: return SignInAnswer.STALE
        val pending = flow.pendingCode
        if (pending == null || !screen.codeNeeded) return SignInAnswer.STALE
        if (app.engine.clock() > flow.pendingPasswordUntilMs) {
            // Past the ten minutes the password was kept for: the step goes, and the password is asked again.
            cancelPendingCode(flow)
            swap(EntryScreen.SignIn(flow, screen.prompt, codeNeeded = false))
            return SignInAnswer.STALE
        }
        flow.pendingCode = null
        val kept = flow.pendingPassword ?: CharArray(0)
        flow.pendingPassword = null
        val called = try {
            call(screen) { app.onboardingFor(flow.origin).signInCode(pending, code.trim()) }
        } catch (e: Throwable) {
            kept.fill('\u0000')
            backToPassword(flow)
            throw e
        }
        val answer = signInCalled(screen, flow, flow.pendingEmail, kept, called)
        backToPassword(flow)
        answer
    }

    /**
     * A sign-in's code step is used once, whatever came of it (an answer of any kind, none, or a late one): where the screen
     * of [flow] still asks for a code that no step holds any more, it goes back to the password, so that a further code is
     * never refused as stale. A step that asks for a code again ([SignIn.TotpRequired]) keeps the code screen.
     */
    private fun backToPassword(flow: EngineFlow) {
        val now = this.screen as? EntryScreen.SignIn ?: return
        if (flowOf(now) !== flow || !now.codeNeeded || flow.pendingCode != null) return
        val offer = earlier?.takeIf { it.on === now }
        val next = EntryScreen.SignIn(flow, now.prompt, codeNeeded = false)
        // An offer of the forgetting that the code's answer raised on this screen stays with it, at the same step.
        if (offer != null) earlier = app.earlierOffer(offer.origin, offer.email, next, offer.confirming, offer.servedUserId)
        swap(next)
    }

    /** A sign-in step's answer, or a late one: then the password copy is wiped and keys the engine holds for a code go. */
    private suspend fun signInCalled(screen: EntryScreen.SignIn, flow: EngineFlow, email: String, kept: CharArray, called: Called<SignIn>): SignInAnswer {
        val r = (called as? Called.Answered)?.value
        if (r == null) {
            kept.fill('\u0000')
            // A late "code needed" holds derived keys in the engine: they go too.
            ((called as? Called.Left)?.late as? SignIn.TotpRequired)?.let { app.onboardingFor(flow.origin).cancelSignIn(it) }
            // Spec 01 §5: the keeper refused the session because the typed address is bound here
            // to another account: the security fault, not "another account is kept".
            if ((called as? Called.Left)?.identity == true) {
                // Offered only where the keeper said the address is tied to ANOTHER account than the one served.
                raiseEarlier(flow.origin, email, ((called as Called.Left).late as? SignIn.IdentityFault)?.anotherAccountServed)
                return SignInAnswer.IDENTITY_FAULT
            }
            // The keeper's own reason, as the sign-in hands it up (`Refused` with the keeper's code): each is said as what
            // it is, and only a refusal that really is another kept session says so.
            val left = called as? Called.Left
            val code = (left?.late as? SignIn.Refused)?.code
            if (left != null && left.refused && code != null) keeperSignInRefusal(code)?.let { return it }
            return lateAnswer(called, SignInAnswer.FAILED)
        }
        return signInAnswer(screen, flow, email, kept, r)
    }

    override suspend fun submitSignIn(screen: EntryScreen.SignIn, email: String, password: String): SignInAnswer = step(screen) {
        // The origin this screen was made for, and no other: whatever was opened since.
        val flow = flowOf(screen) ?: return SignInAnswer.STALE
        cancelPendingCode(flow)
        // Another account is kept here: the password is not sent where it could only open a session to be refused.
        keptStop(flow.origin, email)?.let { return if (it == OPERATOR_ACCOUNT_HELD) SignInAnswer.OPERATOR_ACCOUNT_HELD else SignInAnswer.ANOTHER_ACCOUNT_KEPT }
        val chars = password.toCharArray()
        // The engine wipes what it is handed. This copy is for a kit that turns out never to have been saved, which
        // is made afresh with the password; it is wiped as soon as the answer says it is not needed.
        val kept = chars.copyOf()
        val called = try {
            call(screen) { app.onboardingFor(flow.origin).signIn(email, chars, null) }
        } catch (e: Throwable) {
            kept.fill('\u0000')
            throw e
        } finally {
            chars.fill('\u0000')
        }
        signInCalled(screen, flow, email, kept, called)
    }

    /** The sign-in's answer for the keeper's refusal [code] (a sign-in's `Refused` code), or null for any other code. */
    private fun keeperSignInRefusal(code: String): SignInAnswer? = io.silencelen.andvari.core.app.KeeperReasons.signIn(code)

    /** What a sign-in step came to. [password] is this binding's own copy: handed on, kept for the code, or wiped here. */
    private suspend fun signInAnswer(screen: EntryScreen.SignIn, flow: EngineFlow, email: String, password: CharArray, r: SignIn): SignInAnswer {
        val origin = flow.origin
        if (r is SignIn.SignedIn) {
            if (r.role == "operator" && !app.takesSetupLinks) {
                // §9.1: the operator account signs in only where the operator views are. The session the engine just
                // opened is ended at once, and nothing of the account is kept on this phone.
                password.fill('\u0000')
                app.endServerSaidOperator()
                return SignInAnswer.OPERATOR_NEEDS_COMPUTER
            }
            app.accountEmail = email.trim()
            inviteUsed(flow)
            signedIn(origin, email.trim(), password, r)
            return SignInAnswer.DONE
        }
        if (r is SignIn.TotpRequired) {
            flow.pendingCode = r
            flow.pendingEmail = email
            flow.pendingPassword = password
            flow.pendingPasswordUntilMs = app.engine.clock() + PASSWORD_KEPT_MS
            if (!screen.codeNeeded) swap(EntryScreen.SignIn(flow, screen.prompt, codeNeeded = true))
            return SignInAnswer.CODE_NEEDED
        }
        password.fill('\u0000')
        return when (r) {
            SignIn.InvalidCredentials -> {
                // A wrong code: the engine dropped the derived keys, so the password is asked again.
                if (screen.codeNeeded) swap(EntryScreen.SignIn(flow, screen.prompt, codeNeeded = false))
                SignInAnswer.WRONG
            }
            SignIn.LinkRequired -> {
                val label = app.labelFor(origin) ?: return SignInAnswer.FAILED
                go(EntryScreen.LinkRequired(flow, label, email.trim()))
                SignInAnswer.LINK_REQUIRED
            }
            SignIn.TrustGateFirst -> {
                val wording = if (app.trust.pinState(origin) is PinState.Pinned) TrustGateWording.LINK_OFFER_SIGN_IN else TrustGateWording.TYPED_ADDRESS
                val back: suspend () -> ServerResult = {
                    val label = app.labelFor(origin)
                    if (label == null) {
                        ServerResult.FAILED
                    } else {
                        go(EntryScreen.SignIn(flow, MasterPasswordPrompt(null, label), codeNeeded = false))
                        ServerResult.DONE
                    }
                }
                val fp = app.trust.beginTrustGate(origin, wording)
                if (!stillOn(screen)) return SignInAnswer.STALE
                when (fp) {
                    is FirstPin.NeedsTrustGate -> {
                        // The sign-in screen is not a place to come back to past the gate: confirming shows a fresh one.
                        if (stack.isNotEmpty()) this.screen = stack.removeAt(stack.size - 1)
                        raiseGate(flow, fp, false, back)
                        SignInAnswer.TRUST_GATE_FIRST
                    }
                    // The origin is blocked: it is the server of the screen on show, so its card says why.
                    is FirstPin.Blocked -> {
                        app.publish()
                        SignInAnswer.FAILED
                    }
                    FirstPin.Unreachable -> SignInAnswer.UNREACHABLE
                    else -> SignInAnswer.FAILED
                }
            }
            is SignIn.IdentityFault -> {
                // The keeper's own reason for an address known here under ANOTHER account offers the forgetting; the same
                // account under another key, and a fault of the served account in itself, do not.
                if (r.reason == SELF_IDENTITY_MISMATCH) raiseEarlier(origin, email, r.anotherAccountServed)
                SignInAnswer.IDENTITY_FAULT
            }
            is SignIn.Refused -> {
                // The server did not take the two-step code: never "wrong password". The screen goes back to the password.
                if (r.code == io.silencelen.andvari.core.client.onboard.WireOnboarding.REFUSED_AFTER_CODE) {
                    if (screen.codeNeeded) swap(EntryScreen.SignIn(flow, screen.prompt, codeNeeded = false))
                    return SignInAnswer.REFUSED_AFTER_CODE
                }
                // Spec 01 §7: the server's copy opened to another key than the one this device keeps for the account; and the
                // keeper's other reasons (this device holds its server's operator account, or its copy is damaged), each
                // said as what it is.
                keeperSignInRefusal(r.code)?.let { return it }
                common(r.code, r.retryAfterSeconds)?.let { return troubleOf(it) }
                // A blocked origin is the server of the screen on show, so its card says why.
                if (r.code == "instance_blocked") app.publish()
                SignInAnswer.FAILED
            }
            SignIn.Unreachable -> SignInAnswer.UNREACHABLE
            else -> SignInAnswer.FAILED
        }
    }

    /** The session is established (the sink has it): open the vault, or show a new kit first when none was ever saved. */
    private suspend fun signedIn(origin: String, email: String, password: CharArray, r: SignIn.SignedIn) {
        // Spec 01 §7: the copy this device kept was sealed under another password than the one typed; it follows the
        // server's now, and the person is told so in one line after the sign-in.
        app.signInNotice = if (r.copyUnderOtherPassword) io.silencelen.andvari.core.app.CopyLine.of(CopyKey.SIGNED_IN_COPY_FOLLOWS_SERVER) else null
        val label = app.labelFor(origin)
        if (r.recoveryConfirmed || label == null) {
            // Spec 01 §7: a sign-in with the master password is followed by the quiet re-key (and the served wrap's
            // settling), inside this opening, with the password it proved; the keeper runs it only for a password
            // sign-in. Its outcome changes nothing the person sees. The password is wiped on every path.
            try { app.opened(); withContext(app.engine.work) { app.keeper.reKeyAfterOpening(password) { app.policies.fetch(it, app.engine.clock())?.kdfParams } } } finally { password.fill('\u0000') }
            return
        }
        leave()
        // The kit's rotation takes the password and wipes it.
        app.kitFlow.make(password, KitReason.NEVER_SAVED, email, label, origin, inEntry = true) { app.opened() }
    }

    /** To "Link from your other device", as if the person had walked there from the first screen. */
    private fun toLinkEntry() {
        drop()
        stack += firstRun()
        stack += EntryScreen.SignInChoice()
        screen = EntryScreen.LinkDeviceEntry()
        app.publish()
    }

    override fun linkInstead(screen: EntryScreen.LinkRequired) {
        if (on(screen)) toLinkEntry()
    }

    // ---- §8.2: linking this device (the device-link engine, new-device side) ----

    private fun linkToken(s: NewStep): DeviceLinkToken? = when (s) {
        is NewStep.TrustGate -> s.token
        is NewStep.Claimed -> s.token
        is NewStep.ShowCode -> s.token
        is NewStep.PasswordNeeded -> s.token
        is NewStep.TotpNeeded -> s.token
        is NewStep.WrongPassword -> s.token
        else -> null
    }

    /** How a link that stopped after its claim is told (§8.2): nothing was linked in any of these. */
    internal fun ended(reason: DeviceLinkStop): LinkDeviceEnd = when (reason) {
        DeviceLinkStop.CANCELLED, DeviceLinkStop.CODE_MISMATCH, DeviceLinkStop.TRUST_GATE_DECLINED -> LinkDeviceEnd.CANCELLED
        DeviceLinkStop.EXPIRED -> LinkDeviceEnd.EXPIRED
        DeviceLinkStop.LINK_CLAIMED -> LinkDeviceEnd.ALREADY_CLAIMED
        DeviceLinkStop.PIN_MISMATCH -> LinkDeviceEnd.WRONG_SERVER
        DeviceLinkStop.UNREACHABLE -> LinkDeviceEnd.NO_ANSWER
        // The server did not take the two-step code: the link stopped there; start again with a new link.
        DeviceLinkStop.REFUSED_AFTER_CODE -> LinkDeviceEnd.REFUSED_AFTER_CODE
        // Refused as one of too many requests at a step that cannot wait: never "unreachable", never "a check failed".
        DeviceLinkStop.TOO_MANY -> LinkDeviceEnd.TOO_MANY
        // Spec 01 §7 and the keeper's own reasons (the account this device keeps under another key on the server, another
        // account kept, the address known here under another account or key, its server's operator account held here, a
        // damaged copy): each its own end, never "a check failed".
        else -> io.silencelen.andvari.core.app.KeeperReasons.linkEnd(reason) ?: LinkDeviceEnd.DID_NOT_CHECK_OUT
    }

    /** What a pickup that stopped answers: the result of each end that says its own way out, else ENDED. */
    internal fun pickupStopped(reason: DeviceLinkStop): LinkPasswordResult = when (reason) {
        DeviceLinkStop.UNREACHABLE -> LinkPasswordResult.UNREACHABLE
        DeviceLinkStop.SERVER_KEYS_NOT_KNOWN_HERE -> LinkPasswordResult.SERVER_KEYS_NOT_KNOWN_HERE
        DeviceLinkStop.ANOTHER_SESSION_KEPT -> LinkPasswordResult.ANOTHER_SESSION_KEPT
        DeviceLinkStop.IDENTITY_MISMATCH -> LinkPasswordResult.IDENTITY_FAULT
        DeviceLinkStop.OPERATOR_ACCOUNT_HELD -> LinkPasswordResult.OPERATOR_ACCOUNT_HELD
        DeviceLinkStop.KEPT_COPY_DAMAGED -> LinkPasswordResult.KEPT_COPY_DAMAGED
        DeviceLinkStop.REFUSED_AFTER_CODE -> LinkPasswordResult.REFUSED_AFTER_CODE
        DeviceLinkStop.TOO_MANY -> LinkPasswordResult.RATE_LIMITED
        else -> LinkPasswordResult.ENDED
    }

    /** The screen of [flow]'s link is on show (the poll and the password screen act only then). */
    private fun linkOnShow(flow: EngineFlow): Boolean = app.phase == AppPhase.ENTRY && screen?.flow === flow

    /** The link ended: its screen gives way to [LinkDeviceEnded], and the flow is left behind (polling stops). */
    private fun linkEnded(flow: EngineFlow, reason: DeviceLinkStop, addressKnownHere: String? = null,
                          anotherAccountServed: String? = null, retryAfterSeconds: Long? = null, end: LinkDeviceEnd = ended(reason)) {
        // The wait a refusal for too many requests named, for the end's line ([AppApi.retryAfterSeconds]).
        if (reason == DeviceLinkStop.TOO_MANY) app.noteRetryAfter(retryAfterSeconds)
        flow.linkStep = null
        flow.linkPoll?.cancel()
        flow.linkPoll = null
        flow.wipePassword()
        val left = screen
        screen = EntryScreen.LinkDeviceEnded(end, wait = if (end == LinkDeviceEnd.TOO_MANY) app.namedWait(retryAfterSeconds) else null)
        leftBehind(left)
        // The keeper refused the link because this device knows its address at the link's server under another account
        // (at the approval, before the pickup, or at the take): the link's end offers the forgetting there as a sign-in
        // does, where the earlier account stands as the forgetting would remove it ([EngineAppApi.earlierOffer]).
        if (reason == DeviceLinkStop.IDENTITY_MISMATCH && addressKnownHere != null && anotherAccountServed != null)
            raiseEarlier(flow.origin, addressKnownHere, anotherAccountServed)
        app.publish()
    }

    /** The screen for a step that waits on the other device, or asks for the password; false for a step no screen shows. */
    private fun linkScreen(flow: EngineFlow, s: NewStep, replace: Boolean): Boolean {
        val label = app.labelFor(flow.origin) ?: return false
        val next = when (s) {
            is NewStep.Claimed -> EntryScreen.LinkDeviceWaiting(flow, label)
            is NewStep.ShowCode -> EntryScreen.LinkDeviceCode(flow, label, s.code)
            is NewStep.PasswordNeeded -> {
                flow.pendingEmail = s.email
                EntryScreen.LinkDevicePassword(flow, MasterPasswordPrompt(s.email, label), codeNeeded = false)
            }
            else -> return false
        }
        if (replace) swap(next) else go(next)
        return true
    }

    /**
     * What [s], from a start or a confirmed Trust Gate, came to. Called after the wait for [s]: when the person left
     * [asked] meanwhile, the link is cancelled (the engine forgets its keys, the link is deleted) and nothing is shown.
     */
    private suspend fun linkStarted(asked: EntryScreen, flow: EngineFlow, s: NewStep): DeviceLinkScanResult {
        flow.linkStep = s
        if (!stillOn(asked)) {
            abandon(flow)
            return DeviceLinkScanResult.STALE
        }
        return when (s) {
            is NewStep.Stopped -> {
                flow.linkStep = null
                when (s.reason) {
                    DeviceLinkStop.BAD_LINK, DeviceLinkStop.WRONG_ENTRY -> DeviceLinkScanResult.NOT_A_DEVICE_LINK
                    DeviceLinkStop.INSTANCE_BLOCKED -> if (showServer(flow.origin)) DeviceLinkScanResult.IDENTITY_CONFLICT else DeviceLinkScanResult.FAILED
                    DeviceLinkStop.PIN_REFUSED -> DeviceLinkScanResult.CARD_NOT_ACCEPTED
                    DeviceLinkStop.UNREACHABLE -> DeviceLinkScanResult.UNREACHABLE
                    // The claim refused as one of too many requests: nothing was claimed; the wait it named is kept.
                    DeviceLinkStop.TOO_MANY -> {
                        app.noteRetryAfter(s.retryAfterSeconds)
                        DeviceLinkScanResult.RATE_LIMITED
                    }
                    DeviceLinkStop.BAD_NAME, DeviceLinkStop.KDF_REFUSED, DeviceLinkStop.STALE, DeviceLinkStop.NO_SESSION -> DeviceLinkScanResult.FAILED
                    // Spent, gone or cancelled before anything was linked: the screen says how.
                    else -> {
                        go(EntryScreen.LinkDeviceEnded(ended(s.reason)))
                        DeviceLinkScanResult.DONE
                    }
                }
            }
            is NewStep.OriginMismatch -> {
                flow.linkStep = null
                val m = s.mismatch
                go(EntryScreen.AddressMismatch(null, m.dialedOrigin, m.cardOrigin, AddressMismatchFor.DEVICE_LINK, publicInstance = app.engine.baked?.origin == m.dialedOrigin))
                DeviceLinkScanResult.OTHER_ADDRESS
            }
            is NewStep.PinChanged -> {
                flow.linkStep = null
                // §2.4: a moved or re-kinded chain under an existing pin is handled first; the person scans again after.
                app.cardStatuses[flow.origin] = s.change.status
                if (showServer(flow.origin)) DeviceLinkScanResult.SERVER_CHANGED else DeviceLinkScanResult.FAILED
            }
            is NewStep.TrustGate -> {
                // Nothing is claimed before this device holds a password pin there: the device-link wording of the gate.
                raiseGate(flow, s.gate, false) {
                    val next = app.deviceLinks.afterTrustGate(s, confirmed = true)
                    scanToServer(linkStarted(asked, flow, next))
                }
                DeviceLinkScanResult.DONE
            }
            is NewStep.Claimed, is NewStep.ShowCode, is NewStep.PasswordNeeded -> {
                if (!linkScreen(flow, s, replace = false)) return DeviceLinkScanResult.FAILED
                if (s !is NewStep.PasswordNeeded) poll(flow)
                DeviceLinkScanResult.DONE
            }
            // Not a step a start or a gate answers.
            is NewStep.TotpNeeded, is NewStep.WrongPassword, is NewStep.Linked -> DeviceLinkScanResult.FAILED
        }
    }

    private fun scanToServer(r: DeviceLinkScanResult): ServerResult = when (r) {
        DeviceLinkScanResult.DONE -> ServerResult.DONE
        DeviceLinkScanResult.IDENTITY_CONFLICT -> ServerResult.IDENTITY_CONFLICT
        DeviceLinkScanResult.SERVER_CHANGED -> ServerResult.SERVER_CHANGED
        DeviceLinkScanResult.CARD_NOT_ACCEPTED -> ServerResult.CARD_NOT_ACCEPTED
        DeviceLinkScanResult.OTHER_ADDRESS -> ServerResult.OTHER_ADDRESS
        DeviceLinkScanResult.UNREACHABLE -> ServerResult.UNREACHABLE
        DeviceLinkScanResult.RATE_LIMITED -> ServerResult.RATE_LIMITED
        DeviceLinkScanResult.UPDATE_REQUIRED -> ServerResult.UPDATE_REQUIRED
        DeviceLinkScanResult.STALE -> ServerResult.STALE
        DeviceLinkScanResult.NOT_A_DEVICE_LINK, DeviceLinkScanResult.FAILED -> ServerResult.FAILED
    }

    /** Advance [flow]'s link every [EngineAppApi.linkPollMs] while it waits on the other device; [startOver] cancels it. */
    private fun poll(flow: EngineFlow) {
        flow.linkPoll?.cancel()
        flow.linkPoll = app.scope.launch {
            while (true) {
                kotlinx.coroutines.delay(app.linkPollMs)
                if (!pollOnce(flow)) break
            }
        }
    }

    /** One advance of the link of the screen on show (tests drive the poll with it). True while it still waits. */
    internal suspend fun pollDeviceLink(): Boolean {
        val flow = screen?.flow as? EngineFlow ?: return false
        return pollOnce(flow)
    }

    private suspend fun pollOnce(flow: EngineFlow): Boolean {
        val s = flow.linkStep
        if (s !is NewStep.Claimed && s !is NewStep.ShowCode) return false
        val next = app.deviceLinks.advance(s)
        // Left meanwhile (start over, a lock of the journey): what the engine answered is not shown.
        if (flow.linkStep !== s || !linkOnShow(flow)) return false
        flow.linkStep = next
        return when (next) {
            is NewStep.Claimed -> true
            is NewStep.ShowCode -> {
                if (s !is NewStep.ShowCode || s.code != next.code) linkScreen(flow, next, replace = true)
                true
            }
            is NewStep.PasswordNeeded -> {
                linkScreen(flow, next, replace = true)
                false
            }
            is NewStep.Stopped -> {
                // At the approval (before the pickup, so with no served key) an identity stop that names no address is one
                // this device cannot tell apart: its own line, which points to the password sign-in.
                val cannotTell = next.reason == DeviceLinkStop.IDENTITY_MISMATCH && next.addressKnownHere == null
                linkEnded(flow, next.reason, next.addressKnownHere, next.anotherAccountServed, next.retryAfterSeconds,
                    if (cannotTell) LinkDeviceEnd.IDENTITY_FAULT_CANNOT_TELL else ended(next.reason))
                false
            }
            else -> {
                // A step no waiting screen shows: the link is given up at the engine (its keys and its hold on the address
                // go), not only dropped here.
                linkToken(next)?.let { t -> app.scope.launch { app.deviceLinks.cancel(t) } }
                linkEnded(flow, DeviceLinkStop.STALE)
                false
            }
        }
    }

    override suspend fun submitDeviceLink(screen: EntryScreen.LinkDeviceEntry, payload: String, source: PayloadSource): DeviceLinkScanResult = step(screen) {
        if (shape(payload) != Shape.DEVICE_LINK) return DeviceLinkScanResult.NOT_A_DEVICE_LINK
        val text = payload.trim()
        val parsed = DeviceLinkUrl.parse(text) ?: return DeviceLinkScanResult.NOT_A_DEVICE_LINK
        val origin = parsed.origin
        parsed.wipe()
        if (blocked(origin)) return if (showServer(origin)) DeviceLinkScanResult.IDENTITY_CONFLICT else DeviceLinkScanResult.FAILED
        val flow = EngineFlow(origin)
        linkStarted(screen, flow, app.deviceLinks.start(text, GateEntry.LINK_DEVICE_SCREEN))
    }

    override suspend fun submitLinkPassword(screen: EntryScreen.LinkDevicePassword, password: String): LinkPasswordResult = step(screen) {
        val flow = flowOf(screen) ?: return LinkPasswordResult.STALE
        val s = flow.linkStep
        if (s !is NewStep.PasswordNeeded && s !is NewStep.WrongPassword) return LinkPasswordResult.STALE
        if (password.isEmpty()) return LinkPasswordResult.WRONG
        keptStop(flow.origin, flow.pendingEmail.ifEmpty { null })?.let {
            return if (it == OPERATOR_ACCOUNT_HELD) LinkPasswordResult.OPERATOR_ACCOUNT_HELD else LinkPasswordResult.ANOTHER_ACCOUNT_KEPT
        }
        val chars = password.toCharArray()
        // A kit that was never saved is made once the account is open, and that needs the password again.
        val forKit = chars.copyOf()
        val next = try {
            call(screen) { app.deviceLinks.pickup(s, chars) }
        } catch (e: Throwable) {
            forKit.fill('\u0000')
            throw e
        } finally {
            chars.fill('\u0000')
        }
        pickedCalled(screen, flow, next, forKit)
    }

    override suspend fun submitLinkCode(screen: EntryScreen.LinkDevicePassword, code: String): LinkPasswordResult = step(screen) {
        val flow = flowOf(screen) ?: return LinkPasswordResult.STALE
        val s = flow.linkStep as? NewStep.TotpNeeded ?: return LinkPasswordResult.STALE
        // Past its ten minutes the kept password is gone (a kit never saved is then made at the next unlock).
        if (app.engine.clock() > flow.pendingPasswordUntilMs) flow.wipePassword()
        val forKit = flow.pendingPassword?.copyOf() ?: CharArray(0)
        flow.wipePassword()
        val next = try {
            call(screen) { app.deviceLinks.pickup(s, CharArray(0), code.trim()) }
        } catch (e: Throwable) {
            forKit.fill('\u0000')
            throw e
        }
        pickedCalled(screen, flow, next, forKit)
    }

    private suspend fun pickedCalled(screen: EntryScreen.LinkDevicePassword, flow: EngineFlow, next: Called<NewStep>, forKit: CharArray): LinkPasswordResult {
        val r = (next as? Called.Answered)?.value
        if (r == null) {
            // The keeper refused the pickup's session with the screen still on show: the pickup's own stop says why
            // (another session kept, the keys not this account's, an identity fault), and the link ends with it.
            val left = (next as? Called.Left)?.takeIf { it.refused }
            val stopped = left?.late as? NewStep.Stopped
            if (stopped != null && stopped.reason != DeviceLinkStop.ANOTHER_SESSION_KEPT) {
                // The offer to forget an earlier account is made only where the engine's stop names the address
                // ([NewStep.Stopped.addressKnownHere], raised in [linkEnded]): the address tied here to ANOTHER account
                // than the one served. A refusal that names no address (the same account under another key, or a cause
                // the device cannot tell) raises none.
                return picked(screen, flow, stopped, forKit)
            }
            forKit.fill('\u0000')
            flow.wipePassword()
            return lateAnswer(next, LinkPasswordResult.ANOTHER_ACCOUNT_KEPT)
        }
        return picked(screen, flow, r, forKit)
    }

    /** What a pickup came to. [forKit] is the password, kept only for a kit never saved, and wiped here or by the kit. */
    private suspend fun picked(screen: EntryScreen.LinkDevicePassword, flow: EngineFlow, next: NewStep, forKit: CharArray): LinkPasswordResult {
        flow.wipePassword()
        return when (next) {
            is NewStep.TotpNeeded -> {
                flow.linkStep = next
                flow.pendingPassword = forKit
                flow.pendingPasswordUntilMs = app.engine.clock() + PASSWORD_KEPT_MS
                if (!screen.codeNeeded) swap(EntryScreen.LinkDevicePassword(flow, screen.prompt, codeNeeded = true))
                LinkPasswordResult.CODE_NEEDED
            }
            is NewStep.WrongPassword -> {
                forKit.fill('\u0000')
                flow.linkStep = next
                // A wrong code drops the derived keys: the password is asked again.
                if (screen.codeNeeded) swap(EntryScreen.LinkDevicePassword(flow, screen.prompt, codeNeeded = false))
                // The server refused the proof of a password that opens this device's copy: the link and the password
                // screen stay, and the line asks for the account's current password (never "wrong password"). A refusal
                // after the code step is said as that, with the link still open (never "wrong password" either).
                when {
                    next.proofRefused -> LinkPasswordResult.PROOF_REFUSED
                    next.afterCode -> LinkPasswordResult.CODE_REFUSED_LINK_STAYS
                    else -> LinkPasswordResult.WRONG
                }
            }
            is NewStep.Linked -> {
                flow.linkStep = next
                linkedIn(flow, forKit)
            }
            is NewStep.Stopped -> {
                forKit.fill('\u0000')
                linkEnded(flow, next.reason, next.addressKnownHere, next.anotherAccountServed, next.retryAfterSeconds)
                pickupStopped(next.reason)
            }
            else -> {
                forKit.fill('\u0000')
                LinkPasswordResult.STALE
            }
        }
    }

    /**
     * Linked: the keeper holds the session the pickup opened. A phone refuses the operator account at once (§9.1,
     * §12.2 rule 7); otherwise the vault opens, or a new kit is made first when the account never saved one (§10).
     */
    private suspend fun linkedIn(flow: EngineFlow, forKit: CharArray): LinkPasswordResult {
        if (app.refuseHeldOperator()) {
            forKit.fill('\u0000')
            return LinkPasswordResult.OPERATOR_NEEDS_COMPUTER
        }
        // The pickup's role is the server's word (no card names the account): ended here as at a sign-in, nothing deleted.
        if (app.keeper.session?.role == "operator" && !app.takesSetupLinks) {
            forKit.fill('\u0000')
            app.endServerSaidOperator()
            reset(io.silencelen.andvari.core.app.FirstRunNotice.OPERATOR_NEEDS_COMPUTER)
            app.publish()
            return LinkPasswordResult.OPERATOR_NEEDS_COMPUTER
        }
        val email = flow.pendingEmail
        app.accountEmail = email
        // Spec 01 §7: the copy this device kept was sealed under another master password than the one typed; it follows
        // the server's now, and the person is told in the one line a sign-in has for it.
        val over = (flow.linkStep as? NewStep.Linked)?.copyUnderOtherPassword == true
        app.signInNotice = if (over) io.silencelen.andvari.core.app.CopyLine.of(CopyKey.SIGNED_IN_COPY_FOLLOWS_SERVER) else null
        val kept = app.keeper.session
        val label = app.labelFor(flow.origin)
        if (kept == null || kept.recoveryConfirmed || label == null || forKit.isEmpty()) {
            forKit.fill('\u0000')
            app.opened()
        } else {
            leave()
            // The kit's rotation takes the password and wipes it.
            app.kitFlow.make(forKit, KitReason.NEVER_SAVED, email, label, flow.origin, inEntry = true) { app.opened() }
        }
        return LinkPasswordResult.DONE
    }

    override fun dismissLinkDevice(screen: EntryScreen.LinkDeviceEnded) {
        if (on(screen)) toLinkEntry()
    }

    // ---- §10, §9.3: forgot the master password (bound with the recovery engine) ----

    override fun openKitEntry(screen: EntryScreen.Forgot) {
        if (on(screen)) go(EntryScreen.KitEntry())
    }

    override fun openAskOperator(screen: EntryScreen.Forgot) {
        // The public instance offers no operator recovery (variant R, §7.7), so it is not among the choices here.
        if (on(screen)) go(EntryScreen.SignInServer(ServerPurpose.ASK_OPERATOR, offersPublicInstance = false))
    }

    override suspend fun submitKit(screen: EntryScreen.KitEntry, payload: String, source: PayloadSource): KitScanResult = step(screen) {
        if (shape(payload) != Shape.KIT) return KitScanResult.NOT_A_KIT
        val kit = RecoveryKit.parseQr(payload.trim()) ?: return KitScanResult.NOT_A_KIT
        val origin = kit.origin
        kitStarted(screen, origin, typed = false, app.kitRecovery.start(kit, GateEntry.KIT_RECOVERY_SCREEN))
    }

    override suspend fun submitTypedKit(screen: EntryScreen.KitEntry, email: String, serverAddress: String, groups: String): KitScanResult = step(screen) {
        if (TrustGrammar.emailNorm(email) == null) return KitScanResult.INVALID_EMAIL
        val origin = typedOrigin(serverAddress) ?: return KitScanResult.NOT_AN_ADDRESS
        val check = RecoveryKit.parseSecret(groups) ?: return KitScanResult.NOT_A_KIT
        check.fill(0)
        if (blocked(origin)) return if (showServer(origin)) KitScanResult.IDENTITY_CONFLICT else KitScanResult.FAILED
        kitStarted(screen, origin, typed = true, app.kitRecovery.startTyped(email.trim(), origin, groups, GateEntry.KIT_RECOVERY_SCREEN))
    }

    /**
     * What starting a kit recovery at [origin] came to: the confirmation (behind a Trust Gate when one stands), or why
     * not. Called after the wait for [s]: when the person left [asked] meanwhile, the engine drops the kit's secret and
     * nothing is shown.
     */
    private fun kitStarted(asked: EntryScreen?, origin: String, typed: Boolean, s: KitRecoveryStep): KitScanResult {
        if (stillOn(asked)) return kitShown(origin, typed, s)
        if (s is KitRecoveryStep.ConfirmTarget || s is KitRecoveryStep.OriginMismatch) app.kitRecovery.cancel(s)
        return KitScanResult.STALE
    }

    private fun kitShown(origin: String, typed: Boolean, s: KitRecoveryStep): KitScanResult = when (s) {
        is KitRecoveryStep.ConfirmTarget -> {
            val flow = EngineFlow(s.origin)
            flow.kitStep = s
            flow.kitTyped = typed
            val recover: suspend () -> ServerResult = {
                go(EntryScreen.KitRecover(flow, s.email, kitLabel(s)))
                ServerResult.DONE
            }
            val gate = s.gate
            if (gate != null) {
                flow.gate = gate
                flow.afterGate = recover
                go(EntryScreen.TrustGate(flow, app.gatePrompt(gate, kitChanged = s.kitAnchorMismatch, typedKit = typed)))
            } else {
                go(EntryScreen.KitRecover(flow, s.email, kitLabel(s)))
            }
            KitScanResult.DONE
        }
        is KitRecoveryStep.OriginMismatch -> {
            val flow = EngineFlow(s.mismatch.dialedOrigin)
            flow.kitStep = s
            flow.kitTyped = typed
            val opening = if (typed) AddressMismatchFor.TYPED_KIT else AddressMismatchFor.KIT
            go(EntryScreen.AddressMismatch(flow, s.mismatch.dialedOrigin, s.mismatch.cardOrigin, opening, publicInstance = app.engine.baked?.origin == s.mismatch.dialedOrigin))
            KitScanResult.OTHER_ADDRESS
        }
        is KitRecoveryStep.PinChanged -> {
            app.cardStatuses[origin] = s.change.status
            if (showServer(origin)) KitScanResult.SERVER_CHANGED else KitScanResult.FAILED
        }
        is KitRecoveryStep.Stopped -> when (s.reason) {
            WireKitRecovery.INSTANCE_BLOCKED -> if (showServer(origin)) KitScanResult.IDENTITY_CONFLICT else KitScanResult.FAILED
            WireKitRecovery.UNREACHABLE -> KitScanResult.UNREACHABLE
            WireKitRecovery.BAD_ORIGIN -> KitScanResult.NOT_AN_ADDRESS
            WireKitRecovery.INVALID_EMAIL -> KitScanResult.INVALID_EMAIL
            WireKitRecovery.BAD_KIT -> KitScanResult.NOT_A_KIT
            WireKitRecovery.TRUST_GATE_FIRST, WireKitRecovery.WRONG_SCREEN, WireKitRecovery.STALE -> KitScanResult.FAILED
            // The keeper's answer before anything was sent: an account at another server (or one held as an operator) is
            // kept here. Never "the server's card was not accepted": nothing was asked of that server.
            // (Asked with the origin only, the keeper never answers the identity fault here: no address is named yet.)
            WireKitRecovery.ANOTHER_SESSION_KEPT -> KitScanResult.ANOTHER_ACCOUNT_KEPT
            // This device holds its server's operator account: said as that, with its own way out.
            WireKitRecovery.OPERATOR_ACCOUNT_HELD -> KitScanResult.OPERATOR_ACCOUNT_HELD
            else -> common(s.reason, null)?.let { troubleOf<KitScanResult>(it) } ?: KitScanResult.CARD_NOT_ACCEPTED
        }
        else -> KitScanResult.FAILED
    }

    /** The server a kit recovery names: its pinned card when this device holds one, else the card the gate showed. */
    private fun kitLabel(s: KitRecoveryStep.ConfirmTarget): InstanceLabel = app.labelFor(s.origin)
        ?: s.gate?.let { g -> InstanceLabel(g.name, g.origin, app.kindOf(g.confirm.candidate.kind), selfNamed = true) }
        ?: InstanceLabel(s.instanceName, s.origin, ServerKind.PRIVATE_SERVER, selfNamed = true)

    override suspend fun recoverAtNamedAddress(screen: EntryScreen.AddressMismatch): KitScanResult = step(screen) {
        val flow = flowOf(screen) ?: return KitScanResult.STALE
        val mismatch = flow.kitStep as? KitRecoveryStep.OriginMismatch ?: return KitScanResult.STALE
        flow.kitStep = null
        // Every check runs again at the address the card names, as a fresh start there.
        val next = app.kitRecovery.retargetOrigin(mismatch)
        if (!stillOn(screen)) return kitStarted(null, mismatch.mismatch.cardOrigin, flow.kitTyped, next)
        pop()
        kitStarted(this.screen, mismatch.mismatch.cardOrigin, flow.kitTyped, next).also { app.publish() }
    }

    /** A kit is proved once: whatever the answer, its recovery is over and the journey is back at "Scan your recovery kit". */
    private fun backToKitEntry(flow: EngineFlow) {
        flow.kitStep?.let { app.kitRecovery.cancel(it) }
        flow.kitStep = null
        while (screen?.flow === flow) pop()
        if (screen !is EntryScreen.KitEntry) {
            screen?.let { stack += it }
            screen = EntryScreen.KitEntry()
        }
        app.publish()
    }

    override suspend fun confirmKitRecovery(screen: EntryScreen.KitRecover): KitRecoverResult = step(screen) {
        val flow = flowOf(screen) ?: return KitRecoverResult.STALE
        val target = flow.kitStep as? KitRecoveryStep.ConfirmTarget ?: return KitRecoverResult.STALE
        keptStop(target.origin, target.email)?.let { stop ->
            // The kit is proved once, as on every refusal here: its secret goes, and nothing was sent.
            backToKitEntry(flow)
            return if (stop == OPERATOR_ACCOUNT_HELD) KitRecoverResult.OPERATOR_ACCOUNT_HELD else KitRecoverResult.ANOTHER_ACCOUNT_KEPT
        }
        flow.kitStep = null
        // The step's handle is this call's alone now (no screen holds it): a stop of the host's own while the proof is
        // in flight (the intent's coroutine cancelled) cancels it, so the pin `start` made and the kit's secret go
        // (`KitRecovery.cancel`'s contract: on EVERY stop after a step with a handle).
        val verified = try {
            app.kitRecovery.verify(target)
        } catch (e: Throwable) {
            app.kitRecovery.cancel(target)
            throw e
        }
        if (!stillOn(screen)) {
            // Left meanwhile: the password step's secret goes, and the screen the person went to stays.
            if (verified is KitRecoveryStep.ChoosePassword) app.kitRecovery.cancel(verified)
            return KitRecoverResult.STALE
        }
        when (val r = verified) {
            is KitRecoveryStep.ChoosePassword -> {
                flow.kitStep = r
                go(EntryScreen.ReplacePassword(flow, screen.email, app.labelFor(flow.origin) ?: screen.instance, RecoveryRoute.KIT))
                KitRecoverResult.DONE
            }
            else -> {
                // Anything but the password step ends the recovery: the engine wiped the kit, and it is handed in again.
                backToKitEntry(flow)
                when (r) {
                    KitRecoveryStep.Rejected -> KitRecoverResult.KIT_NOT_ACCEPTED
                    is KitRecoveryStep.Stopped -> when (r.reason) {
                        // The kit's checks stop as `identity_mismatch`: what the server served does not open to the account's
                        // identity. A security fault, said as one (the older code is still read).
                        WireKitRecovery.IDENTITY_MISMATCH, WireKitRecovery.IDENTITY_FAULT -> KitRecoverResult.IDENTITY_FAULT
                        WireKitRecovery.SERVER_KEYS_NOT_KNOWN_HERE -> KitRecoverResult.SERVER_KEYS_NOT_KNOWN_HERE
                        // The keeper, asked once the verify named the account and before a password is asked: another
                        // account is kept here, or the address is known here under another account or key. Nothing was
                        // committed; the old password and kit stand.
                        WireKitRecovery.ANOTHER_SESSION_KEPT -> KitRecoverResult.ANOTHER_ACCOUNT_KEPT
                        SELF_IDENTITY_MISMATCH -> {
                            raiseEarlier(target.origin, target.email, r.anotherAccountServed)
                            KitRecoverResult.IDENTITY_FAULT
                        }
                        // The keeper's other reasons, each with its own way out.
                        WireKitRecovery.OPERATOR_ACCOUNT_HELD -> KitRecoverResult.OPERATOR_ACCOUNT_HELD
                        WireKitRecovery.KEPT_COPY_DAMAGED -> KitRecoverResult.KEPT_COPY_DAMAGED
                        WireKitRecovery.UNREACHABLE -> KitRecoverResult.UNREACHABLE
                        else -> common(r.reason, null)?.let { troubleOf<KitRecoverResult>(it) } ?: KitRecoverResult.FAILED
                    }
                    else -> KitRecoverResult.FAILED
                }
            }
        }
    }

    override suspend fun chooseReplacementPassword(screen: EntryScreen.ReplacePassword, password: String): ReplacePasswordResult = step(screen) {
        val flow = flowOf(screen) ?: return ReplacePasswordResult.STALE
        if (screen.after == RecoveryRoute.OPERATOR_HELP) return assistedCommit(screen, flow, password)
        val choose = flow.kitStep as? KitRecoveryStep.ChoosePassword ?: return ReplacePasswordResult.STALE
        val origin = flow.origin
        val chars = password.toCharArray()
        val watched = app.commitWatch.notTaken
        val called = try {
            call(screen, refusedHere = { (it as? KitRecoveryStep.Recovered)?.let { rec -> rec.notKept != null } ?: false }) { app.kitRecovery.commit(choose, chars) }
        } finally {
            chars.fill('\u0000')
        }
        val answered = (called as? Called.Answered)?.value
        if (answered is KitRecoveryStep.Stopped && app.commitWatch.notTaken != watched) {
            flow.kitStep = null
            return committedNotOpened()
        }
        if (answered == null) {
            val late = (called as? Called.Left)?.late as? KitRecoveryStep.Recovered
            val reason = late?.notKept
            if (late != null && reason != null && (called as Called.Left).refused) {
                // The commit stood at the server and the keeper refused its session, for its own reason, with the screen
                // still on show: the new kit is the account's only one now, so it is shown with the refusal and kept until
                // it is confirmed.
                val result = committedNotKept(reason)
                flow.kitStep = null
                notKeptKit(late.newKit, KitReason.AFTER_RECOVERY, result, screen.email, app.labelFor(origin) ?: screen.instance, origin)
                return result
            }
            // The person left, or it ran out of time: the late commit's new kit goes with the session it opened.
            late?.newKit?.wipe()
            return lateRecoveryAnswer(called)
        }
        when (val r = answered) {
            is KitRecoveryStep.Recovered -> {
                flow.kitStep = null
                if (app.keeper.session?.role == "operator" && !app.takesSetupLinks) {
                    // §9.1: known only from the commit's session. The new password is in force; the session ends here.
                    r.newKit.wipe()
                    app.endServerSaidOperator()
                    reset(null)
                    app.publish()
                    return ReplacePasswordResult.OPERATOR_NEEDS_COMPUTER
                }
                app.accountEmail = screen.email
                val label = app.labelFor(origin) ?: screen.instance
                // The commit replaced the kit: the new one is saved before the vault opens (FS-B1).
                app.kitFlow.show(r.newKit, KitReason.AFTER_RECOVERY, screen.email, label, origin, inEntry = true) { app.opened() }
                drop()
                app.publish()
                ReplacePasswordResult.DONE
            }
            is KitRecoveryStep.Stopped -> when (r.reason) {
                // The step stays: choose another.
                WireKitRecovery.PASSWORD_TOO_WEAK -> ReplacePasswordResult.WEAK_PASSWORD
                WireKitRecovery.UNKNOWN -> {
                    // It may have landed: the way on is a sign-in with the new password.
                    flow.kitStep = null
                    reset(null)
                    this.screen?.let { beginSignIn(it, EngineFlow(origin)) }
                    app.publish()
                    ReplacePasswordResult.MAY_HAVE_WORKED
                }
                else -> {
                    flow.kitStep = null
                    backToKitEntry(flow)
                    when (r.reason) {
                        "recovery_account_not_active" -> ReplacePasswordResult.ACCOUNT_DISABLED
                        // Nothing was committed: the old password and kit stand.
                        WireKitRecovery.SERVER_KEYS_NOT_KNOWN_HERE -> ReplacePasswordResult.SERVER_KEYS_NOT_KNOWN_HERE
                        WireKitRecovery.ANOTHER_SESSION_KEPT -> ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT_NOT_COMMITTED
                        SELF_IDENTITY_MISMATCH -> {
                            raiseEarlier(origin, screen.email, r.anotherAccountServed)
                            ReplacePasswordResult.IDENTITY_FAULT
                        }
                        WireKitRecovery.OPERATOR_ACCOUNT_HELD -> ReplacePasswordResult.OPERATOR_ACCOUNT_HELD
                        WireKitRecovery.KEPT_COPY_DAMAGED -> ReplacePasswordResult.KEPT_COPY_DAMAGED
                        WireKitRecovery.UNREACHABLE -> ReplacePasswordResult.UNREACHABLE
                        else -> common(r.reason, null)?.let { troubleOf<ReplacePasswordResult>(it) } ?: ReplacePasswordResult.FAILED
                    }
                }
            }
            KitRecoveryStep.Rejected -> {
                flow.kitStep = null
                backToKitEntry(flow)
                ReplacePasswordResult.TOO_LATE
            }
            else -> ReplacePasswordResult.FAILED
        }
    }

    // ---- §9.3: a request for the operator's help (the engine's WireAssistedRecovery) ----

    /** The origin an engine step acts on, where it names one. */
    private fun assistOrigin(s: AssistedStep): String? = when (s) {
        is AssistedStep.Requested -> s.origin
        is AssistedStep.Waiting -> s.origin
        is AssistedStep.CheckAccount -> s.origin
        is AssistedStep.ConfirmTarget -> s.origin
        else -> null
    }

    private fun groups(code: String): List<String> = code.split(' ').filter { it.isNotEmpty() }

    private fun stageOf(state: String): OperatorHelpStage = when (state) {
        RecoveryRequestState.UNVERIFIED -> OperatorHelpStage.CODE_NEEDED
        RecoveryRequestState.HOLDING -> OperatorHelpStage.HOLDING
        RecoveryRequestState.AWAITING_OPERATOR -> OperatorHelpStage.AWAITING_OPERATOR
        RecoveryRequestState.VETOED -> OperatorHelpStage.VETOED
        RecoveryRequestState.EXPIRED -> OperatorHelpStage.EXPIRED
        else -> OperatorHelpStage.DID_NOT_CHECK_OUT
    }

    private fun helpScreen(
        flow: EngineFlow, stage: OperatorHelpStage, code: String, holdEndsAt: Long?, replaced: CopyKey? = null,
        stoppedByKey: Boolean = false, unknown: Boolean = false, keysNotKnown: Boolean = false, keeperStop: String? = null,
    ): EntryScreen.OperatorHelp {
        val label = labelOf(flow.origin)
        return EntryScreen.OperatorHelp(flow, label, flow.assistEmail, stage, groups(code), holdEndsAt ?: 0L, replaced,
            keyChange = keyChangeOf(flow.origin, label, stoppedByKey), requestUnknown = if (unknown) CopyKey.ASSIST_REQUEST_UNKNOWN else null,
            keysNotKnownHere = if (keysNotKnown) CopyKey.SIGN_IN_SERVER_KEYS_NOT_KNOWN_HERE else null,
            anotherAccountKept = if (keeperStop == ANOTHER_SESSION_KEPT) CopyKey.ASSIST_ANOTHER_ACCOUNT_KEPT else null,
            identityFault = if (keeperStop == SELF_IDENTITY_MISMATCH) CopyKey.IDENTITY_FAULT_ADDRESS_KNOWN else null,
            operatorAccountHeld = if (keeperStop == OPERATOR_ACCOUNT_HELD) CopyKey.OPERATOR_ACCOUNT_HELD_HERE else null,
            keptCopyDamaged = if (keeperStop == KEPT_COPY_DAMAGED) CopyKey.KEPT_COPY_DAMAGED else null,
            notTheKeptAccount = if (keeperStop == NOT_THE_KEPT_ACCOUNT) CopyKey.ASSIST_NOT_THE_KEPT_ACCOUNT else null)
    }

    /** The keeper's (or a flow's own check's) reasons that stop a recovery with the operator's help and keep its request. */
    private fun keepsRequest(reason: String): Boolean =
        reason == ANOTHER_SESSION_KEPT || reason == SELF_IDENTITY_MISMATCH || reason == OPERATOR_ACCOUNT_HELD || reason == KEPT_COPY_DAMAGED ||
            reason == NOT_THE_KEPT_ACCOUNT

    private fun labelOf(origin: String): InstanceLabel = app.labelFor(origin) ?: InstanceLabel("", origin, ServerKind.PRIVATE_SERVER, selfNamed = true)

    /**
     * The change of the recovery key the engine saw for the request kept for [origin]. [stopped]: the
     * look that just ended stopped on an unsigned change, so the warning is shown even if the engine names none. A signed
     * change is shown only while the request goes on (never beside an unsigned one).
     */
    private fun keyChangeOf(origin: String, label: InstanceLabel, stopped: Boolean): io.silencelen.andvari.core.app.AssistKeyChange? {
        val c = app.assisted.recoveryKeyChange(origin)
        if (stopped) return io.silencelen.andvari.core.app.AssistKeyChange(label, byOldKey = false, rotatedAtMs = 0L)
        if (c == null || !c.signed) return null
        return io.silencelen.andvari.core.app.AssistKeyChange(label, byOldKey = true, rotatedAtMs = c.rotatedAt ?: 0L)
    }

    /** The stage the request's screen showed last for [flow]; awaiting the operator when none was shown. */
    private fun shownStage(flow: EngineFlow): OperatorHelpStage = lastHelp(flow)?.stage ?: OperatorHelpStage.AWAITING_OPERATOR

    /**
     * The journey leaves [flow]'s account check and password screens (what they were opened for is gone) and shows [next],
     * the request's screen, in place of the one under them, or on top when there is none. Publishes.
     */
    private fun backToRequest(flow: EngineFlow, next: EntryScreen.OperatorHelp) {
        fun answerScreen(s: EntryScreen?) = s?.flow === flow && (s is EntryScreen.CheckAccount || s is EntryScreen.ReplacePassword)
        while (answerScreen(screen) && stack.isNotEmpty() && (stack.last().flow === flow)) screen = stack.removeAt(stack.size - 1)
        if (answerScreen(screen)) screen = null
        if ((screen as? EntryScreen.OperatorHelp)?.flow === flow) swap(next) else go(next)
        app.publish()
    }

    /** The last request code shown on a flow's screen, kept for a stage the engine names without it. */
    private fun shownCode(flow: EngineFlow): List<String> = lastHelp(flow)?.requestCode.orEmpty()

    /** The request's screen last shown for [flow]: the one on show, or the newest one under it in the journey. */
    private fun lastHelp(flow: EngineFlow): EntryScreen.OperatorHelp? =
        (listOfNotNull(screen) + stack.asReversed()).firstOrNull { it is EntryScreen.OperatorHelp && it.flow === flow } as? EntryScreen.OperatorHelp

    /**
     * Show what an engine step of a request came to: the request's screen at its stage, or the delivered account to
     * check. [replace]: the request's screen is on show and is replaced in place. A stop that ends the request (a veto,
     * an expiry, an answer that did not check out) is a stage of that screen.
     */
    private fun assistShown(flow: EngineFlow, s: AssistedStep, replace: Boolean): ServerResult {
        val next: EntryScreen = when (s) {
            is AssistedStep.Requested -> helpScreen(flow, OperatorHelpStage.CODE_NEEDED, s.requestCode, null)
            is AssistedStep.Waiting -> helpScreen(flow, stageOf(s.state), s.requestCode, s.holdEndsAt)
            is AssistedStep.CheckAccount -> {
                flow.assistStep = s
                val label = app.labelFor(flow.origin) ?: InstanceLabel(s.instanceName, flow.origin, ServerKind.PRIVATE_SERVER, selfNamed = true)
                go(EntryScreen.CheckAccount(flow, label, flow.assistEmail.ifEmpty { s.email }, s.accountId, keyChange = keyChangeOf(flow.origin, label, stopped = false)))
                app.publish()
                return ServerResult.DONE
            }
            is AssistedStep.Stopped -> return assistStopped(flow, s, replace)
            else -> return ServerResult.FAILED
        }
        flow.assistStep = s
        if (replace) swap(next) else go(next)
        app.publish()
        return ServerResult.DONE
    }

    private fun assistStopped(flow: EngineFlow, s: AssistedStep.Stopped, replace: Boolean): ServerResult {
        // Found by this device's own check before any password is asked: the stored answer is
        // not the one it opened. The request is kept; the screen says the operator must upload it again.
        if (s.reason == WireAssistedRecovery.COMMIT_MISMATCH) {
            flow.assistStep = null
            val next = helpScreen(flow, OperatorHelpStage.AWAITING_OPERATOR, shownCode(flow).joinToString(" "), null, CopyKey.ASSIST_ANSWER_REPLACED)
            if (replace) swap(next) else go(next)
            app.publish()
            return ServerResult.DONE
        }
        // The recovery key changed with no signed rotation covering it (the request is stopped
        // at every look and nothing is opened), or the server no longer knows the request. Either way the request is KEPT,
        // and its screen says which, in place of its stage's own line: never "expired", never "start again" by itself.
        if (s.reason == WireAssistedRecovery.RECOVERY_KEY_CHANGED || s.reason == WireAssistedRecovery.REQUEST_UNKNOWN) {
            val keyChanged = s.reason == WireAssistedRecovery.RECOVERY_KEY_CHANGED
            val stage = shownStage(flow)
            val holdEnds = lastHelp(flow)?.holdEndsAtMs?.takeIf { it > 0 }
            flow.assistStep?.let(app.assisted::setAside)
            flow.assistStep = null
            val next = helpScreen(flow, stage, shownCode(flow).joinToString(" "), holdEnds, stoppedByKey = keyChanged, unknown = !keyChanged)
            if (replace) swap(next) else go(next)
            app.publish()
            return ServerResult.DONE
        }
        // Spec 01 §7: the delivered key is not this account's as this device knows it. Nothing was opened for the person,
        // nothing committed, nothing kept replaced; the request is KEPT, and its screen says so with the way out.
        // The keeper, asked at the pick-up before anything is shown to check: another account is kept here, or the address is
        // known here under another account or key. The request is KEPT (after the sign-out, the next look picks the answer
        // up again), and its screen says which; never "the answer did not check out".
        // So too for the keeper's other reasons (this device holds its server's operator account; its copy is damaged) and
        // an answer that names another account than the one kept for the address: each its own line, the request kept.
        // So too the answer's identity check against this device's own record of the account's key (it runs before the
        // keeper is asked): the account the server gave for the address is not the one this device knows under it, which is
        // the identity fault, said in its own line with the request kept; never "the answer did not check out". No offer.
        val recordMismatch = s.reason == WireAssistedRecovery.IDENTITY_MISMATCH
        if (s.reason == WireAssistedRecovery.SERVER_KEYS_NOT_KNOWN_HERE || keepsRequest(s.reason) || recordMismatch) {
            val holdEnds = lastHelp(flow)?.holdEndsAtMs?.takeIf { it > 0 }
            flow.assistStep?.let(app.assisted::setAside)
            flow.assistStep = null
            val keys = s.reason == WireAssistedRecovery.SERVER_KEYS_NOT_KNOWN_HERE
            val stop = if (recordMismatch) SELF_IDENTITY_MISMATCH else s.reason.takeIf { !keys }
            val next = helpScreen(flow, shownStage(flow), shownCode(flow).joinToString(" "), holdEnds, keysNotKnown = keys, keeperStop = stop)
            if (replace) swap(next) else go(next)
            app.publish()
            if (s.reason == SELF_IDENTITY_MISMATCH) raiseEarlier(flow.origin, flow.assistEmail, s.anotherAccountServed)
            return ServerResult.DONE
        }
        val stage = when (s.reason) {
            RecoveryRequestState.VETOED -> OperatorHelpStage.VETOED
            RecoveryRequestState.EXPIRED -> OperatorHelpStage.EXPIRED
            WireAssistedRecovery.UNOPENABLE, WireAssistedRecovery.BAD_RESPONSE -> OperatorHelpStage.DID_NOT_CHECK_OUT
            WireAssistedRecovery.UNREACHABLE -> return ServerResult.UNREACHABLE
            WireAssistedRecovery.STALE -> return ServerResult.STALE
            // The server or its pin no longer serves this request here: a plain refusal (the engine forgot a request a
            // changed pin no longer covers).
            WireAssistedRecovery.NOT_OFFERED, WireAssistedRecovery.PIN_CHANGED, WireAssistedRecovery.TRUST_GATE_FIRST,
            WireAssistedRecovery.INSTANCE_BLOCKED -> return ServerResult.FAILED
            // Anything else is the verdict of the payload's checks (the shared verifiers' codes): the answer did not check out.
            else -> common(s.reason, s.retryAfterSeconds)?.let { return troubleOf(it) } ?: OperatorHelpStage.DID_NOT_CHECK_OUT
        }
        flow.assistStep = null
        val next = helpScreen(flow, stage, shownCode(flow).joinToString(" "), null)
        if (replace) swap(next) else go(next)
        app.publish()
        return ServerResult.DONE
    }

    override fun openMailboxValue(screen: EntryScreen.AskOperator) {
        if (!on(screen) || screen.mailboxValueOpen) return
        val flow = flowOf(screen) ?: return
        swap(EntryScreen.AskOperator(flow, screen.instance, mailboxValueOpen = true))
        app.publish()
    }

    override suspend fun requestOperatorHelp(screen: EntryScreen.AskOperator, email: String): AskOperatorResult = askOperator(screen, email, null)

    override suspend fun requestOperatorHelpWithValue(screen: EntryScreen.AskOperator, email: String, mailboxValue: String): AskOperatorResult =
        askOperator(screen, email, mailboxValue)

    private suspend fun askOperator(screen: EntryScreen.AskOperator, email: String, mailboxValue: String?): AskOperatorResult = step(screen) {
        val flow = flowOf(screen) ?: return AskOperatorResult.STALE
        if (TrustGrammar.emailNorm(email) == null) return AskOperatorResult.INVALID_EMAIL
        // Decided on 2026-11-17: a value from a mail about a request the person did not make goes with the request. A text
        // that cannot be one is said as that before anything starts; blank is none.
        val value = mailboxValue?.takeIf { it.isNotBlank() }
        if (value != null && WireAssistedRecovery.mailboxValueOf(value) == null) return AskOperatorResult.NOT_A_MAILBOX_VALUE
        val target = when (val s = app.assisted.start(email, flow.origin)) {
            is AssistedStep.ConfirmTarget -> s
            is AssistedStep.Stopped -> return askRefused(s)
            else -> return AskOperatorResult.FAILED
        }
        // The server was chosen behind its own Trust Gate on the way here: a gate the person has not seen is never confirmed for them.
        if (target.gate != null) {
            app.assisted.cancel(target)
            return AskOperatorResult.FAILED
        }
        val r = app.assisted.request(target, value)
        if (r is AssistedStep.Stopped && r.reason == WireAssistedRecovery.BAD_MAILBOX_VALUE) {
            // The engine's own check of the form (the screen's above should have caught it): nothing was sent.
            app.assisted.cancel(target)
            return AskOperatorResult.NOT_A_MAILBOX_VALUE
        }
        if (!on(screen)) return AskOperatorResult.STALE
        when (r) {
            is AssistedStep.Requested -> {
                flow.assistEmail = email.trim()
                assistShown(flow, r, replace = false)
                AskOperatorResult.DONE
            }
            is AssistedStep.Stopped -> askRefused(r)
            else -> AskOperatorResult.FAILED
        }
    }

    /**
     * §9.3 step 5: the commit with the new password, after the person confirmed the delivered account. As after a kit
     * recovery, the commit replaced the kit, and the new one is saved before the vault opens; the request is gone.
     */
    private suspend fun assistedCommit(screen: EntryScreen.ReplacePassword, flow: EngineFlow, password: String): ReplacePasswordResult {
        val choose = flow.assistStep as? AssistedStep.ChoosePassword ?: return ReplacePasswordResult.STALE
        keptStop(flow.origin, null)?.let { stop ->
            // Nothing is sent: what was opened goes, the request is kept, and its screen says why (never "the new password
            // is in force": no commit went).
            app.assisted.setAside(choose)
            flow.assistStep = null
            backToRequest(flow, helpScreen(flow, shownStage(flow), shownCode(flow).joinToString(" "), null, keeperStop = stop))
            return io.silencelen.andvari.core.app.KeeperReasons.beforeCommit(stop) ?: ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT_NOT_COMMITTED
        }
        val origin = flow.origin
        val chars = password.toCharArray()
        val watched = app.commitWatch.notTaken
        val called = try {
            call(screen, refusedHere = { (it as? AssistedStep.Recovered)?.let { rec -> rec.notKept != null } ?: false }) { app.assisted.commit(choose, chars) }
        } finally {
            chars.fill('\u0000')
        }
        val answered = (called as? Called.Answered)?.value
        // The engine used the request up with the commit: it is not kept, and the screen never says it is.
        if (answered is AssistedStep.Stopped && app.commitWatch.notTaken != watched) {
            flow.assistStep = null
            return committedNotOpened()
        }
        if (answered == null) {
            val late = (called as? Called.Left)?.late as? AssistedStep.Recovered
            val reason = late?.notKept
            if (late != null && reason != null && (called as Called.Left).refused) {
                // Committed at the server, refused here for the keeper's own reason with the screen on show: the request is
                // used up (never "kept"), the new password is in force, and the new kit is the account's only one; it is
                // shown with the refusal.
                val result = committedNotKept(reason)
                flow.assistStep = null
                notKeptKit(late.newKit, KitReason.AFTER_RECOVERY, result, flow.assistEmail.ifEmpty { screen.email }, app.labelFor(origin) ?: screen.instance, origin)
                return result
            }
            late?.newKit?.wipe()
            return lateRecoveryAnswer(called)
        }
        return when (val r = answered) {
            is AssistedStep.Recovered -> {
                flow.assistStep = null
                if (app.keeper.session?.role == "operator" && !app.takesSetupLinks) {
                    r.newKit.wipe()
                    app.endServerSaidOperator()
                    reset(null)
                    app.publish()
                    return ReplacePasswordResult.OPERATOR_NEEDS_COMPUTER
                }
                // The account is the delivered one: its address is the one the session names, not the one typed.
                val email = app.keeper.session?.emailNorm ?: screen.email
                app.accountEmail = email
                val label = app.labelFor(origin) ?: screen.instance
                app.kitFlow.show(r.newKit, KitReason.AFTER_RECOVERY, email, label, origin, inEntry = true) { app.opened() }
                drop()
                app.publish()
                ReplacePasswordResult.DONE
            }
            is AssistedStep.Stopped -> when (r.reason) {
                WireAssistedRecovery.PASSWORD_TOO_WEAK -> ReplacePasswordResult.WEAK_PASSWORD
                WireAssistedRecovery.UNKNOWN -> {
                    // It may have landed: the way on is a sign-in with the new password.
                    flow.assistStep = null
                    reset(null)
                    this.screen?.let { beginSignIn(it, EngineFlow(origin)) }
                    app.publish()
                    ReplacePasswordResult.MAY_HAVE_WORKED
                }
                WireAssistedRecovery.UNREACHABLE -> ReplacePasswordResult.UNREACHABLE
                // The answer on the server is not the one this device opened. The engine dropped what
                // it opened and kept the request: the journey goes back to the request's screen, which says so, and its next
                // look picks the operator's new upload up. Never "start again".
                WireAssistedRecovery.COMMIT_MISMATCH -> {
                    flow.assistStep = null
                    backToRequest(flow, helpScreen(flow, OperatorHelpStage.AWAITING_OPERATOR, shownCode(flow).joinToString(" "), null, CopyKey.ASSIST_ANSWER_REPLACED))
                    ReplacePasswordResult.ANSWER_REPLACED
                }
                // The server no longer knows the request. The engine dropped what it opened and kept
                // the request until its own lifetime ends: back to the request's screen, which says so. Never "too late".
                WireAssistedRecovery.REQUEST_UNKNOWN -> {
                    flow.assistStep = null
                    backToRequest(flow, helpScreen(flow, shownStage(flow), shownCode(flow).joinToString(" "), null, unknown = true))
                    ReplacePasswordResult.REQUEST_UNKNOWN
                }
                // Spec 01 §7, asked again before the commit: nothing was committed, the engine dropped what it opened and kept
                // the request. Back to the request's screen, which says so.
                WireAssistedRecovery.SERVER_KEYS_NOT_KNOWN_HERE -> {
                    flow.assistStep = null
                    backToRequest(flow, helpScreen(flow, shownStage(flow), shownCode(flow).joinToString(" "), null, keysNotKnown = true))
                    ReplacePasswordResult.SERVER_KEYS_NOT_KNOWN_HERE
                }
                // The keeper, asked again just before the commit: another account is kept here now, the address is known
                // here under another account or key, this device holds its server's operator account, or its copy of the
                // account is damaged; or the answer names another account than the one kept for the address. Nothing was
                // committed; the engine dropped what it opened and kept the request. Back to the request's screen, which
                // says which.
                ANOTHER_SESSION_KEPT, SELF_IDENTITY_MISMATCH, OPERATOR_ACCOUNT_HELD, KEPT_COPY_DAMAGED, NOT_THE_KEPT_ACCOUNT -> {
                    flow.assistStep = null
                    backToRequest(flow, helpScreen(flow, shownStage(flow), shownCode(flow).joinToString(" "), null, keeperStop = r.reason))
                    if (r.reason == SELF_IDENTITY_MISMATCH) raiseEarlier(origin, flow.assistEmail, r.anotherAccountServed)
                    io.silencelen.andvari.core.app.KeeperReasons.beforeCommit(r.reason) ?: ReplacePasswordResult.FAILED
                }
                else -> common(r.reason, r.retryAfterSeconds)?.let { troubleOf<ReplacePasswordResult>(it) } ?: run {
                    // The request cannot be committed any more (vetoed, also by whoever runs the server; expired, not
                    // confirmed, refused): it is over, and its own line says so.
                    flow.assistStep = null
                    reset(null)
                    app.publish()
                    ReplacePasswordResult.REQUEST_ENDED
                }
            }
            else -> ReplacePasswordResult.FAILED
        }
    }

    private fun askRefused(s: AssistedStep.Stopped): AskOperatorResult = when (s.reason) {
        WireAssistedRecovery.INVALID_EMAIL -> AskOperatorResult.INVALID_EMAIL
        WireAssistedRecovery.MAIL_UNAVAILABLE -> AskOperatorResult.MAIL_UNAVAILABLE
        WireAssistedRecovery.UNREACHABLE -> AskOperatorResult.UNREACHABLE
        WireAssistedRecovery.STALE -> AskOperatorResult.STALE
        else -> common(s.reason, s.retryAfterSeconds)?.let { troubleOf<AskOperatorResult>(it) } ?: AskOperatorResult.FAILED
    }

    override suspend fun verifyOperatorHelp(screen: EntryScreen.OperatorHelp, code: String): CodeResult = step(screen) {
        val flow = flowOf(screen) ?: return CodeResult.STALE
        val requested = flow.assistStep as? AssistedStep.Requested ?: return CodeResult.STALE
        val r = app.assisted.verifyCode(requested, code)
        if (!on(screen)) return CodeResult.STALE
        when (r) {
            is AssistedStep.Waiting -> {
                assistShown(flow, r, replace = true)
                CodeResult.DONE
            }
            is AssistedStep.Stopped -> when (r.reason) {
                // The step stays: type it again.
                WireAssistedRecovery.BAD_CODE -> CodeResult.WRONG_CODE
                // Kept until its own lifetime ends, and its screen says so. Never "expired".
                WireAssistedRecovery.REQUEST_UNKNOWN -> {
                    swap(helpScreen(flow, OperatorHelpStage.CODE_NEEDED, shownCode(flow).joinToString(" "), null, unknown = true))
                    CodeResult.REQUEST_UNKNOWN
                }
                // The server cancelled the request (its owner changed the password or the recovery setting, or the
                // account was recovered): the link engine forgot it, so nothing of it is left to show or to wait on.
                WireAssistedRecovery.REQUEST_CANCELLED -> {
                    flow.assistStep = null
                    reset(null)
                    app.publish()
                    CodeResult.REQUEST_CANCELLED
                }
                WireAssistedRecovery.UNREACHABLE -> CodeResult.UNREACHABLE
                WireAssistedRecovery.STALE -> CodeResult.STALE
                else -> common(r.reason, r.retryAfterSeconds)?.let { troubleOf<CodeResult>(it) } ?: CodeResult.FAILED
            }
            else -> CodeResult.FAILED
        }
    }

    override suspend fun refreshOperatorHelp(screen: EntryScreen.OperatorHelp): ServerResult = step(screen) {
        val flow = flowOf(screen) ?: return ServerResult.STALE
        // A screen shown from a kept request after a restart holds no step: the kept request is asked again.
        val r = flow.assistStep?.let { app.assisted.poll(it) } ?: app.assisted.resume(flow.origin) ?: return ServerResult.STALE
        if (!on(screen)) return ServerResult.STALE
        assistShown(flow, r, replace = true)
    }

    override fun acceptRecoveredAccount(screen: EntryScreen.CheckAccount) {
        if (!on(screen)) return
        val flow = flowOf(screen) ?: return
        val check = flow.assistStep as? AssistedStep.CheckAccount ?: return
        // The first "it is the same" shows the comparison's second step, so one tap cannot pass it.
        if (!screen.confirming) {
            swap(EntryScreen.CheckAccount(flow, screen.instance, screen.email, screen.accountId, confirming = true, keyChange = screen.keyChange))
            app.publish()
            return
        }
        // Local only (nothing is sent): the engine marks the delivered account confirmed and hands the password step.
        app.scope.launch(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) {
            val r = app.assisted.confirmAccount(check, same = true)
            if (!on(screen) || r !is AssistedStep.ChoosePassword) return@launch
            flow.assistStep = r
            go(EntryScreen.ReplacePassword(flow, screen.email, screen.instance, RecoveryRoute.OPERATOR_HELP))
            app.publish()
        }
    }

    override fun rejectRecoveredAccount(screen: EntryScreen.CheckAccount) {
        if (!on(screen)) return
        val flow = flowOf(screen) ?: return
        val check = flow.assistStep as? AssistedStep.CheckAccount
        flow.assistStep = null
        // "If it is different, stop": the engine drops the request's secrets for good; the server is told nothing.
        if (check != null) app.scope.launch(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) { app.assisted.confirmAccount(check, same = false) }
        reset(FirstRunNotice.RECOVERY_STOPPED)
        app.publish()
    }

    override fun recoveredAccountNotNow(screen: EntryScreen.CheckAccount) {
        if (!on(screen)) return
        // Nothing is dropped: the request stays kept, and the first screen offers it again.
        reset(null)
        app.publish()
    }

    override fun abandonOperatorHelp(screen: EntryScreen.OperatorHelp) {
        if (!on(screen)) return
        val flow = flowOf(screen) ?: return
        val step = flow.assistStep
        flow.assistStep = null
        // The offer of the forgetting this request's refusal raised outlives the request it waited on: the first screen
        // keeps it, where the forgetting is no longer held up by the request.
        val offered = earlierOnShow()
        // The kept request, its secrets and any pin the flow made go; the server is told nothing and the request lapses there.
        if (step != null) app.assisted.cancel(step) else KeptAssistRequests.forget(app.requestStore, flow.origin)
        reset(null)
        app.publish()
        offered?.let { raiseEarlier(it.origin, it.email, it.servedUserId) }
    }

    private companion object {
        /** [io.silencelen.andvari.core.app.KeeperReasons.WHILE_ANOTHER_KEPT], read by the fake too. */
        val WHILE_ANOTHER_KEPT: Set<IntentResult> get() = io.silencelen.andvari.core.app.KeeperReasons.WHILE_ANOTHER_KEPT

        /** How long a password typed before a code step is kept: the two-step key's ten minutes. */
        const val PASSWORD_KEPT_MS = 10 * 60_000L

        /** The keeper's answer for an address this device knows under another account or key (its identity fault). */
        const val SELF_IDENTITY_MISMATCH = io.silencelen.andvari.core.client.onboard.AccountOpen.SELF_IDENTITY_MISMATCH

        /** The keeper's answer while another account's session is kept on this device. */
        const val ANOTHER_SESSION_KEPT = io.silencelen.andvari.core.client.session.Establishing.ANOTHER_SESSION_KEPT

        /** The keeper's answer while this device holds its server's operator account. */
        const val OPERATOR_ACCOUNT_HELD = io.silencelen.andvari.core.client.session.Establishing.OPERATOR_ACCOUNT_HELD

        /** The keeper's answer for a copy of the account on this device that is damaged. */
        const val KEPT_COPY_DAMAGED = io.silencelen.andvari.core.client.session.Establishing.KEPT_COPY_DAMAGED

        /** The operator's answer names another account than the one this device keeps for the address. */
        const val NOT_THE_KEPT_ACCOUNT = io.silencelen.andvari.core.client.recovery.WireAssistedRecovery.NOT_THE_KEPT_ACCOUNT
    }
}
