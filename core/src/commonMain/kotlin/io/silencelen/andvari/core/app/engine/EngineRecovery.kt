package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.KitAfterMovePrompt
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.KitReason
import io.silencelen.andvari.core.app.OperatorHelpStage
import io.silencelen.andvari.core.app.OperatorRecoveryWarning
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.RecoveryApi
import io.silencelen.andvari.core.app.RecoveryChangeResult
import io.silencelen.andvari.core.app.RecoveryQuestion
import io.silencelen.andvari.core.app.RecoveryRequestRow
import io.silencelen.andvari.core.app.RecoveryScreen
import io.silencelen.andvari.core.app.WhoCanRecover
import io.silencelen.andvari.core.client.account.Fetched
import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.account.RecoveryPostureView
import io.silencelen.andvari.core.client.account.WireAccountSettings
import io.silencelen.andvari.core.client.account.WireRecoverySettings
import io.silencelen.andvari.core.client.onboard.OperatorRecoveryOffer
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.recovery.EscrowDecision
import io.silencelen.andvari.core.client.recovery.LiveRecoveryRequests
import io.silencelen.andvari.core.client.recovery.VetoOutcome
import io.silencelen.andvari.core.client.recovery.WireRecoveryRequests
import io.silencelen.andvari.core.model.wire.RecoveryPosture
import io.silencelen.andvari.core.model.wire.RecoveryRequestState
import io.silencelen.andvari.core.model.wire.RecoveryRequestSummary
import io.silencelen.andvari.core.model.wire.WireErrors

/**
 * Recovery in Settings (design §4.5, §7.7, §9.3 step 2, §10) on the engine's [WireRecoverySettings] and
 * [WireRecoveryRequests]: who can recover the account, as the account's own `recovery` record says (never a served
 * posture, T-B4); turning operator recovery on only behind the warning, its box and the master password, with the offer
 * this device made from the pinned card; turning it off; a new kit through the kit screen; and the veto of a request
 * for the operator's help.
 *
 * At every opening of the vault (not over a copy the server signed out) the posture is read once in the vault's scope:
 * §4.5's silent re-seal happens there when its rules allow it, and otherwise "Keep that?" or the unsigned-change warning
 * is asked as a prompt, until it is answered or put off until the next unlock. The same read gives §8.5's operator
 * clause ([operatorRecorded]).
 */
internal class EngineRecovery(private val app: EngineAppApi) : RecoveryApi {
    private var open = false
    private var reviewing = false

    /** The posture as last read this opening; null before the first read. */
    private var view: RecoveryPostureView? = null

    /** The offer this device made from the pinned card when the screen opened; null when none is offered. */
    private var offer: OperatorRecoveryOffer? = null
    private var requests: List<RecoveryRequestSummary> = emptyList()
    private var shown: RecoveryScreen? = null
    private val rowsShown = HashMap<String, RecoveryRequestRow>()

    /** Prompts put off until the next unlock ("Later", "Not now"). */
    private var putOff = false
    private var keyChanged: AccountPrompt.RecoveryKeyChanged? = null
    private var keepOperator: AccountPrompt.KeepOperatorRecovery? = null

    /** Moves on at every lock and end, so an answer for an opening that went is not applied. */
    private var generation = 0

    fun locked() {
        open = false
        reviewing = false
        view = null
        offer = null
        requests = emptyList()
        requestsUnreadable = 0
        requestsNotRead = false
        shown = null
        rowsShown.clear()
        putOff = false
        keyChanged = null
        keepOperator = null
        postureDue = false
        alerts = null
        alertCountRead = -1
        alertUnreadable = false
        alertReading = false
        alertShown = null
        unreadableDismissedAt = null
        cancelNotTaken.clear()
        syncSeen = false
        generation++
    }

    fun ended() = locked()

    private fun unlocked() = app.phase == AppPhase.UNLOCKED && app.keeper.established != null && app.vault?.signedOutByServer != true

    private fun origin(): String? = app.keeper.established?.origin

    private fun accountSettings(): WireAccountSettings? {
        val est = app.keeper.established ?: return null
        val pin = app.trust.pinFor(est.origin) ?: return null
        val reauth = app.keeper.reauth() ?: return null
        return WireAccountSettings(est.origin, est.emailNorm, pin.card0Hash, est.account, app.clientFor(est.origin), app.crypto, reauth,
            app.keeper.accountKdfParams() ?: io.silencelen.andvari.core.crypto.KdfParams.DEFAULT, thisDevice = est.deviceId)
    }

    private fun settings(): WireRecoverySettings? {
        val est = app.keeper.established ?: return null
        val kit = accountSettings() ?: return null
        val reauth = app.keeper.reauth() ?: return null
        return WireRecoverySettings(est.origin, est.account, app.clientFor(est.origin), app.crypto, app.engine.state, app.trust, reauth, kit, app.engine.clock)
    }

    private fun requestsFlow(): WireRecoveryRequests? {
        val est = app.keeper.established ?: return null
        return WireRecoveryRequests(est.origin, est.account, app.clientFor(est.origin), app.trust, app.crypto, app.engine.clock)
    }

    private fun operatorAccount(): Boolean = app.keeper.established?.role == "operator"

    /**
     * §8.5: the account's record says the operator may restore it (as last read this opening); null while this
     * opening's read has not answered, or failed (unknown is shown as unknown).
     */
    fun operatorRecorded(): Boolean? {
        if (!unlocked()) return false
        val v = view ?: return null
        return v.record?.posture == RecoveryPosture.OPERATOR
    }

    // ---- at an opening of the vault ----

    /**
     * This opening's posture is still to be read: set at the opening, cleared at the answer taken, a lock or an end. A
     * vault composed again meanwhile (update required, the policy or the consent) cancels the read with the old vault's
     * scope, so [recomposed] reads it again on the new one.
     */
    private var postureDue = false

    /** Read the posture once for this opening, in the vault's scope; a prompt follows when §4.5 asks one. */
    fun opened() {
        postureDue = true
        readPosture()
        readAlerts()
    }

    /** The open vault was composed again: a posture read it cancelled is made again, in the new vault's scope. */
    fun recomposed() {
        if (postureDue) readPosture()
        if (alerts == null) readAlerts()
    }

    // ---- §9.3 step 2: a request for the operator's help made for this account (the alert) ----

    /** The account's live requests as last read this opening; null before the first read answered. */
    private var alerts: List<RecoveryRequestSummary>? = null

    /**
     * What the last read stands for: the number the list showed (or the sync's count when it could not be read), so that
     * a sync whose count differs reads the list again; -2 after a read that failed (the next completed sync reads again).
     */
    private var alertCountRead = -1

    /** The server's count names more requests than its list shows, or the list could not be read while it names one. */
    private var alertUnreadable = false

    /** The screen's list as last read: rows the server sent that this device could not read, and a list not read at all. */
    private var requestsUnreadable = 0
    private var requestsNotRead = false
    private var alertReading = false
    private var alertShown: AccountPrompt.RecoveryRequest? = null

    /** "This was me" on an alert that could not be read: not raised again until the count changes. */
    private var unreadableDismissedAt: Int? = null

    /** Requests a cancel from this device was answered as done for, which the server still lists. */
    private val cancelNotTaken = HashSet<String>()
    private var syncSeen = false

    /**
     * The open vault's content published a new state: after a completed sync whose count of requests (spec 03 §4,
     * `recoveryRequests`) differs from what the last read stands for, the list is read again, in the vault's scope.
     */
    fun contentChanged() {
        if (!unlocked()) return
        val v = app.vault ?: return
        if (v.content.state.syncing) {
            syncSeen = true
            return
        }
        if (!syncSeen) return
        syncSeen = false
        val counted = v.recoveryRequestsCounted
        if (counted >= 0 && counted != alertCountRead) readAlerts()
    }

    private fun readAlerts() {
        if (!unlocked() || alertReading) return
        val v = app.vault ?: return
        val flow = requestsFlow() ?: return
        val g = generation
        alertReading = true
        v.launch {
            try {
                val r = flow.live()
                if (g != generation || !unlocked()) return@launch
                takeAlerts(r, v.recoveryRequestsCounted)
                app.publish()
            } finally {
                if (g == generation) alertReading = false
            }
        }
    }

    /** What a read of the account's list answered, against the sync's [counted] (-1 when no pull answered yet). */
    private fun takeAlerts(r: LiveRecoveryRequests, counted: Int) {
        when (r) {
            is LiveRecoveryRequests.Listed -> {
                alerts = r.requests
                alertCountRead = r.requests.size
                // The server's count and its list disagree, or it sent rows this device could not read
                // (each dropped and counted): which one lies is not known here, so the alert is raised.
                alertUnreadable = counted > r.requests.size || r.unreadable > 0
                val ids = r.requests.mapTo(HashSet()) { it.requestId }
                cancelNotTaken.retainAll(ids)
                if (open) {
                    requests = r.requests
                    requestsUnreadable = r.unreadable
                    requestsNotRead = false
                    shown = null
                }
            }
            LiveRecoveryRequests.NotOffered -> {
                alerts = emptyList()
                alertCountRead = counted
                alertUnreadable = false
            }
            else -> {
                // Not read: what was shown stays, and the alert is raised when the count (or what was shown) names one.
                alertCountRead = -2
                alertUnreadable = counted > 0 || !alerts.isNullOrEmpty()
            }
        }
        if (!alertUnreadable) unreadableDismissedAt = null
    }

    private fun mineKey(): String? = app.keeper.established?.let { "$MINE_KEY${it.origin}|${it.userId}" }

    private fun mine(): Set<String> =
        mineKey()?.let { app.engine.state.get(it) }?.split(',')?.filter { it.isNotEmpty() }?.toSet().orEmpty()

    /** The row for [r], the same object while nothing it shows changed (the screen's and the alert's rows are one). */
    private fun rowOf(r: RecoveryRequestSummary): RecoveryRequestRow {
        val answered = r.state == RecoveryRequestState.READY
        val now = app.engine.clock()
        // §9.3: every request waits seven days after its code was proved. A shorter wait, or "over" before then, is the
        // server's own doing; nothing here can stop it, so it is said.
        val cut = r.holdEndsAt - r.verifiedAt < HOLD_MS - HOLD_SLACK_MS ||
            (r.state != RecoveryRequestState.HOLDING && now < r.verifiedAt + HOLD_MS - HOLD_SLACK_MS)
        val notTaken = r.requestId in cancelNotTaken
        val stage = stageOf(r)
        rowsShown[r.requestId]?.takeIf {
            it.stage == stage && it.holdEndsAtMs == r.holdEndsAt && it.askedAtMs == r.createdAt && it.verifiedAtMs == r.verifiedAt &&
                it.answered == answered && it.holdCutShort == cut && it.cancelNotTaken == notTaken && it.reportedPlatform.wireName == platformOf(r).wireName
        }?.let { return it }
        return RecoveryRequestRow(r.requestId, stage, r.createdAt, r.verifiedAt, r.holdEndsAt, platformOf(r), answered, cut, notTaken)
            .also { rowsShown[r.requestId] = it }
    }

    private fun platformOf(r: RecoveryRequestSummary): AppPlatform =
        AppPlatform.entries.firstOrNull { it.wireName == r.platform && it != AppPlatform.UNKNOWN } ?: AppPlatform.UNKNOWN

    /** The alert to raise, while the account has a live request the person has not said was theirs. */
    private fun alertPrompt(): AccountPrompt.RecoveryRequest? {
        val minePrior = mine()
        val live = alerts.orEmpty().filter { it.requestId !in minePrior }
        val unreadable = alertUnreadable && unreadableDismissedAt != alertCountRead
        if (live.isEmpty() && !unreadable) {
            alertShown = null
            return null
        }
        val rows = live.map(::rowOf)
        alertShown?.takeIf { it.unreadable == unreadable && it.requests.size == rows.size && it.requests.zip(rows).all { (a, b) -> a === b } }?.let { return it }
        return AccountPrompt.RecoveryRequest(rows, unreadable).also { alertShown = it }
    }

    override fun recoveryRequestWasMe(prompt: AccountPrompt.RecoveryRequest) {
        if (!unlocked() || alertShown !== prompt) return
        val key = mineKey() ?: return
        val ids = mine() + prompt.requests.map { it.requestId }
        app.engine.state.set(key, ids.sorted().joinToString(",").ifEmpty { null })
        if (prompt.unreadable) unreadableDismissedAt = alertCountRead
        alertShown = null
        app.publish()
    }

    private fun readPosture() {
        if (!unlocked()) return
        val v = app.vault ?: return
        val g = generation
        v.launch {
            val s = settings() ?: return@launch
            val r = s.posture()
            if (g != generation || !unlocked() || r !is Fetched.Ok) return@launch
            postureDue = false
            take(r.value)
            app.publish()
        }
    }

    private fun take(next: RecoveryPostureView) {
        view = next
        shown = null
    }

    /** The prompts of §4.5 to show, while not put off. */
    fun prompts(): List<AccountPrompt> {
        if (!unlocked()) return emptyList()
        // §9.3 step 2 first: it is the one a person must see, and nothing puts it off but "this was me" or the cancel.
        val alert = listOfNotNull(alertPrompt())
        if (putOff) return alert
        val label = origin()?.let(app::labelFor) ?: return alert
        return alert + when (view?.pending) {
            is EscrowDecision.UnsignedChange -> listOf(keyChanged?.takeIf { sameLabel(it.instance, label) }
                ?: AccountPrompt.RecoveryKeyChanged(label).also { keyChanged = it })
            is EscrowDecision.AskOwnMirror -> listOf(keepOperator?.takeIf { sameLabel(it.instance, label) }
                ?: AccountPrompt.KeepOperatorRecovery(label).also { keepOperator = it })
            else -> emptyList()
        }
    }

    private fun sameLabel(a: io.silencelen.andvari.core.app.InstanceLabel, b: io.silencelen.andvari.core.app.InstanceLabel) =
        a.origin == b.origin && a.name == b.name && a.kind == b.kind

    // ---- the screen ----

    fun screen(): RecoveryScreen? {
        if (!open || !unlocked()) return null
        shown?.let { return it }
        val v = view ?: return null
        val label = origin()?.let(app::labelFor) ?: return null
        val unsigned = v.pending is EscrowDecision.UnsignedChange
        val o = offer
        val rows = requests.map(::rowOf)
        return RecoveryScreen(
            whoCanRecover = if (v.record?.posture == RecoveryPosture.OPERATOR) WhoCanRecover.ME_OR_OPERATOR else WhoCanRecover.ONLY_ME,
            question = if (o != null) RecoveryQuestion(label, unsigned) else null,
            warning = if (o != null && reviewing) OperatorRecoveryWarning(label, unsigned) else null,
            requests = rows,
            unreadableRequests = requestsUnreadable,
            requestsNotRead = requestsNotRead,
        ).also { shown = it }
    }

    /** `ready` (answered, not committed) is past the hold too: [RecoveryRequestRow.answered] says it was answered. */
    private fun stageOf(r: RecoveryRequestSummary): OperatorHelpStage =
        if (r.state == RecoveryRequestState.HOLDING) OperatorHelpStage.HOLDING else OperatorHelpStage.AWAITING_OPERATOR

    override suspend fun openRecovery(): PlainResult {
        if (!unlocked()) return PlainResult.STALE
        val s = settings() ?: return PlainResult.STALE
        val g = ++generation
        // A lock while the posture is read (its re-seal is under the account's guard): STALE.
        val r = app.unlessLocked(null) { app.working { s.posture() } }
        if (r == null || g != generation || !unlocked()) return PlainResult.STALE
        val v = when (r) {
            is Fetched.Ok -> r.value
            is Fetched.Refused -> return when (r.code) {
                WireErrors.RATE_LIMITED -> PlainResult.RATE_LIMITED
                WireErrors.UPGRADE_REQUIRED -> PlainResult.UPDATE_REQUIRED
                else -> PlainResult.FAILED
            }
            Fetched.Unreachable -> return PlainResult.UNREACHABLE
        }
        // The offer comes from the pinned card only, and never for the operator account (§7.7).
        val o = if (v.operatorOffered && !operatorAccount()) app.working { s.operatorOffer() } else null
        val listed = app.working { requestsFlow()?.live() }
        if (g != generation || !unlocked()) return PlainResult.STALE
        take(v)
        offer = o
        requests = (listed as? LiveRecoveryRequests.Listed)?.requests ?: emptyList()
        requestsUnreadable = (listed as? LiveRecoveryRequests.Listed)?.unreadable ?: 0
        // Not read at all (no answer, a refusal, a body that is not a list): the empty list says so, never "nobody asked".
        requestsNotRead = listed is LiveRecoveryRequests.Unreachable || listed is LiveRecoveryRequests.Refused
        // The same read feeds the alert.
        if (listed != null) takeAlerts(listed, app.vault?.recoveryRequestsCounted ?: -1)
        open = true
        reviewing = false
        shown = null
        app.publish()
        return PlainResult.DONE
    }

    override fun closeRecovery() {
        if (!open) return
        open = false
        reviewing = false
        shown = null
        app.publish()
    }

    override fun reviewOperatorRecovery(screen: RecoveryScreen) {
        if (!open || shown !== screen || screen.question == null) return
        reviewing = true
        shown = null
        app.publish()
    }

    override suspend fun turnOnOperatorRecovery(warning: OperatorRecoveryWarning, understood: Boolean, password: String): RecoveryChangeResult {
        if (!open || !unlocked() || shown?.warning !== warning) return RecoveryChangeResult.STALE
        // The box is part of the consent: without it nothing is derived or sent.
        if (!understood) return RecoveryChangeResult.NOT_TICKED
        val o = offer ?: return RecoveryChangeResult.OPERATOR_RECOVERY_UNAVAILABLE
        return change { it.setPosture(RecoveryChoiceKind.OPERATOR, o, true, password.toCharArray()) }
    }

    override fun keepRecoveryPrivate(warning: OperatorRecoveryWarning) {
        if (shown?.warning !== warning) return
        reviewing = false
        shown = null
        app.publish()
    }

    override suspend fun turnOffOperatorRecovery(screen: RecoveryScreen, password: String): RecoveryChangeResult {
        if (!open || !unlocked() || shown !== screen) return RecoveryChangeResult.STALE
        return change { it.setPosture(RecoveryChoiceKind.PRIVATE, null, false, password.toCharArray()) }
    }

    /** One `PUT /account/recovery`† through [WireRecoverySettings]; on success the posture is read again. */
    private suspend fun change(send: suspend (WireRecoverySettings) -> Reauthed<*>): RecoveryChangeResult {
        val s = settings() ?: return RecoveryChangeResult.STALE
        val g = generation
        // A lock during the change's waits: the escrow is sealed and sent under the guard only, so nothing
        // more went, and the intent answers STALE.
        val r = app.unlessLocked(null) { app.working { send(s) } }
        if (r == null || g != generation || !unlocked()) return RecoveryChangeResult.STALE
        val result = result(r)
        if (result == RecoveryChangeResult.DONE) {
            reviewing = false
            keyChanged = null
            keepOperator = null
            // The change was made; a lock while the posture is read again leaves it for the next opening's read.
            (app.unlessLocked(null) { app.working { s.posture() } } as? Fetched.Ok)?.let { if (g == generation) take(it.value) }
            shown = null
            app.publish()
        }
        return result
    }

    private fun result(r: Reauthed<*>): RecoveryChangeResult = when (r) {
        is Reauthed.Done -> RecoveryChangeResult.DONE
        Reauthed.WrongPassword -> RecoveryChangeResult.WRONG_PASSWORD
        Reauthed.Unknown -> RecoveryChangeResult.UNREACHABLE
        Reauthed.NoSession, Reauthed.PasswordTooWeak -> RecoveryChangeResult.FAILED
        is Reauthed.Refused -> {
            app.noteRetryAfter(r.retryAfterSeconds)
            when (r.code) {
                WireErrors.RATE_LIMITED -> RecoveryChangeResult.RATE_LIMITED
                WireErrors.UPGRADE_REQUIRED -> RecoveryChangeResult.UPDATE_REQUIRED
                WireErrors.CREDENTIAL_CHANGED -> RecoveryChangeResult.CHANGED_ELSEWHERE
                WireErrors.ESCROW_WRONG_FORM -> RecoveryChangeResult.ESCROW_WRONG_FORM
                Reauthed.PROOF_REFUSED -> app.proofRefused(RecoveryChangeResult.KEYS_NOT_KNOWN_HERE, RecoveryChangeResult.PROOF_REFUSED)
                WireRecoverySettings.OPERATOR_RECOVERY_UNAVAILABLE -> RecoveryChangeResult.OPERATOR_RECOVERY_UNAVAILABLE
                WireRecoverySettings.CONSENT_REQUIRED -> RecoveryChangeResult.NOT_TICKED
                WireRecoverySettings.STALE_OFFER, WireRecoverySettings.STALE_PROMPT, "stale_state" -> RecoveryChangeResult.STALE
                else -> RecoveryChangeResult.FAILED
            }
        }
    }

    // ---- a new kit ----

    override suspend fun makeKit(password: String): RecoveryChangeResult {
        if (!unlocked()) return RecoveryChangeResult.STALE
        val est = app.keeper.established ?: return RecoveryChangeResult.STALE
        val label = app.labelFor(est.origin) ?: return RecoveryChangeResult.STALE
        val r = app.kitFlow.make(password.toCharArray(), KitReason.MADE_IN_SETTINGS, app.accountEmail ?: est.emailNorm, label, est.origin, inEntry = false) {}
        return when (r) {
            // Made, not yet confirmed: the kit-after-move prompt is settled only when this kit is confirmed
            // (EngineKit.confirmKit), as the kept "kit confirmed" is.
            KitConfirmResult.DONE -> {
                app.publish()
                RecoveryChangeResult.DONE
            }
            KitConfirmResult.WRONG_PASSWORD -> RecoveryChangeResult.WRONG_PASSWORD
            KitConfirmResult.STALE -> RecoveryChangeResult.STALE
            KitConfirmResult.UNREACHABLE -> RecoveryChangeResult.UNREACHABLE
            KitConfirmResult.RATE_LIMITED -> RecoveryChangeResult.RATE_LIMITED
            KitConfirmResult.UPDATE_REQUIRED -> RecoveryChangeResult.UPDATE_REQUIRED
            else -> RecoveryChangeResult.FAILED
        }
    }

    override fun kitAfterMoveLater(prompt: KitAfterMovePrompt) = app.kitAfterMoveLater(prompt)

    internal companion object {
        /** Requests the person said were their own ("this was me"), per origin and account: ids, comma-separated. */
        const val MINE_KEY = "ovh.app.recovery-mine|"

        /** §9.3 step 2: the hold every verified request waits. */
        const val HOLD_MS = 7L * 86_400_000L

        /** Clocks differ: a wait shorter than the hold by more than this is said. */
        const val HOLD_SLACK_MS = 5L * 60_000L
    }

    // ---- requests for the operator's help ----

    override suspend fun cancelRecoveryRequest(request: RecoveryRequestRow): PlainResult {
        if (!unlocked()) return PlainResult.STALE
        // A row of the Settings screen on show, or of the alert on show (§9.3 step 2: "If this wasn't you, cancel it").
        val onScreen = open && shown?.requests?.any { it === request } == true
        val onAlert = alertShown?.requests?.any { it === request } == true && app.snapshot.account?.prompts?.any { it === alertShown } == true
        if (!onScreen && !onAlert) return PlainResult.STALE
        val flow = requestsFlow() ?: return PlainResult.STALE
        val g = generation
        // A lock before the veto is signed refuses it, and nothing is sent: STALE.
        val r = app.unlessLocked(null) { app.working { flow.veto(request.requestId) } }
        if (r == null || g != generation || !unlocked()) return PlainResult.STALE
        // Vetoed or not, the list is read again so the screen and the alert show what the server holds now.
        val listed = app.working { flow.live() }
        if (g != generation || !unlocked()) return PlainResult.STALE
        val still = (listed as? LiveRecoveryRequests.Listed)?.requests?.any { it.requestId == request.requestId }
        if (r == VetoOutcome.Vetoed && still == true) cancelNotTaken += request.requestId
        // The last sync's count predates this cancel: only the list read now counts, until the next sync.
        takeAlerts(listed, if (r == VetoOutcome.Vetoed) -1 else app.vault?.recoveryRequestsCounted ?: -1)
        shown = null
        app.publish()
        return when (r) {
            // Answered as done: DONE only once the server no longer lists it. Still listed, the server did not do what it
            // said; a list that could not be read leaves it unconfirmed.
            VetoOutcome.Vetoed -> when (still) {
                false -> PlainResult.DONE
                true -> PlainResult.FAILED
                null -> PlainResult.UNREACHABLE
            }
            VetoOutcome.NotOffered -> PlainResult.FAILED
            VetoOutcome.Unknown -> PlainResult.UNREACHABLE
            is VetoOutcome.Refused -> when (r.code) {
                WireErrors.RATE_LIMITED -> PlainResult.RATE_LIMITED
                WireErrors.UPGRADE_REQUIRED -> PlainResult.UPDATE_REQUIRED
                else -> PlainResult.FAILED
            }
        }
    }

    // ---- the prompts of §4.5 ----

    override suspend fun answerRecoveryKeyChanged(prompt: AccountPrompt.RecoveryKeyChanged, keep: Boolean, password: String): RecoveryChangeResult {
        if (keyChanged !== prompt || prompts().none { it === prompt }) return RecoveryChangeResult.STALE
        val decision = view?.pending as? EscrowDecision.UnsignedChange ?: return RecoveryChangeResult.STALE
        return change { it.answerEscrowPrompt(decision, keep, password.toCharArray()) }
    }

    override fun recoveryKeyChangedLater(prompt: AccountPrompt.RecoveryKeyChanged) {
        if (keyChanged !== prompt) return
        putOff = true
        app.publish()
    }

    override suspend fun answerKeepOperatorRecovery(prompt: AccountPrompt.KeepOperatorRecovery, keep: Boolean, password: String): RecoveryChangeResult {
        if (keepOperator !== prompt || prompts().none { it === prompt }) return RecoveryChangeResult.STALE
        val decision = view?.pending as? EscrowDecision.AskOwnMirror ?: return RecoveryChangeResult.STALE
        return change { it.answerEscrowPrompt(decision, keep, password.toCharArray()) }
    }

    override fun keepOperatorRecoveryNotNow(prompt: AccountPrompt.KeepOperatorRecovery) {
        if (keepOperator !== prompt) return
        putOff = true
        app.publish()
    }
}
