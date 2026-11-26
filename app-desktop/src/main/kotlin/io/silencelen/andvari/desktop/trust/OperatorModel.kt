package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.DesktopAppApi
import io.silencelen.andvari.core.app.DisableWhy
import io.silencelen.andvari.core.app.OperatorConsole
import io.silencelen.andvari.core.app.OperatorDeleteWhy
import io.silencelen.andvari.core.app.OperatorResult
import io.silencelen.andvari.core.app.QuotaLimits
import io.silencelen.andvari.core.model.wire.AccountSummary
import io.silencelen.andvari.core.model.wire.AdminEscrowResponse
import io.silencelen.andvari.core.model.wire.AdminPolicy
import io.silencelen.andvari.core.model.wire.AdminSignupPolicy
import io.silencelen.andvari.core.model.wire.Quota
import io.silencelen.andvari.core.trust.TrustGrammar
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * The operator's console on the desktop (design §9.1, §9.2): the window for the person who runs an andvari server. A
 * thin layer over [io.silencelen.andvari.core.app.OperatorApi], reached only through [TrustModel.operator]; no screen
 * calls the operator interface itself (a source test pins it).
 *
 * - **Who has it.** Only the instance's operator account, with its vault open, on a server not stopped on this computer
 *   ([available]). Every intent here checks that first and sends nothing otherwise, so no other role can reach one.
 * - **What it shows** is the operator's own server speaking about its own accounts ([OperatorConsole], as served).
 * - **Every answer is said in place** ([answerAt]): beside the view or the row it was about, not above the page.
 * - **A lock** closes the console (core). An intent a lock overtakes is said on the lock screen as the lock
 *   ([TrustModel.lockOvertook], through [TrustModel.runSaying]); nothing of the console is kept here across it.
 *
 * No Compose type appears here, so the JVM tests drive it against the fake.
 */
class OperatorModel internal constructor(private val model: TrustModel) {
    private val api: DesktopAppApi get() = model.api

    /** The console while it is open (core's flow); null otherwise. */
    val consoles: StateFlow<OperatorConsole?> get() = api.operatorApi.consoles

    /** The operator account, unlocked, on a server that is not stopped here: the only one the console is for. */
    fun available(s: AppSnapshot = api.snapshot): Boolean =
        s.phase == AppPhase.UNLOCKED && s.account?.operatorAccount == true && !forked(s)

    // ---- opening the console ----

    /** Where the console's first read stands while no console is on show. */
    enum class Opening { NOT_ASKED, READING, REFUSED }

    private val openingFlow = MutableStateFlow(Opening.NOT_ASKED)
    val opening: StateFlow<Opening> get() = openingFlow

    /**
     * Open the console: status, accounts, policy and recovery requests are read. While the first read is under way
     * nothing of the server is shown ([Opening.READING]); a refused first read shows nothing either, says why in place
     * and offers to try again ([Opening.REFUSED]). Null when the console is not this account's to open.
     */
    fun open(): Job? {
        if (!available()) return null
        openingFlow.value = Opening.READING
        return act(Area.CONSOLE, null, { operatorApi.openConsole() }) { r ->
            openingFlow.value = if (r.done && api.operatorApi.console != null) Opening.NOT_ASKED else Opening.REFUSED
            followAuditKinds()
        }
    }

    /**
     * Read the console again. A refused read keeps the lists on show (core does not replace them) and says so: what
     * the server answered, and that what is shown is the last list read.
     */
    fun refresh(): Job? {
        if (!available() || stepOpen()) return null
        if (api.operatorApi.console == null) return open()
        return act(Area.CONSOLE, null, { operatorApi.refreshConsole() }, previousKept = true, after = { followAuditKinds() })
    }

    /**
     * Close the console (its page was left). After a lock core has closed it already, and nothing is called: the
     * page goes away after the lock screen may have said what the lock overtook, which this must not clear.
     */
    fun close() {
        model.quietly { if (available() && api.operatorApi.console != null) api.operatorApi.closeConsole() }
        reset()
    }

    // ---- accounts ----

    /**
     * † Disable a listed account, for one of the closed reasons: its sessions end and the person is emailed (§9.2).
     * [named] is the address the done line names (the one on show when the action was chosen); by default the console's.
     */
    fun disable(userId: String, why: DisableWhy, password: String, named: String? = null, after: (OperatorResult) -> Unit = {}): Job? =
        act(Area.ACCOUNT, userId, { operatorApi.disableAccount(userId, why, password) }, UiText.ph(Placeholder.OP_DONE_DISABLED, plainName(named ?: emailOf(userId))), action = Action.DISABLE, after = after)

    /** † Enable a listed account again: the person is emailed (§9.2). */
    fun enable(userId: String, password: String, named: String? = null, after: (OperatorResult) -> Unit = {}): Job? =
        act(Area.ACCOUNT, userId, { operatorApi.enableAccount(userId, password) }, UiText.ph(Placeholder.OP_DONE_ENABLED, plainName(named ?: emailOf(userId))), action = Action.ENABLE, after = after)

    /** The address of [userId] as the console lists it now, else the id itself. */
    private fun emailOf(userId: String): String = api.operatorApi.console?.accounts?.firstOrNull { it.userId == userId }?.email ?: userId

    /**
     * † Delete a listed account as the operator, for one of the two fixed reasons ([OperatorDeleteWhy], a choice, never
     * typed): the 30-day rule, or the account holder is under the minimum age (which lifts the 30 days and nothing
     * else). A refusal is said on the account's row; a deletion that is done is said at the top of the console, since
     * the row is gone ([email] names it there).
     */
    fun delete(userId: String, email: String, why: OperatorDeleteWhy, password: String, after: (OperatorResult) -> Unit = {}): Job? =
        act(Area.ACCOUNT, userId, { operatorApi.deleteAccountFor(userId, why, password) }, action = Action.DELETE) { r ->
            if (r.done) sayAt(Area.CONSOLE, null, UiText.ph(Placeholder.OP_DELETED, plainName(email)), Action.DELETE, result = r)
            after(r)
        }

    /**
     * † One account's quota overrides, as typed: each field a whole number of at least 0, or empty for the instance's
     * default. Anything else is said in place before anything is sent.
     */
    fun setQuota(userId: String, typed: QuotaTyped, password: String, named: String? = null, after: (OperatorResult) -> Unit = {}): Job? {
        if (!available()) return null
        val limits = typed.limits() ?: run {
            sayAt(Area.ACCOUNT, userId, UiText.ph(Placeholder.OP_NOT_A_WHOLE_NUMBER), Action.QUOTA)
            return null
        }
        return act(Area.ACCOUNT, userId, { operatorApi.setAccountQuota(userId, limits, password) }, UiText.ph(Placeholder.OP_DONE_QUOTA, plainName(named ?: emailOf(userId))), action = Action.QUOTA, after = after)
    }

    // ---- an account's devices ----

    private val devicesAskedFlow = MutableStateFlow<String?>(null)

    /** The account whose devices were asked for; its list shows once core has read the last page ([devicesShown]). */
    val devicesAsked: StateFlow<String?> get() = devicesAskedFlow

    /** The devices of [userId], when the console holds that account's whole list; null while it is read or not asked. */
    fun devicesShown(c: OperatorConsole?, userId: String): List<io.silencelen.andvari.core.model.wire.Device>? =
        c?.takeIf { it.devicesOfUserId == userId && devicesAskedFlow.value == userId }?.devices

    /** Read a listed account's devices (in pages, by core): nothing is shown until the last page arrived. */
    fun openDevices(userId: String): Job? {
        if (!available() || stepOpen()) return null
        devicesAskedFlow.value = userId
        return act(Area.DEVICES, userId, { operatorApi.openAccountDevices(userId) })
    }

    fun closeDevices() {
        devicesAskedFlow.value = null
        if (available() && api.operatorApi.console?.devicesOfUserId != null) api.operatorApi.closeAccountDevices()
    }

    /** † Revoke a device of the list on show (core sends nothing for any other): the person is emailed (§9.2). */
    fun revokeDevice(deviceId: String, password: String, after: (OperatorResult) -> Unit = {}): Job? {
        val c = api.operatorApi.console ?: return null
        val of = c.devicesOfUserId ?: return null
        val device = c.devices.firstOrNull { it.deviceId == deviceId } ?: return null
        return act(
            Area.DEVICES, of, { operatorApi.revokeAccountDevice(deviceId, password) },
            UiText.ph(Placeholder.OP_DONE_REVOKED, plainName(device.name), plainName(emailOf(of))), action = Action.REVOKE, about = deviceId, after = after,
        )
    }

    // ---- the audit ----

    /** The filters the audit list was last read with; the account filter is set from an account's row. */
    class AuditFilter(val sinceMs: Long, val type: String?, val userId: String?)

    private val auditFilterFlow = MutableStateFlow<AuditFilter?>(null)
    val auditFilter: StateFlow<AuditFilter?> get() = auditFilterFlow

    /**
     * Read the audit since [sinceMs], narrowed to [type] and [userId] when given. The filters go to the server, which
     * answers with the newest [AUDIT_PAGE_ROWS] rows that match; a full page is said on the screen.
     */
    fun loadAudit(sinceMs: Long, type: String?, userId: String?): Job? {
        if (!available() || stepOpen()) return null
        // The type is chosen from the types the server has sent, never typed (a passphrase typed
        // there would go into an address). Anything else is no filter.
        val t = type?.takeIf { it in auditTypesFlow.value }
        if (type != null && t == null) return null
        auditFilterFlow.value = AuditFilter(sinceMs, t, userId)
        return act(Area.AUDIT, null, { operatorApi.loadAudit(sinceMs, t, userId) }, previousKept = true) { r ->
            if (r.done) api.operatorApi.console?.audit?.let { rows -> auditSeen += rows.map { it.type } }
            followAuditKinds()
        }
    }

    /** The kinds seen in the audit rows this console has read. */
    private val auditSeen = LinkedHashSet<String>()

    private val auditTypesFlow = MutableStateFlow<List<String>>(emptyList())

    /**
     * The audit types the list can be narrowed to: the kinds the server's status serves, when it serves them, with any
     * kind seen in a row that the list lacks after them; without that field, the kinds seen in rows, sorted, as before.
     */
    val auditTypes: StateFlow<List<String>> get() = auditTypesFlow

    /** [auditTypes] from the console's status as it stands now and the rows read so far. */
    private fun followAuditKinds() {
        auditTypesFlow.value = auditKindChoices(api.operatorApi.console?.status?.auditKinds, auditSeen)
    }

    /** A step is open (its inputs or its password): nothing is read again under it. */
    private fun stepOpen(): Boolean = chosenFlow.value != null || stepFlow.value != null

    // ---- the policy ----

    /**
     * † Save the policy as typed over [base] (the one read). A field that is not a whole number in its place is said
     * before anything is sent; the server's own refusal of a value is said in a sentence ([Placeholder.OP_BAD_POLICY]).
     */
    fun savePolicy(base: AdminPolicy, typed: PolicyTyped, password: String, after: (OperatorResult) -> Unit = {}): Job? {
        if (!available()) return null
        val policy = typed.over(base) ?: run {
            sayAt(Area.POLICY, null, typed.refusalLine(), Action.POLICY)
            return null
        }
        return act(Area.POLICY, null, { operatorApi.savePolicy(policy, password) }, UiText.ph(Placeholder.OP_DONE_POLICY), action = Action.POLICY, after = after)
    }

    // ---- operator recovery (§9.3) ----

    /**
     * † Upload what `recovery-cli assist` produced for a request on show (core sends nothing for any other). The server
     * refuses before the hold has passed and after a veto. There is no "refuse" here: the operator has none.
     */
    fun fulfil(requestId: String, answerText: String, password: String, after: (OperatorResult) -> Unit = {}): Job? {
        val c = api.operatorApi.console ?: return null
        val request = c.recoveryRequests.firstOrNull { it.requestId == requestId } ?: return null
        if (!available()) return null
        // Only an answer this computer checked is sent, and only the answer itself: the server stores whatever it is
        // given, once, and a wrong one is found only by the person's device, after the hold (found in a run).
        val answer = checkAnswer(requestId, answerText) ?: return null
        return act(Area.REQUESTS, requestId, { operatorApi.fulfilRecovery(requestId, answer.sealed, password) }, action = Action.FULFIL) { r ->
            // Said above the requests: a server that lists answered requests keeps the row (now "answered"), an older one drops it.
            if (r.done) sayAt(Area.REQUESTS, null, UiText.ph(Placeholder.OP_FULFILLED, plainName(request.email)), Action.FULFIL, result = r)
            after(r)
        }
    }

    /**
     * Check [answerText] as the answer `recovery-cli assist` made for [requestId] ([AssistAnswer]), on this computer and
     * before anything is sent. A refusal is said beside the request and answers null; an answer that passes clears what
     * was said there and is returned (the screen says what this computer could tell, and what only the person's device can).
     */
    internal fun checkAnswer(requestId: String, answerText: String): AssistAnswer.Ok? =
        checked(requestId) { AssistAnswer.read(answerText, it) }

    /**
     * [checkAnswer] for a picked file's [bytes], through the shared reader's own file function: bytes that are not UTF-8
     * are refused, nothing is decoded leniently, and what the file holds is never put on screen. The
     * bytes are wiped here, whatever the answer.
     */
    internal fun checkAnswerFile(requestId: String, bytes: ByteArray): AssistAnswer.Ok? =
        try {
            checked(requestId) { AssistAnswer.readFile(bytes, it) }
        } finally {
            bytes.fill(0)
        }

    private fun checked(requestId: String, read: (io.silencelen.andvari.core.model.wire.AdminRecoveryRequest) -> AssistAnswer): AssistAnswer.Ok? =
        when (val a = api.operatorApi.console?.recoveryRequests?.firstOrNull { it.requestId == requestId }
            ?.let(read) ?: AssistAnswer.Refused(Placeholder.OP_REQUEST_NOT_READY)) {
            is AssistAnswer.Refused -> {
                sayAt(Area.REQUESTS, requestId, a.text, Action.FULFIL)
                null
            }
            is AssistAnswer.Ok -> {
                if (answerAt(Area.REQUESTS, requestId) != null) clearAnswer()
                a
            }
        }

    private val escrowForFlow = MutableStateFlow<String?>(null)

    /** The account whose recovery copy was downloaded and waits to be saved to a file ([takeEscrowFile]). */
    val escrowFor: StateFlow<String?> get() = escrowForFlow

    /**
     * † Download a listed account's recovery copy for `recovery-cli` on an offline machine (§9.2; only an account that
     * chose operator recovery has one). The person is emailed. It is then saved to a file once ([takeEscrowFile]).
     */
    fun downloadEscrow(userId: String, password: String, named: String? = null, after: (OperatorResult) -> Unit = {}): Job? =
        act(Area.ACCOUNT, userId, { operatorApi.downloadEscrow(userId, password) }, UiText.ph(Placeholder.OP_ESCROW_READY, plainName(named ?: emailOf(userId))), action = Action.ESCROW) { r ->
            if (r.done) escrowForFlow.value = userId
            after(r)
        }

    /**
     * The downloaded recovery copy as the file `recovery-cli --identity-file` reads (the route's own JSON), handed over
     * once: core gives it out a single time. Asked again, it answers null and says in place that it was handed over
     * already, and that a new download (which emails the person again) is the way to another copy.
     */
    fun takeEscrowFile(userId: String): ByteArray? {
        if (!available()) return null
        escrowForFlow.value = null
        val escrow = api.operatorApi.takeEscrow()
        if (escrow == null || escrow.userId != userId) {
            sayAt(Area.ACCOUNT, userId, UiText.ph(Placeholder.OP_ESCROW_TAKEN), Action.ESCROW)
            return null
        }
        return ESCROW_JSON.encodeToString(AdminEscrowResponse.serializer(), escrow).toByteArray(Charsets.UTF_8)
    }

    // ---- the server's identity card (§4.3): each is a new card this account's key signs ----

    // A card change that is done shows at once: core republishes the console after every card intent,
    // so the console reads nothing a second time.

    /** † Rename the server. An empty name is said here and nothing is signed. */
    fun rename(name: String, password: String, after: (OperatorResult) -> Unit = {}): Job? {
        if (!available()) return null
        val n = name.trim()
        if (n.isEmpty()) {
            sayAt(Area.CARD, CARD_RENAME, UiText.ph(Placeholder.OP_CARD_NAME_EMPTY), Action.RENAME)
            return null
        }
        return act(Area.CARD, CARD_RENAME, { operatorApi.renameInstance(n, password) }, UiText.ph(Placeholder.OP_DONE_RENAMED, n), action = Action.RENAME, after = after)
    }

    /**
     * † Move the server to [origin]. The address is checked against the origin grammar here, before anything is
     * derived from the password, signed or sent; the grammar's own sentence says a refusal.
     */
    fun move(origin: String, password: String, after: (OperatorResult) -> Unit = {}): Job? {
        if (!available()) return null
        val to = origin.trim().trimEnd('/')
        if (!TrustGrammar.isOrigin(to)) {
            sayAt(Area.CARD, CARD_MOVE, operatorWords(OperatorResult.NOT_AN_ADDRESS, 0)!!, Action.MOVE)
            return null
        }
        // DONE never comes for a move (its card is never current at the old address); the words stay for the day it can.
        return act(Area.CARD, CARD_MOVE, { operatorApi.moveInstance(to, password) }, UiText.ph(Placeholder.OP_DONE_MOVED, to), action = Action.MOVE, after = after)
    }

    /**
     * † Set or rotate the recovery key: [fingerprint] the new key's 64-hex fingerprint, [rotationStatement] what
     * `recovery-cli rotate` produced with the outgoing key (empty: an unsigned change, which every account that chose
     * operator recovery is asked about, with turning it off as the default). A fingerprint of the wrong shape is said
     * here and nothing is signed.
     */
    fun changeRecoveryKey(fingerprint: String, rotationStatement: String, password: String, after: (OperatorResult) -> Unit = {}): Job? {
        if (!available()) return null
        val fp = fingerprint.trim().lowercase()
        if (!HEX64.matches(fp)) {
            sayAt(Area.CARD, CARD_RECOVERY, UiText.ph(Placeholder.OP_FINGERPRINT_SHAPE), Action.RECOVERY_SET)
            return null
        }
        val statement = rotationStatement.trim().takeIf { it.isNotEmpty() }
        return act(Area.CARD, CARD_RECOVERY, { operatorApi.changeRecoveryKey(fp, statement, password) }, UiText.ph(Placeholder.OP_DONE_RECOVERY_SET, fp), action = Action.RECOVERY_SET, after = after)
    }

    /** † Stop offering operator recovery (`recoveryFp = none`). */
    fun removeRecoveryKey(password: String, after: (OperatorResult) -> Unit = {}): Job? =
        act(Area.CARD, CARD_RECOVERY, { operatorApi.removeRecoveryKey(password) }, UiText.ph(Placeholder.OP_DONE_RECOVERY_REMOVED), action = Action.RECOVERY_REMOVE, after = after)

    // ---- one step per action that asks for the master password ----

    /** Every action of the console that asks for the master password (†). */
    enum class Action { DISABLE, ENABLE, QUOTA, REVOKE, ESCROW, DELETE, FULFIL, POLICY, RENAME, MOVE, RECOVERY_SET, RECOVERY_REMOVE }

    /** A label and its value as a step shows them: the value as it was when the action was chosen. */
    class StepValue internal constructor(val label: UiText, val value: UiText)

    /** A line of a step; [warn] is said in the error tone (what the server will record of a deletion). */
    class StepLine internal constructor(val text: UiText, val warn: Boolean = false)

    /**
     * An action chosen on the console, before its inputs are checked: which action, where its answer is said ([area],
     * [key], [about]: beside the control that was pressed), and the account, device, request or server it is for, as
     * they were on show when it was chosen ([values]). Inputs are entered against it; nothing here asks for a password.
     */
    class Chosen internal constructor(
        val action: Action,
        val area: Area,
        val key: String?,
        val about: String?,
        val values: List<StepValue>,
        internal val userId: String?,
        internal val email: String?,
        internal val requestId: String?,
        /** The server's address as it was on show, for a server-wide action. */
        internal val origin: String? = null,
        /** The server's name as it was on show, for a server-wide action. */
        internal val serverName: String? = null,
        /** For answering a request: the server listed it as answered already, so an upload replaces the answer there. */
        internal val answered: Boolean = false,
    )

    /**
     * The step that asks for the master password: what will be done ([title], [lines]) and to what ([values], as they
     * were when the action was chosen, never read again), with nothing above the password field that can change while
     * it is open. [confirm] names the button that sends it.
     */
    class Step internal constructor(
        val chosen: Chosen,
        val title: UiText,
        val lines: List<StepLine>,
        val values: List<StepValue>,
        val confirm: UiText,
        internal val send: (String, (OperatorResult) -> Unit) -> Job?,
    ) {
        val action: Action get() = chosen.action
    }

    private val chosenFlow = MutableStateFlow<Chosen?>(null)
    private val stepFlow = MutableStateFlow<Step?>(null)

    /** The action whose inputs are being entered, or null. */
    val chosen: StateFlow<Chosen?> get() = chosenFlow

    /** The open password step, or null. */
    val step: StateFlow<Step?> get() = stepFlow

    private fun accountValues(a: AccountSummary) = listOf(
        StepValue(UiText.ph(Placeholder.OP_STEP_ACCOUNT), UiText.Plain(a.email)),
        StepValue(UiText.ph(Placeholder.OP_STEP_ACCOUNT_ID), UiText.Plain(a.userId)),
    )

    private fun serverValues(c: OperatorConsole) = listOf(
        StepValue(UiText.ph(Placeholder.OP_STEP_SERVER), UiText.Plain(c.instance.name)),
        StepValue(UiText.ph(Placeholder.OP_STEP_SERVER_ADDRESS), UiText.Plain(c.instance.origin)),
    )

    /**
     * Choose [action] for account [a] as it is on show ([device] for a revoke). An action without inputs goes straight
     * to its password step; the others wait for theirs ([chosen]). Null when the console is not this account's.
     */
    fun chooseFor(action: Action, a: AccountSummary, device: io.silencelen.andvari.core.model.wire.Device? = null): Chosen? {
        if (!available() || api.operatorApi.console == null) return null
        val values = accountValues(a) + listOfNotNull(
            device?.let { StepValue(UiText.ph(Placeholder.OP_STEP_DEVICE), UiText.Plain(it.name + "  ·  " + it.platform)) },
            device?.let { StepValue(UiText.ph(Placeholder.OP_STEP_DEVICE_ID), UiText.Plain(it.deviceId)) },
        )
        val area = if (action == Action.REVOKE) Area.DEVICES else Area.ACCOUNT
        val chosen = Chosen(action, area, a.userId, device?.deviceId, values, a.userId, a.email, null)
        return begin(chosen) {
            when (action) {
                Action.ENABLE -> stepOf(chosen, UiText.ph(Placeholder.OP_ENABLE, stepTarget(chosen)),listOf(StepLine(UiText.Plain(OperatorDesignWords.ENABLE)))) { pw, after ->
                    enable(a.userId, pw, a.email, after)
                }
                Action.ESCROW -> stepOf(chosen, UiText.ph(Placeholder.OP_ESCROW_DOWNLOAD, stepTarget(chosen)),listOf(StepLine(UiText.Plain(OperatorDesignWords.ESCROW)))) { pw, after ->
                    downloadEscrow(a.userId, pw, a.email, after)
                }
                Action.REVOKE -> device?.let { d ->
                    stepOf(chosen, UiText.ph(Placeholder.OP_REVOKE_DEVICE, plainName(d.name)),emptyList()) { pw, after -> revokeDevice(d.deviceId, pw, after) }
                }
                else -> null
            }
        }
    }

    /** Choose a server-wide action (the policy or the identity card), for the server as it is on show. */
    fun chooseForServer(action: Action): Chosen? {
        val c = api.operatorApi.console
        if (!available() || c == null) return null
        val (area, key) = when (action) {
            Action.POLICY -> Area.POLICY to null
            Action.RENAME -> Area.CARD to CARD_RENAME
            Action.MOVE -> Area.CARD to CARD_MOVE
            Action.RECOVERY_SET, Action.RECOVERY_REMOVE -> Area.CARD to CARD_RECOVERY
            else -> return null
        }
        // Stopping operator recovery names the recovery key the pinned card names and the server's id as well.
        val values = if (action == Action.RECOVERY_REMOVE) serverValues(c) + pinnedCardValues(c.pinnedRecoveryFp, c.pinnedInstanceId, false) else serverValues(c)
        val chosen = Chosen(action, area, key, null, values, null, null, null, c.instance.origin, c.instance.name)
        // Every server-wide action has inputs; stopping operator recovery asks for its typed confirmation first.
        return begin(chosen) { null }
    }

    /**
     * Stop offering operator recovery: it cannot be undone by a rotation, so it is confirmed by
     * typing the server's address as it was on show; anything else is said and no step opens. The password step then
     * says again what it does.
     */
    fun checkRecoveryRemove(chosen: Chosen, typed: String): Step? {
        if (chosen.action != Action.RECOVERY_REMOVE || chosenFlow.value !== chosen) return null
        val origin = chosen.origin ?: return null
        if (typed.trim().trimEnd('/') != origin) {
            sayAt(Area.CARD, CARD_RECOVERY, UiText.ph(Placeholder.OP_REMOVE_TYPED_WRONG), Action.RECOVERY_REMOVE)
            return null
        }
        return toStep(chosen, stepOf(chosen, UiText.ph(Placeholder.OP_RECOVERY_REMOVE, stepTarget(chosen)),recoveryRemoveLines(warn = true)) { pw, after -> removeRecoveryKey(pw, after) })
    }

    /** Choose to answer a request on show, for the request and its account as they are on show. */
    fun chooseFulfil(requestId: String): Chosen? {
        val r = api.operatorApi.console?.recoveryRequests?.firstOrNull { it.requestId == requestId }
        if (!available() || r == null) return null
        // The address the request was made for and the request: never the server's account ID.
        val values = listOf(
            StepValue(UiText.ph(Placeholder.OP_STEP_ACCOUNT), UiText.Plain(r.email)),
            StepValue(UiText.ph(Placeholder.OP_STEP_REQUEST), UiText.Plain(r.requestId)),
        )
        return begin(Chosen(Action.FULFIL, Area.REQUESTS, requestId, null, values, r.userId, r.email, requestId, answered = requestState(r) == RequestState.ANSWERED)) { null }
    }

    private fun begin(chosen: Chosen, direct: () -> Step?): Chosen {
        answerFlow.value = null
        stepFlow.value = null
        val step = direct()
        chosenFlow.value = if (step == null) chosen else null
        stepFlow.value = step
        return chosen
    }

    private fun stepOf(chosen: Chosen, title: UiText, lines: List<StepLine>, extra: List<StepValue> = emptyList(), confirm: UiText = title, send: (String, (OperatorResult) -> Unit) -> Job?) =
        Step(chosen, title, lines, chosen.values + extra, confirm, send)

    /** Open [chosen]'s password step, when it is still the one being entered. */
    private fun toStep(chosen: Chosen, step: Step): Step? {
        if (chosenFlow.value !== chosen || !available()) return null
        if (answerAt(chosen.area, chosen.key)?.result == null) answerFlow.value = null
        chosenFlow.value = null
        stepFlow.value = step
        return step
    }

    /** Disable, for the reason picked: then the password step. */
    fun checkDisable(chosen: Chosen, why: DisableWhy): Step? {
        val id = chosen.userId ?: return null
        if (chosen.action != Action.DISABLE) return null
        return toStep(chosen, stepOf(chosen, UiText.ph(Placeholder.OP_DISABLE, stepTarget(chosen)),listOf(StepLine(UiText.Plain(OperatorDesignWords.DISABLE)), StepLine(disableWhyLabel(why)))) { pw, after ->
            disable(id, why, pw, chosen.email, after)
        })
    }

    /** The quota as typed, checked here: a field that is neither empty nor a whole number is said and no step opens. */
    fun checkQuota(chosen: Chosen, typed: QuotaTyped): Step? {
        val id = chosen.userId ?: return null
        if (chosen.action != Action.QUOTA || chosenFlow.value !== chosen) return null
        val limits = typed.limits() ?: run {
            sayAt(chosen.area, chosen.key, UiText.ph(Placeholder.OP_NOT_A_WHOLE_NUMBER), Action.QUOTA)
            return null
        }
        fun v(n: Long?) = n?.let { UiText.Plain(it.toString()) } ?: UiText.ph(Placeholder.OP_STEP_DEFAULT)
        val extra = listOf(
            StepValue(UiText.ph(Placeholder.OP_QUOTA_BYTES), v(limits.accountBytes)),
            StepValue(UiText.ph(Placeholder.OP_QUOTA_ITEMS), v(limits.items)),
            StepValue(UiText.ph(Placeholder.OP_QUOTA_VAULTS), v(limits.ownedSharedVaults)),
            StepValue(UiText.ph(Placeholder.OP_QUOTA_LINKS), v(limits.openLinks)),
        )
        return toStep(chosen, stepOf(chosen, UiText.ph(Placeholder.OP_QUOTA_SAVE, stepTarget(chosen)),listOf(StepLine(UiText.Plain(OperatorDesignWords.QUOTA))), extra) { pw, after ->
            setQuota(id, typed, pw, chosen.email, after)
        })
    }

    /** Delete, for the reason picked: the step says what the server will record before it asks for the password. */
    fun checkDelete(chosen: Chosen, why: OperatorDeleteWhy): Step? {
        val id = chosen.userId ?: return null
        val email = chosen.email ?: return null
        if (chosen.action != Action.DELETE) return null
        val lines = listOf(StepLine(UiText.Plain(OperatorDesignWords.DELETE_RULE)), StepLine(deleteWhyLabel(why)), StepLine(deleteRecordLine(why), warn = true))
        return toStep(chosen, stepOf(chosen, UiText.ph(Placeholder.OP_DELETE_CONFIRM, plainName(email)), lines) { pw, after -> delete(id, email, why, pw, after) })
    }

    /** The answer, checked here ([checkAnswer]): only one that passes opens the password step. */
    fun checkFulfil(chosen: Chosen, answerText: String): Step? {
        val requestId = chosen.requestId ?: return null
        if (chosen.action != Action.FULFIL || chosenFlow.value !== chosen) return null
        return fulfilStep(chosen, answerText, checkAnswer(requestId, answerText) ?: return null)
    }

    /** The password step for an answer [ok] said passes ([checkAnswer]); fulfilling checks it again before it sends. */
    internal fun fulfilStep(chosen: Chosen, answerText: String, ok: AssistAnswer.Ok, fromFile: Boolean = false): Step? {
        val requestId = chosen.requestId ?: return null
        if (chosen.action != Action.FULFIL || chosenFlow.value !== chosen) return null
        // Only what this computer checked is claimed; an answer already on the server is said to be replaced. A file's
        // content is not shown, so the step says it was read.
        val lines = (if (fromFile) listOf(StepLine(UiText.ph(Placeholder.OP_FULFIL_FILE_READ))) else emptyList()) +
            listOf(StepLine(UiText.ph(Placeholder.OP_FULFIL_CHECKED))) +
            (if (chosen.answered) listOf(StepLine(UiText.ph(Placeholder.OP_FULFIL_REPLACES), warn = true)) else emptyList())
        return toStep(chosen, stepOf(chosen, UiText.ph(Placeholder.OP_FULFIL, stepTarget(chosen)), lines) { pw, after -> fulfil(requestId, answerText, pw, after) })
    }

    /** The policy as typed over [base], checked here; the step lists what changes. */
    fun checkPolicy(chosen: Chosen, base: AdminPolicy, typed: PolicyTyped): Step? {
        if (chosen.action != Action.POLICY || chosenFlow.value !== chosen) return null
        val policy = typed.over(base) ?: run {
            sayAt(Area.POLICY, null, typed.refusalLine(), Action.POLICY)
            return null
        }
        val changes = policyChanges(base, policy).map { (what, from, to) -> StepLine(changeLine(what, from, to)) }
            .ifEmpty { listOf(StepLine(UiText.ph(Placeholder.OP_STEP_NO_CHANGE))) }
        return toStep(chosen, stepOf(chosen, UiText.ph(Placeholder.OP_POLICY_SAVE, stepTarget(chosen)),changes) { pw, after -> savePolicy(base, typed, pw, after) })
    }

    /** The new name, checked here (an empty one is said and nothing is signed). */
    fun checkRename(chosen: Chosen, name: String): Step? {
        if (chosen.action != Action.RENAME || chosenFlow.value !== chosen) return null
        val n = name.trim()
        if (n.isEmpty()) {
            sayAt(Area.CARD, CARD_RENAME, UiText.ph(Placeholder.OP_CARD_NAME_EMPTY), Action.RENAME)
            return null
        }
        val extra = listOf(StepValue(UiText.ph(Placeholder.OP_STEP_NEW_NAME), UiText.Plain(n)))
        return toStep(chosen, stepOf(chosen, UiText.ph(Placeholder.OP_CARD_RENAME, stepTarget(chosen)),emptyList(), extra) { pw, after -> rename(n, pw, after) })
    }

    /** The new address, checked against the origin grammar here. */
    fun checkMove(chosen: Chosen, origin: String): Step? {
        if (chosen.action != Action.MOVE || chosenFlow.value !== chosen) return null
        val to = origin.trim().trimEnd('/')
        if (!TrustGrammar.isOrigin(to)) {
            sayAt(Area.CARD, CARD_MOVE, operatorWords(OperatorResult.NOT_AN_ADDRESS, 0)!!, Action.MOVE)
            return null
        }
        val extra = listOf(StepValue(UiText.ph(Placeholder.OP_STEP_NEW_ADDRESS), UiText.Plain(to)))
        val lines = listOf(StepLine(UiText.ph(Placeholder.OP_CARD_MOVE_WHAT)), StepLine(UiText.Plain(OperatorDesignWords.ADDRESS_STAYS)))
        return toStep(chosen, stepOf(chosen, UiText.ph(Placeholder.OP_CARD_MOVE, stepTarget(chosen)),lines, extra) { pw, after -> move(to, pw, after) })
    }

    /** The new recovery key's fingerprint, checked for its shape here; an empty statement is said to be an unsigned change. */
    fun checkRecoverySet(chosen: Chosen, fingerprint: String, rotationStatement: String): Step? {
        if (chosen.action != Action.RECOVERY_SET || chosenFlow.value !== chosen) return null
        val fp = fingerprint.trim().lowercase()
        if (!HEX64.matches(fp)) {
            sayAt(Area.CARD, CARD_RECOVERY, UiText.ph(Placeholder.OP_FINGERPRINT_SHAPE), Action.RECOVERY_SET)
            return null
        }
        val extra = listOf(StepValue(UiText.ph(Placeholder.OP_STEP_NEW_FP), UiText.Plain(fp)))
        val lines = listOf(StepLine(UiText.ph(if (rotationStatement.isBlank()) Placeholder.OP_ROTATION_UNSIGNED else Placeholder.OP_STEP_STATEMENT_GIVEN), warn = rotationStatement.isBlank()))
        return toStep(chosen, stepOf(chosen, UiText.ph(Placeholder.OP_RECOVERY_SET, stepTarget(chosen)),lines, extra) { pw, after -> changeRecoveryKey(fp, rotationStatement, pw, after) })
    }

    /**
     * Send [step] with [password]. A wrong password is said in the step, which stays open for another try; any other
     * answer closes it and is said beside the control that was pressed. When what it was for is no longer on show
     * (a device or a request the list no longer holds) nothing is sent, the step closes, and that is said.
     */
    fun confirm(step: Step, password: String): Job? {
        if (!available() || stepFlow.value !== step || password.isEmpty()) return null
        val job = step.send(password) { r -> if (r != OperatorResult.WRONG_PASSWORD && stepFlow.value === step) stepFlow.value = null }
        if (job == null && stepFlow.value === step) {
            // Its row is gone from the list, so the console's top says it.
            stepFlow.value = null
            sayAt(Area.CONSOLE, null, UiText.ph(Placeholder.OP_STEP_GONE), step.action)
        }
        return job
    }

    /**
     * §6.7 Resume: "Finish setting up this server" from the open vault's prompt, with the master password from its own
     * step. Only while core raises the prompt (the operator's server has no card pinned); otherwise nothing is sent.
     */
    fun finishServerSetup(password: String, after: (OperatorResult) -> Unit): Job? {
        val raised = api.snapshot.account?.prompts.orEmpty().any { it is io.silencelen.andvari.core.app.AccountPrompt.FinishServerSetup }
        if (!raised || password.isEmpty()) return null
        return model.runSaying({ operatorApi.finishServerSetup(password) }, { setupWords(it, api.retryAfterSeconds()) }, after = after)
    }

    /** Leave the action being entered or its password step: nothing is sent. */
    fun cancelStep() {
        chosenFlow.value = null
        stepFlow.value = null
    }

    // ---- what each intent answered, in place ----

    /** The part of the console an answer is about. */
    enum class Area { CONSOLE, ACCOUNT, DEVICES, AUDIT, POLICY, REQUESTS, CARD }

    /**
     * What an intent of the console answered: in [area], about [key] (an account's, a device's or a request's id), for
     * [action] (null for a read) and, within it, [about] (the device a revoke was for). [previousKept]: a read was
     * refused and what is on show is the list as it was last read; the screen says so.
     */
    class Answer internal constructor(
        val area: Area,
        val key: String?,
        val result: OperatorResult?,
        val text: UiText,
        val previousKept: Boolean = false,
        val action: Action? = null,
        val about: String? = null,
    )

    private val answerFlow = MutableStateFlow<Answer?>(null)
    val answers: StateFlow<Answer?> get() = answerFlow

    /** The answer said in [area] about [key], whichever action it was for; null when the last answer was about something else. */
    fun answerAt(area: Area, key: String? = null): Answer? = answerFlow.value?.takeIf { it.area == area && it.key == key }

    /** The answer of [action] in [area] about [key] (and [about]): the one said beside that action's control. */
    fun answerFor(area: Area, key: String?, action: Action?, about: String? = null): Answer? =
        answerAt(area, key)?.takeIf { it.action == action && it.about == about }

    /** Say [text] in place, for a check this computer makes before anything is sent (or, with [result], what an intent came to). */
    internal fun sayAt(area: Area, key: String?, text: UiText, action: Action? = null, about: String? = null, result: OperatorResult? = null) {
        answerFlow.value = Answer(area, key, result, text, action = action, about = about)
    }

    fun clearAnswer() {
        answerFlow.value = null
    }

    /**
     * Run one operator intent through the model's one launcher ([TrustModel.runSaying]), which says a lock that
     * overtook it as the lock. Its own answer is said here, in place, only while the console is still this account's
     * (a lock closed it otherwise, and the lock screen says what happened). [done] is what a DONE says, if anything.
     */
    internal fun act(
        area: Area,
        key: String?,
        intent: suspend DesktopAppApi.() -> OperatorResult,
        done: UiText? = null,
        previousKept: Boolean = false,
        action: Action? = null,
        about: String? = null,
        after: (OperatorResult) -> Unit = {},
    ): Job? {
        if (!available()) return null
        answerFlow.value = null
        // A card the server stored and does not show yet already held its number when this was asked: a card change then
        // signs nothing, and its answer is not this change's card (the check of 2026-11-18).
        val cardHeldBefore = api.operatorApi.console?.cardStoredNotShown == true
        // An unexpected exception from the shared code is said above the page as "something went wrong";
        // the step it came from closes, since nothing more can be done there.
        return model.runSaying(intent, { null }, failed = { stepFlow.value = null; chosenFlow.value = null }) { r ->
            if (!available()) return@runSaying
            val words = if (r.done) done else operatorWords(r, api.retryAfterSeconds(), action, cardHeldBefore)
            answerFlow.value = words?.let { Answer(area, key, r, it, previousKept && !r.done && api.operatorApi.console != null, action, about) }
            after(r)
        }
    }

    // ---- following the app ----

    /** Call on every snapshot ([TrustModel.onSnapshot]): away from the open operator vault nothing of the console stays. */
    fun onSnapshot(s: AppSnapshot) {
        if (!available(s)) reset()
    }

    private fun reset() {
        openingFlow.value = Opening.NOT_ASKED
        answerFlow.value = null
        devicesAskedFlow.value = null
        auditFilterFlow.value = null
        escrowForFlow.value = null
        chosenFlow.value = null
        stepFlow.value = null
        auditSeen.clear()
        auditTypesFlow.value = emptyList()
    }

    companion object {
        /**
         * The audit filter's kinds: [served] as the server's status lists them, in its order, with each kind [seen] in a
         * row that it does not list after them (a kind is never dropped, and an unknown one is shown as served); with no
         * list served (an older server, or a field that was not a list of strings), the [seen] kinds, sorted.
         */
        fun auditKindChoices(served: List<String>?, seen: Collection<String>): List<String> =
            if (served == null) seen.toSortedSet().toList()
            else served.distinct() + seen.filter { it !in served }.toSortedSet()

        private val ESCROW_JSON = kotlinx.serialization.json.Json { encodeDefaults = true }
        private val HEX64 = Regex("^[0-9a-f]{64}$")

        /** The keys of the card's answers ([Area.CARD]): one per action. */
        const val CARD_RENAME = "rename"
        const val CARD_MOVE = "move"
        const val CARD_RECOVERY = "recovery"
    }
}

/** A quota override as typed: the four limits of `PUT /admin/accounts/{id}/quota`, each empty for the instance's default. */
class QuotaTyped(val accountBytes: String, val items: String, val ownedSharedVaults: String, val openLinks: String) {
    /** The limits, or null when a field is neither empty nor a whole number of at least 0. */
    fun limits(): QuotaLimits? {
        val values = listOf(accountBytes, items, ownedSharedVaults, openLinks).map { t ->
            val v = t.trim()
            if (v.isEmpty()) null else (v.toLongOrNull()?.takeIf { it >= 0 } ?: return null)
        }
        return QuotaLimits(values[0], values[1], values[2], values[3])
    }
}

/**
 * The policy as typed: every number of `AdminPolicy` the console edits, as text, the switch for an offline copy, and
 * sign-up's tighten-only pair ([signupMode] one of the wire's modes or null to store nothing; [signupCap] empty for
 * nothing). The minimum versions are kept as read.
 */
class PolicyTyped(
    val autoLockSeconds: String,
    val clipboardClearSeconds: String,
    val offlineCacheAllowed: Boolean,
    val sessionAccessTtlSeconds: String,
    val sessionRefreshTtlDays: String,
    val attachmentMaxBytes: String,
    val itemAttachmentsMaxBytes: String,
    val quotaBytes: String,
    val quotaItems: String,
    val quotaVaults: String,
    val quotaLinks: String,
    val kdfOps: String,
    val kdfMemBytes: String,
    val signupMode: String?,
    val signupCap: String,
) {
    /**
     * [base] with these values, or null when a number field is not a whole number of at least 0 (only the sign-up cap may
     * be left empty), or when the key derivation's memory is not a whole number of KiB, which this computer's shared code
     * refuses before anything is sent ([refusalLine] says which).
     */
    fun over(base: AdminPolicy): AdminPolicy? {
        fun n(t: String): Long? = t.trim().toLongOrNull()?.takeIf { it >= 0 }
        val cap = signupCap.trim().let { if (it.isEmpty()) null else (n(it) ?: return null) }
        if (kdfMemNotKib()) return null
        val kdf = runCatching { base.kdfParams.copy(ops = n(kdfOps) ?: return null, memBytes = n(kdfMemBytes) ?: return null) }.getOrNull() ?: return null
        return base.copy(
            kdfParams = kdf,
            autoLockSeconds = n(autoLockSeconds) ?: return null,
            clipboardClearSeconds = n(clipboardClearSeconds) ?: return null,
            offlineCacheAllowed = offlineCacheAllowed,
            sessionAccessTtlSeconds = n(sessionAccessTtlSeconds) ?: return null,
            sessionRefreshTtlDays = n(sessionRefreshTtlDays) ?: return null,
            attachmentMaxBytes = n(attachmentMaxBytes) ?: return null,
            itemAttachmentsMaxBytes = n(itemAttachmentsMaxBytes) ?: return null,
            quotaDefaults = Quota(n(quotaBytes) ?: return null, n(quotaItems) ?: return null, n(quotaVaults) ?: return null, n(quotaLinks) ?: return null),
            signup = AdminSignupPolicy(signupMode, cap),
        )
    }

    /** The key derivation's memory is a whole number of bytes that is not a whole number of KiB (a multiple of 1024). */
    private fun kdfMemNotKib(): Boolean = kdfMemBytes.trim().toLongOrNull()?.let { it >= 0 && it % 1024 != 0L } == true

    /** What [over] refusing says: the memory's own line, or that each field takes a whole number. Nothing was sent. */
    fun refusalLine(): UiText =
        UiText.ph(if (kdfMemNotKib()) Placeholder.OP_POLICY_KDF_MEM_NOT_KIB else Placeholder.OP_POLICY_NOT_A_WHOLE_NUMBER)

    companion object {
        /** The fields as [p] has them. */
        fun of(p: AdminPolicy) = PolicyTyped(
            p.autoLockSeconds.toString(), p.clipboardClearSeconds.toString(), p.offlineCacheAllowed,
            p.sessionAccessTtlSeconds.toString(), p.sessionRefreshTtlDays.toString(), p.attachmentMaxBytes.toString(),
            p.itemAttachmentsMaxBytes.toString(), p.quotaDefaults.accountBytes.toString(), p.quotaDefaults.items.toString(),
            p.quotaDefaults.ownedSharedVaults.toString(), p.quotaDefaults.openLinks.toString(), p.kdfParams.ops.toString(),
            p.kdfParams.memBytes.toString(), p.signup.mode, p.signup.cap?.toString().orEmpty(),
        )
    }
}

/** What a chosen action's controls name as its target: the account's address, or the server's name, drawn plainly. */
internal fun stepTarget(chosen: OperatorModel.Chosen): String = plainName(chosen.email ?: chosen.serverName ?: "")

/** What stopping operator recovery does, in plain words: said before the typed confirmation and again in its password step. */
/**
 * What this computer's pin says of the server ([io.silencelen.andvari.core.app.OperatorConsole.pinnedInstanceId]
 * and `pinnedRecoveryFp`): its instance id, and the recovery key its card names (not for a public server, which
 * names none, [public]). A value the pin does not hold is said as such, never left out.
 */
internal fun pinnedCardValues(recoveryFp: String?, instanceId: String?, public: Boolean): List<OperatorModel.StepValue> = buildList {
    add(OperatorModel.StepValue(UiText.ph(Placeholder.OP_STEP_INSTANCE_ID), instanceId?.let { UiText.Plain(it) } ?: UiText.ph(Placeholder.OP_PIN_HOLDS_NONE)))
    if (!public) {
        val fp = recoveryFp?.let { UiText.Plain(it.chunked(4).joinToString(" ")) } ?: UiText.ph(Placeholder.OP_CARD_NAMES_NO_RECOVERY_KEY)
        add(OperatorModel.StepValue(UiText.ph(Placeholder.OP_STEP_RECOVERY_FP), fp))
    }
}

/** A card change is offered only while no stored card waits to be shown. */
internal fun cardChangeOffered(storedNotShown: Boolean): Boolean = !storedNotShown

internal fun recoveryRemoveLines(warn: Boolean): List<OperatorModel.StepLine> = listOf(
    Placeholder.OP_REMOVE_WHAT_CARD, Placeholder.OP_REMOVE_WHAT_LATER, Placeholder.OP_REMOVE_REQUESTS_STOP,
).map { OperatorModel.StepLine(UiText.ph(it), warn) }

/**
 * What saving [after] over [before] changes, field by field, for the policy's password step: the field's label, the
 * value read and the value to store. Fields left as read are not listed.
 */
/**
 * The step's line for one change: the row the person changed, named by that row's own words as the panel shows them,
 * then what it was and what it becomes. While both the line and the row still await their words, the row's gloss goes in
 * unmarked (the line's own mark covers it); once either has words, the row is what it shows, marked or not. Each slot
 * gets its own value, so the owner's words for the line can be put in by count.
 */
internal fun changeLine(row: Placeholder, from: String, to: String): UiText {
    val asPlaceholders = UiText.ph(Placeholder.OP_STEP_CHANGE, row.gloss, from, to)
    val rowShown = UiText.ph(row)
    if (asPlaceholders.isPlaceholder && rowShown.isPlaceholder) return asPlaceholders
    return UiText.ph(Placeholder.OP_STEP_CHANGE, rowShown.shown(), from, to)
}

internal fun policyChanges(before: AdminPolicy, after: AdminPolicy): List<Triple<Placeholder, String, String>> {
    val pairs = listOf(
        Placeholder.OP_POLICY_AUTO_LOCK to (before.autoLockSeconds to after.autoLockSeconds),
        Placeholder.OP_POLICY_CLIPBOARD to (before.clipboardClearSeconds to after.clipboardClearSeconds),
        Placeholder.OP_POLICY_OFFLINE to (before.offlineCacheAllowed to after.offlineCacheAllowed),
        Placeholder.OP_POLICY_ACCESS_TTL to (before.sessionAccessTtlSeconds to after.sessionAccessTtlSeconds),
        Placeholder.OP_POLICY_REFRESH_TTL to (before.sessionRefreshTtlDays to after.sessionRefreshTtlDays),
        Placeholder.OP_POLICY_ATTACHMENT to (before.attachmentMaxBytes to after.attachmentMaxBytes),
        Placeholder.OP_POLICY_ITEM_ATTACHMENTS to (before.itemAttachmentsMaxBytes to after.itemAttachmentsMaxBytes),
        Placeholder.OP_QUOTA_BYTES_DEFAULT to (before.quotaDefaults.accountBytes to after.quotaDefaults.accountBytes),
        Placeholder.OP_QUOTA_ITEMS_DEFAULT to (before.quotaDefaults.items to after.quotaDefaults.items),
        Placeholder.OP_QUOTA_VAULTS_DEFAULT to (before.quotaDefaults.ownedSharedVaults to after.quotaDefaults.ownedSharedVaults),
        Placeholder.OP_QUOTA_LINKS_DEFAULT to (before.quotaDefaults.openLinks to after.quotaDefaults.openLinks),
        Placeholder.OP_POLICY_KDF_OPS to (before.kdfParams.ops to after.kdfParams.ops),
        Placeholder.OP_POLICY_KDF_MEM to (before.kdfParams.memBytes to after.kdfParams.memBytes),
        // The sign-up mode's row is headed "sign-up" in the panel; its choices' own line names one mode each.
        Placeholder.OP_POLICY_SIGNUP to (before.signup.mode to after.signup.mode),
        Placeholder.OP_POLICY_CAP to (before.signup.cap to after.signup.cap),
    )
    return pairs.filter { (_, v) -> v.first != v.second }.map { (what, v) -> Triple(what, v.first?.toString() ?: "-", v.second?.toString() ?: "-") }
}

/**
 * The counts line ([OperatorConsole.countsDisagree]): the server's own count of accounts and the rows of its own list,
 * both as served, when they differ; null when they agree or nothing says.
 */
internal fun countsDisagreeLine(c: OperatorConsole): UiText? =
    if (!c.countsDisagree) null else UiText.ph(Placeholder.OP_COUNTS_DISAGREE, c.status?.userCount?.toString() ?: "", c.accounts.size.toString())

/** Where a request for the operator's help stands, from the server's `state`, read against the closed list only (spec 03 §18.3). */
internal enum class RequestState(val words: Placeholder) {
    HOLDING(Placeholder.OP_REQUEST_STATE_HOLDING),
    WAITING(Placeholder.OP_REQUEST_STATE_WAITING),
    ANSWERED(Placeholder.OP_REQUEST_STATE_READY),

    /** No state, or one outside the list: not drawn as anything it might be. */
    NOT_GIVEN(Placeholder.OP_REQUEST_STATE_NOT_GIVEN),
}

internal fun requestState(r: io.silencelen.andvari.core.model.wire.AdminRecoveryRequest): RequestState = when (r.state) {
    "holding" -> RequestState.HOLDING
    "awaiting_operator" -> RequestState.WAITING
    "ready" -> RequestState.ANSWERED
    else -> RequestState.NOT_GIVEN
}

/**
 * What finishing the set-up answered: [OperatorResult.CARD_REFUSED] there is the server's `bad_card`, and also a card 0
 * the server took (it answered 200) that this computer then could not pin or match to the card it signed. FAILED there
 * is also a session that had ended before anything was sent, where no answer of the server's came at all.
 */
internal fun setupWords(r: OperatorResult, retryAfterSeconds: Int): UiText? = when (r) {
    OperatorResult.CARD_REFUSED -> UiText.ph(Placeholder.OP_SETUP_CARD_NOT_TAKEN)
    OperatorResult.FAILED -> UiText.ph(Placeholder.OP_SETUP_NOT_FINISHED)
    else -> operatorWords(r, retryAfterSeconds)
}

/**
 * What an operator intent's refusal says ([OperatorResult] carries words only for the address grammar). Null for DONE.
 * [action]:the console's action it answers, where the same result means another thing (a card change).
 *
 * The identity card's results, as the shared code gives them: [OperatorResult.CARD_MOVED_ON] is every chain refresh that
 * was not current (another device's newer card, or a chain that could not be read just now); [OperatorResult.CARD_REFUSED]
 * is the server's refusal and also refusals of this computer before anything was sent. For a recovery key set with a
 * rotation statement, either comes after the statement may already be stored. Each is said in words true of all of them.
 * [cardHeldBefore]: a card the server stored and does not show yet held the number when the intent was asked, so a card
 * change answered [OperatorResult.CARD_STORED_NOT_SHOWN] for that earlier card and signed nothing now: the shared code's
 * own sentence, never the move's "signed and stored".
 */
internal fun operatorWords(r: OperatorResult, retryAfterSeconds: Int, action: OperatorModel.Action? = null, cardHeldBefore: Boolean = false): UiText? {
    val rotation = action == OperatorModel.Action.RECOVERY_SET
    val words: UiText = when (r) {
        OperatorResult.DONE -> return null
        OperatorResult.WRONG_PASSWORD -> UiText.ph(Placeholder.OP_WRONG_PASSWORD)
        OperatorResult.NOT_THE_OPERATOR -> UiText.ph(Placeholder.OP_NOT_THE_OPERATOR)
        OperatorResult.NO_SUCH_ACCOUNT -> UiText.ph(Placeholder.OP_NO_SUCH_ACCOUNT)
        OperatorResult.CANNOT_TARGET_SELF -> UiText.ph(Placeholder.OP_CANNOT_TARGET_SELF)
        OperatorResult.NOT_DISABLED_LONG_ENOUGH -> UiText.ph(Placeholder.OP_NOT_DISABLED_LONG_ENOUGH)
        OperatorResult.BLOCKED_BY_SHARED_VAULT -> UiText.ph(Placeholder.OP_BLOCKED_BY_SHARED_VAULT)
        OperatorResult.NO_SUCH_DEVICE -> UiText.ph(Placeholder.OP_NO_SUCH_DEVICE)
        OperatorResult.NOT_TIGHTER -> UiText.ph(Placeholder.OP_NOT_TIGHTER)
        OperatorResult.BAD_POLICY -> UiText.ph(Placeholder.OP_BAD_POLICY)
        OperatorResult.NO_ESCROW -> UiText.ph(Placeholder.OP_NO_ESCROW)
        OperatorResult.REQUEST_NOT_READY -> UiText.ph(Placeholder.OP_REQUEST_NOT_READY)
        OperatorResult.CARD_MOVED_ON -> UiText.ph(if (rotation) Placeholder.OP_ROTATION_CARD_NOT_CURRENT else Placeholder.OP_CARD_NOT_CURRENT)
        OperatorResult.CARD_REFUSED -> UiText.ph(if (rotation) Placeholder.OP_ROTATION_CARD_REFUSED else Placeholder.OP_CARD_REFUSED_EITHER)
        // A move's card is never current at the old address (a card that moves the server never is), so a move answers this.
        OperatorResult.CARD_STORED_NOT_SHOWN -> if (action == OperatorModel.Action.MOVE && !cardHeldBefore) UiText.ph(Placeholder.OP_MOVE_CARD_STORED) else UiText.forResult(r, retryAfterSeconds) ?: return null
        // The shared code gives one result for a statement that does not check out and for one that leads to another key
        // than the fingerprint typed: one line that is true of both.
        OperatorResult.ROTATION_REFUSED -> UiText.ph(Placeholder.OP_ROTATION_REFUSED_EITHER)
        OperatorResult.SETUP_ALREADY_DONE -> UiText.ph(Placeholder.OP_SETUP_ALREADY_DONE)
        // The shared reader's refusals, as core read the answer again (and the server's request_key_mismatch): the console's own sentences.
        OperatorResult.ANSWER_EMPTY, OperatorResult.ANSWER_IS_THE_COPY, OperatorResult.ANSWER_NOT_AN_ANSWER, OperatorResult.ANSWER_BARE,
        OperatorResult.ANSWER_OTHER_REQUEST, OperatorResult.ANSWER_OTHER_REQUEST_KEY, OperatorResult.ANSWER_CUT_SHORT,
        OperatorResult.ANSWER_TOO_LONG -> UiText.ph(AssistAnswer.words(r)!!)
        // A list that contradicted itself is refused whole by core, as FAILED: nothing of it was taken.
        OperatorResult.FAILED -> UiText.ph(Placeholder.OP_NOT_TAKEN)
        // The address grammar's own sentence, and the troubles every intent shares.
        else -> UiText.forResult(r, retryAfterSeconds) ?: return null
    }
    return words
}
