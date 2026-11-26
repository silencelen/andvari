package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.DisableWhy
import io.silencelen.andvari.core.app.InstanceDetails
import io.silencelen.andvari.core.app.OperatorApi
import io.silencelen.andvari.core.app.OperatorConsole
import io.silencelen.andvari.core.app.OperatorDeleteWhy
import io.silencelen.andvari.core.app.OperatorResult
import io.silencelen.andvari.core.app.QuotaLimits
import io.silencelen.andvari.core.app.Subscription
import io.silencelen.andvari.core.client.account.CardChangeResult
import io.silencelen.andvari.core.client.account.Fetched
import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.account.WireOperatorCards
import io.silencelen.andvari.core.client.account.WireOperatorRoutes
import io.silencelen.andvari.core.model.wire.AccountSummary
import io.silencelen.andvari.core.model.wire.AdminEscrowResponse
import io.silencelen.andvari.core.model.wire.AdminPolicy
import io.silencelen.andvari.core.model.wire.AdminRecoveryRequest
import io.silencelen.andvari.core.model.wire.AdminStatus
import io.silencelen.andvari.core.model.wire.AuditRow
import io.silencelen.andvari.core.model.wire.Device
import io.silencelen.andvari.core.model.wire.OperatorDeleteReason
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.trust.TrustGrammar
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * The operator views (design §9.2) on the engine, for the desktop app only ([EngineDesktopAppApi]): the operator
 * account's own session, its server's admin routes through [WireOperatorRoutes] and its card through
 * [WireOperatorCards].
 *
 * **What is shown is the operator's own server speaking**, so its lists are shown as served, except where a list
 * contradicts itself; then it is refused whole and the console keeps what it showed:
 * - accounts: an id that is not a uuid, or one account twice;
 * - an account's devices: read in pages ([io.silencelen.andvari.core.client.account.DevicePages]: a list that never
 *   ends stops at its stated number of pages, a looping cursor or a repeated device is refused), and a row marked as
 *   this session's (`current`), which the operator's view never carries;
 * - the audit: more rows than one page holds (500), one row twice, or a row outside the filters asked;
 * - recovery requests: an id outside its grammar, or one request twice.
 * [OperatorConsole.countsDisagree] says when the server's own count and its own list differ.
 *
 * **Nothing is sent for a row that is not on show:** an action names an account of [OperatorConsole.accounts], a device
 * of [OperatorConsole.devices] or a request of [OperatorConsole.recoveryRequests]; any other id is refused here. A row
 * the server lists for an account that is not there is refused by the server (`no_such_user`).
 *
 * **Every † route** re-authenticates through the session's one path ([io.silencelen.andvari.core.client.account.Reauth]),
 * which proves the password on this device first: a wrong password sends no request at all. **A lock** closes the
 * console, and an intent it overtakes answers [OperatorResult.STALE]; the card's intents run under
 * [EngineAppApi.unlessLocked], so a lock that wiped the key they sign with is their own STALE, never a throw.
 */
internal class EngineOperator(private val app: EngineAppApi) : OperatorApi {
    private val flow = MutableStateFlow<OperatorConsole?>(null)
    private val listeners = ArrayList<(OperatorConsole?) -> Unit>()

    private var open = false
    private var generation = 0
    private var origin: String? = null
    private var status: AdminStatus? = null
    private var accounts: List<AccountSummary> = emptyList()
    private var devicesOf: String? = null
    private var devices: List<Device> = emptyList()
    private var requests: List<AdminRecoveryRequest> = emptyList()
    private var policy: AdminPolicy? = null
    private var audit: List<AuditRow> = emptyList()
    private var escrow: AdminEscrowResponse? = null

    override val console: OperatorConsole? get() = flow.value
    override val consoles: StateFlow<OperatorConsole?> get() = flow

    override fun observeConsole(listener: (OperatorConsole?) -> Unit): Subscription {
        listeners += listener
        listener(flow.value)
        return object : Subscription {
            override fun close() {
                listeners -= listener
            }
        }
    }

    // ---- who may, and the console ----

    /** The operator account's session, unlocked on this desktop, at a server this device may dial. */
    private fun session() = app.keeper.established?.takeIf {
        app.phase == AppPhase.UNLOCKED && it.role == WireOperatorRoutes.OPERATOR_ROLE && app.mayDial(it.origin)
    }

    private fun routes(): WireOperatorRoutes? {
        val est = session() ?: return null
        val reauth = app.keeper.reauth() ?: return null
        return WireOperatorRoutes(est.userId, est.role, app.clientFor(est.origin), app.trust, reauth)
    }

    private fun cards(): WireOperatorCards? {
        val est = session() ?: return null
        val reauth = app.keeper.reauth() ?: return null
        return WireOperatorCards(est, app.clientFor(est.origin), app.crypto, app.trust, reauth, app.engine.clock)
    }

    /** Still the console this intent started on: not closed, not locked, the same session. */
    private fun still(g: Int): Boolean = g == generation && open && session()?.origin == origin

    private fun publish() {
        val next = if (!open) null else build()
        if (next == null) open = false
        flow.value = next
        for (l in listeners.toList()) l(next)
    }

    private fun build(): OperatorConsole? {
        val o = origin ?: return null
        if (session()?.origin != o) return null
        val label = app.labelFor(o) ?: return null
        val details = app.snapshot.instance?.takeIf { it.label.origin == o }?.details ?: InstanceDetails("", 0L, "")
        val pin = app.trust.pinFor(o)
        val s = status
        return OperatorConsole(
            instance = label,
            details = details,
            setupUnfinished = app.trust.pinFor(o) == null,
            status = s,
            accounts = accounts,
            devicesOfUserId = devicesOf,
            devices = devices,
            recoveryRequests = requests,
            policy = policy,
            audit = audit,
            countsDisagree = s != null && s.userCount != accounts.size.toLong(),
            serverSentBadRows = badAccounts + badRequests + badDevices > 0,
            cardStoredNotShown = pin != null && storedNotShown(o, pin.seq) != null,
            // From this device's own pin, never from a server's answer at this moment (the desktop app needs it so).
            pinnedRecoveryFp = pin?.recoveryFp,
            pinnedInstanceId = pin?.instanceId,
            policyRefusal = policyRefusal,
        )
    }

    /** [OperatorConsole.policyRefusal]: why the last policy was refused; null after a stored one, a lock or a close. */
    private var policyRefusal: io.silencelen.andvari.core.app.CopyLine? = null

    /** The line for a policy the server (or this device's own check) refused with [code]; null for a refusal of another kind. */
    private fun policyRefusalOf(code: String): io.silencelen.andvari.core.app.CopyLine? = when {
        code == WireOperatorRoutes.KDF_TOO_WEAK -> io.silencelen.andvari.core.app.CopyLine.of(io.silencelen.andvari.core.app.CopyKey.OPERATOR_POLICY_KDF_TOO_WEAK)
        code == WireOperatorRoutes.KDF_MEM_NOT_KIB_MULTIPLE -> io.silencelen.andvari.core.app.CopyLine.of(io.silencelen.andvari.core.app.CopyKey.OPERATOR_POLICY_KDF_MEM_NOT_KIB)
        code.startsWith("bad_") -> io.silencelen.andvari.core.app.CopyLine.of(io.silencelen.andvari.core.app.CopyKey.OPERATOR_POLICY_OUT_OF_BOUNDS)
        else -> null
    }

    /** A lock, a sign-out or the session's end: the console closes and every read it held goes. */
    fun locked() {
        if (!open && flow.value == null) return
        open = false
        generation++
        origin = null
        status = null
        badAccounts = 0
        badRequests = 0
        badDevices = 0
        accounts = emptyList()
        devicesOf = null
        devices = emptyList()
        requests = emptyList()
        policy = null
        policyRefusal = null
        audit = emptyList()
        escrow = null
        publish()
    }

    override suspend fun openConsole(): OperatorResult {
        val est = app.keeper.established
        if (app.phase != AppPhase.UNLOCKED || est == null) return OperatorResult.STALE
        if (est.role != WireOperatorRoutes.OPERATOR_ROLE) return OperatorResult.NOT_THE_OPERATOR
        if (routes() == null) return OperatorResult.FAILED
        open = true
        origin = est.origin
        generation++
        return refreshConsole()
    }

    override fun closeConsole() {
        locked()
    }

    /** Status, accounts, policy and (where the card offers operator recovery) the recovery requests, each checked. */
    override suspend fun refreshConsole(): OperatorResult {
        if (!open) return OperatorResult.STALE
        val r = routes() ?: return OperatorResult.STALE
        val g = generation
        val readAccounts = app.working { r.accounts() }
        if (!still(g)) return OperatorResult.STALE
        val listed = when (readAccounts) {
            is Fetched.Ok -> readAccounts.value
            is Fetched.Refused -> return fetched(readAccounts.code)
            Fetched.Unreachable -> return OperatorResult.UNREACHABLE
        }
        if (!accountsHold(listed)) return OperatorResult.FAILED
        val readStatus = app.working { r.status() }
        if (!still(g)) return OperatorResult.STALE
        val readPolicy = app.working { r.policy() }
        if (!still(g)) return OperatorResult.STALE
        val readRequests = app.working { r.recoveryRequests() }
        if (!still(g)) return OperatorResult.STALE
        // Every field a screen draws or a clipboard takes, checked where the rows are read.
        val checkedAccounts = OperatorRows.accounts(listed)
        accounts = checkedAccounts.rows
        badAccounts = checkedAccounts.bad
        (readStatus as? Fetched.Ok)?.let { status = it.value }
        (readPolicy as? Fetched.Ok)?.let { policy = it.value }
        when (readRequests) {
            is Fetched.Ok -> OperatorRows.requests(readRequests.value)?.let {
                requests = it.rows
                badRequests = it.bad
            }
            // Variant R (a public card) has no operator recovery: an empty list, nothing asked.
            is Fetched.Refused -> if (readRequests.code == WireOperatorRoutes.OPERATOR_RECOVERY_UNAVAILABLE) requests = emptyList()
            Fetched.Unreachable -> Unit
        }
        // An account no longer listed takes its open devices list with it.
        if (devicesOf != null && listed.none { it.userId == devicesOf }) {
            devicesOf = null
            devices = emptyList()
        }
        publish()
        return OperatorResult.DONE
    }

    /** One list that contradicts itself is refused whole: an id outside its grammar, or one account twice. */
    private fun accountsHold(list: List<AccountSummary>): Boolean =
        list.all { TrustGrammar.isUuid(it.userId) } && list.map { it.userId }.toSet().size == list.size

    /** Rows of the last reads that the server should not have sent (dropped, or their free text blanked): [OperatorRows]. */
    private var badAccounts = 0
    private var badRequests = 0
    private var badDevices = 0

    /**
     * §6.7 Resume (R10): the engine's `SetupResume.finish` for the open operator session, under the account's guard (a
     * lock that overtakes it is STALE, nothing sealed or sent after it). It signs card 0 only while the instance serves
     * none, only for the session's own origin, and pins only the card 0 it signed, once the server's answer names it.
     * Desktop only (a phone cannot sign a card, §9.5).
     */
    override suspend fun finishServerSetup(password: String): OperatorResult {
        val chars = password.toCharArray()
        try {
            if (!app.takesSetupLinks) return OperatorResult.STALE
            val est = session() ?: return OperatorResult.STALE
            val resume = app.setupResume(est.origin) ?: return OperatorResult.STALE
            val r = app.unlessLocked(null) { app.working { resume.finish(chars) } } ?: return OperatorResult.STALE
            if (session() !== est) return OperatorResult.STALE
            val result = when (r) {
                is Reauthed.Refused -> when (r.code) {
                    io.silencelen.andvari.core.client.onboard.SetupResume.SETUP_DONE -> OperatorResult.SETUP_ALREADY_DONE
                    io.silencelen.andvari.core.client.onboard.SetupResume.CARD_MISMATCH, io.silencelen.andvari.core.client.onboard.SetupResume.PIN_FAILED,
                    "bad_card" -> OperatorResult.CARD_REFUSED
                    "card_head_moved" -> OperatorResult.CARD_MOVED_ON
                    else -> reauthed(r)
                }
                else -> reauthed(r)
            }
            app.publish()
            if (open) publish()
            return result
        } finally {
            chars.fill('\u0000')
        }
    }

    // ---- accounts and devices ----

    private fun listedAccount(userId: String): Boolean = open && accounts.any { it.userId == userId }

    /** A † action on an account of the list: [call] runs only for a listed account; then the list is read again. */
    private suspend fun onAccount(userId: String, password: String, call: suspend (WireOperatorRoutes, CharArray) -> Reauthed<*>): OperatorResult {
        val chars = password.toCharArray()
        try {
            if (!open) return OperatorResult.STALE
            if (!listedAccount(userId)) return OperatorResult.NO_SUCH_ACCOUNT
            val r = routes() ?: return OperatorResult.STALE
            val g = generation
            val answer = app.working { call(r, chars) }
            if (!still(g)) return OperatorResult.STALE
            val result = reauthed(answer)
            if (result == OperatorResult.DONE) refreshConsole()
            return result
        } finally {
            chars.fill('\u0000')
        }
    }

    override suspend fun disableAccount(userId: String, why: DisableWhy, password: String): OperatorResult =
        onAccount(userId, password) { r, pw -> r.disable(userId, why.wireName, pw) }

    override suspend fun enableAccount(userId: String, password: String): OperatorResult =
        onAccount(userId, password) { r, pw -> r.enable(userId, pw) }

    override suspend fun deleteAccount(userId: String, password: String): OperatorResult =
        deleteAccountFor(userId, OperatorDeleteWhy.DISABLED_30_DAYS, password)

    override suspend fun deleteAccountFor(userId: String, why: OperatorDeleteWhy, password: String): OperatorResult {
        // The reason is a closed choice: the one value the route takes, or none (the 30-day rule).
        val reason = when (why) {
            OperatorDeleteWhy.DISABLED_30_DAYS -> null
            OperatorDeleteWhy.UNDER_MINIMUM_AGE -> OperatorDeleteReason.UNDER_MINIMUM_AGE
        }
        return onAccount(userId, password) { r, pw -> r.deleteAccount(userId, pw, reason) }
    }

    override suspend fun openAccountDevices(userId: String): OperatorResult {
        if (!open) return OperatorResult.STALE
        if (!listedAccount(userId)) return OperatorResult.NO_SUCH_ACCOUNT
        val r = routes() ?: return OperatorResult.STALE
        val g = generation
        val read = app.working { r.accountDevices(userId) }
        if (!still(g)) return OperatorResult.STALE
        return when (read) {
            is Fetched.Ok -> {
                // The operator's view carries no `current` (spec 03 §7.1): a row that claims it is not this account's list.
                if (read.value.any { it.current }) return OperatorResult.FAILED
                val checked = OperatorRows.devices(read.value)
                devicesOf = userId
                devices = checked.rows
                badDevices = checked.bad
                publish()
                OperatorResult.DONE
            }
            is Fetched.Refused -> fetched(read.code)
            Fetched.Unreachable -> OperatorResult.UNREACHABLE
        }
    }

    override fun closeAccountDevices() {
        if (devicesOf == null) return
        devicesOf = null
        devices = emptyList()
        publish()
    }

    override suspend fun revokeAccountDevice(deviceId: String, password: String): OperatorResult {
        val chars = password.toCharArray()
        try {
            if (!open) return OperatorResult.STALE
            val of = devicesOf
            if (of == null || devices.none { it.deviceId == deviceId }) return OperatorResult.NO_SUCH_DEVICE
            val r = routes() ?: return OperatorResult.STALE
            val g = generation
            val answer = app.working { r.revokeDevice(deviceId, chars) }
            if (!still(g)) return OperatorResult.STALE
            val result = reauthed(answer)
            if (result == OperatorResult.DONE) openAccountDevices(of)
            return result
        } finally {
            chars.fill('\u0000')
        }
    }

    override suspend fun setAccountQuota(userId: String, limits: QuotaLimits, password: String): OperatorResult =
        onAccount(userId, password) { r, pw -> r.setQuota(userId, limits.accountBytes, limits.items, limits.ownedSharedVaults, limits.openLinks, pw) }

    // ---- policy, audit ----

    override suspend fun savePolicy(policy: AdminPolicy, password: String): OperatorResult {
        val chars = password.toCharArray()
        try {
            if (!open) return OperatorResult.STALE
            val r = routes() ?: return OperatorResult.STALE
            val g = generation
            val answer = app.working { r.setPolicy(policy, chars) }
            if (!still(g)) return OperatorResult.STALE
            if (answer is Reauthed.Done) {
                this.policy = answer.value
                policyRefusal = null
                publish()
            }
            // The operator is told why a policy was refused, by the server's reason (a field outside its bounds is
            // `400 bad_<field>`, spec 03 §7.2; a key cost below the floor is `kdf_too_weak`): nothing was stored.
            if (answer is Reauthed.Refused) {
                policyRefusalOf(answer.code)?.let {
                    policyRefusal = it
                    publish()
                }
            }
            if (answer is Reauthed.Refused && answer.code.startsWith("bad_")) return OperatorResult.BAD_POLICY
            return reauthed(answer)
        } finally {
            chars.fill('\u0000')
        }
    }

    override suspend fun loadAudit(sinceMs: Long, type: String?, userId: String?): OperatorResult {
        if (!open) return OperatorResult.STALE
        val r = routes() ?: return OperatorResult.STALE
        val g = generation
        // The shared page read, with the checks every host makes (at most a page of rows, none twice, newest first, every
        // row inside the filters): a page that fails one is a list that lies, never a short list.
        val read = app.working { r.auditPage(sinceMs, type, userId) }
        if (!still(g)) return OperatorResult.STALE
        val rows = when (read) {
            is Fetched.Ok -> read.value.rows
            is Fetched.Refused -> return if (read.code == io.silencelen.andvari.core.client.account.WireOperatorRoutes.AUDIT_PAGE_LIES) OperatorResult.FAILED else fetched(read.code)
            Fetched.Unreachable -> return OperatorResult.UNREACHABLE
        }
        audit = rows
        publish()
        return OperatorResult.DONE
    }

    // ---- operator recovery ----

    override suspend fun downloadEscrow(userId: String, password: String): OperatorResult {
        val chars = password.toCharArray()
        try {
            if (!open) return OperatorResult.STALE
            if (!listedAccount(userId)) return OperatorResult.NO_SUCH_ACCOUNT
            val r = routes() ?: return OperatorResult.STALE
            val g = generation
            val answer = app.working { r.escrow(userId, chars) }
            if (!still(g)) return OperatorResult.STALE
            if (answer is Reauthed.Done) escrow = answer.value
            return reauthed(answer)
        } finally {
            chars.fill('\u0000')
        }
    }

    override fun takeEscrow(): AdminEscrowResponse? = escrow.also { escrow = null }

    override suspend fun fulfilRecovery(requestId: String, sealedAnswer: String, password: String): OperatorResult {
        val chars = password.toCharArray()
        try {
            if (!open) return OperatorResult.STALE
            val row = requests.firstOrNull { it.requestId == requestId } ?: return OperatorResult.REQUEST_NOT_READY
            // The one shared reader of an answer, against the listed request, before the password is touched (spec 04 §7
            // step 3): a refusal says what is wrong with the text, and nothing is sent.
            val emailNorm = io.silencelen.andvari.core.trust.TrustGrammar.emailNorm(row.email) ?: return OperatorResult.FAILED
            val read = when (val a = io.silencelen.andvari.core.trust.AnswerToken.read(sealedAnswer, row.requestId, row.rPub, emailNorm)) {
                is io.silencelen.andvari.core.trust.AnswerRead.Ok -> a
                is io.silencelen.andvari.core.trust.AnswerRead.Refused -> return OperatorResult.of(a.refusal)
            }
            val r = routes() ?: return OperatorResult.STALE
            val g = generation
            val answer = app.working { r.fulfil(requestId, read, chars) }
            if (!still(g)) return OperatorResult.STALE
            val result = reauthed(answer)
            if (result == OperatorResult.DONE) refreshConsole()
            return result
        } finally {
            chars.fill('\u0000')
        }
    }

    // ---- the instance card (§4.3): a new card this account's key signs, under the key's guard ----

    private suspend fun card(password: String, change: suspend (WireOperatorCards, CharArray) -> CardChangeResult): OperatorResult {
        val chars = password.toCharArray()
        try {
            if (!open) return OperatorResult.STALE
            val c = cards() ?: return OperatorResult.STALE
            val reauth = app.keeper.reauth() ?: return OperatorResult.STALE
            val o = origin ?: return OperatorResult.STALE
            // F10: a card the server said it stored and does not serve yet holds its number: no second card is signed at
            // it (two genuine siblings a server could show to different members). Settled once the pin reaches it.
            var pinSeq = app.trust.pinFor(o)?.seq ?: return OperatorResult.STALE
            if (storedNotShown(o, pinSeq) != null) {
                // Read the chain once more: when the server serves it now, the pin follows and the hold goes.
                val g0 = generation
                app.working { app.trust.refresh(o) }
                if (!still(g0)) return OperatorResult.STALE
                pinSeq = app.trust.pinFor(o)?.seq ?: return OperatorResult.STALE
                if (storedNotShown(o, pinSeq) != null) {
                    publish()
                    return OperatorResult.CARD_STORED_NOT_SHOWN
                }
            }
            val g = generation
            // The card's flow reads the chain before it re-authenticates; the password is proven on this device
            // first, so a wrong one sends no request at all (the proof is local; the flow proves it again before it sends).
            val proof = app.working { reauth.currentAuthKey(chars.copyOf()) }
            if (!still(g)) return OperatorResult.STALE
            if (proof is io.silencelen.andvari.core.client.account.ReauthKey.WrongPassword) return OperatorResult.WRONG_PASSWORD
            // The card is signed with the account's key: a lock that wiped it during a wait is this intent's own STALE.
            // What was signed is sent whole or not at all: a lock before the flow's guard check (after its last wait
            // before the first send) sends nothing; once that check passed, the rotations and the card signed before
            // the lock are all uploaded, so the server never holds a rotation its newest card does not name.
            // Either way the intent the lock overtook answers STALE.
            val answer = app.unlessLocked<CardChangeResult?>(null) { app.working { change(c, chars) } } ?: return OperatorResult.STALE
            if (!still(g)) return OperatorResult.STALE
            val result = when (answer) {
                is CardChangeResult.Changed -> OperatorResult.DONE
                is CardChangeResult.Stored -> {
                    // Signed on the pin as the flow left it (the pin did not follow the new card).
                    val signedOn = app.trust.pinFor(o)?.seq ?: pinSeq
                    app.engine.state.set(STORED_KEY + o, "${signedOn + 1}:${answer.hash}")
                    OperatorResult.CARD_STORED_NOT_SHOWN
                }
                is CardChangeResult.NotCurrent -> OperatorResult.CARD_MOVED_ON
                CardChangeResult.NotOperator -> OperatorResult.NOT_THE_OPERATOR
                is CardChangeResult.HeadMoved -> OperatorResult.CARD_MOVED_ON
                // The server's own refusals.
                CardChangeResult.BadCard, CardChangeResult.HandoverTargetInvalid -> OperatorResult.CARD_REFUSED
                // This device's own refusals, before anything was sent: never said as the server's.
                CardChangeResult.PublicRefusesRecoveryKey -> OperatorResult.CARD_REFUSED_HERE
                is CardChangeResult.BadRotation -> OperatorResult.ROTATION_REFUSED
                is CardChangeResult.Invalid -> if (answer.code == WireOperatorCards.BAD_ORIGIN) OperatorResult.NOT_AN_ADDRESS else OperatorResult.CARD_REFUSED_HERE
                CardChangeResult.NoSession -> OperatorResult.FAILED
                CardChangeResult.WrongPassword -> OperatorResult.WRONG_PASSWORD
                is CardChangeResult.Refused -> fetched(answer.code)
                CardChangeResult.Unknown -> OperatorResult.UNREACHABLE
            }
            app.publish()
            // The console shows the pinned card (its name, its address): a change the pin followed shows at once, with no
            // second read of the console.
            publish()
            return result
        } finally {
            chars.fill('\u0000')
        }
    }

    /**
     * The card [o]'s server said it stored at a number above the pin's [pinSeq] and does not serve yet (F10), as
     * `seq:hash`; null when there is none, or once the pin has reached that number (the record then goes).
     */
    private fun storedNotShown(o: String, pinSeq: Long): String? {
        val kept = app.engine.state.get(STORED_KEY + o) ?: return null
        val seq = kept.substringBefore(':').toLongOrNull()
        if (seq == null || pinSeq >= seq) {
            app.engine.state.set(STORED_KEY + o, null)
            return null
        }
        return kept
    }

    override suspend fun renameInstance(name: String, password: String): OperatorResult = card(password) { c, pw -> c.rename(name, pw) }

    override suspend fun moveInstance(origin: String, password: String): OperatorResult {
        // The address as typed, checked by the origin grammar before anything is derived or sent.
        val to = origin.trim().trimEnd('/')
        if (!TrustGrammar.isOrigin(to)) return OperatorResult.NOT_AN_ADDRESS
        return card(password) { c, pw -> c.move(to, pw) }
    }

    override suspend fun changeRecoveryKey(recoveryFingerprint: String, rotationStatement: String?, password: String): OperatorResult {
        val typed = recoveryFingerprint.trim().lowercase()
        if (rotationStatement == null) return card(password) { c, pw -> c.setRecoveryKey(typed, pw) }
        val statement = runCatching { io.silencelen.andvari.core.crypto.Bytes.fromB64(rotationStatement.trim()) }.getOrNull() ?: return OperatorResult.ROTATION_REFUSED
        // The typed fingerprint and the statement must agree. The statement is checked against
        // this device's pinned card before the password is used; one that leads to another key than the one typed (or
        // a blank field) is refused here, with nothing derived or sent.
        val pin = origin?.let { app.trust.pinFor(it) } ?: return OperatorResult.STALE
        val v = io.silencelen.andvari.core.trust.RecoveryRotation.verify(app.crypto, statement, pin.instanceId, pin.recoveryFp)
        if (v !is io.silencelen.andvari.core.trust.Checked.Ok || v.value.fields.toFp != typed) return OperatorResult.ROTATION_REFUSED
        return card(password) { c, pw -> c.rotateRecoveryKey(listOf(statement), pw) }
    }

    override suspend fun removeRecoveryKey(password: String): OperatorResult = card(password) { c, pw -> c.removeRecoveryKey(pw) }

    // ---- results ----

    private fun reauthed(r: Reauthed<*>): OperatorResult = when (r) {
        is Reauthed.Done -> OperatorResult.DONE
        Reauthed.WrongPassword -> OperatorResult.WRONG_PASSWORD
        Reauthed.Unknown -> OperatorResult.UNREACHABLE
        is Reauthed.Refused -> {
            app.noteRetryAfter(r.retryAfterSeconds)
            fetched(r.code)
        }
        Reauthed.NoSession, Reauthed.PasswordTooWeak -> OperatorResult.FAILED
    }

    private fun fetched(code: String): OperatorResult = when (code) {
        WireOperatorRoutes.NOT_OPERATOR, WireOperatorRoutes.OPERATOR_WEB_REFUSED -> OperatorResult.NOT_THE_OPERATOR
        WireOperatorRoutes.NO_SUCH_USER, WireOperatorRoutes.BAD_USER_ID -> OperatorResult.NO_SUCH_ACCOUNT
        WireOperatorRoutes.CANNOT_TARGET_SELF -> OperatorResult.CANNOT_TARGET_SELF
        WireOperatorRoutes.NOT_DISABLED_LONG_ENOUGH -> OperatorResult.NOT_DISABLED_LONG_ENOUGH
        WireOperatorRoutes.ACCOUNT_DELETE_BLOCKED -> OperatorResult.BLOCKED_BY_SHARED_VAULT
        WireOperatorRoutes.NO_SUCH_DEVICE, WireOperatorRoutes.BAD_DEVICE_ID -> OperatorResult.NO_SUCH_DEVICE
        WireOperatorRoutes.NOT_TIGHTER -> OperatorResult.NOT_TIGHTER
        WireOperatorRoutes.KDF_TOO_WEAK, WireOperatorRoutes.KDF_MEM_NOT_KIB_MULTIPLE, WireOperatorRoutes.BAD_QUOTA -> OperatorResult.BAD_POLICY
        WireOperatorRoutes.NO_ESCROW, WireOperatorRoutes.OPERATOR_RECOVERY_UNAVAILABLE, WireOperatorRoutes.NOT_FOUND -> OperatorResult.NO_ESCROW
        WireOperatorRoutes.REQUEST_STATE, WireOperatorRoutes.REQUEST_UNKNOWN, WireOperatorRoutes.BAD_REQUEST_ID -> OperatorResult.REQUEST_NOT_READY
        // The upload's own refusals (spec 03 §18.6): never "the request is not ready" for an answer that is wrong.
        WireOperatorRoutes.BAD_SEALED, WireOperatorRoutes.BAD_REQUEST_KEY, WireOperatorRoutes.BAD_COMMIT_HASH -> OperatorResult.ANSWER_NOT_AN_ANSWER
        WireOperatorRoutes.REQUEST_KEY_MISMATCH -> OperatorResult.ANSWER_OTHER_REQUEST_KEY
        WireErrors.RATE_LIMITED -> OperatorResult.RATE_LIMITED
        WireErrors.UPGRADE_REQUIRED -> OperatorResult.UPDATE_REQUIRED
        Reauthed.PROOF_REFUSED -> app.proofRefused(OperatorResult.KEYS_NOT_KNOWN_HERE, OperatorResult.PROOF_REFUSED)
        else -> OperatorResult.FAILED
    }

    companion object {
        /** `GET /admin/audit` answers one page of at most this many rows (spec 03 §0.4). */
        const val AUDIT_PAGE_ROWS = 500

        /** Device state: a card the server said it stored and does not serve yet, `seq:hash`, per origin (F10). */
        const val STORED_KEY = "ovh.cardstored|"
    }
}
