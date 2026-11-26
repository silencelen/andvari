package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AnsweredLinkRow
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.ConnectResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CopyLine
import io.silencelen.andvari.core.app.InviteResult
import io.silencelen.andvari.core.app.LinkCreateResult
import io.silencelen.andvari.core.app.LinkLifetimes
import io.silencelen.andvari.core.app.LinksApi
import io.silencelen.andvari.core.app.LinksScreen
import io.silencelen.andvari.core.app.OpenedInvite
import io.silencelen.andvari.core.app.OwnLinkKind
import io.silencelen.andvari.core.app.OwnLinkRow
import io.silencelen.andvari.core.app.OwnNameResult
import io.silencelen.andvari.core.trust.TrustGrammar
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.PendingShareRow
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.ShareChoice
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.client.link.CompareState
import io.silencelen.andvari.core.client.link.CreateOutcome
import io.silencelen.andvari.core.client.link.LinkShare
import io.silencelen.andvari.core.client.log.AppendOutcome
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.link.CreatedLink
import io.silencelen.andvari.core.client.link.CreatorStep
import io.silencelen.andvari.core.client.link.LinkStop
import io.silencelen.andvari.core.client.link.RecipientStep
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.trust.MemberRole
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Links over the engine's [io.silencelen.andvari.core.client.link.WireLinkFlows] ([EngineAppApi.entryLinks], which sees
 * the open account). Bound:
 * - the connection a connect link opened signed out still owes once the account it led to is open (§6.7 "Connect,
 *   recipient has no account"), with its [AccountPrompt.ConnectionNotMade];
 * - the links screen: this device's own links, made, shared and revoked, and the answers processed (§6.7, §6.8 creator
 *   side), each answer with the contact it made;
 * - a connect link opened while signed in to its own server (§6.8 recipient side): "Connect with …?", the key-change
 *   acknowledgement, and the answer.
 *
 * - the vaults attached to a connect link (§6.10): attached when it is made, shared through the vault log once this
 *   device's own entry of the codes matched (the link engine's release), listed while they wait, and released by hand
 *   behind [io.silencelen.andvari.core.app.UncomparedShareWarning].
 *
 * - an invite for another server opened while signed in (§6.7's dead end): [OpenedInvite.OtherInstance], the Trust Gate
 *   of an enrol link for a server this device does not pin ([OpenedInvite.TrustGate]), and "Switch to …", which signs
 *   out here and goes on with the invite signed out.
 *
 * Not yet: [OpenedInvite.ServerChanged] signed in (a server this device pins, met moved or changed under that pin).
 */
internal class EngineLinks(private val app: EngineAppApi, unbound: Unbound) : LinksApi by unbound {
    /** The prompt on show for a connection the held answer did not make; null when none is. */
    var notMade: AccountPrompt.ConnectionNotMade? = null
        private set

    private var open = false

    /** Links answered while this session was open, newest first: (link id, contact user id, key changed). */
    private val answered = ArrayList<Triple<String, String, Boolean>>()

    /** When each link made in this process was created, on the monotonic clock, for its countdown (SR-1). */
    private val madeAt = HashMap<String, Long>()

    /** The invite opened while signed in, with the engine's step it stands for. */
    private var opened: OpenedInvite? = null
    private var openedStep: RecipientStep? = null

    /** Why the link just opened is not used here ([InviteResult.NOT_USABLE_SIGNED_IN]); it goes with [closeOpened]. */
    private var notUsed: CopyLine? = null

    /** How often the answers to this device's links are fetched while the links screen is open. Tests set it out of reach. */
    var answersPollMs: Long = 5_000L
    private var poll: Job? = null

    /** The session ended, locked or moved: the prompt and the screens go; an opened invite's flow is closed. */
    fun ended() {
        notMade = null
        open = false
        poll?.cancel()
        poll = null
        answered.clear()
        keyChanges.clear()
        closeOpened()
    }

    private fun closeOpened() {
        openedStep?.let(app.entryLinks::dismiss)
        openedStep = null
        opened = null
        notUsed = null
    }

    private fun unlocked(): EngineVault? = app.vault?.takeIf { !it.closed && app.phase == AppPhase.UNLOCKED }

    private fun nowMono(): Long = app.engine.clocks?.monotonicMs() ?: app.engine.clock()

    /** The vault opened: a connect link the person came in through is answered now, and answers to this device's links are read. */
    fun vaultOpened() {
        val step = app.connectAfterEntry
        val v = unlocked()
        // A key change an earlier opening processed is still waiting for its comparison: the link engine's record says so.
        if (v != null) {
            for (userId in v.store.local().contacts.keys) {
                val st = app.entryLinks.compareState(userId)
                if (st is CompareState.Ready && st.replacesKey) keyChanges.getOrPut(userId) { null }
            }
        }
        app.scope.launch {
            if (step != null) answer(step)
            processAnswers()
        }
    }

    /**
     * Contacts whose answer to one of this device's links came under another key than the pinned one (§6.8 step 6,
     * creator side), each with the prompt on show for it. The old key stays pinned; the prompt stays until this device's
     * own matched comparison replaces the key, or the link engine's record of that answer is no longer waiting for one.
     */
    private val keyChanges = LinkedHashMap<String, AccountPrompt.KeyChanged?>()

    /** [AccountPrompt.KeyChanged], one for each contact in [keyChanges] still waiting: the same object while it waits. */
    fun keyChangePrompts(): List<AccountPrompt.KeyChanged> {
        if (unlocked() == null || keyChanges.isEmpty()) return emptyList()
        val out = ArrayList<AccountPrompt.KeyChanged>()
        for (userId in keyChanges.keys.toList()) {
            val st = app.entryLinks.compareState(userId)
            if (st !is CompareState.Ready || !st.replacesKey) {
                keyChanges.remove(userId)
                continue
            }
            // The label as pinned: the contact's own record, else the one the answer's record kept.
            val label = app.contactsFlow.rowFor(userId)?.label ?: st.label
            val before = keyChanges[userId]
            out += if (before != null && before.label == label) before else AccountPrompt.KeyChanged(userId, label).also { keyChanges[userId] = it }
        }
        return out
    }

    // ---- what the snapshot shows ----

    private val rows = HashMap<String, OwnLinkRow>()
    private var screenShown: LinksScreen? = null

    private fun row(l: CreatedLink): OwnLinkRow {
        val kind = if (l.kind == "register") OwnLinkKind.INVITATION else OwnLinkKind.CONNECT
        rows[l.linkId]?.let { return it }
        val shares = l.shares.mapNotNull { s -> MemberRole.fromLiteral(s.role)?.let { ShareChoice(s.vaultId, it) } }
        return OwnLinkRow(l.linkId, kind, shares).also { rows[l.linkId] = it }
    }

    fun screen(): LinksScreen? {
        val v = unlocked() ?: return null
        if (!open) return null
        val now = app.engine.clock()
        app.entryLinks.expireRecords(now)
        val links = app.entryLinks.createdLinks().map(::row)
        // A row leaves once its contact is compared.
        val done = answered.mapNotNull { (linkId, userId, changed) ->
            val contact = app.contactsFlow.rowFor(userId) ?: return@mapNotNull null
            if (contact.compared && !changed) null else Triple(linkId, contact, changed)
        }
        val shown = screenShown
        val answeredRows = done.map { (linkId, contact, changed) ->
            shown?.answered?.firstOrNull { it.linkId == linkId && it.contact === contact && it.keyChanged == changed } ?: AnsweredLinkRow(linkId, contact, changed)
        }
        // GAP (§6.6): whether members may invite here is not served to the app; the operator may, and a refusal says the rest.
        val invite = app.keeper.established?.role == "operator"
        val waiting = waiting(v)
        if (shown != null && shown.invitationsAllowed == invite && same(shown.links, links) && same(shown.answered, answeredRows) && same(shown.waitingShares, waiting)) return shown
        return LinksScreen(links, answeredRows, waiting, invite).also { screenShown = it }
    }

    private fun <T> same(a: List<T>, b: List<T>) = a.size == b.size && a.indices.all { a[it] === b[it] }

    fun openedInvite(): OpenedInvite? = if (unlocked() == null) null else opened

    fun inviteNotUsed(): CopyLine? = if (unlocked() == null) null else notUsed

    // ---- the links screen ----

    override suspend fun openLinks(): PlainResult {
        unlocked() ?: return PlainResult.STALE
        open = true
        app.publish()
        processAnswers()
        startPolling()
        return PlainResult.DONE
    }

    override fun closeLinks() {
        if (!open) return
        open = false
        poll?.cancel()
        poll = null
        app.publish()
    }

    private fun startPolling() {
        if (poll != null || answersPollMs == Long.MAX_VALUE) return
        poll = app.scope.launch {
            while (open && unlocked() != null) {
                delay(answersPollMs)
                processAnswers()
            }
        }
    }

    /** Process the answers to this device's links (§6.8 creator side): each one pins its answerer as a contact, uncompared. */
    suspend fun processAnswers() {
        val v = unlocked() ?: return
        if (!app.mayDial(v.origin)) return
        // A lock while the answers are read: the link engine pinned and sent nothing more; the next opening
        // reads them again.
        val steps = app.unlessLocked(null) { app.entryLinks.processAnswers() } ?: return
        var changed = false
        for (s in steps) {
            when (s) {
                is CreatorStep.Processed -> {
                    answered.add(0, Triple(s.linkId, s.contactUserId, false))
                    changed = true
                }
                is CreatorStep.KeyChanged -> {
                    answered.add(0, Triple(s.linkId, s.answererUserId, true))
                    // §6.8 step 6, creator side: the prompt, never a verdict, until a matched comparison replaces the key.
                    keyChanges.getOrPut(s.answererUserId) { null }
                    changed = true
                }
                // An answer to another device's link is that device's; a deferred one finishes at the next run.
                is CreatorStep.Ignored, is CreatorStep.Deferred -> {}
            }
        }
        if (changed) app.publish()
    }

    override suspend fun createConnectLink(shares: List<ShareChoice>, minutes: Int): LinkCreateResult {
        if (minutes !in LinkLifetimes.SHORTEST_MINUTES..LinkLifetimes.CONNECT_LONGEST_MINUTES) return LinkCreateResult.BAD_LIFETIME
        unlocked() ?: return LinkCreateResult.STALE
        // Design §6.10: each vault attached is one this account owns in its verified log and can sign for, once, as a
        // writer or a reader. Choosing it is the person confirming that (vault, person) pair; it is shared only after the
        // codes matched, or by a release behind the warning (T-B2).
        val rows = app.vaultsFlow.rows()
        if (shares.map { it.vaultId }.distinct().size != shares.size) return LinkCreateResult.NOT_ALLOWED
        for (s in shares) {
            val row = rows.firstOrNull { it.vaultId == s.vaultId } ?: return LinkCreateResult.NOT_ALLOWED
            if (row.role != io.silencelen.andvari.core.app.RoleInVault.OWNER || !row.writable || row.deleted) return LinkCreateResult.NOT_ALLOWED
            if (app.vaultsFlow.moveDeleteWaiting(s.vaultId)) return LinkCreateResult.NOT_ALLOWED
        }
        return create("connect", minutes, shares.map { LinkShare(it.vaultId, it.role.literal) })
    }

    override suspend fun createInvitation(minutes: Int): LinkCreateResult {
        if (minutes !in LinkLifetimes.SHORTEST_MINUTES..LinkLifetimes.INVITATION_LONGEST_MINUTES) return LinkCreateResult.BAD_LIFETIME
        return create("register", minutes, emptyList())
    }

    // ---- the vaults attached to a link (design §6.10) ----

    /** What the last share through the vault log came to (the link engine itself answers only yes or no). */
    private var lastRelease: AppendOutcome? = null

    /**
     * The link engine's [io.silencelen.andvari.core.client.link.LinkShareRelease]: the `add` of [contactUserId] to the
     * share's vault on the open vault's log. True only once the server stored it; sent without an answer, the log engine
     * keeps it and the share stays waiting, so the next release re-posts it.
     */
    suspend fun releaseThroughLog(contactUserId: String, share: LinkShare, uncompared: Boolean): Boolean {
        val v = unlocked() ?: return false
        // The vault's deletion by a move is signed and waiting: nothing is signed on its log, and the share stays waiting
        // (by hand and by itself, when the codes match).
        if (app.vaultsFlow.moveDeleteWaiting(share.vaultId)) {
            lastRelease = AppendOutcome.NotAllowed(EngineSharedVaults.MOVE_DELETE_WAITING_REASON)
            return false
        }
        val r = v.logs.append(share.vaultId, LogAction.Add(contactUserId, share.role, releaseUncompared = uncompared))
        lastRelease = r
        if (r is AppendOutcome.Appended || r is AppendOutcome.Pending) v.afterLogAction()
        if (r is AppendOutcome.Appended) return true
        // An earlier add sent without an answer, re-posted first and stored now: the log refuses a second one. The add
        // the server stored, with this role, is the share.
        val held = (v.logs.status(share.vaultId) as? io.silencelen.andvari.core.client.log.VaultLogStatus.Verified)?.state?.members?.get(contactUserId)
        if (r is AppendOutcome.NotAllowed && held?.role == share.role) {
            lastRelease = null
            return true
        }
        return false
    }

    private val waitingRows = HashMap<String, PendingShareRow>()

    /** The vaults attached to answered links of this device and not shared yet, each with its contact (§6.10). */
    private fun waiting(v: EngineVault): List<PendingShareRow> {
        val names = app.vaultsFlow.rows().associate { it.vaultId to it.name }
        val out = ArrayList<PendingShareRow>()
        for ((userId, list) in app.entryLinks.pendingShares().entries.sortedBy { it.key }) {
            val contact = app.contactsFlow.rowFor(userId) ?: continue
            for (s in list) {
                val role = MemberRole.fromLiteral(s.role) ?: continue
                val name = names[s.vaultId] ?: v.content.state.vaults.firstOrNull { it.vaultId == s.vaultId }?.name ?: continue
                val key = "$userId|${s.vaultId}|${s.role}|$name|${contact.label}"
                out += waitingRows.getOrPut(key) { PendingShareRow(s.vaultId, name, role, userId, contact.label) }
            }
        }
        return out
    }

    override suspend fun releaseShare(share: PendingShareRow): VaultActionResult {
        unlocked() ?: return VaultActionResult.STALE
        if (screenShown?.waitingShares?.any { it === share } != true) return VaultActionResult.STALE
        val contact = app.contactsFlow.rowFor(share.userId) ?: return VaultActionResult.NOT_A_CONTACT_HERE
        if (app.vaultsFlow.moveDeleteWaiting(share.vaultId)) return VaultActionResult.MOVE_DELETE_WAITING
        // §6.7 step 8: to a contact whose codes were not compared, nothing is shared until the warning is confirmed.
        if (!contact.compared) {
            app.vaultsFlow.warnForLinkShare(share)
            return VaultActionResult.NEEDS_UNCOMPARED_WARNING
        }
        return release(share)
    }

    /** Share [share] now through the link engine's own record, so it leaves the waiting list only once the server stored it. */
    internal suspend fun release(share: PendingShareRow): VaultActionResult {
        unlocked() ?: return VaultActionResult.STALE
        lastRelease = null
        val ok = app.unlessLocked(null) { app.working { app.entryLinks.releaseShare(share.userId, LinkShare(share.vaultId, share.role.literal)) } }
            ?: return VaultActionResult.STALE
        app.publish()
        if (ok) return VaultActionResult.DONE
        // The link engine refused before any append (no such waiting share, or the contact's pin is not the link's).
        return lastRelease?.let { app.vaultsFlow.resultOf(it) } ?: VaultActionResult.NOT_ALLOWED
    }

    // ---- the name this account's links carry (§6.3, §6.7) ----

    /**
     * The server serves no account its own name, so a device knows it only where it was chosen: at the registration on
     * this device, or by [setOwnName]. Without one the link engine signs nothing (its `bad_name` stop), so every road
     * that would need it asks for it first and keeps what it holds.
     */
    override fun ownName(): String? = unlocked()?.link?.displayName?.takeIf { TrustGrammar.encodeName(it) != null }

    override fun setOwnName(name: String): OwnNameResult {
        val v = unlocked() ?: return OwnNameResult.STALE
        if (TrustGrammar.encodeName(name) == null) return OwnNameResult.NOT_A_NAME
        app.rememberName(v.origin, v.userId, name)
        v.named(name)
        app.publish()
        return OwnNameResult.DONE
    }

    private suspend fun create(kind: String, minutes: Int, shares: List<LinkShare>): LinkCreateResult {
        val v = unlocked() ?: return LinkCreateResult.STALE
        if (ownName() == null) return LinkCreateResult.NAME_NEEDED
        if (!app.mayDial(v.origin)) return LinkCreateResult.FAILED
        val r = app.unlessLocked(null) { app.working { app.entryLinks.create(kind, minutes * 60_000L, shares) } }
            ?: return LinkCreateResult.STALE
        return when (r) {
            is CreateOutcome.Created -> {
                madeAt[r.link.linkId] = nowMono()
                open = true
                startPolling()
                app.publish()
                LinkCreateResult.DONE
            }
            // The record stays; the link may or may not exist at the server.
            is CreateOutcome.Unknown -> {
                madeAt[r.link.linkId] = nowMono()
                app.publish()
                LinkCreateResult.UNREACHABLE
            }
            is CreateOutcome.Refused -> when (r.code) {
                LinkStop.TOO_MANY_CONTACTS.code -> LinkCreateResult.TOO_MANY_CONTACTS
                "quota_exceeded" -> LinkCreateResult.TOO_MANY_OPEN_LINKS
                "not_operator", "forbidden", "invites_disabled" -> LinkCreateResult.NOT_ALLOWED
                "bad_lifetime", "bad_expiry" -> LinkCreateResult.BAD_LIFETIME
                "rate_limited" -> {
                    app.noteRetryAfter(r.retryAfterSeconds)
                    LinkCreateResult.RATE_LIMITED
                }
                "update_required" -> LinkCreateResult.UPDATE_REQUIRED
                else -> LinkCreateResult.FAILED
            }
        }
    }

    private fun own(link: OwnLinkRow): CreatedLink? =
        if (unlocked() == null || rows[link.linkId] !== link) null else app.entryLinks.createdLinks().firstOrNull { it.linkId == link.linkId }

    override fun linkToShare(link: OwnLinkRow): String? = own(link)?.url

    override fun linkTimeLeftMs(link: OwnLinkRow): Long {
        val l = own(link) ?: return 0L
        val ttl = l.ttlMs ?: return 0L
        // GAP: a link made before this process started is counted from when this process first saw it.
        val since = madeAt.getOrPut(l.linkId) { nowMono() }
        return (ttl - (nowMono() - since)).coerceAtLeast(0L)
    }

    override suspend fun revokeLink(link: OwnLinkRow): PlainResult {
        val l = own(link) ?: return PlainResult.STALE
        // The record goes first, so a later answer is ignored whatever the server says (T-R3).
        val confirmed = app.unlessLocked(null) { app.working { app.entryLinks.revoke(l.linkId) } } ?: return PlainResult.STALE
        rows.remove(l.linkId)
        madeAt.remove(l.linkId)
        app.publish()
        return if (confirmed) PlainResult.DONE else PlainResult.UNREACHABLE
    }

    // ---- an invite opened while signed in ----

    override suspend fun openInvite(payload: String, source: PayloadSource): InviteResult {
        unlocked() ?: return InviteResult.STALE
        val entry = if (source == PayloadSource.SCANNED) GateEntry.SCAN_INVITE else GateEntry.PASTE_INVITE
        return openText(payload.trim(), entry)
    }

    /** An app link tapped while unlocked ([io.silencelen.andvari.core.app.AppApi.openAppLink]). */
    suspend fun openAppLink(url: String): InviteResult {
        unlocked() ?: return InviteResult.STALE
        return openText(url.trim(), GateEntry.APP_LINK)
    }

    private suspend fun openText(text: String, entry: GateEntry): InviteResult {
        val v = unlocked() ?: return InviteResult.STALE
        closeOpened()
        val step = app.unlessLocked(null) { app.working { app.entryLinks.open(text, entry) } } ?: return InviteResult.STALE
        if (unlocked() !== v) {
            app.entryLinks.dismiss(step)
            return InviteResult.STALE
        }
        return show(v, step)
    }

    private fun show(v: EngineVault, step: RecipientStep): InviteResult {
        val label = app.labelFor(v.origin)
        val result = when (step) {
            is RecipientStep.Stopped -> return stopped(step.reason)
            is RecipientStep.Confirm -> {
                if (step.offer.kind != "connect" || step.offer.origin != v.origin || label == null) {
                    app.entryLinks.dismiss(step)
                    if (step.offer.origin != v.origin) return InviteResult.FAILED
                    // A link that creates an account, on the instance this app is signed in to: nothing is sent, and
                    // the approved sentence (entry 7) is filled with the pinned card's name and address.
                    val key = when (step.offer.kind) {
                        "register" -> CopyKey.ALREADY_SIGNED_IN_THERE
                        "enrol" -> CopyKey.ALREADY_SIGNED_IN_THERE_ENROL
                        "setup" -> return InviteResult.SETUP_ALREADY_DONE
                        else -> return InviteResult.FAILED
                    }
                    notUsed = label?.let { CopyLine.of(key, it.name, it.origin) }
                    app.publish()
                    return InviteResult.NOT_USABLE_SIGNED_IN
                }
                OpenedInvite.Connect(label, step.offer.creatorName.orEmpty())
            }
            is RecipientStep.KeyChanged -> OpenedInvite.KeyChanged(step.existingLabel)
            // §6.7's dead end: the invite is for another instance than the one this app is signed in to. Its name is a
            // pinned card's word (the link's signed offer anchored it, or this device pinned that server before); nothing
            // was sent to it but the reads of the link and of its card.
            is RecipientStep.OtherInstance -> {
                val theirs = app.labelFor(step.offer.origin)
                if (theirs == null || label == null) {
                    app.entryLinks.dismiss(step)
                    return InviteResult.FAILED
                }
                // The line beside "switch" says what is true for this account: with "New devices must be linked" on (or
                // not known here), signing in again on this device will not bring it back by itself.
                OpenedInvite.OtherInstance(theirs, label, app.devicesFlow.requireLinkKnown())
            }
            // An enrol link for a server this device holds no pin for: its host's own claim, so the Trust Gate comes
            // before anything else, in its enrol wording. Nothing is pinned until the person confirms it.
            is RecipientStep.TrustGate -> {
                if (label == null) {
                    app.entryLinks.dismiss(step)
                    return InviteResult.FAILED
                }
                OpenedInvite.TrustGate(app.gatePrompt(step.gate, kitChanged = false, typedKit = false), label)
            }
            // §2.4: the card the link's server serves was made for another address. Nothing was pinned; signed in, no
            // screen follows and the stop names neither address.
            is RecipientStep.OriginMismatch -> return InviteResult.OTHER_ADDRESS
            // GAP: a server this device pins, met moved or changed under that pin while signed in elsewhere. Nothing
            // was sent; the flow is closed, and with it any pin it made.
            else -> {
                app.entryLinks.dismiss(step)
                return InviteResult.FAILED
            }
        }
        openedStep = step
        opened = result
        app.publish()
        return InviteResult.DONE
    }

    private fun stopped(reason: LinkStop): InviteResult = when (reason) {
        LinkStop.BAD_LINK, LinkStop.WRONG_ENTRY -> InviteResult.NOT_AN_INVITE
        LinkStop.WRONG_SCREEN_DEVICE_LINK -> InviteResult.DEVICE_LINK_NOT_HERE
        LinkStop.WRONG_SCREEN_KIT -> InviteResult.KIT_NOT_AN_INVITE
        LinkStop.UNKNOWN -> InviteResult.NOT_FOUND
        LinkStop.EXPIRED, LinkStop.OFFER_EXPIRED -> InviteResult.EXPIRED
        LinkStop.ALREADY_USED -> InviteResult.ALREADY_USED
        LinkStop.OWN_LINK -> InviteResult.OWN_LINK
        LinkStop.ORIGIN_MISMATCH -> InviteResult.OTHER_ADDRESS
        LinkStop.UPDATE_REQUIRED -> InviteResult.UPDATE_REQUIRED
        LinkStop.SETUP_ON_PHONE -> InviteResult.SETUP_NEEDS_COMPUTER
        LinkStop.ALREADY_SET_UP -> InviteResult.SETUP_ALREADY_DONE
        LinkStop.UNREACHABLE -> InviteResult.UNREACHABLE
        LinkStop.STALE, LinkStop.DECLINED -> InviteResult.STALE
        // A blocked server is not shown from here yet (GAP: OpenedInvite.ServerChanged signed in).
        LinkStop.FORK, LinkStop.DAMAGED -> InviteResult.FAILED
        else -> InviteResult.DOES_NOT_CHECK_OUT
    }

    override fun acknowledgeKeyChange(prompt: OpenedInvite.KeyChanged) {
        val v = unlocked() ?: return
        if (opened !== prompt) return
        val step = openedStep ?: return
        app.scope.launch {
            val next = app.unlessLocked(null) { app.working { app.entryLinks.proceed(step) } } ?: return@launch
            if (opened !== prompt || unlocked() !== v) {
                app.entryLinks.dismiss(next)
                return@launch
            }
            openedStep = null
            opened = null
            show(v, next)
        }
    }

    override suspend fun connect(prompt: OpenedInvite.Connect): ConnectResult {
        val v = unlocked() ?: return ConnectResult.STALE
        if (opened !== prompt) return ConnectResult.STALE
        val step = openedStep as? RecipientStep.Confirm ?: return ConnectResult.STALE
        // The answer carries this account's name: without one the link engine would end the flow with nothing sent.
        if (ownName() == null) return ConnectResult.NAME_NEEDED
        if (!app.mayDial(v.origin)) return ConnectResult.FAILED
        val r = app.unlessLocked(null) { app.working { app.entryLinks.confirm(step) } }
        if (r == null || opened !== prompt || unlocked() !== v) return ConnectResult.STALE
        return when (r) {
            is RecipientStep.Answered, is RecipientStep.CodeReady -> {
                val userId = if (r is RecipientStep.Answered) r.contactUserId else (r as RecipientStep.CodeReady).contactUserId
                openedStep = null
                val row = app.contactsFlow.rowFor(userId)
                opened = row?.let { OpenedInvite.Connected(it) }
                app.publish()
                ConnectResult.DONE
            }
            is RecipientStep.KeyChanged -> {
                openedStep = r
                opened = OpenedInvite.KeyChanged(r.existingLabel)
                app.publish()
                ConnectResult.FAILED
            }
            // No answer: the flow is kept, and this prompt again is the retry.
            is RecipientStep.Stopped -> if (r.reason == LinkStop.UNREACHABLE) ConnectResult.UNREACHABLE else {
                openedStep = null
                opened = null
                app.publish()
                connectResult(r.reason)
            }
            else -> ConnectResult.STALE
        }
    }

    /**
     * The Trust Gate of an enrol link opened while signed in elsewhere, confirmed: the link engine pins the server (an
     * enrol pin, which is never a password pin) and runs its account checks, which end at [OpenedInvite.OtherInstance].
     */
    override suspend fun confirmOpenedGate(prompt: OpenedInvite.TrustGate): ServerResult {
        val v = unlocked() ?: return ServerResult.STALE
        if (opened !== prompt) return ServerResult.STALE
        val step = openedStep as? RecipientStep.TrustGate ?: return ServerResult.STALE
        val next = app.unlessLocked(null) { app.working { app.entryLinks.proceed(step) } } ?: return ServerResult.STALE
        // The screen was left, or the session ended meanwhile: what came back is not shown, and the flow ends with the
        // pin it made.
        if (opened !== prompt || unlocked() !== v) {
            app.entryLinks.dismiss(next)
            return ServerResult.STALE
        }
        openedStep = null
        opened = null
        val r = show(v, next)
        if (r != InviteResult.DONE) app.publish()
        return app.entryFlow.inviteToServer(r)
    }

    /**
     * "Switch to …" (§6.7): sign out of this instance, as "Sign out" does, and go on with the invite on its own server,
     * signed out. The invite's server is asked first whether it answers at all, so a server that does not leaves this
     * session as it was. The link's flow, with the pin its opening made, is taken off this screen before the sign-out,
     * so the sign-out does not end it; the journey then shows what the link engine's account checks come to with no
     * account (the join screen, the sign-up form, or the server's refusal of new accounts).
     */
    override suspend fun switchInstance(prompt: OpenedInvite.OtherInstance): ServerResult = switchTo(prompt, null)

    override suspend fun switchInstanceConfirmed(prompt: OpenedInvite.OtherInstance, check: io.silencelen.andvari.core.app.SignOutCheck): ServerResult =
        switchTo(prompt, check)

    /**
     * The switch is a sign-out (rule of 2026-11-17): with changes on this device not sent, it needs the person's second
     * confirmation of the check on show ([confirmed]), checked before the other server is asked anything and again just
     * before the sign-out (the wait for its answer is time in which more can be changed).
     */
    private fun unsentRefused(confirmed: io.silencelen.andvari.core.app.SignOutCheck?): Boolean {
        val now = app.signOutCheck() ?: return true
        return now.needsConfirmation && now !== confirmed
    }

    private suspend fun switchTo(prompt: OpenedInvite.OtherInstance, confirmed: io.silencelen.andvari.core.app.SignOutCheck?): ServerResult {
        val v = unlocked() ?: return ServerResult.STALE
        if (opened !== prompt) return ServerResult.STALE
        val step = openedStep as? RecipientStep.OtherInstance ?: return ServerResult.STALE
        if (unsentRefused(confirmed)) return ServerResult.UNSENT_NOT_CONFIRMED
        val reach = app.unlessLocked(null) { app.working { app.entryFlow.answers(step.offer.origin) } } ?: return ServerResult.STALE
        if (opened !== prompt || unlocked() !== v) return ServerResult.STALE
        if (reach != ServerResult.DONE) return reach
        if (unsentRefused(confirmed)) return ServerResult.UNSENT_NOT_CONFIRMED
        openedStep = null
        opened = null
        if (app.signOutNow() != PlainResult.DONE) {
            app.entryLinks.dismiss(step)
            app.publish()
            return ServerResult.FAILED
        }
        return app.entryFlow.continueInvite(step)
    }

    override fun dismissOpened() {
        if (opened == null && openedStep == null && notUsed == null) return
        closeOpened()
        app.publish()
    }

    private fun connectResult(reason: LinkStop): ConnectResult = when (reason) {
        LinkStop.UNREACHABLE -> ConnectResult.UNREACHABLE
        LinkStop.ALREADY_USED -> ConnectResult.ALREADY_USED
        LinkStop.EXPIRED, LinkStop.OFFER_EXPIRED -> ConnectResult.EXPIRED
        LinkStop.TOO_MANY_CONTACTS -> ConnectResult.TOO_MANY_CONTACTS
        LinkStop.STALE -> ConnectResult.STALE
        else -> ConnectResult.FAILED
    }

    // ---- the connection a connect link opened signed out still owes ----

    /**
     * Post the answer [step] holds (design §6.7 step 6) with the open account's link engine. A server that did not answer
     * keeps the flow, so the same step is the retry; any other stop ends it, and only a new link helps.
     */
    suspend fun answer(step: RecipientStep.Confirm): ConnectResult {
        if (unlocked() == null) return ConnectResult.STALE
        // An account signed in on a device where it was not made: its name is asked for, and the step stays held for
        // the retry once it is chosen.
        if (ownName() == null) return owed(step, ConnectResult.NAME_NEEDED)
        // A lock during the answer's waits signs and sends nothing more: the step stays held, and the
        // next opening answers it again.
        val r = app.unlessLocked(null) { app.working { app.entryLinks.confirm(step) } }
        // The session ended, locked or moved meanwhile: what came back is not shown.
        if (r == null || app.connectAfterEntry !== step || app.phase != AppPhase.UNLOCKED) return ConnectResult.STALE
        val why = when (r) {
            is RecipientStep.Answered, is RecipientStep.CodeReady -> ConnectResult.DONE
            // The account was not open for the link engine: nothing was sent, and the step stays held.
            is RecipientStep.Confirm -> return ConnectResult.STALE
            is RecipientStep.Stopped -> connectResult(r.reason).let { if (it == ConnectResult.STALE) ConnectResult.FAILED else it }
            // A fresh account has no contact whose key could differ; anything else is a failure, and the flow is closed.
            else -> {
                app.entryLinks.dismiss(r)
                ConnectResult.FAILED
            }
        }
        return owed(step, why)
    }

    /** What [answer] came to, [why], on the prompt: retried after no answer or once a name is chosen, otherwise dropped. */
    private fun owed(step: RecipientStep.Confirm, why: ConnectResult): ConnectResult {
        val retry = why == ConnectResult.UNREACHABLE || why == ConnectResult.NAME_NEEDED
        if (!retry) app.connectAfterEntry = null
        notMade = if (why == ConnectResult.DONE) {
            null
        } else {
            val from = step.offer.creatorName.orEmpty()
            notMade?.takeIf { it.from == from && it.why == why && it.canRetry == retry } ?: AccountPrompt.ConnectionNotMade(from, why, retry)
        }
        app.publish()
        return why
    }

    override suspend fun retryConnection(prompt: AccountPrompt.ConnectionNotMade): ConnectResult {
        if (app.phase != AppPhase.UNLOCKED || prompt !== notMade || !prompt.canRetry) return ConnectResult.STALE
        val step = app.connectAfterEntry ?: return ConnectResult.STALE
        return answer(step)
    }

    override fun dropConnection(prompt: AccountPrompt.ConnectionNotMade) {
        if (app.phase != AppPhase.UNLOCKED || prompt !== notMade) return
        // The settled flow ends with its answer key; the pin the account stands on stays (LinkFlows.settle).
        app.connectAfterEntry?.let(app.entryLinks::dismiss)
        app.connectAfterEntry = null
        notMade = null
        app.publish()
    }
}
