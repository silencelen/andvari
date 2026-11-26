package io.silencelen.andvari.core.app.fake

import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.CompareScreen
import io.silencelen.andvari.core.app.ComparisonResult
import io.silencelen.andvari.core.app.ConnectResult
import io.silencelen.andvari.core.app.ContactRow
import io.silencelen.andvari.core.app.ContactsApi
import io.silencelen.andvari.core.app.ContactsScreen
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.InviteResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CopyLine
import io.silencelen.andvari.core.app.KitApi
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.KitDocument
import io.silencelen.andvari.core.app.KitReason
import io.silencelen.andvari.core.app.KitScreen
import io.silencelen.andvari.core.app.KitStep
import io.silencelen.andvari.core.app.LinkCreateResult
import io.silencelen.andvari.core.app.LinkLifetimes
import io.silencelen.andvari.core.app.LinksApi
import io.silencelen.andvari.core.app.OpenedInvite
import io.silencelen.andvari.core.app.OwnLinkKind
import io.silencelen.andvari.core.app.OwnLinkRow
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.PendingShareRow
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.RoleInVault
import io.silencelen.andvari.core.app.ServerKind
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.ShareChoice
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.VaultLogState
import io.silencelen.andvari.core.client.pin.PinRoot

/** The recovery kit's steps in the fake, for the signed-out journey and for Settings alike. */
internal class FakeKitFlow(private val app: FakeAppApi) : KitApi {
    /** A kit the server already holds (a registration or a recovery committed it): reveal it. */
    fun show(account: FakeAccount, reason: KitReason, inEntry: Boolean, then: () -> Unit) {
        val kit = FakeKitState(account, reason, KitStep.REVEAL, inEntry, then)
        app.session?.kit = kit
        account.kitShownUnconfirmed = true
        put(kit)
    }

    /** A kit shown with a refusal: no session holds its account, so it is held here and its confirm is checked on the device. */
    private var loose: FakeKitState? = null

    /**
     * As the engine: a kit the server holds (a recovery or a registration was committed) for an account this device then
     * did not keep. Shown with [line]; kept until its groups are typed, then [then] runs. The server is not told.
     * [whileAnotherKept]: what [line] names stands only while another account is kept here (as the engine's `KitMark`).
     */
    fun showNotKept(account: FakeAccount, reason: KitReason, line: io.silencelen.andvari.core.app.CopyKey, whileAnotherKept: Boolean, then: () -> Unit) {
        val kit = FakeKitState(account, reason, KitStep.REVEAL, inEntry = true, then)
        kit.notKeptLine = line
        kit.whileAnotherKept = whileAnotherKept
        // As the engine: a kit that comes on show while the app is away is not seen until it comes back.
        kit.seen = !app.away
        loose = kit
        account.kitShownUnconfirmed = true
        put(kit)
    }

    /** The journey left the kit shown with a refusal: it goes. */
    fun dropNotKept() {
        loose = null
    }

    /**
     * As the engine's lock: the kit shown with a refusal is wiped, and what the notice says of it is answered (whether it
     * came after a recovery, its address, the refusal's line while it still stands); null when none was on show.
     */
    fun wipeNotKeptAtLock(anotherKept: Boolean): io.silencelen.andvari.core.app.KitWipedNotice? {
        val kit = loose ?: return null
        loose = null
        if ((app.entryScreen as? EntryScreen.Kit)?.kit?.notKeptLine != null) app.entryScreen = null
        val why = kit.notKeptLine?.takeIf { !kit.whileAnotherKept || anotherKept }
        return io.silencelen.andvari.core.app.KitWipedNotice.of(kit.reason != KitReason.FIRST_KIT, kit.account.email, why, unseen = !kit.seen,
            namedKept = app.keptMark().ifEmpty { null })
    }

    /** The app is on show again: the kit shown with a refusal is seen. */
    fun seenNow() {
        loose?.seen = true
    }

    /** A fresh kit that has to be committed first: it replaces the account's kit when the commit lands. */
    fun make(account: FakeAccount, reason: KitReason, inEntry: Boolean, then: () -> Unit) {
        val kit = FakeKitState(account, reason, KitStep.MAKING, inEntry, then)
        app.session?.kit = kit
        commit(kit)
    }

    private fun commit(kit: FakeKitState) {
        when {
            app.script.kitCommitFails -> {
                app.script.kitCommitFails = false
                kit.step = KitStep.NOT_MADE
            }
            app.script.holdKitCommit -> Unit
            else -> {
                kit.account.kitSerial++
                kit.account.kitSaved = false
                kit.step = KitStep.REVEAL
                // As the engine: the server replaced the kit, so one shown here before and never confirmed is void.
                kit.replacesShown = kit.account.kitShownUnconfirmed
                kit.account.kitShownUnconfirmed = true
            }
        }
        put(kit)
    }

    /** The held commit of a fresh kit lands. */
    fun finishCommit() {
        val kit = app.session?.kit ?: return
        if (kit.step != KitStep.MAKING) return
        app.script.holdKitCommit = false
        commit(kit)
    }

    private fun put(kit: FakeKitState) {
        if (kit.inEntry) {
            val screen = app.kitScreen(kit)
            // The same entry screen while the kit's screen did not change.
            if ((app.entryScreen as? EntryScreen.Kit)?.kit !== screen) app.entryScreen = EntryScreen.Kit(kit.flow, screen)
        }
        app.publish()
    }

    /** The kit whose screen is [screen], if that screen is the one on show. */
    private fun shown(screen: KitScreen): FakeKitState? {
        val kit = loose ?: app.session?.kit ?: return null
        val current = if (kit.inEntry) (app.entryScreen as? EntryScreen.Kit)?.kit else app.snapshot.account?.kit
        return kit.takeIf { current === screen }
    }

    override fun kitDocument(screen: KitScreen): KitDocument? {
        val kit = shown(screen) ?: return null
        if (kit.step != KitStep.REVEAL) return null
        val account = kit.account
        return KitDocument(
            email = account.email,
            instance = app.label(account.server),
            madeAtMs = app.nowMs,
            groups = FakeText.kitGroups(account, account.kitSerial),
            qrPayload = "andvari-kit:2:${FakeText.originToken(account.server.origin)}:c${account.kitSerial}:${account.userId}:shown",
            accountId = account.accountId,
        )
    }

    override fun proceedToConfirm(screen: KitScreen) {
        val kit = shown(screen) ?: return
        if (kit.step != KitStep.REVEAL) return
        kit.step = KitStep.CONFIRM
        kit.groups = app.script.kitGroupsAsked
        put(kit)
    }

    override fun showKitAgain(screen: KitScreen) {
        val kit = shown(screen) ?: return
        if (kit.step != KitStep.CONFIRM) return
        kit.step = KitStep.REVEAL
        put(kit)
    }

    override suspend fun confirmKit(screen: KitScreen, typedGroups: List<String>): KitConfirmResult {
        if (shown(screen)?.step != KitStep.CONFIRM) return KitConfirmResult.STALE
        app.pause()
        app.injected<KitConfirmResult>()?.let { return it }
        val kit = shown(screen) ?: return KitConfirmResult.STALE
        val account = kit.account
        if (app.script.kitReplacedElsewhere) {
            // `409 recovery_piece_stale`: the kit on screen is void. A fresh one needs the master password
            // (`PUT /recovery/self-setup`), so the screen waits for it on NOT_MADE.
            app.script.kitReplacedElsewhere = false
            account.kitSerial++
            kit.reason = KitReason.REPLACED_ELSEWHERE
            kit.step = KitStep.NOT_MADE
            kit.tries = 0
            put(kit)
            return KitConfirmResult.REPLACED
        }
        val groups = FakeText.kitGroups(account, account.kitSerial)
        val right = typedGroups.size == kit.groups.size && kit.groups.indices.all { typedGroups[it] == groups[kit.groups[it] - 1] }
        if (right && kit === loose) {
            // Checked here only: no session can tell the server, which keeps the account's kit unconfirmed.
            loose = null
            kit.then()
            app.publish()
            return KitConfirmResult.DONE
        }
        if (!right) {
            kit.tries++
            if (kit.tries >= 3) {
                // After three wrong entries the kit is shown again (§10).
                kit.tries = 0
                kit.step = KitStep.REVEAL
            }
            put(kit)
            return KitConfirmResult.MISMATCH
        }
        account.kitSaved = true
        account.kitShownUnconfirmed = false
        app.session?.kit = null
        kit.then()
        app.publish()
        return KitConfirmResult.DONE
    }

    override suspend fun retryKit(screen: KitScreen, password: String): KitConfirmResult {
        if (shown(screen)?.step != KitStep.NOT_MADE) return KitConfirmResult.STALE
        app.pause()
        app.injected<KitConfirmResult>()?.let { return it }
        val kit = shown(screen) ?: return KitConfirmResult.STALE
        app.reach(kit.account.server)?.let { return troubled(it) }
        if (password != kit.account.password) return KitConfirmResult.WRONG_PASSWORD
        app.script.proofRefusal(KitConfirmResult.KEYS_NOT_KNOWN_HERE, KitConfirmResult.PROOF_REFUSED)?.let { return it }
        kit.step = KitStep.MAKING
        commit(kit)
        return if (kit.step == KitStep.NOT_MADE) KitConfirmResult.UNREACHABLE else KitConfirmResult.DONE
    }
}

/** Contacts and links of the signed-in account, in the fake. */
internal class FakePeople(private val app: FakeAppApi) : ContactsApi, LinksApi {
    // ---- contacts ----

    override suspend fun openContacts(): PlainResult = app.act { s ->
        s.contactsOpen = true
        app.publish()
        PlainResult.DONE
    }

    override fun closeContacts() {
        app.session?.contactsOpen = false
        app.publish()
    }

    private fun notUsed(s: FakeSession): HashSet<String> = app.notUsedContacts.getOrPut(s.account.userId) { HashSet() }

    override suspend fun removeContact(contact: ContactRow): PlainResult = app.act { s ->
        val found = s.account.contacts.firstOrNull { it.userId == contact.userId } ?: return PlainResult.STALE
        s.account.contacts -= found
        s.currentContacts -= found.userId
        notUsed(s) -= found.userId
        if (s.comparing == found.userId) s.comparing = null
        // Vaults already shared are not touched; the member is simply no longer someone this account vouches for.
        s.account.vaults.forEach { v -> v.members.filter { it.contact === found }.forEach { it.contact = null } }
        app.publish()
        PlainResult.DONE
    }

    override suspend fun useOnThisDevice(prompt: AccountPrompt.NewPerson): PlainResult = app.act { s ->
        if (app.currentPrompts().none { it === prompt }) return PlainResult.STALE
        s.currentContacts += prompt.userId
        app.publish()
        PlainResult.DONE
    }

    override fun dontUseOnThisDevice(prompt: AccountPrompt.NewPerson) {
        val s = app.session ?: return
        if (app.phase != AppPhase.UNLOCKED || app.currentPrompts().none { it === prompt }) return
        // This device's own record: the contact stays in the account, and this prompt does not come back for it.
        notUsed(s) += prompt.userId
        app.publish()
    }

    override suspend fun confirmOnThisDevice(contact: ContactRow): PlainResult = app.act { s ->
        val found = s.account.contacts.firstOrNull { it.userId == contact.userId } ?: return PlainResult.STALE
        // The person's own confirmation on this device (§6.9 (c)), whatever they answered about this contact before.
        s.currentContacts += found.userId
        notUsed(s) -= found.userId
        app.publish()
        PlainResult.DONE
    }

    override suspend fun usePeople(prompt: AccountPrompt.PeopleList, userIds: List<String>): PlainResult = app.act { s ->
        if (app.currentPrompts().none { it === prompt }) return PlainResult.STALE
        val listed = prompt.people.map { it.userId }.toSet()
        val ticked = userIds.filter { it in listed }.toSet()
        s.currentContacts += ticked
        // The unticked stay in the account, not used here, and no prompt asks about them again: the list was the question.
        notUsed(s) += listed - ticked
        s.peopleListDue = false
        app.peoplePutOff -= s.account.userId
        app.publish()
        PlainResult.DONE
    }

    override fun peopleLater(prompt: AccountPrompt.PeopleList) {
        val s = app.session ?: return
        if (app.currentPrompts().none { it === prompt }) return
        // Put away, not for an unlock but until it matters: someone on it shares a vault, or the person asks for it.
        app.peoplePutOff += s.account.userId
        app.publish()
    }

    override fun reviewPeople(screen: ContactsScreen) {
        val s = app.session ?: return
        if (app.snapshot.account?.contacts !== screen || !screen.peopleNotReviewed) return
        app.peoplePutOff -= s.account.userId
        app.publish()
    }

    override suspend fun openCompare(contact: ContactRow): PlainResult = app.act { s ->
        val c = s.account.contacts.firstOrNull { it.userId == contact.userId } ?: return PlainResult.STALE
        // As the engine: the answerer's opening of the comparison fetches the creator's reveal, once it was posted.
        if (c.revealWaiting && c.revealPosted) {
            c.revealWaiting = false
            c.codesReady = true
        }
        s.comparing = contact.userId
        app.publish()
        PlainResult.DONE
    }

    override suspend fun openCompareForNewKey(prompt: AccountPrompt.KeyChanged): PlainResult = app.act { s ->
        if (app.currentPrompts().none { it === prompt }) return PlainResult.STALE
        s.comparing = prompt.userId
        app.publish()
        PlainResult.DONE
    }

    override fun closeCompare() {
        app.session?.comparing = null
        app.publish()
    }

    override suspend fun submitComparison(screen: CompareScreen.Ready, digits: String): ComparisonResult = app.act { s ->
        if (app.snapshot.account?.comparing !== screen) return ComparisonResult.STALE
        val contact = s.account.contacts.firstOrNull { it.userId == screen.userId } ?: return ComparisonResult.STALE
        if (contact.linkFailed) {
            app.publish()
            return ComparisonResult.LINK_FAILED
        }
        // §6.11: compared as text. Every ASCII space goes, and what is left must be exactly six ASCII digits, equal to
        // the OTHER side's code. Nothing else is normalised, and a wrong entry is no verdict: the screen stays as it is.
        val typed = digits.filter { it != ' ' }
        if (typed.length != 6 || typed.any { it !in '0'..'9' } || typed != contact.theirCode) return ComparisonResult.MISMATCH
        if (app.script.comparisonNotSaved) {
            // The digits were right, but the account could not be written: nothing is compared yet, and typing again retries.
            app.script.comparisonNotSaved = false
            return ComparisonResult.NOT_SAVED
        }
        contact.compared = true
        contact.keyChangeWaiting = false
        s.currentContacts += contact.userId
        notUsed(s) -= contact.userId
        // The vaults attached to the link go out now (§6.10), where this account still owns them. One whose deletion by a
        // move is signed and waiting is not shared: it stays waiting, as the engine keeps it.
        for (share in contact.waitingShares.toList()) {
            val vault = s.account.vaults.firstOrNull { it.vaultId == share.vaultId } ?: continue
            if (vault.moveDeleteWaiting) continue
            if (vault.role == RoleInVault.OWNER && vault.log == VaultLogState.VERIFIED && vault.purgeAtMs == 0L) {
                app.shared.add(vault, contact, share.role)
            }
        }
        contact.waitingShares.removeAll { share -> s.account.vaults.none { it.vaultId == share.vaultId && it.moveDeleteWaiting } }
        app.publish()
        ComparisonResult.DONE
    }

    // ---- links ----

    override suspend fun openLinks(): PlainResult = app.act { s ->
        s.linksOpen = true
        app.publish()
        PlainResult.DONE
    }

    override fun closeLinks() {
        app.session?.linksOpen = false
        app.publish()
    }

    override suspend fun createConnectLink(shares: List<ShareChoice>, minutes: Int): LinkCreateResult = app.act { s ->
        if (minutes !in LinkLifetimes.SHORTEST_MINUTES..LinkLifetimes.CONNECT_LONGEST_MINUTES) return LinkCreateResult.BAD_LIFETIME
        // A link with shares is the person choosing each vault for whoever answers: only vaults this account owns.
        val owned = shares.all { c -> s.account.vaults.any { it.vaultId == c.vaultId && it.role == RoleInVault.OWNER && it.log == VaultLogState.VERIFIED } }
        if (!owned) return LinkCreateResult.NOT_ALLOWED
        make(s, OwnLinkKind.CONNECT, shares, minutes)
    }

    override suspend fun createInvitation(minutes: Int): LinkCreateResult = app.act { s ->
        if (minutes !in LinkLifetimes.SHORTEST_MINUTES..LinkLifetimes.INVITATION_LONGEST_MINUTES) return LinkCreateResult.BAD_LIFETIME
        val allowed = s.account.isOperator || (s.server.kind == ServerKind.PRIVATE_SERVER && s.server.membersMayInvite)
        if (!allowed) return LinkCreateResult.NOT_ALLOWED
        make(s, OwnLinkKind.INVITATION, emptyList(), minutes)
    }

    private fun make(s: FakeSession, kind: OwnLinkKind, shares: List<ShareChoice>, minutes: Int): LinkCreateResult {
        if (s.account.nameHere == null) return LinkCreateResult.NAME_NEEDED
        if (s.account.contacts.size >= 1000) return LinkCreateResult.TOO_MANY_CONTACTS
        if (s.ownLinks.count { it.open && it.expiresAtMs > app.nowMs } >= 20) return LinkCreateResult.TOO_MANY_OPEN_LINKS
        val n = app.serial++
        // The record is this device's alone: the link's secret is in no snapshot and on no other device (T-B6).
        val payload = "${FakeText.JOIN_BASE}/l#v2.${FakeText.originToken(s.server.origin)}.s$n.f$n"
        s.ownLinks += FakeOwnLink("link-$n", kind, shares.map { FakeShare(it.vaultId, it.role) }, payload, app.nowMs + minutes * FakeScript.MINUTE)
        s.linksOpen = true
        app.publish()
        return LinkCreateResult.DONE
    }

    private fun own(link: OwnLinkRow): FakeOwnLink? =
        app.session?.ownLinks?.firstOrNull { it.linkId == link.linkId && it.open && it.expiresAtMs > app.nowMs }

    override fun linkToShare(link: OwnLinkRow): String? = if (app.phase == AppPhase.UNLOCKED) own(link)?.payload else null

    override fun linkTimeLeftMs(link: OwnLinkRow): Long = own(link)?.let { it.expiresAtMs - app.nowMs } ?: 0L

    override suspend fun revokeLink(link: OwnLinkRow): PlainResult = app.act {
        val found = own(link) ?: return PlainResult.STALE
        found.open = false
        app.publish()
        PlainResult.DONE
    }

    override suspend fun releaseShare(share: PendingShareRow): VaultActionResult = app.act { s ->
        val contact = s.account.contacts.firstOrNull { it.userId == share.userId } ?: return VaultActionResult.STALE
        val waiting = contact.waitingShares.firstOrNull { it.vaultId == share.vaultId } ?: return VaultActionResult.STALE
        val vault = s.account.vaults.firstOrNull { it.vaultId == share.vaultId } ?: return VaultActionResult.STALE
        app.shared.refusal(vault, owner = true)?.let { return it }
        if (!contact.compared) {
            // Never by itself: the person confirms this one vault for this one person behind the warning (T-B2).
            s.warning = FakeWarning(vault, contact, waiting.role, fromLink = true)
            app.publish()
            return VaultActionResult.NEEDS_UNCOMPARED_WARNING
        }
        app.shared.add(vault, contact, waiting.role)
        contact.waitingShares -= waiting
        app.publish()
        VaultActionResult.DONE
    }

    override suspend fun openInvite(payload: String, source: PayloadSource): InviteResult = app.act { s -> open(s, payload) }

    suspend fun openAppLink(url: String): InviteResult = app.act { s -> open(s, url) }

    /** Pin [opened]'s server through [root]; a pin made where none existed is the opened invite's own until something comes of it. */
    private fun pinFor(opened: FakeOpened, root: PinRoot) {
        val server = opened.invite.server
        val had = app.pins.containsKey(server.origin)
        app.pin(server, root, null)
        if (!had) opened.madePin = app.pins[server.origin]?.firstOrNull { it.root == root && it.account == null }
    }

    private fun dropMadePin(opened: FakeOpened) {
        val made = opened.madePin ?: return
        opened.madePin = null
        val list = app.pins[made.origin] ?: return
        list.remove(made)
        if (list.isEmpty()) app.pins.remove(made.origin)
    }

    private fun put(s: FakeSession, opened: FakeOpened?) {
        s.opened?.takeIf { it !== opened }?.let(::dropMadePin)
        s.opened = opened
        app.publish()
    }

    /**
     * §6.8, recipient side, signed in. Only an invite is acted on, and nothing is sent before the person confirms.
     * The link's server comes first (step 5, each root as §4.4 has it), and only then §6.7's dead end.
     */
    private fun open(s: FakeSession, payload: String): InviteResult {
        if (s.notUsed != null) {
            s.notUsed = null
            app.publish()
        }
        val (shape, key) = FakeText.shape(payload)
        when (shape) {
            PayloadShape.DEVICE_LINK -> return InviteResult.DEVICE_LINK_NOT_HERE
            PayloadShape.KIT -> return InviteResult.KIT_NOT_AN_INVITE
            PayloadShape.NOTHING -> return InviteResult.NOT_AN_INVITE
            PayloadShape.INVITE -> Unit
        }
        if (s.ownLinks.any { it.payload.substringAfter('#') == key }) return InviteResult.OWN_LINK
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
        if (found.kind == FakeInviteKind.SETUP && !app.takesSetupLinks) return InviteResult.SETUP_NEEDS_COMPUTER
        if (server === s.server) {
            if (found.kind != FakeInviteKind.CONNECT) {
                // The engine's answer: a setup link for a server that has its card; the approved sentence (entry 7) otherwise.
                val key = when (found.kind) {
                    FakeInviteKind.REGISTER -> CopyKey.ALREADY_SIGNED_IN_THERE
                    FakeInviteKind.ENROL -> CopyKey.ALREADY_SIGNED_IN_THERE_ENROL
                    else -> return InviteResult.SETUP_ALREADY_DONE
                }
                val label = app.label(server)
                s.notUsed = CopyLine.of(key, label.name, label.origin)
                app.publish()
                return InviteResult.NOT_USABLE_SIGNED_IN
            }
            put(s, FakeOpened(if (found.newKeyOf != null) FakeOpenedKind.KEY_CHANGED else FakeOpenedKind.CONNECT, found))
            return InviteResult.DONE
        }
        val opened = FakeOpened(FakeOpenedKind.OTHER_INSTANCE, found)
        if (found.kind != FakeInviteKind.SETUP) {
            val pinned = app.pins.containsKey(server.origin)
            if (pinned && server.identityChanged) app.forked += server.origin
            if (app.blockOn(server) != null) {
                // The other server is blocked on this device: its card says why, and it can be forgotten from here.
                opened.kind = FakeOpenedKind.SERVER_CHANGED
                put(s, opened)
                return InviteResult.IDENTITY_CONFLICT
            }
            if (!server.hasCard) return InviteResult.DOES_NOT_CHECK_OUT
            if (!pinned) {
                if (server.servesAnotherServersCard) return InviteResult.OTHER_ADDRESS
                if (server === app.baked && server.identityChanged) return InviteResult.DOES_NOT_CHECK_OUT
            } else {
                when (app.cardOf(server)) {
                    FakeCard.MOVED, FakeCard.KIND_CHANGED, FakeCard.UPDATE_MOVED, FakeCard.UPDATE_CHANGED, FakeCard.WITHHELD -> {
                        opened.kind = FakeOpenedKind.SERVER_CHANGED
                        put(s, opened)
                        return InviteResult.SERVER_CHANGED
                    }
                    FakeCard.NOT_VERIFIED -> return InviteResult.DOES_NOT_CHECK_OUT
                    else -> Unit
                }
            }
            when {
                // At the baked origin the baked root comes first, whatever the link: no gate, and a password pin.
                server === app.baked -> pinFor(opened, PinRoot.BAKED)
                found.kind != FakeInviteKind.ENROL -> pinFor(opened, PinRoot.LINK_OFFER)
                // An enrol link is its host's own claim: with no pin for the server, the Trust Gate before anything else.
                !pinned -> opened.kind = FakeOpenedKind.TRUST_GATE
            }
        }
        // §6.7's dead end: an app talks to one instance at a time, and switching is explicit.
        put(s, opened)
        return InviteResult.DONE
    }

    override fun acknowledgeKeyChange(prompt: OpenedInvite.KeyChanged) {
        val s = app.session ?: return
        if (app.snapshot.account?.opened !== prompt) return
        s.opened?.kind = FakeOpenedKind.CONNECT
        app.publish()
    }

    override suspend fun connect(prompt: OpenedInvite.Connect): ConnectResult = app.act { s ->
        val opened = s.opened ?: return ConnectResult.STALE
        if (app.snapshot.account?.opened !== prompt) return ConnectResult.STALE
        // As the engine: an account with no name kept on this device answers nothing, and the question stays.
        if (s.account.nameHere == null) return ConnectResult.NAME_NEEDED
        val found = opened.invite
        if (found.state == FakeInviteState.USED) return ConnectResult.ALREADY_USED
        if (found.state != FakeInviteState.OPEN || found.expiresAtMs <= app.nowMs) return ConnectResult.EXPIRED
        val known = found.newKeyOf
        if (known == null && s.account.contacts.size >= 1000) return ConnectResult.TOO_MANY_CONTACTS
        found.state = FakeInviteState.USED
        val contact = if (known != null) {
            // The old key stays pinned; only a matched comparison accepts the new one (§6.8 step 6).
            known.keyChangeWaiting = true
            known.code = FakeText.digits6("code:${found.payload}")
            known.codesReady = false
            known
        } else {
            s.account.addContact(found.from.orEmpty(), compared = false).also {
                it.madeOnDeviceId = app.deviceId
                it.connectedAtMs = app.nowMs
                it.code = FakeText.digits6("code:${found.payload}")
                s.currentContacts += it.userId
            }
        }
        // The answer is posted: the invite's screen now names the contact it made, so the codes can follow at once.
        opened.kind = FakeOpenedKind.CONNECTED
        opened.contact = contact
        opened.madePin = null
        app.publish()
        ConnectResult.DONE
    }

    override suspend fun confirmOpenedGate(prompt: OpenedInvite.TrustGate): ServerResult = app.act { s ->
        val opened = s.opened ?: return ServerResult.STALE
        if (app.snapshot.account?.opened !== prompt || opened.kind != FakeOpenedKind.TRUST_GATE) return ServerResult.STALE
        app.reach(opened.invite.server)?.let { return troubled(it) }
        // An enrol pin: enough to create an account there, never to sign in to one.
        pinFor(opened, PinRoot.ENROL)
        opened.kind = FakeOpenedKind.OTHER_INSTANCE
        app.publish()
        ServerResult.DONE
    }

    override fun dismissOpened() {
        val s = app.session ?: return
        if (s.opened == null && s.notUsed == null) return
        s.notUsed = null
        put(s, null)
    }

    /** The server an opened invite named was followed, accepted or forgotten ([io.silencelen.andvari.core.app.InstanceApi]): the invite is opened again by the person. */
    fun openedServerSettled(server: FakeServer) {
        val s = app.session ?: return
        val opened = s.opened ?: return
        if (opened.kind != FakeOpenedKind.SERVER_CHANGED || opened.invite.server !== server) return
        if (app.pinnedOrBlocked(server.origin) && app.cardOf(server) != FakeCard.OK) return
        s.opened = null
    }

    override suspend fun switchInstance(prompt: OpenedInvite.OtherInstance): ServerResult = switchTo(prompt, null)

    override suspend fun switchInstanceConfirmed(prompt: OpenedInvite.OtherInstance, check: io.silencelen.andvari.core.app.SignOutCheck): ServerResult =
        switchTo(prompt, check)

    /** As the engine: the switch is a sign-out, so unsent changes need the person's second confirmation of the check on show. */
    private fun unsentRefused(confirmed: io.silencelen.andvari.core.app.SignOutCheck?): Boolean {
        val now = app.signOutCheck() ?: return true
        return now.needsConfirmation && now !== confirmed
    }

    private suspend fun switchTo(prompt: OpenedInvite.OtherInstance, confirmed: io.silencelen.andvari.core.app.SignOutCheck?): ServerResult = app.act { s ->
        val opened = s.opened ?: return ServerResult.STALE
        if (app.snapshot.account?.opened !== prompt || opened.kind != FakeOpenedKind.OTHER_INSTANCE) return ServerResult.STALE
        if (unsentRefused(confirmed)) return ServerResult.UNSENT_NOT_CONFIRMED
        app.reach(opened.invite.server)?.let { return troubled(it) }
        if (unsentRefused(confirmed)) return ServerResult.UNSENT_NOT_CONFIRMED
        // Signing out here leaves this instance's data in its own namespace; the invite goes on signed out, and the
        // pin its opening made goes with it.
        val payload = "${FakeText.JOIN_BASE}/l#${opened.invite.payload}"
        opened.madePin = null
        app.endSession(null)
        when (app.entryFlow.continueWith(payload)) {
            InviteResult.DONE -> ServerResult.DONE
            InviteResult.UNREACHABLE -> ServerResult.UNREACHABLE
            InviteResult.IDENTITY_CONFLICT -> ServerResult.IDENTITY_CONFLICT
            InviteResult.SERVER_CHANGED -> ServerResult.SERVER_CHANGED
            InviteResult.OTHER_ADDRESS -> ServerResult.OTHER_ADDRESS
            else -> ServerResult.FAILED
        }
    }

    override suspend fun retryConnection(prompt: AccountPrompt.ConnectionNotMade): ConnectResult = app.act { s ->
        val waiting = s.connectionNotMade ?: return ConnectResult.STALE
        if (app.currentPrompts().none { it === prompt } || !prompt.canRetry) return ConnectResult.STALE
        val found = waiting.invite
        val result = when {
            s.account.nameHere == null -> ConnectResult.NAME_NEEDED
            found.state == FakeInviteState.USED -> ConnectResult.ALREADY_USED
            found.state != FakeInviteState.OPEN || found.expiresAtMs <= app.nowMs -> ConnectResult.EXPIRED
            else -> ConnectResult.DONE
        }
        if (result == ConnectResult.DONE) {
            found.state = FakeInviteState.USED
            app.entryFlow.connectWith(s, found)
            s.connectionNotMade = null
        } else {
            // The link is spent meanwhile: the prompt stays to say so, and can only be put away.
            waiting.why = result
        }
        app.publish()
        result
    }

    override fun ownName(): String? = app.session?.takeIf { app.snapshot.account != null }?.account?.nameHere

    override fun setOwnName(name: String): io.silencelen.andvari.core.app.OwnNameResult {
        val s = app.session?.takeIf { app.snapshot.account != null } ?: return io.silencelen.andvari.core.app.OwnNameResult.STALE
        if (io.silencelen.andvari.core.trust.TrustGrammar.encodeName(name) == null) return io.silencelen.andvari.core.app.OwnNameResult.NOT_A_NAME
        s.account.nameHere = name
        app.publish()
        return io.silencelen.andvari.core.app.OwnNameResult.DONE
    }

    override fun dropConnection(prompt: AccountPrompt.ConnectionNotMade) {
        val s = app.session ?: return
        if (app.currentPrompts().none { it === prompt }) return
        s.connectionNotMade = null
        app.publish()
    }

    // ---- the other party, and the clock ----

    /** Someone answers a link this device made (§6.8, creator side). An answer to a dropped link is ignored (T-R3). */
    fun answered(linkId: String, name: String): FakeContact? {
        val s = app.session ?: return null
        val link = s.ownLinks.firstOrNull { it.linkId == linkId && it.open && it.expiresAtMs > app.nowMs } ?: return null
        link.open = false
        val contact = s.account.addContact(name, compared = false)
        contact.madeOnDeviceId = app.deviceId
        contact.connectedAtMs = app.nowMs
        // This device posts the reveal once it has processed the answer, so both sides can compare at once.
        contact.codesReady = true
        contact.code = FakeText.digits6("code:${link.payload}")
        contact.waitingShares += link.shares
        s.currentContacts += contact.userId
        // What ties the link to its contact, for whoever is showing the link's QR (§6.7 "In person").
        s.answered.add(0, FakeAnswered(link.linkId, contact, keyChanged = false))
        app.publish()
        return contact
    }

    /**
     * [contact], a contact already, answers a link this device made under another key than the pinned one (§6.8 step 6,
     * creator side): nothing is replaced; the answered row says the key changed, and [AccountPrompt.KeyChanged] stays
     * until a matched comparison accepts the new key.
     */
    fun answeredUnderNewKey(linkId: String, contact: FakeContact): Boolean {
        val s = app.session ?: return false
        val link = s.ownLinks.firstOrNull { it.linkId == linkId && it.open && it.expiresAtMs > app.nowMs } ?: return false
        if (contact !in s.account.contacts) return false
        link.open = false
        contact.keyChangeWaiting = true
        contact.codesReady = true
        contact.code = FakeText.digits6("code:${link.payload}")
        s.answered.add(0, FakeAnswered(link.linkId, contact, keyChanged = true))
        app.publish()
        return true
    }

    /** A link's record is dropped at its expiry (T-R3). */
    fun tick(s: FakeSession) {
        s.ownLinks.filter { it.expiresAtMs <= app.nowMs }.forEach { it.open = false }
        app.ownPart.tick(s)
    }
}
