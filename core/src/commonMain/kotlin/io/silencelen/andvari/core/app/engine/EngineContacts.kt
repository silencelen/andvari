package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.CompareScreen
import io.silencelen.andvari.core.app.ComparisonResult
import io.silencelen.andvari.core.app.ContactRow
import io.silencelen.andvari.core.app.ContactsApi
import io.silencelen.andvari.core.app.ContactsScreen
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.client.link.CompareResult
import io.silencelen.andvari.core.client.link.CompareState
import io.silencelen.andvari.core.client.link.ContactEntry
import io.silencelen.andvari.core.client.link.ContactPrompt
import io.silencelen.andvari.core.client.state.ContactRecord

/**
 * The account's contacts (§6.9) and the comparison of codes (§6.11), over the open vault's own
 * [io.silencelen.andvari.core.client.link.AccountContactBook] and the link engine that answered or processed the link
 * ([EngineAppApi.entryLinks], which sees the open account). Nothing here makes a contact: every one comes from a link.
 *
 * What only this device decides is kept here: the screen on show, the people the person chose not to use here (in
 * device state, per account, so the prompt does not come back at any unlock) and a list put off ("Later", until the
 * next time it matters).
 */
internal class EngineContacts(private val app: EngineAppApi) : ContactsApi {
    private var open = false
    private var comparing: String? = null

    /** Accounts whose one-tap list was put off ("Later"), until the person asks for it again. */
    private val putOff = HashSet<String>()

    /** The session ended, locked or moved: the screens close. What this device decided stays. */
    fun ended() {
        open = false
        comparing = null
        stateDue = false
        stateReadOn = null
        stateSyncSeen = false
    }

    // ---- the account's state, read once per opening ----

    /**
     * This opening's read of the account's state has not answered yet. What the account's other devices decided (its
     * contacts and their compared state, §8.5's one-tap list, a shared vault's sender to confirm, the `accepted` records
     * of §3.6) lives there, and nothing else reads it before the contacts screen opens.
     */
    private var stateDue = false

    /** The open vault whose read is running; a vault composed again reads again in its own scope. */
    private var stateReadOn: EngineVault? = null
    private var stateSyncSeen = false

    /**
     * The vault opened (a sign-in or an unlock): the account's state is read once, in the vault's scope and in the
     * background, so nothing waits for it. The server's copy is merged into this device's, never adopted
     * ([io.silencelen.andvari.core.client.state.StoredAccountState.read]): a server can withhold or roll back, and
     * nothing this device holds is lost. A read that gets no usable answer changes nothing and is tried again after the
     * next completed sync ([contentChanged]); a lock stops it (nothing is opened or kept under a wiped key).
     */
    fun opened() {
        stateDue = true
        readState()
    }

    /** The open vault was composed again: a read its old scope cancelled is made again. */
    fun recomposed() {
        if (stateDue) readState()
    }

    /** The content published a new state: after a completed sync, a read still due is tried again. */
    fun contentChanged() {
        val v = vault() ?: return
        if (v.content.state.syncing) {
            stateSyncSeen = true
            return
        }
        if (!stateSyncSeen) return
        stateSyncSeen = false
        if (stateDue) readState()
    }

    private fun readState() {
        val v = vault() ?: return
        if (!stateDue || stateReadOn === v || v.signedOutByServer || !app.mayDial(v.origin)) return
        stateReadOn = v
        v.launch {
            try {
                val before = v.store.local()
                val r = v.store.read()
                if (v.closed || r !is io.silencelen.andvari.core.client.state.AccountStateRead.Ok) return@launch
                stateDue = false
                if (r.document != before) app.accountStateMerged(v)
            } finally {
                if (stateReadOn === v) stateReadOn = null
            }
        }
        // A vault that closed before the read could start: nothing runs.
        if (v.closed && stateReadOn === v) stateReadOn = null
    }

    private fun vault(): EngineVault? = app.vault?.takeIf { !it.closed && app.phase == AppPhase.UNLOCKED }

    // ---- what this device decided ----

    private fun notUsedKey(v: EngineVault) = "$NOT_USED_KEY${v.origin}|${v.userId}"

    private fun notUsed(v: EngineVault): Set<String> =
        app.engine.state.get(notUsedKey(v))?.split(',')?.filter { it.isNotEmpty() }?.toSet().orEmpty()

    private fun setNotUsed(v: EngineVault, ids: Set<String>) {
        app.engine.state.set(notUsedKey(v), ids.sorted().joinToString(",").takeIf { it.isNotEmpty() })
    }

    // ---- what the snapshot shows ----

    private val rows = HashMap<String, ContactRow>()
    private var screenShown: ContactsScreen? = null
    private var compareShown: CompareScreen? = null
    private val newPeople = HashMap<String, AccountPrompt.NewPerson>()
    private var listShown: AccountPrompt.PeopleList? = null

    private fun row(v: EngineVault, e: ContactEntry): ContactRow {
        val r = e.record
        val state = app.entryLinks.compareState(r.userId)
        val ready = state is CompareState.Ready
        // The answerer's record waits for the creator's reveal, which only opening the comparison fetches: the comparison is
        // offered then too, or the side that answered a link could never compare (its screen shows Waiting, no code, until
        // the reveal arrived and opened the commitment). A creator's record always holds its code.
        val canCompare = ready || state is CompareState.Waiting
        val current = e.current != null
        val before = rows[r.userId]
        // The account's record names the device that made it by id only; the account's device list names it.
        val madeOn = app.devicesFlow.nameOf(r.madeOn)
        if (before != null && before.label == e.labelText && before.connectedAtMs == r.verifiedAt && before.compared == r.compared &&
            before.currentHere == current && before.codesReady == ready && before.canCompare == canCompare && before.madeOn == madeOn
        ) return before
        return ContactRow(r.userId, e.labelText, r.verifiedAt, r.compared, current, madeOn, ready, canCompare).also { rows[r.userId] = it }
    }

    /** [userId]'s contact row as the contacts screen shows it (the same object while nothing in it changed); null when there is none. */
    fun rowFor(userId: String): ContactRow? {
        val v = vault() ?: return null
        return v.contacts.list().firstOrNull { it.record.userId == userId }?.let { row(v, it) }
    }

    private fun sameList(a: List<ContactRow>, b: List<ContactRow>) = a.size == b.size && a.indices.all { a[it] === b[it] }

    /** The contacts screen while it is open: the account's contacts by label. */
    fun screen(): ContactsScreen? {
        val v = vault() ?: return null
        if (!open) return null
        val list = v.contacts.list().map { row(v, it) }.sortedBy { it.label.lowercase() }
        val notReviewed = v.contacts.oneTapListDue() && v.userId in putOff
        val shown = screenShown
        if (shown != null && shown.peopleNotReviewed == notReviewed && sameList(shown.contacts, list)) return shown
        return ContactsScreen(list, notReviewed).also { screenShown = it }
    }

    /** The comparison on show, from what the link engine holds for that contact on this device. */
    fun compare(): CompareScreen? {
        val v = vault() ?: return null
        val id = comparing ?: return null
        val record = v.store.local().contacts[id]
        val entry = record?.let { r -> v.contacts.list().firstOrNull { it.record.userId == r.userId } }
        val label = entry?.labelText.orEmpty()
        val next: CompareScreen = when (val st = app.entryLinks.compareState(id)) {
            is CompareState.Ready -> CompareScreen.Ready(id, label, st.code, st.replacesKey)
            is CompareState.Failed -> CompareScreen.LinkFailed(id, label)
            is CompareState.Matched -> CompareScreen.Matched(id, label)
            is CompareState.Waiting -> CompareScreen.Waiting(id, label)
            // This device holds no link record for them (the link was another device's): no code can exist here.
            null -> if (record?.compared == true) CompareScreen.Matched(id, label) else CompareScreen.Waiting(id, label)
        }
        val shown = compareShown
        if (shown != null && shown::class == next::class && shown.userId == next.userId && shown.label == next.label &&
            (shown !is CompareScreen.Ready || (next is CompareScreen.Ready && shown.code == next.code && shown.replacesKey == next.replacesKey))
        ) return shown
        return next.also { compareShown = it }
    }

    /**
     * The contact prompts, in order: a "new person" for each contact made elsewhere and not current here (unless the
     * person said not to use them here), or, on a device that signed in with only the password, the one-tap list once.
     */
    fun prompts(): List<AccountPrompt> {
        val v = vault() ?: return emptyList()
        val book = v.contacts
        if (book.oneTapListDue()) {
            if (v.userId in putOff) return emptyList()
            val people = book.prompts().mapNotNull { p -> book.list().firstOrNull { it.record.userId == p.record.userId }?.let { row(v, it) } }
            if (people.isEmpty()) return emptyList()
            // §8.5: the part in braces appears only for an account whose recovery record says `operator`.
            // Unknown (the posture read has not answered this opening) is shown as unknown, never as "not operator".
            val recorded = app.recoveryFlow.operatorRecorded()
            val clause = recorded == true
            val known = recorded != null
            val shown = listShown
            if (shown != null && shown.operatorClause == clause && shown.operatorClauseKnown == known && sameList(shown.people, people)) return listOf(shown)
            return listOf(AccountPrompt.PeopleList(people, operatorClause = clause, operatorClauseKnown = known).also { listShown = it })
        }
        val skip = notUsed(v)
        return book.prompts().filter { it.record.userId !in skip }.map { p ->
            val before = newPeople[p.record.userId]
            val madeOn = app.devicesFlow.nameOf(p.record.madeOn)
            if (before != null && before.label == p.labelText && before.madeOn == madeOn) before
            else AccountPrompt.NewPerson(p.record.userId, p.labelText, madeOn).also { newPeople[p.record.userId] = it }
        }
    }

    // ---- intents ----

    override suspend fun openContacts(): PlainResult {
        val v = vault() ?: return PlainResult.STALE
        open = true
        app.publish()
        // The account's contacts as the server holds them now; a server that does not answer leaves this device's copy.
        // A lock while the account's state is read: nothing more is opened or written under the wiped key.
        if (app.mayDial(v.origin) && app.unlessLocked(false) { app.working { v.store.read() }; true } != true) return PlainResult.STALE
        // A contact made on another device is named by that device's name, from the account's device list.
        if (app.mayDial(v.origin)) app.devicesFlow.readNamesIfNeeded()
        return PlainResult.DONE
    }

    override fun closeContacts() {
        if (!open) return
        open = false
        app.publish()
    }

    private fun recordOf(v: EngineVault, userId: String): ContactRecord? = v.store.local().contacts[userId]

    override suspend fun removeContact(contact: ContactRow): PlainResult {
        val v = vault() ?: return PlainResult.STALE
        if (screen()?.contacts?.none { it === contact } != false) return PlainResult.STALE
        if (!app.mayDial(v.origin)) return PlainResult.FAILED
        val ok = app.unlessLocked(null) { app.working { v.contacts.remove(contact.userId) } } ?: return PlainResult.STALE
        // Not written: the server did not answer or refused; nothing changed on this device.
        if (!ok) return PlainResult.FAILED
        if (comparing == contact.userId) comparing = null
        setNotUsed(v, notUsed(v) - contact.userId)
        app.publish()
        return PlainResult.DONE
    }

    /** Make [userId]'s contact current here, as the account's record holds it now (the person's own confirmation, §6.9 (c)). */
    private suspend fun confirm(v: EngineVault, userId: String): PlainResult {
        val r = recordOf(v, userId) ?: return PlainResult.STALE
        val done = app.unlessLocked(null) { v.contacts.confirmHere(ContactPrompt(r, null, "")) } ?: return PlainResult.STALE
        if (!done) return PlainResult.FAILED
        setNotUsed(v, notUsed(v) - userId)
        app.publish()
        return PlainResult.DONE
    }

    override suspend fun useOnThisDevice(prompt: AccountPrompt.NewPerson): PlainResult {
        val v = vault() ?: return PlainResult.STALE
        if (app.snapshot.account?.prompts?.none { it === prompt } != false) return PlainResult.STALE
        return confirm(v, prompt.userId)
    }

    override fun dontUseOnThisDevice(prompt: AccountPrompt.NewPerson) {
        val v = vault() ?: return
        if (app.snapshot.account?.prompts?.none { it === prompt } != false) return
        setNotUsed(v, notUsed(v) + prompt.userId)
        app.publish()
    }

    override suspend fun confirmOnThisDevice(contact: ContactRow): PlainResult {
        val v = vault() ?: return PlainResult.STALE
        if (screen()?.contacts?.none { it === contact } != false) return PlainResult.STALE
        return confirm(v, contact.userId)
    }

    override suspend fun usePeople(prompt: AccountPrompt.PeopleList, userIds: List<String>): PlainResult {
        val v = vault() ?: return PlainResult.STALE
        if (app.snapshot.account?.prompts?.none { it === prompt } != false) return PlainResult.STALE
        val listed = prompt.people.map { it.userId }.toSet()
        val ticked = userIds.filter { it in listed }.toSet()
        if (app.unlessLocked(false) { v.contacts.confirmOneTap(ticked) } != true) return PlainResult.STALE
        // The unticked stay in the account, not used here; the list was the question, so no prompt asks again.
        setNotUsed(v, notUsed(v) + (listed - ticked))
        putOff -= v.userId
        app.publish()
        return PlainResult.DONE
    }

    override fun peopleLater(prompt: AccountPrompt.PeopleList) {
        val v = vault() ?: return
        if (app.snapshot.account?.prompts?.none { it === prompt } != false) return
        putOff += v.userId
        app.publish()
    }

    override fun reviewPeople(screen: ContactsScreen) {
        val v = vault() ?: return
        if (app.snapshot.account?.contacts !== screen || !screen.peopleNotReviewed) return
        putOff -= v.userId
        app.publish()
    }

    override suspend fun openCompare(contact: ContactRow): PlainResult {
        val v = vault() ?: return PlainResult.STALE
        if (recordOf(v, contact.userId) == null) return PlainResult.STALE
        return openCompareFor(v, contact.userId)
    }

    override suspend fun openCompareForNewKey(prompt: AccountPrompt.KeyChanged): PlainResult {
        val v = vault() ?: return PlainResult.STALE
        if (app.snapshot.account?.prompts?.none { it === prompt } != false) return PlainResult.STALE
        return openCompareFor(v, prompt.userId)
    }

    private suspend fun openCompareFor(v: EngineVault, userId: String): PlainResult {
        comparing = userId
        compareShown = null
        app.publish()
        // The creator's reveal, when this device answered their link and it has not arrived yet (§6.11).
        if (app.mayDial(v.origin) && app.entryLinks.compareState(userId) is CompareState.Waiting) {
            if (app.unlessLocked(false) { app.working { app.entryLinks.refreshReveal(userId) }; true } != true) return PlainResult.STALE
        }
        return PlainResult.DONE
    }

    override fun closeCompare() {
        if (comparing == null) return
        comparing = null
        app.publish()
    }

    override suspend fun submitComparison(screen: CompareScreen.Ready, digits: String): ComparisonResult {
        val v = vault() ?: return ComparisonResult.STALE
        if (app.snapshot.account?.comparing !== screen) return ComparisonResult.STALE
        if (!app.mayDial(v.origin)) return ComparisonResult.FAILED
        val r = app.unlessLocked(null) { app.working { app.entryLinks.typeCode(screen.userId, digits) } }
        app.publish()
        if (r == null) return ComparisonResult.STALE
        return when (r) {
            CompareResult.Matched -> {
                setNotUsed(v, notUsed(v) - screen.userId)
                ComparisonResult.DONE
            }
            CompareResult.Mismatch -> ComparisonResult.MISMATCH
            CompareResult.Failed -> ComparisonResult.LINK_FAILED
            CompareResult.Unsaved -> ComparisonResult.NOT_SAVED
        }
    }

    internal companion object {
        /** The contacts the person chose not to use on this device, per origin and account (device state). */
        const val NOT_USED_KEY = "ovh.notused|"
    }
}
