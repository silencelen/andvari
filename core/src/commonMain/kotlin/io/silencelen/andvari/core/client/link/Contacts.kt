package io.silencelen.andvari.core.client.link

import io.silencelen.andvari.core.client.state.AccountMerge
import io.silencelen.andvari.core.client.state.AccountStateWrite
import io.silencelen.andvari.core.client.state.ContactRecord
import io.silencelen.andvari.core.trust.TrustGrammar

/**
 * When a contact counts on this device (design §6.9): it is CURRENT when (a) this device processed or
 * answered the link, (b) it arrived in a device-link bundle with the same key hash, (c) the person
 * confirmed it here, or (d) the person confirmed the one-tap list on a password-only device (§8.5).
 * Only current contacts make grants adoptable (design §3.6) and labels shown (design §3.9).
 */
enum class Currency(val code: String) { LINK("link"), BUNDLE("bundle"), CONFIRMED("confirmed"), ONE_TAP("one_tap") }

/** One contact as this device sees it (named apart from the app API's `core.app.ContactView`). */
data class ContactEntry(val record: ContactRecord, val current: Currency?, val labelText: String)

/** A contact made elsewhere and not yet current here: "New person from your *device*: *label* — Use on this device?" */
class ContactPrompt internal constructor(val record: ContactRecord, val madeOnName: String?, val labelText: String)

/**
 * The account's contacts (design §6.9), merged from account state, with this device's own
 * `pins.confirmed = {userId, keyHash}` records. No contact is ever made from a typed value, a QR other
 * than a link, an email or a server lookup.
 */
interface ContactBook {
    fun list(): List<ContactEntry>

    /** The contact for [userId] whose key equals [identityPub] and is current here; the only source of a label. */
    fun currentFor(userId: String, identityPub: String): ContactEntry?

    /** Contacts that came from other devices and wait for one tap each. */
    fun prompts(): List<ContactPrompt>

    /** The person confirmed [prompt] on this device. */
    suspend fun confirmHere(prompt: ContactPrompt): Boolean

    /** True on a device that signed in with only the password and has not shown the one-tap list yet (design §8.5). */
    fun oneTapListDue(): Boolean

    /** The person ticked [userIds] on the one-tap list; the rest stay not current. */
    suspend fun confirmOneTap(userIds: Set<String>): Boolean

    /** Remove a contact: writes a tombstone (newest act wins). */
    suspend fun remove(userId: String): Boolean
}

/**
 * [ContactBook] over the account's merged account state ([LinkAccount.store]) and this device's [ContactCurrency].
 *
 * Trust: a contact record in account state may have been written by any holder of the UVK (a hostile web bundle
 * included, T-R6), so a record alone makes nothing current: only this device's own records do, keyed by the hash of
 * the exact key. Every confirmation is re-derived from the account state as it is now ([confirmHere] refuses a
 * prompt whose record changed). [passwordOnly] is true when this device's session came from a password sign-in
 * (design §8.5): the one-tap list is then due once.
 */
class AccountContactBook(
    private val account: LinkAccount,
    private val currency: ContactCurrency,
    private val passwordOnly: Boolean,
    private val clock: () -> Long,
) : ContactBook {
    private fun records(): List<ContactRecord> = account.store.local().contacts.values.sortedBy { it.userId }

    private fun entry(r: ContactRecord) = ContactEntry(r, currency.currency(r.userId, r.identityPub), TrustGrammar.decodeName(r.label) ?: "")

    override fun list(): List<ContactEntry> = records().map(::entry)

    override fun currentFor(userId: String, identityPub: String): ContactEntry? {
        val r = account.store.local().contacts[userId] ?: return null
        if (r.identityPub != identityPub) return null
        return entry(r).takeIf { it.current != null }
    }

    override fun prompts(): List<ContactPrompt> = records()
        .filter { currency.currency(it.userId, it.identityPub) == null }
        .map { ContactPrompt(it, null, TrustGrammar.decodeName(it.label) ?: "") }

    override suspend fun confirmHere(prompt: ContactPrompt): Boolean {
        val now = account.store.local().contacts[prompt.record.userId] ?: return false
        if (now.identityPub != prompt.record.identityPub) return false
        return currency.mark(now.userId, now.identityPub, Currency.CONFIRMED)
    }

    override fun oneTapListDue(): Boolean = passwordOnly && !currency.oneTapShown()

    override suspend fun confirmOneTap(userIds: Set<String>): Boolean {
        if (!oneTapListDue()) return false
        val contacts = account.store.local().contacts
        for (id in userIds) {
            val r = contacts[id] ?: continue
            if (currency.currency(r.userId, r.identityPub) == null) currency.mark(r.userId, r.identityPub, Currency.ONE_TAP)
        }
        currency.setOneTapShown()
        return true
    }

    override suspend fun remove(userId: String): Boolean {
        val w = account.store.update { AccountMerge.removeContact(it, userId, clock()) }
        val ok = w is AccountStateWrite.Written || w is AccountStateWrite.Unchanged
        if (ok) currency.drop(userId)
        return ok
    }
}
