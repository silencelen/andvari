package io.silencelen.andvari.core.app

/**
 * The people this account connected with (§6.9). Every contact comes from a connect or register link: no intent
 * here, or anywhere in IF-3, makes one from a typed value, an email or a server look-up.
 */
class ContactsScreen internal constructor(
    /** By label. */
    val contacts: List<ContactRow>,
    /**
     * This device signed in with only the password and the person put the list of people off
     * ([ContactsApi.peopleLater]): nobody on it is used here yet, and vaults they share wait. Show a notice above
     * the list; [ContactsApi.reviewPeople] brings [AccountPrompt.PeopleList] back.
     *
     * GAP (§8.5): the design gives no wording for it.
     */
    val peopleNotReviewed: Boolean,
)

/** One contact, as this device sees it (the engine's `ContactView`). */
class ContactRow internal constructor(
    val userId: String,
    /** The name they chose in the link this account connected with them through. Plain text. */
    val label: String,
    /** When the contact was made, unix milliseconds. */
    val connectedAtMs: Long,
    /**
     * The comparison codes were typed and matched on a device of this account (§6.11). Until then the contact is
     * unconfirmed: a vault is shared with them only behind [UncomparedShareWarning], and nothing happens for them
     * automatically (T12).
     */
    val compared: Boolean,
    /**
     * The contact counts on this device (§6.9 "current"). False: show [CopyKey.CONFIRM_ON_THIS_DEVICE], which is
     * [ContactsApi.confirmOnThisDevice]; vaults they share wait, and they cannot be added to a vault from here.
     */
    val currentHere: Boolean,
    /**
     * The device that made the contact, by the name the person gave that device; empty when this app cannot name it
     * (see [AccountPrompt.NewPerson.madeOn]).
     */
    val madeOn: String,
    /** A comparison can run now: this device holds the link's record and the reveal arrived ([ContactsApi.openCompare]). */
    val codesReady: Boolean,
    /**
     * Offer "Compare codes" ([ContactsApi.openCompare]) while not [compared]: [codesReady], or this device answered their
     * link and the creator's reveal has not been fetched yet. Opening the comparison is what fetches it: until the reveal
     * arrives and opens the link's commitment, the comparison shows [CompareScreen.Waiting] (no code); a reveal that does
     * not open it shows [CompareScreen.LinkFailed]. No code is shown before it is the right one. Additive.
     */
    val canCompare: Boolean = codesReady,
)

/**
 * A comparison of codes with one contact (§6.11), typed in both the remote and the in-person flow: each person reads
 * out the code their own app shows and types the six digits the other reads. (The engine's `RecipientStep.Answered`,
 * `CodeReady` and `CreatorStep.Processed`, and its `LinkFlows.code`.)
 *
 * GAP (§6.11): the design's example "Ask Alice to read the code on her iPhone, then type it here." names the other
 * person's device, and no format in §6 carries one. The screens carry the contact's label and no such sentence.
 */
sealed class CompareScreen {
    abstract val userId: String

    /** The contact's label. */
    abstract val label: String

    /** The creator's reveal has not arrived. **No code exists yet**: it is fixed only by both nonces. */
    class Waiting internal constructor(override val userId: String, override val label: String) : CompareScreen()

    /**
     * Both nonces are fixed and the reveal matched the offer's commitment: [code] is **this side's own** six digits
     * (the link's `creator` code on the device that made the link, its `answerer` code on the one that answered,
     * §2.3, §6.11), for this person to read out. The other side's code, which this person types, is computed by core
     * and never exposed, so [code] typed back is simply a wrong entry. **This is the only state that carries a code,
     * and the only one [ContactsApi.submitComparison] takes.** The codes are computed once and never again (T2-R-b).
     * Show [code] as two groups of three (`481 207`); a typed code may carry the same space.
     */
    class Ready internal constructor(
        override val userId: String,
        override val label: String,
        val code: String,
        /** A match will replace the key pinned for this contact (§6.8 step 6). */
        val replacesKey: Boolean,
    ) : CompareScreen()

    /** A second, different nonce was seen, or the reveal did not match the commitment: the link is failed and no code is shown. */
    class LinkFailed internal constructor(override val userId: String, override val label: String) : CompareScreen()

    /** This device's own entry matched: the contact is compared. */
    class Matched internal constructor(override val userId: String, override val label: String) : CompareScreen()
}

interface ContactsApi {
    suspend fun openContacts(): PlainResult

    fun closeContacts()

    /** Remove a contact from the account (a tombstone; the newest act wins). Vaults already shared are not touched. */
    suspend fun removeContact(contact: ContactRow): PlainResult

    /** "Use on this device?": one tap makes a contact made elsewhere current here. */
    suspend fun useOnThisDevice(prompt: AccountPrompt.NewPerson): PlainResult

    /**
     * The other answer to "Use on this device?": no. The contact stays in the account and is not used on this
     * device; the prompt does not return for it, on this device, at any unlock. Nothing is sent: it is this
     * device's own record. [confirmOnThisDevice] still accepts them later, and [removeContact] removes them from
     * the account.
     */
    fun dontUseOnThisDevice(prompt: AccountPrompt.NewPerson)

    /**
     * "Confirm on this device", from the list: make [contact], which is not current here
     * ([ContactRow.currentHere]), current here. It is the person's own confirmation on this device (§6.9 (c)), for
     * someone they chose not to use earlier, left unticked, or have not been asked about.
     */
    suspend fun confirmOnThisDevice(contact: ContactRow): PlainResult

    /**
     * "Use these on this device": the ticked people become current here. The rest stay "confirm on this device":
     * they raise no [AccountPrompt.NewPerson] afterwards, and [confirmOnThisDevice] accepts them later.
     */
    suspend fun usePeople(prompt: AccountPrompt.PeopleList, userIds: List<String>): PlainResult

    /**
     * "Later": nothing becomes current, and the list is put away. It returns when someone on it shares a vault with
     * this account, and through [reviewPeople]; not by itself at the next unlock.
     */
    fun peopleLater(prompt: AccountPrompt.PeopleList)

    /** "Review the list": raise [AccountPrompt.PeopleList] again after it was put off ([ContactsScreen.peopleNotReviewed]). */
    fun reviewPeople(screen: ContactsScreen)

    /** Open the comparison of codes with [contact]. */
    suspend fun openCompare(contact: ContactRow): PlainResult

    /** Open the comparison that would accept a contact's new key. */
    suspend fun openCompareForNewKey(prompt: AccountPrompt.KeyChanged): PlainResult

    fun closeCompare()

    /**
     * The six digits the **other** person read out from their own screen, **as typed**: pass the field's text
     * through untouched. The engine compares it as text (§6.11): every ASCII space is removed, and what is left must
     * be exactly six ASCII digits equal to the other side's code, which core computes and never exposes. A UI
     * neither trims, pads nor converts it: a dropped leading zero is a mismatch. [CompareScreen.Ready.code], this
     * side's own, does not match (except for the one link in a million whose two codes are equal, where it is
     * accepted like any right entry).
     *
     * **There is no intent that says "they match"**: only this device's own correct entry marks the contact compared,
     * and nothing the server or the other app sends can (T2-R-i). A match releases the vaults attached to the link.
     */
    suspend fun submitComparison(screen: CompareScreen.Ready, digits: String): ComparisonResult
}

/** The engine's `CompareResult`, as an intent answers it. */
enum class ComparisonResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    /** Matched. */
    DONE,

    /**
     * Not the code on the other screen. **It is not a verdict and it ends nothing**: nothing was verified or
     * refused, [CompareScreen.Ready] stays as it is, and the person may type again, as often as they like (typing is
     * between them and their own app; there is nothing for anyone else to retry). The design's sentence for a
     * comparison the two people give up on is [sentence].
     */
    MISMATCH(sentence = CopyKey.CODES_DO_NOT_MATCH),

    /**
     * The digits matched and this device recorded it, but the account could not be told (no answer, or a refusal):
     * the contact is not compared in the account yet and no vault went out. Typing the same digits again retries
     * (the engine's `CompareResult.Unsaved`).
     */
    NOT_SAVED,

    /** The link failed meanwhile: [CompareScreen.LinkFailed]. */
    LINK_FAILED,
    STALE(Trouble.STALE),
    UNREACHABLE(Trouble.UNREACHABLE),
    RATE_LIMITED(Trouble.RATE_LIMITED),
    UPDATE_REQUIRED(Trouble.UPDATE_REQUIRED),
    FAILED(Trouble.FAILED),
    ;

    override val done: Boolean get() = this == DONE
}
