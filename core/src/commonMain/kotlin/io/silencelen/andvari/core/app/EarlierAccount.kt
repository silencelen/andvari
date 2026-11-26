package io.silencelen.andvari.core.app

/**
 * "Forget the earlier account on this device" (decided on 2026-11-17). A device remembers, for an address at a server,
 * which account it is (its id and identity key), and that memory outlives a sign-out on purpose: it stops a server from
 * handing the device another account under a known address. It also means that when a person deletes their account and
 * makes it again under the same address, this device refuses the new one. This is that refusal, and the person's way out.
 *
 * It stands in [AppSnapshot.earlierAccount] while the screen whose refusal raised it is on show: a sign-in, a registration
 * before anything was made, a recovery with the kit (its check or its commit, nothing committed), a request for the
 * operator's help (its answer, kept), or a device link's pickup, each refused because this device knows the address under
 * an earlier account (the session keeper's own reason, not a fault of the server's answer in itself), ANOTHER account (by
 * its id) than the one the server serves now. It is never raised where the server serves the SAME account under another
 * identity key (that is the identity fault, and nothing can be forgotten there: a remade account never has its old id),
 * where the device cannot tell the two apart, where the refusal was about something else, and never for an account this
 * device keeps open, keeps under another address or at the server's new address, or holds as its server's operator.
 *
 * The screen shows [title], [refusal], [ifRemade], [ifServer] and [howToTell] (each a sentence of its own), with
 * [forgetLabel] and [CopyKey.CANCEL], neither preselected or focused:
 * - [forgetLabel] is [EntryApi.askToForgetEarlierAccount]: the second confirmation, this object again with [confirming],
 *   which shows [confirmTitle], [confirmLines] and [confirmLabel] with [CopyKey.CANCEL]. Nothing is forgotten yet.
 * - [confirmLabel] is [EntryApi.forgetEarlierAccount] with the confirming object; [ForgetEarlierResult] says what came of
 *   it, and [lineFor] its sentence with the address.
 * - [CopyKey.CANCEL] is [EntryApi.keepEarlierAccount]: from the confirmation back to the offer, from the offer away.
 *
 * Only the person, on this device, sets it off: no server answer, link, mail or timer reaches it, and a lock between the two
 * steps takes the confirmation back (nothing is forgotten). It carries the person's confirmation, so only the app interface
 * makes one, and it has no `copy`.
 */
class EarlierAccountKnown internal constructor(
    /** The address the refused flow was for. */
    val email: String,
    /** The server the refusal is about, as this device's pin names it. */
    val instance: InstanceLabel,
    /**
     * This device keeps a copy of the earlier account (locked, its session ended), or holds its data without reading it as
     * the kept session (a session record that could not be read), which the forgetting deletes with its changes that were
     * not sent. False when no copy of it is kept or held here.
     */
    val keptCopy: Boolean,
    /**
     * How many changes made on this device under that account were never sent and go with the forgetting: with [keptCopy],
     * those of its copy counted as a sign-out counts them ([AppApi.signOutCheck]) plus its signed changes to shared vaults
     * waiting here; without a copy, those signed changes alone (a sign-out keeps them; the forgetting does not). Null when
     * this device cannot tell (always, where its data is held here). Never 0 over a change that waits.
     */
    val unsentChanges: Int?,
    /** The second confirmation is on show ([EntryApi.askToForgetEarlierAccount] was taken). */
    val confirming: Boolean,
    internal val origin: String,
    internal val emailNorm: String,
    /** The account this device knows under the address: the one the forgetting forgets, and no other. */
    internal val earlierUserId: String,
    /** The screen whose refusal raised it: shown only while that screen is on show. */
    internal val on: Any,
    /**
     * The account the server served when the refusal was made: ANOTHER account than [earlierUserId] (by id), or no offer is
     * made. Where the address comes to be tied to this very account, the offer is not made and its confirmation is not taken.
     */
    internal val servedUserId: String,
) {
    val title: CopyKey get() = CopyKey.REMADE_ACCOUNT_TITLE

    /** The address and the server's name. */
    val refusal: CopyLine get() = CopyLine.of(CopyKey.REMADE_ACCOUNT_REFUSAL, email, instance.name)

    /** The first possibility: the account was deleted and made again, and this device remembers the earlier one. */
    val ifRemade: CopyKey get() = CopyKey.REMADE_ACCOUNT_IF_REMADE

    /** The second possibility: the server is not giving this device the account it knows; nothing should be forgotten. */
    val ifServer: CopyKey get() = CopyKey.REMADE_ACCOUNT_IF_SERVER

    /** How to tell: the person knows whether they (or the operator, with their knowledge) deleted it and made it again. */
    val howToTell: CopyKey get() = CopyKey.REMADE_ACCOUNT_HOW_TO_TELL

    /** The offer's button. Never preselected. */
    val forgetLabel: CopyKey get() = CopyKey.REMADE_ACCOUNT_FORGET

    /** While [confirming]: the second confirmation's heading; null otherwise. */
    val confirmTitle: CopyKey? get() = if (confirming) CopyKey.REMADE_ACCOUNT_CONFIRM_TITLE else null

    /**
     * While [confirming], in this order: what goes; with [keptCopy], that its copy is deleted with how many changes were
     * not sent (or that this device cannot tell); and always, that it cannot be undone and what it means if the account was
     * not made again. Empty otherwise.
     */
    val confirmLines: List<CopyLine>
        get() {
            if (!confirming) return emptyList()
            val copy = if (!keptCopy) {
                // No copy here: only that account's signed changes to shared vaults never sent go; said where there are any.
                when (val n = unsentChanges) {
                    null -> CopyLine.of(CopyKey.REMADE_ACCOUNT_CONFIRM_SHARED_CANNOT_TELL, email)
                    0 -> null
                    1 -> CopyLine.of(CopyKey.REMADE_ACCOUNT_CONFIRM_SHARED_ONE_UNSENT, email)
                    else -> CopyLine.of(CopyKey.REMADE_ACCOUNT_CONFIRM_SHARED_UNSENT, email, n.toString())
                }
            } else when (val n = unsentChanges) {
                null -> CopyLine.of(CopyKey.REMADE_ACCOUNT_CONFIRM_COPY_CANNOT_TELL, email)
                0 -> CopyLine.of(CopyKey.REMADE_ACCOUNT_CONFIRM_COPY_ALL_SENT, email)
                1 -> CopyLine.of(CopyKey.REMADE_ACCOUNT_CONFIRM_COPY_ONE_UNSENT, email)
                else -> CopyLine.of(CopyKey.REMADE_ACCOUNT_CONFIRM_COPY_UNSENT, email, n.toString())
            }
            return listOfNotNull(CopyLine.of(CopyKey.REMADE_ACCOUNT_CONFIRM, email), copy, CopyLine.of(CopyKey.REMADE_ACCOUNT_CONFIRM_ALWAYS))
        }

    /** While [confirming]: the button that forgets ([EntryApi.forgetEarlierAccount]); null otherwise. */
    val confirmLabel: CopyKey? get() = if (confirming) CopyKey.REMADE_ACCOUNT_CONFIRM_FORGET else null

    /** [result]'s sentence for this address; null for a result with no sentence of its own ([ForgetEarlierResult.STALE]). */
    fun lineFor(result: ForgetEarlierResult): CopyLine? = result.sentence?.let { CopyLine.of(it, email) }
}

/** What [EntryApi.forgetEarlierAccount] came to. Nothing is sent to the server in any of them. */
enum class ForgetEarlierResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    /**
     * Forgotten: this device no longer ties the address at that server to the earlier account, and nothing of that account
     * is left here (its copy, if one was kept, with its changes not sent, and every record kept for it). What this device
     * knows of the server stays: it is checked as before. [AppSnapshot.earlierAccount] goes; the next sign-in, registration,
     * recovery or link under the address is taken as on a device that never knew it, and [AppSnapshot.rememberedNewAccount]
     * says so once.
     */
    FORGOTTEN(sentence = CopyKey.REMADE_ACCOUNT_FORGOTTEN),

    /** This device no longer remembers an earlier account under the address: nothing was removed. The offer goes. */
    NOTHING_TO_FORGET(sentence = CopyKey.REMADE_ACCOUNT_NOTHING_TO_FORGET),

    /** A flow for that address at that server is under way on this device: nothing was removed. The offer stays, at its first step. */
    UNDER_WAY(sentence = CopyKey.REMADE_ACCOUNT_FORGET_UNDER_WAY),

    /**
     * This device keeps a request for the operator's help at that server, which holds the address for as long as it is kept:
     * nothing was removed. The way on is to leave the request first ([EntryApi.abandonOperatorHelp]). The offer stays, at its
     * first step.
     */
    REQUEST_KEPT(sentence = CopyKey.REMADE_ACCOUNT_FORGET_REQUEST_KEPT),

    /**
     * The account the address is tied to is one this device keeps (open, kept under another address or at the server's new
     * address, or held as its server's operator): nothing was removed. The offer goes; the way out is that account's own
     * (its sign-out, or the removal of the operator's account).
     */
    ACCOUNT_OPEN(sentence = CopyKey.REMADE_ACCOUNT_FORGET_ACCOUNT_OPEN),

    /**
     * Not the confirming step, or what it said no longer holds (a lock took the confirmation back; the copy or its count of
     * changes not sent changed): nothing was removed. The snapshot shows what holds now; confirm that.
     */
    NOT_CONFIRMED(sentence = CopyKey.REMADE_ACCOUNT_FORGET_NOT_CONFIRMED),

    /**
     * The address came to name, on this device, the very account the server serves (a take of it under the address while
     * the confirmation was on show): nothing was forgotten, because this device now knows the address as that account. No
     * offer stands, so there is nothing to read again; the way on is to try again (a sign-in). Where the address came to
     * name a third account, the answer is [NOT_CONFIRMED] with the confirmation shown again. Additive.
     */
    ADDRESS_NOW_THE_SERVED_ACCOUNT(sentence = CopyKey.REMADE_ACCOUNT_FORGET_ADDRESS_NOW_SERVED),

    STALE(Trouble.STALE),
    ;

    override val done: Boolean get() = this == FORGOTTEN
}

/**
 * [AppSnapshot.rememberedNewAccount]: said once, after the person forgot an earlier account under [email], when the next
 * account under that address at that server was taken on this device. [AppApi.dismissNewAccountRemembered] takes it away.
 */
class NewAccountRememberedNotice internal constructor(
    val email: String,
) {
    val line: CopyLine get() = CopyLine.of(CopyKey.REMADE_ACCOUNT_REMEMBERED, email)
}
