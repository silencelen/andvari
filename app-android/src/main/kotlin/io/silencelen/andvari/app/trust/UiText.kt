package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CopyLine
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.Trouble
import io.silencelen.andvari.core.app.VaultActionResult

/**
 * What a screen of the new path says, and whose words they are.
 *
 * Every sentence the design gives comes from the app API's copy ([CopyKey], [CopyLine]) and is shown as plain text.
 * Where the design gives no words (a reserved key with an empty `english`, a refusal with no sentence, a field label or
 * a button the design does not name), the screen shows a **visible placeholder** instead: [Placeholder], rendered as
 * `⟦…⟧` in a distinct style. None of them may ship; the owner has not approved any wording for them. Words the owner
 * approved where the design gave none are in [Approved] and show as plain text.
 */
sealed class UiText {
    /** Words the design gives (or values the state carries, such as an origin). */
    class Plain(val text: String) : UiText()

    /**
     * A placeholder: no approved words exist for this yet. [ownGloss] is an outcome's own gloss ([OutcomeWords]), in
     * place of the placeholder's.
     */
    class Ph(val placeholder: Placeholder, val args: List<String>, val ownGloss: String? = null, internal val unnamed: Set<Int> = emptySet()) : UiText()

    /**
     * The text as shown. A placeholder is marked so nobody mistakes it for final copy, once: a value that is itself a
     * placeholder's text loses its own marks inside it, so a placeholder never shows nested in another. Approved words
     * that quote a slot (“{0}”) lose those quotes around a slot in [Ph.unnamed]: the words that stand where no name is
     * known are not a name ([fillNames]).
     */
    fun shown(): String = when (this) {
        is Plain -> text
        is Ph -> if (ownGloss == null && placeholder.words != null) fillNames(placeholder.words, args, unnamed) else "⟦" + (ownGloss ?: placeholder.gloss) +
            (if (args.isEmpty()) "" else ": " + args.joinToString(", ") { unmarked(it) }) + "⟧"
    }

    val isPlaceholder: Boolean get() = this is Ph && (ownGloss != null || placeholder.words == null)

    companion object {
        /**
         * A key's sentence, from the shared code: the design's or the owner's approved words (the shared code carries
         * entries 3, 4, 5, 14, 27 and 28 itself). A key still reserved there (an empty sentence) is a placeholder.
         */
        fun of(key: CopyKey): UiText = when {
            key.reserved -> Ph(Placeholder.RESERVED_COPY, listOf(key.name))
            // A key awaiting the owner's wording: its english is a gloss, shown as a placeholder.
            key.awaitingOwner -> Ph(Placeholder.AWAITING_OWNER, listOf(unbracket(key.english)))
            else -> Plain(key.english)
        }

        fun of(line: CopyLine): UiText = when {
            line.key.reserved -> Ph(Placeholder.RESERVED_COPY, listOf(line.key.name) + line.values)
            line.key.awaitingOwner -> Ph(Placeholder.AWAITING_OWNER, listOf(unbracket(line.english)))
            else -> Plain(line.english)
        }

        /** A key's sentence with [values] in place of `{0}`, `{1}`, … (the way core fills a [CopyLine]). */
        fun of(key: CopyKey, vararg values: String): UiText = when {
            key.reserved -> Ph(Placeholder.RESERVED_COPY, listOf(key.name) + values)
            key.awaitingOwner -> Ph(Placeholder.AWAITING_OWNER, listOf(unbracket(fillTemplate(key.english, values.toList()))))
            else -> Plain(fillTemplate(key.english, values.toList()))
        }

        private fun unbracket(s: String): String = s.trim().removePrefix("⟦").removeSuffix("⟧")

        /** [s] without a placeholder's marks anywhere in it. */
        internal fun unmarked(s: String): String = s.replace("⟦", "").replace("⟧", "")

        fun ph(p: Placeholder, vararg args: String): UiText = Ph(p, args.toList())

        /** An outcome's own placeholder ([OutcomeWords]): its gloss says what happened, and no type's name is in it. */
        fun outcome(gloss: String, vararg args: String): UiText = Ph(Placeholder.OUTCOME, args.toList(), gloss)

        /** Approved words with [values] in place of `{0}`, `{1}`, … (filled the way core fills a key). */
        fun approved(template: String, vararg values: String): UiText = Plain(fillTemplate(template, values.toList()))

        /**
         * Approved words whose slots may hold names ([NameSlot]): a name goes in as it is and is quoted once, by the
         * sentence; where no name is known, the words that say so stand there without the sentence's quotes.
         */
        internal fun approvedNamed(template: String, vararg slots: NameSlot): UiText =
            Plain(fillNames(template, slots.map { it.text }, unnamedOf(slots)))

        /** A key's sentence as [of] with values, with [approvedNamed]'s rule for its name slots. */
        internal fun ofNamed(key: CopyKey, vararg slots: NameSlot): UiText =
            if (key.reserved || key.awaitingOwner) of(key, *slots.map { it.text }.toTypedArray())
            else Plain(fillNames(key.english, slots.map { it.text }, unnamedOf(slots)))

        /** A placeholder as [ph], with [approvedNamed]'s rule for its name slots once it has words. */
        internal fun phNamed(p: Placeholder, vararg slots: NameSlot): UiText = Ph(p, slots.map { it.text }, unnamed = unnamedOf(slots))

        private fun unnamedOf(slots: Array<out NameSlot>): Set<Int> = slots.indices.filter { !slots[it].named }.toSet()

        /**
         * What an intent's result says in place: null when it was done; the design's sentence when the result carries
         * one; the owner's approved words where they exist for it; otherwise the outcome's own placeholder
         * ([OutcomeWords]: a trouble, or the intent's own refusal). Never a type's name.
         */
        fun forResult(result: IntentResult, retryAfterSeconds: Int): UiText? {
            if (result.done) return null
            result.sentence?.let { return of(it) }
            if (result == VaultActionResult.SENT_PENDING) return Plain(Approved.VAULT_CHANGE_WAITING)
            if (result == io.silencelen.andvari.core.app.ComparisonResult.NOT_SAVED) return Plain(Approved.COMPARE_MATCHED_NOT_SAVED)
            result.trouble?.let { return OutcomeWords.trouble(it, retryAfterSeconds) }
            return OutcomeWords.refusal(result) ?: Ph(Placeholder.REFUSAL, emptyList())
        }
    }
}

/**
 * One value of a sentence that may quote it: a name someone chose ([named]), or the words that stand where no name is
 * known, which are not a name to quote. As the shared code fills its own lines (`ContentCopy.fillNames`).
 */
internal class NameSlot(val text: String, val named: Boolean) {
    companion object {
        /** [name], or [missing]'s words where it is not known (null or blank). */
        fun of(name: String?, missing: UiText): NameSlot = if (name.isNullOrBlank()) NameSlot(missing.shown(), named = false) else NameSlot(name, named = true)

        /** A value that is no name (a count, a date), quoted as the sentence quotes it. */
        fun said(text: String): NameSlot = NameSlot(text, named = true)
    }
}

/**
 * [template] filled as [fillTemplate] does, except that a slot in [unnamed] that the template quotes (“{n}”) goes in
 * without those quotes. One pass, so a value that itself reads "{0}" is copied and never filled in again.
 */
internal fun fillNames(template: String, values: List<String>, unnamed: Set<Int>): String {
    if (unnamed.isEmpty()) return fillTemplate(template, values)
    val out = StringBuilder(template.length + 32)
    var i = 0
    while (i < template.length) {
        val quoted = template[i] == '“' && i + 1 < template.length && template[i + 1] == '{'
        val open = if (quoted) i + 1 else i
        val close = if (template[open] == '{') template.indexOf('}', open) else -1
        val index = if (close > open + 1) template.substring(open + 1, close).toIntOrNull()?.takeIf { it in values.indices } else null
        if (index == null) {
            out.append(template[i])
            i++
            continue
        }
        val closed = quoted && close + 1 < template.length && template[close + 1] == '”'
        if (closed && index in unnamed) {
            out.append(values[index])
            i = close + 2
        } else {
            if (quoted) out.append('“')
            out.append(values[index])
            i = close + 1
        }
    }
    return out.toString()
}

/** [template] with [values] in place of `{0}`, `{1}`, …: one pass, so a value that itself reads "{0}" is copied. */
internal fun fillTemplate(template: String, values: List<String>): String {
    val out = StringBuilder(template.length + 32)
    var i = 0
    while (i < template.length) {
        val close = if (template[i] == '{') template.indexOf('}', i) else -1
        val index = if (close > i + 1) template.substring(i + 1, close).toIntOrNull() else null
        if (index != null && index in values.indices) {
            out.append(values[index])
            i = close + 1
        } else {
            out.append(template[i])
            i++
        }
    }
    return out.toString()
}

/**
 * Words the owner approved where the design gave none (the copy page of 2026-11-15, all 28 entries approved on
 * 2026-11-15). Each is used exactly as approved, `{0}`, `{1}`, … included; the comment names the entry and what each
 * slot stands for.
 */
internal object Approved {
    // ---- 1, 2: the first screen's second button, and the line under it ----
    const val FIRST_SIGNUP_INVITATION_ONLY = "Sign-up is invitation-only right now"

    /** {0} the first button's label on this device ([CopyKey.FIRST_SCAN_INVITE]). */
    const val FIRST_SIGNUP_INVITATION_ONLY_LINE = "If someone sent you an invitation link, use {0}."
    const val FIRST_SIGNUP_CLOSED = "Sign-up is closed right now"
    const val FIRST_SIGNUP_CLOSED_LINE = "You can still sign in to an account you already have."

    // ---- 6: old data that could not be removed ----
    const val OLD_DATA_NOT_REMOVED_TITLE = "Some old andvari data is still on this device"
    const val OLD_DATA_NOT_REMOVED_BODY =
        "andvari couldn't remove data that an earlier version left on this device. This version never opens it. andvari will try again each time it starts."
    const val OLD_DATA_NOT_REMOVED_TRY_AGAIN = "Try again"
    const val OLD_DATA_NOT_REMOVED_CONTINUE = "Continue"

    // ---- 8: the address dialed serves another address's card ----
    const val CARD_OTHER_ADDRESS_TITLE = "This address doesn't match the server's identity card"

    /** {0} the address that was typed or scanned, whole; {1} the address the card names. */
    const val CARD_OTHER_ADDRESS_BODY =
        "The server at {0} showed an identity card made for a different address, {1}. andvari didn't connect, and nothing of yours was sent. The address may be wrong, the server may have moved, or someone may be imitating it. Check the address with the person who runs the server."

    // ---- 10: the Trust Gate in its kind-change wording ----
    const val GATE_TITLE_KIND_CHANGE = "This server says it changed"
    const val GATE_KIND_CHANGE_CONTINUE = "Continue"
    const val GATE_KIND_CHANGE_NOT_NOW = "Not now"

    // ---- 11, 12, 13: what a server's card says ----
    const val CARD_NOT_VERIFIED =
        "This server showed an update to its identity card that andvari can't verify. andvari ignored it and kept the card it had already checked. If this message stays, ask the operator what happened."
    const val CARD_RECORD_DAMAGED_TITLE = "andvari can't read its record of this server"

    /** {0} the server's address. Two paragraphs. */
    const val CARD_RECORD_DAMAGED_BODY =
        "The record this device keeps of the identity of {0} is damaged, or comes from a newer version of andvari. Without it andvari can't tell whether this is still the same server, so it has stopped using it on this device.\nIf you went back to an older version of andvari, update it. Otherwise choose Forget this server and connect again. That removes this server's data from this device, including changes that hadn't synced. Your account on the server is not affected."
    const val CARD_MOVE_NOT_FOLLOWED_TITLE = "andvari didn't follow this move"

    /** {0} the address the server says it moved to. */
    const val CARD_MOVE_NOT_FOLLOWED_BODY =
        "This device already knows {0} as a server, and a move never replaces a server this device already knows. Nothing changed. If you set it up on this device yourself, as this server's new address, sign out and sign in there. If you didn't, ask this server's operator what happened."

    // ---- 16, 17: checking the account a recovery delivered ----
    const val RECOVERY_CHECK_ACCOUNT_TITLE = "Is this your account?"
    const val RECOVERY_CHECK_ACCOUNT_BODY = "Check this against the account ID in an earlier andvari email to you. If it is different, stop."
    const val RECOVERY_CHECK_ACCOUNT_DIFFERENT = "It's different"
    const val RECOVERY_CHECK_ACCOUNT_NOT_NOW = "Not now"
    const val RECOVERY_CHECK_STOPPED =
        "andvari stopped. No password was set and nothing was changed. Tell the operator that the account they restored wasn't yours."

    // ---- 18, 19, 20, 21: people ----
    const val PERSON_FROM_OTHER_DEVICE_HINT = "If you don't recognise them, choose Don't use."
    const val PERSON_USE_ON_THIS_DEVICE = "Use on this device"
    const val PERSON_DONT_USE = "Don't use"
    const val PEOPLE_NOT_REVIEWED = "You haven't said which of these people to use on this device. Vaults they share with you wait until you do."
    const val PEOPLE_REVIEW_THE_LIST = "Review the list"

    /** {0} the sender's name as the server reports it. */
    const val INCOMING_CONFIRM_FIRST = "{0} wants to share a vault with you. Confirm them on this device first."

    /** {0} the contact's label. Beside this device's own code. */
    const val COMPARE_READ_THIS = "Read this to {0}."

    /** {0} the contact's label. Beside the field for the other person's six digits. */
    const val COMPARE_TYPE_THEIRS = "Ask {0} to read the code on their device, then type it here."

    /** The codes matched and this device recorded it, but the account could not be told ([ComparisonResult.NOT_SAVED]). */
    const val COMPARE_MATCHED_NOT_SAVED =
        "The codes match, but your account couldn't be updated, so your other devices still show this person as not compared. Try again."

    // ---- 22 to 28: shared vaults ----
    const val VAULT_HISTORY_FORKED =
        "This shared vault's history has two versions that can't both be true. The server may be misbehaving. The vault is read-only on this device from now on. You can still read it, copy items out, or remove it from this device."

    /** Stands in for the vault's name, which nothing decrypted. */
    const val VAULT_KEY_MISSING_TITLE = "A shared vault andvari can't open"
    const val VAULT_KEY_MISSING =
        "The server didn't give this device a key that opens this vault, so nothing in it can be shown here. Try again later. If it stays closed, ask the vault's owner to share it with you again. If you own it, open it on another of your devices and use Move everything to a new vault."

    /** Where the change was made ([VaultActionResult.SENT_PENDING]). */
    const val VAULT_CHANGE_WAITING =
        "andvari sent your change but got no answer from this server, so it can't tell yet whether it went through. It will keep sending the same change until the server confirms it. You don't need to do it again."

    /** The mark on the vault's row until the server confirms. */
    const val VAULT_CHANGE_WAITING_MARK = "waiting for the server"
    const val MEMBERS_MAY_BE_INCOMPLETE_WHY = "An item in this vault mentions history the server hasn't shown, so there may be members this device can't see."

    /** {0} the member's label, {1} the vault's name, {2} the day the offer ends. The note while the offer is open. */
    const val OWNERSHIP_OFFER_NOTE = "You asked {0} to take over “{1}”. They can accept until {2}."

    /** Entry 26, the dialog before the offer: {0} the member's label, {1} the vault's name. */
    const val OWNERSHIP_OFFER_TITLE = "Make {0} the owner of “{1}”?"

    /** {0} the member's label. The confirm button; the other is the existing [CopyKey.CANCEL]. */
    const val OWNERSHIP_OFFER_ASK = "Ask {0} to take over"

    /** The dialog's body. It names 14 days, which core's offer now lasts (`OwnershipOffer.DAYS`). */
    const val OWNERSHIP_OFFER_BODY =
        "Nothing changes until they accept in their app. They have 14 days, and you can cancel until then. Afterwards they manage the vault's members, and only they can rename it, hand it over or delete it. You stay in it as a writer."

    // Entries 3, 4, 5, 14 (the SERVER_* and LINK_REQUIRED_* keys) and 27, 28 (OWNER_OUT_OF_SPACE_YOURS/THEIRS) are carried
    // by the shared code itself, so the app keeps no copy of their words.
}

/**
 * A line with a count before its noun (copy page, PQ17): [one], whose words carry the 1 and the noun for one, when [n]
 * is 1; otherwise [many] with [slots] and then the count, which is its last value.
 */
internal fun counted(n: Long, many: Placeholder, one: Placeholder, vararg slots: String): UiText =
    if (n == 1L) UiText.ph(one, *slots) else UiText.ph(many, *slots, n.toString())

/**
 * Every string of the new path the design does not give. Each is shown as `⟦gloss⟧`; the gloss says what the string
 * is for and is not proposed wording.
 */
enum class Placeholder(val gloss: String, val words: String? = null) {
    // ---- generic ----
    RESERVED_COPY("reserved copy key"),
    AWAITING_OWNER("awaiting the owner's words"),
    REFUSAL("result without wording"),
    TROUBLE("trouble without wording"),
    BACK("back", words = "Back"),
    START_OVER("start over", words = "Start over"),
    CONTINUE("continue", words = "Continue"),
    NOT_BUILT_YET("screen not built yet in this build"),
    WORKING("working", words = "Working…"),

    // ---- fields ----
    EMAIL_FIELD("email address", words = "Email address"),
    PASSWORD_FIELD("master password", words = "Master password"),
    NEW_PASSWORD_FIELD("new master password", words = "New master password"),
    NEW_PASSWORD_AGAIN_FIELD("new master password again", words = "Type it again"),
    PASSWORDS_DIFFER("the two passwords differ", words = "The two passwords don't match."),
    CODE_FIELD("six-digit code", words = "6-digit code"),
    TWO_STEP_CODE_FIELD("two-step sign-in code", words = "Code from your authenticator app"),
    SERVER_ADDRESS_FIELD("server address", words = "Server address"),
    DISPLAY_NAME_FIELD("your name, as people you connect with will see it", words = "Your name"),
    DISPLAY_NAME_UNDER("under the name field: people you connect with see this name", words = "People you connect with see this name."),
    LINK_FIELD("paste a link here", words = "Paste the link here"),
    LINK_NAME_FIELD("the name your links carry, as the other person will see it"),

    // ---- the sign-in's new results ----
    SIGN_IN_KEYS_WAY_OUT("what you can do: contact whoever runs this server; if you are sure, sign out of this phone's copy of the account (changes not sent go with it) and sign in again"),
    // ---- the QR scanner ----
    SCAN_OPEN("scan the QR code with the camera", words = "Scan with the camera"),
    SCAN_STOP("stop scanning", words = "Stop scanning"),
    SCAN_POINT("point the camera at the QR code", words = "Point the camera at the QR code."),
    SCAN_NOT_ALLOWED("the camera is not allowed: use the field below instead", words = "andvari isn't allowed to use the camera. Use the field below, or allow the camera for andvari in your phone's settings."),
    SCAN_NO_CAMERA("this phone has no camera: use the field below instead", words = "This phone has no camera andvari can use. Use the field below."),
    SCAN_CAMERA_FAILED("the camera did not start: use the field below instead", words = "The camera didn't start. Use the field below, or try again."),

    // ---- first screen and entry ----
    NOTICE_SIGNED_OUT_BY_SERVER("notice: the server ended this device's session", words = "The server signed this device out. That happens when this device is removed from your account, when your master password is changed or reset on another device, or when the operator turns your account off. To use your account here, sign in again."),
    NOTICE_OPERATOR_NEEDS_COMPUTER("notice: this account now runs the server, so this phone signed it out; use the desktop app or the command-line tool", words = "This is the server's operator account. It can only be used in the andvari desktop app or in andvari-cli, so andvari doesn't keep it on this phone."),
    DISMISS("dismiss", words = "Close"),
    RESUME_OPERATOR_HELP("resume the request for the operator's help", words = "Check on your request for help"),
    SUBMIT_ADDRESS("connect", words = "Connect"),
    SEND_CODE("send code", words = "Send me a code"),
    PROVING_WORK("preparing sign-up"),
    RESEND_CODE("send another code", words = "Send another code"),
    VERIFY_CODE("verify", words = "Verify"),
    CREATE_ACCOUNT_BUTTON("create account", words = "Create account"),
    INVITED_BY("invited by"),
    SIGN_IN_BUTTON("sign in"),
    PUBLIC_INSTANCE_CHOICE("the public instance", words = "andvari"),
    TRUST_GATE_CONNECT("connect (Trust Gate confirm)", words = "Connect"),
    OPERATOR_KEY("operator key", words = "Operator key"),
    PUNYCODE_CAUTION("punycode caution"),
    HTTP_CAUTION("plain-http caution"),
    FOLLOW_MOVE("follow the move", words = "Use the new address"),
    FORGET_OTHER_SERVER("forget the server at the new address", words = "Forget the server at the new address"),
    NOT_NOW("not now", words = "Not now"),
    ADDRESS_MISMATCH_INVITE("the link cannot be used: ask the person who sent it for a new one", words = "You can't use this invite. Ask the person who sent it for a new one."),
    ADDRESS_MISMATCH_DEVICE_LINK("start again from your other device", words = "Nothing was linked. Start again on your other device."),
    RECOVER_THERE("recover at the address the card names", words = "Recover at the address on its identity card"),
    MAY_EXIST_SIGN_IN("the account may exist: sign in"),
    RECOVERY_CHOICE_SELECTED("selected"),
    TAKEOVER_BODY_SHOWN("unsigned recovery-key change"),
    OPERATOR_ACCOUNT_REFUSED("the operator account signs in only on a computer"),

    // ---- linking this device, recovery ----
    LINK_DEVICE_WAITING("waiting for your other device", words = "Waiting for your other device…"),
    KIT_TEXT_FIELD("recovery kit text", words = "Your kit's text"),
    KIT_GROUPS_FIELD("the eleven groups of your kit", words = "The 11 groups on your kit"),
    RECOVERY_IDLE_DROPPED("the recovery was left unattended and was dropped", words = "This recovery was left unfinished for too long, so andvari dropped it. Nothing was changed. Start again."),

    // ---- the kit ----
    KIT_MAKING("making your recovery kit", words = "Making your recovery kit…"),
    KIT_NOT_MADE("the recovery kit could not be saved", words = "andvari couldn't save your recovery kit to the server, so it doesn't work yet. Make it again."),
    KIT_REPLACED_ELSEWHERE("another device made a newer kit", words = "A newer recovery kit was made on another of your devices, so the one shown here doesn't work. Make a new one here, and throw away any copy of the old one."),
    KIT_RETRY("make the kit again", words = "Make the kit again"),
    KIT_PRINT("print or save as PDF", words = "Print or save as PDF"),
    KIT_PRINT_HANDS_OVER("printing hands the kit to Android's print service and to the printer app you pick; a failed job keeps its copy until it is cancelled", words = "Printing hands your kit to Android's print service and to the printer app you choose. If a print job fails, that app may keep a copy until you cancel the job.",
    ),
    KIT_SAVED_NEXT("I have saved it", words = "I've saved my kit"),
    KIT_SHOW_AGAIN("show the kit again", words = "Show the kit again"),
    KIT_GROUP_FIELD("group", words = "Group {0}"),
    KIT_CONFIRM("confirm", words = "Confirm"),
    KIT_MADE_ON("made on"),
    KIT_FAILED_TRIES("wrong tries", words = "Tries used: {0} of 3"),

    // ---- lock, account, wall ----
    UNLOCK_BUTTON("unlock", words = "Unlock"),
    UNLOCKING("unlocking", words = "Unlocking…"),
    UNLOCK_STALE("the unlock did not run: another one was running, or the app locked meanwhile; try again", words = "That unlock didn't finish. Try again."),
    SIGNED_OUT_BY_SERVER("the server signed this device out; the master password opens this device's copy, read-only", words = "The server signed this device out. Your master password still opens the copy on this device, to read only. Sign in again to sync and make changes."),
    SIGNED_OUT_BY_SERVER_OPEN("signed out by the server: this is this device's copy, read-only, and nothing is sent; lock, then sign in again", words = "The server signed this device out. You're reading the copy on this device: nothing is sent, and nothing can be changed. To sync again, lock, then sign in."),
    SIGN_IN_AGAIN("sign in again", words = "Sign in again"),
    FILL_FROM_COPY("signed out by the server: this fills from this device's copy, and nothing is saved", words = "The server signed this device out. andvari fills from the copy on this device, and nothing new is saved."),
    LOCK_PREVIOUS_PASSWORD_OPENS("your master password was changed, but this device's copy still opens with the previous one", words = "Your master password was changed, but on this device andvari still opens with your previous one."),
    PASSWORD_CHANGED_PREVIOUS_OPENS_HERE("changed: the new password is in force for your account, but this phone's copy still opens with the previous one until it is wrapped again", words = "Your master password is changed, but andvari on this device couldn't switch to it. Here, your previous master password still opens andvari. Everywhere else, use the new one."),
    OPERATOR_HELP_CODE_NEEDED("type the code sent to this email address", words = "If your account uses operator recovery, an email with a 6-digit code is on its way. Enter it here."),
    // The person who asked, on their own screen: the request code is shown ABOVE these lines.
    OPERATOR_HELP_HOLDING("the request is waiting: your signed-in devices can cancel it until", words = "Your request is in its wait. Until it ends, your signed-in devices can cancel it."),
    OPERATOR_HELP_AWAITING_OPERATOR("the wait is over: the operator has yet to act", words = "The wait is over. The operator will contact you. Read them the code above."),
    OPERATOR_HELP_EXPIRED("the request expired", words = "This request has expired. You can ask again."),
    OPERATOR_HELP_DID_NOT_CHECK_OUT("the operator's answer did not check out: nothing was applied", words = "The operator's answer didn't pass andvari's checks, so nothing was changed. Ask the operator what happened."),
    FILL_CHOOSE_LOGIN("choose a login in andvari", words = "Choose a login from andvari"),
    FILL_CHOOSE_CARD("choose a card in andvari", words = "Choose a card from andvari"),
    FILL_CHOOSER_LOGINS("which login goes into this app", words = "Which login goes into this app?"),
    FILL_CHOOSER_CARDS("which card goes into this app", words = "Which card goes into this app?"),
    FILL_CHOOSER_NOTHING("nothing to fill here now: tap the field again", words = "andvari has nothing to fill here right now. Tap the field again."),
    FILL_CHOOSER_APP_CHANGED_BEFORE("the app changed since you tapped the field: tap it again"),
    FILL_CHOOSER_APP_CHANGED("the app changed while andvari's list was open: nothing was filled"),
    FILL_CHOOSER_NOT_FILLED("that could not be filled: open andvari and try again"),
    // The toasts of andvari's two fill confirms (an app's login, a card), marked as placeholders.
    FILL_CONFIRM_APP_CHANGED_BEFORE("the app changed since you tapped the field: tap it again"),
    FILL_CONFIRM_APP_CHANGED("the app changed while andvari's confirm was open: nothing was filled"),
    FILL_CONFIRM_LOGIN_NOT_FILLED("that login could not be filled: open andvari and try again"),
    FILL_CONFIRM_CARD_NOT_FILLED("that card could not be filled: open andvari and try again"),
    FILL_TOUCH_OBSCURED("another app is drawing over this window, so the tap was ignored: close it, then tap again", words = "Another app is showing something over andvari, so andvari ignored that tap. Close that app, then tap again."),
    SAVE_QUEUED("kept for andvari: open andvari to see it saved or to check it", words = "Kept for andvari. Open andvari to check it and save it."),
    SAVE_NOT_SIGNED_IN("not saved: no account is signed in here", words = "Not saved: no account is signed in to andvari on this device."),
    SAVE_NOT_NOW("not saved: the server signed this device out, or is stopped here", words = "Not saved: the server signed this device out, or andvari has stopped using it here."),
    SAVE_REFUSED("not saved", words = "Not saved."),
    PENDING_SAVES("logins autofill captured, to check", words = "Logins from autofill to check"),
    PENDING_SAVE_REPLACES("would replace the password of", words = "This would replace the password of {0}."),
    PENDING_SAVE_HTTP("captured on a plain-http page", words = "Captured on a page that isn't secure (http)."),
    PENDING_SAVE_SAVE("save it", words = "Save it"),
    PENDING_SAVE_DISCARD("discard it", words = "Don't save it"),
    PENDING_SAVE_SHOW("show its password", words = "Show its password"),
    APPLIED_SAVES("saved by itself from autofill", words = "Saved by autofill"),
    APPLIED_SAVE_REPLACED("replaced the password of", words = "Replaced the password of {0}."),
    APPLIED_SAVE_UNDO("take it back", words = "Undo"),
    APPLIED_SAVES_UNDO_ALL("take them all back", words = "Undo all"),
    APPLIED_SAVES_DISMISS("done", words = "Done"),
    RECENTLY_DELETED("recently deleted shared vaults", words = "Recently deleted shared vaults"),
    RECENTLY_DELETED_NONE("no shared vault deleted recently", words = "No shared vault was deleted recently."),
    SIGN_OUT("sign out", words = "Sign out"),
    SIGN_OUT_CONFIRM("sign out of this device?", words = "Sign out of this device?"),
    STAY_SIGNED_IN("stay signed in", words = "Stay signed in"),
    /** The second confirmation's one button, over changes not sent or that this phone cannot count (SignOutAsk). */
    SIGN_OUT_SECOND_CONFIRM("second confirmation's title: sign out of this phone although what was not sent is lost?", words = "Sign out anyway?"),
    SIGN_OUT_ALL_THE_SAME("second confirmation's button: sign out all the same, losing what was not sent"),
    SWITCH_SECOND_CONFIRM("second confirmation's title: switch to the other server although what was not sent is lost?", words = "Switch servers anyway?"),
    SWITCH_ALL_THE_SAME("second confirmation's button: switch all the same, losing what was not sent"),
    ACCOUNT_ID_TITLE("your account ID", words = "Your account ID"),
    ACCOUNT_ID_LINE("the same ID is on your recovery kit and in andvari's emails about this account, except those about a request for the operator's help", words = "The same ID is on your recovery kit and in andvari's emails about this account, except the emails about a request for the operator's help."),
    APPEARANCE("appearance", words = "Appearance"),
    APPEARANCE_LINE("auto follows this device's light or dark setting", words = "Auto follows this device's light or dark setting."),
    APPEARANCE_AUTO("auto (match this device)", words = "Auto"),
    APPEARANCE_LIGHT("light", words = "Light"),
    APPEARANCE_DARK("dark", words = "Dark"),
    SIGN_OUT_BODY("signing out removes this device's copy of the account and its quick unlock; signing in again needs the master password and the server", words = "Signing out removes your vault from this device, including changes that haven't synced. Your account on the server is not affected."),
    LOCK("lock", words = "Lock"),
    VAULT_ITEMS("passwords", words = "Passwords"),
    VAULT_SEARCH("search vault", words = "Search your vault"),
    VAULT_EMPTY("no items", words = "Nothing here yet."),
    SYNC_NOT_YET("showing this device's copy; not synced yet", words = "Showing the copy on this device. It hasn't synced yet."),
    SYNC_OFFLINE("offline; showing this device's copy; changes waiting", words = "Offline. Showing the copy on this device. Changes waiting to be sent: {0}"),
    SYNC_QUEUED("changes waiting to send", words = "Changes waiting to be sent: {0}"),
    SYNC_ROLLBACK("the server sent an older vault; nothing of it was used", words = "The server sent an older version of your vault. andvari didn't use it, and kept what it has."),
    SYNC_REFUSED("the server refused the sync", words = "The server refused to sync, so this is the copy on this device."),
    SYNC_STOPPED("server stopped on this device: readable, nothing can be saved", words = "andvari has stopped using this server on this device. What's here stays readable, but nothing can be saved."),
    ITEM_WAITING("not on the server yet", words = "Not on the server yet"),
    ITEM_BACK("back", words = "Back"),
    ITEM_COPY_USERNAME("copy user name"),
    ITEM_PASSWORD("password", words = "Password"),
    ITEM_CARD_NUMBER("card number", words = "Card number"),
    ITEM_CARD_CODE("security code", words = "Security code"),
    ITEM_NOTES("notes", words = "Notes"),
    ITEM_CODE("one-time code", words = "One-time code"),
    ITEM_REVEAL("show", words = "Show"),
    ITEM_HIDE("hide", words = "Hide"),
    ITEM_COPY("copy", words = "Copy"),
    ITEM_DELETE("delete", words = "Delete"),
    ITEM_DELETE_CONFIRM("move this item to the trash?", words = "Move this item to the trash?"),
    ITEM_NEW("new"),
    TRASH("trash", words = "Trash"),
    HISTORY("earlier versions", words = "Earlier versions"),
    RECENTLY_REMOVED("recently removed", words = "No longer shared with you"),
    HEALTH("vault health", words = "Password health"),
    HEALTH_TAB_PASSWORDS("tab: passwords", words = "Passwords"),
    HEALTH_TAB_DUPLICATES("tab: duplicates", words = "Duplicates"),
    HEALTH_TAB_STALENESS("tab: when last checked", words = "Last checked"),
    HEALTH_TILE_LOGINS("logins", words = "Logins"),
    HEALTH_TILE_WEAK("weak", words = "Weak"),
    HEALTH_TILE_REUSED("reused", words = "Reused"),
    HEALTH_TILE_BREACHED("breached", words = "In a breach"),
    HEALTH_TILE_DUPLICATES("duplicates", words = "Duplicates"),
    HEALTH_TILE_UNCHECKED("unchecked", words = "Not checked"),
    HEALTH_TILE_FAILING("failing", words = "Not working"),
    HEALTH_CHECKING("checking"),
    HEALTH_CHECK_BREACHES("check for breaches", words = "Check for breaches"),
    HEALTH_REFRESH("check again", words = "Check again"),
    HEALTH_REUSED("also used by this many other logins", words = "Also used by {0} other logins"),
    HEALTH_BREACHED("seen in breaches", words = "Seen in {0} breaches"),
    HEALTH_DUPLICATES("duplicates for"),
    HEALTH_KEEP_THIS("keep this one", words = "Keep this one"),
    HEALTH_MERGE("merge", words = "Merge"),
    HEALTH_NOT_DUPLICATES("not duplicates", words = "Not duplicates"),
    VAULT_RENAME("rename this vault", words = "Rename"),
    VAULT_RENAME_SAVE("save the new name", words = "Save name"),
    VAULT_RENAME_NOT_DONE("the vault was not renamed", words = "The vault wasn't renamed."),
    HEALTH_MARKED_NOT_DUPLICATES("copies marked as not duplicates", words = "Marked as not duplicates"),
    HEALTH_PUT_BACK("put back on the list", words = "Put back on the list"),
    HEALTH_STALENESS("logins by when they were last checked", words = "Logins by when you last checked them"),
    HEALTH_SHOW_SNOOZED("show snoozed logins too", words = "Show snoozed logins too"),
    HEALTH_ALL_SNOOZED("every login is snoozed for now", words = "Every login is snoozed for now."),
    HEALTH_RUN_ALL("check every login, worst first", words = "Check every login, most urgent first"),
    HEALTH_RUN_NEVER_CHECKED("check the never-checked only", words = "Check only those never checked"),
    HEALTH_CHECK_THIS("check this login", words = "Check this login"),
    HEALTH_UNSNOOZE("unsnooze", words = "Stop snoozing"),
    HEALTH_RUN_POSITION("checking login, of"),
    HEALTH_OPEN_SITE("open the site to sign in", words = "Open the site to sign in"),
    HEALTH_VERDICT("what happened"),
    HEALTH_SKIP("skip", words = "Skip"),
    HEALTH_STOP("stop the check", words = "Stop checking"),
    HEALTH_OFFER_GONE("marked as gone; move it to the trash?"),
    HEALTH_KEEP_IT("keep it", words = "Keep it"),
    HEALTH_TO_TRASH("move to the trash", words = "Move to trash"),
    HEALTH_OFFER_BAD("marked as refusing its password; change it?"),
    HEALTH_OPEN_ITEM("open the item", words = "Open the item"),
    HEALTH_NEW_PASSWORD("generate a new password", words = "Make a new password"),
    IMPORT_CSV("import a CSV", words = "Import a CSV file"),
    IMPORT_TOO_LARGE("this file is larger than the import takes", words = "This file is too large to import. The most andvari takes is {0}."),
    IMPORT_COUNT("items to import"),
    IMPORT_PROGRESS("importing"),
    IMPORT_CONFIRM("import", words = "Import"),
    IMPORT_CHOOSE_FILE("choose file…", words = "Choose a file"),
    IMPORT_SOURCES("works with exports from Chrome, Edge, Brave, Opera, Firefox, Bitwarden, 1Password 8 or newer, LastPass and Safari; the file itself decides how it is read", words = "Works with exports from Chrome, Edge, Brave, Opera, Firefox, Bitwarden, 1Password 8 or newer, LastPass and Safari. andvari reads each file by what's in it."),
    IMPORT_PLAIN_TEXT("this file holds every secret in plain text; nothing is uploaded, each item is encrypted on this device; afterwards delete the file and empty the trash", words = "This file holds every password in plain text. Nothing is uploaded: each item is encrypted on this device. When the import is done, delete the file, and empty your phone's trash if it keeps deleted files."),
    IMPORT_HELP("how do I export from…?", words = "How to export from another app"),
    IMPORT_HELP_HIDE("hide the export steps", words = "Hide the export steps"),
    EXPORT_BACKUP("export an encrypted backup", words = "Export an encrypted backup"),
    EXPORT_CSV("export a CSV", words = "Export a CSV file"),
    EXPORT_COUNT("items in the export"),
    EXPORT_FILES("include attached files"),
    EXPORT_PASSPHRASE("backup passphrase", words = "Backup passphrase"),
    EXPORT_PASSPHRASE_AGAIN("backup passphrase again", words = "Type it again"),
    EXPORT_CHOOSE_PLACE("choose where to save it", words = "Choose where to save it"),
    ATTACHMENTS("files", words = "Files"),
    ATTACHMENT_SAVE("save to device", words = "Save a copy"),
    ATTACHMENT_ADD("add a file", words = "Add a file"),
    ATTACHMENT_REMOVE("remove", words = "Remove"),
    ATTACHMENT_LIMITS("used, per-file limit, per-item limit"),
    ATTACHMENT_UPLOADING("sending files"),
    ATTACHMENT_NOT_WRITTEN("the file could not be written there", words = "The file couldn't be saved there. Try another place."),
    ATTACHMENT_NOT_READ("the picked file could not be read", words = "andvari couldn't read that file."),
    COPYING("copying items"),
    HELD_ITEM_COUNT("items"),
    HELD_COPY_TO_PERSONAL("copy its items to your personal vault", words = "Copy its items to your personal vault"),
    HELD_REMOVE_CONFIRM("remove this device's copy? the server is not told", words = "Remove this vault's copy from this device? Nothing is sent to the server."),
    MOVE_OR_COPY("move or copy to another vault", words = "Move or copy to another vault"),
    MOVE_NO_TARGETS("no other vault can take it", words = "There's no other vault this item can go to."),
    COPY_TO_VAULT("copy here", words = "Copy here"),
    MOVE_TO_VAULT("move here", words = "Move here"),
    TRASH_RESTORE("restore", words = "Restore"),
    TRASH_PURGE("delete forever", words = "Delete forever"),
    TRASH_PURGE_CONFIRM("delete forever, now", words = "Delete it forever now"),
    ITEM_CARDHOLDER("cardholder", words = "Name on card"),
    ITEM_EXP_MONTH("expiry month (or MM/YY)", words = "Expiry month (MM, or MM/YY)"),
    ITEM_EXP_YEAR("expiry year", words = "Expiry year"),
    ITEM_POSTAL_CODE("postal code", words = "ZIP or postal code"),
    ITEM_EDIT("edit"),
    ITEM_NAME("name", words = "Name"),
    ITEM_USERNAME("user name", words = "Username"),
    ITEM_GENERATE("generate a password", words = "Generate a password"),
    ITEM_ADDRESS("web address", words = "Website"),
    ITEM_TOTP("one-time code key (otpauth:// or base32)", words = "One-time code setup key (otpauth:// link or text)"),
    ITEM_VAULT("save in", words = "Save in"),
    ITEM_SHARED_VAULT_SEES("everyone in this vault will see it", words = "Everyone in this vault will see it."),
    ITEM_SAVE("save", words = "Save"),
    SHARED_VAULTS("shared vaults", words = "Shared vaults"),
    PEOPLE("people", words = "People"),
    DEVICES("your devices", words = "Your devices"),
    SETTINGS("settings", words = "Settings"),
    SHARING("sharing: shared vaults, people, links", words = "Sharing"),
    ACCOUNT_ID("your account ID"),
    SERVER_SECTION("server", words = "Server"),
    PROMPTS("waiting for your answer", words = "Waiting for your answer"),
    UPDATE_REQUIRED("update required: this build is too old for this server; update andvari. Until then this device's copy is read-only: you can read and fill from it, but not change it", words = "This server needs a newer version of andvari. Update andvari to keep using it. Until then, what's on this device stays readable: you can read it and fill from it, but not change it."),
    OPEN_SITE_REFUSED("not opened: the address carries a user name or password before the host, which can hide where it really goes", words = "andvari didn't open this address. It has a user name or password in front of the site's name, which can hide where it really goes."),
    TRY_AGAIN("try again", words = "Try again"),

    // ---- quick unlock, two-step sign-in, the policy, a kit after a move ----
    TURN_ON("turn on", words = "Turn on"),
    TURN_OFF("turn off", words = "Turn off"),
    CLOSE("close", words = "Close"),
    LATER("later", words = "Later"),
    QUICK_UNLOCK_BUTTON("unlock with fingerprint or face", words = "Unlock with fingerprint or face"),
    QUICK_UNLOCK_USE_PASSWORD("enter your master password: quick unlock needs it this time", words = "Enter your master password. Quick unlock needs it this time."),
    QUICK_UNLOCK_TURNED_OFF("quick unlock is off now; turn it on again in Settings", words = "Quick unlock is off, because the fingerprints or face on this device changed. You can turn it on again in Settings."),
    QUICK_UNLOCK_TITLE("quick unlock", words = "Quick unlock"),
    QUICK_UNLOCK_OFFER("offer: unlock with fingerprint or face next time", words = "Unlock with your fingerprint or face next time?"),
    QUICK_UNLOCK_UNAVAILABLE("quick unlock: no strong fingerprint or face on this device", words = "This device has no fingerprint or face unlock that andvari can use. A screen lock code isn't enough."),
    QUICK_UNLOCK_NOT_ALLOWED("quick unlock: your server does not allow it", words = "Quick unlock isn't allowed: your server doesn't permit it, or this device hasn't checked your server's rules for a week."),
    QUICK_UNLOCK_OFF("quick unlock is off", words = "Quick unlock is off."),
    QUICK_UNLOCK_ON("quick unlock is on", words = "Quick unlock is on."),
    AUTOFILL_TRUST_TITLE("autofill: browsers trusted and apps remembered on this device", words = "Autofill on this device"),
    AUTOFILL_TRUST_NONE("no browser trusted and no app remembered", words = "No browser is trusted and no app is remembered yet."),
    AUTOFILL_TRUSTED_BROWSER("browser trusted to fill on this device (name)"),
    AUTOFILL_REMEMBERED_APP("app that fills its own logins without asking (package)"),
    AUTOFILL_REVOKE("revoke", words = "Remove"),
    TWO_STEP_TITLE("two-step sign-in", words = "Two-step sign-in"),
    TWO_STEP_OPEN("show two-step sign-in", words = "Show two-step sign-in"),
    TWO_STEP_ON("two-step sign-in is on", words = "Two-step sign-in is on."),
    TWO_STEP_OFF("two-step sign-in is off", words = "Two-step sign-in is off."),
    TWO_STEP_SCAN("scan this with your authenticator app", words = "Scan this with your authenticator app."),
    TWO_STEP_TYPE_KEY("or type this key", words = "Or type this key:"),
    TWO_STEP_KEY_GONE("the key's ten minutes are up: close and turn it on again for a new key", words = "This key has expired: it lasts 10 minutes. Close this, then turn two-step sign-in on again for a new key."),
    POLICY_AUTO_LOCK("locks after N idle seconds (server policy)", words = "Locks after {0} seconds without use, as your server sets."),
    POLICY_CLIPBOARD("clears a copied secret after N seconds (server policy)", words = "Clears a copied password after {0} seconds, as your server sets."),
    POLICY_NOT_READ("the server's policy has not been read yet", words = "andvari hasn't read your server's rules yet."),
    KIT_AFTER_MOVE("the server moved: make a new recovery kit", words = "This server has moved, and your recovery kit names its old address. Make a new recovery kit."),
    KIT_AFTER_MOVE_MAKE("make a new kit", words = "Make a new kit"),
    CHANGE_PASSWORD("change master password", words = "Change master password"),
    CHANGE_PASSWORD_EFFECT("every other session ends; your recovery kit and any operator recovery stay valid", words = "This signs you out on your other devices. Your recovery kit, and operator recovery if you use it, keep working."),
    DEVICE_THIS_ONE("this device", words = "This device"),
    DEVICE_JOINED_REGISTERED("joined: created the account", words = "Created the account"),
    DEVICE_JOINED_PASSWORD("joined: signed in with the password", words = "Signed in with the master password"),
    DEVICE_JOINED_LINKED("joined: linked from (device)", words = "Linked from {0}"),
    DEVICE_JOINED_RECOVERED("joined: through a recovery", words = "Added through a recovery"),
    DEVICE_JOINED_NOT_KNOWN("joined: not known", words = "How it joined isn't known"),
    DEVICE_LIVE("signed in (added, last seen, version)"),
    DEVICE_NOT_LIVE("signed out (added, last seen, version)"),
    DEVICE_REVOKE("sign this device out", words = "Sign this device out"),
    DEVICE_REQUIRE_LINK_TITLE("the setting's name: new devices must be linked", words = "New devices must be linked"),
    DEVICE_REQUIRE_LINK_BODY("what the setting does: a new device joins only by a link from one already used; a kit recovery still works and turns it off", words = "When this is on, a new device can join your account only by being linked from one you already use. Recovering with your recovery kit still works, and turns this off."),
    DEVICE_REQUIRE_LINK_ON("require new devices to be linked from one of mine", words = "Turn on"),
    DEVICE_REQUIRE_LINK_OFF("stop requiring new devices to be linked", words = "Turn off"),
    DEVICE_REQUIRE_LINK_UNKNOWN("new devices must be linked from one of mine: not known on this device (the server does not say); choose on or off", words = "This device doesn't know whether it's on, because the server doesn't say. Choose on or off."),
    DEVICE_REQUIRE_LINK_IS_ON("new devices must be linked from one of mine: on", words = "It's on."),
    DEVICE_REQUIRE_LINK_IS_OFF("new devices must be linked from one of mine: off", words = "It's off."),
    DEVICE_ADD("add a device", words = "Add a device"),
    DEVICE_LINK_TIME_LEFT("time left (seconds)", words = "{0} seconds left"),
    LINK_TIME_LEFT("a link's time left (minutes:seconds)"),
    DEVICE_LINK_QR("the link as a QR code, for the new device to scan", words = "QR code for your new device to scan"),
    DEVICE_LINK_AS_TEXT("or paste this link on the new device's Link from your other device screen", words = "Or, on the new device, open andvari → Sign in → Link from your other device and paste this link."),
    DEVICE_LINK_COPY("copy the link", words = "Copy"),
    DEVICE_LINK_WRONG_PASSWORD("the master password is wrong; nothing was approved", words = "That master password isn't right. Nothing was approved, and the new device is still waiting: try again."),
    DEVICE_LINK_CHANGED_ELSEWHERE("the master password was changed on another device meanwhile; nothing was approved", words = "Your master password was changed on another device meanwhile. Nothing was approved."),
    DEVICE_LINK_APPROVED_NEXT("the new device now asks for your master password; it shows in Your devices once it has signed in", words = "The new device shows in Your devices once it has signed in."),
    DEVICE_LINK_DIGITS_DIFFERED("the digits typed here were not the ones the new device showed", words = "The digits typed here weren't the ones the new device showed."),
    DEVICE_LINK_EXPIRED("the link ran out of time; nothing was linked", words = "The link ran out of time, and nothing was linked. To add the device, start again."),
    DEVICE_LINK_DID_NOT_CHECK_OUT("the new device's answers did not check out, so the link was stopped; nothing was linked", words = "The new device's answer didn't pass andvari's checks, so andvari stopped the link. Nothing was linked."),
    DONE("done", words = "Done"),
    DEVICE_LINK_CLAIMED("a new device picked up the link (name, platform)", words = "A new device opened the link: {0} ({1})."),
    DEVICE_LINK_APPROVE("approve adding (name, platform)"),
    DEVICE_LINK_APPROVE_BUTTON("approve", words = "Add this device"),
    DEVICE_LINK_APPROVE_BIOMETRIC("approve with fingerprint or face", words = "Approve with fingerprint or face"),
    DEVICE_LINK_APPROVED("approved, waiting for the new device's password", words = "Approved. Now enter your master password on {0}."),
    VAULT_YOU("you", words = "You"),
    VAULT_OWNER("owner", words = "Owner: {0}"),
    VAULT_LOG_STATE("history state without wording"),
    VAULT_REMOVED_BY_OWNER("the owner removed you from this vault", words = "The owner removed you from this vault."),
    VAULT_REMOVED_UNVERIFIED("you no longer have this vault (not verified as the owner's act)", words = "You no longer have this vault. andvari couldn't confirm that its owner removed you."),
    VAULT_DELETED_IN_GRACE("deleted; can be restored until", words = "Deleted. It can be restored until {0}."),
    VAULT_HELD_UNTIL("this device keeps a copy until", words = "This device keeps a copy until {0}."),
    /** To a member who is neither the owner nor the person offered: {0} is the person offered. */
    VAULT_OFFER("ownership offered to", words = "{0} has been asked to become this vault's owner."),
    /** To the person offered. */
    VAULT_OFFER_TO_YOU("you were offered this vault's ownership", words = "You've been asked to become this vault's owner. As its owner you would manage its members, and only you could rename it, hand it over or delete it."),
    VAULT_ACCEPT_OWNERSHIP("accept ownership", words = "Become the owner"),
    VAULT_CANCEL_OFFER("cancel the offer", words = "Cancel the offer"),
    VAULT_MEMBERS("members", words = "Members"),
    VAULT_MEMBERS_OF("members of", words = "Members of “{0}”"),
    /** Where a sentence names a vault this phone knows no name for: not a name, so never in the sentence's quotes. */
    VAULT_NAME_IN_LINE_NOT_KNOWN("a vault whose name this phone does not know", words = "a vault whose name this device doesn't know"),
    VAULT_REMOVE_MEMBER("remove", words = "Remove"),
    VAULT_OFFER_OWNERSHIP("offer ownership", words = "Make owner"),
    VAULT_ADD_MEMBER("add someone", words = "Add someone"),
    VAULT_ADD_THIS_PERSON("add (person) as a reader", words = "Add {0} as a reader"),
    VAULT_RESTORE("restore", words = "Restore"),
    VAULT_DELETE("delete this vault", words = "Delete this vault"),
    VAULT_LEAVE("leave this vault", words = "Leave this vault"),
    VAULT_SAVE_ELSEWHERE("save its items in my own vault", words = "Copy its items to your personal vault"),
    VAULT_NAME_FIELD("vault name", words = "Vault name"),
    VAULT_CREATE("create a shared vault", words = "Create a shared vault"),
    MOVE_CONNECT_FIRST("connect with this person first", words = "Connect with this person first."),
    MOVE_PROGRESS("copied (n) of (total)", words = "Copied {0} of {1}"),
    MOVE_REMOVING("being removed, and not added to the new vault", words = "{0} is removed from the old vault first, and isn't added to the new vault."),
    MOVE_STOPPED_REMOVING_MEMBER("the move stopped while removing the member from the old vault", words = "The move stopped while removing the member from the old vault."),
    MOVE_STOPPED_MAKING_VAULT("the move stopped while making the new vault", words = "The move stopped while making the new vault."),
    MOVE_STOPPED_COPYING("the move stopped while copying the items", words = "The move stopped while copying the items."),
    MOVE_STOPPED_ADDING_MEMBERS("the move stopped while adding the members to the new vault", words = "The move stopped while adding the members to the new vault."),
    MOVE_STOPPED_DELETING_OLD("the move stopped while deleting the old vault", words = "The move stopped while deleting the old vault."),
    MOVE_FINISHED_INTO("moved into the new vault (vault), items copied (n)", words = "Done. {1} items are in “{0}” now."),
    MOVE_FINISH("finish the move", words = "Finish the move"),

    /** The button under [io.silencelen.andvari.core.app.SharedVaultRow.frozenMoveClose], the shared code's line of what it does. */
    MOVE_FROZEN_CLOSE_BUTTON("close this move"),

    // ---- a change to a shared vault that waits: what the change is (the shared code's line says how it stands) ----
    WAITING_KIND_ADD("this change adds a member: (person), as (role)"),
    WAITING_KIND_REMOVE("this change removes a member: (person)"),
    WAITING_KIND_ROLE("this change gives a member another role: (person), from (role now) to (new role)"),
    WAITING_KIND_ROLE_TO("this change gives a member another role: (person), to (new role)"),
    WAITING_KIND_OFFER("this change offers a member the vault's ownership: (person)"),

    // ---- an undo of a change found made after all, where the member or the vault it names is not there now ----
    WAITING_UNDO_MEMBER_NOT_LISTED("they are not a member of this vault now; nothing was changed"),
    WAITING_UNDO_CONTACT_NOT_HERE("they are not a contact on this device; nothing was changed"),
    WAITING_UNDO_VAULT_GONE("this vault is not on this device now; nothing was changed"),
    ROLE_CHANGE_ASK("change this person's role? (person), (new role)", words = "Make {0} a {1}?"),
    ROLE_CHANGE_CONFIRM("change role", words = "Change role"),
    ROLE_WRITER_ALLOWS("a writer can add, change and delete this vault's items", words = "A writer can add, change and delete the items in this vault."),
    ROLE_READER_ALLOWS("a reader can see this vault's items but not change them", words = "A reader can see the items in this vault but can't change them."),
    LINKS("links", words = "Links"),
    LINK_LIFETIME("how long the link works", words = "How long the link works"),
    LINK_MINUTES("minutes"),
    LINK_ROLE_SWITCH("switch between reader and writer", words = "Change role"),
    LINK_CREATE("make a connect link", words = "Make a connect link"),
    LINK_KIND_CONNECT("connect link (vaults to share)"),
    LINK_KIND_INVITATION("invitation (vaults to share)"),
    LINK_SHARE("share", words = "Share"),
    LINK_COPY("copy", words = "Copy"),
    LINK_REVOKE("revoke", words = "Cancel this link"),
    LINK_ANSWERED("answered by (person)"),
    LINK_ANSWERED_KEY_CHANGED("answered by (person), whose key changed"),
    LINK_RELEASE_SHARE("share now", words = "Share now"),
    LINK_CONNECTED("connected with (person)", words = "You're connected with {0}."),
    CONTACT_COMPARED("(person): codes compared"),
    CONTACT_NOT_COMPARED("(person): codes not compared yet"),
    CONTACT_REMOVE("remove this person", words = "Remove this person"),
    COMPARE_WAITING("waiting: no code exists yet", words = "Waiting for the code…"),
    COMPARE_OWN_CODE_REFUSED("that is your own code: type the one they read out", words = "That's your own code. Type the one they read to you."),
    COMPARE_LINK_FAILED("the connection could not be checked", words = "The connection couldn't be checked, so andvari didn't use it. Connect again with a new link."),
    COMPARE_MATCHED("the codes match", words = "The codes match."),
    RECOVERY_SETTINGS("recovery", words = "Recovery"),
    RECOVERY_ME_OR_OPERATOR("you or the operator can recover this account", words = "You or the operator can recover this account."),
    RECOVERY_REQUEST_ROW("request (stage, asked, hold ends, platform as reported)", words = "Request for help: {0} · asked {1} · wait ends {2} · from {3}, as that device reported it"),
    DELETE_ACCOUNT("delete account", words = "Delete account"),
    DELETION_WHAT_GOES("deleting the account deletes it on the server with every device's sign-in, its recovery kit, and links it made that nobody used; and on this phone, its copy", words = "Deleting your account removes it from the server for good, with your personal vault and every vault nobody else is in. Every device is signed out, your recovery kit and any operator recovery stop working, and links you made that nobody used stop working too. The copy on this device is removed."),
    DELETION_VAULT_GOES("deleted with the account: (vault)", words = "Deleted for good: “{0}”"),
    DELETION_VAULT_GOES_UNREADABLE("deleted with the account: a vault whose name this phone cannot read", words = "Deleted for good: a vault whose name can't be read on this device"),
    DELETION_VAULT_LEFT("left, with a signed leave; what you saved there stays for the others: (vault)", words = "You'll leave “{0}”. What you saved there stays for the others in it."),
    DELETION_VAULT_LEFT_UNREADABLE("left, with a signed leave: a shared vault whose name this phone cannot read", words = "You'll leave a shared vault whose name can't be read on this device. What you saved there stays for the others in it."),
    DELETION_CANNOT_UNDO("this cannot be undone", words = "This can't be undone."),
    DELETION_BLOCKER_SHARED("blocker: a shared vault others hold (vault, others)", words = "You own “{0}”, which {1} others also have. Hand it over, or remove them, first."),
    DELETION_BLOCKER_SHARED_UNREADABLE("blocker: a shared vault others hold, whose name this phone cannot read (others)", words = "You own a shared vault whose name can't be read on this device, and {0} others also have it."),
    DELETION_BLOCKER_SHARED_DO("first: delete that vault, or hand it over to one of its members, in its settings", words = "In that vault's settings, choose Delete this vault, or make one of its members the owner."),
    DELETION_BLOCKER_OPERATOR("blocker: this is the operator account", words = "This is the operator account. Hand the server over to another account first."),
    DELETION_BLOCKER_OPERATOR_DO("first: make another account the operator, from the desktop app or andvari-cli", words = "In the andvari desktop app or andvari-cli, make another account the operator."),
    DELETION_BLOCKER_UNKNOWN("blocker this build cannot explain", words = "Something stops this account being deleted that this version of andvari can't explain. Update andvari and try again."),
    DELETION_BLOCKER_UNKNOWN_DO("first: update andvari, or ask whoever runs your server", words = "Update andvari, or ask the operator."),
    DELETION_TYPE_EMAIL("to confirm, type this account's email address (email)", words = "To confirm, type your email address, {0}."),
    DELETION_RUNNING("deleting the account", words = "Deleting your account…"),
    DELETION_RETRYING("a vault's history moved on; retrying by itself, nothing was deleted", words = "A shared vault changed meanwhile, so andvari is trying again. Nothing has been deleted."),
    DELETION_OUTCOME_UNKNOWN("andvari can't tell yet whether the account was deleted: the answer never came", words = "The server didn't answer, so your account may have been deleted."),
    DELETION_CHECK("check whether the account still exists", words = "Check whether the account still exists"),
    DELETION_CHECKED_STILL_THERE("the account is still there; nothing was deleted", words = "Your account is still there. Nothing was deleted."),
    DELETION_EMAIL_MISMATCH("that is not this account's email address; nothing was deleted", words = "That isn't this account's email address. Nothing was deleted."),
    DELETION_WRONG_PASSWORD("the master password is wrong; nothing was deleted", words = "That master password isn't right. Nothing was deleted."),
    DELETION_CODE_NEEDED("this account has two-step sign-in: type the current code; nothing was deleted", words = "This account uses two-step sign-in. Enter the code from your authenticator app. Nothing was deleted."),
    DELETION_WRONG_CODE("the two-step code is wrong or was used already; nothing was deleted", words = "That code isn't right, or it was already used. Wait for the next one and try again. Nothing was deleted."),
    DELETION_BLOCKED("something now stands in the way (listed above); nothing was deleted", words = "Something now stands in the way, listed above. Nothing was deleted."),
    DELETION_STILL_CHANGING("your shared vaults kept changing while andvari tried; nothing was deleted; try again", words = "Your shared vaults kept changing, so nothing was deleted. Try again."),
    DELETION_CHANGED_ELSEWHERE("the master password was changed on another device meanwhile; nothing was deleted", words = "Your master password was changed on another device meanwhile. Nothing was deleted. Sign in again with the new one."),
    DELETION_CANNOT_TELL("andvari can't tell yet whether your account was deleted; this phone keeps its copy; sign in again to find out", words = "The server signed this device out while your account was being deleted, so andvari can't tell whether it was deleted. The copy on this device is kept. Sign in again to find out: if your account still exists, you can."),
    LOCK_DELETION_OUTCOME_UNKNOWN("we cannot tell yet whether your account was deleted", words = "andvari asked the server to delete your account and got no answer, so it can't tell yet whether your account was deleted."),
    KIT_COVERED("the kit was hidden when andvari went to the background", words = "andvari hid your kit while it was in the background. Choose Show the kit again to see it."),
    SAVED_SIGN_IN_UNREADABLE("this device's saved sign-in can't be read right now; it is kept, and andvari reads it again at its next start (signing in again replaces it)", words = "andvari couldn't read the sign-in saved on this device. Sign in again to use your account here."),

    // ---- a second account while a server-ended one is kept ----
    KEPT_ACCOUNT_SIGN_OUT_FIRST("this phone keeps another account that its server signed out: sign out of it first (account, server, address)"),
    KEPT_ACCOUNT_PASSWORD_IN_FORCE("your new master password is in force, but this phone keeps another account that its server signed out: sign out of it, then sign in with the new password (account, server, address)"),
    KEPT_ACCOUNT_SIGN_OUT_FIRST_NOT_CONFIRMED("this phone keeps another account whose session it could not confirm with its server in time (nothing was sent again, so no other session ended): sign out of it first (account, server, address)"),
    KEPT_ACCOUNT_PASSWORD_IN_FORCE_NOT_CONFIRMED("your new master password is in force, but this phone keeps another account whose session it could not confirm with its server in time: sign out of it, then sign in with the new password (account, server, address)"),
    FORGET_UNKNOWN_DELETION_CONFIRM("the button of the second step: forget this account on this phone now (the server is kept)"),
    KEPT_ACCOUNT_SIGN_OUT("sign out of that account", words = "Sign out of that account"),
    KEPT_ACCOUNT_SIGN_OUT_WARNING("signing out deletes this phone's copy of (account) on (server, address), with any changes not yet sent; it cannot be undone"),

    // ---- the ways out of the keeper's own stops, and a kit that came with a refusal ----
    COPY_REMOVE("remove this phone's copy of the account (it says first how many changes were not sent, or that it cannot tell)"),
    COPY_REMOVE_WARNING("removing deletes this phone's copy of (account) on (server, address), with any changes not yet sent; it cannot be undone; then sign in, or recover the account, again"),
    SIGN_IN_CODE_STEP_SPENT("this two-step step has ended: the server will not take another code for it; start the sign-in again with your master password"),
    SIGN_IN_START_AGAIN("start the sign-in again"),
    DELETION_CANNOT_TELL_NO_COPY("andvari can't tell yet whether your account was deleted; this phone keeps no copy of it; sign in again to find out: if your account still exists, you can"),

    // ---- changing the master password ----
    PASSWORD_CHANGE_WRONG("the current master password is wrong; nothing changed", words = "That master password isn't right. Nothing was changed."),
    PASSWORD_CHANGE_WEAK("the new master password is too weak; nothing was sent", words = "The new master password is too weak. Choose a longer one. Nothing was sent."),
    PASSWORD_CHANGE_CHANGED_ELSEWHERE("the master password was changed on another device or by a recovery meanwhile; nothing changed here", words = "Your master password was changed on another device, or by a recovery, while you were changing it here. Nothing was changed here. Sign in again with the new one."),
    PASSWORD_CHANGE_NO_ANSWER("the server did not answer; try again", words = "The server didn't answer, so andvari can't tell whether your master password changed. Next time you sign in, try the new one. If it doesn't work, the old one still does."),
    PASSWORD_CHANGED("master password changed; your other devices were signed out", words = "Your master password is changed. Your other devices were signed out. They need the new master password to sign in again."),
    PASSWORD_CHANGED_NO_KIT("no new recovery kit: the one you have stays valid, and so does any operator recovery", words = "Your recovery kit, and operator recovery if you use it, still work. You don't need a new kit."),
    PASSWORD_CHANGED_THIS_PHONE("this phone opens with the new master password from now on; the old one no longer opens it", words = "andvari on this device opens with the new master password from now on. The old one no longer opens it."),
    PASSWORD_CHANGED_QUICK_UNLOCK("quick unlock after the change:"),

    // ---- work a lock overtook ----
    LOCK_OVERTOOK("not done: andvari locked before this finished; do it again once unlocked", words = "andvari locked before this was done. Do it again once you've unlocked."),
    // The same throw and the same STALE come when the SERVER ended the session: said as that, never as a lock.
    SESSION_ENDED_OVERTOOK("not done: the server ended this phone's session before this finished; it cannot be done again in this session (the screen says what you can do now)"),
    // The same throw and STALE after the person's OWN end here (a sign-out, the account's deletion, "Forget this server",
    // the switch to another server's invitation): the server ended nothing, so the line says the work was not done.
    PERSON_ENDED_OVERTOOK("not done: this was still under way when you signed out, deleted the account, forgot the server or switched to another server here; nothing of it was done"),
    // At the autofill window's unlock, where the work overtaken is the unlock itself.
    UNLOCK_NOT_FINISHED("not opened: the unlock did not finish; unlock again"),

    // ---- a fault the app contained ----
    VAULT_WENT_WRONG("something went wrong with this vault; your other vaults and the rest of andvari still work", words = "Something went wrong with this vault. Your other vaults and the rest of andvari still work."),
    WENT_WRONG("something went wrong here; nothing else is affected, and you can try again", words = "Something went wrong here. Nothing else is affected, and you can try again."),

    // ---- found by looking at the drawn screens ----
    UNLOCK_WRONG_PASSWORD("the master password is wrong", words = "That master password isn't right."),
    /** A line under a shared vault not accepted yet (it must connect or confirm first); never its name. */
    VAULT_NAME_NOT_KNOWN("a shared vault whose name you will see once you accept it", words = "You'll see this vault's name once you accept it."),
    /** In place of a shared vault's name (the row's head, the page's top bar, its settings) where this device knows none. */
    VAULT_NAME_NOT_KNOWN_TITLE("a vault whose name this device does not know, as its name", words = "A vault whose name this device doesn't know"),

    // ---- a request's stage in Settings › Recovery's list of live requests, which may be a stranger's: a stage's name only ----
    RECOVERY_ROW_STAGE_HOLDING("the request is in its wait", words = "In its wait"),
    RECOVERY_ROW_STAGE_AWAITING_OPERATOR("the request's wait is over and it waits for the operator", words = "Waiting for the operator"),
    LINK_CODE_TYPE_THERE("type these digits on your other device", words = "Type these digits on your other device."),

    // ---- no internal name on a screen: each outcome its own placeholder ----
    /** The kind of an outcome's own placeholder; the gloss shown is the outcome's ([OutcomeWords]). */
    OUTCOME("outcome without approved words"),
    TROUBLE_STALE("this screen was out of date, so nothing was done: look again and retry", words = "This screen was out of date, so nothing was done. Look again, then try again."),
    TROUBLE_UNREACHABLE("the server did not answer: check the connection and try again", words = "The server didn't answer. Check your connection and try again."),
    TROUBLE_RATE_LIMITED("the server asks you to wait before trying again (seconds)", words = "The server asks you to wait {0} seconds before trying again."),
    // A wait the server named, as a length of time inside a sentence of the shared code's ([OutcomeWords.waitLength]).
    WAIT_A_WHILE("a wait the server did not name: a while"),
    WAIT_ONE_SECOND("a wait of one second"),
    WAIT_SECONDS("a wait in seconds (n)"),
    WAIT_ONE_MINUTE("a wait of one minute"),
    WAIT_MINUTES("a wait in whole minutes, rounded up (n)"),
    WAIT_ONE_HOUR("a wait of one hour"),
    WAIT_HOURS("a wait in whole hours, rounded up (n)"),
    TROUBLE_UPDATE_REQUIRED("this build is too old for this server: update andvari", words = "This version of andvari is too old for this server. Update andvari."),
    TROUBLE_FAILED("that did not work: try again", words = "That didn't work. Try again."),
    CONNECTION_NOT_MADE("your answer to this person's link did not reach them: only a new link from them helps (person, why)"),
    CONNECTION_NOT_MADE_RETRY("your answer to this person's link was not sent yet: you can send it again (person, why)"),

    // ---- found by looking at the drawn screens, fixed ----
    BACK_TO_VAULT("back to your vault", words = "Back to your vault"),
    KIND_CHANGE_PUT_OFF("put off: andvari asks about this server's change again the next time you unlock; until then the server's old kind stays in force", words = "andvari asks about this server's change again the next time you unlock. Until then, the server's old kind stays in force."),
    KIND_CHANGE_ANSWER_NOW("answer it now", words = "Answer it now"),
    TIME_NOT_KNOWN("not known", words = "Not known"),
    ADDRESS_YOU_TYPED("the address you typed", words = "The address you typed"),
    ADDRESS_THE_LINK_NAMES("the address the link names", words = "The address in the link"),
    ADDRESS_DEVICE_LINK_NAMES("the address your other device's link names", words = "The address in your other device's link"),
    ADDRESS_THE_KIT_NAMES("the address your recovery kit names", words = "The address on your recovery kit"),
    ADDRESS_CARD_NAMES("the address the server's identity card gave", words = "The address on the server's identity card"),
    CARD_SEQ("the server's identity card, number (n) in its chain", words = "Identity card number {0}"),
    LINK_LIFETIME_IN_PERSON("for while you are together: (n) minutes", words = "{0} minutes, while you're together"),
    LINK_LIFETIME_MINUTES("(n) minutes", words = "{0} minutes"),
    LINK_LIFETIME_HOURS("(n) hours", words = "{0} hours"),
    LINK_LIFETIME_A_DAY("a day", words = "1 day"),
    LINK_LIFETIME_DAYS("(n) days, the longest", words = "{0} days, the longest"),

    // ---- the screens follow the current app's structure ----
    ITEM_ADD("add", words = "Add"),
    KIND_LOGIN("login", words = "Login"),
    KIND_CARD("card", words = "Card"),
    KIND_NOTE("secure note", words = "Secure note"),
    KIND_OTHER("item", words = "Item"),
    ITEM_EXPIRY("expiry", words = "Expiry"),
    ITEM_KEEP("keep", words = "Keep"),

    // ---- what a login's view and a card's view and editor show, as the current app's ----
    ITEM_HEALTH_STRENGTH("strength of the password", words = "Password strength: {0}"),
    ITEM_HEALTH_LAST_USED("last used on", words = "Last used {0}"),
    ITEM_HEALTH_NO_USE_RECORD("no use of it recorded", words = "No use recorded yet"),
    ITEM_EXPIRED("expired", words = "Expired"),

    // ---- the vault, an item and the editors drawn beside the current app ----
    VAULT_NO_MATCH("nothing matches", words = "Nothing matches."),
    VAULT_BACKUP("vault backup", words = "Vault backup"),
    ITEM_VIEW_ONLY("view only", words = "View only"),
    ITEM_COPIED("copied", words = "Copied"),
    ITEM_COPIED_NOTE("copied: andvari clears it in (n) seconds while open; your device hides it from other apps", words = "Copied. andvari clears it in {0} seconds while it's open, and your phone hides it from other apps."),
    ITEM_CODE_TAP_TO_COPY("one-time code: double-tap to copy", words = "One-time code. Double-tap to copy."),
    ITEM_CANCEL("cancel", words = "Cancel"),
    ITEM_DISCARD_TITLE("discard changes?", words = "Discard your changes?"),
    ITEM_DISCARD_BODY("anything typed in this editor will be lost", words = "What you typed here hasn't been saved and will be lost."),
    ITEM_DISCARD("discard", words = "Discard"),
    ITEM_KEEP_EDITING("keep editing", words = "Keep editing"),
    ITEM_GENERATE_REPLACE("replace it?", words = "Replace it?"),
    STORAGE("your account's storage on this server", words = "Your space on this server"),
    STORAGE_BYTES("stored: (used) of (limit)"),
    STORAGE_ITEMS("items: (used) of (limit)"),
    STORAGE_SHARED_VAULTS("shared vaults you own: (used) of (limit)"),
    STORAGE_LINKS("open links: (used) of (limit)"),
    ITEM_GENERATE_REPLACE_NOTE("this replaces the password typed here: tap again to confirm, or change the field to cancel", words = "This replaces the password typed here. Tap again to confirm, or change the field to cancel."),

    // ---- the list's rows as the current app has them ----
    LIST_SORT_NAME("sort: name", words = "Sort: name"),
    LIST_SORT_RECENT("sort: recently updated", words = "Sort: recently updated"),
    LIST_BY_NAME("name", words = "Name"),
    LIST_BY_RECENT("recently updated", words = "Recently updated"),
    LIST_ALL_TYPES("all types", words = "All types"),
    LIST_LOGINS("logins", words = "Logins"),
    LIST_NOTES("notes", words = "Notes"),
    LIST_CARDS("cards", words = "Cards"),
    LIST_ALL_VAULTS("all vaults", words = "All vaults"),
    LIST_SHARED_VAULT("shared vault", words = "Shared vault"),
    TRASH_DELETED_ON("deleted", words = "Deleted {0}"),
    TRASH_NOT_READ_YET("not read yet; restore reads it first", words = "Not read yet. Restore reads it first."),
    TRASH_UNREADABLE("no readable version: it can only be deleted forever", words = "No version of this item can be read, so it can only be deleted forever."),

    // ---- two-step sign-in asks for the master password ----
    TWO_STEP_NEW_KEY("get a new key for the authenticator app", words = "Get a new key for your authenticator app"),
    /** The wait after too many tries, said alone: it replaces the shared code's sentence, which says the same without the time. */
    TWO_STEP_WAIT("try again in (seconds) seconds", words = "Too many tries. Wait {0} seconds, then try again."),

    // ---- a count of one: each line for one beside the line for several (copy page, PQ17), chosen by [counted] ----
    TWO_STEP_WAIT_ONE("too many tries: wait one second", words = "Too many tries. Wait 1 second, then try again."),
    TROUBLE_RATE_LIMITED_ONE("the server asks you to wait one second", words = "The server asks you to wait 1 second before trying again."),
    HEALTH_REUSED_ONE("also used by one other login", words = "Also used by 1 other login"),
    HEALTH_BREACHED_ONE("seen in one breach", words = "Seen in 1 breach"),
    POLICY_AUTO_LOCK_ONE("locks after one idle second (server policy)", words = "Locks after 1 second without use, as your server sets."),
    POLICY_CLIPBOARD_ONE("clears a copied secret after one second (server policy)", words = "Clears a copied password after 1 second, as your server sets."),
    DELETION_BLOCKER_SHARED_ONE("blocker: a shared vault one other person holds (vault)", words = "You own “{0}”, which 1 other person also has. Hand it over, or remove them, first."),
    DELETION_BLOCKER_SHARED_UNREADABLE_ONE("blocker: you own a shared vault whose name can't be read on this device, and one other person also has it"),
    LINK_KIND_CONNECT_ONE("connect link sharing one vault", words = "Connect link, sharing 1 vault"),
    LINK_KIND_INVITATION_ONE("invitation sharing one vault", words = "Invitation, sharing 1 vault"),
    DEVICE_LINK_TIME_LEFT_ONE("one second left"),
    MOVE_FINISHED_INTO_ONE("done: one item is in the new vault now (vault)"),
    ITEM_COPIED_NOTE_ONE("copied: andvari clears it in one second while it's open, and your phone hides it from other apps"),

    // ---- Sharing's per-vault page, as the current app's vault settings ----
    VAULT_SETTINGS("settings of the vault", words = "Settings for “{0}”"),

    // ---- an item's history on its detail, as the current app's version history ----
    HISTORY_HIDE("hide the earlier versions", words = "Hide earlier versions"),
    HISTORY_RESTORE_CONFIRM("restore this version?", words = "Restore this version?"),
    HISTORY_RESTORE_CONFIRM_BODY("the item's current version is replaced by the one from (date); the replaced version stays in its history", words = "The item's current version is replaced by the one from {0}. The replaced version stays in its earlier versions."),

    // ---- a move's deletion the server stored outside the move ----
    MOVE_STORED_COPY("copy them into the new vault", words = "Copy them into the new vault"),

    // ---- an account a hand-over made the operator, on a phone ----
    OPERATOR_HELD_REMOVE("remove this account from this phone", words = "Remove this account from this phone"),
    OPERATOR_HELD_REMOVE_CONFIRM("remove it from this phone", words = "Remove it from this phone"),
}
