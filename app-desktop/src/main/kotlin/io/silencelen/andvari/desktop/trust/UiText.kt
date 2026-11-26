package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CopyLine
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.Trouble

/**
 * What a screen of the new path says, and whose words they are (ported from the Android app).
 *
 * Every sentence the design gives comes from the app API's copy ([CopyKey], [CopyLine]) and is shown as plain text.
 * Where the design gives no words (a reserved key with an empty `english`, a refusal with no sentence, a field label or
 * a button the design does not name), the screen shows a **visible placeholder** instead: [Placeholder], rendered as
 * `⟦…⟧` in a distinct style. None of them may ship; the owner has not approved any wording for them.
 */
sealed class UiText {
    /** Words the design gives (or values the state carries, such as an origin). */
    class Plain(val text: String) : UiText()

    /** A placeholder: no approved words exist for this yet. */
    class Ph(val placeholder: Placeholder, val args: List<String>, internal val unnamed: Set<Int> = emptySet()) : UiText()

    /**
     * Core's own placeholder ([CopyKey.awaitingOwner]): its gloss in `⟦…⟧`, with the values filled in, shown in the
     * placeholder style so it reads as unfinished like the desktop's own.
     */
    class Awaiting(val text: String) : UiText()

    /** The text as shown. A placeholder is marked so nobody mistakes it for final copy. */
    fun shown(): String = when (this) {
        is Plain -> text
        is Awaiting -> text
        is Ph -> when {
            placeholder.words != null -> fillTemplate(placeholder.words, args, unnamed)
            // A draft awaiting the owner's words with its values in place, as core marks one ([CopyKey.awaitingOwner]).
            "{0}" in placeholder.gloss -> "⟦" + fillTemplate(placeholder.gloss, args, unnamed) + "⟧"
            else -> "⟦" + placeholder.gloss + (if (args.isEmpty()) "" else ": " + args.joinToString(", ")) + "⟧"
        }
    }

    val isPlaceholder: Boolean get() = (this is Ph && placeholder.words == null) || this is Awaiting

    companion object {
        /**
         * Core's words for [key]. The owner's approved words for the `SERVER_*` and `LINK_REQUIRED_*` keys now come from
         * core itself, so the desktop keeps no copy of its own; a key core still reserves is a placeholder.
         */
        fun of(key: CopyKey): UiText = when {
            key.reserved -> Ph(Placeholder.RESERVED_COPY, listOf(key.name))
            key.awaitingOwner -> Awaiting(key.english)
            else -> Plain(key.english)
        }

        fun of(line: CopyLine): UiText = when {
            line.key.reserved -> Ph(Placeholder.RESERVED_COPY, listOf(line.key.name) + line.values)
            line.key.awaitingOwner -> Awaiting(line.english)
            else -> Plain(line.english)
        }

        /** Core's words for [key] with its `{0}`, `{1}`, … filled by the app (a date it formats), as [of] a line. */
        fun filled(key: CopyKey, vararg values: String): UiText = when {
            key.reserved -> Ph(Placeholder.RESERVED_COPY, listOf(key.name) + values)
            key.awaitingOwner -> Awaiting(fillTemplate(key.english, values.toList()))
            else -> Plain(fillTemplate(key.english, values.toList()))
        }

        fun ph(p: Placeholder, vararg args: String): UiText = Ph(p, args.toList())

        /** As [ph], where some slots may hold the plain words for a name not known ([Slot]): those are not quoted. */
        internal fun phWith(p: Placeholder, vararg slots: Slot): UiText = Ph(p, slots.map { it.text }, unnamedOf(slots))

        /** The owner's approved words [id] ([ApprovedCopy]), filled with [values]. */
        fun approved(id: String, vararg values: String): UiText = Plain(ApprovedCopy.words(id, *values))

        /** Line [n] of the approved words [id]. */
        fun approvedLine(id: String, n: Int, vararg values: String): UiText = Plain(ApprovedCopy.line(id, n, *values))

        /**
         * What an intent's result says in place: null when it was done; the design's sentence when the result carries
         * one; otherwise a placeholder naming the outcome (a trouble, or the intent's own refusal).
         */
        fun forResult(result: IntentResult, retryAfterSeconds: Int): UiText? {
            if (result.done) return null
            result.sentence?.let { return of(it) }
            // The account asks for its two-step code: the screen asks for it in its own field, and nothing is refused.
            if (result === io.silencelen.andvari.core.app.SignInAnswer.CODE_NEEDED || result === io.silencelen.andvari.core.app.LinkPasswordResult.CODE_NEEDED) return null
            // Approved entry 24, first line: where the change was made.
            if (result === io.silencelen.andvari.core.app.VaultActionResult.SENT_PENDING) return approvedLine("VAULT_CHANGE_WAITING.body", 0)
            // A match the account could not record, and a move followed to an address that did not check out: each has
            // its own approved line.
            if (result === io.silencelen.andvari.core.app.ComparisonResult.NOT_SAVED) return ph(Placeholder.COMPARE_MATCHED_NOT_SAVED)
            if (result === io.silencelen.andvari.core.app.MoveResult.MOVED_NOT_VERIFIED) return ph(Placeholder.MOVE_NOT_VERIFIED)
            // A move whose data has still not reached its new address: its own line, never "result without wording".
            if (result === io.silencelen.andvari.core.app.MoveResult.NOT_FINISHED) return ph(Placeholder.MOVE_NOT_FINISHED_AGAIN)
            val name = (result as? Enum<*>)?.let { result.javaClass.simpleName + "." + it.name } ?: result.toString()
            return when (result.trouble) {
                // Refused as one of too many requests, and the shared code hands no sentence: a line of the desktop's own
                // with the wait as a length of time, never the line without wording.
                Trouble.RATE_LIMITED -> Ph(Placeholder.TROUBLE_TOO_MANY, listOf(waitText(retryAfterSeconds).shown()))
                // Said in place on the screen it was answered on, which stays usable.
                Trouble.UPDATE_REQUIRED -> Ph(Placeholder.UPDATE_REQUIRED, listOf(io.silencelen.andvari.desktop.DESKTOP_VERSION))
                // The server did not answer, and the shared code hands no sentence: a line of the desktop's own, never the
                // line without wording (every result drawn in place comes through here).
                Trouble.UNREACHABLE -> Ph(Placeholder.TROUBLE_UNREACHABLE, emptyList())
                null -> Ph(Placeholder.REFUSAL, listOf(name))
                else -> Ph(Placeholder.TROUBLE, listOf(name))
            }
        }
    }
}

/**
 * A wait the server named, in seconds, as a length of time a person reads: seconds under two minutes, then minutes, then
 * hours (each rounded up, so the wait said is never shorter than the server's); "a while" where none was named (0 or
 * less). The desktop's one helper for a wait: every line with a server's wait fills its value with this.
 */
internal fun waitText(seconds: Int): UiText = when {
    seconds <= 0 -> UiText.ph(Placeholder.WAIT_A_WHILE)
    seconds < 120 -> UiText.ph(Placeholder.WAIT_SECONDS, seconds.toString())
    seconds < 2 * 3600 -> UiText.ph(Placeholder.WAIT_MINUTES, ((seconds + 59) / 60).toString())
    else -> UiText.ph(Placeholder.WAIT_HOURS, ((seconds + 3599) / 3600).toString())
}

/** "Also used by …" under a login whose password [others] other logins share: the line for one where it is one. */
internal fun reusedLine(others: Int): UiText =
    if (others == 1) UiText.ph(Placeholder.HEALTH_REUSED_ONE) else UiText.ph(Placeholder.HEALTH_REUSED, others.toString())

/**
 * Every string of the new path the design does not give. Each is shown as `⟦gloss⟧`; the gloss says what the string
 * is for and is not proposed wording. Names are the Android
 * app's where the string is the same, so the two lists can be read side by side.
 */
enum class Placeholder(val gloss: String, val words: String? = null) {
    // ---- generic ----
    RESERVED_COPY("reserved copy key"),
    REFUSAL("result without wording"),
    TROUBLE("trouble without wording"),
    TROUBLE_UNREACHABLE("the server did not answer: check the connection and try again"),
    TROUBLE_TOO_MANY("the server refused this as one of too many requests for now: try again after (the wait); never “unreachable”"),
    BACK("back", words = "Back"),
    START_OVER("start over", words = "Start over"),
    CONTINUE("continue", words = "Continue"),
    NOT_BUILT_YET("screen not built yet in this build"),
    DISMISS("dismiss", words = "Close"),
    OPEN_SECTION("open this section", words = "Open"),
    CHECKING_PASSWORD("checking the master password; this takes a few seconds", words = "Checking your master password. This takes a few seconds."),
    NOT_NOW("not now"),
    TRY_AGAIN("try again", words = "Try again"),

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
    DISPLAY_NAME_HINT("under the name field: people you connect with see this name", words = "People you connect with see this name."),
    LINK_FIELD("paste a link here", words = "Paste the link here"),
    LINK_NAME_TITLE("title of the window that asks for the name your links carry"),
    LINK_NAME_FIELD("the name the other person will see"),
    // The eye button's name for a screen reader, with the field's name in it (the wording page's line "Show {0}").
    SHOW_FIELD_NAMED("the eye button's name for a screen reader: show (the field's name)"),
    HIDE_FIELD_NAMED("the eye button's name for a screen reader, once the field is shown: hide (the field's name)"),

    // ---- first screen and entry ----
    NOTICE_SIGNED_OUT_BY_SERVER("notice: the server ended this device's session", words = "The server signed this device out. That happens when this device is removed from your account, when your master password is changed or reset on another device, or when the operator turns your account off. To use your account here, sign in again."),
    NOTICE_OPERATOR_NEEDS_COMPUTER("notice: this account now runs the server and must sign in on a computer", words = "This is the server's operator account. It can only be used in the andvari desktop app or in andvari-cli, so andvari doesn't keep it on this phone."),
    RESUME_OPERATOR_HELP("resume the request for the operator's help", words = "Check on your request for help"),
    SUBMIT_ADDRESS("connect", words = "Connect"),
    SEND_CODE("send code", words = "Send me a code"),
    PROVING_WORK("preparing sign-up"),
    RESEND_CODE("send another code", words = "Send another code"),
    VERIFY_CODE("verify", words = "Verify"),
    CREATE_ACCOUNT_BUTTON("create account", words = "Create account"),
    INVITED_BY("invited by", words = "Invited by {0} (as they call themselves)"),
    SIGN_IN_BUTTON("sign in"),
    PUBLIC_INSTANCE_CHOICE("the public instance", words = "andvari"),
    TRUST_GATE_CONNECT("connect (Trust Gate confirm)", words = "Connect"),
    OPERATOR_KEY("operator key", words = "Operator key"),
    FOLLOW_MOVE("follow the move", words = "Use the new address"),
    FORGET_OTHER_SERVER("forget the server at the new address", words = "Forget the server at the new address"),
    FORGET_DELETES_COPY_MOVE_UNFINISHED("under a server move not finished yet, where nothing of the copy is read: forget this server removes it from this computer, including changes that have not synced; your account on the server is not affected"),
    FORGET_DELETES_COPY("forgetting this server deletes this computer's copy of the account", words ="What andvari has on this device stays readable until you forget this server. Forget this server removes it from this device, including changes that haven't synced. Your account on the server is not affected."),
    RECOVER_THERE("recover at the address the card names", words = "Recover at the address on its identity card"),
    // ---- screen capture on this computer (the owner's decision of 2026-11-16) ----
    CAPTURE_TITLE("screenshots and screen recording", words = "Screenshots and screen recording"),
    CAPTURE_SWITCH("allow screen capture of andvari on this computer", words = "Allow screen capture of andvari on this computer"),
    CAPTURE_SWITCH_MEANS("turned on, screenshots, screen recording, screen sharing and remote-support tools (Windows Recall included) can see andvari's window, passwords, card numbers, one-time codes and the recovery kit included, while they are on screen; it applies to this computer only", words = "When this is on, screenshots, screen recording, screen sharing and remote-support tools, Windows Recall among them, can see andvari's window while it's on screen, with any password, card number, one-time code or recovery kit it shows. This applies to this computer only."),
    CAPTURE_HIDDEN("andvari's window is hidden from screenshots, screen recording, screen sharing and remote support on this computer", words = "andvari's window is hidden from screenshots, screen recording, screen sharing and remote support on this computer."),
    CAPTURE_BLACKED_OUT("on this version of Windows andvari's window shows as black in screenshots, recordings and screen sharing (newer Windows leaves it out entirely)", words = "On this version of Windows, andvari's window shows as black in screenshots, recordings and screen sharing."),
    CAPTURE_NOT_ACTIVE("hiding andvari's window from screen capture is not active on this computer: Windows did not accept it, so screenshots and recordings can see it", words = "Windows didn't accept the request to hide andvari's window, so screenshots and recordings can see it."),
    CAPTURE_ALLOWED("screen capture is allowed: screenshots, recording, screen sharing and remote support can see andvari's window on this computer", words = "Screen capture is allowed. Screenshots, recording, screen sharing and remote support can see andvari's window on this computer."),
    CAPTURE_NOT_POSSIBLE_HERE("on this operating system andvari cannot hide its window from screenshots or screen recording", words = "On this computer, andvari can't hide its window from screenshots or screen recording."),

    // ---- a server set up from this computer (§6.7) ----
    OWN_SERVER_TAKES_SETUP_LINK("this field also takes the setup link your server printed, to set the server up from this computer", words = "You can also paste the setup link your server printed, to set it up from this computer."),
    CREATE_AS_OPERATOR("this account becomes the operator of this server (its name)"),
    SETUP_TITLE("setting up this server (its name)", words = "Setting up {0}"),
    SETUP_SIGNING("signing this server's identity card on this computer and uploading it", words = "Signing the server's identity card on this computer and uploading it…"),
    SETUP_FINISHED("this server is set up: this computer signed its identity card, the server took it, and it is pinned here", words = "This server is set up. This computer signed its identity card, the server accepted it, and this computer keeps it."),
    SETUP_COMPARE_KEY("compare this operator key with the one the server's setup printed: they must be the same", words = "Compare this operator key with the one the server's setup printed. They must be the same."),
    SETUP_CARD0_HASH("card 0's hash (what a store build of andvari would bake for this server)", words = "The first identity card's hash, for an andvari build made for this server"),
    SETUP_TO_KIT("go on to your recovery kit", words = "Go on to your recovery kit"),
    SETUP_NOT_UPLOADED("your account exists, but the server's identity card could not be uploaded, so the server is not set up yet; your recovery kit comes once it is. Try again with your master password", words = "Your account exists, but the server's identity card couldn't be uploaded, so the server isn't set up yet. Your recovery kit comes once it is. Try again with your master password."),
    SETUP_RETRY("try the upload again", words = "Try the upload again"),
    SETUP_STEP_WHAT("this signs this server's identity card on this computer, uploads it and pins it here; it needs your master password", words = "This signs the server's identity card on this computer, uploads it and keeps it on this computer. It needs your master password."),
    SETUP_SEND("upload the identity card", words = "Upload the identity card"),
    SETUP_UNFINISHED("this server has no identity card yet, so it is not set up: until it is, it takes no other accounts", words = "This server has no identity card yet, so it isn't set up. Until it is, it takes no other accounts."),

    // ---- linking this device, recovery ----
    LINK_DEVICE_WAITING("waiting for your other device", words = "Waiting for your other device…"),
    KIT_TEXT_FIELD("recovery kit text", words = "Your kit's text"),
    KIT_GROUPS_FIELD("the eleven groups of your kit", words = "The 11 groups on your kit"),
    OPERATOR_HELP_STAGE("where the request stands"),
    RECOVERY_IDLE_DROPPED("the recovery was left unattended and was dropped", words = "This recovery was left unfinished for too long, so andvari dropped it. Nothing was changed. Start again."),

    // ---- the kit ----
    KIT_MAKING("making your recovery kit", words = "Making your recovery kit…"),
    KIT_NOT_MADE("the recovery kit could not be saved", words = "andvari couldn't save your recovery kit to the server, so it doesn't work yet. Make it again."),
    KIT_REPLACED_ELSEWHERE("another device made a newer kit", words = "A newer recovery kit was made on another of your devices, so the one shown here doesn't work. Make a new one here, and throw away any copy of the old one."),
    KIT_RETRY("make the kit again", words = "Make the kit again"),
    KIT_PRINT("print", words = "Print"),
    KIT_PRINT_FAILED("the kit could not be printed", words = "The kit wasn't printed ({0}). Try again."),
    KIT_PRINT_STOPPED_BY_LOCK("said on the screen the app returns to when the lock stopped a print of the kit (Print pressed in the system's print dialog after the app locked, or the lock came while the page was printing): the lock stopped the print, so nothing of the kit comes out of the printer, or at most part of one page"),
    KIT_PRINT_LEAVES("printing hands the kit to this computer's print system, which can keep a copy after it prints (a spool file, the printer's job history), and \"print to file\" saves one where you choose", words = "Printing hands your kit to this computer's print system, which may keep a copy after it prints, such as in its list of print jobs. Print to file saves a copy wherever you choose."),
    KIT_SAVED_NEXT("I have saved it", words = "I've saved my kit"),
    KIT_SHOW_AGAIN("show the kit again", words = "Show the kit again"),
    KIT_GROUP_FIELD("group", words = "Group {0}"),
    KIT_CONFIRM("confirm", words = "Confirm"),
    KIT_FAILED_TRIES("wrong tries", words = "Tries used: {0} of 3"),

    // ---- lock, account, wall ----
    UNLOCK_BUTTON("unlock", words = "Unlock"),
    UNLOCKING("unlocking", words = "Unlocking…"),
    SIGN_OUT("sign out", words = "Sign out"),
    SIGN_OUT_CONFIRM("sign out of this computer?", words = "Sign out of this device?"),
    STAY_SIGNED_IN("stay signed in", words = "Stay signed in"),
    LOCK("lock", words = "Lock"),
    UPDATE_REQUIRED("this server needs a newer andvari than this one (version); what is on this computer stays readable"),
    KEEP_SIGN_IN("keep me signed in on this computer (the sign-in and an offline copy are stored on disk)", words = "Keep me signed in on this computer"),
    SETTINGS("settings", words = "Settings"),
    SERVER_SECTION("server", words = "Server"),
    PROMPTS("waiting for your answer", words = "Waiting for your answer"),
    SHARING("sharing", words = "Sharing"),
    SYNC_NOW("sync now", words = "Sync now"),
    TWO_STEP_WAITING("a two-step sign-in set-up is waiting for its first code (in Settings)", words = "Two-step sign-in is waiting for its first code. Finish turning it on in Settings."),
    MOVE_UNFINISHED("the server moved, and this computer's copy has not reached its new address yet; nothing opens until it has (from, to)", words = "{0} moved to {1}, but the data on this device hasn't moved with it yet. Your vault won't open here until it has."),
    MOVE_NOT_FINISHED_AGAIN("after Try again under a move not finished: this computer's data still has not reached the new address; nothing changed, and the vault stays shut until it has"),
    MOVE_NOT_VERIFIED("the move was followed, but the new address did not check out; nothing is sent there", words = "andvari followed the move, but the server at the new address didn't pass andvari's checks. Nothing is sent there while that stands."),
    LINK_DEVICE_NO_ANSWER("the server did not answer: nothing was linked; start a new link from your other device", words = "The server didn't answer, so nothing was linked. Start a new link on your other device."),
    CONNECTION_NOT_MADE_RETRY("your account exists, but the connection with (person) was not made: the server did not answer"),
    CONNECTION_NOT_MADE_SPENT("your account exists, but the connection with (person) was not made: their link can no longer be used; ask them for a new one"),

    // ---- the vault's items ----
    VAULT_ITEMS("passwords", words = "Passwords"),
    VAULT_SEARCH("search vault", words = "Search your vault"),
    VAULT_EMPTY("no items", words = "Nothing here yet."),
    SYNC_NOT_YET("showing this computer's copy; not synced yet", words = "Showing the copy on this device. It hasn't synced yet."),
    SYNC_OFFLINE("offline; showing this computer's copy; changes waiting", words = "Offline. Showing the copy on this device. Changes waiting to be sent: {0}"),
    SYNC_QUEUED("changes waiting to send", words = "Changes waiting to be sent: {0}"),
    SYNC_ROLLBACK("the server sent an older vault; nothing of it was used", words = "The server sent an older version of your vault. andvari didn't use it, and kept what it has."),
    SYNC_REFUSED("the server refused the sync", words = "The server refused to sync, so this is the copy on this device."),
    SYNC_STOPPED("server stopped on this computer: readable, nothing can be saved", words = "andvari has stopped using this server on this device. What's here stays readable, but nothing can be saved."),
    ITEM_WAITING("not on the server yet", words = "Not on the server yet"),
    ITEM_COPY_USERNAME("copy user name"),
    ITEM_PASSWORD("password", words = "Password"),
    ITEM_CARD_NUMBER("card number", words = "Card number"),
    ITEM_CARD_NUMBER_BRAND("card number, with the card's brand", words = "Card number · {0}"),
    ITEM_CARD_CODE("security code", words = "Security code"),
    ITEM_NOTES("notes", words = "Notes"),
    ITEM_CODE("one-time code", words = "One-time code"),
    ITEM_REVEAL("show"),
    ITEM_HIDE("hide"),
    ITEM_COPY("copy", words = "Copy"),
    ITEM_DELETE("delete", words = "Delete"),
    ITEM_DELETE_CONFIRM("move this item to the trash?", words = "Move this item to the trash?"),
    ITEM_NEW("new"),
    ITEM_EDIT("edit"),
    ITEM_NAME("name", words = "Name"),
    ITEM_USERNAME("user name", words = "Username"),
    ITEM_GENERATE("generate a password", words = "Generate a password"),
    ITEM_ADDRESS("web address", words = "Website"),
    ITEM_TOTP("one-time code key (otpauth:// or base32)", words = "One-time code setup key (otpauth:// link or text)"),
    ITEM_VAULT("save in", words = "Save in"),
    ITEM_SHARED_VAULT_SEES("everyone in this vault will see it", words = "Everyone in this vault will see it."),
    ITEM_SAVE("save", words = "Save"),
    ITEM_CARDHOLDER("cardholder", words = "Name on card"),
    ITEM_EXP_MONTH("expiry month (or MM/YY)", words = "Expiry month (MM, or MM/YY)"),
    ITEM_EXP_YEAR("expiry year", words = "Expiry year"),
    ITEM_POSTAL_CODE("postal code", words = "ZIP or postal code"),
    TRASH("trash", words = "Trash"),
    TRASH_RESTORE("restore", words = "Restore"),
    TRASH_PURGE("delete forever", words = "Delete forever"),
    TRASH_PURGE_CONFIRM("delete forever, now", words = "Delete it forever now"),
    HISTORY("earlier versions", words = "Earlier versions"),
    RECENTLY_REMOVED("recently removed", words = "No longer shared with you"),
    COPYING("copying items"),
    HELD_ITEM_COUNT("items", words = "Items: {0}"),
    HELD_COPY_TO_PERSONAL("copy its items to your personal vault", words = "Copy its items to your personal vault"),
    HELD_REMOVE_CONFIRM("remove this computer's copy? the server is not told", words = "Remove this vault's copy from this device? Nothing is sent to the server."),
    MOVE_OR_COPY("move or copy to another vault", words = "Move or copy to another vault"),
    COPY_TO_ANOTHER_VAULT("copy to another vault (an item that may only be viewed is copied, never moved)", words = "Copy to another vault"),
    MOVE_NO_TARGETS("no other vault can take it", words = "There's no other vault this item can go to."),
    COPY_TO_VAULT("copy here", words = "Copy here"),
    MOVE_TO_VAULT("move here", words = "Move here"),
    ATTACHMENTS("files", words = "Files"),
    ATTACHMENT_SAVE("save to this computer", words = "Save a copy"),
    ATTACHMENT_ADD("add a file", words = "Add a file"),
    ATTACHMENT_REMOVE("remove", words = "Remove"),
    ATTACHMENT_LIMITS("used, per-file limit, per-item limit"),
    ATTACHMENT_UPLOADING("sending files"),
    ATTACHMENT_NOT_WRITTEN("the file could not be written there", words = "The file couldn't be saved there. Try another place."),
    ATTACHMENT_NOT_READ("the picked file could not be read", words = "andvari couldn't read that file."),
    FILE_REPLACE_CONFIRM("a file with this name is already there: replace it?", words = "A file named {0} is already there. Replace it?"),
    FILE_REPLACE("replace", words = "Replace"),
    FILE_KEPT_ASIDE("the checked file could not take the old one's place; it was left beside it as", words = "The file couldn't replace the old one, so it was saved beside it as {0}."),

    // ---- import, export, health ----
    IMPORT_CSV("import a CSV", words = "Import a CSV file"),
    IMPORT_TOO_LARGE("this file is larger than the import takes", words = "This file is too large to import. The most andvari takes is {0}."),
    IMPORT_COUNT("items to import"),
    IMPORT_PROGRESS("importing"),
    IMPORT_CONFIRM("import", words = "Import"),
    EXPORT_BACKUP("export an encrypted backup", words = "Export an encrypted backup"),
    EXPORT_CSV("export a CSV", words = "Export a CSV file"),
    EXPORT_COUNT("items in the export"),
    EXPORT_FILES("include attached files", words = "Include attached files ({0})"),
    EXPORT_PASSPHRASE("backup passphrase", words = "Backup passphrase"),
    EXPORT_PASSPHRASE_AGAIN("backup passphrase again", words = "Type it again"),
    EXPORT_CHOOSE_PLACE("choose where to save it", words = "Choose where to save it"),

    // ---- "Restore a backup" (the design's sentences, approved on 22 November 2026, and drafts awaiting the owner) ----
    RESTORE_ENTRY("restore a backup", words = "Restore a backup"),
    RESTORE_PASSPHRASE_NOT_MASTER("the backup's passphrase is not the master password", words = "This is the passphrase of the backup, not your master password."),
    RESTORE_OPEN("Open the backup", words = "Open the backup"),
    // Both said that the file may be damaged (decided on 23 November 2026): a damaged byte draws them too.
    RESTORE_WRONG_PASSPHRASE("the backup does not open with this passphrase, or the file is damaged", words = "The backup does not open with this passphrase, or the file is damaged."),
    RESTORE_NOT_A_BACKUP("the file is not an andvari backup, or it is damaged", words = "This is not an andvari backup file, or it is damaged."),
    RESTORE_NOT_OPENED("The backup does not open: {0}", words = "This backup file does not open ({0}). It is damaged, or it was made in a way this version of andvari does not read."),
    RESTORE_ID_REFUSED(
        "Restore: this file is refused, as its file id is not the form every andvari app writes; nothing was read or written",
        words = "This file is refused: the id it carries is not in the form every andvari app writes. Nothing was read or written.",
    ),
    RESTORE_MADE("when and where the file says it was made", words = "Made on {0} from {1}."),
    RESTORE_MADE_UNNAMED("Made on {0}; the file names no server", words = "Made on {0}. The file names no server."),
    RESTORE_PERSONAL("the personal vault in the file", words = "Personal vault: {0} items"),
    RESTORE_SHARED_OWNED("a shared vault the person owned", words = "{0}: {1} items. You owned it."),
    RESTORE_SHARED_MEMBER("a shared vault the person was a member of", words = "{0}: {1} items. You were a member."),
    // A count of one reads in the singular (decided on 23 November 2026); a count of none keeps the lines above.
    RESTORE_PERSONAL_ONE("the personal vault in the file, holding one item", words = "Personal vault: {0} item"),
    RESTORE_SHARED_OWNED_ONE("a shared vault the person owned, holding one item", words = "{0}: {1} item. You owned it."),
    RESTORE_SHARED_MEMBER_ONE("a shared vault the person was a member of, holding one item", words = "{0}: {1} item. You were a member."),
    RESTORE_OVER_CAP_ONE("one attached file too large for the backup", words = "{0} attached file was too large for the backup. Attach it again by hand."),
    RESTORE_UNREADABLE_ONE("one item the device that made the backup could not read", words = "{0} item could not be read by the device that made the backup."),
    RESTORE_ACCOUNT_HOLDS_ONE(
        "the account already holds one item",
        words = "This account already holds {0} item. Restoring adds the backup's items beside it. Nothing is replaced, and an item you have in both will be there twice.",
    ),
    RESTORE_PROGRESS_ONE("the restore's progress, where it restores one item", words = "Restoring: {0} of {1} item."),
    RESTORE_DONE_FILES_ONE("the one attached file the restore stored", words = "{0} attached file restored."),
    RESTORE_RESTORED_AT("{0}: restored into this account on {1}; not offered again", words = "{0} Restored into this account; this computer saw it finished on {1}. Not offered again."),
    RESTORE_FILES("the attached files in the file", words = "Attached files: {0} ({1})."),
    RESTORE_OVER_CAP("attached files too large for the backup", words = "{0} attached files were too large for the backup. Attach them again by hand."),
    RESTORE_FETCH_FAILED("{0} attached files could not be fetched by the device that made the backup", words = "{0} attached files could not be fetched by the device that made the backup."),
    RESTORE_UNREADABLE("items the device that made the backup could not read", words = "{0} items could not be read by the device that made the backup."),
    RESTORE_NOT_IN_BACKUP("what no backup holds", words = "Not in any backup: two-step sign-in, earlier versions of items, the trash."),
    RESTORE_ACCOUNT_HOLDS("the account already holds items", words = "This account already holds {0} items. Restoring adds the backup's items beside them. Nothing is replaced, and an item you have in both will be there twice."),
    // Decided on 25 November 2026: only what is true on every road, also where an item was stored at a later try whose
    // answer was lost.
    RESTORE_REFUSED_BEFORE(
        "the items the server refused in an earlier restore; a run tries them again where their vault is ticked: {0}",
        words = "Refused by the server in an earlier restore: {0}. Where their vault can be ticked, the restore tries them again.",
    ),
    RESTORE_LEFT_OUT_VAULTS_TWICE("Left out, as the file names their id twice: {0} vaults", words = "Left out, as the file names their id twice: {0} vaults."),
    RESTORE_LEFT_OUT_ITEMS_TWICE("Left out, as the file names their id twice: {0} items", words = "Left out, as the file names their id twice: {0} items."),
    RESTORE_LEFT_OUT_ITEMS_NO_VAULT("Left out, in no vault the file lists: {0} items", words = "Left out, in no vault the file lists: {0} items."),
    RESTORE_LEFT_OUT_FILES_NO_ITEM("Left out, of no item the file lists: {0} attached files", words = "Left out, of no item the file lists: {0} attached files."),
    RESTORE_LEFT_OUT_SECTIONS("Not read, as nothing in the file names them: {0} parts of the file", words = "Not read, as nothing in the file names them: {0} parts of the file."),
    RESTORE_ONE_COMPUTER("restore from one computer at a time", words = "Run a restore from one computer."),
    RESTORE_NOTHING_LEFT("nothing in this backup is left to restore into this account", words = "Nothing in this backup is left to restore into this account."),
    RESTORE_CONFIRM("restore the chosen items", words = "Restore {0} items"),
    RESTORE_NO_ROOM("not enough room in this account", words = "There is not enough room in this account"),
    RESTORE_PROGRESS("the restore's progress", words = "Restoring: {0} of {1} items."),
    RESTORE_WAITING("The server asked for a wait: the restore goes on in {0}", words = "The server asked for a wait. The restore goes on in {0}."),
    RESTORE_WAITING_VAULTS(
        "The server lets an account make ten shared vaults an hour: the next one in {0}",
        words = "The server lets an account make ten shared vaults an hour. The next one is made in {0}.",
    ),
    RESTORE_STOPPED(
        "The restore stopped ({0}). Nothing it wrote is undone; Try again continues where it stopped",
        words = "The restore stopped ({0}). Nothing it stored is undone. Try again continues where it stopped.",
    ),
    // Decided on 25 November 2026: one line for every case in which the app gives the restore no vault to write to (none
    // open, a locked one, or an open one that cannot be written here).
    RESTORE_NO_VAULT(
        "the app gives the restore no vault to write to now: choose the file again when it does",
        words = "This vault cannot take a restore now. When it can, choose the file again.",
    ),
    RESTORE_DONE("what the restore stored", words = "{0} items restored into {1} vault."),
    RESTORE_DONE_FILES("the attached files the restore stored", words = "{0} attached files restored."),
    RESTORE_REFUSED(
        "Did not arrive, refused by the server (Try again sends them again): {0}",
        words = "Refused by the server, so not in the account. Try again sends them again: {0}",
    ),
    RESTORE_MEMORY_ONLY(
        "this computer keeps nothing once andvari is closed; keep andvari open until the restore has finished; after it was closed, choosing the same file again starts from the beginning and stores again what is already stored",
        words = "This computer keeps nothing of this restore once andvari is closed. Keep andvari open until the restore has finished: if andvari is closed before, the same file chosen again starts from the beginning and stores again what was already stored.",
    ),
    RESTORE_ROOM_UNKNOWN(
        "the server did not say how much room this account has, so that was not checked before the restore started; if the account is full, the server refuses what does not fit",
        words = "The server did not say how much room this account has, so that was not checked before the restore started. If the account is full, the server refuses what does not fit.",
    ),
    RESTORE_CONFIRM_ONE("restore the one chosen item", words = "Restore {0} item"),
    RESTORE_VAULT_LEFT(
        "{0}: {1} of them are not in this account yet, and only those are restored (an earlier restore of this file stored the others)",
        words = "{0} Still to restore: {1}.",
    ),
    RESTORE_VAULT_IN_ACCOUNT(
        "{0}: every item of it is in this account already (an earlier restore of this file stored them); not offered again",
        words = "{0} Every item of it is in this account already. Not offered again.",
    ),
    RESTORE_FILES_NOT_IN_BACKUP(
        "{0} attached files that items to be restored name are not in this backup: those items are restored without them; attach them again by hand",
        words = "{0} attached files named by items to be restored are not in this backup. Those items are restored without them. Attach them again by hand.",
    ),
    RESTORE_PART_UNREADABLE(
        "a part of the backup file cannot be read ({0}): the restore cannot go past it; what it stored stays; trying again with this file stops at the same place",
        words = "The attached file “{0}” in this backup cannot be read, so the restore cannot go past it. What it stored stays. Trying again with this file stops at the same place.",
    ),
    RESTORE_UNFINISHED_AT_SIGN_OUT(
        "this computer's record of a restore of a backup into this account does not show that restore as finished (it says nothing of what the account holds): this deletes the record, and the same file chosen again afterwards stores again whatever that restore already stored; choose the file again and finish the restore first",
        words = "This computer does not show a restore of a backup into this account as finished. What it stored stays in the account, but after this, the same backup file chosen again stores again what it already stored. Choose the file again and finish the restore first.",
    ),
    RESTORE_DONE_ONE("what the restore stored: one item into one vault", words = "{0} item restored into {1} vault."),
    RESTORE_DONE_VAULTS("{0} items restored into {1} vaults (the end, where the run restored more than one vault, or none)", words = "{0} items restored into {1} vaults."),
    // Why a restore stopped, a phrase for each kind of stop inside the line of a stop; what the program saw follows it.
    RESTORE_STOP_ITEM_UNREADABLE("an item in the backup does not read as an item"),
    RESTORE_STOP_ROOM_CHECK("the check of this account's limits on this server did not finish"),
    RESTORE_STOP_NO_PERSONAL_VAULT("this account has no personal vault"),
    // The two phrases decided on 25 November 2026: true whether or not anything left this computer.
    RESTORE_STOP_BATCH("a batch of items not confirmed as stored", words = "these items are not confirmed as stored in the account"),
    RESTORE_STOP_FILE_KEY("the key kept for the attached file “{0}” does not open"),
    RESTORE_STOP_FILE_SIZE("the attached file “{0}” is not the size the backup names"),
    RESTORE_STOP_FILE_REFUSED("an attached file not confirmed as stored: “{0}”", words = "the attached file “{0}” is not confirmed as stored in the account"),
    RESTORE_STOP_OTHER_VAULT("the server's answer to making the vault “{0}” named another vault"),
    RESTORE_STOP_VAULT_NOT_MADE("the shared vault “{0}” could not be made"),
    RESTORE_STOP_VAULT_NOT_CONFIRMED("the new shared vault “{0}” is not confirmed yet"),
    RESTORE_STOP_KEY_NOT_ADOPTED("the key of the new shared vault “{0}” could not be taken into use"),
    RESTORE_SEEN_NO_ANSWER("no answer from the server"),
    RESTORE_STOPPED_SAME_PLACE("The restore stopped ({0}). Nothing it stored is undone. Trying again with this file stops at the same place."),
    RESTORE_DONE_NOTHING_LEFT("the end of a run that found nothing of the chosen vaults left to restore", words = "Nothing of the chosen vaults was left to restore, so nothing was sent."),
    RESTORE_VAULT_STARTED("a shared vault whose restore started on this computer and stored nothing yet", words = "{0} Its restore started on this computer and has not finished."),
    RESTORE_INTERRUPTED(
        "the restore was interrupted on this computer (its page was closed, the vault locked, or something went wrong); nothing it stored is undone; Try again goes on where it stopped",
        words = "The restore was interrupted on this computer: its page was closed, the vault locked, or something went wrong. Nothing it stored is undone. Try again goes on where it stopped.",
    ),
    RESTORE_TOO_LARGE(
        "this file is larger than any andvari backup can be, so it was not opened",
        words = "This file, or a part of it, is larger than an andvari backup can be, so it was not opened.",
    ),
    RESTORE_CUT_SHORT(
        "this backup file is cut short: it ends before its last part, so it was not opened and nothing was restored; copy or make the file again",
        words = "This backup file is cut short or damaged, so it was not opened and nothing was restored. Copy the file again, or make a new backup.",
    ),
    RESTORE_CHANGED(
        "what this account holds changed after the page was drawn (a sync sent items an earlier stop had left waiting): nothing was sent; the page now shows what is left",
        words = "What this account holds changed after this page was drawn, so nothing was sent. The page now shows what is left to restore.",
    ),
    RESTORE_DONE_STRIPPED(
        "{0} attached files that items of the backup name are not in the backup (made without its attached files, too large for it, or not fetched when it was made): those items were restored without them; attach them again by hand",
        words = "{0} attached files named by items of the backup are not in the backup: it was made without its attached files, they were too large for it, or they were not fetched when it was made. Those items were restored without them. Attach them again by hand.",
    ),
    HEALTH("vault health", words = "Password health"),
    HEALTH_TILES("logins, weak, reused, breached, duplicates, unchecked, failing", words = "Logins · Weak · Reused · In a breach · Duplicates · Not checked · Not working"),
    HEALTH_CHECKING("checking"),
    HEALTH_CHECK_BREACHES("check for breaches", words = "Check for breaches"),
    HEALTH_REFRESH("check again", words = "Check again"),
    HEALTH_REUSED("also used by this many other logins", words = "Also used by {0} other logins"),
    /** The line for one beside [HEALTH_REUSED] (the phone's own, from the same wording page), chosen by [reusedLine]. */
    HEALTH_REUSED_ONE("also used by one other login", words = "Also used by 1 other login"),
    HEALTH_BREACHED("seen in breaches", words = "Seen in {0} breaches"),
    HEALTH_STRENGTH("strength of its password", words = "Password strength: {0}"),
    HEALTH_LAST_USED("last used on", words = "Last used {0}"),
    HEALTH_DUPLICATES("duplicates for"),
    HEALTH_KEEP_THIS("keep this one", words = "Keep this one"),
    HEALTH_MERGE("merge", words = "Merge"),
    HEALTH_NOT_DUPLICATES("not duplicates", words = "Not duplicates"),
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

    // ---- Settings: two-step, the policy, the kit after a move, password, deletion ----
    TURN_ON("turn on", words = "Turn on"),
    TURN_OFF("turn off", words = "Turn off"),
    CLOSE("close", words = "Close"),
    LATER("later", words = "Later"),
    WORKING("working", words = "Working…"),
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
    DELETE_ACCOUNT("delete account", words = "Delete account"),
    DELETION_GOES("deleted for good", words = "Deleted for good: {0}"),
    DELETION_LEAVES("left, with a signed leave each", words = "You'll leave these shared vaults, and the others in them keep them: {0}"),
    DELETION_BLOCKER_SHARED("blocker: a shared vault others hold (vault, others)", words = "You own “{0}”, which {1} others also have. Hand it over, or remove them, first."),
    DELETION_BLOCKER_OPERATOR("blocker: this is the operator account; hand it over first", words = "This is the operator account. Hand the server over to another account first."),
    DELETION_BLOCKER_UNKNOWN("blocker this build cannot explain", words = "Something stops this account being deleted that this version of andvari can't explain. Update andvari and try again."),
    DELETION_RETRYING("a vault's history moved on; retrying by itself, nothing was deleted", words = "A shared vault changed meanwhile, so andvari is trying again. Nothing has been deleted."),
    DELETION_OUTCOME_UNKNOWN("andvari can't tell yet whether your account was deleted: the server's answer did not come; check whether it went through", words = "The server didn't answer, so your account may have been deleted."),
    DELETION_CHECK("check whether it went through", words = "Check whether the account still exists"),
    DELETION_WHAT("deleting your account removes it, your personal vault and every vault only you hold from the server for good, and signs out every device", words = "Deleting your account removes it from the server for good, with your personal vault and every vault nobody else is in. Every device is signed out, your recovery kit and any operator recovery stop working, and links you made that nobody used stop working too. The copy on this device is removed."),
    DELETION_CANNOT_UNDO("this can't be undone", words = "This can't be undone."),
    DELETION_BACK_UP_FIRST("back up first: export from the vault page", words = "To keep a copy of what's in your vault, export it first from the vault page."),
    DELETION_TYPE_EMAIL("type your email address to confirm (address)", words = "To confirm, type your email address, {0}."),
    DELETION_CONFIRM("delete my account permanently", words = "Delete my account permanently"),
    DELETION_EMAIL_MISMATCH("the address typed is not this account's; nothing was deleted", words = "That isn't this account's email address. Nothing was deleted."),
    DELETION_WRONG_PASSWORD("the master password is wrong; nothing was deleted", words = "That master password isn't right. Nothing was deleted."),
    DELETION_CODE_NEEDED("this account has two-step sign-in: type the current code; nothing was deleted", words = "This account uses two-step sign-in. Enter the code from your authenticator app. Nothing was deleted."),
    DELETION_WRONG_CODE("the two-step code is wrong or was used already; wait for the next one; nothing was deleted", words = "That code isn't right, or it was already used. Wait for the next one and try again. Nothing was deleted."),
    DELETION_BLOCKED("something now stands in the way (listed above); nothing was deleted", words = "Something now stands in the way, listed above. Nothing was deleted."),
    DELETION_STILL_CHANGING("your shared vaults kept changing while andvari tried; nothing was deleted; try again", words = "Your shared vaults kept changing, so nothing was deleted. Try again."),
    DELETION_CHANGED_ELSEWHERE("your master password was changed elsewhere meanwhile; nothing was deleted", words = "Your master password was changed on another device meanwhile. Nothing was deleted. Sign in again with the new one."),
    DELETION_STILL_THERE("your account is still there: nothing was deleted", words = "Your account is still there. Nothing was deleted."),
    VAULT_NAME_UNREADABLE("a vault whose name can't be read here", words = "a vault whose name can't be read on this device"),

    // ---- Settings: devices, adding a device, recovery ----
    DEVICES("your devices", words = "Your devices"),
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
    DEVICE_REQUIRE_LINK_BODY("what the setting does", words = "When this is on, a new device can join your account only by being linked from one you already use. Recovering with your recovery kit still works, and turns this off."),
    DEVICE_REQUIRE_LINK_IS_ON("the setting is on", words = "It's on."),
    DEVICE_REQUIRE_LINK_IS_OFF("the setting is off", words = "It's off."),
    DEVICE_REQUIRE_LINK_ON("require new devices to be linked from one of mine", words = "Turn on"),
    DEVICE_REQUIRE_LINK_OFF("stop requiring new devices to be linked", words = "Turn off"),
    SIGNED_OUT_BY_SERVER("the server ended this computer's session: the copy here opens read-only, and nothing is sent until you sign in again"),
    SIGN_IN_AGAIN("sign in again"),
    DEVICE_REQUIRE_LINK_NOT_KNOWN("new devices must be linked from one of mine: whether this is on is not known on this computer", words = "This device doesn't know whether it's on, because the server doesn't say. Choose on or off."),
    DEVICE_ADD("add a device", words = "Add a device"),
    DEVICE_LINK_TIME_LEFT("time left (m:ss)", words = "Time left: {0}"),
    DEVICE_LINK_EXPIRED("the link ran out of time; nothing was linked; add the device again", words = "The link ran out of time, and nothing was linked. To add the device, start again."),
    DEVICE_LINK_DID_NOT_CHECK_OUT("the new device's answer did not check out, so the link was stopped; nothing was linked", words = "The new device's answer didn't pass andvari's checks, so andvari stopped the link. Nothing was linked."),
    DEVICE_LINK_WRONG_PASSWORD("the master password is wrong; nothing was approved and the link still waits", words = "That master password isn't right. Nothing was approved, and the new device is still waiting: try again."),
    DEVICE_LINK_CLAIMED("a new device picked up the link (name, platform)", words = "A new device opened the link: {0} ({1})."),
    DEVICE_LINK_APPROVE("approve adding (name, platform)"),
    DEVICE_LINK_APPROVE_BUTTON("approve", words = "Add this device"),
    DEVICE_LINK_APPROVED("approved, waiting for the new device's password", words = "Approved. Now enter your master password on {0}."),
    RECOVERY_SETTINGS("recovery", words = "Recovery"),
    RECOVERY_ME_OR_OPERATOR("you or the operator can recover this account", words = "You or the operator can recover this account."),

    // ---- people and the comparison codes ----
    PEOPLE("people", words = "People"),
    CONTACT_COMPARED("(person): codes compared"),
    CONTACT_NOT_COMPARED("(person): codes not compared yet"),
    CONTACT_REMOVE("remove this person", words = "Remove this person"),
    COMPARE_WAITING("waiting: no code exists yet", words = "Waiting for the code…"),
    COMPARE_THEIR_CODE("the six digits they read out", words = "Their code"),
    COMPARE_LINK_FAILED("the connection could not be checked", words = "The connection couldn't be checked, so andvari didn't use it. Connect again with a new link."),
    COMPARE_MATCHED("the codes match", words = "The codes match."),
    COMPARE_MATCHED_NOT_SAVED("the codes match, but the account could not record it; try again", words = "The codes match, but your account couldn't be updated, so your other devices still show this person as not compared. Try again."),

    // ---- links ----
    LINKS("links", words = "Links"),
    LINK_LIFETIME("how long the link works", words = "How long the link works"),
    LINK_MINUTES("minutes", words = "{0} minutes"),
    LINK_ROLE_SWITCH("switch between reader and writer", words = "Change role"),
    LINK_CREATE("make a connect link", words = "Make a connect link"),
    LINK_KIND_CONNECT("connect link (vaults to share)"),
    LINK_KIND_INVITATION("invitation (vaults to share)"),
    LINK_COPY("copy", words = "Copy"),
    LINK_REVOKE("revoke", words = "Cancel this link"),
    LINK_ANSWERED("answered by (person)"),
    LINK_ANSWERED_KEY_CHANGED("answered by (person), whose key changed"),
    LINK_RELEASE_SHARE("share now", words = "Share now"),
    LINK_CONNECTED("connected with (person)", words = "You're connected with {0}."),
    OTHER_INSTANCE_TITLE("switch to another server?", words = "Switch to a different server?"),

    // ---- shared vaults ----
    SHARED_VAULTS("shared vaults", words = "Shared vaults"),
    VAULT_YOU("you", words = "You"),
    VAULT_OWNER("owner", words = "Owner: {0}"),
    VAULT_ROLE_OWNER("shared vault, you own it", words = "Shared vault · you own it"),
    VAULT_ROLE_WRITER("shared vault, you can change its items", words = "Shared vault · you can change its items"),
    VAULT_ROLE_READER("shared vault, you can only view its items", words = "Shared vault · you can only view its items"),
    VAULT_LOG_STATE("history state without wording (copy.json 22, 23)"),
    VAULT_REMOVED_BY_OWNER("the owner removed you from this vault", words = "The owner removed you from this vault."),
    VAULT_REMOVED_UNVERIFIED("you no longer have this vault (not verified as the owner's act)", words = "You no longer have this vault. andvari couldn't confirm that its owner removed you."),
    VAULT_DELETED_IN_GRACE("deleted; can be restored until", words = "Deleted. It can be restored until {0}."),
    VAULT_HELD_UNTIL("this computer keeps a copy until", words = "This device keeps a copy until {0}."),
    VAULT_OFFER("ownership offered to"),
    VAULT_ACCEPT_OWNERSHIP("accept ownership", words = "Become the owner"),
    VAULT_CANCEL_OFFER("cancel the offer", words = "Cancel the offer"),
    VAULT_MEMBERS("members", words = "Members"),
    VAULT_MEMBERS_OF("members of", words = "Members of “{0}”"),
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
    VAULT_RENAME("rename this vault", words = "Rename"),
    VAULT_RENAME_SAVE("save the new name", words = "Save name"),
    VAULT_RENAME_NOT_DONE("the vault was not renamed", words = "The vault wasn't renamed."),
    MOVE_FROZEN_CLOSE_BUTTON("button: close this move (the line above says what closing does)"),
    WAITING_UNDO_ROLE_BACK("button on a notice: change the member's role back to (role)"),
    WAITING_UNDO_VAULT_NOT_LISTED("after an undo on a notice: the vault the notice names is not listed on this device now; nothing was changed"),
    WAITING_UNDO_MEMBER_NOT_LISTED("after an undo on a notice: the member the notice names is not in the vault's member list now; nothing was changed"),
    WAITING_UNDO_ALREADY_MEMBER("after an undo on a notice: the person the notice names is in the vault's member list already; nothing was changed"),
    WAITING_UNDO_NOT_A_CONTACT("after an undo on a notice: the person the notice names is not a contact of this account on this device now; nothing was changed"),
    MOVE_SHORT_OF_SPACE("not enough space on the server for the copy", words = "There isn't enough space on the server for the copy."),
    MOVE_CONNECT_FIRST("connect with this person first", words = "Connect with this person first."),
    MOVE_PROGRESS("copied (n) of (total)", words = "Copied {0} of {1}"),
    MOVE_REMOVING("being removed, and not added to the new vault", words = "{0} is removed from the old vault first, and isn't added to the new vault."),
    MOVE_ADDED_AGAIN("everyone below is added to the new vault again, with the role they have now, and asked to accept it", words = "Everyone below is added to the new vault with the role they have now, and asked to accept it."),
    MOVE_TICK_WHO("tick who is added to the new vault; nobody is ticked to begin with", words = "Tick who to add to the new vault. Nobody is ticked to begin with."),
    MOVE_STOPPED_REMOVING("stopped while removing the member from the old vault", words = "The move stopped while removing the member from the old vault."),
    MOVE_STOPPED_CREATING("stopped while making the new vault", words = "The move stopped while making the new vault."),
    MOVE_STOPPED_COPYING("stopped while copying the items", words = "The move stopped while copying the items."),
    MOVE_STOPPED_ADDING("stopped while adding the members to the new vault", words = "The move stopped while adding the members to the new vault."),
    MOVE_STOPPED_DELETING("stopped while deleting the old vault", words = "The move stopped while deleting the old vault."),
    MOVE_FINISHED("done: (n) items are in the new vault (name)", words = "Done. {0} items are in “{1}” now."),
    MOVE_FINISH("the button under the offer to finish a move this computer started: opens the move again on the old vault, where it carries on"),

    // ---- the desktop's own ----
    ALREADY_OPEN("andvari is already open on this computer; this second start does nothing", words = "andvari is already open on this computer."),
    INSTANCE_CHECK_FAILED("andvari could not make sure it is not already open, so it did not start (reason)", words = "andvari couldn't check whether it's already open on this computer, so it didn't start. ({0})"),
    KEEP_FORBIDDEN("this server does not allow an offline copy, so the sign-in is not kept on this computer", words = "This server doesn't allow a copy of your vault on devices, so your sign-in isn't kept on this computer."),
    KEEP_BELONGS_TO_ANOTHER("the sign-in kept on this computer is another account's; this account is not kept here, and nothing of the other was deleted", words = "The sign-in kept on this computer is another account's. This account isn't kept here, and nothing of the other one was deleted."),
    KEEP_UNKNOWN("andvari could not read its settings on this computer, so nothing kept was used or deleted; keep the sign-in here?", words = "andvari couldn't read its settings on this computer, so it hasn't used or removed anything it kept. Keep your sign-in on this computer?"),
    KEEP_UNKNOWN_YES("keep it on this computer", words = "Keep it on this computer"),
    KEEP_UNKNOWN_NO("do not keep it here (deletes what is kept)", words = "Remove it from this computer"),
    KEEP_NO_KEY_STORE("this computer has no key store to lock the kept sign-in with, so it would be kept in a file that only your account on this computer can read; keep it that way?"),
    KEEP_NO_KEY_STORE_FILE("keep it in that file"),
    KEEP_NO_KEY_STORE_NOT("do not keep me signed in"),
    // A wait the server named, as a length of time ([waitText]), filled into the lines that say a wait.
    WAIT_SECONDS("(n) seconds", words = "{0} seconds"),
    WAIT_MINUTES("(n) minutes", words = "{0} minutes"),
    WAIT_HOURS("(n) hours", words = "{0} hours"),
    WAIT_A_WHILE("a while (the server named no wait)", words = "a while"),
    // Before the app ends by the person's own act, where changes made here wait in memory only (AppApi.waitingInMemory).
    QUIT_WAITING("quit andvari? (n) changes made on this computer wait to be sent and are kept only while andvari runs: quitting now loses them; unlocking and staying online sends them"),
    QUIT_WAITING_UNKNOWN("quit andvari? changes made on this computer may wait to be sent, kept only while andvari runs (how many cannot be told while it is locked): quitting now loses them"),
    QUIT_WAITING_STAY("stay: do not quit"),
    QUIT_WAITING_ANYWAY("quit anyway (the waiting changes are lost)"),
    KEPT_UNOPENABLE("the sign-in kept on this computer could not be opened here; sign in again (the kept file was not deleted)", words = "andvari couldn't open the sign-in kept on this computer. Sign in again. The kept file wasn't deleted."),
    ASSIST_REQUEST_THIS_RUN_ONLY("this computer has no key store, so this request is kept only while andvari stays open; if andvari closes, you will have to ask again", words = "This computer has no key store andvari can use, so this request is kept only while andvari stays open. If andvari closes, you'll have to ask again, and the 7-day wait starts over."),
    QR_TOO_LONG("this is too long to draw as a QR code; its text is below", words = "This is too long to show as a QR code. Its text is below."),
    SCREEN_FAILED("something went wrong in this window, so andvari stopped it; what happened is in the diagnostic log (path)"),
    QUIT("quit andvari", words = "Quit andvari"),
    STATE_FILE_UNREADABLE("this file of andvari's on this computer could not be read, and nothing in it was used or changed (path)"),
    STATE_FILE_FRESH_WHAT("starting fresh keeps the file under a new name; andvari then no longer knows the servers it trusted here and asks again", words = "Starting fresh keeps that file under a new name. andvari then no longer knows the servers you used on this computer, and asks you to check each one again before it connects."),
    STATE_FILE_FRESH("keep it under a new name and start fresh on this computer", words = "Start fresh"),
    OPEN_SITE_USERINFO("this address carries a user name or password before the site's name, which can send the browser elsewhere, so andvari does not open it"),
    FILE_RISKY_TYPE("this file's name ends like a program, a shortcut or a script, which can run when opened; it came from whoever wrote this item; save it anyway? (name, type)", words = "“{0}” is a kind of file ({1}) that can run something when it's opened. It came from whoever added it to this item. Save it anyway?"),
    FILE_RISKY_SAVE("save it anyway", words = "Save it anyway"),
    UPDATE_LAST_CHECKED("updates: the last verified list came from (source), signed on (the list's own date), last checked (when)", words = "Updates last checked {2}, from {0}. The list there is dated {1}."),
    UPDATE_SIGNED_NOT_GIVEN("no date given"),
    UPDATE_NOT_ASKED("updates are not checked until a server is chosen", words = "andvari doesn't check for updates until you choose a server."),
    UPDATE_COULD_NOT_CHECK_SINCE("could not check for updates since (when)", words = "andvari hasn't been able to check for updates since {0}."),
    UPDATE_NEVER("never", words = "it was installed"),
    UPDATE_AVAILABLE_BANNER("version (version) is available; download it from (the signed list's address, or the project's GitHub releases page)"),
    UPDATE_COULD_NOT_VERIFY("could not verify the update list from (source)", words = "andvari couldn't verify the list of updates from {0}."),
    UPDATE_STALE("the update list from (source) is old, so a newer version may be held back", words = "The list of updates from {0} is old, so a newer version may be held back."),
    STATE_FILE_ASIDE_FAILED("the file could not be moved aside, so andvari did not start fresh (path)"),

    // ---- a second account while a server-ended one is kept ----
    KEPT_ACCOUNT_SIGN_OUT_FIRST("this computer keeps (account) on (server) ((origin)), which its server signed out; sign out of it first", words = "This device still keeps {0} on {1} ({2}), which its server signed out. Sign out of that account first, then try again."),
    KEPT_ACCOUNT_NOT_CONFIRMED_SIGN_OUT_FIRST("this computer keeps (account) on (server) ((origin)); sign out of it first (the shared code's line for its unconfirmed session follows)"),
    KEPT_ACCOUNT_UNNAMED("an account whose address this computer does not know", words = "an account whose address this computer doesn't know"),
    FORGET_UNKNOWN_CONFIRM("button on the confirmation, after a deletion whose outcome is not known: forget this account on this computer now (the confirmation's lines are above it)"),
    KEPT_ACCOUNT_SIGN_OUT_DELETES("signing it out deletes its copy on this computer, with any changes not yet sent", words = "Signing out removes it from this device. Changes that haven't synced are lost, and that can't be undone. Your account on the server is not affected."),

    // ---- the session keeper's other reasons (the check of 2026-11-17) ----
    KEPT_COPY_REMOVE("button: remove this computer's damaged copy of the account (it says first how many changes were not sent)"),
    HELD_OPERATOR_REMOVE("button: remove this server's operator account from this computer (never a sign-out)"),
    MOVE_STORED_COPY("button under the notice that the server deleted the old vault before the move finished: copy into the new vault what was added or changed in the old one after the move's copies"),

    // ---- signing out, or switching servers, over changes not sent (the rule of 2026-11-17) ----
    SIGN_OUT_SECOND_CONFIRM("second confirmation's title: sign out of this computer although what was not sent is lost?", words = "Sign out anyway?"),
    SIGN_OUT_ALL_THE_SAME("second confirmation's button: sign out all the same, losing what was not sent", words = "Sign out and lose unsent changes"),
    SWITCH_SECOND_CONFIRM("second confirmation's title: switch to the other server although what was not sent is lost?", words = "Switch servers anyway?"),
    SWITCH_ALL_THE_SAME("second confirmation's button: switch all the same, losing what was not sent", words = "Switch and lose unsent changes"),

    // ---- changing the master password ----
    PASSWORD_CHANGE_WRONG("the current master password is wrong; nothing was changed", words = "That master password isn't right. Nothing was changed."),
    PASSWORD_CHANGE_WEAK("the new master password is too weak; nothing was sent", words = "The new master password is too weak. Choose a longer one. Nothing was sent."),
    PASSWORD_CHANGE_ELSEWHERE("your master password was changed on another device or by a recovery meanwhile; this change was not made", words = "Your master password was changed on another device, or by a recovery, while you were changing it here. Nothing was changed here. Sign in again with the new one."),
    PASSWORD_CHANGE_NO_ANSWER("the server did not answer, so andvari can't tell whether your master password changed; if your current one is refused next time, the new one is in force", words = "The server didn't answer, so andvari can't tell whether your master password changed. Next time you sign in, try the new one. If it doesn't work, the old one still does."),
    PASSWORD_CHANGED("your master password is changed; this computer's copy now opens with the new one, not the old", words = "Your master password is changed. andvari on this device opens with the new master password from now on. The old one no longer opens it."),
    PASSWORD_CHANGED_OTHERS_SIGNED_OUT("every other device was signed out and signs in with the new password", words = "Your other devices were signed out. They need the new master password to sign in again."),
    PASSWORD_CHANGED_KIT_STAYS("your recovery kit and any operator recovery still work; no new kit is needed", words = "Your recovery kit, and operator recovery if you use it, still work. You don't need a new kit."),
    PASSWORD_CHANGED_PREVIOUS_OPENS_HERE("your master password is changed at the server, but this computer's copy could not follow: your previous master password still opens it here", words = "Your master password is changed, but andvari on this device couldn't switch to it. Here, your previous master password still opens andvari. Everywhere else, use the new one."),
    LOCKED_PREVIOUS_PASSWORD_OPENS("your master password was changed, but this computer's copy still opens with the previous one", words = "Your master password was changed, but on this device andvari still opens with your previous one."),
    INVITE_NOT_USED_DISMISS("put this away"),

    // ---- what the shared code threw that nobody expected ----
    SOMETHING_WENT_WRONG("something went wrong here, and nothing else was affected; try again, or quit and start andvari again if it keeps happening", words = "Something went wrong here, and nothing else was affected. Try again, or quit andvari and start it again if it keeps happening."),
    SOMETHING_WENT_WRONG_IN_VAULT("something went wrong with this vault (its name), and your other vaults were not affected; try again, or quit and start andvari again if it keeps happening"),

    // ---- work a lock overtook (the key fix) ----
    DELETION_OUTCOME_UNKNOWN_LOCKED("we cannot tell yet whether your account was deleted", words = "andvari asked the server to delete your account and got no answer, so it can't tell yet whether your account was deleted."),
    LOCK_OVERTOOK("not done: andvari locked before this finished; do it again once unlocked", words = "andvari locked before this was done. Do it again once you've unlocked."),
    LOCK_AFTER_DONE("done, as andvari locked: what you asked for went through", words = "This went through just as andvari locked."),
    // Where a lock did not do it (the reader of 2026-11-17): the same throw and the same STALE come when the server ends
    // the session, and on the first screen there is nothing to unlock.
    SERVER_ENDED_BEFORE_DONE("not done: the server signed this computer out before this was finished (andvari did not lock); this computer's copy opens read-only, so it cannot be done again here until you sign in again"),
    STOPPED_BEFORE_DONE("not done: this stopped before it was finished, because this computer's session ended or its keys were put away; nothing more of it was done"),
    CHANGE_CUT_BY_LOCK("andvari locked while a change of yours was being made: it may or may not have gone through, so check that it is there after you unlock, before you make it again (wording page U1, line 4)"),
    CHANGE_CUT_BY_SERVER_END("the server signed this computer out while a change of yours was being made: it may or may not have gone through, so check that it is there before you make it again"),
    // Where this computer could not confirm its session in time (not the server's end): the end is the shared code's line.
    NOT_CONFIRMED_BEFORE_DONE("not done: this computer's session ended before this was finished, as the line given says (andvari did not lock); this computer's copy opens read-only, so it cannot be done again here until you sign in again; the end"),
    CHANGE_CUT_BY_NOT_CONFIRMED("this computer's session ended while a change of yours was being made, as the line given says: it may or may not have gone through, so check that it is there before you make it again; the end"),
    SOMETHING_WENT_WRONG_IN_BACKGROUND("something andvari was doing by itself (a sync, sending changes, a session's end) stopped with an error; nothing you asked for failed; what is on show may not be up to date until the next sync, or quit and start andvari again if it keeps happening"),
    SWITCH_UNSENT_NOT_CONFIRMED("you're still on this server: some changes may not have been sent, so switching servers needs you to confirm that they will be lost (wording page PQ6, line 0)"),

    // ---- the account's own use and limits (Settings) ----
    STORAGE_TITLE("what this account uses, and its limits on this server", words = "Your space on this server"),
    STORAGE_BYTES("storage: used, of the limit", words = "Space: {0} of {1}"),
    STORAGE_ITEMS("items: used, of the limit", words = "Items: {0} of {1}"),
    STORAGE_VAULTS("shared vaults you own: used, of the limit", words = "Shared vaults you own: {0} of {1}"),
    STORAGE_LINKS("open links: used, of the limit", words = "Open links: {0} of {1}"),

    // ---- the operator's console ----
    OPERATOR_CONSOLE("the server's operator console", words = "Operator panel"),
    OP_READING("reading what the server says about its accounts", words = "Reading the server…"),
    OP_NOT_READ("nothing of the server is shown: its first read was refused", words = "andvari couldn't read the server, so nothing of it is shown."),
    OP_READ_AGAIN("read the server again", words = "Refresh"),
    OP_SHOWING_PREVIOUS("what is shown is the list as it was last read", words = "What's shown is the list as andvari last read it."),
    OP_MAIL_STALLED("the server's mail is stuck: nothing has gone out for 10 minutes, and sign-up and recovery requests are refused until it moves (oldest waiting since)", words = "This server's email is stuck: messages are waiting, and none has gone out for 10 minutes. Until mail moves again, the server refuses sign-ups and requests for the operator's help. The oldest message has waited since {0}."),
    OP_NOT_GIVEN("not given", words = "not given"),
    OP_STATUS("server: version, kind, sign-up mode, accounts the cap counts, cap, full or not", words = "andvari server {0} · {1} · sign-up: {2} · {3} of {4} accounts · {5}"),
    OP_WRONG_PASSWORD("the master password is wrong; nothing was sent", words = "That master password isn't right. Nothing was sent."),
    OP_NOT_THE_OPERATOR("the server says this account is not its operator; nothing was done", words = "The server says this account isn't its operator. Nothing was changed."),
    OP_NO_SUCH_ACCOUNT("the server has no such account (any more); nothing was done", words = "The server has no such account, or no longer has it. Nothing was changed."),
    OP_CANNOT_TARGET_SELF("the operator account cannot disable or delete itself; nothing was done", words = "The operator account can't disable or delete itself. Nothing was changed."),
    OP_NOT_DISABLED_LONG_ENOUGH("not deleted: the account is not disabled, or not for 30 days yet; nothing was deleted", words = "Not deleted: the account isn't disabled, or hasn't been for 30 days yet."),
    OP_BLOCKED_BY_SHARED_VAULT("not deleted: the account owns a shared vault that others are in; nothing was deleted", words = "Not deleted: the account owns a shared vault that others are in."),
    OP_NO_SUCH_DEVICE("the server has no such device (any more); nothing was done", words = "The server has no such device, or no longer has it. Nothing was changed."),
    OP_NOT_TIGHTER("not saved: here sign-up can only be made stricter; loosening it is done on the server's host; nothing was stored", words = "Not saved. Here you can only make sign-up stricter: to open it up, change the server's settings on its host. Nothing was stored."),
    OP_BAD_POLICY("not saved: the server refused a value outside what it allows; nothing was stored", words = "Not saved: the server refused a value outside what it allows. Nothing was stored."),
    OP_NO_ESCROW("this account keeps no recovery copy for the operator", words = "The server holds no recovery copy for this account. Nothing was changed."),
    OP_REQUEST_NOT_READY("not uploaded: the server says the request is still in its hold, was cancelled, or is gone", words = "Not sent: the server says this request is still in its 7-day wait, was cancelled, or has ended."),
    // The shared code's CARD_MOVED_ON is every chain refresh that was not current, and its CARD_REFUSED also this computer's
    // own refusals before sending (the reader of 2026-11-17): lines true of all of them, until it tells them apart.
    OP_CARD_NOT_CURRENT("the identity card was not changed: another device of this account may have changed the server's card meanwhile, or andvari could not read the card just now; nothing was signed or changed; refresh, then try again"),
    OP_CARD_REFUSED_EITHER("the new identity card was refused, by the server or by this computer before anything was sent; nothing was changed"),
    OP_ROTATION_CARD_NOT_CURRENT("setting the recovery key stopped before the identity card changed: another device may have changed the card meanwhile, or andvari could not read it just now; if you gave a rotation statement, the server may already hold it; refresh and look at the card before trying again"),
    OP_ROTATION_CARD_REFUSED("the identity card naming the new recovery key was refused, by the server or by this computer before sending; if you gave a rotation statement, the server may already hold it; refresh and look at the card before trying again"),
    OP_SETUP_NOT_FINISHED("finishing the set-up did not go through: the server refused it for a reason andvari has no words for, or this computer's session had ended before anything was sent; nothing is pinned here; refresh, then try again"),
    OP_SETUP_CARD_NOT_TAKEN("finishing the set-up stopped: the server refused the server's first identity card, or took it and this computer could not confirm it as the card it signed, so nothing is pinned here; refresh, then try again"),
    OP_MOVE_CARD_STORED("after a move: the identity card that names the new address is signed and the server says it stored it; a card that moves the server is never shown as current at the old address, so this console shows no more of it here; say what the operator does next"),
    OP_POLICY_NOT_A_WHOLE_NUMBER("the server's rules: each field takes a whole number of 0 or more (only the sign-up cap may be left empty); nothing was sent"),
    OP_POLICY_KDF_MEM_NOT_KIB("the server's rules: the memory for the key derivation must be a whole number of KiB (a multiple of 1024 bytes); nothing was sent"),
    OP_ESCROW_NOT_SAVED("the recovery copy was not saved there; it was handed over once and is gone from this computer, so to save another, download it again, which emails the person again"),
    OP_AUDIT_REFRESH_GRACE("audit line (refresh_grace): a session token the server had already replaced was presented again within a minute and answered (the server's sixty-second grace); the account, the device and the caller's address are shown with it"),
    // The shared code answers ROTATION_REFUSED also for a statement that checks out but leads to another key than the
    // fingerprint typed, so the line must be true of both (the earlier one named only the first).
    OP_ROTATION_REFUSED_EITHER("the rotation statement does not check out against the current recovery key, or it leads to another recovery key than the fingerprint you typed; nothing was changed"),
    OP_SETUP_ALREADY_DONE("this server already has its identity card", words = "This server already has its identity card."),
    OP_NOT_TAKEN("the server's answer could not be used (it contradicted itself, or something failed); nothing of it was taken", words = "andvari couldn't use the server's answer, so it took nothing from it. Refresh to see where things stand."),
    OP_DONE_DISABLED("disabled (account)", words = "{0} is disabled."),
    OP_DONE_ENABLED("enabled (account)", words = "{0} is enabled again."),
    OP_DONE_QUOTA("quota saved for (account)", words = "The limits for {0} are saved."),
    OP_DONE_REVOKED("signed out (device) of (account)", words = "{0} of {1} is signed out."),
    OP_DONE_POLICY("policy saved", words = "The server's rules are saved."),
    OP_DONE_RENAMED("card signed: the server is now called (name)", words = "The new identity card is signed. The server is now called {0}."),
    OP_DONE_MOVED("card signed: the server's address is now (address)", words = "The new identity card is signed. The server's address is now {0}."),
    OP_DONE_RECOVERY_SET("card signed: the recovery key is now (fingerprint)", words = "The new identity card is signed. The recovery key is now {0}."),
    OP_DONE_RECOVERY_REMOVED("card signed: this server no longer offers operator recovery", words = "The new identity card is signed. This server no longer offers operator recovery."),
    OP_STEP_ACCOUNT("account", words = "Account"),
    OP_STEP_ACCOUNT_ID("account's id", words = "Account ID"),
    OP_STEP_DEVICE("device", words = "Device"),
    OP_STEP_DEVICE_ID("device's id", words = "Device ID"),
    OP_STEP_REQUEST("request", words = "Request"),
    OP_STEP_SERVER("server", words = "Server"),
    OP_STEP_SERVER_ADDRESS("server's address", words = "Server's address"),
    OP_STEP_NEW_NAME("new name", words = "New name"),
    OP_STEP_NEW_ADDRESS("new address", words = "New address"),
    OP_STEP_NEW_FP("new recovery key's fingerprint", words = "New recovery key's fingerprint"),
    OP_STEP_STATEMENT_GIVEN("with the rotation statement given: a signed change", words = "With the rotation statement: a signed change"),
    OP_STEP_DEFAULT("the server's default", words = "The server's default"),
    OP_STEP_CHANGE("changes (what, from, to)", words = "{0}: {1} → {2}"),
    OP_STEP_NO_CHANGE("nothing changes", words = "Nothing changes"),
    OP_STEP_AS_CHOSEN("as on show when this was chosen; the list is not read again for this step", words = "As shown when you chose this. The list isn't read again for this step."),
    OP_STEP_GONE("what this was for is no longer on show; nothing was sent", words = "What this was for isn't shown any more, so nothing was sent."),
    OP_STEP_NEXT("next: the master password", words = "Next: your master password"),
    OP_REMOVE_WHAT_CARD("this signs a new identity card that names no recovery key: the server stops offering operator recovery", words = "This signs a new identity card that names no recovery key, so the server stops offering operator recovery."),
    OP_REMOVE_WHAT_LATER("it cannot be undone by a rotation: a recovery key set later is an unsigned change, so everyone who turns operator recovery on afterwards is warned, every time", words = "A rotation can't undo it: a recovery key set later is an unsigned change, so everyone who turns operator recovery on afterwards is warned, every time."),
    // The person's device reads the card before every look at a kept request and stops at its next look, during the
    // 7-day wait too: it never reaches an answer to refuse (the earlier line said it says so only after the wait).
    OP_REMOVE_REQUESTS_STOP("requests for help made before cannot be answered any more: the person's device stops each one the next time it looks, also during the 7-day wait"),
    OP_REMOVE_TYPE("to confirm, type this server's address as shown above", words = "To confirm, type this server's address as shown above."),
    OP_REMOVE_TYPED_WRONG("what was typed is not this server's address; nothing was signed", words = "That isn't this server's address. Nothing was signed."),
    OP_STEP_INSTANCE_ID("this server's instance id, as this computer's pin holds it (recovery-cli assist and rotate need it)", words = "This server's instance ID, as this computer keeps it (recovery-cli assist and rotate ask for it)"),
    OP_STEP_RECOVERY_FP("the recovery key the pinned card names (its fingerprint)", words = "The recovery key the server's identity card names, by its fingerprint"),
    OP_PIN_HOLDS_NONE("this computer's pin does not hold it", words = "This computer doesn't keep it"),
    OP_CARD_NAMES_NO_RECOVERY_KEY("the pinned card names no recovery key", words = "The server's identity card names no recovery key"),
    OP_ACCOUNTS("accounts", words = "Accounts"),
    OP_COUNTS_DISAGREE("the server's own count of accounts and its own list disagree (count, accounts listed); both are shown as the server gave them", words = "The server counts {0} accounts but lists {1}. Both are shown as the server gave them."),
    OP_STATUS_DISABLED("disabled", words = "Disabled"),
    OP_ROLE_OPERATOR("this server's operator account", words = "This server's operator account"),
    OP_ACCOUNT_ROW("created, last seen, recovery as the server records it, storage used, items, vaults owned, devices signed in"),
    OP_NEVER("never", words = "never"),
    OP_DISABLED_SINCE("disabled since", words = "Disabled since {0}"),
    OP_MANAGE("manage (account)", words = "Manage {0}"),
    OP_DISABLE_WHY("why it is disabled (the person is told which)", words = "Why are you disabling it? The person is told which of these you chose."),
    OP_WHY_ABUSE("abuse", words = "Abuse"),
    OP_WHY_REQUEST("at the person's request", words = "At the person's request"),
    OP_WHY_OTHER("other", words = "Another reason"),
    OP_DISABLE("disable (account)", words = "Disable {0}"),
    OP_ENABLE("enable (account)", words = "Enable {0}"),
    OP_QUOTA("quota for (account)", words = "Limits of {0}"),
    OP_QUOTA_DEFAULTS("the server's defaults: storage in bytes, items, shared vaults owned, open links", words = "The server's defaults: storage {0} · items {1} · shared vaults it can own {2} · open links {3}"),
    OP_QUOTA_BYTES("storage, in bytes (empty: the server's default)", words = "Storage, in bytes"),
    OP_QUOTA_ITEMS("items (empty: the server's default)", words = "Items"),
    OP_QUOTA_VAULTS("shared vaults owned (empty: the server's default)", words = "Shared vaults it can own"),
    OP_QUOTA_LINKS("open links (empty: the server's default)", words = "Open links"),
    OP_QUOTA_SAVE("save the quota for (account)", words = "Save the limits of {0}"),
    OP_NOT_A_WHOLE_NUMBER("each field takes a whole number of 0 or more, or nothing; nothing was sent", words = "Each field takes a whole number, 0 or more, or nothing. Nothing was sent."),
    OP_DELETE("delete this account (account)", words = "Delete {0}"),
    OP_DELETE_WHAT("deleting it removes the account, its personal vault and every vault only it holds from the server for good, and the person is emailed at the address the server has; it signs nothing for them, so they stay in other people's vault histories until each owner removes them", words = "Deleting removes the account from the server for good, with its personal vault and every vault nobody else is in. The person is emailed at the address the server has. Shared vaults they were in keep listing them, as deleted by the operator, until each vault's owner removes them from the list."),
    OP_DELETE_WHY("why it is deleted"),
    OP_DELETE_WHY_30_DAYS("it has been disabled for at least 30 days"),
    OP_DELETE_WHY_UNDER_AGE("the account holder is under the minimum age"),
    OP_DELETE_UNDER_AGE_DETAIL("this lifts the 30 days and nothing else: the account must already be disabled"),
    OP_DELETE_RECORD("the server will record in its audit that its operator deleted an account, naming it by a pseudonym; this record is the operator's own and is kept for the audit's usual time, after the account itself is gone", words = "The server will record in its audit list that you, its operator, deleted an account. The record names the account by a pseudonym, not by its email address, and stays for as long as the audit list keeps its records, after the account itself is gone."),
    OP_DELETE_RECORD_UNDER_AGE("the server will record in its audit that its operator deleted an account because its holder is under the minimum age, naming it by a pseudonym; this record is the operator's own and is kept for the audit's usual time, after the account itself is gone", words = "The server will record in its audit list that you, its operator, deleted an account because its holder is under the minimum age. The record names the account by a pseudonym, not by its email address, and stays for as long as the audit list keeps its records, after the account itself is gone."),
    OP_DELETE_CONFIRM("delete (account) permanently", words = "Delete {0} permanently"),
    OP_DELETED("deleted: (account)", words = "{0} was deleted."),
    OP_DEVICES_OF("devices of (account)", words = "Devices of {0}"),
    OP_DEVICES_READING("reading the devices; they show once the whole list has arrived", words = "Reading the devices. They show once the whole list has arrived."),
    OP_NO_DEVICES("no devices", words = "No devices"),
    OP_DEVICE_LIVE("signed in (added, last seen, version, how it joined)"),
    OP_DEVICE_NOT_LIVE("signed out (added, last seen, version, how it joined)"),
    OP_REVOKE_DEVICE("sign this device out (device); the person is emailed", words = "Sign out {0}"),
    OP_DEVICES_CLOSE("hide the devices", words = "Hide the devices"),
    OP_AUDIT("audit", words = "Audit list"),
    OP_AUDIT_OF("show the audit for (account)", words = "Audit list for {0}"),
    OP_AUDIT_DAY("the last day", words = "The last day"),
    OP_AUDIT_WEEK("the last 7 days", words = "The last 7 days"),
    OP_AUDIT_MONTH("the last 30 days", words = "The last 30 days"),
    OP_AUDIT_ALL("everything the server keeps", words = "Everything the server keeps"),
    OP_AUDIT_TYPE("type, chosen from those the server has sent", words = "Type: {0}"),
    OP_AUDIT_ANY_TYPE("every type", words = "Every type"),
    OP_AUDIT_FOR("only (account)", words = "Only {0}"),
    OP_AUDIT_ANY_ACCOUNT("every account", words = "Every account"),
    OP_AUDIT_READ("read the audit", words = "Read the audit list"),
    OP_AUDIT_FILTERED_HERE("the filters are sent to the server, which answers with the newest 500 rows that match them, newest first", words = "andvari sends these choices to the server, which answers with the newest 500 records that match them, newest first."),
    OP_AUDIT_PAGE_FULL("the page is full: older rows that match exist and are not shown; narrow the time, the type or the account to see them", words = "The page is full: older rows that match aren't shown. Narrow the time, the type or the account to see them."),
    OP_AUDIT_EMPTY("no rows", words = "No records"),
    OP_POLICY("policy", words = "The server's rules"),
    OP_POLICY_SUMMARY("locks after, clears copies after, offline copy allowed, sign-up mode stored, cap stored", words = "Locks after {0} seconds · clears a copied password after {1} seconds · offline copy {2} · sign-up set here: {3} · cap set here: {4}"),
    OP_POLICY_EDIT("change the policy of (server)", words = "Change the rules of {0}"),
    OP_POLICY_AUTO_LOCK("lock after this many idle seconds (1 to 900)", words = "Lock after this many seconds without use (1 to 900)"),
    OP_POLICY_CLIPBOARD("clear a copied secret after this many seconds (1 to 300)", words = "Clear a copied password after this many seconds (1 to 300)"),
    OP_POLICY_OFFLINE("devices may keep an offline copy", words = "Devices may keep an offline copy"),
    OP_POLICY_ACCESS_TTL("a session's access lasts this many seconds (at least 60)", words = "A device's access lasts this many seconds before it renews it (at least 60)"),
    OP_POLICY_REFRESH_TTL("a session can be renewed for this many days (at least 1)", words = "A device can renew its sign-in for this many days (at least 1)"),
    OP_POLICY_ATTACHMENT("largest file, in bytes", words = "Largest file, in bytes"),
    OP_POLICY_ITEM_ATTACHMENTS("files of one item together, in bytes", words = "All the files on one item together, in bytes"),
    OP_QUOTA_DEFAULTS_TITLE("each account's default quota", words = "Each account's limits, unless set for that account"),
    OP_QUOTA_BYTES_DEFAULT("storage, in bytes", words = "Storage, in bytes"),
    OP_QUOTA_ITEMS_DEFAULT("items", words = "Items"),
    OP_QUOTA_VAULTS_DEFAULT("shared vaults owned", words = "Shared vaults it can own"),
    OP_QUOTA_LINKS_DEFAULT("open links", words = "Open links"),
    OP_POLICY_KDF_OPS("master-password hashing: passes", words = "Master-password hashing: passes"),
    OP_POLICY_KDF_MEM("master-password hashing: memory, in bytes (a whole number of KiB)", words = "Master-password hashing: memory, in bytes (a multiple of 1024)"),
    OP_POLICY_SIGNUP("sign-up", words = "Sign-up"),
    OP_SIGNUP_MODE("mode"),
    OP_SIGNUP_NOTHING_STORED("mode: store nothing (the host's setting governs)", words = "As the host sets it"),
    OP_POLICY_CAP("cap on accounts (empty: store nothing)", words = "Most accounts allowed (leave empty to keep the host's setting)"),
    OP_POLICY_MIN_VERSIONS("minimum app versions, kept as read", words = "Oldest andvari versions the server accepts, not changed here: {0}"),
    OP_POLICY_SAVE("save the policy of (server)", words = "Save the rules of {0}"),
    OP_ESCROW("the account's recovery copy, for recovery-cli on an offline computer", words = "This account's recovery copy, for recovery-cli on a computer kept offline"),
    OP_ESCROW_DOWNLOAD("download the recovery copy of (account)", words = "Download the recovery copy of {0}"),
    OP_ESCROW_READY("the recovery copy of (account) is here: save it to a file; it is handed over once", words = "The recovery copy of {0} is here. Save it to a file: andvari hands it over only once."),
    OP_ESCROW_SAVE("save the recovery copy of (account) to a file", words = "Save the recovery copy of {0} to a file"),
    OP_ESCROW_SAVED("the recovery copy of (account) is saved at (file): take it to the offline computer, and delete it from this one once it has been used", words = "The recovery copy of {0} is saved as {1}. Take it to the computer you keep offline, and delete it from this one once it has been used."),
    OP_ESCROW_TAKEN("the recovery copy was handed over once already; to save another, download it again (the person is emailed again)", words = "The recovery copy was handed over once already. To save another, download it again. The person is emailed again."),
    OP_REQUESTS("requests for the operator's help", words = "Requests for the operator's help"),
    OP_NO_REQUESTS("no requests", words = "No requests"),
    OP_FULFIL_FOR_OPERATOR("what answering a request means for you", words = "What answering a request means for you"),
    OP_FULFIL_FOR_PERSON("what it means for the person", words = "What it means for the person"),
    OP_NO_REFUSE("there is no refusing a request here: only the person's own devices can cancel it; left alone, it ends by itself", words = "You can't refuse a request here. Only the person's own signed-in devices can cancel it, and if nobody acts, it ends by itself."),
    OP_REQUEST_ROW("asked, address checked, hold ends, platform as the requesting device reported it", words = "Asked {0} · email confirmed {1} · wait ends {2} · from {3}, as that device reported it"),
    OP_REQUEST_IDS("the request and its key, which recovery-cli assist needs; whatever you check the account against comes from the person, never from the server, so the server's account ID is not shown here", words = "The person's account ID, then what recovery-cli assist takes as --request, --request-key and --user, in that order."),
    OP_FULFIL("upload the answer for (account)"),
    OP_FULFIL_AGAIN("upload another answer for (account): it replaces the one uploaded before"),
    OP_FULFIL_ANSWER("the last line recovery-cli assist printed (it starts andvari-answer:), or its whole output", words = "The answer recovery-cli assist made"),
    OP_FULFIL_FROM_FILE("read the answer from a file", words = "Read the answer from a file"),
    OP_FULFIL_FILE_READ("the answer was read from the file and passed the check; what the file holds is not shown here", words = "The answer was read from the file and passed the check. What the file holds isn't shown here."),
    OP_FULFIL_EMPTY("there is no answer to upload yet; nothing was sent", words = "There's no answer to send yet. Nothing was sent."),
    OP_FULFILLED("answer uploaded for (account); until the person has finished, another upload replaces it", words = "The answer for {0} was sent."),
    OP_IDS_HOW_SHOWN("in groups of four; every digit bold, underlined and in colour; copy takes the value whole, without spaces", words = "In groups of four, every digit bold, underlined and in colour. Copy takes the value whole, without spaces."),
    OP_COPY("copy (what)", words = "Copy {0}"),
    OP_COPIED("copied (what): paste it into recovery-cli assist", words = "Copied {0}. Paste it into recovery-cli assist."),
    OP_FULFIL_CHECK("check the answer", words = "Check the answer"),
    OP_FULFIL_CHECKED("this names this request and its key, and has the size of an answer for the address the request was made for; this computer cannot open it, so only the person's device can tell whether it is right", words = "This answer names this request and its key, and has the size of an answer for the address the request was made for. This computer can't open it, so only the person's device can tell whether it's right."),
    OP_FULFIL_REPLACES("an answer is already on the server for this request: this upload replaces it", words = "An answer is already on the server for this request. This upload replaces it."),
    OP_REQUEST_ADDRESS_SAID("this is the address the server says the request was made for; recovery-cli assist will ask you to type the person's address from your own knowledge, and compares it with the recovery copy", words = "This is the address the server says the request was made for. recovery-cli assist asks you to type the person's address from what you know, and compares it with the recovery copy."),
    OP_REQUEST_STATE_HOLDING("not answered: still in its hold", words = "Not answered: still in its 7-day wait"),
    OP_REQUEST_STATE_WAITING("not answered yet", words = "Not answered yet"),
    OP_REQUEST_STATE_READY("answered: an answer is on the server; until the person has finished, you can upload another, and the newer upload replaces the older", words = "Answered. Until the person has finished, you can upload another answer, and the newer one replaces the older."),
    OP_REQUEST_STATE_NOT_GIVEN("the server did not say whether this request was answered", words = "The server didn't say whether this request was answered."),
    OP_REQUEST_ROW_NOT_VALID("the server's row for this request has no valid address, so no answer can be checked against it; nothing was sent", words = "The server's row for this request has no valid address, so no answer can be checked against it. Nothing was sent."),
    OP_ANSWER_NOT_ONE("this is not an answer: copy only the last line recovery-cli assist printed (it starts andvari-answer:); nothing was sent", words = "This isn't an answer. Copy only the last line recovery-cli assist printed, which starts andvari-answer:. Nothing was sent."),
    OP_ANSWER_BARE("this is an answer without its request: give the whole last line recovery-cli assist printed (andvari-answer:…), not only its end; nothing was sent", words = "This is an answer without its request. Paste the whole last line recovery-cli assist printed (andvari-answer:…), not only its end. Nothing was sent."),
    OP_ANSWER_IS_THE_COPY("this is the recovery copy, which recovery-cli assist reads, not the answer it writes; nothing was sent", words = "This is the recovery copy, which recovery-cli assist reads, not the answer it writes. Nothing was sent."),
    OP_ANSWER_OTHER_REQUEST("this answer names another request; nothing was sent", words = "This answer names another request. Nothing was sent."),
    OP_ANSWER_OTHER_KEY("this answer names this request with another request key: it was made for another request's key; nothing was sent", words = "This answer names this request but another request key, so it was made for another request. Nothing was sent."),
    OP_ANSWER_CUT_SHORT("this answer is shorter than an answer for this request's address: it was cut or damaged, or made for another address; nothing was sent", words = "This answer is shorter than an answer for this request's address: it was cut short or damaged, or made for another address. Nothing was sent."),
    OP_ANSWER_TOO_LONG("this answer is longer than an answer for this request's address: something was added to it or it is damaged, or it was made for another address; nothing was sent", words = "This answer is longer than an answer for this request's address: something was added to it, it's damaged, or it was made for another address. Nothing was sent."),
    OP_CARD("this server's identity card", words = "This server's identity card"),
    OP_HANDOVER_CLI("handing this server over to another operator is done with the command-line tool (andvari-cli operator), not here", words = "To hand this server over to another operator, use andvari-cli operator. It can't be done here."),
    OP_CARD_CHANGE("change the name, the address or the recovery key", words = "Change the name, the address or the recovery key"),
    OP_CARD_NAME("the server's name", words = "The server's name"),
    OP_CARD_NAME_EMPTY("the name is empty; nothing was signed", words = "The name is empty. Nothing was changed."),
    OP_CARD_RENAME("sign a card for (server) with a new name", words = "Rename {0}"),
    OP_CARD_ORIGIN("the server's new address", words = "The server's new address"),
    OP_CARD_MOVE_WHAT("devices follow the move after one tap; the store apps never follow a move of the public server", words = "Devices that use this server follow the move with one tap, and are asked to make a new recovery kit. The store versions of andvari never follow a move of the public server: it moves with an app update."),
    OP_CARD_MOVE("sign a card for (server) with a new address"),
    OP_RECOVERY_KEY("the recovery key for operator recovery", words = "The recovery key for operator recovery"),
    OP_RECOVERY_FP("the new recovery key's fingerprint (64 hex, from recovery-cli)", words = "The new recovery key's fingerprint, from recovery-cli (64 characters, 0–9 and a–f)"),
    OP_ROTATION_STATEMENT("the rotation statement recovery-cli rotate made with the old key (empty: none)", words = "The rotation statement recovery-cli rotate made with the old key (leave empty if you have none)"),
    OP_ROTATION_UNSIGNED("without a rotation statement the change is unsigned: everyone who chose operator recovery is asked whether to keep it, with turning it off as the default", words = "Without a rotation statement, the change isn't vouched for by the old key: everyone who chose operator recovery is asked whether to keep it, with turning it off as the default."),
    OP_RECOVERY_SET("sign a card for (server) with a new recovery key", words = "Use this recovery key for {0}"),
    OP_RECOVERY_REMOVE("stop offering operator recovery on (server)", words = "Stop offering operator recovery on {0}"),
    OP_FINGERPRINT_SHAPE("a fingerprint is 64 hex characters; nothing was signed", words = "A fingerprint is 64 characters, 0–9 and a–f. Nothing was changed."),

    // The current app's structure (the vault's toolbar, its list, an item's view, the editors, Settings, Sharing): the
    // labels its controls carry, none of them approved for the new line yet.
    ITEM_ADD("add", words = "Add"),
    ITEM_ADD_NOTE("add note", words = "Add note"),
    ITEM_ADD_CARD("add card", words = "Add card"),
    TYPE_ALL("all types", words = "All types"),
    TYPE_LOGINS("logins", words = "Logins"),
    TYPE_NOTES("notes", words = "Notes"),
    TYPE_CARDS("cards", words = "Cards"),
    KIND_LOGIN("login", words = "Login"),
    KIND_CARD("card", words = "Card"),
    KIND_NOTE("note", words = "Secure note"),
    ROW_NOTE("secure note", words = "Secure note"),
    VAULT_NO_MATCH("nothing matches", words = "Nothing matches."),
    ITEM_EDIT_BUTTON("edit", words = "Edit"),
    ITEM_DELETE_TITLE("delete this item?", words = "Move this item to the trash?"),
    ITEM_KEEP("keep", words = "Keep"),
    ITEM_EXPIRY("expiry", words = "Expiry"),
    ITEM_EXPIRED("expired", words = "Expired"),
    EDITOR_CANCEL("cancel", words = "Cancel"),
    EDITOR_DISCARD_TITLE("discard changes?", words = "Discard your changes?"),
    EDITOR_DISCARD_BODY("anything typed in this editor will be lost", words = "What you typed here hasn't been saved and will be lost."),
    EDITOR_KEEP_EDITING("keep editing", words = "Keep editing"),
    EDITOR_DISCARD("discard", words = "Discard"),
    IMPORT_PASSWORDS("import passwords", words = "Import passwords"),
    BACKUP_TITLE("vault backup", words = "Vault backup"),
    ACCOUNT_TITLE("this account", words = "This account"),

    // Seen on the virtual display: states that drew nothing.
    VAULT_OPENING("opening your vault", words = "Opening your vault…"),
    PEOPLE_NONE("nobody yet: the people you connect with through a link are listed here", words = "Nobody here yet. The people you connect with through a link show up here."),

    // The list's rows as the current app has them.
    // The chip names the sort once; its menu's lines name only the order, as the current app's menu does.
    SORT_NAME("sort: name", words = "Sort: name"),
    SORT_RECENT("sort: recent", words = "Sort: recently updated"),
    SORT_CHOICE_NAME("name", words = "Name"),
    SORT_CHOICE_RECENT("recently updated", words = "Recently updated"),
    VAULTS_ALL("all vaults", words = "All vaults"),
    ROW_SHARED_VAULT("a shared vault", words = "Shared vault"),
    VIEW_ONLY("view only", words = "View only"),
    TRASH_NOT_READ("not read yet; restore reads it first", words = "Not read yet. Restore reads it first."),
    TRASH_NAME_UNREADABLE("an item no version of which can be read here", words = "An item that can't be read on this computer"),

    // The console's answer read from a file.
    OP_ANSWER_FILE_NOT_TEXT("this file is not text: choose the file recovery-cli assist wrote, or paste its last line", words = "This file isn't text. Choose the file recovery-cli assist wrote, or paste its last line."),

    // Two-step sign-in with the master password.
    TWO_STEP_NEW_KEY("get a new authenticator key", words = "Get a new key for your authenticator app"),
}
