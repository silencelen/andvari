package io.silencelen.andvari.desktop.trust

/**
 * The wording the owner approved on 2026-11-15 (`andvari-copy-2026-11-15/copy.json`, all 28 entries), for the strings
 * the desktop held as placeholders. Each entry is copied exactly; its id is `<copy.json key>.<title|body|buttonN>`.
 * `{0}`, `{1}`, … are filled as core fills its sentences ([fillTemplate]). A body of two lines (entries 12, 21, 24, 26)
 * is split at its line break where the two lines stand in different places ([line]).
 *
 * `ApprovedCopyTest` compares every entry here with the approved file when that file is on the machine.
 */
internal object ApprovedCopy {
    val text: Map<String, String> = mapOf(
        "FIRST_SIGNUP_INVITATION_ONLY.body" to "If someone sent you an invitation link, use {0}.",
        "FIRST_SIGNUP_INVITATION_ONLY.button0" to "Sign-up is invitation-only right now",
        "FIRST_SIGNUP_CLOSED.body" to "You can still sign in to an account you already have.",
        "FIRST_SIGNUP_CLOSED.button0" to "Sign-up is closed right now",
        "SERVER_CREATE_ACCOUNT.button0" to "Create an account here",
        "SERVER_CREATE_ACCOUNT.button1" to "Sign in",
        "SERVER_INVITATION_ONLY.body" to "This server is invitation-only. To create an account, ask someone who uses it for an invitation link.",
        "SERVER_INVITATION_ONLY.button0" to "Sign in",
        "SERVER_NOT_TAKING_ACCOUNTS.body" to "This server isn't taking new accounts right now.",
        "SERVER_NOT_TAKING_ACCOUNTS.button0" to "Sign in",
        "OLD_DATA_NOT_REMOVED.title" to "Some old andvari data is still on this device",
        "OLD_DATA_NOT_REMOVED.body" to "andvari couldn't remove data that an earlier version left on this device. This version never opens it. andvari will try again each time it starts.",
        "OLD_DATA_NOT_REMOVED.button0" to "Try again",
        "OLD_DATA_NOT_REMOVED.button1" to "Continue",
        "CARD_OTHER_ADDRESS.title" to "This address doesn't match the server's identity card",
        "CARD_OTHER_ADDRESS.body" to "The server at {0} showed an identity card made for a different address, {1}. andvari didn't connect, and nothing of yours was sent. The address may be wrong, the server may have moved, or someone may be imitating it. Check the address with the person who runs the server.",
        "GATE_TITLE_KIND_CHANGE.title" to "This server says it changed",
        "GATE_TITLE_KIND_CHANGE.button0" to "Continue",
        "GATE_TITLE_KIND_CHANGE.button1" to "Not now",
        "CARD_NOT_VERIFIED.body" to "This server showed an update to its identity card that andvari can't verify. andvari ignored it and kept the card it had already checked. If this message stays, ask the operator what happened.",
        "CARD_RECORD_DAMAGED.title" to "andvari can't read its record of this server",
        "CARD_RECORD_DAMAGED.body" to "The record this device keeps of the identity of {0} is damaged, or comes from a newer version of andvari. Without it andvari can't tell whether this is still the same server, so it has stopped using it on this device.\nIf you went back to an older version of andvari, update it. Otherwise choose Forget this server and connect again. That removes this server's data from this device, including changes that hadn't synced. Your account on the server is not affected.",
        "CARD_RECORD_DAMAGED.button0" to "Forget this server",
        "CARD_MOVE_NOT_FOLLOWED.title" to "andvari didn't follow this move",
        "CARD_MOVE_NOT_FOLLOWED.body" to "This device already knows {0} as a server, and a move never replaces a server this device already knows. Nothing changed. If you set it up on this device yourself, as this server's new address, sign out and sign in there. If you didn't, ask this server's operator what happened.",
        "LINK_REQUIRED.title" to "This device needs to be linked",
        "LINK_REQUIRED.body" to "{0} on {1} ({2}) has “New devices must be linked” turned on, and this device is new to it. Your master password was right. Link this device from one you already use. If you have none, recover the account with your recovery kit, which sets a new master password and turns this setting off.",
        "LINK_REQUIRED.button0" to "Link from your other device",
        "LINK_REQUIRED.button1" to "Cancel",
        "RECOVERY_CHECK_ACCOUNT.title" to "Is this your account?",
        "RECOVERY_CHECK_ACCOUNT.body" to "Check this against the account ID in an earlier andvari email to you. If it is different, stop.",
        "RECOVERY_CHECK_ACCOUNT.button0" to "It's the same",
        "RECOVERY_CHECK_ACCOUNT.button1" to "It's different",
        "RECOVERY_CHECK_ACCOUNT.button2" to "Not now",
        "RECOVERY_CHECK_STOPPED.body" to "andvari stopped. No password was set and nothing was changed. Tell the operator that the account they restored wasn't yours.",
        "PERSON_FROM_OTHER_DEVICE_HINT.body" to "If you don't recognise them, choose Don't use.",
        "PERSON_FROM_OTHER_DEVICE_HINT.button0" to "Use on this device",
        "PERSON_FROM_OTHER_DEVICE_HINT.button1" to "Don't use",
        "PEOPLE_NOT_REVIEWED.body" to "You haven't said which of these people to use on this device. Vaults they share with you wait until you do.",
        "PEOPLE_NOT_REVIEWED.button0" to "Review the list",
        "INCOMING_CONFIRM_FIRST.body" to "{0} wants to share a vault with you. Confirm them on this device first.",
        "COMPARE_READ_AND_TYPE.body" to "Read this to {0}.\nAsk {0} to read the code on their device, then type it here.",
        "VAULT_HISTORY_FORKED.body" to "This shared vault's history has two versions that can't both be true. The server may be misbehaving. The vault is read-only on this device from now on. You can still read it, copy items out, or remove it from this device.",
        "VAULT_KEY_MISSING.title" to "A shared vault andvari can't open",
        "VAULT_KEY_MISSING.body" to "The server didn't give this device a key that opens this vault, so nothing in it can be shown here. Try again later. If it stays closed, ask the vault's owner to share it with you again. If you own it, open it on another of your devices and use Move everything to a new vault.",
        "VAULT_CHANGE_WAITING.body" to "andvari sent your change but got no answer from this server, so it can't tell yet whether it went through. It will keep sending the same change until the server confirms it. You don't need to do it again.\nwaiting for the server",
        "MEMBERS_MAY_BE_INCOMPLETE_WHY.body" to "An item in this vault mentions history the server hasn't shown, so there may be members this device can't see.",
        "OWNERSHIP_OFFER.title" to "Make {0} the owner of “{1}”?",
        "OWNERSHIP_OFFER.body" to "Nothing changes until they accept in their app. They have 14 days, and you can cancel until then. Afterwards they manage the vault's members, and only they can rename it, hand it over or delete it. You stay in it as a writer.\nYou asked {0} to take over “{1}”. They can accept until {2}.",
        "OWNERSHIP_OFFER.button0" to "Ask {0} to take over",
        "OWNERSHIP_OFFER.button1" to "Cancel",
    )

    /** The approved words [id], filled with [values]. */
    fun words(id: String, vararg values: String): String = fillTemplate(text.getValue(id), values.toList())

    /** Line [n] (from 0) of the approved words [id], filled with [values]. */
    fun line(id: String, n: Int, vararg values: String): String = fillTemplate(text.getValue(id).split('\n')[n], values.toList())

    /** As [words], where some slots may hold the plain words for a name not known ([Slot]). */
    fun wordsWith(id: String, vararg slots: Slot): String = fillTemplate(text.getValue(id), slots.map { it.text }, unnamedOf(slots))

    /** As [line], where some slots may hold the plain words for a name not known ([Slot]). */
    fun lineWith(id: String, n: Int, vararg slots: Slot): String =
        fillTemplate(text.getValue(id).split('\n')[n], slots.map { it.text }, unnamedOf(slots))

    // The SERVER_* and LINK_REQUIRED_* keys: core carries their approved words itself now, so the
    // desktop shows core's; `ApprovedCopyTest` pins that core's words are these entries exactly.
}

/**
 * What goes into one slot of a sentence: a name someone chose ([named]), or the plain words that stand where no name
 * is known. A sentence quotes a name's slot itself (“{0}”); plain words are not a name to quote, so the sentence's
 * quotes around their slot go, as the shared code fills its own lines.
 */
internal class Slot(val text: String, val named: Boolean)

/** A value that is not a name, or a name that is known: it goes in as it is. */
internal fun said(text: String) = Slot(text, named = true)

/** A vault's name, or, where it is not known (null or empty), the plain words for a vault whose name can't be read. */
internal fun vaultSlot(name: String?): Slot =
    if (name.isNullOrEmpty()) Slot(UiText.ph(Placeholder.VAULT_NAME_UNREADABLE).shown(), named = false) else Slot(name, named = true)

internal fun unnamedOf(slots: Array<out Slot>): Set<Int> = slots.indices.filter { !slots[it].named }.toSet()

/**
 * A sentence with its values, filled the way core fills one (one pass; a value reading "{0}" is copied as it is). A
 * slot in [unnamed] holds plain words, not a name: the sentence's own quotes around it (“{n}”) are left out.
 */
internal fun fillTemplate(t: String, values: List<String>, unnamed: Set<Int> = emptySet()): String {
    val out = StringBuilder()
    var i = 0
    while (i < t.length) {
        val quoted = t[i] == '“' && i + 1 < t.length && t[i + 1] == '{'
        val open = if (quoted) i + 1 else i
        val close = if (t[open] == '{') t.indexOf('}', open) else -1
        val index = if (close > open + 1) t.substring(open + 1, close).toIntOrNull() else null
        if (index != null && index in values.indices) {
            val closed = quoted && close + 1 < t.length && t[close + 1] == '”'
            if (closed && index in unnamed) {
                out.append(values[index])
                i = close + 2
            } else {
                if (quoted) out.append('“')
                out.append(values[index])
                i = close + 1
            }
        } else {
            out.append(t[i])
            i++
        }
    }
    return out.toString()
}
