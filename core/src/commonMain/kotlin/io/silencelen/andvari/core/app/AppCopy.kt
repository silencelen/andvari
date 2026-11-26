package io.silencelen.andvari.core.app

/**
 * The sentences the onboarding and trust design gives word for word (docs/design/2026-11-15-onboarding-trust.md),
 * one key each. IF-3 never carries a display string the server supplied: a state carries a key and the values the
 * sentence names, and each value's type says whose word it is ([InstanceLabel]: the pinned card's; [PersonName]:
 * a contact's own, or only the server's).
 *
 * [english] is the design's sentence, with `{0}`, `{1}`, … where it names something; the entry's comment says what
 * each stands for. The copy is normative (§7.7: "all clients use the same strings, pinned by tests"), so a client
 * that shows its own words for a key is wrong. Where the design gives no sentence there is no key: a state then
 * carries only its typed reason, and the gap is listed in [AppApi].
 *
 * The exception is a **reserved** key ([reserved]): a screen the design gives no wording at all needs names for its
 * parts before it can be built, so those keys exist with an empty [english] until the owner approves their
 * sentences. The key, where it is shown and the values it takes are final; only the sentence is to come. A client
 * shows its own placeholder for a reserved key and nothing a person is meant to rely on.
 */
enum class CopyKey(
    val english: String,
    /**
     * A PLACEHOLDER, not wording: a line the design requires where neither the design nor the owner has given words
     * yet. [english] is a gloss in `⟦…⟧` that says what the line must say, so it is visibly unfinished if a screen shows
     * it. The key, where it is shown and its values are final; the owner's next wording page replaces the gloss.
     *
     * A line the owner has worded that must gain a clause he has not worded yet is awaiting too: [english] is then his
     * words with that clause as a gloss in `⟦…⟧` where it goes, and the whole line is shown as unfinished until his
     * words for it arrive.
     */
    val awaitingOwner: Boolean = false,
) {
    // ---- §2.2, §3.3: addresses and clocks ----

    /** §2.2: an address the origin grammar cannot carry, refused before the Trust Gate opens (R4). */
    ADDRESS_NEEDS_HTTPS_DOMAIN("andvari needs an https address with a domain name for this server."),

    /** §3.3: the server refused an entry dated ahead of its clock (`400 at_ahead`). The device adopts no time the server suggests. */
    CLOCK_AHEAD("Your device's clock is ahead. Set the correct time and try again."),

    // ---- §3: shared vaults ----

    /** §3.4: a vault key that fails the log's commitment is refused; nothing is decrypted or written under it. */
    VAULT_KEY_REFUSED("key doesn't match this vault's history — the server may be misbehaving"),

    /** §3.6: {0} the contact's label, {1} the vault's name (decrypted only after the log and the key checked). */
    INCOMING_VAULT("{0} wants to share “{1}” with you"),
    INCOMING_ACCEPT("Accept"),
    INCOMING_DECLINE("Decline"),

    /** §3.6: {0} the sender's name as the server reports it. The vault's name is not shown and nothing is decrypted. */
    INCOMING_CONNECT_FIRST("{0} wants to share a vault with you. Connect with them first."),

    /** §3.6: the copy dialog of a frozen or failed vault. */
    CHECK_WHAT_YOU_COPY("Items in this vault may have been changed by someone the server let in. Check what you copy."),

    /** §3.8: said only once the log verified through the tombstone's head and ends in the owner's signed delete. */
    VAULT_DELETED_FOR_GOOD("deleted for good"),

    /**
     * [SharedVaultRow.deletedNoDayLine]: on a deleted shared vault whose grace end the server did not serve. Names no
     * day: the device's own estimate is shown nowhere, since how long a server keeps a deleted vault is its operator's
     * setting. No values.
     */
    VAULT_DELETED_NO_DAY("⟦On a deleted shared vault where the server named no day: the vault is deleted and its owner can restore it for a limited time; names no day (the owner's list of deleted vaults shows until when)⟧", awaitingOwner = true),

    /** §3.9: the log does not verify. */
    VAULT_HISTORY_FAILED("This shared vault's history doesn't check out — the server may be misbehaving."),

    /** §3.9: a served head below the verified one, or entries this device verified are missing. */
    VAULT_HISTORY_WITHHELD("The server is showing an older version of this vault's history."),

    /** §3.9: an item names history a fetch did not bring; the vault's state does not change (FS-R4). */
    VAULT_HISTORY_HINT("An item mentions history the server hasn't shown"),

    /** §3.9: a member whose key is not a pinned contact's (T-R5). */
    MEMBER_UNVERIFIED("unverified member (as the server names them)"),

    /** §3.9: the mark on the member list while an item's hint is unresolved (FC-10). */
    MEMBERS_MAY_BE_INCOMPLETE("may be incomplete"),

    /** §3.11: a deletion met an unverified head dated more than a day ahead; nothing was signed (FS-R7). */
    DELETION_FAR_FUTURE("One of your shared vaults reports a time far in the future. Try again later."),

    /** §3.11: {0} the member's name (their label where pinned, else as the server names them). */
    MEMBER_DELETED_BY_OPERATOR("{0}'s account was deleted by the server's operator."),
    REMOVE_FROM_THE_LIST("Remove from the list"),

    /** §3.13: the remove dialog, which says what removal does not do (T-R6). */
    REMOVE_MEMBER_WARNING(
        "Removing someone stops the server from giving them this vault. It doesn't change the vault's key: if they kept a copy and the server helps them, they could still read and change what's in it. To be sure, move everything to a new vault.",
    ),
    MOVE_EVERYTHING("Move everything to a new vault"),
    REMOVE_FROM_THIS_DEVICE("Remove from this device"),

    // ---- §4.4, §12.3: the instance card and the Trust Gate ----

    /** §12.3: the gate's title on first use. */
    GATE_TITLE_CONNECT("Connect to this server?"),

    /** §12.3: the gate's title when a server is already set. */
    GATE_TITLE_SWITCH("Switch to a different server?"),

    /** §12.3: the gate's title in the device-link wording. */
    GATE_TITLE_DEVICE_LINK("Is this your server?"),

    /** §12.3 "the existing baseline sentence" (design 2026-07-15 §4.3), kept word for word. */
    GATE_BASELINE("This server will store your encrypted vault and see your account activity (email, sign-ins, item counts). Only continue if you trust it."),

    /** §4.4: {0} what the server calls itself. Nobody vouches for it, which is the point of the sentence. */
    GATE_CALLS_ITSELF("It calls itself “{0}” — nobody you know has vouched for it"),

    /** §12.3: added when the person is about to sign in through a pin that is not a password pin (§4.4). */
    GATE_ENTERING_PASSWORD("You're about to enter your master password for this server."),

    /** §12.3, device-link wording: {0} the origin, {1} what the server calls itself. */
    GATE_DEVICE_LINK_BODY("{0} — it calls itself “{1}”. This device hasn't used it before. Your other device shows the address it links to: continue only if it is exactly the same."),
    GATE_ITS_THE_SAME("It's the same"),
    CANCEL("Cancel"),

    /** §12.3, `kind` change: {0} the name, {1} the origin, {2} "public" or "private". */
    GATE_KIND_CHANGE("{0} ({1}) now says it is a {2} server. This changes who can be offered operator recovery. Continue only if you expected this."),

    /** §4.4: the gate a kit falls back to when its `card0Hash` no longer matches (N2). */
    GATE_KIT_IDENTITY_CHANGED("This server's identity changed since your kit was made. Continue only if you know why"),

    /** The owner's approved words (copy page 2026-11-15, entry 9): the Trust Gate's title for a kit typed by hand. */
    GATE_TITLE_KIT_TYPED("Is this the server on your kit?"),

    /** Entry 9's body: {0} the address the person typed, {1} what the server calls itself. The buttons are [GATE_ITS_THE_SAME] and [CANCEL]. */
    GATE_KIT_TYPED_BODY("{0} calls itself “{1}”. This device hasn't used it before. Your recovery kit shows your server's address: continue only if it is exactly the same."),

    /** §4.4: every screen that asks for an existing account's master password. {0} the email, {1} the name, {2} the origin. */
    MASTER_PASSWORD_FOR("Master password for {0} on {1} ({2})"),

    /** §4.4: the chain no longer contains the pinned card. The app stops using the instance. */
    CARD_FORK("This server's identity changed in a way andvari can't verify. Don't continue. If you trust the operator, ask them what happened."),
    FORGET_THIS_SERVER("Forget this server"),

    /** §4.4: the chain ends below the pinned card. Nothing stops. */
    CARD_WITHHELD("This server is showing an older version of its identity card"),

    /** §4.4: {0} the name, {1} the old origin, {2} the new origin. */
    CARD_MOVED("{0} ({1}) moved to {2}, signed by its operator"),

    /** §4.4: a store build never follows a move of the baked public instance (T-R7). */
    CARD_MOVED_UPDATE("This server says it moved. Update andvari."),

    /** §4.4: a store build never follows a `kind` change of the baked public instance (T2-Rec). */
    CARD_CHANGED_UPDATE("This server says it changed. Update andvari."),

    /** §4.5: the mark on a name nobody but the server vouches for (a typed-address pin). */
    AS_THE_SERVER_NAMES_ITSELF("(as the server names itself)"),

    // ---- §4.5, §7.7: recovery ----

    /** §4.5, a device without its own mirror of the recovery record: {0} the name, {1} the origin. */
    KEEP_OPERATOR_QUESTION("Your account lets the operator of {0} ({1}) restore it. Keep that?"),
    KEEP_OPERATOR_NOT_NOW("Not now"),
    KEEP_OPERATOR_KEEP("Keep operator recovery"),
    KEEP_OPERATOR_TURN_OFF("Turn it off"),

    /** §4.5, an unsigned change of the recovery key: {0} the name, {1} the origin (T2-R-f). */
    RECOVERY_KEY_CHANGED_TITLE("The recovery key for {0} ({1}) changed without the old key's signature."),
    RECOVERY_KEY_CHANGED_BODY("This can mean the operator lost the old key. It can also mean someone has taken over this server's identity. Keep operator recovery only if the operator has told you why it changed."),
    RECOVERY_KEY_CHANGED_TURN_OFF("Turn off operator recovery"),
    RECOVERY_KEY_CHANGED_KEEP("Keep it with the new key"),
    RECOVERY_KEY_CHANGED_LATER("Later"),

    /** §7.7: the recovery choice. */
    RECOVERY_QUESTION("How should this account be recovered if you forget your master password?"),
    RECOVERY_ONLY_ME("Only me"),
    RECOVERY_ONLY_ME_DETAIL("You'll save a recovery kit now. If you lose both your master password and your recovery kit, nobody can get your vault back, not even the people who run this server."),

    /** §7.7, public wording: {0} the instance name. */
    RECOVERY_OPERATOR("Me, or the operator of {0}"),
    RECOVERY_OPERATOR_DETAIL("The operator keeps a key that can restore your account if you ask."),

    /** §7.7, public wording, shown before anything changes: {0} the instance name, {1} the origin. */
    RECOVERY_WARNING_TITLE("Let the operator of {0} ({1}) restore your account?"),

    /** {0} the instance name. */
    RECOVERY_WARNING_WHAT("With operator recovery on, the people who run {0} hold a key that can restore your account. Restoring it means they can open your vault, every password, note and card in it, and act as you, including in vaults others share with you. They will only use it if you ask, but you are trusting them not to misuse it and to keep that key safe."),
    RECOVERY_WARNING_WHO_CAN_ASK("Anyone who gets into your email can ask them to reset your account. A request waits 7 days, and your signed-in devices can cancel it."),
    RECOVERY_WARNING_KIT("You will still get your own recovery kit, and you can turn this off later in Settings."),
    RECOVERY_WARNING_UNDERSTAND("I understand that the operator could open my vault and act as me."),
    RECOVERY_TURN_ON("Turn on operator recovery"),
    RECOVERY_KEEP_PRIVATE("Keep it private"),

    /** §7.7: turning operator recovery off later. */
    RECOVERY_TURN_OFF_NOTE("This deletes the operator's recovery copy from the server. It cannot undo a copy the operator may already have made."),

    /** §7.7, private (family) wording: {0} the instance name. */
    FAMILY_RECOVERY_OPERATOR("Me, or the person who runs {0}"),
    FAMILY_RECOVERY_OPERATOR_DETAIL("They can restore your account if you forget your master password."),

    /** {0} the instance name, {1} the origin. */
    FAMILY_RECOVERY_WARNING_TITLE("Let the person who runs {0} ({1}) restore your account?"),
    FAMILY_RECOVERY_WARNING("With this on, they keep a key that can restore your account. Restoring it means they could open your vault, every password, note and card in it, and act as you. Anyone who gets into your email can ask them to reset your account; a request waits 7 days, and your signed-in devices can cancel it. Choose this only if you trust the person who runs this server with your passwords. You will still get your own recovery kit."),
    FAMILY_RECOVERY_UNDERSTAND("I understand that the person who runs this server could open my vault and act as me."),

    /** §7.7, variant R: sign-up on a public instance shows no choice, only this. */
    RECOVERY_KIT_ONLY("You'll save a recovery kit now. If you lose both your master password and your recovery kit, nobody can get your vault back."),

    // ---- §6: links, contacts and codes ----

    /** §6.7: {0} the creator's name. */
    CONNECT_QUESTION("Connect with {0} (as they call themselves)?"),
    CONNECT("Connect"),

    /** §6.7 step 8: {0} the vault's name, {1} the contact's label. */
    SHARE_ONCE_COMPARED("Share {0} with {1} once you've compared codes"),

    /** §6.7 step 8: the warning a share with an uncompared contact is released behind (T-B2). */
    UNCOMPARED_WARNING("You haven't compared codes with this person. Anyone who saw the link first could be on the other end."),

    /** §6.7: {0} the instance name, {1} the creator's name. */
    JOIN_TO_CONNECT("Create an account on {0} to connect with {1}"),

    /** §6.7 dead end: {0} the invite's instance, {1} its origin, {2} the instance this app is signed in to. */
    OTHER_INSTANCE("This invite is for {0} ({1}). You're signed in to {2}. Connecting means using an account on that other server."),

    /** {0} the invite's instance. */
    OTHER_INSTANCE_SWITCH("Switch to {0}"),

    /**
     * The owner's approved words (copy page 2026-11-15, entry 7) for [InviteResult.NOT_USABLE_SIGNED_IN] on a register
     * link: {0} the server's name, {1} its address (the pinned card's, of the instance this app is signed in to).
     */
    ALREADY_SIGNED_IN_THERE("This link creates a new account on {0} ({1}). You're already signed in there. andvari didn't use the link, so it still works for whoever it was meant for. To connect with the person who sent it, ask them to choose Connect with someone and send you that link."),

    /** The same for an enrol link: entry 7 without its last sentence (a host-minted link has no person to connect with). */
    ALREADY_SIGNED_IN_THERE_ENROL("This link creates a new account on {0} ({1}). You're already signed in there. andvari didn't use the link, so it still works for whoever it was meant for."),

    /** §6.7 dead end: {0} the creator's name, {1} the instance name. */
    NOT_TAKING_ACCOUNTS("{0} invited you to connect on {1}, but that server isn't taking new accounts right now."),

    /** {0} the creator's name. */
    NOT_TAKING_INVITATION_ONLY("It is invitation-only: ask {0} for an invitation link."),
    NOT_TAKING_CLOSED("It is closed."),
    NOT_TAKING_FULL("It is full."),

    /** §6.7: offered on a private instance where members may create register links. */
    SEND_INVITATION_INSTEAD("Send an invitation instead"),

    /** §6.8 step 6: {0} the contact's label. Only a matched code replaces the pin. */
    CONTACT_KEY_CHANGED("{0}'s key is different from the one you connected with before. They may have reinstalled or made a new account. Compare codes to accept the new key."),

    /** §6.9: {0} the device the contact was made on, as the person named that device; {1} the contact's label. */
    PERSON_FROM_OTHER_DEVICE("New person from your {0}: {1} — Use on this device?"),

    /**
     * §6.9, when the device that made the contact is not one this app can name (it is gone from the account's
     * devices, or the list could not be read): {0} the contact's label. The design's sentence with "another of your
     * devices" in the device's place.
     */
    PERSON_FROM_ANOTHER_DEVICE("New person from another of your devices: {0} — Use on this device?"),

    /** §6.9: a contact that is not current on this device. */
    CONFIRM_ON_THIS_DEVICE("confirm on this device"),
    COMPARE_CODES("Compare codes"),

    /** §6.11: a failed comparison changes nothing. */
    CODES_DO_NOT_MATCH("The codes don't match. Don't share anything with this person until you've talked."),

    // ---- §7: sign-up ----

    /** §7.2: the mail outbox is stalled (`503 mail_unavailable`), for every address alike (R8). */
    MAIL_UNAVAILABLE("We can't send email right now. Try again in a while."),

    /** §11.4: under every "we sent a code" answer, which is the same whether or not the address has an account. */
    EMAIL_CHECK_SPAM("If no email arrives in a few minutes, check spam or try again."),

    /** §7.4: every over-quota refusal, per mutation or per request. */
    OWNER_OUT_OF_SPACE("This vault's owner is out of space on this server."),

    /** §7.6. */
    AGE_13_OR_OLDER("I am 13 or older"),

    // ---- §8: devices ----

    /** §8.1, beside the QR on the existing device: {0} the name, {1} the origin. */
    DEVICE_LINK_SHOW("On the new device, open andvari → Sign in → Link from your other device and scan this. It links to {0} ({1})."),

    /** §8.2 step 0: a device link that arrived anywhere but "Link from your other device". Nothing starts. */
    DEVICE_LINK_GOES_ELSEWHERE("To add this device to your account, open Sign in → Link from your other device and scan the code there."),

    /** §8.2 step 5, on the existing device: {0} the new device's name, {1} its platform. */
    DEVICE_LINK_ADD("Add {0} ({1})? Type the six digits shown on the new device"),

    /** §8.2 step 8: the bundle disagreed with the pin made before the claim. The device signed out. */
    DEVICE_LINK_WRONG_SERVER("This isn't the server your other device uses. Nothing was linked."),
    DEVICE_LINK_CANCELLED("Linking was cancelled"),

    /** §8.5: the one-tap list on a device that signed in with only the password. */
    PEOPLE_TITLE("People you've connected with"),
    PEOPLE_BODY("You signed in without linking from another device, so andvari can't yet tell whether this list is current. The server keeps it sealed under your account's key. On its own, the server can hide people or bring back someone you removed, but it can't add anyone. Whoever holds your account's key could: a page from a dishonest server while you used andvari on the web. Untick anyone you don't recognise."),

    /** §8.5: the same, for an account whose recovery record says operator. */
    PEOPLE_BODY_OPERATOR("You signed in without linking from another device, so andvari can't yet tell whether this list is current. The server keeps it sealed under your account's key. On its own, the server can hide people or bring back someone you removed, but it can't add anyone. Whoever holds your account's key could: a page from a dishonest server while you used andvari on the web, or the operator, because you chose operator recovery. Untick anyone you don't recognise."),
    PEOPLE_USE("Use these on this device"),
    PEOPLE_LATER("Later"),

    // ---- §9: the operator ----

    /** §9.3 step 1. */
    LOST_PASSWORD_AND_KIT("I lost my master password and my recovery kit"),
    ASK_THE_OPERATOR("Ask the operator for help"),
    ASK_OPERATOR_WHO_CAN("Anyone who gets into your email can ask too. The operator waits 7 days and checks with you, and your other devices can cancel."),

    /** §9.3 step 1, beside the request code. */
    REQUEST_CODE_READ_OUT("Read this to the operator when they contact you."),

    /**
     * §9.3 step 4: shown with the delivered account's ID before any new password can be set. The design quotes it
     * without a closing full stop.
     */
    RECOVERY_CHECK_ACCOUNT_ID("Check this against the account ID in an earlier andvari email to you. If it is different, stop"),

    /** §9.3 step 2, on every signed-in device of the account. */
    RECOVERY_REQUEST_ALERT("Someone asked the operator to reset your account. If this wasn't you, cancel it."),

    /** §9.5: a setup link opened on a phone, which then does nothing else. */
    SETUP_LINK_NEEDS_COMPUTER("This link sets up a server's operator account. Open it in the andvari desktop app, or with andvari-cli operator enrol."),

    /** §6.7 Resume. */
    FINISH_SERVER_SETUP("Finish setting up this server"),

    // ---- §10: the recovery kit ----

    KIT_TITLE("andvari recovery kit"),
    KIT_KEEP_PRIVATE("Keep this private. Anyone with this kit and your email address can reset your master password and open your vault."),

    /** {0} the account ID: the identity fingerprint's short form, 32 hex. */
    KIT_ACCOUNT_ID("Your account ID: {0}"),
    KIT_HOW_TO_RECOVER("To recover: open andvari → Sign in → Forgot your master password? → Scan your recovery kit"),

    /** {0}, {1}, {2}: the three group numbers, 1 to 11. */
    KIT_TYPE_GROUPS("Type groups {0}, {1} and {2}"),

    /** §10, §12.1: a kit scanned or pasted on "Scan an invite". No directions, on purpose (FC-9). */
    KIT_NOT_AN_INVITE("This is a recovery kit, not an invite."),

    /** §10: before anything is sent. {0} the email from the kit, {1} the name, {2} the origin. */
    KIT_RECOVER("Recover {0} on {1} ({2})"),

    // ---- §12.1: the first screen ----

    FIRST_SCAN_INVITE("Scan an invite"),
    FIRST_PASTE_LINK("Paste a link"),

    /** The first button on desktop. */
    FIRST_PASTE_INVITE_LINK("Paste an invite link"),
    FIRST_CREATE_ACCOUNT("Create an account on andvari"),
    FIRST_CREATE_ACCOUNT_LINE("Free · best effort · US only · 13+"),

    /** The second button's label when `signup.full` is set; the button is then disabled. */
    FIRST_SIGNUP_FULL("Sign-up is full right now"),
    FIRST_OWN_SERVER("Use your own server"),
    FIRST_SIGN_IN("Already have an account? Sign in"),
    SIGN_IN_LINK_DEVICE("Link from your other device"),
    SIGN_IN_PASSWORD("Email and master password"),
    SIGN_IN_FORGOT("Forgot your master password?"),
    SIGN_IN_SCAN_KIT("Scan your recovery kit"),

    // ---- screens the design gives no wording: the owner's approved words (copy page 2026-11-15, entries 3, 4, 5, 14) ----

    /** [EntryScreen.Server], the first button: create an account on the server on show. Its name is left out on purpose: the heading carries it. */
    SERVER_CREATE_ACCOUNT("Create an account here"),

    /** [EntryScreen.Server], the second button: sign in on the server on show. */
    SERVER_SIGN_IN("Sign in"),

    /** [EntryScreen.Server], where the first button would be, when the server takes accounts by invitation link only. */
    SERVER_INVITATION_ONLY("This server is invitation-only. To create an account, ask someone who uses it for an invitation link."),

    /** [EntryScreen.Server], where the first button would be, when the server is closed or full; [NOT_TAKING_CLOSED] or [NOT_TAKING_FULL] follows. */
    SERVER_NOT_TAKING_ACCOUNTS("This server isn't taking new accounts right now."),

    /** [EntryScreen.LinkRequired]: the title. */
    LINK_REQUIRED_TITLE("This device needs to be linked"),

    /** [EntryScreen.LinkRequired]: {0} the account's address, {1} the instance's name, {2} its origin. It says the password was right. */
    LINK_REQUIRED_BODY(
        "{0} on {1} ({2}) has “New devices must be linked” turned on, and this device is new to it. Your master password was right. " +
            "Link this device from one you already use. If you have none, recover the account with your recovery kit, which sets a new master " +
            "password and turns this setting off.",
    ),

    /** Approved entry 27, under [OWNER_OUT_OF_SPACE] when the refused account owns the vault ([SharedVaultRow.outOfSpaceLine]). */
    OWNER_OUT_OF_SPACE_YOURS("This wasn't saved. You own this vault: remove items or attachments you no longer need, or ask the operator for more space."),

    /** Approved entry 28, under [OWNER_OUT_OF_SPACE] when someone else owns the vault ([SharedVaultRow.outOfSpaceLine]). */
    OWNER_OUT_OF_SPACE_THEIRS("This wasn't saved. Ask the vault's owner to free up space."),

    // ---- awaiting the owner's next wording page ([awaitingOwner]): what each line must say, not its wording ----

    /**
     * [DevicesScreen.revokeLine], always on the Devices screen (§4.4): revoking a lost device stops it syncing and does
     * not wipe it; its copy stays encrypted under the master password.
     */
    DEVICES_REVOKE_DOES_NOT_WIPE("⟦Devices: revoking a lost device stops it syncing; it does not wipe it, and its copy stays encrypted under the master password⟧", awaitingOwner = true),

    /**
     * [EntryScreen.SignUpCode.codeLine], above the code field on phone and desktop. {0} the address as typed. It must
     * stay true for an address that already has an account, which gets no code (so not "We sent a code to {0}").
     */
    SIGN_UP_CODE_LINE("⟦Sign-up code: where the code for {0} comes from, true also when that address already has an account⟧", awaitingOwner = true),

    /** [EntryScreen.KitRecover.setsPasswordLine] (§10): this sets a new master password for that existing account. {0} the email from the kit. */
    KIT_RECOVER_SETS_PASSWORD("⟦Recovery: this sets a new master password for the existing account {0}⟧", awaitingOwner = true),

    /**
     * [RecoveryScreen.kitVoidsOldLine], beside "Make a new recovery kit" in Settings, before the person starts:
     * the kit they hold stops working the moment the new one is made, and until the new one is
     * confirmed every unlock asks for a kit again.
     */
    PEOPLE_BODY_OPERATOR_UNKNOWN("You signed in without linking from another device, so andvari can't yet tell whether this list is current. The server keeps it sealed under your account's key. On its own, the server can hide people or bring back someone you removed, but it can't add anyone. Whoever holds your account's key could: a page from a dishonest server while you used andvari on the web, or the operator, if you chose operator recovery. Untick anyone you don't recognise."),
    KIT_NEW_VOIDS_OLD("Your current kit stops working as soon as the new one is made. Until you've finished checking the new one, andvari shows it to you again each time you unlock."),

    /**
     * [LiveUpdates.line]: one quiet line on the open vault while live updates cannot connect. It
     * must not alarm or ask for anything: the vault is fine and syncs when opened or brought to the front.
     */
    /**
     * [AccountDeletedNotice.line]: the first screen, once, after this device deleted the
     * account. {0} the account's address, {1} the server's name, {2} its address.
     */
    ACCOUNT_DELETED_DONE("{0} on {1} ({2}) was deleted. Everything only that account held is gone from the server, and nothing of it is left on this device."),

    /**
     * [AccountDeletedNotice.line] since a confirmed deletion leaves this device as new for that server (decided on
     * 2026-11-18): the server is forgotten with the account, its pin and address included. {0} the account's address,
     * {1} the server's name, {2} its address, all as this device knew them before the deletion.
     */
    ACCOUNT_DELETED_SERVER_FORGOTTEN("⟦The first screen, once, after this device deleted the account: {0} on {1} ({2}) was deleted; everything only that account held is gone from the server; this device kept nothing of the account and has forgotten that server too, so using it again starts as on a new device, by its address⟧", awaitingOwner = true),

    /** [ForgetUnknownDeletion.unsentLine]: {0} the number of changes made here and not sent that go (more than one). */
    DELETION_UNKNOWN_FORGET_UNSENT("⟦Below the confirmation of forgetting an account whose deletion's outcome is not known: {0} changes made on this device and not sent, changes to shared vaults among them, go with it and cannot be sent afterwards⟧", awaitingOwner = true),

    /** [ForgetUnknownDeletion.unsentLine] for exactly one change not sent. */
    DELETION_UNKNOWN_FORGET_ONE_UNSENT("⟦Same place: one change made on this device and not sent goes with it and cannot be sent afterwards⟧", awaitingOwner = true),

    /** [ForgetUnknownDeletion.unsentLine] where every change made here was sent. */
    DELETION_UNKNOWN_FORGET_ALL_SENT("⟦Same place: every change made on this device was sent; none is lost⟧", awaitingOwner = true),

    /** [ForgetUnknownDeletion.unsentLine] where this device cannot count them (its copy is not open). */
    DELETION_UNKNOWN_FORGET_UNSENT_CANNOT_TELL("⟦Same place: this device cannot tell now whether changes made here were not sent; any that were not go with it⟧", awaitingOwner = true),

    /**
     * [AccountDeletedNotice.line] where this device still keeps something of another account at that server (its copy, a
     * record of its identity key, a device's row or an address's record, a record kept under its id there; no copy is
     * claimed): {0} the address, {1} the server's name, {2} its address.
     */
    ACCOUNT_DELETED_SERVER_KEPT("⟦The first screen, once, after this device deleted the account: {0} on {1} ({2}) was deleted; everything only that account held is gone from the server and from this device; this device keeps that server, because it still keeps something of another account there⟧", awaitingOwner = true),

    /**
     * [LockedScreen.endLine] and [EntryScreen.FirstRun.sessionNotConfirmed]: the session ended on this device because it
     * could not be confirmed with its server in time; never "signed out by its server".
     */
    SESSION_NOT_CONFIRMED("⟦On the lock screen, and once on the first screen after “Sign in again”: andvari could not confirm this device's session with its server in time; it sent nothing again, so no other session was ended; sign in again⟧", awaitingOwner = true),

    /**
     * [AppSnapshot.keptSignedOutSignOutFirstLine], [LockedScreen.endLineBesideSignOut] and
     * [EntryScreen.FirstRun.sessionNotConfirmedBesideSignOut]: the end of a session this device could not confirm, said
     * wherever a way out that signs that kept account out stands beside it. Must not tell them to sign in again. No values.
     */
    SESSION_NOT_CONFIRMED_SIGN_OUT_FIRST("⟦Beside a kept account that must be signed out first: andvari could not confirm this account's session with its server in time; it sent nothing again, so no other session was ended⟧", awaitingOwner = true),

    /**
     * [AccountSnapshot.endLine]: the copy is open read-only after the session ended on this device because it could not be
     * confirmed with its server in time; never "signed out by its server".
     */
    SESSION_NOT_CONFIRMED_COPY_OPEN("⟦Above a copy opened read-only: andvari could not confirm this device's session with its server in time, so this is the copy kept on this device and nothing can be changed or sent; sign in again to go on⟧", awaitingOwner = true),

    /** [LinkPasswordResult.PROOF_REFUSED]: the link's password screen stays on show with this line. */
    LINK_PROOF_REFUSED_TYPE_CURRENT("⟦At a device link, on its password screen, which stays: the server did not take this master password, although it opens this device's copy of the account; the account's password may have been changed on another device since; the link is still open; type the account's current master password⟧", awaitingOwner = true),

    /**
     * [ForgetUnknownDeletion.offerLine]: where a deletion's outcome is not known, the offer to forget the account on this
     * device (on the deletion screen, the lock screen and the first screen's notice).
     */
    DELETION_UNKNOWN_FORGET_OFFER("⟦An offer beside “can't tell yet whether the account was deleted”: forget this account on this device⟧", awaitingOwner = true),

    /**
     * [ForgetUnknownDeletion.confirmLine]: the confirmation before that forgetting. {0} the account's address, {1} the
     * server's name, {2} its address.
     */
    DELETION_UNKNOWN_FORGET_CONFIRM("⟦The confirmation before forgetting {0} on {1} ({2}) on this device after a deletion whose outcome is not known: this device's copy of the account and every change made here and not sent go; the server is kept; if the account was not deleted, it is still on the server and can be signed in to again; this device asks the server to end its session there⟧", awaitingOwner = true),

    /**
     * [DeletionOutcomeUnknownNotice.line]: the first screen, after a deletion sent from here got
     * no answer and the server then signed this device out. {0} the account's address, {1} the server's name, {2} its address.
     */
    ACCOUNT_DELETION_UNKNOWN("andvari can't tell yet whether {0} on {1} ({2}) was deleted. Sign in again to find out: if it opens, the account is still there."),

    /**
     * [HeldOperatorAccount.line] (the owner's decision of 2026-11-16): the first screen of a phone whose account a
     * handover made its server's operator. {0} the account's address, {1} the server's name, {2} its address.
     */
    OPERATOR_HELD_ON_PHONE("{0} is now the operator account of {1} ({2}), and the operator account can't be used on a phone. This phone stopped using it and sends nothing with it. Its copy stays here, locked, until you remove it. Use the account in the andvari desktop app."),

    /**
     * [HeldOperatorAccount.removeLine] when the device counted what it had not sent: the confirmation before
     * [EntryApi.removeHeldOperatorAccount]. {0} the account's address, {1} the number of changes not sent.
     */
    OPERATOR_HELD_REMOVE_LOSES("This deletes this phone's copy of {0}. {1} changes made on this phone that weren't sent yet are lost. The account itself and everything already on the server stay."),

    /** [HeldOperatorAccount.removeLine] when the device could not count what it had not sent. {0} the account's address. */
    OPERATOR_HELD_REMOVE_UNKNOWN("This deletes this phone's copy of {0}. Anything made on this phone that wasn't sent yet is lost, and this phone can't tell whether there is any. The account itself and everything already on the server stay."),

    LIVE_UPDATES_NOT_CONNECTED("andvari isn't getting changes as they happen right now. Changes from your other devices show up the next time this vault syncs."),

    // ---- §3.13 "Move everything to a new vault" (the web's walk, as decided on 16 November 2026) ----

    /** [OperatorConsole.serverSentBadRows]: one line above the console's lists. */
    OPERATOR_SERVER_SENT_BAD_ROWS("The server sent rows this computer won't show, because something in them isn't what it should be. A list may be missing entries, or show a name left blank. Nothing was done with them."),

    /** [OperatorResult.CARD_STORED_NOT_SHOWN] and [OperatorConsole.cardStoredNotShown]. */
    OPERATOR_CARD_STORED_NOT_SHOWN("The server says it stored the new identity card but doesn't show it yet. No other card change can be signed until it does. Look again later."),

    /** [OperatorResult.CARD_REFUSED_HERE]: this computer's own refusal, nothing sent. */
    OPERATOR_CARD_REFUSED_HERE("This computer didn't send that card change: it changes nothing, or a value isn't valid here. The server wasn't asked."),

    /**
     * [SharedVaultRow.unfinishedMove] and [UnfinishedVaultMove.line] while the old vault's deletion is signed and waiting:
     * {0} the old vault's name, {1} the new vault's name (empty when this device does not know it).
     */
    MOVE_DELETE_WAITING("Moving everything out of “{0}” into “{1}” isn't finished. The deletion of “{0}” is signed and waiting for the server, and it can't be taken back. Finish the move: it first copies anything new in “{0}”, then sends the deletion again."),

    /**
     * [VaultActionResult.MOVE_DELETE_WAITING]: a change to a vault whose deletion by a move is signed and waiting was
     * refused before anything was signed or sent (a member added, removed or given another role, an ownership offer, a
     * rename, a delete, a share released from a link). No placeholder.
     */
    MOVE_WAITING_REFUSED("This vault's deletion is signed and waiting for the server, so it can't be changed until its move is finished. Finish the move first."),

    /** [RecoveryChangeResult.ESCROW_WRONG_FORM]. No placeholder. */
    ESCROW_WRONG_FORM("This version of andvari made a recovery copy in a form this server no longer takes, so nothing was stored and nothing changed. Update andvari, then try again. If it happens again, tell the operator."),

    /** [SharedVaultRow.readOnlyLine]: {0} the old vault's name, {1} the new vault's name (empty when not known here). */
    MOVE_WAITING_READ_ONLY("“{0}” is read-only on this device while its deletion waits for the server. Finish the move into “{1}” to go on."),

    /**
     * [MoveStoredNotice.line]: the old vault's deletion by a move was stored outside the move. {0} the old vault's name,
     * {1} the new vault's, {2} how many items this device holds that were added after the copies, {3} how many were
     * changed after their copy.
     */
    MOVE_STORED_OUTSIDE("⟦A notice: the server stored the deletion of {0} before moving everything into {1} was finished; this device still holds its copy; {2} items were added and {3} were changed in {0} after they were copied, and they are not in {1} yet: copy them; anything another member added that this device never received cannot be saved here⟧", awaitingOwner = true),

    /** The same notice when nothing was added or changed after the copies: {0} and {1} as above. */
    MOVE_STORED_OUTSIDE_NOTHING_LATE("The server deleted “{0}” before moving everything into “{1}” was finished. Everything this device had of “{0}” is already in “{1}”. Anything another member added that this device never received can't be saved here."),

    /** After [SharedVaultsApi.bringLateIntoMove]: {0} how many items were copied, {1} the new vault's name. */
    MOVE_STORED_COPIED("Items copied into “{1}”: {0}."),

    /** The same for a move that stopped before the old vault's deletion was signed: the same placeholders. */
    MOVE_UNFINISHED("Moving everything out of “{0}” into “{1}” stopped part-way. Everything is still in “{0}”. Move everything again to carry on from where it stopped."),

    /** [MoveEverythingScreen.startsFresh]: before the person starts. {0} is not filled. */
    MOVE_STARTS_FRESH("The new vault made last time has someone in it who isn't part of this move, so andvari makes a fresh one. The one made last time holds only copies, and is deleted when this move finishes."),

    /** [MoveEverythingScreen.whatMoves], before the person starts. */
    MOVE_ONLY_LIVE_ITEMS("Only the items move. Items in the trash and earlier versions of items stay with the old vault, and go when it is erased for good."),

    /** [ReplacePasswordResult.ANSWER_REPLACED] and [EntryScreen.OperatorHelp.answerReplaced]. */
    ASSIST_ANSWER_REPLACED("The answer on the server isn't the one this device opened. The operator needs to upload it again. This request is kept, so you don't need to start again."),

    /** [AssistKeyChange.line]: {0} the date the app formats from [AssistKeyChange.rotatedAtMs]. */
    ASSIST_RECOVERY_KEY_ROTATED("This server's recovery key changed on {0}, and the old key signed the change. Your request goes on, and only an answer signed by the new key is accepted."),

    /** [AssistKeyChange.warningBody], under [RECOVERY_KEY_CHANGED_TITLE]. */
    ASSIST_RECOVERY_KEY_CHANGED_BODY("This can mean the operator lost the old key. It can also mean someone has taken over this server's identity. Your request is stopped, and nothing the server sends for it is opened. Stop this request unless the operator has told you why the key changed. If you keep it, it waits until a change the old key signed is shown."),

    /** [AssistKeyChange.stop]: the warning's default button. */
    ASSIST_KEY_CHANGED_STOP("Stop this request"),

    /** [AssistKeyChange.keepWaiting]: the warning's second button. */
    ASSIST_KEY_CHANGED_KEEP_WAITING("Keep waiting"),

    /** [EntryScreen.OperatorHelp.requestUnknown], [ReplacePasswordResult.REQUEST_UNKNOWN] and [CodeResult.REQUEST_UNKNOWN]. */
    ASSIST_REQUEST_UNKNOWN("The server no longer knows this request. This device keeps it until its time runs out, in case the server finds it again. Wait, or start again with a new request."),

    /** The first button beside [ASSIST_REQUEST_UNKNOWN]: the screen stays. */
    ASSIST_REQUEST_UNKNOWN_WAIT("Wait"),

    /** The second button beside [ASSIST_REQUEST_UNKNOWN]: this request is dropped and a new one can be made. */
    ASSIST_REQUEST_UNKNOWN_START_AGAIN("Start again"),

    /** [LateRecoveryNotice.line] for [LateRecoveryResult.RESET]: {0} the address, {1} the server's name, {2} its address. */
    LATE_RECOVERY_RESET("The master password of {0} on {1} ({2}) was reset. Sign in with the new one to make your new recovery kit."),

    /** [LateRecoveryNotice.line] for [LateRecoveryResult.REFUSED]: the same placeholders. */
    LATE_RECOVERY_REFUSED("The reset of {0} on {1} ({2}) didn't go through. Your master password is unchanged."),

    /** [LateRecoveryNotice.line] for [LateRecoveryResult.UNKNOWN]: the same placeholders. */
    LATE_RECOVERY_UNKNOWN("andvari couldn't tell whether the reset of {0} on {1} ({2}) went through. Try the new master password, then the old one."),

    /** [RecoveryScreen.unreadableLine]: {0} how many requests the server sent that this device cannot show. */
    RECOVERY_REQUESTS_SOME_UNREADABLE("The server sent {0} more requests for this account that this device can't show, so this list may not be complete. Tell the operator."),

    /** [AppSnapshot.containedFaultLine]. */
    CONTAINED_FAULT("Something went wrong in the background, and andvari stopped it. Nothing was lost. If it keeps happening, restart andvari."),

    /**
     * The `KEYS_NOT_KNOWN_HERE` value of every result of an action that proves the master password: the server refused
     * the proof while this session knows that the account's keys on the server are not the ones this device knows.
     */
    KEYS_NOT_KNOWN_HERE("The server's keys for this account aren't the ones this device knows, so nothing was changed. That isn't a wrong password. Sign in again on this device."),

    /** [OperatorConsole.outgoingKeyLine]: {0} the outgoing recovery key's fingerprint, {1} the current one's. */
    OPERATOR_COPY_ON_OUTGOING_KEY("The server says this account's recovery copy was made for the outgoing recovery key {0}, before the key changed to {1}. You need both recovery sheets: the current one signs the answer, and the outgoing one opens the copy."),

    /** [InstanceDetails.pinnedCard0Label]. */
    INSTANCE_CARD0_PINNED("The fingerprint of this server's first identity card, as this device first saw it. Compare it with the one the operator gives you."),

    /** [OpenedInvite.OtherInstance.signOutLine]: {0} the name and {1} the address of the server this app is signed in to. */
    OTHER_INSTANCE_SIGNS_OUT("Switching signs you out of {0} ({1}) on this device, as Sign out does. Your account and vaults there stay as they are; this device's copy of them is deleted. Sign in there again to come back."),

    /**
     * [OpenedInvite.OtherInstance.signOutLine] when this device set "New devices must be linked" on for the account:
     * {0} the name and {1} the address of the server this app is signed in to.
     */
    OTHER_INSTANCE_SIGNS_OUT_LINK_REQUIRED("Switching signs you out of {0} ({1}) on this device, as Sign out does, and deletes this device's copy. This account has “New devices must be linked” on, so signing in here again won't bring it back by itself: another of your devices has to link this one, or you recover the account with your recovery kit."),

    /**
     * [OpenedInvite.OtherInstance.signOutLine] when this device does not know whether "New devices must be linked" is on
     * (the server serves no read of it): {0} the name and {1} the address of the server this app is signed in to.
     */
    OTHER_INSTANCE_SIGNS_OUT_LINK_UNKNOWN("Switching signs you out of {0} ({1}) on this device, as Sign out does, and deletes this device's copy. If this account has “New devices must be linked” on, signing in here again won't bring it back by itself: another of your devices has to link this one, or you recover the account with your recovery kit."),

    /** [SignOutCheck.line]: {0} how many changes made on this device were not sent. */
    SIGN_OUT_UNSENT_LOST("⟦A second confirmation before signing out or switching servers: {0} changes made on this device have not been sent to the server yet; signing out deletes this device's copy, and they are lost; you can try sending them first⟧", awaitingOwner = true),

    /** [SignOutCheck.line] while the vault is locked. */
    SIGN_OUT_UNSENT_UNKNOWN("While the vault is locked, andvari can't tell whether changes made on this device haven't been sent yet. Any that haven't are lost when you sign out. Unlock first to see how many, and to send them."),

    /** [SignOutCheck.sendFirstLabel]: the button. */
    SIGN_OUT_SEND_FIRST("Try sending them first"),

    /** [SendFirstResult.NOT_ALL_SENT]. */
    SIGN_OUT_SEND_FIRST_FAILED("Not every change could be sent. The ones that weren't are still only on this device."),

    /** [PlainResult.UNSENT_NOT_CONFIRMED], [ServerResult.UNSENT_NOT_CONFIRMED]. */
    UNSENT_NOT_CONFIRMED("You're still signed in. Some changes may not have been sent, so signing out needs you to confirm that they will be lost."),

    /**
     * [CodeResult.REQUEST_CANCELLED]: the right code for a request the server ended before its mailed code was typed.
     * The approved words, with one clause still to be worded (in `⟦…⟧`): whoever runs the server can end such a request
     * too, and the device is told the same state then, so the sentence must be true of that cause as well. It names no
     * restore. No values.
     */
    ASSIST_REQUEST_CANCELLED("This request was cancelled, because the account's master password or recovery setting changed, or the account was recovered, after it was made⟦, or it was ended by whoever runs the server⟧. If you still need help, ask again.", awaitingOwner = true),

    /**
     * [EntryScreen.OperatorHelp.endedLine], at [OperatorHelpStage.VETOED]: the server answers "vetoed" for a request a
     * signed-in device of the account refused, for one it ended itself because the master password or the recovery
     * setting changed, and for one ended by whoever runs the server; the device cannot tell which, so the line is true of
     * every cause. It names no restore. No values.
     */
    ASSIST_REQUEST_ENDED("⟦On a request for the operator's help, in place of its stage: this request was ended from the account's side (by one of its signed-in devices, or because the account's master password or recovery setting changed) or by whoever runs the server; if that was not you, tell whoever runs the server; you can ask again⟧", awaitingOwner = true),

    /**
     * [ReplacePasswordResult.REQUEST_ENDED]: the commit of a new master password after the operator's answer was opened
     * on this device, refused because the request can no longer be finished: it ran out of time or was used, or whoever
     * runs the server ended it. Nothing was changed. It names no restore. No values.
     */
    ASSIST_ANSWERED_REQUEST_ENDED("⟦After the operator's answer was opened, at setting the new master password: this request can no longer be finished: it ran out of time or was used, or it was ended by whoever runs the server; nothing was changed; start again with a new request⟧", awaitingOwner = true),

    /** [TwoStepResult.PASSWORD_NEEDED]. */
    TWO_STEP_PASSWORD_NEEDED("To turn two-step sign-in off, or to get a new key for your authenticator app, enter your master password as well as the current code."),

    /** [TwoStepResult.TOO_MANY_TRIES]: the wait is the app's to show from the retry time. */
    TWO_STEP_TOO_MANY_TRIES("Too many wrong master passwords or codes. Wait a while, then try again."),

    /** [RecoveryScreen.notReadLine]. */
    RECOVERY_REQUESTS_NOT_READ("This device couldn't read the requests for the operator's help on this account. An empty list here doesn't mean nobody asked. Try again."),

    /**
     * [EntryScreen.CheckAccount.compareLine]: in the command-line tool's sense. It replaces
     * [RECOVERY_CHECK_ACCOUNT_ID] on that screen.
     */
    RECOVERY_CHECK_ACCOUNT_KIT("Compare this with the account ID printed on your recovery kit. An andvari email to you counts only if it's older than this request, because this server sent it. If you have neither, tell the operator. If it's different, stop."),

    /** [EntryScreen.CheckAccount.confirming]: the second step of "it is the same", so one tap cannot pass the comparison. */
    RECOVERY_CHECK_ACCOUNT_CONFIRM("It's the same"),

    /** [AccountPrompt.RecoveryRequest.rowLine]: {0} when it was asked, {1} the kind of device the server says, {2} when the wait ends. */
    RECOVERY_REQUEST_DETAILS("Asked on {0}, from a device the server says is {1}. The wait ends on {2}. After that, the operator will be asked to help whoever made this request set a new master password for this account."),

    /** [RecoveryRequestRow.answered]. */
    RECOVERY_REQUEST_ANSWERED("The operator has already answered this request, so whoever made it can set a new master password now. If it wasn't you, cancel it now."),

    /** [RecoveryRequestRow.holdCutShort]. */
    RECOVERY_REQUEST_HOLD_CUT_SHORT("The server says this request's wait ends sooner than the 7 days every request must wait. This device can't stop that. If it wasn't you, cancel it and tell the operator."),

    /** [RecoveryRequestRow.cancelNotTaken]. */
    RECOVERY_REQUEST_CANCEL_NOT_TAKEN("The server said this request was cancelled, but it still lists it. Try again, and tell the operator."),

    /** [AccountPrompt.RecoveryRequest.unreadable]. */
    RECOVERY_REQUEST_UNREADABLE("The server says someone asked the operator to reset this account, but this device couldn't read the request. Open Settings → Recovery to see it and cancel it, and tell the operator."),

    /** [AccountPrompt.RecoveryRequest.wasMe]: the alert's second button. */
    RECOVERY_REQUEST_WAS_ME("This was me"),

    /** [MoveStop.line]: {0} the new vault's name, {1} the old vault's name, {2} items copied, {3} items in all. */
    MOVE_STOPPED("The move stopped after copying {2} of {3} items into “{0}”. Everything is still in “{1}”. Move everything again to carry on from there."),

    /**
     * [MoveStop.line] at [MoveStage.DELETE_OLD_VAULT] when the old vault's delete was sent and the server has not
     * confirmed it: the same placeholders as [MOVE_STOPPED].
     */
    MOVE_DELETE_UNCONFIRMED("{2} items are in “{0}” and its members are added. The deletion of “{1}” is signed and waiting for the server, and it can't be taken back. Finish the move: it first copies anything new in “{1}”, then sends the deletion again."),

    /**
     * [MoveStop.line] at [MoveStage.DELETE_OLD_VAULT] when the delete of a new vault an earlier try made (it holds only
     * copies) was sent and the server has not confirmed it: the same placeholders as [MOVE_STOPPED].
     */
    MOVE_DISCARD_UNCONFIRMED("The move isn't finished: the new vault an earlier try made holds only copies, and the server hasn't confirmed its deletion yet. Everything is still in “{1}”. Move everything again to finish the move."),

    /** [MoveStop.line]: the half-made vault of an earlier try could not be read, so nothing was deleted; {1} the old vault. */
    MOVE_DISCARD_UNREAD("⟦The move isn't finished: the new vault an earlier try made could not be read just now, so it was not deleted and nothing is said of what it holds; everything is still in “{1}”; move everything again to finish the move⟧", awaitingOwner = true),

    /**
     * [MoveStop.line] at [MoveStage.DELETE_OLD_VAULT] when a change this device signed for the old vault, or for a vault an
     * earlier try made, waits and is not the move's own (the person's own deletion of it waits for their word; another
     * change goes out with the next sync): the move does not send it. The same placeholders as [MOVE_STOPPED].
     */
    MOVE_OTHER_CHANGE_WAITING("⟦The move stopped: a change made on this device to “{1}”, or to the vault an earlier try made, is waiting and is not the move's to send (a deletion waits for your word on that vault); everything is still in “{1}”; once that change is settled, move everything again⟧", awaitingOwner = true),

    /**
     * [MoveStop.line]: the vault an earlier try made is frozen on this device, so it was not deleted. The same placeholders as
     * [MOVE_STOPPED]. No longer handed by the shared code: such a vault is kept with a note ([MOVE_HALF_MADE_FROZEN]) and
     * the move goes on; the key stays for the apps that still name it.
     */
    MOVE_DISCARD_FROZEN("⟦The move isn't finished: the new vault an earlier try made is frozen on this device (its history shows two different changes at one place), so it was not deleted and its deletion will not be sent; everything is still in “{1}”⟧", awaitingOwner = true),

    /** [MoveStop.line]: the old vault froze while the move's deletion of it waited; nothing more is sent. The same placeholders as [MOVE_STOPPED]. */
    MOVE_OLD_VAULT_FROZEN("⟦The move stopped: “{1}” is frozen on this device (its history shows two different changes at one place), so its deletion will not be sent and it stays read-only here; the {2} items copied into “{0}” stay there⟧", awaitingOwner = true),

    /** [MoveNote]: {0} the half-made vault's name, {1} how many items in it the move did not make. */
    MOVE_HALF_MADE_KEPT("⟦“{0}”, the new vault an earlier try of this move made, holds {1} items the move did not make (someone saved or changed them there), so it was not deleted: it stays a vault of its own, with everyone who has it⟧", awaitingOwner = true),

    /** [MoveNote]: {0} the half-made vault's name; this device kept no record of what the move made in it. */
    MOVE_HALF_MADE_KEPT_CANNOT_TELL("⟦“{0}”, the new vault an earlier try of this move made, was not deleted: this device cannot tell whether it holds only the move's copies, so it stays a vault of its own, with everyone who has it⟧", awaitingOwner = true),

    /** [MoveNote], after the line above, where the move removes a member who has that vault: {0} its name; [MoveNote.member] names them. */
    MOVE_HALF_MADE_KEPT_MEMBER_HOLDS("⟦The member this move removes still has “{0}” and everything in it, copies of the old vault's items included; delete that vault, or remove them from it, to cut them off⟧", awaitingOwner = true),

    /** [MoveNote]: {0} the half-made vault's name; it is frozen on this device, so the move kept it and went on with a new vault. */
    MOVE_HALF_MADE_FROZEN("⟦“{0}”, the new vault an earlier try of this move made, is frozen on this device (its history shows two different changes at one place): it was not deleted and nothing of it is sent from here; it stays a vault of its own, read-only here, with everyone who has it, and the move went on with a new vault⟧", awaitingOwner = true),

    /** [MoveNote], after [MOVE_HALF_MADE_FROZEN], where the move removes a member who has that vault: {0} its name; [MoveNote.member] names them. */
    MOVE_HALF_MADE_FROZEN_MEMBER_HOLDS("⟦The member this move removes still has “{0}” and everything in it, copies of the old vault's items included; it cannot be deleted from this device, nor can they be removed from it here⟧", awaitingOwner = true),

    /** [MoveNote] and [MoveStoredNotice.keptBesideLines]: {0} how many, {1} the new vault's name. */
    MOVE_KEPT_BESIDE_CHANGED("⟦{0} earlier copies in “{1}” were changed there after the move made them, so they were not deleted: each stands beside its newer copy⟧", awaitingOwner = true),
    MOVE_KEPT_BESIDE_NO_REVISION("⟦{0} earlier copies in “{1}” were not deleted: this device does not know which version the move made, so each stands beside its newer copy⟧", awaitingOwner = true),
    MOVE_KEPT_BESIDE_REFUSED("⟦{0} earlier copies in “{1}” were not deleted because the server refused it: each stands beside its newer copy⟧", awaitingOwner = true),

    /** [MoveStoredNotice.deletedThereLine]: {0} how many, {1} the new vault's name. Never "you deleted": another member may have. */
    MOVE_STORED_DELETED_THERE("⟦{0} items were deleted in “{1}” after their copy was made, and were not copied again⟧", awaitingOwner = true),

    /** [MoveEverythingScreen.oldVaultKept] and [MoveFinished.line] for [MoveKept.SOURCE_STAYS]. */
    MOVE_KEPT_SOURCE_STAYS("Its history doesn't check out, so the old vault stays as it is. Remove it from this device when you're done."),

    /** The same for [MoveKept.MEMBER_CANNOT_BE_ADDED]: the members named are those with [MoveMemberRow.canBeAdded] false. */
    MOVE_KEPT_NOT_ADDED("Some people can't be added to the new vault from this device, so the old vault is kept, and they keep it. Connect with them here first."),

    /** The same for [MoveKept.UNREADABLE_ITEMS]: {0} the number of items this device cannot read. */
    MOVE_KEPT_UNREADABLE("{0} items in this vault can't be read on this device, so they weren't copied. The old vault is kept so that they aren't lost."),

    // ---- the check before a large copy (spec 03 §14.4; design §3.13 "the app checks first and says so") ----

    /** [io.silencelen.andvari.core.app.content.SpaceCheck.line] on storage: {0} the account's storage limit, {1} how much more the copy needs (sizes as "25 MB"). */
    SPACE_SHORT_BYTES("This didn't start: it needs {1} more space than your account has on this server, whose limit is {0}. Remove what you no longer need, or ask the operator to raise the limit."),

    /** The same on the item count: {0} the account's item limit, {1} how many items over it the copy would go. */
    SPACE_SHORT_ITEMS("This didn't start: it would go {1} items over your account's limit of {0} items on this server. Delete items you no longer need, or ask the operator to raise the limit."),

    /** The same on owned shared vaults: {0} the account's limit, which it has reached, so no new vault can be made. */
    SPACE_SHORT_VAULTS("This didn't start: your account already owns {0} shared vaults, the most this server allows, so a new one can't be made. Delete one you no longer need, or ask the operator to raise the limit."),

    // ---- what a lock cut short, said once at the next unlock ([io.silencelen.andvari.core.app.content.LockCut]) ----

    /** {0} the vault copied from, {1} the vault copied into, {2} items copied at least, {3} items in all. */
    LOCK_CUT_COPY("The vault locked while andvari was copying the items of “{0}” into “{1}”. At least {2} of {3} were copied, and maybe a few more. Copy them again for the rest: that makes no duplicates."),

    /** {0} the item, {1} the vault it was being moved into. */
    LOCK_CUT_MOVE("The vault locked while “{0}” was being moved into “{1}”, so the move may not have finished. Check both vaults, and move it again if it's still where it was."),

    /** {0} the item, {1} the vault it was being copied into. */
    LOCK_CUT_COPY_ITEM("The vault locked while “{0}” was being copied into “{1}”, so it may not have been copied. Check “{1}”, and copy it again if it isn't there."),

    /** {0} the item. */
    LOCK_CUT_DELETE("The vault locked while “{0}” was being deleted, so it may still be there. Check."),

    /** {0} the file's name. */
    LOCK_CUT_FILE("The file “{0}” wasn't added: the vault locked while it was being added. Add it again."),

    /** {0} the item. */
    LOCK_CUT_RESTORE("The vault locked while “{0}” was being restored from the trash, so it may not have been. Check the vault and the trash."),

    /** {0} the item. */
    LOCK_CUT_VERSION("The earlier version of “{0}” wasn't put back: the vault locked first. Put it back again from the item's history."),

    /** A held vault's line when this account, its owner, deleted it. {0} until when this device keeps the copy (a sentence). */
    HELD_DELETED_BY_YOU("You deleted this vault. {0}"),

    /** A held vault's line when this account, its owner, deleted it and its grace ended. {0} as above. */
    HELD_PURGED_BY_YOU("You deleted this vault for good. {0}"),

    /** {0} the item. Said once, at the next read of the trash after a restore the server answered as done. */
    TRASH_RESTORE_NOT_DONE("The server said “{0}” was restored, but it's in the trash again, so the restore didn't happen. Restore it again."),

    /** {0} the item. Said once, at the next read of the trash after a delete for good the server answered as done. */
    TRASH_PURGE_NOT_DONE("The server said “{0}” was deleted for good, but it's still in the trash, so it wasn't. Delete it forever again."),

    /**
     * {0} the item. Said once, at the next read of the trash, when an item restored or deleted for good on this device
     * is in the trash again after a later deletion (another device or member): no one is blamed.
     */
    /** Said when a change to a vault whose deletion is signed and waiting is refused before anything is sealed. */
    VAULT_CLOSED_DELETION_WAITING("This vault's deletion is signed and waiting for the server, so nothing can be added or changed in it here until its move is finished. You can still copy items out."),

    /**
     * NEW. Said when a change to a vault is refused because a change of it waits on this device that this device cannot
     * read, which may be its signed deletion (a move of everything): this device cannot tell, so it holds the vault as if.
     */
    VAULT_CLOSED_DELETION_MAY_BE_WAITING("⟦A vault closed for writing on this device: a change of this vault waits here that this device cannot read, and it may be the vault's signed deletion, so nothing can be added or changed in it here until its move is finished; items can still be copied out⟧", awaitingOwner = true),

    TRASH_IN_AGAIN("In the trash again: “{0}”, deleted again after your change, on another device or by another member."),

    /**
     * §6.3, §6.7: a link carries the name its account goes by, as the person chose it, and the server serves no account
     * its own name; on a device where the account was not made, the name is asked for before a link is made or answered.
     */
    LINK_NAME_NEEDED("⟦Before making or answering a link on this device: this device does not know the name your account goes by in its links, because the account was made on another device; type the name the other person will see⟧", awaitingOwner = true),

    /**
     * After an action that proves the master password: the server refused the proof, although the password opened this
     * account on this device, and this session does not know that the server's keys differ. Never a wrong password.
     */
    SERVER_REFUSED_PROOF("The server didn't accept your master password, although it opened your account on this device. That isn't a wrong password. Nothing changed. If it keeps happening, sign in again."),

    /** Spec 01 §7: a sign-in on a device that keeps this account, where the key the server's copy opened is not that account's. */
    SIGN_IN_SERVER_KEYS_NOT_KNOWN_HERE("⟦On sign-in, on a device that keeps this account: the account's keys on the server are not the ones this device knows; nothing on this device was changed⟧", awaitingOwner = true),

    /** Spec 01 §7: after a sign-in over a copy this device kept sealed under another master password than the one typed. */
    SIGNED_IN_COPY_FOLLOWS_SERVER("This device's copy of your vault was locked with a different master password than the one you just typed. It now uses the one on the server, the one you typed."),

    /** `400 escrow_wrong_form` at registration: no account was made. */
    REGISTER_ESCROW_WRONG_FORM("The server no longer takes the recovery copy this version of andvari makes, so no account was made. Update andvari, then create your account again."),

    /** §8.2 step 6: the fingerprint or face prompt that would approve a new device was cancelled. */
    DEVICE_APPROVAL_CANCELLED("Nothing was approved. The new device is still waiting: you can approve it again."),

    /** The name typed for this account's links is not one a link can carry. Nothing was kept. */
    LINK_NAME_NOT_A_NAME("⟦That name cannot go in a link: it must be 1 to 64 bytes long, with no invisible or control characters and no space at its start or end⟧", awaitingOwner = true),

    /** §8.2: a device link whose pickup this device did not take, because it keeps another account's session. */
    DEVICE_LINK_ANOTHER_SESSION_KEPT("⟦After linking this device: nothing was linked, because this device keeps another account; sign out of that account on this device first (changes it has not sent go with it), then start a new link from your other device⟧", awaitingOwner = true),

    /** "Ask the operator for help" (decided on 2026-11-17): the quiet line that opens the mailbox value's field. */
    ASSIST_MAILBOX_VALUE_LINE("⟦A quiet line below the address on \"ask the operator for help\": have a value from a mail about a request you did not make?⟧", awaitingOwner = true),

    /** The mailbox value's field, once its line was opened. */
    ASSIST_MAILBOX_VALUE_FIELD("⟦The label of the field for that value: the value from that mail (four groups of four)⟧", awaitingOwner = true),

    /** §8.2 step 6: the approval of a new device came after the link's time ran out. */
    DEVICE_APPROVAL_LINK_EXPIRED("⟦After approving a new device too late: the link ran out of time before it was approved, so nothing was approved; start a new link from this device⟧", awaitingOwner = true),

    /** A move whose deletion was stored outside it carried the person's own waiting deletions. {0} how many, {1} the new vault. */
    MOVE_STORED_DELETIONS_CARRIED("⟦In the same notice: {0} items you had deleted in the old vault were deleted in {1} too; each is in {1}'s trash for 30 days, where you can restore it⟧", awaitingOwner = true),

    /**
     * A move whose deletion was stored outside it did NOT carry some of the person's own waiting deletions
     * ([MoveStoredNotice.keptLine]): the copy in the new vault was changed since the move made it, or the server refused
     * its deletion. {0} how many, {1} the new vault.
     */
    MOVE_STORED_DELETIONS_KEPT("⟦In the same notice: {0} items you had deleted in the old vault are still in {1}: this device deletes a copy there only when it can be sure nobody changed it after the move, and it could not be sure of these; delete them in {1} yourself if you still want them gone⟧", awaitingOwner = true),

    /** The mailbox value's field holds text that is not a value's form: nothing was sent. */
    ASSIST_NOT_A_MAILBOX_VALUE("⟦Under the field: this is not a value from such a mail; check it, or empty the field to ask without it⟧", awaitingOwner = true),

    /**
     * A recovery with the kit stopped before anything was committed because this device keeps another account (at another
     * server, or one this device must sign out first): [KitScanResult.ANOTHER_ACCOUNT_KEPT],
     * [ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT_NOT_COMMITTED]. Names no account.
     */
    RECOVERY_ANOTHER_ACCOUNT_KEPT("⟦During a recovery: nothing was changed, because this device keeps another account; sign out of that account on this device first (its sign-out says how many of its changes were not sent), then start the recovery again⟧", awaitingOwner = true),

    /** The request's screen, when the operator's answer cannot be used while this device keeps another account ([EntryScreen.OperatorHelp.anotherAccountKept]). */
    ASSIST_ANOTHER_ACCOUNT_KEPT("⟦On the request's screen: the operator's answer cannot be used on this device while it keeps another account; nothing was changed and the request is kept; sign out of that account on this device first (its sign-out says how many of its changes were not sent), then look again⟧", awaitingOwner = true),

    /**
     * An address this device knows under another account or key ([LinkDeviceEnd.IDENTITY_FAULT], [LinkPasswordResult.IDENTITY_FAULT],
     * [ReplacePasswordResult.IDENTITY_FAULT], [EntryScreen.OperatorHelp.identityFault], [SignInAnswer.IDENTITY_FAULT],
     * [KitRecoverResult.IDENTITY_FAULT], [CreateAccountResult.IDENTITY_FAULT]): the identity fault a sign-in has.
     */
    IDENTITY_FAULT_ADDRESS_KNOWN("⟦The identity fault: the account the server gave for this address does not match its own record, or is not the account this device knows under the address; nothing was changed on this device⟧", awaitingOwner = true),

    // ---- An address this device knows under an earlier account: "Forget the earlier account on this device" (decided on 2026-11-17) ----

    /** [EarlierAccountKnown.title]: the heading of the refusal that offers the forgetting. */
    REMADE_ACCOUNT_TITLE("⟦Heading of the refusal for an address this device knows as another account: this address belongs to another account on this device⟧", awaitingOwner = true),

    /** [EarlierAccountKnown.refusal]: {0} the address, {1} the server's name. */
    REMADE_ACCOUNT_REFUSAL("⟦The refusal: this device knows {0} on {1} as another account, so andvari stopped and nothing was changed⟧", awaitingOwner = true),

    /** [EarlierAccountKnown.ifRemade]: the first possibility, a sentence of its own. */
    REMADE_ACCOUNT_IF_REMADE("⟦The first possibility, a sentence of its own: the account under this address was deleted and made again, and this device still remembers the earlier one⟧", awaitingOwner = true),

    /** [EarlierAccountKnown.ifServer]: the second possibility, a sentence of its own. */
    REMADE_ACCOUNT_IF_SERVER("⟦The second possibility, a sentence of its own: the server is not giving this device the account it knows; then something is wrong with the server, and nothing should be forgotten⟧", awaitingOwner = true),

    /** [EarlierAccountKnown.howToTell]: how the person tells the two apart. */
    REMADE_ACCOUNT_HOW_TO_TELL("⟦How to tell: the person knows which, because they, or the operator with their knowledge, deleted the account and made it again⟧", awaitingOwner = true),

    /** [EarlierAccountKnown.forgetLabel]: the button that offers the forgetting, in the owner's own words of 2026-11-17. Never preselected. */
    REMADE_ACCOUNT_FORGET("Forget the earlier account on this device"),

    /** [EarlierAccountKnown.confirmTitle]: the heading of the second confirmation. */
    REMADE_ACCOUNT_CONFIRM_TITLE("⟦Heading of the second confirmation: forget the earlier account?⟧", awaitingOwner = true),

    /** [EarlierAccountKnown.confirmLines], first: {0} the address. */
    REMADE_ACCOUNT_CONFIRM("⟦What goes: this device forgets the earlier account under {0}; the server and what this device knows of it stay as they are⟧", awaitingOwner = true),

    /** [EarlierAccountKnown.confirmLines] with a kept copy: {0} the address, {1} the number of its changes not sent (more than one). */
    REMADE_ACCOUNT_CONFIRM_COPY_UNSENT("⟦This device's copy of the earlier account is deleted; {1} changes made on this device under that account (in its copy or to shared vaults) were not sent, and they are lost⟧", awaitingOwner = true),

    /** [EarlierAccountKnown.confirmLines] with a kept copy and one change not sent: {0} the address. */
    REMADE_ACCOUNT_CONFIRM_COPY_ONE_UNSENT("⟦This device's copy of the earlier account is deleted; one change made on this device under that account (in its copy or to a shared vault) was not sent, and it is lost⟧", awaitingOwner = true),

    /** [EarlierAccountKnown.confirmLines] with a kept copy whose unsent changes this device cannot count: {0} the address. */
    REMADE_ACCOUNT_CONFIRM_COPY_CANNOT_TELL("⟦This device's copy of the earlier account is deleted; andvari cannot tell whether changes made on this device under that account were not sent, and any that were not are lost⟧", awaitingOwner = true),

    /** [EarlierAccountKnown.confirmLines] with a kept copy that has nothing waiting: {0} the address. */
    REMADE_ACCOUNT_CONFIRM_COPY_ALL_SENT("⟦This device's copy of the earlier account is deleted; every change made on this device under that account was sent⟧", awaitingOwner = true),

    /** [EarlierAccountKnown.confirmLines] without a kept copy, where that account's signed changes to shared vaults were never sent: {0} the address, {1} how many (more than one). */
    REMADE_ACCOUNT_CONFIRM_SHARED_UNSENT("⟦No copy of the earlier account is kept here, but {1} changes to shared vaults made on this device under that account were never sent; they are deleted with it and lost⟧", awaitingOwner = true),

    /** [EarlierAccountKnown.confirmLines] without a kept copy, with one such change: {0} the address. */
    REMADE_ACCOUNT_CONFIRM_SHARED_ONE_UNSENT("⟦No copy of the earlier account is kept here, but one change to a shared vault made on this device under that account was never sent; it is deleted with it and lost⟧", awaitingOwner = true),

    /** [EarlierAccountKnown.confirmLines] without a kept copy where this device cannot count such changes: {0} the address. */
    REMADE_ACCOUNT_CONFIRM_SHARED_CANNOT_TELL("⟦No copy of the earlier account is kept here; andvari cannot tell whether changes to shared vaults made on this device under that account were sent, and any that were not are deleted with it and lost⟧", awaitingOwner = true),

    /** [EarlierAccountKnown.confirmLines], last, always. */
    REMADE_ACCOUNT_CONFIRM_ALWAYS("⟦Always: this cannot be undone; if the account was not deleted and made again, forgetting means this device trusts whatever account the server gives it under this address from now on⟧", awaitingOwner = true),

    /** [EarlierAccountKnown.confirmLabel]: the second confirmation's button. */
    REMADE_ACCOUNT_CONFIRM_FORGET("⟦The second confirmation's button: forget it⟧", awaitingOwner = true),

    /** [ForgetEarlierResult.FORGOTTEN]: {0} the address. */
    REMADE_ACCOUNT_FORGOTTEN("⟦After the forgetting: this device has forgotten the earlier account under {0}; nothing was sent to the server, and andvari still checks the server as before; try again to go on⟧", awaitingOwner = true),

    /** [ForgetEarlierResult.NOTHING_TO_FORGET]: {0} the address. */
    REMADE_ACCOUNT_NOTHING_TO_FORGET("⟦This device does not remember an earlier account under {0}, so there was nothing to forget; nothing changed⟧", awaitingOwner = true),

    /** [ForgetEarlierResult.UNDER_WAY]: {0} the address. */
    REMADE_ACCOUNT_FORGET_UNDER_WAY("⟦Nothing was forgotten: andvari is still doing something on this device for that address; try again in a moment⟧", awaitingOwner = true),

    /** [ForgetEarlierResult.REQUEST_KEPT]: {0} the address. */
    REMADE_ACCOUNT_FORGET_REQUEST_KEPT("⟦Nothing was forgotten: this device keeps a request for the operator's help at this server; leave that request first, on its screen, then try again⟧", awaitingOwner = true),

    /** [ForgetEarlierResult.ACCOUNT_OPEN]: {0} the address. */
    REMADE_ACCOUNT_FORGET_ACCOUNT_OPEN("⟦Nothing was forgotten: the earlier account is open or kept on this device; sign out of it first (its sign-out says how many changes were not sent), then try again⟧", awaitingOwner = true),

    /** [ForgetEarlierResult.NOT_CONFIRMED]: {0} the address. */
    REMADE_ACCOUNT_FORGET_NOT_CONFIRMED("⟦Nothing was forgotten: the second confirmation was not given, or what it said has changed since (a lock took it back, or the count of changes not sent changed); read it again before confirming⟧", awaitingOwner = true),

    /**
     * [ForgetEarlierResult.ADDRESS_NOW_THE_SERVED_ACCOUNT]: the address came to name here the very account the server serves.
     * Must not say "read it again" (no offer stands). No values.
     */
    REMADE_ACCOUNT_FORGET_ADDRESS_NOW_SERVED("⟦After “Forget”, where this device came to know the address as the account the server serves: nothing was forgotten, because this device now knows the address as that account; try again to go on⟧", awaitingOwner = true),

    /** [NewAccountRememberedNotice.line]: once, at the next sign-in, registration, recovery or link taken under the address after the forgetting. {0} the address. */
    REMADE_ACCOUNT_REMEMBERED("⟦Once, after the forgetting, when the next account under the address is taken: this device now remembers the new account under {0}⟧", awaitingOwner = true),

    /** On the kit screen after a recovery whose session this device did not keep because it keeps another account ([KitScreen.notKeptLine]). */
    KIT_RECOVERED_NOT_KEPT("⟦With the new kit: the new master password is in force and the old kit no longer works, so save this kit now; this device keeps another account, so the recovered account opens here with the new password only once that account is signed out on this device⟧", awaitingOwner = true),

    /** On the kit screen after a registration whose session this device did not keep because it keeps another account ([KitScreen.notKeptLine], [CreateAccountResult.ACCOUNT_MADE_NOT_KEPT]). */
    KIT_REGISTERED_NOT_KEPT("⟦With the first kit of an account this device did not keep: the account was made, so save this kit now; this device keeps another account, so the new account opens here with its master password only once that account is signed out on this device⟧", awaitingOwner = true),

    /**
     * On the kit screen after a registration whose session this device did not keep because it came to hold its server's
     * operator account meanwhile ([KitScreen.notKeptLine], [CreateAccountResult.ACCOUNT_MADE_OPERATOR_ACCOUNT_HELD]).
     */
    KIT_REGISTERED_OPERATOR_ACCOUNT_HELD("⟦With the first kit of an account this device did not keep: the account was made, so save this kit now; this device holds its server's operator account, so the new account opens here with its master password only once that operator account is removed from this device (signing out is not the way)⟧", awaitingOwner = true),

    /**
     * [AppSnapshot.kitWiped] with [KitWipedNotice.unseen], after a recovery: the kit was made while andvari was not on the
     * screen and wiped before it came back. Never "the kit that was on the screen", never "save this kit".
     */
    KIT_WIPED_UNSEEN_AFTER_RECOVERY("⟦Once, after a lock or a restart: a recovery kit was made while andvari was not on the screen, and it was taken away before it was ever shown; the recovery itself stands and the new master password is in force; the next sign-in with it, on any device, shows a new kit⟧", awaitingOwner = true),

    /** As [KIT_WIPED_UNSEEN_AFTER_RECOVERY], after a registration. */
    KIT_WIPED_UNSEEN_AFTER_REGISTRATION("⟦Once, after a lock or a restart: the new account's recovery kit was made while andvari was not on the screen, and it was taken away before it was ever shown; the account was made all the same; the next sign-in with its master password, on any device, shows a new kit⟧", awaitingOwner = true),

    /** As [KIT_WIPED_UNSEEN_AFTER_RECOVERY], where this device cannot take the account now; shown with [KitWipedNotice.whyHere]. */
    KIT_WIPED_UNSEEN_AFTER_RECOVERY_NOT_HERE("⟦Once, after a lock or a restart: a recovery kit was made while andvari was not on the screen, and it was taken away before it was ever shown; the recovery itself stands and the new master password is in force; the next sign-in to that account shows a new kit; on this device that sign-in waits until what stands in its way here is gone (the line below says what)⟧", awaitingOwner = true),

    /** As [KIT_WIPED_UNSEEN_AFTER_RECOVERY_NOT_HERE], after a registration. */
    KIT_WIPED_UNSEEN_AFTER_REGISTRATION_NOT_HERE("⟦Once, after a lock or a restart: the new account's recovery kit was made while andvari was not on the screen, and it was taken away before it was ever shown; the account was made all the same; the next sign-in to that account shows a new kit; on this device that sign-in waits until what stands in its way here is gone (the line below says what)⟧", awaitingOwner = true),

    /** [AppSnapshot.kitWiped] after a recovery: a lock (or the app's close) wiped the kit shown with a refusal. */
    KIT_WIPED_AFTER_RECOVERY("⟦Once, after a lock or a restart: the recovery kit that was on the screen is gone; the recovery itself stands and the new master password is in force; the next sign-in with it, on any device, shows a new kit to save⟧", awaitingOwner = true),

    /** [AppSnapshot.kitWiped] after a registration: a lock (or the app's close) wiped the first kit shown with a refusal. */
    KIT_WIPED_AFTER_REGISTRATION("⟦Once, after a lock or a restart: the recovery kit that was on the screen is gone; the account was made all the same; the next sign-in with its master password, on any device, shows a new kit to save⟧", awaitingOwner = true),

    /**
     * [AppSnapshot.kitWiped] after a recovery, where this device cannot take the account now (another account kept, a
     * fault of the account's identity, its server's operator account held): never "on any device". Shown with
     * [KitWipedNotice.whyHere], the refusal's own line, which says what stands in the way here.
     */
    KIT_WIPED_AFTER_RECOVERY_NOT_HERE("⟦Once, after a lock or a restart: the recovery kit that was on the screen is gone; the recovery itself stands and the new master password is in force; the next sign-in to that account shows a new kit to save; on this device that sign-in waits until what stands in its way here is gone (the line below says what)⟧", awaitingOwner = true),

    /** As [KIT_WIPED_AFTER_RECOVERY_NOT_HERE], after a registration. */
    KIT_WIPED_AFTER_REGISTRATION_NOT_HERE("⟦Once, after a lock or a restart: the recovery kit that was on the screen is gone; the account was made all the same; the next sign-in to that account shows a new kit to save; on this device that sign-in waits until what stands in its way here is gone (the line below says what)⟧", awaitingOwner = true),

    /**
     * After a registration the server took, whose session this device refused for a fault of the account's identity
     * ([CreateAccountResult.ACCOUNT_MADE_IDENTITY_FAULT]); also the kit screen's line.
     */
    KIT_REGISTERED_IDENTITY_FAULT("⟦With the first kit of an account this device did not keep: the account was made, so save this kit now; but what the server answered about the new account does not match what this device knows of that address (the identity fault), so nothing of the account is kept or opened here; sign in to it on another device⟧", awaitingOwner = true),

    // ---- a server's policy that forbids the offline copy (decided on 2026-11-17) ----
    // Values of every line below: {0} the changes that could not be sent, {1} the server's name, {2} the changes that may
    // or may not have arrived. [PolicyWipeNotice.lines] gives the opening line, then the "may or may not" line if any.

    /** [PolicyWipeNotice]: every change was sent first. */
    POLICY_COPY_REMOVED_NOTHING_LOST("⟦Once, after the wipe: {1} doesn't allow a copy of the vault on devices, so andvari removed this device's copy; every change made here was sent first: nothing was lost⟧", awaitingOwner = true),

    /** [PolicyWipeNotice]: one change could not be sent. */
    POLICY_COPY_REMOVED_ONE_LOST("⟦Once, after the wipe: {1} doesn't allow a copy of the vault on devices, so andvari removed this device's copy; 1 change made here couldn't be sent first, and it is lost⟧", awaitingOwner = true),

    /** [PolicyWipeNotice]: {0} changes could not be sent. */
    POLICY_COPY_REMOVED_LOST("⟦Once, after the wipe: {1} doesn't allow a copy of the vault on devices, so andvari removed this device's copy; {0} changes made here couldn't be sent first, and they are lost⟧", awaitingOwner = true),

    /** [PolicyWipeNotice]: part of the copy could not be read, so what was lost cannot be told (never "nothing"). */
    POLICY_COPY_REMOVED_CANNOT_TELL("⟦Once, after the wipe: {1} doesn't allow a copy of the vault on devices, so andvari removed this device's copy; andvari couldn't open the copy to send what waited in it, so it can't tell whether changes made here were lost⟧", awaitingOwner = true),

    /**
     * [PolicyWipeNotice]: {0} changes are known to be lost, and more may be: part of what waited (saves kept to be
     * finished, or the copy itself) could not be read. The known number is said, never hidden behind "cannot tell".
     */
    POLICY_COPY_REMOVED_AT_LEAST_LOST("⟦Once, after the wipe: {1} doesn't allow a copy of the vault on devices, so andvari removed this device's copy; at least {0} of the changes made here couldn't be sent first and are lost, and andvari can't tell whether more were⟧", awaitingOwner = true),

    /**
     * [PolicyWipeNotice]: the copy's queue was read and nothing in it is known to be lost, but the saves kept to be
     * finished (a lock cut them short) could not be read, so whether they were lost cannot be told. Not "the copy could
     * not be opened": it was.
     */
    POLICY_COPY_REMOVED_KEPT_UNREAD("⟦Once, after the wipe: {1} doesn't allow a copy of the vault on devices, so andvari removed this device's copy; andvari couldn't read the saves it had kept to finish later, so it can't tell whether any of them were lost⟧", awaitingOwner = true),

    /** [PolicyWipeNotice]: none is known to be lost, and some may or may not have arrived (the next line says how many). */
    POLICY_COPY_REMOVED_NONE_KNOWN_LOST("⟦Once, after the wipe: {1} doesn't allow a copy of the vault on devices, so andvari removed this device's copy; no change made here is known to be lost⟧", awaitingOwner = true),

    /** [PolicyWipeNotice], second line: one change was sent and no answer came in time. */
    POLICY_COPY_REMOVED_UNSURE_ONE("⟦1 change was sent, but no answer came in time: it may or may not have arrived; check the vault for it⟧", awaitingOwner = true),

    /** [PolicyWipeNotice], second line: {2} changes were sent and no answer came in time. */
    POLICY_COPY_REMOVED_UNSURE("⟦{2} changes were sent, but no answer came in time: they may or may not have arrived; check the vault for them⟧", awaitingOwner = true),

    /**
     * [PolicyWipeNotice], last line: one "Move everything" this device started was not finished; it stands half-done at
     * the server, and this device's record of it went with the copy, so this device cannot finish it.
     */
    POLICY_COPY_REMOVED_MOVE_UNFINISHED_ONE("⟦1 \"Move everything\" started on this device wasn't finished: it stands half-done on the server, and this device can no longer finish it; check both vaults and move what is left by hand⟧", awaitingOwner = true),

    /** As [POLICY_COPY_REMOVED_MOVE_UNFINISHED_ONE], {3} of them. */
    POLICY_COPY_REMOVED_MOVES_UNFINISHED("⟦{3} \"Move everything\" runs started on this device weren't finished: they stand half-done on the server, and this device can no longer finish them; check the vaults and move what is left by hand⟧", awaitingOwner = true),

    /**
     * [ServerPolicy.capturesKeptLine]: on a phone, while the server's rules forbid keeping data on it, logins andvari
     * catches are still kept on the phone, sealed, until the person saves or discards them.
     */
    POLICY_CAPTURES_KEPT_SEALED("⟦In Settings, with the server's rules, on a phone: the server doesn't allow keeping data on this phone, but logins andvari catches are kept here, sealed, until you save or discard them; opening them needs the server⟧", awaitingOwner = true),

    /** The content's notice: one login andvari caught could not be read (opened) by the account, so it was removed. */
    CAPTURES_UNREADABLE_REMOVED_ONE("⟦A content notice: 1 login andvari caught on this device could not be read, so it was removed; save it again if you need it⟧", awaitingOwner = true),

    /** As [CAPTURES_UNREADABLE_REMOVED_ONE], {0} of them. */
    CAPTURES_UNREADABLE_REMOVED_MANY("⟦A content notice: {0} logins andvari caught on this device could not be read, so they were removed; save them again if you need them⟧", awaitingOwner = true),

    /** As [CAPTURES_UNREADABLE_REMOVED_ONE], where how many is not known. */
    CAPTURES_UNREADABLE_REMOVED("⟦A content notice, where the number is not known: some logins andvari caught on this device could not be read, so they were removed; save them again if you need them⟧", awaitingOwner = true),

    /**
     * A change the person makes while this device's copy is being removed for the policy (the content's refusal): it
     * was not made, why, and to make it again in a moment. What the person typed stays on the screen.
     */
    SAVE_COPY_BEING_REMOVED("⟦This change wasn't made: the server doesn't allow a copy of the vault on devices, and andvari is removing this device's copy now; make it again in a moment⟧", awaitingOwner = true),

    /**
     * [io.silencelen.andvari.core.app.content.ContentState.removingLine]: shown with the vault, where the stopped line would
     * be, for as long as this device's copy is being removed for the policy. Not a refusal: nothing was asked for.
     */
    POLICY_COPY_BEING_REMOVED("⟦With the vault, while the copy is being removed: andvari is removing this device's copy of the vault because the server's rules don't allow keeping one; what waits here is being sent first; you can make changes again in a moment⟧", awaitingOwner = true),

    /**
     * A save that was already in this device's copy when its removal began (the policy's one try sends it): it is not
     * said as "not made"; it may or may not arrive, and the notice after the removal says what could not be sent.
     */
    SAVE_IN_POLICY_ATTEMPT("⟦This change was already on its way when andvari began removing this device's copy for the server's rules: it is sent in the one try before the removal, and may or may not arrive; the notice afterwards says what couldn't be sent⟧", awaitingOwner = true),

    /**
     * A change into a shared vault whose deletion stands (a new item, an edit, a deletion, a move or copy into it): the
     * server ended every grant with the deletion, so nothing is taken in on the device. Says that the vault was deleted,
     * that its owner can restore it for a limited time, and that nothing can be saved into it until then; no day and no
     * name of the owner.
     */
    SAVE_VAULT_DELETED("⟦This vault was deleted. Its owner can restore it for a limited time; nothing can be saved into it until then⟧", awaitingOwner = true),

    /**
     * [AppSnapshot.closedForPolicy]: the server's policy as kept on this device cannot be read, so this device's copy
     * stays closed (not opened, not deleted) until the policy has been read from the server again; nothing is lost.
     */
    POLICY_UNREADABLE_COPY_CLOSED("⟦This device couldn't read the server's rules it kept, so it keeps its copy of the vault closed, untouched, until it has read them from the server again; nothing was deleted; connect to the server to go on⟧", awaitingOwner = true),

    /**
     * [LockedScreen.keysAtServerLine]: under a server policy that forbids keeping data on the device, this device keeps
     * no key that opens the account, so every unlock asks the server, and there is no unlock while it cannot be reached.
     */
    UNLOCK_KEYS_AT_SERVER("⟦On the lock screen, while the server's rules forbid keeping data on this device: this device keeps no key that opens your account, so andvari asks the server each time you unlock; while the server can't be reached, andvari can't unlock, and nothing is removed⟧", awaitingOwner = true),

    /**
     * [LockedScreen.endLine]: the server ended this session while its rules keep the account's keys at the server, so no
     * password opens anything on this device. Must claim no copy. No values.
     */
    SIGNED_OUT_KEYS_AT_SERVER("⟦On the lock screen, where the server ended this session and its rules keep the account's keys at the server: the server ended this session; this device keeps no key and no copy that opens your account, so nothing opens here until you sign in again; nothing was removed; logins andvari caught stay sealed until then⟧", awaitingOwner = true),

    /**
     * [LockedScreen.endLineBesideSignOut]: as [SIGNED_OUT_KEYS_AT_SERVER], said where a way out that signs this kept account
     * out stands beside it. Must not tell them to sign in again. No values.
     */
    SIGNED_OUT_KEYS_AT_SERVER_SIGN_OUT_FIRST("⟦Beside a kept account that must be signed out first, where the server ended its session and its rules keep the account's keys at the server: the server ended this session; this device keeps no key and no copy that opens that account; nothing was removed; logins andvari caught stay sealed⟧", awaitingOwner = true),

    /** [VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE]: said in place after the unlock. No values. */
    UNLOCK_KEYS_AT_SERVER_UNREACHABLE("⟦After an unlock, while the server's rules keep the account's keys at the server and the server did not answer: nothing was opened and nothing was removed; your password could not be checked, because under this server's rules only the server can; try again when the server can be reached⟧", awaitingOwner = true),

    /** [VaultUnlockResult.KEYS_AT_SERVER_ENDED]: said in place after the unlock, beside [LockedScreen.endLine]. No values. */
    UNLOCK_KEYS_AT_SERVER_ENDED("⟦After an unlock, while the server's rules keep the account's keys at the server and this session has ended: nothing was opened and nothing was removed; nothing opens on this device until you sign in again⟧", awaitingOwner = true),

    /**
     * [VaultUnlockResult.KEYS_AT_SERVER_REFUSED]: the server answered and refused to hand over the account's keys (not a
     * wait, not the session's end). Never "the server did not answer". No values.
     */
    UNLOCK_KEYS_AT_SERVER_REFUSED("⟦After an unlock, while the server's rules keep the account's keys at the server: the server answered but refused to hand over your account's keys, so nothing was opened; nothing was removed; your password could not be checked⟧", awaitingOwner = true),

    /**
     * [KitScreen.idleWarningLine]: thirty seconds before the kit screen's idle limit locks the app, where the limit is longer
     * than thirty seconds (a shorter one has [KIT_IDLE_WARNING_SHORT]).
     */
    KIT_IDLE_WARNING("⟦On the kit screen, thirty seconds before the idle limit: if nobody touches this screen, the app locks and the kit is wiped from the screen; touch the screen to keep it⟧", awaitingOwner = true),

    /**
     * [KitScreen.idleWarningLine] where the limit is thirty seconds or less, so the warning shows from the start of the
     * screen. {0} the limit in whole seconds ([KitScreen.idleWarning] fills it).
     */
    KIT_IDLE_WARNING_SHORT("⟦On the kit screen, from its start, where the idle limit is {0} seconds (thirty or less): if nobody touches this screen for {0} seconds, the app locks and the kit is wiped from the screen; touch the screen to keep it⟧", awaitingOwner = true),

    /**
     * [KitWipedNotice.whyHere] and [KeptStops.lineWithoutKit]: why this device cannot open the account, once the kit shown
     * with the refusal is gone or typed back; none of them is about the kit. Another account is kept here.
     */
    KIT_NOT_HERE_WHY_ANOTHER_KEPT("⟦Under the notice that a kit is gone, or on the first screen after such a kit was typed back: this device keeps another account, so it cannot open this one until that account is signed out here; signing out says first how many of its changes were not sent⟧", awaitingOwner = true),

    /** As [KIT_NOT_HERE_WHY_ANOTHER_KEPT]: this device holds its server's operator account. */
    KIT_NOT_HERE_WHY_OPERATOR_HELD("⟦Same place: this device holds its server's operator account, so it cannot open this one until that account is removed from this device; signing it out is not enough⟧", awaitingOwner = true),

    /** As [KIT_NOT_HERE_WHY_ANOTHER_KEPT]: the identity fault. */
    KIT_NOT_HERE_WHY_IDENTITY_FAULT("⟦Same place: this device knows this address as another account, or with other keys, so it keeps nothing of this account; sign in to it on another device⟧", awaitingOwner = true),

    /** As [KIT_NOT_HERE_WHY_ANOTHER_KEPT]: the server's keys are not the ones this device knows; the way out is the copy's removal. */
    KIT_NOT_HERE_WHY_SERVER_KEYS("⟦Same place: the keys the server gave are not the ones this device knows for this account (the server serves other keys, or this device's copy is damaged); to go on here, remove this device's copy (it says first how many changes made here were not sent), then sign in again⟧", awaitingOwner = true),

    /** As [KIT_NOT_HERE_WHY_ANOTHER_KEPT]: this device's copy of the account is damaged; the way out is the copy's removal. */
    KIT_NOT_HERE_WHY_COPY_DAMAGED("⟦Same place: this device's copy of the account is damaged, so andvari did not open it; remove this device's copy (it says first how many changes were not sent, or that it cannot tell), then sign in again⟧", awaitingOwner = true),

    /** As [KIT_NOT_HERE_WHY_ANOTHER_KEPT]: not opened here, for no reason this device can name. */
    KIT_NOT_HERE_WHY_NOT_OPENED("⟦Same place: this device did not open the account; sign in to it again⟧", awaitingOwner = true),

    /**
     * [ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT]: a recovery the server made, then not opened here because this device keeps
     * another account. Never "nothing was changed" ([RECOVERY_ANOTHER_ACCOUNT_KEPT] is the stop before the commit).
     */
    RECOVERY_COMMITTED_ANOTHER_ACCOUNT_KEPT("⟦After a recovery that went through while this device keeps another account: the new master password is set and the old kit no longer works; this device keeps another account, so it did not open this one here; sign out of that account on this device first (its sign-out says how many of its changes were not sent), then sign in with the new password⟧", awaitingOwner = true),

    /**
     * [KitScreen.earlierKitVoidLine]: first on the reveal of a kit made because one shown on this device before was never
     * confirmed (a lock took it, or it was left).
     */
    KIT_EARLIER_NOT_CONFIRMED_VOID("⟦First on a new kit's screen, before anything else: a recovery kit was shown on this device before and was not confirmed; it no longer works; do not keep it (destroy anything you wrote down or stored of it) and save this one instead⟧", awaitingOwner = true),

    /** After a recovery's commit the server took, whose answer did not open the account here ([ReplacePasswordResult.COMMITTED_NOT_OPENED]). */
    RECOVERY_COMMITTED_NOT_OPENED("⟦After a recovery that went through: the new master password is in force and the old kit no longer works, but what the server answered did not open the account on this device, so nothing of it is kept here and no new kit could be shown; sign in with the new master password, which shows a new kit to save⟧", awaitingOwner = true),

    /**
     * Beside every kit shown with a refusal after a commit ([KitScreen.notKeptHoldsLine]): how long the kit holds. This
     * device cannot tell the server that the kit was typed back, so the next sign-in to the account, on any device, shows
     * a new kit that replaces this one.
     */
    KIT_NOT_KEPT_HOLDS_UNTIL_SIGN_IN("⟦How long this kit holds: keep it until you next sign in to this account, on any device; you will then be shown a new kit, and this one stops working⟧", awaitingOwner = true),

    /** On the kit screen after a recovery or registration whose session this device refused for another reason, which the result says ([KitScreen.notKeptLine]). */
    KIT_NOT_KEPT_HERE("⟦With a new kit for an account this device did not keep: the account's old kit, if it had one, no longer works and this kit is the only one, so save it now; the line about why this device did not keep the account says what to do next⟧", awaitingOwner = true),

    /** After a recovery's commit the server took, refused here as the identity fault ([ReplacePasswordResult.IDENTITY_FAULT_COMMITTED]); also the kit screen's line. */
    RECOVERY_COMMITTED_IDENTITY_FAULT("⟦With the new kit, after a recovery: the new master password is in force and the old kit no longer works, so save this kit now; but this device knows this address under another account or key, so it did not open the account (the identity fault); nothing of it is kept here⟧", awaitingOwner = true),

    /** After a recovery's commit the server took, refused here because the session's key does not open this device's copy ([ReplacePasswordResult.SERVER_KEYS_NOT_KNOWN_HERE_COMMITTED]); also the kit screen's line. */
    RECOVERY_COMMITTED_SERVER_KEYS_NOT_KNOWN_HERE("⟦With the new kit, after a recovery: the new master password is in force and the old kit no longer works, so save this kit now; but the keys the server gave are not the ones this device knows for the account (the server serves other keys, or this device's own copy is damaged), so it did not open the account; removing this device's copy (it says first how many changes were not sent) and signing in again is the way on⟧", awaitingOwner = true),

    /** After a recovery's commit the server took, refused here for another reason of the keeper's ([ReplacePasswordResult.COMMITTED_NOT_KEPT]); also the kit screen's line. */
    RECOVERY_COMMITTED_NOT_KEPT("⟦With the new kit, after a recovery: the new master password is in force and the old kit no longer works, so save this kit now; this device did not open the account, and signing in with the new password is the way on⟧", awaitingOwner = true),

    /** After a recovery's commit the server took, refused here because this device holds its server's operator account ([ReplacePasswordResult.OPERATOR_ACCOUNT_HELD_COMMITTED]); also the kit screen's line. */
    RECOVERY_COMMITTED_OPERATOR_ACCOUNT_HELD("⟦With the new kit, after a recovery: the new master password is in force and the old kit no longer works, so save this kit now; this device holds the operator's account of a server, so it did not open the account; remove that account from this device first, then sign in with the new password⟧", awaitingOwner = true),

    /** After a recovery's commit the server took, refused here because this device's copy of the account is damaged ([ReplacePasswordResult.KEPT_COPY_DAMAGED_COMMITTED]); also the kit screen's line. */
    RECOVERY_COMMITTED_KEPT_COPY_DAMAGED("⟦With the new kit, after a recovery: the new master password is in force and the old kit no longer works, so save this kit now; this device's copy of the account is damaged, so it did not open the account; remove this device's copy (it says first how many changes were not sent, or that it cannot tell), then sign in with the new password⟧", awaitingOwner = true),

    /** A flow stopped because this device holds its server's operator account (the keeper's own reason, `operator_account_held`), at every place that can show it. */
    OPERATOR_ACCOUNT_HELD_HERE("⟦This device holds the operator's account of a server; nothing was changed; remove that account from this device first (never just a sign-out), then try again⟧", awaitingOwner = true),

    /** A flow stopped because this device's copy of the account is damaged (the keeper's own reason, `kept_copy_damaged`), at every place that can show it. */
    KEPT_COPY_DAMAGED("⟦This device's copy of the account is damaged; nothing was changed; remove it from this device (its removal says first how many changes were not sent, or that it cannot tell), then sign in or recover⟧", awaitingOwner = true),

    /** [OperatorConsole.policyRefusal]: the server refused the policy, answering that its key cost is below the server's floor. */
    OPERATOR_POLICY_KDF_TOO_WEAK("⟦Beside the policy, after a save: the server refused it, saying the key cost asked for is below what it accepts, so nothing was stored; said as the server's answer, never as a fact about the policy; raise it, then save again⟧", awaitingOwner = true),

    /** [OperatorConsole.policyRefusal]: the server refused the policy, answering that the memory cost is not a whole number of KiB. */
    OPERATOR_POLICY_KDF_MEM_NOT_KIB("⟦Beside the policy, after a save: the server refused it, saying the memory cost must be a whole number of KiB, so nothing was stored; said as the server's answer, never as a fact about the policy; correct it, then save again⟧", awaitingOwner = true),

    /** [OperatorConsole.policyRefusal]: the server refused the policy, answering that one of its fields is outside its bounds. */
    OPERATOR_POLICY_OUT_OF_BOUNDS("⟦Beside the policy, after a save: the server refused it, saying one of its values is outside what it accepts, so nothing was stored; said as the server's answer, never as a fact about the policy; check the values, then save again⟧", awaitingOwner = true),

    /** [LinkDeviceEnd.TOO_MANY], on the new device: {0} the wait the server named ([AppApi.retryAfterSeconds]), where it named one. */
    DEVICE_LINK_TOO_MANY("⟦A device link stopped on the new device because the server refused its requests as too many for now: nothing was linked; say the wait {0} where the server named one; then start again with a new link from the other device; never “unreachable”⟧", awaitingOwner = true),

    /** [DeviceLinkHost.Ended.line], on the device that showed the link: {0} the wait the server named, where it named one. */
    DEVICE_LINK_HOST_TOO_MANY("⟦A device link stopped on the device that showed it because the server refused its requests as too many for now: nothing was linked; say the wait {0} where the server named one; then show a new link; never “unreachable”⟧", awaitingOwner = true),

    /**
     * [EntryScreen.LinkDeviceEnded.lineNow], on the new device, once the wait the server named at a [LinkDeviceEnd.TOO_MANY]
     * end has run out ([NamedWait.over]). In place of [DEVICE_LINK_TOO_MANY]; never "the server named no wait".
     */
    DEVICE_LINK_TOO_MANY_WAIT_OVER("⟦A device link stopped on the new device because the server refused its requests as too many: nothing was linked; the wait the server named is over now; start again with a new link from the other device; never “unreachable”, never that the server named no wait⟧", awaitingOwner = true),

    /**
     * [DeviceLinkHost.Ended.lineNow], on the device that showed the link, once the wait the server named at a too-many end has
     * run out ([NamedWait.over]). In place of [DEVICE_LINK_HOST_TOO_MANY]; never "the server named no wait".
     */
    DEVICE_LINK_HOST_TOO_MANY_WAIT_OVER("⟦A device link stopped on the device that showed it because the server refused its requests as too many: nothing was linked; the wait the server named is over now; show a new link; never “unreachable”, never that the server named no wait⟧", awaitingOwner = true),

    /** [LinkPasswordResult.CODE_REFUSED_LINK_STAYS]: the link's password screen is back at the password, and the link stays. */
    DEVICE_LINK_CODE_REFUSED_LINK_STAYS("⟦At a device link's pickup: the server did not take the two-step code, most likely wrong or already used; never “wrong password”; the link is still open; type the master password and then the current code again⟧", awaitingOwner = true),

    /** A sign-in refused after the two-step code ([SignInAnswer.REFUSED_AFTER_CODE]). */
    SIGN_IN_REFUSED_AFTER_CODE("⟦The server did not take the two-step code; it answers a wrong code and a wrong master password alike, but it asked for the code only after this password, so most likely the code was wrong or already used; try again with a new code⟧", awaitingOwner = true),

    /** A device link that stopped after the two-step code ([LinkDeviceEnd.REFUSED_AFTER_CODE]). */
    DEVICE_LINK_REFUSED_AFTER_CODE("⟦The link stopped after the two-step code: the server did not take the code (most likely wrong or already used); start again with a new link from your other device⟧", awaitingOwner = true),

    /**
     * A device link stopped before its pickup for an address this device knows under another account, where it holds a
     * record of the link's account's key and the link alone cannot tell a remade account from a substitution
     * ([LinkDeviceEnd.IDENTITY_FAULT_CANNOT_TELL]): true of both causes, it points to the sign-in, which tells them apart.
     */
    DEVICE_LINK_IDENTITY_CANNOT_TELL("⟦A device link stopped before it was picked up: this device knows this address at this server under another account, and from the link alone it cannot tell whether that account was deleted and made again or the server is not giving the account it knows; nothing was changed on this device; sign in on this device with the master password instead, which can tell and says what can be done⟧", awaitingOwner = true),

    /** An operator's answer that names another account than the one this device keeps for the address ([EntryScreen.OperatorHelp.notTheKeptAccount]). */
    ASSIST_NOT_THE_KEPT_ACCOUNT("⟦On the request's screen: the operator's answer names an account that is not the one this device keeps for this address; nothing was changed and the request stays as it is; tell whoever runs the server⟧", awaitingOwner = true),

    /**
     * Short only by the file sizes the items say they have, which another member may have
     * written: the copy goes on and the server decides. {0} the storage limit, {1} how much more the stated sizes need.
     */
    SPACE_SHORT_DECLARED("This may not all fit: by the sizes its files state, it needs {1} more space than your account has, whose limit is {0}. Those sizes come from whoever added the files and may be wrong, so andvari goes on: the server decides, and andvari tells you about anything it refuses."),

    // ---- the vault content's own lines ([io.silencelen.andvari.core.app.content.ContentCopy]); a name goes in through
    // ContentCopy.fillNames, which quotes it once, by the sentence, and leaves the plain words for a missing name unquoted ----

    /** A held vault's line when its owner (not this account) deleted it. {0} until when this device keeps the copy ([HELD_KEPT_UNTIL]). */
    HELD_DELETED_BY_OWNER("Deleted by its owner. {0}"),

    /** A held vault's line when its owner (not this account) deleted it for good. {0} as above. */
    HELD_PURGED_BY_OWNER("Deleted for good by its owner. {0}"),

    /** A held vault's line when this account left it. {0} as above. */
    HELD_LEFT("You left. {0}"),

    /** A held vault's line when this account's access was removed. {0} as above. */
    HELD_ACCESS_REMOVED("Your access was removed. {0}"),

    /** The sentence a held vault's line ends with: {0} the day this device stops keeping its copy ("November 19"). */
    HELD_KEPT_UNTIL("Kept on this device until {0}."),

    /**
     * A held vault's whole line while this account was added to it again and this device holds an invitation it can
     * answer now, so its copy does not open (decided on 22 November 2026: closed for that stretch): it stands in the
     * place of the reason and of [HELD_KEPT_UNTIL] together. {0} the vault, {1} the day this device stops keeping its
     * copy, as [HELD_KEPT_UNTIL] gets it.
     */
    HELD_ADDED_AGAIN("You were added to “{0}” again. Until you accept, this device can't open the copy it kept. Accept before {1} to get it back. On that day it goes from this device."),

    /** {0} the vault. A notice: its owner deleted it, and its items left this device. */
    NOTICE_VAULT_DELETED("“{0}” was deleted by its owner. Its items were moved off this device."),

    /**
     * Follows [NOTICE_VAULT_DELETED] when edits made here had not reached the server: {0} how many. It names no period:
     * how long the server keeps a deleted vault restorable is the operator's setting (none to ten years), and this device
     * keeps its copy, with the edits, until the date the holding area shows.
     */
    NOTICE_EDITS_KEPT_MANY("⟦Follows the deletion notice: {0} edits made on this device had not reached the server; they are kept with this device's copy and sent if the vault is restored while this device still keeps it⟧", awaitingOwner = true),

    /** {0} the vault. A notice: its owner deleted it for good. */
    NOTICE_VAULT_PURGED("“{0}” was deleted for good by its owner. A copy stays on this device for 30 days under Recently removed."),

    /** {0} the vault. A notice: this account's access to it was removed. */
    NOTICE_ACCESS_REMOVED("Your access to “{0}” was removed."),

    /** {0} the vault. A notice: this account left it. */
    NOTICE_LEFT("You left “{0}”."),

    /** {0} the vault. A notice: its deletion was undone. */
    NOTICE_RESTORED("“{0}” was restored."),

    /**
     * {0} the item, {1} the vault. A notice: a change this device sent brought back an item that had been deleted
     * elsewhere (by another device or another member); it is back with the change, and no copy was made.
     */
    NOTICE_ITEM_BROUGHT_BACK_ONE("⟦A vault notice: your change to {0} in {1} brought it back, because it had been deleted elsewhere; it is back with your change, and no copy was made⟧", awaitingOwner = true),

    /** As [NOTICE_ITEM_BROUGHT_BACK_ONE], {0} changes in the vault {1} (or one whose item's name is not known). */
    NOTICE_ITEM_BROUGHT_BACK_MANY("⟦A vault notice: {0} of your changes in {1} brought back items that had been deleted elsewhere; they are back with your changes, and no copies were made⟧", awaitingOwner = true),

    /** {0} the vault. A warning: the server stopped serving it with no verified reason (spec 02 §10.6). */
    NOTICE_WITHHELD("The server stopped showing you “{0}”, and nothing in the vault's history says why. andvari keeps this device's copy, read-only. If nobody you share it with did this, ask the operator: the server may be misbehaving."),

    /** {0} the vault. A recovered edit (one only) could not be applied after the vault came back. */
    NOTICE_REPLAY_DENIED_ONE("A recovered edit to “{0}” couldn't be applied — your access may have changed while the vault was deleted."),

    /** {0} how many, {1} the vault: recovered edits that could not be applied after the vault came back. */
    NOTICE_REPLAY_DENIED_MANY("{0} recovered edits to “{1}” couldn't be applied — your access may have changed while the vault was deleted."),

    /** {0} the vault: as [NOTICE_REPLAY_DENIED_ONE], for a vault that was not deleted (taken away with no verified reason, or open again after a removal or a departure). */
    NOTICE_REPLAY_DENIED_BACK_ONE("⟦A notice: an edit to {0} that waited on this device while the vault was not open to you here was sent when it came back, and the server refused it; your access may have changed meanwhile⟧", awaitingOwner = true),

    /** {0} the count, {1} the vault: as [NOTICE_REPLAY_DENIED_BACK_ONE], for several edits. */
    NOTICE_REPLAY_DENIED_BACK_MANY("⟦A notice: {0} edits to {1} that waited on this device while the vault was not open to you here were sent when it came back, and the server refused them; your access may have changed meanwhile⟧", awaitingOwner = true),

    /** {0} the vault. One offline change refused because an attachment it named is gone. */
    NOTICE_WRITE_REJECTED_ATTACHMENT_ONE("An offline change to “{0}” couldn't be applied — an attachment it referenced no longer exists there."),

    /** {0} how many, {1} the vault: offline changes refused because attachments they named are gone. */
    NOTICE_WRITE_REJECTED_ATTACHMENT_MANY("{0} offline changes to “{1}” couldn't be applied — attachments they referenced no longer exist there."),

    /** {0} the vault. One offline change refused as too large. */
    NOTICE_WRITE_REJECTED_TOO_LARGE_ONE("An offline change to “{0}” couldn't be applied — it was too large for the server to accept."),

    /** {0} how many, {1} the vault: offline changes refused as too large. */
    NOTICE_WRITE_REJECTED_TOO_LARGE_MANY("{0} offline changes to “{1}” couldn't be applied — they were too large for the server to accept."),

    /**
     * {0} the item, {1} the vault. A warning notice: the server refused for good a change of this device to one item (the
     * account may no longer be allowed to change that vault), and the change was undone on this device. Shown at the
     * moment it happens: beside a save of another item that the server stored, and at a sync.
     */
    NOTICE_WRITE_DENIED_ONE("⟦A vault notice: the server refused your change to {0} in {1}, so it was undone on this device; your access to that vault may have changed⟧", awaitingOwner = true),

    /** As [NOTICE_WRITE_DENIED_ONE], {0} how many items' changes in the vault {1} were refused and undone. */
    NOTICE_WRITE_DENIED_MANY("⟦A vault notice: the server refused your changes to {0} items in {1}, so they were undone on this device; your access to that vault may have changed⟧", awaitingOwner = true),

    /** {0} the vault. One offline change the server refused for another reason. */
    NOTICE_WRITE_REJECTED_ONE("An offline change to “{0}” couldn't be applied — the server refused it."),

    /** {0} how many, {1} the vault: offline changes the server refused for another reason. */
    NOTICE_WRITE_REJECTED_MANY("{0} offline changes to “{1}” couldn't be applied — the server refused them."),

    /** {0} the vault. A warning for a notice of a kind this app does not know. */
    NOTICE_SOMETHING_CHANGED("Something changed in “{0}”."),

    /** {0} the vault the item went to. */
    ITEM_MOVED_TO("Moved to “{0}”."),

    /** {0} the vault the copy went to. */
    ITEM_COPIED_TO("Copied to “{0}”."),

    /** {0} the item, {1} the vault: an earlier try's copy is there, unchanged since. */
    ITEM_ALREADY_COPIED("An earlier try already copied “{0}” to “{1}”, so nothing more was done. Delete the copy you don't need, or Cancel to start over."),

    /** {0} the item, {1} the vault: an earlier try's copy is there, and it changed since. */
    ITEM_ALREADY_COPIED_CHANGED("An earlier try already copied “{0}” to “{1}”, and it has changed since, so nothing more was done. Cancel to start over, or delete the copy you don't need."),

    /** {0} the item, {1} the vault it was copied into, {2} the vault it stayed in: a move whose original could not be deleted. */
    ITEM_IN_BOTH_VAULTS("“{0}” is now in both “{1}” and “{2}”: the copy was made, but the original couldn't be deleted."),

    /** {0} the item, {1} why its save with files failed (a sentence). */
    KEPT_SAVE_WITHOUT_FILES("“{0}” could not be saved with its files: {1}"),

    /** {0} the item: a save with files that was cut short is tried again at the next unlock. */
    KEPT_SAVE_LATER("“{0}” has not been saved with its files yet. andvari tries again the next time you unlock."),

    /** {0} the item: changed after its save with files was cut short; only the files it added were kept. */
    KEPT_SAVE_FILES_ONLY("“{0}” was changed after a save with files was cut short: the files it added were added to it as it is now, and nothing else of that save was kept."),

    /** {0} the item: as [KEPT_SAVE_FILES_ONLY], and the files that save took off are still in the item. */
    KEPT_SAVE_FILES_ONLY_REMOVALS_KEPT("“{0}” was changed after a save with files was cut short: the files it added were added to it as it is now, and nothing else of that save was kept: the files it took off are still in the item."),

    /** {0} the item: a save with files that was cut short could not be finished because the server ended the session; it is tried again after the next sign-in. */
    KEPT_SAVE_LATER_SIGN_IN("⟦A save with files that was cut short, for {0}: not saved yet because the server ended this session; still kept on this device, and andvari tries again after you sign in⟧", awaitingOwner = true),

    /** {0} the new item, {1} why (a sentence), {2} the files ([COUNT_FILES_ONE] or many): a kept save of a new item let go for good. */
    KEPT_SAVE_GIVEN_UP_NEW("⟦A save with files that was cut short, for the new item {0}, could not be finished and andvari stopped trying: {1} The new item and the {2} added to it are no longer kept on this device; add them again if you still need them⟧", awaitingOwner = true),

    /** {0} the item, {1} why (a sentence), {2} the files ([COUNT_FILES_ONE] or many): a kept save of an edit let go for good. */
    KEPT_SAVE_GIVEN_UP_EDIT("⟦A save with files that was cut short, for changes to {0}, could not be finished and andvari stopped trying: {1} Those changes and the {2} added with them are no longer kept on this device; make them again if you still need them⟧", awaitingOwner = true),

    /** Why a kept save is let go: a file set aside for it is no longer on this device (a sentence that fills {1} above). */
    KEPT_FILE_NOT_ON_DEVICE("⟦A file set aside for this save is no longer on this device.⟧", awaitingOwner = true),

    // ---- the vault's content, continued: what a lock cut short, copies out and in, and saved exports ----

    /** {0} the item whose save a lock overtook before this device kept it. */
    UNSAVED_AT_LOCK_ONE("Your change to “{0}” wasn't saved: the vault locked first. Make it again."),

    /** {0} and {1} the two items whose saves a lock overtook. */
    UNSAVED_AT_LOCK_TWO("Your changes to “{0}” and “{1}” weren't saved: the vault locked first. Make them again."),

    /** {0}, {1} and {2} the three items whose saves a lock overtook. */
    UNSAVED_AT_LOCK_THREE("Your changes to “{0}”, “{1}” and “{2}” weren't saved: the vault locked first. Make them again."),

    /** {0}, {1} and {2} three of the items whose saves a lock overtook, {3} how many more. */
    UNSAVED_AT_LOCK_MORE("Your changes to “{0}”, “{1}”, “{2}” and {3} more weren't saved: the vault locked first. Make them again."),

    /**
     * An import a lock stopped: one item saved, one not. One can be all it saved: a batch the server refuses as too large
     * is split, so single items land on their own.
     */
    LOCK_CUT_IMPORT_KEPT_ONE_LOST_ONE("The import stopped when the vault locked: 1 item was saved and 1 was not. Import the file again for the rest."),

    /** An import a lock stopped: one item saved, {0} not. */
    LOCK_CUT_IMPORT_KEPT_ONE_LOST_MANY("The import stopped when the vault locked: 1 item was saved and {0} were not. Import the file again for the rest."),

    /** An import a lock stopped: {0} items saved (none included), one not. */
    LOCK_CUT_IMPORT_KEPT_MANY_LOST_ONE("The import stopped when the vault locked: {0} items were saved and 1 was not. Import the file again for the rest."),

    /** An import a lock stopped: {0} items saved (none included), {1} not. */
    LOCK_CUT_IMPORT_KEPT_MANY_LOST_MANY("The import stopped when the vault locked: {0} items were saved and {1} were not. Import the file again for the rest."),

    /** [LOCK_CUT_COPY] when one item was copied: {0} the vault copied from, {1} the vault copied into, {2} how many it holds. */
    LOCK_CUT_COPY_ONE("⟦The vault locked while andvari was copying the items of “{0}” into “{1}”. At least 1 of {2} was copied, and maybe a few more. Copy them again for the rest: that makes no duplicates.⟧", awaitingOwner = true),

    /**
     * A copy of a vault's items into the personal vault that a lock cut short: {0} the vault copied from, {1} the personal
     * vault, {2} items copied at least, {3} items in all. Copying again copies every item again, also those already
     * copied: the line must say so, and never that a second copy makes no duplicates.
     */
    LOCK_CUT_COPY_TO_PERSONAL("⟦The vault locked while andvari was copying the items of “{0}” into “{1}”. At least {2} of {3} were copied, and maybe a few more. Copying again copies every item again, the ones already copied too.⟧", awaitingOwner = true),

    /** [LOCK_CUT_COPY_TO_PERSONAL] when one item was copied: {0} the vault copied from, {1} the personal vault, {2} how many it holds. */
    LOCK_CUT_COPY_TO_PERSONAL_ONE("⟦The vault locked while andvari was copying the items of “{0}” into “{1}”. At least 1 of {2} was copied, and maybe a few more. Copying again copies every item again, the one already copied too.⟧", awaitingOwner = true),

    /** [NOTICE_EDITS_KEPT_MANY] for one edit. */
    NOTICE_EDITS_KEPT_ONE("⟦Follows the deletion notice: 1 edit made on this device had not reached the server; it is kept with this device's copy and sent if the vault is restored while this device still keeps it⟧", awaitingOwner = true),

    /** [SPACE_SHORT_ITEMS] when the work would go one item over: {0} the limit of items. */
    SPACE_SHORT_ITEMS_ONE_OVER("⟦This didn't start: it would go 1 item over your account's limit of {0} items on this server. Delete items you no longer need, or ask the operator to raise the limit.⟧", awaitingOwner = true),

    /** [SPACE_SHORT_VAULTS] when the server allows one shared vault and the account owns it. */
    SPACE_SHORT_VAULTS_ONE("⟦This didn't start: your account already owns 1 shared vault, the most this server allows, so a new one can't be made. Delete it if you no longer need it, or ask the operator to raise the limit.⟧", awaitingOwner = true),

    /** Under an item's history when it has no earlier versions (not the empty vault's line). */
    ITEM_HISTORY_EMPTY("⟦This item has no earlier versions.⟧", awaitingOwner = true),

    /** A save (or a deletion) the server refused for now because it ended the session: kept on this device, sent at the next sign-in. */
    SAVE_KEPT_SESSION_ENDED("⟦Kept on this device: the server ended this session, so the change is sent when you sign in again.⟧", awaitingOwner = true),

    /** A save (or a deletion) the server refused for now with too many requests: kept on this device, sent later by itself. */
    SAVE_KEPT_TOO_MANY("⟦Kept on this device: the server asked andvari to wait, so the change is sent later by itself.⟧", awaitingOwner = true),

    /** A save (or a deletion) the server refused for now with a fault of its own: kept on this device, sent when it answers again. */
    SAVE_KEPT_SERVER_FAULT("⟦Kept on this device: the server had a problem, so the change is sent when it answers again.⟧", awaitingOwner = true),

    /** An import cut short on a copy kept only in memory: one item saved, one not, and that one is not sent later. */
    IMPORT_STOPPED_SAVED_ONE_NOT_ONE("⟦The import stopped before it finished: 1 item was saved and 1 was not. The one not saved is not sent later.⟧", awaitingOwner = true),

    /** As [IMPORT_STOPPED_SAVED_ONE_NOT_ONE]: one item saved, {0} not. */
    IMPORT_STOPPED_SAVED_ONE_NOT_MANY("⟦The import stopped before it finished: 1 item was saved and {0} were not. The ones not saved are not sent later.⟧", awaitingOwner = true),

    /** As [IMPORT_STOPPED_SAVED_ONE_NOT_ONE]: {0} items saved (at least two), one not. */
    IMPORT_STOPPED_SAVED_MANY_NOT_ONE("⟦The import stopped before it finished: {0} items were saved and 1 was not. The one not saved is not sent later.⟧", awaitingOwner = true),

    /** As [IMPORT_STOPPED_SAVED_ONE_NOT_ONE]: {0} items saved (at least two), {1} not. */
    IMPORT_STOPPED_SAVED_MANY_NOT_MANY("⟦The import stopped before it finished: {0} items were saved and {1} were not. The ones not saved are not sent later.⟧", awaitingOwner = true),

    /** Follows an IMPORT_STOPPED_ line when the import can be tried again: Retry imports what was not saved, without duplicates. */
    IMPORT_RETRY_THE_REST("⟦Retry imports the ones not saved, without making duplicates.⟧", awaitingOwner = true),

    /** An import cut short on a copy kept at rest (no answer, too many requests, a server fault): one item kept here, sent later. */
    IMPORT_KEPT_ONE("⟦1 imported item is kept on this device and sent when the server answers again.⟧", awaitingOwner = true),

    /** As [IMPORT_KEPT_ONE]: {0} items kept here, sent later. */
    IMPORT_KEPT_MANY("⟦{0} imported items are kept on this device and sent when the server answers again.⟧", awaitingOwner = true),

    /**
     * An import that is done whose items the list shows only after the next sync (the server took them all, and its last
     * answer did not come): {0} how many were added, {1} the vault. The line must say that they show after the next sync,
     * that importing the file again before then adds them twice, and (as the done line does) to delete the CSV file.
     */
    IMPORT_DONE_LISTED_LATER("⟦Added {0} items to “{1}”. They show in the list after the next sync: don't import the file again before then, or they're added twice. Then delete the CSV file: it holds your passwords in plain text.⟧", awaitingOwner = true),

    /** [IMPORT_DONE_LISTED_LATER] for one item: {0} the vault. */
    IMPORT_DONE_LISTED_LATER_ONE("⟦Added 1 item to “{0}”. It shows in the list after the next sync: don't import the file again before then, or it's added twice. Then delete the CSV file: it holds your passwords in plain text.⟧", awaitingOwner = true),

    /** An import cut short on a copy kept at rest because the server ended the session: one item kept here, sent at the next sign-in. */
    IMPORT_KEPT_UNTIL_SIGN_IN_ONE("⟦1 imported item is kept on this device. The server ended this session, so it is sent when you sign in again.⟧", awaitingOwner = true),

    /** As [IMPORT_KEPT_UNTIL_SIGN_IN_ONE]: {0} items kept here, sent at the next sign-in. */
    IMPORT_KEPT_UNTIL_SIGN_IN_MANY("⟦{0} imported items are kept on this device. The server ended this session, so they are sent when you sign in again.⟧", awaitingOwner = true),

    /** One item copied out of a shared vault into the personal vault. */
    COPIED_TO_PERSONAL_ONE("Copied 1 item to your personal vault. Deleting the shared vault won't remove those copies."),

    /** {0} items copied out of a shared vault into the personal vault. */
    COPIED_TO_PERSONAL_MANY("Copied {0} items to your personal vault. Deleting the shared vault won't remove those copies."),

    /** One item of a held vault copied into the personal vault; [FILES_NOT_HANDED_OVER_ONE] or its many may follow. */
    COPIED_OUT_OF_HELD_ONE("Copied 1 item to your personal vault."),

    /** {0} items of a held vault copied into the personal vault. */
    COPIED_OUT_OF_HELD_MANY("Copied {0} items to your personal vault."),

    /** {0} the vault: one held item brought into it, with files left out (said by what follows). */
    BROUGHT_INTO_ONE("Copied 1 item to “{0}”."),

    /** {0} how many, {1} the vault: held items brought into it, with files left out. */
    BROUGHT_INTO_MANY("Copied {0} items to “{1}”."),

    /** Follows a copy out or in: one attached file the server no longer hands over was left out. */
    FILES_NOT_HANDED_OVER_ONE("1 attached file wasn't copied: the server no longer sends it to this device."),

    /** Follows a copy out or in: {0} attached files the server no longer hands over were left out. */
    FILES_NOT_HANDED_OVER_MANY("{0} attached files weren't copied: the server no longer sends them to this device."),

    /** {0} the file, {1} the folder, {2} what it holds ([EXPORT_CSV_HOLDS_ONE], [EXPORT_BACKUP_HOLDS], …): an export saved. */
    EXPORT_SAVED_TO("Saved “{0}” to {1}: {2}"),

    /** {0} the file, {1} what it holds: an export saved where the picker names no folder (Android's document picker). */
    EXPORT_SAVED("Saved “{0}”: {1}"),

    /** What a saved CSV export holds: one login, and the warning. */
    EXPORT_CSV_HOLDS_ONE("1 login. It holds every password in plain text: delete it once the other manager has imported it."),

    /** What a saved CSV export holds: {0} logins, and the warning. */
    EXPORT_CSV_HOLDS_MANY("{0} logins. It holds every password in plain text: delete it once the other manager has imported it."),

    /** What a saved backup holds: {0} the items ([COUNT_ITEMS_ONE] or many), {1} the vaults ([COUNT_VAULTS_ONE] or many). */
    EXPORT_BACKUP_HOLDS("{0} from {1}."),

    /** As [EXPORT_BACKUP_HOLDS], with {2} the files ([COUNT_FILES_ONE] or many). */
    EXPORT_BACKUP_HOLDS_FILES("{0} from {1}, with {2}."),

    /** One item, in a count. */
    COUNT_ITEMS_ONE("1 item"),

    // ---- §3.7: a change to a shared vault that waits to be sent ([WaitingChange], [WaitingResult], [WaitingNotice]) ----

    /** [WaitingChange.line] for a vault's deletion that waits. No values. */
    WAITING_DELETE("⟦On a shared vault's row and panel: your deletion of this vault is signed and waits; nothing is sent until you choose to delete it now or keep the vault⟧", awaitingOwner = true),

    /** [WaitingChange.line]: the server said it took the change, and this device has not read it back yet. No values. */
    WAITING_SERVER_SAYS_STORED("⟦On a shared vault's row and panel, beside the member it names: the server says it has this change; the vault's history as andvari read it does not show it yet; andvari keeps sending it as it is while it waits, and signs no other change to this vault's history from this device meanwhile⟧", awaitingOwner = true),

    /** [WaitingChange.line]: known not made yet (the server asked this device to slow down). No values. */
    WAITING_NOT_MADE_YET("⟦On a shared vault's row and panel, beside the member it names: this change is not made yet (the server asked andvari to wait); andvari sends it again; you can withdraw it⟧", awaitingOwner = true),

    /** [WaitingChange.line]: its outcome cannot be told yet. No values. */
    WAITING_MAY_BE_MADE("⟦On a shared vault's row and panel, beside the member it names: andvari sent this change and got no answer that settles it, so it may already be made; it keeps sending the same change; you can withdraw it⟧", awaitingOwner = true),

    /** [WaitingChange.sendingLine]. No values. */
    WAITING_SENDING("⟦Beside a waiting change: it is being sent now⟧", awaitingOwner = true),

    /** [WaitingChange.withdrawLabel]: the button for a member's change. */
    WAITING_WITHDRAW("⟦Button: withdraw this change⟧", awaitingOwner = true),

    /** [WaitingChange.withdrawLabel] for a deletion, and the question's second button: the deletion is withdrawn. */
    WAITING_KEEP_VAULT("⟦Button: keep the vault (the deletion is withdrawn)⟧", awaitingOwner = true),

    /** The question's first button ([WaitingChanges.deleteWaitingNow]). */
    WAITING_DELETE_NOW("⟦Button: delete the vault now⟧", awaitingOwner = true),

    /**
     * The question for a deletion that waits ([WaitingChange.asksForWord]), asked only after a look in the vault's log
     * that sent nothing. {0} the vault's name, or [WAITING_UNNAMED_VAULT].
     */
    WAITING_DELETE_ASK("⟦A notice: your deletion of {0} was signed and is still waiting; deleting it now deletes it for every member, with everything saved in it since; or keep the vault⟧", awaitingOwner = true),

    /** [WaitingResult.WITHDRAWN_NOT_MADE]. No values. */
    WAITING_WITHDRAWN_NOT_MADE("⟦After “withdraw”: the change was not made and will not be⟧", awaitingOwner = true),

    /** [WaitingResult.WITHDRAWN_MAY_BE_MADE]. No values. */
    WAITING_WITHDRAWN_MAY_BE_MADE("⟦After “withdraw”: this device will not send the change again; it may already be made; andvari reads the vault's history and tells you what it finds⟧", awaitingOwner = true),

    /** [WaitingResult.KEPT_NOT_DELETED]. No values. */
    WAITING_KEPT_NOT_DELETED("⟦After “keep the vault”: the vault was not deleted and will not be by that deletion⟧", awaitingOwner = true),

    /** [WaitingResult.KEPT_MAY_BE_DELETED]. No values. */
    WAITING_KEPT_MAY_BE_DELETED("⟦After “keep the vault”: this device will not send the deletion again; the server may already have it; andvari reads the vault's history and tells you what it finds⟧", awaitingOwner = true),

    /** [WaitingResult.DELETED]. No values. */
    WAITING_DELETED("⟦After “delete it now”: the vault is deleted; its owner can restore it for a limited time⟧", awaitingOwner = true),

    /** [WaitingResult.DELETE_STILL_WAITING]. No values. */
    WAITING_DELETE_STILL_WAITING("⟦After “delete it now”: the deletion was sent and no answer settled it; it still waits, and you will be asked again⟧", awaitingOwner = true),

    /** [WaitingResult.DELETE_DID_NOT_HAPPEN]. No values. */
    WAITING_DELETE_DID_NOT_HAPPEN("⟦After “delete it now”: the deletion did not happen, because another change to the vault came first; delete the vault again if you still want to⟧", awaitingOwner = true),

    /** [WaitingResult.DELETE_REFUSED]. No values. */
    WAITING_DELETE_REFUSED("⟦After “delete it now”: the server refused the deletion; the vault was not deleted⟧", awaitingOwner = true),

    /** [WaitingResult.DELETE_GIVEN_UP]. No values. */
    WAITING_DELETE_GIVEN_UP("⟦After “delete it now”: the deletion waited more than a day, so it was given up and nothing was sent; delete the vault again if you still want to⟧", awaitingOwner = true),

    /** [WaitingResult.STILL_SENDING]. No values. */
    WAITING_STILL_SENDING("⟦The change is still being sent; try again once it has an answer⟧", awaitingOwner = true),

    /** [WaitingResult.SERVER_SAYS_STORED]. No values. */
    WAITING_SERVER_HAS_IT("⟦The server says it already has this change, so it cannot be withdrawn; if it shows up in the vault's history, undo it there the ordinary way⟧", awaitingOwner = true),

    /** [WaitingResult.NOTHING_WAITING]. No values. */
    WAITING_NOTHING_WAITS("⟦Nothing waits for this vault any more; what became of the change is said in its own notice⟧", awaitingOwner = true),

    /** [WaitingResult.NOT_OFFERED]. No values. */
    WAITING_NOT_OFFERED("⟦This change is not one that can be withdrawn or sent from here; nothing was done⟧", awaitingOwner = true),

    /** [WaitingResult.RECORD_UNREADABLE]. No values. */
    WAITING_RECORD_UNREADABLE("⟦andvari cannot read this device's record of the change right now; nothing was done⟧", awaitingOwner = true),

    /**
     * [WaitingResult.FROZEN]: a vault frozen at the read that shows its server contradicting itself takes no act. Says
     * nothing of whether a change sent before the freeze was made. No values.
     */
    WAITING_VAULT_FROZEN("⟦The server's record of this vault contradicts itself, so andvari has stopped changing it on this device, for good; nothing was sent now⟧", awaitingOwner = true),

    /** The words for {0} of a notice where this device cannot name the vault; never quoted, never another flow's words. */
    WAITING_UNNAMED_VAULT("⟦a shared vault whose name this device cannot read⟧", awaitingOwner = true),

    /** [WaitingNotice.line]: the person's own deletion, which waited for their word, is in the vault's log. {0} the vault. */
    WAITING_FOUND_DELETED("⟦A notice: {0} was deleted after all, by your deletion that waited; its owner can restore it for a limited time⟧", awaitingOwner = true),

    /** [WaitingNotice.line]: a deletion you withdrew (kept the vault) is in the log after all. {0} the vault. */
    WAITING_FOUND_DELETED_AFTER_ALL("⟦A notice: the deletion of {0} that you withdrew was made after all; its owner can restore it for a limited time⟧", awaitingOwner = true),

    /** [WaitingNotice.line]: the deletion of a vault a stopped move made, dropped by the move, is in the log after all. {0} the vault. */
    WAITING_FOUND_HALF_MADE_DELETED("⟦A notice: {0}, a vault an earlier try of a move made, was deleted after all; its owner can restore it for a limited time⟧", awaitingOwner = true),

    /** [WaitingNotice.line]: a change withdrawn or given up is in the log after all; [WaitingNotice.undo] names the way back. {0} the vault. */
    WAITING_FOUND_MADE_AFTER_ALL("⟦A notice: a change to {0} that andvari stopped sending was made after all; undo it if you do not want it⟧", awaitingOwner = true),

    /** [WaitingNotice.line]: a withdrawn change that never will be made (another entry took its place). {0} the vault. */
    WAITING_FOUND_NOT_MADE("⟦A notice: the change to {0} that you withdrew was not made, and never will be⟧", awaitingOwner = true),

    /** [WaitingNotice.line]: a withdrawn change the vault's log does not hold as read now; it may still be made later. {0} the vault. */
    WAITING_FOUND_NOT_MADE_YET("⟦A notice: the change to {0} that you withdrew is not in the vault's history as andvari read it; if it shows up later, andvari tells you⟧", awaitingOwner = true),

    /** [WaitingNotice.line]: given up after a day, known not made. {0} the vault. */
    WAITING_GIVEN_UP_NOT_MADE("⟦A notice: a change to {0} waited more than a day and was given up; it was not made⟧", awaitingOwner = true),

    /** [WaitingNotice.line]: given up after a day; not made at the last read, may still land. {0} the vault. */
    WAITING_GIVEN_UP_ABSENT("⟦A notice: a change to {0} waited more than a day and was given up; it was not in the vault's history when andvari last read it; if it shows up later, andvari tells you⟧", awaitingOwner = true),

    /** [WaitingNotice.line]: given up after a day, and nothing can be told of it. Never "nothing changed". {0} the vault. */
    WAITING_GIVEN_UP_CANNOT_TELL("⟦A notice: a change to {0} waited more than a day and was given up; andvari cannot tell whether it was made; if it shows up later, andvari tells you⟧", awaitingOwner = true),

    /** [WaitingNotice.line]: a change sent again will never be made: another entry took its place. {0} the vault. */
    WAITING_FOUND_PLACE_TAKEN("⟦A notice: a change to {0} did not happen, because another change to the vault came first; make it again if you still want it⟧", awaitingOwner = true),

    /** [WaitingNotice.line]: a change sent again was refused for good. {0} the vault. */
    WAITING_FOUND_REFUSED("⟦A notice: the server refused a change to {0}; it was not made⟧", awaitingOwner = true),

    /**
     * [WaitingChange.line] for the person's deletion of a vault that the server's answer called stored, while the vault's
     * log as read here does not hold it: nothing is offered for it. No values.
     */
    WAITING_DELETE_SERVER_SAYS_STORED("⟦On a shared vault's row and panel: the server says it has your deletion of this vault; the vault's history as andvari read it does not show it yet; andvari signs no other change to this vault's history (its members, its owner, its deletion) from this device meanwhile⟧", awaitingOwner = true),

    /** [WaitingResult.DELETE_REFUSED_CANNOT_TELL]. No values. */
    WAITING_DELETE_REFUSED_CANNOT_TELL("⟦After “delete it now”: the server refused the deletion this time; an earlier send of it got no answer, so andvari cannot tell whether the vault was deleted; andvari does not send the deletion again; if it shows up in the vault's history later, andvari tells you⟧", awaitingOwner = true),

    /** [WaitingResult.MOVE_IN_PROGRESS]. No values. */
    WAITING_MOVE_IN_PROGRESS("⟦A move of this vault is running, or the move's own deletion of it waits; nothing was sent; try again once the move has stopped or finished⟧", awaitingOwner = true),

    /** [VaultActionResult.OTHER_CHANGE_WAITS]: nothing was signed or sent, because another change of the vault waits. No values. */
    WAITING_OTHER_CHANGE_FIRST("⟦Another change you made to this vault on this device is still waiting to be sent, so this one was not made: nothing was signed or sent for it; once the waiting change is settled or withdrawn, make this one again⟧", awaitingOwner = true),

    /**
     * [WaitingNotice.line]: an addition was not sent again because its contact is gone, has another key or is no longer
     * compared, and an earlier send of it may have reached the server. {0} the vault.
     */
    WAITING_FOUND_CONTACT_CHANGED("⟦A notice: a member's addition to {0} was not sent again, because the contact it names is gone from this device, has another key now, or is no longer compared; an earlier send of it may have reached the server, so it may still be made; if it shows up, andvari tells you and you can remove them⟧", awaitingOwner = true),

    /** [WaitingNotice.line]: as [WAITING_FOUND_CONTACT_CHANGED], where it was known not stored. {0} the vault. */
    WAITING_FOUND_CONTACT_CHANGED_NOT_MADE("⟦A notice: a member's addition to {0} was not sent again, because the contact it names is gone from this device, has another key now, or is no longer compared; it was not made⟧", awaitingOwner = true),

    /** [WaitingNotice.line]: a re-send refused by the server where an earlier send of it may have stored it. {0} the vault. */
    WAITING_FOUND_REFUSED_CANNOT_TELL("⟦A notice: the server refused a change to {0} when andvari sent it again; an earlier send of it got no answer, so andvari cannot tell whether it was made; andvari stopped sending it; if it shows up later, andvari tells you⟧", awaitingOwner = true),

    /** [WaitingNotice.line]: a deletion that was given up (never withdrawn by the person) is in the log after all. {0} the vault. */
    WAITING_FOUND_GIVEN_UP_DELETED_AFTER_ALL("⟦A notice: your deletion of {0}, which andvari gave up sending, was made after all; its owner can restore it for a limited time⟧", awaitingOwner = true),

    /** [WaitingNotice.line]: a deletion this device held was made, and the vault reads restored here since. {0} the vault. */
    WAITING_FOUND_DELETED_RESTORED_SINCE("⟦A notice: a deletion of {0} that andvari held was made, and the vault has been restored since; it reads as a live vault on this device now⟧", awaitingOwner = true),

    /** [WaitingNotice.line]: a deletion this device held was made, and the vault's state here offers no restore. {0} the vault. */
    WAITING_FOUND_DELETED_NO_RESTORE("⟦A notice: a deletion of {0} that andvari held was made; this device cannot offer to restore the vault now⟧", awaitingOwner = true),

    /**
     * [SharedVaultRow.frozenMoveClose]: what closing a move stopped on a frozen old vault does, said before the tap. {0} the
     * new vault's name, {1} the old vault's, {2} how many items were copied.
     */
    MOVE_FROZEN_CLOSE("⟦Close this move: the {2} items copied are in “{0}”; “{1}” still exists at its server with what it held and stays frozen and read-only on this device; nothing more will be sent, moved or deleted by this move⟧", awaitingOwner = true),

    /** {0} items, in a count. */
    COUNT_ITEMS_MANY("{0} items"),

    /** One vault, in a count. */
    COUNT_VAULTS_ONE("1 vault"),

    /** {0} vaults, in a count. */
    COUNT_VAULTS_MANY("{0} vaults"),

    /** One file, in a count. */
    COUNT_FILES_ONE("1 file"),

    /** {0} files, in a count. */
    COUNT_FILES_MANY("{0} files"),

    /** The plain words that stand for a move's target vault whose name this device cannot read; never quoted. */
    NAME_THE_OTHER_VAULT("the other vault"),

    /** The plain words that stand for the vault an item is in, when its name cannot be read; never quoted. */
    NAME_ITS_VAULT("its vault"),

    /** The plain words that stand for an item with no name in a move's lines; never quoted. */
    NAME_THIS_ITEM("This item"),
    ;

    /** The design gives this key no sentence yet: [english] is empty until the owner approves one. */
    val reserved: Boolean get() = english.isEmpty()

    /**
     * This sentence with [values] in place of `{0}`, `{1}`, …: plain text, to be rendered as plain text. One pass over
     * the template, so a value that itself reads "{0}" (a name someone chose) is copied, never filled in again.
     */
    internal fun fill(values: List<String>): String {
        val out = StringBuilder(english.length + 32)
        var i = 0
        while (i < english.length) {
            val c = english[i]
            val close = if (c == '{') english.indexOf('}', i) else -1
            val index = if (close > i + 1) english.substring(i + 1, close).toIntOrNull() else null
            if (index != null && index in values.indices) {
                out.append(values[index])
                i = close + 1
            } else {
                out.append(c)
                i++
            }
        }
        return out.toString()
    }
}

/**
 * One sentence of the design's copy as a screen shows it: which sentence, and the values it names, in the order of
 * its placeholders. Only core makes one, from values whose source the state's own fields state.
 */
class CopyLine internal constructor(
    val key: CopyKey,
    /** The values of `{0}`, `{1}`, … in [CopyKey.english]. Each is plain text. */
    val values: List<String>,
) {
    /** The design's sentence with the values filled in. Render it as plain text, never as markup. */
    val english: String get() = key.fill(values)

    internal companion object {
        fun of(key: CopyKey, vararg values: String): CopyLine = CopyLine(key, values.toList())
    }
}
