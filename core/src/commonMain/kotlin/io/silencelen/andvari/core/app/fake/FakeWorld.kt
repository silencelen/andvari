package io.silencelen.andvari.core.app.fake

import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.HowDeviceJoined
import io.silencelen.andvari.core.app.JoinMode
import io.silencelen.andvari.core.app.OperatorHelpStage
import io.silencelen.andvari.core.app.RoleInVault
import io.silencelen.andvari.core.app.ServerKind
import io.silencelen.andvari.core.app.VaultLogState
import io.silencelen.andvari.core.app.WhoCanRecover
import io.silencelen.andvari.core.trust.MemberRole

/*
 * The world the fake app lives in: servers, the accounts on them, and the links, device links and kits that exist.
 * Everything is plain mutable state a test sets up and changes; nothing here talks to a network or does any
 * cryptography. After changing the world by hand while the app is running, call [FakeScript.changed].
 */

/** One server. Its fields are what a real one would decide; set them to put the app in front of any answer. */
class FakeServer internal constructor(
    /** Its origin. It changes only when its operator signs a move. */
    origin: String,
    /** The name its card carries. */
    var name: String,
    var kind: ServerKind,
) {
    var origin: String = origin
        internal set

    /** False: every request to it gets no answer. */
    var reachable: Boolean = true

    /**
     * False: its live updates do not connect (the open vault's [io.silencelen.andvari.core.app.LiveUpdates] shows the
     * quiet line), while every request is still answered. Call `FakeScript.changed()` after setting it on an open vault.
     */
    var liveUpdatesConnect: Boolean = true

    /** Its client policy (spec 03 §1.1), as declared: the fake clamps it as the engine does. */
    var autoLockSeconds: Int = 300
    var clipboardClearSeconds: Int = 30
    var offlineCacheAllowed: Boolean = true
    var attachmentMaxBytes: Long = 25L * 1024 * 1024
    var itemAttachmentsMaxBytes: Long = 100L * 1024 * 1024

    /** True: it answers `426 upgrade_required` to this build. */
    var tooNewForThisBuild: Boolean = false

    /** False: it serves no identity card yet (its setup is unfinished). */
    var hasCard: Boolean = true

    /** It has an operator account. A fresh server has none until its setup link is used. */
    var operatorExists: Boolean = true

    /** True: the card chain it serves does not continue a pin made before (a fork), or card 0 is not the baked one. */
    var identityChanged: Boolean = false

    /**
     * Under this device's pin for it, the newest card moves the server to this address (the engine's
     * `CardStatus.Moved`, and `FirstPin.PinChanged` for a flow that opens it): its card says so wherever it is on
     * show, and a flow that opens it shows [io.silencelen.andvari.core.app.EntryScreen.ServerChanged] first.
     */
    var movedUnderPinTo: String? = null

    /** Under this device's pin for it, the newest card says the other `kind` (the engine's `CardStatus.KindChanged`). */
    var kindChangedUnderPin: Boolean = false

    /** It serves less of its chain than this device pinned (`withheld` under a pin): nothing stops, and no flow opens it. */
    var servesOlderChain: Boolean = false

    /** A card newer than this device's pin does not verify (`CardStatus.Refused`): the pin stays. */
    var newerCardDoesNotVerify: Boolean = false

    /**
     * True: the chain it serves is another server's, so its newest card names [cardNamesOrigin], not this origin
     * (§2.4 `origin_mismatch`). No root makes a first pin from it.
     */
    var servesAnotherServersCard: Boolean = false

    /** The origin the card it serves names, while [servesAnotherServersCard]. */
    var cardNamesOrigin: String = "https://vault.elsewhere.example"

    var mode: JoinMode = JoinMode.ANYONE
    var full: Boolean = false
    var ageConfirmRequired: Boolean = false

    /** Above 0, sign-up computes a proof of work first. */
    var powBits: Int = 0

    /**
     * Its status counts this many more accounts (or, below 0, fewer) than its accounts list holds: the operator's
     * console shows [io.silencelen.andvari.core.app.OperatorConsole.countsDisagree]. Call `FakeScript.changed()` after
     * setting it on an open console.
     */
    var userCountOffBy: Long = 0

    /** The mail outbox is stalled: sign-up and requests for help answer `503 mail_unavailable`. */
    var mailStalled: Boolean = false

    /** The day's new accounts are used up (`429 signup_daily_max`). */
    var dailyLimitReached: Boolean = false

    /** Email domains sign-up refuses (`400 email_domain_blocked`). */
    val blockedDomains: MutableSet<String> = HashSet()

    /** Its card names a recovery key. On a public server the app ignores it (variant R). */
    var recoveryKey: Boolean = false

    /** Somewhere along its card chain the recovery key changed without the old key's signature. */
    var unsignedRecoveryKeyChange: Boolean = false

    /** Members may make register links (the default on a private server). */
    var membersMayInvite: Boolean = kind == ServerKind.PRIVATE_SERVER

    /** The operator key's short form, as the Trust Gate and "Instance details" show it. */
    var operatorKeyShort: String = "0f3a9c417be25d60a1c8e94f7b2d0356"

    /** Accounts by normalised address. */
    val accounts: MutableMap<String, FakeAccount> = LinkedHashMap()

    internal var nextUser: Int = 1

    /** Add an account whose kit is saved and whose devices are none. Returns it for further set-up. */
    fun addAccount(email: String, password: String): FakeAccount {
        val norm = FakeText.emailNorm(email) ?: error("not an email address: $email")
        val account = FakeAccount(this, norm, password, "user-${origin.hashCode().toUInt().toString(16)}-${nextUser++}")
        accounts[norm] = account
        return account
    }

    /** The app offers operator recovery here: the card names a recovery key and the server is not public (§7.7). */
    internal val offersOperatorRecovery: Boolean get() = recoveryKey && kind == ServerKind.PRIVATE_SERVER
}

/** One account on a [FakeServer], with what its sealed account state would hold. */
class FakeAccount internal constructor(
    val server: FakeServer,
    val email: String,
    var password: String,
    val userId: String,
) {
    /** Two-step sign-in: the code the server accepts now; null when it is off. */
    var twoStepCode: String? = null

    /**
     * The name the fake's device keeps for this account's links ([io.silencelen.andvari.core.app.LinksApi.ownName]). A
     * seeded account goes by its address's first part; null is an account made on another device, whose links ask for
     * a name first. A registration on the fake's device keeps the name typed.
     */
    var nameHere: String? = email.substringBefore('@')

    /** "New devices must be linked". */
    var requireLink: Boolean = false
    var whoCanRecover: WhoCanRecover = WhoCanRecover.ONLY_ME

    /** The account confirmed a kit (`recoveryConfirmed`). False: the next sign-in shows one. */
    var kitSaved: Boolean = true

    /**
     * As the engine's mark: a kit of this account was shown on this device and not confirmed at the server since; the next
     * kit made for it says that the earlier one no longer works ([io.silencelen.andvari.core.app.KitScreen.earlierKitVoidLine]).
     */
    internal var kitShownUnconfirmed: Boolean = false

    /** Each new kit has the next serial; a kit with an older one is refused. */
    var kitSerial: Int = 1
    var disabled: Boolean = false

    /** When it was disabled, on the fake clock. */
    var disabledAtMs: Long = 0L

    /** The instance's operator account. */
    var isOperator: Boolean = false

    /** The instance's recovery key changed without a signed rotation since this account chose operator recovery. */
    var recoveryKeyChangedUnsigned: Boolean = false

    /** Device ids the server knows for this account (§8.7). */
    val knownDevices: MutableSet<String> = HashSet()
    val devices: MutableList<FakeDevice> = ArrayList()
    val contacts: MutableList<FakeContact> = ArrayList()
    val vaults: MutableList<FakeVault> = ArrayList()

    /** Live requests for the operator's help in this account's name. */
    val helpRequests: MutableList<FakeHelpRequest> = ArrayList()

    /** Requests the person said were their own ("This was me"): the alert is not raised for them again. */
    val helpRequestsMine: MutableSet<String> = HashSet()

    /** Rows of the account's list of requests that the server sends and a device cannot read: dropped and counted. */
    var unreadableHelpRows: Int = 0

    /** The account's list of requests cannot be read at all (no answer, or a body that is not a list). */
    var helpListUnread: Boolean = false

    /** "This was me" on an alert raised for rows that could not be read: not raised again for them on this device. */
    internal var unreadableHelpDismissed: Boolean = false

    internal var nextId: Int = 1

    /** The account ID: the identity fingerprint's short form, 32 hex. */
    val accountId: String get() = FakeText.hex32("id:$userId")

    /**
     * A contact made on another device of the account, [compared] or not. It is not current on the fake app's device
     * until confirmed there, and no device of the account's list is named as its maker ([FakeContact.madeOnDeviceId]).
     */
    fun addContact(label: String, compared: Boolean): FakeContact {
        val contact = FakeContact("contact-${nextId++}", label, compared, 0L)
        contacts += contact
        return contact
    }

    /** A shared vault this account holds, in good standing, as [role]. */
    fun addVault(name: String, role: RoleInVault): FakeVault {
        val vault = FakeVault("vault-${userId.takeLast(3)}-${nextId++}", name)
        vault.role = role
        vault.members += FakeMember(userId, "", role, contact = null)
        vaults += vault
        return vault
    }

    /** Another device of the account, as "Your devices" lists it. */
    fun addDevice(name: String, platform: AppPlatform, how: HowDeviceJoined): FakeDevice {
        val device = FakeDevice("device-${nextId++}", name, platform, how)
        devices += device
        knownDevices += device.deviceId
        return device
    }
}

class FakeDevice internal constructor(
    val deviceId: String,
    var name: String,
    var platform: AppPlatform,
    var how: HowDeviceJoined,
) {
    var live: Boolean = true
    var addedAtMs: Long = 0L
    var lastSeenAtMs: Long = 0L
    var linkedFrom: String = ""
    var clientVersion: String = "1.0.0"
}

/** A contact as the account's state holds it. */
class FakeContact internal constructor(
    val userId: String,
    var label: String,
    var compared: Boolean,
    var connectedAtMs: Long,
) {
    /** The link's reveal arrived and this device holds its record: a comparison can run. */
    var codesReady: Boolean = false

    /**
     * As the engine on the side that answered a link: this device holds the link's record and the creator's reveal has not
     * been fetched. "Compare codes" is offered; opening the comparison fetches the reveal ([revealPosted]: the creator has
     * posted it), and only then is the code ready.
     */
    var revealWaiting: Boolean = false

    /** The creator posted its reveal at the server; the answerer's next opening of the comparison takes it. */
    var revealPosted: Boolean = false

    /**
     * This side's six digits (§6.11: each side of a link has its own code, `creator` or `answerer`): what this person
     * reads out. The app shows it in [io.silencelen.andvari.core.app.CompareScreen.Ready.code].
     */
    var code: String = "000000"

    /**
     * The other side's six digits, which the other person reads out and this person types. The app computes it and
     * never shows it. It differs from [code] here, so typing one's own code is a wrong entry.
     */
    val theirCode: String get() = FakeText.digits6("other side:$code")

    /** The id of the device that made the contact, as the account's record holds it; null for one no device list names. */
    var madeOnDeviceId: String? = null

    /** The link failed (a second, different nonce, or a reveal that does not match). */
    var linkFailed: Boolean = false

    /** They answered or made a link under another key than the pinned one. */
    var keyChangeWaiting: Boolean = false

    /** Vaults attached to the link they answered, waiting for the codes. */
    val waitingShares: MutableList<FakeShare> = ArrayList()
}

class FakeShare internal constructor(val vaultId: String, val role: MemberRole)

/** A shared vault as one account sees it. */
class FakeVault internal constructor(val vaultId: String, var name: String) {
    var role: RoleInVault? = RoleInVault.OWNER
    var log: VaultLogState = VaultLogState.VERIFIED
    var historyHint: Boolean = false
    var ownerOutOfSpace: Boolean = false

    /** Above 0: the owner deleted it, and it is purged then. */
    var purgeAtMs: Long = 0L
    var heldUntilMs: Long = 0L
    var removedByOwner: Boolean = false
    var itemCount: Int = 3

    /** Of [itemCount], how many this device cannot read: "Move everything" cannot copy them, so it keeps the old vault. */
    var unreadable: Int = 0
    val members: MutableList<FakeMember> = ArrayList()
    var offer: FakeOffer? = null

    /** [VaultLogState.CONNECT_FIRST] and [VaultLogState.CONFIRM_FIRST]: who the server says shares it. */
    var sharedByServerName: String? = null

    /** [VaultLogState.CONFIRM_FIRST]: the sender, a contact of the account that is not current on this device. */
    var sharedByContact: FakeContact? = null

    /** A change this device signed for it waits for the server's acknowledgement. */
    var changeWaiting: Boolean = false

    /** The change this device signed for it and keeps to send again, as the engine describes it ([SharedVaultRow.waiting]). */
    internal var waiting: FakeWaiting? = null

    /**
     * A "Move everything" out of it stopped part-way, into the vault named here ([SharedVaultRow.unfinishedMove]); with
     * [moveDeleteWaiting] its deletion is signed and waiting. Kept across a lock, as the engine keeps it.
     */
    var moveUnfinishedInto: String? = null
    var moveDeleteWaiting: Boolean = false

    /**
     * The server stored that waiting deletion outside the move ([FakeScript.serverStoresMoveDeleteLater]): the new vault's
     * name, and how many items were added and changed after the copies ([io.silencelen.andvari.core.app.MoveStoredNotice]).
     */
    var storedOutsideInto: String? = null
    var lateAdded: Int = 0
    var lateChanged: Int = 0
    var lateCopied: Int? = null

    /** The person's own waiting deletions the move kept rather than carried ([FakeScript.moveDeletionsKept]). */
    var deletionsKept: Int = 0

    /** An `add` of this account that waits for its answer: the owner's label and the entry's position. */
    var incomingFrom: String? = null
    var incomingAddSeq: Long = 0L

    /** The next position in its log. */
    internal var seq: Long = 1L

    /** Another member, as the verified log holds them. [contact] is their contact when their key is a pinned one. */
    fun addMember(name: String, role: RoleInVault, contact: FakeContact?): FakeMember {
        val member = FakeMember(contact?.userId ?: "member-$vaultId-${members.size + 1}", name, role, contact)
        members += member
        return member
    }
}

class FakeMember internal constructor(
    val userId: String,
    /** What the server calls them. */
    var serverName: String,
    var role: RoleInVault,
    /** Their contact, when the log's key for them equals a pinned key. */
    var contact: FakeContact?,
) {
    /** In the log, without a grant: the operator deleted their account. */
    var deletedByOperator: Boolean = false
}

class FakeOffer internal constructor(val toUserId: String, val expiresAtMs: Long)

/** A request for the operator's help. */
class FakeHelpRequest internal constructor(
    val requestId: String,
    val server: FakeServer,
    val email: String,
    val createdAtMs: Long,
    /** The address belongs to an account that chose operator recovery: only then was a code mailed. */
    val codeMailed: Boolean,
    val platform: AppPlatform,
) {
    var stage: OperatorHelpStage = OperatorHelpStage.CODE_NEEDED
    var verifiedAtMs: Long = 0L
    var holdEndsAtMs: Long = 0L
    var wrongTries: Int = 0
    var fulfilled: Boolean = false

    /** The operator's answer is not signed by the recovery key the pinned card names. */
    var answerForged: Boolean = false

    /** The answer delivers this account instead of the one the address names (§9.3 step 4); null: the address's own. */
    var delivers: FakeAccount? = null

    /** The server's recovery key changed under the request, by rotations the old key signed, at this time; null: it did not. */
    var keyRotatedAtMs: Long? = null

    /** The server's recovery key changed under the request with no rotation the old key signed: every look stops. */
    var keyChangedUnsigned: Boolean = false

    /** The server answers 404 for this request (it lost the row, or lies): kept here, and said. */
    var unknownToServer: Boolean = false

    /** The server cancelled this request (the account's password or recovery setting changed, or it was recovered). */
    var cancelledByServer: Boolean = false

    /**
     * Spec 01 §7: the operator's answer delivers a key that does not open what this device's kept copy of the account holds
     * sealed under it. Every look at the answer stops, nothing is asked or committed, and the request is kept.
     */
    var keyNotKept: Boolean = false

    /**
     * The operator's answer is for an account this device knows the address under another account or key for (the keeper's
     * identity fault): every look stops at the pick-up, nothing is asked or committed, and the request is kept.
     */
    var boundElsewhere: Boolean = false

    /**
     * The operator's answer names an account that is not the one this device keeps for the address (as the engine's
     * `not_the_kept_account`, decided before the keeper is asked): every look stops at the pick-up, nothing is asked or
     * committed, and the request stays as it is.
     */
    var namesAnotherAccount: Boolean = false

    /** The mailbox value the request carried, in its sent form (no spaces or dashes, capitals); null: none. */
    var mailboxValue: String? = null

    /** The answer on the server is not the one this device opened (the operator uploaded another): the commit is refused. */
    var answerReplaced: Boolean = false
}

internal enum class FakeInviteKind { CONNECT, REGISTER, ENROL, SETUP }

internal enum class FakeInviteState { OPEN, USED, REVOKED, EXPIRED, DAMAGED }

/** An invite someone else made, which the fake app can open. */
internal class FakeInvite(
    val payload: String,
    val kind: FakeInviteKind,
    val server: FakeServer,
    /** The creator's name, as they call themselves; null for a host-minted link. */
    val from: String?,
    val boundEmail: String?,
    var expiresAtMs: Long,
) {
    var state: FakeInviteState = FakeInviteState.OPEN

    /** The creator is already a contact, and this link is under another key. */
    var newKeyOf: FakeContact? = null
}

internal enum class FakeLinkStep { OPEN, CLAIMED, REVEALED, APPROVED, PICKED_UP, CANCELLED }

/** A device link another device of [account] shows, which the fake app can scan. */
internal class FakeDeviceLink(
    val payload: String,
    val server: FakeServer,
    val account: FakeAccount,
    val fromDevice: String,
    var expiresAtMs: Long,
) {
    var step: FakeLinkStep = FakeLinkStep.OPEN
    var claimedByOther: Boolean = false
    var code: String = "482913"
}

/** A recovery kit of [account], as its QR reads. */
internal class FakeKit(
    val payload: String,
    /** The server and the address the kit names. */
    val server: FakeServer,
    val email: String,
    /** The account there, when the address has one: only the server knows, and it says so only at the confirm. */
    val account: FakeAccount?,
    /** The serial of the kit the secret belongs to; -1 for typed groups that are no kit of that account. */
    val serial: Int,
) {
    /** False: the kit was made before the server's identity was reset; its `card0Hash` no longer matches. */
    var card0Matches: Boolean = true
}

/** What a scanned or pasted string is, by its shape alone (§6.1, §8.1, §10). */
internal enum class PayloadShape { INVITE, DEVICE_LINK, KIT, NOTHING }

/** Small pure helpers: shapes, addresses, deterministic stand-ins for what real keys would give. */
internal object FakeText {
    const val JOIN_BASE = "https://andvaripass.com"

    /** The key a payload is looked up by, and its shape. White space is stripped first, as chat apps wrap lines. */
    fun shape(text: String): Pair<PayloadShape, String> {
        val clean = text.filterNot { it == ' ' || it == '\t' || it == '\r' || it == '\n' }
        if (clean.startsWith("andvari-kit:")) return PayloadShape.KIT to clean
        val fragment = clean.substringAfter('#', clean)
        val parts = fragment.split('.')
        if (parts.firstOrNull() != "v2" || parts.any { it.isEmpty() }) return PayloadShape.NOTHING to clean
        // The page before the fragment is not authenticated; only the fragment is acted on (§6.1).
        return when (parts.size) {
            4 -> PayloadShape.INVITE to fragment
            3 -> PayloadShape.DEVICE_LINK to fragment
            else -> PayloadShape.NOTHING to clean
        }
    }

    /** §2.3 `emailNorm`, or null for an address it refuses. */
    fun emailNorm(email: String): String? {
        val t = email.trim { it == ' ' || it == '\t' || it == '\r' || it == '\n' }
        if (t.length > 254 || t.any { it.code < 0x21 || it.code > 0x7e }) return null
        val at = t.indexOf('@')
        if (at <= 0 || at != t.lastIndexOf('@') || at == t.length - 1) return null
        return buildString { for (c in t) append(if (c in 'A'..'Z') c + 32 else c) }
    }

    /**
     * The origin [input] spells, if the origin grammar can carry it (§2.2): https with a domain name of at least two
     * labels, an optional port that is not 443, and nothing after it; or plain http to `localhost` or `127.0.0.1`.
     * A stand-in for the real grammar, strict on purpose.
     */
    fun origin(input: String): String? {
        val t = input.trim()
        if (t != t.lowercase()) return null
        val rest = when {
            t.startsWith("https://") -> t.removePrefix("https://")
            t.startsWith("http://") -> t.removePrefix("http://")
            else -> return null
        }
        val host = rest.substringBefore(':')
        val port = if (rest.contains(':')) rest.substringAfter(':') else null
        if (port != null && (port.isEmpty() || port.startsWith('0') || port.any { it !in '0'..'9' } || port.length > 5 || port.toInt() !in 1..65535)) return null
        if (t.startsWith("http://")) return if (host == "localhost" || host == "127.0.0.1") t else null
        if (port == "443") return null
        val labels = host.split('.')
        val label = Regex("[a-z0-9]([a-z0-9-]*[a-z0-9])?")
        if (labels.size < 2 || labels.any { !label.matches(it) }) return null
        if (labels.all { l -> l.all { it in '0'..'9' } }) return null // an IP literal
        return t
    }

    /** A master password the fake accepts for a new account: twelve characters or more. */
    fun strongEnough(password: String): Boolean = password.length >= 12

    /** 32 hex characters that depend only on [seed]. Not a hash anyone should trust: the fake has no keys. */
    fun hex32(seed: String): String {
        var h = 1125899906842597L
        for (c in seed) h = 31 * h + c.code
        val out = StringBuilder()
        var x = h
        repeat(32) {
            x = x * 6364136223846793005L + 1442695040888963407L
            out.append("0123456789abcdef"[((x ushr 33) and 15).toInt()])
        }
        return out.toString()
    }

    /** Six digits that depend only on [seed]. */
    fun digits6(seed: String): String = (hex32(seed).take(7).toLong(16) % 1_000_000).toString().padStart(6, '0')

    /** The 11 groups of a kit's secret (ten of four characters, one of three), for one account and kit serial. */
    fun kitGroups(account: FakeAccount, serial: Int): List<String> {
        val alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_"
        val seed = hex32("kit:${account.userId}:$serial")
        val chars = StringBuilder()
        for (i in 0 until 43) chars.append(alphabet[(seed[i % 32].code * 7 + i * 13 + serial) % alphabet.length])
        return (0 until 11).map { g -> chars.substring(g * 4, minOf(g * 4 + 4, 43)) }
    }

    /** A request code: six groups of four hex characters. */
    fun requestCode(seed: String): List<String> = hex32("request:$seed").take(24).chunked(4)

    /** A token for [origin] that can stand in a link's fragment. */
    fun originToken(origin: String): String = origin.map { if (it in 'a'..'z' || it in '0'..'9') it else '-' }.joinToString("")
}
