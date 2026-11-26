package io.silencelen.andvari.core.app.fake

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.DeviceLinkHostEnd
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.HowDeviceJoined
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.KitReason
import io.silencelen.andvari.core.app.KitStep
import io.silencelen.andvari.core.app.LinkDeviceEnd
import io.silencelen.andvari.core.app.OperatorHelpStage
import io.silencelen.andvari.core.app.OwnLinkKind
import io.silencelen.andvari.core.app.OwnLinkRow
import io.silencelen.andvari.core.app.RoleInVault
import io.silencelen.andvari.core.app.ServerKind
import io.silencelen.andvari.core.app.Trouble
import io.silencelen.andvari.core.app.VaultLogState
import io.silencelen.andvari.core.app.WhoCanRecover
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.trust.MemberRole

/**
 * The stage directions of a [FakeAppApi]: the world it runs in, the part of everyone else (the other device, the
 * person on the other end of a link, the operator, the server's clock), and outcomes to inject.
 *
 * Three ways to reach a state:
 * - **Set the world up**: [publicInstance], [addServer], the accounts on them ([FakeServer.addAccount]), and what
 *   exists to scan ([connectInvite], [invitation], [enrolLink], [setupLink], [deviceLinkFrom], [kitOf]).
 * - **Play the other party**: [otherDeviceAnswers], [someoneAnswers], [operatorAnswers], [advance], …
 * - **Inject an outcome**: [forceNext] makes the next intent of that result type return it; [failNext] makes the
 *   next intent, whichever it is, fail with a trouble; [holdNext] stops the next intent midway until [releaseHold].
 */
class FakeScript internal constructor(private val app: FakeAppApi) {
    // ---- the world ----

    /** The baked public instance: "andvari" at `https://vault.andvaripass.com`, open to sign-up. */
    val publicInstance: FakeServer = FakeServer("https://vault.andvaripass.com", "andvari", ServerKind.PUBLIC_SERVER).also {
        it.ageConfirmRequired = true
        app.servers[it.origin] = it
    }

    /** A server at [origin] (as the origin grammar spells it), set up and invitation-only, as a self-hosted one is by default. */
    fun addServer(origin: String, name: String, kind: ServerKind): FakeServer {
        val server = FakeServer(origin, name, kind)
        server.mode = io.silencelen.andvari.core.app.JoinMode.INVITATION_ONLY
        app.servers[origin] = server
        return server
    }

    /** The server at [origin], if the world has one. */
    fun server(origin: String): FakeServer? = app.servers[origin]

    /** The code every email of the fake carries. */
    var emailCode: String = "123456"

    /** The groups a kit's confirm step asks for (each 1 to 11, ascending). */
    var kitGroupsAsked: List<Int> = listOf(2, 7, 10)

    /** Quick unlock is set up on this device: a device link can be approved with it. */
    var quickUnlock: Boolean = true

    /**
     * The platform fails to move its data to a followed move's new address: [InstanceApi.followMove] answers
     * [MoveResult.NOT_FINISHED], and [InstanceApi.finishMove] keeps answering it until this is set back to false.
     */
    var namespaceMoveFails: Boolean = false

    /**
     * The session knows that the account's keys on the server are not the ones this device knows (the quiet re-key after
     * a sign-in found them so): the server refuses the right password's proof on every action that proves it, and each
     * answers `KEYS_NOT_KNOWN_HERE`. A wrong password stays a wrong password.
     */
    var serverKeysNotKnownHere: Boolean = false

    /**
     * The server refuses the right password's proof while the session does not know that its keys differ: every action
     * that proves the password answers `PROOF_REFUSED`, never a wrong password. [serverKeysNotKnownHere] goes first.
     */
    var serverRefusesProof: Boolean = false

    /** What an action that proves the password answers for a server's refusal of the proof; null when there is none. */
    internal fun <R> proofRefusal(keys: R, refused: R): R? = when {
        serverKeysNotKnownHere -> keys
        serverRefusesProof -> refused
        else -> null
    }

    /** The next password sign-in finds that the server's copy opens to another key than the one this device keeps (spec 01 §7). */
    var signInServerKeysNotKnown: Boolean = false

    /** The next password sign-in, or device link, goes through over a copy this device kept sealed under another master password. */
    var signInOverOtherPasswordCopy: Boolean = false

    /**
     * Spec 01 §7: the key the next recovery with the kit opens does not open what this device's kept copy of the account
     * holds sealed under it: the proof answers `SERVER_KEYS_NOT_KNOWN_HERE`, or, set after the proof, the commit does
     * (nothing committed). For the operator's help, see [FakeHelpRequest.keyNotKept].
     */
    var recoveredKeyNotKept: Boolean = false

    /** The next device link's pickup finds the server's keys are not this account's as this device knows it (spec 01 §7). */
    var linkKeysNotKnownHere: Boolean = false

    /** The next device link's pickup is not taken: this device keeps another account's session. */
    var linkAnotherSessionKept: Boolean = false

    /**
     * As the engine where the server refuses the next step of a device link as one of too many requests (`429`; the wait is
     * [rateLimitNext]'s seconds, or 30): on this device as the new one, the claim after the scan
     * ([io.silencelen.andvari.core.app.DeviceLinkScanResult.RATE_LIMITED], nothing claimed) or the pickup (the link ends as
     * [io.silencelen.andvari.core.app.LinkDeviceEnd.TOO_MANY]); on this device as the one that shows the link, its start
     * ([io.silencelen.andvari.core.app.PlainResult.RATE_LIMITED], no link), the digits or the approval (the link ends, with
     * [io.silencelen.andvari.core.app.DeviceLinkHost.Ended.line]). Used once.
     */
    var linkTooMany: Boolean = false

    /**
     * As the engine's keeper when another account is kept here by the time the next recovery's commit is about to go (with
     * the kit or the operator's help): nothing is committed. The kit's recovery goes back to where the kit is handed in;
     * the operator's help back to the request's screen, which keeps the request and says why.
     */
    var anotherAccountTakenBeforeCommit: Boolean = false

    /**
     * The next recovery's commit (with the kit or the operator's help), or the next registration, is taken by the server,
     * and this device then refuses its session because another account was kept here meanwhile: the new kit is shown with
     * the refusal ([io.silencelen.andvari.core.app.KitScreen.notKeptLine]) and kept until it is confirmed; nothing of the
     * account is kept.
     */
    var anotherAccountTakenDuringCommit: Boolean = false

    /**
     * As [anotherAccountTakenDuringCommit], for a recovery's commit or a registration, with the keeper's own reason for the
     * refusal (one of the engine's: `another_session_kept`, `self_identity_mismatch`, `server_keys_not_known_here`, and the
     * keeper's other reasons): the result and the kit's line say that reason, and that the change was committed.
     */
    var refusedAfterCommit: String? = null

    /**
     * While set, as the engine's keeper with this reason of its own (`operator_account_held`: this device holds its server's
     * operator account; `kept_copy_damaged`: this device's copy of the account is damaged): a sign-in, a recovery's check
     * and its commit, a device link once its approval names the account, and an operator's answer at its pick-up stop
     * with it, nothing committed, each said as what it is.
     */
    var keeperRefuses: String? = null

    /**
     * As the engine's keeper for an address this device knows under another account or key: the next device link ends at the
     * approval with the identity fault, before any password is asked; the next recovery's commit stops with it.
     */
    var keeperIdentityFault: Boolean = false

    /**
     * As the engine at a device link's approval where this device holds a record of the link's account's key and so cannot
     * tell from the link alone a remade account from a substitution: the next link ends there, before any password is asked,
     * with [io.silencelen.andvari.core.app.LinkDeviceEnd.IDENTITY_FAULT_CANNOT_TELL] (its line points to the password
     * sign-in), and no offer to forget anything is made. Used once.
     */
    var linkIdentityCannotTell: Boolean = false

    /**
     * As the engine for a device that remembers an earlier account under the address: the identity fault the next sign-in
     * or kit check has ([identityFault]), the next recovery's commit ([keeperIdentityFault]), an operator's answer for an
     * address bound elsewhere, and every registration while it is set (the keeper refuses the account made; a registration's
     * [identityFault] is the server's answer's own fault and offers nothing), each offer "Forget the earlier account on this
     * device" ([io.silencelen.andvari.core.app.AppSnapshot.earlierAccount]). Cleared by a forgetting that answers FORGOTTEN,
     * NOTHING_TO_FORGET or ACCOUNT_OPEN, after which the engine offers nothing for it. (The
     * engine offers it at a device link's pickup only, which the fake's link does not reach with this fault.)
     */
    var earlierAccountKnown: Boolean = false

    /**
     * As the engine where the server serves the SAME account under another identity key than this device knows (decided on
     * 2026-11-19): every identity fault that [earlierAccountKnown] would offer the forgetting for (a sign-in, a kit check, a
     * recovery's commit, an operator's answer) is said as the identity fault and offers nothing; a registration, whose
     * account is always new, is offered as before. It stays set across a forgetting: after FORGOTTEN, the engine keeps the
     * earlier account's key, so that account served under another key ([identityFault] then) is refused with no offer.
     */
    var sameAccountOtherKey: Boolean = false

    /**
     * As the engine where the address comes to be tied here to the very account the server serves (a take under it while the
     * offer stands): the offer's first step is refused and the offer goes; a confirmation answers NOT_CONFIRMED, the offer
     * goes, and nothing is forgotten.
     */
    var addressTiedToServed: Boolean = false

    /**
     * As the engine after a forgetting, once the next account was taken under the address: the earlier account served again
     * under its own key ([identityFault] then) is refused with the offer to forget the NEW account, the one the address names
     * now (someone who forgot by mistake finds the way back). Cleared by a forgetting that answers FORGOTTEN.
     */
    var earlierBackUnderOwnKey: Boolean = false

    /** With [earlierAccountKnown]: this device keeps a copy of the earlier account, which the forgetting deletes. */
    var earlierCopyKept: Boolean = false

    /**
     * With [earlierCopyKept]: 0 for a kept copy whose data this device does not hold; anything else (null or a number) is
     * played as null, "cannot tell", which is all the engine ever gives for a copy it holds (the account is never open
     * while it is offered).
     */
    var earlierCopyUnsent: Int? = null

    /**
     * With [earlierAccountKnown]: this device holds the earlier account's data without keeping its session (a session record
     * that could not be read); offered as a copy that is deleted, its changes not sent "cannot tell".
     */
    var earlierCopyHeld: Boolean = false

    /**
     * With [earlierAccountKnown]: how many signed changes to shared vaults made on this device under the earlier account wait
     * here, never sent (a sign-out keeps them; the forgetting removes them). Counted in the offer's
     * [io.silencelen.andvari.core.app.EarlierAccountKnown.unsentChanges] wherever the count can be told (no copy kept, or a
     * kept copy whose data is not held), as the engine counts them; set while the offer is on show, the confirmation shown
     * before no longer holds. A forgetting removes them (back to 0).
     */
    var earlierSharedChangesUnsent: Int = 0

    /** What the next forgetting answers once confirmed. */
    var forgetAnswer: io.silencelen.andvari.core.app.ForgetEarlierResult = io.silencelen.andvari.core.app.ForgetEarlierResult.FORGOTTEN

    /**
     * The next confirmed forgetting fails part-way, as the engine's does with a store that fails after the keeper forgot: the
     * call throws, the second step stays on show, and the next tap finishes it and answers FORGOTTEN.
     */
    var forgetFailsOnce: Boolean = false

    /** The next registration is refused with `400 escrow_wrong_form`. */
    var escrowWrongForm: Boolean = false

    /** The next biometric prompt is cancelled. */
    var biometricsCancelled: Boolean = false

    /** The next fingerprint or face check that would approve a new device is overtaken by a lock: the vault locks. */
    var lockDuringPresence: Boolean = false

    /** The device has a strong biometric and a platform key (quick unlock can exist at all). */
    var biometricAvailable: Boolean = true

    /** The next quick-unlock prompt locks out or fails: the master password is the way in, and quick unlock stays on. */
    var biometricsRefused: Boolean = false

    /** The device's biometrics changed: the next quick unlock finds its key invalidated, and quick unlock turns off. */
    var biometricsChanged: Boolean = false

    /** The periodic full password (30 days) is due: quick unlock waits for one password unlock. */
    var passwordDue: Boolean = false

    /**
     * The next master-password change is taken by the server but this device's copy cannot follow it: the change answers
     * [io.silencelen.andvari.core.app.PasswordChangeResult.CHANGED_PREVIOUS_OPENS_HERE] and the previous password opens
     * the copy here. Used once.
     */
    var deviceCannotFollowPassword: Boolean = false

    /** The code the person's authenticator app shows now, for two-step sign-in in Settings. */
    var authenticatorCode: String = "246810"

    /**
     * The server's back-off for this account's proofs or codes is on (too many wrong passwords or codes): turning
     * two-step sign-in off and replacing its key answer [io.silencelen.andvari.core.app.TwoStepResult.TOO_MANY_TRIES]
     * before anything is looked at. A wrong password or a wrong code is simply typed.
     */
    var twoStepTriesLocked: Boolean = false

    /** [io.silencelen.andvari.core.app.AppSnapshot.containedFaults]: [backgroundWorkFaults] adds one. */
    internal var containedFaults: Int = 0
        private set

    /**
     * The server's policy that forbids the copy is recorded for [userId]'s copy (by default the account kept on this
     * device): as the engine, [io.silencelen.andvari.core.app.AppSnapshot.policyWipeOwed] reads true for that account's
     * kept session, across a lock and a restart, until [policyCopyRemoved] says the copy is gone and counted.
     */
    fun policyForbidsCopy(userId: String? = (app.session?.account ?: app.storedSession?.second)?.userId) {
        app.policyWipeOwedFor = userId
        app.publish()
    }

    /**
     * The server's policy forbids the copy and this device's copy is gone after the one try to send what waited (as the
     * engine's run): [io.silencelen.andvari.core.app.AppSnapshot.policyWipe] says so, with these numbers, in every phase
     * until the person dismisses it. Its origin is always `https://example.test`, its server name [serverName].
     * [unopened]: with [cannotTell], the copy itself could not be opened (false: only kept saves could not be read).
     * Unlike the engine, the fake sets it independently of the content's removal
     * ([io.silencelen.andvari.core.app.content.FakeVaultContent.removingForPolicy]), and it does not survive a restart.
     * [userId]: the account whose copy it was (by default the account kept on this device, or anyone's where none is):
     * as the engine, inside a kept session only that account's own notice is shown, and any notice where none is kept.
     * Where it is that account's, its copy is gone and the account goes on in memory: [waitingInMemory] counts then.
     * [unfinishedMoves]: "Move everything" runs left half-done, said on a line of their own.
     */
    fun policyCopyRemoved(
        notSent: Int, unsure: Int = 0, cannotTell: Boolean = false, serverName: String = "Example server",
        unopened: Boolean = cannotTell, userId: String? = (app.session?.account ?: app.storedSession?.second)?.userId,
        unfinishedMoves: Int = 0,
    ) {
        app.policyWipe = io.silencelen.andvari.core.app.PolicyWipeNotice.of("https://example.test", serverName, notSent, unsure, cannotTell, unopened, unfinishedMoves)
        app.policyWipeOwner = userId
        // The copy is gone and counted: its removal is no longer owed.
        if (userId == null || userId == app.policyWipeOwedFor) app.policyWipeOwedFor = null
        if (userId != null && userId == (app.session?.account ?: app.storedSession?.second)?.userId) app.copyInMemory = true
        app.publish()
    }

    /**
     * [io.silencelen.andvari.core.app.AppApi.waitingInMemory]: changes held in memory only, which ending the app would
     * lose; null plays "cannot be told" (locked, with saves or moves kept in memory). After [policyCopyRemoved] for the
     * kept account the fake counts what waits instead, as the engine does.
     */
    var waitingInMemory: Int? = 0

    /** [io.silencelen.andvari.core.app.AppApi.policyWipeOwed] for every account, as the script plays it. */
    var policyWipeOwed: Boolean = false

    /** Background work of the app interface met an unexpected fault, which was contained (as the engine's scope does). */
    fun backgroundWorkFaults() {
        containedFaults++
        app.publish()
    }

    /** The store build of the baked instance: it follows neither a move nor a `kind` change of it (§4.4). */
    var storeBuild: Boolean = true

    /**
     * This build bakes no public instance (§0.3): the first screen has no "Create an account on andvari", the server
     * choice of a sign-in offers none, and [publicInstance] is a server like any other. Set it before [FakeAppApi.start].
     */
    var noBakedInstance: Boolean = false

    /**
     * The public instance has not said yet what it does about new accounts: the first screen shows
     * [io.silencelen.andvari.core.app.JoinMode.NOT_KNOWN] until "Create an account on andvari" asks, or until this is
     * set back and [changed] is called.
     */
    var publicStatusNotFetched: Boolean = false

    /**
     * Old stores the first-launch wipe cannot delete (§12.4): each stays, start after start, until it is taken out
     * of this set. Only for a fake made without its own [io.silencelen.andvari.core.app.PreCutoverStores].
     */
    val oldStoresThatStay: MutableSet<io.silencelen.andvari.core.app.PreCutoverStore> = HashSet()

    /** The deletion preview lists a blocker of a kind this build does not know. */
    var unknownDeletionBlocker: Boolean = false

    // ---- what exists to scan ----

    /** A connect link [from] made on [server], as its QR or text reads. */
    fun connectInvite(server: FakeServer, from: String): String = invite(FakeInviteKind.CONNECT, server, from, null)

    /** A register link (an invitation) [from] made on [server]. */
    fun invitation(server: FakeServer, from: String): String = invite(FakeInviteKind.REGISTER, server, from, null)

    /** A host-minted enrol link for [server], bound to [boundEmail] when given. */
    fun enrolLink(server: FakeServer, boundEmail: String?): String = invite(FakeInviteKind.ENROL, server, null, boundEmail)

    /** The setup link of a fresh [server]: it has no card and no operator until the link is used. */
    fun setupLink(server: FakeServer): String {
        server.hasCard = false
        server.operatorExists = false
        return invite(FakeInviteKind.SETUP, server, null, null)
    }

    private fun invite(kind: FakeInviteKind, server: FakeServer, from: String?, email: String?): String {
        val n = app.serial++
        val fingerprint = if (from == null) "-" else "f$n"
        val fragment = "v2.${FakeText.originToken(server.origin)}.s$n.$fingerprint"
        val life = if (kind == FakeInviteKind.SETUP) 24 * HOUR else 7 * DAY
        app.invites[fragment] = FakeInvite(fragment, kind, server, from, email?.let(FakeText::emailNorm), app.nowMs + life)
        return "${FakeText.JOIN_BASE}/l#$fragment"
    }

    /** The invite expired. */
    fun expire(invite: String) = setInvite(invite, FakeInviteState.EXPIRED)

    /** Someone else used or answered the invite first. */
    fun useUp(invite: String) = setInvite(invite, FakeInviteState.USED)

    /** Whoever made the invite revoked it. */
    fun revoke(invite: String) = setInvite(invite, FakeInviteState.REVOKED)

    /** The invite fails a check of §6.8 (a swapped offer, a wrong fingerprint, a card the chain does not hold). */
    fun damage(invite: String) = setInvite(invite, FakeInviteState.DAMAGED)

    private fun setInvite(invite: String, state: FakeInviteState) {
        app.invites[FakeText.shape(invite).second]?.state = state
    }

    /** The invite's creator is [contact] of the signed-in account, under another key than the pinned one. */
    fun inviteIsNewKeyOf(invite: String, contact: FakeContact) {
        app.invites[FakeText.shape(invite).second]?.newKeyOf = contact
    }

    /** A device link another device of [account], called [deviceName], shows: as its QR reads. */
    fun deviceLinkFrom(account: FakeAccount, deviceName: String): String {
        val fragment = "v2.${FakeText.originToken(account.server.origin)}.d${app.serial++}"
        app.deviceLinks[fragment] = FakeDeviceLink(fragment, account.server, account, deviceName, app.nowMs + 5 * MINUTE)
        return "${FakeText.JOIN_BASE}/d#$fragment"
    }

    /** The recovery kit of [account], as its QR reads. */
    fun kitOf(account: FakeAccount): String {
        val payload = "andvari-kit:2:${FakeText.originToken(account.server.origin)}:c${account.kitSerial}:${account.userId}:k${app.serial++}"
        app.kits[payload] = FakeKit(payload, account.server, account.email, account, account.kitSerial)
        return payload
    }

    /**
     * A kit of [account] made while its server still lived at [oldOrigin]: the kit names that address, where a
     * server now serves the real one's chain, whose newest card names the address it moved to (§2.4
     * `origin_mismatch`). Scanning it ends at [io.silencelen.andvari.core.app.EntryScreen.AddressMismatch], which
     * offers to recover at the address the card names.
     */
    fun kitFromBeforeMove(account: FakeAccount, oldOrigin: String): String {
        val old = FakeServer(oldOrigin, account.server.name, account.server.kind)
        old.servesAnotherServersCard = true
        old.cardNamesOrigin = account.server.origin
        app.servers[oldOrigin] = old
        val payload = "andvari-kit:2:${FakeText.originToken(oldOrigin)}:c${account.kitSerial}:${account.userId}:k${app.serial++}"
        app.kits[payload] = FakeKit(payload, old, account.email, account, account.kitSerial)
        return payload
    }

    /** The eleven groups of [account]'s current kit as its sheet prints them, separated by spaces: what a person types by hand. */
    fun kitGroupsOf(account: FakeAccount): String = FakeText.kitGroups(account, account.kitSerial).joinToString(" ")

    /** The kit was made before the server's identity was reset: its card hash no longer matches. */
    fun kitPredatesReset(kit: String) {
        app.kits[kit]?.card0Matches = false
    }

    // ---- injected outcomes ----

    /** The next intent whose result type is [result]'s returns it, once, and does nothing else. */
    fun forceNext(result: IntentResult) {
        app.forced = result
    }

    /** The next intent, whichever it is, fails with [trouble] and does nothing else. */
    fun failNext(trouble: Trouble) {
        app.forcedTrouble = trouble
    }

    /** The next intent is told to wait [seconds] (`429` with `Retry-After`). */
    fun rateLimitNext(seconds: Int) {
        app.retryAfterNext = seconds
        app.forcedTrouble = Trouble.RATE_LIMITED
    }

    /** The next `suspend` intent stops midway, with the snapshot busy, until [releaseHold]. */
    fun holdNext() {
        app.holdArmed = true
    }

    /** Let the held intent go on. */
    fun releaseHold() = app.releaseHold()

    /** An intent is being held. */
    val holding: Boolean get() = app.holding

    /** The next sign-up's proof of work does not finish by itself: [setWorkProgress] moves it, [finishWork] ends it. */
    var holdProofOfWork: Boolean = false

    fun setWorkProgress(percent: Int) = app.entryFlow.workProgress(percent)

    fun finishWork() = app.entryFlow.finishWork()

    /** The next sign-in, registration, unlock or kit proof meets keys that fail the identity checks (§5.2). */
    var identityFault: Boolean = false

    /**
     * The answer a registration through a connect link posts right afterwards is not taken, for this reason
     * ([io.silencelen.andvari.core.app.ConnectResult.UNREACHABLE]: no answer, and it can be tried again): the
     * account exists, and [io.silencelen.andvari.core.app.AccountPrompt.ConnectionNotMade] says the connection does not.
     */
    var connectAnswerFails: io.silencelen.andvari.core.app.ConnectResult? = null

    /** The next comparison that matches cannot be written to the account ([io.silencelen.andvari.core.app.ComparisonResult.NOT_SAVED]). */
    var comparisonNotSaved: Boolean = false

    /** The next upload of card 0 gets no answer. */
    var cardUploadFails: Boolean = false

    /** The next recovery commit lands on the server but its answer is lost: [ReplacePasswordResult.MAY_HAVE_WORKED]. */
    var recoveryCommitUnanswered: Boolean = false

    /**
     * As the engine: the next recovery commit lands on the server, and its answer cannot open the account on this device
     * (a fault while opening): [io.silencelen.andvari.core.app.ReplacePasswordResult.COMMITTED_NOT_OPENED], on the first
     * screen, with nothing of the account kept here and no kit shown. Also when another session was refused meanwhile.
     */
    var recoveryCommitNotOpened: Boolean = false

    /**
     * As the engine: the person's own deletions that waited in the old vault when "Move everything" ran and whose copies
     * the move had made are kept, not carried ([io.silencelen.andvari.core.app.MoveStoredNotice.deletionsKept] and its
     * [io.silencelen.andvari.core.app.MoveStoredNotice.keptLine]), when [serverStoresMoveDeleteLater] stores the move.
     */
    var moveDeletionsKept: Int = 0

    /** The next upload of card 0 does not land by itself: [finishCardUpload] lets it. */
    var holdCardUpload: Boolean = false

    fun finishCardUpload() = app.entryFlow.finishCardUpload()

    /** The next commit of a fresh kit gets no answer. */
    var kitCommitFails: Boolean = false

    /** The next commit of a fresh kit does not land by itself: [finishKitCommit] lets it. */
    var holdKitCommit: Boolean = false

    fun finishKitCommit() = app.kitFlow.finishCommit()

    /** Another device makes a newer kit while this device's is on its confirm step. */
    var kitReplacedElsewhere: Boolean = false

    /** How many times the next deletion is refused because a vault's history moved (`account_delete_log_stale`). */
    var deletionStaleRounds: Int = 0

    /** A vault's unverified head is dated more than a day ahead of this device's clock. */
    var deletionFarFutureHead: Boolean = false

    /** The next deletion request gets no answer; [deletionHappenedAnyway] says whether it committed. */
    var deletionAnswerLost: Boolean = false
    var deletionHappenedAnyway: Boolean = false

    /**
     * This device keeps records of another account at the session's server (an account that signed out here, or a copy it
     * holds): as the engine, a confirmed deletion then removes the deleted account's records only, the server stays known,
     * and the first screen's notice says so ([io.silencelen.andvari.core.app.AccountDeletedNotice.serverForgotten] false).
     */
    var anotherAccountKnownAtServer: Boolean = false

    /**
     * The server serves the day a deleted vault's grace ends (true, as the reference server does). False: a server that
     * serves none; as the engine, a deleted vault's row then carries no day
     * ([io.silencelen.andvari.core.app.SharedVaultRow.purgeAtMs] 0) and says
     * [io.silencelen.andvari.core.app.SharedVaultRow.deletedNoDayLine] instead, and it stays
     * [io.silencelen.andvari.core.app.SharedVaultRow.deleted].
     */
    var servesGraceDay: Boolean = true

    /**
     * The kept account's deletion was sent with no answer, and nothing since said whether it landed (as the engine keeps
     * it, across locks and a session the server ends): [io.silencelen.andvari.core.app.LockedScreen.deletionOutcomeUnknown]
     * on the lock screen, and [io.silencelen.andvari.core.app.EntryScreen.FirstRun.deletionOutcomeUnknown] after "Sign in
     * again". A lost deletion answer sets it; the account's next answer, a sign-out or the account's end clear it. A
     * screen test may set it itself (then publish, for example with a lock).
     */
    var deletionOutcomeUnknown: Boolean = false

    /**
     * The owner's decision of 2026-11-16, on the fake: an account this phone holds stopped and locked because a verified
     * card names it as its server's operator. While set, the first screen carries
     * [io.silencelen.andvari.core.app.EntryScreen.FirstRun.heldAsOperator]; [io.silencelen.andvari.core.app.EntryApi.removeHeldOperatorAccount]
     * clears it. A screen test sets it, then reaches the first screen (or calls [changed]).
     */
    var heldAsOperator: HeldOperator? = null

    /** [heldAsOperator]'s account: its address, its server's name and address, and the changes not sent (null: not known). */
    class HeldOperator(val email: String, val serverName: String, val origin: String, val unsentChanges: Int?)

    /** The owner has no space left for another vault. */
    var noSpaceForVaults: Boolean = false

    /**
     * "Move everything": the old vault's delete gets no answer. The move stops at [io.silencelen.andvari.core.app.MoveStage.DELETE_OLD_VAULT]
     * with [io.silencelen.andvari.core.app.CopyKey.MOVE_DELETE_UNCONFIRMED], the old vault still there (not deleted);
     * set back to false, moving again finishes it.
     */
    var moveDeleteUnanswered: Boolean = false

    /**
     * As the engine's "Move everything" whose finishing run meets a half-made vault of an earlier try that holds items the
     * move did not make: that vault is kept as a vault of its own (named as the new vault, with the member the move removes
     * still in it), and a note says so until dismissed ([io.silencelen.andvari.core.app.AccountSnapshot.moveNotes]). The
     * number of those items, or null where this device cannot tell; 0 (the default): no such vault. Used once.
     */
    var nextMoveKeepsHalfMade: Int? = 0

    /** As the engine's finishing run that kept earlier copies beside newer ones, counted by reason, said in a note until dismissed. Used once. */
    var nextMoveKeptBeside: KeptBeside? = null

    /** Earlier copies a move kept beside newer ones: changed there since, with no revision to compare, refused by the server. */
    class KeptBeside(val changed: Int, val noRevision: Int, val refused: Int)

    /**
     * As the engine's "Move everything" while a change made on this device to the old vault waits and is not the move's (the
     * person's own deletion of it, a change of a role): each run makes and fills the new vault, then stops at
     * [io.silencelen.andvari.core.app.MoveStage.DELETE_OLD_VAULT] with [io.silencelen.andvari.core.app.CopyKey.MOVE_OTHER_CHANGE_WAITING]
     * and SENT_PENDING, the old vault untouched and open for writing. Set back to false (the change settled), moving again
     * finishes it.
     */
    var moveOtherChangeWaiting: Boolean = false

    /** As the engine's run of "Move everything" that meets one of [MoveStopAt]'s stops. Used once. */
    var nextMoveStop: MoveStopAt? = null

    /** The stops of the engine's "Move everything" that [nextMoveStop] plays. */
    enum class MoveStopAt {
        /**
         * An item of the old vault moved after the move's read: the server refused its deletion, nothing is stored or held,
         * the old vault is open for writing again, and the run stops at TRANSFER_ITEMS with CHANGED_MEANWHILE; moving again
         * carries what is late and finishes.
         */
        OLD_VAULT_CHANGED_AFTER_READ,

        /**
         * An item of a half-made vault of an earlier try moved after its read: its deletion was refused, nothing is stored,
         * and the run stops before the new vault is made, at DELETE_OLD_VAULT with CHANGED_MEANWHILE (no item copied yet);
         * the next run reads that vault again.
         */
        HALF_MADE_CHANGED_AFTER_READ,

        /**
         * The old vault froze on this device while the move's deletion of it waited (found at the run's own first read): the
         * held deletion is dropped and not sent, the old vault stays (frozen, read-only here), and the run stops before
         * anything else, at DELETE_OLD_VAULT with READ_ONLY and [io.silencelen.andvari.core.app.CopyKey.MOVE_OLD_VAULT_FROZEN],
         * keeping the old vault's mark of a waiting deletion and offering no fresh start; every later run stops the same way.
         * (A freeze found at the deletion's re-post is [OLD_VAULT_FROZEN_AT_RESEND].)
         */
        OLD_VAULT_FROZEN,

        /**
         * The move's deletion of the old vault waited, and its re-send is refused because the old vault is frozen on this
         * device (the server named the deletion stored at a place where another entry stands): nothing more is sent, the old
         * vault stays frozen and read-only (never opened for writing again), and the run stops at DELETE_OLD_VAULT with
         * READ_ONLY and [io.silencelen.andvari.core.app.CopyKey.MOVE_OLD_VAULT_FROZEN].
         */
        OLD_VAULT_FROZEN_AT_RESEND,
    }

    /**
     * As the engine's run that meets a half-made vault of an earlier try frozen on this device: that vault is kept as a vault
     * of its own (frozen, named as the new vault, with the member the move removes still in it), a note says so until
     * dismissed, and the move goes on with a new vault. Used once.
     */
    var nextMoveHalfMadeFrozen: Boolean = false

    /**
     * The app's process ends and starts again on this device: what lives in memory goes (the open vault and every screen,
     * the journey, the notices kept in memory, the objects last shown); what the device keeps stays (the kept account and
     * its copy, the pins, a move's notes). The app starts again, locked where an account is kept.
     */
    fun restart() = app.restart()

    /**
     * The server stores a "Move everything" deletion that waits ([moveDeleteUnanswered]) later, outside the move, after
     * [added] items were added and [changed] changed in the old vault since the copies: the old vault is deleted, and
     * [io.silencelen.andvari.core.app.AccountSnapshot.movesStoredOutside] says so, as the engine does. False when no
     * move's deletion waits.
     */
    fun serverStoresMoveDeleteLater(added: Int, changed: Int): Boolean {
        val s = app.session ?: return false
        val v = s.account.vaults.firstOrNull { it.moveDeleteWaiting } ?: return false
        v.storedOutsideInto = v.moveUnfinishedInto.orEmpty()
        v.moveUnfinishedInto = null
        v.moveDeleteWaiting = false
        app.fakeContent?.markVaultClosedForWriting(v.vaultId, null)
        v.lateAdded = added
        v.lateChanged = changed
        v.deletionsKept = moveDeletionsKept
        moveDeletionsKept = 0
        v.itemCount += added
        v.purgeAtMs = app.nowMs + 7 * DAY
        v.seq++
        if (s.moving?.vault === v) s.moving = null
        app.publish()
        return true
    }

    /**
     * The account-ID check takes two steps, as the engine's does: the first
     * [io.silencelen.andvari.core.app.EntryApi.acceptRecoveredAccount] shows the screen again with `confirming`, the
     * second goes on. False (the default) until the apps take the second step; then it becomes the default.
     */
    var checkAccountConfirmStep: Boolean = false

    /** The next vault action is signed and gets no answer: it stays pending. */
    var appendGetsNoAnswer: Boolean = false

    // ---- a change to a shared vault that waits (§3.7), as the engine reports it ----

    private fun sharedNamed(name: String): FakeVault? = app.session?.account?.vaults?.firstOrNull { it.name == name }

    /**
     * A change of [kind] this device signed for the shared vault called [vaultName] waits to be sent again ([known]: what
     * the engine knows of it), naming the member [memberId] (a member of the vault) with [role] where it gives one. As the
     * engine: since now, and a deletion is not asked about before a look. False when no such vault is open.
     */
    fun changeWaits(
        vaultName: String, kind: io.silencelen.andvari.core.app.WaitingKind,
        known: io.silencelen.andvari.core.app.WaitingKnown = io.silencelen.andvari.core.app.WaitingKnown.CANNOT_TELL,
        memberId: String? = null, role: io.silencelen.andvari.core.app.RoleInVault? = null,
    ): Boolean {
        val v = sharedNamed(vaultName) ?: return false
        v.waiting = FakeWaiting(kind, memberId, role, app.nowMs, known)
        v.changeWaiting = true
        app.publish()
        return true
    }

    /** The look in the log of [vaultName] (nothing sent) found its deletion still waiting: it is asked about, as after an unlock. */
    fun waitingDeletionLooked(vaultName: String): Boolean {
        val w = sharedNamed(vaultName)?.waiting?.takeIf { it.kind == io.silencelen.andvari.core.app.WaitingKind.DELETION } ?: return false
        w.looked = true
        app.publish()
        return true
    }

    /** The waiting change of [vaultName] has its first request out ([requestOut]), or no longer. */
    fun waitingFirstRequestOut(vaultName: String, requestOut: Boolean = true): Boolean {
        val w = sharedNamed(vaultName)?.waiting ?: return false
        w.firstOut = requestOut
        app.publish()
        return true
    }

    /**
     * The server's answer about the waiting change of [vaultName] and its log contradict each other at a read: the vault
     * freezes, the change is dropped and nothing is said of it (no notice), as the engine plays it.
     */
    fun waitingVaultFreezes(vaultName: String): Boolean {
        val v = sharedNamed(vaultName) ?: return false
        v.log = io.silencelen.andvari.core.app.VaultLogState.FROZEN
        v.waiting = null
        v.changeWaiting = false
        app.publish()
        return true
    }

    /**
     * What a read found about a change of [vaultName] this device let go of or sent again: a notice with [key], undone by
     * [undo] where it was made after all, the waiting change gone (as the engine's settle drops it).
     */
    fun waitingFound(
        vaultName: String, key: io.silencelen.andvari.core.app.CopyKey, undo: io.silencelen.andvari.core.app.WaitingUndo? = null,
        kind: io.silencelen.andvari.core.app.WaitingKind? = null,
    ): Boolean {
        val s = app.session ?: return false
        val v = sharedNamed(vaultName) ?: return false
        val w = v.waiting
        v.waiting = null
        v.changeWaiting = false
        app.shared.found(s, v, kind ?: w?.kind ?: io.silencelen.andvari.core.app.WaitingKind.OTHER, w?.memberId, key, undo)
        app.publish()
        return true
    }

    /** The next "Delete it now" is sent and gets no answer: it still waits, and is asked about again after a later look. */
    var deleteNowGetsNoAnswer: Boolean = false

    /** The device's clock runs ahead of the server's by more than ten minutes. */
    var clockAhead: Boolean = false

    // ---- the clock ----

    /** The fake's time, unix milliseconds. It moves only by [advance]. */
    val nowMs: Long get() = app.nowMs

    /** Let [ms] pass: links, codes, device-link steps, holds and offers that run out do so. */
    fun advance(ms: Long) {
        app.nowMs += ms
        app.entryFlow.tick()
        app.session?.let { app.people.tick(it) }
        app.publish()
    }

    /** The world was changed by hand: publish a snapshot of it. */
    fun changed() = app.publish()

    // ---- the session ----

    /**
     * This device already holds a locked session of [account], on a server it pinned when it signed in: the app
     * starts on the lock screen. Call before [FakeAppApi.start].
     */
    fun storeSession(account: FakeAccount) {
        app.pin(account.server, if (account.server === app.baked) PinRoot.BAKED else PinRoot.TRUST_GATE, null)
        app.storedSession = account.server to account
        app.formatMarker = true
    }

    /** This install already ran the first-launch wipe. Call before [FakeAppApi.start]. */
    fun wipeAlreadyDone() {
        app.formatMarker = true
    }

    /** The vault locks, as [io.silencelen.andvari.core.app.AppApi.lock] does (an auto-lock, say). */
    fun lock() = app.lock()

    /**
     * The person unlocks with the stored account's own master password, through
     * [io.silencelen.andvari.core.app.AppApi.unlock]: prompts that were put off "until the next unlock" return.
     */
    fun unlock() {
        val screen = app.snapshot.locked ?: return
        val stored = app.storedSession ?: return
        FakeRun.now { app.unlock(screen, stored.second.password) }
    }

    /**
     * Sign in as [account] without walking the journey: this device is one the account was created on, so its
     * contacts are current here and it holds its own record of the recovery choice.
     */
    fun signedInAs(account: FakeAccount) {
        if (app.phase == AppPhase.STARTING) app.start()
        app.pin(account.server, if (account.server === app.baked) PinRoot.BAKED else PinRoot.TRUST_GATE, null)
        app.beginSession(account.server, account, HowDeviceJoined.REGISTERED, "", allContactsCurrent = true)
        app.openVault()
    }

    /** This device signed in to [account] before and was not revoked since: the account knows it (§8.7). */
    fun thisDeviceIsKnownTo(account: FakeAccount) {
        account.knownDevices += app.deviceId
    }

    /**
     * The server ended this device's session (it was revoked elsewhere, or the account was disabled). As the engine
     * (design §4.4): the account stays here as signed out by the server, on its lock screen
     * ([io.silencelen.andvari.core.app.LockedScreen.signedOutByServer]), its copy kept and opened read-only.
     */
    fun sessionEndedByServer() = app.endedByServer()

    /**
     * This device could not confirm its session with its server in time (as the engine's end where no try of a refresh is
     * left): kept like [sessionEndedByServer], and said as its own end
     * ([io.silencelen.andvari.core.app.LockedScreen.sessionNotConfirmed]).
     */
    fun sessionNotConfirmed() = app.endedUnconfirmed()

    /**
     * A handover made the signed-in account its server's operator, and the app checked the newest card (§12.2 rule 7):
     * a phone stops using it and keeps it locked ([heldAsOperator], the owner's decision of 2026-11-16) with
     * [io.silencelen.andvari.core.app.FirstRunNotice.OPERATOR_NEEDS_COMPUTER]; the desktop app keeps it open.
     */
    fun handoverMadeThisAccountTheOperator() {
        val s = app.session ?: return
        if (app.takesSetupLinks) return
        heldAsOperator = HeldOperator(s.account.email, s.server.name, s.server.origin, unsentChanges = null)
        app.endSession(io.silencelen.andvari.core.app.FirstRunNotice.OPERATOR_NEEDS_COMPUTER)
    }

    /** This device's pins for [server] are gone, as after "Forget this server". */
    fun dropPins(server: FakeServer) {
        app.pins.remove(server.origin)
        app.forked -= server.origin
        app.damaged -= server.origin
    }

    /** This device already holds a pin for [server]: it passed the Trust Gate for it some time ago. */
    fun thisDevicePins(server: FakeServer) {
        app.pin(server, PinRoot.TRUST_GATE, null)
    }

    /**
     * This device's stored pin for the server it is signed in to no longer decodes (§4.4): the server is blocked
     * until it is forgotten. With [server] given, that server's record instead.
     */
    fun pinRecordDamaged(server: FakeServer?) {
        val target = server ?: app.sessionServer ?: return
        app.pin(target, PinRoot.TRUST_GATE, null)
        app.damaged += target.origin
        app.publish()
    }

    // ---- the instance card of the server this app is signed in to ----
    //
    // For a server the app is not signed in to, set what it serves on the [FakeServer] itself
    // ([FakeServer.movedUnderPinTo], [FakeServer.kindChangedUnderPin], [FakeServer.servesOlderChain], …).

    /** The server serves an older card chain than this device pinned. */
    fun cardWithheld() = onSessionServer { it.servesOlderChain = true }

    /**
     * The served chain no longer contains the pinned card: the app stops using the instance. The fork is stored with
     * the pin, so setting [FakeServer.identityChanged] back does not lift it; only "Forget this server" does.
     */
    fun cardForked() = onSessionServer {
        it.identityChanged = true
        app.forked += it.origin
    }

    /** A newer card does not verify. */
    fun cardNotVerified() = onSessionServer { it.newerCardDoesNotVerify = true }

    /** The operator signed a move to [origin]. A store build of the baked instance shows "Update andvari" instead. */
    fun cardMoved(origin: String) = onSessionServer { it.movedUnderPinTo = origin }

    /** The operator signed a card with the other `kind`. A store build of the baked instance shows "Update andvari" instead. */
    fun cardKindChanged() = onSessionServer { it.kindChangedUnderPin = true }

    /** The server serves the chain this device pinned again. A fork stays (§4.4). */
    fun cardOk() = onSessionServer {
        it.servesOlderChain = false
        it.newerCardDoesNotVerify = false
        it.movedUnderPinTo = null
        it.kindChangedUnderPin = false
    }

    private fun onSessionServer(change: (FakeServer) -> Unit) {
        val server = app.sessionServer ?: return
        change(server)
        app.publish()
    }

    // ---- linking this device: the existing device's part ----

    /** The existing device verified this device's claim, sent its nonce, and this device revealed: the code shows. */
    fun otherDeviceAnswers() = app.entryFlow.otherDeviceAnswers()

    /** The person typed this device's digits into the existing device and approved there. */
    fun otherDeviceApproves() = app.entryFlow.otherDeviceApproves()

    /** The existing device cancelled, or the digits typed there did not match. */
    fun otherDeviceCancels() = app.entryFlow.endLink(LinkDeviceEnd.CANCELLED)

    /** The server showed a second, different nonce, or an approval that fails its checks. */
    fun linkFailsItsChecks() = app.entryFlow.endLink(LinkDeviceEnd.DID_NOT_CHECK_OUT)

    /** Someone else claimed [deviceLink] before this device did. */
    fun someoneElseClaims(deviceLink: String) {
        app.deviceLinks[FakeText.shape(deviceLink).second]?.claimedByOther = true
    }

    /** The existing device cancelled [deviceLink], or made a newer one. */
    fun cancelDeviceLink(deviceLink: String) {
        app.deviceLinks[FakeText.shape(deviceLink).second]?.step = FakeLinkStep.CANCELLED
    }

    /** The bundle the existing device made names another server than the one this device pinned. */
    var bundleDisagreesWithPin: Boolean = false

    /** The bundle does not open under the account's key. */
    var bundleDoesNotOpen: Boolean = false

    // ---- linking a new device from this one: the new device's part ----

    /** A device called [name] claims the link this device shows. */
    fun joiningDeviceClaims(name: String, platform: AppPlatform) = app.ownPart.host { h ->
        if (h.step == FakeHostStep.SHOWN) {
            h.name = name
            h.platform = platform
            h.step = FakeHostStep.CLAIMED
            h.expiresAtMs = app.nowMs + 5 * MINUTE
        }
    }

    /** The new device reveals its nonce; [matches] false: it is not the one it committed to. */
    fun joiningDeviceReveals(matches: Boolean) = app.ownPart.host { h ->
        if (h.step == FakeHostStep.CLAIMED) {
            if (matches) {
                h.step = FakeHostStep.TYPE_DIGITS
                h.expiresAtMs = app.nowMs + 5 * MINUTE
            } else {
                h.end(DeviceLinkHostEnd.DID_NOT_CHECK_OUT)
            }
        }
    }

    /** The six digits the new device shows. */
    val joiningDeviceCode: String get() = app.session?.hostLink?.code.orEmpty()

    /**
     * The new device proved the master password and picked up: it is a device of the account now. This device is not
     * told: its link stays on [io.silencelen.andvari.core.app.DeviceLinkHost.Approved], and the new device shows in
     * "Your devices".
     */
    fun joiningDevicePicksUp() = app.ownPart.host { h ->
        if (h.step == FakeHostStep.APPROVED && !h.pickedUp) {
            val account = app.session!!.account
            account.addDevice(h.name, h.platform, HowDeviceJoined.LINKED).also {
                it.linkedFrom = app.deviceName
                it.addedAtMs = app.nowMs
            }
            h.pickedUp = true
        }
    }

    /** Another device of the account made a newer device link: this one is cancelled (S3-C3). */
    fun newerLinkMadeElsewhere() = app.ownPart.host { h -> if (h.step != FakeHostStep.ENDED) h.end(DeviceLinkHostEnd.CANCELLED) }

    // ---- links this device made, and contacts ----

    /** Someone calling themselves [name] answers [link]: they become a contact, uncompared, and the codes are ready. */
    fun someoneAnswers(link: OwnLinkRow, name: String): FakeContact? = app.people.answered(link.linkId, name)

    /** [contact], a contact already, answers [link] under another key: the key-change prompt, from the creator's side. */
    fun contactAnswersUnderNewKey(link: OwnLinkRow, contact: FakeContact): Boolean = app.people.answeredUnderNewKey(link.linkId, contact)

    /** The creator of the link this account answered posted the reveal: the codes are ready. */
    fun revealArrives(contact: FakeContact) {
        contact.codesReady = true
        app.publish()
    }

    /**
     * The six digits the contact [userId] reads out from their own screen: the other side's code, which this app never
     * shows (§6.11). Null when the signed-in account has no such contact.
     */
    fun codeTheyReadOut(userId: String): String? = app.session?.account?.contacts?.firstOrNull { it.userId == userId }?.theirCode

    /** A second, different nonce was seen for the link with [contact]: it failed, and no code is shown. */
    fun linkFails(contact: FakeContact) {
        contact.linkFailed = true
        app.publish()
    }

    /**
     * Another device of the account, which the person named [deviceName], connected with someone called [label].
     * The device is in the account's list (it is added when no device there has that name), so the prompt can name it.
     */
    fun otherDeviceAddsContact(label: String, deviceName: String): FakeContact? {
        val account = app.session?.account ?: return null
        val device = account.devices.firstOrNull { it.name == deviceName } ?: account.addDevice(deviceName, AppPlatform.UNKNOWN, HowDeviceJoined.PASSWORD)
        val contact = account.addContact(label, compared = false)
        contact.madeOnDeviceId = device.deviceId
        contact.connectedAtMs = app.nowMs
        app.publish()
        return contact
    }

    /**
     * A contact called [label] turns up in the account's record, made by a device the account's list does not name
     * (a device that was revoked since, or an id a hostile page wrote, R24): the prompt says "another of your devices".
     */
    fun unnamedDeviceAddsContact(label: String): FakeContact? {
        val account = app.session?.account ?: return null
        val contact = account.addContact(label, compared = false)
        contact.connectedAtMs = app.nowMs
        app.publish()
        return contact
    }

    /** A known contact shows up under another key (another device's record, or an answer to a link). */
    fun contactKeyChanges(contact: FakeContact) {
        contact.keyChangeWaiting = true
        contact.codesReady = true
        contact.code = FakeText.digits6("newkey:${contact.userId}")
        app.publish()
    }

    // ---- shared vaults ----

    /**
     * [contact] shares a vault called [name] with the signed-in account: a prompt when the contact is current on
     * this device; otherwise a vault that waits for the contact to be confirmed on this device
     * ([VaultLogState.CONFIRM_FIRST]), and becomes that prompt once they are. A list of people that was put off
     * comes back, since now it matters.
     */
    fun contactSharesVault(contact: FakeContact, name: String): FakeVault? {
        val session = app.session ?: return null
        val vault = FakeVault("vault-in-${app.serial++}", name)
        vault.role = RoleInVault.WRITER
        vault.addMember(contact.label, RoleInVault.OWNER, contact)
        vault.members += FakeMember(session.account.userId, "", RoleInVault.WRITER, null)
        if (contact.userId in session.currentContacts) {
            vault.incomingFrom = contact.label
            vault.incomingAddSeq = vault.seq++
        } else {
            vault.log = VaultLogState.CONFIRM_FIRST
            vault.sharedByServerName = contact.label
            vault.sharedByContact = contact
            app.peoplePutOff -= session.account.userId
        }
        session.account.vaults += vault
        app.publish()
        return vault
    }

    /** Someone the account is not connected with, whom the server calls [serverName], shares a vault. */
    fun strangerSharesVault(serverName: String): FakeVault? {
        val session = app.session ?: return null
        val vault = FakeVault("vault-in-${app.serial++}", "")
        vault.role = null
        vault.log = VaultLogState.CONNECT_FIRST
        vault.sharedByServerName = serverName
        session.account.vaults += vault
        app.publish()
        return vault
    }

    /** The owner removed the account from [vault] and added it again: the earlier answer no longer counts (FS-R6). */
    fun ownerAddsAgain(vault: FakeVault) {
        val session = app.session ?: return
        session.hidden -= vault.vaultId
        vault.log = VaultLogState.VERIFIED
        vault.incomingFrom = vault.members.firstOrNull { it.role == RoleInVault.OWNER }?.contact?.label ?: "the owner"
        vault.incomingAddSeq = vault.seq++
        app.publish()
    }

    /** The owner of [vault] offers its ownership to the signed-in account, for [days]. */
    fun ownerOffersOwnership(vault: FakeVault, days: Int) {
        val me = app.session?.account ?: return
        vault.offer = FakeOffer(me.userId, app.nowMs + days * DAY)
        app.publish()
    }

    // ---- recovery ----

    /** Someone asks the operator to reset the signed-in account, from a device that says it is [platform]; the request is in its hold. */
    fun someoneAsksOperator(platform: AppPlatform): FakeHelpRequest? {
        val account = app.session?.account ?: return null
        val request = FakeHelpRequest("request-${app.serial++}", account.server, account.email, app.nowMs, codeMailed = true, platform = platform)
        request.stage = OperatorHelpStage.HOLDING
        request.verifiedAtMs = app.nowMs
        request.holdEndsAtMs = app.nowMs + 7 * DAY
        account.helpRequests += request
        app.publish()
        return request
    }

    /** The instance's recovery key changes with no statement the old key signed. */
    fun recoveryKeyChangesUnsigned() {
        val server = app.sessionServer ?: return
        server.unsignedRecoveryKeyChange = true
        server.accounts.values.filter { it.whoCanRecover == WhoCanRecover.ME_OR_OPERATOR }.forEach { it.recoveryKeyChangedUnsigned = true }
        app.publish()
    }

    /**
     * The operator answers the request this device made. False: the server refused, because the hold has not passed
     * or the request was cancelled. [forged]: the answer is not signed by the recovery key the pinned card names.
     */
    fun operatorAnswers(forged: Boolean): Boolean {
        val request = app.helpRequest ?: return false
        app.entryFlow.tick()
        if (request.stage != OperatorHelpStage.AWAITING_OPERATOR) return false
        request.fulfilled = true
        request.answerForged = forged
        return true
    }

    /**
     * As [operatorAnswers], with a genuine answer that delivers [account] instead of the account the person asked
     * for: a member working with the server pointed their own request at this device's request key (§9.3 step 4).
     * Every check passes; only the account ID on the check screen differs.
     */
    fun operatorAnswersWithAnotherAccount(account: FakeAccount): Boolean {
        val answered = operatorAnswers(forged = false)
        if (answered) app.helpRequest?.delivers = account
        return answered
    }

    /** A signed-in device of the account cancels the request this device made. */
    fun accountDeviceCancelsRequest() {
        app.helpRequest?.stage = OperatorHelpStage.VETOED
    }

    /**
     * The server's recovery key changes while the request this device made is open. [signed]: by
     * rotations the old key signed ([byOldKey]), which the device follows and says ([io.silencelen.andvari.core.app.AssistKeyChange.byOldKey]),
     * dated now. Not signed: every look stops with the warning, nothing of an answer is opened, and the request is kept.
     * False when this device holds no request.
     */
    fun recoveryKeyChangesWhileRequestOpen(byOldKey: Boolean): Boolean {
        val request = app.helpRequest ?: return false
        if (byOldKey) {
            request.keyRotatedAtMs = app.nowMs
            request.keyChangedUnsigned = false
        } else {
            request.keyChangedUnsigned = true
        }
        app.publish()
        return true
    }

    /** A signed rotation covering an earlier unsigned change is served after all: the request goes on. */
    fun recoveryKeyChangeSignedLater(): Boolean = recoveryKeyChangesWhileRequestOpen(byOldKey = true)

    /** The server answers 404 for the request this device made (it lost the row, or lies); [known] false undoes it. */
    fun serverForgetsRequest(known: Boolean = false): Boolean {
        val request = app.helpRequest ?: return false
        request.unknownToServer = !known
        return true
    }

    /**
     * The server cancelled the request this device made, before its code was typed: the account's owner changed the
     * password or the recovery setting, or the account was recovered. The code step answers REQUEST_CANCELLED, and the
     * request is forgotten here.
     */
    fun serverCancelsRequest(): Boolean {
        val request = app.helpRequest ?: return false
        request.cancelledByServer = true
        return true
    }

    /**
     * Whoever runs the server ends the request this device made (as the server's command after a restore does): before its
     * mailed code it is cancelled (the code step answers REQUEST_CANCELLED); after it, it is refused, with any answer the
     * operator gave dropped (a look says VETOED; a commit of an answer already opened here answers REQUEST_ENDED). The
     * device is told the same states as for the account's own causes. False when this device holds no request.
     */
    fun serverEndsRequest(): Boolean {
        val request = app.helpRequest ?: return false
        if (request.stage == OperatorHelpStage.CODE_NEEDED) {
            request.cancelledByServer = true
        } else {
            request.stage = OperatorHelpStage.VETOED
            request.fulfilled = false
        }
        return true
    }

    /**
     * The answer on the server is no longer the one this device opened (the operator uploaded another, or it was
     * damaged): the commit is refused, the request is kept, and the operator must upload again.
     */
    fun operatorAnswerReplaced(): Boolean {
        val request = app.helpRequest?.takeIf { it.fulfilled } ?: return false
        request.answerReplaced = true
        return true
    }

    /**
     * A recovery this device's person left after its new password was sent is answered now: the first screen says what
     * it came to ([io.silencelen.andvari.core.app.EntryScreen.FirstRun.lateRecovery]), for [email] at the first server
     * this device knows (or the request's).
     */
    fun leftRecoveryAnswered(
        result: io.silencelen.andvari.core.app.LateRecoveryResult,
        via: io.silencelen.andvari.core.app.RecoveryRoute = io.silencelen.andvari.core.app.RecoveryRoute.OPERATOR_HELP,
        email: String = app.helpRequest?.email ?: "alex@example.com",
    ): Boolean {
        val server = app.helpRequest?.server ?: app.servers.values.firstOrNull() ?: return false
        app.entryFlow.lateOutcome(io.silencelen.andvari.core.app.LateRecoveryNotice(email, app.label(server), via, result))
        return true
    }

    /**
     * The signed-in account's list of requests, as the server sends it: [unreadableRows] rows this
     * device cannot read (dropped and counted), or [unreadable] the whole list. Both raise the alert.
     */
    fun requestListServed(unreadableRows: Int = 0, unreadable: Boolean = false) {
        val account = app.session?.account ?: return
        account.unreadableHelpRows = unreadableRows
        account.helpListUnread = unreadable
        account.unreadableHelpDismissed = false
        app.publish()
    }

    internal companion object {
        const val MINUTE = 60_000L
        const val HOUR = 60 * MINUTE
        const val DAY = 24 * HOUR
    }
}

/** A signed-in session on the fake's device. */
internal class FakeSession(
    val server: FakeServer,
    val account: FakeAccount,
    /** The device signed in with only the password: none of the account's contacts is current here (§8.5). */
    val passwordOnly: Boolean,
    /** The contacts that count on this device (§6.9). */
    val currentContacts: MutableSet<String>,
) {
    /** The list of people is owed (§8.5): it is shown until it is answered, unless the person put it off. */
    var peopleListDue = false
    var keepOperatorNotNow = false
    var keyChangedLater = false

    /** Vaults declined, or removed from this device. */
    val hidden = HashSet<String>()

    var contactsOpen = false
    var comparing: String? = null
    var linksOpen = false
    val ownLinks = ArrayList<FakeOwnLink>()

    /** Links of this device answered in this session, newest first, until their contact is compared. */
    val answered = ArrayList<FakeAnswered>()
    var opened: FakeOpened? = null

    /** Why the link just opened is not used here ([io.silencelen.andvari.core.app.AccountSnapshot.inviteNotUsed]). */
    var notUsed: io.silencelen.andvari.core.app.CopyLine? = null

    /** A registration through a connect link whose answer was not taken. */
    var connectionNotMade: FakeConnectionNotMade? = null
    var membersOf: String? = null
    var warning: FakeWarning? = null
    var moving: FakeMove? = null

    /** Moves that stopped and were closed, by the old vault: opening the move again carries on. */
    val movesStopped = HashMap<String, FakeMove>()

    /** The first screen's offers to finish a move the person put off ([SharedVaultsApi.unfinishedMoveLater]). */
    val movesPutOff = HashSet<String>()
    var devicesOpen = false

    /** What this device set for "New devices must be linked" in this session; null: not known here, as on the engine. */
    var requireLinkSetHere: Boolean? = null
    var hostLink: FakeHostLink? = null
    var recoveryOpen = false
    var reviewing = false
    var kit: FakeKitState? = null
    var deletionOpen = false
    var deletionPlanned = false
    var deletionRetrying = false
    var deletionUnknown = false
    var twoStepOpen = false

    /** A two-step enrolment awaiting its first code: the key shown. */
    var twoStepPending: String? = null
}

internal class FakeOwnLink(
    val linkId: String,
    val kind: OwnLinkKind,
    val shares: List<FakeShare>,
    val payload: String,
    val expiresAtMs: Long,
) {
    var open = true
}

internal enum class FakeOpenedKind { CONNECT, KEY_CHANGED, OTHER_INSTANCE, TRUST_GATE, SERVER_CHANGED, CONNECTED }

internal class FakeOpened(var kind: FakeOpenedKind, val invite: FakeInvite) {
    /** [FakeOpenedKind.CONNECTED]: the contact the answer made. */
    var contact: FakeContact? = null

    /** The pin opening this invite made where none existed: it goes again when the invite is dismissed (§4.4). */
    var madePin: io.silencelen.andvari.core.client.pin.GatePin? = null
}

internal class FakeAnswered(val linkId: String, val contact: FakeContact, val keyChanged: Boolean)

internal class FakeConnectionNotMade(val invite: FakeInvite, var why: io.silencelen.andvari.core.app.ConnectResult)

internal class FakeWarning(val vault: FakeVault, val contact: FakeContact, val role: MemberRole, val fromLink: Boolean)

internal class FakeMove(val vault: FakeVault, val sourceStays: Boolean, val short: Boolean, val removing: String? = null) {
    val ticked = HashSet<String>()
    var running = false
    var copied = 0
    var stop: io.silencelen.andvari.core.app.MoveStop? = null
    var finished: io.silencelen.andvari.core.app.MoveFinished? = null
    /** What the short run's check for space found ([io.silencelen.andvari.core.app.MoveEverythingScreen.space]). */
    var space: io.silencelen.andvari.core.app.content.SpaceCheck? = null
    /** The new vault a stopped run made, which the next run carries on into. */
    var made: FakeVault? = null
    /** The new vault's name a run stopped before making it (short of space), which the next run makes, as the engine's run keeps it. */
    var runName: String? = null
    /** The member an earlier run of this move removed from the old vault (the remove dialog's), for the notes of a later run. */
    var removedMember: FakeMember? = null
}

internal enum class FakeHostStep { SHOWN, CLAIMED, TYPE_DIGITS, APPROVABLE, APPROVED, ENDED }

internal class FakeHostLink(val payload: String, var expiresAtMs: Long, val code: String) {
    var step = FakeHostStep.SHOWN
    var name = ""
    var platform = AppPlatform.UNKNOWN
    var end = DeviceLinkHostEnd.CANCELLED

    /** [io.silencelen.andvari.core.app.DeviceLinkHost.Ended.line]: a line of its own where [end] has none that is true. */
    var endLine: io.silencelen.andvari.core.app.CopyKey? = null

    /** The new device picked up: nothing tells this device, and the link's screen stays on Approved. */
    var pickedUp = false

    /** [io.silencelen.andvari.core.app.DeviceLinkHost.Ended.wait]: the wait the server named with a too-many end. */
    var endWait: io.silencelen.andvari.core.app.NamedWait? = null

    fun end(outcome: DeviceLinkHostEnd, line: io.silencelen.andvari.core.app.CopyKey? = null, wait: io.silencelen.andvari.core.app.NamedWait? = null) {
        end = outcome
        endLine = line
        endWait = wait
        step = FakeHostStep.ENDED
    }
}

internal class FakeKitState(
    val account: FakeAccount,
    var reason: KitReason,
    var step: KitStep,
    /** The kit belongs to the signed-out journey ([EntryScreen.Kit]); otherwise to Settings. */
    val inEntry: Boolean,
    /** What follows once the kit is confirmed. */
    val then: () -> Unit,
) {
    var groups: List<Int> = emptyList()
    var tries = 0

    /** Shown with a refusal: no session holds the account ([io.silencelen.andvari.core.app.KitScreen.notKeptLine]). */
    var notKeptLine: io.silencelen.andvari.core.app.CopyKey? = null

    /** On show while the app was on show ([FakeAppApi.away] false): it may have been seen. */
    var seen: Boolean = true

    /** With [notKeptLine]: what stands in the way goes once no other account is kept here (as the engine's `KitMark`). */
    var whileAnotherKept: Boolean = false

    /** Made while a kit shown here before was never confirmed ([io.silencelen.andvari.core.app.KitScreen.earlierKitVoidLine]). */
    var replacesShown: Boolean = false

    /** The flow of the kit's screen in the signed-out journey: at the account's server. */
    val flow: FakeFlow = FakeFlow(account.server)
}
