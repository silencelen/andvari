package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.model.wire.AccountSummary
import io.silencelen.andvari.core.model.wire.AdminEscrowResponse
import io.silencelen.andvari.core.model.wire.AdminPolicy
import io.silencelen.andvari.core.model.wire.AdminRecoveryRequest
import io.silencelen.andvari.core.model.wire.AdminStatus
import io.silencelen.andvari.core.model.wire.AuditRow
import io.silencelen.andvari.core.model.wire.Device
import kotlinx.coroutines.flow.StateFlow

/**
 * The operator views (§9.2), for the desktop app and `andvari-cli operator` only. They are reached through
 * [DesktopAppApi.operatorApi]; nothing a phone app or the iOS bridge is handed leads here (§9.1, N9), and the web
 * client has no operator surface at all.
 *
 * What the console lists is the operator's own server speaking about its own accounts, so it is shown as served:
 * the wire's own types ([AccountSummary], [Device], [AdminPolicy], [AdminStatus], [AuditRow],
 * [AdminRecoveryRequest]) are used as they are, and nothing here is a trust decision of this device. The exception
 * is the instance's own name and origin, which come from the pinned card ([OperatorConsole.instance]).
 *
 * Every route marked † in §9.2 needs a fresh proof of the operator's master password, so each such intent takes it.
 * The operator's password is typed only into a native app or the CLI, never into anything the server serves.
 */
class OperatorConsole internal constructor(
    val instance: InstanceLabel,
    val details: InstanceDetails,
    /**
     * The instance serves no identity card: its setup stopped between registering the operator and signing card 0
     * (§6.7 Resume). Offer [CopyKey.FINISH_SERVER_SETUP]; until then every other registration is refused. The same
     * offer is made outside the console, at every unlock of the operator account in a desktop app:
     * [AccountPrompt.FinishServerSetup].
     */
    val setupUnfinished: Boolean,
    /** `GET /admin/status`; null until it answered. Its `mail.stalled` drives the banner of §11.4. */
    val status: AdminStatus?,
    /** `GET /admin/accounts`. */
    val accounts: List<AccountSummary>,
    /** The account whose devices are listed in [devices] ([OperatorApi.openAccountDevices]); null while none is open. */
    val devicesOfUserId: String?,
    val devices: List<Device>,
    /**
     * `GET /admin/recovery-requests`: the verified requests for help. **None carries the request code**, and no
     * intent here shows it: the operator gets it from the person and types it into `recovery-cli assist`, which
     * checks it against the request's key (T2-R-c). A code on screen could be copied without asking anyone.
     */
    val recoveryRequests: List<AdminRecoveryRequest>,
    /** `GET /admin/policy`; null until it answered. */
    val policy: AdminPolicy?,
    /** The rows the last [OperatorApi.loadAudit] brought. */
    val audit: List<AuditRow>,
    /**
     * The server's own counts disagree with its own list: [AdminStatus.userCount] is not the number of rows in
     * [accounts]. Both are shown as served; a screen may say the two do not match. Additive (false where nothing says).
     */
    val countsDisagree: Boolean = false,
    /**
     * A list the console read held rows the server should not have sent: a recovery request,
     * account or device with a field outside its grammar is not shown at all, and a display name, device name or client
     * version that is not plain text (control, direction-override, zero-width or line-separator characters, or over 64
     * bytes) is blanked. Say [CopyKey.OPERATOR_SERVER_SENT_BAD_ROWS] above the lists. Every value still shown in [accounts],
     * [devices] and [recoveryRequests] passed its check: ids are ids, addresses normalised addresses, a request's key 32
     * bytes of canonical base64url, a platform one of the closed list; names and versions are the server's text, drawn as
     * plain text only. Additive.
     */
    val serverSentBadRows: Boolean = false,
    /**
     * The server said it stored a card this account signed, and does not serve it yet. Until
     * the pin reaches it every card change answers [OperatorResult.CARD_STORED_NOT_SHOWN] and nothing is signed (no
     * second card at that number). Say [CopyKey.OPERATOR_CARD_STORED_NOT_SHOWN] in the card section. Additive.
     */
    val cardStoredNotShown: Boolean = false,
    /**
     * The recovery key the pinned card names (`hex64`, or `none`), and the instance id, both from this device's own pin,
     * never from a server's answer at the moment (what `recovery-cli assist` and `rotate` need). Null when no pin is
     * read. Additive.
     */
    val pinnedRecoveryFp: String? = null,
    val pinnedInstanceId: String? = null,
    /**
     * Why the last [OperatorApi.savePolicy] was refused ([OperatorResult.BAD_POLICY]), by the server's own reason: the key
     * cost below the server's floor ([CopyKey.OPERATOR_POLICY_KDF_TOO_WEAK]), a memory cost that is not a whole number of
     * KiB ([CopyKey.OPERATOR_POLICY_KDF_MEM_NOT_KIB]), or a field outside its bounds ([CopyKey.OPERATOR_POLICY_OUT_OF_BOUNDS]).
     * Show it beside the policy; the next save that is stored, a lock and the console's closing clear it. Null otherwise.
     * Additive. (The server's own message for the refusal does not reach this layer yet.)
     */
    val policyRefusal: CopyLine? = null,
) {
    val serverSentBadRowsLine: CopyKey? get() = if (serverSentBadRows) CopyKey.OPERATOR_SERVER_SENT_BAD_ROWS else null

    /**
     * The sentence for a recovery request whose copy the server says is sealed to another recovery key than the one the
     * pinned card names ([AdminRecoveryRequest.escrowFingerprint] present and not [pinnedRecoveryFp]): both recovery
     * sheets are needed, the current one, which signs the answer, and the outgoing one, which opens the copy. {0} is the
     * outgoing key's fingerprint, {1} the current one's. Null when the two are the same, when the server sent no key,
     * when no pin is read, or when the pinned card names no recovery key (`none`: no answer can be signed then). The
     * fingerprint is the server's word: it chooses what is said, never what is trusted. Show it on the request's row and
     * in its detail. Additive.
     */
    fun outgoingKeyLine(request: AdminRecoveryRequest): CopyLine? {
        val sealed = request.escrowFingerprint ?: return null
        val current = pinnedRecoveryFp?.takeIf { it != "none" } ?: return null
        if (sealed == current) return null
        return CopyLine.of(CopyKey.OPERATOR_COPY_ON_OUTGOING_KEY, sealed, current)
    }
}

/**
 * Why an account is deleted by the operator ([OperatorApi.deleteAccount]): a closed choice, never free text (spec 03
 * §7.1 row 76).
 */
enum class OperatorDeleteWhy {
    /** The 30-day rule: the account has been disabled for at least 30 days. */
    DISABLED_30_DAYS,

    /**
     * The account holder is under the minimum age (owner policy 2026-11-15): lifts the 30 days and nothing else. The
     * account must still be disabled first (the disable's email is the one that comes first).
     */
    UNDER_MINIMUM_AGE,
}

/** A per-account quota override (`PUT /admin/accounts/{id}/quota`): a limit, or null to return it to the instance's default. */
class QuotaLimits(val accountBytes: Long?, val items: Long?, val ownedSharedVaults: Long?, val openLinks: Long?)

/** Why an account is disabled: the wire's `DisableReason` values, typed. The person is told the category. */
enum class DisableWhy(val wireName: String) { ABUSE("abuse"), REQUEST("request"), OTHER("other") }

interface OperatorApi {
    /** The console while it is open; null otherwise. */
    val console: OperatorConsole?

    /** The console as a flow, for Compose. */
    val consoles: StateFlow<OperatorConsole?>

    fun observeConsole(listener: (OperatorConsole?) -> Unit): Subscription

    /** Open the console: status, accounts, policy and recovery requests. Only the operator account can ([OperatorResult.NOT_THE_OPERATOR]). */
    suspend fun openConsole(): OperatorResult

    fun closeConsole()

    suspend fun refreshConsole(): OperatorResult

    /**
     * "Finish setting up this server": sign card 0 from the setup offer this device kept, or from what the server
     * says `andvari setup` wrote, upload it and pin it. The server's own checks bind card 0 to the operator account
     * either way (§6.7 Resume, R10).
     */
    suspend fun finishServerSetup(password: String): OperatorResult

    // ---- accounts and devices ----

    /** † Disable an account: its sessions end and the person is emailed the reason's category. */
    suspend fun disableAccount(userId: String, why: DisableWhy, password: String): OperatorResult

    /** † Re-enable an account. The cap is not checked (S3-Q7). */
    suspend fun enableAccount(userId: String, password: String): OperatorResult

    /**
     * † Delete an account that has been disabled for at least 30 days (W2). No leaves are signed: its memberships
     * stay in the vaults' histories until each owner removes them (§3.11).
     */
    suspend fun deleteAccount(userId: String, password: String): OperatorResult

    /**
     * † [deleteAccount] with its reason, offered as a choice ([OperatorDeleteWhy]): [OperatorDeleteWhy.DISABLED_30_DAYS]
     * is [deleteAccount] itself; [OperatorDeleteWhy.UNDER_MINIMUM_AGE] lifts the 30 days for a disabled account. Additive
     * (a name of its own: the API has no overloads, for the iPhone's export).
     */
    suspend fun deleteAccountFor(userId: String, why: OperatorDeleteWhy, password: String): OperatorResult

    /**
     * The devices of [userId], an account of [OperatorConsole.accounts] (any other id sends nothing:
     * [OperatorResult.NO_SUCH_ACCOUNT]), read in pages: the list is shown only once its last page arrived.
     */
    suspend fun openAccountDevices(userId: String): OperatorResult

    fun closeAccountDevices()

    /** † Revoke a device of an account; the person is emailed. */
    suspend fun revokeAccountDevice(deviceId: String, password: String): OperatorResult

    /** † Override an account's quotas, for example before a large restore (§14.1). */
    suspend fun setAccountQuota(userId: String, limits: QuotaLimits, password: String): OperatorResult

    // ---- policy, audit ----

    /** † Store the policy. Its sign-up controls can only tighten ([OperatorResult.NOT_TIGHTER]); loosening is done on the host. */
    suspend fun savePolicy(policy: AdminPolicy, password: String): OperatorResult

    /**
     * `GET /admin/audit`: the rows since [sinceMs]. [type] and [userId], when given, narrow what
     * [OperatorConsole.audit] shows; **they are applied on this device**, to the rows the server sent (the route
     * has no filter of its own), so they save no traffic and hide nothing from the operator's own server.
     */
    suspend fun loadAudit(sinceMs: Long, type: String?, userId: String?): OperatorResult

    // ---- operator recovery (private instances; absent on a public one under variant R) ----

    /**
     * † Download an account's recovery copy, for `recovery-cli` on an offline machine. The person is emailed that
     * the operator downloaded it. The file is handed over once, by [takeEscrow].
     */
    suspend fun downloadEscrow(userId: String, password: String): OperatorResult

    /** The recovery copy the last [downloadEscrow] brought; null after it was taken once, or when there is none. */
    fun takeEscrow(): AdminEscrowResponse?

    /**
     * † Upload what `recovery-cli assist` produced for a request: [sealedAnswer] is what the operator gave (the tool's whole
     * output, or its last line, the answer token), read by the one shared reader against the listed request BEFORE the
     * password is touched (spec 04 §7 step 3); each refusal has its own result (the `ANSWER_` ones), never
     * [OperatorResult.REQUEST_NOT_READY]. The server refuses before the hold has passed or after a veto, and an answer for
     * another request key ([OperatorResult.ANSWER_OTHER_REQUEST_KEY]). Until the commit it may be uploaded again.
     */
    suspend fun fulfilRecovery(requestId: String, sealedAnswer: String, password: String): OperatorResult

    // ---- the instance card (§4.3): each is a new card this account's key signs ----
    //
    // The four intents below sign and upload a new card of the chain (the engine's `OperatorCards` flow). They are
    // part of this interface for good; an implementation that cannot sign a card yet answers [OperatorResult.FAILED].
    // Handing the operator role over to another account is not here: in this version it is done with the
    // command-line tool (`andvari-cli operator`), which is where the incoming operator's keys are checked.

    /** † Rename the instance. */
    suspend fun renameInstance(name: String, password: String): OperatorResult

    /** † Move the instance to [origin]. Devices follow after a one-tap prompt; store builds never follow a move of the public instance. */
    suspend fun moveInstance(origin: String, password: String): OperatorResult

    /**
     * † Change the instance's recovery key to the one [recoveryFingerprint] names. [rotationStatement] is what
     * `recovery-cli rotate` produced with the outgoing key; it is uploaded before the card. Without it the change is
     * unsigned: every account that chose operator recovery is then asked whether to keep it, with turning it off as
     * the default (§4.5).
     */
    suspend fun changeRecoveryKey(recoveryFingerprint: String, rotationStatement: String?, password: String): OperatorResult

    /** † Stop offering operator recovery (`recoveryFp = none`). */
    suspend fun removeRecoveryKey(password: String): OperatorResult
}

enum class OperatorResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    DONE,

    /** `403 reauth_failed`: that password is wrong. */
    WRONG_PASSWORD,

    /** As [ProofResult.KEYS_NOT_KNOWN_HERE]: never a wrong password while the session knows it. Additive. */
    KEYS_NOT_KNOWN_HERE(sentence = CopyKey.KEYS_NOT_KNOWN_HERE),

    /** As [ProofResult.PROOF_REFUSED]: the server refused a proof this device made; never a wrong password. Additive. */
    PROOF_REFUSED(sentence = CopyKey.SERVER_REFUSED_PROOF),

    /** `403 not_operator`: this account is not the instance's operator. */
    NOT_THE_OPERATOR,
    NO_SUCH_ACCOUNT,

    /** `400 cannot_target_self`: the operator cannot disable or delete its own account. */
    CANNOT_TARGET_SELF,

    /** `409 not_disabled_long_enough`: only an account disabled for 30 days can be deleted. */
    NOT_DISABLED_LONG_ENOUGH,

    /** `409 account_delete_blocked`: the account owns a shared vault that others hold. */
    BLOCKED_BY_SHARED_VAULT,
    NO_SUCH_DEVICE,

    /** `400 not_tighter`: the panel can only tighten sign-up (R7). */
    NOT_TIGHTER,

    /** The policy's key-derivation settings are below the floor, or not a whole number of KiB. */
    BAD_POLICY,

    /** `404 no_escrow`: the account did not choose operator recovery. */
    NO_ESCROW,

    /** `409 request_state`: the request is in its hold, vetoed, or gone. */
    REQUEST_NOT_READY,

    // ---- what the shared reader of an answer refused, before the password was touched (spec 04 §7 step 3) ----

    /** There is no answer in what was given. */
    ANSWER_EMPTY,

    /** The recovery copy (the file `recovery-cli assist` reads), not the answer it writes. */
    ANSWER_IS_THE_COPY,

    /** Not an answer from `recovery-cli assist`; also the server's `bad_sealed`, `bad_request_key`, `bad_commit_hash`. */
    ANSWER_NOT_AN_ANSWER,

    /** A sealed answer without its request (the old tool's form, or the token's tail): the whole last line is needed. */
    ANSWER_BARE,

    /** The tool made this answer for another request. */
    ANSWER_OTHER_REQUEST,

    /** The answer was made for another request key; also the server's `400 request_key_mismatch`. */
    ANSWER_OTHER_REQUEST_KEY,

    /** Shorter than an answer for this request's address: part of it is missing. */
    ANSWER_CUT_SHORT,

    /** Longer than an answer for this request's address. */
    ANSWER_TOO_LONG,

    /** `409 card_head_moved`: another device of this account signed a card meanwhile; refresh and ask again. */
    CARD_MOVED_ON,

    /** `400 bad_card`: the server refused the card (for one, a recovery key on a public instance under variant R). */
    CARD_REFUSED,

    /** `400 bad_rotation`: the rotation statement does not verify against the current recovery key. */
    ROTATION_REFUSED,

    /** The address fails the origin grammar. */
    NOT_AN_ADDRESS(sentence = CopyKey.ADDRESS_NEEDS_HTTPS_DOMAIN),

    /** There is nothing to finish: the instance already has its identity card. */
    SETUP_ALREADY_DONE,

    /**
     * F10: the server says it stored the card, and does not serve it yet ([OperatorConsole.cardStoredNotShown]); or one
     * stored earlier still holds its number, so nothing was signed now. Not "done": refresh later.
     */
    CARD_STORED_NOT_SHOWN(sentence = CopyKey.OPERATOR_CARD_STORED_NOT_SHOWN),

    /** This device refused the change before anything was sent (no change, a value outside its grammar, a recovery key on a public instance). Not the server's refusal. */
    CARD_REFUSED_HERE(sentence = CopyKey.OPERATOR_CARD_REFUSED_HERE),
    STALE(Trouble.STALE),
    UNREACHABLE(Trouble.UNREACHABLE),
    RATE_LIMITED(Trouble.RATE_LIMITED),
    UPDATE_REQUIRED(Trouble.UPDATE_REQUIRED),
    FAILED(Trouble.FAILED),
    ;

    override val done: Boolean get() = this == DONE

    companion object {
        /** The result for each refusal of the shared reader of an answer ([io.silencelen.andvari.core.trust.AnswerToken.read]). */
        fun of(refusal: io.silencelen.andvari.core.trust.AnswerRefusal): OperatorResult = when (refusal) {
            io.silencelen.andvari.core.trust.AnswerRefusal.EMPTY -> ANSWER_EMPTY
            io.silencelen.andvari.core.trust.AnswerRefusal.IS_THE_COPY -> ANSWER_IS_THE_COPY
            io.silencelen.andvari.core.trust.AnswerRefusal.NOT_AN_ANSWER -> ANSWER_NOT_AN_ANSWER
            io.silencelen.andvari.core.trust.AnswerRefusal.BARE -> ANSWER_BARE
            io.silencelen.andvari.core.trust.AnswerRefusal.OTHER_REQUEST -> ANSWER_OTHER_REQUEST
            io.silencelen.andvari.core.trust.AnswerRefusal.OTHER_REQUEST_KEY -> ANSWER_OTHER_REQUEST_KEY
            io.silencelen.andvari.core.trust.AnswerRefusal.CUT_SHORT -> ANSWER_CUT_SHORT
            io.silencelen.andvari.core.trust.AnswerRefusal.TOO_LONG -> ANSWER_TOO_LONG
        }
    }
}
