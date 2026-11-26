package io.silencelen.andvari.cli

import io.silencelen.andvari.core.model.wire.AdminRecoveryRequest
import io.silencelen.andvari.core.model.wire.RecoveryRequestState
import io.silencelen.andvari.core.trust.TrustGrammar
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

/** The message key of a server answer that holds a row this tool will not show (the row is left out, the command fails). */
const val KEY_SERVER_ROW_REFUSED = "server_row_refused"

/**
 * A verified, live assisted-recovery request, as the operator's listing shows it (design §9.3).
 * Built only by [ServedRows.request], after every field was checked, so nothing unchecked reaches the terminal or a
 * script. The server's account ID is not kept at all: it is a value a server could offer as a check, and the check
 * comes from the person (the account ID on their recovery kit), never from the server's row.
 *
 * [state] is the row's own (spec 03 §18.6): `holding`, `awaiting_operator` or `ready`, or null from a server that does
 * not send it. The listing holds rows still in their hold beside the ones past it, so each
 * row says its own state ([stateWords]) and no heading claims one for all of them.
 */
class ShownRequest internal constructor(
    val requestId: String, val userId: String, val email: String, val requestKey: String, val platform: String,
    val createdAt: Long, val verifiedAt: Long, val holdEndsAt: Long, val state: String?,
    /** The recovery key the server says the account's recovery copy is sealed to (`hex64`), or null when it sent none. */
    val escrowFingerprint: String? = null,
) {
    /** The `--json` row: the wire row's names, without `accountId`; `state` and `escrowFingerprint` null when the server sent none. */
    fun json(): JsonObject = buildJsonObject {
        put("requestId", JsonPrimitive(requestId)); put("userId", JsonPrimitive(userId)); put("email", JsonPrimitive(email))
        put("rPub", JsonPrimitive(requestKey)); put("platform", JsonPrimitive(platform))
        put("createdAt", JsonPrimitive(createdAt)); put("verifiedAt", JsonPrimitive(verifiedAt)); put("holdEndsAt", JsonPrimitive(holdEndsAt))
        put("state", state?.let(::JsonPrimitive) ?: JsonNull)
        put("escrowFingerprint", escrowFingerprint?.let(::JsonPrimitive) ?: JsonNull)
    }

    /**
     * The line for a row whose recovery copy the server says is sealed to another recovery key than the one the pinned card
     * names ([pinnedRecoveryFp], from this device's pin): both recovery sheets are needed, the current one, which signs the
     * answer, and the outgoing one, which opens the copy. Null when the two are the same, when the server sent no key, when
     * no pin is read, or when the pinned card names no recovery key (`none`). The rule of the shared code's console
     * (`OperatorConsole.outgoingKeyLine`), in the tool's words. The fingerprint is the server's word: it chooses what is
     * said, never what is trusted.
     */
    fun outgoingKeyLine(pinnedRecoveryFp: String?): String? {
        val sealed = escrowFingerprint ?: return null
        val current = pinnedRecoveryFp?.takeIf { it != "none" } ?: return null
        if (sealed == current) return null
        return fill(OUTGOING_KEY_LINE, sealed, current)
    }

    companion object {
        /**
         * The line (the tool's own sentence, not yet on the wording page; it replaces the shared console's words there,
         * entry NK8, which say that both sheets are needed, also where no sheet opens the copy): `{0}` the fingerprint the
         * server names for the copy, `{1}` the one the pinned card names. At this row the tool knows only those two: not
         * how the key changed. It leads with "The server says": the fingerprint is the server's word. What follows is what
         * `recovery-cli assist` does with either change: it opens such a copy only with the sheet of a key that signed
         * rotation statements lead from to the current one, and a card that named no recovery key ends that path (operator
         * recovery removed, then a key set again), so it then opens no sheet's copy and refuses the copy.
         */
        const val OUTGOING_KEY_LINE = "The server says this account's recovery copy was made for the recovery key {0}, not for {1}, " +
            "the one this server's card names now. If the key was changed by a signed rotation statement, recovery-cli assist needs " +
            "both recovery sheets: the current one signs the answer, and the earlier one opens the copy. If operator recovery was " +
            "turned off in between and a key set again later, no sheet opens this copy, and it can't be answered."
    }

    /** What this row's state means for the operator, in the row's own words. */
    fun stateWords(): String = when (state) {
        RecoveryRequestState.HOLDING -> "holding until ${at(holdEndsAt)} (not yet to be answered)"
        RecoveryRequestState.AWAITING_OPERATOR -> "waiting for the operator (the hold ended ${at(holdEndsAt)})"
        RecoveryRequestState.READY -> "answered (the person's device can finish; until it does, a corrected answer can replace it)"
        else -> "state not given by the server (the hold ends ${at(holdEndsAt)})"
    }

    private fun at(ms: Long): String = java.time.Instant.ofEpochMilli(ms).toString()
}

/** The checks a server's rows pass before this tool shows any part of them. */
object ServedRows {
    private val ACCOUNT_ID = Regex("^[0-9a-f]{32}$")

    /**
     * [r] when every field is what spec 03 says it is, else null: the request id `b64_16`, the user id a uuid, the address
     * an `emailNorm` already in its normal form, the server's account ID 32 lowercase hex digits (checked though never
     * shown), the request key canonical `b64_32`, the platform one of the closed list, the three times `ms`, and the state
     * absent or one of the three a listed request can be in, and the recovery key the copy is sealed to absent or `hex64`.
     */
    fun request(r: AdminRecoveryRequest): ShownRequest? {
        val ok = TrustGrammar.isB64_16(r.requestId) && TrustGrammar.isUuid(r.userId) && TrustGrammar.emailNorm(r.email) == r.email &&
            ACCOUNT_ID.matches(r.accountId) && TrustGrammar.isB64_32(r.rPub) && TrustGrammar.isPlatform(r.platform) &&
            TrustGrammar.isMs(r.createdAt) && TrustGrammar.isMs(r.verifiedAt) && TrustGrammar.isMs(r.holdEndsAt) &&
            (r.state == null || r.state in LISTED_STATES) && (r.escrowFingerprint == null || TrustGrammar.isHex64(r.escrowFingerprint!!))
        return if (ok) ShownRequest(r.requestId, r.userId, r.email, r.rPub, r.platform, r.createdAt, r.verifiedAt, r.holdEndsAt, r.state, r.escrowFingerprint) else null
    }

    private val LISTED_STATES = setOf(RecoveryRequestState.HOLDING, RecoveryRequestState.AWAITING_OPERATOR, RecoveryRequestState.READY)

    /** What the person reads when [refused] of the server's rows of [what] failed those checks. */
    fun refused(origin: String, what: String, refused: Int): CliError = CliError(
        "the server at $origin sent $refused $what that this device will not show (a field that is not what the protocol allows): " +
            "${if (refused == 1) "it was" else "they were"} left out, and nothing of ${if (refused == 1) "it" else "them"} was used. " +
            "That is a fault of the server's answer; tell whoever runs the server's host",
        EXIT_SERVER_ANSWER, KEY_SERVER_ROW_REFUSED,
    )
}
