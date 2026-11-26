package io.silencelen.andvari.core.client.account

import io.silencelen.andvari.core.client.pin.CardPin
import io.silencelen.andvari.core.client.pin.CardStatus

/**
 * What a card change came to (design §4.2, §4.3; spec 03 §17.2, §17.3). Every refusal spec 03 lists for
 * `PUT /instance/card` and `PUT /instance/rotation` has its own type; anything else the server answers is
 * [Refused] with its code.
 */
sealed class CardChangeResult {
    /**
     * The server stored the card ([hash]), and this device's own pin followed it through the normal refresh: [pin] is
     * the new newest card, now pinned.
     */
    class Changed internal constructor(val hash: String, val pin: CardPin) : CardChangeResult()

    /**
     * The server stored the card ([hash]), but this device's refresh did not simply land on it: [status] is what the
     * refresh said. A [CardStatus.Moved] (the operator moved the instance) is confirmed like anyone else's, through
     * [io.silencelen.andvari.core.client.pin.InstanceTrust.followMove]; a withheld or unreachable chain is retried on the
     * next probe. The pin was not written here.
     */
    class Stored internal constructor(val hash: String, val status: CardStatus) : CardChangeResult()

    /**
     * Before anything was built: this device's pin is not at the served chain's newest card ([status]: a fork, a
     * withheld chain, a move or kind change waiting for its prompt, or no answer). Nothing was derived or sent.
     */
    class NotCurrent internal constructor(val status: CardStatus) : CardChangeResult()

    /**
     * `403 not_operator`, or this device's own check before anything was sent: the session is not the operator account's,
     * or the pinned newest card does not name this account and its signing key, so this account cannot sign the next card.
     */
    data object NotOperator : CardChangeResult()

    /**
     * `409 card_head_moved {seq, hash}`: someone uploaded a card first, and this one is not the next. Nothing was stored.
     * [seq] and [hash] are the server's report of its head, shown for information only; the change is started again,
     * which refreshes the pin through the verified chain first.
     */
    data class HeadMoved(val seq: Long?, val hash: String?) : CardChangeResult()

    /** `400 bad_card`: the server's parse, chain, signature or field checks refused the card (a public card with a recovery key included). */
    data object BadCard : CardChangeResult()

    /** `409 handover_target_invalid`: the named account is not active, or on a public instance owns a shared vault. */
    data object HandoverTargetInvalid : CardChangeResult()

    /**
     * `400 bad_rotation` from the server ([verdict] null), or this device's own check of the 0x08 statements before
     * anything was sent ([verdict] is the §2.4 rotation verdict, e.g. `fp_mismatch`, `signer_not_pinned_key`). When
     * the server refused a later statement of a chain, earlier ones may be stored; the card was not sent.
     */
    data class BadRotation(val verdict: String?) : CardChangeResult()

    /** A recovery key on a `public` card (variant R, design §7.7, spec 03 §18.6): refused here, nothing sent. */
    data object PublicRefusesRecoveryKey : CardChangeResult()

    /**
     * The requested change itself is refused here, before the password is touched: [code] is [WireOperatorCards.BAD_NAME],
     * [WireOperatorCards.BAD_ORIGIN], [WireOperatorCards.BAD_KEY], [WireOperatorCards.HANDOVER_KEY_MISMATCH],
     * [WireOperatorCards.BAD_FP], [WireOperatorCards.RECOVERY_KEY_SET], [WireOperatorCards.ORIGIN_PINNED] or
     * [WireOperatorCards.NO_CHANGE].
     */
    data class Invalid(val code: String) : CardChangeResult()

    /** The password gate refused at the entry: no session for this account at this origin. Nothing was derived or sent. */
    data object NoSession : CardChangeResult()

    /**
     * The password typed here did not open this device's own wrap: nothing was sent or stored. The server's
     * `403 reauth_failed` is [Refused] with [Reauthed.PROOF_REFUSED].
     */
    data object WrongPassword : CardChangeResult()

    /** Another refusal of the route (`rate_limited`, `operator_web_refused`, …), or `card_mismatch` when the server reported storing another card. */
    data class Refused(val code: String, val retryAfterSeconds: Long? = null) : CardChangeResult()

    /** No answer, or a `5xx`: the upload may have landed. The next refresh shows which; nothing was pinned. */
    data object Unknown : CardChangeResult()
}

/**
 * The operator's changes to the instance's identity card after setup (design §4.1, §4.2, §4.3, §4.5, §4.6, §9.2, §9.5;
 * spec 03 §17), for the desktop app and `andvari-cli operator`. Only the operator account reaches them: every call
 * first refreshes this device's pin through the verified chain, and refuses ([CardChangeResult.NotOperator]) unless the
 * session is the operator's and the newest card names this account and its signing key.
 *
 * Each call builds the next card from the verified, pinned newest card (`seq + 1`, `prev` its hash, the same
 * `instanceId`, and only the named field changed), signs it with the operator account's signing key
 * ([io.silencelen.andvari.core.trust.InstanceCard.sign]), checks it against the pin as every verifier would, and only then
 * runs the one re-authentication path ([Reauth], purpose `reauth`) and uploads it. The pin moves only through the
 * engine's normal refresh afterwards. Every `password` array is wiped before the call returns.
 *
 * A `kind` change is not offered: the design makes `kind` the host's `ANDVARI_INSTANCE_KIND`, written by
 * `andvari setup` (§4.1, §7.1, §9.5), and the server checks a card's `kind` against it only at card 0, so a client-made
 * kind change would leave the card and the server's own rules (variant R, handover) disagreeing.
 */
interface OperatorCards {
    /** Rename the instance: the card's `name` (§4.1), always shown with the origin. */
    suspend fun rename(name: String, password: CharArray): CardChangeResult

    /**
     * Move the instance to [origin] (§4.3 "Moves"): the card is uploaded to the current server, which keeps serving the
     * chain. This device then sees the move like any other ([CardChangeResult.Stored] with a [CardStatus.Moved]).
     * Refused here when this device already pins [origin] (§4.4: a move never replaces a pin).
     */
    suspend fun move(origin: String, password: CharArray): CardChangeResult

    /**
     * Hand the instance over (§4.3, §9.1) to the account [operatorUserId], whose Ed25519 signing key is [operatorSignKey]
     * (`b64_32`, as the new operator's own device shows it). [identityPub], when this account holds a key for that
     * person (a compared contact), is their X25519 identity key: [operatorSignKey] must map to it
     * ([WireOperatorCards.HANDOVER_KEY_MISMATCH] otherwise). After the handover this account can no longer sign cards.
     */
    suspend fun handOver(operatorUserId: String, operatorSignKey: String, identityPub: String?, password: CharArray): CardChangeResult

    /**
     * Name a recovery key where the card names none (§4.5): [recoveryFp] is its `hex64` fingerprint, as
     * `recovery-cli keygen` printed it. Refused on a `public` card, and when a key is named already (a change of key is
     * [rotateRecoveryKey]). Every opted-in person sees a change from `none` behind the unsigned-change warning (§4.5).
     */
    suspend fun setRecoveryKey(recoveryFp: String, password: CharArray): CardChangeResult

    /**
     * Change the recovery key (§4.5 "Signed rotation"): [rotations] are the 0x08 statements `recovery-cli rotate` produced
     * OFFLINE with the outgoing seed, oldest first, leading from the card's `recoveryFp` to the new one (the last
     * statement's `toFp`). Each is checked here, then uploaded (`PUT /instance/rotation`) before the card. This flow never
     * holds a recovery seed.
     */
    suspend fun rotateRecoveryKey(rotations: List<ByteArray>, password: CharArray): CardChangeResult

    /** Remove the recovery key: the card's `recoveryFp` becomes `none`, and operator recovery is no longer offered (§4.5). */
    suspend fun removeRecoveryKey(password: CharArray): CardChangeResult
}
