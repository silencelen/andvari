package io.silencelen.andvari.core.client.account

import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.EstablishedSession
import io.silencelen.andvari.core.client.pin.CardPin
import io.silencelen.andvari.core.client.pin.CardStatus
import io.silencelen.andvari.core.client.pin.InstanceTrust
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.model.wire.InstanceCardPut
import io.silencelen.andvari.core.model.wire.InstanceCardPutResponse
import io.silencelen.andvari.core.model.wire.InstanceRotationPut
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.CardFields
import io.silencelen.andvari.core.trust.CardHead
import io.silencelen.andvari.core.trust.Checked
import io.silencelen.andvari.core.trust.InstanceCard
import io.silencelen.andvari.core.trust.InstanceKind
import io.silencelen.andvari.core.trust.RecoveryRotation
import io.silencelen.andvari.core.trust.SignedFrame
import io.silencelen.andvari.core.trust.TrustGrammar
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * [OperatorCards] over the wire (spec 03 §17.2, §17.3). [session] is the operator account's own session at its origin
 * (borrowed: the caller wipes its keys at lock); [client] that origin's authenticated client; [trust] this device's
 * instance trust, whose [InstanceTrust.refresh] is the only way the pin moves; [reauth] the one re-authentication path.
 *
 * Trust:
 * - The next card is built from the pin as the refresh just left it, which is the newest card of a chain verified from
 *   card 0 against this device's pin. No served value becomes a field of the card: the only inputs are the pin and the
 *   operator's own arguments, each checked against its grammar here.
 * - The signed card is verified as the card after the pin ([InstanceCard.verify] from the pin's head) before the
 *   password is touched, so a card every verifier would refuse is never uploaded.
 * - The password is derived only after every check that needs no secret, and only on [Reauth]'s `proceed`.
 * - After the upload the pin is brought forward by [InstanceTrust.refresh], never written here; a move it reports is
 *   returned for the operator to confirm like anyone else.
 */
class WireOperatorCards(
    private val session: EstablishedSession,
    private val client: WireClient,
    private val crypto: CryptoProvider,
    private val trust: InstanceTrust,
    private val reauth: Reauth,
    private val clock: () -> Long,
) : OperatorCards {
    private val lock = Mutex()
    private val origin get() = session.origin

    override suspend fun rename(name: String, password: CharArray): CardChangeResult = change(password) { pin, f ->
        if (TrustGrammar.encodeName(name) == null) return@change Plan.Refuse(CardChangeResult.Invalid(BAD_NAME))
        if (name == pin.name) return@change Plan.Refuse(CardChangeResult.Invalid(NO_CHANGE))
        Plan.Upload(f.copy(name = name))
    }

    override suspend fun move(origin: String, password: CharArray): CardChangeResult = change(password) { pin, f ->
        if (!TrustGrammar.isOrigin(origin)) return@change Plan.Refuse(CardChangeResult.Invalid(BAD_ORIGIN))
        if (origin == pin.origin) return@change Plan.Refuse(CardChangeResult.Invalid(NO_CHANGE))
        // §4.4: a move never replaces a pin that already exists for the new origin; this device could not follow it.
        if (trust.pinState(origin) != PinState.None) return@change Plan.Refuse(CardChangeResult.Invalid(ORIGIN_PINNED))
        Plan.Upload(f.copy(origin = origin))
    }

    override suspend fun handOver(operatorUserId: String, operatorSignKey: String, identityPub: String?, password: CharArray): CardChangeResult =
        change(password) { pin, f ->
            if (!TrustGrammar.isUuid(operatorUserId) || !TrustGrammar.isB64_32(operatorSignKey)) return@change Plan.Refuse(CardChangeResult.Invalid(BAD_KEY))
            if (operatorUserId == pin.operator) return@change Plan.Refuse(CardChangeResult.Invalid(NO_CHANGE))
            // The card names the Ed25519 key; the server maps it to the target's stored identityPub (§4.1). A key with no
            // X25519 image can never pass that, and a key this account holds for the person must be its image.
            val image = InstanceCard.operatorIdentityKey(crypto, operatorSignKey) ?: return@change Plan.Refuse(CardChangeResult.Invalid(BAD_KEY))
            if (identityPub != null) {
                val known = Bytes.fromB64Exact(identityPub, 32)
                if (known == null || !Bytes.ctEquals(known, image)) return@change Plan.Refuse(CardChangeResult.Invalid(HANDOVER_KEY_MISMATCH))
            }
            Plan.Upload(f.copy(operator = operatorUserId, operatorSignKey = operatorSignKey))
        }

    override suspend fun setRecoveryKey(recoveryFp: String, password: CharArray): CardChangeResult = change(password) { pin, f ->
        if (pin.kind == InstanceKind.PUBLIC.literal) return@change Plan.Refuse(CardChangeResult.PublicRefusesRecoveryKey)
        if (!TrustGrammar.isHex64(recoveryFp)) return@change Plan.Refuse(CardChangeResult.Invalid(BAD_FP))
        if (pin.recoveryFp == recoveryFp) return@change Plan.Refuse(CardChangeResult.Invalid(NO_CHANGE))
        // A change from one key to another travels with its signed rotation (rotateRecoveryKey), never as a bare card.
        if (pin.recoveryFp != TrustGrammar.NONE) return@change Plan.Refuse(CardChangeResult.Invalid(RECOVERY_KEY_SET))
        Plan.Upload(f.copy(recoveryFp = recoveryFp))
    }

    override suspend fun rotateRecoveryKey(rotations: List<ByteArray>, password: CharArray): CardChangeResult = change(password) { pin, f ->
        if (pin.kind == InstanceKind.PUBLIC.literal) return@change Plan.Refuse(CardChangeResult.PublicRefusesRecoveryKey)
        if (rotations.isEmpty()) return@change Plan.Refuse(CardChangeResult.BadRotation(FP_MISMATCH))
        // Each statement against the fingerprint reached so far, starting from the pinned card's (§4.5, spec 04 §5): signed
        // by the recovery key that fingerprint names, for this instance. A card naming `none` has no key to rotate from.
        var reached = pin.recoveryFp
        for (frame in rotations) {
            when (val v = RecoveryRotation.verify(crypto, frame, pin.instanceId, reached)) {
                is Checked.Ok -> reached = v.value.fields.toFp
                is Checked.Refused -> return@change Plan.Refuse(CardChangeResult.BadRotation(v.verdict.code))
            }
        }
        if (reached == pin.recoveryFp) return@change Plan.Refuse(CardChangeResult.Invalid(NO_CHANGE))
        Plan.Upload(f.copy(recoveryFp = reached), rotations.map { it.copyOf() })
    }

    override suspend fun removeRecoveryKey(password: CharArray): CardChangeResult = change(password) { pin, f ->
        if (pin.recoveryFp == TrustGrammar.NONE) return@change Plan.Refuse(CardChangeResult.Invalid(NO_CHANGE))
        Plan.Upload(f.copy(recoveryFp = null))
    }

    /** What one change came to before the password: refuse with a result, or upload this card after these rotations. */
    private sealed class Plan {
        class Refuse(val result: CardChangeResult) : Plan()
        class Upload(val card: CardFields, val rotations: List<ByteArray> = emptyList()) : Plan()
    }

    /**
     * The one path of every change: refresh the pin, check that this account may sign the next card, let [plan] change
     * one field of the card the pin names, sign and self-verify it, re-authenticate, upload (rotations first), and bring
     * the pin forward through the refresh. [password] is wiped on every path.
     */
    private suspend fun change(password: CharArray, plan: (CardPin, CardFields) -> Plan): CardChangeResult = try {
        lock.withLock { changeLocked(password, plan) }
    } finally {
        password.fill('\u0000')
    }

    /** The card after [pin], as it stands, for a plan to change one field of. */
    private fun nextAfter(pin: CardPin, kind: InstanceKind) = CardFields(
        instanceId = pin.instanceId, seq = pin.seq + 1, prev = pin.hash, origin = pin.origin, name = pin.name, kind = kind,
        operator = pin.operator, operatorSignKey = pin.operatorSignKey,
        recoveryFp = pin.recoveryFp.takeIf { it != TrustGrammar.NONE }, issuedAt = clock(),
    )

    private suspend fun changeLocked(password: CharArray, plan: (CardPin, CardFields) -> Plan): CardChangeResult {
        // Who is the operator is the newest verified card's word (below), never the role this session was opened with: after
        // a hand-over the new operator's session still says "member" until it signs in again, and it may sign the next card
        // now. The server decides its own role for the call; the card decides whether this device signs at all.
        // A change the card this device pins already refuses (no change, a bad value) is refused before the password is
        // touched, with nothing derived or sent; the newest card is asked again below, after the proof.
        trust.pinFor(origin)?.let { local ->
            InstanceKind.fromLiteral(local.kind)?.let { k -> (plan(local, nextAfter(local, k)) as? Plan.Refuse)?.let { return it.result } }
        }
        // The password first, through the one gate (purpose reauth, this session's origin and account), proven on this
        // device: the act sends its first request, the read of the cards included, only once the proof has held, so a
        // wrong password sends nothing at all (spec 01 §7).
        val current = when (val k = reauth.currentAuthKey(password)) {
            is ReauthKey.Key -> k.currentAuthKey
            ReauthKey.Refused -> return CardChangeResult.NoSession
            ReauthKey.Unreachable -> return CardChangeResult.Unknown
            ReauthKey.WrongPassword -> return CardChangeResult.WrongPassword
        }
        // The newest verified card, as this device pins it (design §4.4): anything but ok stops here.
        val pin = when (val s = trust.refresh(origin)) {
            is CardStatus.Ok -> s.pin
            else -> return CardChangeResult.NotCurrent(s)
        }
        val signing = session.account.signing
        val ownKey = Bytes.toB64(signing.publicKey)
        // Only the account the newest card names, with the key it names, can sign the next card (§4.2).
        if (pin.operator != session.userId || pin.operatorSignKey != ownKey) return CardChangeResult.NotOperator
        val kind = InstanceKind.fromLiteral(pin.kind) ?: return CardChangeResult.BadCard
        val upload = when (val p = plan(pin, nextAfter(pin, kind))) {
            is Plan.Refuse -> return p.result
            is Plan.Upload -> p
        }
        val card = upload.card
        // Exactly the intended field changed, on the card after the pin (seq, prev, instanceId and kind as the pin's).
        if (card.instanceId != pin.instanceId || card.seq != pin.seq + 1 || card.prev != pin.hash || card.kind != kind) return CardChangeResult.BadCard
        // Variant R once more on the card itself: a public card never names a recovery key.
        if (kind == InstanceKind.PUBLIC && card.recoveryFp != null) return CardChangeResult.PublicRefusesRecoveryKey
        val frame = signing.use { InstanceCard.sign(crypto, it, card) }
        val head = CardHead(pin.instanceId, pin.card0Hash, pin.seq, pin.hash, pin.operatorSignKey)
        if (InstanceCard.verify(crypto, head, frame) !is Checked.Ok) return CardChangeResult.BadCard
        val hash = SignedFrame.hash(crypto, frame)

        // A lock during the re-authentication's wait or the cards' read wipes the signing key: the signing above then
        // refuses, or the check below does, and its KeysGoneException reaches the caller as "locked";
        // nothing is sent. Once the
        // first rotation is sent, the upload is finished even if a lock lands between its calls:
        // stopping there would leave the server holding rotations that its newest card does not name, until the operator
        // re-ran the change with the very same statements, while finishing sends only what was signed before the lock and
        // leaves the server's rotations and card consistent.
        signing.guard.check()
        // §4.3, S3-C4: the rotations first, oldest first, so a client sees the change as signed once the card is served.
        for (rotation in upload.rotations) {
            val body = WireJson.json.encodeToString(InstanceRotationPut.serializer(), InstanceRotationPut(Bytes.toB64(rotation), current))
            refusal(client.call(WireRoute.INSTANCE_ROTATION_PUT, bodyJson = body, decode = { }))?.let { return it }
        }
        val body = WireJson.json.encodeToString(InstanceCardPut.serializer(), InstanceCardPut(Bytes.toB64(frame), current))
        val r = client.call(WireRoute.INSTANCE_CARD_PUT, bodyJson = body, decode = { WireJson.json.decodeFromString(InstanceCardPutResponse.serializer(), it) })
        refusal(r)?.let { return it }
        val stored = (r as WireResult.Ok).value
        if (stored.seq != card.seq || stored.hash != hash) return CardChangeResult.Refused(CARD_MISMATCH)
        // The pin follows through the engine's normal path only (design §4.4), like any other device's.
        return when (val s = trust.refresh(origin)) {
            is CardStatus.Ok -> if (s.pin.hash == hash) CardChangeResult.Changed(hash, s.pin) else CardChangeResult.Stored(hash, s)
            else -> CardChangeResult.Stored(hash, s)
        }
    }

    /** The typed result of a refused upload (spec 03 §17.2, §17.3); null when [r] is a success. */
    private fun refusal(r: WireResult<*>): CardChangeResult? = when (r) {
        is WireResult.Ok -> null
        is WireResult.NoAnswer -> CardChangeResult.Unknown
        is WireResult.Refused -> when {
            r.status >= 500 -> CardChangeResult.Unknown
            r.code == Reauthed.PROOF_REFUSED -> CardChangeResult.Refused(Reauthed.PROOF_REFUSED, r.retryAfterSeconds)
            r.code == "not_operator" -> CardChangeResult.NotOperator
            r.code == "card_head_moved" -> CardChangeResult.HeadMoved(r.error.seq, r.error.hash?.takeIf(TrustGrammar::isHex64))
            r.code == "bad_card" -> CardChangeResult.BadCard
            r.code == "handover_target_invalid" -> CardChangeResult.HandoverTargetInvalid
            r.code == "bad_rotation" -> CardChangeResult.BadRotation(null)
            else -> CardChangeResult.Refused(r.code, r.retryAfterSeconds)
        }
    }

    companion object {
        const val OPERATOR_ROLE = "operator"

        /** The new name is not a `name` (§2.2). */
        const val BAD_NAME = "bad_name"

        /** The new origin is not a canonical https origin (§2.2). */
        const val BAD_ORIGIN = "bad_origin"

        /** The handover target's userId is not a uuid, or its signing key is not an Ed25519 key with an X25519 image. */
        const val BAD_KEY = "bad_key"

        /** The handover key does not map to the identity key this account holds for that person. */
        const val HANDOVER_KEY_MISMATCH = "handover_key_mismatch"

        /** The recovery fingerprint is not a `hex64`. */
        const val BAD_FP = "bad_fp"

        /** The card names a recovery key already: a change of key needs its rotation ([OperatorCards.rotateRecoveryKey]). */
        const val RECOVERY_KEY_SET = "recovery_key_set"

        /** This device already pins the move's target origin (§4.4 `pin_conflict`). */
        const val ORIGIN_PINNED = "origin_pinned"

        /** The change would leave the card as it is. */
        const val NO_CHANGE = "no_change"

        /** The rotation chain does not lead away from the card's fingerprint. */
        const val FP_MISMATCH = "fp_mismatch"

        /** The server answered another card than the one sent. */
        const val CARD_MISMATCH = "card_mismatch"
    }
}
