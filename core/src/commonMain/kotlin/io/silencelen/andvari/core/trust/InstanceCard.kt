package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.KeyPairBytes
import kotlinx.serialization.Serializable

/** `ANDVARI_INSTANCE_KIND`, as a card or a setup offer carries it (design 2026-11-15 §4.1, §6.4). It grants nothing. */
@Serializable
enum class InstanceKind(val literal: String) {
    PUBLIC("public"),
    PRIVATE("private"),
    ;

    companion object {
        fun fromLiteral(literal: String): InstanceKind? = entries.firstOrNull { it.literal == literal }
    }
}

/**
 * One instance card as its statement says it (§4.1):
 *
 * ```
 * {"v":2,"purpose":"instance-card","instanceId":<uuid>,"seq":<int>,"prev":<hex64>,"origin":<origin>,
 *  "name":<name>,"kind":"public"|"private","operator":<uuid>,"operatorSignKey":<b64_32>,
 *  "recoveryFp":<hex64n>,"issuedAt":<ms>}
 * ```
 *
 * [name] is the DECODED display name (the statement carries it in the `name` type; render it only as
 * plain text, and always with [origin] beside it, T-R8). [operatorSignKey] is the operator account's
 * **Ed25519** joint key as `b64_32` text. [recoveryFp] is `hexLower(SHA-256(instance recovery public
 * key))`, or null for the statement's `none` (no operator recovery).
 */
data class CardFields(
    val instanceId: String,
    val seq: Long,
    val prev: String,
    val origin: String,
    val name: String,
    val kind: InstanceKind,
    val operator: String,
    val operatorSignKey: String,
    val recoveryFp: String?,
    val issuedAt: Long,
)

/**
 * A position in a card chain: what the NEXT card must chain from (§4.2), and what a device holds as
 * its pin (§4.4). [instanceId] stays constant along the chain; [card0Hash] is `H(card 0)` of that
 * chain; [seq] and [hash] name the card itself; [operatorSignKey] is the key that card names, which
 * must sign the next one.
 *
 * A verified card gives one ([VerifiedCard.head]). A device's pinned card record holds the same five
 * values (§4.4: `{instanceId, card0Hash, seq, hash, …, operatorSignKey, …}`), which is how a device
 * "verifies forward from the pinned card". [card0Hash] is what tells a NEW chain under the same
 * `instanceId` (an operator reset, §4.6) from the same chain served short: the first is a fork
 * however short it is, the second is withheld.
 */
@Serializable
data class CardHead(val instanceId: String, val card0Hash: String, val seq: Long, val hash: String, val operatorSignKey: String)

/** A card that passed the strict parse only: NOT authenticated and not placed in a chain. */
class UnverifiedCard internal constructor(val fields: CardFields, val hash: String, internal val parts: FrameParts) {
    /** The Ed25519 key the frame says signed it. Never a key to verify that same frame against. */
    val signerPub: ByteArray get() = parts.signerPub
}

/**
 * A card that [InstanceCard.verify] accepted as the next card after the head it was given. [hash] is
 * `H(frame)`; [card0Hash] is the hash of its chain's card 0 (its own hash when it is card 0).
 */
class VerifiedCard internal constructor(val fields: CardFields, val hash: String, val card0Hash: String, frame: ByteArray) {
    private val frameBytes = frame.copyOf()
    val frame: ByteArray get() = frameBytes.copyOf()

    /** What the card after this one must chain from, and what a device pins for this card. */
    val head: CardHead get() = CardHead(fields.instanceId, card0Hash, fields.seq, hash, fields.operatorSignKey)
}

/**
 * Why a card was refused (§4.2; names and order from §2.4 "Card chain", VR-10): the vault log's
 * verdicts without `precondition`, with `instance_mismatch` in `wrong_vault`'s place. The order of the
 * entries is the check order.
 */
enum class CardVerdict(val code: String) {
    /** The §2 parse: see [FrameVerdict]. A card has no template rule of its own, so `bad_statement` is only `v` or the purpose literal. */
    BAD_FRAME("bad_frame"),
    UNKNOWN_FORMAT("unknown_format"),
    NON_CANONICAL("non_canonical"),
    BAD_STATEMENT("bad_statement"),

    /** `instanceId` is not card 0's of the same chain (§4.2: "`instanceId` is constant"), or, on the server, not its own. */
    INSTANCE_MISMATCH("instance_mismatch"),

    /** `seq` is not the previous card's plus one (or not 0 for the first card). */
    BAD_SEQ("bad_seq"),

    /** `prev` is not `H(previous card)` (card 0: not 64 zeros). */
    BAD_PREV("bad_prev"),

    /** `signerPub` is not byte-equal to the previous card's `operatorSignKey` (card 0: to its own). */
    NOT_AUTHORIZED("not_authorized"),

    /** The Ed25519 signature does not verify. */
    BAD_SIGNATURE("bad_signature"),

    /**
     * Checked last, and only where the verifier holds a trustworthy **Ed25519 signing key** for the
     * account the card names as `operator` (§4.1, VR-11): the operator's own devices, with the key they
     * derive from their own identity seed, and the server at upload, with the key that signed that
     * account's genesis. `operatorSignKey` is not BYTE-EQUAL to that key. Other clients hold no such key
     * and do not check; nothing rests on it, because every card is still signed by the previous card's
     * key.
     */
    OPERATOR_KEY_MISMATCH("operator_key_mismatch"),
    ;

    companion object {
        internal fun of(v: FrameVerdict): CardVerdict = when (v) {
            FrameVerdict.BAD_FRAME -> BAD_FRAME
            FrameVerdict.UNKNOWN_FORMAT -> UNKNOWN_FORMAT
            FrameVerdict.NON_CANONICAL -> NON_CANONICAL
            FrameVerdict.BAD_STATEMENT -> BAD_STATEMENT
        }
    }
}

/**
 * The **Ed25519 signing keys** a verifier TRUSTS for operator accounts (§4.1, VR-11), for the
 * `operator_key_mismatch` check. Every client that is not a device of the operator account passes none.
 *
 * The key handed over is the Ed25519 key itself, and [InstanceCard.verify] compares it with the card's
 * `operatorSignKey` byte for byte. It is NEVER the X25519 `identityPub`, and nothing here goes through
 * `ed25519_pk_to_curve25519`: a key `A` and its negation `-A` have the same X25519 image, and the
 * holder of `A` can sign under either. A handover card that named `-A` for the incoming operator would
 * pass a comparison of images, and from then on every card would have to be signed under `-A`: the
 * operator's real key would be `not_authorized` for good, and the instance could never sign another
 * card.
 */
fun interface OperatorKeys {
    /**
     * The trusted Ed25519 signing key (32 bytes) of account [userId], or null when this verifier holds
     * none for it.
     * - **An operator's own device** answers for its own `userId` only, with the key it derives from its
     *   own identity seed: `CryptoProvider.signKeypairFromSeed(seed).publicKey`.
     * - **The server** answers for any account, with the key that signed that account's genesis: the
     *   stored genesis frame's `signerPub` ([AccountGenesis.signerOf]).
     *
     * An X25519 key handed here by mistake matches no card: the verdict is `operator_key_mismatch`.
     */
    fun signKeyOf(userId: String): ByteArray?
}

/**
 * Why a served chain cannot make, or no longer matches, a pin (§4.4; names and ORDER from §2.4
 * "Pinning", VR-12). These are expectations from OUTSIDE the chain (baked, kit, offer, pin): they are
 * checked after the chain verified, never passed into the chain verifier.
 */
enum class PinVerdict(val code: String) {
    /**
     * FIRST, for every root that makes a first pin: the newest verified card's `origin` is not the
     * origin the client dialed. Cards are public, so any server can serve another instance's genuine
     * chain; without this check a look-alike address would pass the Trust Gate, a link offer, a kit or
     * the CLI's `--trust-card` under the real instance's name and key. Under an EXISTING pin a changed
     * origin is a move ([InstanceCard.follow]), never this verdict.
     */
    ORIGIN_MISMATCH("origin_mismatch"),

    /** Card 0 of the served chain does not hash to the baked `PUBLIC_INSTANCE.card0Hash`, or to the kit's `card0Hash`. */
    CARD0_MISMATCH("card0_mismatch"),

    /** The chain's `instanceId` is not the baked `PUBLIC_INSTANCE.instanceId`; or an offer's `cardHash` is in the chain under another `instanceId` than the offer's. */
    INSTANCE_MISMATCH("instance_mismatch"),

    /** A chain is served, and no card of it has the hash a link offer names. */
    CARD_NOT_IN_CHAIN("card_not_in_chain"),

    /**
     * Card 0 of the served chain does not hash to the pin's `card0Hash` (a new chain, however short: an
     * operator reset, §4.6, or another instance), or another hash stands at the pinned `seq`. The
     * client STOPS using the instance: no sign-in, sync or writes; the only way on is "Forget this server".
     */
    FORK("fork"),

    /**
     * The SAME chain ends below the pinned `seq`, or no card is served at all (a stale cache, a server
     * hiding an update, an instance whose identity was reset and has no card yet, FC-4). For EVERY
     * root (baked, kit, link offer, typed address): no card is served. A state, not a stop: the device
     * keeps its pin, says "This server is showing an older version of its identity card" and retries
     * at the next probe.
     */
    WITHHELD("withheld"),
}

/**
 * A run of verified cards in chain order. From [InstanceCard.verifyChain] with no starting head it
 * begins at card 0; with a starting head it holds the cards after that head.
 */
class CardChain internal constructor(val cards: List<VerifiedCard>) {
    /** The newest verified card, or null when the run is empty. */
    val newest: VerifiedCard? get() = cards.lastOrNull()

    /** `H(card 0)` of the chain these cards belong to, or null when the run is empty. */
    val card0Hash: String? get() = cards.firstOrNull()?.card0Hash

    /** The card with this `seq`, or null. */
    fun at(seq: Long): VerifiedCard? = cards.firstOrNull { it.fields.seq == seq }

    /** The card whose frame hash is [hash], or null (§4.4 link-offer root: "a card with `H = offer.cardHash`"). */
    fun byHash(hash: String): VerifiedCard? = cards.firstOrNull { it.hash == hash }
}

/**
 * The result of [InstanceCard.verifyChain]: [chain] holds the cards that verified, in order; when a
 * frame failed, [failedAt] is its index in the input and [verdict] why, and nothing after it was looked
 * at. Both are null when every frame verified.
 */
class CardChainResult internal constructor(val chain: CardChain, val failedAt: Int?, val verdict: CardVerdict?) {
    val complete: Boolean get() = verdict == null
}

/**
 * What a served chain means for a device that pins a card (§4.4 "On every policy probe or sync").
 *
 * [pin] is null when the served chain contains the pinned hash at the pinned `seq`; otherwise it is
 * [PinVerdict.FORK] or [PinVerdict.WITHHELD] and [newer] is empty. With the pin contained, [newer] are
 * the cards after it that verified, oldest first (empty: the pin is still the newest). When a later
 * card did not verify, [verdict] says why and [newer] stops before it: the device may advance its pin
 * to the last of [newer] and must not act on anything past it.
 */
class CardFollow internal constructor(val pin: PinVerdict?, val newer: List<VerifiedCard>, val verdict: CardVerdict?)

/**
 * The instance card and its chain (design 2026-11-15 §4.1, §4.2; pin checks of §4.4). An instance
 * names itself with a chain of cards, each signed by the operator key of the card before it; card 0 is
 * signed by its own. The same verifier runs in every full client and on the server
 * (`PUT /instance/card`, §4.3).
 *
 * This object verifies chains and judges them against a pin. Which ROOT may make a first pin, and what
 * a pin allows (the password rule), is the engine's `PasswordGate` (§4.4), not decided here.
 */
object InstanceCard {
    /**
     * Encode and sign a card with [signer]: for card 0 the operator's own joint key (which must be the
     * card's `operatorSignKey`), for card n the key the PREVIOUS card names. Refuses
     * (`IllegalArgumentException`) values outside the grammar, a name that is not a `name`, and a card 0
     * whose `prev` is not 64 zeros or whose `operatorSignKey` is not [signer]'s public key.
     */
    fun sign(crypto: CryptoProvider, signer: KeyPairBytes, card: CardFields): ByteArray {
        val name = requireNotNull(TrustGrammar.encodeName(card.name)) { "the card's name is not a name (§2.2)" }
        require(card.recoveryFp == null || TrustGrammar.isHex64(card.recoveryFp)) { "recoveryFp is a hex64, or null for none" }
        if (card.seq == 0L) {
            require(card.prev == TrustGrammar.ZERO_HASH) { "card 0 has prev = 64 zeros" }
            require(card.operatorSignKey == Bytes.toB64(signer.publicKey)) { "card 0 is signed by its own operatorSignKey" }
        }
        val statement = StatementCodec.encode(
            TrustPurpose.INSTANCE_CARD,
            mapOf(
                "instanceId" to card.instanceId, "seq" to card.seq.toString(), "prev" to card.prev, "origin" to card.origin,
                "name" to name, "kind" to card.kind.literal, "operator" to card.operator, "operatorSignKey" to card.operatorSignKey,
                "recoveryFp" to (card.recoveryFp ?: TrustGrammar.NONE), "issuedAt" to card.issuedAt.toString(),
            ),
        )
        return SignedFrame.sign(crypto, signer, TrustPurpose.INSTANCE_CARD, statement)
    }

    /** The §2 parse of one card and nothing more: the frame, purpose 0x04 and the strict canonical parse. */
    fun parse(crypto: CryptoProvider, frame: ByteArray): Checked<UnverifiedCard, CardVerdict> {
        val parsed = when (val p = StatementCodec.parseFrame(frame, TrustPurpose.INSTANCE_CARD)) {
            is Checked.Ok -> p.value
            is Checked.Refused -> return Checked.Refused(CardVerdict.of(p.verdict))
        }
        val raw = parsed.raw
        // The codec proved every value in its grammar; the two lookups below cannot miss.
        val name = TrustGrammar.decodeName(raw.str("name")) ?: return Checked.Refused(CardVerdict.NON_CANONICAL)
        val kind = InstanceKind.fromLiteral(raw.str("kind")) ?: return Checked.Refused(CardVerdict.NON_CANONICAL)
        val fields = CardFields(
            instanceId = raw.str("instanceId"), seq = raw.long("seq"), prev = raw.str("prev"), origin = raw.str("origin"),
            name = name, kind = kind, operator = raw.str("operator"), operatorSignKey = raw.str("operatorSignKey"),
            recoveryFp = raw.str("recoveryFp").takeIf { it != TrustGrammar.NONE }, issuedAt = raw.long("issuedAt"),
        )
        return Checked.Ok(UnverifiedCard(fields, SignedFrame.hash(crypto, frame), parsed.parts))
    }

    /**
     * Verify ONE card as the next card after [prior] (null: it must be card 0). §4.2, in §2.4's order
     * ("Card chain", VR-10); the first failure is the verdict:
     *
     * 1. `bad_frame`, `unknown_format`, `non_canonical`, `bad_statement`: [parse];
     * 2. `instance_mismatch`: `instanceId` is not [prior]'s, that is card 0's of the same chain; or it
     *    is not [expectedInstanceId]. ONLY THE SERVER passes [expectedInstanceId] (its own instance
     *    id). A client never passes a baked, kit, offer or pinned id here: those are pin verdicts,
     *    checked after the chain verified ([checkBakedRoot], [checkKitRoot], [checkOfferRoot], [follow]);
     * 3. `bad_seq`: `seq` is not 0 for card 0, or not `prior.seq + 1`;
     * 4. `bad_prev`: `prev` is not `prior.hash` (card 0: not 64 zeros);
     * 5. `not_authorized`: `signerPub` is not byte-equal to `prior.operatorSignKey` (card 0: to its own
     *    `operatorSignKey`). This is the Ed25519 form of the signer binding, which a verifier without a
     *    Montgomery map (the extension) can run too;
     * 6. `bad_signature`;
     * 7. `operator_key_mismatch`, only when [operatorKeys] holds a key for the account the card names as
     *    `operator`: `operatorSignKey` is not byte-equal to that Ed25519 key (§4.1, VR-11). The
     *    comparison is on the Ed25519 key itself, never through its X25519 image, which a key shares
     *    with its negation ([OperatorKeys]).
     *
     * Cards have no `precondition`. Any field except `instanceId` may differ from the card before: a
     * move (`origin`), a rename, a handover (`operator`, `operatorSignKey`), a `kind` change, a
     * recovery-key change (`recoveryFp`). What a client DOES about a move or a `kind` change is §4.4's,
     * decided by the engine.
     */
    fun verify(
        crypto: CryptoProvider,
        prior: CardHead?,
        frame: ByteArray,
        expectedInstanceId: String? = null,
        operatorKeys: OperatorKeys? = null,
    ): Checked<VerifiedCard, CardVerdict> {
        val card = when (val p = parse(crypto, frame)) {
            is Checked.Ok -> p.value
            is Checked.Refused -> return p
        }
        val f = card.fields
        if (prior != null && f.instanceId != prior.instanceId) return refuse(CardVerdict.INSTANCE_MISMATCH)
        if (expectedInstanceId != null && f.instanceId != expectedInstanceId) return refuse(CardVerdict.INSTANCE_MISMATCH)
        if (f.seq != (if (prior == null) 0L else prior.seq + 1)) return refuse(CardVerdict.BAD_SEQ)
        if (f.prev != (prior?.hash ?: TrustGrammar.ZERO_HASH)) return refuse(CardVerdict.BAD_PREV)
        val signerKey = Bytes.fromB64Exact(prior?.operatorSignKey ?: f.operatorSignKey, 32) ?: return refuse(CardVerdict.NOT_AUTHORIZED)
        if (!SignedFrame.signerIs(card.parts, signerKey)) return refuse(CardVerdict.NOT_AUTHORIZED)
        if (!SignedFrame.signatureValid(crypto, card.parts)) return refuse(CardVerdict.BAD_SIGNATURE)
        val trusted = operatorKeys?.signKeyOf(f.operator)
        if (trusted != null) {
            // Byte for byte, on the Ed25519 key itself: an image comparison cannot tell A from -A (§4.1).
            val named = Bytes.fromB64Exact(f.operatorSignKey, SignedFrame.SIGNER_BYTES)
            if (named == null || !Bytes.ctEquals(named, trusted)) return refuse(CardVerdict.OPERATOR_KEY_MISMATCH)
        }
        return Checked.Ok(VerifiedCard(f, card.hash, prior?.card0Hash ?: card.hash, frame))
    }

    private fun refuse(verdict: CardVerdict): Checked.Refused<CardVerdict> = Checked.Refused(verdict)

    /**
     * Verify [frames] in order, starting after [from] (null: the first frame must be card 0, as
     * `GET /instance` serves "card 0 first"). Stops at the first card that fails.
     */
    fun verifyChain(
        crypto: CryptoProvider,
        frames: List<ByteArray>,
        from: CardHead? = null,
        expectedInstanceId: String? = null,
        operatorKeys: OperatorKeys? = null,
    ): CardChainResult {
        var head = from
        val cards = ArrayList<VerifiedCard>(frames.size)
        for ((i, frame) in frames.withIndex()) {
            when (val card = verify(crypto, head, frame, expectedInstanceId, operatorKeys)) {
                is Checked.Ok -> {
                    cards += card.value
                    head = card.value.head
                }
                is Checked.Refused -> return CardChainResult(CardChain(cards), i, card.verdict)
            }
        }
        return CardChainResult(CardChain(cards), null, null)
    }

    /**
     * §2.4 "Pinning", the first of the mismatches: the newest verified card of [chain] names
     * [dialedOrigin], the origin this client dialed to fetch it (`origin_mismatch`). Null when it does,
     * and for an empty chain, which has no card to compare: every root answers `withheld` for that.
     * It holds after a move too: a device with no pin that dials an instance's OLD address gets
     * `origin_mismatch`; the app may offer to dial the origin the card names, and every check runs
     * again from the start there.
     *
     * Every root below runs it first. It is NOT run under an existing pin: there a changed origin is a
     * move, signed by the operator, which [follow] reports as newer cards.
     */
    fun checkDialedOrigin(chain: CardChain, dialedOrigin: String): PinVerdict? {
        val newest = chain.newest ?: return null
        return if (newest.fields.origin != dialedOrigin) PinVerdict.ORIGIN_MISMATCH else null
    }

    /**
     * The BAKED root (§4.4), in §2.4's pinning order. [chain] is the served chain, verified from card 0,
     * and [dialedOrigin] the origin it was fetched from. No card served is `withheld`; the newest card
     * must name [dialedOrigin] (`origin_mismatch`); card 0 must hash to `PUBLIC_INSTANCE.card0Hash`
     * (`card0_mismatch`, also when the `instanceId` differs too); then its `instanceId` must be the
     * baked one (`instance_mismatch`). Null when the root holds; the newest card of [chain] is then
     * pinned.
     */
    fun checkBakedRoot(chain: CardChain, dialedOrigin: String, card0Hash: String, instanceId: String): PinVerdict? {
        val first = chain.cards.firstOrNull() ?: return PinVerdict.WITHHELD
        checkDialedOrigin(chain, dialedOrigin)?.let { return it }
        if (first.card0Hash != card0Hash) return PinVerdict.CARD0_MISMATCH
        if (first.fields.instanceId != instanceId) return PinVerdict.INSTANCE_MISMATCH
        return null
    }

    /**
     * The KIT root (§4.4, §10): no card served is `withheld`; the newest card must name [dialedOrigin]
     * (`origin_mismatch`); card 0 of the verified served chain must hash to the kit's `card0Hash`
     * (`card0_mismatch`). A kit made before an operator reset does not match; the client then falls
     * back to the Trust Gate with its warning (N2).
     */
    fun checkKitRoot(chain: CardChain, dialedOrigin: String, card0Hash: String): PinVerdict? {
        val first = chain.cards.firstOrNull() ?: return PinVerdict.WITHHELD
        checkDialedOrigin(chain, dialedOrigin)?.let { return it }
        return if (first.card0Hash != card0Hash) PinVerdict.CARD0_MISMATCH else null
    }

    /**
     * The LINK-OFFER root (§4.4): no card served is `withheld`, as for every root; the newest card of
     * the verified served chain must name [dialedOrigin], the origin in the link (`origin_mismatch`);
     * the chain must contain a card with `H = offer.cardHash` (`card_not_in_chain`) and that card must
     * be under `offer.instanceId` (`instance_mismatch`). The newest card of [chain] is then pinned. An
     * enrol link is NOT a root (U3).
     */
    fun checkOfferRoot(chain: CardChain, dialedOrigin: String, cardHash: String, instanceId: String): PinVerdict? {
        if (chain.cards.isEmpty()) return PinVerdict.WITHHELD
        checkDialedOrigin(chain, dialedOrigin)?.let { return it }
        val card = chain.byHash(cardHash) ?: return PinVerdict.CARD_NOT_IN_CHAIN
        return if (card.fields.instanceId != instanceId) PinVerdict.INSTANCE_MISMATCH else null
    }

    /**
     * The TYPED-ADDRESS root (§4.4: the Trust Gate, the CLI's printed card and `--trust-card`, and the
     * gate an enrol link passes): trust on first use of [dialedOrigin]. No card served is `withheld`
     * (there is nothing to show or pin); the newest card must name [dialedOrigin]
     * (`origin_mismatch`). Null when the gate may be shown; Connect then pins the newest card.
     */
    fun checkTypedRoot(chain: CardChain, dialedOrigin: String): PinVerdict? {
        if (chain.cards.isEmpty()) return PinVerdict.WITHHELD
        return checkDialedOrigin(chain, dialedOrigin)
    }

    /**
     * §4.4 "On every policy probe or sync": judge the chain a server SERVED (card 0 first) against the
     * card this device pins, then verify forward from the pin.
     *
     * - No card served: `withheld`.
     * - Card 0 of the served chain does not hash to `pin.card0Hash`: `fork`, however short the chain is
     *   (a new chain after an operator reset, or a chain of another instance).
     * - The same chain with fewer than `pin.seq + 1` cards: `withheld`.
     * - The frame at index `pin.seq` does not hash to `pin.hash`: `fork`.
     * - Otherwise the pin is contained, and the cards after it are verified from it ([verify] with
     *   [pin] as the first head). The pinned hash fixes every earlier card through `prev`, so nothing
     *   below the pin is verified again.
     *
     * The first four are [Checkpoints.compareCard] over the served frame hashes.
     */
    fun follow(crypto: CryptoProvider, pin: CardHead, served: List<ByteArray>, operatorKeys: OperatorKeys? = null): CardFollow {
        val hashes = served.map { SignedFrame.hash(crypto, it) }
        when (Checkpoints.compareCard(pin.card0Hash, Checkpoint(pin.seq, pin.hash), hashes)) {
            CheckpointVerdict.OK -> Unit
            CheckpointVerdict.FORK -> return CardFollow(PinVerdict.FORK, emptyList(), null)
            else -> return CardFollow(PinVerdict.WITHHELD, emptyList(), null)
        }
        val result = verifyChain(crypto, served.drop((pin.seq + 1).toInt()), from = pin, operatorKeys = operatorKeys)
        return CardFollow(null, result.chain.cards, result.verdict)
    }

    /**
     * The X25519 image of a card's `operatorSignKey` (§4.1): the operator account's `identityPub`, over
     * which the operator's short fingerprint is SHOWN. Null when the key has no image.
     *
     * For display only. Two Ed25519 keys, a key and its negation, have the same image, so the image
     * never decides whose key a card names: that is [verify]'s byte comparison ([OperatorKeys]).
     */
    fun operatorIdentityKey(crypto: CryptoProvider, operatorSignKey: String): ByteArray? {
        val ed25519 = Bytes.fromB64Exact(operatorSignKey, 32) ?: return null
        return try {
            crypto.ed25519PkToCurve25519(ed25519)
        } catch (e: CryptoException) {
            null
        }
    }

    /**
     * §4.5 condition 3: the served recovery public key [recoveryPub] hashes to the card's [recoveryFp]
     * at full length (`hexLower(SHA-256(key))`, all 64 characters). False for a `none` fingerprint.
     */
    fun recoveryKeyMatches(crypto: CryptoProvider, recoveryFp: String?, recoveryPub: ByteArray): Boolean =
        recoveryFp != null && recoveryPub.size == 32 && TrustGrammar.isHex64(recoveryFp) &&
            Bytes.toHexLower(crypto.sha256(recoveryPub)) == recoveryFp
}
