package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Hkdf
import io.silencelen.andvari.core.crypto.KeyPairBytes

/** The kinds of link (design 2026-11-15 §6, §6.4). `SETUP` and `ENROL` are minted on the host and carry no signature. */
enum class LinkKind(val literal: String) {
    CONNECT("connect"),
    REGISTER("register"),
    SETUP("setup"),
    ENROL("enrol"),
    ;

    companion object {
        fun fromLiteral(literal: String): LinkKind? = entries.firstOrNull { it.literal == literal }
    }
}

/**
 * A parsed `/l` link (§6.1): the instance [origin] (already inside the §2.2 grammar), the 32-byte
 * link [secret] `s`, and the creator fingerprint [creatorFp] (`F`, 22 characters), or null for the `-`
 * of a host-minted setup or enrol link.
 *
 * The secret is the whole capability of the link. On the creating device it is kept ONLY in that
 * device's own state (§6.7 step 2, T-B6): never in account state, never on the web.
 */
class ParsedLink internal constructor(val origin: String, secret: ByteArray, val creatorFp: String?) {
    private val secretBytes = secret.copyOf()
    val secret: ByteArray get() = secretBytes.copyOf()
    fun wipe() = secretBytes.fill(0)
}

/**
 * The link URL and QR payload (§6.1):
 *
 * ```
 * https://andvaripass.com/l#v2.<O>.<S>.<F>
 * O = b64url(UTF-8(origin of the instance))        S = b64url(s), s = 32 CSPRNG bytes
 * F = the creator fingerprint (22 characters), or "-" for host-minted setup and enrol links
 * ```
 *
 * The host and path before `#` are NOT authenticated: any page could carry the fragment, so nothing
 * here reads them. The QR carries the full URL string, in byte mode at error-correction level M.
 */
object LinkUrl {
    /** The join base baked into store builds (§0.3). */
    const val JOIN_BASE = "https://andvaripass.com"

    /** §6.1: "Total length is at most 512", after ASCII white space is stripped. */
    const val MAX_LENGTH = 512

    /**
     * The link for [origin], [secret] (32 bytes) and [creatorFp] (the creator's `F`, or null for a
     * host-minted link, written `-`). Null when a part is outside its grammar or the result would be
     * longer than [MAX_LENGTH]: compose never makes a link [parse] would refuse.
     */
    fun compose(origin: String, secret: ByteArray, creatorFp: String?): String? {
        if (secret.size != 32) return null
        val url = "$JOIN_BASE/l#" + LinkText.fragment(origin, secret) + "." + (creatorFp ?: "-")
        val parsed = parse(url) ?: return null
        parsed.wipe()
        return url
    }

    /**
     * Total parse (§6.1): null on ANY malformed input, never a throw.
     *
     * - The input may be the whole URL or only the fragment (with or without its `#`).
     * - ASCII white space (space, tab, CR, LF) is stripped first; the result is at most 512 characters.
     * - The fragment is exactly four `.`-separated parts: `v2`, `O`, `S`, `F`.
     * - `O` decodes to an `origin` (§2.2); `O` and `S` re-encode identically (canonical unpadded
     *   base64url); `S` decodes to exactly 32 bytes.
     * - `F` is `-`, or decodes to exactly 16 bytes and re-encodes identically.
     *
     * The secret arrives inside [input], a `String` this code cannot wipe: that copy lives until the
     * runtime collects it. The decoded bytes are held once, in the result, which [ParsedLink.wipe] zeroes.
     */
    fun parse(input: String): ParsedLink? {
        val parts = LinkText.fragmentParts(input) ?: return null
        if (parts.size != 4) return null
        val origin = LinkText.origin(parts[1]) ?: return null
        val secret = Bytes.fromB64Exact(parts[2], 32) ?: return null
        // No real link's secret is all zeros, and nothing is derived from one: a bad link, never a lock.
        if (io.silencelen.andvari.core.crypto.KeyFloor.allZero(secret)) return null
        val f = parts[3]
        if (f != "-" && (f.length != 22 || Bytes.fromB64Exact(f, 16) == null)) {
            secret.fill(0)
            return null
        }
        return ParsedLink(origin, secret, f.takeIf { it != "-" }).also { secret.fill(0) }
    }

    /**
     * The creator fingerprint `F = b64url(SHA-256(raw 32 bytes of the creator's identityPub)[0..16])`
     * (§2.3, T-B6). It ties a link to the key of the person who made it: whoever learns `s` some other
     * way cannot swap in an offer under their own key.
     */
    fun creatorFingerprint(crypto: CryptoProvider, identityPub: ByteArray): String {
        require(identityPub.size == 32) { "identity key must be 32 bytes" }
        return Bytes.toB64(crypto.sha256(identityPub).copyOf(16))
    }
}

/** What `/l` and `/d` links share (§6.1, §8.1): the fragment's shape, and how `O` carries an origin. */
internal object LinkText {
    /**
     * The `.`-separated parts of a link's fragment, or null. ASCII white space is stripped first; the
     * result may be at most 512 characters; whatever stands before the first `#` is ignored, because the
     * host and path are not authenticated; the first part must be `v2`.
     */
    fun fragmentParts(input: String): List<String>? {
        val text = TrustGrammar.stripAsciiSpace(input)
        if (text.length > LinkUrl.MAX_LENGTH) return null
        val hash = text.indexOf('#')
        val parts = (if (hash < 0) text else text.substring(hash + 1)).split('.')
        return if (parts[0] == "v2") parts else null
    }

    /** `O`: canonical unpadded base64url of the UTF-8 of an `origin` (§2.2). Null otherwise. */
    fun origin(o: String): String? {
        val bytes = Bytes.fromB64Canonical(o) ?: return null
        if (bytes.any { it < 0x20 || it > 0x7E }) return null
        return bytes.decodeToString().takeIf(TrustGrammar::isOrigin)
    }

    /** `v2.<O>.<S>`: what both kinds of link start their fragment with. */
    fun fragment(origin: String, secret: ByteArray): String = "v2." + Bytes.toB64(origin.encodeToByteArray()) + "." + Bytes.toB64(secret)
}

/**
 * Everything derived from a link secret `s` (§2.3, §6.2). [linkId] is the `b64_16` text the server
 * keys the link by; [registerToken] the 43-character token of a register, setup or enrol link. The
 * server never sees `s`, [offerKey] or [answerKey] (§6.6).
 */
class LinkKeys internal constructor(val linkId: String, offerKey: ByteArray, answerKey: ByteArray, val registerToken: String) {
    private val offerKeyBytes = offerKey.copyOf()
    private val answerKeyBytes = answerKey.copyOf()
    val offerKey: ByteArray get() = offerKeyBytes.copyOf()
    val answerKey: ByteArray get() = answerKeyBytes.copyOf()

    fun wipe() {
        offerKeyBytes.fill(0)
        answerKeyBytes.fill(0)
    }
}

/** The derivations of a link (§2.3, §6.2). */
object Links {
    /**
     * §6.3 and §6.5: "at most 2,732 characters as sent (that is 2,049 bytes of envelope)", the offer
     * and the answer alike (FI-R6). An envelope is refused above this size by its builder
     * ([LinkOffer.seal], [LinkAnswer.seal]) and by its reader ([LinkOffer.open], [LinkAnswer.open]),
     * which answers `unopenable` before it derives a key or opens a byte. An envelope of exactly this
     * size is opened, and what is inside decides.
     */
    const val MAX_ENVELOPE_BYTES = 2049

    /**
     * From `s` (32 bytes), HKDF-SHA-256 with an empty salt:
     * - `linkId = b64url(HKDF(s, "andvari/v2|link|id", 16))`;
     * - `offerKey = HKDF(s, "andvari/v2|link|offer", 32)`;
     * - `answerKey = HKDF(s, "andvari/v2|link|answer", 32)`;
     * - `registerToken = b64url(HKDF(s, "andvari/v2|link|register", 32))`.
     */
    fun deriveKeys(crypto: CryptoProvider, secret: ByteArray): LinkKeys {
        require(secret.size == 32) { "link secret must be 32 bytes" }
        fun hkdf(info: String, length: Int) = Hkdf.sha256(crypto, ikm = secret, salt = ByteArray(0), info = info.encodeToByteArray(), length = length)
        val offerKey = hkdf("andvari/v2|link|offer", 32)
        val answerKey = hkdf("andvari/v2|link|answer", 32)
        val token = hkdf("andvari/v2|link|register", 32)
        try {
            return LinkKeys(
                linkId = Bytes.toB64(hkdf("andvari/v2|link|id", 16)),
                offerKey = offerKey,
                answerKey = answerKey,
                // The token travels as text in the register body, so it is a String from here on, and a
                // String cannot be wiped; the bytes it was made from are.
                registerToken = Bytes.toB64(token),
            )
        } finally {
            offerKey.fill(0)
            answerKey.fill(0)
            token.fill(0)
        }
    }

    /**
     * `tokenHash = b64url(SHA-256(ASCII(token)))` over the 43-character token string (§2.3): what the
     * server stores for a register, setup or enrol link (its `hashToken`).
     */
    fun tokenHash(crypto: CryptoProvider, registerToken: String): String =
        Bytes.toB64(crypto.sha256(registerToken.encodeToByteArray()))
}

/**
 * The code commitment both kinds of link use (§2.3, §6.11, T-B1): a party commits to a 32-byte nonce
 * before it sees the other side's, so neither side can steer the comparison code.
 */
object CodeCommit {
    const val NONCE_BYTES = 32

    /** `commit = hexLower(SHA-256("andvari/v2|code-commit|" + b64url(nonce)))`. [nonce] is 32 CSPRNG bytes. */
    fun commit(crypto: CryptoProvider, nonce: ByteArray): String {
        require(nonce.size == NONCE_BYTES) { "code nonce must be 32 bytes" }
        return Bytes.toHexLower(crypto.sha256(("andvari/v2|code-commit|" + Bytes.toB64(nonce)).encodeToByteArray()))
    }

    /**
     * True when the revealed [nonce] is the one [commit] committed to. False is `bad_reveal` (§6.11
     * pass 3, §8.2 step 4): the link is marked failed and no code is shown.
     */
    fun opens(crypto: CryptoProvider, nonce: ByteArray, commit: String): Boolean =
        nonce.size == NONCE_BYTES && Bytes.ctEquals(commit(crypto, nonce).encodeToByteArray(), commit.encodeToByteArray())

    /**
     * [opens] for a nonce as it arrives on the wire (a `b64_32` string): the link's `reveal`, or the
     * device link's `nonceN`. False when the text is not a `b64_32` at all.
     */
    fun opens(crypto: CryptoProvider, nonceB64: String, commit: String): Boolean {
        val nonce = if (nonceB64.length == 43) Bytes.fromB64Exact(nonceB64, NONCE_BYTES) else null
        return nonce != null && opens(crypto, nonce, commit)
    }
}

/**
 * The side of a link a comparison code belongs to (§2.3 "Link comparison code", §6.11): the link's
 * creator shows the [CREATOR] code and the answerer the [ANSWERER] code; each app accepts as typed
 * input only the [other] side's code. [code] is the literal the derivation hashes.
 */
enum class LinkSide(val code: String) {
    CREATOR("creator"),
    ANSWERER("answerer"),
    ;

    /** The side whose code this side's person types. */
    val other: LinkSide get() = if (this == CREATOR) ANSWERER else CREATOR

    companion object {
        /** The side named by [literal] exactly, or null. */
        fun fromCode(literal: String): LinkSide? = entries.firstOrNull { it.code == literal }
    }
}

/**
 * The six-digit comparison codes (§2.3, §6.11, §8.2 step 5). A code is computed ONCE, from the first
 * value a side accepted for the other side's nonce (T2-R-b); a second, different value is an anomaly
 * that fails the link, and no code is shown. `compared` is set only by this device's own correct
 * typed entry ([matches]); no wire message carries it (T2-R-i).
 */
object ComparisonCode {
    /**
     * `u32be(SHA-256("andvari/v2|link|code|" + side + "|" + linkId + "|" + offerHash + "|" + answerHash
     * + "|" + b64url(nonceA) + "|" + b64url(nonceB))[0..4]) mod 10^6`, zero-padded to 6 digits, with
     * `side` the literal of [side]. A link has two codes: its creator shows the [LinkSide.CREATOR] one
     * and its answerer the [LinkSide.ANSWERER] one, and each app checks the typed digits against the
     * OTHER side's code, which it never displays. [nonceA] is committed in the offer and revealed after
     * the answer; [nonceB] travels in the answer.
     */
    fun link(crypto: CryptoProvider, side: LinkSide, linkId: String, offerHash: String, answerHash: String, nonceA: ByteArray, nonceB: ByteArray): String {
        require(TrustGrammar.isB64_16(linkId)) { "linkId is not a b64_16" }
        require(TrustGrammar.isHex64(offerHash) && TrustGrammar.isHex64(answerHash)) { "frame hashes are hex64" }
        require(nonceA.size == 32 && nonceB.size == 32) { "code nonces are 32 bytes" }
        return sixDigits(crypto, "andvari/v2|link|code|${side.code}|$linkId|$offerHash|$answerHash|${Bytes.toB64(nonceA)}|${Bytes.toB64(nonceB)}")
    }

    /** `u32be(SHA-256(text)[0..4]) mod 10^6`, zero-padded to six digits. */
    private fun sixDigits(crypto: CryptoProvider, text: String): String {
        val d = crypto.sha256(text.encodeToByteArray())
        val u32 = ((d[0].toLong() and 0xFF) shl 24) or ((d[1].toLong() and 0xFF) shl 16) or ((d[2].toLong() and 0xFF) shl 8) or (d[3].toLong() and 0xFF)
        return (u32 % 1_000_000).toString().padStart(6, '0')
    }

    /**
     * `u32be(SHA-256("andvari/v2|device-link|code|" + linkId + "|" + nPub + "|" + b64url(nonceN) + "|"
     * + b64url(nonceE))[0..4]) mod 10^6`, zero-padded to 6 digits. [nPub] is the new device's 32-byte
     * key (it enters the string as its 43-character base64url).
     */
    fun deviceLink(crypto: CryptoProvider, linkId: String, nPub: ByteArray, nonceN: ByteArray, nonceE: ByteArray): String {
        require(TrustGrammar.isB64_16(linkId)) { "linkId is not a b64_16" }
        require(nPub.size == 32 && nonceN.size == 32 && nonceE.size == 32) { "the key and the code nonces are 32 bytes" }
        return sixDigits(crypto, "andvari/v2|device-link|code|$linkId|${Bytes.toB64(nPub)}|${Bytes.toB64(nonceN)}|${Bytes.toB64(nonceE)}")
    }

    /**
     * Whether [typed] is [code] as a person types it (§6.11 "Typed input"). The comparison is on TEXT:
     * every ASCII space (U+0020) is removed, because a code is shown as `481 207`, and what is left must
     * be exactly six ASCII digits, equal to [code]. Nothing else is normalised: a tab, a line break, any
     * other character, a seventh digit and a dropped leading zero are all a mismatch.
     *
     * [code] is the code this app ACCEPTS: for a link the OTHER side's code ([linkAccepts]), for a device
     * link the one code. There is no "they match" button. For a link a wrong entry is not a verdict: the
     * answer is no, the app says so, and the person may type again (§6.11); for a device link the engine
     * cancels the link (`code_mismatch`, §8.2).
     */
    fun matches(typed: String, code: String): Boolean {
        val entry = if (' ' in typed) typed.filterNot { it == ' ' } else typed
        if (entry.length != 6 || code.length != 6 || entry.any { it !in '0'..'9' }) return false
        return Bytes.ctEquals(entry.encodeToByteArray(), code.encodeToByteArray())
    }

    /**
     * The typed-entry check of a LINK (§6.11): digits typed into the app of [typedInto] are accepted only
     * when they are the OTHER side's code, which that app computes and never displays. This alone sets
     * `compared = true`, on that device only (T2-R-i).
     *
     * When the two codes of a link happen to be the same six digits (about one link in a million) nothing
     * special happens: the app still accepts exactly the other side's code, which is then also the one
     * on its own screen. A typed code is never refused for being equal to the app's own.
     */
    fun linkAccepts(
        crypto: CryptoProvider,
        typedInto: LinkSide,
        typed: String,
        linkId: String,
        offerHash: String,
        answerHash: String,
        nonceA: ByteArray,
        nonceB: ByteArray,
    ): Boolean = matches(typed, link(crypto, typedInto.other, linkId, offerHash, answerHash, nonceA, nonceB))
}

/**
 * A connect or register offer as its statement says it (§6.3, purpose 0x06). [kind] is `CONNECT` or
 * `REGISTER`. [fromKey] is the creator's X25519 identity key (`b64_32`), [name] the creator's display
 * name as they chose it (decoded; show it "as they call themselves"), [cardHash] the hash of the
 * newest card the creator's device verified, [commit] the commitment to the creator's code nonce.
 */
data class LinkOfferFields(
    val linkId: String,
    val kind: LinkKind,
    val origin: String,
    val instanceId: String,
    val cardHash: String,
    val from: String,
    val fromKey: String,
    val name: String,
    val commit: String,
    val expiresAt: Long,
    val issuedAt: Long,
)

/** The host-minted setup offer (§6.4): canonical JSON, no signature. [recoveryFp] null is `none`. */
data class SetupOfferFields(
    val linkId: String,
    val origin: String,
    val instanceId: String,
    val name: String,
    val kind: InstanceKind,
    val recoveryFp: String?,
    val expiresAt: Long,
)

/**
 * The host-minted enrol offer (§6.4): canonical JSON, no signature. [email] is the `emailNorm` the link
 * is bound to, or null for `none`. [cardHash] is the host's own claim: it is shown in the Trust Gate
 * and is NEVER a pin root (§4.4, U3).
 */
data class EnrolOfferFields(
    val linkId: String,
    val origin: String,
    val instanceId: String,
    val cardHash: String,
    val email: String?,
    val expiresAt: Long,
)

/** What `GET /links/{linkId}` reported about a link (§6.6). All of it is the server's word: compared, never trusted. */
class ServedLink(val kind: String, val creatorUserId: String?, val creatorIdentityPub: String?)

/** An offer that passed §6.8 steps 3 and 4. It is still only an offer: the card chain (step 5), the key-change check (step 6) and the person's confirmation (step 7) are the engine's. */
sealed class OpenedOffer {
    abstract val kind: LinkKind
    abstract val linkId: String
    abstract val origin: String
    abstract val instanceId: String
    abstract val expiresAt: Long

    /** A connect or register offer, signed by its creator. [offerHash] is `H(offer frame)`, which the answer repeats. */
    class Signed internal constructor(val fields: LinkOfferFields, val offerHash: String) : OpenedOffer() {
        override val kind get() = fields.kind
        override val linkId get() = fields.linkId
        override val origin get() = fields.origin
        override val instanceId get() = fields.instanceId
        override val expiresAt get() = fields.expiresAt
    }

    /** A setup offer: enrols the first operator (§6.7). The instance must serve no cards yet. */
    class Setup internal constructor(val fields: SetupOfferFields) : OpenedOffer() {
        override val kind get() = LinkKind.SETUP
        override val linkId get() = fields.linkId
        override val origin get() = fields.origin
        override val instanceId get() = fields.instanceId
        override val expiresAt get() = fields.expiresAt
    }

    /** An enrol offer: registers an ordinary member with no inviter; no contact is pinned (§6.4). */
    class Enrol internal constructor(val fields: EnrolOfferFields) : OpenedOffer() {
        override val kind get() = LinkKind.ENROL
        override val linkId get() = fields.linkId
        override val origin get() = fields.origin
        override val instanceId get() = fields.instanceId
        override val expiresAt get() = fields.expiresAt
    }
}

/**
 * Why a link offer or answer was refused (§6.4, §6.8, §6.11; names and order from §2.4 "Opening a
 * link", "Processing an answer" and "Host JSON offer", VR-14, VR-15). These are the FORMAT-level
 * verdicts. The flow around them adds its own, which are the engine's: `bad_link` (the URL does not
 * parse, [LinkUrl.parse] returned null), the server's `link_unknown`, `link_expired` and `link_used`,
 * the pinning verdicts ([PinVerdict]), and the `key_changed` prompt, which is not a verdict.
 */
enum class LinkVerdict(val code: String) {
    /** Creator step 1: this device holds no record for the link (dropped at expiry or revocation, T-R3). The answer is ignored, whatever the server says. */
    UNKNOWN_LINK("unknown_link"),

    /** The envelope does not open under the link's key and AD. */
    UNOPENABLE("unopenable"),

    /** The opened plaintext is neither a signed frame nor host JSON, or is host JSON whose `purpose` is neither `setup-offer` nor `enrol-offer` (§6.4, VR-15). */
    UNKNOWN_FORMAT("unknown_format"),

    /** The offer's kind is not the kind the server reported for the link (§6.4): nothing is sent, nothing is pinned. */
    KIND_MISMATCH("kind_mismatch"),

    /** A frame that is not purpose 0x06 (an offer) or 0x07 (an answer), or is not a usable frame. */
    BAD_FRAME("bad_frame"),
    NON_CANONICAL("non_canonical"),
    BAD_STATEMENT("bad_statement"),

    /** `fromKey` does not hash to the link's `F`, or a host-minted offer came through a link whose `F` is not `-` (T-B6). */
    CREATOR_MISMATCH("creator_mismatch"),

    /** The signer does not map to the key the helper was handed: the statement's own `fromKey` (§2.4, VR-9). */
    SIGNER_NOT_PINNED_KEY("signer_not_pinned_key"),
    BAD_SIGNATURE("bad_signature"),

    /** The statement's `linkId` is not the one derived from the link's secret. */
    LINK_MISMATCH("link_mismatch"),

    /** The offer's `origin` is not the link's. */
    ORIGIN_MISMATCH("origin_mismatch"),

    /** The offer's `expiresAt` is not after the time the caller passed. */
    OFFER_EXPIRED("offer_expired"),

    /** The offer's `from` or `fromKey` is not the creator the server reported for the link: an anomaly, nothing is sent (T-R5). */
    REPORTED_CREATOR_MISMATCH("reported_creator_mismatch"),

    /** An answer whose `offerHash` is not the offer this device made. */
    OFFER_MISMATCH("offer_mismatch"),

    /** An answer whose `to` or `toKey` is not this account. */
    MISADDRESSED("misaddressed"),

    /** An answer whose `from` is not the answerer the server reported: an anomaly, nothing is pinned. */
    REPORTED_ANSWERER_MISMATCH("reported_answerer_mismatch"),

    /** The revealed nonce does not open the offer's commitment (§6.11 pass 3). */
    BAD_REVEAL("bad_reveal"),
}

/** Offers (§6.3, §6.4) and the recipient's checks on them (§6.8). */
object LinkOffer {
    /**
     * Encode and sign a connect or register offer with [signer], the creator's joint Ed25519 key.
     * Refuses (`IllegalArgumentException`) values outside the grammar, a kind other than connect or
     * register, and a [signer] that does not map to `fromKey`. Returns the frame; `H(frame)` is the
     * `offerHash` the creating device stores with the link (§6.7 step 2).
     */
    fun sign(crypto: CryptoProvider, signer: KeyPairBytes, offer: LinkOfferFields): ByteArray {
        require(offer.kind == LinkKind.CONNECT || offer.kind == LinkKind.REGISTER) { "a signed offer is a connect or a register offer" }
        require(signerKeyIs(crypto, signer, offer.fromKey)) { "an offer is signed by the fromKey it names" }
        val name = requireNotNull(TrustGrammar.encodeName(offer.name)) { "the offer's name is not a name (§2.2)" }
        val statement = StatementCodec.encode(
            TrustPurpose.LINK_OFFER,
            mapOf(
                "linkId" to offer.linkId, "kind" to offer.kind.literal, "origin" to offer.origin, "instanceId" to offer.instanceId,
                "cardHash" to offer.cardHash, "from" to offer.from, "fromKey" to offer.fromKey, "name" to name, "commit" to offer.commit,
                "expiresAt" to offer.expiresAt.toString(), "issuedAt" to offer.issuedAt.toString(),
            ),
        )
        return SignedFrame.sign(crypto, signer, TrustPurpose.LINK_OFFER, statement)
    }

    /** The canonical JSON of a setup offer (§6.4), for `andvari setup`. */
    fun encodeSetup(offer: SetupOfferFields): ByteArray {
        val name = requireNotNull(TrustGrammar.encodeName(offer.name)) { "the offer's name is not a name (§2.2)" }
        require(offer.recoveryFp == null || TrustGrammar.isHex64(offer.recoveryFp)) { "recoveryFp is a hex64, or null for none" }
        return StatementCodec.encodeHostOffer(
            StatementCodec.SETUP_OFFER,
            mapOf(
                "linkId" to offer.linkId, "origin" to offer.origin, "instanceId" to offer.instanceId, "name" to name,
                "kind" to offer.kind.literal, "recoveryFp" to (offer.recoveryFp ?: TrustGrammar.NONE), "expiresAt" to offer.expiresAt.toString(),
            ),
        )
    }

    /** The canonical JSON of an enrol offer (§6.4), for `andvari admin enrol-link`. */
    fun encodeEnrol(offer: EnrolOfferFields): ByteArray {
        val email = requireNotNull(TrustGrammar.encodeEmail(offer.email)) { "the offer's email is not an emailNorm (§2.3)" }
        return StatementCodec.encodeHostOffer(
            StatementCodec.ENROL_OFFER,
            mapOf(
                "linkId" to offer.linkId, "origin" to offer.origin, "instanceId" to offer.instanceId, "cardHash" to offer.cardHash,
                "email" to email, "expiresAt" to offer.expiresAt.toString(),
            ),
        )
    }

    /**
     * `Envelope(offerKey, plaintext, AD = "andvari/v2|link-offer|" + linkId)` (§6.3, §6.4), for a
     * signed offer frame or a host offer's JSON. Refuses a result above [Links.MAX_ENVELOPE_BYTES].
     */
    fun seal(crypto: CryptoProvider, keys: LinkKeys, plaintext: ByteArray): ByteArray {
        val key = keys.offerKey
        try {
            val envelope = Envelope.seal(crypto, key, plaintext, Ad.linkOffer(keys.linkId))
            require(envelope.size <= Links.MAX_ENVELOPE_BYTES) { "an offer envelope is at most 2,049 bytes" }
            return envelope
        } finally {
            key.fill(0)
        }
    }

    /** True when [signer]'s X25519 image is the key [keyB64] (`b64_32` text) names. */
    internal fun signerKeyIs(crypto: CryptoProvider, signer: KeyPairBytes, keyB64: String): Boolean = try {
        Bytes.toB64(crypto.ed25519PkToCurve25519(signer.publicKey)) == keyB64
    } catch (e: CryptoException) {
        false
    }

    /**
     * The recipient's checks on an offer (§6.8 steps 3 and 4), in §2.4's order; the first failure is
     * the verdict. The signed-statement helper's checks run BEFORE the field checks (VR-14), and
     * `kind_mismatch` is returned as soon as it can be known.
     *
     * 1. The envelope is at most [Links.MAX_ENVELOPE_BYTES] (§6.3), checked before a key is derived or
     *    a byte is opened, and opens under `offerKey` with the AD (`unopenable` for either: a longer one
     *    is not an envelope any creator's [seal] can have made).
     * 2. Recognise the plaintext (§6.4): the frame magic means a signed frame; `{` means host JSON,
     *    which must be printable ASCII and a JSON object with a string `purpose` (`non_canonical`),
     *    that purpose being `setup-offer` or `enrol-offer` (`unknown_format`); anything else is
     *    `unknown_format`.
     * 3. `kind_mismatch` from the FORM alone, before any parse: a signed frame where [served]`.kind`
     *    is `setup` or `enrol`, host JSON where it is `connect` or `register`, or host JSON of the
     *    other host kind.
     * 4. **A signed offer:** a frame of purpose 0x06 (`bad_frame`) and the strict parse
     *    (`non_canonical`, `bad_statement`); its own `kind` is [served]`.kind` (`kind_mismatch`);
     *    `fromKey` hashes to the link's `F` (`creator_mismatch`, also when `F` is `-`); the signer maps
     *    to `fromKey` (`signer_not_pinned_key`); the signature verifies (`bad_signature`).
     *    **Host JSON:** the template's strict parse (`non_canonical`, `bad_statement`); the link's `F`
     *    is `-` (`creator_mismatch`).
     * 5. The field checks: `linkId` is the derived one (`link_mismatch`); `origin` is the link's
     *    (`origin_mismatch`); `expiresAt > nowMs` (`offer_expired`); and for a signed offer `from` is
     *    the served `creatorUserId` and `fromKey` the served `creatorIdentityPub`
     *    (`reported_creator_mismatch`).
     *
     * [nowMs] is the caller's clock: this function reads none. What comes after is the engine's: the
     * card chain under §4.4's roots, the key-change check, and the person's confirmation.
     */
    fun open(
        crypto: CryptoProvider,
        link: ParsedLink,
        envelope: ByteArray,
        served: ServedLink,
        nowMs: Long,
    ): Checked<OpenedOffer, LinkVerdict> {
        // 1, before anything is derived or opened: no creator can have built an envelope above the bound.
        if (envelope.size > Links.MAX_ENVELOPE_BYTES) return refuse(LinkVerdict.UNOPENABLE)
        // `link.secret` hands out a copy: it is zeroed as soon as the keys are derived from it.
        val secret = link.secret
        val keys = try {
            Links.deriveKeys(crypto, secret)
        } finally {
            secret.fill(0)
        }
        val offerKey = keys.offerKey
        try {
            // 1. The envelope.
            val plaintext = try {
                Envelope.open(crypto, offerKey, envelope, Ad.linkOffer(keys.linkId))
            } catch (e: CryptoException) {
                return refuse(LinkVerdict.UNOPENABLE)
            }
            val servedKind = LinkKind.fromLiteral(served.kind)
            // 2, 3. Recognise the plaintext by its form, and refuse a form the reported kind cannot have.
            return when {
                SignedFrame.hasMagic(plaintext) -> {
                    if (servedKind != LinkKind.CONNECT && servedKind != LinkKind.REGISTER) return refuse(LinkVerdict.KIND_MISMATCH)
                    openSigned(crypto, link, keys.linkId, plaintext, servedKind, served, nowMs)
                }
                plaintext.isNotEmpty() && plaintext[0] == '{'.code.toByte() -> {
                    if (servedKind != LinkKind.SETUP && servedKind != LinkKind.ENROL) return refuse(LinkVerdict.KIND_MISMATCH)
                    openHost(link, keys.linkId, plaintext, servedKind, nowMs)
                }
                else -> refuse(LinkVerdict.UNKNOWN_FORMAT)
            }
        } finally {
            offerKey.fill(0)
            keys.wipe()
        }
    }

    private fun openSigned(
        crypto: CryptoProvider,
        link: ParsedLink,
        linkId: String,
        frame: ByteArray,
        servedKind: LinkKind,
        served: ServedLink,
        nowMs: Long,
    ): Checked<OpenedOffer, LinkVerdict> {
        // 4. The helper's checks: the parse, the kind, F, the signer, the signature.
        val parsed = when (val p = StatementCodec.parseFrame(frame, TrustPurpose.LINK_OFFER)) {
            is Checked.Ok -> p.value
            is Checked.Refused -> return refuse(frameVerdict(p.verdict))
        }
        val raw = parsed.raw
        val kind = LinkKind.fromLiteral(raw.str("kind")) ?: return refuse(LinkVerdict.NON_CANONICAL)
        if (kind != servedKind) return refuse(LinkVerdict.KIND_MISMATCH)
        val fromKey = Bytes.fromB64Exact(raw.str("fromKey"), 32) ?: return refuse(LinkVerdict.NON_CANONICAL)
        // The link's F ties it to the key of the person who made it (T-B6). A host-minted link has none.
        if (link.creatorFp == null || LinkUrl.creatorFingerprint(crypto, fromKey) != link.creatorFp) return refuse(LinkVerdict.CREATOR_MISMATCH)
        // The helper is handed fromKey only now that it passed F (§2.4).
        if (!SignedFrame.signerMapsTo(crypto, parsed.parts, fromKey)) return refuse(LinkVerdict.SIGNER_NOT_PINNED_KEY)
        if (!SignedFrame.signatureValid(crypto, parsed.parts)) return refuse(LinkVerdict.BAD_SIGNATURE)
        // 5. The field checks.
        if (raw.str("linkId") != linkId) return refuse(LinkVerdict.LINK_MISMATCH)
        if (raw.str("origin") != link.origin) return refuse(LinkVerdict.ORIGIN_MISMATCH)
        if (raw.long("expiresAt") <= nowMs) return refuse(LinkVerdict.OFFER_EXPIRED)
        val reportedKey = served.creatorIdentityPub?.let { runCatching { Bytes.fromB64(it) }.getOrNull() }
        if (served.creatorUserId != raw.str("from") || reportedKey == null || !Bytes.ctEquals(reportedKey, fromKey)) {
            return refuse(LinkVerdict.REPORTED_CREATOR_MISMATCH)
        }
        val name = TrustGrammar.decodeName(raw.str("name")) ?: return refuse(LinkVerdict.NON_CANONICAL)
        val fields = LinkOfferFields(
            linkId = raw.str("linkId"), kind = kind, origin = raw.str("origin"), instanceId = raw.str("instanceId"),
            cardHash = raw.str("cardHash"), from = raw.str("from"), fromKey = raw.str("fromKey"), name = name, commit = raw.str("commit"),
            expiresAt = raw.long("expiresAt"), issuedAt = raw.long("issuedAt"),
        )
        return Checked.Ok(OpenedOffer.Signed(fields, SignedFrame.hash(crypto, frame)))
    }

    private fun openHost(link: ParsedLink, linkId: String, json: ByteArray, servedKind: LinkKind, nowMs: Long): Checked<OpenedOffer, LinkVerdict> {
        // 2. A JSON object with a string purpose, which is setup-offer or enrol-offer.
        val purpose = when (val p = StatementCodec.hostOfferPurpose(json)) {
            is Checked.Ok -> p.value
            is Checked.Refused -> return refuse(frameVerdict(p.verdict))
        }
        // 3. The other host kind than the one the server reported.
        val kind = if (purpose == StatementCodec.SETUP_OFFER) LinkKind.SETUP else LinkKind.ENROL
        if (kind != servedKind) return refuse(LinkVerdict.KIND_MISMATCH)
        // 4. The template, then F: a host-minted link carries no creator fingerprint.
        val raw = when (val p = StatementCodec.parseHostOffer(json)) {
            is Checked.Ok -> p.value
            is Checked.Refused -> return refuse(frameVerdict(p.verdict))
        }
        if (link.creatorFp != null) return refuse(LinkVerdict.CREATOR_MISMATCH)
        // 5. The field checks.
        if (raw.str("linkId") != linkId) return refuse(LinkVerdict.LINK_MISMATCH)
        if (raw.str("origin") != link.origin) return refuse(LinkVerdict.ORIGIN_MISMATCH)
        if (raw.long("expiresAt") <= nowMs) return refuse(LinkVerdict.OFFER_EXPIRED)
        if (kind == LinkKind.SETUP) {
            val name = TrustGrammar.decodeName(raw.str("name")) ?: return refuse(LinkVerdict.NON_CANONICAL)
            val instanceKind = InstanceKind.fromLiteral(raw.str("kind")) ?: return refuse(LinkVerdict.NON_CANONICAL)
            return Checked.Ok(
                OpenedOffer.Setup(
                    SetupOfferFields(
                        raw.str("linkId"), raw.str("origin"), raw.str("instanceId"), name, instanceKind,
                        raw.str("recoveryFp").takeIf { it != TrustGrammar.NONE }, raw.long("expiresAt"),
                    ),
                ),
            )
        }
        val email = TrustGrammar.decodeEmail(raw.str("email")) ?: return refuse(LinkVerdict.NON_CANONICAL)
        return Checked.Ok(
            OpenedOffer.Enrol(
                EnrolOfferFields(raw.str("linkId"), raw.str("origin"), raw.str("instanceId"), raw.str("cardHash"), email.orNull, raw.long("expiresAt")),
            ),
        )
    }

    internal fun refuse(verdict: LinkVerdict): Checked.Refused<LinkVerdict> = Checked.Refused(verdict)

    internal fun frameVerdict(v: FrameVerdict): LinkVerdict = when (v) {
        FrameVerdict.BAD_FRAME -> LinkVerdict.BAD_FRAME
        FrameVerdict.UNKNOWN_FORMAT -> LinkVerdict.UNKNOWN_FORMAT
        FrameVerdict.NON_CANONICAL -> LinkVerdict.NON_CANONICAL
        FrameVerdict.BAD_STATEMENT -> LinkVerdict.BAD_STATEMENT
    }
}

/**
 * A link answer as its statement says it (§6.5, purpose 0x07). [to] and [toKey] are the offer's
 * `from` and `fromKey`; [from] and [fromKey] the answering account; [nonce] the answerer's code nonce
 * `nonceB` (`b64_32`), sent in the open inside the sealed answer.
 */
data class LinkAnswerFields(
    val linkId: String,
    val offerHash: String,
    val to: String,
    val toKey: String,
    val from: String,
    val fromKey: String,
    val name: String,
    val nonce: String,
    val issuedAt: Long,
)

/** An answer that passed the creator's checks 2 to 5 of §6.8. [answerHash] is `H(answer frame)`, an input of the comparison code. */
class OpenedAnswer internal constructor(val fields: LinkAnswerFields, val answerHash: String)

/** Answers (§6.5) and the creator's checks on them (§6.8). */
object LinkAnswer {
    /**
     * Encode and sign an answer with [signer], the answering account's joint Ed25519 key. Refuses
     * (`IllegalArgumentException`) values outside the grammar and a [signer] that does not map to
     * `fromKey`. `H(frame)` is the `answerHash` of the comparison code.
     */
    fun sign(crypto: CryptoProvider, signer: KeyPairBytes, answer: LinkAnswerFields): ByteArray {
        require(LinkOffer.signerKeyIs(crypto, signer, answer.fromKey)) { "an answer is signed by the fromKey it names" }
        val name = requireNotNull(TrustGrammar.encodeName(answer.name)) { "the answer's name is not a name (§2.2)" }
        val statement = StatementCodec.encode(
            TrustPurpose.LINK_ANSWER,
            mapOf(
                "linkId" to answer.linkId, "offerHash" to answer.offerHash, "to" to answer.to, "toKey" to answer.toKey,
                "from" to answer.from, "fromKey" to answer.fromKey, "name" to name, "nonce" to answer.nonce,
                "issuedAt" to answer.issuedAt.toString(),
            ),
        )
        return SignedFrame.sign(crypto, signer, TrustPurpose.LINK_ANSWER, statement)
    }

    /** `Envelope(answerKey, frame, AD = "andvari/v2|link-answer|" + linkId)` (§6.5). Refuses a result above [Links.MAX_ENVELOPE_BYTES]. */
    fun seal(crypto: CryptoProvider, keys: LinkKeys, frame: ByteArray): ByteArray {
        val key = keys.answerKey
        try {
            val envelope = Envelope.seal(crypto, key, frame, Ad.linkAnswer(keys.linkId))
            require(envelope.size <= Links.MAX_ENVELOPE_BYTES) { "an answer envelope is at most 2,049 bytes" }
            return envelope
        } finally {
            key.fill(0)
        }
    }

    /**
     * The creating device's checks on an answer (§6.8 creator steps 2 to 5), in §2.4's order; the
     * first failure is the verdict. Step 1 is the caller's: it finds its own record for the link in
     * THIS device's state and passes that record's [secret] and [offerHash]; without a record there is
     * nothing to open (`unknown_link`).
     *
     * 1. The envelope is at most [Links.MAX_ENVELOPE_BYTES] (§6.5), checked before a key is derived or
     *    a byte is opened, and opens under `answerKey` with the AD (`unopenable` for either).
     * 2. A frame of purpose 0x07 (`unknown_format`, `bad_frame`) and the strict parse (`non_canonical`,
     *    `bad_statement`).
     * 3. The signer maps to the answer's own `fromKey` (`signer_not_pinned_key`) and the signature
     *    verifies (`bad_signature`). This is proof of possession only: the comparison code is what
     *    authenticates the answerer later.
     * 4. `linkId` is the derived one (`link_mismatch`); `offerHash` is [offerHash] (`offer_mismatch`);
     *    `to` is [myUserId] and `toKey` is [myIdentityPub] (`misaddressed`); `from` is
     *    [servedAnswererUserId] (`reported_answerer_mismatch`).
     */
    fun open(
        crypto: CryptoProvider,
        secret: ByteArray,
        offerHash: String,
        myUserId: String,
        myIdentityPub: ByteArray,
        envelope: ByteArray,
        servedAnswererUserId: String,
    ): Checked<OpenedAnswer, LinkVerdict> {
        // 1, before anything is derived or opened: no answerer can have built an envelope above the bound.
        if (envelope.size > Links.MAX_ENVELOPE_BYTES) return LinkOffer.refuse(LinkVerdict.UNOPENABLE)
        val keys = Links.deriveKeys(crypto, secret)
        val answerKey = keys.answerKey
        try {
            // 1. The envelope.
            val frame = try {
                Envelope.open(crypto, answerKey, envelope, Ad.linkAnswer(keys.linkId))
            } catch (e: CryptoException) {
                return LinkOffer.refuse(LinkVerdict.UNOPENABLE)
            }
            // 2. The frame and the strict parse.
            val parsed = when (val p = StatementCodec.parseFrame(frame, TrustPurpose.LINK_ANSWER)) {
                is Checked.Ok -> p.value
                is Checked.Refused -> return LinkOffer.refuse(LinkOffer.frameVerdict(p.verdict))
            }
            val raw = parsed.raw
            // 3. Proof of possession of the answer's own fromKey.
            val fromKey = Bytes.fromB64Exact(raw.str("fromKey"), 32) ?: return LinkOffer.refuse(LinkVerdict.NON_CANONICAL)
            if (!SignedFrame.signerMapsTo(crypto, parsed.parts, fromKey)) return LinkOffer.refuse(LinkVerdict.SIGNER_NOT_PINNED_KEY)
            if (!SignedFrame.signatureValid(crypto, parsed.parts)) return LinkOffer.refuse(LinkVerdict.BAD_SIGNATURE)
            // 4. The field checks.
            if (raw.str("linkId") != keys.linkId) return LinkOffer.refuse(LinkVerdict.LINK_MISMATCH)
            if (raw.str("offerHash") != offerHash) return LinkOffer.refuse(LinkVerdict.OFFER_MISMATCH)
            val toKey = Bytes.fromB64Exact(raw.str("toKey"), 32)
            if (raw.str("to") != myUserId || toKey == null || !Bytes.ctEquals(toKey, myIdentityPub)) return LinkOffer.refuse(LinkVerdict.MISADDRESSED)
            if (raw.str("from") != servedAnswererUserId) return LinkOffer.refuse(LinkVerdict.REPORTED_ANSWERER_MISMATCH)
            val name = TrustGrammar.decodeName(raw.str("name")) ?: return LinkOffer.refuse(LinkVerdict.NON_CANONICAL)
            val fields = LinkAnswerFields(
                linkId = raw.str("linkId"), offerHash = raw.str("offerHash"), to = raw.str("to"), toKey = raw.str("toKey"),
                from = raw.str("from"), fromKey = raw.str("fromKey"), name = name, nonce = raw.str("nonce"), issuedAt = raw.long("issuedAt"),
            )
            return Checked.Ok(OpenedAnswer(fields, SignedFrame.hash(crypto, frame)))
        } finally {
            answerKey.fill(0)
            keys.wipe()
        }
    }
}
