package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Bytes

/** The value types a template field can have (design 2026-11-15 §2.2). */
internal enum class FieldType {
    /** The `v` number: the `int` type (§2.2, VR-4). Its value must then be 2 (`bad_statement`). */
    V,

    /** The `purpose` literal: one of the literals the caller allows. It must then be the expected one (`bad_statement`). */
    PURPOSE,
    UUID,
    B64_16,
    B64_32,

    /**
     * A `b64_32` that is a KEY (a grant's `vk`, an assisted recovery's `uvk`): the same grammar, but its
     * text is never made into a `String`. It is checked where it stands in the statement bytes and read
     * with [RawStatement.secret].
     */
    SECRET_B64_32,
    HEX64,
    HEX64N,
    MS,
    INT,
    ORIGIN,
    NAME,
    ROLE,
    EMAIL_B64N,

    /** `email_b64` (spec 01 §5.1): the `email_b64n` grammar without the literal `none`, so always an address. */
    EMAIL_B64,

    /** One of the ten log kinds (§3.1). */
    LOG_KIND,

    /** `public` or `private` (§4.1, §6.4). */
    INSTANCE_KIND,

    /** `connect` or `register` (§6.3). */
    LINK_KIND,
    ;

    /** JSON numbers are written bare; every other value is a JSON string that never needs escaping. */
    val isNumber: Boolean get() = this == V || this == MS || this == INT
}

internal class Field(val name: String, val type: FieldType)

/** One statement template: its fields in their exact order (§2.2: "exact key order per template, every key present exactly once"). */
internal class Template(val fields: List<Field>)

/**
 * A statement that passed the canonical parse: each PLAIN field's value as the exact text it had in the
 * statement (a number's digits, a string's content). NOT authenticated.
 *
 * A secret field (a grant's `vk`, an assisted recovery's `uvk`) is not among [values] and never becomes
 * a `String`: [secret] decodes it straight from the statement bytes, which this object does not copy.
 */
internal class RawStatement(
    val template: Template,
    val values: Map<String, String>,
    private val statement: ByteArray,
    private val secretAt: Map<String, Int>,
) {
    fun str(name: String): String = values.getValue(name)
    fun long(name: String): Long = values.getValue(name).toLong()

    /**
     * The 32 bytes of the secret field [name], decoded from the statement bytes into a fresh array that
     * the caller wipes. Refuses (`IllegalStateException`) a field that is not a secret field of this
     * statement, and a statement whose bytes were wiped since ([FrameParts.wipe]).
     */
    fun secret(name: String): ByteArray {
        val at = checkNotNull(secretAt[name]) { "$name is not a secret field of this statement" }
        val key = Bytes.fromB64Bytes(statement, at, at + StatementCodec.B64_32_CHARS)
        check(key != null && key.size == 32) { "the statement was wiped" }
        return key
    }
}

/** A frame that passed the whole §2 parse for one purpose: its parts and its statement's values. NOT authenticated. */
internal class ParsedFrame(val parts: FrameParts, val raw: RawStatement)

/**
 * The strict canonical parser and encoder behind every statement of this package (design §2.2, spec 01
 * §5.1).
 *
 * It never hands a statement to a JSON parser. It walks the template over the statement BYTES and
 * consumes one literal and one typed value at a time: the exact text `"name":`, then a bare run of
 * digits for a number or a quoted run for a string, each judged by its type's grammar. A statement is
 * accepted exactly when it IS the canonical rendering of in-grammar values, which is what "strict parse
 * followed by a re-encode byte-compare" (§2.2) decides: white space, key order, a missing, extra or
 * repeated key, an escape and every other number form fail to match. The web twin was written on its
 * own and works the same way (`web/src/crypto/trust/codec.ts`); `statement-v2.json` grades both.
 *
 * Two things follow from working on the bytes.
 * - **No nesting can reach a parser** (§2.2: "a `[` anywhere, or a second `{`, is `non_canonical`,
 *   refused before any general JSON parser sees the text"). There is no parser to reach, and nothing
 *   here recurses, so a statement of a thousand brackets is a verdict and never a stack overflow.
 * - **A key never becomes a `String`**, which could not be wiped. A secret field is checked where it
 *   stands, and [RawStatement.secret] decodes it into a byte array; [encode] writes one from bytes.
 *
 * A host-minted offer (§6.4) is first recognised by [StrictJson], which bounds its own recursion at 32
 * open containers, and then matched against its template in the same way.
 */
internal object StatementCodec {
    /** A `b64_32` is 43 characters of base64url. */
    const val B64_32_CHARS = 43

    private fun t(vararg fields: Pair<String, FieldType>) = Template(fields.map { Field(it.first, it.second) })

    private val HEAD = arrayOf("v" to FieldType.V, "purpose" to FieldType.PURPOSE)

    // ---- §3.1 vault-log -----------------------------------------------------------------------------

    private val LOG_HEAD = arrayOf(
        *HEAD, "vaultId" to FieldType.UUID, "seq" to FieldType.INT, "prev" to FieldType.HEX64,
        "kind" to FieldType.LOG_KIND, "actor" to FieldType.UUID, "at" to FieldType.MS,
    )

    /** What every log entry starts with, up to and including `at`: the `kind` it names picks the rest. */
    private val LOG_HEAD_FIELDS: List<Field> = t(*LOG_HEAD).fields

    val LOG_KINDS: Set<String> = setOf("genesis", "add", "role", "remove", "leave", "offer", "cancel", "accept", "delete", "restore")

    private val LOG: Map<String, Template> = mapOf(
        "genesis" to t(*LOG_HEAD, "ownerKey" to FieldType.B64_32, "vkCommit" to FieldType.HEX64),
        "add" to t(*LOG_HEAD, "member" to FieldType.UUID, "memberKey" to FieldType.B64_32, "role" to FieldType.ROLE, "grantId" to FieldType.B64_16),
        "role" to t(*LOG_HEAD, "member" to FieldType.UUID, "role" to FieldType.ROLE),
        "remove" to t(*LOG_HEAD, "member" to FieldType.UUID),
        "leave" to t(*LOG_HEAD),
        "offer" to t(*LOG_HEAD, "to" to FieldType.UUID, "toKey" to FieldType.B64_32, "offerId" to FieldType.B64_16, "expiresAt" to FieldType.MS),
        "cancel" to t(*LOG_HEAD, "offerId" to FieldType.B64_16),
        "accept" to t(*LOG_HEAD, "offerId" to FieldType.B64_16),
        "delete" to t(*LOG_HEAD, "deleteId" to FieldType.B64_16),
        "restore" to t(*LOG_HEAD, "deleteId" to FieldType.B64_16),
    )

    // ---- the single-template purposes ---------------------------------------------------------------

    /** Spec 01 §6 (unchanged): the vault grant. `vk` is the vault key. */
    private val GRANT = t(
        *HEAD, "from" to FieldType.UUID, "to" to FieldType.UUID, "toKey" to FieldType.B64_32, "vaultId" to FieldType.UUID,
        "grantId" to FieldType.B64_16, "issuedAt" to FieldType.MS, "vk" to FieldType.SECRET_B64_32,
    )

    /** §4.1. */
    private val CARD = t(
        *HEAD, "instanceId" to FieldType.UUID, "seq" to FieldType.INT, "prev" to FieldType.HEX64, "origin" to FieldType.ORIGIN,
        "name" to FieldType.NAME, "kind" to FieldType.INSTANCE_KIND, "operator" to FieldType.UUID,
        "operatorSignKey" to FieldType.B64_32, "recoveryFp" to FieldType.HEX64N, "issuedAt" to FieldType.MS,
    )

    /** §5.1. */
    private val GENESIS = t(
        *HEAD, "userId" to FieldType.UUID, "identityKey" to FieldType.B64_32, "instanceId" to FieldType.UUID,
        "personalVaultId" to FieldType.UUID, "createdAt" to FieldType.MS,
    )

    /** §6.3. */
    private val LINK_OFFER = t(
        *HEAD, "linkId" to FieldType.B64_16, "kind" to FieldType.LINK_KIND, "origin" to FieldType.ORIGIN,
        "instanceId" to FieldType.UUID, "cardHash" to FieldType.HEX64, "from" to FieldType.UUID, "fromKey" to FieldType.B64_32,
        "name" to FieldType.NAME, "commit" to FieldType.HEX64, "expiresAt" to FieldType.MS, "issuedAt" to FieldType.MS,
    )

    /** §6.5. */
    private val LINK_ANSWER = t(
        *HEAD, "linkId" to FieldType.B64_16, "offerHash" to FieldType.HEX64, "to" to FieldType.UUID, "toKey" to FieldType.B64_32,
        "from" to FieldType.UUID, "fromKey" to FieldType.B64_32, "name" to FieldType.NAME, "nonce" to FieldType.B64_32,
        "issuedAt" to FieldType.MS,
    )

    /** §4.5. */
    private val ROTATION = t(
        *HEAD, "instanceId" to FieldType.UUID, "fromFp" to FieldType.HEX64, "toFp" to FieldType.HEX64, "issuedAt" to FieldType.MS,
    )

    /** §9.3 step 3 (FI-B13). `uvk` is the account's UVK. */
    private val ASSISTED = t(
        *HEAD, "instanceId" to FieldType.UUID, "userId" to FieldType.UUID, "requestId" to FieldType.B64_16,
        "requestKey" to FieldType.B64_32, "uvk" to FieldType.SECRET_B64_32, "issuedAt" to FieldType.MS,
    )

    /**
     * Spec 04 §7 step 3, version 3: the old fields with the account's address after
     * `userId` and the commit value after `requestKey`. The only form a device accepts.
     */
    private val ASSISTED_V3 = t(
        *HEAD, "instanceId" to FieldType.UUID, "userId" to FieldType.UUID, "email" to FieldType.EMAIL_B64, "requestId" to FieldType.B64_16,
        "requestKey" to FieldType.B64_32, "commit" to FieldType.B64_32, "uvk" to FieldType.SECRET_B64_32, "issuedAt" to FieldType.MS,
    )

    /** §9.3 step 2 (N3). */
    private val VETO = t(*HEAD, "requestId" to FieldType.B64_16, "userId" to FieldType.UUID, "issuedAt" to FieldType.MS)

    // ---- §6.4 host-minted offers (canonical JSON, no frame) -----------------------------------------

    const val SETUP_OFFER = "setup-offer"
    const val ENROL_OFFER = "enrol-offer"
    private val HOST_PURPOSES: Set<String> = setOf(SETUP_OFFER, ENROL_OFFER)

    private val SETUP = t(
        *HEAD, "linkId" to FieldType.B64_16, "origin" to FieldType.ORIGIN, "instanceId" to FieldType.UUID,
        "name" to FieldType.NAME, "kind" to FieldType.INSTANCE_KIND, "recoveryFp" to FieldType.HEX64N, "expiresAt" to FieldType.MS,
    )

    private val ENROL = t(
        *HEAD, "linkId" to FieldType.B64_16, "origin" to FieldType.ORIGIN, "instanceId" to FieldType.UUID,
        "cardHash" to FieldType.HEX64, "email" to FieldType.EMAIL_B64N, "expiresAt" to FieldType.MS,
    )

    // ---- grammar ------------------------------------------------------------------------------------

    private fun inGrammar(type: FieldType, raw: String, purposes: Set<String>): Boolean = when (type) {
        FieldType.V -> TrustGrammar.parseInt(raw) != null
        FieldType.PURPOSE -> raw in purposes
        FieldType.UUID -> TrustGrammar.isUuid(raw)
        FieldType.B64_16 -> TrustGrammar.isB64_16(raw)
        FieldType.B64_32 -> TrustGrammar.isB64_32(raw)
        FieldType.SECRET_B64_32 -> false // never judged as text: see secretInGrammar
        FieldType.HEX64 -> TrustGrammar.isHex64(raw)
        FieldType.HEX64N -> TrustGrammar.isHex64n(raw)
        FieldType.MS -> TrustGrammar.parseMs(raw) != null
        FieldType.INT -> TrustGrammar.parseInt(raw) != null
        FieldType.ORIGIN -> TrustGrammar.isOrigin(raw)
        FieldType.NAME -> TrustGrammar.isName(raw)
        FieldType.ROLE -> TrustGrammar.isRole(raw)
        FieldType.EMAIL_B64N -> TrustGrammar.isEmailB64n(raw)
        FieldType.EMAIL_B64 -> TrustGrammar.decodeEmail(raw) is TrustGrammar.Email.Of
        FieldType.LOG_KIND -> raw in LOG_KINDS
        FieldType.INSTANCE_KIND -> raw == "public" || raw == "private"
        FieldType.LINK_KIND -> raw == "connect" || raw == "register"
    }

    /** The `b64_32` grammar for a key, judged on the bytes where they stand: 43 characters, canonical, 32 bytes. */
    private fun secretInGrammar(bytes: ByteArray, start: Int, end: Int): Boolean {
        if (end - start != B64_32_CHARS) return false
        val key = Bytes.fromB64Bytes(bytes, start, end) ?: return false
        key.fill(0)
        return true
    }

    // ---- the template match -------------------------------------------------------------------------

    private const val QUOTE: Byte = 0x22 // "
    private const val COMMA: Byte = 0x2C // ,
    private const val OPEN: Byte = 0x7B // {
    private const val CLOSE: Byte = 0x7D // }
    private const val DIGIT_0: Byte = 0x30
    private const val DIGIT_9: Byte = 0x39

    /** What a match collects: the plain values, and where each secret value starts. */
    private class Matching(val purposes: Set<String>) {
        val values = HashMap<String, String>()
        val secretAt = HashMap<String, Int>()
    }

    /** True when [bytes] hold exactly the ASCII characters of [text] at [pos]. */
    private fun hasAt(bytes: ByteArray, pos: Int, text: String): Boolean {
        if (pos + text.length > bytes.size) return false
        for (i in text.indices) if (bytes[pos + i] != text[i].code.toByte()) return false
        return true
    }

    /**
     * Consume [fields] from [bytes] at [at]: for each, the exact text `"name":` (after a comma unless it
     * is the first field of the object), then a bare run of digits for a number or a quoted run for a
     * string. No grammar here admits `"` or `\`, so a string value ends at the next quote. A plain value
     * becomes a `String` in [into]; a secret one is checked where it stands and only its position is
     * kept. Returns the position after the last value, or -1 when the bytes are not this template.
     * A loop over the fields: nothing here recurses, whatever the bytes are.
     */
    private fun consume(bytes: ByteArray, at: Int, fields: List<Field>, firstOfObject: Boolean, into: Matching): Int {
        var pos = at
        var first = firstOfObject
        for (f in fields) {
            if (!first) {
                if (pos >= bytes.size || bytes[pos] != COMMA) return -1
                pos++
            }
            first = false
            if (pos >= bytes.size || bytes[pos] != QUOTE || !hasAt(bytes, pos + 1, f.name) || !hasAt(bytes, pos + 1 + f.name.length, "\":")) return -1
            pos += f.name.length + 3
            if (f.type.isNumber) {
                var end = pos
                while (end < bytes.size && bytes[end] in DIGIT_0..DIGIT_9) end++
                val raw = bytes.decodeToString(pos, end)
                if (!inGrammar(f.type, raw, into.purposes)) return -1
                into.values[f.name] = raw
                pos = end
                continue
            }
            if (pos >= bytes.size || bytes[pos] != QUOTE) return -1
            var close = pos + 1
            while (close < bytes.size && bytes[close] != QUOTE) close++
            if (close >= bytes.size) return -1
            if (f.type == FieldType.SECRET_B64_32) {
                if (!secretInGrammar(bytes, pos + 1, close)) return -1
                into.secretAt[f.name] = pos + 1
            } else {
                val raw = bytes.decodeToString(pos + 1, close)
                if (!inGrammar(f.type, raw, into.purposes)) return -1
                into.values[f.name] = raw
            }
            pos = close + 1
        }
        return pos
    }

    /** Printable ASCII only (0x20..0x7E): step 2 of the strict parse. */
    private fun isPrintableAscii(bytes: ByteArray): Boolean = bytes.none { it < 0x20 || it > 0x7E }

    /** [statement] as exactly `{` + the fields of [template] + `}`, or null. */
    private fun matchWhole(statement: ByteArray, template: Template, purposes: Set<String>): RawStatement? {
        if (statement.isEmpty() || statement[0] != OPEN) return null
        val into = Matching(purposes)
        val end = consume(statement, 1, template.fields, true, into)
        if (end < 0 || end != statement.size - 1 || statement[end] != CLOSE) return null
        return RawStatement(template, into.values, statement, into.secretAt)
    }

    /** A vault-log statement: the head, then the fields of whatever `kind` the head names. */
    private fun matchLog(statement: ByteArray): RawStatement? {
        if (statement.isEmpty() || statement[0] != OPEN) return null
        val into = Matching(TrustPurpose.LITERALS)
        val afterHead = consume(statement, 1, LOG_HEAD_FIELDS, true, into)
        if (afterHead < 0) return null
        val template = LOG[into.values.getValue("kind")] ?: return null
        val end = consume(statement, afterHead, template.fields.subList(LOG_HEAD_FIELDS.size, template.fields.size), false, into)
        if (end < 0 || end != statement.size - 1 || statement[end] != CLOSE) return null
        return RawStatement(template, into.values, statement, into.secretAt)
    }

    /** The template of a single-template purpose; null for the vault log (by kind) and for 0x02. */
    private fun templateOf(purpose: TrustPurpose): Template? = when (purpose) {
        TrustPurpose.VAULT_GRANT -> GRANT
        TrustPurpose.ESCROW_UVK -> null // spec 04 §3: escrow statements verify only through crypto.Escrow.open
        TrustPurpose.VAULT_LOG -> null
        TrustPurpose.INSTANCE_CARD -> CARD
        TrustPurpose.ACCOUNT_GENESIS -> GENESIS
        TrustPurpose.LINK_OFFER -> LINK_OFFER
        TrustPurpose.LINK_ANSWER -> LINK_ANSWER
        TrustPurpose.RECOVERY_ROTATION -> ROTATION
        TrustPurpose.ASSISTED_RECOVERY -> ASSISTED
        TrustPurpose.RECOVERY_VETO -> VETO
    }

    /**
     * Step 6 for a statement that is canonical: the TEMPLATE rules of its own section (`bad_statement`).
     * The design names exactly two (§2.4, VR-1): a grant's `from != to`, and the vault log's "a genesis
     * has seq 0 and a zero prev; every other kind has seq >= 1". Everything else about position is a
     * chain verdict, including a card 0 whose `prev` is not zero (`bad_prev`, [InstanceCard.verify]).
     */
    private fun sectionRulesHold(purpose: TrustPurpose, raw: RawStatement): Boolean = when (purpose) {
        // Spec 01 §5.1: a grant is never addressed to its sender.
        TrustPurpose.VAULT_GRANT -> raw.str("from") != raw.str("to")
        // §3.2: `genesis` has seq 0 and prev = 64 zeros; every later entry has seq >= 1.
        TrustPurpose.VAULT_LOG -> {
            val genesis = raw.str("kind") == "genesis"
            val first = raw.str("seq") == "0"
            genesis == first && (!genesis || raw.str("prev") == TrustGrammar.ZERO_HASH)
        }
        else -> true
    }

    /**
     * The strict parse of a FRAMED statement under [purpose] (§2.2, §2.4; spec 01 §5.1 steps 2–6). The
     * frame itself was split by [SignedFrame.split]. Verdicts: `bad_frame` for a length outside 2..1024
     * or a purpose this package has no template for; `non_canonical` (steps 2–5: not printable ASCII,
     * or not the canonical rendering of its template with every value in its grammar); `bad_statement`
     * (step 6) when `v` is not 2, the `purpose` literal is another purpose's, or a template rule of the
     * owning section fails (VR-1: a log `genesis` has `seq` 0 and zero `prev`, every other kind
     * `seq >= 1`).
     *
     * The result reads its secret field, if it has one, from [statement] itself: the caller keeps that
     * array, and wipes it when it is done.
     */
    fun parse(purpose: TrustPurpose, statement: ByteArray, version: Int = 2): Checked<RawStatement, FrameVerdict> {
        if (statement.size !in SignedFrame.MIN_STATEMENT_BYTES..SignedFrame.MAX_STATEMENT_BYTES) return Checked.Refused(FrameVerdict.BAD_FRAME)
        if (purpose == TrustPurpose.ESCROW_UVK) return Checked.Refused(FrameVerdict.BAD_FRAME)
        require(version == 2 || (version == 3 && purpose == TrustPurpose.ASSISTED_RECOVERY)) { "no version-$version template for ${purpose.literal}" }
        if (!isPrintableAscii(statement)) return Checked.Refused(FrameVerdict.NON_CANONICAL)
        if (version == 3) {
            // Spec 04 §7 step 4: only the version-3 answer; one canonical under the old template is an old version.
            val raw = matchWhole(statement, ASSISTED_V3, TrustPurpose.LITERALS)
                ?: return Checked.Refused(if (matchWhole(statement, ASSISTED, TrustPurpose.LITERALS) != null) FrameVerdict.BAD_STATEMENT else FrameVerdict.NON_CANONICAL)
            if (raw.str("v") != "3" || raw.str("purpose") != purpose.literal) return Checked.Refused(FrameVerdict.BAD_STATEMENT)
            return Checked.Ok(raw)
        }
        val raw = (if (purpose == TrustPurpose.VAULT_LOG) matchLog(statement) else templateOf(purpose)?.let { matchWhole(statement, it, TrustPurpose.LITERALS) })
            ?: return Checked.Refused(FrameVerdict.NON_CANONICAL)
        if (raw.str("v") != "2") return Checked.Refused(FrameVerdict.BAD_STATEMENT)
        if (raw.str("purpose") != purpose.literal) return Checked.Refused(FrameVerdict.BAD_STATEMENT)
        if (!sectionRulesHold(purpose, raw)) return Checked.Refused(FrameVerdict.BAD_STATEMENT)
        return Checked.Ok(raw)
    }

    /**
     * The whole §2 parse of [frame] by the helper for [purpose], in §2.4's order: `bad_frame` if shorter
     * than 4 bytes; `unknown_format` for a wrong magic; `bad_frame` for a length outside 103..1125, a
     * reserved purpose code or a purpose other than [purpose]; then [parse]. No signature is checked.
     *
     * The parts are this function's own cut of the frame's bytes. When it refuses, it wipes them, so a
     * refused frame leaves nothing behind (what it held may still have been a key); when it accepts,
     * they are the caller's, who wipes them if the statement holds a secret ([FrameParts.wipe]).
     */
    fun parseFrame(frame: ByteArray, purpose: TrustPurpose, version: Int = 2): Checked<ParsedFrame, FrameVerdict> {
        val parts = when (val split = SignedFrame.split(frame)) {
            is Checked.Ok -> split.value
            is Checked.Refused -> return split
        }
        val raw = if (parts.purpose != purpose) Checked.Refused(FrameVerdict.BAD_FRAME) else parse(purpose, parts.statementRaw(), version)
        return when (raw) {
            is Checked.Ok -> Checked.Ok(ParsedFrame(parts, raw.value))
            is Checked.Refused -> {
                parts.wipe()
                raw
            }
        }
    }

    /**
     * Recognising a host-minted offer (§6.4; §2.4 "Host JSON offer", VR-15), before its template is
     * applied: printable ASCII and a JSON object with a string `purpose`, else `non_canonical`; a
     * `purpose` other than `setup-offer` and `enrol-offer` is `unknown_format`. Returns that purpose.
     *
     * "A JSON object" is decided by [StrictJson], not by the platform parser, which would take a bare
     * token such as `abc` for a value: a bare token, `NaN`, a trailing comma, trailing bytes and nesting
     * deeper than 32 open containers are all `non_canonical`. So is a key that appears twice at the top
     * level, a repeated `purpose` included, whichever value comes last: parsers differ on duplicates,
     * so the rule does not depend on one.
     */
    fun hostOfferPurpose(plaintext: ByteArray): Checked<String, FrameVerdict> {
        if (!isPrintableAscii(plaintext)) return Checked.Refused(FrameVerdict.NON_CANONICAL)
        val obj = StrictJson.parse(plaintext.decodeToString()) as? JsonNode.Obj ?: return Checked.Refused(FrameVerdict.NON_CANONICAL)
        if (obj.hasRepeatedName) return Checked.Refused(FrameVerdict.NON_CANONICAL)
        val purpose = (obj.last("purpose") as? JsonNode.Str)?.value ?: return Checked.Refused(FrameVerdict.NON_CANONICAL)
        return if (purpose in HOST_PURPOSES) Checked.Ok(purpose) else Checked.Refused(FrameVerdict.UNKNOWN_FORMAT)
    }

    /**
     * The strict parse of a host-minted offer: [hostOfferPurpose], then the template's own steps:
     * `non_canonical`, and `bad_statement` when `v` is not 2.
     */
    fun parseHostOffer(plaintext: ByteArray): Checked<RawStatement, FrameVerdict> {
        val purpose = when (val p = hostOfferPurpose(plaintext)) {
            is Checked.Ok -> p.value
            is Checked.Refused -> return p
        }
        val template = if (purpose == SETUP_OFFER) SETUP else ENROL
        val raw = matchWhole(plaintext, template, HOST_PURPOSES) ?: return Checked.Refused(FrameVerdict.NON_CANONICAL)
        if (raw.str("v") != "2") return Checked.Refused(FrameVerdict.BAD_STATEMENT)
        return Checked.Ok(raw)
    }

    // ---- encode -------------------------------------------------------------------------------------

    /**
     * The canonical bytes of a framed statement of [purpose] with [fields] (every plain field but `v`
     * and `purpose`, as its statement text) and [secrets] (a grant's `vk`, an assisted recovery's `uvk`:
     * the 32 key bytes, never text). Refuses (`IllegalArgumentException`) whatever [parse] would
     * refuse, so a statement this code signs always parses back. [kind] picks the vault-log template.
     *
     * A statement with a secret holds that key in the clear, as base64url written straight from the
     * bytes: the caller wipes the result once it is framed.
     */
    fun encode(
        purpose: TrustPurpose,
        fields: Map<String, String>,
        kind: String? = null,
        secrets: Map<String, ByteArray> = emptyMap(),
        version: Int = 2,
    ): ByteArray {
        val template = when {
            purpose == TrustPurpose.VAULT_LOG -> LOG[kind] ?: throw IllegalArgumentException("unknown log kind")
            purpose == TrustPurpose.ESCROW_UVK -> throw IllegalArgumentException("escrow statements are built by crypto.Escrow")
            version == 3 && purpose == TrustPurpose.ASSISTED_RECOVERY -> ASSISTED_V3
            version != 2 -> throw IllegalArgumentException("no version-$version template for ${purpose.literal}")
            else -> templateOf(purpose) ?: throw IllegalArgumentException("no template for ${purpose.literal}")
        }
        val bytes = render(template, purpose.literal, fields, secrets, version)
        val back = parse(purpose, bytes, version)
        if (back !is Checked.Ok) {
            bytes.fill(0)
            throw IllegalArgumentException("${purpose.literal} statement is outside its grammar (${back.verdictOrNull()?.code})")
        }
        return bytes
    }

    /** The canonical bytes of a host-minted offer ([purposeLiteral] is `setup-offer` or `enrol-offer`). */
    fun encodeHostOffer(purposeLiteral: String, fields: Map<String, String>): ByteArray {
        val template = when (purposeLiteral) {
            SETUP_OFFER -> SETUP
            ENROL_OFFER -> ENROL
            else -> throw IllegalArgumentException("not a host offer purpose")
        }
        val bytes = render(template, purposeLiteral, fields, emptyMap())
        val back = parseHostOffer(bytes)
        require(back is Checked.Ok) { "$purposeLiteral is outside its grammar (${back.verdictOrNull()?.code})" }
        return bytes
    }

    /**
     * The canonical text for [fields] and [secrets] under [template]: no white space, the template's key
     * order, numbers bare. A plain value is written from its `String`; a secret one from its bytes, as
     * base64url, through an array that is wiped: the key never becomes a `String`. A secret given as a
     * plain value, or a plain value given as a secret, is refused.
     */
    private fun render(template: Template, purposeLiteral: String, fields: Map<String, String>, secrets: Map<String, ByteArray>, version: Int = 2): ByteArray {
        val values = HashMap<String, String>(fields)
        values["v"] = version.toString()
        values["purpose"] = purposeLiteral
        val chunks = ArrayList<ByteArray>(template.fields.size * 2 + 1)
        val keyTexts = ArrayList<ByteArray>(secrets.size)
        try {
            for ((i, f) in template.fields.withIndex()) {
                val lead = (if (i == 0) "{\"" else ",\"") + f.name + "\":"
                if (f.type == FieldType.SECRET_B64_32) {
                    val key = secrets[f.name] ?: throw IllegalArgumentException("field ${f.name} is given as 32 secret bytes")
                    require(key.size == 32) { "field ${f.name} is given as 32 secret bytes" }
                    val text = Bytes.toB64Bytes(key)
                    keyTexts += text
                    chunks += (lead + "\"").encodeToByteArray()
                    chunks += text
                    chunks += byteArrayOf(QUOTE)
                    continue
                }
                val v = values[f.name] ?: throw IllegalArgumentException("missing field ${f.name}")
                // The grammars exclude both characters; this keeps a wrong value from changing the structure
                // before the parse-back refuses it.
                require('"' !in v && '\\' !in v) { "field ${f.name} cannot be written into a statement" }
                chunks += (if (f.type.isNumber) lead + v else "$lead\"$v\"").encodeToByteArray()
            }
            require(values.size + secrets.size == template.fields.size) { "unexpected field for this template" }
            chunks += byteArrayOf(CLOSE)
            val out = ByteArray(chunks.sumOf { it.size })
            var at = 0
            for (chunk in chunks) {
                chunk.copyInto(out, at)
                at += chunk.size
            }
            return out
        } finally {
            for (text in keyTexts) text.fill(0)
        }
    }
}
