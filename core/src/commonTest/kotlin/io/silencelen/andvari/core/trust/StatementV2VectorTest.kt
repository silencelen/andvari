package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The frame and the canonical statement grammar of design 2026-11-15 §2.1, §2.2 and §2.4, graded off
 * `statement-v2.json` from the independent oracle. The bytes pin "correct", not "the engines agree":
 * the statement text, the signed message `M`, the deterministic signature, the frame and its hash for
 * every template of purposes 0x03 to 0x0A, and one exact verdict for every rejection row.
 */
class StatementV2VectorTest {
    private val crypto = createCryptoProvider()
    private val v = vector("statement-v2.json")
    private val keys = v.o("keys")

    /** The fields that carry a key: the codec takes them as bytes, never as text. */
    private val SECRET_FIELDS = setOf("vk", "uvk")

    private fun code(r: Checked<*, FrameVerdict>): String = when (r) {
        is Checked.Ok -> "ok"
        is Checked.Refused -> r.verdict.code
    }

    private fun purposeOf(row: JsonObject): TrustPurpose? =
        row.getValue("purposeCode").takeIf { it !is JsonNull }?.let { TrustPurpose.fromCode(it.jsonPrimitive.int) }

    @Test
    fun theFileHasTheSectionsThisSuiteGrades_andNoOther() {
        assertSections(
            v, "_about", "domainAscii", "magicHex", "purposeCodes", "statementBytes", "frameBytes", "keys", "templates", "valid", "grammar", "parse",
            "frames", "binding",
        )
    }

    @Test
    fun constants_matchTheFile() {
        assertEquals(v.s("domainAscii"), SignedFrame.DOMAIN)
        assertEquals(v.s("magicHex"), Bytes.toHexLower(SignedFrame.MAGIC))
        val codes = v.o("purposeCodes")
        assertEquals(TrustPurpose.entries.size, codes.size)
        for (p in TrustPurpose.entries) assertEquals(codes.l(p.literal).toInt(), p.code, p.literal)
        assertEquals(v.o("statementBytes").l("min").toInt(), SignedFrame.MIN_STATEMENT_BYTES)
        assertEquals(v.o("statementBytes").l("max").toInt(), SignedFrame.MAX_STATEMENT_BYTES)
        assertEquals(v.o("frameBytes").l("min").toInt(), SignedFrame.STATEMENT_OFFSET + SignedFrame.MIN_STATEMENT_BYTES)
        assertEquals(v.o("frameBytes").l("max").toInt(), SignedFrame.MAX_FRAME_BYTES)
    }

    @Test
    fun cast_jointKeysAndRecoveryKeysDeriveAsTheFileSays() {
        for ((name, element) in keys) {
            val k = element.jsonObject
            val seed = k.b64("seedB64")
            val sign = crypto.signKeypairFromSeed(seed)
            val box = crypto.boxKeypairFromSeed(seed)
            assertContentEquals(k.b64("signPubB64"), sign.publicKey, name)
            // An account's identity key, or a recovery seed's X25519 public key: the same construction.
            val x25519 = k.sOrNull("identityPubB64") ?: k.s("publicKeyB64")
            assertEquals(x25519, Bytes.toB64(box.publicKey), name)
            assertContentEquals(box.publicKey, crypto.ed25519PkToCurve25519(sign.publicKey), name)
            k.sOrNull("fingerprint")?.let { assertEquals(it, Bytes.toHexLower(crypto.sha256(box.publicKey)), name) }
        }
    }

    @Test
    fun valid_everyTemplateEncodesSignsHashesAndBinds() {
        val seen = HashSet<Int>()
        gradeEvery("statement-v2.valid", v.rows("valid")) { r ->
            val name = r.s("name")
            val purpose = purposeOf(r)!!
            seen += purpose.code
            assertEquals(r.s("purpose"), purpose.literal, name)
            // A key (a grant's `vk`, an assisted recovery's `uvk`) is handed to the codec as bytes and read back as bytes.
            val all = r.o("fields").asFields()
            val fields = all.filterKeys { it !in SECRET_FIELDS }
            val secrets = all.filterKeys { it in SECRET_FIELDS }.mapValues { Bytes.fromB64(it.value) }
            val kind = if (purpose == TrustPurpose.VAULT_LOG) fields.getValue("kind") else null

            // The canonical bytes, from the values alone.
            val statement = StatementCodec.encode(purpose, fields, kind, secrets)
            assertEquals(r.s("statementUtf8"), statement.decodeToString(), "$name: canonical statement")
            // The strict parse gives the same values back.
            val parsed = assertIs<Checked.Ok<RawStatement>>(StatementCodec.parse(purpose, statement), name).value
            for ((k, value) in fields) assertEquals(value, parsed.str(k), "$name: field $k")
            for ((k, key) in secrets) {
                assertTrue(k !in parsed.values, "$name: $k is not among the plain values")
                assertContentEquals(key, parsed.secret(k), "$name: secret $k")
            }

            // M, the deterministic signature, the frame and its hash.
            val signer = signerOf(crypto, keys, r.s("signer"))
            assertContentEquals(r.b64("signerPubB64"), signer.publicKey, "$name: signer key")
            val m = SignedFrame.signedMessage(purpose.code, signer.publicKey, statement)
            assertEquals(r.s("messageHex"), Bytes.toHexLower(m), "$name: signed message M")
            val frame = SignedFrame.sign(crypto, signer, purpose, statement)
            assertEquals(r.s("frameB64"), Bytes.toB64(frame), "$name: frame bytes")
            assertEquals(r.s("frameHash"), SignedFrame.hash(crypto, frame), "$name: H(frame)")

            // The whole parse for this purpose, then both signer-binding forms where the row lists them.
            val whole = assertIs<Checked.Ok<ParsedFrame>>(StatementCodec.parseFrame(frame, purpose), name).value
            assertContentEquals(r.b64("signatureB64"), whole.parts.signature, "$name: signature")
            assertTrue(SignedFrame.signatureValid(crypto, whole.parts), "$name: signature verifies")
            for (key in r.getValue("expectedKeys").jsonArray.map { it.jsonObject }) {
                val bytes = key.b64("keyB64")
                when (key.s("form")) {
                    "x25519" -> assertTrue(SignedFrame.signerMapsTo(crypto, whole.parts, bytes), "$name: X25519 binding")
                    "ed25519" -> assertTrue(SignedFrame.signerIs(whole.parts, bytes), "$name: Ed25519 binding")
                    else -> error("unknown form in $name")
                }
            }
        }
        assertEquals((0x03..0x0A).toSet(), seen, "every purpose 0x03-0x0A has a valid frame")
    }

    /** Rows with no purpose code are the host-minted offers of §6.4, which have no frame. */
    private fun parseRow(purpose: TrustPurpose?, statement: ByteArray) =
        if (purpose == null) StatementCodec.parseHostOffer(statement) else StatementCodec.parse(purpose, statement)

    @Test
    fun grammarAndParse_everyRowGetsItsExactVerdict() {
        for (section in listOf("grammar", "parse")) {
            gradeEvery("statement-v2.$section", v.rows(section)) { r ->
                assertEquals(r.s("verdict"), code(parseRow(purposeOf(r), r.b64("statementB64"))), "${r.s("template")}: ${r.s("why")}")
            }
        }
    }

    /**
     * `templates` describes each template's keys and types; the valid, grammar and parse rows grade them.
     * Here every template must be met by at least one statement this parser accepts, and every accepted
     * statement has exactly its template's keys, in order.
     */
    @Test
    fun templates_eachIsExercisedByAcceptedStatementsWithExactlyItsKeys() {
        val accepted = v.rows("valid").map { Triple(it.s("name"), purposeOf(it), it.s("statementUtf8").encodeToByteArray()) } +
            (v.rows("grammar") + v.rows("parse")).filter { it.s("verdict") == "ok" }
                .map { Triple(it.s("why"), purposeOf(it), it.b64("statementB64")) }
        fun templateOf(statement: ByteArray): String {
            val obj = Json.parseToJsonElement(statement.decodeToString()).jsonObject
            val purpose = obj.s("purpose")
            return if (purpose == TrustPurpose.VAULT_LOG.literal) "$purpose/${obj.s("kind")}" else purpose
        }
        val templates = v.o("templates")
        val met = accepted.groupBy { templateOf(it.third) }
        assertEquals(emptySet(), met.keys - templates.keys, "statements of no listed template")
        gradeEvery("statement-v2.templates", templates.entries.toList()) { (name, spec) ->
            val keys = spec.jsonArray.map { it.jsonArray[0].jsonPrimitive.content }
            val statements = met[name].orEmpty()
            assertTrue(statements.isNotEmpty(), "$name: an accepted statement of this template")
            for ((why, purpose, statement) in statements) {
                assertEquals(keys, Json.parseToJsonElement(statement.decodeToString()).jsonObject.keys.toList(), "$name: $why")
                assertEquals("ok", code(parseRow(purpose, statement)), "$name: $why")
            }
        }
    }

    @Test
    fun frames_theWholeParseInOrder() {
        gradeEvery("statement-v2.frames", v.rows("frames")) { r ->
            val purpose = TrustPurpose.fromCode(r.l("expectedPurposeCode").toInt())!!
            assertEquals(r.s("verdict"), code(StatementCodec.parseFrame(r.b64("frameB64"), purpose)), r.s("why"))
        }
    }

    @Test
    fun binding_theTwoFormsAndTheSignature() {
        gradeEvery("statement-v2.binding", v.rows("binding")) { r ->
            val parts = assertIs<Checked.Ok<FrameParts>>(SignedFrame.split(r.b64("frameB64")), r.s("why")).value
            assertEquals(r.l("purposeCode").toInt(), parts.purpose.code, r.s("why"))
            val key = r.b64("expectedKeyB64")
            val binds = when (r.s("form")) {
                "x25519" -> SignedFrame.signerMapsTo(crypto, parts, key)
                "ed25519" -> SignedFrame.signerIs(parts, key)
                else -> error("unknown form")
            }
            assertEquals(r.bool("signerBinds"), binds, "binds: ${r.s("why")}")
            assertEquals(r.bool("signatureValid"), SignedFrame.signatureValid(crypto, parts), "signature: ${r.s("why")}")
        }
    }

    @Test
    fun encode_refusesWhatTheParseWouldRefuse() {
        val genesis = v.rows("valid").first { it.s("name") == "vault-log/genesis" }.o("fields").asFields()
        fun with(vararg change: Pair<String, String>) = HashMap(genesis).apply { putAll(change) }
        // A value outside its type, a template rule, a missing field, an extra field, a structure-breaking value.
        assertFailsWith<IllegalArgumentException> { StatementCodec.encode(TrustPurpose.VAULT_LOG, with("vaultId" to genesis.getValue("vaultId").uppercase()), "genesis") }
        assertFailsWith<IllegalArgumentException> { StatementCodec.encode(TrustPurpose.VAULT_LOG, with("seq" to "1"), "genesis") }
        assertFailsWith<IllegalArgumentException> { StatementCodec.encode(TrustPurpose.VAULT_LOG, with("at" to "0"), "genesis") }
        assertFailsWith<IllegalArgumentException> { StatementCodec.encode(TrustPurpose.VAULT_LOG, genesis - "ownerKey", "genesis") }
        assertFailsWith<IllegalArgumentException> { StatementCodec.encode(TrustPurpose.VAULT_LOG, with("member" to genesis.getValue("actor")), "genesis") }
        assertFailsWith<IllegalArgumentException> { StatementCodec.encode(TrustPurpose.VAULT_LOG, with("actor" to "x\",\"at\":1,\"z\":\""), "genesis") }
        assertFailsWith<IllegalArgumentException> { StatementCodec.encode(TrustPurpose.VAULT_LOG, genesis, "nonsense") }
        assertFailsWith<IllegalArgumentException> { StatementCodec.encode(TrustPurpose.ESCROW_UVK, genesis) }
    }
}
