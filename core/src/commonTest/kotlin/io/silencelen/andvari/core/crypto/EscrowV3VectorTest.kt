package io.silencelen.andvari.core.crypto

import io.silencelen.andvari.core.readVector
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The version-3 recovery copy (spec 04 §3, §4 as corrected on 2026-11-16), graded off `escrow-v3.json`, which the independent oracle
 * wrote from the specification text alone. Layers (spec 04 §4 "Two layers" and "Who reads what a person typed"):
 * [Escrow.openForAssist] and [Escrow.openForFleet] are the shared check of the tools' whole check and answer each
 * `open` row's `expectShared` where it has one (a grouped anchor, an acknowledgment with space or tab at its ends:
 * only the command line reads what a person typed), and its `expect` everywhere else; [Escrow.open] is the shared
 * opener and answers `expectOpener`. Rows whose inputs this layer cannot carry (an argument the operator left out,
 * both anchors given, the fleet dump's own fingerprint column, a copy that is not canonical base64url) belong to
 * `recovery-cli`'s AssistV3VectorTest.
 *
 * A row the code answers otherwise is a finding: it is listed in [KNOWN] with its finding's name and left out of the
 * graded tests so the build stays green. [FIXED] names the rows of findings since fixed or settled.
 */
class EscrowV3VectorTest {
    private val crypto = createCryptoProvider()
    private val v: JsonObject = Json.parseToJsonElement(readVector("escrow-v3.json")).jsonObject
    private fun JsonObject.s(key: String): String = getValue(key).jsonPrimitive.content
    private fun JsonObject.sOrNull(key: String): String? = get(key)?.takeIf { it !is JsonNull }?.jsonPrimitive?.content
    private fun JsonObject.b(key: String): ByteArray = Bytes.fromB64(s(key))

    private val sheet = v.getValue("sheet").jsonObject
    private val org get() = crypto.boxKeypairFromSeed(sheet.b("seedB64"))
    private val files = v.getValue("identityFiles").jsonObject

    private fun identityCheck(name: String?): IdentityCheck? =
        name?.let { files.getValue(it).jsonObject }?.let { IdentityCheck(it.s("encryptedIdentitySeedB64"), it.s("identityPubB64")) }

    /** What a refusal or an opening reads as, in the rows' terms. */
    private fun describe(block: () -> EscrowOpened, opener: Boolean): JsonObject = try {
        val o = block()
        val m = LinkedHashMap<String, kotlinx.serialization.json.JsonElement>()
        m["verdict"] = JsonPrimitive("ok")
        if (opener) m["format"] = JsonPrimitive(o.format.code)
        m["userId"] = JsonPrimitive(o.userId)
        if (o.email != null) m["email"] = JsonPrimitive(o.email)
        if (!opener) m["emailB64"] = JsonPrimitive(Bytes.toB64(o.email!!.encodeToByteArray()))
        m["uvkB64"] = JsonPrimitive(Bytes.toB64(o.uvk))
        m["identityKeyB64"] = JsonPrimitive(Bytes.toB64(o.identityKey))
        m["anchored"] = JsonPrimitive(o.anchored)
        o.wipe()
        JsonObject(m)
    } catch (e: EscrowOpenException) {
        val m = LinkedHashMap<String, kotlinx.serialization.json.JsonElement>()
        m["verdict"] = JsonPrimitive(e.verdict.code)
        e.copyEmail?.let { m["copyEmail"] = JsonPrimitive(it) }
        JsonObject(m)
    }

    /** null: the row's inputs are not this layer's (an absent argument, both anchors); see recovery-cli's AssistV3VectorTest. */
    private fun tool(row: JsonObject): JsonObject? {
        val i = row.getValue("input").jsonObject
        // The shared check is handed bytes: a copy that is not canonical base64url is the command line's to refuse.
        val sealed = Bytes.fromB64Canonical(i.s("sealedB64"))?.takeIf { it.isNotEmpty() } ?: return null
        if (i.sOrNull("dumpFingerprint") != null) return null
        val user = i.sOrNull("user") ?: return null
        val check = identityCheck(i.sOrNull("identityFile"))
        if (i.s("mode") == "verify") return describe({ Escrow.openForFleet(crypto, org, sealed, user, check) }, opener = false)
        val email = i.sOrNull("email") ?: return null
        val noAnchor = i["noIdentityAnchor"]?.jsonPrimitive?.booleanOrNull == true
        val fp = i.sOrNull("identityFp")
        // Both anchors, or none without --no-identity-anchor: a null prefix here IS the unanchored mode.
        if (noAnchor == (fp != null)) return null
        return describe({ Escrow.openForAssist(crypto, org, sealed, user, email, if (noAnchor) null else fp, check, i.sOrNull("unanchoredAck")) }, opener = false)
    }

    private fun opener(row: JsonObject): JsonObject? {
        val i = row.getValue("input").jsonObject
        val noAnchor = i["noIdentityAnchor"]?.jsonPrimitive?.booleanOrNull == true
        if (!noAnchor && i.sOrNull("identityFp") == null) return null
        return describe({
            Escrow.open(crypto, org, i.b("sealedB64"), i.s("user"), if (noAnchor) null else i.sOrNull("identityFp"), identityCheck(i.sOrNull("identityFile")), i.sOrNull("unanchoredAck"))
        }, opener = true)
    }

    private val rows get() = v.getValue("open").jsonArray.map { it.jsonObject }

    /**
     * Graded row → what the code answers, for every row of [rows] this layer can carry; [which] is `expect` or `expectOpener`.
     * For `expect` the shared check answers the row's `expectShared` where it has one (spec 04 §4 "Who reads what a person typed": the command line reads what a
     * person typed, the shared check takes values already in their grammar), and `expect` everywhere else.
     */
    private fun differences(which: String, only: Set<String>? = null): List<String> = rows.mapNotNull { row ->
        val name = row.s("name")
        if (only != null && name !in only) return@mapNotNull null
        if (only == null && "$which/$name" in KNOWN) return@mapNotNull null
        val want = (if (which == "expect") row["expectShared"] ?: row[which] else row[which])?.jsonObject ?: return@mapNotNull null
        val got = (if (which == "expect") tool(row) else opener(row)) ?: return@mapNotNull null
        if (got != want) "$which/$name: the oracle expects $want, the code answers $got" else null
    }

    @Test
    fun seal_sealUvkV3ProducesThePinnedFrame_andTheOraclesSealOpensToIt() {
        val accounts = v.getValue("accounts").jsonObject
        for (row in v.getValue("seal").jsonArray.map { it.jsonObject }) {
            val i = row.getValue("input").jsonObject
            val e = row.getValue("expect").jsonObject
            val seed = accounts.getValue(i.s("account")).jsonObject.b("seedB64")
            val sealed = Escrow.sealUvkV3(
                crypto, i.b("recoveryPubB64"), sheet.s("recoveryFp"), i.s("userId"), e.s("emailNorm"), crypto.boxKeypairFromSeed(seed).publicKey,
                crypto.signKeypairFromSeed(seed), i.b("uvkB64"), i.s("issuedAt").toLong(),
            )
            assertEquals(e.s("sealedBytes").toInt(), sealed.size, row.s("name"))
            assertContentEquals(e.b("frameB64"), crypto.sealOpen(org.publicKey, org.privateKey, sealed), row.s("name"))
            assertContentEquals(e.b("frameB64"), crypto.sealOpen(org.publicKey, org.privateKey, e.b("sealedB64")), row.s("name") + " (the oracle's seal)")
            val frame = e.b("frameB64")
            assertEquals(e.s("statementUtf8"), frame.copyOfRange(SignedStatement.STATEMENT_OFFSET, frame.size).decodeToString(), row.s("name"))
        }
    }

    @Test
    fun sealRefuse_anAddressThatIsNotAnEmailNormSealsNothing() {
        val alice = v.getValue("accounts").jsonObject.getValue("alice").jsonObject
        val seed = alice.b("seedB64")
        for (row in v.getValue("sealRefuse").jsonArray.map { it.jsonObject }) {
            assertFailsWith<CryptoException>(row.s("name")) {
                Escrow.sealUvkV3(crypto, Bytes.fromB64(sheet.s("recoveryPubB64")), sheet.s("recoveryFp"), alice.s("userId"), row.s("address"),
                    crypto.boxKeypairFromSeed(seed).publicKey, crypto.signKeypairFromSeed(seed), alice.b("uvkB64"), 1_763_524_800_000L)
            }
        }
    }

    @Test
    fun open_theToolsWholeCheck_everyRowItCanCarry() {
        val d = differences("expect")
        assertTrue(d.isEmpty(), d.joinToString("\n"))
    }

    @Test
    fun open_theSharedOpener_everyRowWithAnOpenerExpectation() {
        val d = differences("expectOpener")
        assertTrue(d.isEmpty(), d.joinToString("\n"))
        assertTrue(rows.count { it["expectOpener"] != null } > 60)
    }

    @Test
    fun theKnownFindingsNameRowsThatExist() {
        val names = rows.map { it.s("name") }.toSet()
        for (k in KNOWN.keys + FIXED.keys) assertTrue(k.substringAfter('/') in names, k)
    }

    private fun of(map: Map<String, String>, finding: String): List<String> =
        map.filterValues { it == finding }.keys.groupBy({ it.substringBefore('/') }, { it.substringAfter('/') }).flatMap { (which, names) -> differences(which, names.toSet()) }

    /** V4-K1, fixed: both core openers decide the absent identity file at step 0, before the acknowledgment of step 2 (spec 04 §4 step 0.3). */
    @Test
    fun fixed_V4_K1_theIdentityFileIsCheckedBeforeTheAcknowledgment() {
        val d = of(FIXED, K1)
        assertTrue(d.isEmpty(), d.joinToString("\n"))
    }

    /**
     * V4-K2, settled (spec 04 §4 "Who reads what a person typed"): the command line removes the separators of a grouped
     * anchor; the shared check takes only 32 to 64 lowercase hex, so these rows' `expectShared` is `bad_anchor`.
     */
    @Test
    fun settled_V4_K2_theSharedCheckTakesNoGroupedAnchor() {
        assertTrue(rows.filter { "expect/${it.s("name")}" in FIXED && FIXED["expect/${it.s("name")}"] == K2 }.all { it["expectShared"] != null })
        val d = of(FIXED, K2)
        assertTrue(d.isEmpty(), d.joinToString("\n"))
    }

    /**
     * V4-K3, settled (same paragraph, and step 2): the command line removes space and tab from both ends of a typed
     * acknowledgment; the shared check and the shared opener compare it exactly (`unanchored_not_acknowledged`).
     */
    @Test
    fun settled_V4_K3_theSharedCheckComparesTheAcknowledgmentExactly() {
        assertTrue(rows.filter { "expect/${it.s("name")}" in FIXED && FIXED["expect/${it.s("name")}"] == K3 }.all { it["expectShared"] != null && it["expectOpener"] != null })
        val d = of(FIXED, K3)
        assertTrue(d.isEmpty(), d.joinToString("\n"))
    }

    private companion object {
        const val K1 = "V4-K1: unanchored_not_acknowledged at step 0, before identity_check_required (spec 04 §4: step 2)"
        const val K2 = "V4-K2: the command line removes spaces, tabs and dashes from a typed anchor; the shared check does not"
        const val K3 = "V4-K3: the command line trims a typed acknowledgment; the shared check and opener compare it exactly"

        /** `expect/<row>` or `expectOpener/<row>` → the finding the code still shows: such a row is left out of the graded tests. None is open. */
        val KNOWN: Map<String, String> = emptyMap()

        /** The rows of findings since fixed in the code or settled in the text: graded with every row, and again by the test that names the finding. */
        val FIXED: Map<String, String> = mapOf(
            "expect/order-identity-file-before-acknowledgment" to K1,
            "expectOpener/order-identity-file-before-acknowledgment" to K1,
            "expect/anchor-grouped-with-spaces" to K2,
            "expect/anchor-grouped-with-dashes" to K2,
            "expect/anchor-grouped-with-tabs" to K2,
            "expect/acknowledgment-with-spaces-around" to K3,
            "expect/acknowledgment-with-a-tab-after" to K3,
            "expectOpener/acknowledgment-with-spaces-around" to K3,
            "expectOpener/acknowledgment-with-a-tab-after" to K3,
        )
    }
}
