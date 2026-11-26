package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.IdentityCheck
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Operator recovery of design 2026-11-15 §4.5 and §9.3 with the verdicts and order of §2.4, graded off
 * `recovery.json` from the independent oracle: the 0x08 rotation statement, the chain
 * `PUT /escrow/self` carries, the first-consent walk of the card chain, the request code, the 0x09
 * assisted-recovery payload as the requesting device opens it and the 0x0A veto as the server verifies
 * it. Every row gets its exact verdict; [gradeEvery] proves no row is skipped, with the counts the file has.
 */
class RecoveryVectorTest {
    private val crypto = createCryptoProvider()
    private val v = vector("recovery.json")

    @Test
    fun theFileHasTheSectionsThisSuiteGrades_andNoOther() {
        assertSections(
            v, "_about", "instanceId", "keys", "requestKey", "rotation", "rotationFrames", "escrowRotations", "cardChains", "firstConsent",
            "requestCode", "assisted", "veto",
        )
    }
    private val keys = v.o("keys")
    private val rotationFrames: Map<String, ByteArray> =
        v.o("rotationFrames").entries.associate { (name, frame) -> name to Bytes.fromB64(frame.jsonPrimitive.content) }

    private fun named(row: JsonObject, key: String): List<ByteArray> = row.getValue(key).jsonArray.strings().map { rotationFrames.getValue(it) }

    private fun statementOf(frame: ByteArray): String = assertIs<Checked.Ok<FrameParts>>(SignedFrame.split(frame)).value.statement.decodeToString()

    private fun assertEveryVerdictHasARow(seen: Set<String>, vararg verdicts: String) {
        for (verdict in verdicts) assertTrue(verdict in seen, "no row for $verdict")
    }

    // ---- §2.3 the recovery-key signing key ---------------------------------------------------------

    @Test
    fun keys_oneSeedGivesTheRecoveryKeyItsSigningKeyAndItsFingerprint() {
        for (name in listOf("recoveryA", "recoveryB", "recoveryC")) {
            val k = keys.o(name)
            val seed = k.b64("seedB64")
            val box = crypto.boxKeypairFromSeed(seed)
            val sign = crypto.signKeypairFromSeed(seed)
            assertEquals(k.s("publicKeyB64"), Bytes.toB64(box.publicKey), name)
            assertEquals(k.s("signPubB64"), Bytes.toB64(sign.publicKey), name)
            assertEquals(k.s("fingerprint"), Bytes.toHexLower(crypto.sha256(box.publicKey)), name)
            // The signing key maps to the recovery key, so a fingerprint alone names the key that must sign.
            assertContentEquals(box.publicKey, crypto.ed25519PkToCurve25519(sign.publicKey), name)
            assertTrue(RecoveryRotation.signerIsRecoveryKey(crypto, sign.publicKey, k.s("fingerprint")), name)
            assertTrue(InstanceCard.recoveryKeyMatches(crypto, k.s("fingerprint"), box.publicKey), name)
        }
        for (name in listOf("operator", "alice", "bob")) {
            val k = keys.o(name)
            assertEquals(k.s("identityPubB64"), Bytes.toB64(crypto.boxKeypairFromSeed(k.b64("seedB64")).publicKey), name)
            assertEquals(k.s("signPubB64"), Bytes.toB64(signerOf(crypto, keys, name).publicKey), name)
            // An identity key is no recovery key: its signer names none of the three fingerprints.
            for (recovery in listOf("recoveryA", "recoveryB", "recoveryC")) {
                assertFalse(RecoveryRotation.signerIsRecoveryKey(crypto, signerOf(crypto, keys, name).publicKey, keys.o(recovery).s("fingerprint")), name)
            }
        }
    }

    // ---- §4.5 rotation (purpose 0x08) --------------------------------------------------------------

    @Test
    fun rotation_everyRowGetsItsExactVerdict() {
        val rows = v.rows("rotation")
        val seen = HashSet<String>()
        gradeEvery("recovery.rotation", rows) { r ->
            val why = "${r.s("name")}: ${r.s("why")}"
            val frame = r.b64("frameB64")
            val expect = r.o("expect")
            val expected = expect.s("verdict")
            // The verifier is handed a fingerprint, and the key that fingerprint names is the row's recoveryPubB64.
            assertTrue(InstanceCard.recoveryKeyMatches(crypto, r.s("currentFp"), r.b64("recoveryPubB64")), why)
            r.sOrNull("statementUtf8")?.let { assertEquals(it, statementOf(frame), why) }

            val result = RecoveryRotation.verify(crypto, frame, r.s("instanceId"), r.s("currentFp"))
            if (expected == "ok") {
                val rotation = assertIs<Checked.Ok<VerifiedRotation>>(result, why).value
                // On ok the verifier's fingerprint becomes toFp.
                assertEquals(expect.s("toFp"), rotation.fields.toFp, why)
                assertEquals(r.s("currentFp"), rotation.fields.fromFp, why)
                assertEquals(r.s("instanceId"), rotation.fields.instanceId, why)
                assertEquals(SignedFrame.hash(crypto, frame), rotation.hash, why)
                // The typed fields are the statement: the outgoing seed signs them to the same bytes.
                assertContentEquals(frame, RecoveryRotation.sign(crypto, signerOf(crypto, keys, r.s("signer")), rotation.fields), "$why: re-sign")
            } else {
                assertEquals(expected, assertIs<Checked.Refused<RecoveryVerdict>>(result, why).verdict.code, why)
            }
            seen += expected
        }
        assertEveryVerdictHasARow(
            seen, "ok", "bad_frame", "non_canonical", "bad_statement", "fp_mismatch", "signer_not_pinned_key", "bad_signature", "instance_mismatch",
        )
    }

    @Test
    fun rotationFrames_eachNamedFrameIsARotationStatement() {
        assertTrue(rotationFrames.size >= 6)
        for ((name, frame) in rotationFrames) {
            val parsed = assertIs<Checked.Ok<ParsedFrame>>(StatementCodec.parseFrame(frame, TrustPurpose.RECOVERY_ROTATION), name).value
            assertEquals(TrustPurpose.RECOVERY_ROTATION, parsed.parts.purpose, name)
        }
        // The two the chains are built from verify for the verifier standing at their own fromFp.
        val a = keys.o("recoveryA").s("fingerprint")
        val b = keys.o("recoveryB").s("fingerprint")
        val c = keys.o("recoveryC").s("fingerprint")
        assertEquals(b, RecoveryRotation.verify(crypto, rotationFrames.getValue("A-to-B"), v.s("instanceId"), a).valueOrNull()?.fields?.toFp)
        assertEquals(c, RecoveryRotation.verify(crypto, rotationFrames.getValue("B-to-C"), v.s("instanceId"), b).valueOrNull()?.fields?.toFp)
        assertEquals(c, RecoveryRotation.verify(crypto, rotationFrames.getValue("A-to-C"), v.s("instanceId"), a).valueOrNull()?.fields?.toFp)
    }

    @Test
    fun escrowRotations_theChainOfPutEscrowSelf() {
        val rows = v.rows("escrowRotations")
        var accepted = 0
        gradeEvery("recovery.escrowRotations", rows) { r ->
            val why = "${r.s("name")}: ${r.s("why")}"
            val frames = named(r, "rotations")
            val instanceId = r.s("instanceId")
            val expect = r.o("expect")

            val verdict = RecoveryRotation.verifyChain(crypto, frames, instanceId, r.s("currentEscrowFp"), r.s("fingerprint"))
            assertEquals(expect.bool("accepted"), verdict == null, why)

            // The link that fails, where one does: each link is verified against the fingerprint the chain has reached.
            var reached = r.s("currentEscrowFp")
            var failedAt: Int? = null
            var linkVerdict: RecoveryVerdict? = null
            for ((i, frame) in frames.withIndex()) {
                val link = RecoveryRotation.verify(crypto, frame, instanceId, reached)
                if (link is Checked.Ok) {
                    reached = link.value.fields.toFp
                } else {
                    failedAt = i
                    linkVerdict = link.verdictOrNull()
                    break
                }
            }
            assertEquals(expect.sOrNull("failedAt")?.toInt(), failedAt, why)
            assertEquals(expect.sOrNull("linkVerdict"), linkVerdict?.code, why)

            if (expect.bool("accepted")) {
                accepted++
                assertEquals(r.s("fingerprint"), reached, why)
                // What the server stores an escrow for is also what a client's consent follows (§4.5 condition 2).
                assertTrue(RecoveryRotation.follows(crypto, frames, instanceId, r.s("currentEscrowFp"), r.s("fingerprint")), why)
            } else {
                assertEquals("409 escrow_not_due", expect.s("wire"), why)
                // The chain's verdict is its failing link's; with every link valid, the last toFp is not the fingerprint.
                assertEquals(linkVerdict ?: RecoveryVerdict.FP_MISMATCH, verdict, why)
            }
        }
        assertTrue(accepted >= 2, "a chain of one and a chain of two are accepted")
    }

    // ---- §4.5 first consent (FS-R2, FC-2) ----------------------------------------------------------

    @Test
    fun firstConsent_theWalkFromCardZeroNamesEveryUncoveredChange() {
        val rows = v.rows("firstConsent")
        val roots = HashSet<String>()
        gradeEvery("recovery.firstConsent", rows) { r ->
            val why = "${r.s("name")}: ${r.s("why")}"
            val chainRow = v.o("cardChains").o(r.s("cards"))
            val served = InstanceCard.verifyChain(crypto, chainRow.getValue("frames").jsonArray.strings().map(Bytes::fromB64))
            assertTrue(served.complete, "$why: the served chain verifies")
            val cards = served.chain.cards
            assertEquals(chainRow.getValue("recoveryFps").jsonArray.strings(), cards.map { it.fields.recoveryFp ?: TrustGrammar.NONE }, why)
            assertEquals(v.s("instanceId"), cards.first().fields.instanceId, why)

            // This device's pin is a card of that chain. The walk takes no pin: it starts at card 0 for every root (FC-2).
            val pin = r.o("pin")
            assertEquals(pin.s("cardHash"), served.chain.at(pin.l("seq"))?.hash, "$why: the pin is a card of the chain")
            roots += pin.s("root")

            val uncovered = RecoveryRotation.unsignedChanges(crypto, cards.map { it.fields }, named(r, "rotations"))
            val expect = r.o("expect")
            val expected = expect.rows("uncovered").map { change ->
                FpChange(change.l("seq"), change.s("from").takeIf { it != TrustGrammar.NONE }, change.s("to").takeIf { it != TrustGrammar.NONE })
            }
            assertEquals(expected, uncovered, why)
            // Any uncovered change shows the unsigned-change warning, with "Only me" preselected.
            assertEquals(expect.bool("warning"), uncovered.isNotEmpty(), why)
        }
        assertEquals(setOf("baked", "kit", "setup", "link_offer", "enrol", "trust_gate"), roots, "a row for every pin root")
    }

    // ---- §2.3, §9.3 the request code ---------------------------------------------------------------

    @Test
    fun requestCode_ninetySixBitsOfTheRequestKeyInSixGroupsOfFour() {
        val rows = v.rows("requestCode")
        gradeEvery("recovery.requestCode", rows) { r ->
            val why = r.s("why")
            val rPub = r.b64("rPubB64")
            val code = AssistedRecovery.requestCode(crypto, rPub)
            assertEquals(r.s("code"), code, why)
            assertEquals(r.s("code"), Bytes.toHexLower(crypto.sha256(r.s("inputUtf8").encodeToByteArray())).take(24), why)
            assertEquals(r.s("grouped"), AssistedRecovery.groupedRequestCode(code), why)
            // recovery-cli assist: the code as displayed, typed back, is the one the request key gives.
            assertTrue(AssistedRecovery.requestCodeMatches(crypto, r.s("grouped"), rPub), why)
            assertTrue(AssistedRecovery.requestCodeMatches(crypto, r.s("code"), rPub), why)
        }
        // Another request key gives another code, which is how a swapped rPub is caught.
        assertFalse(AssistedRecovery.requestCodeMatches(crypto, rows[0].s("grouped"), rows[1].b64("rPubB64")))
        assertFalse(AssistedRecovery.requestCodeMatches(crypto, rows[1].s("grouped"), rows[0].b64("rPubB64")))
        // The first row is the request key of this file's requests.
        assertEquals(v.o("requestKey").s("rPubB64"), rows[0].s("rPubB64"))
    }

    // ---- §9.3 step 4: the assisted-recovery payload (purpose 0x09) --------------------------------

    /** The requesting device opens the row's seal; [userId] is the account it holds, or null on a fresh install. */
    private fun open(r: JsonObject, userId: String?): Checked<OpenedAssistedRecovery, RecoveryVerdict> {
        val requestKey = v.o("requestKey")
        val request = r.o("request")
        return AssistedRecovery.open(
            crypto, requestKey.b64("rPubB64"), requestKey.b64("rSecB64"), r.b64("sealedB64"), r.s("cardRecoveryFp"),
            request.s("instanceId"), request.s("requestId"), IdentityCheck(r.s("encryptedIdentitySeedB64"), r.s("identityPubB64")), userId,
        )
    }

    @Test
    fun assisted_everyRowGetsItsExactVerdict() {
        val rows = v.rows("assisted")
        val requestKey = v.o("requestKey")
        val rPub = requestKey.b64("rPubB64")
        val rSec = requestKey.b64("rSecB64")
        val seen = HashSet<String>()
        gradeEvery("recovery.assisted", rows) { r ->
            val why = "${r.s("name")}: ${r.s("why")}"
            val request = r.o("request")
            val expect = r.o("expect")
            val expected = expect.s("verdict")
            assertEquals(requestKey.s("rPubB64"), request.s("requestKey"), "$why: the request names this device's key")
            // The function is handed the pinned card's recoveryFp; the key it names is the row's recoveryPubB64.
            assertTrue(InstanceCard.recoveryKeyMatches(crypto, r.s("cardRecoveryFp"), r.b64("recoveryPubB64")), why)

            // A fresh install holds no userId: the row's request.userId is null (§2.4 "Small cases").
            val heldUserId = request.sOrNull("userId")
            val result = open(r, heldUserId)
            if (expected == "ok") {
                val opened = assertIs<Checked.Ok<OpenedAssistedRecovery>>(result, why).value
                assertEquals(expect.s("uvkB64"), Bytes.toB64(opened.uvk), why)
                // The account comes from the payload, which the seed's AD bound; on a fresh install it is the one learned.
                assertEquals(heldUserId ?: keys.o("alice").s("userId"), opened.userId, why)
                // The frame inside the seal: its statement, and the recovery seed signs the same fields to the same bytes.
                val frame = crypto.sealOpen(rPub, rSec, r.b64("sealedB64"))
                assertEquals(r.s("statementUtf8"), statementOf(frame), why)
                val fields = AssistedRecoveryFields(request.s("instanceId"), opened.userId, request.s("requestId"), request.s("requestKey"), opened.uvk, opened.issuedAt)
                assertContentEquals(frame, AssistedRecovery.sign(crypto, signerOf(crypto, keys, r.s("signer")), fields), "$why: re-sign")
                // A seal made here opens to the same payload.
                val resealed = AssistedRecovery.open(
                    crypto, rPub, rSec, AssistedRecovery.seal(crypto, rPub, frame), r.s("cardRecoveryFp"), request.s("instanceId"),
                    request.s("requestId"), IdentityCheck(r.s("encryptedIdentitySeedB64"), r.s("identityPubB64")), heldUserId,
                )
                assertEquals(expect.s("uvkB64"), Bytes.toB64(assertIs<Checked.Ok<OpenedAssistedRecovery>>(resealed, why).value.uvk), why)
                opened.wipe()
                assertContentEquals(ByteArray(32), opened.uvk, why)
            } else {
                assertEquals(expected, assertIs<Checked.Refused<RecoveryVerdict>>(result, why).verdict.code, why)
            }
            seen += expected
        }
        assertEveryVerdictHasARow(
            seen, "ok", "unopenable", "bad_frame", "unknown_format", "non_canonical", "signer_not_pinned_key", "bad_signature",
            "request_mismatch", "identity_mismatch",
        )
    }

    /**
     * §2.4 "Small cases": a device that holds no `userId` (a fresh install) skips the `userId` comparison,
     * because the identity seed's AD binds it. The file has two such rows of its own; here every row that
     * holds a `userId` is opened again without one, and keeps its verdict except a payload whose ONLY
     * fault is the account it names: that one passes the request checks, and the served seed then does
     * not open under another account's AD.
     */
    @Test
    fun assisted_aFreshInstallSkipsTheUserIdComparison_andTheSeedsAdStillBindsTheAccount() {
        var boundByTheSeed = 0
        for (r in v.rows("assisted")) {
            val why = "${r.s("name")} on a fresh install"
            val request = r.o("request")
            val expected = r.o("expect").s("verdict")
            val onlyTheUserDiffers = expected == "request_mismatch" && r.sOrNull("statementUtf8")?.let { text ->
                val statement = Json.parseToJsonElement(text).jsonObject
                statement.s("instanceId") == request.s("instanceId") && statement.s("requestId") == request.s("requestId") &&
                    statement.s("requestKey") == request.s("requestKey") && statement.s("userId") != request.sOrNull("userId")
            } == true
            val result = open(r, userId = null)
            if (onlyTheUserDiffers) {
                boundByTheSeed++
                assertEquals(RecoveryVerdict.IDENTITY_MISMATCH, result.verdictOrNull(), why)
            } else {
                assertEquals(expected, result.verdictOrNull()?.code ?: "ok", why)
            }
        }
        assertTrue(boundByTheSeed >= 1, "the corpus has a payload for another account")
    }

    // ---- §9.3 step 2: the veto (purpose 0x0A) ------------------------------------------------------

    @Test
    fun veto_everyRowGetsItsExactVerdict() {
        val rows = v.rows("veto")
        val seen = HashSet<String>()
        gradeEvery("recovery.veto", rows) { r ->
            val why = "${r.s("name")}: ${r.s("why")}"
            val frame = r.b64("frameB64")
            val expected = r.o("expect").s("verdict")
            r.sOrNull("statementUtf8")?.let { assertEquals(it, statementOf(frame), why) }

            val result = RecoveryVeto.verify(crypto, frame, r.b64("storedIdentityPubB64"), r.s("sessionUserId"), r.s("requestId"))
            if (expected == "ok") {
                val veto = assertIs<Checked.Ok<VetoFields>>(result, why).value
                assertEquals(r.s("requestId"), veto.requestId, why)
                assertEquals(r.s("sessionUserId"), veto.userId, why)
                // The account's key signs the same fields to the same bytes.
                assertContentEquals(frame, RecoveryVeto.sign(crypto, signerOf(crypto, keys, r.s("signer")), veto), "$why: re-sign")
            } else {
                assertEquals(expected, assertIs<Checked.Refused<RecoveryVerdict>>(result, why).verdict.code, why)
            }
            seen += expected
        }
        assertEveryVerdictHasARow(
            seen, "ok", "bad_frame", "non_canonical", "bad_statement", "signer_not_pinned_key", "bad_signature", "user_mismatch", "request_mismatch",
        )
    }
}
