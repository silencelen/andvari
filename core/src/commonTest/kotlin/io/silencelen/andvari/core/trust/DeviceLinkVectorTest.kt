package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Hkdf
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Device linking (design 2026-11-15 §8, derivations of §2.3, verdicts and order of §2.4's "Device
 * link" row), graded off `devicelink.json` from the independent oracle: the derivations, the URL, the
 * commitment, the code, the three MACs, E's check of the claim, N's checks of `outer` before the
 * password, and N's checks after the pickup.
 *
 * The post-pickup rows are a flow: the genesis is verified when the device unlocks, before the bundle
 * is touched, so its verdicts come first ([AccountGenesis.verify]); then [DeviceLink.openBundle]
 * (`bundle_unopenable`, `bad_bundle`) and [DeviceLink.checkBundle] (`identity_mismatch`,
 * `pin_mismatch`). The harness below runs exactly those three calls in that order.
 */
class DeviceLinkVectorTest {
    private val crypto = createCryptoProvider()
    private val v = vector("devicelink.json")
    private val account = v.o("account")
    private val link = v.o("link")
    private val newDevice = v.o("newDevice")
    private val keys = DeviceLink.deriveKeys(crypto, link.b64("secretB64"))

    private fun keysOf(row: JsonObject) = DeviceLinkKeys(row.s("linkId"), row.b64("macKeyB64"))

    private fun claimOf(o: JsonObject): DeviceClaim {
        assertExpectGraded(o, setOf("nPub", "name", "platform", "commitN", "mac"), "a claim")
        return DeviceClaim(o.s("nPub"), o.s("name"), o.s("platform"), o.s("commitN"), o.s("mac"))
    }

    /**
     * Every key of a row is one this harness reads ([inputs], which for a section without an `expect`
     * object include the outputs it compares), and its `expect` holds exactly the keys the grader checks
     * for that row ([expect], null for a section without one). A key the oracle adds later fails here.
     */
    private fun keysGraded(r: JsonObject, label: String, inputs: Set<String>, expect: Set<String>? = null) {
        val name = "$label ${r.sOrNull("name") ?: r.sOrNull("why") ?: ""}"
        assertInputsKnown(r, inputs + (if (expect != null) setOf("expect") else emptySet()), name)
        if (expect != null) assertExpectGraded(r.o("expect"), expect, name)
    }

    private val verdictOnly = setOf("verdict")

    /** The MAC input text a row gives is the one whose HMAC under the row's `macKey` is the row's MAC. */
    private fun assertMacInput(r: JsonObject, macKey: String) {
        assertEquals(r.s(macKey), Bytes.toB64(crypto.hmacSha256(r.b64("macKeyB64"), r.s("inputUtf8").encodeToByteArray())), r.s("why"))
    }

    // ---- §2.3, §8.1 --------------------------------------------------------------------------------

    @Test
    fun theFileHasTheSectionsThisSuiteGrades_andNoOther() {
        assertSections(
            v, "_about", "origin", "account", "link", "newDevice", "existingDevice", "derive", "bundleKey", "url", "reveal", "code", "typedCode",
            "macs", "claim", "claimChanged", "nonceChanged", "outer", "bundleDefaults", "bundle", "imports", "checkpoints", "accountState",
        )
        assertSections(v.o("url"), "compose", "parse")
        assertSections(v.o("macs"), "claim", "pickup", "approve")
        assertSections(v.o("imports"), "keyHash", "currency")
    }

    @Test
    fun derive_linkIdAndMacKey() {
        gradeEvery("devicelink.derive", v.rows("derive")) { r ->
            keysGraded(r, "derive", setOf("why", "secretB64", "linkId", "macKeyB64"))
            // Every row is derived. The all-zero secret this table once held is refused (spec 01 "Keys in memory and the
            // lock", rule 4); keyfloor.json carries it as a must-refuse row and KeyFloorVectorTest grades it.
            val k = DeviceLink.deriveKeys(crypto, r.b64("secretB64"))
            assertEquals(r.s("linkId"), k.linkId, r.s("why"))
            assertContentEquals(r.b64("macKeyB64"), k.macKey, r.s("why"))
        }
        assertEquals(link.s("linkId"), keys.linkId)
        assertContentEquals(link.b64("macKeyB64"), keys.macKey)
    }

    @Test
    fun bundleKey_fromTheUvkAndTheLink() {
        gradeEvery("devicelink.bundleKey", v.rows("bundleKey")) { r ->
            keysGraded(r, "bundleKey", setOf("why", "uvkB64", "linkId", "bundleKeyB64", "adUtf8", "infoUtf8"))
            assertContentEquals(r.b64("bundleKeyB64"), DeviceLink.bundleKey(crypto, r.b64("uvkB64"), r.s("linkId")), r.s("why"))
            // The info text the row gives is the one HKDF takes: it derives the same key.
            assertContentEquals(r.b64("bundleKeyB64"), Hkdf.sha256(crypto, r.b64("uvkB64"), ByteArray(0), r.s("infoUtf8").encodeToByteArray(), 32), r.s("why"))
            assertEquals(r.s("adUtf8"), Ad.deviceLinkBundle(r.s("linkId")).decodeToString(), r.s("why"))
        }
    }

    @Test
    fun url_composeAndParse() {
        gradeEvery("devicelink.url.compose", v.o("url").rows("compose")) { r ->
            keysGraded(r, "url.compose", setOf("origin", "secretB64", "url"))
            assertEquals(r.s("url"), DeviceLinkUrl.compose(r.s("origin"), r.b64("secretB64")))
        }
        assertEquals(link.s("url"), DeviceLinkUrl.compose(v.s("origin"), link.b64("secretB64")))
        gradeEvery("devicelink.url.parse", v.o("url").rows("parse")) { r ->
            val why = r.s("why")
            val expect = r.o("expect")
            keysGraded(r, "url.parse", setOf("why", "input"), if (expect.s("verdict") == "ok") setOf("verdict", "origin", "secretB64") else verdictOnly)
            val parsed = DeviceLinkUrl.parse(r.s("input"))
            if (expect.s("verdict") == "ok") {
                assertNotNull(parsed, why)
                assertEquals(expect.s("origin"), parsed.origin, why)
                assertContentEquals(expect.b64("secretB64"), parsed.secret, why)
                assertEquals(ScanPayload.DEVICE_LINK, ScanPayload.of(r.s("input")), why)
            } else {
                assertEquals("bad_link", expect.s("verdict"), why)
                assertNull(parsed, why)
                assertTrue(ScanPayload.of(r.s("input")) != ScanPayload.DEVICE_LINK, why)
            }
        }
    }

    // ---- §8.2 the commitment, the code and the MACs ------------------------------------------------

    @Test
    fun reveal_opensOnlyItsCommitment() {
        assertEquals(newDevice.s("commitN"), CodeCommit.commit(crypto, newDevice.b64("nonceNB64")))
        gradeEvery("devicelink.reveal", v.rows("reveal")) { r ->
            keysGraded(r, "reveal", setOf("why", "commitN", "revealB64"), verdictOnly)
            val verdict = DeviceLink.checkReveal(crypto, r.s("commitN"), r.s("revealB64"))?.code ?: "ok"
            assertEquals(r.o("expect").s("verdict"), verdict, r.s("why"))
        }
    }

    @Test
    fun code_andTheTypedDigits() {
        gradeEvery("devicelink.code", v.rows("code")) { r ->
            keysGraded(r, "code", setOf("why", "linkId", "nPubB64", "nonceNB64", "nonceEB64", "code", "digestHex", "inputUtf8"))
            val code = ComparisonCode.deviceLink(crypto, r.s("linkId"), r.b64("nPubB64"), r.b64("nonceNB64"), r.b64("nonceEB64"))
            assertEquals(r.s("code"), code, r.s("why"))
            assertEquals(r.s("digestHex"), Bytes.toHexLower(crypto.sha256(r.s("inputUtf8").encodeToByteArray())), r.s("why"))
        }
        gradeEvery("devicelink.typedCode", v.rows("typedCode")) { r ->
            keysGraded(r, "typedCode", setOf("why", "typed", "code"), verdictOnly)
            val verdict = if (ComparisonCode.matches(r.s("typed"), r.s("code"))) "ok" else "code_mismatch"
            assertEquals(r.o("expect").s("verdict"), verdict, r.s("why"))
        }
    }

    @Test
    fun macs_claimPickupAndApprove() {
        val macs = v.o("macs")
        gradeEvery("devicelink.macs.claim", macs.rows("claim")) { r ->
            keysGraded(r, "macs.claim", setOf("why", "linkId", "macKeyB64", "nPub", "name", "platform", "commitN", "mac", "inputUtf8"))
            assertEquals(r.s("mac"), DeviceLink.claimMac(crypto, keysOf(r), r.s("nPub"), r.s("name"), r.s("platform"), r.s("commitN")), r.s("why"))
            assertMacInput(r, "mac")
        }
        gradeEvery("devicelink.macs.pickup", macs.rows("pickup")) { r ->
            keysGraded(r, "macs.pickup", setOf("why", "linkId", "macKeyB64", "nPub", "proof", "proofHash", "inputUtf8"))
            assertMacInput(r, "proof")
            val proof = DeviceLink.pickupProof(crypto, keysOf(r), r.s("nPub"))
            assertEquals(r.s("proof"), proof, r.s("why"))
            assertEquals(r.s("proofHash"), DeviceLink.proofHash(crypto, proof), r.s("why"))
        }
        gradeEvery("devicelink.macs.approve", macs.rows("approve")) { r ->
            keysGraded(r, "macs.approve", setOf("why", "linkId", "macKeyB64", "outerB64", "outerSha256Hex", "approveMac", "inputUtf8"))
            assertMacInput(r, "approveMac")
            assertEquals(r.s("outerSha256Hex"), Bytes.toHexLower(crypto.sha256(r.b64("outerB64"))), r.s("why"))
            assertEquals(r.s("approveMac"), DeviceLink.approveMac(crypto, keysOf(r), r.b64("outerB64")), r.s("why"))
        }
    }

    // ---- §8.2 step 3: E's check of the claim -------------------------------------------------------

    @Test
    fun claim_everyRowGetsItsExactVerdict() {
        gradeEvery("devicelink.claim", v.rows("claim")) { r ->
            keysGraded(r, "claim", setOf("why", "name", "claim"), verdictOnly)
            val name = r.s("name")
            val claim = claimOf(r.o("claim"))
            when (val result = DeviceLink.verifyClaim(crypto, keys, claim)) {
                is Checked.Refused -> assertEquals(r.o("expect").s("verdict"), result.verdict.code, name)
                is Checked.Ok -> {
                    assertEquals(r.o("expect").s("verdict"), "ok", name)
                    assertContentEquals(Bytes.fromB64(claim.nPub), result.value.nPub, name)
                    assertEquals(claim.name, TrustGrammar.encodeName(result.value.deviceName), name)
                }
            }
        }
    }

    @Test
    fun claimChanged_andNonceChanged() {
        gradeEvery("devicelink.claimChanged", v.rows("claimChanged")) { r ->
            keysGraded(r, "claimChanged", setOf("why", "fixed", "later"), verdictOnly)
            val verdict = if (claimOf(r.o("fixed")).sameClaim(claimOf(r.o("later")))) "ok" else "claim_changed"
            assertEquals(r.o("expect").s("verdict"), verdict, r.s("why"))
        }
        // The new device's single-assignment rule is plain equality of the two nonce strings.
        gradeEvery("devicelink.nonceChanged", v.rows("nonceChanged")) { r ->
            keysGraded(r, "nonceChanged", setOf("why", "heldB64", "servedB64"), verdictOnly)
            val verdict = if (r.s("heldB64") == r.s("servedB64")) "ok" else "nonce_changed"
            assertEquals(r.o("expect").s("verdict"), verdict, r.s("why"))
        }
    }

    // ---- §8.2 step 7: N's checks before the password -----------------------------------------------

    @Test
    fun outer_everyRowGetsItsExactVerdict() {
        val rows = v.rows("outer")
        val nPub = newDevice.b64("nPubB64")
        val nSec = newDevice.b64("nSecB64")
        val seen = HashSet<String>()
        val differ = ArrayList<String>()
        gradeEvery("devicelink.outer", rows) { r ->
            val name = r.s("name")
            val expect = r.o("expect")
            val expected = expect.s("verdict")
            keysGraded(
                r, "outer", setOf("why", "name", "outerB64", "approveMac", "pinnedOrigin", "plaintextUtf8"),
                if (expected == "ok") setOf("verdict", "outer") else verdictOnly,
            )
            val result = DeviceLink.openOuter(crypto, keys, nPub, nSec, r.b64("outerB64"), r.s("approveMac"), r.s("pinnedOrigin"))
            when (result) {
                is Checked.Refused -> if (result.verdict.code != expected) differ += "$name: expected $expected, was ${result.verdict.code}"
                is Checked.Ok -> {
                    if (expected != "ok") {
                        differ += "$name: expected $expected, was ok"
                    } else {
                        val o = expect.o("outer")
                        assertExpectGraded(o, setOf("v", "origin", "userId", "email"), "$name: outer")
                        assertEquals(2L, o.l("v"), name)
                        assertEquals(DeviceLinkOuter(o.s("origin"), o.s("userId"), o.s("email")), result.value, name)
                    }
                }
            }
            // Where the row gives the sealed text, the decoder alone agrees with the verdict: it refuses
            // a bad_outer text and reads the text of a row that got past the decode. A row stopped
            // earlier (bad_mac, outer_unopenable) says nothing about its text.
            r.sOrNull("plaintextUtf8")?.let { text ->
                val decoded = DeviceLink.decodeOuter(text.encodeToByteArray())
                when (expected) {
                    "bad_outer" -> assertNull(decoded, "$name: the decoder alone")
                    "ok", "origin_mismatch" -> assertNotNull(decoded, "$name: the decoder alone")
                }
            }
            seen += expected
        }
        assertEquals(emptyList(), differ, "rows that got another verdict")
        for (verdict in listOf("ok", "bad_mac", "outer_unopenable", "bad_outer", "origin_mismatch")) assertTrue(verdict in seen, "no row for $verdict")
        // The row named valid is in the design's key order: encoding its values gives the same text.
        val valid = rows.first { it.s("name") == "valid" }
        val o = valid.o("expect").o("outer")
        assertEquals(valid.s("plaintextUtf8"), DeviceLink.encodeOuter(DeviceLinkOuter(o.s("origin"), o.s("userId"), o.s("email"))).decodeToString())
    }

    // ---- §8.2 step 8, §8.3: N's checks after the pickup --------------------------------------------

    private fun checkpointOf(o: JsonObject) = Checkpoint(o.l("seq"), o.s("hash"))

    private fun bundleOf(o: JsonObject): DeviceLinkBundle {
        assertExpectGraded(
            o, setOf("v", "origin", "instanceId", "card", "userId", "email", "identityPub", "personalVaultId", "contacts", "vaults", "accountState", "issuedAt"),
            "an expected bundle",
        )
        assertEquals(2L, o.l("v"), "an expected bundle's v")
        return bundleFields(o)
    }

    private fun bundleFields(o: JsonObject) = DeviceLinkBundle(
        o.s("origin"), o.s("instanceId"), checkpointOf(o.o("card")), o.s("userId"), o.s("email"), o.s("identityPub"), o.s("personalVaultId"),
        o.rows("contacts").map { BundleContact(it.s("userId"), it.s("keyHash"), it.l("verifiedAt")) },
        o.rows("vaults").map { BundleVault(it.s("vaultId"), it.l("seq"), it.s("hash")) },
        checkpointOf(o.o("accountState")), o.l("issuedAt"),
    )

    private sealed class Finish {
        class Refused(val verdict: String) : Finish()
        class Ok(val bundle: DeviceLinkBundle) : Finish()
    }

    /** §8.2 step 8 in §2.4's order: the genesis at unlock, then the bundle. */
    private fun finish(r: JsonObject): Finish {
        val defaults = v.o("bundleDefaults")
        val sessionUserId = r.sOrNull("sessionUserId") ?: defaults.s("sessionUserId")
        val genesisFrame = Bytes.fromB64(r.sOrNull("genesisB64") ?: defaults.s("genesisB64"))
        val pin = r.oOrNull("pin") ?: defaults.o("pin")
        val chain = (r["verifiedChain"] ?: defaults.getValue("verifiedChain")).jsonArray.strings()
        // The key this device derived from the identity seed it unlocked, never a served one.
        val identityPub = crypto.boxKeypairFromSeed(account.b64("seedB64")).publicKey
        assertContentEquals(account.b64("identityPubB64"), identityPub)
        val signPub = crypto.signKeypairFromSeed(account.b64("seedB64")).publicKey

        val genesis = when (val g = AccountGenesis.verify(crypto, genesisFrame, signPub, identityPub, sessionUserId, pin.s("instanceId"), null)) {
            is Checked.Refused -> return Finish.Refused(g.verdict.code)
            is Checked.Ok -> g.value
        }
        val bundle = when (val b = DeviceLink.openBundle(crypto, account.b64("uvkB64"), keys.linkId, r.b64("innerB64"))) {
            is Checked.Refused -> return Finish.Refused(b.verdict.code)
            is Checked.Ok -> b.value
        }
        val verdict = DeviceLink.checkBundle(bundle, sessionUserId, identityPub, genesis.fields.personalVaultId, pin.s("origin"), pin.s("instanceId")) { seq ->
            if (seq >= 0 && seq < chain.size) chain[seq.toInt()] else null
        }
        return if (verdict != null) Finish.Refused(verdict.code) else Finish.Ok(bundle)
    }

    @Test
    fun bundle_everyRowGetsItsExactVerdict() {
        val rows = v.rows("bundle")
        val seen = HashSet<String>()
        gradeEvery("devicelink.bundle", rows) { r ->
            val name = r.s("name")
            val expect = r.o("expect")
            val expectKeys = when {
                expect.s("verdict") != "ok" -> verdictOnly
                expect.oOrNull("bundle") != null -> setOf("verdict", "bundle")
                else -> setOf("verdict", "contacts", "vaults", "plaintextBytes")
            }
            // sessionUserId, pin and verifiedChain override bundleDefaults when a row gives them (finish).
            keysGraded(r, "bundle", setOf("why", "name", "genesisB64", "innerB64", "plaintextUtf8", "sessionUserId", "pin", "verifiedChain"), expectKeys)
            when (val result = finish(r)) {
                is Finish.Refused -> assertEquals(expect.s("verdict"), result.verdict, name)
                is Finish.Ok -> {
                    assertEquals(expect.s("verdict"), "ok", name)
                    val expected = expect.oOrNull("bundle")
                    if (expected != null) {
                        assertEquals(bundleOf(expected), result.bundle, name)
                    } else {
                        // The 64 KiB row gives the plaintext length and the entry counts instead.
                        assertEquals(expect.l("contacts").toInt(), result.bundle.contacts.size, name)
                        assertEquals(expect.l("vaults").toInt(), result.bundle.vaults.size, name)
                        assertEquals(expect.l("plaintextBytes").toInt(), DeviceLink.encodeBundle(result.bundle).size, name)
                        assertTrue(DeviceLink.fits(result.bundle), name)
                    }
                }
            }
            // Where the row gives the sealed text, the decoder alone agrees with the verdict: it refuses
            // a bad_bundle text and reads the text of a row that got past the decode. A row stopped
            // earlier (a genesis verdict, bundle_unopenable) says nothing about its text.
            r.sOrNull("plaintextUtf8")?.let { text ->
                val decoded = DeviceLink.decodeBundle(text.encodeToByteArray())
                when (expect.s("verdict")) {
                    "bad_bundle" -> assertNull(decoded, "$name: the decoder alone")
                    "ok", "identity_mismatch", "pin_mismatch" -> assertNotNull(decoded, "$name: the decoder alone")
                }
            }
            seen += expect.s("verdict")
        }
        val named = listOf(
            "ok", "bad_frame", "signer_not_pinned_key", "user_mismatch", "instance_mismatch",
            "bundle_unopenable", "bad_bundle", "identity_mismatch", "pin_mismatch",
        )
        for (verdict in named) assertTrue(verdict in seen, "no row for $verdict")
        // The row named valid is in the design's key order: encoding its values gives the same text,
        // and sealing it again gives an inner this device opens.
        val valid = rows.first { it.s("name") == "valid" }
        val bundle = bundleOf(valid.o("expect").o("bundle"))
        assertEquals(valid.s("plaintextUtf8"), DeviceLink.encodeBundle(bundle).decodeToString())
        val resealed = DeviceLink.sealBundle(crypto, account.b64("uvkB64"), keys.linkId, bundle)
        assertEquals(bundle, assertIs<Checked.Ok<DeviceLinkBundle>>(DeviceLink.openBundle(crypto, account.b64("uvkB64"), keys.linkId, resealed)).value)
    }

    // ---- §8.3 how the new device imports the bundle ------------------------------------------------

    @Test
    fun imports_theBundleConfersCurrencyNeverContacts() {
        val imports = v.o("imports")
        gradeEvery("devicelink.imports.keyHash", imports.rows("keyHash")) { r ->
            keysGraded(r, "imports.keyHash", setOf("identityPubB64", "keyHash"))
            assertEquals(r.s("keyHash"), DeviceLink.contactKeyHash(crypto, r.b64("identityPubB64")))
        }
        gradeEvery("devicelink.imports.currency", imports.rows("currency")) { r ->
            keysGraded(r, "imports.currency", setOf("why", "accountStateContacts", "bundleContacts"), setOf("current"))
            val held = r.o("accountStateContacts")
            val current = r.rows("bundleContacts")
                .map { BundleContact(it.s("userId"), it.s("keyHash"), it.l("verifiedAt")) }
                .filter { c -> DeviceLink.confirmsContact(crypto, c, held.oOrNull(c.userId)?.b64("identityPub")) }
                .map { it.userId }
            assertEquals(r.o("expect").getValue("current").jsonArray.strings(), current, r.s("why"))
        }
    }

    @Test
    fun checkpoints_andTheAccountStateMark() {
        gradeEvery("devicelink.checkpoints", v.rows("checkpoints")) { r ->
            keysGraded(r, "checkpoints", setOf("why", "held", "servedHashes"), verdictOnly)
            val verdict = Checkpoints.compare(checkpointOf(r.o("held")), r.getValue("servedHashes").jsonArray.strings())
            assertEquals(r.o("expect").s("verdict"), verdict.code, r.s("why"))
        }
        gradeEvery("devicelink.accountState", v.rows("accountState")) { r ->
            keysGraded(r, "accountState", setOf("why", "checkpoint", "served"), setOf("rollback", "fork"))
            val served = r.o("served")
            val hash = Bytes.toHexLower(crypto.sha256(served.s("sealedState").encodeToByteArray()))
            val verdict = Checkpoints.compareAccountState(checkpointOf(r.o("checkpoint")), served.l("seq"), hash)
            assertEquals(r.o("expect").bool("rollback"), verdict == CheckpointVerdict.ROLLBACK, r.s("why"))
            assertEquals(r.o("expect").bool("fork"), verdict == CheckpointVerdict.FORK, r.s("why"))
        }
    }
}
