package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Bytes
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
 * The vault log of design 2026-11-15 §3.1–§3.4, graded off `vaultlog.json` from the independent oracle:
 * five chains with the state after every entry, one rejection for every signer rule and precondition of
 * §3.3's table, the check order, the time rules (including the clock-free row with `at = 2^53 − 1`),
 * undefined signer keys (FI-B1), forks against seen hashes, the checkpoint comparison and `vkCommit`.
 *
 * The verifier under test is [VaultLog.verify], the same code the server runs (T-R2).
 */
class VaultLogVectorTest {
    private val crypto = createCryptoProvider()
    private val v = vector("vaultlog.json")
    private val vaultId = v.s("vaultId")
    private val accounts = v.o("accounts")
    private val chains: Map<String, List<JsonObject>> = v.rows("chains").associate { it.s("name") to it.rows("entries") }

    private fun frames(chain: String, count: Int): List<ByteArray> = chains.getValue(chain).take(count).map { it.b64("frameB64") }

    // The chain rules alone, from the genesis, on a device that holds no hash for any position. The `forks`
    // rows are the ones that hold something, and they say so where they call the verifier.
    private fun replay(vaultId: String, frames: List<ByteArray>): VaultLogReplay = VaultLog.replay(crypto, vaultId, frames, from = null, known = KnownHashes.NONE_HELD)

    private fun verify(vaultId: String, prior: VaultState?, frame: ByteArray) = VaultLog.verify(crypto, vaultId, prior, frame, KnownHashes.NONE_HELD)

    /** The state as the vector writes it: §3.3's S, with `head.at` and null for "none". */
    private fun assertState(expected: JsonObject, state: VaultState, why: String) {
        assertEquals(expected.s("vaultId"), state.vaultId, why)
        val head = expected.o("head")
        assertEquals(head.l("seq"), state.head.seq, "$why: head.seq")
        assertEquals(head.s("hash"), state.head.hash, "$why: head.hash")
        assertEquals(head.l("at"), state.at, "$why: head.at")
        assertEquals(expected.s("owner"), state.owner, "$why: owner")
        assertEquals(expected.s("ownerKey"), state.ownerKey, "$why: ownerKey")
        assertEquals(expected.s("vkCommit"), state.vkCommit, "$why: vkCommit")

        val members = expected.o("members")
        assertEquals(members.keys, state.members.keys, "$why: members")
        for ((userId, m) in state.members) {
            val want = members.o(userId)
            assertEquals(want.s("key"), m.key, "$why: key of $userId")
            assertEquals(want.s("role"), m.role.literal, "$why: role of $userId")
        }
        val pending = expected.oOrNull("pending")
        if (pending == null) {
            assertNull(state.pending, "$why: pending")
        } else {
            val p = assertNotNull(state.pending, "$why: pending")
            assertEquals(pending.s("offerId"), p.offerId, why)
            assertEquals(pending.s("to"), p.to, why)
            assertEquals(pending.s("toKey"), p.toKey, why)
            assertEquals(pending.l("expiresAt"), p.expiresAt, why)
        }
        assertEquals(expected.oOrNull("deleted")?.s("deleteId"), state.deleteId, "$why: deleted")
    }

    @Test
    fun constants_matchTheFile() {
        assertEquals(v.l("offerMaxLifetimeMs"), VaultLog.MAX_OFFER_WINDOW_MS)
        assertEquals(v.l("maxMs"), TrustGrammar.INT_CEILING - 1)
    }

    @Test
    fun theFileHasTheSectionsThisSuiteGrades_andNoOther() {
        assertSections(
            v, "_about", "vaultId", "otherVaultId", "vkB64", "vkCommitHex", "offerMaxLifetimeMs", "maxMs", "accounts", "vkCommit", "chains",
            "reject", "forks", "checkpoints",
        )
        assertSections(v.o("vkCommit"), "derive", "check")
    }

    @Test
    fun chains_everyEntryVerifiesAndGivesTheExpectedState() {
        gradeEvery("vaultlog.chains", chains.entries.toList()) { (name, entries) ->
            var state: VaultState? = null
            gradeEvery("vaultlog.chains.$name", entries.withIndex().toList()) { (i, e) ->
                val why = "$name[$i] ${e.s("why")}"
                val frame = e.b64("frameB64")
                val step = assertIs<Checked.Ok<VaultLogStep>>(verify(vaultId, state, frame), why).value
                assertEquals(e.s("hash"), step.hash, "$why: H(frame)")
                assertEquals(i.toLong(), step.entry.seq, why)
                assertState(e.o("state"), step.state, why)

                // The typed entry is the statement: signing it again with the row's signer gives the same bytes.
                assertContentEquals(frame, VaultLog.sign(crypto, signerOf(crypto, accounts, e.s("signer")), step.entry), "$why: re-sign")
                val parsed = assertIs<Checked.Ok<UnverifiedLogEntry>>(VaultLog.parse(crypto, frame), why).value
                assertEquals(step.entry, parsed.entry, why)
                assertEquals(e.s("statementUtf8"), assertIs<Checked.Ok<FrameParts>>(SignedFrame.split(frame)).value.statement.decodeToString(), why)

                // What the state derives beyond S: the genesis hash, the creator, and the add index.
                assertEquals(entries[0].s("hash"), step.state.genesisHash, why)
                assertEquals(entries[0].o("state").s("owner"), step.state.creator, why)

                // A stored state restores to an equal one, and the log goes on from it.
                val restored = assertNotNull(VaultState.decode(step.state.encode()), why)
                assertEquals(step.state, restored, why)
                state = restored
            }
            // The same frames through replay.
            val replay = replay(vaultId, entries.map { it.b64("frameB64") })
            assertNull(replay.verdict, name)
            assertEquals(entries.size, replay.accepted, name)
            assertEquals(state, replay.state, name)
        }
    }

    @Test
    fun reject_everyRowGetsItsExactVerdictAndTheStateStays() {
        gradeEvery("vaultlog.reject", v.rows("reject")) { r ->
            val name = r.s("name")
            val asVault = r.sOrNull("vaultId") ?: vaultId
            val before = replay(asVault, frames(r.s("chain"), r.l("after").toInt()))
            assertNull(before.verdict, "$name: the entries before the row verify")
            val result = verify(asVault, before.state, r.b64("frameB64"))
            val refused = assertIs<Checked.Refused<VaultLogVerdict>>(result, name)
            assertEquals(r.o("expect").s("verdict"), refused.verdict.code, "$name: ${r.s("why")}")

            // replay stops at the same frame with the same verdict and keeps the last good state.
            val whole = replay(asVault, frames(r.s("chain"), r.l("after").toInt()) + r.b64("frameB64"))
            assertEquals(refused.verdict, whole.verdict, name)
            assertEquals(r.l("after").toInt(), whole.accepted, name)
            assertEquals(before.state, whole.state, name)
        }
    }

    @Test
    fun forks_aDifferentValidEntryAtASeenPosition() {
        gradeEvery("vaultlog.forks", v.rows("forks")) { r ->
            val name = r.s("name")
            val seen = r.rows("seen").associate { it.l("seq") to it.s("hash") }
            val framesB64 = r.getValue("frames").jsonArray.strings()
            // What this device holds for a position: the one place in this file where fork detection has something to detect.
            val replay = VaultLog.replay(crypto, vaultId, framesB64.map(Bytes::fromB64), from = null, known = { seq -> seen[seq] })
            val expect = r.o("expect")
            if (expect.s("verdict") == "ok") {
                assertNull(replay.verdict, name)
                assertEquals(framesB64.size, replay.accepted, name)
            } else {
                assertEquals(expect.s("verdict"), replay.verdict?.code, "$name: ${r.s("why")}")
                assertEquals(expect.l("failedAt").toInt(), replay.accepted, "$name: failedAt")
            }
        }
    }

    @Test
    fun checkpoints_servedChainAgainstAHeldHead() {
        gradeEvery("vaultlog.checkpoints", v.rows("checkpoints")) { r ->
            val name = r.s("name")
            val framesB64 = r.getValue("frames").jsonArray.strings()
            // The served chain verifies; the verdict depends only on the held head and the served hashes.
            val served = framesB64.map(Bytes::fromB64)
            assertNull(replay(vaultId, served).verdict, name)
            val hashes = served.map { SignedFrame.hash(crypto, it) }
            val held = Checkpoint(r.o("held").l("seq"), r.o("held").s("hash"))
            assertEquals(r.o("expect").s("verdict"), Checkpoints.compare(held, hashes).code, "$name: ${r.s("why")}")
        }
    }

    @Test
    fun vkCommit_deriveAndCheck() {
        val kc = v.o("vkCommit")
        gradeEvery("vaultlog.vkCommit.derive", kc.rows("derive")) { r ->
            // Every row is derived. The all-zero key this table once held is refused (spec 01 "Keys in memory and the
            // lock", rule 4); keyfloor.json carries it as a must-refuse row and KeyFloorVectorTest grades it.
            assertEquals(r.s("vkCommit"), VaultLog.vkCommit(crypto, r.b64("vkB64"), r.s("vaultId")), r.s("why"))
        }
        gradeEvery("vaultlog.vkCommit.check", kc.rows("check")) { r ->
            assertEquals(
                r.bool("matches"),
                VaultLog.keyMatches(crypto, r.s("vaultId"), r.s("vkCommit"), r.b64("candidateVkB64")),
                r.s("why"),
            )
        }
        // The chains' own key matches the state every chain commits to.
        val state = assertNotNull(replay(vaultId, frames("lifecycle", 1)).state)
        assertEquals(v.s("vkCommitHex"), state.vkCommit)
        assertTrue(VaultLog.keyMatches(crypto, state, v.b64("vkB64")))
        assertTrue(!VaultLog.keyMatches(crypto, state, ByteArray(32)))
        assertTrue(!VaultLog.keyMatches(crypto, state, ByteArray(31)))
    }
}
