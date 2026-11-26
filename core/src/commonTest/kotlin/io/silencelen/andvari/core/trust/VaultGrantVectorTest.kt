package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Grants under design 2026-11-15 §3.5, graded off the REWRITTEN `sharedgrant-v2.json` from the
 * independent oracle. It lives in `spec/test-vectors/next/` until integration; the old file of that
 * name stays where the old `crypto.SignedGrant` tests read it.
 *
 * Each case: account `me` opens `sealedB64` from its grant row for `rowVaultId`, with the vault's log
 * as served. The log is replayed first: when it does not verify the grant is never evaluated and the
 * result is the log's own verdict (§3.5 step 6); a log with no entry gives no state, and then no `add`.
 */
class VaultGrantVectorTest {
    private val crypto = createCryptoProvider()
    private val v = vector("next/sharedgrant-v2.json")
    private val accounts = v.o("accounts")

    @Test
    fun theFileHasTheSectionsThisSuiteGrades_andNoOther() {
        assertSections(v, "_about", "vaultId", "otherVaultId", "vkB64", "vkCommitHex", "accounts", "logs", "cases")
    }

    @Test
    fun logs_replayToTheirOwnVerdict() {
        gradeEvery("sharedgrant-v2.logs", v.o("logs").entries.toList()) { (name, element) ->
            val log = element.jsonObject
            val frames = log.getValue("frames").jsonArray.strings().map(Bytes::fromB64)
            val replay = VaultLog.replay(crypto, v.s("vaultId"), frames, from = null, known = KnownHashes.NONE_HELD)
            assertEquals(log.s("verdict"), replay.verdict?.code ?: "ok", "log $name")
            if (replay.verdict != null) {
                assertEquals(log.l("failedAt").toInt(), replay.accepted, "log $name: the entries accepted before the failing one")
                return@gradeEvery
            }
            val expected = log.oOrNull("state")
            val state = replay.state
            if (expected == null) {
                assertNull(state, "log $name: no entry, no state")
                return@gradeEvery
            }
            assertNotNull(state, "log $name")
            assertEquals(expected.o("head").l("seq"), state.head.seq, "log $name")
            assertEquals(expected.o("head").s("hash"), state.head.hash, "log $name")
            assertEquals(expected.s("owner"), state.owner, "log $name")
            assertEquals(expected.s("ownerKey"), state.ownerKey, "log $name")
            assertEquals(expected.s("vkCommit"), state.vkCommit, "log $name")
            assertEquals(expected.o("members").keys, state.members.keys, "log $name")
        }
    }

    @Test
    fun cases_everyRowGetsItsExactVerdict() {
        val replays = v.o("logs").mapValues { (_, log) ->
            VaultLog.replay(crypto, v.s("vaultId"), log.jsonObject.getValue("frames").jsonArray.strings().map(Bytes::fromB64), from = null, known = KnownHashes.NONE_HELD)
        }
        gradeEvery("sharedgrant-v2.cases", v.rows("cases")) { c ->
            val name = c.s("name")
            val me = accounts.o(c.s("me"))
            val box = crypto.boxKeypairFromSeed(me.b64("seedB64"))
            assertEquals(me.s("identityPubB64"), Bytes.toB64(box.publicKey), name)
            val expect = c.o("expect")
            val expected = expect.s("verdict")
            // The log is replayed before any grant is opened; one that does not verify decides alone.
            val replay = replays.getValue(c.s("log"))
            val logVerdict = replay.verdict
            if (logVerdict != null) {
                assertEquals(expected, logVerdict.code, "$name: ${c.s("why")}")
                return@gradeEvery
            }
            val result = VaultGrant.open(crypto, me.s("userId"), box.publicKey, box.privateKey, c.s("rowVaultId"), c.b64("sealedB64"), replay.state)
            if (expected == "ok") {
                val opened = assertIs<Checked.Ok<OpenedGrant>>(result, "$name: ${c.s("why")}").value
                assertEquals(expect.s("vkB64"), Bytes.toB64(opened.vk), name)
                assertEquals(expect.s("from"), opened.from, name)
                assertEquals(expect.s("grantId"), opened.grantId, name)
                assertEquals(expect.l("issuedAt"), opened.issuedAt, name)
                // The add it was bound to is this account's latest, and the one this grant names.
                assertEquals(opened.grantId, opened.add.grantId, name)
                assertEquals(me.s("userId"), opened.add.member, name)
                assertEquals(opened.from, opened.add.actor, name)
                assertEquals(replay.state?.latestAdd(me.s("userId")), opened.add, name)
            } else {
                val refused = assertIs<Checked.Refused<VaultGrantVerdict>>(result, "$name: ${c.s("why")}")
                assertEquals(expected, refused.verdict.code, "$name: ${c.s("why")}")
            }
        }
    }
}
