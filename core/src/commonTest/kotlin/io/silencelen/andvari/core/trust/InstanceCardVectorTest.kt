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
 * The instance card of design 2026-11-15 §4.1, §4.2 and §4.4, graded off `instancecard.json` from the
 * independent oracle: two chains (a rename, a move, operator recovery turned on, a rotation, a
 * handover, a kind change), one rejection per chain rule in §2.4's order, the pin comparison (fork,
 * withheld), the three roots, and `operator_key_mismatch` on an operator's own device (VR-11).
 */
class InstanceCardVectorTest {
    private val crypto = createCryptoProvider()
    private val v = vector("instancecard.json")
    private val keys = v.o("keys")
    private val chains: Map<String, List<JsonObject>> = v.rows("chains").associate { it.s("name") to it.rows("cards") }

    private fun frames(row: JsonObject): List<ByteArray> = row.getValue("frames").jsonArray.strings().map(Bytes::fromB64)

    /** The pin record of §4.4 as the vector writes it, against a verified card. */
    private fun assertRecord(record: JsonObject, card: VerifiedCard, why: String) {
        val f = card.fields
        assertEquals(record.s("instanceId"), f.instanceId, "$why: instanceId")
        assertEquals(record.s("card0Hash"), card.card0Hash, "$why: card0Hash")
        assertEquals(record.l("seq"), f.seq, "$why: seq")
        assertEquals(record.s("hash"), card.hash, "$why: hash")
        assertEquals(record.s("origin"), f.origin, "$why: origin")
        assertEquals(record.s("name"), TrustGrammar.encodeName(f.name), "$why: name")
        assertEquals(record.s("kind"), f.kind.literal, "$why: kind")
        assertEquals(record.s("operator"), f.operator, "$why: operator")
        assertEquals(record.s("operatorSignKey"), f.operatorSignKey, "$why: operatorSignKey")
        assertEquals(record.s("recoveryFp"), f.recoveryFp ?: "none", "$why: recoveryFp")
        // The head a device pins carries the same five values.
        assertEquals(CardHead(f.instanceId, card.card0Hash, f.seq, card.hash, f.operatorSignKey), card.head, why)
    }

    @Test
    fun theFileHasTheSectionsThisSuiteGrades_andNoOther() {
        assertSections(v, "_about", "instanceId", "keys", "chains", "reject", "pinned", "roots", "operatorDevice")
    }

    @Test
    fun chains_everyCardVerifiesAndGivesItsRecord() {
        gradeEvery("instancecard.chains", chains.entries.toList()) { (name, cards) ->
            var head: CardHead? = null
            gradeEvery("instancecard.chains.$name", cards.withIndex().toList()) { (i, c) ->
                val why = "$name[$i] ${c.s("why")}"
                val frame = c.b64("frameB64")
                val card = assertIs<Checked.Ok<VerifiedCard>>(InstanceCard.verify(crypto, head, frame), why).value
                assertEquals(c.s("hash"), card.hash, "$why: H(frame)")
                assertRecord(c.o("record"), card, why)
                assertContentEquals(frame, card.frame, why)
                // The typed fields are the statement: signing them again with the row's signer gives the same bytes.
                assertContentEquals(frame, InstanceCard.sign(crypto, signerOf(crypto, keys, c.s("signer")), card.fields), "$why: re-sign")
                assertEquals(c.s("statementUtf8"), assertIs<Checked.Ok<FrameParts>>(SignedFrame.split(frame)).value.statement.decodeToString(), why)
                head = card.head
            }
            val whole = InstanceCard.verifyChain(crypto, cards.map { it.b64("frameB64") })
            assertTrue(whole.complete, name)
            assertEquals(cards.size, whole.chain.cards.size, name)
            assertEquals(cards[0].s("hash"), whole.chain.card0Hash, name)
            assertEquals(head, whole.chain.newest?.head, name)
        }
    }

    @Test
    fun reject_everyRowGetsItsExactVerdict() {
        gradeEvery("instancecard.reject", v.rows("reject")) { r ->
            val name = r.s("name")
            val after = r.l("after").toInt()
            val before = InstanceCard.verifyChain(crypto, chains.getValue(r.s("chain")).take(after).map { it.b64("frameB64") })
            assertTrue(before.complete, "$name: the cards before the row verify")
            val result = InstanceCard.verify(crypto, before.chain.newest?.head, r.b64("frameB64"))
            assertEquals(r.o("expect").s("verdict"), assertIs<Checked.Refused<CardVerdict>>(result, name).verdict.code, "$name: ${r.s("why")}")
        }
    }

    @Test
    fun pinned_servedChainAgainstAPin() {
        gradeEvery("instancecard.pinned", v.rows("pinned")) { r ->
            val name = r.s("name")
            val served = frames(r)
            val chain = InstanceCard.verifyChain(crypto, served)
            assertTrue(chain.complete, "$name: the served chain verifies")
            val pin = r.o("pin")
            val expect = r.o("expect")

            // The pure comparison: the pin's card0Hash, seq and hash against the served hashes.
            val hashes = served.map { SignedFrame.hash(crypto, it) }
            val compared = Checkpoints.compareCard(pin.s("card0Hash"), Checkpoint(pin.l("seq"), pin.s("hash")), hashes)
            assertEquals(expect.s("verdict"), compared.code, "$name: ${r.s("why")}")

            // follow: the same verdict, then the cards after the pin verified from it.
            val pinnedCard = chain.chain.at(pin.l("seq"))?.takeIf { it.hash == pin.s("hash") }
            val head = CardHead(
                instanceId = pinnedCard?.fields?.instanceId ?: v.s("instanceId"),
                card0Hash = pin.s("card0Hash"),
                seq = pin.l("seq"),
                hash = pin.s("hash"),
                operatorSignKey = pinnedCard?.fields?.operatorSignKey ?: keys.o("operator").s("signPubB64"),
            )
            val follow = InstanceCard.follow(crypto, head, served)
            assertEquals(expect.s("verdict"), follow.pin?.code ?: "ok", name)
            if (follow.pin == null) {
                assertNull(follow.verdict, name)
                val newest = expect.o("newest")
                assertEquals(newest.l("seq"), follow.newer.lastOrNull()?.fields?.seq ?: head.seq, name)
                assertEquals(newest.s("hash"), follow.newer.lastOrNull()?.hash ?: head.hash, name)
                // Verifying forward from the pin gives the same cards as verifying from card 0.
                assertEquals(chain.chain.cards.drop(head.seq.toInt() + 1).map { it.head }, follow.newer.map { it.head }, name)
            } else {
                assertTrue(follow.newer.isEmpty(), name)
            }
        }
    }

    @Test
    fun roots_theFirstPinInOrder() {
        val seen = HashSet<String>()
        gradeEvery("instancecard.roots", v.rows("roots")) { r ->
            val name = r.s("name")
            val result = InstanceCard.verifyChain(crypto, frames(r))
            assertTrue(result.complete, "$name: the served chain verifies")
            val chain = result.chain
            val root = r.o("root")
            // The origin the client dialed to fetch the chain: `origin_mismatch` is the first mismatch.
            val dialed = r.s("dialedOrigin")
            val verdict = when (root.s("root")) {
                "baked" -> InstanceCard.checkBakedRoot(chain, dialed, root.s("card0Hash"), root.s("instanceId"))
                "kit" -> InstanceCard.checkKitRoot(chain, dialed, root.s("card0Hash"))
                "link_offer" -> InstanceCard.checkOfferRoot(chain, dialed, root.s("cardHash"), root.s("instanceId"))
                "typed" -> InstanceCard.checkTypedRoot(chain, dialed)
                else -> error("unknown root in $name")
            }
            val expect = r.o("expect")
            assertEquals(expect.s("verdict"), verdict?.code ?: "ok", "$name: ${r.s("why")}")
            // On ok the NEWEST verified card is pinned.
            if (verdict == null) assertRecord(expect.o("pinned"), assertNotNull(chain.newest), name)
            seen += root.s("root") + ":" + expect.s("verdict")
        }
        // Every root has its origin_mismatch row and its empty chain.
        for (root in listOf("baked", "kit", "link_offer", "typed")) {
            for (verdict in listOf("ok", "origin_mismatch", "withheld")) assertTrue("$root:$verdict" in seen, "no row for $root:$verdict")
        }
    }

    @Test
    fun operatorDevice_checksItsOwnKeyOnly() {
        gradeEvery("instancecard.operatorDevice", v.rows("operatorDevice")) { r ->
            val name = r.s("name")
            // §4.1: the device is handed `self` = {userId, signPubB64}, the Ed25519 key it derives from its own identity seed.
            val self = r.oOrNull("self")
            assertTrue(self == null || "signPubB64" in self, "$name: self is not {userId, signPubB64}: this instancecard.json predates §4.1's comparison on the Ed25519 key")
            val operatorKeys = self?.let { s -> OperatorKeys { userId -> if (userId == s.s("userId")) s.b64("signPubB64") else null } }
            val result = InstanceCard.verifyChain(crypto, frames(r), operatorKeys = operatorKeys)
            val expect = r.o("expect")
            assertEquals(expect.s("verdict"), result.verdict?.code ?: "ok", "$name: ${r.s("why")}")
            if (result.verdict != null) assertEquals(expect.l("failedAt").toInt(), result.failedAt, name)
        }
    }
}
