package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.Envelope
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
 * Links v2 (design 2026-11-15 §6, derivations of §2.3, verdicts and order of §2.4), graded off
 * `links.json` from the independent oracle: the derivations, the creator fingerprint, the commitment
 * and its reveal, the comparison code, the URL, the two envelopes, and the two flows row by row
 * (the openings of a link by its recipient, the answers processed by the creating device), every row
 * of every section through [gradeEvery].
 *
 * The two flows are more than this package: the URL that does not parse, what the server answered, the
 * device's own link record and the contact list are the engine's. The small harness here does those
 * steps exactly as the vector's `_about` states them, so every verdict that IS this package's comes
 * out of the real functions ([LinkOffer.open], [InstanceCard.verifyChain], [Checkpoints.compareCard],
 * [InstanceCard.checkOfferRoot], [LinkAnswer.open], [ComparisonCode.link]) in the vector's order.
 */
class LinksVectorTest {
    private val crypto = createCryptoProvider()
    private val v = vector("links.json")
    private val accounts = v.o("accounts")
    private val cardChains: Map<String, List<ByteArray>> =
        v.o("cardChains").entries.associate { (name, frames) -> name to frames.jsonArray.strings().map(Bytes::fromB64) }

    @Test
    fun theFileHasTheSectionsThisSuiteGrades_andNoOther() {
        assertSections(
            v, "_about", "origin", "instanceId", "accounts", "link", "cardChains", "derive", "fingerprint", "commit", "reveal", "code", "typedCode",
            "url", "envelopes", "recipient", "creator",
        )
        assertSections(v.o("url"), "compose", "parse")
        assertSections(v.o("envelopes"), "seal", "open")
    }

    // ---- §2.3, §6.2 ----------------------------------------------------------------------------

    @Test
    fun derive_everyValueFromTheSecret() {
        gradeEvery("links.derive", v.rows("derive")) { r ->
            val why = r.s("why")
            // Every row is derived. The all-zero secret this table once held is refused (spec 01 "Keys in memory and the
            // lock", rule 4); keyfloor.json carries it as a must-refuse row and KeyFloorVectorTest grades it.
            val keys = Links.deriveKeys(crypto, r.b64("secretB64"))
            assertEquals(r.s("linkId"), keys.linkId, why)
            assertContentEquals(r.b64("offerKeyB64"), keys.offerKey, why)
            assertContentEquals(r.b64("answerKeyB64"), keys.answerKey, why)
            assertEquals(r.s("offerAdUtf8"), Ad.linkOffer(keys.linkId).decodeToString(), why)
            assertEquals(r.s("answerAdUtf8"), Ad.linkAnswer(keys.linkId).decodeToString(), why)
            assertEquals(r.s("registerToken"), keys.registerToken, why)
            assertEquals(r.s("tokenHash"), Links.tokenHash(crypto, keys.registerToken), why)
        }
    }

    @Test
    fun fingerprint_ofEachCreatorKey() {
        gradeEvery("links.fingerprint", v.rows("fingerprint")) { r ->
            assertEquals(r.s("f"), LinkUrl.creatorFingerprint(crypto, r.b64("identityPubB64")), r.s("why"))
        }
    }

    @Test
    fun commit_andItsReveal() {
        gradeEvery("links.commit", v.rows("commit")) { r ->
            assertEquals(r.s("commit"), CodeCommit.commit(crypto, r.b64("nonceB64")), r.s("inputUtf8"))
            assertTrue(CodeCommit.opens(crypto, r.s("nonceB64"), r.s("commit")))
        }
        gradeEvery("links.reveal", v.rows("reveal")) { r ->
            assertExpectGraded(r.o("expect"), setOf("verdict"), r.s("why"))
            val expected = r.o("expect").s("verdict")
            val verdict = if (CodeCommit.opens(crypto, r.s("revealB64"), r.s("commit"))) "ok" else LinkVerdict.BAD_REVEAL.code
            assertEquals(expected, verdict, r.s("why"))
        }
    }

    /** The code of [side] for the five inputs a `code` or `typedCode` row carries. */
    private fun codeOf(r: JsonObject, side: LinkSide): String =
        ComparisonCode.link(crypto, side, r.s("linkId"), r.s("offerHash"), r.s("answerHash"), r.b64("nonceAB64"), r.b64("nonceBB64"))

    @Test
    fun code_eachSideShowsItsOwnAndAcceptsTheOthers() {
        // §2.3, §6.11: a link has TWO codes. Under `creator` and `answerer` a row says what THAT side's app does:
        // `shows` is its own code (`inputUtf8` and `digestHex` are its derivation), `accepts` the other side's.
        gradeEvery("links.code", v.rows("code")) { r ->
            val why = r.s("why")
            for (side in LinkSide.entries) {
                val app = r.o(side.code)
                assertEquals(app.s("shows"), codeOf(r, side), "$why: what the ${side.code} shows")
                assertEquals(app.s("accepts"), codeOf(r, side.other), "$why: what the ${side.code} accepts")
                // The derivation as the row writes it: the hashed text names the side, and the six digits are its first four bytes mod 10^6.
                val digest = crypto.sha256(app.s("inputUtf8").encodeToByteArray())
                assertEquals(app.s("digestHex"), Bytes.toHexLower(digest), why)
                assertTrue(app.s("inputUtf8").startsWith("andvari/v2|link|code|${side.code}|${r.s("linkId")}|"), why)
                val u32 = digest.take(4).fold(0L) { acc, b -> (acc shl 8) or (b.toLong() and 0xFF) }
                assertEquals(app.s("shows"), (u32 % 1_000_000).toString().padStart(6, '0'), why)
                // The typed check: the app accepts what it `accepts`, and what it `shows` only when the two codes are equal.
                assertTrue(ComparisonCode.linkAccepts(crypto, side, app.s("accepts"), r.s("linkId"), r.s("offerHash"), r.s("answerHash"), r.b64("nonceAB64"), r.b64("nonceBB64")), why)
                assertEquals(
                    app.s("shows") == app.s("accepts"),
                    ComparisonCode.linkAccepts(crypto, side, app.s("shows"), r.s("linkId"), r.s("offerHash"), r.s("answerHash"), r.b64("nonceAB64"), r.b64("nonceBB64")),
                    "$why: the code on its own screen",
                )
            }
        }
    }

    @Test
    fun typedCode_isAcceptedOnlyAsTheOtherSidesCode() {
        // §6.11 "Typed input": text, with every ASCII space removed, then exactly six digits equal to the OTHER side's code.
        // A wrong code is not a verdict, so the expectation is a boolean.
        gradeEvery("links.typedCode", v.rows("typedCode")) { r ->
            val into = assertNotNull(LinkSide.fromCode(r.s("typedInto")), r.s("why"))
            val accepted = ComparisonCode.linkAccepts(
                crypto, into, r.s("typed"), r.s("linkId"), r.s("offerHash"), r.s("answerHash"), r.b64("nonceAB64"), r.b64("nonceBB64"),
            )
            assertExpectGraded(r.o("expect"), setOf("accepted"), r.s("why"))
            assertEquals(r.o("expect").bool("accepted"), accepted, r.s("why"))
            assertEquals(accepted, ComparisonCode.matches(r.s("typed"), codeOf(r, into.other)), r.s("why"))
        }
    }

    // ---- §6.1 the URL --------------------------------------------------------------------------

    @Test
    fun url_composeIsByteExact() {
        gradeEvery("links.url.compose", v.o("url").rows("compose")) { r ->
            val f = r.s("f").takeIf { it != "-" }
            assertEquals(r.s("url"), LinkUrl.compose(r.s("origin"), r.b64("secretB64"), f), r.s("why"))
        }
    }

    @Test
    fun url_parseIsTotal() {
        gradeEvery("links.url.parse", v.o("url").rows("parse")) { r ->
            val why = r.s("why")
            val expect = r.o("expect")
            val parsed = LinkUrl.parse(r.s("input"))
            if (expect.s("verdict") == "ok") {
                assertExpectGraded(expect, setOf("verdict", "origin", "secretB64", "f"), why)
                assertNotNull(parsed, why)
                assertEquals(expect.s("origin"), parsed.origin, why)
                assertContentEquals(expect.b64("secretB64"), parsed.secret, why)
                assertEquals(expect.s("f"), parsed.creatorFp ?: "-", why)
            } else {
                assertExpectGraded(expect, setOf("verdict"), why)
                assertEquals("bad_link", expect.s("verdict"), why)
                assertNull(parsed, why)
            }
        }
    }

    // ---- §6.3, §6.5 the two statements and their envelopes -------------------------------------------

    @Test
    fun theOfferAndTheAnswerOfThisFile_signToTheSameBytes() {
        val link = v.o("link")
        val alice = signerOf(crypto, accounts, "alice")
        val bob = signerOf(crypto, accounts, "bob")

        val offer = link.o("offer")
        val of = offer.o("fields")
        val offerFields = LinkOfferFields(
            of.s("linkId"), assertNotNull(LinkKind.fromLiteral(of.s("kind"))), of.s("origin"), of.s("instanceId"), of.s("cardHash"),
            of.s("from"), of.s("fromKey"), assertNotNull(TrustGrammar.decodeName(of.s("name"))), of.s("commit"), of.l("expiresAt"), of.l("issuedAt"),
        )
        val offerFrame = LinkOffer.sign(crypto, alice, offerFields)
        assertContentEquals(offer.b64("frameB64"), offerFrame)
        assertEquals(offer.s("statementUtf8"), assertIs<Checked.Ok<FrameParts>>(SignedFrame.split(offerFrame)).value.statement.decodeToString())
        assertEquals(offer.s("offerHash"), SignedFrame.hash(crypto, offerFrame))
        assertEquals(link.s("linkId"), Links.deriveKeys(crypto, link.b64("secretB64")).linkId)
        assertEquals(link.s("f"), LinkUrl.creatorFingerprint(crypto, accounts.o("alice").b64("identityPubB64")))
        assertEquals(of.s("commit"), CodeCommit.commit(crypto, link.b64("nonceAB64")))

        val answer = link.o("answer")
        val af = answer.o("fields")
        val answerFields = LinkAnswerFields(
            af.s("linkId"), af.s("offerHash"), af.s("to"), af.s("toKey"), af.s("from"), af.s("fromKey"),
            assertNotNull(TrustGrammar.decodeName(af.s("name"))), af.s("nonce"), af.l("issuedAt"),
        )
        val answerFrame = LinkAnswer.sign(crypto, bob, answerFields)
        assertContentEquals(answer.b64("frameB64"), answerFrame)
        assertEquals(answer.s("statementUtf8"), assertIs<Checked.Ok<FrameParts>>(SignedFrame.split(answerFrame)).value.statement.decodeToString())
        assertEquals(answer.s("answerHash"), SignedFrame.hash(crypto, answerFrame))
        assertEquals(offer.s("offerHash"), af.s("offerHash"))
        assertEquals(link.s("nonceBB64"), af.s("nonce"))
    }

    @Test
    fun envelopes_sealByteExactAndOpenOnlyUnderTheirKeyAndAd() {
        gradeEvery("links.envelopes.seal", v.o("envelopes").rows("seal")) { r ->
            val sealed = Envelope.sealWithNonce(crypto, r.b64("keyB64"), r.b64("nonceB64"), r.b64("plaintextB64"), r.s("adUtf8").encodeToByteArray())
            assertContentEquals(r.b64("envelopeB64"), sealed, r.s("name"))
        }
        gradeEvery("links.envelopes.open", v.o("envelopes").rows("open")) { r ->
            val opened = try {
                Envelope.open(crypto, r.b64("keyB64"), r.b64("envelopeB64"), r.s("adUtf8").encodeToByteArray())
                true
            } catch (e: CryptoException) {
                false
            }
            assertExpectGraded(r.o("expect"), setOf("opens"), r.s("name"))
            assertEquals(r.o("expect").bool("opens"), opened, r.s("name"))
        }
    }

    // ---- §6.8 opening a link -----------------------------------------------------------------------

    private sealed class Opening {
        class Refused(val verdict: String) : Opening()
        /** [pinRoot] is the root the origin's pin has after this opening, where this harness knows it: `baked` at the baked origin. */
        class Ok(val offer: OpenedOffer, val pinned: VerifiedCard?, val keyChanged: Boolean, val pinRoot: String?) : Opening()
    }

    /** The values of a pin's `root` and of `expect.pinRoot`: passwordgate.json's roots (§4.4). */
    private val roots = setOf("baked", "kit", "setup", "trust_gate", "link_offer", "enrol")

    /** §6.8 as the recipient's device runs it; the first failure is the verdict. */
    private fun open(r: JsonObject): Opening {
        // 1. The link text.
        val link = LinkUrl.parse(r.s("link")) ?: return Opening.Refused("bad_link")
        // 2. What GET /links/{linkId} answered: the engine's names for the server's refusals.
        val server = r.o("server")
        when (server.l("status")) {
            404L -> return Opening.Refused("link_unknown")
            410L -> return Opening.Refused("link_expired")
        }
        val body = server.o("body")
        if (body.s("state") == "answered") return Opening.Refused("link_used")
        // 3, 4. The offer: the envelope, the form, the parse, the helper's checks, the fields.
        val served = ServedLink(body.s("kind"), body.sOrNull("creatorUserId"), body.sOrNull("creatorIdentityPub"))
        val offer = when (val o = LinkOffer.open(crypto, link, body.b64("offer"), served, r.l("now"))) {
            is Checked.Refused -> return Opening.Refused(o.verdict.code)
            is Checked.Ok -> o.value
        }
        // 5. The card chain the origin serves. A pin this device already holds is compared first and
        //    is never replaced by a root (§4.4 "Rules for the pin store"); then the step for the kind (§6.8 step 5).
        val chain = InstanceCard.verifyChain(crypto, cardChains.getValue(r.s("cards")))
        assertTrue(chain.complete, r.s("name") + ": the served chain verifies")
        val pin = r.oOrNull("pin")
        if (pin != null) {
            assertInputsKnown(pin, setOf("card0Hash", "seq", "hash", "root"), r.s("name") + ": pin")
            // The held pin's root, when the row names one (else this harness's default: none known). It
            // changes no verdict: the chain is compared with the pin whatever its root.
            pin.sOrNull("root")?.let { assertTrue(it in roots, "${r.s("name")}: pin.root $it") }
            val held = Checkpoint(pin.l("seq"), pin.s("hash"))
            when (Checkpoints.compareCard(pin.s("card0Hash"), held, chain.chain.cards.map { it.hash })) {
                CheckpointVerdict.OK -> Unit
                CheckpointVerdict.FORK -> return Opening.Refused(PinVerdict.FORK.code)
                else -> return Opening.Refused(PinVerdict.WITHHELD.code)
            }
        }
        // What this build bakes (PUBLIC_INSTANCE), on the rows that carry it. It has a say only for a link
        // to the baked origin; a link to any other origin reads the same on every build (§4.4).
        val baked = r.oOrNull("baked")?.takeIf { it.s("origin") == link.origin }
        if (baked != null) {
            // "At the baked origin the baked root always comes first", whatever the kind of link: withheld
            // for an empty chain, origin_mismatch, card0_mismatch, instance_mismatch, in that order. The pin's
            // root is `baked`, and no Trust Gate shows. Then what the link adds on top.
            InstanceCard.checkBakedRoot(chain.chain, link.origin, baked.s("card0Hash"), baked.s("instanceId"))?.let { return Opening.Refused(it.code) }
            when (offer.kind) {
                // Refused: a build that bakes an instance never signs that instance's card 0. An empty chain
                // was `withheld` under the baked root just above; a served one is already set up.
                LinkKind.SETUP -> return Opening.Refused("already_set_up")
                // Nothing more. A pin held under another root (a Trust Gate's) is raised to `baked` (§4.4).
                LinkKind.ENROL -> return Opening.Ok(offer, null, false, "baked")
                // The offer's own card check follows, below.
                LinkKind.CONNECT, LinkKind.REGISTER -> Unit
            }
        } else {
            when (offer.kind) {
                // Setup: the instance must serve no card yet; one that does is already set up (§2.4 "Small cases").
                LinkKind.SETUP -> return if (chain.chain.cards.isEmpty()) Opening.Ok(offer, null, false, null) else Opening.Refused("already_set_up")
                // Enrol is no root of its own: the typed-address root, after which the Trust Gate shows (§4.4, U3).
                LinkKind.ENROL -> {
                    InstanceCard.checkTypedRoot(chain.chain, link.origin)?.let { return Opening.Refused(it.code) }
                    return Opening.Ok(offer, null, false, null)
                }
                LinkKind.CONNECT, LinkKind.REGISTER -> Unit
            }
        }
        offer as OpenedOffer.Signed
        InstanceCard.checkOfferRoot(chain.chain, link.origin, offer.fields.cardHash, offer.fields.instanceId)?.let { return Opening.Refused(it.code) }
        // 6. The key_changed prompt: a known contact under another key. A prompt, never a verdict.
        val known = r.o("contacts").sOrNull(offer.fields.from)
        return Opening.Ok(offer, chain.chain.newest, known != null && known != offer.fields.fromKey, if (baked != null) "baked" else null)
    }

    @Test
    fun recipient_everyRowGetsItsExactVerdict() {
        val rows = v.rows("recipient")
        val seen = HashSet<String>()
        val inputs = setOf("name", "why", "link", "server", "now", "cards", "pin", "baked", "contacts", "expect")
        gradeEvery("links.recipient", rows) { r ->
            val name = r.s("name")
            val expect = r.o("expect")
            assertInputsKnown(r, inputs, name)
            val graded = mutableSetOf("verdict")
            when (val result = open(r)) {
                is Opening.Refused -> assertEquals(expect.s("verdict"), result.verdict, name)
                is Opening.Ok -> {
                    assertEquals(expect.s("verdict"), "ok", name)
                    assertEquals(expect.s("kind"), result.offer.kind.literal, name)
                    graded += "kind"
                    val offer = result.offer
                    if (offer is OpenedOffer.Signed) {
                        assertEquals(expect.s("from"), offer.fields.from, name)
                        assertEquals(expect.s("fromKey"), offer.fields.fromKey, name)
                        assertEquals(expect.s("name"), TrustGrammar.encodeName(offer.fields.name), name)
                        assertEquals(expect.s("offerHash"), offer.offerHash, name)
                        val pinned = assertNotNull(result.pinned, name)
                        assertEquals(expect.o("pinned").l("seq"), pinned.fields.seq, name)
                        assertEquals(expect.o("pinned").s("hash"), pinned.hash, name)
                        assertEquals(expect.bool("keyChanged"), result.keyChanged, name)
                        graded += setOf("from", "fromKey", "name", "offerHash", "pinned", "keyChanged")
                    }
                    // The pin's root after the opening, where this harness knows it (the baked origin):
                    // a row that names one gets it, and a row this harness computes one for must name it.
                    if (result.pinRoot != null || "pinRoot" in expect) {
                        assertEquals(expect.sOrNull("pinRoot"), result.pinRoot, "$name: the pin's root")
                        graded += "pinRoot"
                    }
                }
            }
            // A host offer pins no card and names no contact: its rows carry nothing else.
            assertExpectGraded(expect, graded, name)
            seen += expect.s("verdict")
        }
        // Every verdict of §2.4's "Opening a link" row that a recipient can meet is in the corpus.
        val named = listOf(
            "bad_link", "link_unknown", "link_expired", "link_used", "unopenable", "unknown_format", "kind_mismatch", "bad_frame",
            "non_canonical", "bad_statement", "creator_mismatch", "signer_not_pinned_key", "bad_signature", "link_mismatch",
            "origin_mismatch", "offer_expired", "reported_creator_mismatch", "card0_mismatch", "card_not_in_chain", "instance_mismatch", "fork",
            "withheld", "already_set_up", "ok",
        )
        for (verdict in named) assertTrue(verdict in seen, "no row for $verdict")
        // The baked rule is graded too: some row opens a link on a build that bakes an instance.
        assertTrue(rows.any { it.oOrNull("baked") != null }, "no row for a link on a build that bakes an instance")
    }

    // ---- §6.8 processing an answer -----------------------------------------------------------------

    private sealed class Processing {
        class Refused(val verdict: String) : Processing()

        /** [shows] is the creator code, on this device's screen; [accepts] the answerer code, the only typed input it takes. */
        class Ok(val answer: OpenedAnswer, val shows: String, val accepts: String, val keyChanged: Boolean) : Processing()
    }

    /** §6.8 as the creating device runs it. */
    private fun process(r: JsonObject): Processing {
        val me = accounts.o(r.s("me"))
        val served = r.o("served")
        // The device's own record of the link: none, or one past its expiry (T-R3), and the answer is ignored.
        val record = r.o("records").oOrNull(served.s("linkId")) ?: return Processing.Refused(LinkVerdict.UNKNOWN_LINK.code)
        if (r.l("now") >= record.l("expiresAt")) return Processing.Refused(LinkVerdict.UNKNOWN_LINK.code)
        val secret = record.b64("secretB64")
        val opened = LinkAnswer.open(crypto, secret, record.s("offerHash"), me.s("userId"), me.b64("identityPubB64"), served.b64("answer"), served.s("answererUserId"))
        val answer = when (opened) {
            is Checked.Refused -> return Processing.Refused(opened.verdict.code)
            is Checked.Ok -> opened.value
        }
        val linkId = Links.deriveKeys(crypto, secret).linkId
        assertEquals(served.s("linkId"), linkId, r.s("name"))
        // The creating device's two codes (§2.3, §6.11): it shows the creator's and accepts the answerer's.
        fun code(side: LinkSide) =
            ComparisonCode.link(crypto, side, linkId, record.s("offerHash"), answer.answerHash, record.b64("nonceAB64"), Bytes.fromB64(answer.fields.nonce))
        val known = r.o("contacts").sOrNull(answer.fields.from)
        return Processing.Ok(answer, code(LinkSide.CREATOR), code(LinkSide.CREATOR.other), known != null && known != answer.fields.fromKey)
    }

    @Test
    fun creator_everyRowGetsItsExactVerdict() {
        val rows = v.rows("creator")
        val seen = HashSet<String>()
        val inputs = setOf("name", "why", "me", "served", "records", "now", "contacts", "expect")
        gradeEvery("links.creator", rows) { r ->
            val name = r.s("name")
            val expect = r.o("expect")
            assertInputsKnown(r, inputs, name)
            when (val result = process(r)) {
                is Processing.Refused -> {
                    assertEquals(expect.s("verdict"), result.verdict, name)
                    assertExpectGraded(expect, setOf("verdict"), name)
                }
                is Processing.Ok -> {
                    assertExpectGraded(expect, setOf("verdict", "from", "fromKey", "name", "answerHash", "code", "keyChanged"), name)
                    assertExpectGraded(expect.o("code"), setOf("shows", "accepts"), "$name: code")
                    assertEquals(expect.s("verdict"), "ok", name)
                    assertEquals(expect.s("from"), result.answer.fields.from, name)
                    assertEquals(expect.s("fromKey"), result.answer.fields.fromKey, name)
                    assertEquals(expect.s("name"), TrustGrammar.encodeName(result.answer.fields.name), name)
                    assertEquals(expect.s("answerHash"), result.answer.answerHash, name)
                    assertEquals(expect.o("code").s("shows"), result.shows, "$name: the code on this device's screen")
                    assertEquals(expect.o("code").s("accepts"), result.accepts, "$name: the only typed input it accepts")
                    assertEquals(expect.bool("keyChanged"), result.keyChanged, name)
                }
            }
            seen += expect.s("verdict")
        }
        val named = listOf(
            "unknown_link", "unopenable", "unknown_format", "bad_frame", "non_canonical", "bad_statement", "signer_not_pinned_key",
            "bad_signature", "link_mismatch", "offer_mismatch", "misaddressed", "reported_answerer_mismatch", "ok",
        )
        for (verdict in named) assertTrue(verdict in seen, "no row for $verdict")
    }
}
