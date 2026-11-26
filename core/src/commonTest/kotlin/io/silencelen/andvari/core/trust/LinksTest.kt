package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Hkdf
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Links v2 (design 2026-11-15 §6): the URL, the derivations, offers and answers with their envelopes,
 * and the committed comparison code, with every verdict of §2.4's "Opening a link" and "Processing an
 * answer" rows in order. Built from the design's rules; `links.json` grades the same code once its
 * vector file lands.
 */
class LinksTest {
    private val crypto = createCryptoProvider()
    private val alice = Party(crypto, Ids.ALICE, 1)
    private val bob = Party(crypto, Ids.BOB, 2)
    private val mallory = Party(crypto, Ids.DAVE, 4)
    private val origin = "https://vault.example.org"
    private val secret = ByteArray(32) { (0x11 + it).toByte() }
    private val keys = Links.deriveKeys(crypto, secret)
    private val now = Ids.T0
    private val cardHash = "ab".repeat(32)
    private val nonceA = ByteArray(32) { (0x70 + it).toByte() }
    private val nonceB = ByteArray(32) { (0x30 + it).toByte() }

    private fun offer(
        linkId: String = keys.linkId,
        kind: LinkKind = LinkKind.CONNECT,
        offerOrigin: String = origin,
        from: Party = alice,
        fromKey: String = from.key,
        expiresAt: Long = now + 600_000,
    ) = LinkOfferFields(linkId, kind, offerOrigin, Ids.INSTANCE, cardHash, from.userId, fromKey, "Alice", CodeCommit.commit(crypto, nonceA), expiresAt, now)

    private fun link(creator: Party? = alice): ParsedLink =
        assertNotNull(LinkUrl.parse(assertNotNull(LinkUrl.compose(origin, secret, creator?.let { LinkUrl.creatorFingerprint(crypto, it.box.publicKey) }))))

    private fun served(kind: String = "connect", creator: Party? = alice) = ServedLink(kind, creator?.userId, creator?.key)

    private fun verdict(envelope: ByteArray, link: ParsedLink = link(), served: ServedLink = served(), nowMs: Long = now): LinkVerdict =
        assertIs<Checked.Refused<LinkVerdict>>(LinkOffer.open(crypto, link, envelope, served, nowMs)).verdict

    private fun sealed(frameOrJson: ByteArray) = LinkOffer.seal(crypto, keys, frameOrJson)

    /** The statement of [frame], signed again by [by]: a forgery that names a key its signer does not hold. No builder makes one. */
    private fun resign(frame: ByteArray, by: Party, purpose: TrustPurpose): ByteArray =
        SignedFrame.sign(crypto, by.sign, purpose, assertIs<Checked.Ok<FrameParts>>(SignedFrame.split(frame)).value.statement)

    // ---- §6.1 the URL ------------------------------------------------------------------------------

    @Test
    fun url_composesAndParsesBothForms() {
        val f = LinkUrl.creatorFingerprint(crypto, alice.box.publicKey)
        assertEquals(22, f.length)
        assertEquals(Bytes.toB64(crypto.sha256(alice.box.publicKey).copyOf(16)), f)

        val url = assertNotNull(LinkUrl.compose(origin, secret, f))
        assertEquals("https://andvaripass.com/l#v2." + Bytes.toB64(origin.encodeToByteArray()) + "." + Bytes.toB64(secret) + "." + f, url)
        for (input in listOf(url, url.substringAfter('#'), "#" + url.substringAfter('#'), url.chunked(20).joinToString("\n "), "\t$url\r\n", "https://evil.example/whatever#" + url.substringAfter('#'))) {
            val parsed = assertNotNull(LinkUrl.parse(input), input)
            assertEquals(origin, parsed.origin)
            assertContentEquals(secret, parsed.secret)
            assertEquals(f, parsed.creatorFp)
        }
        // A host-minted link carries "-" and no fingerprint.
        val host = assertNotNull(LinkUrl.compose(origin, secret, null))
        assertTrue(host.endsWith(".-"))
        assertNull(assertNotNull(LinkUrl.parse(host)).creatorFp)
    }

    @Test
    fun url_parseIsTotalAndStrict() {
        val o = Bytes.toB64(origin.encodeToByteArray())
        val s = Bytes.toB64(secret)
        val f = LinkUrl.creatorFingerprint(crypto, alice.box.publicKey)
        val bad = listOf(
            "", "#", "v2", "https://andvaripass.com/l", "v2.$o.$s", "v2.$o.$s.$f.extra", "v1.$o.$s.$f", "V2.$o.$s.$f",
            "v2.$o=.$s.$f", // padding
            "v2.${Bytes.toB64("https://Vault.example.org".encodeToByteArray())}.$s.$f", // uppercase host
            "v2.${Bytes.toB64("http://192.168.1.9:8080".encodeToByteArray())}.$s.$f", // not in the origin grammar
            "v2.${Bytes.toB64("$origin/".encodeToByteArray())}.$s.$f", // a path
            "v2.$o.${Bytes.toB64(ByteArray(31))}.$f", "v2.$o.${Bytes.toB64(ByteArray(33))}.$f",
            "v2.$o.$s.${Bytes.toB64(ByteArray(15))}", "v2.$o.$s.${Bytes.toB64(ByteArray(17))}", "v2.$o.$s.", "v2.$o.$s.--",
            "v2.$o.${s.dropLast(1)}B.$f", // non-zero trailing bits: not canonical
            "v2.$o.$s.$f#again",
        )
        for (input in bad) assertNull(LinkUrl.parse(input), input)
        // At most 512 characters after the white space is gone. The longest origin of the grammar (a
        // 253-character host and port 65535) still makes a link of 452, so only what stands before
        // the `#` can push a well-formed link over the cap.
        val longest = "https://" + listOf("a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(61)).joinToString(".") + ":65535"
        assertTrue(TrustGrammar.isOrigin(longest))
        val longestUrl = assertNotNull(LinkUrl.compose(longest, secret, f))
        assertEquals(452, longestUrl.length)
        assertEquals(longest, assertNotNull(LinkUrl.parse(longestUrl)).origin)
        val fragment = "#v2.$o.$s.$f"
        val at512 = "https://andvaripass.com/" + "p".repeat(512 - 24 - fragment.length) + fragment
        assertEquals(512, at512.length)
        assertNotNull(LinkUrl.parse(at512), "exactly 512")
        assertNull(LinkUrl.parse(at512.replaceFirst("/p", "/pp")), "513")
        assertNotNull(LinkUrl.parse(at512.chunked(64).joinToString("\n")), "the length is taken after the white space is stripped")
        assertNotNull(LinkUrl.parse("  " + " ".repeat(600) + "v2.$o.$s.$f"), "white space does not count")
        assertNull(LinkUrl.compose("http://192.168.1.9", secret, f))
        assertNull(LinkUrl.compose(origin, ByteArray(31), f))
        assertNull(LinkUrl.compose(origin, secret, "short"))
    }

    // ---- §6.2 derivations --------------------------------------------------------------------------

    @Test
    fun derivations_followTheDomainStrings() {
        fun hkdf(info: String, n: Int) = Hkdf.sha256(crypto, secret, ByteArray(0), info.encodeToByteArray(), n)
        assertEquals(Bytes.toB64(hkdf("andvari/v2|link|id", 16)), keys.linkId)
        assertContentEquals(hkdf("andvari/v2|link|offer", 32), keys.offerKey)
        assertContentEquals(hkdf("andvari/v2|link|answer", 32), keys.answerKey)
        assertEquals(Bytes.toB64(hkdf("andvari/v2|link|register", 32)), keys.registerToken)
        assertEquals(43, keys.registerToken.length)
        // What the server stores: SHA-256 over the 43 ASCII characters of the token, as base64url.
        assertEquals(Bytes.toB64(crypto.sha256(keys.registerToken.encodeToByteArray())), Links.tokenHash(crypto, keys.registerToken))
        assertNotEquals(keys.linkId, Links.deriveKeys(crypto, ByteArray(32) { 9 }).linkId)
        assertFailsWith<IllegalArgumentException> { Links.deriveKeys(crypto, ByteArray(31)) }
    }

    // ---- §6.11 the committed code ------------------------------------------------------------------

    @Test
    fun commitment_opensOnlyForItsNonce() {
        val commit = CodeCommit.commit(crypto, nonceA)
        assertEquals(Bytes.toHexLower(crypto.sha256(("andvari/v2|code-commit|" + Bytes.toB64(nonceA)).encodeToByteArray())), commit)
        assertTrue(CodeCommit.opens(crypto, nonceA, commit))
        assertTrue(CodeCommit.opens(crypto, Bytes.toB64(nonceA), commit))
        assertTrue(!CodeCommit.opens(crypto, nonceB, commit), "bad_reveal")
        assertTrue(!CodeCommit.opens(crypto, nonceA.copyOf(31), commit))
        assertTrue(!CodeCommit.opens(crypto, Bytes.toB64(nonceA) + "=", commit))
        assertTrue(!CodeCommit.opens(crypto, "not base64", commit))
        assertFailsWith<IllegalArgumentException> { CodeCommit.commit(crypto, ByteArray(16)) }
    }

    /** §2.3's link comparison code, spelled out from the design text with no andvari code beyond SHA-256. */
    private fun formulaCode(side: String, linkId: String, offerHash: String, answerHash: String, nA: ByteArray, nB: ByteArray): String {
        val d = crypto.sha256("andvari/v2|link|code|$side|$linkId|$offerHash|$answerHash|${Bytes.toB64(nA)}|${Bytes.toB64(nB)}".encodeToByteArray())
        val u32 = ((d[0].toLong() and 0xFF) shl 24) or ((d[1].toLong() and 0xFF) shl 16) or ((d[2].toLong() and 0xFF) shl 8) or (d[3].toLong() and 0xFF)
        return (u32 % 1_000_000).toString().padStart(6, '0')
    }

    @Test
    fun comparisonCode_creatorSide_isTheFormulaWithTheCreatorLiteral() {
        val offerHash = "11".repeat(32)
        val answerHash = "22".repeat(32)
        val code = ComparisonCode.link(crypto, LinkSide.CREATOR, keys.linkId, offerHash, answerHash, nonceA, nonceB)
        assertTrue(code.length == 6 && code.all { it in '0'..'9' })
        assertEquals(formulaCode("creator", keys.linkId, offerHash, answerHash, nonceA, nonceB), code)
        assertEquals("creator", LinkSide.CREATOR.code)
    }

    @Test
    fun comparisonCode_answererSide_isTheFormulaWithTheAnswererLiteral() {
        val offerHash = "11".repeat(32)
        val answerHash = "22".repeat(32)
        val code = ComparisonCode.link(crypto, LinkSide.ANSWERER, keys.linkId, offerHash, answerHash, nonceA, nonceB)
        assertTrue(code.length == 6 && code.all { it in '0'..'9' })
        assertEquals(formulaCode("answerer", keys.linkId, offerHash, answerHash, nonceA, nonceB), code)
        assertEquals("answerer", LinkSide.ANSWERER.code)
        // Each side types the other's code.
        assertEquals(LinkSide.CREATOR, LinkSide.ANSWERER.other)
        assertEquals(LinkSide.ANSWERER, LinkSide.CREATOR.other)
        assertEquals(LinkSide.ANSWERER, LinkSide.fromCode("answerer"))
        assertNull(LinkSide.fromCode("Answerer"))
        // These fixed inputs give two different codes, so neither screen shows the digits its own person types.
        assertNotEquals(ComparisonCode.link(crypto, LinkSide.CREATOR, keys.linkId, offerHash, answerHash, nonceA, nonceB), code)
    }

    @Test
    fun comparisonCode_isSixDigitsAndMovesWithEveryInput() {
        val offerHash = "11".repeat(32)
        val answerHash = "22".repeat(32)
        for (side in LinkSide.entries) {
            val code = ComparisonCode.link(crypto, side, keys.linkId, offerHash, answerHash, nonceA, nonceB)
            assertTrue(code.length == 6 && code.all { it in '0'..'9' })
            val others = listOf(
                ComparisonCode.link(crypto, side.other, keys.linkId, offerHash, answerHash, nonceA, nonceB),
                ComparisonCode.link(crypto, side, Ids.id16(3), offerHash, answerHash, nonceA, nonceB),
                ComparisonCode.link(crypto, side, keys.linkId, "33".repeat(32), answerHash, nonceA, nonceB),
                ComparisonCode.link(crypto, side, keys.linkId, offerHash, "33".repeat(32), nonceA, nonceB),
                ComparisonCode.link(crypto, side, keys.linkId, offerHash, answerHash, nonceB, nonceB),
                ComparisonCode.link(crypto, side, keys.linkId, offerHash, answerHash, nonceA, nonceA),
                ComparisonCode.link(crypto, side, keys.linkId, offerHash, answerHash, nonceB, nonceA), // the two nonces are not interchangeable
            )
            assertTrue(others.count { it != code } >= others.size - 1, "a six-digit code may collide once by chance, not across the board")
        }
        val code = ComparisonCode.link(crypto, LinkSide.CREATOR, keys.linkId, offerHash, answerHash, nonceA, nonceB)

        // There is no "they match" button: only the typed digits count.
        assertTrue(ComparisonCode.matches(code, code))
        assertTrue(!ComparisonCode.matches(code.dropLast(1), code))
        assertTrue(!ComparisonCode.matches(code + "0", code))
        assertTrue(!ComparisonCode.matches(code.reversed().takeIf { it != code } ?: "000000".takeIf { it != code } ?: "111111", code))
        assertTrue(!ComparisonCode.matches("", code))
    }

    @Test
    fun aTypedCode_isComparedAsText_withOnlySpacesRemoved() {
        // §6.11 "Typed input": every ASCII space is removed (a code is shown as `481 207`); nothing else is normalised.
        assertTrue(ComparisonCode.matches("481207", "481207"))
        assertTrue(ComparisonCode.matches("481 207", "481207"))
        assertTrue(ComparisonCode.matches("  4 8 1   2 0 7 ", "481207"))
        // Other kinds of space, by code point so that the source shows them: no-break, thin, ideographic, zero-width.
        val otherSpaces = listOf(0xA0, 0x2009, 0x3000, 0x200B).map { "481" + it.toChar() + "207" }
        for (other in listOf("481\t207", "481207\n", "481207\r\n", "\n481207", "481-207", "481.207", "481207x", "+481207", "４８１２０７") + otherSpaces) {
            assertTrue(!ComparisonCode.matches(other, "481207"), "any character but a space is a mismatch: ${other.map { it.code }}")
        }
        // A dropped leading zero is a mismatch, and so is a number that is merely equal.
        assertTrue(ComparisonCode.matches("008097", "008097"))
        assertTrue(ComparisonCode.matches("008 097", "008097"))
        assertTrue(!ComparisonCode.matches("8097", "008097"))
        assertTrue(!ComparisonCode.matches("08097", "008097"))
        assertTrue(!ComparisonCode.matches("0008097", "008097"))
        assertTrue(!ComparisonCode.matches("", "000000"))
        assertTrue(!ComparisonCode.matches("      ", "000000"))
        // A held code that is not six digits accepts nothing.
        assertTrue(!ComparisonCode.matches("48120", "48120"))
    }

    @Test
    fun eachSideOfALink_acceptsOnlyTheOtherSidesCode() {
        val keys = Links.deriveKeys(crypto, ByteArray(32) { 5 })
        val offerHash = "11".repeat(32)
        val answerHash = "22".repeat(32)
        val nonceA = ByteArray(32) { 6 }
        fun codes(nonceB: ByteArray) = LinkSide.entries.associateWith { ComparisonCode.link(crypto, it, keys.linkId, offerHash, answerHash, nonceA, nonceB) }
        fun accepts(into: LinkSide, typed: String, nonceB: ByteArray) =
            ComparisonCode.linkAccepts(crypto, into, typed, keys.linkId, offerHash, answerHash, nonceA, nonceB)

        // Two different codes: each app accepts the other side's, and not the one on its own screen.
        var n = 0
        var nonceB = ByteArray(32) { 7 }
        while (codes(nonceB).values.toSet().size != 2) nonceB = ByteArray(32) { (8 + n++).toByte() }
        val differ = codes(nonceB)
        for (side in LinkSide.entries) {
            assertTrue(accepts(side, differ.getValue(side.other), nonceB))
            assertTrue(accepts(side, differ.getValue(side.other).let { it.take(3) + " " + it.drop(3) }, nonceB))
            assertTrue(!accepts(side, differ.getValue(side), nonceB), "the code on its own screen is not the one it accepts")
        }
    }

    // ---- §6.3, §6.8 a signed offer -----------------------------------------------------------------

    @Test
    fun aConnectOfferOpensForItsRecipient() {
        val frame = LinkOffer.sign(crypto, alice.sign, offer())
        val opened = assertIs<Checked.Ok<OpenedOffer>>(LinkOffer.open(crypto, link(), sealed(frame), served(), now)).value
        val signedOffer = assertIs<OpenedOffer.Signed>(opened)
        assertEquals(offer(), signedOffer.fields)
        assertEquals(SignedFrame.hash(crypto, frame), signedOffer.offerHash)
        assertEquals(LinkKind.CONNECT, opened.kind)
        assertEquals(origin, opened.origin)
        // A register offer is the same statement with another kind, and the server must report that kind.
        val register = LinkOffer.sign(crypto, alice.sign, offer(kind = LinkKind.REGISTER))
        assertIs<Checked.Ok<OpenedOffer>>(LinkOffer.open(crypto, link(), sealed(register), served("register"), now))
    }

    @Test
    fun offer_eachCheckHasItsVerdict() {
        val good = LinkOffer.sign(crypto, alice.sign, offer())
        val statement = assertIs<Checked.Ok<FrameParts>>(SignedFrame.split(good)).value.statement.decodeToString()
        fun signedRaw(text: String) = SignedFrame.sign(crypto, alice.sign, TrustPurpose.LINK_OFFER, text.encodeToByteArray())

        // The envelope: another link's key, a tampered byte, or this key under another link's AD.
        val otherKeys = Links.deriveKeys(crypto, ByteArray(32) { 5 })
        assertEquals(LinkVerdict.UNOPENABLE, verdict(LinkOffer.seal(crypto, otherKeys, good)))
        assertEquals(LinkVerdict.UNOPENABLE, verdict(sealed(good).also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }))
        assertEquals(LinkVerdict.UNOPENABLE, verdict(Envelope.seal(crypto, keys.offerKey, good, Ad.linkOffer(otherKeys.linkId))), "the AD binds the link id")
        assertEquals(LinkVerdict.UNOPENABLE, verdict(Envelope.seal(crypto, keys.offerKey, good, Ad.linkAnswer(keys.linkId))), "an answer envelope is not an offer")
        assertEquals(LinkVerdict.UNOPENABLE, verdict(ByteArray(5)))

        // Neither a frame nor host JSON.
        assertEquals(LinkVerdict.UNKNOWN_FORMAT, verdict(sealed("hello".encodeToByteArray())))
        assertEquals(LinkVerdict.UNKNOWN_FORMAT, verdict(sealed(ByteArray(0))))

        // kind_mismatch from the form alone: a signed frame where the server reported a host-minted kind.
        assertEquals(LinkVerdict.KIND_MISMATCH, verdict(sealed(good), served = served("setup")))
        assertEquals(LinkVerdict.KIND_MISMATCH, verdict(sealed(good), served = served("enrol")))
        assertEquals(LinkVerdict.KIND_MISMATCH, verdict(sealed(good), served = served("nonsense")))

        // The parse.
        val answerFrame = SignedFrame.sign(crypto, alice.sign, TrustPurpose.LINK_ANSWER, statement.encodeToByteArray())
        assertEquals(LinkVerdict.BAD_FRAME, verdict(sealed(answerFrame)), "a frame of another purpose")
        assertEquals(LinkVerdict.BAD_FRAME, verdict(sealed(good.copyOf(60))), "truncated")
        assertEquals(LinkVerdict.NON_CANONICAL, verdict(sealed(signedRaw(statement.replace("\"v\":2", "\"v\": 2")))))
        assertEquals(LinkVerdict.NON_CANONICAL, verdict(sealed(signedRaw(statement.replace("\"connect\"", "\"setup\"")))), "the listed kinds are a type")
        assertEquals(LinkVerdict.BAD_STATEMENT, verdict(sealed(signedRaw(statement.replace("\"v\":2", "\"v\":3")))))

        // kind_mismatch from the statement's own kind, right after the parse.
        assertEquals(LinkVerdict.KIND_MISMATCH, verdict(sealed(good), served = served("register")))

        // The link's F: another creator's fingerprint, or none at all.
        assertEquals(LinkVerdict.CREATOR_MISMATCH, verdict(sealed(good), link = link(mallory)))
        assertEquals(LinkVerdict.CREATOR_MISMATCH, verdict(sealed(good), link = link(null)))

        // The signer is handed fromKey once it passed F: mallory signs a statement that names alice's key.
        val forged = resign(LinkOffer.sign(crypto, alice.sign, offer()), mallory, TrustPurpose.LINK_OFFER)
        assertEquals(LinkVerdict.SIGNER_NOT_PINNED_KEY, verdict(sealed(forged)))
        assertEquals(LinkVerdict.BAD_SIGNATURE, verdict(sealed(good.copyOf().also { it[70] = (it[70].toInt() xor 2).toByte() })))

        // The field checks.
        assertEquals(LinkVerdict.LINK_MISMATCH, verdict(sealed(LinkOffer.sign(crypto, alice.sign, offer(linkId = Ids.id16(8))))))
        assertEquals(LinkVerdict.ORIGIN_MISMATCH, verdict(sealed(LinkOffer.sign(crypto, alice.sign, offer(offerOrigin = "https://other.example.org")))))
        assertEquals(LinkVerdict.OFFER_EXPIRED, verdict(sealed(LinkOffer.sign(crypto, alice.sign, offer(expiresAt = now)))), "expiresAt must be after now")
        assertEquals(LinkVerdict.OFFER_EXPIRED, verdict(sealed(good), nowMs = now + 600_000))
        assertEquals(LinkVerdict.REPORTED_CREATOR_MISMATCH, verdict(sealed(good), served = ServedLink("connect", Ids.BOB, alice.key)))
        assertEquals(LinkVerdict.REPORTED_CREATOR_MISMATCH, verdict(sealed(good), served = ServedLink("connect", Ids.ALICE, bob.key)))
        assertEquals(LinkVerdict.REPORTED_CREATOR_MISMATCH, verdict(sealed(good), served = ServedLink("connect", null, null)))
        assertEquals(LinkVerdict.REPORTED_CREATOR_MISMATCH, verdict(sealed(good), served = ServedLink("connect", Ids.ALICE, "not base64")))
    }

    @Test
    fun offer_theHelperChecksComeBeforeTheFieldChecks() {
        // Expired, for another origin, under another link id AND forged: the signer verdict comes first (VR-14).
        val everythingWrong = resign(LinkOffer.sign(crypto, alice.sign, offer(linkId = Ids.id16(8), offerOrigin = "https://other.example.org", expiresAt = 1)), mallory, TrustPurpose.LINK_OFFER)
        assertEquals(LinkVerdict.SIGNER_NOT_PINNED_KEY, verdict(sealed(everythingWrong)))
        // F before the signer: mallory's own offer through alice's link.
        val mallorys = LinkOffer.sign(crypto, mallory.sign, offer(from = mallory, expiresAt = 1))
        assertEquals(LinkVerdict.CREATOR_MISMATCH, verdict(sealed(mallorys)))
        // The statement's kind before F.
        assertEquals(LinkVerdict.KIND_MISMATCH, verdict(sealed(mallorys), served = served("register")))
        // Then the fields in their order: link, origin, expiry, the reported creator.
        val fields = LinkOffer.sign(crypto, alice.sign, offer(linkId = Ids.id16(8), offerOrigin = "https://other.example.org", expiresAt = 1))
        assertEquals(LinkVerdict.LINK_MISMATCH, verdict(sealed(fields), served = served(creator = bob)))
        val originAndLater = LinkOffer.sign(crypto, alice.sign, offer(offerOrigin = "https://other.example.org", expiresAt = 1))
        assertEquals(LinkVerdict.ORIGIN_MISMATCH, verdict(sealed(originAndLater), served = served(creator = bob)))
        val expiredAndReported = LinkOffer.sign(crypto, alice.sign, offer(expiresAt = 1))
        assertEquals(LinkVerdict.OFFER_EXPIRED, verdict(sealed(expiredAndReported), served = served(creator = bob)))
    }

    @Test
    fun offer_buildersRefuseWhatTheRecipientWouldRefuse() {
        assertFailsWith<IllegalArgumentException> { LinkOffer.sign(crypto, mallory.sign, offer()) } // not the fromKey's holder
        assertFailsWith<IllegalArgumentException> { LinkOffer.sign(crypto, alice.sign, offer(kind = LinkKind.SETUP)) }
        assertFailsWith<IllegalArgumentException> { LinkOffer.sign(crypto, alice.sign, offer().copy(name = "")) }
        assertFailsWith<IllegalArgumentException> { LinkOffer.sign(crypto, alice.sign, offer(offerOrigin = "http://10.0.0.1")) }
        assertFailsWith<IllegalArgumentException> { LinkOffer.seal(crypto, keys, ByteArray(2100)) } // over 2 KiB
    }

    // ---- §6.4 host-minted offers -------------------------------------------------------------------

    @Test
    fun hostOffers_openOnlyThroughAHostMintedLink() {
        val setup = SetupOfferFields(keys.linkId, origin, Ids.INSTANCE, "Family vault", InstanceKind.PRIVATE, null, now + 86_400_000)
        val setupJson = LinkOffer.encodeSetup(setup)
        assertEquals(
            """{"v":2,"purpose":"setup-offer","linkId":"${keys.linkId}","origin":"$origin","instanceId":"${Ids.INSTANCE}","name":"${TrustGrammar.encodeName("Family vault")}","kind":"private","recoveryFp":"none","expiresAt":${now + 86_400_000}}""",
            setupJson.decodeToString(),
        )
        val openedSetup = assertIs<OpenedOffer.Setup>(assertIs<Checked.Ok<OpenedOffer>>(LinkOffer.open(crypto, link(null), sealed(setupJson), served("setup", null), now)).value)
        assertEquals(setup, openedSetup.fields)
        assertEquals(LinkKind.SETUP, openedSetup.kind)

        val enrol = EnrolOfferFields(keys.linkId, origin, Ids.INSTANCE, cardHash, "new@example.com", now + 3_600_000)
        val enrolJson = LinkOffer.encodeEnrol(enrol)
        val openedEnrol = assertIs<OpenedOffer.Enrol>(assertIs<Checked.Ok<OpenedOffer>>(LinkOffer.open(crypto, link(null), sealed(enrolJson), served("enrol", null), now)).value)
        assertEquals(enrol, openedEnrol.fields)
        val unbound = LinkOffer.encodeEnrol(enrol.copy(email = null))
        assertTrue(unbound.decodeToString().contains("\"email\":\"none\""))
        assertNull(assertIs<OpenedOffer.Enrol>(assertIs<Checked.Ok<OpenedOffer>>(LinkOffer.open(crypto, link(null), sealed(unbound), served("enrol", null), now)).value).fields.email)

        // kind_mismatch from the form: host JSON where the server reported connect or register.
        assertEquals(LinkVerdict.KIND_MISMATCH, verdict(sealed(setupJson), link = link(null), served = served("connect")))
        assertEquals(LinkVerdict.KIND_MISMATCH, verdict(sealed(setupJson), link = link(null), served = served("register")))
        // The other host kind, known from the purpose before the template is applied.
        assertEquals(LinkVerdict.KIND_MISMATCH, verdict(sealed(setupJson), link = link(null), served = served("enrol", null)))
        assertEquals(LinkVerdict.KIND_MISMATCH, verdict(sealed(enrolJson), link = link(null), served = served("setup", null)))
        // Recognition and the template.
        assertEquals(LinkVerdict.UNKNOWN_FORMAT, verdict(sealed("""{"v":2,"purpose":"other-offer"}""".encodeToByteArray()), link = link(null), served = served("setup", null)))
        assertEquals(LinkVerdict.NON_CANONICAL, verdict(sealed("""{"v":2}""".encodeToByteArray()), link = link(null), served = served("setup", null)))
        assertEquals(LinkVerdict.NON_CANONICAL, verdict(sealed(setupJson.decodeToString().replace("\"v\":2", "\"v\": 2").encodeToByteArray()), link = link(null), served = served("setup", null)))
        assertEquals(LinkVerdict.BAD_STATEMENT, verdict(sealed(setupJson.decodeToString().replace("\"v\":2", "\"v\":3").encodeToByteArray()), link = link(null), served = served("setup", null)))
        // A host-minted offer through a link that carries a creator fingerprint.
        assertEquals(LinkVerdict.CREATOR_MISMATCH, verdict(sealed(setupJson), link = link(alice), served = served("setup", null)))
        // The field checks.
        assertEquals(LinkVerdict.LINK_MISMATCH, verdict(sealed(LinkOffer.encodeSetup(setup.copy(linkId = Ids.id16(8)))), link = link(null), served = served("setup", null)))
        assertEquals(LinkVerdict.ORIGIN_MISMATCH, verdict(sealed(LinkOffer.encodeSetup(setup.copy(origin = "https://other.example.org"))), link = link(null), served = served("setup", null)))
        assertEquals(LinkVerdict.OFFER_EXPIRED, verdict(sealed(setupJson), link = link(null), served = served("setup", null), nowMs = now + 86_400_000))

        assertFailsWith<IllegalArgumentException> { LinkOffer.encodeEnrol(enrol.copy(email = "New@Example.com")) } // not already normal
        assertFailsWith<IllegalArgumentException> { LinkOffer.encodeSetup(setup.copy(recoveryFp = "none")) } // null is none
    }

    // ---- §6.5, §6.8 the answer ---------------------------------------------------------------------

    private fun answer(
        offerHash: String,
        linkId: String = keys.linkId,
        to: Party = alice,
        toKey: String = to.key,
        from: Party = bob,
        fromKey: String = from.key,
    ) = LinkAnswerFields(linkId, offerHash, to.userId, toKey, from.userId, fromKey, "Bob", Bytes.toB64(nonceB), now + 5)

    private fun answerVerdict(envelope: ByteArray, offerHash: String, me: Party = alice, reported: String = Ids.BOB): LinkVerdict =
        assertIs<Checked.Refused<LinkVerdict>>(LinkAnswer.open(crypto, secret, offerHash, me.userId, me.box.publicKey, envelope, reported)).verdict

    @Test
    fun theWholeExchange_eachSideComputesBothCodesAlike() {
        // A creates the offer and keeps (secret, nonceA, offerHash) in its own device state.
        val offerFrame = LinkOffer.sign(crypto, alice.sign, offer())
        val offerHash = SignedFrame.hash(crypto, offerFrame)
        // B opens it and answers, with its nonce in the open.
        val opened = assertIs<OpenedOffer.Signed>(assertIs<Checked.Ok<OpenedOffer>>(LinkOffer.open(crypto, link(), sealed(offerFrame), served(), now)).value)
        val answerFrame = LinkAnswer.sign(crypto, bob.sign, answer(opened.offerHash))
        val answerEnvelope = LinkAnswer.seal(crypto, keys, answerFrame)
        // A processes the answer.
        val processed = assertIs<Checked.Ok<OpenedAnswer>>(LinkAnswer.open(crypto, secret, offerHash, Ids.ALICE, alice.box.publicKey, answerEnvelope, Ids.BOB)).value
        assertEquals(answer(offerHash), processed.fields)
        assertEquals(SignedFrame.hash(crypto, answerFrame), processed.answerHash)
        // A reveals nonceA; B checks it against the offer's commitment before it computes anything.
        assertTrue(CodeCommit.opens(crypto, Bytes.toB64(nonceA), opened.fields.commit))
        // A's inputs and B's inputs are the same, so the code A shows is the one B expects, and the other way round.
        for (side in LinkSide.entries) {
            val onA = ComparisonCode.link(crypto, side, keys.linkId, offerHash, processed.answerHash, nonceA, Bytes.fromB64(processed.fields.nonce))
            val onB = ComparisonCode.link(crypto, side, opened.linkId, opened.offerHash, SignedFrame.hash(crypto, answerFrame), nonceA, nonceB)
            assertEquals(onA, onB, side.code)
        }
    }

    @Test
    fun answer_eachCheckHasItsVerdict_inOrder() {
        val offerHash = SignedFrame.hash(crypto, LinkOffer.sign(crypto, alice.sign, offer()))
        val good = LinkAnswer.sign(crypto, bob.sign, answer(offerHash))
        fun seal(frame: ByteArray) = LinkAnswer.seal(crypto, keys, frame)

        assertEquals(LinkVerdict.UNOPENABLE, answerVerdict(sealed(good), offerHash), "sealed under the offer key")
        assertEquals(LinkVerdict.UNOPENABLE, answerVerdict(LinkAnswer.seal(crypto, Links.deriveKeys(crypto, ByteArray(32) { 5 }), good), offerHash))
        // The frame parse of §2.4: shorter than the magic is bad_frame; another magic is unknown_format.
        assertEquals(LinkVerdict.BAD_FRAME, answerVerdict(seal("{}".encodeToByteArray()), offerHash))
        assertEquals(LinkVerdict.UNKNOWN_FORMAT, answerVerdict(seal("{\"v\":2}".encodeToByteArray()), offerHash))
        assertEquals(LinkVerdict.BAD_FRAME, answerVerdict(seal(LinkOffer.sign(crypto, alice.sign, offer())), offerHash), "an offer frame is not an answer")

        // Proof of possession of the answer's own fromKey.
        val forged = resign(LinkAnswer.sign(crypto, bob.sign, answer(offerHash)), mallory, TrustPurpose.LINK_ANSWER)
        assertEquals(LinkVerdict.SIGNER_NOT_PINNED_KEY, answerVerdict(seal(forged), offerHash))
        assertEquals(LinkVerdict.BAD_SIGNATURE, answerVerdict(seal(good.copyOf().also { it[70] = (it[70].toInt() xor 2).toByte() }), offerHash))

        // The fields.
        assertEquals(LinkVerdict.LINK_MISMATCH, answerVerdict(seal(LinkAnswer.sign(crypto, bob.sign, answer(offerHash, linkId = Ids.id16(8)))), offerHash))
        assertEquals(LinkVerdict.OFFER_MISMATCH, answerVerdict(seal(good), "ee".repeat(32)))
        assertEquals(LinkVerdict.MISADDRESSED, answerVerdict(seal(LinkAnswer.sign(crypto, bob.sign, answer(offerHash, to = mallory))), offerHash))
        assertEquals(LinkVerdict.MISADDRESSED, answerVerdict(seal(LinkAnswer.sign(crypto, bob.sign, answer(offerHash, toKey = mallory.key))), offerHash))
        assertEquals(LinkVerdict.REPORTED_ANSWERER_MISMATCH, answerVerdict(seal(good), offerHash, reported = Ids.CAROL))

        // Order: the signer before the fields; then link, offer, address, the reported answerer.
        val allWrong = resign(LinkAnswer.sign(crypto, bob.sign, answer("ee".repeat(32), linkId = Ids.id16(8), to = mallory)), mallory, TrustPurpose.LINK_ANSWER)
        assertEquals(LinkVerdict.SIGNER_NOT_PINNED_KEY, answerVerdict(seal(allWrong), offerHash, reported = Ids.CAROL))
        val fieldsWrong = LinkAnswer.sign(crypto, bob.sign, answer("ee".repeat(32), linkId = Ids.id16(8), to = mallory))
        assertEquals(LinkVerdict.LINK_MISMATCH, answerVerdict(seal(fieldsWrong), offerHash, reported = Ids.CAROL))
        val offerAndLater = LinkAnswer.sign(crypto, bob.sign, answer("ee".repeat(32), to = mallory))
        assertEquals(LinkVerdict.OFFER_MISMATCH, answerVerdict(seal(offerAndLater), offerHash, reported = Ids.CAROL))
        val addressAndLater = LinkAnswer.sign(crypto, bob.sign, answer(offerHash, to = mallory))
        assertEquals(LinkVerdict.MISADDRESSED, answerVerdict(seal(addressAndLater), offerHash, reported = Ids.CAROL))

        assertFailsWith<IllegalArgumentException> { LinkAnswer.sign(crypto, mallory.sign, answer(offerHash)) }
    }

    // ---- the size bound is the reader's too -----------

    /** Counts what opening an envelope takes: the key derivation (HKDF is HMAC) and the AEAD opening. */
    private class Counting(private val real: CryptoProvider) : CryptoProvider by real {
        var macs = 0
        var opens = 0

        override fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
            macs++
            return real.hmacSha256(key, data)
        }

        override fun aeadDecrypt(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, ad: ByteArray): ByteArray {
            opens++
            return real.aeadDecrypt(key, nonce, ciphertext, ad)
        }
    }

    @Test
    fun anEnvelopeAboveTheBound_isUnopenable_beforeAKeyIsDerivedOrAByteOpened() {
        val max = Links.MAX_ENVELOPE_BYTES
        // §6.3: 2,732 base64url characters as sent, which is 2,049 bytes of envelope (it was 2,048 here once).
        assertEquals(2049, max)
        assertEquals(2732, Bytes.toB64(ByteArray(max)).length)
        val overhead = Envelope.seal(crypto, keys.offerKey, ByteArray(0), Ad.linkOffer(keys.linkId)).size
        // Real envelopes under the link's own keys and ADs, of a size no builder makes (`seal` refuses
        // them): the bound is all that stands between such an envelope and the opener.
        fun offerOf(size: Int) = Envelope.seal(crypto, keys.offerKey, ByteArray(size - overhead) { 'x'.code.toByte() }, Ad.linkOffer(keys.linkId))
        fun answerOf(size: Int) = Envelope.seal(crypto, keys.answerKey, ByteArray(size - overhead) { 'x'.code.toByte() }, Ad.linkAnswer(keys.linkId))
        val offerHash = "ab".repeat(32)
        val counting = Counting(crypto)
        fun openOffer(envelope: ByteArray) = assertIs<Checked.Refused<LinkVerdict>>(LinkOffer.open(counting, link(), envelope, served(), now)).verdict
        fun openAnswer(envelope: ByteArray) =
            assertIs<Checked.Refused<LinkVerdict>>(LinkAnswer.open(counting, secret, offerHash, Ids.ALICE, alice.box.publicKey, envelope, Ids.BOB)).verdict

        // At the bound an envelope is opened, and what is inside decides.
        assertEquals(max, offerOf(max).size)
        assertEquals(LinkVerdict.UNKNOWN_FORMAT, openOffer(offerOf(max)), "the plaintext is neither a frame nor host JSON")
        assertTrue(counting.macs > 0, "the keys were derived")
        assertEquals(1, counting.opens)
        counting.macs = 0
        counting.opens = 0
        assertNotEquals(LinkVerdict.UNOPENABLE, openAnswer(answerOf(max)))
        assertTrue(counting.macs > 0)
        assertEquals(1, counting.opens)

        // One byte above it, and far above it: `unopenable`, with nothing derived and nothing opened.
        for (size in listOf(max + 1, max + 2, 4 * max, 1 shl 20)) {
            for ((what, verdict) in listOf("offer" to { openOffer(offerOf(size)) }, "answer" to { openAnswer(answerOf(size)) })) {
                counting.macs = 0
                counting.opens = 0
                assertEquals(LinkVerdict.UNOPENABLE, verdict(), "an $what envelope of $size bytes")
                assertEquals(0, counting.macs, "an $what envelope of $size bytes: no key is derived")
                assertEquals(0, counting.opens, "an $what envelope of $size bytes: nothing is opened")
            }
        }
        // The builders stop at the same size.
        assertFailsWith<IllegalArgumentException> { LinkOffer.seal(crypto, keys, ByteArray(max + 1 - overhead)) }
        assertFailsWith<IllegalArgumentException> { LinkAnswer.seal(crypto, keys, ByteArray(max + 1 - overhead)) }
        assertEquals(max, LinkOffer.seal(crypto, keys, ByteArray(max - overhead)).size)
    }
}
