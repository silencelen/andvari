package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.CardOps
import io.silencelen.andvari.cli.CardWrite
import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.ok
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.link.CompareResult
import io.silencelen.andvari.core.client.link.CompareState
import io.silencelen.andvari.core.client.link.CreateOutcome
import io.silencelen.andvari.core.client.link.CreatedLink
import io.silencelen.andvari.core.client.link.CreatorStep
import io.silencelen.andvari.core.client.link.LinkShare
import io.silencelen.andvari.core.client.link.LinkStop
import io.silencelen.andvari.core.client.link.RecipientStep
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.pin.CardStatus
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.Frames
import io.silencelen.andvari.hostile.proxy.Gate
import io.silencelen.andvari.hostile.proxy.Resp
import io.silencelen.andvari.hostile.proxy.answer
import io.silencelen.andvari.hostile.proxy.editAnswer
import io.silencelen.andvari.hostile.proxy.hold
import io.silencelen.andvari.hostile.proxy.obj
import io.silencelen.andvari.hostile.proxy.serveCards
import io.silencelen.andvari.hostile.proxy.set
import io.silencelen.andvari.hostile.proxy.str
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Links under a hostile server and a hostile link channel (design §6.6 to §6.11, §2.4 "Opening a link" and "Processing
 * an answer", §16.2 T12). The server never sees the link secret, so it cannot read or forge an offer or an answer; it
 * can lie about what it stores, swap envelopes, replay and race. `compared` is set only by a person's own typed match.
 */
class LinkTest {
    private val otherNonce = Frames.b64(ByteArray(32) { 9 })

    private suspend fun connectLink(h: Host, shares: List<LinkShare> = emptyList()): CreatedLink =
        assertIs<CreateOutcome.Created>(h.links.create("connect", 3_600_000L, shares), "a connect link").link

    private suspend fun answer(h: Host, link: CreatedLink): RecipientStep.Answered {
        val confirm = assertIs<RecipientStep.Confirm>(h.links.open(link.url, GateEntry.PASTE_INVITE))
        return assertIs<RecipientStep.Answered>(h.links.confirm(confirm), "the answer is posted")
    }

    /**
     * §6.11 (T2-R-b), §17: "a second link reveal … cancel[s]": "A second, different value, from either the server or the
     * other side, is an anomaly: the link is marked failed and no code is shown." The failure stays when the genuine
     * value is served again, and nothing can then set `compared`.
     */
    @Test fun aSecondDifferentRevealFailsTheLinkForGoodAndNoCodeIsShown() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val a = account(ah)
        val b = account(bh)
        val answered = answer(bh, connectLink(ah))
        assertIs<CreatorStep.Processed>(ah.links.processAnswers().single())
        assertIs<RecipientStep.CodeReady>(bh.links.awaitReveal(answered))
        assertNotNull(bh.links.code(a.userId), "the first reveal fixed the answerer's code")
        val creatorsCode = assertNotNull(ah.links.code(b.userId))

        val lie = proxy.on(WireRoute.LINK_FETCH, "bob", handler = editAnswer { it.set("reveal", otherNonce) })
        assertIs<CompareState.Failed>(bh.links.refreshReveal(a.userId), "a second, different reveal marks the link failed")
        assertNull(bh.links.code(a.userId), "no code is shown")
        assertEquals(CompareResult.Failed, bh.links.typeCode(a.userId, creatorsCode), "and none is accepted")
        lie.remove()
        assertIs<CompareState.Failed>(bh.links.refreshReveal(a.userId), "the failure is not undone by the genuine value")
        assertEquals(false, b.store.local().contacts.getValue(a.userId).compared)
    }

    /** §6.11 pass 3: "The answerer checks it against `commit` (`bad_reveal`)": a reveal the offer never committed to. */
    @Test fun aRevealThatDoesNotOpenTheOffersCommitmentIsBadRevealAndNoCodeExists() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val a = account(ah)
        val b = account(bh)
        val answered = answer(bh, connectLink(ah))
        proxy.on(WireRoute.LINK_FETCH, "bob", handler = editAnswer { it.set("reveal", otherNonce) })
        assertEquals(RecipientStep.Stopped(LinkStop.BAD_REVEAL), bh.links.awaitReveal(answered))
        assertNull(bh.links.code(a.userId))
        assertEquals(CompareResult.Failed, bh.links.typeCode(a.userId, "123456"))
        assertEquals(false, b.store.local().contacts.getValue(a.userId).compared, "the contact stays unconfirmed")
    }

    /**
     * §6.8 recipient step 4 (T-R5), §2.4: the offer's `from` and `fromKey` must be the creator the server reports
     * (`reported_creator_mismatch`: "an anomaly, and nothing is sent"), and its kind the kind the server reports
     * (`kind_mismatch`: "nothing is sent, and nothing is pinned"). Another link's offer does not open at all.
     */
    @Test fun aServerThatLiesAboutALinksCreatorKindOrOfferStopsTheRecipientBeforeAnythingIsSentOrPinned() = world {
        operator()
        val ah = member("alice")
        val ch = member("carol")
        val c = account(ch)
        val carolsKey = proxy.last(WireRoute.REGISTER, "carol")!!.upstream!!.json!!.obj("accountKeys")!!.str("identityPub")!!
        val link = connectLink(ah)
        connectLink(ch)
        val otherOffer = proxy.last(WireRoute.LINK_CREATE, "carol")!!.req.json!!.str("offer")!!
        val bh = member("bob")
        val lies: List<Pair<LinkStop, (JsonObject) -> JsonObject>> = listOf(
            LinkStop.REPORTED_CREATOR_MISMATCH to { r -> r.set("creatorUserId", c.userId) },
            LinkStop.REPORTED_CREATOR_MISMATCH to { r -> r.set("creatorIdentityPub", carolsKey) },
            LinkStop.KIND_MISMATCH to { r -> r.set("kind", "register") },
            LinkStop.KIND_MISMATCH to { r -> r.set("kind", "enrol") },
            LinkStop.UNOPENABLE to { r -> r.set("offer", otherOffer) },
        )
        for ((i, lie) in lies.withIndex()) {
            // A signed-in member, and a device with no account and no pin: neither sends or pins anything.
            val fresh = device("fresh$i")
            for (h in listOf(bh, fresh)) {
                val tag = tag(h)
                val rule = proxy.on(WireRoute.LINK_FETCH, tag, handler = editAnswer(lie.second))
                val mark = proxy.mark()
                assertEquals(RecipientStep.Stopped(lie.first), h.links.open(link.url, GateEntry.PASTE_INVITE), "lie $i on $tag")
                assertEquals(listOf(WireRoute.LINK_FETCH), proxy.requests(tag = tag, since = mark).map { it.route }, "lie $i: nothing is sent after the lie was met")
                rule.remove()
            }
            assertNull(account(bh).store.local().contacts[account(ah).userId], "lie $i: nobody is pinned")
            assertEquals(PinState.None, fresh.trust.pinState(origin), "lie $i: no instance is pinned")
        }
    }

    /**
     * §6.8 creator steps 2 to 5, §2.4 "Processing an answer": an answer swapped for another link's does not open
     * (`unopenable`); a genuine answer the server attributes to someone else is `reported_answerer_mismatch`. "A
     * mismatch is an anomaly, and nothing is pinned."
     */
    @Test fun anAnswerSwappedForAnotherLinksOrAttributedToSomeoneElseIsIgnoredAndNobodyIsPinned() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val ch = member("carol")
        val a = account(ah)
        val b = account(bh)
        val c = account(ch)
        // Two links of Alice's; Bob answers one, Carol the other. The server serves each link the other's answer.
        val one = connectLink(ah)
        val two = connectLink(ah)
        answer(bh, one)
        answer(ch, two)
        proxy.on(WireRoute.LINK_ANSWERS, "alice", times = 1) { x ->
            val real = x.forward()
            val rows = Json.parseToJsonElement(real.text).jsonArray.map { it.jsonObject }
            val envelope = rows.associate { it.str("linkId")!! to it.str("answer")!! }
            real.withBody(JsonArray(rows.map { r -> r.set("answer", envelope.getValue(if (r.str("linkId") == one.linkId) two.linkId else one.linkId)) }).toString())
        }
        val swapped = ah.links.processAnswers()
        assertEquals(setOf(CreatorStep.Ignored(one.linkId, "unopenable"), CreatorStep.Ignored(two.linkId, "unopenable")), swapped.toSet(), "$swapped")
        assertTrue(a.store.local().contacts.isEmpty(), "nobody is pinned from a swapped answer")

        // A genuine answer, attributed by the server to another account.
        val three = connectLink(ah)
        answer(bh, three)
        proxy.on(WireRoute.LINK_ANSWERS, "alice", times = 1) { x ->
            val real = x.forward()
            real.withBody(JsonArray(Json.parseToJsonElement(real.text).jsonArray.map { r -> r.jsonObject.let { if (it.str("linkId") == three.linkId) it.set("answererUserId", c.userId) else it } }).toString())
        }
        val misattributed = ah.links.processAnswers().single { it is CreatorStep.Ignored && it.linkId == three.linkId }
        assertEquals(CreatorStep.Ignored(three.linkId, "reported_answerer_mismatch"), misattributed)
        assertNull(a.store.local().contacts[b.userId])
        assertNull(a.store.local().contacts[c.userId])
        assertNull(ah.links.code(b.userId), "and no code exists for a link that was ignored")
    }

    /**
     * §6.6: "The first answer wins; later ones get `409 link_used`." Two people hold the same link (T12: "whoever reads a
     * link or QR first can answer or claim it first"); the one who loses the race is told, and has pinned nobody.
     */
    @Test fun ofTwoAnswersRacingForOneLinkTheLoserIsToldItIsUsedAndPinsNobody() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val ch = member("carol")
        val a = account(ah)
        val link = connectLink(ah)
        val bobs = assertIs<RecipientStep.Confirm>(bh.links.open(link.url, GateEntry.PASTE_INVITE))
        val carols = assertIs<RecipientStep.Confirm>(ch.links.open(link.url, GateEntry.PASTE_INVITE))
        val gate = Gate()
        proxy.on(WireRoute.LINK_ANSWER, "bob", handler = hold(gate))
        withContext(Dispatchers.IO) {
            val slow = async { bh.links.confirm(bobs) }
            gate.awaitArrival()
            assertIs<RecipientStep.Answered>(ch.links.confirm(carols), "the other answer lands first")
            gate.release()
            assertEquals(RecipientStep.Stopped(LinkStop.ALREADY_USED), slow.await())
        }
        assertNull(account(bh).store.local().contacts[a.userId], "the loser pinned nobody")
        assertNull(bh.links.code(a.userId))
        assertEquals(RecipientStep.Stopped(LinkStop.ALREADY_USED), bh.links.open(link.url, GateEntry.PASTE_INVITE), "\"already used\"")
        assertEquals(account(ch).userId, assertIs<CreatorStep.Processed>(ah.links.processAnswers().single()).contactUserId)
    }

    /**
     * §6.7 step 9 (T-R3): "A's device deletes its record at `expiresAt` or when A revokes the link. An answer arriving
     * later finds no record and is ignored (`unknown_link`), whatever the server says."
     */
    @Test fun anAnswerToARevokedLinkIsIgnoredWhateverTheServerSays() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val link = connectLink(ah)
        // The server pretends to revoke, and keeps the link open.
        proxy.on(WireRoute.LINK_REVOKE, "alice", handler = answer { Resp.ok() })
        assertTrue(ah.links.revoke(link.linkId))
        assertTrue(ah.links.createdLinks().isEmpty(), "the creator's record is gone")
        answer(bh, link)
        assertEquals(listOf<CreatorStep>(CreatorStep.Ignored(link.linkId, "unknown_link")), ah.links.processAnswers())
        assertNull(account(ah).store.local().contacts[account(bh).userId], "a late answer pins nobody")
        assertTrue(proxy.requests(WireRoute.LINK_REVEAL, "alice").isEmpty(), "and no nonce is revealed for it")
    }

    /** A processed answer served again changes nothing: the pin, the code and the comparison stand as they were. */
    @Test fun aReplayedLinkAnswerChangesNothing() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val a = account(ah)
        val b = account(bh)
        answer(bh, connectLink(ah))
        assertIs<CreatorStep.Processed>(ah.links.processAnswers().single())
        val served = proxy.last(WireRoute.LINK_ANSWERS, "alice")!!.upstream!!
        val code = assertNotNull(ah.links.code(b.userId))
        val pinned = a.store.local().contacts.getValue(b.userId)
        proxy.on(WireRoute.LINK_ANSWERS, "alice", handler = answer { served })
        val mark = proxy.mark()
        assertTrue(ah.links.processAnswers().isEmpty(), "an answer already processed is not processed again")
        assertEquals(code, ah.links.code(b.userId))
        assertEquals(pinned, a.store.local().contacts.getValue(b.userId))
        assertTrue(sent(ah, WireRoute.LINK_REVEAL, mark).isEmpty(), "no second reveal is posted")
    }

    /**
     * §4.4 link-offer root, §2.4: "the served chain must contain a card with `H = offer.cardHash`"; a server that
     * withholds that card from the recipient gets `card_not_in_chain`, and nothing is pinned or sent.
     */
    @Test fun aLinkWhoseCardTheServerWithholdsFromTheRecipientIsCardNotInChain() = world {
        val oh = operator()
        val ah = member("alice")
        assertIs<CardWrite.Stored>(CardOps(oh, oh.session(origin)!!).sign(Steps.PASSWORD.toCharArray(), name = "renamed"))
        assertEquals(1L, assertIs<CardStatus.Ok>(ah.trust.refresh(origin)).pin.seq)
        val link = assertIs<CreateOutcome.Created>(ah.links.create("register", 3_600_000L, emptyList())).link // its offer names card 1
        val fresh = device("fresh")
        proxy.serveCards("fresh") { it.take(1) }
        assertEquals(RecipientStep.Stopped(LinkStop.CARD_NOT_IN_CHAIN), fresh.links.open(link.url, GateEntry.PASTE_INVITE))
        assertEquals(PinState.None, fresh.trust.pinState(origin))
    }

    /**
     * §6.11, §6.10 (T-B1, T-B2), T12: a middle party answers the creator with its own key and hands the real answerer a
     * link of its own. Each person then shows a code of a DIFFERENT link than the one the other must type, so neither
     * entry matches: "`compared` stays false", and the vault attached to the link is not shared.
     */
    @Test fun aMiddlePartyRelayingALinkCannotMakeTheCodesMatchAndNothingAttachedIsShared() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val mh = member("mallory")
        val a = account(ah)
        val b = account(bh)
        val m = account(mh)
        a.synced()
        val v = a.ok(null, LogAction.Create("Family"))
        val mark = proxy.mark()
        // Alice's invitation for Bob, with the vault attached, travels over a channel Mallory controls.
        val forBob = connectLink(ah, listOf(LinkShare(v, "writer")))
        // Mallory answers it as "bob", and passes Bob a link of her own as "alice".
        mh.rememberName(origin, m.userId, "bob")
        answer(mh, forBob)
        mh.rememberName(origin, m.userId, "alice")
        val relayed = connectLink(mh)
        val bobAnswered = answer(bh, relayed)
        val atAlice = assertIs<CreatorStep.Processed>(ah.links.processAnswers().single())
        assertEquals("bob", atAlice.label, "Alice sees the name the other side chose")
        assertIs<CreatorStep.Processed>(mh.links.processAnswers().single())
        assertIs<RecipientStep.CodeReady>(bh.links.awaitReveal(bobAnswered))

        // Alice and Bob get on a call, each reads the code on their own screen, and each types what the other read.
        val alicesCode = assertNotNull(ah.links.code(m.userId))
        val bobsCode = assertNotNull(bh.links.code(m.userId))
        // What each would have to type is on Mallory's screens, not on the other person's (one link in a million apart).
        if (bobsCode == mh.links.code(a.userId) || alicesCode == mh.links.code(b.userId)) return@world
        assertEquals(CompareResult.Mismatch, ah.links.typeCode(m.userId, bobsCode), "Bob's code is not the one Alice's link expects")
        assertEquals(CompareResult.Mismatch, bh.links.typeCode(m.userId, alicesCode), "Alice's code is not the one Bob's link expects")
        assertEquals(false, a.store.local().contacts.getValue(m.userId).compared, "compared stays false")
        assertEquals(false, b.store.local().contacts.getValue(m.userId).compared)

        // Nothing attached was shared: no add was signed, and the share still waits for a comparison.
        assertEquals(listOf(LinkShare(v, "writer")), ah.links.pendingShares()[m.userId])
        assertTrue(proxy.requests(WireRoute.LOG_APPEND, "alice", mark).none { it.param("vaultId") == v && Frames.kind(it.json!!.str("entry")!!) == "add" }, "no add was signed for the attached vault")
        m.synced()
        assertTrue(v !in m.vaultIds(), "the middle party was given nothing")
    }
}
