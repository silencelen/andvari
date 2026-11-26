package io.silencelen.andvari.core.client.link

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.onboard.EstablishedSession
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.RegistrationForm
import io.silencelen.andvari.core.client.onboard.SessionSink
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.client.state.ContactRecord
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.trust.CodeCommit
import io.silencelen.andvari.core.trust.DeviceLinkUrl
import io.silencelen.andvari.core.trust.TrustGrammar
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Links and contacts (design §6) end to end against [LinkServer]: both roles, the committed code, shares and the stops. */
class LinkFlowsTest {
    private val crypto = createCryptoProvider()
    private val alice = "11111111-1111-4111-8111-111111111111"
    private val bob = "22222222-2222-4222-8222-222222222222"
    private val hour = 3_600_000L
    private val vault = "abababab-abab-4bab-8bab-abababababab"

    private suspend fun pair(server: LinkServer = LinkServer(crypto)): Pair<LinkPerson, LinkPerson> =
        LinkPerson(crypto, server, 1, alice, "Alice").start() to LinkPerson(crypto, server, 2, bob, "Bob").start()

    private suspend fun connected(a: LinkPerson, b: LinkPerson, shares: List<LinkShare> = emptyList()): Pair<String, String> {
        val link = assertIs<CreateOutcome.Created>(a.flows.create("connect", hour, shares)).link
        val confirm = assertIs<RecipientStep.Confirm>(b.flows.open(link.url, GateEntry.SCAN_INVITE))
        val answered = assertIs<RecipientStep.Answered>(b.flows.confirm(confirm))
        assertIs<CreatorStep.Processed>(a.flows.processAnswers().single())
        assertIs<RecipientStep.CodeReady>(b.flows.awaitReveal(answered))
        return a.flows.code(bob)!! to b.flows.code(alice)!!
    }

    /** §2.3's link comparison code from the design text alone (SHA-256 of the literal input), for [side]. */
    private fun formulaCode(side: String, r: CodeRecord): String {
        val d = crypto.sha256("andvari/v2|link|code|$side|${r.linkId}|${r.offerHash}|${r.answerHash}|${r.nonceA}|${r.nonceB}".encodeToByteArray())
        val u32 = ((d[0].toLong() and 0xFF) shl 24) or ((d[1].toLong() and 0xFF) shl 16) or ((d[2].toLong() and 0xFF) shl 8) or (d[3].toLong() and 0xFF)
        return (u32 % 1_000_000).toString().padStart(6, '0')
    }

    /** The creator [creator] shows the `creator` code of its latest link with [answerer], and [answererCode] is the `answerer` code. */
    private fun assertEachShowsItsOwnCode(creator: LinkPerson, answererUserId: String, answererCode: String?) {
        val rec = CodeRecordStore(creator.state, creator.account.origin, creator.userId).latestFor(answererUserId)!!
        assertEquals(CodeRecord.CREATOR, rec.role)
        assertEquals(formulaCode("creator", rec), creator.flows.code(answererUserId), "the creator shows the creator's code")
        assertEquals(formulaCode("answerer", rec), answererCode, "the answerer shows the answerer's code")
    }

    /**
     * The create answer's `ttlMs` is the server's word. The countdown kept (and shown again from the record)
     * is never below 0 nor longer than the lifetime this device chose, at each edge and beyond it; within them it is
     * the served value.
     */
    @Test fun aCreatedLinksCountdownIsTheServedOneBoundedByTheLifetimeChosen() = runBlocking<Unit> {
        val (a, _) = pair()
        for ((served, shown) in listOf(
            -1L to 0L, Long.MIN_VALUE to 0L, 0L to 0L, 1L to 1L, hour - 1 to hour - 1, hour to hour, hour + 1 to hour,
            240 * hour to hour, Long.MAX_VALUE to hour,
        )) {
            a.server.override[io.silencelen.andvari.core.model.wire.WireRoute.LINK_CREATE] = io.silencelen.andvari.core.client.net.WireResult.Ok(
                io.silencelen.andvari.core.model.wire.WireJson.json.encodeToString(io.silencelen.andvari.core.model.wire.LinkCreatedResponse.serializer(),
                    io.silencelen.andvari.core.model.wire.LinkCreatedResponse(a.server.instance.now + hour, served)), 201)
            val link = assertIs<CreateOutcome.Created>(a.flows.create("connect", hour, emptyList()), "ttlMs $served").link
            assertEquals(shown, link.ttlMs, "ttlMs $served")
            assertEquals(shown, a.flows.createdLinks().single { it.linkId == link.linkId }.ttlMs, "ttlMs $served, as kept")
        }
    }

    @Test fun connectBothSidesTypeTheOtherCodeAndOnlyThenShare() = runBlocking<Unit> {
        val (a, b) = pair()
        val share = LinkShare(vault, "writer")
        val link = assertIs<CreateOutcome.Created>(a.flows.create("connect", hour, listOf(share))).link
        assertEquals(hour, link.ttlMs)
        assertEquals(listOf(link.linkId), a.flows.createdLinks().map { it.linkId })
        val confirm = assertIs<RecipientStep.Confirm>(b.flows.open(link.url, GateEntry.SCAN_INVITE))
        assertFalse(confirm.needsAccount)
        assertEquals("Alice", confirm.offer.creatorName)
        assertEquals("Home", confirm.offer.instanceName)
        val answered = assertIs<RecipientStep.Answered>(b.flows.confirm(confirm))
        // The answerer pinned the creator, uncompared, current here; no code before the reveal.
        val pinnedA = b.store.doc.contacts.getValue(alice)
        assertFalse(pinnedA.compared)
        assertEquals(a.identityPubB64, pinnedA.identityPub)
        assertNull(b.flows.code(alice))
        assertSame(b.flows.awaitReveal(answered), answered)
        // The creator processes: pinned uncompared, reveal posted, secret gone, acknowledged; the share waits.
        val processed = assertIs<CreatorStep.Processed>(a.flows.processAnswers().single())
        assertEquals(listOf(share), processed.pendingShares)
        assertTrue(a.flows.createdLinks().isEmpty(), "the secret is deleted once the answer is processed")
        assertTrue(a.releases.isEmpty())
        assertEquals(mapOf(bob to listOf(share)), a.flows.pendingShares())
        assertFalse(a.store.doc.contacts.getValue(bob).compared)
        assertIs<RecipientStep.CodeReady>(b.flows.awaitReveal(answered))
        val codeA = a.flows.code(bob)!!
        val codeB = b.flows.code(alice)!!
        // Each app shows its OWN side's code (§2.3): the creator's on Alice's screen, the answerer's on Bob's.
        assertEachShowsItsOwnCode(a, bob, codeB)
        assertEquals(codeA, assertIs<CompareState.Ready>(a.flows.compareState(bob)).code)
        assertEquals(codeB, assertIs<CompareState.Ready>(b.flows.compareState(alice)).code)
        // A wrong entry changes nothing.
        val wrong = ((codeB.toInt() + 1) % 1_000_000).toString().padStart(6, '0')
        assertEquals(CompareResult.Mismatch, a.flows.typeCode(bob, wrong))
        assertFalse(a.store.doc.contacts.getValue(bob).compared)
        assertTrue(a.releases.isEmpty())
        // Alice types the digits Bob reads out: compared on HER side only, and the share goes out.
        assertEquals(CompareResult.Matched, a.flows.typeCode(bob, " ${codeB.substring(0, 3)} ${codeB.substring(3)} "))
        assertTrue(a.store.doc.contacts.getValue(bob).compared)
        assertEquals(listOf(Triple(bob, share, false)), a.releases)
        assertTrue(a.flows.pendingShares().isEmpty())
        assertFalse(b.store.doc.contacts.getValue(alice).compared, "nothing the other app does sets compared here")
        assertIs<CompareState.Ready>(b.flows.compareState(alice))
        assertEquals(CompareResult.Matched, b.flows.typeCode(alice, codeA))
        assertTrue(b.store.doc.contacts.getValue(alice).compared)
        assertIs<CompareState.Matched>(b.flows.compareState(alice))
        // Both contacts are current on the device that made them (§6.9 (a)).
        assertEquals(Currency.LINK, ContactCurrency(a.state, crypto, a.account.origin, alice).currency(bob, b.identityPubB64))
        assertEquals(Currency.LINK, ContactCurrency(b.state, crypto, b.account.origin, bob).currency(alice, a.identityPubB64))
    }

    private fun assertSame(a: Any, b: Any) = assertTrue(a === b)

    @Test fun aRevealThatDoesNotOpenTheCommitmentFailsTheLinkAndNoCodeIsShown() = runBlocking<Unit> {
        val server = LinkServer(crypto)
        val (a, b) = pair(server)
        val link = assertIs<CreateOutcome.Created>(a.flows.create("connect", hour, emptyList())).link
        val answered = assertIs<RecipientStep.Answered>(b.flows.confirm(assertIs(b.flows.open(link.url, GateEntry.PASTE_INVITE))))
        server.revealOverride = Bytes.toB64(ByteArray(32) { 9 })
        assertEquals(RecipientStep.Stopped(LinkStop.BAD_REVEAL), b.flows.awaitReveal(answered))
        assertNull(b.flows.code(alice))
        assertEquals(CompareResult.Failed, b.flows.typeCode(alice, "000000"))
        // The honest reveal arriving later does not revive it (single assignment, T2-R-b).
        server.revealOverride = null
        a.flows.processAnswers()
        assertIs<CompareState.Failed>(b.flows.refreshReveal(alice))
        assertNull(b.flows.code(alice))
    }

    @Test fun aSecondDifferentRevealAfterTheCodeWasFixedFailsTheLink() = runBlocking<Unit> {
        val server = LinkServer(crypto)
        val (a, b) = pair(server)
        connected(a, b)
        // The server now serves another value: an anomaly, whatever it is.
        server.revealOverride = Bytes.toB64(ByteArray(32) { 3 })
        assertIs<CompareState.Failed>(b.flows.refreshReveal(alice))
        assertNull(b.flows.code(alice))
    }

    @Test fun anAnswerAfterRevocationOrExpiryIsIgnoredAndPinsNothing() = runBlocking<Unit> {
        val server = LinkServer(crypto)
        val (a, b) = pair(server)
        val link = assertIs<CreateOutcome.Created>(a.flows.create("connect", hour, emptyList())).link
        assertIs<RecipientStep.Answered>(b.flows.confirm(assertIs(b.flows.open(link.url, GateEntry.SCAN_INVITE))))
        // The creator revokes locally after the answer landed: the server refuses (link_state), the record is gone anyway.
        assertFalse(a.flows.revoke(link.linkId))
        assertEquals(CreatorStep.Ignored(link.linkId, "unknown_link"), a.flows.processAnswers().single())
        assertTrue(a.store.doc.contacts.isEmpty())
        assertTrue(server.rows.getValue(link.linkId).delivered)
        // Expiry binds the creator too: exactly at expiresAt the record is gone.
        val c = LinkPerson(crypto, server, 3, "33333333-3333-4333-8333-333333333333", "Carol").start()
        val link2 = assertIs<CreateOutcome.Created>(a.flows.create("connect", hour, emptyList())).link
        assertIs<RecipientStep.Answered>(c.flows.confirm(assertIs(c.flows.open(link2.url, GateEntry.SCAN_INVITE))))
        server.instance.now += hour
        assertEquals(CreatorStep.Ignored(link2.linkId, "unknown_link"), a.flows.processAnswers().single())
        assertTrue(a.store.doc.contacts.isEmpty())
    }

    @Test fun anotherDeviceOfTheAccountLeavesTheAnswerForTheDeviceThatMadeTheLink() = runBlocking<Unit> {
        // GET /links/answers lists every answered link of the ACCOUNT (spec 03 §15.6): two devices of alice read it.
        val server = LinkServer(crypto)
        val (a, b) = pair(server)
        val a2 = LinkPerson(crypto, server, 1, alice, "Alice").start()
        val share = LinkShare(vault, "writer")
        val link = assertIs<CreateOutcome.Created>(a.flows.create("connect", hour, listOf(share))).link
        val answered = assertIs<RecipientStep.Answered>(b.flows.confirm(assertIs(b.flows.open(link.url, GateEntry.SCAN_INVITE))))
        // The other device reads the inbox first: it neither acknowledges nor pins.
        assertEquals(listOf<CreatorStep>(CreatorStep.Ignored(link.linkId, "unknown_link")), a2.flows.processAnswers())
        assertFalse(server.rows.getValue(link.linkId).delivered, "a device that did not create the link leaves its answer alone")
        assertTrue(a2.store.doc.contacts.isEmpty())
        assertEquals(listOf<CreatorStep>(CreatorStep.Ignored(link.linkId, "unknown_link")), a2.flows.processAnswers(), "still listed for the creator")
        // The creating device still gets it: pin, reveal, code, and the share waits for its match.
        val processed = assertIs<CreatorStep.Processed>(a.flows.processAnswers().single())
        assertEquals(listOf(share), processed.pendingShares)
        assertTrue(server.rows.getValue(link.linkId).delivered)
        assertIs<RecipientStep.CodeReady>(b.flows.awaitReveal(answered))
        assertEachShowsItsOwnCode(a, bob, b.flows.code(alice))
        // A link this device created and dropped at its expiry is still its own to acknowledge.
        val c = LinkPerson(crypto, server, 3, "33333333-3333-4333-8333-333333333333", "Carol").start()
        val link2 = assertIs<CreateOutcome.Created>(a.flows.create("connect", hour, emptyList())).link
        assertIs<RecipientStep.Answered>(c.flows.confirm(assertIs(c.flows.open(link2.url, GateEntry.SCAN_INVITE))))
        server.instance.now += hour
        a.flows.expireRecords(server.instance.now)
        assertTrue(a.flows.createdLinks().isEmpty())
        assertEquals(listOf<CreatorStep>(CreatorStep.Ignored(link2.linkId, "unknown_link")), a2.flows.processAnswers())
        assertFalse(server.rows.getValue(link2.linkId).delivered)
        assertEquals(CreatorStep.Ignored(link2.linkId, "unknown_link"), a.flows.processAnswers().single())
        assertTrue(server.rows.getValue(link2.linkId).delivered)
    }

    @Test fun aLostAnswerReplyStillLeadsToTheCodeOnARetry() = runBlocking<Unit> {
        val server = LinkServer(crypto)
        val (a, b) = pair(server)
        val link = assertIs<CreateOutcome.Created>(a.flows.create("connect", hour, emptyList())).link
        val confirm = assertIs<RecipientStep.Confirm>(b.flows.open(link.url, GateEntry.SCAN_INVITE))
        // The answer lands, but its reply is lost.
        server.loseReply += io.silencelen.andvari.core.model.wire.WireRoute.LINK_ANSWER
        assertEquals(RecipientStep.Stopped(LinkStop.UNREACHABLE), b.flows.confirm(confirm))
        assertEquals("answered", server.rows.getValue(link.linkId).state)
        server.loseReply.clear()
        // The person retries: link_used, and this device continues with the answer the server holds.
        val answered = assertIs<RecipientStep.Answered>(b.flows.confirm(confirm))
        assertIs<CreatorStep.Processed>(a.flows.processAnswers().single())
        assertIs<RecipientStep.CodeReady>(b.flows.awaitReveal(answered))
        assertEachShowsItsOwnCode(a, bob, b.flows.code(alice))
        assertNotNull(b.flows.code(alice))
    }

    @Test fun aLostAnswerReplyStillLeadsToTheCodeOnReopening() = runBlocking<Unit> {
        val server = LinkServer(crypto)
        val (a, b) = pair(server)
        val link = assertIs<CreateOutcome.Created>(a.flows.create("connect", hour, emptyList())).link
        val confirm = assertIs<RecipientStep.Confirm>(b.flows.open(link.url, GateEntry.SCAN_INVITE))
        server.loseReply += io.silencelen.andvari.core.model.wire.WireRoute.LINK_ANSWER
        assertEquals(RecipientStep.Stopped(LinkStop.UNREACHABLE), b.flows.confirm(confirm))
        server.loseReply.clear()
        b.flows.dismiss(confirm)
        // Opening the link again finds it answered by this device's own kept answer.
        val answered = assertIs<RecipientStep.Answered>(b.flows.open(link.url, GateEntry.SCAN_INVITE))
        assertIs<CreatorStep.Processed>(a.flows.processAnswers().single())
        assertIs<RecipientStep.CodeReady>(b.flows.awaitReveal(answered))
        assertEachShowsItsOwnCode(a, bob, b.flows.code(alice))
    }

    @Test fun anAnswerThatNeverLandedIsSentAgainUnchangedOnARetry() = runBlocking<Unit> {
        val server = LinkServer(crypto)
        val (a, b) = pair(server)
        val link = assertIs<CreateOutcome.Created>(a.flows.create("connect", hour, emptyList())).link
        val confirm = assertIs<RecipientStep.Confirm>(b.flows.open(link.url, GateEntry.SCAN_INVITE))
        server.override[io.silencelen.andvari.core.model.wire.WireRoute.LINK_ANSWER] =
            io.silencelen.andvari.core.client.net.WireResult.NoAnswer(io.silencelen.andvari.core.client.net.NoAnswerKind.TRANSPORT)
        assertEquals(RecipientStep.Stopped(LinkStop.UNREACHABLE), b.flows.confirm(confirm))
        assertEquals("open", server.rows.getValue(link.linkId).state)
        server.override.clear()
        val answered = assertIs<RecipientStep.Answered>(b.flows.confirm(confirm))
        assertIs<CreatorStep.Processed>(a.flows.processAnswers().single())
        assertIs<RecipientStep.CodeReady>(b.flows.awaitReveal(answered))
        assertEachShowsItsOwnCode(a, bob, b.flows.code(alice))
    }

    @Test fun typingTheCodeOnOnesOwnScreenIsRefusedAndOnlyTheOtherSidesCodeMatches() = runBlocking<Unit> {
        // The two codes of a link coincide once in a million; take a link where they differ, so the test means something.
        var people: Pair<LinkPerson, LinkPerson>? = null
        var codes: Pair<String, String>? = null
        for (attempt in 1..5) {
            val (a, b) = pair()
            val c = connected(a, b)
            people = a to b
            codes = c
            if (c.first != c.second) break
        }
        val (a, b) = people!!
        val (codeA, codeB) = codes!!
        assertNotEquals(codeA, codeB, "the two sides of a link show different codes")
        assertEachShowsItsOwnCode(a, bob, codeB)
        // Alice copies her own screen: refused, nothing changes, and it says so.
        assertEquals(CompareResult.Mismatch, a.flows.typeCode(bob, codeA))
        assertFalse(a.store.doc.contacts.getValue(bob).compared)
        assertIs<CompareState.Ready>(a.flows.compareState(bob))
        assertEquals(CompareResult.Mismatch, b.flows.typeCode(alice, " $codeB "))
        assertFalse(b.store.doc.contacts.getValue(alice).compared)
        assertIs<CompareState.Ready>(b.flows.compareState(alice))
        // The code a person must type is on no object this device returns and in no record it keeps.
        val stateA = a.state.get("ovh.codes|${a.account.origin}|$alice")!!
        val stateB = b.state.get("ovh.codes|${b.account.origin}|$bob")!!
        assertTrue(stateA.contains("\"$codeA\"") && !stateA.contains("\"$codeB\""), "the creator keeps only its own code")
        assertTrue(stateB.contains("\"$codeB\"") && !stateB.contains("\"$codeA\""), "the answerer keeps only its own code")
        // Each types the code the other reads out.
        assertEquals(CompareResult.Matched, a.flows.typeCode(bob, codeB))
        assertEquals(CompareResult.Matched, b.flows.typeCode(alice, codeA))
        assertTrue(a.store.doc.contacts.getValue(bob).compared)
        assertTrue(b.store.doc.contacts.getValue(alice).compared)
    }

    @Test fun aContactPinnedAgainAfterItsRemovalOnASlowClockSupersedesTheTombstone() = runBlocking<Unit> {
        // design §5.4: the removal happened on a device whose clock ran ahead of these two; the new pins are stamped after it.
        val (a, b) = pair()
        val removedAt = a.server.instance.now + 30L * 24 * 3600 * 1000
        b.store.doc = b.store.doc.copy(contactTombstones = mapOf(alice to io.silencelen.andvari.core.client.state.ContactTombstone(alice, removedAt)))
        a.store.doc = a.store.doc.copy(contactTombstones = mapOf(bob to io.silencelen.andvari.core.client.state.ContactTombstone(bob, removedAt)))
        val (codeA, codeB) = connected(a, b)
        assertEquals(removedAt + 1, b.store.doc.contacts.getValue(alice).verifiedAt, "the answerer's pin is stamped after the tombstone")
        assertEquals(removedAt + 1, a.store.doc.contacts.getValue(bob).verifiedAt, "the creator's pin too")
        // The tombstone no longer removes them when any device merges.
        val merged = io.silencelen.andvari.core.client.state.AccountMerge.merge(b.store.doc, b.store.doc.copy(contacts = emptyMap())).document
        assertNotNull(merged.contacts[alice])
        // The matched comparison keeps the pin and its stamp.
        assertEquals(CompareResult.Matched, a.flows.typeCode(bob, codeB))
        assertEquals(CompareResult.Matched, b.flows.typeCode(alice, codeA))
        assertTrue(a.store.doc.contacts.getValue(bob).compared)
        assertTrue(a.store.doc.contacts.getValue(bob).verifiedAt > removedAt)
    }

    @Test fun aKnownContactUnderAnotherKeyIsReplacedOnlyByAMatchedCode() = runBlocking<Unit> {
        val (a, b) = pair()
        val oldKey = Bytes.toB64(ByteArray(32) { 5 })
        val label = TrustGrammar.encodeName("Alice (old)")!!
        b.store.doc = b.store.doc.copy(contacts = mapOf(alice to ContactRecord(alice, oldKey, label, verifiedAt = 1, compared = true, madeOn = "x")))
        a.store.doc = a.store.doc.copy(contacts = mapOf(bob to ContactRecord(bob, oldKey, TrustGrammar.encodeName("Bob (old)")!!, verifiedAt = 1, compared = true, madeOn = "x")))
        val link = assertIs<CreateOutcome.Created>(a.flows.create("connect", hour, listOf(LinkShare(vault, "reader")))).link
        val changed = assertIs<RecipientStep.KeyChanged>(b.flows.open(link.url, GateEntry.SCAN_INVITE))
        assertEquals("Alice (old)", changed.existingLabel)
        // A confirm without the acknowledgement returns to the prompt.
        val confirm = assertIs<RecipientStep.Confirm>(b.flows.proceed(changed))
        assertTrue(confirm.replacesKey)
        val answered = assertIs<RecipientStep.Answered>(b.flows.confirm(confirm))
        assertEquals(oldKey, b.store.doc.contacts.getValue(alice).identityPub, "nothing replaced yet")
        val creator = assertIs<CreatorStep.KeyChanged>(a.flows.processAnswers().single())
        assertEquals("Bob (old)", creator.existingLabel)
        assertEquals(oldKey, a.store.doc.contacts.getValue(bob).identityPub)
        assertIs<RecipientStep.CodeReady>(b.flows.awaitReveal(answered))
        val ready = assertIs<CompareState.Ready>(a.flows.compareState(bob))
        assertTrue(ready.replacesKey)
        // Alice's share waits for her match, and it was never sent to the old key.
        assertFalse(a.flows.releaseShare(bob, LinkShare(vault, "reader")), "no per-vault release to a key that is not the pinned one")
        assertEquals(CompareResult.Matched, a.flows.typeCode(bob, b.flows.code(alice)!!))
        val replaced = a.store.doc.contacts.getValue(bob)
        assertEquals(b.identityPubB64, replaced.identityPub)
        assertTrue(replaced.compared)
        assertEquals("Bob", TrustGrammar.decodeName(replaced.label))
        assertEquals(1, a.releases.size)
        assertEquals(CompareResult.Matched, b.flows.typeCode(alice, a.flows.code(bob)!!))
        assertEquals(a.identityPubB64, b.store.doc.contacts.getValue(alice).identityPub)
    }

    @Test fun aPerVaultReleaseToAnUncomparedContactIsExplicitAndMarked() = runBlocking<Unit> {
        val (a, b) = pair()
        val share = LinkShare(vault, "writer")
        val link = assertIs<CreateOutcome.Created>(a.flows.create("connect", hour, listOf(share))).link
        b.flows.confirm(assertIs(b.flows.open(link.url, GateEntry.SCAN_INVITE)))
        a.flows.processAnswers()
        assertTrue(a.flows.releaseShare(bob, share))
        assertEquals(listOf(Triple(bob, share, true)), a.releases)
        assertTrue(a.flows.pendingShares().isEmpty())
    }

    @Test fun theCodeMatchIsRecordedEvenWhenAccountStateCannotBeWrittenYet() = runBlocking<Unit> {
        val (a, b) = pair()
        val (_, codeB) = connected(a, b)
        a.store.refuse = "account_state_full"
        assertEquals(CompareResult.Unsaved, a.flows.typeCode(bob, codeB))
        assertFalse(a.store.doc.contacts.getValue(bob).compared)
        a.store.refuse = null
        // The person's correct entry stands; the write is retried without asking again for a match.
        assertEquals(CompareResult.Matched, a.flows.typeCode(bob, "not digits"))
        assertTrue(a.store.doc.contacts.getValue(bob).compared)
    }

    @Test fun recipientStopsBeforeAnythingIsSent() = runBlocking<Unit> {
        val server = LinkServer(crypto)
        val (a, b) = pair(server)
        val link = assertIs<CreateOutcome.Created>(a.flows.create("connect", hour, emptyList())).link
        assertEquals(RecipientStep.Stopped(LinkStop.WRONG_ENTRY), b.flows.open(link.url, GateEntry.LINK_DEVICE_SCREEN))
        assertEquals(RecipientStep.Stopped(LinkStop.WRONG_ENTRY), b.flows.open(link.url, GateEntry.KIT_RECOVERY_SCREEN))
        val d = DeviceLinkUrl.compose(server.instance.origin, ByteArray(32) { 1 })!!
        assertEquals(RecipientStep.Stopped(LinkStop.WRONG_SCREEN_DEVICE_LINK), b.flows.open(d, GateEntry.SCAN_INVITE))
        assertEquals(RecipientStep.Stopped(LinkStop.BAD_LINK), b.flows.open("https://andvaripass.com/l#v2.x", GateEntry.SCAN_INVITE))
        // A `/d` URL with an invite's four-part fragment is a device link that does not parse: never opened as an invite.
        assertEquals(RecipientStep.Stopped(LinkStop.BAD_LINK), b.flows.open(link.url.replace("/l#", "/d#"), GateEntry.SCAN_INVITE))
        assertEquals(RecipientStep.Stopped(LinkStop.OWN_LINK), a.flows.open(link.url, GateEntry.SCAN_INVITE))
        // Someone else answered first: "already used".
        val c = LinkPerson(crypto, server, 3, "33333333-3333-4333-8333-333333333333", "Carol").start()
        c.flows.confirm(assertIs(c.flows.open(link.url, GateEntry.SCAN_INVITE)))
        assertEquals(RecipientStep.Stopped(LinkStop.ALREADY_USED), b.flows.open(link.url, GateEntry.SCAN_INVITE))
        // The answerer itself finds its own answered link, not "already used".
        assertIs<RecipientStep.Answered>(c.flows.open(link.url, GateEntry.SCAN_INVITE))
        // A server that reports another creator: an anomaly, nothing sent.
        val link2 = assertIs<CreateOutcome.Created>(a.flows.create("connect", hour, emptyList())).link
        val row = server.rows.getValue(link2.linkId)
        server.rows[link2.linkId] = LinkServer.Row(row.linkId, row.kind, row.offer, row.expiresAt, bob, b.identityPubB64, null)
        val before = server.calls.size
        assertEquals(RecipientStep.Stopped(LinkStop.REPORTED_CREATOR_MISMATCH), b.flows.open(link2.url, GateEntry.SCAN_INVITE))
        assertFalse(server.calls.drop(before).any { it.name == "LINK_ANSWER" })
    }

    @Test fun aConfirmedStepIsReDerivedAndADismissedOneIsStale() = runBlocking<Unit> {
        val (a, b) = pair()
        val link = assertIs<CreateOutcome.Created>(a.flows.create("connect", hour, emptyList())).link
        val confirm = assertIs<RecipientStep.Confirm>(b.flows.open(link.url, GateEntry.SCAN_INVITE))
        b.flows.dismiss(confirm)
        assertEquals(RecipientStep.Stopped(LinkStop.STALE), b.flows.confirm(confirm))
        // Another engine's step is not this one's.
        val other = LinkPerson(crypto, b.server, 2, bob, "Bob").start()
        val confirm2 = assertIs<RecipientStep.Confirm>(b.flows.open(link.url, GateEntry.SCAN_INVITE))
        assertEquals(RecipientStep.Stopped(LinkStop.STALE), other.flows.confirm(confirm2))
    }

    /** A new device of [userId], signed out ([acct] null) and pinning nothing, against [server]. */
    private class NewDevice(val flows: WireLinkFlows, val trust: io.silencelen.andvari.core.client.pin.CardTrust) {
        var acct: LinkAccount? = null
    }

    private fun newDevice(server: LinkServer, userId: String): NewDevice {
        val state = MemoryDeviceState()
        val trust = io.silencelen.andvari.core.client.pin.CardTrust(io.silencelen.andvari.core.client.pin.PinStore(state),
            io.silencelen.andvari.core.client.pin.TrustCardChainVerifier(crypto), { server.client(userId) }, crypto, null, false)
        lateinit var d: NewDevice
        d = NewDevice(WireLinkFlows({ server.client(d.acct?.userId) }, trust, state, crypto, { server.instance.now }, { d.acct }, false), trust)
        return d
    }

    @Test fun aFlowSettledAfterSignInKeepsItsPinAndOnlyTheAnswerKey() = runBlocking<Unit> {
        val server = LinkServer(crypto)
        val (a, b) = pair(server)
        val origin = server.instance.origin
        val link = assertIs<CreateOutcome.Created>(a.flows.create("connect", hour, emptyList())).link
        val d = newDevice(server, bob)
        val confirm = assertIs<RecipientStep.Confirm>(d.flows.open(link.url, GateEntry.APP_LINK))
        assertTrue(confirm.needsAccount)
        assertNotNull(d.trust.pinFor(origin), "the link made the pin")
        assertTrue(d.flows.holdsLinkSecret(confirm))
        // Bob signs in on that pin; the app settles the flow and holds it for the connection.
        d.acct = b.account
        val held = assertNotNull(d.flows.settle(confirm))
        assertFalse(d.flows.holdsLinkSecret(held), "the link's secret is wiped; only the answer key is kept")
        assertEquals(1, d.flows.openFlows())
        // Dismissed now, the flow ends and the pin the account stands on stays.
        d.flows.dismiss(held)
        assertEquals(0, d.flows.openFlows())
        assertNotNull(d.trust.pinFor(origin))
        assertNull(d.flows.settle(held), "an ended flow")
        // Another device: settled, then confirmed once the vault is open. The answer sealed with the kept key opens at Alice.
        val e = newDevice(server, bob)
        val confirm2 = assertIs<RecipientStep.Confirm>(e.flows.open(link.url, GateEntry.APP_LINK))
        e.acct = b.account
        val held2 = assertNotNull(e.flows.settle(confirm2))
        assertNotNull(e.flows.settle(held2), "settling twice changes nothing")
        val answered = assertIs<RecipientStep.Answered>(e.flows.confirm(held2))
        assertEquals(0, e.flows.openFlows())
        assertNotNull(e.trust.pinFor(origin))
        assertIs<CreatorStep.Processed>(a.flows.processAnswers().single())
        assertIs<RecipientStep.CodeReady>(e.flows.awaitReveal(answered))
        // Any other kind has nothing left to confirm: settling ends the flow and keeps the pin.
        val reg = assertIs<CreateOutcome.Created>(a.flows.create("register", hour, emptyList())).link
        val f = newDevice(server, bob)
        val confirm3 = assertIs<RecipientStep.Confirm>(f.flows.open(reg.url, GateEntry.APP_LINK))
        assertNull(f.flows.settle(confirm3))
        assertEquals(0, f.flows.openFlows())
        assertNotNull(f.trust.pinFor(origin))
    }

    @Test fun connectWithoutAnAccountOnAnInstanceNotTakingSignUps() = runBlocking<Unit> {
        val server = LinkServer(crypto)
        val (a, b) = pair(server)
        b.signedIn = false
        val link = assertIs<CreateOutcome.Created>(a.flows.create("connect", hour, emptyList())).link
        val open = assertIs<RecipientStep.Confirm>(b.flows.open(link.url, GateEntry.APP_LINK))
        assertTrue(open.needsAccount)
        // Without an account here, confirm sends nothing.
        assertSame(open, b.flows.confirm(open))
        server.instance.mode = "links"
        val closed = assertIs<RecipientStep.NotTakingAccounts>(b.flows.open(link.url, GateEntry.APP_LINK))
        assertEquals("links", closed.mode)
    }

    @Test fun anInviteForAnotherInstanceIsADeadEndUntilTheAppSwitches() = runBlocking<Unit> {
        val (a, b) = pair()
        val far = LinkServer(crypto, FakeInstance(crypto, origin = "https://far.example"))
        val c = LinkPerson(crypto, far, 3, "33333333-3333-4333-8333-333333333333", "Carol").start()
        val link = assertIs<CreateOutcome.Created>(c.flows.create("connect", hour, emptyList())).link
        // Bob is signed in at a.origin; the link is for far.example. His engine dials the link's origin.
        val route = { o: String -> if (o == far.instance.origin) far.client(bob) else b.server.client(bob) }
        val trust = io.silencelen.andvari.core.client.pin.CardTrust(io.silencelen.andvari.core.client.pin.PinStore(b.state),
            io.silencelen.andvari.core.client.pin.TrustCardChainVerifier(crypto), route, crypto, null, false)
        val bobEngine = WireLinkFlows(route, trust, b.state, crypto,
            { b.server.instance.now }, { if (b.signedIn) b.account else null }, true)
        val dead = assertIs<RecipientStep.OtherInstance>(bobEngine.open(link.url, GateEntry.SCAN_INVITE))
        assertEquals(b.account.origin, dead.currentOrigin)
        b.signedIn = false
        val confirm = assertIs<RecipientStep.Confirm>(bobEngine.proceed(dead))
        assertTrue(confirm.needsAccount)
    }

    @Test fun createRefusesBeforeAnythingIsSent() = runBlocking<Unit> {
        val (a, _) = pair()
        assertEquals(CreateOutcome.Refused("bad_lifetime"), a.flows.create("connect", 60_000, emptyList()))
        assertEquals(CreateOutcome.Refused("bad_lifetime"), a.flows.create("register", 73 * hour, emptyList()))
        assertEquals(CreateOutcome.Refused("bad_kind"), a.flows.create("setup", hour, emptyList()))
        assertEquals(CreateOutcome.Refused("shares_on_register"), a.flows.create("register", hour, listOf(LinkShare(vault, "writer"))))
        assertTrue(a.flows.createdLinks().isEmpty())
        assertTrue(a.server.rows.isEmpty())
        // A server refusal drops the record; no answer keeps it until its expiry.
        a.server.override[io.silencelen.andvari.core.model.wire.WireRoute.LINK_CREATE] =
            io.silencelen.andvari.core.client.net.WireResult.Refused(413, io.silencelen.andvari.core.model.wire.WireError("quota_exceeded", "x"))
        assertEquals(CreateOutcome.Refused("quota_exceeded"), a.flows.create("connect", hour, emptyList()))
        assertTrue(a.flows.createdLinks().isEmpty())
        a.server.override[io.silencelen.andvari.core.model.wire.WireRoute.LINK_CREATE] =
            io.silencelen.andvari.core.client.net.WireResult.NoAnswer(io.silencelen.andvari.core.client.net.NoAnswerKind.TIMEOUT)
        val unknown = assertIs<CreateOutcome.Unknown>(a.flows.create("connect", hour, emptyList()))
        assertNull(unknown.link.ttlMs)
        assertEquals(1, a.flows.createdLinks().size)
        a.flows.expireRecords(a.server.instance.now + hour)
        assertTrue(a.flows.createdLinks().isEmpty())
    }

    @Test fun theLinkSecretIsSealedInDeviceState() = runBlocking<Unit> {
        val (a, _) = pair()
        val link = assertIs<CreateOutcome.Created>(a.flows.create("connect", hour, emptyList())).link
        val secretText = link.url.substringAfter("#").split('.')[2]
        val stored = a.state.get("ovh.links|${a.account.origin}|$alice")!!
        assertFalse(stored.contains(secretText))
    }

    @Test fun registerLinkPinsBothSidesThroughRegistration() = runBlocking<Unit> {
        val server = LinkServer(crypto)
        val (a, _) = pair(server)
        val link = assertIs<CreateOutcome.Created>(a.flows.create("register", hour, emptyList())).link
        // A new person, signed out, on this instance.
        val state = MemoryDeviceState()
        val trust = server.instance.pinnedTrust(state)
        var acct: LinkAccount? = null
        val sessions = ArrayList<EstablishedSession>()
        val newcomer = WireLinkFlows({ server.client(acct?.userId) }, trust, state, crypto, { server.instance.now }, { acct }, false)
        val confirm = assertIs<RecipientStep.Confirm>(newcomer.open(link.url, GateEntry.SCAN_INVITE))
        assertTrue(confirm.needsAccount)
        assertEquals("register", confirm.offer.kind)
        val onboarding = WireOnboarding(server.instance.origin, server.client(null), trust, KnownDevices(state, crypto), SessionSink { sessions += it }, crypto, state,
            "android", "Pixel", { server.instance.now }, links = newcomer, work = Dispatchers.Unconfined)
        val form = RegistrationForm("dana@example.com", "Dana", "correct horse Battery 9 staple".toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel", "android")
        val reg = assertIs<Registration.Registered>(onboarding.register(RegistrationAuth.RegisterLink(confirm), form))
        val session = sessions.single()
        // The new account pinned its inviter, uncompared, in its own account state on the server.
        server.keys[reg.userId] = Bytes.toB64(session.account.identity.publicKey)
        acct = LinkAccount.of(session, "Dana", io.silencelen.andvari.core.client.state.StoredAccountState(reg.userId, session.account.uvk, server.client(reg.userId), crypto, state))
        val pinned = acct!!.store.local().contacts.getValue(alice)
        assertEquals(a.identityPubB64, pinned.identityPub)
        assertFalse(pinned.compared)
        // The creator processes the answer the registration carried, and each side shows its own code.
        val processed = assertIs<CreatorStep.Processed>(a.flows.processAnswers().single())
        assertEquals(reg.userId, processed.contactUserId)
        assertEquals("Dana", processed.label)
        assertIs<CompareState.Ready>(newcomer.refreshReveal(alice))
        assertNotNull(newcomer.code(alice))
        assertEachShowsItsOwnCode(a, reg.userId, newcomer.code(alice))
    }

    /**
     * A registration through a register link whose session the session keeper refuses once the server answered (what the
     * device keeps changed meanwhile): the link is spent at the server, and its flow ends here with its secret, nothing
     * pinned. Before, the flow stayed open, holding the link's secret, until the app closed.
     */
    @Test fun aRegisterLinksFlowEndsWhenItsRegistrationStopsAfterTheServerAnswered() = runBlocking<Unit> {
        val server = LinkServer(crypto)
        val (a, _) = pair(server)
        val link = assertIs<CreateOutcome.Created>(a.flows.create("register", hour, emptyList())).link
        val state = MemoryDeviceState()
        val trust = server.instance.pinnedTrust(state)
        val newcomer = WireLinkFlows({ server.client(null) }, trust, state, crypto, { server.instance.now }, { null }, false)
        val confirm = assertIs<RecipientStep.Confirm>(newcomer.open(link.url, GateEntry.SCAN_INVITE))
        val refusing = object : SessionSink {
            override suspend fun established(session: EstablishedSession) = error("never kept")
            override suspend fun take(session: EstablishedSession): String {
                session.account.wipe()
                return io.silencelen.andvari.core.client.session.Establishing.ANOTHER_SESSION_KEPT
            }
        }
        val onboarding = WireOnboarding(server.instance.origin, server.client(null), trust, KnownDevices(state, crypto), refusing, crypto, state,
            "android", "Pixel", { server.instance.now }, links = newcomer, work = Dispatchers.Unconfined)
        val form = RegistrationForm("dana@example.com", "Dana", "correct horse Battery 9 staple".toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel", "android")
        assertEquals(1, newcomer.openFlows())
        val reg = assertIs<Registration.Registered>(onboarding.register(RegistrationAuth.RegisterLink(confirm), form))
        assertEquals(io.silencelen.andvari.core.client.session.Establishing.ANOTHER_SESSION_KEPT, reg.notKept)
        assertEquals(0, newcomer.openFlows(), "the spent link's flow ended with its secret")
    }

    @Test fun setupLinksOnlyOnAComputerAndOnlyBeforeCardZero() = runBlocking<Unit> {
        val crypto = crypto
        val server = LinkServer(crypto, FakeInstance(crypto, withCard = false))
        val secret = ByteArray(32) { 4 }
        val keys = io.silencelen.andvari.core.trust.Links.deriveKeys(crypto, secret)
        val offer = io.silencelen.andvari.core.trust.LinkOffer.encodeSetup(io.silencelen.andvari.core.trust.SetupOfferFields(
            keys.linkId, server.instance.origin, server.instance.instanceId, "Family", io.silencelen.andvari.core.trust.InstanceKind.PRIVATE, null,
            server.instance.now + hour))
        server.rows[keys.linkId] = LinkServer.Row(keys.linkId, "setup", Bytes.toB64(io.silencelen.andvari.core.trust.LinkOffer.seal(crypto, keys, offer)),
            server.instance.now + hour, null, null, null)
        val url = io.silencelen.andvari.core.trust.LinkUrl.compose(server.instance.origin, secret, null)!!
        fun engine(state: MemoryDeviceState, computer: Boolean) = WireLinkFlows({ server.client(null) }, server.instance.trust(state), state, crypto,
            { server.instance.now }, { null }, computer)
        assertEquals(RecipientStep.Stopped(LinkStop.SETUP_ON_PHONE), engine(MemoryDeviceState(), false).open(url, GateEntry.PASTE_INVITE))
        val desk = engine(MemoryDeviceState(), true)
        val confirm = assertIs<RecipientStep.Confirm>(desk.open(url, GateEntry.PASTE_INVITE))
        assertEquals("Family", confirm.offer.instanceName)
        assertNotNull(desk.resolve(confirm))
        // Once the instance serves a card, a setup link is already_set_up.
        server.instance.cards += FakeInstance(crypto).cards[0]
        assertEquals(RecipientStep.Stopped(LinkStop.ALREADY_SET_UP), desk.open(url, GateEntry.PASTE_INVITE))
    }

    @Test fun contactsAreCurrentOnlyByThisDevicesOwnRecords() = runBlocking<Unit> {
        val (a, b) = pair()
        connected(a, b)
        // A contact written into account state by another holder of the UVK is not current here.
        val eve = "55555555-5555-4555-8555-555555555555"
        val eveKey = Bytes.toB64(ByteArray(32) { 8 })
        a.store.doc = a.store.doc.copy(contacts = a.store.doc.contacts + (eve to ContactRecord(eve, eveKey, TrustGrammar.encodeName("Eve")!!, verifiedAt = 2, compared = true, madeOn = "web")))
        val book = AccountContactBook(a.account, ContactCurrency(a.state, crypto, a.account.origin, alice), passwordOnly = true, clock = { a.server.instance.now })
        assertNotNull(book.currentFor(bob, b.identityPubB64))
        assertNull(book.currentFor(eve, eveKey))
        assertNull(book.currentFor(bob, eveKey), "a label follows the key")
        val prompt = book.prompts().single()
        assertEquals("Eve", prompt.labelText)
        // The one-tap list is due once on a password-only device; unticked people stay not current.
        assertTrue(book.oneTapListDue())
        assertTrue(book.confirmOneTap(emptySet()))
        assertFalse(book.oneTapListDue())
        assertNull(book.currentFor(eve, eveKey))
        // A prompt whose record changed meanwhile is refused.
        val saved = a.store.doc
        a.store.doc = saved.copy(contacts = saved.contacts + (eve to saved.contacts.getValue(eve).copy(identityPub = Bytes.toB64(ByteArray(32) { 6 }))))
        assertFalse(book.confirmHere(prompt))
        a.store.doc = saved
        assertTrue(book.confirmHere(prompt))
        assertEquals(Currency.CONFIRMED, book.currentFor(eve, eveKey)!!.current)
        assertTrue(book.prompts().isEmpty())
        assertTrue(book.remove(eve))
        assertNull(a.store.doc.contacts[eve])
        assertNull(book.currentFor(eve, eveKey))
    }
}
