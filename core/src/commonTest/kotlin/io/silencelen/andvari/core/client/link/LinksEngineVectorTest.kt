package io.silencelen.andvari.core.client.link

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.pin.CardPin
import io.silencelen.andvari.core.client.pin.CardTrust
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.client.pin.TrustCardChainVerifier
import io.silencelen.andvari.core.client.state.AccountDocument
import io.silencelen.andvari.core.client.state.ContactRecord
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.InstanceResponse
import io.silencelen.andvari.core.model.wire.LinkRevealRequest
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.TrustGrammar
import io.silencelen.andvari.core.trust.b64
import io.silencelen.andvari.core.trust.l
import io.silencelen.andvari.core.trust.o
import io.silencelen.andvari.core.trust.oOrNull
import io.silencelen.andvari.core.trust.rows
import io.silencelen.andvari.core.trust.s
import io.silencelen.andvari.core.trust.sOrNull
import io.silencelen.andvari.core.trust.strings
import io.silencelen.andvari.core.trust.vector
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Grades the link ENGINE ([WireLinkFlows]) on `spec/test-vectors/links.json`: every recipient row is opened through
 * [WireLinkFlows.open] against a server that answers exactly as the row says, with the row's card chain, this device's
 * pin and the account's contacts; every creator row is processed through [WireLinkFlows.processAnswers] with the row's
 * device records. The first stop must be the row's verdict; on `ok` the engine must have pinned the row's card, named
 * the row's creator, raised the key-change prompt exactly when the row says, and (creator) fixed the row's code.
 */
class LinksEngineVectorTest {
    private val crypto = createCryptoProvider()
    private val v = vector("links.json")
    private val origin = v.s("origin")
    private val accounts = v.o("accounts")
    private val cardChains: Map<String, List<String>> = v.o("cardChains").entries.associate { (k, f) -> k to f.jsonArray.strings() }

    private fun keysOf(name: String) = accounts.o(name).b64("seedB64").let { crypto.boxKeypairFromSeed(it) to crypto.signKeypairFromSeed(it) }

    private fun accountFor(name: String, contacts: JsonObject): LinkAccount {
        val (identity, signing) = keysOf(name)
        val doc = AccountDocument.EMPTY.copy(contacts = contacts.entries.associate { (id, key) ->
            id to ContactRecord(id, key.jsonPrimitive.content, TrustGrammar.encodeName("Known")!!, verifiedAt = 1, compared = false, madeOn = "elsewhere")
        })
        return LinkAccount(origin, "$name@example.org", accounts.o(name).s("userId"), "dddddddd-dddd-4ddd-8ddd-dddddddddddd", name,
            ByteArray(32) { 1 }, identity, signing, MemoryAccountState(doc))
    }

    /** A server that answers one row: GET /links/{id} as the row says, GET /instance with the row's chain, and the creator routes. */
    private class RowServer(override val origin: String, val fetch: WireResult<String>?, val cards: List<String>, val answers: String = "[]") : WireClient {
        val reveals = ArrayList<String>()
        val calls = ArrayList<WireRoute>()

        @Suppress("UNCHECKED_CAST")
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            calls += route
            return when (route) {
                WireRoute.LINK_FETCH -> when (val f = fetch!!) {
                    is WireResult.Ok -> WireResult.Ok(decode(f.value), 200)
                    else -> f as WireResult<T>
                }
                WireRoute.INSTANCE -> WireResult.Ok(decode(WireJson.json.encodeToString(InstanceResponse.serializer(), InstanceResponse(cards, emptyList()))), 200)
                WireRoute.LINK_ANSWERS -> WireResult.Ok(decode(answers), 200)
                WireRoute.LINK_REVEAL -> {
                    reveals += WireJson.json.decodeFromString(LinkRevealRequest.serializer(), bodyJson!!).nonce
                    WireResult.Ok(decode("{}"), 200)
                }
                WireRoute.LINK_ACK -> WireResult.Ok(decode("{}"), 200)
                // A signed-out connect asks whether the instance takes accounts (§6.7): this one does.
                WireRoute.CLIENT_POLICY -> WireResult.Ok(decode(WireJson.json.encodeToString(io.silencelen.andvari.core.model.wire.ClientPolicy.serializer(),
                    io.silencelen.andvari.core.model.wire.ClientPolicy(emptyMap(), io.silencelen.andvari.core.crypto.KdfParams(), 300, 30, true, 3600, 30, 1, 2, 3,
                        io.silencelen.andvari.core.model.wire.SignupPolicy(io.silencelen.andvari.core.model.wire.SignupMode.OPEN, false, true, 20), false, "andvari", origin, null))), 200)
                else -> WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
            }
        }
    }

    private fun fetchOf(server: JsonObject): WireResult<String> = when (val status = server.l("status")) {
        200L -> WireResult.Ok(server.o("body").toString(), 200)
        404L -> WireResult.Refused(404, WireError("link_unknown", "x"))
        410L -> WireResult.Refused(410, WireError("link_expired", "x"))
        else -> error("status $status")
    }

    @Test
    fun recipient_theEngineStopsAtEachRowsVerdictAndPinsOnlyOnOk() = runBlocking<Unit> {
        val rows = v.rows("recipient")
        assertTrue(rows.size >= 58)
        var originMismatchSteps = 0
        for (r in rows) {
            val name = r.s("name")
            val expect = r.o("expect")
            val server = RowServer(origin, if (r.s("link").let { io.silencelen.andvari.core.trust.LinkUrl.parse(it) } == null) null else fetchOf(r.o("server")), cardChains.getValue(r.s("cards")))
            val state = MemoryDeviceState()
            // A row's `baked` is the build's baked public instance (§4.4): at that origin the baked root comes first.
            val baked = r.oOrNull("baked")?.let { b -> io.silencelen.andvari.core.client.pin.BakedInstance(b.s("origin"), b.s("instanceId"), b.s("card0Hash"), b.s("kind")) }
            val trust = CardTrust(PinStore(state), TrustCardChainVerifier(crypto), { server }, crypto, baked, false)
            // The link's own origin: the file's, or (rows with `baked`) the baked one. A pin this device holds is for it, and at
            // the baked origin a build's pin is a baked one.
            val dialed = io.silencelen.andvari.core.trust.LinkUrl.parse(r.s("link"))?.origin ?: origin
            val atBaked = baked != null && dialed == baked.origin
            r.oOrNull("pin")?.let { p ->
                // The pin's root: the row's `pin.root` when it names one (a later vector batch), else baked at the baked origin.
                val root = p.sOrNull("root")?.let { code -> PinRoot.entries.first { it.code == code } } ?: if (atBaked) PinRoot.BAKED else PinRoot.TRUST_GATE
                PinStore(state).put(CardPin(if (atBaked) baked!!.instanceId else v.s("instanceId"), p.l("seq"), p.s("hash"), dialed, "Pinned",
                    if (atBaked) baked!!.kind else "private", "99999999-9999-4999-8999-999999999999",
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "none", root, null, p.s("card0Hash")))
            }
            // Bob is signed in at the file's origin; a link to another origin (an enrol link to the baked instance) is opened signed out.
            val bob = accountFor("bob", r.o("contacts")).takeIf { dialed == origin }
            val engine = WireLinkFlows({ server }, trust, state, crypto, { r.l("now") }, { bob }, setupAllowed = true)
            val step = engine.open(r.s("link"), GateEntry.SCAN_INVITE)
            val verdict = when (step) {
                is RecipientStep.Stopped -> step.cardVerdict ?: step.reason.code
                is RecipientStep.OriginMismatch -> {
                    // The step carries both addresses: the dialed one and the other one the served card names.
                    assertEquals(dialed, step.dialedOrigin, "$name: the dialed origin")
                    assertTrue(step.cardOrigin != dialed && step.cardOrigin.isNotEmpty(), "$name: the card's origin")
                    originMismatchSteps++
                    step.reason.code
                }
                is RecipientStep.Confirm, is RecipientStep.KeyChanged, is RecipientStep.TrustGate -> "ok"
                else -> "unexpected ${step::class.simpleName}"
            }
            assertEquals(expect.s("verdict"), verdict, name)
            if (verdict != "ok") {
                // A stop ends the flow (an origin mismatch too, which carries no token): the link's secret is not held.
                assertEquals(0, engine.openFlows(), "$name: a stopped flow is ended")
                assertTrue(server.calls.none { it == WireRoute.LINK_ANSWER }, "$name: nothing is sent")
                if (r.oOrNull("pin") == null) assertNull(trust.pinFor(dialed), "$name: nothing is pinned on a stop")
                continue
            }
            // The optional `expect.pinRoot`: the root the pin records after an `ok`.
            expect.sOrNull("pinRoot")?.let { assertEquals(it, trust.pinFor(dialed)?.root?.code, "$name: the pin's root") }
            val kind = expect.s("kind")
            when (step) {
                is RecipientStep.Confirm -> assertEquals(kind, step.offer.kind, name)
                is RecipientStep.KeyChanged -> assertEquals(kind, step.offer.kind, name)
                is RecipientStep.TrustGate -> assertEquals("enrol", kind, "$name: only an enrol link asks the Trust Gate")
                else -> {}
            }
            if (baked != null && io.silencelen.andvari.core.trust.LinkUrl.parse(r.s("link"))?.origin == baked.origin) {
                // At the baked origin no Trust Gate shows, and the pin's root is the baked one (a password pin).
                assertTrue(step !is RecipientStep.TrustGate, "$name: the baked root shows no Trust Gate")
                assertEquals(PinRoot.BAKED, trust.pinFor(baked.origin)?.root, "$name: pinned through the baked root")
            }
            if (kind == "connect" || kind == "register") {
                assertEquals(expect["keyChanged"]!!.jsonPrimitive.boolean, step is RecipientStep.KeyChanged, name)
                val view = (step as? RecipientStep.Confirm)?.offer ?: (step as RecipientStep.KeyChanged).offer
                assertEquals(expect.s("from"), view.creatorUserId, name)
                assertEquals(expect.s("name"), TrustGrammar.encodeName(view.creatorName!!), name)
                val pin = trust.pinFor(dialed)!!
                assertEquals(expect.o("pinned").l("seq"), pin.seq, name)
                assertEquals(expect.o("pinned").s("hash"), pin.hash, name)
            } else if (!(atBaked && kind == "enrol")) {
                // Host-minted offers are no pin root: setup pins nothing; enrol only through the Trust Gate (at the baked
                // origin an enrol link takes the baked root instead, checked above).
                if (r.oOrNull("pin") == null) assertNull(trust.pinFor(dialed), name)
            }
        }
        assertTrue(originMismatchSteps > 0, "some row stops at the first pin's origin_mismatch, carrying both addresses")
    }

    @Test
    fun creator_theEngineProcessesEachRowToItsVerdictAndCode() = runBlocking<Unit> {
        val rows = v.rows("creator")
        assertTrue(rows.size >= 20)
        for (r in rows) {
            val name = r.s("name")
            val expect = r.o("expect")
            val served = r.o("served")
            val server = RowServer(origin, null, emptyList(), "[" + served.toString() + "]")
            val state = MemoryDeviceState()
            val me = accountFor(r.s("me"), r.o("contacts"))
            val store = LinkRecordStore(state, crypto, origin, me.userId)
            for ((id, rec) in r.o("records")) {
                rec as JsonObject
                store.put(me.uvk, LinkRecord(id, rec.s("secretB64"), rec.s("nonceAB64"), rec.s("kind"), rec.s("offerHash"), rec.l("expiresAt"),
                    emptyList(), "", 0))
            }
            val trust = CardTrust(PinStore(state), TrustCardChainVerifier(crypto), { server }, crypto, null, false)
            val engine = WireLinkFlows({ server }, trust, state, crypto, { r.l("now") }, { me }, setupAllowed = false)
            val step = engine.processAnswers().single()
            val before = (me.store as MemoryAccountState).doc
            when (step) {
                is CreatorStep.Ignored -> {
                    assertEquals(expect.s("verdict"), step.reason, name)
                    assertTrue(server.reveals.isEmpty(), "$name: no reveal")
                    assertEquals(r.o("contacts").size, before.contacts.size, "$name: nothing pinned")
                    assertNull(store.get(me.uvk, served.s("linkId")), "$name: the link's record is dropped")
                    assertEquals(r.o("records").keys - served.s("linkId"), store.all(me.uvk).map { it.linkId }.toSet(), "$name: other records stay")
                }
                is CreatorStep.Processed, is CreatorStep.KeyChanged -> {
                    assertEquals(expect.s("verdict"), "ok", name)
                    val from = expect.s("from")
                    assertEquals(expect["keyChanged"]!!.jsonPrimitive.boolean, step is CreatorStep.KeyChanged, name)
                    // The creating device shows the creator's code (§2.3, §6.11): the row's `code.shows`.
                    val code = expect.o("code")
                    assertEquals(code.s("shows"), engine.code(from), name)
                    assertEquals(code.s("shows"), assertIs<CompareState.Ready>(engine.compareState(from)).code, name)
                    // It accepts only `code.accepts`, the answerer's code; its own is a plain no unless the two happen to be equal.
                    if (code.s("shows") != code.s("accepts")) assertEquals(CompareResult.Mismatch, engine.typeCode(from, code.s("shows")), name)
                    assertEquals(CompareResult.Matched, engine.typeCode(from, code.s("accepts")), name)
                    assertEquals(listOf(r.o("records").o(served.s("linkId")).s("nonceAB64")), server.reveals, "$name: nonceA is revealed")
                    assertTrue(store.all(me.uvk).isEmpty(), "$name: the secret is deleted")
                    val pinned = before.contacts.getValue(from)
                    if (step is CreatorStep.Processed) {
                        assertEquals(expect.s("fromKey"), pinned.identityPub, name)
                        assertEquals(expect.s("name"), pinned.label, name)
                        assertEquals(false, pinned.compared, name)
                    } else {
                        assertEquals(r.o("contacts").s(from), pinned.identityPub, "$name: nothing replaced")
                    }
                }
                else -> error("$name: ${step::class.simpleName}")
            }
        }
    }

    @Test
    fun typedCode_theEngineAcceptsExactlyTheRowsTypedInput() = runBlocking<Unit> {
        // Every row (and every row a later revision adds): this device's comparison record holds the row's fixed inputs,
        // the person types the row's text into the row's side, and only an accepted entry sets compared (§6.11, T2-R-i).
        val rows = v.rows("typedCode")
        assertTrue(rows.isNotEmpty())
        for (r in rows) {
            val why = r.s("why")
            val side = assertNotNull(io.silencelen.andvari.core.trust.LinkSide.fromCode(r.s("typedInto")), why)
            val state = MemoryDeviceState()
            val me = accountFor(if (side == io.silencelen.andvari.core.trust.LinkSide.CREATOR) "alice" else "bob", JsonObject(emptyMap()))
            val peer = "33333333-3333-4333-8333-333333333333"
            val nonceA = r.s("nonceAB64")
            val nonceB = r.s("nonceBB64")
            val own = io.silencelen.andvari.core.trust.ComparisonCode.link(crypto, side, r.s("linkId"), r.s("offerHash"), r.s("answerHash"), Bytes.fromB64(nonceA), Bytes.fromB64(nonceB))
            CodeRecordStore(state, origin, me.userId).put(CodeRecord(
                linkId = r.s("linkId"), role = side.code, contactUserId = peer, contactKey = Bytes.toB64(ByteArray(32) { 4 }),
                label = TrustGrammar.encodeName("Peer")!!, offerHash = r.s("offerHash"), answerHash = r.s("answerHash"), nonceB = nonceB,
                nonceA = nonceA, code = own, at = 1,
            ))
            val server = RowServer(origin, null, emptyList())
            val trust = CardTrust(PinStore(state), TrustCardChainVerifier(crypto), { server }, crypto, null, false)
            val engine = WireLinkFlows({ server }, trust, state, crypto, { 2 }, { me }, setupAllowed = false)
            assertEquals(own, engine.code(peer), "$why: the app shows its own side's code")
            val result = engine.typeCode(peer, r.s("typed"))
            if (r.o("expect")["accepted"]!!.jsonPrimitive.boolean) {
                assertEquals(CompareResult.Matched, result, why)
                assertTrue((me.store as MemoryAccountState).doc.contacts.getValue(peer).compared, why)
            } else {
                assertEquals(CompareResult.Mismatch, result, "$why: a plain no, and the person may type again")
                assertTrue((me.store as MemoryAccountState).doc.contacts[peer]?.compared != true, why)
                assertIs<CompareState.Ready>(engine.compareState(peer), "$why: nothing changed")
            }
        }
    }
}
