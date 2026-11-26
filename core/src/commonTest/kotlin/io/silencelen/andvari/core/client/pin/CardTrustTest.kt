package io.silencelen.andvari.core.client.pin

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.InstanceResponse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The chain rules and pin store of design §4.4 against a fake card verifier: a "frame" here is the card's
 * fields joined by `|`, and its hash is the frame text itself padded to 64 hex characters.
 */
class CardTrustTest {
    private val crypto = createCryptoProvider()
    private val inst = "0b6f3c2e-4d5a-4b7c-8d9e-0f1a2b3c4d5e"
    private val op = "1c7f4d3e-5e6b-4c8d-9e0f-1a2b3c4d5e6f"
    private val opKey = Bytes.toB64(crypto.signKeypairFromSeed(ByteArray(32) { 7 }).publicKey)
    private val home = "https://home.example"
    private val moved = "https://new.example"

    private fun h(tag: String) = (tag.encodeToByteArray().joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') } + "0".repeat(64)).take(64)
    private fun card(seq: Long, tag: String, origin: String = home, kind: String = "private", instanceId: String = inst) =
        VerifiedCard(seq, h(tag), instanceId, origin, "Home", kind, op, opKey, "none")

    private fun frameOf(c: VerifiedCard) = Bytes.toB64(listOf(c.seq, c.hash, c.instanceId, c.origin, c.name, c.kind, c.operator, c.operatorSignKey, c.recoveryFp).joinToString("|").encodeToByteArray())

    /** The root checks of design §2.4 over the fake chain (production binds the shared verifiers'; see [realChainThroughTheSharedVerifiers]). */
    private fun rootsOf(cards: List<VerifiedCard>) = object : RootChecks {
        override fun typed(dialedOrigin: String): String? = if (cards.last().origin != dialedOrigin) "origin_mismatch" else null
        override fun baked(dialedOrigin: String, card0Hash: String, instanceId: String): String? = when {
            cards.isEmpty() -> "withheld"
            cards.last().origin != dialedOrigin -> "origin_mismatch"
            cards[0].hash != card0Hash -> "card0_mismatch"
            cards[0].instanceId != instanceId -> "instance_mismatch"
            else -> null
        }
        override fun kit(dialedOrigin: String, card0Hash: String): String? = if (cards.isEmpty()) "withheld" else if (cards.last().origin != dialedOrigin) "origin_mismatch" else if (cards[0].hash != card0Hash) "card0_mismatch" else null
        override fun offer(dialedOrigin: String, cardHash: String, instanceId: String): String? {
            if (cards.last().origin != dialedOrigin) return "origin_mismatch"
            val c = cards.firstOrNull { it.hash == cardHash } ?: return "card_not_in_chain"
            return if (c.instanceId != instanceId) "instance_mismatch" else null
        }
    }

    private val verifier = CardChainVerifier { frames, _ ->
        val cards = frames.map { f ->
            val p = f.decodeToString().split("|")
            VerifiedCard(p[0].toLong(), p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8])
        }
        ChainCheck.Ok(cards, rootsOf(cards))
    }

    private class FakeClient(override val origin: String, var cards: List<String>?) : WireClient {
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            check(route == WireRoute.INSTANCE)
            val c = cards ?: return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
            return WireResult.Ok(decode(WireJson.json.encodeToString(InstanceResponse.serializer(), InstanceResponse(c, emptyList()))), 200)
        }
    }

    private val servers = HashMap<String, FakeClient>()
    private fun serve(origin: String, vararg cards: VerifiedCard) { servers.getOrPut(origin) { FakeClient(origin, null) }.cards = cards.map(::frameOf) }
    private fun trust(state: MemoryDeviceState = MemoryDeviceState(), baked: BakedInstance? = null, storeBuild: Boolean = false) =
        CardTrust(PinStore(state), verifier, { o -> servers.getOrPut(o) { FakeClient(o, null) } }, crypto, baked, storeBuild)

    @Test fun trustGatePinsExactlyTheChainShownAndRefreshAdvances() = runBlocking<Unit> {
        serve(home, card(0, "c0"), card(1, "c1"))
        val t = trust()
        val gate = assertIs<FirstPin.NeedsTrustGate>(t.beginTrustGate(home, TrustGateWording.TYPED_ADDRESS))
        assertEquals(32, gate.operatorShortFp.length)
        assertNull(t.pinFor(home), "nothing pinned before the person confirms")
        serve(home, card(0, "c0"), card(1, "c1"), card(2, "c2"))
        val pinned = assertIs<FirstPin.Pinned>(t.confirmTrustGate(gate.confirm)).pin
        assertEquals(1, pinned.seq, "the confirmed pin is the chain that was shown")
        assertEquals(PinRoot.TRUST_GATE, pinned.root)
        val ok = assertIs<CardStatus.Ok>(t.refresh(home))
        assertEquals(2, ok.pin.seq)
        assertEquals(h("c0"), ok.pin.card0Hash)
    }

    private suspend fun gatePinned(t: CardTrust, origin: String = home) =
        assertIs<FirstPin.Pinned>(t.confirmTrustGate(assertIs<FirstPin.NeedsTrustGate>(t.beginTrustGate(origin, TrustGateWording.TYPED_ADDRESS)).confirm))

    @Test fun withheldAndDurableFork() = runBlocking<Unit> {
        val state = MemoryDeviceState()
        serve(home, card(0, "c0"), card(1, "c1"))
        val t = trust(state)
        gatePinned(t)
        serve(home, card(0, "c0"))
        assertIs<CardStatus.Withheld>(t.refresh(home))
        serve(home)
        assertIs<CardStatus.Withheld>(t.refresh(home), "an empty chain while pinned is withholding")
        serve(home, card(0, "c0"), card(1, "other"))
        assertIs<CardStatus.Fork>(t.refresh(home))
        serve(home, card(0, "c0"), card(1, "c1"), card(2, "c2"))
        assertIs<CardStatus.Fork>(t.refresh(home), "a fork is durable: a later good chain does not clear it")
        val restarted = trust(state)
        assertIs<PinState.Forked>(restarted.pinState(home), "and survives a restart")
        assertNull(restarted.pinFor(home))
        assertTrue(restarted.gatePins().single().blocked)
        val gate = PasswordGate.decide(GateInput(GatePurpose.SIGN_IN, GateEntry.SERVER_CHOICE, null, home, "a@x.example", restarted.gatePins()))
        assertEquals(GateDecision.REFUSE_ENTRY, gate, "the gate refuses a forked origin")
        assertIs<PinState.Forked>(assertIs<FirstPin.Blocked>(restarted.beginTrustGate(home, TrustGateWording.TYPED_ADDRESS)).state)
        assertEquals("fork", assertIs<FirstPin.Blocked>(restarted.pinFromKit(home, h("c0"), "a@x.example")).verdict)
        restarted.forget(home)
        assertEquals(PinState.None, restarted.pinState(home), "forget is the only way on")
    }

    @Test fun operatorResetIsAForkAtOnce() = runBlocking<Unit> {
        serve(home, card(0, "c0"), card(1, "c1"))
        val t = trust()
        gatePinned(t)
        serve(home, card(0, "reset"), card(1, "r1"), card(2, "r2"), card(3, "r3"))
        assertIs<CardStatus.Fork>(t.refresh(home), "a new card 0 is a fork however long the new chain")
    }

    @Test fun kindChangeWithAMoveIsAKindChangeFirst() = runBlocking<Unit> {
        serve(home, card(0, "c0"), card(1, "c1"))
        val t = trust()
        gatePinned(t)
        serve(home, card(0, "c0"), card(1, "c1"), card(2, "c2", origin = moved, kind = "public"))
        serve(moved, card(0, "c0"), card(1, "c1"), card(2, "c2", origin = moved, kind = "public"))
        val k = assertIs<CardStatus.KindChanged>(t.refresh(home), "origin and kind changed: the kind gate, never one move tap")
        assertEquals("private", t.pinFor(home)!!.kind, "the old kind stays until confirmed")
        val m = assertIs<CardStatus.Moved>(t.acceptKindChange(k), "then the move is its own prompt")
        assertEquals("public", t.pinFor(home)!!.kind)
        assertTrue(assertIs<CardStatus.Ok>(t.followMove(m)).newKitDue, "after a move the person makes a new kit (design §4.4)")
        assertTrue(!assertIs<CardStatus.Ok>(t.refresh(moved)).newKitDue, "only the move's own answer carries the flag")
        assertNull(t.pinFor(home))
        assertEquals(moved, t.pinFor(moved)!!.origin)
        servers.getValue(moved).cards = null
        assertIs<CardStatus.Unreachable>(t.refresh(moved))
        assertEquals(2, t.pinFor(moved)!!.seq)
    }

    @Test fun aMoveNeverReplacesAnotherOriginsPin() = runBlocking<Unit> {
        serve(home, card(0, "c0"))
        serve(moved, card(0, "m0", origin = moved))
        val t = trust()
        gatePinned(t)
        gatePinned(t, moved)
        serve(home, card(0, "c0"), card(1, "c1", origin = moved))
        val m = assertIs<CardStatus.Moved>(t.refresh(home))
        assertEquals(PIN_CONFLICT, assertIs<CardStatus.PinConflict>(t.followMove(m)).verdict)
        assertEquals(h("m0"), t.pinFor(moved)!!.card0Hash, "the other origin's pin is untouched")
    }

    @Test fun originMismatchIsTheFirstPinningVerdictAndTyped() = runBlocking<Unit> {
        // A look-alike address serves the real instance's genuine chain: no root may pin it there.
        val look = "https://h0me.example"
        serve(look, card(0, "c0"), card(1, "c1"))
        val t = trust()
        for (r in listOf(
            t.beginTrustGate(look, TrustGateWording.TYPED_ADDRESS),
            t.pinFromKit(look, h("c0"), "a@x.example"),
            t.pinFromLinkOffer(look, inst, h("c1")),
            t.pinFromKit(look, h("other"), "a@x.example"),
        )) {
            val m = assertIs<FirstPin.OriginMismatch>(r, "origin_mismatch comes before every root check")
            assertEquals(look, m.dialedOrigin)
            assertEquals(home, m.cardOrigin)
            assertEquals(ORIGIN_MISMATCH, m.verdict)
        }
        assertNull(t.pinFor(look))
        // The old address after a move, with no pin: origin_mismatch; dialing the named origin starts again there.
        serve(home, card(0, "c0"), card(1, "c1", origin = moved))
        serve(moved, card(0, "c0"), card(1, "c1", origin = moved))
        val om = assertIs<FirstPin.OriginMismatch>(t.pinFromKit(home, h("c0"), "a@x.example"))
        assertEquals(PinRoot.KIT, assertIs<FirstPin.Pinned>(t.pinFromKit(om.cardOrigin, h("c0"), "a@x.example")).pin.root, "the kit's card0Hash still anchors it")
        // An empty chain is withheld for every root, the typed address included.
        serve("https://empty.example")
        assertEquals("withheld", assertIs<FirstPin.Refused>(t.beginTrustGate("https://empty.example", TrustGateWording.TYPED_ADDRESS)).reason)
    }

    @Test fun aMoveUnderAnExistingPinIsHandledAsAMoveFirst() = runBlocking<Unit> {
        serve(home, card(0, "c0"))
        val t = trust()
        gatePinned(t)
        serve(home, card(0, "c0"), card(1, "c1", origin = moved))
        serve(moved, card(0, "c0"), card(1, "c1", origin = moved))
        for (r in listOf(t.pinFromLinkOffer(home, inst, h("c1")), t.pinFromKit(home, h("c0"), "a@x.example"), t.beginTrustGate(home, TrustGateWording.DEVICE_LINK))) {
            assertIs<CardStatus.Moved>(assertIs<FirstPin.PinChanged>(r, "not origin_mismatch: a move under a pin").status)
        }
        assertEquals(h("c0"), t.pinFor(home)!!.hash, "nothing changed until the move is followed")
        val m = assertIs<CardStatus.Moved>(assertIs<FirstPin.PinChanged>(t.pinFromKit(home, h("c0"), "a@x.example")).status)
        assertIs<CardStatus.Ok>(t.followMove(m))
        assertEquals(PinRoot.TRUST_GATE, assertIs<FirstPin.Pinned>(t.pinFromKit(moved, h("c0"), "a@x.example"), "opened again at the new origin").pin.root)
    }

    @Test fun pinConflictIsTyped() = runBlocking<Unit> {
        serve(home, card(0, "c0"), card(1, "c1"))
        val t = trust()
        val g = assertIs<FirstPin.NeedsTrustGate>(t.beginTrustGate(home, TrustGateWording.TYPED_ADDRESS))
        // Meanwhile another root pinned a different chain at this origin.
        val other = trust(MemoryDeviceState())
        val own = crypto.signKeypairFromSeed(ByteArray(32) { 7 })
        val pinned = assertIs<FirstPin.Pinned>(t.pinFromOwnCard0(home, frameOf(card(0, "x0")), op, "op@x.example", own.publicKey)).pin
        val conflict = assertIs<FirstPin.PinConflict>(t.confirmTrustGate(g.confirm))
        assertEquals(PIN_CONFLICT, conflict.verdict)
        assertEquals(pinned, conflict.pinned)
        assertEquals(pinned, t.pinFor(home), "the existing chain is never swapped")
        assertIs<FirstPin.PinConflict>(t.pinFromOwnCard0(home, frameOf(card(0, "y0")), op, "op@x.example", own.publicKey))
        assertNull(other.pinFor(home))
    }

    @Test fun firstPinPathsNeverSwapAnExistingChain() = runBlocking<Unit> {
        serve(home, card(0, "c0"), card(1, "c1"), card(2, "c2"))
        val t = trust()
        gatePinned(t)
        // The kit's card 0 matches, but the server serves a branch at seq 2, or a rollback to seq 1.
        serve(home, card(0, "c0"), card(1, "c1"), card(2, "evil"))
        assertIs<PinState.Forked>(assertIs<FirstPin.Blocked>(t.pinFromKit(home, h("c0"), "a@x.example")).state)
        val t2 = trust()
        serve(home, card(0, "c0"), card(1, "c1"), card(2, "c2"))
        gatePinned(t2)
        serve(home, card(0, "c0"), card(1, "c1"))
        assertEquals("withheld", assertIs<FirstPin.Refused>(t2.pinFromKit(home, h("c0"), "a@x.example")).reason)
        assertEquals(2, t2.pinFor(home)!!.seq)
        assertEquals(PinRoot.TRUST_GATE, t2.pinFor(home)!!.root, "a kit never lowers a password pin")
        serve(home, card(0, "c0"), card(1, "c1"), card(2, "c2"), card(3, "c3"))
        val kept = assertIs<FirstPin.Pinned>(t2.pinFromKit(home, h("c0"), "a@x.example"))
        assertEquals(3, kept.pin.seq)
        assertEquals(PinRoot.TRUST_GATE, kept.pin.root)
    }

    @Test fun dropOnlyThePinThisCallMade() = runBlocking<Unit> {
        serve(home, card(0, "c0"))
        val t = trust()
        val old = gatePinned(t)
        t.dropPinMade(assertIs<FirstPin.Pinned>(t.beginTrustGate(home, TrustGateWording.DEVICE_LINK)).handle)
        assertEquals(old.pin, t.pinFor(home), "a pin the device already had is never dropped")
        val fresh = trust()
        val made = gatePinned(fresh)
        fresh.dropPinMade(made.handle)
        assertNull(fresh.pinFor(home))
    }

    @Test fun aDamagedRecordBlocks() = runBlocking<Unit> {
        val state = MemoryDeviceState()
        state.set(PinStore.KEY_PREFIX + home, "{not a pin")
        serve(home, card(0, "c0"))
        val t = trust(state)
        assertEquals(PinState.Damaged, t.pinState(home))
        assertEquals(PinState.Damaged, assertIs<FirstPin.Blocked>(t.beginTrustGate(home, TrustGateWording.TYPED_ADDRESS)).state)
        state.set(PinStore.KEY_INDEX, "[\"$home\"]")
        assertTrue(t.gatePins().single().blocked)
        t.forget(home)
        gatePinned(t)
    }

    @Test fun setupPinOnlyFromThisDevicesOwnCard() = runBlocking<Unit> {
        val own = crypto.signKeypairFromSeed(ByteArray(32) { 7 })
        val c0 = card(0, "c0")
        val t = trust()
        val other = crypto.signKeypairFromSeed(ByteArray(32) { 9 }).publicKey
        assertEquals("not_own_card", assertIs<FirstPin.Refused>(t.pinFromOwnCard0(home, frameOf(c0), op, "op@x.example", other)).reason)
        val p = assertIs<FirstPin.Pinned>(t.pinFromOwnCard0(home, frameOf(c0), op, "op@x.example", own.publicKey)).pin
        assertEquals(PinRoot.SETUP, p.root)
        assertEquals("op@x.example", p.rootAccount, "the setup pin is limited to the operator's email, as the gate compares")
    }

    @Test fun bakedRootAndStoreBuilds() = runBlocking<Unit> {
        val b = BakedInstance(home, inst, h("c0"), "public")
        serve(home, card(0, "c0", kind = "public"))
        val t = trust(baked = b, storeBuild = true)
        val pin = assertIs<FirstPin.Pinned>(t.pinBaked(home)).pin
        assertEquals(PinRoot.BAKED, pin.root)
        serve(home, card(0, "c0", kind = "public"), card(1, "c1", origin = moved, kind = "public"))
        val m = assertIs<CardStatus.Moved>(t.refresh(home))
        assertTrue(m.storeBuildMustUpdate)
        assertIs<CardStatus.Moved>(t.followMove(m), "a store build never follows a move of the baked instance")
        assertEquals(home, t.pinFor(home)!!.origin)
        serve(home, card(0, "c0", kind = "public"), card(1, "c1", kind = "private"))
        assertTrue(assertIs<CardStatus.KindChanged>(t.refresh(home)).storeBuildMustUpdate)

        // Keyed on the instance, not the root: a public instance pinned through a kit is the baked instance too.
        val viaKit = trust(baked = b, storeBuild = true)
        serve(home, card(0, "c0", kind = "public"))
        assertEquals(PinRoot.BAKED, assertIs<FirstPin.Pinned>(viaKit.pinFromKit(home, h("c0"), "a@x.example")).pin.root, "the public origin takes the baked root")
        serve(home, card(0, "c0", kind = "public"), card(1, "c1", origin = moved, kind = "public"))
        assertTrue(assertIs<CardStatus.Moved>(viaKit.refresh(home)).storeBuildMustUpdate)

        val other = trust(baked = b, storeBuild = true)
        serve(home, card(0, "forged", kind = "public"))
        assertIs<FirstPin.Refused>(other.pinBaked(home))
        serve(home, card(0, "c0", kind = "public"), card(1, "c1", kind = "private"))
        assertEquals("update_required", assertIs<FirstPin.Refused>(other.pinBaked(home)).reason)
        // A typed address equal to the baked origin takes the baked root, never the gate.
        serve(home, card(0, "c0", kind = "public"))
        assertIs<FirstPin.Pinned>(other.beginTrustGate(home, TrustGateWording.TYPED_ADDRESS))
    }

    @Test fun aTrustGatePinAtTheBakedOriginBecomesBakedWhenTheBakedChecksPass() = runBlocking<Unit> {
        val state = MemoryDeviceState()
        serve(home, card(0, "c0", kind = "public"))
        // Made by a build that does not bake the instance.
        val gate = gatePinned(trust(state)).pin
        assertEquals(PinRoot.TRUST_GATE, gate.root)
        val b = BakedInstance(home, inst, h("c0"), "public")
        val pinned = assertIs<FirstPin.Pinned>(trust(state, baked = b).pinBaked(home)).pin
        assertEquals(PinRoot.BAKED, pinned.root, "design §4.4: the baked checks passing make the pin's root baked")
        assertEquals(PinRoot.BAKED, trust(state).pinFor(home)!!.root)

        // A Trust Gate pin on another card 0, extended by the served chain: the pin passes, the baked checks do not.
        val other = MemoryDeviceState()
        serve(home, card(0, "else", kind = "public"))
        gatePinned(trust(other))
        assertEquals("card0_mismatch", assertIs<FirstPin.Refused>(trust(other, baked = b).pinBaked(home)).reason)
        assertEquals(PinRoot.TRUST_GATE, trust(other).pinFor(home)!!.root)
    }

    @Test fun kitAndLinkOfferAnchors() = runBlocking<Unit> {
        serve(home, card(0, "c0"), card(1, "c1"))
        val t = trust()
        val kitPin = assertIs<FirstPin.Pinned>(t.pinFromKit(home, h("c0"), "a@x.example")).pin
        assertEquals(PinRoot.KIT, kitPin.root)
        assertEquals("a@x.example", kitPin.rootAccount)
        val t2 = trust()
        assertIs<FirstPin.KitAnchorMismatch>(t2.pinFromKit(home, h("old"), "a@x.example"))
        assertNull(t2.pinFor(home))
        val t3 = trust()
        assertIs<FirstPin.Refused>(t3.pinFromLinkOffer(home, inst, h("nope")))
        assertEquals("instance_mismatch", assertIs<FirstPin.Refused>(t3.pinFromLinkOffer(home, op, h("c1"))).reason, "the card is found, under another instanceId")
        assertEquals("card_not_in_chain", assertIs<FirstPin.Refused>(t3.pinFromLinkOffer(home, op, h("nope"))).reason, "card_not_in_chain comes first")
        serve("https://empty.example")
        assertEquals("withheld", assertIs<FirstPin.Refused>(trust().pinFromKit("https://empty.example", h("c0"), "a@x.example")).reason)
        serve(home, card(0, "c0"), card(1, "c1"))
        assertEquals(PinRoot.LINK_OFFER, assertIs<FirstPin.Pinned>(t3.pinFromLinkOffer(home, inst, h("c0"))).pin.root)
        // A later Trust Gate upgrades the link-offer pin to a password pin, keeping card 0.
        val g = assertIs<FirstPin.NeedsTrustGate>(t3.beginTrustGate(home, TrustGateWording.LINK_OFFER_SIGN_IN))
        assertEquals(PinRoot.TRUST_GATE, assertIs<FirstPin.Pinned>(t3.confirmTrustGate(g.confirm)).pin.root)
        // An enrol gate never downgrades it.
        val e = assertIs<FirstPin.Pinned>(t3.beginTrustGate(home, TrustGateWording.ENROL_LINK))
        assertEquals(PinRoot.TRUST_GATE, e.pin.root)
        assertTrue(!e.handle.madeNow)
    }

    /** The production binding: real card frames signed with the shared verifiers' code, verified and root-checked by it. */
    @Test fun realChainThroughTheSharedVerifiers() = runBlocking<Unit> {
        val signer = crypto.signKeypairFromSeed(ByteArray(32) { 7 })
        val name = "Home" // CardFields carries the decoded name; the shared verifiers' code encodes it into the statement
        fun fields(seq: Long, prev: String, origin: String = home) = io.silencelen.andvari.core.trust.CardFields(
            inst, seq, prev, origin, name, io.silencelen.andvari.core.trust.InstanceKind.PRIVATE, op, opKey, null, 1_763_164_800_000 + seq)
        val f0 = io.silencelen.andvari.core.trust.InstanceCard.sign(crypto, signer, fields(0, io.silencelen.andvari.core.trust.TrustGrammar.ZERO_HASH))
        val h0 = Bytes.toHexLower(crypto.sha256(f0))
        val f1 = io.silencelen.andvari.core.trust.InstanceCard.sign(crypto, signer, fields(1, h0))
        val real = object : WireClient {
            override val origin = home
            var frames = listOf(f0, f1)
            override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> =
                WireResult.Ok(decode(WireJson.json.encodeToString(InstanceResponse.serializer(), InstanceResponse(frames.map { Bytes.toB64(it) }, emptyList()))), 200)
        }
        val t = CardTrust(PinStore(MemoryDeviceState()), TrustCardChainVerifier(crypto), { real }, crypto, null, false)
        assertEquals("card0_mismatch", assertIs<FirstPin.KitAnchorMismatch>(t.pinFromKit(home, "f".repeat(64), "a@x.example")).let { "card0_mismatch" })
        val pin = assertIs<FirstPin.Pinned>(t.pinFromKit(home, h0, "a@x.example")).pin
        assertEquals(1, pin.seq)
        assertEquals("Home", pin.name)
        assertEquals("none", pin.recoveryFp)
        assertEquals("card_not_in_chain", assertIs<FirstPin.Refused>(trust().let { CardTrust(PinStore(MemoryDeviceState()), TrustCardChainVerifier(crypto), { real }, crypto, null, false) }.pinFromLinkOffer(home, inst, "e".repeat(64))).reason)
        real.frames = listOf(f0)
        assertIs<CardStatus.Withheld>(t.refresh(home))
        val forged = io.silencelen.andvari.core.trust.InstanceCard.sign(crypto, crypto.signKeypairFromSeed(ByteArray(32) { 9 }), fields(1, h0))
        real.frames = listOf(f0, forged)
        assertIs<CardStatus.Refused>(t.refresh(home), "a card not signed by the previous operator key is refused by the card chain's verifier")
    }

    /** An opened account of [userId] whose signing key comes from [seedByte] (seed 7 is [opKey]'s). */
    private fun opened(userId: String, seedByte: Int = 7): io.silencelen.andvari.core.client.onboard.OpenedAccount {
        val seed = ByteArray(32) { seedByte.toByte() }
        val identity = crypto.boxKeypairFromSeed(seed)
        val genesis = io.silencelen.andvari.core.trust.VerifiedGenesis(
            io.silencelen.andvari.core.trust.GenesisFields(userId, Bytes.toB64(identity.publicKey), inst, "v-personal", 0), "00".repeat(32))
        return io.silencelen.andvari.core.client.onboard.OpenedAccount(userId, ByteArray(32) { 1 }, identity, crypto.signKeypairFromSeed(seed), genesis, null, null)
    }

    /** Design §4.1, VR-11: the operator's own device verifies its chain against its own Ed25519 key, byte for byte. */
    @Test fun theSignedInAccountChecksTheOperatorKeyItsCardsName() = runBlocking<Unit> {
        val a = crypto.signKeypairFromSeed(ByteArray(32) { 7 })
        val b = crypto.signKeypairFromSeed(ByteArray(32) { 8 })
        fun fields(seq: Long, prev: String, key: String) = io.silencelen.andvari.core.trust.CardFields(
            inst, seq, prev, home, "Home", io.silencelen.andvari.core.trust.InstanceKind.PRIVATE, op, key, null, 1_763_164_800_000 + seq)
        val f0 = io.silencelen.andvari.core.trust.InstanceCard.sign(crypto, a, fields(0, io.silencelen.andvari.core.trust.TrustGrammar.ZERO_HASH, opKey))
        val h0 = Bytes.toHexLower(crypto.sha256(f0))
        // A card the previous key signs, naming this account as the operator under ANOTHER key: valid for everyone else.
        val f1 = io.silencelen.andvari.core.trust.InstanceCard.sign(crypto, a, fields(1, h0, Bytes.toB64(b.publicKey)))
        val real = object : WireClient {
            override val origin = home
            var frames = listOf(f0)
            override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> =
                WireResult.Ok(decode(WireJson.json.encodeToString(InstanceResponse.serializer(), InstanceResponse(frames.map { Bytes.toB64(it) }, emptyList()))), 200)
        }
        fun fresh() = CardTrust(PinStore(MemoryDeviceState()), TrustCardChainVerifier(crypto), { real }, crypto, null, false)
        val t = fresh()
        assertEquals(0, assertIs<FirstPin.Pinned>(t.pinFromKit(home, h0, "a@x.example")).pin.seq)
        t.signedIn(opened(op))
        assertIs<CardStatus.Ok>(t.refresh(home), "card 0 names this account with its own key")
        real.frames = listOf(f0, f1)
        assertEquals("operator_key_mismatch", assertIs<CardStatus.Refused>(t.refresh(home)).verdict)
        assertEquals(0, t.pinFor(home)!!.seq, "the pin stays where it was")
        // A first pin on the operator's device takes the same check.
        val first = fresh()
        first.signedIn(opened(op))
        assertEquals("operator_key_mismatch", assertIs<FirstPin.Refused>(first.pinFromKit(home, h0, "a@x.example")).reason)
        // Another account's device has no trustworthy copy of the key and does not check it; nor does a signed-out one.
        val other = fresh()
        other.signedIn(opened("2d8e5f4a-6f7c-4d9e-8f1a-2b3c4d5e6f70", seedByte = 9))
        assertEquals(1, assertIs<FirstPin.Pinned>(other.pinFromKit(home, h0, "a@x.example")).pin.seq)
        t.signedOut()
        assertEquals(1, assertIs<CardStatus.Ok>(t.refresh(home)).pin.seq)
    }

    @Test fun pinsSurviveInDeviceStateAndForgetRemoves() = runBlocking<Unit> {
        val state = MemoryDeviceState()
        serve(home, card(0, "c0"))
        val t = trust(state)
        gatePinned(t)
        assertEquals(t.pinFor(home), trust(state).pinFor(home))
        assertEquals(1, trust(state).pins().size)
        t.forget(home)
        assertNull(trust(state).pinFor(home))
        assertEquals(0, trust(state).pins().size)
    }

    @Test fun aVerifiedCardNamingAnOperatorKeyWithNoX25519ImageIsRefusedAtTheTrustGate() = runBlocking<Unit> {
        // Card 1 is properly signed by card 0's key, but names a small-order point as the next operator key: the chain
        // verifies, and no operator fingerprint can be shown for it, so the gate refuses instead of throwing.
        val instance = io.silencelen.andvari.core.client.onboard.FakeInstance(crypto)
        val c0 = instance.cards[0]
        val card0 = (io.silencelen.andvari.core.trust.InstanceCard.parse(crypto, c0) as io.silencelen.andvari.core.trust.Checked.Ok).value.fields
        instance.cards += io.silencelen.andvari.core.trust.InstanceCard.sign(crypto, instance.operatorSign,
            card0.copy(seq = 1, prev = io.silencelen.andvari.core.trust.SignedFrame.hash(crypto, c0), operatorSignKey = Bytes.toB64(ByteArray(32)), issuedAt = card0.issuedAt + 1))
        assertNull(io.silencelen.andvari.core.trust.InstanceCard.verifyChain(crypto, instance.cards).verdict, "the chain itself verifies")
        assertNull(io.silencelen.andvari.core.trust.InstanceCard.operatorIdentityKey(crypto, Bytes.toB64(ByteArray(32))))
        val t = instance.trust(MemoryDeviceState())
        assertEquals(FirstPin.Refused(BAD_OPERATOR_KEY), t.beginTrustGate(instance.origin, TrustGateWording.TYPED_ADDRESS))
        assertNull(t.pinFor(instance.origin), "nothing pinned")
        assertEquals(FirstPin.Refused(BAD_OPERATOR_KEY), t.pinFromKit(instance.origin, "ab".repeat(32), "alice@example.com"))
    }

    // ---- design §4.4 "Rules for the pin store", written 2026-11-15 ----

    private fun movedChain() {
        serve(home, card(0, "c0"), card(1, "c1", origin = moved))
        serve(moved, card(0, "c0"), card(1, "c1", origin = moved))
    }

    @Test fun aMoveCarriesEveryPerOriginTrustRecordAndResetsNone() = runBlocking<Unit> {
        val state = MemoryDeviceState()
        serve(home, card(0, "c0"))
        val t = trust(state)
        gatePinned(t)
        val records = PinStore.ORIGIN_KEYED.associate { p -> "$p$home|u1" to "value of $p" } + ("ovh.setup|$home" to "offer")
        records.forEach { (k, v) -> state.set(k, v) }
        // Another origin that merely starts with the same text, and the account's own records (keyed by userId), stay.
        state.set("ovh.dev|$home.evil|u1", "theirs")
        state.set("ovh.acct|u1|hw", "7")
        movedChain()
        val m = assertIs<CardStatus.Moved>(t.refresh(home))
        assertIs<CardStatus.Ok>(t.followMove(m))
        for ((k, v) in records) {
            assertNull(state.get(k), "$k: the old namespace is removed")
            assertEquals(v, state.get(k.replaceFirst("|$home", "|$moved")), "$k: carried as it was")
        }
        assertEquals("theirs", state.get("ovh.dev|$home.evil|u1"))
        assertEquals("7", state.get("ovh.acct|u1|hw"), "a mark is never reset")
        assertEquals(PinState.None, t.pinState(home))
    }

    @Test fun aMoveThatWouldReplaceARecordAtTheNewOriginTouchesNothing() = runBlocking<Unit> {
        val state = MemoryDeviceState()
        serve(home, card(0, "c0"))
        val t = trust(state)
        gatePinned(t)
        state.set("ovh.dev|$home|a@x.example", "mine")
        state.set("ovh.dev|$moved|a@x.example", "already there")
        movedChain()
        val m = assertIs<CardStatus.Moved>(t.refresh(home))
        assertEquals(PIN_CONFLICT, assertIs<CardStatus.PinConflict>(t.followMove(m)).verdict)
        assertEquals(h("c0"), t.pinFor(home)!!.card0Hash, "the old pin is untouched")
        assertEquals(PinState.None, t.pinState(moved))
        assertEquals("mine", state.get("ovh.dev|$home|a@x.example"))
        assertEquals("already there", state.get("ovh.dev|$moved|a@x.example"))
    }

    // ---- what a followed move carries can be opened at the new origin ----

    private fun linkRecord(id: String) = io.silencelen.andvari.core.client.link.LinkRecord(id, "s", "n", "connect", "h", 9_999_999_999_999, emptyList(), "u", 1)

    @Test fun linkRecordsAndTheAppInterfacesRecordsAreCarriedAndOpenAfterAMove() = runBlocking<Unit> {
        val state = MemoryDeviceState()
        val userId = "22222222-2222-4222-8222-222222222222"
        val uvk = io.silencelen.andvari.core.client.onboard.GuardedKey.loose(ByteArray(32) { 4 })
        serve(home, card(0, "c0"))
        val t = trust(state)
        gatePinned(t)
        val links = io.silencelen.andvari.core.client.link.LinkRecordStore(state, crypto, home, userId)
        links.put(uvk, linkRecord("aaaaaaaaaaaaaaaaaaaaaa"))
        links.put(uvk, linkRecord("bbbbbbbbbbbbbbbbbbbbbb"))
        links.remove(uvk, "bbbbbbbbbbbbbbbbbbbbbb")
        assertTrue(links.wasDropped("bbbbbbbbbbbbbbbbbbbbbb", 0))
        state.set("ovh.notused|$home|$userId", "someone")
        state.set("ovh.quick.offer|$home|$userId", "offered")
        movedChain()
        val m = assertIs<CardStatus.Moved>(t.refresh(home))
        assertIs<CardStatus.Ok>(t.followMove(m))
        val there = io.silencelen.andvari.core.client.link.LinkRecordStore(state, crypto, moved, userId)
        assertEquals(listOf("aaaaaaaaaaaaaaaaaaaaaa"), there.all(uvk).map { it.linkId }, "the link this device made still opens")
        assertTrue(there.wasDropped("bbbbbbbbbbbbbbbbbbbbbb", 0), "and the dropped one is still this device's to acknowledge")
        assertEquals("someone", state.get("ovh.notused|$moved|$userId"))
        assertEquals("offered", state.get("ovh.quick.offer|$moved|$userId"))
        for (k in listOf("ovh.links|", "ovh.links.dropped|", "ovh.notused|", "ovh.quick.offer|")) assertNull(state.get("$k$home|$userId"), k)
    }

    @Test fun aLinkRecordSealedWithTheOriginInItsDataIsStillReadAtThatOrigin() {
        val state = MemoryDeviceState()
        val userId = "22222222-2222-4222-8222-222222222222"
        val uvk = ByteArray(32) { 4 }
        val list = WireJson.json.encodeToString(kotlinx.serialization.builtins.ListSerializer(io.silencelen.andvari.core.client.link.LinkRecord.serializer()),
            listOf(linkRecord("aaaaaaaaaaaaaaaaaaaaaa")))
        state.set("ovh.links|$home|$userId",
            io.silencelen.andvari.core.crypto.Envelope.sealB64(crypto, uvk, list.encodeToByteArray(), "andvari/v2|link-records|$home|$userId".encodeToByteArray()))
        val links = io.silencelen.andvari.core.client.link.LinkRecordStore(state, crypto, home, userId)
        val held = io.silencelen.andvari.core.client.onboard.GuardedKey.loose(uvk)
        assertEquals(listOf("aaaaaaaaaaaaaaaaaaaaaa"), links.all(held).map { it.linkId })
        // Another account's UVK opens neither form.
        assertTrue(links.all(io.silencelen.andvari.core.client.onboard.GuardedKey.loose(ByteArray(32) { 5 })).isEmpty())
        // The next write seals it under the account and purpose alone: it opens at any origin it is carried to.
        links.put(held, linkRecord("bbbbbbbbbbbbbbbbbbbbbb"))
        state.set("ovh.links|$moved|$userId", state.get("ovh.links|$home|$userId"))
        assertEquals(2, io.silencelen.andvari.core.client.link.LinkRecordStore(state, crypto, moved, userId).all(held).size)
    }

    @Test fun aHostRegisteredPrefixIsCarriedByAMoveAndBlocksATargetThatHoldsOne() = runBlocking<Unit> {
        PinStore.carryWithMoves("ovhtest.host-ns|")
        PinStore.carryWithMoves("ovhtest.host-ns|")
        for (bad in listOf("ovh.pin|", "ovh.moving|", "ovh.acct|", "Upper|", "no-bar", "a|b|", "|")) {
            kotlin.test.assertFailsWith<IllegalArgumentException>(bad) { PinStore.carryWithMoves(bad) }
        }
        val state = MemoryDeviceState()
        serve(home, card(0, "c0"))
        val t = trust(state)
        gatePinned(t)
        state.set("ovhtest.host-ns|$home|u1", "the host's")
        movedChain()
        assertIs<CardStatus.Ok>(t.followMove(assertIs<CardStatus.Moved>(t.refresh(home))))
        assertEquals("the host's", state.get("ovhtest.host-ns|$moved|u1"))
        assertNull(state.get("ovhtest.host-ns|$home|u1"))

        val other = MemoryDeviceState()
        servers.clear()
        serve(home, card(0, "c0"))
        val t2 = trust(other)
        gatePinned(t2)
        other.set("ovhtest.host-ns|$moved", "already there")
        movedChain()
        assertIs<CardStatus.PinConflict>(t2.followMove(assertIs<CardStatus.Moved>(t2.refresh(home))))
        assertEquals(OriginAccess.OPEN, t2.access(home))
    }

    // ---- a target this device cannot keep a pin for is refused before the pin moves ----

    @Test fun aMoveOfAnotherInstanceToTheBakedOriginIsRefusedBeforeThePinMoves() = runBlocking<Unit> {
        val state = MemoryDeviceState()
        serve(home, card(0, "c0"))
        val t = trust(state, baked = BakedInstance(moved, "9a6f3c2e-4d5a-4b7c-8d9e-0f1a2b3c4d5e", h("b0"), "private"))
        gatePinned(t)
        state.set("ovh.dev|$home|a@x.example", "mine")
        movedChain()
        val m = assertIs<CardStatus.Moved>(t.refresh(home))
        assertEquals(MOVE_TO_BAKED_ORIGIN, assertIs<CardStatus.Refused>(t.followMove(m)).verdict)
        assertEquals(h("c0"), t.pinFor(home)!!.card0Hash, "the old pin is in force")
        assertEquals(OriginAccess.OPEN, t.access(home))
        assertEquals(PinState.None, t.pinState(moved), "nothing is pinned at the baked origin")
        assertEquals("mine", state.get("ovh.dev|$home|a@x.example"))
        assertNull(state.get("ovh.dev|$moved|a@x.example"))
    }

    @Test fun theBakedInstanceItselfMayMoveToTheBakedOrigin() = runBlocking<Unit> {
        val state = MemoryDeviceState()
        serve(home, card(0, "c0"))
        val t = trust(state, baked = BakedInstance(moved, inst, h("c0"), "private"))
        gatePinned(t)
        movedChain()
        val m = assertIs<CardStatus.Moved>(t.refresh(home))
        assertIs<CardStatus.Ok>(t.followMove(m))
        assertEquals(PinState.None, t.pinState(home))
        assertIs<PinState.Pinned>(t.pinState(moved))
    }

    @Test fun aMoveToAnOriginThatHoldsAnyRecordIsRefusedBeforeThePinMoves() = runBlocking<Unit> {
        // A record the old origin does not have (so nothing carried would replace it), and a forked pin.
        for (seed in listOf<(MemoryDeviceState) -> Unit>(
            { it.set("ovh.setup|$moved", "an offer") },
            { it.set("ovh.assist|$moved", "a request") },
            { s -> val p = CardChainRules.firstPin(listOf(card(0, "x0", origin = moved)), PinRoot.TRUST_GATE, null); PinStore(s).put(p); PinStore(s).markForked(p) },
            { it.set(PinStore.KEY_PREFIX + moved, "{damaged") },
        )) {
            val state = MemoryDeviceState()
            servers.clear()
            serve(home, card(0, "c0"))
            val t = trust(state)
            gatePinned(t)
            state.set("ovh.dev|$home|a@x.example", "mine")
            seed(state)
            val before = state.keys()!!.associateWith { state.get(it) }
            movedChain()
            val m = assertIs<CardStatus.Moved>(t.refresh(home))
            assertIs<CardStatus.PinConflict>(t.followMove(m))
            assertEquals(OriginAccess.OPEN, t.access(home), "the old pin stays in force")
            assertEquals(before.filterKeys { !it.startsWith(PinStore.KEY_PREFIX + home) }, state.keys()!!.filter { !it.startsWith(PinStore.KEY_PREFIX + home) }.associateWith { state.get(it) },
                "nothing moved")
        }
    }

    @Test fun aStoreThatCannotListItsRecordsCannotFollowAMove() = runBlocking<Unit> {
        val inner = MemoryDeviceState()
        val unlisted = object : io.silencelen.andvari.core.client.DeviceState {
            override fun get(key: String) = inner.get(key)
            override fun set(key: String, value: String?) = inner.set(key, value)
        }
        serve(home, card(0, "c0"))
        val t = CardTrust(PinStore(unlisted), verifier, { o -> servers.getOrPut(o) { FakeClient(o, null) } }, crypto, null, false)
        gatePinned(t)
        inner.set("ovh.dev|$home|a@x.example", "mine")
        movedChain()
        val m = assertIs<CardStatus.Moved>(t.refresh(home))
        assertEquals(CANNOT_CARRY_RECORDS, assertIs<CardStatus.Refused>(t.followMove(m)).verdict)
        assertIs<PinState.Pinned>(t.pinState(home))
        assertEquals(PinState.None, t.pinState(moved))
        assertEquals("mine", inner.get("ovh.dev|$home|a@x.example"))
    }

    @Test fun aRolledBackAccountStateRefusedBeforeAMoveIsStillRefusedAfterIt() = runBlocking<Unit> {
        val state = MemoryDeviceState()
        val userId = "22222222-2222-4222-8222-222222222222"
        val uvk = ByteArray(32) { 9 }
        fun blob(seq: Long) = io.silencelen.andvari.core.crypto.Envelope.sealB64(crypto, uvk,
            io.silencelen.andvari.core.client.state.AccountDocumentCodec.encode(userId,
                io.silencelen.andvari.core.client.state.AccountDocument.EMPTY.copy(seq = seq)).encodeToByteArray(),
            io.silencelen.andvari.core.crypto.Ad.accountState(userId))
        class StateServer(override val origin: String, var sealed: String) : WireClient {
            override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> =
                WireResult.Ok(decode(WireJson.json.encodeToString(io.silencelen.andvari.core.model.wire.AccountStateResponse.serializer(),
                    io.silencelen.andvari.core.model.wire.AccountStateResponse(sealed, 1))), 200)
        }
        fun rollback(r: io.silencelen.andvari.core.client.state.AccountStateRead) =
            assertIs<io.silencelen.andvari.core.client.state.AccountStateRead.Ok>(r).anomalies.filterIsInstance<io.silencelen.andvari.core.client.state.MergeAnomaly.Rollback>()
        val atHome = StateServer(home, blob(5))
        val before = io.silencelen.andvari.core.client.state.StoredAccountState(userId, uvk, atHome, crypto, state)
        assertTrue(rollback(before.read()).isEmpty())
        atHome.sealed = blob(3)
        assertEquals(listOf(io.silencelen.andvari.core.client.state.MergeAnomaly.Rollback(3, 5)), rollback(before.read()), "refused before the move")
        serve(home, card(0, "c0"))
        val t = trust(state)
        gatePinned(t)
        movedChain()
        assertIs<CardStatus.Ok>(t.followMove(assertIs<CardStatus.Moved>(t.refresh(home))))
        val after = io.silencelen.andvari.core.client.state.StoredAccountState(userId, uvk, StateServer(moved, blob(3)), crypto, state)
        assertEquals(listOf(io.silencelen.andvari.core.client.state.MergeAnomaly.Rollback(3, 5)), rollback(after.read()), "still refused after it")
    }

    @Test fun aForkStopsTrafficButNotReadingAndADamagedPinBlocksBoth() = runBlocking<Unit> {
        val state = MemoryDeviceState()
        serve(home, card(0, "c0"), card(1, "c1"))
        serve(moved, card(0, "m0", origin = moved))
        val t = trust(state)
        gatePinned(t)
        gatePinned(t, moved)
        assertEquals(OriginAccess.OPEN, t.access(home))
        assertEquals(OriginAccess.OPEN, t.access("https://never.example"), "no pin: the Trust Gate's card fetch must work")
        serve(home, card(0, "c0"), card(1, "other"))
        assertIs<CardStatus.Fork>(t.refresh(home))
        state.set(PinStore.KEY_PREFIX + moved, "{not a pin")
        assertEquals(OriginAccess.FORKED, t.access(home))
        assertTrue(!t.access(home).mayDial && t.access(home).mayReadLocal, "a fork: no traffic, the device's own copy stays readable")
        assertEquals(OriginAccess.BLOCKED, t.access(moved))
        assertTrue(!t.access(moved).mayDial && !t.access(moved).mayReadLocal, "damaged: nothing")
        // The password rule refuses both; its access query tells them apart from the same pins.
        val pins = t.gatePins()
        for (o in listOf(home, moved)) {
            assertEquals(GateDecision.REFUSE_ENTRY, PasswordGate.decide(GateInput(GatePurpose.SIGN_IN, GateEntry.SERVER_CHOICE, null, o, "a@x.example", pins)))
        }
        assertEquals(OriginAccess.FORKED, PasswordGate.access(home, pins))
        assertEquals(OriginAccess.BLOCKED, PasswordGate.access(moved, pins))
    }

    @Test fun aPinStoredUnderAnotherOriginIsDamaged() = runBlocking<Unit> {
        // The combined kind-and-origin change never stores a pin away from its namespace (kindChangeWithAMoveIsAKindChangeFirst);
        // a record that names another origin than the one it is stored under is damaged, whoever wrote it.
        val state = MemoryDeviceState()
        serve(moved, card(0, "m0", origin = moved))
        val t = trust(state)
        gatePinned(t, moved)
        state.set(PinStore.KEY_PREFIX + home, state.get(PinStore.KEY_PREFIX + moved))
        assertEquals(PinState.Damaged, t.pinState(home))
        assertEquals(OriginAccess.BLOCKED, t.access(home))
    }

    @Test fun aPinRecordThatCannotBeReadIsDamagedNeverNone() = runBlocking<Unit> {
        val failing = object : io.silencelen.andvari.core.client.DeviceState {
            override fun get(key: String): String? = throw IllegalStateException("storage locked")
            override fun set(key: String, value: String?) = throw IllegalStateException("storage locked")
        }
        val store = PinStore(failing)
        assertEquals(PinState.Damaged, store.state(home))
        assertEquals(OriginAccess.BLOCKED, store.access(home))
        val t = CardTrust(store, verifier, { o -> servers.getOrPut(o) { FakeClient(o, null) } }, crypto, null, false)
        serve(home, card(0, "c0"))
        assertEquals("damaged", assertIs<FirstPin.Blocked>(t.beginTrustGate(home, TrustGateWording.TYPED_ADDRESS)).verdict, "no first pin over a record that could not be read")
    }

    /** Serves [cards]; the call made while [hold] is set suspends until it is completed and serves what it completes with. */
    private class RaceClient(override val origin: String, var cards: List<String>) : WireClient {
        var hold: kotlinx.coroutines.CompletableDeferred<List<String>>? = null
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            check(route == WireRoute.INSTANCE)
            val served = hold?.also { hold = null }?.await() ?: cards
            return WireResult.Ok(decode(WireJson.json.encodeToString(InstanceResponse.serializer(), InstanceResponse(served, emptyList()))), 200)
        }
    }

    /**
     * Design §4.4 "A fork is durable": [slow] fetches a good chain and suspends on it; meanwhile another caller's refresh
     * meets a forked chain and marks the fork; then [slow]'s fetch completes. Nothing [slow] writes may clear the mark.
     */
    private fun forkLandsDuring(
        good: List<VerifiedCard>,
        prepare: suspend (CardTrust, RaceClient) -> Unit = { _, _ -> },
        slow: suspend (CardTrust) -> Any,
    ): Any = runBlocking {
        val state = MemoryDeviceState()
        val client = RaceClient(home, listOf(card(0, "c0"), card(1, "c1")).map(::frameOf))
        val t = CardTrust(PinStore(state), verifier, { client }, crypto, null, false)
        gatePinned(t)
        prepare(t, client)
        val release = kotlinx.coroutines.CompletableDeferred<List<String>>()
        client.hold = release
        val inFlight = async(start = CoroutineStart.UNDISPATCHED) { slow(t) }
        assertTrue(client.hold == null, "the slow call is suspended on its fetch")
        client.cards = listOf(card(0, "c0"), card(1, "other")).map(::frameOf)
        assertIs<CardStatus.Fork>(t.refresh(home), "the other caller marks the fork")
        release.complete(good.map(::frameOf))
        val answer = inFlight.await()
        assertIs<PinState.Forked>(t.pinState(home), "the fork mark survives the call that was in flight")
        assertIs<PinState.Forked>(CardTrust(PinStore(state), verifier, { client }, crypto, null, false).pinState(home), "durably")
        assertEquals(OriginAccess.FORKED, t.access(home))
        answer
    }

    @Test fun aRefreshInFlightNeverClearsAForkMarkedDuringItsFetch() {
        val answer = forkLandsDuring(listOf(card(0, "c0"), card(1, "c1"), card(2, "c2"))) { it.refresh(home) }
        assertIs<CardStatus.Fork>(answer, "the refresh answers the fork, not the chain it fetched before it")
    }

    @Test fun aTrustGateBegunBeforeAForkIsBlockedAfterIt() {
        val answer = forkLandsDuring(listOf(card(0, "c0"), card(1, "c1"), card(2, "c2"))) { it.beginTrustGate(home, TrustGateWording.TYPED_ADDRESS) }
        assertIs<FirstPin.Blocked>(answer, "no Trust Gate is offered over a fork")
    }

    @Test fun aLinkOfferPinInFlightNeverClearsAFork() {
        val answer = forkLandsDuring(listOf(card(0, "c0"), card(1, "c1"), card(2, "c2"))) { it.pinFromLinkOffer(home, inst, h("c1")) }
        assertIs<FirstPin.Blocked>(answer)
    }

    @Test fun aMoveFollowedInFlightNeverMovesAForkAway() {
        val movedChain = listOf(card(0, "c0"), card(1, "c1"), card(2, "m", origin = moved))
        var prompt: CardStatus.Moved? = null
        val answer = forkLandsDuring(movedChain, prepare = { t, c ->
            c.cards = movedChain.map(::frameOf)
            prompt = assertIs<CardStatus.Moved>(t.refresh(home))
        }) { it.followMove(prompt!!) }
        assertIs<CardStatus.Fork>(answer)
    }

    @Test fun aKindChangeAcceptedInFlightNeverClearsAFork() {
        val kindChain = listOf(card(0, "c0"), card(1, "c1"), card(2, "k", kind = "public"))
        var prompt: CardStatus.KindChanged? = null
        val answer = forkLandsDuring(kindChain, prepare = { t, c ->
            c.cards = kindChain.map(::frameOf)
            prompt = assertIs<CardStatus.KindChanged>(t.refresh(home))
        }) { it.acceptKindChange(prompt!!) }
        assertIs<CardStatus.Fork>(answer)
    }

    // ---- a fork is marked only on the pin that was judged ----

    /** A trust over one [RaceClient] serving `c0, c1`, pinned through the Trust Gate. */
    private fun racePinned(state: MemoryDeviceState): Pair<CardTrust, RaceClient> {
        val client = RaceClient(home, listOf(card(0, "c0"), card(1, "c1")).map(::frameOf))
        val t = CardTrust(PinStore(state), verifier, { client }, crypto, null, false)
        runBlocking { gatePinned(t) }
        return t to client
    }

    /** A refresh of [home] that suspends on its fetch while [meanwhile] runs, then is served [served]: its answer. */
    private fun staleRefresh(t: CardTrust, client: RaceClient, served: List<VerifiedCard>, meanwhile: suspend () -> Unit): CardStatus = runBlocking {
        val release = kotlinx.coroutines.CompletableDeferred<List<String>>()
        client.hold = release
        val inFlight = async(start = CoroutineStart.UNDISPATCHED) { t.refresh(home) }
        assertTrue(client.hold == null, "the refresh is suspended on its fetch")
        meanwhile()
        release.complete(served.map(::frameOf))
        inFlight.await()
    }

    private val forkOfTheOldChain = listOf(card(0, "c0"), card(1, "other"))

    @Test fun aRefreshThatWaitedThroughAResetAndAFreshTrustGateMarksNothing() {
        val state = MemoryDeviceState()
        val (t, client) = racePinned(state)
        val answer = staleRefresh(t, client, forkOfTheOldChain) {
            // The operator resets the identity; the person forgets the server and confirms the Trust Gate again.
            client.cards = listOf(card(0, "r0"), card(1, "r1")).map(::frameOf)
            t.forget(home)
            gatePinned(t)
        }
        val now = assertIs<PinState.Pinned>(t.pinState(home), "the fresh pin stays in force")
        assertEquals(h("r0"), now.pin.card0Hash, "the old chain's record did not replace it")
        assertEquals(h("r1"), now.pin.hash)
        assertIs<PinState.Pinned>(CardTrust(PinStore(state), verifier, { client }, crypto, null, false).pinState(home), "durably")
        assertIs<CardStatus.Ok>(answer, "judged again from the pin in force now")
    }

    @Test fun aRefreshThatWaitedThroughAMoveLeavesNoRecordAtTheOldOrigin() {
        val state = MemoryDeviceState()
        val (t, client) = racePinned(state)
        client.cards = listOf(card(0, "c0"), card(1, "c1"), card(2, "m", origin = moved)).map(::frameOf)
        val prompt = runBlocking { assertIs<CardStatus.Moved>(t.refresh(home)) }
        val answer = staleRefresh(t, client, forkOfTheOldChain) { assertIs<CardStatus.Ok>(t.followMove(prompt)) }
        assertEquals(PinState.None, t.pinState(home), "no forked record comes back at the old origin")
        assertIs<PinState.Pinned>(t.pinState(moved))
        assertEquals(listOf(moved), PinStore(state).origins(), "one origin holds a record")
        assertEquals("no_pin", assertIs<CardStatus.Refused>(answer).verdict)
    }

    @Test fun aRefreshThatWaitedThroughForgetThisServerDoesNotBringThePinBack() {
        val state = MemoryDeviceState()
        val (t, client) = racePinned(state)
        val answer = staleRefresh(t, client, forkOfTheOldChain) { t.forget(home) }
        assertEquals(PinState.None, t.pinState(home), "the forgotten pin does not return")
        assertTrue(PinStore(state).origins().isEmpty())
        assertEquals("no_pin", assertIs<CardStatus.Refused>(answer).verdict)
    }

    @Test fun markForkedWritesOnlyOverThePinItWasGiven() {
        val state = MemoryDeviceState()
        val store = PinStore(state)
        val a = CardChainRules.firstPin(listOf(card(0, "c0"), card(1, "c1")), PinRoot.TRUST_GATE, null)
        val b = CardChainRules.firstPin(listOf(card(0, "r0")), PinRoot.TRUST_GATE, null)
        assertFalse(store.markForked(a), "no pin: nothing written")
        assertEquals(PinState.None, store.state(home))
        assertTrue(store.put(b))
        assertFalse(store.markForked(a), "another pin: nothing written")
        assertEquals(b, assertIs<PinState.Pinned>(store.state(home)).pin)
        assertTrue(store.markForked(b))
        assertEquals(b, assertIs<PinState.Forked>(store.state(home)).pin)
        assertTrue(store.markForked(b), "already so")
        state.set(PinStore.KEY_PREFIX + home, "{damaged")
        assertFalse(store.markForked(b))
        assertEquals(PinState.Damaged, store.state(home))
    }

    @Test fun theOperatorShortFingerprintIsTheOneTheTrustGateShows() = runBlocking<Unit> {
        serve(home, card(0, "c0"))
        val t = trust()
        val gate = assertIs<FirstPin.NeedsTrustGate>(t.beginTrustGate(home, TrustGateWording.TYPED_ADDRESS))
        assertEquals(gate.operatorShortFp, t.operatorShortFp(opKey), "instance details and the kind-change prompt show the gate's value")
        assertEquals(gate.operatorShortFp, CardTrust.operatorShortFp(crypto, opKey))
    }

    @Test fun theNewestVerifiedCardSaysWhoIsTheOperator() = runBlocking<Unit> {
        serve(home, card(0, "c0"))
        val t = trust()
        assertNull(t.cardNamesOperator(home, op), "no pin: unknown")
        gatePinned(t)
        assertEquals(true, t.cardNamesOperator(home, op))
        val member = "2d8e5f4a-6b7c-4d9e-8f0a-1b2c3d4e5f60"
        assertEquals(false, t.cardNamesOperator(home, member))
        // A handover: the next card names the member as operator. Known once the chain is refreshed.
        serve(home, card(0, "c0"), VerifiedCard(1, h("c1"), inst, home, "Home", "private", member, opKey, "none"))
        assertEquals(false, t.cardNamesOperator(home, member), "reads only: nothing fetched")
        assertIs<CardStatus.Ok>(t.refresh(home))
        assertEquals(true, t.cardNamesOperator(home, member))
        assertEquals(false, t.cardNamesOperator(home, op))
    }

    @Test fun onlyForgetClearsAForkMark() = runBlocking<Unit> {
        val state = MemoryDeviceState()
        serve(home, card(0, "c0"), card(1, "c1"))
        val t = trust(state)
        val made = gatePinned(t)
        val store = PinStore(state)
        store.markForked(made.pin)
        assertTrue(!store.put(made.pin), "a plain write is refused over a fork mark")
        assertTrue(!store.removeIf(home, made.pin.hash), "dropping a pin just made leaves a fork mark")
        t.dropPinMade(made.handle)
        assertIs<PinState.Forked>(t.pinState(home))
        t.forget(home)
        assertEquals(PinState.None, t.pinState(home))
    }

    // ---- the host's platform namespace on a followed move ----

    /** A [CardTrust] with the host's [mover], recording every origin it dials. */
    private fun movingTrust(state: MemoryDeviceState, dialed: MutableList<String>, mover: NamespaceMover) =
        recordingTrust(PinStore(state), dialed, mover)

    /** A [CardTrust] over [store] with the host's [mover] (none: one namespace), recording every origin it dials. */
    private fun recordingTrust(store: PinStore, dialed: MutableList<String>, mover: NamespaceMover?) =
        CardTrust(store, verifier, { o ->
            val inner = servers.getOrPut(o) { FakeClient(o, null) }
            object : WireClient {
                override val origin: String = o
                override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                    dialed += o
                    return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
                }
            }
        }, crypto, null, false, onMoved = mover)

    @Test fun aFollowedMoveCallsTheHostBeforeTheNewOriginIsFetched() = runBlocking<Unit> {
        val state = MemoryDeviceState()
        val dialed = mutableListOf<String>()
        val calls = mutableListOf<String>()
        val t = movingTrust(state, dialed) { from, to ->
            calls += "$from>$to"
            assertTrue(moved !in dialed, "the host moves its namespace before anything is sent to the new origin")
            assertEquals(OriginAccess.MOVING, PinStore(state).access(to), "closed while the host moves")
            assertEquals(PinState.None, PinStore(state).state(from), "called after the pin moved")
            true
        }
        serve(home, card(0, "c0"))
        gatePinned(t)
        movedChain()
        val m = assertIs<CardStatus.Moved>(t.refresh(home))
        val ok = assertIs<CardStatus.Ok>(t.followMove(m))
        assertTrue(ok.newKitDue)
        assertEquals(listOf("$home>$moved"), calls)
        assertTrue(moved in dialed, "the new origin is refreshed after the host moved")
        assertEquals(OriginAccess.OPEN, t.access(moved))
        assertNull(t.unfinishedMove(moved))
        assertNull(state.get(PinStore.MOVE_PREFIX + moved), "the mark is gone")
    }

    @Test fun theHostMovesItsNamespaceAlsoWhenTheRefreshAfterTheMoveIsNotOk() = runBlocking<Unit> {
        val state = MemoryDeviceState()
        val calls = mutableListOf<String>()
        val t = movingTrust(state, mutableListOf()) { from, to -> calls += "$from>$to"; true }
        serve(home, card(0, "c0"))
        gatePinned(t)
        movedChain()
        val m = assertIs<CardStatus.Moved>(t.refresh(home))
        // The new origin serves a chain that forks from the card the move pinned.
        serve(moved, card(0, "c0"), card(1, "other", origin = moved))
        assertIs<CardStatus.Fork>(t.followMove(m))
        assertEquals(listOf("$home>$moved"), calls, "the move stands, so the host's namespace moved with it")
        assertEquals(PinState.None, t.pinState(home))
        assertIs<PinState.Forked>(t.pinState(moved))
        assertNull(t.unfinishedMove(moved))
    }

    @Test fun aFailedHostMoveKeepsTheNewOriginClosedUntilItSucceeds() = runBlocking<Unit> {
        val state = MemoryDeviceState()
        val dialed = mutableListOf<String>()
        val answers = ArrayDeque(listOf<() -> Boolean>({ false }, { throw IllegalStateException("disk full") }, { true }))
        val calls = mutableListOf<String>()
        val t = movingTrust(state, dialed) { from, to -> calls += "$from>$to"; answers.removeFirst()() }
        serve(home, card(0, "c0"))
        gatePinned(t)
        movedChain()
        val m = assertIs<CardStatus.Moved>(t.refresh(home))
        val refused = assertIs<CardStatus.Refused>(t.followMove(m))
        assertEquals(MOVE_UNFINISHED, refused.verdict)
        assertEquals(moved, refused.pinned!!.origin, "the status names the pin at the new origin")
        assertTrue(moved !in dialed, "nothing is sent to the new origin")
        assertEquals(OriginAccess.MOVING, t.access(moved))
        assertTrue(!OriginAccess.MOVING.mayDial && !OriginAccess.MOVING.mayReadLocal)
        assertEquals(home, t.unfinishedMove(moved))
        assertEquals(PinState.None, t.pinState(home), "the pin and the records moved; only the host's namespace did not")
        // Nothing the engine does dials the new origin meanwhile, also after a restart.
        val again = movingTrust(state, dialed) { _, _ -> error("not called by these") }
        assertEquals(MOVE_UNFINISHED, assertIs<CardStatus.Refused>(again.refresh(moved)).verdict)
        assertEquals(MOVE_UNFINISHED, assertIs<FirstPin.Refused>(again.beginTrustGate(moved, TrustGateWording.TYPED_ADDRESS)).reason)
        assertEquals(MOVE_UNFINISHED, assertIs<FirstPin.Refused>(again.pinFromLinkOffer(moved, inst, h("c1"))).reason)
        assertTrue(moved !in dialed)
        assertTrue(!io.silencelen.andvari.core.client.net.OriginGuard(PinStore(state)).mayDial(moved), "the dialer's guard stops every flow")
        val gp = again.gatePins().single { it.origin == moved }
        assertTrue(gp.blocked && gp.damaged, "the password rule refuses everything for it")
        assertEquals(OriginAccess.BLOCKED, PasswordGate.access(moved, again.gatePins()))
        assertTrue(!PinStore(state).put(again.pinFor(moved)!!), "no pin write lands on it")
        // The host fails again (by throwing): still closed.
        assertEquals(MOVE_UNFINISHED, assertIs<CardStatus.Refused>(t.finishMove(moved)).verdict)
        assertEquals(OriginAccess.MOVING, t.access(moved))
        assertTrue(moved !in dialed)
        // Now it succeeds: the origin opens and is refreshed, and the person is asked for a new kit.
        assertTrue(assertIs<CardStatus.Ok>(t.finishMove(moved)).newKitDue)
        assertEquals(listOf("$home>$moved", "$home>$moved", "$home>$moved"), calls)
        assertEquals(OriginAccess.OPEN, t.access(moved))
        assertNull(t.unfinishedMove(moved))
        assertTrue(moved in dialed)
        // With nothing pending, finishing is a refresh.
        assertIs<CardStatus.Ok>(t.finishMove(moved))
        assertEquals(3, calls.size)
    }

    @Test fun forgettingTheNewOriginClearsAnUnfinishedMoveAndAnUnreadableMarkBlocks() = runBlocking<Unit> {
        val state = MemoryDeviceState()
        val t = movingTrust(state, mutableListOf()) { _, _ -> false }
        serve(home, card(0, "c0"))
        gatePinned(t)
        movedChain()
        assertIs<CardStatus.Refused>(t.followMove(assertIs<CardStatus.Moved>(t.refresh(home))))
        // A mark that does not name an origin is unknown, never "no move pending": the origin is blocked.
        state.set(PinStore.MOVE_PREFIX + moved, "")
        assertEquals(OriginAccess.BLOCKED, t.access(moved))
        assertNull(t.unfinishedMove(moved))
        assertEquals("damaged", assertIs<CardStatus.Refused>(t.refresh(moved)).verdict)
        t.forget(moved)
        assertEquals(PinState.None, t.pinState(moved))
        assertEquals(OriginAccess.OPEN, t.access(moved))
        assertNull(state.get(PinStore.MOVE_PREFIX + moved))
    }

    // ---- a followed move stopped at any single write (the app stops, or a write throws) ----

    /** Device state over [inner] whose [stopAt]-th write after arming throws before it lands; later writes land. */
    private class StoppingState(val inner: MemoryDeviceState) : io.silencelen.andvari.core.client.DeviceState {
        var stopAt = 0
        var stopped = false
        private var writes = 0
        override fun get(key: String) = inner.get(key)
        override fun keys(): Set<String> = inner.keys()
        override fun set(key: String, value: String?) {
            if (stopAt > 0 && !stopped && ++writes == stopAt) {
                stopped = true
                throw IllegalStateException("stopped at write $stopAt")
            }
            inner.set(key, value)
        }
    }

    /** One record of every per-origin store, under the old origin. */
    private val originRecords get() = PinStore.ORIGIN_KEYED.associate { p -> "$p$home|u1" to "value of $p" }

    private fun assertRecordsAt(inner: MemoryDeviceState, at: String, gone: String, where: String) {
        for ((k, v) in originRecords) {
            assertEquals(v, inner.get(k.replaceFirst("|$home", "|$at")), "$where: $k is at $at")
            assertNull(inner.get(k.replaceFirst("|$home", "|$gone")), "$where: $k is not also at $gone")
        }
    }

    /**
     * Asserts that [t] sees one of the two outcomes a stopped move may leave and answers whether it is done. Not done:
     * the old origin pinned and open with every record, no mark anywhere. Done: the new origin pinned with every record;
     * with a host namespace [OriginAccess.MOVING] until the host's mover succeeded ([hostMoved]), open otherwise.
     */
    private fun assertSettled(t: CardTrust, inner: MemoryDeviceState, hostNamespace: Boolean, hostMoved: Boolean, where: String): Boolean {
        val old = t.pinState(home)
        val new = t.pinState(moved)
        val done = when {
            old is PinState.Pinned && new == PinState.None -> false
            old == PinState.None && new is PinState.Pinned -> true
            else -> fail("$where: old origin $old, new origin $new: exactly one of them must be pinned")
        }
        val (at, gone) = if (done) moved to home else home to moved
        assertRecordsAt(inner, at, gone, where)
        assertEquals(listOf(at), t.pins().map { it.origin }, "$where: one pin in force")
        assertEquals(OriginAccess.OPEN, t.access(gone), "$where: nothing is left at $gone")
        when {
            !done || !hostNamespace -> {
                assertEquals(OriginAccess.OPEN, t.access(at), where)
                assertTrue(inner.keys().none { it.startsWith(PinStore.MOVE_PREFIX) }, "$where: no mark is left")
            }
            !hostMoved -> {
                assertEquals(OriginAccess.MOVING, t.access(moved), "$where: the new origin stays closed until the host moved")
                assertEquals(home, t.unfinishedMove(moved), where)
            }
            // The host moved; only clearing the mark may have been stopped, and finishing calls the (idempotent) host again.
            else -> assertTrue(t.access(moved) in setOf(OriginAccess.OPEN, OriginAccess.MOVING), where)
        }
        return done
    }

    /**
     * Follows one move with every write in turn stopped (k = 1, 2, … until the move runs through), and after each stop
     * checks the outcome through a NEW store and trust over the same data ([sameStore] false) or through the same one,
     * then a second attempt at the same move. The host's mover checks it runs only with the pin and records at the new
     * origin and before anything is sent there.
     */
    private suspend fun stopAtEveryWrite(hostNamespace: Boolean, sameStore: Boolean): Map<Int, Boolean> {
        val outcomes = LinkedHashMap<Int, Boolean>()
        var k = 1
        while (true) {
            servers.clear()
            val inner = MemoryDeviceState()
            val stopping = StoppingState(inner)
            val dialed = mutableListOf<String>()
            var hostMoved = false
            val mover = if (!hostNamespace) null else NamespaceMover { from, to ->
                assertEquals(home to moved, from to to)
                assertTrue(inner.get(PinStore.KEY_PREFIX + to) != null && inner.get(PinStore.KEY_PREFIX + from) == null,
                    "write $k: the host moves its namespace only once the pin moved")
                assertRecordsAt(inner, moved, home, "write $k, in the host's mover")
                assertTrue(to !in dialed, "write $k: nothing is sent to the new origin before the host moved")
                hostMoved = true
                true
            }
            val t = recordingTrust(PinStore(stopping), dialed, mover)
            serve(home, card(0, "c0"))
            gatePinned(t)
            originRecords.forEach { (key, v) -> inner.set(key, v) }
            movedChain()
            val m = assertIs<CardStatus.Moved>(t.refresh(home))
            stopping.stopAt = k
            val first = try { t.followMove(m) } catch (e: IllegalStateException) { null }
            if (!stopping.stopped) {
                // k is past the move's last write: it ran through.
                assertTrue(assertIs<CardStatus.Ok>(first).newKitDue)
                assertTrue(k > 20, "every write of the move was stopped once (${k - 1})")
                return outcomes
            }
            assertNull(first, "write $k: the stop is the answer, never swallowed")
            val after = if (sameStore) t else recordingTrust(PinStore(inner), dialed, mover)
            outcomes[k] = assertSettled(after, inner, hostNamespace, hostMoved, "write $k")
            // A second attempt at the same move succeeds, from either outcome.
            val again = assertIs<CardStatus.Ok>(after.followMove(m), "write $k: the second attempt")
            assertTrue(again.newKitDue, "write $k")
            assertEquals(PinState.None, after.pinState(home), "write $k")
            assertEquals(h("c1"), assertIs<PinState.Pinned>(after.pinState(moved)).pin.hash, "write $k")
            assertEquals(OriginAccess.OPEN, after.access(moved), "write $k")
            assertNull(after.unfinishedMove(moved), "write $k")
            assertRecordsAt(inner, moved, home, "write $k, after the second attempt")
            assertTrue(inner.keys().none { it.startsWith(PinStore.MOVE_PREFIX) }, "write $k: no mark is left")
            assertEquals(hostNamespace, hostMoved, "write $k: the host moved its namespace exactly when it has one")
            k++
        }
    }

    @Test fun aMoveWithAHostNamespaceStoppedAtAnyWriteIsUndoneOrDone() = runBlocking<Unit> {
        val outcomes = stopAtEveryWrite(hostNamespace = true, sameStore = false)
        assertEquals(false, outcomes[1], "stopped at the intent: not done")
        assertEquals(false, outcomes[2], "stopped at the new pin: not done")
        assertEquals(true, outcomes[3], "the new pin written: done")
        assertTrue(outcomes.values.drop(2).all { it })
    }

    @Test fun aMoveWithOneNamespaceStoppedAtAnyWriteIsUndoneOrDone() = runBlocking<Unit> {
        val outcomes = stopAtEveryWrite(hostNamespace = false, sameStore = false)
        assertEquals(listOf(false, false), outcomes.values.take(2))
        assertTrue(outcomes.values.drop(2).all { it })
    }

    @Test fun aMoveStoppedAtAnyWriteIsSettledByTheSameStoreToo() = runBlocking<Unit> {
        stopAtEveryWrite(hostNamespace = true, sameStore = true)
        stopAtEveryWrite(hostNamespace = false, sameStore = true)
    }

    @Test fun aStoppedMoveThatCannotBeSettledClosesBothOriginsUntilTheNewOneIsForgotten() = runBlocking<Unit> {
        val inner = MemoryDeviceState()
        val stopping = StoppingState(inner)
        val calls = mutableListOf<String>()
        val mover = NamespaceMover { from, to -> calls += "$from>$to"; true }
        val t = recordingTrust(PinStore(stopping), mutableListOf(), mover)
        serve(home, card(0, "c0"))
        gatePinned(t)
        movedChain()
        val m = assertIs<CardStatus.Moved>(t.refresh(home))
        // Write 1 is the intent, 2 the new pin, 3 the pin index: stopped there, the move is to be rolled forward ...
        stopping.stopAt = 3
        assertTrue(runCatching { t.followMove(m) }.exceptionOrNull() is IllegalStateException)
        // ... but the new pin cannot be read any more.
        inner.set(PinStore.KEY_PREFIX + moved, "{not a pin")
        val fresh = recordingTrust(PinStore(inner), mutableListOf(), mover)
        assertEquals(OriginAccess.BLOCKED, fresh.access(home), "the old origin is not open beside an unsettled move")
        assertEquals(OriginAccess.BLOCKED, fresh.access(moved))
        assertEquals(PinState.Damaged, fresh.pinState(home))
        assertTrue(fresh.pins().isEmpty(), "never both origins pinned")
        assertNull(fresh.unfinishedMove(moved))
        assertEquals("damaged", assertIs<CardStatus.Refused>(fresh.finishMove(moved)).verdict)
        assertEquals("damaged", assertIs<CardStatus.Refused>(fresh.refresh(home)).verdict)
        assertTrue(calls.isEmpty(), "the host never moves a namespace whose pin did not move")
        // "Forget this server" on the new origin ends the move: the old origin is pinned and open again.
        fresh.forget(moved)
        assertEquals(OriginAccess.OPEN, fresh.access(home))
        assertIs<PinState.Pinned>(fresh.pinState(home))
        assertTrue(assertIs<CardStatus.Ok>(fresh.followMove(assertIs<CardStatus.Moved>(fresh.refresh(home)))).newKitDue)
        assertEquals(listOf("$home>$moved"), calls)
    }
}
