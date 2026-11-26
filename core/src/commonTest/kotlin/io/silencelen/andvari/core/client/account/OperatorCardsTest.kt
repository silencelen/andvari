package io.silencelen.andvari.core.client.account

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.link.OfferView
import io.silencelen.andvari.core.client.link.RecipientStep
import io.silencelen.andvari.core.client.link.RecipientToken
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.EstablishedSession
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.KeptSetup
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.LinkRegistration
import io.silencelen.andvari.core.client.onboard.LinkRegistrations
import io.silencelen.andvari.core.client.onboard.PasswordKeys
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.RegistrationForm
import io.silencelen.andvari.core.client.onboard.SessionSink
import io.silencelen.andvari.core.client.onboard.SetupOffers
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.client.pin.CardStatus
import io.silencelen.andvari.core.client.pin.CardTrust
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.client.pin.TrustCardChainVerifier
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.KeyPairBytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.InstanceCardPut
import io.silencelen.andvari.core.model.wire.InstanceCardPutResponse
import io.silencelen.andvari.core.model.wire.InstanceRotationPut
import io.silencelen.andvari.core.model.wire.PreloginRequest
import io.silencelen.andvari.core.model.wire.PreloginResponse
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.CardFields
import io.silencelen.andvari.core.trust.Checked
import io.silencelen.andvari.core.trust.InstanceCard
import io.silencelen.andvari.core.trust.InstanceKind
import io.silencelen.andvari.core.trust.RecoveryRotation
import io.silencelen.andvari.core.trust.RotationFields
import io.silencelen.andvari.core.trust.SignedFrame
import io.silencelen.andvari.core.trust.TrustGrammar
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The server side of spec 03 §17.2 and §17.3 over a [FakeInstance]: the operator check, the position
 * (`409 card_head_moved {seq, hash}`), the chain and fields (`400 bad_card`, variant R included), the handover target
 * (`409 handover_target_invalid`), and rotations verified against the current recovery key (`400 bad_rotation`).
 * Every other route is the fake instance's.
 */
class CardServer(val crypto: CryptoProvider, val instance: FakeInstance) : WireClient {
    override val origin: String get() = instance.origin

    /** Accounts the server knows besides the fake instance's own: userId to (identityPub, active). */
    val members = HashMap<String, Pair<String, Boolean>>()

    /** Runs once before the next card upload is checked: "someone else uploads first". */
    var beforeCardPut: (() -> Unit)? = null

    /** Runs once while the next rotation upload is held: "the vault locks during the call". */
    var duringRotationPut: (() -> Unit)? = null

    /** The userId the operator session speaks for (the fake instance's operator unless a test says otherwise). */
    var caller: String? = null
    val calls = ArrayList<WireRoute>()
    private var rotationHead: String? = null

    private fun refuse(status: Int, code: String, seq: Long? = null, hash: String? = null): WireResult<Nothing> =
        WireResult.Refused(status, WireError(code, code, seq = seq, hash = hash))

    private fun identityPubOf(userId: String): String? =
        members[userId]?.first ?: instance.accounts.values.firstOrNull { it.userId == userId }?.identityPub

    private fun reauthed(key: String) = instance.accounts.values.any { it.authKey == key }

    @Suppress("UNCHECKED_CAST")
    override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
        calls += route
        instance.override[route]?.let { return instance.call(route, pathParams, query, bodyJson, authenticated, decode) }
        return when (route) {
            WireRoute.INSTANCE_CARD_PUT -> {
                val b = WireJson.json.decodeFromString(InstanceCardPut.serializer(), bodyJson!!)
                val who = caller ?: instance.operatorUserId
                if (who != instance.operatorUserId) return refuse(403, "not_operator")
                if (!reauthed(b.currentAuthKey)) return refuse(403, "reauth_failed")
                beforeCardPut?.let { beforeCardPut = null; it() }
                val frame = Bytes.fromB64(b.card)
                val card = (InstanceCard.parse(crypto, frame) as? Checked.Ok)?.value?.fields ?: return refuse(400, "bad_card")
                if (instance.cards.isEmpty()) {
                    if (card.seq != 0L) return refuse(400, "bad_card")
                } else {
                    val head = instance.cards.last()
                    val headSeq = instance.cards.size - 1L
                    val headHash = SignedFrame.hash(crypto, head)
                    if (card.seq != headSeq + 1 || card.prev != headHash) return refuse(409, "card_head_moved", headSeq, headHash)
                }
                val chain = InstanceCard.verifyChain(crypto, instance.cards + frame, expectedInstanceId = instance.instanceId)
                if (chain.verdict != null) return refuse(400, "bad_card")
                if (instance.kind == InstanceKind.PUBLIC && card.recoveryFp != null) return refuse(400, "bad_card")
                val target = identityPubOf(card.operator) ?: return refuse(400, "bad_card")
                val image = InstanceCard.operatorIdentityKey(crypto, card.operatorSignKey)
                if (image == null || Bytes.toB64(image) != target) return refuse(400, "bad_card")
                if (card.operator != who) {
                    if (members[card.operator]?.second == false) return refuse(409, "handover_target_invalid")
                    instance.operatorUserId = card.operator
                }
                instance.cards += frame
                WireResult.Ok(decode(WireJson.json.encodeToString(InstanceCardPutResponse.serializer(), InstanceCardPutResponse(card.seq, SignedFrame.hash(crypto, frame)))), 200)
            }
            WireRoute.INSTANCE_ROTATION_PUT -> {
                duringRotationPut?.also { duringRotationPut = null }?.invoke()
                val b = WireJson.json.decodeFromString(InstanceRotationPut.serializer(), bodyJson!!)
                if ((caller ?: instance.operatorUserId) != instance.operatorUserId) return refuse(403, "not_operator")
                if (!reauthed(b.currentAuthKey)) return refuse(403, "reauth_failed")
                val frame = Bytes.fromB64(b.statement)
                if (instance.rotations.any { it.contentEquals(frame) }) return WireResult.Ok(decode("{}"), 200)
                // fromFp may be the newest card's recoveryFp or the newest stored rotation's toFp (§17.3).
                val cardFp = (InstanceCard.parse(crypto, instance.cards.last()) as Checked.Ok).value.fields.recoveryFp ?: "none"
                val from = listOfNotNull(cardFp, rotationHead).distinct() - "none"
                val ok = from.firstNotNullOfOrNull { (RecoveryRotation.verify(crypto, frame, instance.instanceId, it) as? Checked.Ok)?.value }
                    ?: return refuse(400, "bad_rotation")
                instance.rotations += frame
                rotationHead = ok.fields.toFp
                WireResult.Ok(decode("{}"), 200)
            }
            else -> instance.call(route, pathParams, query, bodyJson, authenticated, decode)
        }
    }
}

/** The operator's card changes after setup (design §4.1–§4.6, §9.2; spec 03 §17.2, §17.3), with real cards signed by the shared verifiers' code. */
class OperatorCardsTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    private class Env(
        val instance: FakeInstance, val server: CardServer, val state: MemoryDeviceState, val trust: CardTrust,
        val session: EstablishedSession, val cards: WireOperatorCards,
    )

    /** An instance set up through its setup link: the operator registered, signed card 0 and pinned it (root `setup`). */
    private suspend fun operator(kind: InstanceKind = InstanceKind.PRIVATE): Env {
        val instance = FakeInstance(crypto, withCard = false, kind = kind)
        val server = CardServer(crypto, instance)
        val state = MemoryDeviceState()
        val trust = CardTrust(PinStore(state), TrustCardChainVerifier(crypto), { server }, crypto, null, false)
        val setup = LinkRegistration.Setup(instance.origin, instance.instanceId, "Family", kind.literal, "none", "bGlua2lkbGlua2lkbGlua2", Bytes.toB64(ByteArray(32) { 6 }))
        SetupOffers(state).put(KeptSetup(instance.origin, instance.instanceId, "Family", kind.literal, "none"))
        val links = object : LinkRegistrations {
            override fun resolve(step: RecipientStep.Confirm) = setup
            override suspend fun registered(registration: LinkRegistration, session: EstablishedSession) {}
        }
        val sessions = ArrayList<EstablishedSession>()
        val o = WireOnboarding(instance.origin, server, trust, KnownDevices(state, crypto), SessionSink { sessions += it }, crypto, state, "desktop", "Laptop",
            { instance.now }, links = links, work = Dispatchers.Unconfined)
        val step = RecipientStep.Confirm(OfferView("setup", instance.origin, "Family", null, null, 0, null), true, false, RecipientToken("t"))
        val reg = assertIs<Registration.Registered>(o.register(RegistrationAuth.SetupLink(step),
            RegistrationForm("op@example.org", "Op", strong.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Laptop", "desktop")))
        assertTrue(!reg.cardPending, "card 0 is stored")
        val session = sessions.single()
        assertEquals("operator", session.role)
        assertEquals(PinRoot.SETUP, trust.pinFor(instance.origin)!!.root)
        val reauth = Reauth(object : ReauthSession {
            override val origin = instance.origin
            override val emailNorm = "op@example.org"
            override suspend fun deriveCurrentAuthKey(password: CharArray): String? {
                val p = (server.call(WireRoute.PRELOGIN, bodyJson = WireJson.json.encodeToString(PreloginRequest.serializer(), PreloginRequest(emailNorm)),
                    decode = { WireJson.json.decodeFromString(PreloginResponse.serializer(), it) }) as WireResult.Ok).value
                val k = PasswordKeys.derive(crypto, password.copyOf(), Bytes.fromB64(p.kdfSalt), p.kdfParams, served = true) ?: return null
                return k.authKeyB64.also { k.wipe() }
            }
        }) { trust.gatePins() }
        return Env(instance, server, state, trust, session, WireOperatorCards(session, server, crypto, trust, reauth, { instance.now }))
    }

    /** Another account's device that pinned the instance through the Trust Gate. */
    private suspend fun member(e: Env): CardTrust = e.instance.pinnedTrust(MemoryDeviceState())

    /** The served chain verified by the shared verifiers from card 0: its newest card's fields. */
    private fun newest(e: Env): CardFields {
        val r = InstanceCard.verifyChain(crypto, e.instance.cards)
        assertNull(r.verdict, "the served chain verifies")
        return r.chain.cards.last().fields
    }

    private fun pw() = strong.toCharArray()

    /** A recovery seed's Ed25519 pair and the fingerprint of its X25519 key (design §2.3, §4.5). */
    private fun recoveryKey(seed: Int): Pair<KeyPairBytes, String> {
        val pair = crypto.signKeypairFromSeed(ByteArray(32) { seed.toByte() })
        return pair to Bytes.toHexLower(crypto.sha256(crypto.ed25519PkToCurve25519(pair.publicKey)))
    }

    @Test fun renameBuildsTheNextCardAndBothThisDeviceAndAnotherAccountFollow() = runBlocking<Unit> {
        val e = operator()
        val other = member(e)
        val before = e.trust.pinFor(e.instance.origin)!!
        val password = pw()
        val done = assertIs<CardChangeResult.Changed>(e.cards.rename("The Smiths", password))
        assertTrue(password.all { it == '\u0000' }, "the password is wiped")
        val card = newest(e)
        assertEquals(1, card.seq)
        assertEquals(before.hash, card.prev)
        assertEquals(before.instanceId, card.instanceId)
        assertEquals("The Smiths", card.name)
        // Only the name changed.
        assertEquals(CardFields(before.instanceId, 1, before.hash, before.origin, "The Smiths", InstanceKind.PRIVATE, before.operator, before.operatorSignKey, null, card.issuedAt), card)
        assertEquals(SignedFrame.hash(crypto, e.instance.cards.last()), done.hash)
        assertEquals("The Smiths", done.pin.name)
        assertEquals(PinRoot.SETUP, done.pin.root, "the pin keeps its root")
        // The other account's device follows the chain through its own refresh.
        assertEquals("The Smiths", assertIs<CardStatus.Ok>(other.refresh(e.instance.origin)).pin.name)
        // A no-op or a bad name is refused before the password is touched: nothing derived, nothing sent.
        e.server.calls.clear()
        val wiped = pw()
        assertEquals(CardChangeResult.Invalid(WireOperatorCards.NO_CHANGE), e.cards.rename("The Smiths", wiped))
        assertTrue(wiped.all { it == '\u0000' }, "wiped on a refusal too")
        assertEquals(CardChangeResult.Invalid(WireOperatorCards.BAD_NAME), e.cards.rename("", pw()))
        // Refused on the card this device pins: not even the cards are read.
        assertEquals(emptyList<WireRoute>(), e.server.calls.toList(), "nothing: no refresh, no prelogin, no upload")
    }

    /**
     * Spec 01 §7: the password is proven on this device before the change sends anything, the read of the cards
     * included. A wrong password sends nothing at all. Before, the cards were read first (`GET /instance`).
     */
    @Test fun aWrongPasswordSendsNothingAtAllNotEvenTheCardsRead() = runBlocking<Unit> {
        val e = operator()
        val local = Reauth(object : ReauthSession {
            override val origin = e.instance.origin
            override val emailNorm = "op@example.org"
            override suspend fun deriveCurrentAuthKey(password: CharArray): String? = error("proven on this device")
            override suspend fun proveCurrentAuthKey(password: CharArray) = ReauthKey.WrongPassword
        }) { e.trust.gatePins() }
        val cards = WireOperatorCards(e.session, e.server, crypto, e.trust, local, { e.instance.now })
        e.server.calls.clear()
        val pw = pw()
        assertEquals(CardChangeResult.WrongPassword, cards.rename("Other", pw))
        assertTrue(pw.all { it == '\u0000' }, "wiped")
        assertEquals(emptyList<WireRoute>(), e.server.calls.toList(), "nothing was sent")
        assertEquals(1, e.instance.cards.size)
    }

    @Test fun aWrongPasswordStoresNothingAndTheGateRefusesWithoutASession() = runBlocking<Unit> {
        val e = operator()
        // This session holds no wrap of its own, so the password reaches the server, whose refusal is its own result.
        assertEquals(CardChangeResult.Refused(Reauthed.PROOF_REFUSED), e.cards.rename("Other", "not the password 123".toCharArray()))
        assertEquals(1, e.instance.cards.size)
        // A Reauth whose gate refuses at the entry (the origin is blocked here) derives and sends nothing.
        val noSession = Reauth(object : ReauthSession {
            override val origin = e.instance.origin
            override val emailNorm = "op@example.org"
            override suspend fun deriveCurrentAuthKey(password: CharArray): String? = error("must not derive")
        }) { listOf(io.silencelen.andvari.core.client.pin.GatePin(e.instance.origin, PinRoot.SETUP, "op@example.org", blocked = true)) }
        val cards = WireOperatorCards(e.session, e.server, crypto, e.trust, noSession, { e.instance.now })
        assertEquals(CardChangeResult.NoSession, cards.rename("Other", pw()))
        assertEquals(1, e.instance.cards.size)
    }

    @Test fun aMoveIsStoredAndThisDeviceConfirmsItLikeAnyoneElse() = runBlocking<Unit> {
        val e = operator()
        val other = member(e)
        // §4.4: a move never replaces a pin that already exists for the new origin, so this device refuses to make one.
        val held = e.trust.pinFor(e.instance.origin)!!.copy(origin = "https://taken.example")
        PinStore(e.state).put(held)
        assertEquals(CardChangeResult.Invalid(WireOperatorCards.ORIGIN_PINNED), e.cards.move("https://taken.example", pw()))
        PinStore(e.state).remove("https://taken.example")
        assertEquals(1, e.instance.cards.size)
        val stored = assertIs<CardChangeResult.Stored>(e.cards.move("https://vault.smiths.example", pw()))
        val moved = assertIs<CardStatus.Moved>(stored.status)
        assertEquals("https://vault.smiths.example", moved.newest.origin)
        assertEquals(e.instance.origin, e.trust.pinFor(e.instance.origin)!!.origin, "the pin did not move by itself")
        assertEquals("https://vault.smiths.example", newest(e).origin)
        assertEquals(1, newest(e).seq)
        // The operator confirms the move through the trust's own prompt, as every device does.
        assertIs<CardStatus.Ok>(e.trust.followMove(moved))
        assertEquals(stored.hash, e.trust.pinFor("https://vault.smiths.example")!!.hash)
        assertIs<CardStatus.Moved>(other.refresh(e.instance.origin))
    }

    @Test fun aMoveToSomethingThatIsNotAnOriginIsRefused() = runBlocking<Unit> {
        val e = operator()
        assertEquals(CardChangeResult.Invalid(WireOperatorCards.BAD_ORIGIN), e.cards.move("http://plain.example", pw()))
        assertEquals(CardChangeResult.Invalid(WireOperatorCards.BAD_ORIGIN), e.cards.move("https://vault.example/path", pw()))
        assertEquals(CardChangeResult.Invalid(WireOperatorCards.NO_CHANGE), e.cards.move(e.instance.origin, pw()))
        assertEquals(1, e.instance.cards.size)
    }

    @Test fun aHandoverNamesTheNewOperatorAndItsKeyAndThisAccountCanSignNoMore() = runBlocking<Unit> {
        val e = operator()
        val other = member(e)
        val heir = "77777777-7777-4777-8777-777777777777"
        val heirSign = crypto.signKeypairFromSeed(ByteArray(32) { 42 })
        val heirIdentity = Bytes.toB64(crypto.ed25519PkToCurve25519(heirSign.publicKey))
        e.server.members[heir] = heirIdentity to true
        // The key must be the person's own (when this account holds their identity key), and a real Ed25519 key.
        assertEquals(CardChangeResult.Invalid(WireOperatorCards.HANDOVER_KEY_MISMATCH),
            e.cards.handOver(heir, Bytes.toB64(heirSign.publicKey), Bytes.toB64(ByteArray(32) { 9 }), pw()))
        assertEquals(CardChangeResult.Invalid(WireOperatorCards.BAD_KEY), e.cards.handOver("not-a-uuid", Bytes.toB64(heirSign.publicKey), null, pw()))
        assertEquals(1, e.instance.cards.size)
        // An inactive target is the server's refusal.
        e.server.members[heir] = heirIdentity to false
        assertEquals(CardChangeResult.HandoverTargetInvalid, e.cards.handOver(heir, Bytes.toB64(heirSign.publicKey), heirIdentity, pw()))
        e.server.members[heir] = heirIdentity to true
        val done = assertIs<CardChangeResult.Changed>(e.cards.handOver(heir, Bytes.toB64(heirSign.publicKey), heirIdentity, pw()))
        val card = newest(e)
        assertEquals(heir, card.operator)
        assertEquals(Bytes.toB64(heirSign.publicKey), card.operatorSignKey)
        assertEquals(heir, done.pin.operator)
        assertEquals(heir, assertIs<CardStatus.Ok>(other.refresh(e.instance.origin)).pin.operator)
        // The old operator's key no longer signs the next card: refused before anything is derived.
        assertEquals(CardChangeResult.NotOperator, e.cards.rename("Mine again", pw()))
        // The new operator signs card 2 with its own key, and every verifier accepts it.
        val c2 = InstanceCard.sign(crypto, heirSign, card.copy(seq = 2, prev = done.hash, name = "Heir's", issuedAt = card.issuedAt + 1))
        e.instance.cards += c2
        assertNull(InstanceCard.verifyChain(crypto, e.instance.cards).verdict)
    }

    @Test fun theRecoveryKeyIsSetRotatedWithItsStatementFirstAndRemoved() = runBlocking<Unit> {
        val e = operator()
        val other = member(e)
        val (seedA, fpA) = recoveryKey(31)
        val (_, fpB) = recoveryKey(32)
        assertEquals(CardChangeResult.Invalid(WireOperatorCards.BAD_FP), e.cards.setRecoveryKey("A".repeat(64), pw()))
        assertIs<CardChangeResult.Changed>(e.cards.setRecoveryKey(fpA, pw()))
        assertEquals(fpA, newest(e).recoveryFp)
        // A change of key needs its rotation: a bare card is refused here.
        assertEquals(CardChangeResult.Invalid(WireOperatorCards.RECOVERY_KEY_SET), e.cards.setRecoveryKey(fpB, pw()))
        // A statement not signed by the key the card names is refused before anything is sent.
        val forged = RecoveryRotation.sign(crypto, recoveryKey(33).first, RotationFields(e.instance.instanceId, recoveryKey(33).second, fpB, e.instance.now))
        assertEquals(CardChangeResult.BadRotation("fp_mismatch"), e.cards.rotateRecoveryKey(listOf(forged), pw()))
        assertEquals(CardChangeResult.BadRotation("fp_mismatch"), e.cards.rotateRecoveryKey(emptyList(), pw()))
        // The real one, as `recovery-cli rotate` printed it offline.
        val rotation = RecoveryRotation.sign(crypto, seedA, RotationFields(e.instance.instanceId, fpA, fpB, e.instance.now))
        e.server.calls.clear()
        assertIs<CardChangeResult.Changed>(e.cards.rotateRecoveryKey(listOf(rotation), pw()))
        val order = e.server.calls.filter { it == WireRoute.INSTANCE_ROTATION_PUT || it == WireRoute.INSTANCE_CARD_PUT }
        assertEquals(listOf(WireRoute.INSTANCE_ROTATION_PUT, WireRoute.INSTANCE_CARD_PUT), order, "the rotation is uploaded before the card")
        assertEquals(fpB, newest(e).recoveryFp)
        assertEquals(1, e.instance.rotations.size)
        // Every client sees the change as signed: the served rotations cover it.
        val chainFields = InstanceCard.verifyChain(crypto, e.instance.cards).chain.cards.map { it.fields }
        assertEquals(listOf(1L), RecoveryRotation.unsignedChanges(crypto, chainFields, e.instance.rotations).map { it.seq }, "only the change from none is unsigned")
        assertIs<CardChangeResult.Changed>(e.cards.removeRecoveryKey(pw()))
        assertNull(newest(e).recoveryFp)
        assertEquals(TrustGrammar.NONE, assertIs<CardStatus.Ok>(other.refresh(e.instance.origin)).pin.recoveryFp)
        assertEquals(CardChangeResult.Invalid(WireOperatorCards.NO_CHANGE), e.cards.removeRecoveryKey(pw()))
        assertEquals(3, newest(e).seq, "card 0, then set, rotate and remove")
    }

    /**
     * The rotation call is held, the vault locks, the call is released. The upload goes on to
     * the card, signed before the lock (nothing is signed after it), so the server's card names the rotated key and its
     * rotation is stored with it: never rotations without their card.
     */
    @Test fun aLockWhileARotationIsUploadingStillStoresTheCardSignedBeforeIt() = runBlocking<Unit> {
        val e = operator()
        val (seedA, fpA) = recoveryKey(31)
        val (_, fpB) = recoveryKey(32)
        assertIs<CardChangeResult.Changed>(e.cards.setRecoveryKey(fpA, pw()))
        val rotation = RecoveryRotation.sign(crypto, seedA, RotationFields(e.instance.instanceId, fpA, fpB, e.instance.now))
        val cardsBefore = e.instance.cards.size
        e.server.duringRotationPut = { e.session.account.wipe() }
        val r = e.cards.rotateRecoveryKey(listOf(rotation), pw())
        assertTrue(e.session.account.isWiped, "the lock landed during the rotation's call")
        assertTrue(r is CardChangeResult.Changed || r is CardChangeResult.Stored, "the change was stored: $r")
        assertEquals(cardsBefore + 1, e.instance.cards.size, "the card went up after its rotation")
        assertEquals(fpB, newest(e).recoveryFp, "the server's card names the rotated key")
        assertEquals(1, e.instance.rotations.size)
    }

    @Test fun aPublicInstanceRefusesARecoveryKey() = runBlocking<Unit> {
        val e = operator(InstanceKind.PUBLIC)
        val (seedA, fpA) = recoveryKey(31)
        assertEquals(CardChangeResult.PublicRefusesRecoveryKey, e.cards.setRecoveryKey(fpA, pw()))
        val rotation = RecoveryRotation.sign(crypto, seedA, RotationFields(e.instance.instanceId, fpA, recoveryKey(32).second, e.instance.now))
        assertEquals(CardChangeResult.PublicRefusesRecoveryKey, e.cards.rotateRecoveryKey(listOf(rotation), pw()))
        assertEquals(1, e.instance.cards.size)
        // The rest of the card still changes on a public instance.
        assertIs<CardChangeResult.Changed>(e.cards.rename("andvari", pw()))
        assertEquals(InstanceKind.PUBLIC, newest(e).kind)
    }

    @Test fun aStaleNewestCardIsTheServersHeadMovedAndARetryStartsFromTheNewHead() = runBlocking<Unit> {
        val e = operator()
        // The operator's other device uploads card 1 between this device's refresh and its upload.
        e.server.beforeCardPut = {
            val pin = e.trust.pinFor(e.instance.origin)!!
            val c1 = CardFields(pin.instanceId, 1, pin.hash, pin.origin, "From the laptop", InstanceKind.PRIVATE, pin.operator, pin.operatorSignKey, null, e.instance.now)
            e.instance.cards += e.session.account.signing.use { InstanceCard.sign(crypto, it, c1) }
        }
        val moved = assertIs<CardChangeResult.HeadMoved>(e.cards.rename("From the desk", pw()))
        assertEquals(1L, moved.seq)
        assertEquals(SignedFrame.hash(crypto, e.instance.cards[1]), moved.hash)
        assertEquals(2, e.instance.cards.size, "nothing of this device's was stored")
        assertEquals(0L, e.trust.pinFor(e.instance.origin)!!.seq, "the pin moves only through the refresh")
        // Starting again refreshes first and builds on the new head.
        assertIs<CardChangeResult.Changed>(e.cards.rename("From the desk", pw()))
        assertEquals(2, newest(e).seq)
        assertEquals("From the desk", newest(e).name)
    }

    @Test fun onlyTheOperatorAccountReachesItAndEveryServerRefusalIsTyped() = runBlocking<Unit> {
        val e = operator()
        e.server.caller = "88888888-8888-4888-8888-888888888888"
        assertEquals(CardChangeResult.NotOperator, e.cards.rename("Taken", pw()))
        e.server.caller = null
        e.instance.override[WireRoute.INSTANCE_CARD_PUT] = WireResult.Refused(400, WireError("bad_card", "x"))
        assertEquals(CardChangeResult.BadCard, e.cards.rename("Taken", pw()))
        e.instance.override[WireRoute.INSTANCE_CARD_PUT] = WireResult.Refused(429, WireError("rate_limited", "x"), 30)
        assertEquals(CardChangeResult.Refused("rate_limited", 30), e.cards.rename("Taken", pw()))
        e.instance.override[WireRoute.INSTANCE_CARD_PUT] = WireResult.Refused(503, WireError("unavailable", "x"))
        assertEquals(CardChangeResult.Unknown, e.cards.rename("Taken", pw()))
        e.instance.override[WireRoute.INSTANCE_CARD_PUT] = WireResult.NoAnswer(NoAnswerKind.TIMEOUT)
        assertEquals(CardChangeResult.Unknown, e.cards.rename("Taken", pw()))
        e.instance.override.remove(WireRoute.INSTANCE_CARD_PUT)
        val (seedA, fpA) = recoveryKey(31)
        assertIs<CardChangeResult.Changed>(e.cards.setRecoveryKey(fpA, pw()))
        e.instance.override[WireRoute.INSTANCE_ROTATION_PUT] = WireResult.Refused(400, WireError("bad_rotation", "x"))
        val rotation = RecoveryRotation.sign(crypto, seedA, RotationFields(e.instance.instanceId, fpA, recoveryKey(32).second, e.instance.now))
        e.server.calls.clear()
        assertEquals(CardChangeResult.BadRotation(null), e.cards.rotateRecoveryKey(listOf(rotation), pw()))
        assertTrue(WireRoute.INSTANCE_CARD_PUT !in e.server.calls, "no card after a refused rotation")
        e.instance.override.clear()
        // Who is the operator is the newest verified card's word, never the role a session was opened with (so a hand-over
        // needs no second sign-in): a session opened as "member" by the account the card names signs the next card. Before,
        // the role alone refused it.
        val openedAsMember = WireOperatorCards(
            io.silencelen.andvari.core.client.onboard.EstablishedSession(e.session.origin, e.session.emailNorm, e.session.userId, e.session.deviceId, "member",
                false, false, true, e.session.how, "", "", e.session.accountKeys, e.session.account),
            e.server, crypto, e.trust, Reauth(object : ReauthSession {
                override val origin = e.instance.origin
                override val emailNorm = "op@example.org"
                override suspend fun deriveCurrentAuthKey(password: CharArray): String? {
                    val p = (e.server.call(WireRoute.PRELOGIN, bodyJson = WireJson.json.encodeToString(PreloginRequest.serializer(), PreloginRequest(emailNorm)),
                        decode = { WireJson.json.decodeFromString(PreloginResponse.serializer(), it) }) as WireResult.Ok).value
                    val k = PasswordKeys.derive(crypto, password.copyOf(), Bytes.fromB64(p.kdfSalt), p.kdfParams, served = true) ?: return null
                    return k.authKeyB64.also { k.wipe() }
                }
            }) { e.trust.gatePins() }, { e.instance.now },
        )
        assertIs<CardChangeResult.Changed>(openedAsMember.rename("Taken by the card's word", pw()))
        assertEquals("Taken by the card's word", newest(e).name)
        // And a session opened as "operator" by an account the card does not name never reaches the route: below.
        // A fork stops it before anything is built.
        e.instance.cards.clear()
        e.instance.cards += FakeInstance(crypto).cards[0]
        assertIs<CardStatus.Fork>(assertIs<CardChangeResult.NotCurrent>(e.cards.rename("Taken", pw())).status)
    }
}
