package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.AccountSession
import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.doc
import io.silencelen.andvari.cli.e2e.ok
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.items.ItemFailure
import io.silencelen.andvari.core.client.items.ItemResult
import io.silencelen.andvari.core.client.items.NewAttachment
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.net.BODY_OVER_LIMIT
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.pin.BakedInstance
import io.silencelen.andvari.core.client.pin.CardStatus
import io.silencelen.andvari.core.client.pin.CardTrust
import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.pin.MOVE_TO_BAKED_ORIGIN
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.client.pin.ServerForgotten
import io.silencelen.andvari.core.client.pin.TrustCardChainVerifier
import io.silencelen.andvari.core.client.pin.TrustGateWording
import io.silencelen.andvari.core.crypto.Attachments
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.RefreshRequest
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.TrustGrammar
import io.silencelen.andvari.hostile.proxy.Endless
import io.silencelen.andvari.hostile.proxy.Gate
import io.silencelen.andvari.hostile.proxy.Resp
import io.silencelen.andvari.hostile.proxy.editAnswer
import io.silencelen.andvari.hostile.proxy.hold
import io.silencelen.andvari.hostile.proxy.serveCards
import io.silencelen.andvari.hostile.proxy.set
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The pin store's newer rules under a hostile server (design §4.4 "No credential goes to an origin without a pin in
 * force", "Rules for the pin store"; spec 03 §9): a session left without its pin, a fork judged across "Forget this
 * server", a move onto the baked address, the per-origin wipe under a forked and a damaged pin, and an attachment body
 * larger than its item says.
 */
class PinRulesTest {
    private val password get() = Steps.PASSWORD.toCharArray()

    /** A request that carries a credential: a bearer, or a route that is not credential-free (design §4.4). */
    private fun credentialed(r: io.silencelen.andvari.hostile.proxy.Req) = r.bearer != null || r.route?.credentialFree != true

    /**
     * §4.4: "A kept session whose origin holds no pin record (a move that stopped half-way, a record that was lost) is
     * shown as a blocked server that can be forgotten: it does not unlock, it dials nothing, and signing it out ends it on
     * the device without telling the server."
     */
    @Test fun aKeptSessionWhosePinRecordIsGoneSendsNothingWithACredentialSignOutIncluded() = world {
        operator()
        val ah = member("alice")
        val a = account(ah)
        a.synced()
        val held = ah.session(origin)!!
        // The pin record is lost; the session the device kept is not.
        ah.pins.remove(origin)
        assertEquals(PinState.None, ah.trust.pinState(origin))
        val mark = proxy.mark()

        a.sync()
        a.putItem(a.personalVaultId!!, doc("with no pin"))
        a.logs.append(null, LogAction.Create("with no pin"))
        ah.accountState(held).read()
        val refreshed = ah.client(origin).call(WireRoute.REFRESH, bodyJson = WireJson.json.encodeToString(RefreshRequest.serializer(), RefreshRequest(held.refreshToken)), decode = { it })
        assertIs<WireResult.Refused>(refreshed, "the refresh is stopped")
        ah.reauth(held).currentAuthKey(password)
        // Sign-out as the CLI does it: the logout through the dialer, then the device forgets the session.
        val logout = ah.withToken(origin, held.accessToken).call(WireRoute.LOGOUT, decode = { })
        assertIs<WireResult.Refused>(logout, "the logout is stopped too")
        ah.signedOut(origin)

        val sent = proxy.requests(tag = "alice", since = mark)
        assertTrue(sent.none(::credentialed), "nothing with a credential left the device:\n${sent.filter(::credentialed).joinToString("\n") { "$it  (bearer: ${it.bearer != null})" }}")
        assertTrue(ah.session(origin) == null, "signed out on the device")
    }

    /**
     * §4.4 "Rules for the pin store": a fork mark is written only over the pin that was judged. A refresh of Alice's pin
     * is held at the proxy while the operator's key serves a new card 0 (a fork of her pin); before the held answer
     * arrives she forgets the server and pins the new chain through the Trust Gate. The late judgment marks nothing:
     * the new pin stays in force, also after a restart.
     */
    @Test fun aForkJudgedWhileThePersonForgetsTheServerAndPinsAgainLeavesTheNewPinInForce() = world {
        val oh = operator()
        val ah = member("alice")
        val userId = ah.session(origin)!!.userId
        val base = oh.trust.pinFor(origin)!!
        val reset = Adversary.signCard(oh, origin, base, server.now()) { it.copy(seq = 0, prev = TrustGrammar.ZERO_HASH, name = "After the reset") }
        val newChain = editAnswer { body -> body.set("cards", JsonArray(listOf(JsonPrimitive(reset)))) }
        proxy.on(WireRoute.INSTANCE, "alice", name = "the reset chain", handler = newChain)
        val gate = Gate()
        proxy.on(WireRoute.INSTANCE, "alice", name = "held refresh", times = 1, handler = hold(gate, then = newChain))

        withContext(Dispatchers.IO) {
            val late = async { ah.trust.refresh(origin) }
            gate.awaitArrival()
            assertEquals(ServerForgotten.Done, ah.trust.forgetServer(origin, listOf(userId)))
            val g = assertIs<FirstPin.NeedsTrustGate>(ah.trust.beginTrustGate(origin, TrustGateWording.TYPED_ADDRESS))
            assertIs<FirstPin.Pinned>(ah.trust.confirmTrustGate(g.confirm))
            gate.release()
            val answered = late.await()
            assertTrue(answered !is CardStatus.Fork, "the late judgment is not a fork of the new pin: $answered")
        }
        val now = assertIs<PinState.Pinned>(ah.trust.pinState(origin), "the new pin stays in force")
        assertEquals(io.silencelen.andvari.hostile.proxy.Frames.hash(reset), now.pin.card0Hash)
        assertIs<PinState.Pinned>(restarted(ah).trust.pinState(origin), "and durably")
        assertIs<CardStatus.Ok>(ah.trust.refresh(origin))
    }

    /**
     * §4.4 "A move to an origin this device cannot keep a pin for is refused before the pin moves": the operator's key
     * signs a move of this instance onto the address the build bakes in for ANOTHER instance. The device's trust engine
     * is built as an app build with a baked instance would build it, over its own pin store and its dialer through the
     * proxy. The tap is refused, nothing moves, and the baked address is never dialed.
     */
    @Test fun aMoveOntoTheBakedAddressByAnInstanceThatIsNotTheBakedOneIsRefusedBeforeThePinMoves() = world {
        val oh = operator()
        val base = oh.trust.pinFor(origin)!!
        val bakedOrigin = proxy.dial("baked")
        val dh = device("app")
        val trust = CardTrust(PinStore(dh.state), TrustCardChainVerifier(dh.crypto), dh::client, dh.crypto,
            BakedInstance(bakedOrigin, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "ab".repeat(32), "public"), storeBuild = false)
        val g = assertIs<FirstPin.NeedsTrustGate>(trust.beginTrustGate(origin, TrustGateWording.TYPED_ADDRESS))
        assertIs<FirstPin.Pinned>(trust.confirmTrustGate(g.confirm))
        val pinned = trust.pinFor(origin)!!

        val move = Adversary.signCard(oh, origin, base, server.now()) { it.copy(origin = bakedOrigin) }
        proxy.serveCards("app") { genuine -> genuine + move }
        val moved = assertIs<CardStatus.Moved>(trust.refresh(origin), "a signed move")
        val refused = assertIs<CardStatus.Refused>(trust.followMove(moved), "the tap is refused")
        assertEquals(MOVE_TO_BAKED_ORIGIN, refused.verdict)
        assertEquals(pinned, trust.pinFor(origin), "the pin did not move")
        assertEquals(PinState.None, trust.pinState(bakedOrigin), "nothing was pinned at the baked address")
        assertTrue(proxy.requests(tag = "baked").isEmpty(), "the baked address was never dialed")
    }

    /**
     * Every record [h] keeps for [origin] and its account [userId], mirrored under [otherOrigin] and [otherUser]: what
     * another server and another account would have kept on the same device. Answers the mirrored keys and values.
     */
    private fun World.mirror(h: Host, userId: String, otherOrigin: String, otherUser: String): Map<String, String> {
        val all = h.state.keys()!!
        val copies = all.filter { origin in it || userId in it }.associate { k -> k.replace(origin, otherOrigin).replace(userId, otherUser) to h.state.get(k)!! }
        copies.forEach { (k, v) -> h.state.set(k, v) }
        return copies
    }

    /** No record of [origin] or [userId] is left in [h]'s device state but the identity record and the CLI's own. */
    private fun World.nothingLeftOf(h: Host, userId: String) {
        val left = h.state.keys()!!.filter { (origin in it || userId in it) && !it.startsWith("ovh.identity|") && !it.startsWith("cli.") }
        assertTrue(left.isEmpty(), "records of the forgotten server are left: $left")
    }

    /**
     * §4.4, §12.3 "Forget this server": the only way on after a fork or a damaged pin, local only. Under a forked pin and
     * under a damaged one, every record of that server and of the account kept there goes; another server's and another
     * account's records on the same device stay, value for value, and nothing is sent. Then the address passes the
     * Trust Gate again and the account signs in.
     */
    @Test fun forgetThisServerUnderAForkedAndADamagedPinRemovesEverythingOfThatServerAndNothingElse() = world {
        operator()
        for ((tag, spoil) in listOf<Pair<String, (Host) -> Unit>>(
            "alice" to { h -> val p = h.trust.pinFor(origin)!!; assertTrue(PinStore(h.state).markForked(p)) },
            "bob" to { h -> h.state.set(PinStore.KEY_PREFIX + origin, "{not a pin") },
        )) {
            val h = member(tag)
            val a = account(h)
            a.synced()
            a.ok(null, LogAction.Create("Mine"))
            val userId = h.session(origin)!!.userId
            val others = mirror(h, userId, "https://other.example", "99999999-0000-4000-8000-000000000001")
            assertTrue(others.keys.any { it.startsWith("ovh.log|") } && others.keys.any { it.startsWith("ovh.pin|") }, "the mirror holds log and pin records: ${others.keys}")
            spoil(h)
            assertTrue(h.trust.pinState(origin) !is PinState.Pinned, "$tag: the pin is spoiled")
            val mark = proxy.mark()
            assertEquals(ServerForgotten.Done, h.trust.forgetServer(origin, listOf(userId)), tag)
            h.dropSession(origin)
            assertTrue(proxy.requests(tag = tag, since = mark).isEmpty(), "$tag: forgetting sends nothing")
            assertEquals(PinState.None, h.trust.pinState(origin))
            nothingLeftOf(h, userId)
            for ((k, v) in others) assertEquals(v, h.state.get(k), "$tag: another server's or account's record stays: $k")
            // The way on: the Trust Gate again, then the password.
            val g = assertIs<FirstPin.NeedsTrustGate>(h.trust.beginTrustGate(origin, TrustGateWording.TYPED_ADDRESS))
            assertIs<FirstPin.Pinned>(h.trust.confirmTrustGate(g.confirm))
            assertIs<io.silencelen.andvari.core.client.onboard.SignIn.SignedIn>(h.onboarding(origin).signIn("$tag@example.org", password))
        }
    }

    private suspend fun AccountSession.saveWithFile(vaultId: String, data: ByteArray): AttachmentRef {
        val ref = AttachmentRef(Bytes.uuidV4FromBytes(host.crypto.randomBytes(16)), "file.bin", data.size.toLong(), Bytes.toB64(host.crypto.randomBytes(32)))
        assertIs<ItemResult.Ok<*>>(items.save(null, ItemDoc(type = "note", name = "with a file", attachments = listOf(ref)), vaultId, uploads = listOf(NewAttachment(ref, data))))
        return ref
    }

    /** The two lies of a body larger than its claim: by `Content-Length`, and with no length at all (chunked, endless). */
    private val oversize = listOf("by length" to Endless(declaredLength = 1L shl 30, upTo = 64L shl 20), "with no length" to Endless(declaredLength = null, upTo = 64L shl 20))

    /** At most this much may reach the device before it hangs up: the claim plus what sockets buffer, far below the lie. */
    private val buffered = 16L shl 20

    /**
     * Spec 03 §9 and the engine's capped download: `fetchBytes(…, maxBytes)` reads no more than the cap. The server answers
     * an attachment with a body far larger than the item's claim, once declaring its length and once with none; the
     * capped read is refused (`body_over_limit`) after the device took at most the cap, and the genuine file still opens.
     */
    @Test fun anAttachmentBodyLargerThanItsClaimIsRefusedAtTheCapByLengthAndWithoutOne() = world {
        operator()
        val ah = member("alice")
        val a = account(ah)
        a.synced()
        val data = ByteArray(4096) { 7 }
        val ref = a.saveWithFile(a.personalVaultId!!, data)
        val expected = Attachments.wireLength(ref.size)
        for ((what, lie) in oversize) {
            val rule = proxy.on(WireRoute.ATTACHMENT_GET, "alice", where = { it.param("attachmentId") == ref.id }) { _ ->
                Resp(200, mapOf("Content-Type" to "application/octet-stream"), ByteArray(0), lie)
            }
            val mark = proxy.mark()
            val r = ah.client(origin).fetchBytes(WireRoute.ATTACHMENT_GET, mapOf("attachmentId" to ref.id), null, true, expected)
            assertEquals(BODY_OVER_LIMIT, assertIs<WireResult.Refused>(r, "$what: $r").code, what)
            val ex = proxy.since(mark).single { it.req.route == WireRoute.ATTACHMENT_GET }
            assertTrue(ex.written < buffered, "$what: the device took ${ex.written} bytes of a lie of ${lie.upTo}")
            rule.remove()
        }
        assertContentEquals(data, assertIs<ItemResult.Ok<ByteArray>>(a.items.downloadAttachment(ref)).value, "the genuine file opens")
    }

    /**
     * The same lie through the item engine's own download (the vault-content code's `WireAttachments.download`): the item
     * is refused as the wrong size, and the device must not hold more than the claim to find that out.
     */
    @Test fun anAttachmentBodyLargerThanItsClaimIsRefusedByTheItemEngineAtTheCap() = world {
        operator()
        val ah = member("alice")
        val a = account(ah)
        a.synced()
        val ref = a.saveWithFile(a.personalVaultId!!, ByteArray(4096) { 7 })
        for ((what, lie) in oversize) {
            val rule = proxy.on(WireRoute.ATTACHMENT_GET, "alice", where = { it.param("attachmentId") == ref.id }) { _ ->
                Resp(200, mapOf("Content-Type" to "application/octet-stream"), ByteArray(0), lie)
            }
            val mark = proxy.mark()
            val failed = assertIs<ItemResult.Failed>(a.items.downloadAttachment(ref), what)
            assertEquals(ItemFailure.Corrupt("size"), failed.why, what)
            val ex = proxy.since(mark).single { it.req.route == WireRoute.ATTACHMENT_GET }
            assertTrue(ex.written < buffered, "$what: the device took ${ex.written} bytes of a lie of ${lie.upTo}")
            rule.remove()
        }
    }
}
