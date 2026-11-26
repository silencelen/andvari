package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.CardOps
import io.silencelen.andvari.cli.CardWrite
import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.core.client.account.Fetched
import io.silencelen.andvari.core.client.devicelink.DeviceLinkStop
import io.silencelen.andvari.core.client.devicelink.ExistingStep
import io.silencelen.andvari.core.client.devicelink.NewStep
import io.silencelen.andvari.core.client.pin.CardStatus
import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.client.pin.TrustGateWording
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.Frames
import io.silencelen.andvari.hostile.proxy.Gate
import io.silencelen.andvari.hostile.proxy.edit
import io.silencelen.andvari.hostile.proxy.editAnswer
import io.silencelen.andvari.hostile.proxy.hold
import io.silencelen.andvari.hostile.proxy.obj
import io.silencelen.andvari.hostile.proxy.serveCards
import io.silencelen.andvari.hostile.proxy.set
import io.silencelen.andvari.hostile.proxy.str
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Device links under a hostile server (design §8.2, §8.3, §2.4 "Device link"). E is the existing device, N the new one.
 * Without the link secret the server "cannot forge a claim, swap `nPub`, read the bundle, or produce an approval N
 * accepts"; what it can do is replay, swap and race, and each of those must end the link before any password is typed.
 */
class DeviceLinkTest {
    private val password get() = Steps.PASSWORD.toCharArray()

    private class Pairing(val eh: Host, val nh: Host, val shown: ExistingStep.Shown, val fixed: ExistingStep.ClaimFixed, val code: NewStep.ShowCode)

    /** E shows a link; N starts it from its own screen (passing its Trust Gate when it has no pin), claims; E fixes the claim; N reveals and shows its code. */
    private suspend fun pair(eh: Host, nh: Host): Pairing {
        val shown = assertIs<ExistingStep.Shown>(eh.deviceLinks.create(), "E shows a link")
        var n = nh.deviceLinks.start(shown.url, GateEntry.LINK_DEVICE_SCREEN)
        if (n is NewStep.TrustGate) n = nh.deviceLinks.afterTrustGate(n, confirmed = true)
        val claimed = assertIs<NewStep.Claimed>(n, "N claims: $n")
        val fixed = assertIs<ExistingStep.ClaimFixed>(eh.deviceLinks.advance(shown), "E fixes the claim")
        val code = assertIs<NewStep.ShowCode>(nh.deviceLinks.advance(claimed), "N reveals and shows its code")
        return Pairing(eh, nh, shown, fixed, code)
    }

    /** The person types N's digits into E, and E approves. */
    private suspend fun approve(p: Pairing) {
        val type = assertIs<ExistingStep.TypeDigits>(p.eh.deviceLinks.advance(p.fixed))
        val approvable = assertIs<ExistingStep.Approvable>(p.eh.deviceLinks.typeDigits(type, p.code.code), "the typed digits match")
        assertIs<ExistingStep.Approved>(p.eh.deviceLinks.approve(approvable))
    }

    private fun World.approval(tag: String): JsonObject = proxy.last(WireRoute.DEVICE_LINK_APPROVE, tag)!!.req.json!!

    private val otherNonce = Frames.b64(ByteArray(32) { 7 })

    /**
     * §8.2 step 4 (T2-R-b), §17: "the harness also re-serves a different `nonceE` after the reveal … and asserts that
     * [it] cancel[s]". N holds the first `nonceE` it received; another one served later ends the link before the
     * approval can be read and before any password prompt.
     */
    @Test fun aDifferentNonceEServedAfterTheRevealCancelsTheLinkBeforeAnyPassword() = world {
        operator()
        val eh = member("alice")
        val nh = device("new")
        val p = pair(eh, nh)
        approve(p)
        proxy.on(WireRoute.DEVICE_LINK_POLL, "new", handler = editAnswer { it.set("nonceE", otherNonce) })
        val mark = proxy.mark()
        assertEquals(NewStep.Stopped(DeviceLinkStop.NONCE_CHANGED), nh.deviceLinks.advance(p.code), "a second, different nonceE is an anomaly that cancels the link")
        assertEquals(NewStep.Stopped(DeviceLinkStop.STALE), nh.deviceLinks.advance(p.code), "the link is over on N")
        assertTrue(proxy.requests(tag = "new", since = mark).none { it.route == WireRoute.PRELOGIN || it.route == WireRoute.DEVICE_LINK_PICKUP }, "no password was asked for or sent")
        assertNull(nh.session(origin))
    }

    /**
     * §8.2 step 3 (T2-R-b): "E fixes the claim when it draws `nonceE`. A later poll that shows a different claim (`nPub`,
     * `name`, `platform` or `commitN`) cancels the link."
     */
    @Test fun aClaimThatChangesAfterTheExistingDeviceFixedItCancelsTheLink() = world {
        operator()
        val eh = member("alice")
        for (field in listOf("name" to Frames.b64("someone else's phone".encodeToByteArray()), "nPub" to otherNonce, "commitN" to "cd".repeat(32), "platform" to "android")) {
            val p = pair(eh, device("new-" + field.first))
            val swap = proxy.on(WireRoute.DEVICE_LINK_VIEW, "alice", handler = editAnswer { v -> v.edit("claim") { it.set(field.first, field.second) } })
            val mark = proxy.mark()
            assertEquals(ExistingStep.Stopped(DeviceLinkStop.CLAIM_CHANGED), eh.deviceLinks.advance(p.fixed), "the claim's ${field.first} changed")
            assertEquals(1, sent(eh, WireRoute.DEVICE_LINK_CANCEL, mark).size, "E cancels the link")
            assertTrue(sent(eh, WireRoute.DEVICE_LINK_APPROVE, mark).isEmpty())
            swap.remove()
        }
    }

    /** The same swap one step later: after the person typed the right digits, at the approval. Nothing is sealed to the other key. */
    @Test fun aClaimSwappedAfterTheDigitsWereTypedIsCaughtAtTheApprovalAndNothingIsSealed() = world {
        operator()
        val eh = member("alice")
        val p = pair(eh, device("new"))
        val type = assertIs<ExistingStep.TypeDigits>(eh.deviceLinks.advance(p.fixed))
        val approvable = assertIs<ExistingStep.Approvable>(eh.deviceLinks.typeDigits(type, p.code.code))
        proxy.on(WireRoute.DEVICE_LINK_VIEW, "alice", handler = editAnswer { v -> v.edit("claim") { it.set("nPub", otherNonce) } })
        val mark = proxy.mark()
        assertEquals(ExistingStep.Stopped(DeviceLinkStop.CLAIM_CHANGED), eh.deviceLinks.approve(approvable))
        assertTrue(sent(eh, WireRoute.DEVICE_LINK_APPROVE, mark).isEmpty(), "no outer, bundle or approval was made for a claim E did not fix")
    }

    /** §8.2: "Without `s` it cannot forge a claim, swap `nPub`": a claim E sees first with a field the MAC does not cover is `bad_mac`. */
    @Test fun aClaimTheServerAlteredBeforeTheExistingDeviceSawItIsBadMac() = world {
        operator()
        val eh = member("alice")
        val nh = device("new")
        val shown = assertIs<ExistingStep.Shown>(eh.deviceLinks.create())
        val gate = assertIs<NewStep.TrustGate>(nh.deviceLinks.start(shown.url, GateEntry.LINK_DEVICE_SCREEN))
        assertIs<NewStep.Claimed>(nh.deviceLinks.afterTrustGate(gate, confirmed = true))
        proxy.on(WireRoute.DEVICE_LINK_VIEW, "alice", handler = editAnswer { v -> v.edit("claim") { it.set("nPub", otherNonce) } })
        val mark = proxy.mark()
        assertEquals(ExistingStep.Stopped(DeviceLinkStop.BAD_MAC), eh.deviceLinks.advance(shown))
        assertTrue(sent(eh, WireRoute.DEVICE_LINK_NONCE, mark).isEmpty(), "E draws no nonce for a claim it could not verify")
    }

    /** §8.2 step 4: E checks `commit(nonceN) = commitN` (`bad_reveal`); the server stores one reveal, and a second value is an anomaly. */
    @Test fun aRevealThatDoesNotOpenTheClaimsCommitmentOrChangesLaterIsBadReveal() = world {
        operator()
        val eh = member("alice")
        // A reveal that was never committed to.
        var p = pair(eh, device("new1"))
        var lie = proxy.on(WireRoute.DEVICE_LINK_VIEW, "alice", handler = editAnswer { it.set("nonceN", otherNonce) })
        assertEquals(ExistingStep.Stopped(DeviceLinkStop.BAD_REVEAL), eh.deviceLinks.advance(p.fixed))
        lie.remove()
        // The genuine reveal first, then another.
        p = pair(eh, device("new2"))
        val type = assertIs<ExistingStep.TypeDigits>(eh.deviceLinks.advance(p.fixed))
        lie = proxy.on(WireRoute.DEVICE_LINK_VIEW, "alice", handler = editAnswer { it.set("nonceN", otherNonce) })
        assertEquals(ExistingStep.Stopped(DeviceLinkStop.BAD_REVEAL), eh.deviceLinks.advance(type))
    }

    /**
     * §2.4, §8.2 step 7 (FC-3): on N, before any password prompt, "`bad_mac` first (`approveMac` covers the raw sealed
     * bytes, so it is checked before anything is opened or parsed)". An `outer` of the server's own making, another
     * link's `outer`, or another link's `outer` WITH its own valid MAC: all end there, and no prelogin is sent.
     */
    @Test fun anOuterOrApprovalFromAnotherLinkOrOfTheServersMakingIsBadMacBeforeAnyPasswordPrompt() = world {
        operator()
        val eh = member("alice")
        val bh = member("bob")
        // Another account's link, approved: the server holds its outer, inner and approval.
        approve(pair(bh, device("bobs-new")))
        val foreign = approval("bob")

        val swaps: List<Pair<String, (JsonObject) -> JsonObject>> = listOf(
            "an outer the server made up" to { r -> r.set("outer", Frames.b64(ByteArray(96) { 3 })) },
            "another link's outer under this link's approval" to { r -> r.set("outer", foreign.str("outer")!!) },
            "another link's outer with that link's approval" to { r -> r.set("outer", foreign.str("outer")!!).set("approveMac", foreign.str("approveMac")!!) },
            "this link's outer under another link's approval" to { r -> r.set("approveMac", foreign.str("approveMac")!!) },
        )
        for ((i, swap) in swaps.withIndex()) {
            val tag = "new$i"
            val nh = device(tag)
            val p = pair(eh, nh)
            approve(p)
            proxy.on(WireRoute.DEVICE_LINK_POLL, tag, handler = editAnswer(swap.second))
            val mark = proxy.mark()
            assertEquals(NewStep.Stopped(DeviceLinkStop.BAD_MAC), nh.deviceLinks.advance(p.code), swap.first)
            assertTrue(proxy.requests(tag = tag, since = mark).none { it.route == WireRoute.PRELOGIN || it.route == WireRoute.DEVICE_LINK_PICKUP }, "${swap.first}: no password was asked for")
        }
    }

    /**
     * §2.4, §8.2 step 8: after the pickup and the unlock, an `inner` from another link fails on its AD
     * (`bundle_unopenable`), whether it is another account's or an earlier link of the same account. "If any check
     * fails after the session arrived, N signs that session out at once."
     */
    @Test fun anInnerFromAnotherLinkOrAnotherAccountIsBundleUnopenableAndTheNewSessionIsSignedOut() = world {
        operator()
        val eh = member("alice")
        val bh = member("bob")
        approve(pair(bh, device("bobs-new")))
        val bobs = approval("bob").str("inner")!!
        // An earlier link of Alice's own account, approved and never picked up.
        approve(pair(eh, device("alices-earlier")))
        val earlier = approval("alice").str("inner")!!

        for ((i, case) in listOf("another account's inner" to bobs, "an earlier link's inner of the same account" to earlier).withIndex()) {
            val tag = "new$i"
            val nh = device(tag)
            val p = pair(eh, nh)
            approve(p)
            val need = assertIs<NewStep.PasswordNeeded>(nh.deviceLinks.advance(p.code))
            proxy.on(WireRoute.DEVICE_LINK_PICKUP, tag, handler = editAnswer { it.set("inner", case.second) })
            val mark = proxy.mark()
            assertEquals(NewStep.Stopped(DeviceLinkStop.BUNDLE_UNOPENABLE), nh.deviceLinks.pickup(need, password), case.first)
            assertNull(nh.session(origin), "${case.first}: no session is kept")
            assertEquals(1, proxy.requests(WireRoute.END_SESSION, tag, mark).size, "${case.first}: the session the server created is ended at once, alone")
        }
    }

    /**
     * §2.4 `identity_mismatch`, §8.2 step 8: the session the pickup answers must be the account `outer` named, and its
     * keys must be that account's: the identity seed under the UVK the typed password opens, and the genesis it signed.
     * A session or key material of another account ends the link and is signed out.
     */
    @Test fun aPickupAnswerCarryingAnotherAccountsSessionOrKeysIsIdentityMismatch() = world {
        operator()
        val eh = member("alice")
        member("bob")
        val bobs = proxy.last(WireRoute.REGISTER, "bob")!!.upstream!!.json!!
        val swaps: List<Pair<String, (JsonObject) -> JsonObject>> = listOf(
            "another account's whole session" to { r -> r.set("session", bobs) },
            "another account's key material under this account's id" to { r -> r.edit("session") { s -> s.set("accountKeys", bobs.obj("accountKeys")!!) } },
            "another account's identity key and genesis" to { r ->
                r.edit("session") { s -> s.edit("accountKeys") { k -> k.set("identityPub", bobs.obj("accountKeys")!!.str("identityPub")!!).set("genesis", bobs.obj("accountKeys")!!.str("genesis")!!) } }
            },
        )
        for ((i, swap) in swaps.withIndex()) {
            val tag = "new$i"
            val nh = device(tag)
            val p = pair(eh, nh)
            approve(p)
            val need = assertIs<NewStep.PasswordNeeded>(nh.deviceLinks.advance(p.code))
            proxy.on(WireRoute.DEVICE_LINK_PICKUP, tag, handler = editAnswer(swap.second))
            assertEquals(NewStep.Stopped(DeviceLinkStop.IDENTITY_MISMATCH), nh.deviceLinks.pickup(need, password), swap.first)
            assertNull(nh.session(origin), "${swap.first}: no session is kept")
        }
    }

    /**
     * §8.2 step 8 (T2-B1), §4.4: "the bundle's card checkpoint … must then agree with that pin, or the device signs
     * out", "also when the chain still ends below the checkpoint after fetching forward: the device signs out and
     * removes that pin", and "a device link's `pin_mismatch` removes only the pin that link made in its step 0, never a
     * pin the device already had."
     */
    @Test fun aCardChainThatStaysBelowTheBundlesCheckpointIsPinMismatchSignsOutAndDropsOnlyThePinTheLinkMade() = world {
        val oh = operator()
        val eh = member("alice")
        assertEquals(1L, assertIs<CardWrite.Stored>(CardOps(oh, oh.session(origin)!!).sign(password, name = "renamed")).seq)
        assertEquals(1L, assertIs<CardStatus.Ok>(eh.trust.refresh(origin)).pin.seq) // E's checkpoint is card 1

        // N is only ever shown card 0. Its pin is made by this link's own step 0.
        proxy.serveCards("new") { it.take(1) }
        val nh = device("new")
        var p = pair(eh, nh)
        approve(p)
        var need = assertIs<NewStep.PasswordNeeded>(nh.deviceLinks.advance(p.code))
        var mark = proxy.mark()
        assertEquals(NewStep.Stopped(DeviceLinkStop.PIN_MISMATCH), nh.deviceLinks.pickup(need, password), "the chain N can fetch ends below the bundle's card")
        assertNull(nh.session(origin))
        assertEquals(1, proxy.requests(WireRoute.END_SESSION, "new", mark).size, "N ends its session alone")
        assertEquals(PinState.None, nh.trust.pinState(origin), "the pin this link made in step 0 is removed")

        // A device that had pinned the address before the link keeps that pin.
        proxy.serveCards("old") { it.take(1) }
        val kept = device("old")
        val g = assertIs<FirstPin.NeedsTrustGate>(kept.trust.beginTrustGate(origin, TrustGateWording.TYPED_ADDRESS))
        val own = assertIs<FirstPin.Pinned>(kept.trust.confirmTrustGate(g.confirm)).pin
        p = pair(eh, kept)
        approve(p)
        need = assertIs<NewStep.PasswordNeeded>(kept.deviceLinks.advance(p.code))
        mark = proxy.mark()
        assertEquals(NewStep.Stopped(DeviceLinkStop.PIN_MISMATCH), kept.deviceLinks.pickup(need, password))
        assertNull(kept.session(origin))
        assertEquals(own, kept.trust.pinFor(origin), "a pin the device already had is never removed by a link")
        assertEquals(PinRoot.TRUST_GATE, kept.trust.pinFor(origin)!!.root)
    }

    /**
     * §8.2 step 2 and "What this defeats": "The first claim wins (`409 link_claimed`)." Whoever read the QR first claims
     * it; the person's own device is told so, and the claimant gets nothing: the digits E asks for are not on any
     * screen the person holds, a wrong entry cancels the link, and no device or session was ever created.
     */
    @Test fun aSecondClaimRacingTheFirstLosesAndTheHijackedLinkEndsAtTheTypedDigits() = world {
        operator()
        val eh = member("alice")
        val mine = device("mine")
        val thief = device("thief", name = "alice desktop")
        val shown = assertIs<ExistingStep.Shown>(eh.deviceLinks.create())
        // The person's own claim is held on the wire while the thief's goes first.
        val gate = Gate()
        proxy.on(WireRoute.DEVICE_LINK_CLAIM, "mine", handler = hold(gate))
        withContext(Dispatchers.IO) {
            val own = async {
                val g = assertIs<NewStep.TrustGate>(mine.deviceLinks.start(shown.url, GateEntry.LINK_DEVICE_SCREEN))
                mine.deviceLinks.afterTrustGate(g, confirmed = true)
            }
            gate.awaitArrival()
            val tg = assertIs<NewStep.TrustGate>(thief.deviceLinks.start(shown.url, GateEntry.LINK_DEVICE_SCREEN))
            val claimed = assertIs<NewStep.Claimed>(thief.deviceLinks.afterTrustGate(tg, confirmed = true), "the thief claims first")
            gate.release()
            assertEquals(NewStep.Stopped(DeviceLinkStop.LINK_CLAIMED), own.await(), "the person's device is told the link was claimed")

            val fixed = assertIs<ExistingStep.ClaimFixed>(eh.deviceLinks.advance(shown))
            val code = assertIs<NewStep.ShowCode>(thief.deviceLinks.advance(claimed))
            val type = assertIs<ExistingStep.TypeDigits>(eh.deviceLinks.advance(fixed))
            // The person has no code to type: their own device shows none. Anything else cancels the link.
            val mark = proxy.mark()
            val wrong = if (code.code == "000000") "111111" else "000000"
            assertEquals(ExistingStep.Stopped(DeviceLinkStop.CODE_MISMATCH), eh.deviceLinks.typeDigits(type, wrong))
            assertEquals(1, sent(eh, WireRoute.DEVICE_LINK_CANCEL, mark).size, "a mismatch cancels the link")
            assertEquals(NewStep.Stopped(DeviceLinkStop.CANCELLED), thief.deviceLinks.advance(code))
        }
        assertNull(thief.session(origin))
        val devices = assertIs<Fetched.Ok<List<io.silencelen.andvari.core.model.wire.Device>>>(eh.settings(eh.session(origin)!!).list()).value
        assertEquals(1, devices.size, "no device was added: $devices")
        assertTrue(proxy.requests(WireRoute.DEVICE_LINK_PICKUP).isEmpty() && proxy.requests(WireRoute.PRELOGIN, "thief").isEmpty())
    }

    /** The honest run through the proxy, so that every refusal above is known to be the lie's doing and not the proxy's. */
    @Test fun anUntouchedDeviceLinkLinksThroughTheProxy() = world {
        operator()
        val eh = member("alice")
        val nh = device("new")
        val p = pair(eh, nh)
        approve(p)
        val need = assertIs<NewStep.PasswordNeeded>(nh.deviceLinks.advance(p.code))
        assertEquals("alice@example.org", need.email)
        assertEquals(origin, need.origin)
        val linked = assertIs<NewStep.Linked>(nh.deviceLinks.pickup(need, password))
        assertEquals(account(eh).userId, linked.userId)
        assertNotNull(nh.session(origin))
    }
}
