package io.silencelen.andvari.core.client.devicelink

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.link.LinkAccount
import io.silencelen.andvari.core.client.link.MemoryAccountState
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KeyPairBytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.DeviceLinkClaim
import io.silencelen.andvari.core.model.wire.DeviceLinkPollResponse
import io.silencelen.andvari.core.model.wire.DeviceLinkView
import io.silencelen.andvari.core.model.wire.LinkCreatedResponse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.DeviceLinkUrl
import io.silencelen.andvari.core.trust.b64
import io.silencelen.andvari.core.trust.o
import io.silencelen.andvari.core.trust.rows
import io.silencelen.andvari.core.trust.s
import io.silencelen.andvari.core.trust.vector
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Grades the device-link ENGINE ([WireDeviceLinks]) on the rows of `spec/test-vectors/devicelink.json` that can drive it:
 * the existing device's claim checks, the fixed claim, the reveal, the code and the typed digits; the new device's
 * single nonceE and its checks on `outer` before any password prompt. The engine is given the vector's link secret, key
 * pair and nonces; a scripted server answers each poll as the row says.
 *
 * Not driven here: the `bundle` rows. Their pin checks name a verified card chain only by its hashes, and the engine
 * fetches and verifies real card frames, which the file does not carry; the shared verifiers' own test grades those rows on
 * `DeviceLink.openBundle` and `checkBundle`, the functions the engine calls ([DeviceLinkFlowsTest] drives the engine
 * through each of their stops with real frames).
 */
class DeviceLinkEngineVectorTest {
    private val crypto = createCryptoProvider()
    private val v = vector("devicelink.json")
    private val origin = v.s("origin")
    private val secret = v.o("link").b64("secretB64")
    private val newDevice = v.o("newDevice")
    private val nonceE = v.o("existingDevice").b64("nonceEB64")
    private val validClaim: JsonObject = v.rows("claim").first { it.s("name") == "valid" }.o("claim")

    private fun claimOf(o: JsonObject) = DeviceLinkClaim(o.s("nPub"), o.s("name"), o.s("platform"), o.s("commitN"), o.s("mac"))

    /** A server whose answers are scripted per route; every other route has no answer. */
    private class Scripted(override val origin: String, val instance: FakeInstance) : WireClient {
        val views = ArrayDeque<DeviceLinkView>()
        val polls = ArrayDeque<DeviceLinkPollResponse>()
        val calls = ArrayList<WireRoute>()

        @Suppress("UNCHECKED_CAST")
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            calls += route
            fun <R> ok(text: String): WireResult<R> = WireResult.Ok(decode(text) as R, 200)
            return when (route) {
                WireRoute.DEVICE_LINK_CREATE -> ok(WireJson.json.encodeToString(LinkCreatedResponse.serializer(), LinkCreatedResponse(instance.now + 300_000, 300_000)))
                WireRoute.DEVICE_LINK_VIEW -> ok(WireJson.json.encodeToString(DeviceLinkView.serializer(), if (views.size > 1) views.removeFirst() else views.first()))
                WireRoute.DEVICE_LINK_POLL -> ok(WireJson.json.encodeToString(DeviceLinkPollResponse.serializer(), if (polls.size > 1) polls.removeFirst() else polls.first()))
                WireRoute.DEVICE_LINK_NONCE, WireRoute.DEVICE_LINK_CANCEL, WireRoute.DEVICE_LINK_CLAIM, WireRoute.DEVICE_LINK_REVEAL -> ok("{}")
                WireRoute.INSTANCE -> instance.call(route, pathParams, query, bodyJson, authenticated, decode)
                else -> WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
            }
        }
    }

    private suspend fun existingDevice(server: Scripted, nonceE: ByteArray = this.nonceE): Pair<WireDeviceLinks, ExistingStep.Shown> {
        val state = MemoryDeviceState()
        val trust = server.instance.pinnedTrust(state)
        val seed = ByteArray(32) { 1 }
        val acct = LinkAccount(origin, "alice@example.com", "11111111-1111-4111-8111-111111111111", "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "Alice",
            ByteArray(32) { 2 }, crypto.boxKeypairFromSeed(seed), crypto.signKeypairFromSeed(seed), MemoryAccountState())
        val randoms = ArrayDeque(listOf(secret, nonceE))
        val e = WireDeviceLinks({ server }, trust, state, crypto, { server.instance.now }, { acct }, KnownDevices(state, crypto), { }, { _, _ -> },
            "Laptop", "desktop", random = { n -> randoms.removeFirst().also { require(it.size == n) }.copyOf() })
        return e to assertIs<ExistingStep.Shown>(e.create())
    }

    private fun e(step: ExistingStep): String = when (step) {
        is ExistingStep.Stopped -> step.reason.code
        is ExistingStep.ClaimFixed, is ExistingStep.TypeDigits, is ExistingStep.Approvable -> "ok"
        else -> "unexpected ${step::class.simpleName}"
    }

    @Test fun existingDevice_claimRows() = runBlocking<Unit> {
        val rows = v.rows("claim")
        assertTrue(rows.size >= 14)
        for (r in rows) {
            val server = Scripted(origin, FakeInstance(crypto, origin = origin))
            val (engine, shown) = existingDevice(server)
            server.views += DeviceLinkView("claimed", server.instance.now + 300_000, claimOf(r.o("claim")))
            val step = engine.advance(shown)
            assertEquals(r.o("expect").s("verdict"), e(step), r.s("name"))
            // A bad claim cancels the link; a good one is fixed and answered with nonceE.
            if (step is ExistingStep.Stopped) assertTrue(WireRoute.DEVICE_LINK_CANCEL in server.calls && WireRoute.DEVICE_LINK_NONCE !in server.calls, r.s("name"))
            else assertTrue(WireRoute.DEVICE_LINK_NONCE in server.calls, r.s("name"))
        }
    }

    @Test fun existingDevice_aLaterClaimMustBeTheFixedOne() = runBlocking<Unit> {
        for (r in v.rows("claimChanged")) {
            val server = Scripted(origin, FakeInstance(crypto, origin = origin))
            val (engine, shown) = existingDevice(server)
            server.views += DeviceLinkView("claimed", 0, claimOf(r.o("fixed")))
            server.views += DeviceLinkView("claimed", 0, claimOf(r.o("later")))
            val fixed = assertIs<ExistingStep.ClaimFixed>(engine.advance(shown))
            val verdict = when (val next = engine.advance(fixed)) {
                is ExistingStep.Stopped -> next.reason.code
                else -> "ok"
            }
            assertEquals(r.o("expect").s("verdict"), verdict, r.s("why"))
        }
    }

    @Test fun existingDevice_revealCodeAndTypedDigits() = runBlocking<Unit> {
        for (r in v.rows("reveal")) {
            val server = Scripted(origin, FakeInstance(crypto, origin = origin))
            val (engine, shown) = existingDevice(server)
            server.views += DeviceLinkView("claimed", 0, claimOf(validClaim))
            server.views += DeviceLinkView("revealed", 0, claimOf(validClaim), Bytes.toB64(nonceE), r.s("revealB64"))
            val fixed = assertIs<ExistingStep.ClaimFixed>(engine.advance(shown))
            assertEquals(r.o("expect").s("verdict"), e(engine.advance(fixed)), r.s("why"))
        }
        // Every typed-code row: its inputs are the `code` row whose code it names (a row may name another code than the first,
        // such as the one with a leading zero), the engine computes that code from them, and `typed` goes in untouched.
        val first = v.rows("code").first()
        for (r in v.rows("typedCode")) {
            val inputs = v.rows("code").first { it.s("code") == r.s("code") }
            // The fixture's link, claim and nonceN are the first row's; only nonceE comes from this device's randomness.
            for (f in listOf("linkId", "nPubB64", "nonceNB64")) assertEquals(first.s(f), inputs.s(f), "${r.s("why")}: $f")
            val rowNonceE = inputs.b64("nonceEB64")
            val server = Scripted(origin, FakeInstance(crypto, origin = origin))
            val (engine, shown) = existingDevice(server, rowNonceE)
            server.views += DeviceLinkView("claimed", 0, claimOf(validClaim))
            server.views += DeviceLinkView("revealed", 0, claimOf(validClaim), Bytes.toB64(rowNonceE), newDevice.s("nonceNB64"))
            val type = assertIs<ExistingStep.TypeDigits>(engine.advance(assertIs<ExistingStep.ClaimFixed>(engine.advance(shown))))
            val verdict = when (val next = engine.typeDigits(type, r.s("typed"))) {
                is ExistingStep.Approvable -> "ok"
                is ExistingStep.Stopped -> next.reason.code
                else -> "unexpected"
            }
            assertEquals(r.o("expect").s("verdict"), verdict, r.s("why"))
            if (verdict != "ok") assertTrue(WireRoute.DEVICE_LINK_CANCEL in server.calls, "a mismatch cancels the link")
        }
    }

    /** N with the vector's key pair and nonceN, pinned (password pin) at [pinned], started from a link to that origin. */
    private suspend fun newDevice(pinned: String): Triple<WireDeviceLinks, Scripted, NewStep.Claimed> {
        val server = Scripted(pinned, FakeInstance(crypto, origin = pinned))
        val state = MemoryDeviceState()
        val trust = server.instance.pinnedTrust(state)
        val pair = KeyPairBytes(newDevice.b64("nPubB64"), newDevice.b64("nSecB64"))
        val n = WireDeviceLinks({ server }, trust, state, crypto, { server.instance.now }, { null }, KnownDevices(state, crypto), { }, { _, _ -> },
            "Pixel 9", "android", ephemeral = { KeyPairBytes(pair.publicKey.copyOf(), pair.privateKey.copyOf()) }, random = { newDevice.b64("nonceNB64") })
        val url = DeviceLinkUrl.compose(pinned, secret)!!
        return Triple(n, server, assertIs<NewStep.Claimed>(n.start(url, GateEntry.LINK_DEVICE_SCREEN)))
    }

    @Test fun newDevice_holdsTheFirstNonceE() = runBlocking<Unit> {
        for (r in v.rows("nonceChanged")) {
            val (n, server, claimed) = newDevice(origin)
            server.polls += DeviceLinkPollResponse("claimed", r.s("heldB64"))
            server.polls += DeviceLinkPollResponse("revealed", r.s("servedB64"))
            val shown = assertIs<NewStep.ShowCode>(n.advance(claimed))
            assertEquals(v.rows("code").first().s("code"), shown.code, "the code from the vector's nonces")
            val verdict = when (val next = n.advance(shown)) {
                is NewStep.Stopped -> next.reason.code
                else -> "ok"
            }
            assertEquals(r.o("expect").s("verdict"), verdict, r.s("why"))
        }
    }

    @Test fun newDevice_outerRowsBeforeAnyPasswordPrompt() = runBlocking<Unit> {
        val rows = v.rows("outer")
        assertTrue(rows.size >= 26)
        for (r in rows) {
            val (n, server, claimed) = newDevice(r.s("pinnedOrigin"))
            server.polls += DeviceLinkPollResponse("approved", Bytes.toB64(nonceE), r.s("outerB64"), r.s("approveMac"))
            val step = n.advance(claimed)
            val verdict = when (step) {
                is NewStep.Stopped -> step.reason.code
                is NewStep.PasswordNeeded -> "ok"
                else -> "unexpected ${step::class.simpleName}"
            }
            assertEquals(r.o("expect").s("verdict"), verdict, r.s("name"))
            if (step is NewStep.PasswordNeeded) assertEquals(r.o("expect").o("outer").s("email"), step.email, r.s("name"))
            assertTrue(WireRoute.PRELOGIN !in server.calls && WireRoute.DEVICE_LINK_PICKUP !in server.calls, "${r.s("name")}: nothing derived from a password was sent")
        }
    }
}
