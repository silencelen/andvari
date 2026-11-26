package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.SavedSessions
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.session.ReKeyOutcome
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.Gate
import io.silencelen.andvari.hostile.proxy.Handler
import io.silencelen.andvari.hostile.proxy.Resp
import io.silencelen.andvari.hostile.proxy.answer
import io.silencelen.andvari.hostile.proxy.edit
import io.silencelen.andvari.hostile.proxy.editAnswer
import io.silencelen.andvari.hostile.proxy.long
import io.silencelen.andvari.hostile.proxy.obj
import io.silencelen.andvari.hostile.proxy.set
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Spec 01 §7, "KDF upgrade", against a server that lies about it (spec 05 T1). The device is the command-line tool's
 * host, which opens its account over the keys the server serves; each scenario re-keys right after an opening with the
 * full password ([io.silencelen.andvari.core.client.onboard.EstablishedSession.reKeyAfterOpening]), lets the lie
 * happen, and ends with the same two checks: the next opening with the same password reopens the account, and the
 * re-key there settles (nothing pending, nothing more due or a re-key the honest server takes). No lie turns a weaker,
 * sideways or absurd cost into a request.
 */
class QuietReKeyLiesTest {
    private val email = "alice@example.org"
    private val mib = 1024L * 1024

    /** The policy as the proxy serves it: the real one with its KDF cost replaced. */
    private fun World.policyAsks(ops: Long, memBytes: Long) =
        proxy.on(WireRoute.CLIENT_POLICY, name = "policy $ops/$memBytes", handler = editAnswer { it.edit("kdfParams") { p -> p.set("ops", ops).set("memBytes", memBytes) } })

    private suspend fun reKey(h: Host, origin: String): ReKeyOutcome = withContext(Dispatchers.IO) {
        val held = h.session(origin) ?: error("not signed in")
        held.session.reKeyAfterOpening(h.crypto, h.client(origin), h.reauth(held), Steps.PASSWORD.toCharArray())
    }

    private suspend fun World.keysOf(h: Host): JsonObject =
        Json.parseToJsonElement(assertIs<WireResult.Ok<String>>(h.client(origin).call(WireRoute.ACCOUNT_KEYS, decode = { it })).value).jsonObject

    private fun JsonObject.cost(): Pair<Long, Long> =
        obj("kdfParams")!!.let { it.long("ops")!! to it.long("memBytes")!! }

    /**
     * The next opening: a new run of the tool reopens the saved session with the same password, over the keys the
     * server serves now, and re-keys there. Answers that host, its outcome checked as settled.
     */
    private suspend fun World.nextOpening(h: Host): Host {
        val saved = SavedSessions(h.secure)
        saved.save(h.session(origin)!!)
        val next = Host(h.state, h.secure, server::now, http = server.httpFor(proxy.dial("alice")), deviceName = h.deviceName)
        assertEquals(SavedSessions.Reopen.Reopened, saved.reopen(next, origin, email, Steps.PASSWORD.toCharArray()), "the same password reopens it")
        val outcome = reKey(next, origin)
        assertTrue(outcome == ReKeyOutcome.NOT_DUE || outcome == ReKeyOutcome.DONE, "the next opening settles it: $outcome")
        assertFalse(next.session(origin)!!.session.hasPendingWrap(), "nothing is left pending")
        return next
    }

    /** A second device signs in with the same password: the wrap the server holds opens with it. */
    private suspend fun World.anotherDeviceSignsIn(tag: String) {
        val d = pinnedDevice(tag)
        assertIs<SignIn.SignedIn>(d.onboarding(origin).signIn(email, Steps.PASSWORD.toCharArray()), "the same password signs in on another device")
    }

    @Test fun aPolicyThatAsksForLessOrForAnAbsurdCostIsNeverFollowedAndAMixedOneNeverLowersAFigure() = world {
        operator()
        val alice = member("alice")
        // An honest raise first, so that a lower and a mixed cost exist above the floor.
        val raise = policyAsks(4, 64 * mib)
        assertEquals(ReKeyOutcome.DONE, reKey(alice, origin))
        raise.remove()
        assertEquals(4L to 64 * mib, keysOf(alice).cost())
        val lies = listOf(
            "lower" to (3L to 64 * mib),
            "below the floor" to (2L to 32 * mib),
            "absurd passes" to (50L to 64 * mib),
            "absurd memory" to (4L to 4096 * mib),
            "not a whole KiB" to (5L to 64 * mib + 1),
        )
        for ((what, cost) in lies) {
            val rule = policyAsks(cost.first, cost.second)
            val mark = proxy.mark()
            assertEquals(ReKeyOutcome.NOT_DUE, reKey(alice, origin), what)
            assertTrue(proxy.requests(WireRoute.CLIENT_POLICY, "alice", mark).isNotEmpty(), "$what: the lie was asked for")
            assertEquals(emptyList(), sent(alice, WireRoute.PASSWORD_CHANGE, mark), "$what: nothing was sent")
            rule.remove()
        }
        assertEquals(4L to 64 * mib, keysOf(alice).cost(), "the account keeps its cost")
        // A mixed cost (one figure above the account's, the other below it) can never be used to lower a figure: the wrap
        // is made figure by figure at the higher of the served cost and the account's, so the figure the served cost
        // asks less for stays where it is. (The server refuses a new wrap below its served cost on any figure, which is
        // why the figure that is higher is followed.)
        val mixed = listOf(
            Triple("mixed: memory up, passes down", 3L to 128 * mib, 4L to 128 * mib),
            Triple("mixed: passes up, memory down", 5L to 64 * mib, 5L to 128 * mib),
        )
        for ((what, cost, after) in mixed) {
            val rule = policyAsks(cost.first, cost.second)
            val mark = proxy.mark()
            assertEquals(ReKeyOutcome.DONE, reKey(alice, origin), what)
            assertEquals(1, sent(alice, WireRoute.PASSWORD_CHANGE, mark).size, "$what: one change was sent")
            assertEquals(after, keysOf(alice).cost(), "$what: no figure was lowered, and only the higher one was followed")
            rule.remove()
        }
        nextOpening(alice)
        anotherDeviceSignsIn("d2")
    }

    @Test fun aReKeyTheServerStoresAndAnswersWithAnErrorSettlesAtTheNextOpening() = world {
        operator()
        var alice = member("alice")
        for ((what, status) in listOf("a refusal" to 403, "a server error" to 500)) {
            val ops = if (status == 403) 4L else 5L
            val policy = policyAsks(ops, 64 * mib)
            val rule = proxy.on(WireRoute.PASSWORD_CHANGE, "alice", times = 1, handler = Handler { x -> x.forward(); Resp.error(status, if (status == 403) "reauth_failed" else "internal") })
            val outcome = reKey(alice, origin)
            rule.remove()
            assertEquals(ops to 64 * mib, keysOf(alice).cost(), "$what: the server stored it")
            if (status == 500) {
                assertEquals(ReKeyOutcome.UNKNOWN, outcome, what)
                assertTrue(alice.session(origin)!!.session.hasPendingWrap(), "$what: the wrap stays pending")
            } else {
                assertEquals(ReKeyOutcome.REFUSED, outcome, what)
                assertFalse(alice.session(origin)!!.session.hasPendingWrap(), "$what: the refusal drops its own wrap")
            }
            alice = nextOpening(alice)
            assertEquals(ReKeyOutcome.NOT_DUE, reKey(alice, origin), "$what: settled at the server's cost")
            policy.remove()
        }
        anotherDeviceSignsIn("d2")
    }

    @Test fun aReKeyAnsweredDoneThatTheServerNeverStoredSettlesAtTheNextOpening() = world {
        operator()
        val alice = member("alice")
        policyAsks(4, 64 * mib)
        val rule = proxy.on(WireRoute.PASSWORD_CHANGE, "alice", times = 1, handler = answer { Resp.json(200, JsonObject(emptyMap())) })
        assertEquals(ReKeyOutcome.DONE, reKey(alice, origin))
        rule.remove()
        assertEquals(3L to 64 * mib, keysOf(alice).cost(), "nothing was stored")
        // The next opening reopens over what the server holds and re-keys it honestly this time.
        nextOpening(alice)
        assertEquals(4L to 64 * mib, keysOf(alice).cost())
        anotherDeviceSignsIn("d2")
    }

    @Test fun anEarlierReKeysAnswerOrAnotherAccountsKeysAreNeverTakenForThisOne() = world {
        operator()
        val alice = member("alice")
        val bob = member("bob")
        val bobsKeys = keysOf(bob)
        val raise = policyAsks(4, 64 * mib)
        // The answer to an earlier re-key, replayed without asking the server: a "done" for a change never stored.
        assertEquals(ReKeyOutcome.DONE, reKey(alice, origin))
        val earlier = proxy.last(WireRoute.PASSWORD_CHANGE, "alice")!!.served!!
        raise.remove()
        policyAsks(5, 64 * mib)
        val replay = proxy.on(WireRoute.PASSWORD_CHANGE, "alice", times = 1, handler = answer { earlier })
        assertEquals(ReKeyOutcome.DONE, reKey(alice, origin))
        replay.remove()
        assertEquals(4L to 64 * mib, keysOf(alice).cost(), "the replay stored nothing")
        val reopened = nextOpening(alice)
        assertEquals(5L to 64 * mib, keysOf(reopened).cost(), "the next opening re-keyed for real")
        // A lost answer leaves a pending wrap; the keys read to settle it are another account's: nothing is sent.
        policyAsks(6, 64 * mib)
        val lost = proxy.on(WireRoute.PASSWORD_CHANGE, "alice", times = 1, handler = Handler { x -> x.forward(); null })
        assertEquals(ReKeyOutcome.UNKNOWN, reKey(reopened, origin))
        lost.remove()
        assertTrue(reopened.session(origin)!!.session.hasPendingWrap())
        policyAsks(7, 64 * mib)
        val bobs = proxy.on(WireRoute.ACCOUNT_KEYS, "alice", times = 1, handler = answer { Resp.json(200, bobsKeys) })
        val mark = proxy.mark()
        assertEquals(ReKeyOutcome.UNSETTLED, reKey(reopened, origin))
        bobs.remove()
        assertEquals(emptyList(), proxy.requests(WireRoute.PASSWORD_CHANGE, "alice", mark), "nothing is sent while it cannot be settled")
        nextOpening(reopened)
        anotherDeviceSignsIn("d2")
    }

    /** The server holds the request; the account in the open session stays usable meanwhile, and nothing is lost. */
    @Test fun aServerThatStallsTheReKeyLeavesTheOpeningUsableAndSettlesAtTheNextOne() = world {
        operator()
        val alice = member("alice")
        policyAsks(4, 64 * mib)
        val gate = Gate()
        val stall = proxy.on(WireRoute.PASSWORD_CHANGE, "alice", times = 1, handler = Handler { x -> x.forward(); gate.enter(); null })
        coroutineScope {
            val pending = async(Dispatchers.IO) { reKey(alice, origin) }
            withContext(Dispatchers.IO) { gate.awaitArrival() }
            // The vault of this opening is in use while the re-key waits.
            assertIs<WireResult.Ok<String>>(alice.client(origin).call(WireRoute.ACCOUNT_KEYS, decode = { it }))
            gate.release()
            assertEquals(ReKeyOutcome.UNKNOWN, pending.await())
        }
        stall.remove()
        assertTrue(alice.session(origin)!!.session.hasPendingWrap())
        nextOpening(alice)
        assertEquals(4L to 64 * mib, keysOf(alice).cost())
        anotherDeviceSignsIn("d2")
    }
}
