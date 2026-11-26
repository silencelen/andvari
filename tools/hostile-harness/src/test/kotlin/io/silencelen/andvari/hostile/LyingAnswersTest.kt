package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.SyncOutcome
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.accept
import io.silencelen.andvari.cli.e2e.doc
import io.silencelen.andvari.cli.e2e.ok
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.state.AccountStateRead
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.Endless
import io.silencelen.andvari.hostile.proxy.Handler
import io.silencelen.andvari.hostile.proxy.Resp
import io.silencelen.andvari.hostile.proxy.edit
import io.silencelen.andvari.hostile.proxy.editAnswer
import io.silencelen.andvari.hostile.proxy.set
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Lies the coverage table (README, "What each route is lied to with") had no scenario for, in order of what they could
 * cost the person: the master password first, then what the device is told is true. Each lie is one of the table's
 * kinds: a wrong body, an answer for another route, a truncated answer, a status the route never gives.
 */
class LyingAnswersTest {
    private fun snapshot(h: Host): Map<String, String?> =
        h.state.keys()!!.associateWith { h.state.get(it) } + h.secure.keys()!!.associate { "secure:$it" to h.secure.get(it) }

    /** The real answer to the request, cut at half its length, by its own length or chunked. */
    private fun truncated(declared: Boolean) = Handler { x ->
        val real = x.forward()
        Resp(real.status, real.headers, ByteArray(0), Endless.truncated(real.body, real.body.size / 2, declared))
    }

    /**
     * Design §4.4 and spec 05 T1: the prelogin answer decides how the master password is stretched. A server that
     * weakens the KDF (below the 64 MiB, t=3 floor), inflates it past the ceiling, serves a salt that is not 16 bytes
     * or not base64, an algorithm the client does not run, another route's answer, half an answer, or a status the
     * route never gives, gets NO password proof: no login is sent, nothing is derived from the password for it, the
     * password array is wiped, the result is never "wrong password", and the device keeps nothing. The honest
     * prelogin then signs in.
     */
    @Test fun aPreloginThatWeakensTheKdfOrIsNotAPreloginGetsNoPasswordProof() = world {
        operator()
        member("alice")
        val d = pinnedDevice("d")
        val lies = listOf<Pair<String, Handler>>(
            "memory below the floor" to editAnswer { it.edit("kdfParams") { p -> p.set("memBytes", 1024L) } },
            "passes below the floor" to editAnswer { it.edit("kdfParams") { p -> p.set("ops", 1L) } },
            "memory past the ceiling" to editAnswer { it.edit("kdfParams") { p -> p.set("memBytes", 1L shl 40) } },
            "a salt of 8 bytes" to editAnswer { it.set("kdfSalt", "AAAAAAAAAAA") },
            "a salt that is not base64" to editAnswer { it.set("kdfSalt", "not base64 !") },
            "another algorithm" to editAnswer { it.edit("kdfParams") { p -> p.set("alg", JsonPrimitive("argon2i13")) } },
            "the client policy's answer" to Handler { x -> x.ask(WireRoute.CLIENT_POLICY) },
            "half the answer, by length" to truncated(declared = true),
            "half the answer, chunked" to truncated(declared = false),
            "a 200 that is plain ok" to Handler { _ -> Resp.ok() },
            "a redirect" to Handler { _ -> Resp(302, mapOf("Location" to "/api/v1/auth/prelogin"), ByteArray(0)) },
        )
        for ((what, lie) in lies) {
            val rule = proxy.on(WireRoute.PRELOGIN, "d", handler = lie)
            val before = snapshot(d)
            val mark = proxy.mark()
            val password = Steps.PASSWORD.toCharArray()
            val r = d.onboarding(origin).signIn("alice@example.org", password)
            assertTrue(proxy.requests(WireRoute.PRELOGIN, "d", mark).isNotEmpty(), "$what: the lie was asked for")
            assertTrue(r !is SignIn.SignedIn && r != SignIn.InvalidCredentials && r !is SignIn.TotpRequired, "$what: $r")
            assertTrue(password.all { it == '\u0000' }, "$what: the password is wiped")
            assertEquals(emptyList(), proxy.requests(WireRoute.LOGIN, "d", mark).map { it.toString() }, "$what: no password proof was sent")
            assertTrue(proxy.requests(tag = "d", since = mark).none { it.text.contains("authKey") }, "$what: no request carries an authKey")
            assertEquals(before, snapshot(d), "$what: nothing is kept")
            rule.remove()
        }
        assertIs<SignIn.SignedIn>(d.onboarding(origin).signIn("alice@example.org", Steps.PASSWORD.toCharArray()), "the honest prelogin signs in")
    }

    /** What a member's device holds, to compare before and after a lie: its records, items, log status, account state and pin. */
    private fun World.held(h: Host, v: String): List<Any?> {
        val b = account(h)
        return listOf(snapshot(h), b.items(b.personalVaultId!!), b.items(v), b.logs.status(v), b.store.local(), h.trust.pinFor(origin), h.trust.pinState(origin)::class.simpleName)
    }

    /** Alice and Bob share a vault with an item in it, and Bob has an item of his own; Bob's device is synced. */
    private suspend fun World.sharing(): Triple<Host, Host, String> {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val v = sharedVault(ah, bh)
        val a = account(ah)
        val b = account(bh)
        assertEquals(null, a.putItem(v, doc("shared")).second)
        assertEquals(null, b.putItem(b.personalVaultId!!, doc("own")).second)
        b.synced()
        assertTrue(b.items(v).isNotEmpty() && b.items(b.personalVaultId!!).isNotEmpty())
        return Triple(ah, bh, v)
    }

    /** Run what reads [route] on Bob's device, and answer whether it was asked. */
    private suspend fun World.read(bh: Host, v: String, route: WireRoute, mark: Int): String {
        val b = account(bh)
        val outcome = when (route) {
            WireRoute.SYNC, WireRoute.INSTANCE -> b.sync().also { if (route == WireRoute.SYNC) assertTrue(it !is SyncOutcome.Synced, "a lying sync is not a sync: $it") }
            WireRoute.LOG_FETCH -> b.logs.refresh(v, null, null, force = true)
            WireRoute.ACCOUNT_STATE_GET -> b.store.read().also { assertTrue(it !is AccountStateRead.Ok, "a lying account state is not read: $it") }
            else -> error("no reader for $route")
        }
        assertTrue(proxy.requests(route, tag(bh), mark).isNotEmpty(), "$route was asked")
        return outcome.toString()
    }

    /**
     * Spec 03 §0.4: half an answer, by its own length (the connection closes short) or chunked (a body that ends
     * cleanly, cut mid-row), to a sync, a vault log page, the card chain, or the account state, changes nothing on the
     * device and is never read as "nothing there": no item, vault, log entry, contact or pin is dropped or changed,
     * and the next honest sync works.
     */
    @Test fun aTruncatedAnswerChangesNothingAndIsNeverReadAsNothingThere() = world {
        val (_, bh, v) = sharing()
        for (route in listOf(WireRoute.SYNC, WireRoute.LOG_FETCH, WireRoute.INSTANCE, WireRoute.ACCOUNT_STATE_GET)) {
            for (declared in listOf(true, false)) {
                val what = "$route cut in half " + if (declared) "by its length" else "chunked"
                val before = held(bh, v)
                val mark = proxy.mark()
                val rule = proxy.on(route, "bob", handler = truncated(declared))
                val outcome = read(bh, v, route, mark)
                rule.remove()
                assertEquals(before, held(bh, v), "$what ($outcome): the device holds what it held")
            }
        }
        account(bh).synced()
        assertTrue(account(bh).writeAllowed(v), "the shared vault still works")
    }

    /**
     * An answer the server made for another route (a valid one: the log page, the account state, a sync page)
     * served in place of the route's own: a sync answered with a vault's log page or with the account state, a log
     * page answered with the log of another vault Bob is in, the card chain answered with a sync page, the account
     * state answered with the usage ledger's answer. None of them changes what the device holds. The other vault's
     * log is a log that does not verify (`wrong_vault`), so design §3.9 asks for one visible effect: the failure
     * warning and refused writes, with the verified state kept, until the next fetch verifies; it is asserted so.
     */
    @Test fun anAnswerMadeForAnotherRouteChangesNothing() = world {
        val (ah, bh, v) = sharing()
        val a = account(ah)
        a.synced()
        val other = a.ok(null, LogAction.Create("Other"))
        a.ok(other, LogAction.Add(account(bh).userId, "writer"))
        accept(account(bh), other, "Other")
        account(bh).synced()
        val lies = listOf<Triple<WireRoute, String, Handler>>(
            Triple(WireRoute.SYNC, "the shared vault's log page", Handler { x -> x.ask(WireRoute.LOG_FETCH, mapOf("vaultId" to v)) }),
            Triple(WireRoute.SYNC, "the account state", Handler { x -> x.ask(WireRoute.ACCOUNT_STATE_GET) }),
            Triple(WireRoute.LOG_FETCH, "the other vault's log page", Handler { x ->
                if (x.req.param("vaultId") == v) x.ask(WireRoute.LOG_FETCH, mapOf("vaultId" to other), x.req.query) else x.forward()
            }),
            Triple(WireRoute.INSTANCE, "a sync page", Handler { x -> x.ask(WireRoute.SYNC, query = "since=0") }),
            Triple(WireRoute.ACCOUNT_STATE_GET, "the usage ledger's answer", Handler { x -> x.ask(WireRoute.USAGE_GET) }),
        )
        for ((route, what, lie) in lies) {
            val before = held(bh, v)
            val mark = proxy.mark()
            val rule = proxy.on(route, "bob", handler = lie)
            val outcome = read(bh, v, route, mark)
            rule.remove()
            if (route == WireRoute.LOG_FETCH) {
                // Design §3.9: a log that does not verify is a failure: the verified state stays at the last good
                // entry, the device warns and refuses writes, and the state ends at the first later fetch that verifies.
                val b = account(bh)
                assertFalse(b.writeAllowed(v), "$what ($outcome): a log that does not verify refuses writes")
                @Suppress("UNCHECKED_CAST") val records = before[0] as Map<String, String?>
                assertEquals(records.filterKeys { !it.endsWith("|flag") }, snapshot(bh).filterKeys { !it.endsWith("|flag") },
                    "$what: nothing of the other vault's log is kept, only the warning")
                b.logs.refresh(v, null, null, force = true)
            }
            assertEquals(before, held(bh, v), "$route answered with $what ($outcome): the device holds what it held")
        }
        account(bh).synced()
        assertTrue(account(bh).writeAllowed(v) && account(bh).writeAllowed(other), "both shared vaults still work")
    }
}
