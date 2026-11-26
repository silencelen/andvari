package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.account.Fetched
import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.account.WireOperatorRoutes
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.recovery.AssistedStep
import io.silencelen.andvari.core.client.state.RecoveryRecord
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.AdminRecoveryRequest
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.AssistedRecovery
import io.silencelen.andvari.hostile.proxy.Handler
import io.silencelen.andvari.hostile.proxy.Resp
import io.silencelen.andvari.hostile.proxy.answer
import io.silencelen.andvari.hostile.proxy.refuse
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Ignore
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The operator's lists as the headless host reads them ([WireOperatorRoutes], what `andvari-cli operator` prints): the
 * assisted-recovery requests (rows 84), an account's devices (77), the audit (82), status (83) and policy (80). What is
 * shown is the operator's own server speaking (design §9.2: audit and status are transparency for an honest operator,
 * not controls against a hostile one), so the property of every scenario is that a lie DECIDES nothing: the host sends
 * nothing but the read, a shape the route never gives is a failure (never an empty list), and the one check the design
 * puts on the operator's side, the request code `recovery-cli assist` compares with the one it computes from `rPub`
 * (§9.3 step 3), refuses any key the server swapped in. The upload of an answer (`…/fulfil`) is not touched here.
 */
class OperatorListLiesTest {
    private val crypto = createCryptoProvider()
    private val password get() = Steps.PASSWORD.toCharArray()
    private val recoveryPub = crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey

    private fun recoveryWorld(block: suspend World.() -> Unit) = world(extraSetup = listOf("--recovery-pubkey", Bytes.toB64(recoveryPub)), block = block)

    private suspend fun World.optIn(h: Host): RecoveryRecord {
        val s = h.recoverySettings(h.session(origin)!!)
        return assertIs<Reauthed.Done<RecoveryRecord>>(s.setPosture(RecoveryChoiceKind.OPERATOR, assertNotNull(s.operatorOffer()), understood = true, password = password)).value
    }

    /** A fresh device [tag] asks the operator for [email]'s account and proves the address: its hold has begun. */
    private suspend fun World.verified(tag: String, email: String): AssistedStep.Waiting {
        val seen = Steps.mailCount(server, email, "recovery_request_code")
        val d = device(tag)
        val req = assertIs<AssistedStep.Requested>(d.assisted.request(assertIs<AssistedStep.ConfirmTarget>(d.assisted.start(email, origin))))
        return assertIs<AssistedStep.Waiting>(d.assisted.verifyCode(req, Steps.awaitCode(server, email, "recovery_request_code", seen)))
    }

    private fun World.ops(op: Host): WireOperatorRoutes = op.operator(op.session(origin)!!)

    /** The real answer (a JSON array) passed through [edit]. */
    private fun rows(edit: (List<JsonObject>) -> List<JsonElement>) = Handler { x ->
        val r = x.forward()
        if (!r.ok) r else Resp.json(r.status, JsonArray(edit(Json.parseToJsonElement(r.text).jsonArray.map { it.jsonObject })))
    }

    private fun JsonObject.with(key: String, value: JsonElement) = JsonObject(this + (key to value))

    /** Every request [tag] sent since [mark] was a read. */
    private fun World.onlyReads(tag: String, mark: Int, what: String) {
        val sent = proxy.requests(tag = tag, since = mark)
        assertTrue(sent.all { it.route?.method == "GET" }, "$what: nothing but reads is sent (${sent.map { it.route }})")
    }

    private val shapesNeverGiven: List<Pair<String, Handler>> = listOf(
        "an empty object (X)" to answer { Resp.json(200, JsonObject(emptyMap())) },
        "a plain ok (X)" to answer { Resp.ok() },
        "a 500 (X)" to refuse(500, "internal"),
    )

    /**
     * `GET /admin/recovery-requests` (row 84) with Alice's row given Bob's request key or a fresh one (W), a request code
     * added to every row (W, T2-R-c), the answer from before Bob's request (R: a request withheld, which the device
     * cannot tell), `{}`, `ok` or a `500` (X). The host shows the rows as served, but: no row it hands up ever carries a
     * request code, whatever the server adds; a swapped key never passes the request code Alice's app shows her (the
     * check `recovery-cli assist` makes, so the operator's answer is never sealed to a key the server chose); a shape the
     * route never gives is a failure, never "no requests"; and nothing but the read is sent.
     */
    @Test fun aRecoveryRequestListThatLiesNeverCarriesACodeAndAKeyItSwappedFailsTheOperatorsCheck() = recoveryWorld {
        val op = operator()
        optIn(member("alice"))
        optIn(member("bob"))
        val aw = verified("areq", "alice@example.org")
        val ops = ops(op)
        val alone = assertIs<Fetched.Ok<List<AdminRecoveryRequest>>>(ops.recoveryRequests()).value
        val earlier = assertNotNull(proxy.last(WireRoute.ADMIN_RECOVERY_REQUESTS, "op")?.upstream).text
        assertEquals(1, alone.size)
        val bw = verified("breq", "bob@example.org")
        val honest = assertIs<Fetched.Ok<List<AdminRecoveryRequest>>>(ops.recoveryRequests()).value
        val alices = honest.single { it.email == "alice@example.org" }
        val bobs = honest.single { it.email == "bob@example.org" }
        fun passes(code: String, rPub: String) = AssistedRecovery.requestCodeMatches(crypto, code, Bytes.fromB64(rPub))
        assertTrue(passes(aw.requestCode, alices.rPub) && passes(bw.requestCode, bobs.rPub), "the honest rows pass their own codes")
        val fresh = Bytes.toB64(crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey)
        val mark = proxy.mark()

        for ((what, key) in listOf("Bob's request key in Alice's row (W)" to bobs.rPub, "a fresh key in Alice's row (W)" to fresh)) {
            val rule = proxy.on(WireRoute.ADMIN_RECOVERY_REQUESTS, "op", handler = rows { list ->
                list.map { if (it["email"]?.jsonPrimitive?.content == "alice@example.org") it.with("rPub", JsonPrimitive(key)) else it }
            })
            val shown = assertIs<Fetched.Ok<List<AdminRecoveryRequest>>>(ops.recoveryRequests(), what).value
            rule.remove()
            val row = shown.single { it.email == "alice@example.org" }
            assertEquals(key, row.rPub, "$what: shown as served")
            assertTrue(!passes(aw.requestCode, row.rPub), "$what: the code Alice reads out refuses the swapped key")
        }

        val coded = proxy.on(WireRoute.ADMIN_RECOVERY_REQUESTS, "op", handler = rows { list ->
            list.map { it.with("requestCode", JsonPrimitive(aw.requestCode)).with("code", JsonPrimitive(aw.requestCode.replace(" ", ""))) }
        })
        val shown = assertIs<Fetched.Ok<List<AdminRecoveryRequest>>>(ops.recoveryRequests()).value
        coded.remove()
        val printed = WireJson.json.encodeToString(ListSerializer(AdminRecoveryRequest.serializer()), shown)
        assertTrue(aw.requestCode.replace(" ", "") !in printed.replace(" ", ""), "no request code is ever handed up (T2-R-c): $printed")

        val replay = proxy.on(WireRoute.ADMIN_RECOVERY_REQUESTS, "op", handler = answer { Resp.json(200, Json.parseToJsonElement(earlier)) })
        assertEquals(alone, assertIs<Fetched.Ok<List<AdminRecoveryRequest>>>(ops.recoveryRequests(), "the earlier answer (R)").value,
            "the earlier answer (R): Bob's request withheld, which the device cannot tell (the stated limit)")
        replay.remove()

        for ((what, lie) in shapesNeverGiven) {
            val rule = proxy.on(WireRoute.ADMIN_RECOVERY_REQUESTS, "op", handler = lie)
            assertEquals(Fetched.Unreachable, ops.recoveryRequests(), "$what: a failure, never \"no requests\"")
            rule.remove()
        }
        onlyReads("op", mark, "the requests list")
        assertTrue(proxy.requests(WireRoute.ADMIN_RECOVERY_FULFIL, "op").isEmpty())
    }

    /**
     * `GET /admin/accounts/{id}/devices` (row 77) answered with Bob's real list for Alice (A: its rows name no account, so
     * the device cannot tell, the stated limit) and with `{}`, `ok` or a `500` (X: a failure, never "no devices");
     * `GET /admin/audit` (row 82) with its earlier answer (R) and the three shapes; `GET /admin/status` (row 83) with the
     * instance's kind turned to `public` and absurd counts (W: shown as served; the operator's recovery routes still
     * follow the pinned card's kind, never the status); `GET /admin/policy` (row 80) with weaker values (W: shown as
     * served) and the three shapes. Nothing but reads is sent.
     */
    @Test fun anOperatorViewThatLiesDecidesNothingAndAShapeNeverGivenIsAFailure() = recoveryWorld {
        val op = operator()
        val ah = member("alice")
        val bh = member("bob")
        val ops = ops(op)
        val accounts = assertIs<Fetched.Ok<List<io.silencelen.andvari.core.model.wire.AccountSummary>>>(ops.accounts()).value
        val alice = accounts.single { it.email == "alice@example.org" }.userId
        val bob = accounts.single { it.email == "bob@example.org" }.userId
        assertIs<Fetched.Ok<*>>(ops.accountDevices(bob))
        val bobsDevices = assertNotNull(proxy.last(WireRoute.ADMIN_ACCOUNT_DEVICES, "op")?.upstream).text
        assertIs<Fetched.Ok<*>>(ops.audit())
        val earlierAudit = assertNotNull(proxy.last(WireRoute.ADMIN_AUDIT, "op")?.upstream).text
        account(ah).synced()
        account(bh).synced()
        val mark = proxy.mark()

        // Devices: another account's list, read as served.
        val swapped = proxy.on(WireRoute.ADMIN_ACCOUNT_DEVICES, "op", handler = answer { Resp.json(200, Json.parseToJsonElement(bobsDevices)) })
        assertIs<Fetched.Ok<*>>(ops.accountDevices(alice), "Bob's list for Alice (A): the stated limit")
        swapped.remove()
        for ((what, lie) in shapesNeverGiven) {
            val rule = proxy.on(WireRoute.ADMIN_ACCOUNT_DEVICES, "op", handler = lie)
            assertEquals(Fetched.Unreachable, ops.accountDevices(alice), "devices, $what")
            rule.remove()
        }

        // The audit: an earlier answer reads as an older log; a shape never given is a failure.
        val replay = proxy.on(WireRoute.ADMIN_AUDIT, "op", handler = answer { Resp.json(200, Json.parseToJsonElement(earlierAudit)) })
        assertIs<Fetched.Ok<*>>(ops.audit(), "the earlier audit (R)")
        replay.remove()
        for ((what, lie) in shapesNeverGiven) {
            val rule = proxy.on(WireRoute.ADMIN_AUDIT, "op", handler = lie)
            assertEquals(Fetched.Unreachable, ops.audit(), "audit, $what")
            rule.remove()
        }

        // Status: whatever kind it names, the recovery routes follow the pinned card (private here).
        val publicNow = proxy.on(WireRoute.ADMIN_STATUS, "op", handler = Handler { x ->
            x.forward().withJson { it.with("instanceKind", JsonPrimitive("public")).with("userCount", JsonPrimitive(1_000_000_000L)) }
        })
        val status = assertIs<Fetched.Ok<io.silencelen.andvari.core.model.wire.AdminStatus>>(ops.status()).value
        publicNow.remove()
        assertEquals("public", status.instanceKind, "shown as served")
        assertTrue(ops.recoveryRequests() != Fetched.Refused(WireOperatorRoutes.OPERATOR_RECOVERY_UNAVAILABLE), "the pinned card decides, not the status")
        for ((what, lie) in shapesNeverGiven) {
            val rule = proxy.on(WireRoute.ADMIN_STATUS, "op", handler = lie)
            assertEquals(Fetched.Unreachable, ops.status(), "status, $what")
            rule.remove()
        }

        // Policy: weaker values are shown as served (the server's own policy); a shape never given is a failure.
        val weaker = proxy.on(WireRoute.ADMIN_POLICY_GET, "op", handler = Handler { x ->
            x.forward().withJson { it.with("offlineCacheAllowed", JsonPrimitive(true)).with("autoLockSeconds", JsonPrimitive(86_400L)) }
        })
        val policy = assertIs<Fetched.Ok<io.silencelen.andvari.core.model.wire.AdminPolicy>>(ops.policy()).value
        weaker.remove()
        assertEquals(86_400L, policy.autoLockSeconds)
        for ((what, lie) in shapesNeverGiven) {
            val rule = proxy.on(WireRoute.ADMIN_POLICY_GET, "op", handler = lie)
            assertEquals(Fetched.Unreachable, ops.policy(), "policy, $what")
            rule.remove()
        }
        onlyReads("op", mark, "the operator's views")
    }

    /** The real answer cut at half its length, by its own length or chunked (T). */
    private fun truncated(declared: Boolean) = Handler { x ->
        val real = x.forward()
        Resp(real.status, real.headers, ByteArray(0), io.silencelen.andvari.hostile.proxy.Endless.truncated(real.body, real.body.size / 2, declared))
    }

    /** What may reach the device beyond a route's cap before it hangs up: what the sockets and the engine buffer. */
    private val buffered = 16L shl 20

    /**
     * The columns the operator's lists still lacked: every one of the six reads (`GET /admin/accounts` row 73, an
     * account's devices 77, policy 80, the audit 82, status 83, the recovery requests 84) answered with half its real
     * answer, by its length and chunked (T); with the real answer of ANOTHER of these routes (O: an object for a list, a
     * list of other rows for a list, a list for an object); and with a body that never ends, by a lying length and with
     * none (S: refused at the route's cap, the device takes no more than the cap and what sockets buffer). Each is a
     * failure, never an empty list or a view. And for the routes that had no R or X: the accounts list, status and policy
     * replayed from before a change are shown as served (R: the server speaks about itself, design §9.2, the stated
     * limit), and the accounts list's `{}`, `ok` and `500` are a failure (X). Nothing but reads is sent.
     */
    @Test fun anOperatorListCutShortEndlessOrMadeForAnotherRouteIsAFailure() = recoveryWorld {
        val op = operator()
        optIn(member("alice"))
        member("bob")
        verified("areq", "alice@example.org")
        val ops = ops(op)
        val accounts = assertIs<Fetched.Ok<List<io.silencelen.andvari.core.model.wire.AccountSummary>>>(ops.accounts()).value
        val alice = accounts.single { it.email == "alice@example.org" }.userId
        // Every honest answer, read once, to replay (R) or to serve for another route (O).
        val reads: List<Pair<WireRoute, suspend () -> Fetched<*>>> = listOf(
            WireRoute.ADMIN_ACCOUNTS to { ops.accounts() },
            WireRoute.ADMIN_ACCOUNT_DEVICES to { ops.accountDevices(alice) },
            WireRoute.ADMIN_POLICY_GET to { ops.policy() },
            WireRoute.ADMIN_AUDIT to { ops.audit() },
            WireRoute.ADMIN_STATUS to { ops.status() },
            WireRoute.ADMIN_RECOVERY_REQUESTS to { ops.recoveryRequests() },
        )
        val honest = HashMap<WireRoute, Fetched<*>>()
        val bodies = HashMap<WireRoute, String>()
        for ((route, read) in reads) {
            honest[route] = assertIs<Fetched.Ok<*>>(read(), "$route honest")
            bodies[route] = assertNotNull(proxy.last(route, "op")?.upstream).text
        }
        // Which other route's real answer each is served (O): a list for an object, an object for a list, other rows.
        val otherFor = mapOf(
            WireRoute.ADMIN_ACCOUNTS to WireRoute.ADMIN_AUDIT,
            WireRoute.ADMIN_ACCOUNT_DEVICES to WireRoute.ADMIN_ACCOUNTS,
            WireRoute.ADMIN_POLICY_GET to WireRoute.ADMIN_STATUS,
            WireRoute.ADMIN_AUDIT to WireRoute.ADMIN_RECOVERY_REQUESTS,
            WireRoute.ADMIN_STATUS to WireRoute.ADMIN_POLICY_GET,
            WireRoute.ADMIN_RECOVERY_REQUESTS to WireRoute.ADMIN_STATUS,
        )
        val mark = proxy.mark()
        for ((route, read) in reads) {
            val lies: List<Pair<String, Handler>> = listOf(
                "half the answer, by length (T)" to truncated(declared = true),
                "half the answer, chunked (T)" to truncated(declared = false),
                "the answer of ${otherFor.getValue(route)} (O)" to answer { Resp.json(200, Json.parseToJsonElement(bodies.getValue(otherFor.getValue(route)))) },
                "the answer of ${WireRoute.ADMIN_ACCOUNTS} as one row (O)" to answer { Resp.json(200, Json.parseToJsonElement(bodies.getValue(WireRoute.ADMIN_ACCOUNTS)).jsonArray.first()) },
            )
            for ((what, lie) in lies) {
                if (route == WireRoute.ADMIN_ACCOUNTS && what.endsWith("as one row (O)")) continue
                val rule = proxy.on(route, "op", handler = lie)
                val got = read()
                rule.remove()
                assertEquals(Fetched.Unreachable, got, "$route, $what: a failure, never an empty list or a view")
            }
            val cap = io.silencelen.andvari.core.client.net.ResponseCaps.of(route)
            for ((what, endless) in listOf(
                "endless by length (S)" to io.silencelen.andvari.hostile.proxy.Endless(declaredLength = 1L shl 40, upTo = cap + (64L shl 20)),
                "endless with no length (S)" to io.silencelen.andvari.hostile.proxy.Endless(declaredLength = null, upTo = cap + (64L shl 20)),
            )) {
                val at = proxy.mark()
                val rule = proxy.on(route, "op") { _ -> Resp(200, mapOf("Content-Type" to "application/json"), ByteArray(0), endless) }
                val got = read()
                rule.remove()
                assertEquals(Fetched.Refused(io.silencelen.andvari.core.client.net.BODY_OVER_LIMIT), got, "$route, $what: refused at the cap")
                val exs = proxy.since(at).filter { it.req.route == route }
                assertTrue(exs.isNotEmpty(), "$route, $what: asked")
                for (ex in exs) assertTrue(ex.written <= cap + buffered, "$route, $what: the device took ${ex.written} bytes, cap $cap")
            }
            // The honest answer reads as before once the lie is gone.
            assertIs<Fetched.Ok<*>>(read(), "$route after the lies")
        }

        // R where the column was empty: the answer from before a change, shown as served (the stated limit).
        val earlier = HashMap(bodies)
        member("carol")
        val newer = assertIs<Fetched.Ok<List<io.silencelen.andvari.core.model.wire.AccountSummary>>>(ops.accounts()).value
        assertTrue(newer.any { it.email == "carol@example.org" })
        for ((route, read) in reads.filter { it.first in setOf(WireRoute.ADMIN_ACCOUNTS, WireRoute.ADMIN_STATUS, WireRoute.ADMIN_POLICY_GET) }) {
            val rule = proxy.on(route, "op", handler = answer { Resp.json(200, Json.parseToJsonElement(earlier.getValue(route))) })
            val got = read()
            rule.remove()
            assertEquals(honest[route], got, "$route, the earlier answer (R): shown as served")
        }
        // X on the accounts list.
        for ((what, lie) in shapesNeverGiven) {
            val rule = proxy.on(WireRoute.ADMIN_ACCOUNTS, "op", handler = lie)
            assertEquals(Fetched.Unreachable, ops.accounts(), "accounts, $what: a failure, never \"no accounts\"")
            rule.remove()
        }
        onlyReads("op", mark, "the operator's lists")
    }

    /**
     * FINDING O1: a self-contradicting operator list is handed up as read. The app interface's console (`EngineOperator`)
     * refuses such a list whole: a recovery request twice or with an id outside its grammar, an audit of more than one page
     * (500 rows), a row twice or a row outside the filters asked, and an account's device marked as this session's
     * (`current`, which the operator's view never carries). [WireOperatorRoutes], which the headless host (and any other
     * host) reads them through, answers each as `Fetched.Ok`, so `andvari-cli operator` prints them. The cost is display
     * only (the server speaks about itself, design §9.2), but the two hosts disagree on the same answer, and a request row
     * whose id is not one is printed as something to type into `recovery-cli assist`. The fix, in
     * `core/client/account/`: move `EngineOperator`'s checks (`requestsWhole`, `accountsWhole`, the audit's two lines and
     * the `current` check) into [WireOperatorRoutes] as `Fetched.Refused(BAD_RESPONSE)` for `recoveryRequests`, `accounts`,
     * `audit(since, type, userId)` and `accountDevices`, and let `EngineOperator` keep them or rely on them.
     */
    @Ignore("FINDING O1: WireOperatorRoutes hands up a self-contradicting operator list as read (a request twice or with a bad id, an audit over 500 rows, a row twice or outside the filters, a device marked current); move EngineOperator's checks into WireOperatorRoutes as Fetched.Refused(BAD_RESPONSE)")
    @Test fun aSelfContradictingOperatorListIsRefusedAsTheConsoleRefusesIt() = recoveryWorld {
        val op = operator()
        optIn(member("alice"))
        verified("areq", "alice@example.org")
        val ops = ops(op)
        val alice = assertIs<Fetched.Ok<List<io.silencelen.andvari.core.model.wire.AccountSummary>>>(ops.accounts()).value.single { it.email == "alice@example.org" }.userId
        val audit = assertIs<Fetched.Ok<List<io.silencelen.andvari.core.model.wire.AuditRow>>>(ops.audit()).value
        val type = audit.first().type
        assertTrue(audit.any { it.type != type }, "the honest audit holds more than one type")
        val lies: List<Triple<String, WireRoute, Handler>> = listOf(
            Triple("a request twice", WireRoute.ADMIN_RECOVERY_REQUESTS, rows { it + it }),
            Triple("a request id outside its grammar", WireRoute.ADMIN_RECOVERY_REQUESTS, rows { l -> l.map { it.with("requestId", JsonPrimitive("not-an-id")) } }),
            Triple("an audit row twice", WireRoute.ADMIN_AUDIT, rows { it + it.first() }),
            Triple("501 audit rows", WireRoute.ADMIN_AUDIT, rows { l -> (1..501).map { n -> l.first().with("id", JsonPrimitive(n.toLong())) } }),
            Triple("a device marked current", WireRoute.ADMIN_ACCOUNT_DEVICES, rows { l -> l.mapIndexed { i, d -> if (i == 0) d.with("current", JsonPrimitive(true)) else d } }),
        )
        for ((what, route, lie) in lies) {
            val rule = proxy.on(route, "op", handler = lie)
            val read: Fetched<*> = when (route) {
                WireRoute.ADMIN_RECOVERY_REQUESTS -> ops.recoveryRequests()
                WireRoute.ADMIN_AUDIT -> ops.audit()
                else -> ops.accountDevices(alice)
            }
            rule.remove()
            assertEquals(Fetched.Refused(WireOperatorRoutes.BAD_RESPONSE), read, what)
        }
        // Rows of another type than the filter asked: the whole honest audit served for a filtered read.
        val all = assertNotNull(proxy.last(WireRoute.ADMIN_AUDIT, "op")?.upstream).text
        val outside = proxy.on(WireRoute.ADMIN_AUDIT, "op", handler = answer { Resp.json(200, Json.parseToJsonElement(all)) })
        assertEquals(Fetched.Refused(WireOperatorRoutes.BAD_RESPONSE), ops.audit(null, type, null), "rows outside the filter asked")
        outside.remove()
    }
}
