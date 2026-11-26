package io.silencelen.andvari.core.client.account

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.pin.CardPin
import io.silencelen.andvari.core.client.pin.CardTrust
import io.silencelen.andvari.core.client.pin.ChainCheck
import io.silencelen.andvari.core.client.pin.GatePin
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.AccountDeleteBlocker
import io.silencelen.andvari.core.model.wire.AdminPolicy
import io.silencelen.andvari.core.model.wire.AdminSignupPolicy
import io.silencelen.andvari.core.model.wire.OperatorDeleteReason
import io.silencelen.andvari.core.model.wire.OperatorDeleteRequest
import io.silencelen.andvari.core.model.wire.Quota
import io.silencelen.andvari.core.model.wire.ReauthRequest
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** [WireOperatorRoutes] (spec 03 rows 73 to 86) against a scripted server: routes, bodies, local refusals, typed answers. */
class OperatorRoutesTest {
    private val crypto = createCryptoProvider()
    private val origin = "https://home.example"
    private val me = "1c7f4d3e-5e6b-4c8d-9e0f-1a2b3c4d5e6f"
    private val bob = "2d8e5f4a-6f7c-4d9e-8f1a-2b3c4d5e6f70"
    private val device = "3e9f6a5b-7a8d-4e0f-9a2b-3c4d5e6f7081"
    private val requestId = Bytes.toB64(ByteArray(16) { 5 })

    /** What the shared reader of an answer yields for [requestId] (spec 04 §7 step 3): the only thing the route uploads. */
    private fun answer(forRequest: String = requestId) =
        io.silencelen.andvari.core.trust.AnswerRead.Ok(forRequest, Bytes.toB64(ByteArray(32) { 3 }), "ab".repeat(32), Bytes.toB64(ByteArray(548) { 9 }))
    private val key = "k".repeat(43)

    private class Call(val route: WireRoute, val params: Map<String, String>, val query: String?, val body: String?)

    /** Answers each route with [answers]' text (an `ok` body when absent), or a refusal from [refusals]. */
    private class Script(override val origin: String) : WireClient {
        val calls = ArrayList<Call>()
        val answers = HashMap<WireRoute, String>()
        val refusals = HashMap<WireRoute, WireResult<Nothing>>()
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            calls += Call(route, pathParams, query, bodyJson)
            refusals[route]?.let { return it }
            return WireResult.Ok(decode(answers[route] ?: "ok"), 200)
        }
    }

    private class Env(val routes: WireOperatorRoutes, val server: Script, val derived: () -> Int, val pins: MutableList<GatePin>)

    private fun env(role: String = "operator", kind: String = "private"): Env {
        val server = Script(origin)
        val state = MemoryDeviceState()
        val store = PinStore(state)
        store.put(CardPin("0b6f3c2e-4d5a-4b7c-8d9e-0f1a2b3c4d5e", 0, "a".repeat(64), origin, "Home", kind, me, "s".repeat(43) + "=", "none", PinRoot.TRUST_GATE, null, "a".repeat(64)))
        val trust = CardTrust(store, { _, _ -> ChainCheck.Refused("unused") }, { server }, crypto, null, false)
        var derived = 0
        val pins = mutableListOf(GatePin(origin, PinRoot.TRUST_GATE))
        val reauth = Reauth(object : ReauthSession {
            override val origin = this@OperatorRoutesTest.origin
            override val emailNorm = "op@example.com"
            override suspend fun deriveCurrentAuthKey(password: CharArray): String? { derived++; return key }
        }) { pins }
        return Env(WireOperatorRoutes(me, role, server, trust, reauth), server, { derived }, pins)
    }

    private fun pw() = "operator Passphrase 7".toCharArray()
    private fun wiped(p: CharArray) = assertTrue(p.all { it == '\u0000' }, "the password is wiped")
    private fun body(c: Call) = Json.parseToJsonElement(c.body!!).jsonObject

    private val policy = AdminPolicy(mapOf("android" to "1.0.0"), KdfParams.DEFAULT, 300, 30, true, 3600, 30, 1_000_000, 5_000_000,
        Quota(10_000_000, 1000, 5, 20), AdminSignupPolicy(null, null))

    @Test fun everyRouteGoesWhereTheIndexSaysWithAFreshKeyAndThePasswordWiped() = runBlocking<Unit> {
        val e = env()
        e.server.answers[WireRoute.ADMIN_ACCOUNTS] = "[]"
        e.server.answers[WireRoute.ADMIN_ACCOUNT_DEVICES] = "[]"
        e.server.answers[WireRoute.ADMIN_AUDIT] = "[]"
        e.server.answers[WireRoute.ADMIN_RECOVERY_REQUESTS] = "[]"
        e.server.answers[WireRoute.ADMIN_ACCOUNT_DELETE] = """{"deletedAt":77}"""
        e.server.answers[WireRoute.ADMIN_QUOTA] = """{"accountBytes":1,"items":2,"ownedSharedVaults":3,"openLinks":4}"""
        e.server.answers[WireRoute.ADMIN_POLICY_PUT] = io.silencelen.andvari.core.model.wire.WireJson.json.encodeToString(AdminPolicy.serializer(), policy)
        e.server.answers[WireRoute.ADMIN_ESCROW] = """{"userId":"$bob","sealed":"x","encryptedIdentitySeed":"y","identityPub":"z"}"""
        assertIs<Fetched.Ok<*>>(e.routes.accounts())
        assertIs<Fetched.Ok<*>>(e.routes.accountDevices(bob))
        assertIs<Fetched.Ok<*>>(e.routes.audit(5, "operator_disable", bob))
        assertIs<Fetched.Ok<*>>(e.routes.audit())
        assertIs<Fetched.Ok<*>>(e.routes.recoveryRequests())
        val passwords = List(8) { pw() }
        assertIs<Reauthed.Done<Unit>>(e.routes.disable(bob, "abuse", passwords[0]))
        assertIs<Reauthed.Done<Unit>>(e.routes.enable(bob, passwords[1]))
        assertEquals(Reauthed.Done(77L), e.routes.deleteAccount(bob, passwords[2]))
        assertIs<Reauthed.Done<Unit>>(e.routes.revokeDevice(device, passwords[3]))
        assertEquals(Reauthed.Done(Quota(1, 2, 3, 4)), e.routes.setQuota(bob, 1, null, null, 4, passwords[4]))
        assertEquals(Reauthed.Done(policy), e.routes.setPolicy(policy, passwords[5]))
        assertEquals(bob, assertIs<Reauthed.Done<io.silencelen.andvari.core.model.wire.AdminEscrowResponse>>(e.routes.escrow(bob, passwords[6])).value.userId)
        assertIs<Reauthed.Done<Unit>>(e.routes.fulfil(requestId, answer(), passwords[7]))
        passwords.forEach(::wiped)
        assertEquals(8, e.derived())

        val c = e.server.calls
        assertEquals(listOf(WireRoute.ADMIN_ACCOUNTS, WireRoute.ADMIN_ACCOUNT_DEVICES, WireRoute.ADMIN_AUDIT, WireRoute.ADMIN_AUDIT,
            WireRoute.ADMIN_RECOVERY_REQUESTS, WireRoute.ADMIN_ACCOUNT_DISABLE, WireRoute.ADMIN_ACCOUNT_ENABLE, WireRoute.ADMIN_ACCOUNT_DELETE,
            WireRoute.ADMIN_DEVICE_REVOKE, WireRoute.ADMIN_QUOTA, WireRoute.ADMIN_POLICY_PUT, WireRoute.ADMIN_ESCROW, WireRoute.ADMIN_RECOVERY_FULFIL),
            c.map { it.route })
        assertEquals(mapOf("userId" to bob), c[1].params)
        assertEquals("since=5&type=operator_disable&userId=$bob", c[2].query)
        assertEquals(null, c[3].query, "no filter, no query")
        for (w in c.drop(5)) assertEquals(key, body(w)["currentAuthKey"]!!.jsonPrimitive.content, "${w.route}: a fresh key in the body")
        assertEquals("abuse", body(c[5])["reason"]!!.jsonPrimitive.content)
        assertEquals(mapOf("deviceId" to device), c[8].params)
        val quota = body(c[9])
        assertEquals(JsonNull, quota["items"], "a limit returned to the default is sent as null, never left out")
        assertEquals(JsonNull, quota["ownedSharedVaults"])
        assertEquals("4", quota["openLinks"]!!.jsonPrimitive.content)
        assertTrue("signup" in body(c[10]) && "kdfParams" in body(c[10]))
        assertEquals(mapOf("requestId" to requestId), c[12].params)
    }

    @Test fun aCertainRefusalDerivesAndSendsNothing() = runBlocking<Unit> {
        suspend fun refusedHere(e: Env, code: String, call: suspend (CharArray) -> Reauthed<*>) {
            val p = pw()
            assertEquals(Reauthed.Refused(code), call(p), code)
            wiped(p)
        }
        val member = env(role = "member")
        assertEquals(Fetched.Refused(WireOperatorRoutes.NOT_OPERATOR), member.routes.accounts())
        assertEquals(Fetched.Refused(WireOperatorRoutes.NOT_OPERATOR), member.routes.status())
        assertEquals(Fetched.Refused(WireOperatorRoutes.NOT_OPERATOR), member.routes.recoveryRequests())
        refusedHere(member, WireOperatorRoutes.NOT_OPERATOR) { member.routes.enable(bob, it) }
        refusedHere(member, WireOperatorRoutes.NOT_OPERATOR) { member.routes.setPolicy(policy, it) }
        assertTrue(member.server.calls.isEmpty() && member.derived() == 0)

        val e = env()
        refusedHere(e, WireOperatorRoutes.CANNOT_TARGET_SELF) { e.routes.disable(me, "abuse", it) }
        refusedHere(e, WireOperatorRoutes.CANNOT_TARGET_SELF) { e.routes.deleteAccount(me, it) }
        refusedHere(e, WireOperatorRoutes.BAD_USER_ID) { e.routes.enable("../accounts", it) }
        refusedHere(e, WireOperatorRoutes.BAD_REASON) { e.routes.disable(bob, "because", it) }
        refusedHere(e, WireOperatorRoutes.BAD_DEVICE_ID) { e.routes.revokeDevice("x", it) }
        refusedHere(e, WireOperatorRoutes.BAD_QUOTA) { e.routes.setQuota(bob, -1, null, null, null, it) }
        refusedHere(e, WireOperatorRoutes.KDF_MEM_NOT_KIB_MULTIPLE) { e.routes.setPolicy(policy.copy(kdfParams = KdfParams(memBytes = 67_108_865)), it) }
        refusedHere(e, WireOperatorRoutes.BAD_REQUEST_ID) { e.routes.fulfil("nope", answer("nope"), it) }
        // An answer the reader read for another request is never uploaded to this one.
        refusedHere(e, WireOperatorRoutes.BAD_REQUEST_ID) { e.routes.fulfil(requestId, answer(Bytes.toB64(ByteArray(16) { 6 })), it) }
        assertEquals(Fetched.Refused(WireOperatorRoutes.BAD_USER_ID), e.routes.accountDevices("me"))
        assertEquals(Fetched.Refused(WireOperatorRoutes.BAD_TYPE), e.routes.audit(null, "x&userId=", null))
        assertEquals(Fetched.Refused(WireOperatorRoutes.BAD_USER_ID), e.routes.audit(null, null, "not-a-uuid"))
        assertTrue(e.server.calls.isEmpty() && e.derived() == 0)

        // Variant R: a public card has no operator recovery, so its three routes are never called.
        val pub = env(kind = "public")
        assertEquals(Fetched.Refused(WireOperatorRoutes.OPERATOR_RECOVERY_UNAVAILABLE), pub.routes.recoveryRequests())
        refusedHere(pub, WireOperatorRoutes.OPERATOR_RECOVERY_UNAVAILABLE) { pub.routes.escrow(bob, it) }
        refusedHere(pub, WireOperatorRoutes.OPERATOR_RECOVERY_UNAVAILABLE) { pub.routes.fulfil(requestId, answer(), it) }
        assertTrue(pub.server.calls.isEmpty() && pub.derived() == 0)

        // The password gate refuses at a forked origin: nothing derived, nothing sent.
        val forked = env()
        forked.pins[0] = GatePin(origin, PinRoot.TRUST_GATE, blocked = true)
        val p = pw()
        assertEquals(Reauthed.NoSession, forked.routes.enable(bob, p))
        wiped(p)
        assertTrue(forked.server.calls.isEmpty() && forked.derived() == 0)
    }

    @Test fun theDeleteTypesTheThirtyDayRuleAndASharedVault() = runBlocking<Unit> {
        val e = env()
        fun refuse(status: Int, error: WireError) { e.server.refusals[WireRoute.ADMIN_ACCOUNT_DELETE] = WireResult.Refused(status, error) }
        refuse(409, WireError(WireOperatorRoutes.NOT_DISABLED_LONG_ENOUGH, "m", disabledAt = 1_700_000_000_000))
        assertEquals(OperatorDelete.NotDisabledLongEnough(1_700_000_000_000), e.routes.deleteChecked(bob, pw()))
        refuse(409, WireError(WireOperatorRoutes.NOT_DISABLED_LONG_ENOUGH, "m"))
        assertEquals(OperatorDelete.NotDisabledLongEnough(null), e.routes.deleteChecked(bob, pw()), "an active account reads the same")
        assertEquals(Reauthed.Refused(WireOperatorRoutes.NOT_DISABLED_LONG_ENOUGH), e.routes.deleteAccount(bob, pw()))
        val blockers = listOf(AccountDeleteBlocker("shared_vault", "4fa07b6c-8b9e-4f1a-8b2c-3d4e5f6a7b8c", 2))
        refuse(409, WireError(WireOperatorRoutes.ACCOUNT_DELETE_BLOCKED, "m", blockers = blockers))
        assertEquals(OperatorDelete.Blocked(blockers), e.routes.deleteChecked(bob, pw()))
        assertEquals(Reauthed.Refused(WireOperatorRoutes.ACCOUNT_DELETE_BLOCKED), e.routes.deleteAccount(bob, pw()))
        refuse(400, WireError(WireOperatorRoutes.NO_SUCH_USER, "m"))
        assertEquals(OperatorDelete.Other(Reauthed.Refused(WireOperatorRoutes.NO_SUCH_USER)), e.routes.deleteChecked(bob, pw()))
        refuse(403, WireError(WireOperatorRoutes.REAUTH_FAILED, "m"))
        assertEquals(OperatorDelete.Other(Reauthed.Refused(Reauthed.PROOF_REFUSED)), e.routes.deleteChecked(bob, pw()), "the server's refusal of the proof")
        refuse(503, WireError("unavailable", "m"))
        assertEquals(OperatorDelete.Other(Reauthed.Unknown), e.routes.deleteChecked(bob, pw()))
        assertEquals(OperatorDelete.Other(Reauthed.Refused(WireOperatorRoutes.CANNOT_TARGET_SELF)), e.routes.deleteChecked(me, pw()))
    }

    @Test fun theDeleteCarriesItsReasonAndNoReasonIsTheOldBodyByteForByte() = runBlocking<Unit> {
        assertEquals(OperatorDeleteRequest::class, WireRoute.ADMIN_ACCOUNT_DELETE.request, "the route has its own request type")
        assertEquals("under_minimum_age", OperatorDeleteReason.UNDER_MINIMUM_AGE)
        val e = env()
        e.server.answers[WireRoute.ADMIN_ACCOUNT_DELETE] = """{"deletedAt":77}"""
        val plain = """{"currentAuthKey":"$key"}"""
        assertEquals(plain, WireJson.json.encodeToString(ReauthRequest.serializer(), ReauthRequest(key)), "what was sent before the reason existed")
        assertEquals(plain, WireJson.json.encodeToString(OperatorDeleteRequest.serializer(), OperatorDeleteRequest(key)))

        assertEquals(Reauthed.Done(77L), e.routes.deleteAccount(bob, pw()))
        assertEquals(OperatorDelete.Deleted(77L), e.routes.deleteChecked(bob, pw()))
        assertEquals(Reauthed.Done(77L), e.routes.deleteAccount(bob, pw(), null))
        assertEquals(List(3) { plain }, e.server.calls.map { it.body }, "no reason: the body is unchanged, byte for byte")

        e.server.calls.clear()
        assertEquals(Reauthed.Done(77L), e.routes.deleteAccount(bob, pw(), OperatorDeleteReason.UNDER_MINIMUM_AGE))
        assertEquals(OperatorDelete.Deleted(77L), e.routes.deleteChecked(bob, pw(), OperatorDeleteReason.UNDER_MINIMUM_AGE))
        val under = """{"currentAuthKey":"$key","reason":"under_minimum_age"}"""
        assertEquals(listOf(under, under), e.server.calls.map { it.body })

        // Any other reason is a closed-set refusal here: nothing derived, nothing sent, the password wiped.
        e.server.calls.clear()
        val derivedBefore = e.derived()
        for (bad in listOf("abuse", "UNDER_MINIMUM_AGE", "", "under_minimum_age ")) {
            val p = pw()
            assertEquals(Reauthed.Refused(WireOperatorRoutes.BAD_REASON), e.routes.deleteAccount(bob, p, bad), "'$bad'")
            wiped(p)
            val q = pw()
            assertEquals(OperatorDelete.Other(Reauthed.Refused(WireOperatorRoutes.BAD_REASON)), e.routes.deleteChecked(bob, q, bad))
            wiped(q)
        }
        assertTrue(e.server.calls.isEmpty() && e.derived() == derivedBefore)
        // The server's own refusal of a reason reads as its code.
        e.server.refusals[WireRoute.ADMIN_ACCOUNT_DELETE] = WireResult.Refused(400, WireError(WireOperatorRoutes.BAD_REASON, "m"))
        assertEquals(Reauthed.Refused(WireOperatorRoutes.BAD_REASON), e.routes.deleteAccount(bob, pw(), OperatorDeleteReason.UNDER_MINIMUM_AGE))
        // Self is still refused before the reason helps.
        assertEquals(Reauthed.Refused(WireOperatorRoutes.CANNOT_TARGET_SELF), e.routes.deleteAccount(me, pw(), OperatorDeleteReason.UNDER_MINIMUM_AGE))
    }

    /**
     * A refused policy carries the server's own words for the refusal, without control characters and at most
     * [Reauthed.MESSAGE_MAX] characters; no other route's refusal carries any, nor the server's refusal of the proof.
     */
    @Test fun aRefusedPolicyCarriesTheServersOwnMessage() = runBlocking<Unit> {
        val e = env()
        e.server.refusals[WireRoute.ADMIN_POLICY_PUT] =
            WireResult.Refused(400, WireError(WireOperatorRoutes.KDF_TOO_WEAK, "memory below\nthe floor of 64 MiB\u0007"))
        assertEquals(Reauthed.Refused(WireOperatorRoutes.KDF_TOO_WEAK, message = "memory belowthe floor of 64 MiB"), e.routes.setPolicy(policy, pw()))
        e.server.refusals[WireRoute.ADMIN_POLICY_PUT] = WireResult.Refused(400, WireError(WireOperatorRoutes.NOT_TIGHTER, "x".repeat(5000)))
        assertEquals(Reauthed.MESSAGE_MAX, assertIs<Reauthed.Refused>(e.routes.setPolicy(policy, pw())).message?.length)
        e.server.refusals[WireRoute.ADMIN_POLICY_PUT] = WireResult.Refused(403, WireError(WireOperatorRoutes.REAUTH_FAILED, "say this"))
        assertEquals(Reauthed.Refused(Reauthed.PROOF_REFUSED), e.routes.setPolicy(policy, pw()))
        e.server.refusals[WireRoute.ADMIN_ACCOUNT_DISABLE] = WireResult.Refused(400, WireError(WireOperatorRoutes.NO_SUCH_USER, "say this"))
        assertNull(assertIs<Reauthed.Refused>(e.routes.disable(bob, "request", pw())).message)
    }

    @Test fun refusalsAndFailuresAreTyped() = runBlocking<Unit> {
        val e = env()
        e.server.refusals[WireRoute.ADMIN_ACCOUNT_DISABLE] = WireResult.Refused(400, WireError(WireOperatorRoutes.NO_SUCH_USER, "m"))
        assertEquals(Reauthed.Refused(WireOperatorRoutes.NO_SUCH_USER), e.routes.disable(bob, "request", pw()))
        e.server.refusals[WireRoute.ADMIN_POLICY_PUT] = WireResult.Refused(400, WireError(WireOperatorRoutes.NOT_TIGHTER, "m"))
        assertEquals(Reauthed.Refused(WireOperatorRoutes.NOT_TIGHTER, message = "m"), e.routes.setPolicy(policy, pw()))
        e.server.refusals[WireRoute.ADMIN_RECOVERY_FULFIL] = WireResult.Refused(409, WireError(WireOperatorRoutes.REQUEST_STATE, "m"))
        assertEquals(Reauthed.Refused(WireOperatorRoutes.REQUEST_STATE), e.routes.fulfil(requestId, answer(), pw()))
        e.server.refusals[WireRoute.ADMIN_DEVICE_REVOKE] = WireResult.Refused(429, WireError("rate_limited", "m"), retryAfterSeconds = 12)
        assertEquals(Reauthed.Refused("rate_limited", 12), e.routes.revokeDevice(device, pw()))
        e.server.refusals[WireRoute.ADMIN_ACCOUNT_ENABLE] = WireResult.NoAnswer(NoAnswerKind.TIMEOUT)
        assertEquals(Reauthed.Unknown, e.routes.enable(bob, pw()))
        e.server.refusals[WireRoute.ADMIN_STATUS] = WireResult.Refused(403, WireError(WireOperatorRoutes.OPERATOR_WEB_REFUSED, "m"))
        assertEquals(Fetched.Refused(WireOperatorRoutes.OPERATOR_WEB_REFUSED), e.routes.status())
        e.server.refusals[WireRoute.ADMIN_ACCOUNTS] = WireResult.Refused(500, WireError("internal", "m"))
        assertEquals(Fetched.Unreachable, e.routes.accounts())
        // An escrow answered for another account is not shown as this one's.
        e.server.answers[WireRoute.ADMIN_ESCROW] = """{"userId":"$me","sealed":"x","encryptedIdentitySeed":"y","identityPub":"z"}"""
        assertEquals(Reauthed.Refused(WireOperatorRoutes.BAD_RESPONSE), e.routes.escrow(bob, pw()))
        e.server.refusals[WireRoute.ADMIN_ESCROW] = WireResult.Refused(404, WireError(WireOperatorRoutes.NO_ESCROW, "m"))
        assertEquals(Reauthed.Refused(WireOperatorRoutes.NO_ESCROW), e.routes.escrow(bob, pw()))
    }

    private fun rows(ids: LongProgression, type: String = "operator_disable", userId: String? = bob, at: Long = 10) =
        WireJson.json.encodeToString(kotlinx.serialization.builtins.ListSerializer(io.silencelen.andvari.core.model.wire.AuditRow.serializer()),
            ids.map { io.silencelen.andvari.core.model.wire.AuditRow(it, at, type, userId) })

    /**
     * The audit list in pages, through the one shared call (the command-line tool and the desktop console alike): a
     * full page offers the next one with the same filters and the last row's id as the cursor; the page after a short
     * one is not asked for; and each page is checked as every host checks it. Before, a host joining pages made its own
     * call for later pages and its own checks.
     */
    @Test fun theAuditListIsReadInCheckedPagesWithTheSameFilters() = runBlocking<Unit> {
        val e = env()
        val full = WireOperatorRoutes.AUDIT_PAGE_ROWS.toLong()
        e.server.answers[WireRoute.ADMIN_AUDIT] = rows(1000L downTo 1000L - full + 1)
        val first = assertIs<Fetched.Ok<AuditPage>>(e.routes.auditPage(5, "operator_disable", bob)).value
        assertTrue(first.full)
        assertEquals("since=5&type=operator_disable&userId=$bob", e.server.calls.last().query)
        e.server.answers[WireRoute.ADMIN_AUDIT] = rows(500L downTo 499L)
        val second = assertIs<Fetched.Ok<AuditPage>>(assertIs<Fetched<AuditPage>>(e.routes.nextAuditPage(first))).value
        assertEquals("since=5&type=operator_disable&userId=$bob&after=${first.rows.last().id}", e.server.calls.last().query, "the same filters, the cursor")
        assertEquals(false, second.full)
        assertEquals(null, e.routes.nextAuditPage(second), "a short page is the last")

        // The checks, each one a lie of the server's: refused as such, never shown as a short list.
        suspend fun lies(text: String, after: Long? = null) {
            e.server.answers[WireRoute.ADMIN_AUDIT] = text
            assertEquals(Fetched.Refused(WireOperatorRoutes.AUDIT_PAGE_LIES), e.routes.auditPage(5, "operator_disable", bob, after), text.take(80))
        }
        lies(rows(1000L downTo 1000L - full))                       // more rows than a page holds
        lies(rows(LongProgression.fromClosedRange(3, 7, 2)))        // oldest first
        lies(rows(LongProgression.fromClosedRange(9, 9, 1)).removeSuffix("]") + "," + rows(9L downTo 9L).removePrefix("[")) // a row twice
        lies(rows(500L downTo 498L), after = 499)                   // a row not older than the cursor
        lies(rows(9L downTo 8L, type = "operator_enable"))          // outside the type filter
        lies(rows(9L downTo 8L, userId = me))                       // outside the account filter
        lies(rows(9L downTo 8L, at = 4))                            // older than "since"
        e.server.calls.clear()
        assertEquals(Fetched.Refused(WireOperatorRoutes.BAD_CURSOR), e.routes.auditPage(null, null, null, after = 0))
        assertTrue(e.server.calls.isEmpty(), "a cursor that is not a row id sends nothing")
    }
}
