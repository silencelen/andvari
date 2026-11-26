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
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.Device
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.builtins.ListSerializer
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The devices list read page by page (spec 03 §16.7; index rows 26 and 77): `?after=<last deviceId>` while a page holds
 * 500 rows, the whole list only once the last page arrived, any refused page fails the whole read, and a lying server
 * (a page that never ends, a cursor that loops, more rows than a page may hold, two sessions' views mixed) costs at
 * most [DevicePages.MAX_PAGES] requests and never a list.
 */
class DevicePagesTest {
    private val origin = "https://home.example"
    private val me = "1c7f4d3e-5e6b-4c8d-9e0f-1a2b3c4d5e6f"
    private val bob = "2d8e5f4a-6f7c-4d9e-8f1a-2b3c4d5e6f70"

    private fun id(n: Int) = "00000000-0000-4000-8000-" + n.toString().padStart(12, '0')
    private fun device(n: Int, current: Boolean = false) = Device(id(n), "android", "Phone $n", null, 1_000L + n, null, true, "registered", current = current)

    private fun okPage(rows: List<Device>): WireResult<List<Device>> = WireResult.Ok(rows, 200)

    /** Serves each call from [page] (by the `after` it was sent, null for the first), recording the queries. */
    private class Pages(val page: (after: String?, call: Int) -> WireResult<List<Device>>) : WireClient {
        override val origin = "https://home.example"
        val queries = ArrayList<String?>()
        val routes = ArrayList<Pair<WireRoute, Map<String, String>>>()
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            queries += query
            routes += route to pathParams
            return when (val r = page(query?.removePrefix("after="), queries.size)) {
                is WireResult.Ok -> WireResult.Ok(decode(WireJson.json.encodeToString(ListSerializer(Device.serializer()), r.value)), 200)
                is WireResult.Refused -> r
                is WireResult.NoAnswer -> r
            }
        }
    }

    /** An honest server holding [count] devices, the first of them this session's. */
    private fun honest(count: Int) = Pages { after, _ ->
        val start = if (after == null) 0 else (0 until count).first { id(it) == after } + 1
        okPage((start until minOf(count, start + 500)).map { device(it, current = it == 0) })
    }

    @Test fun everyPageIsReadAndTheWholeListAnsweredOnlyAtTheLast() = runBlocking<Unit> {
        for ((count, requests) in listOf(0 to 1, 1 to 1, 499 to 1, 500 to 2, 1000 to 3, 1201 to 3)) {
            val s = honest(count)
            val r = DevicePages.readAll(s, WireRoute.DEVICES)
            assertEquals(Fetched.Ok((0 until count).map { device(it, current = it == 0) }), r, "count=$count")
            assertEquals(requests, s.queries.size, "count=$count")
            assertEquals(listOf<String?>(null) + (1 until requests).map { "after=" + id(it * 500 - 1) }, s.queries, "count=$count")
        }
        // The operator's view of an account's devices pages the same way, with the account in the path.
        val s = honest(1201)
        DevicePages.readAll(s, WireRoute.ADMIN_ACCOUNT_DEVICES, mapOf("userId" to bob))
        assertEquals(List(3) { WireRoute.ADMIN_ACCOUNT_DEVICES to mapOf("userId" to bob) }, s.routes)
    }

    @Test fun aRefusedOrUnansweredPageFailsTheWholeRead() = runBlocking<Unit> {
        val full = (0 until 500).map { device(it) }
        for ((answer, expected) in listOf(
            WireResult.Refused(400, WireError("bad_request", "after names no device")) to Fetched.Refused("bad_request"),
            WireResult.Refused(401, WireError("session_revoked", "")) to Fetched.Refused("session_revoked"),
            WireResult.Refused(503, WireError("unavailable", "")) to Fetched.Unreachable,
            WireResult.NoAnswer(NoAnswerKind.TIMEOUT) to Fetched.Unreachable,
        )) {
            val s = Pages { after, _ -> if (after == null) okPage(full) else answer }
            assertEquals(expected, DevicePages.readAll(s, WireRoute.DEVICES), "$answer")
            assertEquals(2, s.queries.size)
        }
    }

    @Test fun aLyingServerCostsABoundedReadAndNeverAList() = runBlocking<Unit> {
        // A page that never ends: 500 new devices every time.
        val endless = Pages { _, call -> okPage((0 until 500).map { device(call * 1000 + it) }) }
        assertEquals(Fetched.Refused(DevicePages.TOO_MANY_PAGES), DevicePages.readAll(endless, WireRoute.DEVICES))
        assertEquals(DevicePages.MAX_PAGES, endless.queries.size)

        // A cursor that loops: the second page is the first again; or one row of an earlier page comes back.
        val first = (0 until 500).map { device(it) }
        val loop = Pages { _, _ -> okPage(first) }
        assertEquals(Fetched.Refused(DevicePages.BAD_PAGE), DevicePages.readAll(loop, WireRoute.DEVICES))
        assertEquals(2, loop.queries.size)
        val oneBack = Pages { after, _ -> okPage(if (after == null) first else listOf(device(1000), device(3))) }
        assertEquals(Fetched.Refused(DevicePages.BAD_PAGE), DevicePages.readAll(oneBack, WireRoute.DEVICES))
        val twiceOnAPage = Pages { _, _ -> okPage(listOf(device(1), device(1))) }
        assertEquals(Fetched.Refused(DevicePages.BAD_PAGE), DevicePages.readAll(twiceOnAPage, WireRoute.DEVICES))

        // More rows than a page may hold.
        val over = Pages { _, _ -> okPage((0 until 501).map { device(it) }) }
        assertEquals(Fetched.Refused(DevicePages.BAD_PAGE), DevicePages.readAll(over, WireRoute.DEVICES))
        assertEquals(1, over.queries.size)

        // A page from another session's view (another account's list, or another device's): a second current device.
        val mixed = Pages { after, _ ->
            okPage(if (after == null) (0 until 500).map { device(it, current = it == 0) } else listOf(device(2000, current = true), device(2001)))
        }
        assertEquals(Fetched.Refused(DevicePages.BAD_PAGE), DevicePages.readAll(mixed, WireRoute.DEVICES))

        // Bound to this session's device: the whole list must mark exactly this device current.
        val honestOne = honest(3)
        assertEquals(3, (DevicePages.readAll(honestOne, WireRoute.DEVICES, thisDevice = id(0)) as Fetched.Ok).value.size)
        for (lie in listOf(
            listOf(device(7, current = true), device(8)),   // another account's whole list, its device marked
            listOf(device(0), device(8)),                   // no device marked at all
        )) {
            assertEquals(Fetched.Refused(DevicePages.BAD_PAGE), DevicePages.readAll(Pages { _, _ -> okPage(lie) }, WireRoute.DEVICES, thisDevice = id(0)), "$lie")
            assertEquals(Fetched.Ok(lie), DevicePages.readAll(Pages { _, _ -> okPage(lie) }, WireRoute.DEVICES), "unbound, only the page rules apply")
        }

        // A full page whose last row is not a uuid never becomes a cursor.
        val badId = Pages { _, _ -> okPage((0 until 499).map { device(it) } + device(499).copy(deviceId = "x&after=1")) }
        assertEquals(Fetched.Refused(DevicePages.BAD_PAGE), DevicePages.readAll(badId, WireRoute.DEVICES))
        assertEquals(1, badId.queries.size)
    }

    @Test fun theOperatorsViewOfAnAccountsDevicesReadsEveryPage() = runBlocking<Unit> {
        val server = honest(1201)
        val store = PinStore(MemoryDeviceState())
        store.put(CardPin("0b6f3c2e-4d5a-4b7c-8d9e-0f1a2b3c4d5e", 0, "a".repeat(64), origin, "Home", "private", me, "s".repeat(43) + "=", "none", PinRoot.TRUST_GATE, null, "a".repeat(64)))
        val trust = CardTrust(store, { _, _ -> ChainCheck.Refused("unused") }, { server }, createCryptoProvider(), null, false)
        val reauth = Reauth(object : ReauthSession {
            override val origin = this@DevicePagesTest.origin
            override val emailNorm = "op@example.com"
            override suspend fun deriveCurrentAuthKey(password: CharArray): String? = null
        }) { listOf(GatePin(origin, PinRoot.TRUST_GATE)) }
        val routes = WireOperatorRoutes(me, "operator", server, trust, reauth)
        val r = routes.accountDevices(bob)
        assertEquals(1201, (r as Fetched.Ok).value.size, "every page, not the first 500")
        assertEquals(3, server.queries.size)
        // Not the operator: nothing is asked.
        val notOperator = honest(3)
        assertEquals(Fetched.Refused(WireOperatorRoutes.NOT_OPERATOR), WireOperatorRoutes(me, "member", notOperator, trust, reauth).accountDevices(bob))
        assertEquals(0, notOperator.queries.size)
    }
}
