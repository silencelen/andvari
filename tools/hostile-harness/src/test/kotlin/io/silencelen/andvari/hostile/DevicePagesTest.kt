package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.core.client.account.DevicePages
import io.silencelen.andvari.core.client.account.Fetched
import io.silencelen.andvari.core.client.account.WireAccountSettings
import io.silencelen.andvari.core.model.wire.Device
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.Resp
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The devices list in pages (spec 03 §16.7; index rows 26 and 77), lied to: a page that never ends, a cursor that
 * loops, and a page of another account. The device asks for at most [DevicePages.MAX_PAGES] pages, answers the whole
 * list only when its last page arrived, and shows no list at all when any page breaks the rules.
 */
class DevicePagesTest {
    private val rows = ListSerializer(Device.serializer())

    private fun page(devices: List<Device>): Resp = Resp.json(200, Json.parseToJsonElement(WireJson.json.encodeToString(rows, devices)))

    private fun filler(n: Int, from: Long = 1_700_000_000_000L): List<Device> =
        List(n) { Device(UUID.randomUUID().toString(), "android", "Phone $it", null, from + it, null, true, "registered") }

    private fun served(r: Resp): List<Device> = WireJson.json.decodeFromString(rows, r.text)

    @Test fun aDevicesPageThatNeverEndsStopsAtTheStatedNumberOfPagesAndShowsNoList() = world {
        val oh = operator()
        val ah = member("alice")
        val alice = account(ah)
        // The honest list first: one page, no cursor.
        val honest = assertIs<Fetched.Ok<List<Device>>>(ah.settings(ah.session(origin)!!).list()).value
        assertEquals(1, honest.size)
        assertEquals(listOf<String?>(null), sent(ah, WireRoute.DEVICES).map { it.query })

        // Every page full of new devices, for the account's own view and the operator's view of it.
        proxy.on(WireRoute.DEVICES, "alice") { _ -> page(filler(DevicePages.PAGE_ROWS)) }
        proxy.on(WireRoute.ADMIN_ACCOUNT_DEVICES, "op") { _ -> page(filler(DevicePages.PAGE_ROWS)) }
        val mark = proxy.mark()
        assertEquals(Fetched.Refused(DevicePages.TOO_MANY_PAGES), ah.settings(ah.session(origin)!!).list())
        assertEquals(Fetched.Refused(DevicePages.TOO_MANY_PAGES), oh.operator(oh.session(origin)!!).accountDevices(alice.userId))
        assertEquals(DevicePages.MAX_PAGES, sent(ah, WireRoute.DEVICES, mark).size, "the stated number of pages, then it stops")
        assertEquals(DevicePages.MAX_PAGES, sent(oh, WireRoute.ADMIN_ACCOUNT_DEVICES, mark).size)
        // Each request after the first carried the last device of the page before as its cursor.
        val queries = proxy.log().drop(mark).filter { it.req.route == WireRoute.DEVICES }
        for ((i, x) in queries.withIndex().drop(1)) assertEquals("after=" + served(queries[i - 1].served!!).last().deviceId, x.req.query)

        proxy.honest()
        assertEquals(honest, assertIs<Fetched.Ok<List<Device>>>(ah.settings(ah.session(origin)!!).list()).value, "the honest list again")
    }

    @Test fun aCursorThatLoopsFailsTheWholeRead() = world {
        val oh = operator()
        val ah = member("alice")
        val alice = account(ah)
        for ((tag, route) in listOf("alice" to WireRoute.DEVICES, "op" to WireRoute.ADMIN_ACCOUNT_DEVICES)) {
            // The real first page, made full; every later page is that first page again, or one of its rows again.
            var first: List<Device>? = null
            proxy.on(route, tag) { x ->
                page(first ?: (served(x.forward()) + filler(DevicePages.PAGE_ROWS - 1)).take(DevicePages.PAGE_ROWS).also { first = it })
            }
            val mark = proxy.mark()
            val read = if (tag == "alice") ah.settings(ah.session(origin)!!).list() else oh.operator(oh.session(origin)!!).accountDevices(alice.userId)
            assertEquals(Fetched.Refused(DevicePages.BAD_PAGE), read, tag)
            assertEquals(2, proxy.requests(route, tag, mark).size, "$tag: the loop is seen at the first page that repeats")

            // The second page brings back one device of the first, among new ones.
            proxy.honest()
            first = null
            proxy.on(route, tag) { x ->
                val f = first ?: (served(x.forward()) + filler(DevicePages.PAGE_ROWS - 1)).take(DevicePages.PAGE_ROWS).also { first = it }
                if (x.req.queryParam("after") == null) page(f) else page(filler(3, from = 1_800_000_000_000L) + f[1])
            }
            val again = if (tag == "alice") ah.settings(ah.session(origin)!!).list() else oh.operator(oh.session(origin)!!).accountDevices(alice.userId)
            assertEquals(Fetched.Refused(DevicePages.BAD_PAGE), again, tag)
            proxy.honest()
        }
    }

    /** [h]'s devices reader bound to its session's device id, as every host is to build it (`WireAccountSettings(…, thisDevice)`). */
    private fun World.bound(h: Host): WireAccountSettings {
        val held = h.session(origin)!!
        return WireAccountSettings(held.origin, held.emailNorm, h.trust.pinFor(held.origin)?.card0Hash ?: "", held.session.account,
            h.client(held.origin), h.crypto, h.reauth(held), io.silencelen.andvari.core.crypto.KdfParams.DEFAULT, thisDevice = held.session.deviceId)
    }

    private suspend fun World.bobsOwnList(bh: Host): List<Device> {
        assertIs<Fetched.Ok<List<Device>>>(bh.settings(bh.session(origin)!!).list())
        return served(proxy.last(WireRoute.DEVICES, "bob")!!.served!!).also { assertTrue(it.single().current, "Bob's own view marks his device") }
    }

    /**
     * A page of another account: Alice's first page (made full) and then Bob's own devices list as he was served it, or
     * Bob's list as Alice's whole list. Bob's list marks his own device `current`: with the reader bound to this
     * session's device id, neither is shown. In the operator's view of an account no row is `current` and no row names
     * its account, so a page of another account there cannot be told from the truth (the scenario states the limit).
     */
    @Test fun aPageOfAnotherAccountIsNeverShownAsTheAccountsOwnDevices() = world {
        val oh = operator()
        val ah = member("alice")
        val bh = member("bob")
        val alice = account(ah)
        val bobs = bobsOwnList(bh)
        assertEquals(1, assertIs<Fetched.Ok<List<Device>>>(bound(ah).list()).value.size, "the bound reader takes the honest list")

        proxy.on(WireRoute.DEVICES, "alice") { x ->
            if (x.req.queryParam("after") == null) page((served(x.forward()) + filler(DevicePages.PAGE_ROWS - 1)).take(DevicePages.PAGE_ROWS)) else page(bobs)
        }
        val mark = proxy.mark()
        assertEquals(Fetched.Refused(DevicePages.BAD_PAGE), ah.settings(ah.session(origin)!!).list(), "two current devices, even unbound")
        assertEquals(Fetched.Refused(DevicePages.BAD_PAGE), bound(ah).list())
        assertEquals(4, sent(ah, WireRoute.DEVICES, mark).size)
        proxy.honest()
        proxy.on(WireRoute.DEVICES, "alice") { _ -> page(bobs) }
        assertEquals(Fetched.Refused(DevicePages.BAD_PAGE), bound(ah).list(), "Bob's whole list as Alice's")

        // The operator's view: a second page of Bob's devices as the operator sees them (no current mark) is taken.
        proxy.honest()
        assertIs<Fetched.Ok<List<Device>>>(oh.operator(oh.session(origin)!!).accountDevices(account(bh).userId))
        val bobAsOperatorSees = served(proxy.last(WireRoute.ADMIN_ACCOUNT_DEVICES, "op")!!.served!!)
        proxy.on(WireRoute.ADMIN_ACCOUNT_DEVICES, "op") { x ->
            if (x.req.queryParam("after") == null) page((served(x.forward()) + filler(DevicePages.PAGE_ROWS - 1)).take(DevicePages.PAGE_ROWS)) else page(bobAsOperatorSees)
        }
        val op = assertIs<Fetched.Ok<List<Device>>>(oh.operator(oh.session(origin)!!).accountDevices(alice.userId)).value
        assertTrue(op.containsAll(bobAsOperatorSees), "the limit, stated: the operator's view cannot tell another account's page")
    }

    /**
     * The host's own reader (`Host.settings`). FINDING D1, fixed: it passes the session's device id as `thisDevice`, so
     * Bob's whole list (which marks Bob's device `current`, never Alice's) is `bad_page`. It fails again if `Host.settings`
     * stops passing `thisDevice`, or if `DevicePages` stops requiring the whole list to mark exactly that device current.
     */
    @Test fun theHostsOwnDevicesReaderRefusesAnotherAccountsWholeList() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val bobs = bobsOwnList(bh)
        // The right reason: the same reader takes Alice's own list, which marks her device current.
        val own = assertIs<Fetched.Ok<List<Device>>>(ah.settings(ah.session(origin)!!).list(), "Alice's own list is read").value
        assertEquals(listOf(ah.session(origin)!!.session.deviceId), own.filter { it.current }.map { it.deviceId })
        proxy.on(WireRoute.DEVICES, "alice") { _ -> page(bobs) }
        assertEquals(Fetched.Refused(DevicePages.BAD_PAGE), ah.settings(ah.session(origin)!!).list())
    }
}
