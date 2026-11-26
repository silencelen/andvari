package io.silencelen.andvari.core.client.account

import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.model.wire.Device
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.TrustGrammar
import kotlinx.serialization.builtins.ListSerializer

/**
 * The devices list read whole, page by page (spec 03 §16.7, index rows 26 and 77): `GET /account/devices` and the
 * operator's `GET /admin/accounts/{userId}/devices` answer at most [PAGE_ROWS] rows in `(createdAt, deviceId)` order, and
 * take `?after=<deviceId>`, the last row of the page before. A page shorter than [PAGE_ROWS] is the last one.
 *
 * **What the reader holds to**, so a lying server costs a bounded read and never a wrong list:
 * - the whole list is answered only once the last page arrived; a refusal or no answer on ANY page fails the whole
 *   read (a 4xx is [Fetched.Refused] with its code, a 5xx or no answer [Fetched.Unreachable]);
 * - a page of more than [PAGE_ROWS] rows breaks the server's own rule: [BAD_PAGE];
 * - the cursor is the last row's `deviceId`, sent only when it is a uuid ([BAD_PAGE] otherwise);
 * - a `deviceId` seen before, on this page or an earlier one, is a cursor that loops or a page served twice: [BAD_PAGE];
 * - two rows marked `current` mean pages of two sessions' views were mixed (another account's page, or another
 *   device's): [BAD_PAGE]. With `thisDevice` (the account's own view, given the session's device id) the whole list must
 *   hold exactly one `current` row and it must be this device: another account's whole list, which marks ITS device,
 *   is [BAD_PAGE] too. (A page of another account in the operator's view carries no such mark; nothing on a row names
 *   its account, so that lie can only be told by the loop and page rules above.)
 * - at most [MAX_PAGES] pages ([MAX_PAGES] × [PAGE_ROWS] devices) are asked for: a page that never ends stops there
 *   with [TOO_MANY_PAGES].
 */
object DevicePages {
    /** The server's page size (spec 03 §16.7). */
    const val PAGE_ROWS = 500

    /** The most pages one read asks for: 20,000 devices, about 22 MB of rows at the server's worst-case row size. */
    const val MAX_PAGES = 40

    /** A page that breaks the paging rules (too many rows, a repeated device, a bad cursor, two current devices). */
    const val BAD_PAGE = "bad_page"

    /** The read stopped at [MAX_PAGES] pages with the server still saying "more". */
    const val TOO_MANY_PAGES = "too_many_pages"

    private val listOfDevices = ListSerializer(Device.serializer())

    internal suspend fun readAll(client: WireClient, route: WireRoute, pathParams: Map<String, String> = emptyMap(), thisDevice: String? = null): Fetched<List<Device>> {
        val all = ArrayList<Device>()
        val seen = HashSet<String>()
        var current = 0
        var after: String? = null
        repeat(MAX_PAGES) {
            val query = after?.let { "after=$it" }
            val page = when (val r = client.call(route, pathParams = pathParams, query = query, decode = { WireJson.json.decodeFromString(listOfDevices, it) })) {
                is WireResult.Ok -> r.value
                is WireResult.Refused -> return if (r.status >= 500) Fetched.Unreachable else Fetched.Refused(r.code)
                is WireResult.NoAnswer -> return Fetched.Unreachable
            }
            if (page.size > PAGE_ROWS) return Fetched.Refused(BAD_PAGE)
            for (d in page) {
                if (!seen.add(d.deviceId)) return Fetched.Refused(BAD_PAGE)
                if (d.current && ++current > 1) return Fetched.Refused(BAD_PAGE)
                if (d.current && thisDevice != null && d.deviceId != thisDevice) return Fetched.Refused(BAD_PAGE)
            }
            all += page
            if (page.size < PAGE_ROWS) return if (thisDevice != null && current != 1) Fetched.Refused(BAD_PAGE) else Fetched.Ok(all)
            val last = page.last().deviceId
            if (!TrustGrammar.isUuid(last)) return Fetched.Refused(BAD_PAGE)
            after = last
        }
        return Fetched.Refused(TOO_MANY_PAGES)
    }
}
