package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.CsvImport
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.account.Fetched
import io.silencelen.andvari.core.client.items.ItemResult
import io.silencelen.andvari.core.client.items.QuotaRoom
import io.silencelen.andvari.core.model.wire.AccountSummary
import io.silencelen.andvari.core.model.wire.MutationStatus
import io.silencelen.andvari.core.model.wire.QuotaName
import io.silencelen.andvari.core.model.wire.QuotaUse
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.arr
import io.silencelen.andvari.hostile.proxy.editAnswer
import io.silencelen.andvari.hostile.proxy.obj
import io.silencelen.andvari.hostile.proxy.set
import io.silencelen.andvari.hostile.proxy.str
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The account's own use and limits (spec 03 §14.4, "What an account is told"): `quota` on every `GET /sync` answer and
 * on each row of `GET /admin/accounts`, lied to. The meters only ever let an app refuse early: whatever a server puts
 * there, the device writes nothing the honest server would refuse (the server's own check stays the authority), the
 * sync and the operator's list never fail over it, and a negative or absurd number is "unknown", never room.
 *
 * The device is the command-line tool's engine doing what every app does before a large copy: a fresh sync and the
 * shared check (`ItemEngine.roomFor`, `QuotaCheck`); short, and nothing starts; room or unknown, and the import goes to
 * the server, which decides.
 */
class QuotaLiesTest {
    /** The honest server's item limit for every account in these worlds. */
    private val limit = 5

    private fun quotaWorld(block: suspend World.() -> Unit) = world(extraEnv = mapOf("ANDVARI_QUOTA_ITEMS" to "$limit"), block = block)

    private fun meters(bytes: String, items: String, vaults: String, links: String): JsonElement = Json.parseToJsonElement(
        """{"accountBytes":$bytes,"items":$items,"ownedSharedVaults":$vaults,"openLinks":$links}""",
    )

    private fun m(used: String, limit: String) = """{"used":$used,"limit":$limit}"""

    private fun all(meter: String) = meters(meter, meter, meter, meter)

    private val top = Long.MAX_VALUE.toString()

    private fun plan(n: Int) = List(n) {
        CsvImport.PlannedItem(UUID.randomUUID().toString(), ItemDoc(type = "login", name = "imported $it", login = LoginData(username = "u$it", password = "p$it")))
    }

    /** What the server took and refused of [tag]'s pushes since [mark]: (applied, the refusals' reasons). */
    private fun World.pushed(tag: String, mark: Int): Pair<Int, List<String?>> {
        val results = proxy.since(mark).filter { it.req.route == WireRoute.PUSH && it.req.tag == tag }
            .flatMap { x -> x.upstream?.json?.arr("results")?.map { it.jsonObject } ?: emptyList() }
        return results.count { it.str("status") == MutationStatus.APPLIED } to
            results.filter { it.str("status") != MutationStatus.APPLIED }.map { it.str("reason") ?: it.str("status") }
    }

    /**
     * The app's import of [n] items into [h]'s personal vault: the check first, then (unless short) the import. Answers
     * the check's answer and the import's result (null when nothing started). Neither may throw.
     */
    private suspend fun World.importIfRoom(h: Host, n: Int): Pair<QuotaRoom, ItemResult<Unit>?> {
        val a = account(h)
        val items = plan(n)
        val room = assertIs<ItemResult.Ok<QuotaRoom>>(a.items.roomFor(a.items.importSize(items)), "the sync and the check answer").value
        if (room is QuotaRoom.Short) return room to null
        return room to a.items.importAll(items, vaultId = a.personalVaultId)
    }

    /**
     * Lies in `quota` on Alice's every `/sync` answer, the honest limit 5 items: limits of zero, a use larger than any
     * limit, use and limit both at the top of a `Long` (the sum must not wrap round to room), negative numbers, numbers
     * past a `Long` and not numbers at all, a limit at the top with nothing used, and the object of another account (Bob's).
     * In each: the sync succeeds and Alice's items stay as they were; a short answer sends nothing; an unknown or roomy one
     * lets the import reach the server, which takes exactly what fits and refuses the rest `quota_exceeded`. The server
     * ends holding the honest limit and not one item more; the device then shows exactly that.
     */
    @Test fun aServerThatLiesInTheMetersOnlyMakesTheDeviceRefuseEarlyOrMeetTheServersRefusal() = quotaWorld {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val a = account(ah)
        account(bh).synced()
        a.synced()
        val personal = assertNotNull(a.personalVaultId)
        fun shown() = a.items.items().count { it.vaultId == personal }
        val start = shown()
        assertEquals(0, start, "a new account holds no items")
        // Bob's own object as his server served it; a server without the field yet gets Bob's numbers written out.
        val bobs: JsonElement = proxy.last(WireRoute.SYNC, "bob")?.upstream?.json?.obj("quota")
            ?: meters(m("0", "104857600"), m("0", "$limit"), m("0", "50"), m("0", "20"))

        val honestBytes = m("0", "104857600")
        class Lie(val what: String, val quota: JsonElement, val expect: (QuotaRoom) -> Boolean)

        fun decoded(e: JsonElement): QuotaUse? = WireJson.json.decodeFromJsonElement(io.silencelen.andvari.core.model.wire.QuotaUseOrUnknown, e)
        val lies = listOf(
            Lie("limits of zero", all(m("0", "0"))) { it is QuotaRoom.Short && it.limits.map { s -> s.quota } == listOf(QuotaName.ACCOUNT_BYTES, QuotaName.ITEMS) },
            Lie("a use larger than any limit", meters(m(top, "104857600"), m(top, "$limit"), m(top, "50"), m(top, "20"))) { it is QuotaRoom.Short },
            Lie("use and limit at the top of a Long", all(m(top, top))) { it is QuotaRoom.Short && it.limits.all { s -> s.by > 0 } },
            Lie("negative numbers", meters(m("-1", "104857600"), m("-100", "$limit"), m("0", "-1"), m("0", "20"))) { it == QuotaRoom.Unknown },
            Lie("numbers past a Long, a fraction and a word", meters(m("9223372036854775808", "1e40"), m("1.5", "$limit"), m("0", "\"lots\""), m("0", "20"))) { it == QuotaRoom.Unknown },
            Lie("a limit at the top of a Long with nothing used", meters(honestBytes, m("0", top), m("0", "50"), m("0", "20"))) { it == QuotaRoom.Room },
            Lie("the object of another account (Bob's)", bobs) { it == QuotaRoom.Room },
        )
        var applied = 0
        for (lie in lies) {
            val rule = proxy.on(WireRoute.SYNC, "alice", handler = editAnswer { it.set("quota", lie.quota) })
            val mark = proxy.mark()
            val before = shown()
            val (room, imported) = importIfRoom(ah, 3)
            assertTrue(lie.expect(room), "${lie.what}: the check answered $room")
            assertTrue(proxy.since(mark).any { it.req.route == WireRoute.SYNC && it.req.tag == "alice" && it.rule != null }, "${lie.what}: the lie reached the device")
            assertEquals(decoded(lie.quota), a.items.quota(), "${lie.what}: what the device holds is what it was served, or unknown (null)")
            if (room == QuotaRoom.Unknown) assertNull(a.items.quota(), lie.what)
            val (took, refused) = pushed("alice", mark)
            if (room is QuotaRoom.Short) {
                assertNull(imported, lie.what)
                assertTrue(proxy.since(mark).none { it.req.route == WireRoute.PUSH }, "${lie.what}: short, so nothing was sent")
                assertEquals(before, shown(), "${lie.what}: the sync still applied; nothing was lost")
            } else {
                assertNotNull(imported, "${lie.what}: the import reached the server, which decides")
                assertTrue(refused.all { it == WireErrors.QUOTA_EXCEEDED }, "${lie.what}: every refusal is the server's own quota check: $refused")
                assertEquals(minOf(3, limit - applied), took, "${lie.what}: the server took what fits")
                applied += took
            }
            assertTrue(applied <= limit, "${lie.what}: the server holds at most its limit")
            rule.remove()
        }
        assertEquals(limit, applied, "the lies that let the import through filled the account exactly")

        // The honest answer: the device shows what the server holds, the limit and not one more.
        a.synced()
        assertEquals(limit, shown())
        val honest = a.items.quota()
        if (honest != null) {
            assertEquals(limit.toLong(), honest.items.used)
            assertEquals(QuotaName.ITEMS, assertIs<QuotaRoom.Short>(assertIs<ItemResult.Ok<QuotaRoom>>(a.items.roomFor(a.items.importSize(plan(1)))).value).first.quota)
        }
    }

    /**
     * The operator's accounts list (`GET /admin/accounts`, row 73): each row's `quota` replaced by negative numbers,
     * numbers past a `Long`, something that is not an object, or another account's (Bob's in Alice's row). The list is
     * read every time with every other field as served; what cannot be meters is unknown (null); another account's object
     * is shown in that row (a row's `quota` names no account, as its `usedBytes` does not: the stated limit; it decides
     * nothing, the server's check does). Nothing is sent but the read.
     */
    @Test fun anAccountsListWhoseMetersLieStillReadsAndAnAbsurdMeterIsUnknown() = quotaWorld {
        val oh = operator()
        val ah = member("alice")
        member("bob")
        val alice = account(ah).userId
        val ops = oh.operator(oh.session(origin)!!)
        val honest = assertIs<Fetched.Ok<List<AccountSummary>>>(ops.accounts(), "the honest list").value
        val alicesRow = honest.single { it.userId == alice }
        val bobsQuota = honest.single { it.userId != alice && it.email.startsWith("bob") }.quota

        val bobsObject = Json.parseToJsonElement(WireJson.json.encodeToString(QuotaUse.serializer(), bobsQuota ?: QuotaUse(
            io.silencelen.andvari.core.model.wire.QuotaMeter(0, 1), io.silencelen.andvari.core.model.wire.QuotaMeter(0, 1),
            io.silencelen.andvari.core.model.wire.QuotaMeter(0, 1), io.silencelen.andvari.core.model.wire.QuotaMeter(0, 1),
        )))
        val lies: List<Triple<String, JsonElement, QuotaUse?>> = listOf(
            Triple("negative numbers", all(m("-1", "-1")), null),
            Triple("numbers past a Long", all(m("9223372036854775808", top)), null),
            Triple("not an object", Json.parseToJsonElement("[1,2]"), null),
            Triple("Bob's object in Alice's row", bobsObject, WireJson.json.decodeFromJsonElement(QuotaUse.serializer(), bobsObject)),
        )
        for ((what, quota, shownAs) in lies) {
            val rule = proxy.on(WireRoute.ADMIN_ACCOUNTS, "op", handler = io.silencelen.andvari.hostile.proxy.Handler { x ->
                x.forward().let { r ->
                    if (!r.ok) r
                    else io.silencelen.andvari.hostile.proxy.Resp.json(200, JsonArray((Json.parseToJsonElement(r.text) as JsonArray).map { row ->
                        val o = row.jsonObject
                        if (o.str("userId") == alice) o.set("quota", quota) else o
                    }))
                }
            })
            val mark = proxy.mark()
            val list = assertIs<Fetched.Ok<List<AccountSummary>>>(ops.accounts(), "$what: the list reads").value
            val row = list.single { it.userId == alice }
            assertEquals(shownAs, row.quota, what)
            assertEquals(alicesRow.copy(quota = shownAs), row, "$what: every other field as served")
            assertEquals(honest.size, list.size, what)
            assertTrue(proxy.since(mark).any { it.req.route == WireRoute.ADMIN_ACCOUNTS && it.rule != null }, "$what: the lie reached the device")
            assertTrue(proxy.since(mark).all { it.req.method == "GET" }, "$what: nothing but reads was sent")
            rule.remove()
        }
    }
}
