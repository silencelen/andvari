package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.e2e.doc
import io.silencelen.andvari.cli.e2e.ok
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.devicelink.ExistingStep
import io.silencelen.andvari.core.client.devicelink.NewStep
import io.silencelen.andvari.core.client.devicelink.WireDeviceLinks
import io.silencelen.andvari.core.client.items.ItemResult
import io.silencelen.andvari.core.client.link.CreateOutcome
import io.silencelen.andvari.core.client.link.RecipientStep
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.Handler
import io.silencelen.andvari.hostile.proxy.Resp
import io.silencelen.andvari.hostile.proxy.arr
import io.silencelen.andvari.hostile.proxy.editAnswer
import io.silencelen.andvari.hostile.proxy.fullSyncPage
import io.silencelen.andvari.hostile.proxy.set
import io.silencelen.andvari.hostile.proxy.str
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The answers of the last row that a lie could cost the person most, most dangerous first: the create answers of a
 * device link and of a link (`POST /device-links`, `POST /links`), the vault grant's self-wrap
 * (`PUT /vaults/{id}/grant/self-wrap`) and an item's versions (`GET /items/{id}/versions`). Each lie replaces the answer
 * after the real server acted on the request: a field changed (W), another account's answer (A), an earlier answer of
 * the same account (R), or a shape the route never gives (X).
 */
class CreateAnswerLiesTest {
    private val hour = 3_600_000L

    /** Answers the real server's answer with [lie] applied, a refusal passing through as it is. */
    private fun lying(lie: (Resp) -> Resp) = Handler { x -> x.forward().let { if (it.ok) lie(it) else it } }

    private fun ttl(v: Long): (Resp) -> Resp = { r -> r.withJson { it.set("ttlMs", v) } }

    private fun whole(body: JsonObject): (Resp) -> Resp = { Resp.json(200, body) }

    private fun World.lastAnswer(route: WireRoute, tag: String): JsonObject = assertNotNull(proxy.last(route, tag)?.upstream?.json, "$tag's real $route answer")

    /**
     * `POST /device-links` (row 59), after the server created the link: its `ttlMs` at -1, at the top of a `Long` or ten
     * days, Bob's answer (A), Alice's earlier one (R). Whatever it says, the link shown is the device's own (the link id
     * of its own request) and a new device of Alice's uses it to the code step: nothing in the answer chooses the link.
     * `{}` and `ok` (X) show no link. The countdown is the next test.
     */
    @Test fun aDeviceLinkCreateAnswerThatLiesNeverChangesWhichLinkIsShown() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        assertIs<ExistingStep.Shown>(bh.deviceLinks.create())
        val bobs = lastAnswer(WireRoute.DEVICE_LINK_CREATE, "bob")
        assertIs<ExistingStep.Shown>(ah.deviceLinks.create())
        val earlier = lastAnswer(WireRoute.DEVICE_LINK_CREATE, "alice")

        val lies: List<Pair<String, (Resp) -> Resp>> = listOf(
            "ttlMs -1 (W)" to ttl(-1), "ttlMs at the top of a Long (W)" to ttl(Long.MAX_VALUE), "ttlMs of ten days (W)" to ttl(240 * hour),
            "Bob's answer (A)" to whole(bobs), "Alice's earlier answer (R)" to whole(earlier),
        )
        for ((i, pair) in lies.withIndex()) {
            val (what, lie) = pair
            val rule = proxy.on(WireRoute.DEVICE_LINK_CREATE, "alice", handler = lying(lie))
            val shown = assertIs<ExistingStep.Shown>(ah.deviceLinks.create(), what)
            rule.remove()
            val asked = assertNotNull(proxy.last(WireRoute.DEVICE_LINK_CREATE, "alice")!!.req.json).let { (it["linkId"] as JsonPrimitive).content }
            // A new device of Alice's opens the shown link: it reaches the link this device asked for and claims it.
            val nh = device("new$i")
            var n = nh.deviceLinks.start(shown.url, GateEntry.LINK_DEVICE_SCREEN)
            if (n is NewStep.TrustGate) n = nh.deviceLinks.afterTrustGate(n, confirmed = true)
            assertIs<NewStep.Claimed>(n, "$what: the shown link is the one the device made: $n")
            assertTrue(proxy.requests(WireRoute.DEVICE_LINK_CLAIM, "new$i").all { it.path.contains(asked) }, "$what: the claim went to the device's own link")
            // The next create replaces this link, on the server and on the device.
            assertIs<ExistingStep.ClaimFixed>(ah.deviceLinks.advance(shown), "$what: and the device that made it sees the claim")
        }
        for ((what, lie) in listOf("an empty object (X)" to Resp.json(200, JsonObject(emptyMap())), "a plain ok (X)" to Resp.ok())) {
            val rule = proxy.on(WireRoute.DEVICE_LINK_CREATE, "alice", handler = lying { lie })
            assertTrue(ah.deviceLinks.create() !is ExistingStep.Shown, "$what: no link is shown")
            rule.remove()
        }
    }

    /**
     * Finding L1 (fixed): the served `ttlMs` of a create answer was taken as it is, so a server's `-1` showed a live link
     * as run out (and the app stopped polling it), and `Long.MAX_VALUE` a link that never runs out (in `EngineDevices`,
     * `nowMono() + ttlMs` then wrapped to a deadline in the past). The property: the countdown the device shows is never
     * below 0 nor longer than the lifetime the device asked for (5 minutes for a device link; the chosen lifetime for a
     * link). `WireDeviceLinks.create` and `WireLinkFlows.create` now bound it; the server's clock still counts (spec 03
     * §15.2: the device counts down from `ttlMs`, never its own clock against `expiresAt`).
     */
    @Test fun aCreateAnswersCountdownIsNeverNegativeNorLongerThanAsked() = world {
        operator()
        val ah = member("alice")
        for (v in listOf(-1L, Long.MAX_VALUE, 240 * hour)) {
            val rule = proxy.on(WireRoute.DEVICE_LINK_CREATE, "alice", handler = lying(ttl(v)))
            val shown = assertIs<ExistingStep.Shown>(ah.deviceLinks.create())
            rule.remove()
            assertTrue(shown.ttlMs in 0..WireDeviceLinks.LIFETIME_MS, "device link, ttlMs $v: shown ${shown.ttlMs}")

            val links = proxy.on(WireRoute.LINK_CREATE, "alice", handler = lying(ttl(v)))
            val made = assertIs<CreateOutcome.Created>(ah.links.create("connect", hour, emptyList())).link
            links.remove()
            assertTrue(made.ttlMs != null && made.ttlMs!! in 0..hour, "link, ttlMs $v: shown ${made.ttlMs}")
            ah.links.revoke(made.linkId)
        }
    }

    /**
     * `POST /links` (row 52), after the server stored the link: its `ttlMs` changed (W), Bob's answer (A), Alice's earlier
     * one (R): the link is created and its URL is the device's own; Bob opens it and is shown Alice's offer. `{}` and `ok`
     * (X) never make a link that leads elsewhere: whatever the device keeps is its own URL.
     */
    @Test fun aLinkCreateAnswerThatLiesNeverChangesWhichLinkIsShared() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val ch = member("carol")
        assertIs<CreateOutcome.Created>(bh.links.create("connect", hour, emptyList()))
        val bobs = lastAnswer(WireRoute.LINK_CREATE, "bob")
        assertIs<CreateOutcome.Created>(ah.links.create("connect", hour, emptyList()))
        val earlier = lastAnswer(WireRoute.LINK_CREATE, "alice")
        val alice = account(ah).userId

        val lies: List<Pair<String, Handler>> = listOf(
            "ttlMs -1 (W)" to lying(ttl(-1)), "Bob's answer (A)" to lying(whole(bobs)), "Alice's earlier answer (R)" to lying(whole(earlier)),
            "an empty object (X)" to lying { Resp.json(200, JsonObject(emptyMap())) }, "a plain ok (X)" to lying { Resp.ok() },
        )
        for ((what, lie) in lies) {
            val rule = proxy.on(WireRoute.LINK_CREATE, "alice", handler = lie)
            val out = ah.links.create("connect", hour, emptyList())
            rule.remove()
            val asked = (assertNotNull(proxy.last(WireRoute.LINK_CREATE, "alice")!!.req.json)["linkId"] as JsonPrimitive).content
            val url = when (out) {
                is CreateOutcome.Created -> out.link.also { assertEquals(asked, it.linkId, what) }.url
                is CreateOutcome.Unknown -> out.link.also { assertEquals(asked, it.linkId, what) }.url
                is CreateOutcome.Refused -> null
            }
            if (url == null) continue
            val confirm = assertIs<RecipientStep.Confirm>(ch.links.open(url, GateEntry.PASTE_INVITE), "$what: Carol opens the link")
            assertEquals(alice, confirm.offer.creatorUserId, "$what: it is Alice's own link")
            ah.links.revoke(asked)
        }
    }

    /**
     * `PUT /vaults/{id}/grant/self-wrap` (row 51), after the server stored Bob's self-wrap: its answer replaced by another
     * vault's rev or Bob's earlier answer (A, R), `{}`, `ok`, a `500`, or no answer at all (X). The answer decides
     * nothing: Bob's device reads the vault it accepted and Alice's writes in it, and the server holds on Bob's grant
     * exactly the self-wrap he posted (what his other devices adopt through).
     */
    @Test fun aSelfWrapAnswerThatLiesDecidesNothing() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        io.silencelen.andvari.cli.e2e.connect(ah, bh, origin)
        val a = account(ah)
        val b = account(bh)
        a.synced()
        val lies: List<Pair<String, Handler>> = listOf(
            "a rev a million ahead (W)" to editAnswer { it.set("rev", 1_000_000L) },
            "a rev of -1 (W)" to editAnswer { it.set("rev", -1L) },
            "an empty object (X)" to lying { Resp.json(200, JsonObject(emptyMap())) },
            "a plain ok (X)" to lying { Resp.ok() },
            "a 500 after the server stored it (X)" to lying { Resp.error(500, "internal") },
        )
        for ((i, pair) in lies.withIndex()) {
            val (what, lie) = pair
            val name = "Family $i"
            val v = a.ok(null, LogAction.Create(name))
            a.ok(v, LogAction.Add(b.userId, "writer"))
            val rule = proxy.on(WireRoute.VAULT_SELF_WRAP, "bob", handler = lie)
            io.silencelen.andvari.cli.e2e.accept(b, v, name)
            rule.remove()
            assertTrue(proxy.requests(WireRoute.VAULT_SELF_WRAP, "bob").any { it.path.contains(v) }, "$what: the self-wrap was posted")
            assertEquals(null, a.putItem(v, doc("from Alice $i")).second, "$what: Alice writes")
            a.synced()
            b.synced()
            assertTrue(b.items.items().any { it.vaultId == v && it.doc.name == "from Alice $i" }, "$what: Bob reads the vault")
        }
        // The server holds, on Bob's grant of each vault, exactly the self-wrap Bob posted: what his other devices adopt
        // through (design §3.6), whatever the answer to the post said.
        var full: JsonObject? = null
        val look = proxy.on(WireRoute.SYNC, "bob", times = 1, handler = Handler { x -> full = x.fullSyncPage(); x.forward() })
        b.synced()
        look.remove()
        val grants = assertNotNull(full?.arr("grants")).map { it as JsonObject }
        val vaults = b.items.vaults().map { it.vaultId }.filter { it != b.personalVaultId }
        assertEquals(lies.size, vaults.size)
        for (v in vaults) {
            val posted = proxy.requests(WireRoute.VAULT_SELF_WRAP, "bob").last { it.param("vaultId") == v }.json!!.str("wrappedVk")
            val stored = grants.single { it.str("vaultId") == v && it.str("userId") == b.userId }.str("wrappedVk")
            assertEquals(posted, stored, "vault $v: the stored self-wrap is the one Bob posted")
        }
    }

    /**
     * `GET /items/{id}/versions` (row 38): Alice's item's history answered with the versions of another of her items (W),
     * Bob's item's versions (A), its own earlier answer (R), `{}` and `ok` (X). Every version shown opens under this vault's
     * key as this item (the envelope's AD binds the item and its vault), so another item's or account's version is never
     * shown and never restored; an earlier answer shows fewer versions (the stated limit: the device cannot tell how many
     * there were); a shape the route never gives is a failure, never "no history".
     */
    @Test fun anItemsVersionsAnswerOfAnotherItemOrAccountShowsNothingOfIt() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val a = account(ah)
        val b = account(bh)
        a.synced()
        b.synced()
        suspend fun edited(s: io.silencelen.andvari.cli.AccountSession, name: String, times: Int): String {
            val v = s.personalVaultId!!
            val id = assertNotNull(s.putItem(v, doc("$name 0")).first).itemId
            for (n in 1..times) {
                s.synced()
                assertEquals(null, s.putItem(v, doc("$name $n"), id).second)
            }
            s.synced()
            return id
        }
        val mine = edited(a, "mine", 2)
        val other = edited(a, "other", 3)
        val bobs = edited(b, "bob's", 2)
        val v = a.personalVaultId!!
        fun names(r: ItemResult<List<io.silencelen.andvari.core.client.DecryptedItemVersion>>) =
            assertIs<ItemResult.Ok<List<io.silencelen.andvari.core.client.DecryptedItemVersion>>>(r).value.map { it.doc.name }
        val honest = names(a.items.itemVersions(mine, v))
        assertEquals(listOf("mine 1", "mine 0"), honest.sortedDescending(), "the honest history")
        assertIs<ItemResult.Ok<*>>(a.items.itemVersions(other, v))
        val others: JsonElement = lastAnswer(WireRoute.ITEM_VERSIONS, "alice")
        assertIs<ItemResult.Ok<*>>(b.items.itemVersions(bobs, b.personalVaultId!!))
        val bobsAnswer: JsonElement = lastAnswer(WireRoute.ITEM_VERSIONS, "bob")
        a.items.itemVersions(mine, v)
        val earlierAnswer = lastAnswer(WireRoute.ITEM_VERSIONS, "alice")
        assertEquals(null, a.putItem(v, doc("mine 3"), mine).second)
        a.synced()

        for ((what, body) in listOf("another item's versions (W)" to others, "Bob's item's versions (A)" to bobsAnswer)) {
            val rule = proxy.on(WireRoute.ITEM_VERSIONS, "alice", handler = lying { Resp.json(200, body) })
            assertEquals(emptyList(), names(a.items.itemVersions(mine, v)), "$what: none of it is shown")
            rule.remove()
        }
        val replay = proxy.on(WireRoute.ITEM_VERSIONS, "alice", handler = lying { Resp.json(200, earlierAnswer) })
        assertEquals(honest.toSet(), names(a.items.itemVersions(mine, v)).toSet(), "the earlier answer: this item's own, fewer (the stated limit)")
        replay.remove()
        for ((what, lie) in listOf("an empty object (X)" to Resp.json(200, JsonObject(emptyMap())), "a plain ok (X)" to Resp.ok())) {
            val rule = proxy.on(WireRoute.ITEM_VERSIONS, "alice", handler = lying { lie })
            assertIs<ItemResult.Failed>(a.items.itemVersions(mine, v), "$what: a failure, never no history")
            rule.remove()
        }
        assertEquals(3, names(a.items.itemVersions(mine, v)).size, "the honest history after")
    }
}
