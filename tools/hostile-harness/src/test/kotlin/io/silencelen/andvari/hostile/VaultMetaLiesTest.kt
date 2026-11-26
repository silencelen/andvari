package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.e2e.connect
import io.silencelen.andvari.cli.e2e.ok
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.items.ItemResult
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.Handler
import io.silencelen.andvari.hostile.proxy.Resp
import io.silencelen.andvari.hostile.proxy.answer
import io.silencelen.andvari.hostile.proxy.refuse
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A shared vault's rename (`PUT /vaults/{id}/meta`, spec 03 §11.3; the last row, the most dangerous left): the name is
 * sealed under the vault's key, so the server can only store it or not, and answer truthfully or not. The property: the
 * name every member is shown is the one the server holds and the vault's key opens, never one an answer claims; a lie
 * about the answer takes nothing from the device (no revision is kept from it), and a `stale_meta` answered to every
 * attempt is bounded (one sync and one retry) and refused.
 */
class VaultMetaLiesTest {
    @Test fun aRenameAnswerThatLiesNeverShowsANameTheServerDoesNotHold() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        connect(ah, bh, origin)
        val a = account(ah)
        val b = account(bh)
        a.synced()
        val v = a.ok(null, LogAction.Create("Family"))
        a.ok(v, LogAction.Add(b.userId, "writer"))
        io.silencelen.andvari.cli.e2e.accept(b, v, "Family")
        a.synced()
        b.synced()
        suspend fun rename(name: String) = a.items.renameVault(v, name)
        suspend fun bothSee(name: String, what: String) {
            a.synced()
            b.synced()
            assertEquals(name, a.vaultName(v), "$what: Alice")
            assertEquals(name, b.vaultName(v), "$what: Bob")
        }

        // An honest rename first, for its answer.
        rename("Family 1").let { assertIs<ItemResult.Ok<Unit>>(it, "$it") }
        val earlier = Json.parseToJsonElement(assertNotNull(proxy.last(WireRoute.VAULT_META, "alice")?.upstream).text)
        bothSee("Family 1", "honest")

        // Stored, then answered with a lie (W, R): the new name, everywhere, after the next sync.
        val stored: List<Pair<String, Handler>> = listOf(
            "a revision far below (W)" to Handler { x -> x.forward(); Resp.json(200, Json.parseToJsonElement("""{"rev":1}""")) },
            "a revision far above (W)" to Handler { x -> x.forward(); Resp.json(200, Json.parseToJsonElement("""{"rev":${Long.MAX_VALUE / 2}}""")) },
            "a negative revision (W)" to Handler { x -> x.forward(); Resp.json(200, Json.parseToJsonElement("""{"rev":-5}""")) },
            "an earlier rename's answer (R)" to Handler { x -> x.forward(); Resp.json(200, earlier) },
        )
        for ((i, pair) in stored.withIndex()) {
            val (what, lie) = pair
            val rule = proxy.on(WireRoute.VAULT_META, "alice", handler = lie)
            val got = rename("Family ${i + 2}")
            rule.remove()
            assertIs<ItemResult.Ok<Unit>>(got, what)
            bothSee("Family ${i + 2}", what)
        }
        val held = "Family ${stored.size + 1}"

        // Not stored, answered with a shape or status the route never gives (X): a failure, and the name the server
        // holds stays the one shown.
        val notStored: List<Pair<String, Handler>> = listOf(
            "ok (X)" to answer { Resp.ok() },
            "{} (X)" to answer { Resp.json(200, Json.parseToJsonElement("{}")) },
            "a 500 (X)" to refuse(500, "internal"),
        )
        for ((what, lie) in notStored) {
            val rule = proxy.on(WireRoute.VAULT_META, "alice", handler = lie)
            val got = rename("never stored")
            rule.remove()
            assertIs<ItemResult.Failed>(got, what)
            bothSee(held, what)
        }

        // Not stored and answered as done (W): reported done (the device cannot tell at once); the next sync shows the
        // name the server holds, on both devices. Nothing says that the rename did not happen: the stated limit.
        val done = proxy.on(WireRoute.VAULT_META, "alice", handler = answer { Resp.json(200, Json.parseToJsonElement("""{"rev":424242}""")) })
        assertIs<ItemResult.Ok<Unit>>(rename("claimed only"))
        done.remove()
        bothSee(held, "done, never stored")

        // `stale_meta` to every attempt: one sync, one retry, then a refusal; nothing else is sent.
        val stale = proxy.on(WireRoute.VAULT_META, "alice", handler = refuse(409, WireErrors.STALE_META))
        val mark = proxy.mark()
        val got = rename("contended")
        stale.remove()
        assertIs<ItemResult.Failed>(got)
        assertEquals(2, sent(ah, WireRoute.VAULT_META, mark).size, "bounded: the first attempt and one retry")
        bothSee(held, "stale_meta to every attempt")

        // The next honest rename lands.
        assertIs<ItemResult.Ok<Unit>>(rename("Family at last"))
        bothSee("Family at last", "honest again")
        assertTrue(sent(bh, WireRoute.VAULT_META).isEmpty(), "Bob sent no rename")
    }
}
