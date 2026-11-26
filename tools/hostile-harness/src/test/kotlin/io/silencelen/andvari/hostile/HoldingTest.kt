package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.SyncOutcome
import io.silencelen.andvari.cli.e2e.doc
import io.silencelen.andvari.cli.e2e.ok
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.items.ItemEngine
import io.silencelen.andvari.core.client.items.ItemNotice
import io.silencelen.andvari.core.client.items.VaultStanding
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.log.VaultLogStatus
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.Resp
import io.silencelen.andvari.hostile.proxy.arr
import io.silencelen.andvari.hostile.proxy.editAnswer
import io.silencelen.andvari.hostile.proxy.editEach
import io.silencelen.andvari.hostile.proxy.serveVaultRows
import io.silencelen.andvari.hostile.proxy.set
import io.silencelen.andvari.hostile.proxy.str
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Ignore
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * A vault the server takes away, and the holding area (spec 02 §10.6, spec 03 §4 `removedGrants`, design §3.8 T2-R-h):
 * a server cannot make a device drop its copy, nor the edits it has not sent yet, by revoking a grant; and the time a
 * departed vault is held counts from when this device saw the departure, never from a time the server names.
 */
class HoldingTest {
    private fun names(s: io.silencelen.andvari.cli.AccountSession, v: String) = s.items(v).map { it.doc["name"]!!.jsonPrimitive.content }.toSet()

    /** [body] with [vaultId]'s vault and grant rows gone and the vault listed as taken away, `reason` [reason]. */
    private fun takenAway(body: JsonObject, vaultId: String, reason: String): JsonObject = body
        .set("vaults", JsonArray(body.arr("vaults")!!.filter { it.jsonObject.str("vaultId") != vaultId }))
        .set("grants", JsonArray(body.arr("grants")!!.filter { it.jsonObject.str("vaultId") != vaultId }))
        .set("removedGrants", JsonArray(body.arr("removedGrants")!!.filter { it.jsonPrimitive.content != vaultId } + JsonPrimitive(vaultId)))
        .set("removedGrantsInfo", JsonArray(body.arr("removedGrantsInfo")!!.filter { it.jsonObject.str("vaultId") != vaultId } +
            buildJsonObject { put("vaultId", JsonPrimitive(vaultId)); put("reason", JsonPrimitive(reason)) }))

    /**
     * Spec 03 §4 (amended 2026-11-15): queued mutations for a vault the server takes away "are held back, not
     * discarded. They are dropped only when the log verifies that this account left or was removed … and replayed if
     * the vault comes back." The server denies Bob's edit as if his grant were gone and lists the vault as removed,
     * while the log names no removal: the vault stays, read-only; the edit is kept; when the server serves the vault
     * again, the edit reaches it.
     */
    @Test fun anEditTheServerDeniesWhileTakingTheVaultAwayIsHeldBackAndSentWhenTheVaultComesBack() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val v = sharedVault(ah, bh)
        val a = account(ah)
        val b = account(bh)
        a.synced()
        assertEquals(null, a.putItem(v, doc("wifi")).second)
        b.synced()
        val wifi = b.items(v).single()

        val deny = proxy.on(WireRoute.PUSH, "bob", name = "deny every write") { x ->
            val rev = x.ask(WireRoute.SYNC, query = "since=0").json!!.getValue("rev")
            Resp.json(200, buildJsonObject {
                put("rev", rev)
                put("results", JsonArray(x.req.json!!.arr("mutations")!!.map { m ->
                    buildJsonObject { put("mutationId", m.jsonObject.getValue("mutationId")); put("status", JsonPrimitive("denied")) }
                }))
            })
        }
        val away = proxy.on(WireRoute.SYNC, "bob", name = "take $v away", handler = editAnswer { takenAway(it, v, "removed") })
        val saved = b.putItem(v, doc("wifi, edited offline"), wifi.itemId)
        val outcome = b.sync()
        assertIs<VaultLogStatus.Verified>(b.logs.status(v), "the log names no removal of Bob")
        assertEquals(VaultStanding.WITHHELD, b.vaultKeys.access(v)?.standing, "a loss the log does not explain leaves the vault read-only, not gone (save: $saved, sync: $outcome)")
        assertEquals(setOf("wifi"), names(b, v).filter { it == "wifi" }.toSet(), "the copy stays readable")
        assertFalse(b.items.notices().any { it.kind == ItemNotice.WRITE_REJECTED }, "the edit is not reported as refused")
        assertTrue(outcome !is SyncOutcome.Refused || outcome.code != "denied", "the edit is not dropped as a genuine denial: $outcome")

        // The server serves the vault again.
        deny.remove()
        away.remove()
        proxy.serveVaultRows("bob", v)
        val mark = proxy.mark()
        val back = b.sync()
        b.sync()
        val replayed = sent(bh, WireRoute.PUSH, mark).filter { r -> r.json!!.arr("mutations")!!.any { it.jsonObject.str("itemId") == wifi.itemId } }
        assertTrue(replayed.isNotEmpty(), "the held-back edit is sent once the vault is back (the sync answered $back; notices ${b.items.notices().map { it.kind }})")
        a.synced()
        assertEquals(setOf("wifi, edited offline"), names(a, v), "and the owner sees it")
    }

    /**
     * Spec 03 §4: "The 30 days count from when this device saw the departure, never from a time the server names."
     * The owner deletes the vault (a verified departure); the server tells Bob it will be purged in a minute. Bob's copy
     * goes to the holding area, readable, until 30 days after his device saw the delete, and then goes.
     */
    @Test fun aDepartedVaultIsHeldThirtyDaysFromWhenTheDeviceSawItWhateverPurgeTimeTheServerNames() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val v = sharedVault(ah, bh)
        val a = account(ah)
        val b = account(bh)
        a.synced()
        assertEquals(null, a.putItem(v, doc("wifi")).second)
        b.synced()
        proxy.on(WireRoute.SYNC, "bob", handler = editAnswer { body ->
            body.editEach("removedGrantsInfo") { i ->
                if (i.str("vaultId") == v) i.set("purgeAt", server.now() + 60_000L).set("deletedAt", server.now() - 29L * DAY) else i
            }
        })
        a.ok(v, LogAction.Delete)
        val seen = server.now()
        b.synced()
        val held = b.items.heldVaults().single { it.vaultId == v }
        assertEquals("deleted", held.reason)
        assertEquals(seen + ItemEngine.HOLDING_MS, held.expungeAt, "held for 30 days from when this device saw the delete")
        assertTrue(held.readable)
        assertEquals(listOf("wifi"), b.items.heldItems(v).map { it.doc.name })

        server.advance(2 * DAY)
        b.synced()
        assertEquals(listOf("wifi"), b.items.heldItems(v).map { it.doc.name }, "the server's purge time has passed; the copy has not")
        server.advance(ItemEngine.HOLDING_MS - 2 * DAY - 60_000L)
        b.synced()
        assertTrue(b.items.heldVaults().any { it.vaultId == v }, "a minute before the 30 days end it is still held")
        server.advance(2 * 60_000L)
        b.synced()
        assertTrue(b.items.heldVaults().none { it.vaultId == v }, "30 days after the device saw the delete, it goes")
    }

    private companion object {
        const val DAY = 86_400_000L
    }
}
