package io.silencelen.andvari.cli.e2e

import io.silencelen.andvari.cli.AccountSession
import io.silencelen.andvari.cli.SyncOutcome
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.items.ItemFailure
import io.silencelen.andvari.core.client.items.ItemNotice
import io.silencelen.andvari.core.client.items.ItemRefusal
import io.silencelen.andvari.core.client.items.ItemResult
import io.silencelen.andvari.core.client.items.NewAttachment
import io.silencelen.andvari.core.client.items.VaultStanding
import io.silencelen.andvari.core.client.items.Written
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.log.VaultLogStatus
import io.silencelen.andvari.core.client.state.VaultRecord
import io.silencelen.andvari.core.crypto.Bytes
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Journey 9: the item engine of `:core` on the new session, against the real server. An offline edit queued and
 * drained from a durable cache, and a cold start from that cache with no network; trash, restore and purge; item
 * history; two devices editing one item (a conflict copy); an attachment up and down; a shared vault's items after
 * acceptance, and what becomes of them when the vault is left, deleted and restored, and frozen.
 */
class J9ItemsTest {
    private fun login(name: String) = ItemDoc(type = "login", name = name, login = LoginData(username = "u", password = "p-$name"))
    private fun AccountSession.names(vaultId: String) = items(vaultId).map { it.doc["name"]!!.jsonPrimitive.content }.toSet()
    private fun <T> ItemResult<T>.ok(what: String): T = when (this) {
        is ItemResult.Ok -> value
        is ItemResult.Failed -> throw AssertionError("$what: $why")
    }

    @Test fun thePersonalVaultOffline_trash_history_andAColdStartFromTheCache() {
        TestServer().use { it.journey { val s = this
            Steps.registerThrough(s.device("operator"), s.origin, s.setupLink, "op@example.org")
            val ah = s.switchedDevice("alice phone")
            Steps.registerThrough(ah, s.origin, Steps.enrolLink(s), "alice@example.org", trustGate = true)
            val a = ah.account(s.origin)!!
            a.synced()
            val p = assertNotNull(a.personalVaultId, "the genesis personal vault is in force")
            assertEquals(listOf("personal"), a.items.vaults().map { it.type })

            // Online save, then an edit and a new item with the network gone: queued, shown, drained on return.
            val router = a.items.save(null, login("router")).ok("save")
            assertEquals(Written.APPLIED, router.outcome)
            s.cut += "alice phone"
            assertEquals(Written.QUEUED, a.items.save(router.itemId, login("router v2"), p).ok("offline edit").outcome)
            val nas = a.items.save(null, login("nas")).ok("offline new item")
            assertEquals(Written.QUEUED, nas.outcome)
            assertEquals(SyncOutcome.Unreachable, a.sync())
            assertEquals(setOf("router v2", "nas"), a.names(p), "queued writes are shown at once")
            assertEquals(setOf(router.itemId, nas.itemId), a.items.pendingSyncItemIds())

            // The app restarts with no network: the working set and the queue come back from the SQLite cache.
            a.items.close()
            val a2 = AccountSession(ah, a.held)
            assertEquals(SyncOutcome.Unreachable, a2.sync())
            assertEquals(setOf("router v2", "nas"), a2.names(p), "a cold start reads the cache and overlays the durable queue")
            s.cut -= "alice phone"
            a2.synced()
            assertTrue(a2.items.pendingSyncItemIds().isEmpty(), "the queue drained")
            assertEquals(setOf("router v2", "nas"), a2.names(p))
            assertTrue(a2.items.item(router.itemId)!!.rev > 0)

            // History: the server kept the version the edit displaced.
            val versions = a2.items.itemVersions(router.itemId, p).ok("versions")
            assertEquals(listOf("router"), versions.map { it.doc.name })

            // Trash, restore, delete again, delete forever.
            assertEquals(Written.APPLIED, a2.items.remove(nas.itemId).ok("remove"))
            assertFalse("nas" in a2.names(p))
            val trashed = a2.items.deletedItems().ok("trash").single()
            assertEquals(nas.itemId, trashed.itemId)
            assertEquals("nas", trashed.doc?.name, "a tombstone is named from its last archived version")
            a2.items.restoreDeleted(nas.itemId, p, trashed.doc!!).ok("restore")
            assertTrue("nas" in a2.names(p))
            a2.items.remove(nas.itemId).ok("remove again")
            a2.items.purgeDeleted(nas.itemId, p).ok("purge")
            assertTrue(a2.items.deletedItems().ok("trash after purge").isEmpty())
            assertTrue(a2.items.notices().isEmpty(), "nothing went wrong: ${a2.items.notices()}")

            // Every sync judged the origin's card chain first (design §4.4).
            assertIs<io.silencelen.andvari.core.client.pin.CardStatus.Ok>(a2.gate.lastStatus, "the last sync's look at the card chain: ${a2.gate.lastStatus}")
            // The pin forks (marked here as a refresh that saw the fork marks it). Traffic stops; reading does not.
            io.silencelen.andvari.core.client.pin.PinStore(ah.state).markForked(assertNotNull(ah.trust.pinFor(s.origin)))
            val exchanges = s.trail.size
            assertEquals(SyncOutcome.Refused("halted"), a2.sync())
            assertEquals("halted", a2.putItem(p, doc("late")).second)
            assertEquals("halted", a2.deleteItem(router.itemId).second)
            assertEquals(exchanges, s.trail.size, "under a forked pin nothing is sent with the session's token")
            assertEquals(setOf("router v2"), a2.names(p), "what the cache holds stays readable")
        } }
    }

    @Test fun aSharedVault_conflict_attachment_left_deleted_restored_frozen() {
        TestServer().use { it.journey { val s = this
            Steps.registerThrough(s.device("operator"), s.origin, s.setupLink, "op@example.org")
            val ah = s.device("alice")
            Steps.registerThrough(ah, s.origin, Steps.enrolLink(s), "alice@example.org", trustGate = true)
            val bh = s.device("bob")
            Steps.registerThrough(bh, s.origin, Steps.enrolLink(s), "bob@example.org", trustGate = true)
            connect(ah, bh, s.origin)
            val a = ah.account(s.origin)!!
            val b = bh.account(s.origin)!!
            a.synced()
            val v = a.ok(null, LogAction.Create("Family"))
            a.ok(v, LogAction.Add(b.userId, "writer"))
            a.synced()
            val wifi = a.items.save(null, login("wifi"), v).ok("alice writes before bob accepts")

            // Before bob accepts, the vault is not his: nothing of it is read. After, the rows he already holds open.
            b.synced()
            assertTrue(b.items(v).isEmpty() && b.items.vaults().none { it.vaultId == v }, "not accepted: absent")
            accept(b, v)
            b.synced()
            assertEquals(setOf("wifi"), b.names(v))
            assertEquals("writer", b.items.vaults().single { it.vaultId == v }.role)

            // Two devices edit one item. Alice's edit lands first; bob's, made from the older revision, wins the row and
            // alice's displaced version is kept as a conflict copy that both then see.
            a.items.save(wifi.itemId, login("wifi (alice)"), v).ok("alice's edit")
            b.items.save(wifi.itemId, login("wifi (bob)"), v).ok("bob's edit from the older revision")
            b.synced()
            a.synced()
            for (who in listOf(a, b)) {
                val names = who.names(v)
                assertTrue("wifi (bob)" in names, "the later write is the item: $names")
                assertEquals(1, names.count { it.startsWith("wifi (alice) (conflict ") }, "the displaced edit is one conflict copy: $names")
                assertEquals(2, names.size)
            }
            assertTrue(a.items.envelopes().none { it.conflict } && b.items.envelopes().none { it.conflict }, "the flag was cleared")

            // An attachment: uploaded encrypted by alice, downloaded and decrypted by bob.
            val data = ByteArray(150_000) { (it % 253).toByte() }
            val ref = AttachmentRef(Bytes.uuidV4FromBytes(ah.crypto.randomBytes(16)), "scan.pdf", data.size.toLong(), Bytes.toB64(ah.crypto.randomBytes(32)))
            a.items.save(null, login("passport").copy(attachments = listOf(ref)), v, uploads = listOf(NewAttachment(ref, data))).ok("save with a file")
            b.synced()
            val got = b.items.items().single { it.doc.name == "passport" }.doc.attachments.single()
            assertContentEquals(data, b.items.downloadAttachment(got).ok("download"))

            // Bob leaves: his copy moves to the holding area and nothing of the vault is listed any more.
            b.ok(v, LogAction.Leave)
            b.synced()
            assertTrue(b.items(v).isEmpty() && b.items.vaults().none { it.vaultId == v })
            val held = b.items.heldVaults().single()
            assertEquals("left", held.reason)
            assertEquals(3, held.itemCount)
            assertEquals(ItemNotice.LEFT, b.items.notices().last().kind)
            assertEquals(ItemFailure.NotAllowed(ItemRefusal.VAULT_NOT_OPEN), (b.items.save(null, login("late"), v) as ItemResult.Failed).why)

            // Alice deletes the vault: held on her device, still readable for copying out; a restore brings it back.
            a.synced()
            a.ok(v, LogAction.Delete)
            a.synced()
            assertTrue(a.items(v).isEmpty(), "a deleted vault leaves the list")
            assertEquals("deleted", a.items.heldVaults().single().reason)
            assertEquals(3, a.items.heldItems(v).size, "its owner can still read the held copy")
            a.ok(v, LogAction.Restore)
            a.synced()
            assertTrue(a.items.heldVaults().isEmpty())
            assertEquals(3, a.items(v).size, "restored with its items")
            assertEquals(ItemNotice.RESTORED, a.items.notices().last().kind)
            a.items.save(null, login("after restore"), v).ok("writable again")

            // Frozen: the account's own vault record names another genesis (spec 05 R35). The vault stays readable and
            // can be copied out of; nothing is written to it.
            a.store.update { doc -> doc.copy(vaults = doc.vaults + (v to VaultRecord(v, "0".repeat(64), 0, "0".repeat(64)))) }
            assertIs<VaultLogStatus.Frozen>(a.logs.refresh(v, null, null, force = true))
            a.synced()
            assertEquals(VaultStanding.FROZEN, a.items.vaults().single { it.vaultId == v }.standing)
            assertEquals(4, a.items(v).size, "what is held stays readable")
            assertEquals(ItemFailure.NotAllowed(ItemRefusal.VAULT_READ_ONLY), (a.items.save(null, login("into frozen"), v) as ItemResult.Failed).why)
            assertEquals(ItemFailure.NotAllowed(ItemRefusal.VAULT_READ_ONLY), (a.items.remove(wifi.itemId) as ItemResult.Failed).why)
            assertEquals(4, a.items.rescueToPersonal(v).ok("copy out of a frozen vault"))
            assertEquals(4, a.items(a.personalVaultId!!).size)
            assertNull(a.items.notices().firstOrNull { it.kind == ItemNotice.WRITE_REJECTED || it.kind == ItemNotice.WRONG_VAULT })
        } }
    }
}
