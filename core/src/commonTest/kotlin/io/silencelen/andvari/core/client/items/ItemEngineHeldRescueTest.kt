package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.crypto.Attachments
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.MutationOp
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Spec 02 §10.6: a held copy "can still be copied out" for 30 days, while the trust engine offers the vault's key. */
class ItemEngineHeldRescueTest {
    /** A shared vault with one item carrying two files, then deleted by its owner: held on this device. */
    private fun heldRig(keepKey: Boolean): Pair<ItemRig, String> {
        val r = ItemRig()
        val id = r.id()
        val refs = (1..2).map { n ->
            val key = r.crypto.randomBytes(32)
            val enc = Attachments.encrypt(r.crypto, key, ByteArray(10) { n.toByte() })
            val fileId = r.id()
            r.server.attachments[fileId] = enc.header + enc.ciphertext
            AttachmentRef(fileId, "f$n.txt", 10, Bytes.toB64(key))
        }
        r.openShared(items = listOf(r.itemRow(id, r.shared, r.sharedKey, r.doc.copy(attachments = refs))))
        r.keys.onServed = { report -> if (r.shared in report.lostAccess) r.keys.depart(r.shared, VaultDeparture.DELETED, keepKey) }
        r.server.queue.add(r.response(r.server.rev + 1, removed = listOf(r.shared)))
        runBlocking { r.engine.sync().ok() }
        assertEquals(1, r.engine.heldVaults().single().itemCount)
        return r to id
    }

    @Test
    fun aHeldItem_isCopiedIntoThePersonalVault_andAFileTheServerNoLongerHandsOverIsCounted() = runBlocking<Unit> {
        val (r, _) = heldRig(keepKey = true)
        val gone = r.server.attachments.keys.first()
        r.server.attachments.remove(gone)
        val report = r.engine.rescueHeldToPersonal(r.shared).ok()
        assertEquals(1, report.copied)
        assertEquals(1, report.filesLeftOut)
        val put = r.server.pushes.last().single()
        assertEquals(MutationOp.PUT to r.personal, put.op to put.vaultId)
        val doc = r.pushedDoc(put)
        assertEquals("Router", doc.name)
        assertEquals(listOf("f2.txt"), doc.attachments.map { it.name })
        assertTrue(doc.attachments.single().id !in setOf(gone), "a fresh file id")
    }

    @Test
    fun aRetryOfACopyNotConfirmed_replaysTheSamePlan_andACopyConfirmedIsNeverReplayed() = runBlocking<Unit> {
        val (r, _) = heldRig(keepKey = true)
        // The first try's copy gets a malformed answer: not confirmed.
        r.server.emptyResultsVaults.add(r.personal)
        assertTrue(r.engine.rescueHeldToPersonal(r.shared) is ItemResult.Failed)
        val first = r.server.pushes.last().single()
        r.server.emptyResultsVaults.clear()
        r.engine.rescueHeldToPersonal(r.shared).ok()
        val second = r.server.pushes.last().single()
        assertEquals(first.itemId, second.itemId)
        assertEquals(first.mutationId, second.mutationId, "the server's dedup makes it one copy")
        // Confirmed: copying out again is a new copy, never a replay the server would answer without storing anything.
        r.engine.rescueHeldToPersonal(r.shared).ok()
        val third = r.server.pushes.last().single()
        assertTrue(third.itemId != second.itemId && third.mutationId != second.mutationId)
    }

    @Test
    fun theBreachRelay_takesOnlyFiveHexCharacters_andNothingUnderAStoppedOrigin() = runBlocking<Unit> {
        val r = ItemRig()
        r.server.ranges["ABCDE"] = "0123:7"
        assertEquals("0123:7", r.engine.breachRange("abcde").ok())
        assertEquals(ItemFailure.NotAllowed(ItemRefusal.BAD_ID), r.engine.breachRange("abcdef").failure())
        assertEquals(ItemFailure.NotAllowed(ItemRefusal.BAD_ID), r.engine.breachRange("ab/de").failure())
        r.gate.forked = true
        assertEquals(ItemFailure.Halted, r.engine.breachRange("ABCDE").failure())
        assertEquals(listOf("ABCDE"), r.server.rangePrefixes)
    }

    @Test
    fun withoutTheVaultsKey_nothingIsCopied() = runBlocking<Unit> {
        val (r, _) = heldRig(keepKey = false)
        val pushes = r.server.pushes.size
        assertEquals(ItemFailure.NotAllowed(ItemRefusal.VAULT_NOT_OPEN), r.engine.rescueHeldToPersonal(r.shared).failure())
        assertEquals(pushes, r.server.pushes.size)
    }
}
