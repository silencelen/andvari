package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.AccountSession
import io.silencelen.andvari.cli.SyncOutcome
import io.silencelen.andvari.core.client.items.ItemNotice
import io.silencelen.andvari.cli.e2e.connect
import io.silencelen.andvari.cli.e2e.doc
import io.silencelen.andvari.cli.e2e.ok
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.link.Currency
import io.silencelen.andvari.core.client.log.AppendOutcome
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.state.AccountStateRead
import io.silencelen.andvari.core.client.state.AccountStateWrite
import io.silencelen.andvari.core.client.state.ContactRecord
import io.silencelen.andvari.core.client.state.MergeAnomaly
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.Frames
import io.silencelen.andvari.hostile.proxy.Resp
import io.silencelen.andvari.hostile.proxy.answer
import io.silencelen.andvari.hostile.proxy.obj
import io.silencelen.andvari.hostile.proxy.set
import io.silencelen.andvari.hostile.proxy.str
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Ignore
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The account-state document and the sync page under replay (design §5.4, §8.5, §16.2 R20, R23 and R35; spec 05 T1).
 * "The server alone can only serve an older copy, never a forged one." Whoever holds the account's key can write
 * anything, and a device still uses no contact the person did not confirm there.
 */
class AccountStateTest {
    private val noBlob = Resp.json(200, buildJsonObject { put("sealedState", JsonNull); put("seq", JsonPrimitive(0)) })

    /** The answers of [tag]'s successful account-state writes, oldest first: each is the blob as it stood after that write. */
    private fun World.writes(tag: String): List<Resp> =
        proxy.log().filter { it.req.route == WireRoute.ACCOUNT_STATE_PUT && it.req.tag == tag && it.upstream?.ok == true }.map { it.upstream!! }

    /**
     * §5.4: "Every device merges a served copy with its own on each read … A served copy that is a rollback is still
     * merged the same way: a record only ever refuses." §8.3: "A served state below [the high-water mark] is a rollback".
     * The rollback and the withheld blob are reported; nothing the device holds is lost; and its next write continues
     * from its own counter, not from the server's.
     */
    @Test fun anOlderOrWithheldAccountStateBlobIsReportedMergedNotAdoptedAndTheHighWaterMarkHolds() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val a = account(ah)
        val b = account(bh)
        connect(ah, bh, origin)
        val held = a.store.local()
        assertTrue(held.contacts.getValue(b.userId).compared)
        assertTrue(writes("alice").size >= 2)
        val older = writes("alice").let { it[it.size - 2] } // the write before the last: Bob pinned, and not yet compared

        // The server serves the older blob.
        val replay = proxy.on(WireRoute.ACCOUNT_STATE_GET, "alice", handler = answer { older })
        val read = assertIs<AccountStateRead.Ok>(a.store.read())
        val rollback = read.anomalies.filterIsInstance<MergeAnomaly.Rollback>().single()
        assertEquals(held.seq, rollback.highWater)
        assertTrue(rollback.servedSeq < rollback.highWater, "the served document is older than one this device has seen")
        assertEquals(held.contacts, read.document.contacts, "the merge keeps what the device holds: the comparison stays matched")
        assertEquals(held.seq, a.store.local().seq, "the counter does not go back")
        // A write cannot land while the server keeps replaying (its compare-and-set token is stale), and loses nothing.
        assertFalse(a.contacts.remove(b.userId), "the write does not land")
        assertEquals(held.contacts, a.store.local().contacts)
        replay.remove()

        // The server serves no blob at all, after one was seen.
        val withholding = proxy.on(WireRoute.ACCOUNT_STATE_GET, "alice", handler = answer { noBlob })
        val nothing = assertIs<AccountStateRead.Ok>(a.store.read())
        assertEquals(listOf<MergeAnomaly>(MergeAnomaly.Withheld), nothing.anomalies)
        assertEquals(held.contacts, nothing.document.contacts)
        withholding.remove()

        // Served the current blob again: nothing to report, and the next write is the next number after the high-water mark.
        assertTrue(assertIs<AccountStateRead.Ok>(a.store.read()).anomalies.isEmpty())
        assertTrue(a.contacts.remove(b.userId))
        assertEquals(held.seq + 1, a.store.local().seq)
    }

    /**
     * §8.5, R23: "The one-tap contacts list trusts the account-state copy the server serves. The server alone can hide
     * contacts or restore a removed one, never add one." And on such a device nobody is current before the person
     * confirms the list; whoever they untick stays out.
     */
    @Test fun onAPasswordOnlyDeviceTheServerAloneCanHideOrRestoreAContactButNeverAddOne() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val ch = member("carol")
        val a = account(ah)
        val b = account(bh)
        val c = account(ch)
        connect(ah, bh, origin)
        connect(ah, ch, origin)
        val withBob = writes("alice").last() // Bob and Carol, both compared
        assertTrue(a.contacts.remove(b.userId), "Alice removes Bob: a tombstone")
        val bobsOwn = writes("bob").last() // another account's document, sealed under that account's key

        suspend fun fresh(tag: String, served: Resp?): AccountSession {
            if (served != null) proxy.on(WireRoute.ACCOUNT_STATE_GET, tag, handler = answer { served })
            return account(passwordDevice(tag, "alice@example.org"))
        }

        // Served honestly: Carol, and not Bob. Nobody is current until the person confirms the list.
        val honest = fresh("alice-honest", null)
        assertIs<AccountStateRead.Ok>(honest.store.read())
        assertEquals(setOf(c.userId), honest.store.local().contacts.keys)
        assertTrue(honest.contacts.oneTapListDue(), "a password-only device shows the list once")
        assertTrue(honest.contacts.list().all { it.current == null }, "no contact is current before the person confirms")
        assertTrue(honest.contacts.confirmOneTap(setOf(c.userId)))
        assertEquals(Currency.ONE_TAP, honest.contacts.list().single().current)
        assertFalse(honest.contacts.oneTapListDue())

        // Restored: the blob from before the removal brings Bob back onto the list. The person unticks him.
        val restored = fresh("alice-restored", withBob)
        assertIs<AccountStateRead.Ok>(restored.store.read())
        assertEquals(setOf(b.userId, c.userId), restored.store.local().contacts.keys, "the server can bring back someone the person removed")
        assertTrue(restored.contacts.list().all { it.current == null })
        assertTrue(restored.contacts.confirmOneTap(setOf(c.userId)))
        assertNull(restored.contacts.list().single { it.record.userId == b.userId }.current, "whoever is unticked is not used on this device")
        assertNull(restored.contacts.currentFor(b.userId, restored.store.local().contacts.getValue(b.userId).identityPub))

        // Hidden: no blob, no contacts.
        val hidden = fresh("alice-hidden", noBlob)
        assertIs<AccountStateRead.Ok>(hidden.store.read())
        assertTrue(hidden.store.local().contacts.isEmpty(), "the server can hide people")

        // Added: another account's document, or the account's own with one character changed. Neither opens; nobody appears.
        val text = withBob.json!!.str("sealedState")!!
        val flipped = text.substring(0, text.length / 2) + (if (text[text.length / 2] == 'A') 'B' else 'A') + text.substring(text.length / 2 + 1)
        for ((i, made) in listOf(bobsOwn, withBob.withJson { it.set("sealedState", flipped) }).withIndex()) {
            val added = fresh("alice-added$i", made)
            assertEquals(AccountStateRead.Unopenable, added.store.read(), "a document the account's key did not seal is refused whole")
            assertTrue(added.store.local().contacts.isEmpty(), "the server cannot add anyone")
            assertTrue(added.contacts.list().isEmpty())
        }

        // On the device that holds the tombstone, the same replay brings nobody back.
        proxy.on(WireRoute.ACCOUNT_STATE_GET, "alice", handler = answer { withBob })
        val merged = assertIs<AccountStateRead.Ok>(a.store.read())
        assertEquals(setOf(c.userId), merged.document.contacts.keys, "anything a rollback would bring back is removed again by the tombstone the local copy holds")
        assertTrue(merged.anomalies.any { it is MergeAnomaly.Rollback })
    }

    /**
     * R35, §6.9 (T-R5, T-R6): any holder of the account's key can write a contact into account state (a hostile web
     * bundle, an operator who opened an escrow). "Native devices ask before using any contact made elsewhere": the
     * planted contact is current nowhere, cannot be added to a vault, and becomes current only by the person's own tap.
     */
    @Test fun aContactPlantedByAHolderOfTheAccountsKeyIsCurrentNowhereUntilThePersonConfirmsItOnTheDevice() = world {
        operator()
        val ah = member("alice")
        val mh = member("mallory")
        val a = account(ah)
        val m = account(mh)
        val malloryKey = proxy.last(WireRoute.REGISTER, "mallory")!!.upstream!!.json!!.obj("accountKeys")!!.str("identityPub")!!
        // The plant: written with the account's own key, marked compared, as if a device of the account had made it.
        val planted = ContactRecord(m.userId, malloryKey, Frames.b64("your sister".encodeToByteArray()), verifiedAt = server.now(), compared = true, madeOn = ah.session(origin)!!.session.deviceId)
        assertIs<AccountStateWrite.Written>(a.store.update { it.copy(contacts = it.contacts + (m.userId to planted)) })

        assertNull(a.contacts.currentFor(m.userId, malloryKey), "a record alone makes nothing current")
        assertNull(a.contacts.list().single().current)
        val prompt = a.contacts.prompts().single()
        assertEquals("your sister", prompt.labelText)
        a.synced()
        val v = a.ok(null, LogAction.Create("Family"))
        val mark = proxy.mark()
        assertEquals(AppendOutcome.NotAllowed("not_a_current_contact"), a.logs.append(v, LogAction.Add(m.userId, "writer")), "nothing is shared with a contact the person never confirmed here")
        assertTrue(sent(ah, WireRoute.LOG_APPEND, mark).isEmpty())
        // The same on a second device of the account.
        val second = account(passwordDevice("alice-2", "alice@example.org"))
        assertIs<AccountStateRead.Ok>(second.store.read())
        assertNull(second.contacts.currentFor(m.userId, malloryKey))
        // Only the person's own tap on this device makes it current.
        assertTrue(a.contacts.confirmHere(prompt))
        assertEquals(Currency.CONFIRMED, assertNotNull(a.contacts.currentFor(m.userId, malloryKey)).current)
    }

    /**
     * §3.6 (e), §5.4: the vault record is "updated as the verified head advances", written "at most once every 10
     * minutes". The batching may delay a write; it must not lose it. A fresh device and a device-link bundle take the
     * record as their lower bound for this vault, so a record that stays behind is history the server can hide again.
     */
    @Test fun theAccountsVaultRecordReachesTheVerifiedHeadOnceTheBatchingIntervalHasPassed() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val v = sharedVault(ah, bh) // the owner's record is written at the genesis; the add follows within the same ten minutes
        val a = account(ah)
        a.ok(v, LogAction.Role(account(bh).userId, "reader")) // seq 2
        server.advance(11 * 60_000L)
        a.synced()
        assertEquals(2L, a.store.local().vaults.getValue(v).seq, "ten minutes after the last entry, the record names the head this device verified")
    }

    private fun names(s: AccountSession, v: String) = s.items(v).map { it.doc["name"]!!.jsonPrimitive.content }.toSet()

    /**
     * Spec 05 T1: the server can "roll back the DB — mitigated by client caches noticing rev regression (clients warn,
     * never delete local newer state)". A `/sync` page older than one this device has seen must not make it forget what
     * it holds.
     */
    @Test fun aSyncPageOlderThanOneTheDeviceHasSeenDoesNotMakeItForgetNewerItems() = world {
        operator()
        val ah = member("alice")
        val a = account(ah)
        val pv = a.personalVaultId!!
        a.synced()
        assertEquals(null, a.putItem(pv, doc("first")).second)
        a.synced()
        val older = proxy.last(WireRoute.SYNC, "alice")!!.upstream!!
        assertEquals(null, a.putItem(pv, doc("second")).second)
        a.synced()
        assertEquals(setOf("first", "second"), names(a, pv))
        proxy.on(WireRoute.SYNC, "alice", handler = answer { older })
        assertEquals(SyncOutcome.Refused("rev_regression"), a.sync(), "the older page is refused as a rollback, not applied")
        assertEquals(setOf("first", "second"), names(a, pv), "a page with a lower rev is a rollback: nothing newer is dropped")
        assertTrue(a.items.notices().any { it.kind == ItemNotice.ROLLBACK }, "the person is warned")
    }

    /** Alice holds `first` and `second`; [older] is the whole page (`since=0`) the server would have sent when only `first` existed. */
    private class OlderSnapshot(val a: AccountSession, val pv: String, val older: Resp)

    private suspend fun World.olderSnapshot(): OlderSnapshot {
        operator()
        val a = account(member("alice"))
        val pv = a.personalVaultId!!
        a.synced()
        assertEquals(null, a.putItem(pv, doc("first")).second)
        var older: Resp? = null
        proxy.on(WireRoute.SYNC, "alice", times = 1) { x -> older = x.ask(WireRoute.SYNC, query = "since=0"); x.forward() }
        a.synced()
        assertEquals(null, a.putItem(pv, doc("second")).second)
        a.synced()
        assertEquals(setOf("first", "second"), names(a, pv))
        val page = assertNotNull(older).json!!
        assertEquals(true, page["full"]?.jsonPrimitive?.content?.toBoolean(), "a since=0 page is a whole snapshot")
        return OlderSnapshot(a, pv, older!!)
    }

    /** Spec 05 T1, spec 03 §4: a whole snapshot the device did not ask for, older than its cursor, is a rollback too. */
    @Test fun anOlderWholeSnapshotServedInPlaceOfADeltaIsARollback() = world {
        val s = olderSnapshot()
        proxy.on(WireRoute.SYNC, "alice", handler = answer { s.older })
        assertEquals(SyncOutcome.Refused("rev_regression"), s.a.sync())
        assertEquals(setOf("first", "second"), names(s.a, s.pv), "nothing newer is dropped")
        assertTrue(s.a.items.notices().any { it.kind == ItemNotice.ROLLBACK })
    }

    /**
     * The same older snapshot after a `410 resync_required`: the server says the device's cursor is before its retained
     * history and serves the whole page. A rev is global and only grows (spec 03 §4), so a snapshot whose rev is below
     * the cursor the device holds is a rollback whatever the server says about its history; the newer items stay.
     */
    @Test fun anOlderWholeSnapshotAfterAResyncDemandIsStillARollback() = world {
        val s = olderSnapshot()
        val olderRev = s.older.json!!.getValue("rev").jsonPrimitive.content.toLong()
        proxy.on(WireRoute.SYNC, "alice", where = { it.queryParam("since") != "0" }, handler = answer { Resp.error(410, "resync_required") })
        proxy.on(WireRoute.SYNC, "alice", where = { it.queryParam("since") == "0" }, handler = answer { s.older })
        val mark = proxy.mark()
        val outcome = s.a.sync()
        assertTrue(proxy.requests(WireRoute.SYNC, "alice", mark).any { it.queryParam("since") == "0" }, "the device asked for the whole page")
        assertEquals(setOf("first", "second"), names(s.a, s.pv), "a snapshot below the cursor drops nothing newer (rev $olderRev; the sync answered $outcome)")
        assertEquals(SyncOutcome.Refused("rev_regression"), outcome)
    }
}
