package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.AccountSession
import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.e2e.accept
import io.silencelen.andvari.cli.e2e.connect
import io.silencelen.andvari.cli.e2e.doc
import io.silencelen.andvari.cli.e2e.ok
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.log.AppendOutcome
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.log.StoredVaultLogs
import io.silencelen.andvari.core.client.log.VaultLogStatus
import io.silencelen.andvari.core.client.state.AccountStateRead
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.Frames
import io.silencelen.andvari.hostile.proxy.Resp
import io.silencelen.andvari.hostile.proxy.cutLogAt
import io.silencelen.andvari.hostile.proxy.drop
import io.silencelen.andvari.hostile.proxy.dropAnswer
import io.silencelen.andvari.hostile.proxy.long
import io.silencelen.andvari.hostile.proxy.obj
import io.silencelen.andvari.hostile.proxy.remove
import io.silencelen.andvari.hostile.proxy.serveLog
import io.silencelen.andvari.hostile.proxy.serveVaultRows
import io.silencelen.andvari.hostile.proxy.str
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlin.test.Ignore
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Equivocation (design §16.2 R21, §3.9): the server shows different members different genuine histories. Two validly
 * signed entries at one position are a fork; a device that sees both freezes the vault, and one that sees only one
 * cannot tell. An item's log head is a hint to fetch, never a verdict (FS-R4).
 */
class EquivocationTest {
    /**
     * The race the server can run without forging anything: it hides the owner's entry at position 3 from a member, who
     * then signs a `leave` at that same position. The proxy keeps both. Nothing here is signed by anyone but the two
     * accounts' own engines.
     */
    private class Race(val v: String, val ah: Host, val bh: Host, val ch: Host, val a: AccountSession, val b: AccountSession, val c: AccountSession, val bobsLeave: String)

    /** [ownersHeadRecorded]: the owner's device also writes its head at position 3 into the account's vault record (§5.4). */
    private suspend fun World.race(ownersHeadRecorded: Boolean = false): Race {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val ch = member("carol")
        val v = sharedVault(ah, bh)
        val a = account(ah)
        val b = account(bh)
        val c = account(ch)
        connect(ah, ch, origin)
        a.ok(v, LogAction.Add(c.userId, "writer")) // seq 2
        accept(c, v)
        b.synced()
        assertEquals(2L, assertIs<VaultLogStatus.Verified>(b.logs.status(v)).state.headSeq)

        // From here on Bob is shown nothing after position 2, and what he appends is kept by the server, not stored.
        var stolen: String? = null
        proxy.serveLog("bob", v) { genuine -> genuine.filter { Frames.seq(it) <= 2 } + listOfNotNull(stolen) }
        proxy.on(WireRoute.LOG_APPEND, "bob", where = { it.param("vaultId") == v }) { x ->
            val frame = x.req.json!!.str("entry")!!
            stolen = frame
            Resp.json(200, buildJsonObject { put("rev", JsonPrimitive(1)); put("head", Frames.head(frame)) })
        }
        // The record follows the verified head at most once every ten minutes: let that much pass before the owner signs.
        if (ownersHeadRecorded) server.advance(11 * 60_000L)
        a.ok(v, LogAction.Role(c.userId, "reader")) // the owner's entry at position 3
        assertIs<AppendOutcome.Appended>(b.logs.append(v, LogAction.Leave), "Bob leaves at the head he was shown") // his entry at position 3
        val leave = assertNotNull(stolen)
        assertEquals(3L, Frames.seq(leave))
        assertEquals("leave", Frames.kind(leave))
        return Race(v, ah, bh, ch, a, b, c, leave)
    }

    /**
     * §3.9: "A different entry at a sequence number already seen is a fork (equivocation). The device freezes the vault
     * (read-only) and shows the anomaly." §3.6: a frozen vault is read-only on every path that writes under its key,
     * and copying out stays allowed. The freeze is durable: it is still there after a restart, and after the server
     * goes back to serving one branch.
     */
    @Test fun aDeviceShownTwoGenuineEntriesAtOnePositionFreezesTheVaultAndStaysFrozenAcrossARestart() = world {
        val r = race()
        val v = r.v
        // Carol first sees the owner's branch.
        r.c.synced()
        val seen = assertIs<VaultLogStatus.Verified>(r.c.logs.status(v)).state
        assertEquals(3L, seen.headSeq)
        assertEquals("reader", seen.members.getValue(r.c.userId).role)
        assertEquals(null, r.a.putItem(v, doc("before the fork")).second)
        r.c.synced()

        // Then the server shows her the other one: Bob's leave at the same position.
        val other = proxy.serveLog("carol", v) { genuine -> genuine.filter { Frames.seq(it) <= 2 } + r.bobsLeave }
        var mark = proxy.mark()
        r.c.synced()
        assertTrue(sent(r.ch, WireRoute.LOG_FETCH, mark).isNotEmpty(), "the other head in the sync row made the device fetch the other branch")
        val frozen = assertIs<VaultLogStatus.Frozen>(r.c.logs.status(v), "two validly signed entries at one position freeze the vault: ${r.c.logs.status(v)}")
        assertEquals(3L, frozen.seq)
        // Read-only, with copy-out.
        mark = proxy.mark()
        assertFalse(r.c.writeAllowed(v))
        assertEquals(READ_ONLY, r.c.putItem(v, doc("into a frozen vault")).second)
        assertTrue(sent(r.ch, WireRoute.PUSH, mark).isEmpty() && sent(r.ch, WireRoute.LOG_APPEND, mark).isEmpty(), "nothing is written under a frozen vault's key")
        assertTrue(r.c.logs.copyOutAllowed(v), "copying out stays allowed (T2-R-k)")
        assertNotNull(r.c.logs.keyFor(v))

        // The server serving one branch again does not thaw it, and neither does a restart.
        other.remove()
        r.c.synced()
        assertIs<VaultLogStatus.Frozen>(r.c.logs.status(v), "a fork is not undone by serving one branch again")
        val again = account(restarted(r.ch))
        assertIs<VaultLogStatus.Frozen>(again.logs.status(v), "the freeze outlives a restart")
        again.synced()
        assertIs<VaultLogStatus.Frozen>(again.logs.status(v))
        assertFalse(again.writeAllowed(v))
    }

    /** R21: "a device that sees only one cannot tell." Each of the two signers verifies its own branch and reports nothing; shown the other, it freezes. */
    @Test fun aDeviceThatSeesOnlyOneBranchCannotTellAndFreezesOnceItIsShownTheOther() = world {
        val r = race()
        val v = r.v
        // The owner sees her branch: in order.
        r.a.synced()
        assertEquals(3L, assertIs<VaultLogStatus.Verified>(r.a.logs.status(v)).state.headSeq)
        // Bob sees his: he left, by his own signed entry.
        assertIs<VaultLogStatus.Removed>(r.b.logs.status(v), "Bob verified his own leave: ${r.b.logs.status(v)}")
        // The server stops hiding the owner's entry from Bob: he now holds two entries for position 3.
        proxy.honest()
        r.b.synced()
        r.b.logs.refresh(v, null, null, force = true)
        assertEquals(3L, assertIs<VaultLogStatus.Frozen>(r.b.logs.status(v), "shown the owner's entry where it verified its own, the device freezes: ${r.b.logs.status(v)}").seq)
    }

    /**
     * R21 "partly detected now: the account's own vault records (§3.6 (e))", §5.4: the record is a verified head. A
     * fresh device of the owner's account that is shown the other branch meets a different entry at the recorded
     * position and freezes the vault; it never adopts it.
     */
    @Test fun aBranchThatContradictsTheAccountsVaultRecordFreezesTheVaultOnAFreshDevice() = world {
        val r = race(ownersHeadRecorded = true)
        val v = r.v
        assertEquals(3L, r.a.store.local().vaults.getValue(v).seq, "the owner's first device recorded the head it verified")

        proxy.serveLog("alice2", v) { genuine -> genuine.filter { Frames.seq(it) <= 2 } + r.bobsLeave }
        val a2 = account(passwordDevice("alice2", "alice@example.org"))
        assertIs<AccountStateRead.Ok>(a2.store.read())
        a2.synced()
        assertEquals(3L, assertIs<VaultLogStatus.Frozen>(a2.logs.status(v), "another entry at the recorded position is a fork: ${a2.logs.status(v)}").seq)
        assertFalse(a2.writeAllowed(v))
    }

    private fun World.entriesPosted(tag: String, v: String, seq: Long): List<String> = proxy.requests(WireRoute.LOG_APPEND, tag)
        .filter { it.param("vaultId") == v }.map { it.json!!.str("entry")!! }.filter { Frames.seq(it) == seq }

    /**
     * §3.7 (T-R2): "A client keeps every frame it signed in a durable pending append record until the server
     * acknowledges it. After a timeout it re-posts the same bytes, and never re-signs with a new `at`. Re-signing would
     * hand the server two valid entries for one position." A lost acknowledgement is retried byte for byte, also after
     * a restart, and the entry is then part of the verified log.
     */
    @Test fun anEntryWhoseAcknowledgementWasLostIsRePostedByteForByteAlsoAfterARestart() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val v = sharedVault(ah, bh)
        val a = account(ah)
        val b = account(bh)
        // The server stores the entry and gives no answer; then it does not even take the retry.
        proxy.on(WireRoute.LOG_APPEND, "alice", times = 1, where = { it.param("vaultId") == v }, handler = dropAnswer)
        assertEquals(AppendOutcome.Pending, a.logs.append(v, LogAction.Role(b.userId, "reader")))
        proxy.on(WireRoute.LOG_APPEND, "alice", times = 1, where = { it.param("vaultId") == v }, handler = drop)
        a.logs.retryPending()
        val again = account(restarted(ah))
        again.logs.retryPending()
        val posted = entriesPosted("alice", v, 2)
        assertEquals(3, posted.size, "the entry was posted, retried, and retried again after the restart")
        assertEquals(1, posted.toSet().size, "every retry is the same bytes")
        again.synced()
        val state = assertIs<VaultLogStatus.Verified>(again.logs.status(v)).state
        assertEquals(2L, state.headSeq)
        assertEquals("reader", state.members.getValue(b.userId).role)
    }

    /**
     * The other half of the same rule: while an entry this device signed for a position is unacknowledged, it signs no
     * OTHER entry for that position. A server that swallows the first answer and waits for the person to do something
     * else would otherwise hold two entries the owner validly signed for one position: a fork made of genuine frames.
     */
    @Test fun aDeviceSignsNoSecondEntryForAPositionWhileItsFirstIsUnacknowledged() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val v = sharedVault(ah, bh)
        val a = account(ah)
        val b = account(bh)
        // The server keeps the owner's entry for position 2 and gives no answer.
        val silence = proxy.on(WireRoute.LOG_APPEND, "alice", where = { it.param("vaultId") == v }, handler = drop)
        assertEquals(AppendOutcome.Pending, a.logs.append(v, LogAction.Role(b.userId, "reader")))
        // The person does something else to the vault.
        a.logs.append(v, LogAction.Remove(b.userId))
        silence.remove()
        val signed = entriesPosted("alice", v, 2).toSet()
        assertEquals(1, signed.size, "one position, one signed entry; the server now holds ${signed.map { Frames.kind(it) }} for position 2")
    }

    private fun itemHead(s: AccountSession, v: String, name: String): Pair<Long, String> {
        val head = s.items(v).single { it.doc["name"] == JsonPrimitive(name) }.doc.obj("logHead")!!
        return head.long("seq")!! to head.str("hash")!!
    }

    /**
     * §3.9 (FS-R4, FC-10): an item's head above the verified head makes the reader fetch; if the fetch brings nothing
     * new the vault's state does not change (no freeze, no "withheld"), the details note it and the member list is
     * "may be incomplete". Any writer can put any head on an item, so an unresolved chase is not repeated at once.
     */
    @Test fun anItemHeadAboveTheVerifiedHeadMakesTheDeviceFetchOnceAndThenBackOff() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val v = sharedVault(ah, bh)
        val a = account(ah)
        val b = account(bh)
        val hiding = proxy.cutLogAt("bob", v, maxSeq = 1)
        a.ok(v, LogAction.Role(b.userId, "writer")) // seq 2, hidden from Bob
        a.synced()
        assertEquals(null, a.putItem(v, doc("note")).second) // carries the writer's verified head: position 2
        val before = assertIs<VaultLogStatus.Verified>(b.logs.status(v)).state
        assertEquals(1L, before.headSeq)

        // The sync that decrypts the item hands its head to the vault-log engine, which chases it there and then.
        var mark = proxy.mark()
        b.synced()
        val (seq, hash) = itemHead(b, v, "note")
        assertEquals(2L, seq, "the writer put its verified head into the item")
        assertEquals(1, sent(bh, WireRoute.LOG_FETCH, mark).size, "the device fetches the log once")
        val hinted = assertIs<VaultLogStatus.Verified>(b.logs.status(v), "an item head is a hint, never a verdict")
        assertEquals(before, hinted.state, "the fetch brought nothing new: the vault's state does not change")
        assertTrue(hinted.itemHintUnresolved, "the member list is marked 'may be incomplete'")
        assertTrue(b.writeAllowed(v))

        // The same hint again (by hand and by the next sync), and another item's: no second chase while the first is unresolved.
        mark = proxy.mark()
        assertTrue(assertIs<VaultLogStatus.Verified>(b.logs.noteItemHead(v, seq, hash)).itemHintUnresolved)
        assertTrue(assertIs<VaultLogStatus.Verified>(b.logs.noteItemHead(v, seq + 5, "ab".repeat(32))).itemHintUnresolved)
        b.synced()
        assertTrue(sent(bh, WireRoute.LOG_FETCH, mark).isEmpty(), "the device backs off")
        // After the back-off it looks again.
        server.advance(StoredVaultLogs.HINT_BACKOFF_MS + 1_000)
        mark = proxy.mark()
        b.logs.noteItemHead(v, seq, hash)
        assertEquals(1, sent(bh, WireRoute.LOG_FETCH, mark).size)

        // Served the entry at the next chase, the hint resolves and the mark goes.
        hiding.remove()
        server.advance(StoredVaultLogs.HINT_BACKOFF_MS + 1_000)
        assertEquals(2L, assertIs<VaultLogStatus.Verified>(b.logs.noteItemHead(v, seq, hash)).state.headSeq)
        assertFalse(assertIs<VaultLogStatus.Verified>(b.logs.status(v)).itemHintUnresolved, "the item's head is now part of the verified log")
    }

    /**
     * The same hint, resolved by an ordinary sync instead of by a chase: once the verified log holds the head the item
     * named, nothing is unresolved and the "may be incomplete" mark goes.
     */
    @Test fun anItemHintIsResolvedOnceTheVerifiedLogReachesTheHeadItNamed() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val v = sharedVault(ah, bh)
        val a = account(ah)
        val b = account(bh)
        val hiding = proxy.cutLogAt("bob", v, maxSeq = 1)
        a.ok(v, LogAction.Role(b.userId, "writer"))
        a.synced()
        assertEquals(null, a.putItem(v, doc("note")).second)
        b.synced()
        val (seq, hash) = itemHead(b, v, "note")
        assertTrue(assertIs<VaultLogStatus.Verified>(b.logs.noteItemHead(v, seq, hash)).itemHintUnresolved)
        // The server stops hiding and shows the vault's row with its true head (an honest delta would not carry it again).
        hiding.remove()
        proxy.serveVaultRows("bob", v)
        b.synced()
        assertEquals(2L, assertIs<VaultLogStatus.Verified>(b.logs.status(v)).state.headSeq)
        assertFalse(assertIs<VaultLogStatus.Verified>(b.logs.noteItemHead(v, seq, hash)).itemHintUnresolved, "the verified log now holds the head the item named")
    }

    /**
     * §3.9: "A reader that decrypts an item whose `logHead.seq` is above its own verified head … fetches the log." The
     * check above hands the engine the hint by hand; this one reads items the way the headless host does. The item
     * engine decrypts a served item in the pull that brings it, and reports its head there (not on each later read of
     * the working set), so the fetch belongs to that sync; the hint outlives a restart in device state.
     */
    @Test fun readingAnItemWhoseHeadIsAboveTheVerifiedHeadMakesTheHostFetchTheLog() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val v = sharedVault(ah, bh)
        val a = account(ah)
        val b = account(bh)
        proxy.cutLogAt("bob", v, maxSeq = 1)
        a.ok(v, LogAction.Role(b.userId, "writer"))
        a.synced()
        assertEquals(null, a.putItem(v, doc("note")).second)
        val mark = proxy.mark()
        b.synced()
        assertEquals(1, b.items(v).size)
        assertEquals(1, sent(bh, WireRoute.LOG_FETCH, mark).size, "decrypting the item made the device fetch the log")
        assertTrue(assertIs<VaultLogStatus.Verified>(b.logs.status(v)).itemHintUnresolved)
        assertTrue(assertIs<VaultLogStatus.Verified>(account(restarted(bh)).logs.status(v)).itemHintUnresolved, "the mark is kept in device state")
    }
}
