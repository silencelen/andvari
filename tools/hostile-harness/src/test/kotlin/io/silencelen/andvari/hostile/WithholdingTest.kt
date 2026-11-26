package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.AccountSession
import io.silencelen.andvari.cli.CardOps
import io.silencelen.andvari.cli.CardWrite
import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.doc
import io.silencelen.andvari.cli.e2e.ok
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.items.VaultStanding
import io.silencelen.andvari.core.client.link.CreateOutcome
import io.silencelen.andvari.core.client.link.CreatorStep
import io.silencelen.andvari.core.client.link.RecipientStep
import io.silencelen.andvari.core.client.log.Adoption
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.log.VaultLogStatus
import io.silencelen.andvari.core.client.log.VerifiedVaultState
import io.silencelen.andvari.core.client.pin.CardStatus
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.client.state.AccountStateRead
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.Frames
import io.silencelen.andvari.hostile.proxy.Resp
import io.silencelen.andvari.hostile.proxy.Rule
import io.silencelen.andvari.hostile.proxy.answer
import io.silencelen.andvari.hostile.proxy.arr
import io.silencelen.andvari.hostile.proxy.cutLogAt
import io.silencelen.andvari.hostile.proxy.editAnswer
import io.silencelen.andvari.hostile.proxy.remove
import io.silencelen.andvari.hostile.proxy.serveLog
import io.silencelen.andvari.hostile.proxy.serveVaultRows
import io.silencelen.andvari.hostile.proxy.set
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Ignore
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Withholding (design §16.2 R20, §3.9, §4.4, §5.4): the server hides what is new. A device detects it only against a
 * head or checkpoint it holds, and otherwise sees stale but genuine state; nothing unsigned is ever accepted.
 */
class WithholdingTest {
    private fun names(items: List<io.silencelen.andvari.cli.PlainItem>) = items.map { it.doc["name"]!!.jsonPrimitive.content }

    /** Bob verified the log through position 3; then the server shows him only positions 0 and 1 again. */
    private class RolledBack(val bh: Host, val b: AccountSession, val v: String, val held: VerifiedVaultState, val hiding: List<Rule>)

    private suspend fun World.rolledBack(): RolledBack {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val v = sharedVault(ah, bh)
        val a = account(ah)
        val b = account(bh)
        a.synced()
        assertEquals(null, a.putItem(v, doc("wifi")).second)
        a.ok(v, LogAction.Role(b.userId, "reader")) // seq 2
        a.ok(v, LogAction.Role(b.userId, "writer")) // seq 3
        b.synced()
        val held = assertIs<VaultLogStatus.Verified>(b.logs.status(v)).state
        assertEquals(3L, held.headSeq)
        val hiding = proxy.cutLogAt("bob", v, maxSeq = 1)
        val mark = proxy.mark()
        b.synced()
        assertTrue(sent(bh, WireRoute.LOG_FETCH, mark).isNotEmpty(), "the lower head in the sync row made the device fetch the cut log")
        return RolledBack(bh, b, v, held, hiding)
    }

    /**
     * §3.9: "A served head below the verified head, or a log missing entries this device verified, is withholding. The
     * device keeps its own state and shows 'The server is showing an older version of this vault's history.'" It goes on
     * reading what it holds, and writes nothing under a history the server hides part of.
     */
    @Test fun aVaultLogServedBelowTheVerifiedHeadIsWithheldAndTheDeviceKeepsItsOwnState() = world {
        val r = rolledBack()
        val b = r.b
        val v = r.v
        val withheld = assertIs<VaultLogStatus.Withheld>(b.logs.status(v), "a head below the verified one is withholding: ${b.logs.status(v)}")
        assertEquals(1L, withheld.servedSeq)
        assertEquals(r.held, withheld.state, "the device keeps its own verified state")
        // It keeps working on what it has: the key it adopted still opens what it holds.
        assertNotNull(b.logs.keyFor(v))
        assertTrue(b.logs.copyOutAllowed(v))
        assertEquals(listOf("wifi"), names(b.items(v)))
        // Nothing is written under a history the server is hiding part of, and nothing is sent.
        val mark = proxy.mark()
        assertFalse(b.writeAllowed(v))
        assertEquals(READ_ONLY, b.putItem(v, doc("while withheld")).second)
        assertTrue(sent(r.bh, WireRoute.PUSH, mark).isEmpty())
        // The state is durable: a restart does not turn the withheld vault back into a verified one.
        val again = account(restarted(r.bh))
        assertEquals(r.held, assertIs<VaultLogStatus.Withheld>(again.logs.status(v)).state)
    }

    /**
     * R20's other half: "when the server stops hiding, the device catches up". Served the very head it verified, the
     * device has nothing left to hold against the server: the vault is in order and writable again.
     */
    @Test fun aWithheldVaultIsInOrderAgainWhenTheServerServesTheVerifiedHeadAgain() = world {
        val r = rolledBack()
        assertIs<VaultLogStatus.Withheld>(r.b.logs.status(r.v))
        // The sync row names the verified head itself, so only the re-check of a withheld vault makes the device look.
        r.hiding.remove()
        proxy.serveVaultRows("bob", r.v)
        r.b.synced()
        assertEquals(r.held, assertIs<VaultLogStatus.Verified>(r.b.logs.status(r.v), "served the verified head again, the vault is in order: ${r.b.logs.status(r.v)}").state)
        assertEquals(null, r.b.putItem(r.v, doc("after")).second)
    }

    /**
     * The same for a log that failed: §3.9 "refuses writes to the vault until the log verifies again". An entry nobody
     * signed, served beyond the genuine head, fails the log; once the server serves the genuine log again it verifies.
     */
    @Test fun aVaultWhoseLogFailedOnAnEntryBeyondTheGenuineHeadIsInOrderAgainWhenTheGenuineLogIsServed() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val v = sharedVault(ah, bh)
        val a = account(ah)
        val b = account(bh)
        a.ok(v, LogAction.Role(b.userId, "reader")) // seq 2: the genuine head
        b.synced()
        val held = assertIs<VaultLogStatus.Verified>(b.logs.status(v)).state
        // The server appends a copy of that entry with a broken signature, re-numbered by nobody: it cannot verify.
        val junk = proxy.serveLog("bob", v) { genuine -> genuine + Frames.withBrokenSignature(genuine.last()) }
        b.logs.refresh(v, null, null, force = true)
        assertEquals(held, assertIs<VaultLogStatus.Failed>(b.logs.status(v), "${b.logs.status(v)}").lastGood)
        // The sync row names the verified head itself, so only the re-check of a failed vault makes the device look.
        junk.remove()
        proxy.serveVaultRows("bob", v)
        b.synced()
        assertEquals(held, assertIs<VaultLogStatus.Verified>(b.logs.status(v), "the genuine log is served again: ${b.logs.status(v)}").state)
        // The log no longer stops writes. (The genuine entry at seq 2 made Bob a reader, so the item engine, which
        // follows the role the log gives, still refuses him an item write: that is the log, not the failure.)
        assertEquals(VaultStanding.VERIFIED, b.vaultKeys.access(v)?.standing)
        assertTrue(b.logs.writeAllowed(v), "the log lets this device write again")
        assertEquals("reader", held.members.getValue(b.userId).role)
    }

    /**
     * The same withholding, ended by a NEW entry rather than by the old head being served again: the device verifies
     * forward from its own head and is in order.
     */
    @Test fun aWithheldVaultLogIsInOrderAgainOnceTheServerServesBeyondTheVerifiedHead() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val v = sharedVault(ah, bh)
        val a = account(ah)
        val b = account(bh)
        a.ok(v, LogAction.Role(b.userId, "reader")) // seq 2
        b.synced()
        val hiding = proxy.cutLogAt("bob", v, maxSeq = 1)
        b.synced()
        assertIs<VaultLogStatus.Withheld>(b.logs.status(v))
        a.ok(v, LogAction.Role(b.userId, "writer")) // seq 3
        hiding.remove()
        b.synced()
        assertEquals(3L, assertIs<VaultLogStatus.Verified>(b.logs.status(v), "${b.logs.status(v)}").state.headSeq)
        assertTrue(b.writeAllowed(v))
    }

    /**
     * R20: "Devices detect it only against a head or checkpoint they hold, and otherwise see stale but genuine state."
     * A device that never saw the hidden entry verifies what it is shown, reports nothing, and catches up later.
     */
    @Test fun aHiddenLogEntryLeavesADeviceThatHoldsNoNewerHeadOnStaleButGenuineState() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val v = sharedVault(ah, bh)
        val a = account(ah)
        val b = account(bh)
        val hiding = proxy.cutLogAt("bob", v, maxSeq = 1)
        a.ok(v, LogAction.Role(b.userId, "reader")) // seq 2, which Bob is never shown
        b.synced()
        val stale = assertIs<VaultLogStatus.Verified>(b.logs.status(v), "nothing this device holds contradicts what it is served: ${b.logs.status(v)}")
        assertEquals(1L, stale.state.headSeq)
        assertEquals("writer", stale.state.members.getValue(b.userId).role, "stale, and genuine: the owner did sign this")
        assertFalse(stale.itemHintUnresolved)
        // The server stops hiding: it shows the vault's row with the true head. (Removing the lie alone shows nothing:
        // the row has not changed since the cursor the lying page set, so an honest delta does not carry it.)
        hiding.remove()
        proxy.serveVaultRows("bob", v)
        b.synced()
        val now = assertIs<VaultLogStatus.Verified>(b.logs.status(v))
        assertEquals(2L, now.state.headSeq)
        assertEquals("reader", now.state.members.getValue(b.userId).role)
    }

    /**
     * R20 "nothing unsigned is accepted", §3.9: "A failure leaves the verified state at the last good entry … It keeps
     * reading data already decrypted under a committed key, and refuses writes to the vault until the log verifies again."
     */
    @Test fun aLogEntryNobodySignedIsRefusedTheVerifiedStateStaysAndWritesWaitUntilTheLogVerifiesAgain() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val v = sharedVault(ah, bh)
        val a = account(ah)
        val b = account(bh)
        a.synced()
        assertEquals(null, a.putItem(v, doc("wifi")).second)
        b.synced()
        val good = assertIs<VaultLogStatus.Verified>(b.logs.status(v)).state
        a.ok(v, LogAction.Role(b.userId, "reader")) // seq 2
        // The server serves Bob that entry with one bit of its signature changed.
        val forged = proxy.serveLog("bob", v) { genuine -> genuine.dropLast(1) + Frames.withBrokenSignature(genuine.last()) }
        b.synced()
        val failed = assertIs<VaultLogStatus.Failed>(b.logs.status(v), "an entry nobody signed fails the log: ${b.logs.status(v)}")
        assertEquals("bad_signature", failed.verdict)
        assertEquals(good, failed.lastGood, "the verified state stays at the last good entry")
        assertEquals(listOf("wifi"), names(b.items(v)), "it keeps reading under the committed key")
        // Bob is a writer in the last good state: it is the failed log, not his role, that refuses the write.
        assertEquals("writer", failed.lastGood!!.members.getValue(b.userId).role)
        assertEquals(VaultStanding.FAILED, b.vaultKeys.access(v)?.standing)
        val mark = proxy.mark()
        assertEquals(READ_ONLY, b.putItem(v, doc("on a failed log")).second)
        assertTrue(sent(bh, WireRoute.PUSH, mark).isEmpty())
        forged.remove()
        b.synced()
        val again = assertIs<VaultLogStatus.Verified>(b.logs.status(v), "the genuine log verifies again: ${b.logs.status(v)}").state
        assertEquals(2L, again.headSeq)
        // The log no longer stops writes; the entry that now verified made Bob a reader, and the item engine follows it.
        assertEquals(VaultStanding.VERIFIED, b.vaultKeys.access(v)?.standing)
        assertTrue(b.logs.writeAllowed(v), "the log lets this device write again")
        assertEquals("reader", again.members.getValue(b.userId).role)
        assertFalse(b.writeAllowed(v), "a reader, by the verified log")
    }

    /**
     * §3.6 (e), §3.9: the account's own vault record is a verified head too. A fresh device of the account that is
     * served the log only up to an entry below the record reports withholding and takes the vault's key read-only
     * (decided on 23 November 2026: it can read, never write); served the whole log, it adopts it through the account's
     * own wrap, and the vault is verified again.
     */
    @Test fun aLogServedBelowTheAccountsVaultRecordIsWithheldOnAFreshDeviceOfTheAccount() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val v = sharedVault(ah, bh)
        val a = account(ah)
        val b = account(bh)
        a.ok(v, LogAction.Role(b.userId, "reader")) // seq 2
        a.ok(v, LogAction.Role(b.userId, "writer")) // seq 3
        // The record follows the verified head at most once every ten minutes (design §5.4).
        server.advance(11 * 60_000L)
        b.synced()
        assertEquals(3L, b.store.local().vaults.getValue(v).seq, "Bob's first device recorded the head it verified")

        val hiding = proxy.cutLogAt("bob2", v, maxSeq = 1)
        val b2h = passwordDevice("bob2", "bob@example.org")
        val b2 = account(b2h)
        assertIs<AccountStateRead.Ok>(b2.store.read(), "the fresh device merges the account's state")
        b2.synced()
        val withheld = assertIs<VaultLogStatus.Withheld>(b2.logs.status(v), "a log that ends below the account's record is withholding: ${b2.logs.status(v)}")
        assertEquals(1L, withheld.state.headSeq)
        val readOnly = b2.logs.adoption(v)
        assertIs<Adoption.Adopted>(readOnly, "a vault whose record is ahead of the served log is adopted read-only: $readOnly")
        assertNotNull(b2.logs.keyFor(v), "the key is held")
        assertFalse(b2.writeAllowed(v), "the withheld vault is not writable")
        // The server shows the vault's row with its true head. (Without the row this rests on the re-check of a
        // withheld vault at the head it was last served, finding H3.)
        hiding.remove()
        proxy.serveVaultRows("bob2", v)
        b2.synced()
        assertEquals(3L, assertIs<VaultLogStatus.Verified>(b2.logs.status(v), "${b2.logs.status(v)}").state.headSeq)
        assertIs<Adoption.Adopted>(b2.logs.adoption(v), "served the whole log, the device adopts through the account's own wrap")
        assertTrue(b2.writeAllowed(v), "served the whole log, the vault is writable again")
    }

    /**
     * §3.8 (T2-R-h): "deleted for good" needs the owner's signed `delete` at the tombstone's head; anything else is
     * withholding. A server that merely says the vault was purged changes nothing on the device.
     */
    @Test fun aClaimedPurgeWithoutTheOwnersSignedDeleteDoesNotMakeADeviceGiveUpTheVault() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val v = sharedVault(ah, bh)
        val b = account(bh)
        proxy.on(WireRoute.LOG_FETCH, "bob", handler = editAnswer { it.set("purged", buildJsonObject { put("purgedAt", JsonPrimitive(server.now())) }) })
        b.logs.refresh(v, null, null, force = true)
        assertIs<VaultLogStatus.Verified>(b.logs.status(v), "the log does not end in the owner's delete, so nothing was purged: ${b.logs.status(v)}")
        assertNotNull(b.logs.keyFor(v))
        assertTrue(b.writeAllowed(v))
    }

    /**
     * §4.4: "Withheld. A chain that ends below the pinned `seq` (a stale cache, or a server hiding an update) does not
     * stop anything. The client keeps its newer pinned card … and retries on the next probe." An empty chain is the same.
     */
    @Test fun aCardChainServedBelowThePinIsWithheldAndStopsNothing() = world {
        val oh = operator()
        val ah = member("alice")
        val bh = member("bob")
        assertEquals(1L, assertIs<CardWrite.Stored>(CardOps(oh, oh.session(origin)!!).sign(Steps.PASSWORD.toCharArray(), name = "renamed")).seq)
        val pinned = assertIs<CardStatus.Ok>(ah.trust.refresh(origin)).pin
        assertEquals(1L, pinned.seq)
        assertEquals("renamed", pinned.name)

        // The server shows Alice only card 0 again.
        val hiding = proxy.on(WireRoute.INSTANCE, "alice", handler = editAnswer { it.set("cards", JsonArray(it.arr("cards")!!.take(1))) })
        val withheld = assertIs<CardStatus.Withheld>(ah.trust.refresh(origin), "a chain below the pin is withheld, not a stop")
        assertEquals(0L, withheld.servedSeq)
        assertEquals(pinned, ah.trust.pinFor(origin), "the newer pinned card stays")
        // Nothing stops: the account syncs, and a link is still made under the pinned card.
        account(ah).synced()
        assertIs<CreateOutcome.Created>(ah.links.create("connect", 3_600_000L, emptyList()), "a withheld card stops nothing")
        // No card at all is withholding too.
        proxy.on(WireRoute.INSTANCE, "alice", times = 1, handler = editAnswer { it.set("cards", JsonArray(emptyList())) })
        assertEquals(null, assertIs<CardStatus.Withheld>(ah.trust.refresh(origin)).servedSeq)
        assertEquals(pinned, ah.trust.pinFor(origin))
        hiding.remove()
        assertEquals(pinned, assertIs<CardStatus.Ok>(ah.trust.refresh(origin)).pin)

        // A device that never saw card 1 and is not shown it stays on card 0: stale, genuine, and nothing to report.
        val hidingFromBob = proxy.on(WireRoute.INSTANCE, "bob", handler = editAnswer { it.set("cards", JsonArray(it.arr("cards")!!.take(1))) })
        assertEquals(0L, assertIs<CardStatus.Ok>(bh.trust.refresh(origin)).pin.seq)
        hidingFromBob.remove()
        assertEquals(1L, assertIs<CardStatus.Ok>(bh.trust.refresh(origin)).pin.seq)
    }

    /**
     * R20: a hidden link answer. The creator holds nothing to detect it against, so nothing happens there; the answerer
     * has no reveal and so no code, and the contact it pinned stays unconfirmed. Served the answer, both catch up.
     */
    @Test fun aHiddenLinkAnswerLeavesBothSidesUnconfirmedUntilItIsServed() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val a = account(ah)
        val b = account(bh)
        val link = assertIs<CreateOutcome.Created>(ah.links.create("connect", 3_600_000L, emptyList())).link
        val confirm = assertIs<RecipientStep.Confirm>(bh.links.open(link.url, GateEntry.PASTE_INVITE))
        val answered = assertIs<RecipientStep.Answered>(bh.links.confirm(confirm))
        // The server hides the answer from its creator.
        val hiding = proxy.on(WireRoute.LINK_ANSWERS, "alice", handler = answer { Resp.json(200, JsonArray(emptyList())) })
        assertTrue(ah.links.processAnswers().isEmpty())
        assertEquals(null, a.store.local().contacts[b.userId], "the creator pinned nobody")
        assertIs<RecipientStep.Answered>(bh.links.awaitReveal(answered), "no reveal, so the answerer keeps waiting")
        assertEquals(null, bh.links.code(a.userId), "and has no code to compare")
        assertEquals(false, b.store.local().contacts.getValue(a.userId).compared)
        hiding.remove()
        assertIs<CreatorStep.Processed>(ah.links.processAnswers().single())
        assertIs<RecipientStep.CodeReady>(bh.links.awaitReveal(answered))
        assertNotNull(bh.links.code(a.userId))
    }
}
