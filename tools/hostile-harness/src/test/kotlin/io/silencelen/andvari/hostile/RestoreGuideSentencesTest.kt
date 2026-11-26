package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.SavedSessions
import io.silencelen.andvari.cli.SyncOutcome
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.doc
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.DeletedItemView
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.items.ItemResult
import io.silencelen.andvari.core.client.log.AppendOutcome
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.log.VaultLogStatus
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.pin.ServerForgotten
import io.silencelen.andvari.core.client.pin.TrustGateWording
import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.AccountSession
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Three sentences of the self-hosting guide's section "Before you restore a backup" that were written from reading the
 * code, each run over the real server with real devices of the shared code, after a restore done as the guide says
 * ([restoreFrom]):
 *
 * 1. "a deleted item can be brought back from the trash" (why a restore is not the way to undo a deleted item);
 * 2. a device that shows a shared vault as frozen after a restore "leaves that state only by forgetting the server and
 *    signing in again";
 * 3. "forgetting the server drops what only that device held" (and signing in afresh then gives it everything the
 *    server holds).
 *
 * The device is the command-line tool's host over the shared engines. It keeps the item engine's records in memory for
 * the session it holds and its trust and log records in its durable device state, so its "forget this server" is the
 * shared engine's per-origin wipe ([Host.forgetServer]) plus the end of the session it holds.
 */
class RestoreGuideSentencesTest {
    private val password get() = Steps.PASSWORD.toCharArray()

    private suspend fun World.trash(s: AccountSession): List<DeletedItemView> =
        assertIs<ItemResult.Ok<List<DeletedItemView>>>(s.items.deletedItems(), "the trash reads").value

    /** The item the trash shows for [itemId] and its document, read from the trash itself. */
    private suspend fun World.inTrash(s: AccountSession, itemId: String): Pair<DeletedItemView, ItemDoc> {
        val row = assertNotNull(trash(s).singleOrNull { it.itemId == itemId }, "the deleted item is in the trash")
        val doc = row.doc ?: assertNotNull(assertIs<ItemResult.Ok<ItemDoc?>>(s.items.deletedItemDoc(row.itemId, row.vaultId, row.deletedAt)).value)
        return row to doc
    }

    private fun AccountSession.password(name: String, vaultId: String): String? =
        items(vaultId).firstOrNull { it.doc["name"]!!.jsonPrimitive.content == name }?.doc?.get("login")?.jsonObject?.get("password")?.jsonPrimitive?.content

    /** "Forget this server" on [h], then the typed address through the Trust Gate and the password: a fresh sign-in there. */
    private suspend fun World.forgetAndSignInAgain(h: Host, email: String) {
        assertEquals(ServerForgotten.Done, h.forgetServer(origin, SavedSessions(h.secure), email), "the server is forgotten on ${tag(h)}")
        assertNull(h.session(origin), "${tag(h)} holds no session after forgetting")
        val gate = assertIs<FirstPin.NeedsTrustGate>(h.trust.beginTrustGate(origin, TrustGateWording.TYPED_ADDRESS), "the typed address shows the Trust Gate again")
        assertIs<FirstPin.Pinned>(h.trust.confirmTrustGate(gate.confirm))
        assertIs<SignIn.SignedIn>(h.onboarding(origin).signIn(email, password), "${tag(h)} signs in again")
    }

    /**
     * Sentence 1: a deleted item comes back from the trash, on the live server with no restore at all (the guide's reason
     * not to restore for it), with its contents, on every device of the account; and an item deleted before the snapshot
     * is in the restored server's trash and comes back the same way.
     */
    @Test fun aDeletedItemIsBroughtBackFromTheTrashWithoutARestoreAndAfterOne() = world {
        operator()
        val ah = member("alice")
        val a = account(ah)
        val b = account(passwordDevice("alice2", "alice@example.org"))
        val v = assertNotNull(a.personalVaultId)
        val kept = assertNotNull(a.putItem(v, doc("kept")).also { assertNull(it.second) }.first)
        val mistake = assertNotNull(a.putItem(v, doc("deleted by mistake")).also { assertNull(it.second) }.first)
        a.synced()
        b.synced()
        assertNull(a.deleteItem(mistake.itemId).second, "the item is deleted")
        a.synced()
        b.synced()
        assertEquals(setOf("kept"), itemNames(b.items(v)), "the other device no longer shows it")

        val (row, itsDoc) = inTrash(a, mistake.itemId)
        assertEquals("deleted by mistake", itsDoc.name)
        assertIs<ItemResult.Ok<Unit>>(a.items.restoreDeleted(row.itemId, row.vaultId, itsDoc), "brought back from the trash")
        b.synced()
        assertEquals(setOf("kept", "deleted by mistake"), itemNames(b.items(v)), "the other device shows it again")
        assertEquals("p-deleted by mistake", b.password("deleted by mistake", v), "with what it held")
        assertTrue(trash(b).none { it.itemId == mistake.itemId }, "and it has left the trash")

        // An item deleted before the snapshot: the restored server's trash holds it, and it comes back the same way.
        assertNull(a.deleteItem(kept.itemId).second)
        a.synced()
        val snapshot = takeSnapshot()
        restoreFrom(snapshot)
        val fresh = account(passwordDevice("alice3", "alice@example.org"))
        fresh.synced()
        assertEquals(setOf("deleted by mistake"), itemNames(fresh.items(v)))
        val (row2, doc2) = inTrash(fresh, kept.itemId)
        assertEquals("kept", doc2.name)
        assertIs<ItemResult.Ok<Unit>>(fresh.items.restoreDeleted(row2.itemId, row2.vaultId, doc2), "brought back after the restore")
        val another = account(passwordDevice("alice4", "alice@example.org"))
        another.synced()
        assertEquals(setOf("kept", "deleted by mistake"), itemNames(another.items(v)))
        assertEquals("p-kept", another.password("kept", v))
    }

    /**
     * Sentence 2, and the shared vault after a restore as designed (withheld, then frozen): Alice changes Bob's role after
     * the snapshot; after the restore her device shows the vault withheld (read-only, readable), Bob's device goes on as a
     * writer, and once Bob leaves (an entry at the place of the lost one) Alice's device freezes the vault for good. Her
     * device does not leave that state by syncing, by a forced read, or by signing out and in again; it leaves it by
     * forgetting the server and signing in again, after which the vault is verified, readable and writable there.
     */
    @Test fun aSharedVaultFrozenAfterARestoreIsLeftOnlyByForgettingTheServerAndSigningInAgain() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val v = sharedVault(ah, bh)
        val a = account(ah)
        val b = account(bh)
        assertNull(a.putItem(v, doc("shared before")).second)
        a.synced()
        b.synced()
        val snapshot = takeSnapshot()
        assertIs<AppendOutcome.Appended>(a.logs.append(v, LogAction.Role(b.userId, "reader")), "Alice makes Bob a reader after the snapshot")
        a.synced()

        restoreFrom(snapshot)

        // Withheld on the device that saw the lost entry: read-only, readable.
        assertEquals(SyncOutcome.Refused("rev_regression"), a.sync(), "Alice's device refuses the older state")
        assertIs<VaultLogStatus.Withheld>(a.logs.refresh(v, null, null, force = true), "the vault's history is shorter than the one Alice checked")
        assertFalse(a.writeAllowed(v), "read-only on Alice's device")
        assertEquals(setOf("shared before"), itemNames(a.items(v)), "and readable")
        // The other member's device never saw the lost entry and goes on normally.
        b.synced()
        assertEquals(1L, assertIs<VaultLogStatus.Verified>(b.logs.status(v)).state.headSeq)
        assertTrue(b.writeAllowed(v), "Bob is a writer again")
        assertIs<AppendOutcome.Appended>(b.logs.append(v, LogAction.Leave), "Bob leaves: an entry at the place of the lost one")
        b.synced()
        assertIs<VaultLogStatus.Removed>(b.logs.status(v))

        // Frozen on Alice's device, for good.
        a.sync()
        assertIs<VaultLogStatus.Frozen>(a.logs.refresh(v, null, null, force = true), "two different histories: frozen")
        assertIs<VaultLogStatus.Frozen>(a.logs.status(v))
        assertEquals(READ_ONLY, a.putItem(v, doc("after the fork")).second, "nothing more can be written there")
        assertEquals(setOf("shared before"), itemNames(a.items(v)), "it stays readable")

        // Not left by signing out and in again on the same device.
        ah.signedOut(origin)
        // A sign-in after a sign-out on this device passes the Trust Gate first.
        assertIs<SignIn.TrustGateFirst>(ah.onboarding(origin).signIn("alice@example.org", password), "the sign-in asks for the Trust Gate")
        val gate = assertIs<FirstPin.NeedsTrustGate>(ah.trust.beginTrustGate(origin, TrustGateWording.TYPED_ADDRESS))
        assertIs<FirstPin.Pinned>(ah.trust.confirmTrustGate(gate.confirm))
        assertIs<SignIn.SignedIn>(ah.onboarding(origin).signIn("alice@example.org", password), "Alice signs in again without forgetting the server")
        val again = account(ah)
        again.sync()
        assertIs<VaultLogStatus.Frozen>(again.logs.refresh(v, null, null, force = true), "still frozen after signing out and in")
        assertFalse(again.writeAllowed(v))

        // Left by forgetting the server and signing in again.
        forgetAndSignInAgain(ah, "alice@example.org")
        val after = account(ah)
        after.synced()
        val verified = assertIs<VaultLogStatus.Verified>(after.logs.status(v), "the vault is verified again on Alice's device")
        assertEquals(2L, verified.state.headSeq, "at the history the server holds: Bob's leave")
        assertTrue(after.writeAllowed(v), "writable again")
        assertEquals(setOf("shared before"), itemNames(after.items(v)))
        assertNull(after.putItem(v, doc("after forgetting")).second, "a save is taken")
        after.synced()
        assertEquals(setOf("shared before", "after forgetting"), itemNames(after.items(v)))
    }

    /**
     * Sentence 3: a device that synced after the snapshot holds saves the restored server lost. Forgetting the server on
     * it and signing in again drops them from it, and the device then holds exactly what the server holds, the saves made
     * since the restore included.
     */
    @Test fun forgettingTheServerAfterARestoreDropsWhatOnlyThatDeviceHeldAndASignInThenHoldsWhatTheServerHolds() = world {
        operator()
        val ah = member("alice")
        val a = account(ah)
        val bh = passwordDevice("alice2", "alice@example.org")
        val b = account(bh)
        val v = assertNotNull(a.personalVaultId)
        assertNull(a.putItem(v, doc("before")).second)
        a.synced()
        b.synced()
        val snapshot = takeSnapshot()
        for (i in 1..3) assertNull(a.putItem(v, doc("after $i")).second)
        a.synced()
        b.synced()

        restoreFrom(snapshot)

        val onlyHere = setOf("before", "after 1", "after 2", "after 3")
        assertEquals(SyncOutcome.Refused("rev_regression"), b.sync())
        assertEquals(onlyHere, itemNames(b.items(v)), "the device holds the saves the server lost")
        val c = account(passwordDevice("alice3", "alice@example.org"))
        c.synced()
        assertEquals(setOf("before"), itemNames(c.items(v)), "the server holds what the snapshot held")
        assertNull(c.putItem(v, doc("since the restore")).second)
        c.synced()

        forgetAndSignInAgain(bh, "alice@example.org")
        val after = account(bh)
        after.synced()
        assertEquals(setOf("before", "since the restore"), itemNames(after.items(v)), "what only this device held is gone; what the server holds is here")
        assertEquals(itemNames(account(passwordDevice("alice4", "alice@example.org")).also { it.synced() }.items(v)), itemNames(after.items(v)), "the same as a device that never held anything")
    }
}
