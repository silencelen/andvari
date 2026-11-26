package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.AccountSession
import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.SavedSessions
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.accept
import io.silencelen.andvari.cli.e2e.connect
import io.silencelen.andvari.cli.e2e.doc
import io.silencelen.andvari.cli.e2e.ok
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.content.ContentHost
import io.silencelen.andvari.core.app.content.EngineVaultContent
import io.silencelen.andvari.core.client.items.ItemResult
import io.silencelen.andvari.core.client.log.Adoption
import io.silencelen.andvari.core.client.log.AppendOutcome
import io.silencelen.andvari.core.client.log.KeySource
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.log.VaultLogStatus
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.pin.TrustGateWording
import io.silencelen.andvari.core.client.state.VaultRecord
import io.silencelen.andvari.core.crypto.KdfParams
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlin.reflect.KClass
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A shared vault after an honest restore of the server from an earlier day (design §3.6 (e), §3.9; decided on 23 November
 * 2026). A device of the account saw an entry of the vault's log that the restore lost and wrote its place into the
 * account's own records; the restored server serves the log as it was. Every device of the account then opens the vault
 * read-only: it is listed, its items are read and can be copied into the person's own vault, and every road that writes
 * into it is refused before anything is sent. The account's record is never lowered. What must stay closed stays closed:
 * a chain with another beginning under the vault's id, a key whose other conditions fail, a vault the person left.
 *
 * Over the real server in its test mode, a real restore of its database (`andvari admin restored`) and the devices of
 * the shared code (the command-line host).
 */
class SharedVaultReadOnlyAfterRestoreTest {
    private val aliceMail = "alice@example.org"
    private val bobMail = "bob@example.org"

    /** The owner's scene after the restore: [na] is Alice's first device, signed in again, which wrote the record back. */
    private class Scene(
        val ah: Host, val bh: Host, val a2h: Host, val v: String, val itemId: String, val trashId: String,
        val record: VaultRecord, val na: AccountSession, val aliceId: String, val bobId: String,
    )

    /** A login named [name] whose web address is [uri]. */
    private fun loginAt(name: String, uri: String) = buildJsonObject {
        put("type", JsonPrimitive("login")); put("name", JsonPrimitive(name))
        put("login", buildJsonObject {
            put("username", JsonPrimitive("u")); put("password", JsonPrimitive("p-$name")); put("uris", JsonArray(listOf(JsonPrimitive(uri))))
        })
    }

    private suspend fun World.signIn(h: Host, email: String) {
        var r = h.onboarding(origin).signIn(email, Steps.PASSWORD.toCharArray())
        if (r is SignIn.TrustGateFirst) {
            val gate = assertIs<FirstPin.NeedsTrustGate>(h.trust.beginTrustGate(origin, TrustGateWording.TYPED_ADDRESS))
            h.trust.confirmTrustGate(gate.confirm)
            r = h.onboarding(origin).signIn(email, Steps.PASSWORD.toCharArray())
        }
        assertIs<SignIn.SignedIn>(r, "$email signs in again: $r")
    }

    /** A device's next contact after the restore (its session ended there), the sign-in again, and its syncs. */
    private suspend fun World.again(h: Host, email: String): AccountSession {
        runCatching { h.account(origin)?.sync() }
        if (h.account(origin) == null) signIn(h, email)
        val s = account(h)
        s.sync()
        s.sync()
        return s
    }

    /** "Forget this server" on [h], then the typed address through the Trust Gate, the password and two syncs. */
    private suspend fun World.forgetAndSignIn(h: Host, email: String): AccountSession {
        h.forgetServer(origin, SavedSessions(h.secure), email)
        val gate = assertIs<FirstPin.NeedsTrustGate>(h.trust.beginTrustGate(origin, TrustGateWording.TYPED_ADDRESS))
        h.trust.confirmTrustGate(gate.confirm)
        assertIs<SignIn.SignedIn>(h.onboarding(origin).signIn(email, Steps.PASSWORD.toCharArray()))
        val s = account(h)
        s.sync()
        s.sync()
        return s
    }

    private suspend fun World.fresh(tag: String, email: String): AccountSession {
        val s = account(passwordDevice(tag, email))
        s.sync()
        s.sync()
        return s
    }

    private fun World.restored(snapshot: Snapshot) {
        server.advance(60_000L)
        restoreFrom(snapshot) { env -> adminRestored(env).also { assertEquals(0, it.code, "${it.out} ${it.err}") } }
    }

    /**
     * Alice owns "Shared" with Bob, an item in it and one in its trash; her second device syncs; the snapshot. Alice makes
     * Bob a reader (seq 2, the entry the restore loses) and, ten minutes later, her device writes that head into her
     * account's records. The restore; her first device signs in again and makes a vault, which writes the records back.
     */
    private suspend fun World.ownerScene(shared: JsonObject = doc("shared item")): Scene {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val v = sharedVault(ah, bh, "Shared")
        val a = account(ah)
        val b = account(bh)
        val itemId = assertNotNull(a.putItem(v, shared).first).itemId
        val trashId = assertNotNull(a.putItem(v, doc("trash item")).first).itemId
        a.synced()
        assertNotNull(a.deleteItem(trashId).first)
        a.synced()
        b.synced()
        val a2h = passwordDevice("alice2", aliceMail)
        account(a2h).synced()
        val snapshot = takeSnapshot()
        a.ok(v, LogAction.Role(b.userId, "reader"))
        a.synced()
        server.advance(10 * 60_000L)
        a.synced()
        val record = assertNotNull(a.store.local().vaults[v], "Alice's first device recorded the head it verified")
        assertEquals(2L, record.seq, "the record names the entry the restore will lose")
        restored(snapshot)
        val na = again(ah, aliceMail)
        na.ok(null, LogAction.Create("Another"))
        return Scene(ah, bh, a2h, v, itemId, trashId, record, na, a.userId, b.userId)
    }

    /** Bob, who never saw the lost entry, signs in again and leaves: an entry at the lost place. */
    private suspend fun World.bobLeavesAtTheLostPlace(sc: Scene) {
        val nb = again(sc.bh, bobMail)
        assertIs<AppendOutcome.Appended>(nb.logs.append(sc.v, LogAction.Leave), "Bob's leave is stored")
    }

    /**
     * [s] lists [v] in the [standing] its log engine names, holds its key, reads its items, and cannot write to it: every
     * road that writes into a shared vault is refused before anything is sent. A `leave` is not among them: a member may
     * leave a frozen vault (rule of 2026-11-19). Copying out works: the item opens and a copy is saved into the person's
     * own vault. [someone] is another member, whom the log roads name.
     */
    private suspend fun World.readsAndNeverWrites(
        what: String, s: AccountSession, v: String, itemId: String, trashId: String?,
        standing: KClass<out VaultLogStatus>, someone: String,
    ) {
        val st = s.logs.status(v)
        assertTrue(standing.isInstance(st), "$what: the vault is ${standing.simpleName}: $st")
        assertTrue(v in s.vaultIds(), "$what: the vault is listed")
        assertNotNull(s.logs.keyFor(v), "$what: the vault's key is held: ${s.logs.adoption(v)}")
        assertEquals(setOf("shared item"), itemNames(s.items(v)), "$what: the vault's items are read")
        assertFalse(s.writeAllowed(v), "$what: the vault is not writable")
        assertFalse(s.logs.writeAllowed(v), "$what: the log lets nothing be written")
        val personal = assertNotNull(s.personalVaultId)
        val own = assertNotNull(s.putItem(personal, doc("own item")).first, "$what: an item of the person's own vault").itemId
        val itemDoc = assertNotNull(s.items.item(itemId), "$what: the item opens").doc

        val mark = proxy.mark()
        assertNotNull(s.putItem(v, doc("new")).second, "$what: a new item is refused")
        assertNotNull(s.putItem(v, doc("changed"), itemId).second, "$what: a change is refused")
        assertNotNull(s.deleteItem(itemId).second, "$what: a deletion is refused")
        val moveIn = s.items.planMove(own, v, deleteSource = true)
        val movedIn = (moveIn as? ItemResult.Ok)?.let { s.items.runMove(it.value, finalSync = false) }
        assertTrue(moveIn is ItemResult.Failed || movedIn is ItemResult.Failed, "$what: moving an item in is refused: $moveIn $movedIn")
        val moveOut = s.items.planMove(itemId, personal, deleteSource = true)
        val movedOut = (moveOut as? ItemResult.Ok)?.let { s.items.runMove(it.value, finalSync = false) }
        assertTrue(moveOut is ItemResult.Failed || movedOut is ItemResult.Failed, "$what: moving an item out is refused: $moveOut $movedOut")
        if (trashId != null) assertIs<ItemResult.Failed>(s.items.restoreDeleted(trashId, v, itemDoc), "$what: a restore from the trash is refused")
        assertIs<ItemResult.Failed>(s.items.renameVault(v, "Renamed"), "$what: a rename is refused")
        for (action in listOf(
            LogAction.Add(someone, "writer"), LogAction.Role(someone, "reader"), LogAction.Remove(someone),
            LogAction.Offer(someone, 86_400_000L), LogAction.DeleteVault(), LogAction.Restore,
        )) {
            val r = s.logs.append(v, action)
            assertTrue(r is AppendOutcome.VaultReadOnly || r is AppendOutcome.NotAllowed, "$what: $action is refused: $r")
        }
        val written = proxy.requests(tag = tag(s.host), since = mark).filter { it.method != "GET" }
        assertTrue(written.isEmpty(), "$what: nothing that writes was sent: ${written.map { "${it.method} ${it.path}" }}")
        assertEquals(setOf("shared item"), itemNames(s.items(v)), "$what: the vault's items are unchanged")

        val copy = s.putItem(personal, s.items(v).single { it.itemId == itemId }.doc)
        assertNull(copy.second, "$what: a copy of the item is saved into the person's own vault")
        assertTrue("shared item" in itemNames(s.items(personal)), "$what: the copy is in the person's own vault")
    }

    /** The account's record of [v] as the server holds it now (read by a fresh device): what it was, or higher. */
    private suspend fun World.recordNotLowered(tag: String, email: String, v: String, was: VaultRecord) {
        val s = account(passwordDevice(tag, email))
        s.readAccountStateOnce()
        val now = assertNotNull(s.store.local().vaults[v], "the account still records the vault")
        assertEquals(was.genesisHash, now.genesisHash, "the record names the same beginning")
        assertTrue(now.seq >= was.seq, "the record is not lowered: ${now.seq} against ${was.seq}")
        if (now.seq == was.seq) assertEquals(was.hash, now.hash, "the record names the same entry")
    }

    /** (a) The owner's account: a fresh device and one that synced only before the day read the vault, withheld, and cannot write. */
    @Test fun aTheOwnersFreshDeviceAndOneThatSyncedOnlyBeforeTheDayReadTheWithheldVault() = world {
        val sc = ownerScene()
        val a4 = fresh("alice4", aliceMail)
        assertEquals(sc.record, a4.store.local().vaults[sc.v], "the account's record of the vault is above the restored log")
        readsAndNeverWrites("alice4 (fresh)", a4, sc.v, sc.itemId, sc.trashId, VaultLogStatus.Withheld::class, sc.bobId)
        val a2 = again(sc.a2h, aliceMail)
        readsAndNeverWrites("alice2 (synced only before the day)", a2, sc.v, sc.itemId, sc.trashId, VaultLogStatus.Withheld::class, sc.bobId)
    }

    /** (b) Then a member who never saw the lost entry makes an entry at the lost place: the same devices, and a fresh one, read the frozen vault. */
    @Test fun bAfterAnEntryAtTheLostPlaceTheOwnersDevicesReadTheFrozenVault() = world {
        val sc = ownerScene()
        val a4 = fresh("alice4", aliceMail)
        val a2 = again(sc.a2h, aliceMail)
        bobLeavesAtTheLostPlace(sc)
        a4.sync()
        a2.sync()
        readsAndNeverWrites("alice4 after the entry", a4, sc.v, sc.itemId, sc.trashId, VaultLogStatus.Frozen::class, sc.bobId)
        readsAndNeverWrites("alice2 after the entry", a2, sc.v, sc.itemId, sc.trashId, VaultLogStatus.Frozen::class, sc.bobId)
        val a5 = fresh("alice5", aliceMail)
        readsAndNeverWrites("alice5 (fresh after the entry)", a5, sc.v, sc.itemId, sc.trashId, VaultLogStatus.Frozen::class, sc.bobId)
    }

    /** (c) The device that saw the lost entry forgets the server and signs in again: it reads the vault, withheld and then frozen. */
    @Test fun cTheDeviceThatSawTheLostEntryForgetsTheServerAndReadsTheVault() = world {
        val sc = ownerScene()
        val f1 = forgetAndSignIn(sc.ah, aliceMail)
        readsAndNeverWrites("alice1 after forgetting", f1, sc.v, sc.itemId, sc.trashId, VaultLogStatus.Withheld::class, sc.bobId)
        bobLeavesAtTheLostPlace(sc)
        val f2 = forgetAndSignIn(sc.ah, aliceMail)
        readsAndNeverWrites("alice1 after the entry and forgetting again", f2, sc.v, sc.itemId, sc.trashId, VaultLogStatus.Frozen::class, sc.bobId)
    }

    /**
     * (d) A member's account. Alice makes Bob a reader after the snapshot; Bob's first device sees it and, ten minutes
     * later, writes that head into Bob's records. After the restore it writes them back (it makes a vault). Bob's fresh
     * device and his device that synced only before the day read the withheld vault; after a fresh device of Alice's makes
     * an entry at the lost place, they and another fresh device read it frozen; then Bob's first device forgets the
     * server and reads it too. None of them can write to it, and Bob's record is not lowered.
     */
    @Test fun dAMembersDevicesReadTheVaultWithheldAndFrozen() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val v = sharedVault(ah, bh, "Shared")
        val a = account(ah)
        val b = account(bh)
        val itemId = assertNotNull(a.putItem(v, doc("shared item")).first).itemId
        a.synced()
        b.synced()
        val b2h = passwordDevice("bob2", bobMail)
        account(b2h).synced()
        val snapshot = takeSnapshot()
        a.ok(v, LogAction.Role(b.userId, "reader"))
        a.synced()
        b.synced()
        server.advance(10 * 60_000L)
        b.synced()
        val record = assertNotNull(b.store.local().vaults[v], "Bob's first device recorded the head it verified")
        assertEquals(2L, record.seq)

        restored(snapshot)
        val nb = again(bh, bobMail)
        nb.ok(null, LogAction.Create("Bob's own"))
        val b3 = fresh("bob3", bobMail)
        assertEquals(record, b3.store.local().vaults[v], "Bob's record of the vault is above the restored log")
        readsAndNeverWrites("bob3 (fresh)", b3, v, itemId, null, VaultLogStatus.Withheld::class, a.userId)
        val b2 = again(b2h, bobMail)
        readsAndNeverWrites("bob2 (synced only before the day)", b2, v, itemId, null, VaultLogStatus.Withheld::class, a.userId)

        val a3 = fresh("alice3", aliceMail)
        assertIs<AppendOutcome.Appended>(a3.logs.append(v, LogAction.Role(b.userId, "reader")), "Alice's fresh device makes an entry at the lost place")
        b3.sync()
        b2.sync()
        readsAndNeverWrites("bob3 after the entry", b3, v, itemId, null, VaultLogStatus.Frozen::class, a.userId)
        readsAndNeverWrites("bob2 after the entry", b2, v, itemId, null, VaultLogStatus.Frozen::class, a.userId)
        val b4 = fresh("bob4", bobMail)
        readsAndNeverWrites("bob4 (fresh after the entry)", b4, v, itemId, null, VaultLogStatus.Frozen::class, a.userId)
        val f1 = forgetAndSignIn(bh, bobMail)
        readsAndNeverWrites("bob1 after forgetting", f1, v, itemId, null, VaultLogStatus.Frozen::class, a.userId)
        recordNotLowered("bob9", bobMail, v, record)
    }

    /**
     * (e) Another beginning. "Shared" is made after the snapshot and its record (its genesis) is written; the restore;
     * Alice's first device writes the record back. Bob then makes a vault of his own under the same id, a chain with
     * another genesis, puts an item into it and adds Alice. Alice's fresh device is given no key and reads nothing of it,
     * and her first device reads nothing of Bob's item.
     */
    @Test fun eAChainWithAnotherBeginningUnderTheVaultsIdGivesNoKey() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        connect(ah, bh, origin)
        val a = account(ah)
        val b = account(bh)
        a.synced()
        b.synced()
        val snapshot = takeSnapshot()
        val v = a.ok(null, LogAction.Create("Shared"))
        assertNotNull(a.putItem(v, doc("shared item")).first)
        a.synced()
        val record = assertNotNull(a.store.local().vaults[v], "a new vault's record is written at once")

        restored(snapshot)
        val na = again(ah, aliceMail)
        na.ok(null, LogAction.Create("Another"))
        val nb = again(bh, bobMail)
        assertEquals(v, nb.ok(null, LogAction.Create("Shared", vaultId = v)), "Bob makes a chain of his own under the vault's id")
        assertNotNull(nb.putItem(v, doc("other chain item")).first)
        nb.synced()
        nb.ok(v, LogAction.Add(a.userId, "writer"))
        nb.synced()

        val a3 = fresh("alice3", aliceMail)
        assertEquals(record.genesisHash, a3.store.local().vaults[v]?.genesisHash, "the account's record names the first beginning")
        val adoption = a3.logs.adoption(v)
        assertFalse(adoption is Adoption.Adopted, "a chain with another beginning is not adopted: $adoption")
        assertFalse(adoption is Adoption.AskAccept, "nor offered: $adoption")
        assertNull(a3.logs.keyFor(v), "no key is taken")
        assertTrue(a3.items(v).isEmpty(), "nothing of it is read: ${itemNames(a3.items(v))}")
        na.sync()
        assertFalse("other chain item" in itemNames(na.items(v)), "Alice's first device reads nothing of the other chain")
    }

    /**
     * (e) A key whose other condition fails while the record is ahead. Before the snapshot Bob is added at seq 1 and
     * accepts; after it Alice removes him and adds him again (seq 3), Bob's first device accepts that add and records head
     * 3. After the restore it writes those records back. The restored log's latest add of Bob is seq 1, which the
     * account's answer (seq 3) does not answer: condition (d) fails on both roads, so Bob's fresh device takes no key
     * although the record is ahead.
     */
    @Test fun eAKeyThatFailsAnotherConditionIsNotTakenAlthoughTheRecordIsAhead() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val v = sharedVault(ah, bh, "Shared")
        val a = account(ah)
        val b = account(bh)
        assertNotNull(a.putItem(v, doc("shared item")).first)
        a.synced()
        b.synced()
        val snapshot = takeSnapshot()
        a.ok(v, LogAction.Remove(b.userId))
        a.ok(v, LogAction.Add(b.userId, "writer"))
        accept(b, v, "Shared")
        server.advance(11 * 60_000L)
        b.synced()
        assertEquals(3L, b.store.local().vaults[v]?.seq, "Bob's first device recorded the head after the second add")
        assertEquals(3L, b.store.local().accepted[v]?.addSeq, "and his answer names that add")

        restored(snapshot)
        val nb = again(bh, bobMail)
        nb.ok(null, LogAction.Create("Bob's own"))
        val b3 = fresh("bob3", bobMail)
        assertEquals(3L, b3.store.local().vaults[v]?.seq, "the record is above the restored log")
        assertIs<VaultLogStatus.Withheld>(b3.logs.status(v), "the restored log is withheld against the record")
        val adoption = b3.logs.adoption(v)
        assertFalse(adoption is Adoption.Adopted, "a key whose source does not answer the latest add is not taken: $adoption")
        assertNull(b3.logs.keyFor(v), "no key is taken")
        assertTrue(b3.items(v).isEmpty(), "nothing is read")
        assertFalse(b3.writeAllowed(v))
    }

    /**
     * (e) A vault the person left. Bob leaves "Left" after the snapshot; ten minutes later his device records the head.
     * After the restore his first device holds the leave in the account's records (and writes them back by making a
     * vault): it reads nothing of the vault, and neither does his fresh device, which holds those records too.
     */
    @Test fun eAVaultThePersonLeftStaysClosedOnADeviceThatHoldsTheLeave() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val x = sharedVault(ah, bh, "Left")
        val a = account(ah)
        val b = account(bh)
        assertNotNull(a.putItem(x, doc("x item")).first)
        a.synced()
        b.synced()
        val snapshot = takeSnapshot()
        b.ok(x, LogAction.Leave)
        b.synced()
        server.advance(11 * 60_000L)
        b.synced()
        assertEquals("decline", b.store.local().accepted[x]?.decision, "the leave is in the account's records")

        restored(snapshot)
        val nb = again(bh, bobMail)
        // The key a leave let go of stays held for copy-out of the holding area (spec 02 §10.6); it is not adopted.
        val first = nb.logs.adoption(x)
        assertFalse(first is Adoption.Adopted, "Bob's first device does not adopt a vault he left: $first")
        assertTrue(nb.items(x).isEmpty(), "and reads nothing of it")
        assertFalse(nb.writeAllowed(x))
        nb.ok(null, LogAction.Create("Bob's own"))
        val b3 = fresh("bob3", bobMail)
        assertEquals("decline", b3.store.local().accepted[x]?.decision, "the fresh device holds the leave")
        val adoption = b3.logs.adoption(x)
        assertFalse(adoption is Adoption.Adopted, "a vault the person left is not adopted: $adoption")
        assertNull(b3.logs.keyFor(x), "no key is taken")
        assertTrue(b3.items(x).isEmpty(), "nothing is read")
        assertFalse(b3.writeAllowed(x))
    }

    /** (e) A device of an account with no record of the vault: a share not answered yet is asked, as before; no key is taken. */
    @Test fun eADeviceWithNoRecordOfTheVaultIsAskedAsBefore() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        connect(ah, bh, origin)
        val a = account(ah)
        a.synced()
        val b = account(bh)
        val v = a.ok(null, LogAction.Create("Asked"))
        a.ok(v, LogAction.Add(b.userId, "writer"))
        b.synced()
        assertNull(b.store.local().vaults[v], "the account has no record of the vault")
        assertIs<Adoption.AskAccept>(b.logs.adoption(v), "the share is asked, as before")
        assertNull(b.logs.keyFor(v), "no key is taken before the answer")
        assertFalse(b.writeAllowed(v))
    }

    /**
     * (e) The grant road. Alice adds Bob before the snapshot, and Bob has not answered yet. After it Bob accepts (his first
     * device records his answer and posts his own wrap of the key) and Alice makes him a reader (seq 2), which his first
     * device records. The restore loses the answer, the wrap and the entry; the restored server still holds Alice's grant
     * to Bob. Bob's first device signs in again and, before any sync, makes a vault of his own, which writes his records
     * back. His fresh device, once the person ticks Alice on its one-tap list, takes the key through Alice's grant
     * read-only: it reads the withheld vault and cannot write to it.
     */
    @Test fun eAMembersFreshDeviceTakesTheKeyThroughTheGrantReadOnly() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        connect(ah, bh, origin)
        val a = account(ah)
        val b = account(bh)
        a.synced()
        val v = a.ok(null, LogAction.Create("Shared"))
        val itemId = assertNotNull(a.putItem(v, doc("shared item")).first).itemId
        a.ok(v, LogAction.Add(b.userId, "writer"))
        a.synced()
        b.synced()
        assertNull(b.logs.keyFor(v), "Bob has not answered the share yet")
        val snapshot = takeSnapshot()
        accept(b, v, "Shared")
        a.ok(v, LogAction.Role(b.userId, "reader"))
        a.synced()
        b.synced()
        server.advance(11 * 60_000L)
        b.synced()
        val record = assertNotNull(b.store.local().vaults[v], "Bob's first device recorded the head it verified")
        assertEquals(2L, record.seq)
        assertEquals(1L, b.store.local().accepted[v]?.addSeq, "and his answer names the add")

        restored(snapshot)
        runCatching { bh.account(origin)?.sync() }
        if (bh.account(origin) == null) signIn(bh, bobMail)
        account(bh).ok(null, LogAction.Create("Bob's own"))

        val b3 = fresh("bob3", bobMail)
        assertEquals(record, b3.store.local().vaults[v], "Bob's record of the vault is above the restored log")
        assertEquals(1L, b3.store.local().accepted[v]?.addSeq, "and his answer is back")
        val row = assertNotNull(b3.grant(v), "the restored server lists Bob's grant row")
        assertTrue(row.wrappedVk.isEmpty(), "the restored server holds no wrap of Bob's own: ${row.wrappedVk}")
        assertNotNull(row.signedGrant, "it holds Alice's grant")
        assertIs<VaultLogStatus.Withheld>(b3.logs.status(v), "the restored log is withheld against the record")
        assertIs<Adoption.ConnectFirst>(b3.logs.adoption(v), "the grant's sender is not current on the fresh device yet")
        assertNull(b3.logs.keyFor(v))
        assertTrue(b3.contacts.confirmOneTap(setOf(a.userId)), "the person ticks Alice on the one-tap list")
        assertEquals(Adoption.Adopted(v, KeySource.GRANT), b3.logs.adoption(v), "the key is taken through Alice's grant, read-only")
        b3.sync()
        readsAndNeverWrites("bob3 (fresh, through the grant)", b3, v, itemId, null, VaultLogStatus.Withheld::class, a.userId)
    }

    /**
     * Filling in (decided ahead of the owner's decision: a withheld vault is not filled from, like a frozen one). The owner's
     * fresh device of (a) holds the withheld vault's key and reads its login, which has an address; its content offers
     * nothing of it for filling in, releases nothing of it, and records no use of it. Its own vault is filled from.
     */
    @Test fun aTheOwnersFreshDeviceFillsNothingFromTheWithheldVault() = world {
        val sc = ownerScene(loginAt("shared item", "https://shared.example.org/login"))
        val a4 = fresh("alice4", aliceMail)
        assertIs<VaultLogStatus.Withheld>(a4.logs.status(sc.v))
        assertNotNull(a4.logs.keyFor(sc.v), "the withheld vault's key is held")
        val uses = ArrayList<String>()
        val c = EngineVaultContent(a4.items, a4.host.crypto, object : ContentHost {
            override fun wallMs(): Long = server.now()
            override fun attachmentLimits() = AttachmentRules.limits(null, null)
            override fun origin(): String = a4.origin
            override fun userId(): String = a4.userId
            override fun accountId(): String = "0123456789abcdef0123456789abcdef"
            override fun backupKdfParams(): KdfParams? = null
            override fun recordUse(itemId: String, atMs: Long) {
                uses += itemId
            }
        })
        assertEquals(ActionResult.Ok, c.refresh())
        assertTrue(c.state.items.any { it.itemId == sc.itemId }, "the withheld vault's login is listed")
        assertNotNull(c.itemDetail(sc.itemId), "and opens")
        assertTrue(c.fillLogins(listOf("shared.example.org")).none { it.itemId == sc.itemId }, "it is not offered for its address")
        assertTrue(c.fillLogins(emptyList()).none { it.itemId == sc.itemId }, "nor among every login")
        assertNull(c.fillCredential(sc.itemId), "nothing of it is released to a fill")
        assertFalse(c.fillMatches(sc.itemId, listOf("https://shared.example.org/login")), "it matches nothing")
        assertFalse(c.recordFillPicked(sc.itemId), "a pick of it is not recorded")
        assertTrue(uses.isEmpty(), "no use of it is recorded: $uses")
        val personal = assertNotNull(a4.personalVaultId)
        assertEquals(ActionResult.Ok, c.saveLogin(null, LoginInput("own login", "me", "pw-own", listOf("https://own.example.org"), "", "", false), personal))
        val own = c.state.items.single { it.name == "own login" }.itemId
        assertTrue(c.fillLogins(listOf("own.example.org")).any { it.itemId == own }, "the person's own vault is filled from")
        assertEquals("pw-own", c.fillCredential(own)?.password)
        c.close()
    }

    /** A restart of the owner's fresh device that took the key read-only: not writable before a sync, and after one it reads the vault, still withheld. */
    @Test fun aRestartKeepsTheWithheldVaultReadOnly() = world {
        val sc = ownerScene()
        val a4 = fresh("alice4", aliceMail)
        assertIs<VaultLogStatus.Withheld>(a4.logs.status(sc.v))
        assertNotNull(a4.logs.keyFor(sc.v), "the key is held before the restart")
        val s = account(restarted(a4.host))
        assertFalse(s.writeAllowed(sc.v), "not writable after a restart")
        assertFalse(s.logs.status(sc.v) is VaultLogStatus.Verified, "not verified after a restart: ${s.logs.status(sc.v)}")
        s.sync()
        assertIs<VaultLogStatus.Withheld>(s.logs.status(sc.v), "still withheld after a restart and a sync")
        assertNotNull(s.logs.keyFor(sc.v), "the key is held again: ${s.logs.adoption(sc.v)}")
        assertEquals(setOf("shared item"), itemNames(s.items(sc.v)), "the vault's items are read")
        assertFalse(s.writeAllowed(sc.v), "not writable after a restart and a sync")
        assertFalse(s.logs.writeAllowed(sc.v))
    }

    /**
     * No restore: an honest entry by one device of the account, whose record it writes ten minutes later, leaves the
     * account's other device verified and writable after one sync, never withheld.
     */
    @Test fun anHonestEntryByAnotherDeviceOfTheAccountLeavesNoVaultWithheld() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val v = sharedVault(ah, bh, "Shared")
        val a = account(ah)
        val b = account(bh)
        assertNotNull(a.putItem(v, doc("shared item")).first)
        a.synced()
        val a2 = account(passwordDevice("alice2", aliceMail))
        a2.synced()
        assertEquals(1L, assertIs<VaultLogStatus.Verified>(a2.logs.status(v)).state.headSeq)
        a.ok(v, LogAction.Role(b.userId, "reader"))
        server.advance(11 * 60_000L)
        a.synced()
        assertEquals(2L, a.store.local().vaults[v]?.seq, "Alice's first device recorded the new head")
        a2.sync()
        assertEquals(2L, assertIs<VaultLogStatus.Verified>(a2.logs.status(v), "verified after one sync: ${a2.logs.status(v)}").state.headSeq)
        assertTrue(a2.writeAllowed(v), "and writable")
    }

    /** (g) After the owner's whole course (the record written back, an entry at the lost place, a forget), the record is not lowered. */
    @Test fun gTheAccountsRecordIsNeverLowered() = world {
        val sc = ownerScene()
        val a4 = fresh("alice4", aliceMail)
        val a2 = again(sc.a2h, aliceMail)
        bobLeavesAtTheLostPlace(sc)
        a4.sync()
        a2.sync()
        sc.na.sync()
        val f1 = forgetAndSignIn(sc.ah, aliceMail)
        f1.ok(null, LogAction.Create("After forgetting"))
        a4.ok(null, LogAction.Create("From alice4"))
        recordNotLowered("alice9", aliceMail, sc.v, sc.record)
    }
}
