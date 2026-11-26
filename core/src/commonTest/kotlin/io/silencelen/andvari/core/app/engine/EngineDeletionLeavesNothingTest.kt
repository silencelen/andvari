package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.DeletionResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.RecoveryChangeResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.items.ItemCacheNames
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * After a confirmed deletion this device is as new for that server: everything "Forget this server" removes goes with
 * the account, the pin and the address among it, the notice is built before the pin goes, and the landing is the first
 * screen. Another server known here keeps everything. After a deletion whose outcome is not known, the device offers to
 * forget the account, only behind the person's confirmation, and then removes exactly that account.
 */
class EngineDeletionLeavesNothingTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    private class Files : VaultCacheFiles {
        val deleted = ArrayList<String>()
        override fun open(fileName: String, userId: String): VaultCache = InMemoryVaultCache()
        override fun delete(fileName: String): Boolean {
            deleted += fileName
            return true
        }
    }

    private class Env(val app: EngineAppApi, val state: MemoryDeviceState, val secure: MemoryDeviceState, val files: Files)

    private fun env(vararg servers: FakeInstance, state: MemoryDeviceState = MemoryDeviceState(), secure: MemoryDeviceState = MemoryDeviceState(), files: Files = Files()): Env {
        val first = servers.first()
        val app = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(servers.associateBy { it.origin }), state, secure,
                crypto, { first.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined,
                work = Dispatchers.Unconfined, cacheFiles = files, keepsAtRest = { true }),
        ).also { it.start() }
        return Env(app, state, secure, files)
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    /** A registration of [email] at [address] with its first kit confirmed: the vault is open. */
    private suspend fun register(a: EngineAppApi, address: String, email: String) {
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), address))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), email, true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "Alice", strong, true)))
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    private fun preview(s: FakeInstance) {
        s.override[WireRoute.ACCOUNT_DELETE_PREVIEW] = WireResult.Ok(
            """{"blockers":[],"deletedVaults":[],"leftVaults":[],"memberships":[],"totpRequired":false}""", 200)
    }

    private fun keysOf(store: MemoryDeviceState, origin: String): List<String> = store.keys().filter { origin in it }.sorted()

    @Test fun aConfirmedDeletionLeavesThisDeviceAsNewForThatServerAndKeepsAnotherServer() = runBlocking<Unit> {
        val home = FakeInstance(crypto)
        val other = FakeInstance(crypto, origin = "https://other.example", instanceId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd")
        val e = env(home, other)
        val a = e.app
        // Another server known here, with an account signed out of it: its pin stays.
        register(a, "other.example", "bob@example.com")
        assertEquals(PlainResult.DONE, a.signOutConfirmed(assertNotNull(a.signOutCheck())))
        register(a, "h.example", "alice@example.com")
        val userId = assertNotNull(a.keeper.session).userId
        val name = ItemCacheNames.fileName(crypto, home.origin, userId)
        val label = assertNotNull(a.snapshot.instance).label
        // A kit made in Settings and never confirmed: its mark is a record of that server.
        assertEquals(RecoveryChangeResult.DONE, a.recovery.makeKit(strong))
        assertTrue(keysOf(e.state, home.origin).isNotEmpty())
        val otherKept = keysOf(e.state, other.origin)
        assertTrue(otherKept.isNotEmpty())

        e.files.deleted.clear()
        preview(home)
        home.override[WireRoute.ACCOUNT_DELETE] = WireResult.Ok("""{"deletedAt":1}""", 200)
        assertEquals(PlainResult.DONE, a.settings.openDeletion())
        assertEquals(DeletionResult.DONE, a.settings.deleteAccount(assertNotNull(a.snapshot.account!!.deletion), "alice@example.com", strong, null))

        // The landing is the first screen, which says it once, naming the server as this device knew it.
        assertEquals(AppPhase.ENTRY, a.snapshot.phase)
        val first = a.at<EntryScreen.FirstRun>()
        val said = assertNotNull(first.accountDeleted)
        assertEquals(CopyKey.ACCOUNT_DELETED_SERVER_FORGOTTEN, said.line.key)
        assertEquals(listOf("alice@example.com", label.name, home.origin), said.line.values)
        assertNull(a.snapshot.instance)
        // Nothing of that server stays: its pin, its address and every record kept under it (before: the pin and the
        // records of the server stayed, so the server was still known here).
        assertEquals(PinState.None, a.trust.pinState(home.origin))
        assertEquals(emptyList(), keysOf(e.state, home.origin))
        assertEquals(emptyList(), keysOf(e.secure, home.origin))
        // Every key and every value of both stores, not only the keys that hold the server's address: nothing names the
        // server, the account's user id or its address any more (records keyed by user id, marks kept as values).
        for ((which, store) in listOf("state" to e.state, "secure" to e.secure)) {
            val left = store.keys().sorted().map { it to store.get(it).orEmpty() }.filter { (k, v) ->
                listOf(home.origin, "h.example", userId, "alice@example.com").any { it in k || it in v }
            }
            assertEquals(emptyList(), left, "$which: every key and value")
        }
        assertEquals(listOf(name), e.files.deleted, "the copy goes once, as the deletion's own")
        assertNull(a.keeper.knownIdentity(userId))
        // The other server is untouched.
        assertIs<PinState.Pinned>(a.trust.pinState(other.origin))
        assertEquals(otherKept, keysOf(e.state, other.origin))

        // Using the server again starts as on a new device: its Trust Gate.
        a.entry.dismissNotice(first)
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        a.at<EntryScreen.TrustGate>()
    }

    /**
     * A confirmed deletion never takes another account's copy with it unsaid: where this device holds another account's
     * copy at that server (here: its session record lost, its copy left), only the deleted account's records go, the
     * server stays known with the other account's copy, and the line says so. Before: the server's forgetting deleted the
     * other copy without a word.
     */
    @Test fun aConfirmedDeletionKeepsTheServerAndAnotherAccountsCopyHeldThereAndSaysSo() = runBlocking<Unit> {
        val home = FakeInstance(crypto)
        val first = env(home)
        register(first.app, "h.example", "bob@example.com")
        val bob = assertNotNull(first.app.keeper.session).userId
        val bobsFile = ItemCacheNames.fileName(crypto, home.origin, bob)
        first.app.lock()
        first.app.close()
        // The platform lost Bob's session record; his copy and its kept records are still held here.
        first.secure.set(io.silencelen.andvari.core.client.session.SessionKeeper.KEY, null)
        val e = env(home, state = first.state, secure = first.secure, files = first.files)
        val a = e.app
        assertNull(a.keeper.session)
        register(a, "h.example", "alice@example.com")
        val alice = assertNotNull(a.keeper.session).userId
        e.files.deleted.clear()
        preview(home)
        home.override[WireRoute.ACCOUNT_DELETE] = WireResult.Ok("""{"deletedAt":1}""", 200)
        assertEquals(PlainResult.DONE, a.settings.openDeletion())
        assertEquals(DeletionResult.DONE, a.settings.deleteAccount(assertNotNull(a.snapshot.account!!.deletion), "alice@example.com", strong, null))

        val said = assertNotNull(a.at<EntryScreen.FirstRun>().accountDeleted)
        assertFalse(said.serverForgotten)
        assertEquals(CopyKey.ACCOUNT_DELETED_SERVER_KEPT, said.line.key, "never 'the server was forgotten too'")
        assertIs<PinState.Pinned>(a.trust.pinState(home.origin), "the server stays known")
        assertTrue(bobsFile !in e.files.deleted, "Bob's copy stays: ${e.files.deleted}")
        // Alice's copy goes once, as the deletion's own (before: a second time, as a forgetting of the server).
        assertEquals(listOf(ItemCacheNames.fileName(crypto, home.origin, alice)), e.files.deleted)
        assertTrue(e.state.get(EngineAppApi.HELD_KEY).orEmpty().contains(bob), "and stays held")
        for ((which, store) in listOf("state" to e.state, "secure" to e.secure)) {
            val left = store.keys().sorted().map { it to store.get(it).orEmpty() }.filter { (k, v) ->
                listOf(alice, "alice@example.com").any { it in k || it in v }
            }
            assertEquals(emptyList(), left, "$which: nothing of Alice's account")
        }
    }

    /**
     * The line after a confirmed deletion that kept the server, read for each kind of thing of another account this device
     * keeps there, each alone: a record of its identity key, a device's row for its address, its address's record, a record
     * kept under its id at that server. None is a copy, and the line claims none. (Its copy held:
     * [aConfirmedDeletionKeepsTheServerAndAnotherAccountsCopyHeldThereAndSaysSo].)
     */
    @Test fun theServerKeptLineIsSaidForEachKindOfThingOfAnotherAccountKeptThere() = runBlocking<Unit> {
        val other = "99999999-9999-4999-8999-999999999999"
        val kinds = listOf<(String) -> String>(
            { o -> io.silencelen.andvari.core.client.session.SessionKeeper.EARLIER_IDENTITY_PREFIX + o + "|" + other },
            { o -> "ovh.dev|$o|bob@example.com" },
            { o -> io.silencelen.andvari.core.client.session.SessionKeeper.EMAIL_BINDING_PREFIX + o + "|bob@example.com" },
            { o -> io.silencelen.andvari.core.client.pin.PinStore.originKeyed().first { EngineAppApi.FORGOTTEN_PER_ORIGIN[it] != false } + o + "|" + other },
        )
        for (kind in kinds) {
            val home = FakeInstance(crypto)
            val e = env(home)
            val a = e.app
            register(a, "h.example", "alice@example.com")
            val planted = kind(home.origin)
            e.state.set(planted, "1")
            preview(home)
            home.override[WireRoute.ACCOUNT_DELETE] = WireResult.Ok("""{"deletedAt":1}""", 200)
            assertEquals(PlainResult.DONE, a.settings.openDeletion())
            assertEquals(DeletionResult.DONE, a.settings.deleteAccount(assertNotNull(a.snapshot.account!!.deletion), "alice@example.com", strong, null))
            val said = assertNotNull(a.at<EntryScreen.FirstRun>().accountDeleted)
            assertFalse(said.serverForgotten, planted)
            assertEquals(CopyKey.ACCOUNT_DELETED_SERVER_KEPT, said.line.key, planted)
            assertIs<PinState.Pinned>(a.trust.pinState(home.origin), "the server stays known: $planted")
            assertEquals("1", e.state.get(planted), "what was kept of the other account stays: $planted")
        }
    }

    /**
     * A confirmed deletion forgets the server only where this device keeps nothing of another account there: another
     * account that merely signed out here keeps its device row and its address's record, the server stays known, and the
     * line says so. Before: the server's forgetting took them unsaid, and that account met the server as a new device.
     */
    @Test fun aConfirmedDeletionKeepsTheServerWhereAnotherAccountSignedOutThereAndSaysSo() = runBlocking<Unit> {
        val home = FakeInstance(crypto)
        val e = env(home)
        val a = e.app
        register(a, "h.example", "bob@example.com")
        assertEquals(PlainResult.DONE, a.signOutConfirmed(assertNotNull(a.signOutCheck())))
        val bobsRow = "ovh.dev|${home.origin}|bob@example.com"
        val bobsAddress = io.silencelen.andvari.core.client.session.SessionKeeper.EMAIL_BINDING_PREFIX + home.origin + "|bob@example.com"
        val bobsRecords = e.state.keys().filter { "bob@example.com" in it }.sorted()
        assertTrue(bobsRow in bobsRecords && bobsAddress in bobsRecords, "kept after the sign-out: $bobsRecords")
        register(a, "h.example", "alice@example.com")
        val alice = assertNotNull(a.keeper.session).userId
        preview(home)
        home.override[WireRoute.ACCOUNT_DELETE] = WireResult.Ok("""{"deletedAt":1}""", 200)
        assertEquals(PlainResult.DONE, a.settings.openDeletion())
        assertEquals(DeletionResult.DONE, a.settings.deleteAccount(assertNotNull(a.snapshot.account!!.deletion), "alice@example.com", strong, null))

        val said = assertNotNull(a.at<EntryScreen.FirstRun>().accountDeleted)
        assertFalse(said.serverForgotten)
        assertEquals(CopyKey.ACCOUNT_DELETED_SERVER_KEPT, said.line.key)
        assertIs<PinState.Pinned>(a.trust.pinState(home.origin), "the server stays known")
        assertEquals(bobsRecords, e.state.keys().filter { "bob@example.com" in it }.sorted(), "Bob's records stay")
        for ((which, store) in listOf("state" to e.state, "secure" to e.secure)) {
            val left = store.keys().sorted().map { it to store.get(it).orEmpty() }.filter { (k, v) ->
                listOf(alice, "alice@example.com").any { it in k || it in v }
            }
            assertEquals(emptyList(), left, "$which: nothing of Alice's account")
        }
    }

    @Test fun anUnknownOutcomeOffersToForgetTheAccountOnlyBehindTheConfirmationAndRemovesExactlyIt() = runBlocking<Unit> {
        val home = FakeInstance(crypto)
        val e = env(home)
        val a = e.app
        assertNull(a.forgetAfterUnknownDeletionCheck(), "no deletion: nothing is offered")
        register(a, "h.example", "alice@example.com")
        assertNull(a.forgetAfterUnknownDeletionCheck())
        val userId = assertNotNull(a.keeper.session).userId
        val name = ItemCacheNames.fileName(crypto, home.origin, userId)
        e.files.deleted.clear()
        preview(home)
        assertEquals(PlainResult.DONE, a.settings.openDeletion())
        home.override[WireRoute.ACCOUNT_DELETE] = WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
        assertEquals(DeletionResult.OUTCOME_UNKNOWN, a.settings.deleteAccount(assertNotNull(a.snapshot.account!!.deletion), "alice@example.com", strong, null))

        // A change to a shared vault that the account signed and that waits to be sent (the engine's record of it, and its
        // index), beside what the engine verified of that vault's log.
        val pendingKey = io.silencelen.andvari.core.client.log.StoredVaultLogs.recordKey(userId, "v1", "pending")
        val stateKey = io.silencelen.andvari.core.client.log.StoredVaultLogs.recordKey(userId, "v1", "state")
        e.state.set(pendingKey, "signed")
        e.state.set("ovh.log|$userId|pending-index", "v1")
        e.state.set(stateKey, "verified")

        // The offer, on the deletion screen and on the lock screen, the same object while it holds; nothing goes by itself.
        val offer = assertNotNull(a.forgetAfterUnknownDeletionCheck())
        assertSame(offer, a.forgetAfterUnknownDeletionCheck())
        assertEquals("alice@example.com", offer.email)
        assertEquals(home.origin, offer.instance.origin)
        assertEquals(CopyKey.DELETION_UNKNOWN_FORGET_OFFER, offer.offerLine.key)
        assertEquals(CopyKey.DELETION_UNKNOWN_FORGET_CONFIRM, offer.confirmLine.key)
        // The confirmation says what goes that was not sent, as a sign-out does: here the change to the shared vault.
        assertEquals(1, offer.unsentChanges)
        assertEquals(CopyKey.DELETION_UNKNOWN_FORGET_ONE_UNSENT, offer.unsentLine.key)
        a.lock()
        assertTrue(assertNotNull(a.snapshot.locked).deletionOutcomeUnknown)
        // Locked, the copy cannot be counted: said as that, never as none (a new offer, since what it says changed).
        val lockedOffer = assertNotNull(a.forgetAfterUnknownDeletionCheck())
        assertNull(lockedOffer.unsentChanges)
        assertEquals(CopyKey.DELETION_UNKNOWN_FORGET_UNSENT_CANNOT_TELL, lockedOffer.unsentLine.key)
        assertSame(lockedOffer, a.forgetAfterUnknownDeletionCheck())
        assertEquals(PlainResult.STALE, a.forgetAfterUnknownDeletion(offer), "the offer shown before the lock no longer holds")
        assertNotNull(a.keeper.session)
        assertEquals(emptyList(), e.files.deleted)

        // An offer that no longer holds does nothing.
        val stale = io.silencelen.andvari.core.app.ForgetUnknownDeletion("alice@example.com", offer.instance, home.origin, userId)
        assertEquals(PlainResult.STALE, a.forgetAfterUnknownDeletion(stale))
        assertNotNull(a.keeper.session)

        home.calls.clear()
        assertEquals(PlainResult.DONE, a.forgetAfterUnknownDeletion(lockedOffer))
        // The signed change not sent goes with its index; what the engine verified of the vault stays, as at a sign-out.
        assertNull(e.state.get(pendingKey))
        assertNull(e.state.get("ovh.log|$userId|pending-index"))
        assertEquals("verified", e.state.get(stateKey))
        assertEquals(AppPhase.ENTRY, a.snapshot.phase)
        assertNull(a.keeper.session)
        // The account's key record stays, as at a sign-out: the account may still exist (decided on 2026-11-19).
        assertNotNull(a.keeper.knownIdentity(userId))
        assertEquals(listOf(name), e.files.deleted)
        assertFalse(a.accountSettingsPart.deletionOutcomeUnknown(home.origin, userId))
        assertNull(a.forgetAfterUnknownDeletionCheck())
        // The server is kept (the account may still be there), and the session's end was sent to it.
        assertIs<PinState.Pinned>(a.trust.pinState(home.origin))
        assertEquals(1, home.calls.count { it == WireRoute.END_SESSION }, "sent: ${home.calls}")
        assertEquals(PlainResult.STALE, a.forgetAfterUnknownDeletion(lockedOffer), "once")
    }

    /**
     * The forgetting after a deletion of unknown outcome counts exactly the signed changes it removes: records its index
     * does not name (a store written part-way) are counted, and an index entry with no record is not. Before: the index
     * alone was counted (here two said, three went).
     */
    @Test fun theForgettingCountsExactlyTheSignedChangesItRemoves() = runBlocking<Unit> {
        val home = FakeInstance(crypto)
        val e = env(home)
        val a = e.app
        register(a, "h.example", "alice@example.com")
        val userId = assertNotNull(a.keeper.session).userId
        preview(home)
        assertEquals(PlainResult.DONE, a.settings.openDeletion())
        home.override[WireRoute.ACCOUNT_DELETE] = WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
        assertEquals(DeletionResult.OUTCOME_UNKNOWN, a.settings.deleteAccount(assertNotNull(a.snapshot.account!!.deletion), "alice@example.com", strong, null))
        fun pending(v: String) = io.silencelen.andvari.core.client.log.StoredVaultLogs.recordKey(userId, v, "pending")
        for (v in listOf("v1", "v2", "v4")) e.state.set(pending(v), "signed")
        e.state.set("ovh.log|$userId|pending-index", "v1,v3")

        val offer = assertNotNull(a.forgetAfterUnknownDeletionCheck())
        assertEquals(3, offer.unsentChanges, "v1, v2 and v4 go; v3 has nothing to send")
        assertEquals(CopyKey.DELETION_UNKNOWN_FORGET_UNSENT, offer.unsentLine.key)
        assertEquals(PlainResult.DONE, a.forgetAfterUnknownDeletion(offer))
        assertEquals(emptyList(), e.state.keys().filter { it.startsWith("ovh.log|$userId|") && "pending" in it })
    }

    private fun fakeAt(scene: io.silencelen.andvari.core.app.fake.FakeScene) = io.silencelen.andvari.core.app.fake.FakeScenes.at(scene)

    /**
     * The fake follows the engine where a confirmed deletion keeps the server because another account is known there: the
     * notice says the server was kept, with its own line, and the server stays known. Before: the fake always forgot it.
     */
    @Test fun theFakeKeepsTheServerAfterADeletionAsTheEngineDoes() = runBlocking<Unit> {
        fun read(said: io.silencelen.andvari.core.app.AccountDeletedNotice, pinned: Boolean) =
            listOf(said.serverForgotten, said.line.key, said.line.values.size, pinned)

        val home = FakeInstance(crypto)
        val a = env(home).app
        register(a, "h.example", "bob@example.com")
        assertEquals(PlainResult.DONE, a.signOutConfirmed(assertNotNull(a.signOutCheck())))
        register(a, "h.example", "alice@example.com")
        preview(home)
        home.override[WireRoute.ACCOUNT_DELETE] = WireResult.Ok("""{"deletedAt":1}""", 200)
        assertEquals(PlainResult.DONE, a.settings.openDeletion())
        assertEquals(DeletionResult.DONE, a.settings.deleteAccount(assertNotNull(a.snapshot.account!!.deletion), "alice@example.com", strong, null))
        val engine = read(assertNotNull(a.at<EntryScreen.FirstRun>().accountDeleted), a.trust.pinState(home.origin) is PinState.Pinned)

        val f = fakeAt(io.silencelen.andvari.core.app.fake.FakeScene.DELETION)
        f.script.anotherAccountKnownAtServer = true
        val origin = assertNotNull(f.snapshot.instance).label.origin
        assertEquals(DeletionResult.DONE, f.settings.deleteAccount(assertNotNull(f.snapshot.account!!.deletion),
            io.silencelen.andvari.core.app.fake.FakeScenes.EMAIL, io.silencelen.andvari.core.app.fake.FakeScenes.PASSWORD, null))
        val fake = read(assertNotNull(assertIs<EntryScreen.FirstRun>(f.snapshot.entry).accountDeleted), f.pins.containsKey(origin))

        assertEquals(listOf<Any>(false, CopyKey.ACCOUNT_DELETED_SERVER_KEPT, 3, true), engine)
        assertEquals(engine, fake)
    }

    /**
     * The fake follows the engine for the forgetting after a deletion of unknown outcome: the confirmation counts the
     * change not sent while the account is open, a lock makes a new confirmation that cannot tell, the one shown before
     * no longer holds, and the new one forgets. Before: the fake never counted, and kept the same object across the lock.
     */
    @Test fun theFakeCountsAndRenewsTheForgettingAsTheEngineDoes() = runBlocking<Unit> {
        val home = FakeInstance(crypto)
        val e = env(home)
        val a = e.app
        register(a, "h.example", "alice@example.com")
        val userId = assertNotNull(a.keeper.session).userId
        preview(home)
        assertEquals(PlainResult.DONE, a.settings.openDeletion())
        home.override[WireRoute.ACCOUNT_DELETE] = WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
        assertEquals(DeletionResult.OUTCOME_UNKNOWN, a.settings.deleteAccount(assertNotNull(a.snapshot.account!!.deletion), "alice@example.com", strong, null))
        // One change not sent: here a signed change to a shared vault, as the engine keeps it.
        e.state.set(io.silencelen.andvari.core.client.log.StoredVaultLogs.recordKey(userId, "v1", "pending"), "signed")
        e.state.set("ovh.log|$userId|pending-index", "v1")
        val engine = Readings()
        val offer =assertNotNull(a.forgetAfterUnknownDeletionCheck())
        engine += offer.unsentLine.key
        engine += (a.forgetAfterUnknownDeletionCheck() === offer)
        a.lock()
        val locked = assertNotNull(a.forgetAfterUnknownDeletionCheck())
        engine += listOf(locked !== offer, locked.unsentLine.key, a.forgetAfterUnknownDeletionCheck() === locked)
        engine += a.forgetAfterUnknownDeletion(offer)
        engine += a.forgetAfterUnknownDeletion(locked)
        engine += a.snapshot.phase

        val f = fakeAt(io.silencelen.andvari.core.app.fake.FakeScene.DELETION)
        // One change not sent: here a save made offline, as the fake keeps it.
        val c = assertNotNull(f.fakeContent)
        c.setOffline(true)
        assertEquals(io.silencelen.andvari.core.app.ActionResult.Ok,
            c.saveLogin(null, io.silencelen.andvari.core.app.LoginInput("Bank", "me", "pw-bank", listOf("https://bank.test"), "", "", false), null))
        f.script.deletionAnswerLost = true
        assertEquals(DeletionResult.OUTCOME_UNKNOWN, f.settings.deleteAccount(assertNotNull(f.snapshot.account!!.deletion),
            io.silencelen.andvari.core.app.fake.FakeScenes.EMAIL, io.silencelen.andvari.core.app.fake.FakeScenes.PASSWORD, null))
        val fake = Readings()
        val fOffer = assertNotNull(f.forgetAfterUnknownDeletionCheck())
        fake += fOffer.unsentLine.key
        fake += (f.forgetAfterUnknownDeletionCheck() === fOffer)
        f.lock()
        val fLocked = assertNotNull(f.forgetAfterUnknownDeletionCheck())
        fake += listOf(fLocked !== fOffer, fLocked.unsentLine.key, f.forgetAfterUnknownDeletionCheck() === fLocked)
        fake += f.forgetAfterUnknownDeletion(fOffer)
        fake += f.forgetAfterUnknownDeletion(fLocked)
        fake += f.snapshot.phase

        assertEquals<List<Any?>>(listOf(CopyKey.DELETION_UNKNOWN_FORGET_ONE_UNSENT, true,
            listOf(true, CopyKey.DELETION_UNKNOWN_FORGET_UNSENT_CANNOT_TELL, true), PlainResult.STALE, PlainResult.DONE, AppPhase.ENTRY), engine)
        assertEquals<List<Any?>>(engine, fake)
    }
}
