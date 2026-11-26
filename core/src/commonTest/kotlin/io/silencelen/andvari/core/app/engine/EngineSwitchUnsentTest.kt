package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.InviteResult
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.OpenedInvite
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.ProofResult
import io.silencelen.andvari.core.app.SendFirstResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.link.CreateOutcome
import io.silencelen.andvari.core.client.link.LinkPerson
import io.silencelen.andvari.core.client.link.LinkServer
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.MutationOp
import io.silencelen.andvari.core.model.wire.MutationResult
import io.silencelen.andvari.core.model.wire.MutationStatus
import io.silencelen.andvari.core.model.wire.PushRequest
import io.silencelen.andvari.core.model.wire.PushResponse
import io.silencelen.andvari.core.model.wire.SyncItem
import io.silencelen.andvari.core.model.wire.SyncResponse
import io.silencelen.andvari.core.model.wire.SyncVault
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * "Switch to …" for an invite of another server is a sign-out (design §6.7, §4.4), so it deletes this device's copy: with
 * changes made here that were not sent, it needs the person's second confirmation, offers to send them first, and its
 * line says whether signing in again here will bring the account back (rule of 2026-11-17). Before, the switch signed out
 * over them without a word.
 */
class EngineSwitchUnsentTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    /** The item plane of an honest server for the accounts of [instance] (each one's personal vault and its items); [down]: no answer. */
    private class Items(private val instance: FakeInstance) {
        var down = false
        var rev = 1L
        val items = ArrayList<SyncItem>()

        fun <T> answer(route: WireRoute, query: String?, bodyJson: String?, caller: String?, decode: (String) -> T): WireResult<T>? = when (route) {
            WireRoute.SYNC -> if (down) WireResult.NoAnswer(NoAnswerKind.TRANSPORT) else {
                val since = query?.substringAfter("since=")?.toLongOrNull() ?: 0L
                val pv = instance.accounts.values.firstOrNull { it.userId == caller }?.personalWrap?.vaultId
                val vaults = pv?.let { listOf(SyncVault(it, "personal", 1, "", instance.now)) }.orEmpty()
                val r = SyncResponse(rev, since == 0L, vaults, emptyList(), items.filter { it.rev > since }, emptyList(), emptyList(), 0, 0)
                WireResult.Ok(decode(WireJson.json.encodeToString(SyncResponse.serializer(), r)), 200)
            }
            WireRoute.PUSH -> if (down) WireResult.NoAnswer(NoAnswerKind.TRANSPORT) else {
                val b = WireJson.json.decodeFromString(PushRequest.serializer(), bodyJson!!)
                val results = b.mutations.map { m ->
                    rev++
                    items.removeAll { it.itemId == m.itemId }
                    val up = m.item
                    items += SyncItem(m.itemId, m.vaultId, rev, instance.now, instance.now, m.op == MutationOp.DELETE, false,
                        up?.formatVersion ?: 1, up?.attachmentIds.orEmpty(), up?.blob)
                    MutationResult(m.mutationId, MutationStatus.APPLIED, rev)
                }
                WireResult.Ok(decode(WireJson.json.encodeToString(PushResponse.serializer(), PushResponse(rev, results))), 200)
            }
            else -> null
        }
    }

    /** Cache files in memory that answer as durable, as the SQLite file does: a change made offline is queued in them. */
    private class DurableFiles : VaultCacheFiles {
        private val caches = HashMap<String, VaultCache>()
        override fun open(fileName: String, userId: String): VaultCache =
            caches.getOrPut(fileName) { object : VaultCache by InMemoryVaultCache() { override val durable: Boolean get() = true } }
        override fun delete(fileName: String): Boolean {
            caches.remove(fileName)
            return true
        }
    }

    /** [home] is the server the app is signed in to, with an item plane ([items]); [other] the invite's. */
    private class World(val home: LinkServer, val other: LinkServer, val items: Items, val alice: LinkPerson, val carol: LinkPerson, val app: EngineAppApi)

    private suspend fun world(): World {
        val home = LinkServer(crypto)
        val other = LinkServer(crypto, FakeInstance(crypto, origin = "https://b.example"))
        val items = Items(home.instance)
        val alice = LinkPerson(crypto, home, 1, "11111111-1111-4111-8111-111111111111", "Alice").start()
        val carol = LinkPerson(crypto, other, 3, "33333333-3333-4333-8333-333333333333", "Carol").start()
        var self: EngineAppApi? = null
        fun asApp(server: LinkServer, plane: Items?) = object : WireClient {
            override val origin: String = server.instance.origin
            override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                val caller = self?.keeper?.session?.takeIf { it.origin == server.instance.origin }?.userId
                plane?.answer(route, query, bodyJson, caller, decode)?.let { return it }
                return server.client(caller).call(route, pathParams, query, bodyJson, authenticated, decode)
            }
        }
        val app = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel",
                BearerTransport(mapOf(home.instance.origin to asApp(home, items), other.instance.origin to asApp(other, null))),
                MemoryDeviceState(), MemoryDeviceState(), crypto, { home.instance.now }, baked = null, storeBuild = false, stores = null,
                main = Dispatchers.Unconfined, work = Dispatchers.Unconfined, cacheFiles = DurableFiles()),
        ).also {
            self = it
            it.linksFlow.answersPollMs = Long.MAX_VALUE
            it.start()
        }
        return World(home, other, items, alice, carol, app)
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    private suspend fun link(p: LinkPerson): String = assertIs<CreateOutcome.Created>(p.flows.create("connect", 60 * 60 * 1000L, emptyList())).link.url

    private suspend fun EngineAppApi.joinAndSignUp(email: String) {
        assertEquals(ServerResult.DONE, entry.joinFromInvite(at()))
        assertEquals(io.silencelen.andvari.core.app.SignUpStartResult.DONE, entry.startSignUp(at(), email, true))
        assertEquals(io.silencelen.andvari.core.app.CodeResult.DONE, entry.verifySignUpCode(at(), "482915"))
        assertEquals(CreateAccountResult.DONE, entry.createAccount(at(), NewAccountInput("", "Bob", strong, true)))
        val kit = at<EntryScreen.Kit>()
        val doc = assertNotNull(kit.kit.let { this.kit.kitDocument(it) })
        this.kit.proceedToConfirm(kit.kit)
        val confirm = at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, this.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        assertEquals(AppPhase.UNLOCKED, snapshot.phase)
    }

    private fun login(name: String) = LoginInput(name, "me", "pw-$name", listOf("https://$name.test"), "", "", false)

    /** Signed in at home through Alice's link; two logins saved while home answers nothing; then Carol's invite for the other server. */
    private suspend fun World.unsentThenInvite(): OpenedInvite.OtherInstance {
        app.entry.openInviteEntry(app.at())
        assertEquals(InviteResult.DONE, app.entry.submitInvite(app.at(), link(alice), PayloadSource.SCANNED))
        app.joinAndSignUp("bob@example.com")
        // The second opening has read the policy, which allows an offline copy: the cache is the account's own file.
        app.lock()
        assertEquals(VaultUnlockResult.DONE, app.unlock(app.snapshot.locked!!, strong))
        val c = assertNotNull(app.content)
        assertEquals(ActionResult.Ok, c.syncQuietly())
        items.down = true
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("Bank"), null))
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("Shop"), null))
        assertEquals(InviteResult.DONE, app.links.openInvite(link(carol), PayloadSource.SCANNED))
        return assertIs(app.snapshot.account!!.opened)
    }

    private fun World.stillHere(ask: OpenedInvite.OtherInstance, userId: String?) {
        assertEquals(AppPhase.UNLOCKED, app.snapshot.phase)
        assertEquals(userId, app.keeper.session?.userId, "still signed in here")
        assertSame(ask, app.snapshot.account!!.opened, "the prompt stays")
        assertEquals(2, app.vault!!.queued().pending.size, "both changes still wait in this device's copy")
        assertTrue(other.rows.values.all { it.state == "open" }, "nothing answered at the other server")
    }

    @Test fun theSwitchOverUnsentChangesWithoutTheConfirmationSignsNothingOut() = runBlocking<Unit> {
        val w = world()
        val ask = w.unsentThenInvite()
        val me = w.app.keeper.session?.userId
        val check = assertNotNull(w.app.signOutCheck())
        assertEquals(2, check.unsentChanges)
        assertEquals(CopyKey.SIGN_OUT_UNSENT_LOST, check.line?.key)
        assertTrue(check.canSendFirst)
        val asked = w.other.instance.calls.size
        assertEquals(ServerResult.UNSENT_NOT_CONFIRMED, w.app.links.switchInstance(ask))
        assertEquals(asked, w.other.instance.calls.size, "the other server is asked nothing before the confirmation")
        w.stillHere(ask, me)
    }

    @Test fun theSwitchWithTheSecondConfirmationSignsOutAndGoesOnThere() = runBlocking<Unit> {
        val w = world()
        val ask = w.unsentThenInvite()
        val check = assertNotNull(w.app.signOutCheck())
        assertEquals(ServerResult.DONE, w.app.links.switchInstanceConfirmed(ask, check))
        assertEquals(AppPhase.ENTRY, w.app.snapshot.phase)
        assertNull(w.app.keeper.session, "signed out here")
        assertEquals(w.other.instance.origin, w.app.at<EntryScreen.JoinInvite>().instance.origin)
        assertEquals(0, w.items.items.size, "the two changes never reached home")
    }

    @Test fun sendingFirstThatSucceedsLetsTheSwitchGoWithoutASecondConfirmation() = runBlocking<Unit> {
        val w = world()
        val ask = w.unsentThenInvite()
        val check = assertNotNull(w.app.signOutCheck())
        w.items.down = false
        assertEquals(SendFirstResult.DONE, w.app.sendBeforeSignOut(check))
        assertEquals(2, w.items.items.size, "both changes reached home")
        assertEquals(0, assertNotNull(w.app.signOutCheck()).unsentChanges)
        assertEquals(ServerResult.DONE, w.app.links.switchInstance(ask))
        w.app.at<EntryScreen.JoinInvite>()
    }

    @Test fun sendingFirstThatFailsKeepsTheSwitchBehindTheConfirmation() = runBlocking<Unit> {
        val w = world()
        val ask = w.unsentThenInvite()
        val me = w.app.keeper.session?.userId
        val check = assertNotNull(w.app.signOutCheck())
        assertEquals(SendFirstResult.NOT_ALL_SENT, w.app.sendBeforeSignOut(check))
        assertEquals(ServerResult.UNSENT_NOT_CONFIRMED, w.app.links.switchInstance(ask))
        w.stillHere(ask, me)
        // A check from before a further change confirms nothing.
        assertEquals(ActionResult.Ok, w.app.content!!.saveLogin(null, login("Mail"), null))
        assertEquals(ServerResult.UNSENT_NOT_CONFIRMED, w.app.links.switchInstanceConfirmed(ask, check))
        assertEquals(AppPhase.UNLOCKED, w.app.snapshot.phase)
    }

    /**
     * The line beside "switch": the server serves no read of "New devices must be linked", so by default this device
     * cannot tell and the line says what that would mean; after this device turned it on, the line says that signing in
     * again here will not bring the account back by itself; turned off here, the plain line.
     */
    @Test fun theLineBesideTheSwitchSaysWhetherSigningInAgainBringsTheAccountBack() = runBlocking<Unit> {
        val w = world()
        val a = w.app
        a.entry.openInviteEntry(a.at())
        assertEquals(InviteResult.DONE, a.entry.submitInvite(a.at(), link(w.alice), PayloadSource.SCANNED))
        a.joinAndSignUp("bob@example.com")
        val home = w.home.instance

        assertEquals(InviteResult.DONE, a.links.openInvite(link(w.carol), PayloadSource.SCANNED))
        var ask = assertIs<OpenedInvite.OtherInstance>(a.snapshot.account!!.opened)
        assertNull(ask.linkRequired)
        assertEquals(CopyKey.OTHER_INSTANCE_SIGNS_OUT_LINK_UNKNOWN, ask.signOutLine.key)
        assertEquals(listOf(ask.signedInTo.name, home.origin), ask.signOutLine.values)
        a.links.dismissOpened()

        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.devices.openDevices())
        assertEquals(ProofResult.DONE, a.devices.setRequireLink(true, strong))
        a.devices.closeDevices()
        assertEquals(InviteResult.DONE, a.links.openInvite(link(w.carol), PayloadSource.SCANNED))
        ask = assertIs(a.snapshot.account!!.opened)
        assertEquals(true, ask.linkRequired)
        assertEquals(CopyKey.OTHER_INSTANCE_SIGNS_OUT_LINK_REQUIRED, ask.signOutLine.key)
        assertEquals(listOf(ask.signedInTo.name, home.origin), ask.signOutLine.values)
        a.links.dismissOpened()

        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.devices.openDevices())
        assertEquals(ProofResult.DONE, a.devices.setRequireLink(false, strong))
        a.devices.closeDevices()
        assertEquals(InviteResult.DONE, a.links.openInvite(link(w.carol), PayloadSource.SCANNED))
        ask = assertIs(a.snapshot.account!!.opened)
        assertEquals(CopyKey.OTHER_INSTANCE_SIGNS_OUT, ask.signOutLine.key)
    }
}
