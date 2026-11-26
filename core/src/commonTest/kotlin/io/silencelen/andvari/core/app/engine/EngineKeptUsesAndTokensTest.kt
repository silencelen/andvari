package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.boundedProbe
import io.silencelen.andvari.core.app.waitFor
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.UsageLedger
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
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * What a lock keeps of the uses of logins, and
 * the tokens of a session the keeper rebuilds.
 */
class EngineKeptUsesAndTokensTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    /** The onboarding fake with the item plane and the usage ledger of an honest server; one route can be held. */
    private class Server(val instance: FakeInstance) : WireClient by instance {
        var locked = false
        val sentAfterLock = ArrayList<WireRoute>()
        private var rev = 1L
        private val items = ArrayList<SyncItem>()
        var usage: String? = null
        var usagePuts = 0
        var holdRoute: WireRoute? = null
        val reached = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()

        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            if (locked) sentAfterLock += route
            if (route == holdRoute) {
                holdRoute = null
                reached.complete(Unit)
                release.await()
            }
            return when (route) {
                WireRoute.SYNC -> {
                    val since = query?.substringAfter("since=")?.toLongOrNull() ?: 0L
                    val pv = instance.accounts.values.lastOrNull()?.personalWrap?.vaultId
                    val vaults = pv?.let { listOf(SyncVault(it, "personal", 1, "", instance.now)) }.orEmpty()
                    WireResult.Ok(decode(WireJson.json.encodeToString(SyncResponse.serializer(),
                        SyncResponse(rev, since == 0L, vaults, emptyList(), items.filter { it.rev > since }, emptyList(), emptyList(), 0, 0))), 200)
                }
                WireRoute.PUSH -> {
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
                WireRoute.USAGE_GET -> WireResult.Ok(decode("""{"sealedUsage":${usage?.let { "\"$it\"" } ?: "null"},"updatedAt":0}"""), 200)
                WireRoute.USAGE_PUT -> {
                    usage = WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.UsagePut.serializer(), bodyJson!!).sealedUsage
                    usagePuts++
                    WireResult.Ok(decode(""), 200)
                }
                else -> instance.call(route, pathParams, query, bodyJson, authenticated, decode)
            }
        }
    }

    private class Env(val server: Server, val app: EngineAppApi) {
        var consent = true
        fun lockNow() {
            server.locked = true
            app.lock()
        }
        val origin: String get() = server.instance.origin
        val userId: String get() = assertNotNull(app.keeper.session).userId
    }

    private fun env(): Env {
        val server = Server(FakeInstance(crypto))
        var e: Env? = null
        val app = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.instance.origin to server)), MemoryDeviceState(), MemoryDeviceState(), crypto,
                { server.instance.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
                keepsAtRest = { e?.consent ?: true }),
        ).also {
            it.linkPollMs = Long.MAX_VALUE
            it.start()
        }
        return Env(server, app).also { e = it }
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    /** A new account, its kit confirmed, then locked and unlocked once so the opening has read the policy (an offline copy is allowed). */
    private suspend fun open(e: Env) {
        val a = e.app
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(a.at()))
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), "alice@example.com", true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "Alice", strong, true)))
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    private suspend fun reopen(e: Env) {
        e.app.lock()
        e.server.locked = false
        assertEquals(VaultUnlockResult.DONE, e.app.unlock(e.app.snapshot.locked!!, strong))
    }

    /** Saves "Bank" and answers its id. */
    private suspend fun bank(e: Env): String {
        val c = assertNotNull(e.app.content)
        assertEquals(ActionResult.Ok, c.saveLogin(null, LoginInput("Bank", "me", "pw-secret", listOf("https://bank.test"), "", "", false), null))
        return c.state.items.single { it.name == "Bank" }.itemId
    }

    private fun Env.ledger(): Map<String, UsageLedger.Entry> = UsageLedger.parse(app.vault!!.openUsage(assertNotNull(server.usage)).decodeToString())

    /**
     * The sequence: a use is recorded, the flush after a sync has taken it and waits for the server's copy,
     * and the lock comes. Before, the flush read the lock as "unreadable" and re-armed into a closed session: the use was
     * lost. Now it is kept like the others, sealed before the wipe, nothing is sent after the lock, and the next unlock's
     * first sync sends it once.
     */
    @Test fun aUseAFlushHadTakenWhenTheLockCameIsKeptAndSentOnceAfterTheNextUnlock() = boundedProbe {
        val e = env()
        open(e)
        reopen(e)
        assertTrue(assertNotNull(e.app.vault).keptAtRest)
        val id = bank(e)
        val c = assertNotNull(e.app.content)
        assertNotNull(c.fillCredential(id))
        e.app.vault!!.afterLogAction()
        assertEquals(1L, e.ledger()[id]?.useCount)

        // Past the content's window in which a second release is the same use.
        e.server.instance.now += 600_000
        val secondAt = e.server.instance.now
        assertTrue(assertNotNull(e.ledger()[id]).lastUsedAt < secondAt)
        assertNotNull(c.fillCredential(id))
        e.server.holdRoute = WireRoute.USAGE_GET
        e.app.vault!!.afterLogAction()
        waitFor("the flush's read of the ledger") { e.server.reached.await() }
        e.lockNow()
        e.server.release.complete(Unit)
        assertTrue(WireRoute.USAGE_PUT !in e.server.sentAfterLock, "nothing is sent after the lock: ${e.server.sentAfterLock}")
        assertNotNull(e.app.engine.state.get(EngineVault.keptUsesKey(e.origin, e.userId)), "the use the flush had taken is kept")

        e.server.locked = false
        assertEquals(VaultUnlockResult.DONE, e.app.unlock(e.app.snapshot.locked!!, strong))
        // The ledger merges by the maximum (UsageLedger.merge): the kept use shows as its time.
        assertEquals(secondAt, e.ledger()[id]?.lastUsedAt, "sent by the next opening's sync")
        assertNull(e.app.engine.state.get(EngineVault.keptUsesKey(e.origin, e.userId)), "handed on, so it is sent once")
    }

    /**
     * The kept record is the server's and the account's: one of another server with the same account id is never opened
     * or taken as this account's, and it goes when this account opens here (another account is in use on this device);
     * so does a record under the old, id-only key, which is never read.
     */
    @Test fun theKeptRecordIsKeyedByServerAndAccountAndAnotherAccountsGoesWhenThisOneOpens() = boundedProbe {
        val e = env()
        open(e)
        reopen(e)
        val id = bank(e)
        val other = "https://other.example"
        val state = e.app.engine.state
        state.set(EngineVault.keptUsesKey(other, e.userId), "kept-elsewhere")
        e.app.noteHeld(other, e.userId)
        state.set("ovh.usage.kept|${e.userId}", "kept-before")
        assertNotNull(assertNotNull(e.app.content).fillCredential(id))
        e.lockNow()
        assertNotNull(state.get(EngineVault.keptUsesKey(e.origin, e.userId)))

        e.server.locked = false
        assertEquals(VaultUnlockResult.DONE, e.app.unlock(e.app.snapshot.locked!!, strong))
        assertNull(state.get(EngineVault.keptUsesKey(other, e.userId)), "another account's record goes when this one opens")
        assertNull(state.get("ovh.usage.kept|${e.userId}"), "the record under the old key goes, unread")
        assertNull(state.get(EngineVault.keptUsesKey(e.origin, e.userId)))
        assertEquals(1L, e.ledger()[id]?.useCount, "this account's own kept use is sent")
    }

    /** Kept uses go when keeping is no longer allowed: the platform's consent turned off while locked, and a sign-out. */
    @Test fun keptUsesGoWhenTheConsentTurnsWhileLockedAndAtASignOut() = boundedProbe {
        val e = env()
        open(e)
        reopen(e)
        val id = bank(e)
        val state = e.app.engine.state
        assertNotNull(assertNotNull(e.app.content).fillCredential(id))
        e.lockNow()
        val key = EngineVault.keptUsesKey(e.origin, e.userId)
        assertNotNull(state.get(key))
        e.consent = false
        e.app.atRestConsentChanged()
        assertNull(state.get(key), "the consent turned: nothing stays at rest, locked or not")

        // Allowed again: a new kept record, and the person's sign-out removes it.
        e.consent = true
        reopen(e)
        assertNotNull(assertNotNull(e.app.content).fillCredential(id))
        e.lockNow()
        assertNotNull(state.get(key))
        e.server.locked = false
        assertEquals(PlainResult.DONE, e.app.signOutConfirmed(kotlin.test.assertNotNull(e.app.signOutCheck())))
        assertNull(state.get(key))
    }

    /**
     * A session the keeper rebuilds at each unlock hands out no tokens. Only the session a sign-in
     * made hands its pair over, once.
     */
    @Test fun aSessionTheKeeperRebuildsAtAnUnlockHandsOutNoTokens() = boundedProbe {
        val e = env()
        open(e)
        val first = assertNotNull(e.app.keeper.established)
        assertNotNull(first.takeTokens(), "the session the sign-up made hands its pair over")
        assertNull(first.takeTokens(), "once")
        reopen(e)
        val rebuilt = assertNotNull(e.app.keeper.established)
        assertTrue(rebuilt !== first)
        assertNull(rebuilt.takeTokens(), "a session rebuilt at an unlock hands out nothing")
    }
}
